use anyhow::{Context, Result};
use axum::{
    Router, extract::DefaultBodyLimit, middleware, routing::{delete, get, post, put},
};
use backend_app::{
    graceful_shutdown,
    handlers::{account, auth, blob, healthz, security},
    middlewares::{auth_access, auth_refresh, logging},
    types::{app_resources::AppResources, app_state::AppState, init_config::InitConfig},
    utils::tracing_init::tracing_init,
};
use std::{sync::Arc, time::Instant};
use tokio::net::TcpListener;
use tracing::{Instrument, info, info_span};

#[tokio::main]
async fn main() -> Result<()> {
    // Step 1: InitLog
    tracing_init();
    info!("Hello! RustVault server starting...");

    // Step 2: Initializing...
    let span = info_span!("server_initialization");
    let (app_state, init_config) = async {
        let start = Instant::now();

        // Step 2.1 - Dotenvy
        info!("Loading config...");
        dotenvy::from_path("/run/secrets/rustvault.env")
            .context("Failed to load environment configuration")?;
        info!("Config loaded.");

        // Step 2.2 - InitConfig
        info!("Getting env...");
        let init_config =
            InitConfig::from_env().context("Failed to create InitConfig from environment")?;
        info!("InitConfig created.");

        // Step 2.3 - AppResources
        info!("Creating AppResources...");
        let app_resources = AppResources::from_init_config(&init_config)
            .await
            .context("Failed to create AppResources")?;
        info!("AppResources created.");

        // Step 2.4 - AppState
        info!("Creating AppState...");
        let app_state = AppState::new(app_resources);
        info!("AppState created.");

        let elapsed = start.elapsed();
        info!("Initialization completed in {} ms", elapsed.as_millis());

        Ok::<(AppState, InitConfig), anyhow::Error>((app_state, init_config))
    }
    .instrument(span)
    .await?;

    // SPECIAL STEP 2/5
    info!("Applying migrations...");
    let start = Instant::now();
    sqlx::migrate!("./migrations")
        .run(&app_state.resources.database)
        .await
        .context("Error applying migrations.")?;
    let end = start.elapsed();
    info!("migrations applied with: {}ms", end.as_millis());

    // SPECIAL STEP 2.5/3
    info!("Checking MinIO bucket...");

    if !app_state
        .services
        .blob
        .check_bucket_exists(&app_state.resources.blob_bucket_name)
        .await?
    {
        app_state
            .services
            .blob
            .create_bucket(&app_state.resources.blob_bucket_name)
            .await
            .context("Error creating MinIO bucket.")?;

        info!("Bucket created.");
    } else {
        info!("Bucket already exists.");
    }

    // Step 3: Creating App
    info!("Creating router...");
    let healthz = Router::new().route("/v1/healthz", get(healthz::healthz));

    let app_state = Arc::new(app_state);

    let public_auth = Router::new()
        .route(
            "/v1/auth/register/with-passtotp/step1",
            post(auth::register::with_passtotp::step1::auth_register_with_passtotp_step1),
        )
        .route(
            "/v1/auth/register/with-passtotp/step2",
            post(auth::register::with_passtotp::step2::auth_register_with_passtotp_step2),
        )
        .route(
            "/v1/auth/login/with-passtotp/step1",
            post(auth::login::with_passtotp::step1::auth_login_with_passtotp_step1),
        )
        .route(
            "/v1/auth/login/with-passtotp/step2",
            post(auth::login::with_passtotp::step2::auth_login_with_passtotp_step2),
        )
        .route(
            "/v1/auth/login/with-passkey/step1",
            post(auth::login::with_passkey::step1::auth_login_with_passkey_step1),
        )
        .route(
            "/v1/auth/login/with-passkey/step2",
            post(auth::login::with_passkey::step2::auth_login_with_passkey_step2),
        );

    let refresh_auth = Router::new()
        .route(
            "/v1/auth/refresh",
            post(auth::refresh_tokens::auth_refresh_tokens),
        )
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_refresh::auth_refresh_middleware,
        ));

    let protected = Router::new()
        .route("/v1/auth/logout", delete(auth::logout::auth_logout))
        .route("/v1/account", get(account::get_info::get_account_info))
        .route(
            "/v1/account/delete/with-passkey/step1",
            post(account::delete::with_passkey::step1::delete_account_with_passkey_step1),
        )
        .route(
            "/v1/account/delete/with-passkey/step2",
            delete(account::delete::with_passkey::step2::delete_account_with_passkey_step2),
        )
        .route(
            "/v1/account/delete/with-passtotp/step1",
            post(account::delete::with_passtotp::step1::delete_account_with_passtotp_step1),
        )
        .route(
            "/v1/account/delete/with-passtotp/step2",
            delete(account::delete::with_passtotp::step2::delete_account_with_passtotp_step2),
        )
        .route(
            "/v1/security/events",
            get(security::get_events::get_security_events),
        )
        .route(
            "/v1/security/passkeys",
            get(security::manage_passkeys::get_passkeys::get_passkeys),
        )
        .route(
            "/v1/security/manage-passkeys/add/step1",
            post(security::manage_passkeys::add_passkey::step1::add_passkey_step1),
        )
        .route(
            "/v1/security/manage-passkeys/add/step2",
            post(security::manage_passkeys::add_passkey::step2::add_passkey_step2),
        )
        .route(
            "/v1/security/manage-passkeys/delete/step1",
            post(security::manage_passkeys::delete_passkey::step1::delete_passkey_step1),
        )
        .route(
            "/v1/security/manage-passkeys/delete/step2",
            delete(security::manage_passkeys::delete_passkey::step2::delete_passkey_step2),
        )
        .route(
            "/v1/security/changes/change-password/with-passkey/step1",
            post(security::changes::change_password::with_passkey::step1::change_password_with_passkey_step1),
        )
        .route(
            "/v1/security/changes/change-password/with-passkey/step2",
            put(security::changes::change_password::with_passkey::step2::change_password_with_passkey_step2),
        )
        .route(
            "/v1/security/changes/change-password/with-totp/step1",
            post(security::changes::change_password::with_totp::step1::change_password_with_totp_step1),
        )
        .route(
            "/v1/security/changes/change-password/with-totp/step2",
            put(security::changes::change_password::with_totp::step2::change_password_with_totp_step2),
        )
        .route(
            "/v1/security/changes/change-totp/with-passkey/step1",
            post(security::changes::change_totp::with_passkey::step1::change_totp_with_passkey_step1),
        )
        .route(
            "/v1/security/changes/change-totp/with-passkey/step2",
            put(security::changes::change_totp::with_passkey::step2::change_totp_with_passkey_step2),
        )
        .route(
            "/v1/security/changes/change-totp/with-password/step1",
            post(security::changes::change_totp::with_password::step1::change_totp_with_password_step1),
        )
        .route(
            "/v1/security/changes/change-totp/with-password/step2",
            put(security::changes::change_totp::with_password::step2::change_totp_with_password_step2),
        )
        .route("/v1/blob/meta", get(blob::get_meta::get_meta))
        .route("/v1/blob", get(blob::get_blob::get_blob).put(blob::upload_blob::upload_blob))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_access::auth_access_middleware,
        ));

    let app = Router::new()
        .merge(healthz)
        .merge(public_auth)
        .merge(refresh_auth)
        .merge(protected)
        .layer(DefaultBodyLimit::max(init_config.blob.max_size as usize))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            logging::logging_middleware,
        ))
        .with_state(app_state);
    info!("Router created.");

    // Step 4: Listener
    info!("Creating Listener...");
    let listener = TcpListener::bind(format!("0.0.0.0:{}", init_config.server.port))
        .await
        .context("Failed creating listener.")?;
    info!("Listener created.");
    info!("Listening at: {}", listener.local_addr()?);

    // Step 5: Server
    info!("RustVault server started!");
    axum::serve(listener, app)
        .with_graceful_shutdown(graceful_shutdown::graceful_shutdown())
        .await
        .context("Server starting failed.")?;

    // Step 6: Shutdown
    info!("RustVault server stopped. Goodbyee!");

    Ok(())
}
