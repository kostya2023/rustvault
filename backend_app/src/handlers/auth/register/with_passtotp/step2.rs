use crate::services::user_events::EventType;
use crate::types::{
    app_state::AppState,
    errors::{AppError, InternalKind},
};
use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

#[utoipa::path(
    post,
    path = "/v1/auth/register/with-passtotp/step2",
    tag = "Authentication",
    summary = "Complete password and TOTP registration",
    request_body = crate::api_docs::RegisterStep2Request,
    responses(
        (status = 200, description = "Account created and token pair issued", body = crate::api_docs::TokenPairResponse),
        (status = 400, description = "Invalid password upload or TOTP code", body = crate::api_docs::ErrorBody),
        (status = 404, description = "Registration operation expired or was not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn auth_register_with_passtotp_step2(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Json(request): Json<AuthRegisterWithPasstotpStep2Request>,
) -> Result<Json<AuthRegisterWithPasstotpStep2Response>, AppError> {
    let mut tx = app_state
        .resources
        .database
        .begin()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

    let mut redis_conn = app_state
        .resources
        .cache
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
    let key = format!("auth:register:passtotp:{}", request.operation_id);
    let username: String = redis::cmd("GETDEL")
        .arg(&key)
        .query_async(&mut redis_conn)
        .await
        .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

    app_state
        .services
        .account
        .create_user(&username, &mut tx)
        .await?;

    app_state
        .services
        .blob
        .create_blob(&username, &mut tx)
        .await?;

    let _username = app_state
        .services
        .password
        .register_password_step2(&request.operation_id, &request.password_upload, &mut tx)
        .await?;

    let _username = app_state
        .services
        .totp
        .register_totp_step2(&request.operation_id, &request.totp_code, &mut tx)
        .await?;

    let (access, refresh) = app_state.services.jwtokens.generate_pair(&username)?;

    app_state
        .services
        .user_events
        .create_event(
            &username,
            EventType::SudoAccountCreated,
            None,
            None,
            None,
            Some(&trace_id),
            Some(&request.operation_id),
            &mut tx,
        )
        .await?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

    info!(
        operation_id = %request.operation_id,
        trace_id = %trace_id,
        "Passtotp registration step 2 completed"
    );

    Ok(Json(AuthRegisterWithPasstotpStep2Response {
        username,
        access_token: access,
        refresh_token: refresh,
        access_token_ttl: app_state.resources.jwt_access_token_ttl,
        refresh_token_ttl: app_state.resources.jwt_refresh_token_ttl,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRegisterWithPasstotpStep2Request {
    pub username: String,
    pub password_upload: String,
    pub totp_code: String,
    pub operation_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRegisterWithPasstotpStep2Response {
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_ttl: u64,
    pub refresh_token_ttl: u64,
}
