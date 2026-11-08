use crate::{
    services::user_events::EventType,
    types::{app_state::AppState, errors::AppError},
};
use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;
use webauthn_rs::prelude::RequestChallengeResponse;

#[utoipa::path(
    post,
    path = "/v1/auth/login/with-passkey/step1",
    tag = "Authentication",
    summary = "Begin passkey login",
    request_body = crate::api_docs::LoginPasskeyStep1Request,
    responses(
        (status = 200, description = "WebAuthn request options", body = crate::api_docs::LoginPasskeyStep1Response),
        (status = 404, description = "No passkeys found for account", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn auth_login_with_passkey_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Json(request): Json<AuthLoginWithPasskeyStep1Request>,
) -> Result<Json<AuthLoginWithPasskeyStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();

    let passkey_props = match app_state
        .services
        .passkeys
        .auth_login_passkey_step1(&request.username, &operation_id)
        .await
    {
        Ok(properties) => properties,
        Err(error) => {
            if app_state
                .services
                .account
                .check_user_exists(&request.username)
                .await?
            {
                let error = app_state
                    .services
                    .user_events
                    .record_failure(
                        &request.username,
                        EventType::LoginFailedWithPasskey,
                        &trace_id,
                        Some(&operation_id),
                        error,
                    )
                    .await;
                return Err(error);
            }
            return Err(error);
        }
    };

    info!(
        operation_id = %operation_id,
        trace_id = %trace_id,
        "Passkey authentication step 1 completed"
    );

    Ok(Json(AuthLoginWithPasskeyStep1Response {
        passkey_props,
        operation_id,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthLoginWithPasskeyStep1Request {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthLoginWithPasskeyStep1Response {
    pub passkey_props: RequestChallengeResponse,
    pub operation_id: Uuid,
}
