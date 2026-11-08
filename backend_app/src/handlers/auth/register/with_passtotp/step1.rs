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
    path = "/v1/auth/register/with-passtotp/step1",
    tag = "Authentication",
    summary = "Begin password and TOTP registration",
    request_body = crate::api_docs::RegisterStep1Request,
    responses(
        (status = 200, description = "Password challenge and TOTP provisioning URI", body = crate::api_docs::RegisterStep1Response),
        (status = 400, description = "Malformed registration request", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Username already exists", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn auth_register_with_passtotp_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Json(request): Json<AuthRegisterWithPasstotpStep1Request>,
) -> Result<Json<AuthRegisterWithPasstotpStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();

    let password_response = app_state
        .services
        .password
        .register_password_step1(&request.username, &request.password_request, &operation_id)
        .await?;

    let totp_url = app_state
        .services
        .totp
        .register_totp_step1(&request.username, &operation_id)
        .await?;

    let mut redis_conn = app_state
        .resources
        .cache
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
    let key = format!("auth:register:passtotp:{operation_id}");
    redis::cmd("SETEX")
        .arg(&key)
        .arg(300)
        .arg(request.username)
        .query_async::<()>(&mut redis_conn)
        .await
        .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

    info!(
        operation_id = %operation_id,
        trace_id = %trace_id,
        "Passtotp registration step 1 completed"
    );

    Ok(Json(AuthRegisterWithPasstotpStep1Response {
        password_response,
        totp_url,
        operation_id,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRegisterWithPasstotpStep1Request {
    pub username: String,
    pub password_request: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRegisterWithPasstotpStep1Response {
    pub password_response: String,
    pub totp_url: String,
    pub operation_id: Uuid,
}
