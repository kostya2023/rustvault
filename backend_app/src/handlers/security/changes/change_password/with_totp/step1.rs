use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::{
    services::jwtokens::JWTAccessToken,
    types::{app_state::AppState, errors::AppError},
};

#[utoipa::path(
    post,
    path = "/v1/security/changes/change-password/with-totp/step1",
    tag = "Security",
    summary = "Begin password change with current password and TOTP",
    request_body = crate::api_docs::ChangePasswordTotpStep1Request,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current-password and new-password OPAQUE challenges", body = crate::api_docs::ChangePasswordTotpStep1Response),
        (status = 400, description = "Malformed OPAQUE request", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn change_password_with_totp_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<ChangePasswordStep1Request>,
) -> Result<Json<ChangePasswordStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();
    let current_password_response = app_state
        .services
        .password
        .auth_password_step1(
            &jwt_access.sub,
            &request.current_password_request,
            &operation_id,
        )
        .await?;
    let new_password_response = app_state
        .services
        .password
        .register_password_step1(
            &jwt_access.sub,
            &request.new_password_request,
            &operation_id,
        )
        .await?;

    info!(trace_id = %trace_id, operation_id = %operation_id, "Password change with TOTP started");
    Ok(Json(ChangePasswordStep1Response {
        operation_id,
        current_password_response,
        new_password_response,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordStep1Request {
    pub current_password_request: String,
    pub new_password_request: String,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordStep1Response {
    pub operation_id: Uuid,
    pub current_password_response: String,
    pub new_password_response: String,
}
