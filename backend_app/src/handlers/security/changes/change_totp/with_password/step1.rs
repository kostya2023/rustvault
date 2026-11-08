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
    path = "/v1/security/changes/change-totp/with-password/step1",
    tag = "Security",
    summary = "Begin TOTP replacement with current password",
    request_body = crate::api_docs::ChangeTotpPasswordStep1Request,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Password challenge and new TOTP provisioning URI", body = crate::api_docs::ChangeTotpPasswordStep1Response),
        (status = 400, description = "Malformed password request", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn change_totp_with_password_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<ChangeTotpStep1Request>,
) -> Result<Json<ChangeTotpStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();
    let password_response = app_state
        .services
        .password
        .auth_password_step1(&jwt_access.sub, &request.password_request, &operation_id)
        .await?;
    let totp_url = app_state
        .services
        .totp
        .update_totp_step1(&jwt_access.sub, &operation_id)
        .await?;

    info!(trace_id = %trace_id, operation_id = %operation_id, "TOTP change with password started");
    Ok(Json(ChangeTotpStep1Response {
        operation_id,
        password_response,
        totp_url,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ChangeTotpStep1Request {
    pub password_request: String,
}

#[derive(Debug, Serialize)]
pub struct ChangeTotpStep1Response {
    pub operation_id: Uuid,
    pub password_response: String,
    pub totp_url: String,
}
