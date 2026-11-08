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
    path = "/v1/account/delete/with-passtotp/step1",
    tag = "Account",
    summary = "Begin account deletion using password and TOTP",
    request_body = crate::api_docs::DeletePasswordStep1Request,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Password challenge and operation ID", body = crate::api_docs::DeletePasswordStep1Response),
        (status = 400, description = "Malformed password request", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn delete_account_with_passtotp_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<DeleteAccountStep1Request>,
) -> Result<Json<DeleteAccountStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();
    let password_response = app_state
        .services
        .password
        .auth_password_step1(&jwt_access.sub, &request.password_request, &operation_id)
        .await?;

    info!(trace_id = %trace_id, operation_id = %operation_id, "Account deletion confirmation started");
    Ok(Json(DeleteAccountStep1Response {
        operation_id,
        password_response,
    }))
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountStep1Request {
    pub password_request: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteAccountStep1Response {
    pub operation_id: Uuid,
    pub password_response: String,
}
