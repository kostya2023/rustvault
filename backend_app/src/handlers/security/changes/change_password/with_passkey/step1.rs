use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;
use webauthn_rs::prelude::RequestChallengeResponse;

use crate::{
    services::jwtokens::JWTAccessToken,
    types::{app_state::AppState, errors::AppError},
};

#[utoipa::path(
    post,
    path = "/v1/security/changes/change-password/with-passkey/step1",
    tag = "Security",
    summary = "Begin password change with passkey confirmation",
    request_body = crate::api_docs::ChangePasswordPasskeyStep1Request,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Passkey assertion options and new-password challenge", body = crate::api_docs::ChangePasswordPasskeyStep1Response),
        (status = 400, description = "Malformed OPAQUE registration request", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn change_password_with_passkey_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<ChangePasswordStep1Request>,
) -> Result<Json<ChangePasswordStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();
    let passkey_props = app_state
        .services
        .passkeys
        .auth_passkey_step1(&jwt_access.sub, &operation_id)
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

    info!(trace_id = %trace_id, operation_id = %operation_id, "Password change with passkey started");
    Ok(Json(ChangePasswordStep1Response {
        operation_id,
        passkey_props,
        new_password_response,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordStep1Request {
    pub new_password_request: String,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordStep1Response {
    pub operation_id: Uuid,
    pub passkey_props: RequestChallengeResponse,
    pub new_password_response: String,
}
