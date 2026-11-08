use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::Serialize;
use tracing::info;
use uuid::Uuid;
use webauthn_rs::prelude::RequestChallengeResponse;

use crate::{
    services::jwtokens::JWTAccessToken,
    types::{app_state::AppState, errors::AppError},
};

#[utoipa::path(
    post,
    path = "/v1/security/changes/change-totp/with-passkey/step1",
    tag = "Security",
    summary = "Begin TOTP replacement with passkey confirmation",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Passkey options and new TOTP provisioning URI", body = crate::api_docs::ChangeTotpPasskeyStep1Response),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 404, description = "No registered passkey found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn change_totp_with_passkey_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
) -> Result<Json<ChangeTotpStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();
    let passkey_props = app_state
        .services
        .passkeys
        .auth_passkey_step1(&jwt_access.sub, &operation_id)
        .await?;
    let totp_url = app_state
        .services
        .totp
        .update_totp_step1(&jwt_access.sub, &operation_id)
        .await?;

    info!(trace_id = %trace_id, operation_id = %operation_id, "TOTP change with passkey started");
    Ok(Json(ChangeTotpStep1Response {
        operation_id,
        passkey_props,
        totp_url,
    }))
}

#[derive(Debug, Serialize)]
pub struct ChangeTotpStep1Response {
    pub operation_id: Uuid,
    pub passkey_props: RequestChallengeResponse,
    pub totp_url: String,
}
