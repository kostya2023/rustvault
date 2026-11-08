use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::Serialize;
use tracing::info;
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::{
    services::jwtokens::JWTAccessToken,
    types::{app_state::AppState, errors::AppError},
};

#[utoipa::path(
    post,
    path = "/v1/security/manage-passkeys/add/step1",
    tag = "Security",
    summary = "Begin passkey registration",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "WebAuthn registration options and operation ID", body = crate::api_docs::PasskeyChallengeResponse),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database or WebAuthn error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn add_passkey_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
) -> Result<Json<AddPasskeyStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();
    let passkey_props = app_state
        .services
        .passkeys
        .register_passkey_step1(&jwt_access.sub, &operation_id)
        .await?;

    info!(trace_id = %trace_id, operation_id = %operation_id, "Passkey registration started");
    Ok(Json(AddPasskeyStep1Response {
        operation_id,
        passkey_props,
    }))
}

#[derive(Debug, Serialize)]
pub struct AddPasskeyStep1Response {
    pub operation_id: Uuid,
    pub passkey_props: CreationChallengeResponse,
}
