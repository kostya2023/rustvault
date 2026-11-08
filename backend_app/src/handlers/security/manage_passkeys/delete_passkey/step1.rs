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
    path = "/v1/security/manage-passkeys/delete/step1",
    tag = "Security",
    summary = "Begin passkey deletion",
    request_body = crate::api_docs::DeletePasskeyStep1Request,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "WebAuthn assertion options and operation ID", body = crate::api_docs::DeletePasskeyStep1Response),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 404, description = "No passkey found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database or WebAuthn error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn delete_passkey_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<DeletePasskeyStep1Request>,
) -> Result<Json<DeletePasskeyStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();
    let passkey_props = app_state
        .services
        .passkeys
        .auth_passkey_step1(&jwt_access.sub, &operation_id)
        .await?;

    info!(trace_id = %trace_id, operation_id = %operation_id, "Passkey deletion confirmation started");
    Ok(Json(DeletePasskeyStep1Response {
        operation_id,
        credential_id: request.credential_id,
        passkey_props,
    }))
}

#[derive(Debug, Deserialize)]
pub struct DeletePasskeyStep1Request {
    pub credential_id: String,
}

#[derive(Debug, Serialize)]
pub struct DeletePasskeyStep1Response {
    pub operation_id: Uuid,
    pub credential_id: String,
    pub passkey_props: RequestChallengeResponse,
}
