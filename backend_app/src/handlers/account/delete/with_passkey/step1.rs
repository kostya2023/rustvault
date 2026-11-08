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
    path = "/v1/account/delete/with-passkey/step1",
    tag = "Account",
    summary = "Begin account deletion using a passkey",
    description = "Returns WebAuthn assertion options. Complete the challenge using DELETE step 2.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Passkey assertion options and operation ID", body = crate::api_docs::PasskeyChallengeResponse),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 404, description = "No passkey found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn delete_account_with_passkey_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
) -> Result<Json<DeleteAccountStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();
    let passkey_props = app_state
        .services
        .passkeys
        .auth_passkey_step1(&jwt_access.sub, &operation_id)
        .await?;

    info!(trace_id = %trace_id, operation_id = %operation_id, "Account deletion confirmation started");
    Ok(Json(DeleteAccountStep1Response {
        operation_id,
        passkey_props,
    }))
}

#[derive(Debug, Serialize)]
pub struct DeleteAccountStep1Response {
    pub operation_id: Uuid,
    pub passkey_props: RequestChallengeResponse,
}
