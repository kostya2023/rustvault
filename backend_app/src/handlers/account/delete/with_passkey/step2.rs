use std::sync::Arc;

use axum::{Extension, Json, extract::State, http::StatusCode};
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;
use webauthn_rs::prelude::PublicKeyCredential;

use crate::{
    services::jwtokens::JWTAccessToken,
    types::{
        app_state::AppState,
        errors::{AppError, InternalKind},
    },
};

#[utoipa::path(
    delete,
    path = "/v1/account/delete/with-passkey/step2",
    tag = "Account",
    summary = "Confirm account deletion using a passkey",
    request_body = crate::api_docs::DeletePasskeyConfirmation,
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Account, related records, and vault deleted"),
        (status = 401, description = "Access token or passkey assertion rejected", body = crate::api_docs::ErrorBody),
        (status = 422, description = "Confirmation operation expired or was not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database or object-storage error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn delete_account_with_passkey_step2(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<DeleteAccountStep2Request>,
) -> Result<StatusCode, AppError> {
    let username = &jwt_access.sub;
    let mut tx = app_state
        .resources
        .database
        .begin()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;
    app_state
        .services
        .passkeys
        .auth_passkey_step2(
            &request.operation_id,
            username,
            &request.passkey_props,
            &mut tx,
        )
        .await?;
    app_state.services.blob.delete_blob(username).await?;
    app_state
        .services
        .account
        .delete_user_cascade(username, &mut tx)
        .await?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;
    app_state
        .services
        .jwtokens
        .revoke_pair_access(jwt_access)
        .await?;

    info!(trace_id = %trace_id, operation_id = %request.operation_id, "Account deleted with passkey");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountStep2Request {
    pub operation_id: Uuid,
    pub passkey_props: PublicKeyCredential,
}
