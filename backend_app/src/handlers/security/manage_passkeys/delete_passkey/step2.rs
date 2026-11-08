use std::sync::Arc;

use axum::{Extension, Json, extract::State, http::StatusCode};
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;
use webauthn_rs::prelude::PublicKeyCredential;

use crate::{
    services::{jwtokens::JWTAccessToken, user_events::EventType},
    types::{
        app_state::AppState,
        errors::{AppError, BadRequestKind, InternalKind},
    },
};

#[utoipa::path(
    delete,
    path = "/v1/security/manage-passkeys/delete/step2",
    tag = "Security",
    summary = "Confirm passkey deletion",
    request_body = crate::api_docs::DeletePasskeyStep2Request,
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Passkey deleted"),
        (status = 400, description = "Credential ID is not a valid hex string", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Access token or passkey assertion rejected", body = crate::api_docs::ErrorBody),
        (status = 404, description = "Passkey not found", body = crate::api_docs::ErrorBody),
        (status = 422, description = "Confirmation operation expired or was not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database or WebAuthn error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn delete_passkey_step2(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<DeletePasskeyStep2Request>,
) -> Result<StatusCode, AppError> {
    let credential_id = decode_hex(&request.credential_id)?;
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
    app_state
        .services
        .passkeys
        .delete_passkey(username, &credential_id, &mut tx)
        .await?;
    app_state
        .services
        .user_events
        .create_event(
            username,
            EventType::SudoPasskeyDeletedWithPassword,
            None,
            None,
            None,
            Some(&trace_id),
            Some(&request.operation_id),
            &mut tx,
        )
        .await?;
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

    info!(trace_id = %trace_id, operation_id = %request.operation_id, "Passkey deleted");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct DeletePasskeyStep2Request {
    pub operation_id: Uuid,
    pub credential_id: String,
    pub passkey_props: PublicKeyCredential,
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AppError> {
    if value.is_empty() || value.len() % 2 != 0 {
        return Err(AppError::BadRequest(BadRequestKind::InvalidCredentialId));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16);
            let low = (pair[1] as char).to_digit(16);
            match (high, low) {
                (Some(high), Some(low)) => Ok(((high << 4) | low) as u8),
                _ => Err(AppError::BadRequest(BadRequestKind::InvalidCredentialId)),
            }
        })
        .collect()
}
