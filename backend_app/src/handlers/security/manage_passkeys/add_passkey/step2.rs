use std::sync::Arc;

use axum::{Extension, Json, extract::State, http::StatusCode};
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::{
    services::{jwtokens::JWTAccessToken, user_events::EventType},
    types::{
        app_state::AppState,
        errors::{AppError, InternalKind},
    },
};

#[utoipa::path(
    post,
    path = "/v1/security/manage-passkeys/add/step2",
    tag = "Security",
    summary = "Complete passkey registration",
    request_body = crate::api_docs::AddPasskeyStep2Request,
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Passkey registered"),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 422, description = "Registration operation expired or credential was rejected", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database or WebAuthn error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn add_passkey_step2(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<AddPasskeyStep2Request>,
) -> Result<StatusCode, AppError> {
    let mut tx = app_state
        .resources
        .database
        .begin()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;
    let username = app_state
        .services
        .passkeys
        .register_passkey_step2(
            &request.operation_id,
            &request.passkey_props,
            &request.keyname,
            &mut tx,
        )
        .await?;
    if username != jwt_access.sub {
        return Err(AppError::Forbidden(
            crate::types::errors::ForbiddenKind::ForeignPasskeyAuth,
        ));
    }
    app_state
        .services
        .user_events
        .create_event(
            &jwt_access.sub,
            EventType::SudoPasskeyRegisteredWithPassword,
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

    info!(trace_id = %trace_id, operation_id = %request.operation_id, "Passkey registered");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct AddPasskeyStep2Request {
    pub operation_id: Uuid,
    pub keyname: String,
    pub passkey_props: RegisterPublicKeyCredential,
}
