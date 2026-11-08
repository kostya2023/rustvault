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
        errors::{AppError, InternalKind},
    },
};

#[utoipa::path(
    put,
    path = "/v1/security/changes/change-password/with-passkey/step2",
    tag = "Security",
    summary = "Confirm password change with passkey",
    request_body = crate::api_docs::ChangePasswordPasskeyStep2Request,
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Password changed"),
        (status = 400, description = "Malformed OPAQUE or WebAuthn response", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Access token or passkey assertion rejected", body = crate::api_docs::ErrorBody),
        (status = 422, description = "Operation expired or was not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database or cache error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn change_password_with_passkey_step2(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<ChangePasswordStep2Request>,
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
    let updated_username = app_state
        .services
        .password
        .update_password_step2(&request.operation_id, &request.new_password_upload, &mut tx)
        .await?;
    if updated_username != *username {
        return Err(AppError::Forbidden(
            crate::types::errors::ForbiddenKind::ForeignPasswordAuth,
        ));
    }
    app_state
        .services
        .user_events
        .create_event(
            username,
            EventType::SudoPasswordUpdatedWithPasskey,
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

    info!(trace_id = %trace_id, operation_id = %request.operation_id, "Password changed with passkey");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordStep2Request {
    pub operation_id: Uuid,
    pub passkey_props: PublicKeyCredential,
    pub new_password_upload: String,
}
