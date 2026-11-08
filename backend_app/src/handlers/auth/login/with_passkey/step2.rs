use crate::{
    services::user_events::EventType,
    types::{
        app_state::AppState,
        errors::{AppError, InternalKind},
    },
};
use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;
use webauthn_rs::prelude::PublicKeyCredential;

#[utoipa::path(
    post,
    path = "/v1/auth/login/with-passkey/step2",
    tag = "Authentication",
    summary = "Complete passkey login",
    request_body = crate::api_docs::LoginPasskeyStep2Request,
    responses(
        (status = 200, description = "Token pair issued", body = crate::api_docs::TokenPairResponse),
        (status = 401, description = "Passkey assertion rejected", body = crate::api_docs::ErrorBody),
        (status = 422, description = "Login operation expired or was not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn auth_login_with_passkey_step2(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Json(request): Json<AuthLoginWithPasskeyStep2Request>,
) -> Result<Json<AuthLoginWithPasskeyStep2Response>, AppError> {
    let attempted_username = app_state
        .services
        .passkeys
        .get_auth_login_username(&request.operation_id)
        .await?;
    let mut tx = app_state
        .resources
        .database
        .begin()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

    let username = match app_state
        .services
        .passkeys
        .auth_login_passkey_step2(&request.operation_id, &request.passkey_props, &mut tx)
        .await
    {
        Ok(username) => username,
        Err(error) => {
            drop(tx);
            if let Some(username) = attempted_username {
                let error = app_state
                    .services
                    .user_events
                    .record_failure(
                        &username,
                        EventType::LoginFailedWithPasskey,
                        &trace_id,
                        Some(&request.operation_id),
                        error,
                    )
                    .await;
                return Err(error);
            }
            return Err(error);
        }
    };

    let (access, refresh) = app_state.services.jwtokens.generate_pair(&username)?;

    app_state
        .services
        .user_events
        .create_event(
            &username,
            EventType::LoginWithPasskey,
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

    info!(
        operation_id = %request.operation_id,
        trace_id = %trace_id,
        "Passkey authentication step 2 completed"
    );

    Ok(Json(AuthLoginWithPasskeyStep2Response {
        username,
        access_token: access,
        refresh_token: refresh,
        access_token_ttl: app_state.resources.jwt_access_token_ttl,
        refresh_token_ttl: app_state.resources.jwt_refresh_token_ttl,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthLoginWithPasskeyStep2Request {
    pub passkey_props: PublicKeyCredential,
    pub operation_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthLoginWithPasskeyStep2Response {
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_ttl: u64,
    pub refresh_token_ttl: u64,
}
