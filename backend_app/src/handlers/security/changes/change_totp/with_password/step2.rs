use std::sync::Arc;

use axum::{Extension, Json, extract::State, http::StatusCode};
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;

use crate::{
    services::jwtokens::JWTAccessToken,
    services::user_events::EventType,
    types::{
        app_state::AppState,
        errors::{AppError, InternalKind},
    },
};

#[utoipa::path(
    put,
    path = "/v1/security/changes/change-totp/with-password/step2",
    tag = "Security",
    summary = "Confirm TOTP replacement with current password",
    request_body = crate::api_docs::ChangeTotpPasswordStep2Request,
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "TOTP secret replaced"),
        (status = 400, description = "Malformed password response", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Password, TOTP code, or access token rejected", body = crate::api_docs::ErrorBody),
        (status = 422, description = "Operation expired or was not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database or cache error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn change_totp_with_password_step2(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<ChangeTotpStep2Request>,
) -> Result<StatusCode, AppError> {
    let username = &jwt_access.sub;
    app_state
        .services
        .password
        .auth_password_step2(username, &request.password_upload, &request.operation_id)
        .await?;

    let mut tx = app_state
        .resources
        .database
        .begin()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;
    app_state
        .services
        .totp
        .update_totp_step2(&request.operation_id, &request.totp_code, username, &mut tx)
        .await?;
    app_state
        .services
        .user_events
        .create_event(
            username,
            EventType::SudoTotpUpdatedWithPassword,
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

    info!(trace_id = %trace_id, operation_id = %request.operation_id, "TOTP changed with password");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ChangeTotpStep2Request {
    pub operation_id: Uuid,
    pub password_upload: String,
    pub totp_code: String,
}
