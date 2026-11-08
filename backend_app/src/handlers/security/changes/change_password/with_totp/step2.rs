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
    path = "/v1/security/changes/change-password/with-totp/step2",
    tag = "Security",
    summary = "Confirm password change with current password and TOTP",
    request_body = crate::api_docs::ChangePasswordTotpStep2Request,
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Password changed"),
        (status = 400, description = "Malformed OPAQUE response", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Password, TOTP, or access token rejected", body = crate::api_docs::ErrorBody),
        (status = 422, description = "Operation expired or was not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database or cache error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn change_password_with_totp_step2(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<ChangePasswordStep2Request>,
) -> Result<StatusCode, AppError> {
    let username = &jwt_access.sub;
    app_state
        .services
        .password
        .auth_password_step2(
            username,
            &request.current_password_upload,
            &request.operation_id,
        )
        .await?;
    app_state
        .services
        .totp
        .auth_login_totp(username, &request.totp_code)
        .await?;

    let mut tx = app_state
        .resources
        .database
        .begin()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;
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
            EventType::SudoPasswordUpdatedWithTotp,
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

    info!(trace_id = %trace_id, operation_id = %request.operation_id, "Password changed with TOTP");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordStep2Request {
    pub operation_id: Uuid,
    pub current_password_upload: String,
    pub new_password_upload: String,
    pub totp_code: String,
}
