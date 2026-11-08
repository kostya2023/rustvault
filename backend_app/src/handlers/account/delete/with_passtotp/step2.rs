use std::sync::Arc;

use axum::{Extension, Json, extract::State, http::StatusCode};
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;

use crate::{
    services::jwtokens::JWTAccessToken,
    types::{
        app_state::AppState,
        errors::{AppError, InternalKind},
    },
};

#[utoipa::path(
    delete,
    path = "/v1/account/delete/with-passtotp/step2",
    tag = "Account",
    summary = "Confirm account deletion using password and TOTP",
    request_body = crate::api_docs::DeletePasswordTotpConfirmation,
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Account, related records, and vault deleted"),
        (status = 401, description = "Password, TOTP, or access token rejected", body = crate::api_docs::ErrorBody),
        (status = 422, description = "Confirmation operation expired or was not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database or object-storage error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn delete_account_with_passtotp_step2(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Json(request): Json<DeleteAccountStep2Request>,
) -> Result<StatusCode, AppError> {
    let username = &jwt_access.sub;
    app_state
        .services
        .password
        .auth_password_step2(username, &request.password_upload, &request.operation_id)
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

    info!(trace_id = %trace_id, operation_id = %request.operation_id, "Account deleted with password and TOTP");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountStep2Request {
    pub operation_id: Uuid,
    pub password_upload: String,
    pub totp_code: String,
}
