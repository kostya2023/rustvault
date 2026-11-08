use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::Serialize;
use sqlx::FromRow;
use time::OffsetDateTime;
use tracing::info;
use uuid::Uuid;

use crate::{
    services::jwtokens::JWTAccessToken,
    types::{
        app_state::AppState,
        errors::{AppError, InternalKind, NotFoundKind},
    },
};

#[utoipa::path(
    get,
    path = "/v1/account",
    tag = "Account",
    summary = "Get current account information",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current account", body = crate::api_docs::AccountResponse),
        (status = 401, description = "Missing, expired, or revoked access token", body = crate::api_docs::ErrorBody),
        (status = 404, description = "Account not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn get_account_info(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
) -> Result<Json<AccountInfo>, AppError> {
    let account = sqlx::query_as::<_, AccountInfo>(
        "SELECT username, created_at FROM users WHERE username = $1",
    )
    .bind(&jwt_access.sub)
    .fetch_optional(&app_state.resources.database)
    .await
    .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?
    .ok_or_else(|| AppError::NotFound(NotFoundKind::UserNotFound))?;

    info!(trace_id = %trace_id, "Account information retrieved");
    Ok(Json(account))
}

#[derive(Debug, Serialize, FromRow)]
pub struct AccountInfo {
    pub username: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
