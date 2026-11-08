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
        errors::{AppError, InternalKind},
    },
};

#[utoipa::path(
    get,
    path = "/v1/security/passkeys",
    tag = "Security",
    summary = "List current account passkeys",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Registered passkeys ordered by creation time", body = [crate::api_docs::PasskeyInfo]),
        (status = 401, description = "Missing, expired, or revoked access token", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn get_passkeys(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
) -> Result<Json<Vec<PasskeyInfo>>, AppError> {
    let passkeys = sqlx::query_as::<_, PasskeyInfo>(
        "SELECT encode(credential_id, 'hex') AS credential_id, keyname, created_at, last_used_at
         FROM user_passkeys WHERE username = $1 ORDER BY created_at",
    )
    .bind(&jwt_access.sub)
    .fetch_all(&app_state.resources.database)
    .await
    .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

    info!(trace_id = %trace_id, "Passkeys retrieved");
    Ok(Json(passkeys))
}

#[derive(Debug, Serialize, FromRow)]
pub struct PasskeyInfo {
    pub credential_id: String,
    pub keyname: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_used_at: OffsetDateTime,
}
