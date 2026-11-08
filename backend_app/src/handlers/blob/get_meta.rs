use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use tracing::info;
use uuid::Uuid;

use crate::{
    services::{blob::BlobMetadata, jwtokens::JWTAccessToken, user_events::EventType},
    types::{app_state::AppState, errors::AppError},
};

#[utoipa::path(
    get,
    path = "/v1/blob/meta",
    tag = "Vault",
    summary = "Get encrypted vault metadata",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Metadata for the authenticated user's vault", body = crate::api_docs::BlobMetadata),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 404, description = "Vault metadata not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn get_meta(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
) -> Result<Json<BlobMetadata>, AppError> {
    let metadata = app_state.services.blob.get_meta(&jwt_access.sub).await?;
    app_state
        .services
        .user_events
        .record_event(&jwt_access.sub, EventType::BlobAccessed, &trace_id, None)
        .await?;

    info!(trace_id = %trace_id, "Blob metadata retrieved");

    Ok(Json(metadata))
}
