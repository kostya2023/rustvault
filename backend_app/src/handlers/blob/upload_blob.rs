use std::sync::Arc;

use axum::{
    Extension,
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
};
use tracing::info;
use uuid::Uuid;

use crate::services::{jwtokens::JWTAccessToken, user_events::EventType};
use crate::types::{
    app_state::AppState,
    errors::{AppError, BadRequestKind, InternalKind},
};

#[utoipa::path(
    put,
    path = "/v1/blob",
    tag = "Vault",
    summary = "Upload or replace encrypted vault",
    description = "Sends the raw binary encrypted vault, not JSON. Version must strictly exceed the stored version. Maximum body size is configured by the server.",
    params(
        ("X-Blob-Version" = i64, Header, description = "New monotonically increasing vault version", example = 2)
    ),
    request_body(content = crate::api_docs::BinaryBlob, content_type = "application/octet-stream", description = "Raw encrypted vault bytes"),
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Vault and metadata stored"),
        (status = 400, description = "Missing or invalid X-Blob-Version header", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 413, description = "Payload exceeds configured maximum body size", body = crate::api_docs::ErrorBody),
        (status = 422, description = "Version is not greater than the stored version", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database or object-storage error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn upload_blob(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    request: Request,
) -> Result<StatusCode, AppError> {
    let version = request
        .headers()
        .get("X-Blob-Version")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|version| *version >= 0)
        .ok_or(AppError::BadRequest(
            BadRequestKind::MissingOrInvalidBlobVersion,
        ))?;

    let body_limit = usize::try_from(app_state.resources.blob_max_size)
        .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;
    let blob = to_bytes(request.into_body(), body_limit)
        .await
        .map_err(|_| AppError::BadRequest(BadRequestKind::PayloadTooLarge))?;

    let mut tx = app_state
        .resources
        .database
        .begin()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

    let blob_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_blob WHERE username = $1)")
            .bind(&jwt_access.sub)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

    app_state
        .services
        .blob
        .update_blob(&jwt_access.sub, &blob, version, &mut tx)
        .await?;

    app_state
        .services
        .user_events
        .create_event(
            &jwt_access.sub,
            if blob_exists {
                EventType::BlobUpdated
            } else {
                EventType::BlobCreated
            },
            None,
            None,
            None,
            Some(&trace_id),
            None,
            &mut tx,
        )
        .await?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

    info!(trace_id = %trace_id, version, "Blob uploaded");

    Ok(StatusCode::NO_CONTENT)
}
