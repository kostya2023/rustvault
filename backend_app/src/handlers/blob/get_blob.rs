use std::sync::Arc;

use axum::{
    Extension,
    body::Body,
    extract::State,
    http::{Response, header, header::HeaderValue},
};
use tracing::info;
use uuid::Uuid;

use crate::{
    services::{jwtokens::JWTAccessToken, user_events::EventType},
    types::{app_state::AppState, errors::AppError},
};

#[utoipa::path(
    get,
    path = "/v1/blob",
    tag = "Vault",
    summary = "Download encrypted vault",
    description = "Returns the exact binary vault payload as `application/octet-stream`. The payload is client-side encrypted.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Encrypted vault bytes", content_type = "application/octet-stream", body = crate::api_docs::BinaryBlob),
        (status = 401, description = "Access token rejected", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Object-storage error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn get_blob(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
) -> Result<Response<Body>, AppError> {
    let blob = app_state.services.blob.get_blob(&jwt_access.sub).await?;
    app_state
        .services
        .user_events
        .record_event(&jwt_access.sub, EventType::BlobAccessed, &trace_id, None)
        .await?;

    info!(trace_id = %trace_id, "Blob retrieved");

    let mut response = Response::new(Body::from(blob));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(response)
}
