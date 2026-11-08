use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::{
    services::{jwtokens::JWTAccessToken, user_events::UserEvent},
    types::{
        app_state::AppState,
        errors::{AppError, BadRequestKind},
    },
};

#[utoipa::path(
    get,
    path = "/v1/security/events",
    tag = "Security",
    summary = "List current account security events",
    description = "Events are returned newest-first. The endpoint only returns events belonging to the authenticated user.",
    params(
        ("limit" = Option<i64>, Query, description = "Page size, 1-100; defaults to 50", example = 50),
        ("offset" = Option<i64>, Query, description = "Number of newest events to skip; defaults to 0", example = 0)
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Page of security events", body = crate::api_docs::SecurityEventsResponse),
        (status = 400, description = "Invalid limit or offset", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Missing, expired, or revoked access token", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Database error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn get_security_events(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
    Query(query): Query<GetEventsQuery>,
) -> Result<Json<GetEventsResponse>, AppError> {
    if !(1..=100).contains(&query.limit) || query.offset < 0 {
        return Err(AppError::BadRequest(BadRequestKind::InvalidPagination));
    }

    let events = app_state
        .services
        .user_events
        .get_events(&jwt_access.sub, query.limit, query.offset)
        .await?;

    info!(trace_id = %trace_id, "Security events retrieved");
    Ok(Json(GetEventsResponse { events }))
}

#[derive(Debug, Deserialize)]
pub struct GetEventsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
pub struct GetEventsResponse {
    pub events: Vec<UserEvent>,
}
