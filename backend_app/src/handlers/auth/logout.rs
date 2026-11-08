use crate::{
    services::{jwtokens::JWTAccessToken, user_events::EventType},
    types::{app_state::AppState, errors::AppError},
};
use axum::{Extension, extract::State, http::StatusCode};
use std::sync::Arc;
use uuid::Uuid;

#[utoipa::path(
    delete,
    path = "/v1/auth/logout",
    tag = "Authentication",
    summary = "Log out and revoke the current token pair",
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Token pair revoked"),
        (status = 401, description = "Missing, expired, or revoked access token", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn auth_logout(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_access): Extension<JWTAccessToken>,
) -> Result<StatusCode, AppError> {
    let username = jwt_access.sub.clone();
    app_state
        .services
        .jwtokens
        .revoke_pair_access(jwt_access)
        .await?;
    app_state
        .services
        .user_events
        .record_event(&username, EventType::Logout, &trace_id, None)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
