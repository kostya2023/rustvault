use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::Serialize;
use tracing::info;
use uuid::Uuid;

use crate::{
    services::{jwtokens::JWTRefreshToken, user_events::EventType},
    types::{app_state::AppState, errors::AppError},
};

#[utoipa::path(
    post,
    path = "/v1/auth/refresh",
    tag = "Authentication",
    summary = "Rotate access and refresh tokens",
    description = "Requires the current refresh token in the Bearer authorization header. The old token pair is revoked.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "New token pair", body = crate::api_docs::TokenPairResponse),
        (status = 401, description = "Missing, expired, or revoked refresh token", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn auth_refresh_tokens(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Extension(jwt_refresh): Extension<JWTRefreshToken>,
) -> Result<Json<AuthRefreshTokensResponse>, AppError> {
    let username = jwt_refresh.sub.clone();
    let (access_token, refresh_token) = app_state.services.jwtokens.generate_pair(&username)?;

    app_state
        .services
        .jwtokens
        .revoke_pair_refresh(jwt_refresh)
        .await?;
    app_state
        .services
        .user_events
        .record_event(&username, EventType::TokenRefresh, &trace_id, None)
        .await?;

    info!(trace_id = %trace_id, "JWT token pair refreshed");

    Ok(Json(AuthRefreshTokensResponse {
        username,
        access_token,
        refresh_token,
        access_token_ttl: app_state.resources.jwt_access_token_ttl,
        refresh_token_ttl: app_state.resources.jwt_refresh_token_ttl,
    }))
}

#[derive(Debug, Serialize)]
pub struct AuthRefreshTokensResponse {
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_ttl: u64,
    pub refresh_token_ttl: u64,
}
