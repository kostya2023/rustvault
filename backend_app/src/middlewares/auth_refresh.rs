use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::{
    services::jwtokens::JWTRefreshToken,
    types::{
        app_state::AppState,
        errors::{AppError, UnauthorizedKind},
    },
};

pub async fn auth_refresh_middleware(
    State(app_state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::Unauthorized(UnauthorizedKind::JWTokenError(
                "Missing Bearer refresh token.".to_owned(),
            ))
        })?;

    let jwt_refresh: JWTRefreshToken = app_state.services.jwtokens.parse_refresh(token).await?;
    request.extensions_mut().insert(jwt_refresh);

    Ok(next.run(request).await)
}
