use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::{
    services::jwtokens::JWTAccessToken,
    types::{
        app_state::AppState,
        errors::{AppError, InternalKind, REQUEST_ERROR_CONTEXT, UnauthorizedKind},
    },
};

pub async fn auth_access_middleware(
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
                "Missing Bearer access token.".to_owned(),
            ))
        })?;

    let jwt_access: JWTAccessToken = app_state.services.jwtokens.parse_access(token).await?;
    REQUEST_ERROR_CONTEXT
        .try_with(|context| context.set_username(jwt_access.sub.clone()))
        .map_err(|_| {
            AppError::Internal(InternalKind::InitError(
                "Request context was not initialized by the logging middleware.".to_owned(),
            ))
        })?;
    request.extensions_mut().insert(jwt_access);

    Ok(next.run(request).await)
}
