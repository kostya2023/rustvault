use crate::{
    services::user_events::EventType,
    types::{app_state::AppState, errors::AppError},
};
use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

#[utoipa::path(
    post,
    path = "/v1/auth/login/with-passtotp/step2",
    tag = "Authentication",
    summary = "Complete password and TOTP login",
    request_body = crate::api_docs::LoginPasswordStep2Request,
    responses(
        (status = 200, description = "Token pair issued", body = crate::api_docs::TokenPairResponse),
        (status = 400, description = "Malformed password upload", body = crate::api_docs::ErrorBody),
        (status = 401, description = "Invalid password or TOTP code", body = crate::api_docs::ErrorBody),
        (status = 422, description = "Login operation expired or was not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn auth_login_with_passtotp_step2(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Json(request): Json<AuthLoginWithPasstotpStep2Request>,
) -> Result<Json<AuthLoginWithPasstotpStep2Response>, AppError> {
    let attempted_username = app_state
        .services
        .password
        .get_auth_login_username(&request.operation_id)
        .await?;
    let username = match app_state
        .services
        .password
        .auth_login_password_step2(&request.password_upload, &request.operation_id)
        .await
    {
        Ok(username) => username,
        Err(error) => {
            if let Some(username) = attempted_username {
                let error = app_state
                    .services
                    .user_events
                    .record_failure(
                        &username,
                        EventType::LoginFailedWithPasstotp,
                        &trace_id,
                        Some(&request.operation_id),
                        error,
                    )
                    .await;
                return Err(error);
            }
            return Err(error);
        }
    };

    if let Err(error) = app_state
        .services
        .totp
        .auth_login_totp(&username, &request.totp_code)
        .await
    {
        let error = app_state
            .services
            .user_events
            .record_failure(
                &username,
                EventType::LoginFailedWithPasstotp,
                &trace_id,
                Some(&request.operation_id),
                error,
            )
            .await;
        return Err(error);
    }

    let (access, refresh) = app_state.services.jwtokens.generate_pair(&username)?;

    app_state
        .services
        .user_events
        .record_event(
            &username,
            EventType::LoginWithPasstotp,
            &trace_id,
            Some(&request.operation_id),
        )
        .await?;

    info!(
        operation_id = %request.operation_id,
        trace_id = %trace_id,
        "Password authentication step 2 completed"
    );

    Ok(Json(AuthLoginWithPasstotpStep2Response {
        username,
        access_token: access,
        refresh_token: refresh,
        access_token_ttl: app_state.resources.jwt_access_token_ttl,
        refresh_token_ttl: app_state.resources.jwt_refresh_token_ttl,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthLoginWithPasstotpStep2Request {
    pub password_upload: String,
    pub totp_code: String,
    pub operation_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthLoginWithPasstotpStep2Response {
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_ttl: u64,
    pub refresh_token_ttl: u64,
}
