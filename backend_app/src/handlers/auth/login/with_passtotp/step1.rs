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
    path = "/v1/auth/login/with-passtotp/step1",
    tag = "Authentication",
    summary = "Begin password and TOTP login",
    request_body = crate::api_docs::LoginPasswordStep1Request,
    responses(
        (status = 200, description = "OPAQUE challenge", body = crate::api_docs::LoginPasswordStep1Response),
        (status = 400, description = "Malformed login request", body = crate::api_docs::ErrorBody),
        (status = 404, description = "Account or password credential not found", body = crate::api_docs::ErrorBody),
        (status = 500, description = "Internal service error", body = crate::api_docs::ErrorBody)
    )
)]
pub async fn auth_login_with_passtotp_step1(
    State(app_state): State<Arc<AppState>>,
    Extension(trace_id): Extension<Uuid>,
    Json(request): Json<AuthLoginWithPasstotpStep1Request>,
) -> Result<Json<AuthLoginWithPasstotpStep1Response>, AppError> {
    let operation_id = Uuid::new_v4();

    let password_response = match app_state
        .services
        .password
        .auth_login_password_step1(&request.username, &request.password_request, &operation_id)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            if app_state
                .services
                .account
                .check_user_exists(&request.username)
                .await?
            {
                let error = app_state
                    .services
                    .user_events
                    .record_failure(
                        &request.username,
                        EventType::LoginFailedWithPasstotp,
                        &trace_id,
                        Some(&operation_id),
                        error,
                    )
                    .await;
                return Err(error);
            }
            return Err(error);
        }
    };

    info!(
        operation_id = %operation_id,
        trace_id = %trace_id,
        "Password authentication step 1 completed"
    );

    Ok(Json(AuthLoginWithPasstotpStep1Response {
        password_response,
        operation_id,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthLoginWithPasstotpStep1Request {
    pub username: String,
    pub password_request: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthLoginWithPasstotpStep1Response {
    pub password_response: String,
    pub operation_id: Uuid,
}
