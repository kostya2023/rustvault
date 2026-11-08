use std::time::Instant;

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, header::CONTENT_LENGTH},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::{Instrument, field, info, info_span};
use uuid::Uuid;

use crate::types::errors::{
    AppError, ErrorDetail, ErrorResponse, REQUEST_ERROR_CONTEXT, RequestErrorContext,
};
use crate::{services::user_events::EventType, types::app_state::AppState};

pub async fn logging_middleware(
    State(app_state): State<std::sync::Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let start = Instant::now();
    let trace_id = Uuid::new_v4();

    // Own the values so they remain available after request is moved.
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let version = request.version();
    let real_ip = get_header(request.headers(), "X-Real-IP").to_owned();
    let user_agent = get_header(request.headers(), "User-Agent").to_owned();

    // Make trace_id available to downstream handlers.
    request.extensions_mut().insert(trace_id);

    let request_trace_id = trace_id;
    let trace_id = request_trace_id.to_string();

    let span = info_span!(
        "http.request",
        http.method = %method,
        http.path = %path,
        http.version = ?version,
        http.user_agent = %user_agent,
        http.real_ip = %real_ip,
        trace_id = %trace_id,
        http.status = field::Empty,
        latency_ms = field::Empty,
        response.length = field::Empty,
    );
    let request_context = RequestErrorContext::new(request_trace_id);
    request_context.set_request_metadata(real_ip.parse().ok(), user_agent.clone());

    async move {
        REQUEST_ERROR_CONTEXT
            .scope(request_context, async move {
                let mut response = next.run(request).await;

                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                let status = response.status();

                if status.is_client_error() || status.is_server_error() {
                    if let Some(event_type) = failed_event_for_path(&path) {
                        let username = REQUEST_ERROR_CONTEXT
                            .try_with(|context| context.username.borrow().clone())
                            .ok()
                            .flatten();
                        if let Some(username) = username {
                            if let Err(error) = app_state
                                .services
                                .user_events
                                .record_event(&username, event_type, &request_trace_id, None)
                                .await
                            {
                                tracing::error!(
                                    trace_id = %trace_id,
                                    username,
                                    error = ?error,
                                    "Failed to persist failed-action user event"
                                );
                            }
                        }
                    }

                    let app_error_logged = REQUEST_ERROR_CONTEXT
                        .try_with(|context| context.app_error_logged.get())
                        .unwrap_or(false);

                    if !app_error_logged {
                        let (code, text) = generic_error_for_status(status);
                        let envelope = ErrorResponse {
                            error: ErrorDetail { code, text },
                            trace_id: request_trace_id,
                        };

                        if status.is_server_error() {
                            tracing::error!(
                                trace_id = %trace_id,
                                error_code = code,
                                status = status.as_u16(),
                                "HTTP request failed"
                            );
                        } else {
                            tracing::warn!(
                                trace_id = %trace_id,
                                error_code = code,
                                status = status.as_u16(),
                                "HTTP request rejected"
                            );
                        }

                        response = (status, Json(envelope)).into_response();
                    }
                }

                let response_length = response
                    .headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok());

                // Record fields in the current span for tracing diagnostics.
                let current_span = tracing::Span::current();

                current_span.record("http.status", status.as_u16());
                current_span.record("latency_ms", latency_ms);

                if let Some(length) = response_length {
                    current_span.record("response.length", length);
                }

                // Pass the fields directly to the event. The custom formatter
                // will print every field on its own line.
                if let Some(length) = response_length {
                    info!(
                        http.method = %method,
                        http.path = %path,
                        http.version = ?version,
                        http.user_agent = %user_agent,
                        http.real_ip = %real_ip,
                        trace_id = %trace_id,
                        http.status = status.as_u16(),
                        latency_ms = %format!("{latency_ms:.4}"),
                        response.length = length,
                        "Request finished!"
                    );
                } else {
                    info!(
                        http.method = %method,
                        http.path = %path,
                        http.version = ?version,
                        http.user_agent = %user_agent,
                        http.real_ip = %real_ip,
                        trace_id = %trace_id,
                        http.status = status.as_u16(),
                        latency_ms = %format!("{latency_ms:.4}"),
                        "Request finished!"
                    );
                }

                Ok(response)
            })
            .await
    }
    .instrument(span)
    .await
}

fn failed_event_for_path(path: &str) -> Option<EventType> {
    match path {
        "/v1/account/delete/with-passkey/step2" => {
            Some(EventType::SudoAccountDeleteFailedWithPasskey)
        }
        "/v1/account/delete/with-passtotp/step2" => {
            Some(EventType::SudoAccountDeleteFailedWithPasstotp)
        }
        "/v1/security/changes/change-password/with-passkey/step2" => {
            Some(EventType::SudoPasswordUpdateFailedWithPasskey)
        }
        "/v1/security/changes/change-password/with-totp/step2" => {
            Some(EventType::SudoPasswordUpdateFailedWithTotp)
        }
        "/v1/security/changes/change-totp/with-passkey/step2" => {
            Some(EventType::SudoTotpUpdateFailedWithPasskey)
        }
        "/v1/security/changes/change-totp/with-password/step2" => {
            Some(EventType::SudoTotpUpdateFailedWithPassword)
        }
        "/v1/security/manage-passkeys/add/step2" => {
            Some(EventType::SudoPasskeyRegisterFailedWithPassword)
        }
        "/v1/security/manage-passkeys/delete/step2" => {
            Some(EventType::SudoPasskeyDeleteFailedWithPassword)
        }
        _ => None,
    }
}

fn generic_error_for_status(status: axum::http::StatusCode) -> (&'static str, &'static str) {
    match status {
        axum::http::StatusCode::BAD_REQUEST => (
            "INVALID_REQUEST",
            "The request is invalid. Check the submitted fields and try again.",
        ),
        axum::http::StatusCode::UNAUTHORIZED => (
            "AUTHENTICATION_FAILED",
            "Authentication failed. Check your credentials and try again.",
        ),
        axum::http::StatusCode::FORBIDDEN => (
            "ACCESS_FORBIDDEN",
            "You are not allowed to perform this action.",
        ),
        axum::http::StatusCode::NOT_FOUND => (
            "RESOURCE_NOT_FOUND",
            "The requested resource was not found.",
        ),
        axum::http::StatusCode::PAYLOAD_TOO_LARGE => {
            ("PAYLOAD_TOO_LARGE", "The request exceeds the allowed size.")
        }
        axum::http::StatusCode::UNPROCESSABLE_ENTITY => (
            "REQUEST_UNPROCESSABLE",
            "The request could not be processed. Check the current resource state.",
        ),
        axum::http::StatusCode::CONFLICT => (
            "RESOURCE_CONFLICT",
            "The request conflicts with the current account state.",
        ),
        _ if status.is_server_error() => (
            "INTERNAL_SERVER_ERROR",
            "An unexpected error occurred. Please try again later.",
        ),
        _ => ("REQUEST_REJECTED", "The request could not be completed."),
    }
}

fn get_header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
}

#[cfg(test)]
mod tests {
    use super::failed_event_for_path;
    use crate::services::user_events::EventType;

    #[test]
    fn maps_sensitive_action_failures_to_user_events() {
        assert_eq!(
            failed_event_for_path("/v1/account/delete/with-passkey/step2"),
            Some(EventType::SudoAccountDeleteFailedWithPasskey)
        );
        assert_eq!(
            failed_event_for_path("/v1/security/changes/change-password/with-totp/step2"),
            Some(EventType::SudoPasswordUpdateFailedWithTotp)
        );
        assert_eq!(
            failed_event_for_path("/v1/security/manage-passkeys/delete/step2"),
            Some(EventType::SudoPasskeyDeleteFailedWithPassword)
        );
        assert_eq!(failed_event_for_path("/v1/security/passkeys"), None);
    }
}
