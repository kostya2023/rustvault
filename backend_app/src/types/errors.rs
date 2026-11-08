use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::{cell::RefCell, net::IpAddr};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Internal(InternalKind),

    #[error(transparent)]
    Unauthorized(UnauthorizedKind),

    #[error(transparent)]
    BadRequest(BadRequestKind),

    #[error(transparent)]
    NotFound(NotFoundKind),

    #[error(transparent)]
    UnprocessableEntity(UnprocessableEntityKind),

    #[error(transparent)]
    Forbidden(ForbiddenKind),

    #[error(transparent)]
    Conflict(ConflictKind),
}

#[derive(Debug, thiserror::Error)]
pub enum InternalKind {
    #[error("Application initialization failed: {0}")]
    InitError(String),

    #[error("Database operation failed: {0}")]
    DatabaseError(String),

    #[error("Blob storage operation failed: {0}")]
    BlobError(String),

    #[error("System clock could not be read: {0}")]
    GetTimeError(String),

    #[error("Cache operation failed: {0}")]
    CacheError(String),

    #[error("JWT operation failed: {0}")]
    JWTokenError(String),

    #[error("WebAuthn operation failed: {0}")]
    WebauthnError(String),

    #[error("Serialization failed: {0}")]
    SerdeSerializeError(String),

    #[error("Deserialization failed: {0}")]
    SerdeDeserializeError(String),

    #[error("OPAQUE protocol operation failed: {0}")]
    OpaqueError(String),

    #[error("TOTP operation failed: {0}")]
    TotpError(String),
}

#[derive(Debug, thiserror::Error)]
pub enum UnauthorizedKind {
    #[error("Access or refresh token is missing, invalid, expired, or revoked: {0}")]
    JWTokenError(String),

    #[error("Passkey authentication failed: {0}")]
    LoginWithPasskeyError(String),

    #[error("Password authentication failed: {0}")]
    LoginWithPasswordError(String),

    #[error("TOTP verification failed: {0}")]
    VerifyTotpError(String),
}

#[derive(Debug, thiserror::Error)]
pub enum BadRequestKind {
    #[error("Base64 input is invalid: {0}")]
    DecodeBase64Error(String),

    #[error("Request contains an invalid OPAQUE payload: {0}")]
    DeserializeOpaqueStructError(String),

    #[error("Request body exceeds the configured maximum size.")]
    PayloadTooLarge,

    #[error("X-Blob-Version header is required and must be a non-negative integer.")]
    MissingOrInvalidBlobVersion,

    #[error("Pagination parameters are invalid.")]
    InvalidPagination,

    #[error("Passkey credential ID must be a non-empty hexadecimal string.")]
    InvalidCredentialId,
}

#[derive(Debug, thiserror::Error)]
pub enum NotFoundKind {
    #[error("No account or passkey matches the request.")]
    UserOrPasskeyNotFoundError,

    #[error("Password credentials were not found.")]
    UserOrOpaqueNotFoundError,

    #[error("TOTP credentials were not found.")]
    UserOrTotpNotFoundError,

    #[error("Security event was not found.")]
    UserEventNotFound,

    #[error("Account was not found.")]
    UserNotFound,

    #[error("Vault metadata was not found.")]
    BlobNotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum UnprocessableEntityKind {
    #[error("Blob size exceeds the configured maximum of {0} bytes; received {1} bytes.")]
    BlobVeryLargeError(i64, i64),

    #[error("Blob version must be greater than the stored version ({0}); received {1}.")]
    BlobVersionNotIncreasingError(i64, i64),

    #[error("The operation was not found or has expired.")]
    OperationNotFound,

    #[error("Passkey registration could not be completed: {0}")]
    PasskeyRegistrationError(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ForbiddenKind {
    #[error("Passkey operation belongs to a different account.")]
    ForeignPasskeyAuth,

    #[error("Password operation belongs to a different account.")]
    ForeignPasswordAuth,

    #[error("TOTP operation belongs to a different account.")]
    ForeignTotpAuth,
}

#[derive(Debug, thiserror::Error)]
pub enum ConflictKind {
    #[error("An account with this username already exists.")]
    UserAlreadyExists,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: &'static str,
    pub text: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
    pub trace_id: Uuid,
}

#[derive(Debug)]
pub struct RequestErrorContext {
    pub trace_id: Uuid,
    pub app_error_logged: std::cell::Cell<bool>,
    pub username: RefCell<Option<String>>,
    pub ip_address: RefCell<Option<IpAddr>>,
    pub user_agent: RefCell<Option<String>>,
}

impl RequestErrorContext {
    pub fn new(trace_id: Uuid) -> Self {
        Self {
            trace_id,
            app_error_logged: std::cell::Cell::new(false),
            username: RefCell::new(None),
            ip_address: RefCell::new(None),
            user_agent: RefCell::new(None),
        }
    }

    pub fn set_username(&self, username: String) {
        *self.username.borrow_mut() = Some(username);
    }

    pub fn set_request_metadata(&self, ip_address: Option<IpAddr>, user_agent: String) {
        *self.ip_address.borrow_mut() = ip_address;
        *self.user_agent.borrow_mut() = Some(user_agent);
    }
}

tokio::task_local! {
    pub static REQUEST_ERROR_CONTEXT: RequestErrorContext;
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::BadRequest(BadRequestKind::PayloadTooLarge) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Conflict(_) => StatusCode::CONFLICT,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Internal(_) => "INTERNAL_SERVER_ERROR",
            Self::Unauthorized(UnauthorizedKind::JWTokenError(_)) => "AUTH_TOKEN_INVALID",
            Self::Unauthorized(UnauthorizedKind::LoginWithPasskeyError(_)) => {
                "PASSKEY_AUTHENTICATION_FAILED"
            }
            Self::Unauthorized(UnauthorizedKind::LoginWithPasswordError(_)) => {
                "PASSWORD_AUTHENTICATION_FAILED"
            }
            Self::Unauthorized(UnauthorizedKind::VerifyTotpError(_)) => "TOTP_INVALID",
            Self::BadRequest(BadRequestKind::DecodeBase64Error(_)) => "INVALID_BASE64",
            Self::BadRequest(BadRequestKind::DeserializeOpaqueStructError(_)) => {
                "INVALID_OPAQUE_PAYLOAD"
            }
            Self::BadRequest(BadRequestKind::PayloadTooLarge) => "PAYLOAD_TOO_LARGE",
            Self::BadRequest(BadRequestKind::MissingOrInvalidBlobVersion) => "BLOB_VERSION_INVALID",
            Self::BadRequest(BadRequestKind::InvalidPagination) => "PAGINATION_INVALID",
            Self::BadRequest(BadRequestKind::InvalidCredentialId) => "CREDENTIAL_ID_INVALID",
            Self::NotFound(NotFoundKind::UserOrPasskeyNotFoundError) => {
                "ACCOUNT_OR_PASSKEY_NOT_FOUND"
            }
            Self::NotFound(NotFoundKind::UserOrOpaqueNotFoundError) => {
                "PASSWORD_CREDENTIAL_NOT_FOUND"
            }
            Self::NotFound(NotFoundKind::UserOrTotpNotFoundError) => "TOTP_CREDENTIAL_NOT_FOUND",
            Self::NotFound(NotFoundKind::UserEventNotFound) => "SECURITY_EVENT_NOT_FOUND",
            Self::NotFound(NotFoundKind::UserNotFound) => "ACCOUNT_NOT_FOUND",
            Self::NotFound(NotFoundKind::BlobNotFound) => "VAULT_METADATA_NOT_FOUND",
            Self::UnprocessableEntity(UnprocessableEntityKind::BlobVeryLargeError(_, _)) => {
                "BLOB_TOO_LARGE"
            }
            Self::UnprocessableEntity(UnprocessableEntityKind::BlobVersionNotIncreasingError(
                _,
                _,
            )) => "BLOB_VERSION_NOT_INCREASING",
            Self::UnprocessableEntity(UnprocessableEntityKind::OperationNotFound) => {
                "OPERATION_NOT_FOUND_OR_EXPIRED"
            }
            Self::UnprocessableEntity(UnprocessableEntityKind::PasskeyRegistrationError(_)) => {
                "PASSKEY_REGISTRATION_FAILED"
            }
            Self::Forbidden(ForbiddenKind::ForeignPasskeyAuth) => "PASSKEY_OPERATION_FORBIDDEN",
            Self::Forbidden(ForbiddenKind::ForeignPasswordAuth) => "PASSWORD_OPERATION_FORBIDDEN",
            Self::Forbidden(ForbiddenKind::ForeignTotpAuth) => "TOTP_OPERATION_FORBIDDEN",
            Self::Conflict(ConflictKind::UserAlreadyExists) => "ACCOUNT_ALREADY_EXISTS",
        }
    }

    pub fn client_text(&self) -> &'static str {
        match self {
            Self::Internal(_) => "An unexpected error occurred. Please try again later.",
            Self::Unauthorized(_) => "Authentication failed. Check your credentials and try again.",
            Self::BadRequest(BadRequestKind::PayloadTooLarge) => {
                "The request exceeds the allowed size."
            }
            Self::BadRequest(_) => {
                "The request is invalid. Check the submitted fields and try again."
            }
            Self::NotFound(_) => "The requested resource was not found.",
            Self::UnprocessableEntity(_) => {
                "The request could not be processed. Check the current resource state."
            }
            Self::Forbidden(_) => "You are not allowed to perform this action.",
            Self::Conflict(_) => "The request conflicts with the current account state.",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.code();
        let text = self.client_text();
        let trace_id = REQUEST_ERROR_CONTEXT
            .try_with(|context| {
                context.app_error_logged.set(true);
                context.trace_id
            })
            .unwrap_or_else(|_| Uuid::nil());

        if status.is_server_error() {
            tracing::error!(
                trace_id = %trace_id,
                error_code = code,
                error = ?self,
                "Request failed"
            );
        } else {
            tracing::warn!(
                trace_id = %trace_id,
                error_code = code,
                status = status.as_u16(),
                error = ?self,
                "Request rejected"
            );
        }

        (
            status,
            Json(ErrorResponse {
                error: ErrorDetail { code, text },
                trace_id,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, http::StatusCode};
    use serde_json::Value;

    use super::*;

    #[tokio::test]
    async fn app_errors_return_generic_envelope_with_request_trace_id() {
        let trace_id = Uuid::new_v4();
        let (response, logged) = REQUEST_ERROR_CONTEXT
            .scope(RequestErrorContext::new(trace_id), async {
                let response = AppError::Internal(InternalKind::DatabaseError(
                    "sensitive database diagnostics".to_owned(),
                ))
                .into_response();
                let logged = REQUEST_ERROR_CONTEXT
                    .try_with(|context| context.app_error_logged.get())
                    .expect("request error context should remain in scope");
                (response, logged)
            })
            .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("error response body should be readable");
        let json: Value =
            serde_json::from_slice(&body).expect("error response should contain valid JSON");

        assert_eq!(json["error"]["code"], "INTERNAL_SERVER_ERROR");
        assert_eq!(
            json["error"]["text"],
            "An unexpected error occurred. Please try again later."
        );
        assert_eq!(json["trace_id"], trace_id.to_string());
        assert!(
            !body
                .windows(b"sensitive database diagnostics".len())
                .any(|window| window == b"sensitive database diagnostics")
        );
        assert!(logged);
    }
}
