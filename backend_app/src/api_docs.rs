use utoipa::{
    Modify, OpenApi,
    openapi::{
        self,
        security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    },
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "RustVault API",
        version = "1.0.0",
        description = "HTTP API for RustVault account, authentication, security settings, and encrypted vault storage. Binary vault contents remain client-side encrypted."
    ),
    servers((url = "/", description = "Current server")),
    modifiers(&BearerAuth),
    paths(
        crate::handlers::healthz::healthz,
        crate::handlers::auth::register::with_passtotp::step1::auth_register_with_passtotp_step1,
        crate::handlers::auth::register::with_passtotp::step2::auth_register_with_passtotp_step2,
        crate::handlers::auth::login::with_passtotp::step1::auth_login_with_passtotp_step1,
        crate::handlers::auth::login::with_passtotp::step2::auth_login_with_passtotp_step2,
        crate::handlers::auth::login::with_passkey::step1::auth_login_with_passkey_step1,
        crate::handlers::auth::login::with_passkey::step2::auth_login_with_passkey_step2,
        crate::handlers::auth::refresh_tokens::auth_refresh_tokens,
        crate::handlers::auth::logout::auth_logout,
        crate::handlers::account::get_info::get_account_info,
        crate::handlers::account::delete::with_passkey::step1::delete_account_with_passkey_step1,
        crate::handlers::account::delete::with_passkey::step2::delete_account_with_passkey_step2,
        crate::handlers::account::delete::with_passtotp::step1::delete_account_with_passtotp_step1,
        crate::handlers::account::delete::with_passtotp::step2::delete_account_with_passtotp_step2,
        crate::handlers::security::get_events::get_security_events,
        crate::handlers::security::manage_passkeys::get_passkeys::get_passkeys,
        crate::handlers::security::manage_passkeys::add_passkey::step1::add_passkey_step1,
        crate::handlers::security::manage_passkeys::add_passkey::step2::add_passkey_step2,
        crate::handlers::security::manage_passkeys::delete_passkey::step1::delete_passkey_step1,
        crate::handlers::security::manage_passkeys::delete_passkey::step2::delete_passkey_step2,
        crate::handlers::security::changes::change_password::with_passkey::step1::change_password_with_passkey_step1,
        crate::handlers::security::changes::change_password::with_passkey::step2::change_password_with_passkey_step2,
        crate::handlers::security::changes::change_password::with_totp::step1::change_password_with_totp_step1,
        crate::handlers::security::changes::change_password::with_totp::step2::change_password_with_totp_step2,
        crate::handlers::security::changes::change_totp::with_passkey::step1::change_totp_with_passkey_step1,
        crate::handlers::security::changes::change_totp::with_passkey::step2::change_totp_with_passkey_step2,
        crate::handlers::security::changes::change_totp::with_password::step1::change_totp_with_password_step1,
        crate::handlers::security::changes::change_totp::with_password::step2::change_totp_with_password_step2,
        crate::handlers::blob::get_meta::get_meta,
        crate::handlers::blob::get_blob::get_blob,
        crate::handlers::blob::upload_blob::upload_blob
    ),
    components(schemas(
        ErrorBody,
        ErrorDetail,
        HealthResponse,
        RegisterStep1Request,
        RegisterStep1Response,
        RegisterStep2Request,
        TokenPairResponse,
        LoginPasswordStep1Request,
        LoginPasswordStep1Response,
        LoginPasswordStep2Request,
        LoginPasskeyStep1Request,
        LoginPasskeyStep1Response,
        LoginPasskeyStep2Request,
        AccountResponse,
        PasskeyChallengeResponse,
        DeletePasswordStep1Request,
        DeletePasswordStep1Response,
        DeletePasskeyConfirmation,
        DeletePasswordTotpConfirmation,
        SecurityEventsResponse,
        SecurityEvent,
        PasskeyInfo,
        AddPasskeyStep2Request,
        DeletePasskeyStep1Request,
        DeletePasskeyStep1Response,
        DeletePasskeyStep2Request,
        ChangePasswordPasskeyStep1Request,
        ChangePasswordPasskeyStep1Response,
        ChangePasswordPasskeyStep2Request,
        ChangePasswordTotpStep1Request,
        ChangePasswordTotpStep1Response,
        ChangePasswordTotpStep2Request,
        ChangeTotpPasskeyStep1Response,
        ChangeTotpPasskeyStep2Request,
        ChangeTotpPasswordStep1Request,
        ChangeTotpPasswordStep1Response,
        ChangeTotpPasswordStep2Request,
        BlobMetadata,
        BinaryBlob
    )),
    tags(
        (name = "Health", description = "Service liveness"),
        (name = "Authentication", description = "Registration, sign-in, token rotation, and logout"),
        (name = "Account", description = "Current account operations"),
        (name = "Security", description = "Account security settings, passkeys, and audit events"),
        (name = "Vault", description = "Encrypted vault data and metadata")
    )
)]
pub struct ApiDoc;

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

#[derive(utoipa::ToSchema)]
pub struct ErrorBody {
    /// Stable error code and generic client-facing text.
    pub error: ErrorDetail,
    /// Request correlation ID. Include it when contacting support.
    pub trace_id: uuid::Uuid,
}

#[derive(utoipa::ToSchema)]
pub struct ErrorDetail {
    /// Stable machine-readable error code.
    pub code: String,
    /// Generic, safe-to-display message.
    pub text: String,
}

#[derive(utoipa::ToSchema)]
pub struct HealthResponse {
    /// Liveness status.
    pub status: String,
}

#[derive(utoipa::ToSchema)]
pub struct RegisterStep1Request {
    /// Account name to register.
    pub username: String,
    /// OPAQUE registration request, Base64 URL-safe encoded without padding.
    pub password_request: String,
}

#[derive(utoipa::ToSchema)]
pub struct RegisterStep1Response {
    /// OPAQUE registration response, Base64 URL-safe encoded without padding.
    pub password_response: String,
    /// TOTP provisioning URI. Treat as a secret until registration completes.
    pub totp_url: String,
    /// Registration operation identifier, valid for five minutes.
    pub operation_id: uuid::Uuid,
}

#[derive(utoipa::ToSchema)]
pub struct RegisterStep2Request {
    pub username: String,
    /// OPAQUE registration upload, Base64 URL-safe encoded without padding.
    pub password_upload: String,
    /// Current TOTP code generated by the authenticator for the provisioned URI.
    pub totp_code: String,
    /// Operation identifier returned from registration step 1.
    pub operation_id: uuid::Uuid,
}

#[derive(utoipa::ToSchema)]
pub struct TokenPairResponse {
    pub username: String,
    /// Access token. Send as `Authorization: Bearer <access_token>`.
    pub access_token: String,
    /// Refresh token. Send to `/v1/auth/refresh` as a Bearer token.
    pub refresh_token: String,
    /// Access token lifetime in seconds.
    pub access_token_ttl: u64,
    /// Refresh token lifetime in seconds.
    pub refresh_token_ttl: u64,
}

#[derive(utoipa::ToSchema)]
pub struct LoginPasswordStep1Request {
    pub username: String,
    /// OPAQUE credential request, Base64 URL-safe encoded without padding.
    pub password_request: String,
}

#[derive(utoipa::ToSchema)]
pub struct LoginPasswordStep1Response {
    /// OPAQUE credential response, Base64 URL-safe encoded without padding.
    pub password_response: String,
    /// Login operation identifier, valid for five minutes.
    pub operation_id: uuid::Uuid,
}

#[derive(utoipa::ToSchema)]
pub struct LoginPasswordStep2Request {
    /// OPAQUE credential finalization, Base64 URL-safe encoded without padding.
    pub password_upload: String,
    /// Current authenticator code.
    pub totp_code: String,
    /// Operation identifier from password login step 1.
    pub operation_id: uuid::Uuid,
}

#[derive(utoipa::ToSchema)]
pub struct LoginPasskeyStep1Request {
    /// Username whose registered passkeys should be challenged.
    pub username: String,
}

#[derive(utoipa::ToSchema)]
pub struct LoginPasskeyStep1Response {
    /// WebAuthn authentication request options to pass to the browser WebAuthn API.
    pub passkey_props: serde_json::Value,
    pub operation_id: uuid::Uuid,
}

#[derive(utoipa::ToSchema)]
pub struct LoginPasskeyStep2Request {
    /// WebAuthn `PublicKeyCredential` assertion returned by the browser.
    pub passkey_props: serde_json::Value,
    pub operation_id: uuid::Uuid,
}

#[derive(utoipa::ToSchema)]
pub struct AccountResponse {
    pub username: String,
    /// Account creation time in RFC 3339 format.
    #[schema(value_type = String, format = DateTime)]
    pub created_at: String,
}

#[derive(utoipa::ToSchema)]
pub struct PasskeyChallengeResponse {
    pub operation_id: uuid::Uuid,
    /// WebAuthn assertion options for the registered passkey.
    pub passkey_props: serde_json::Value,
}

#[derive(utoipa::ToSchema)]
pub struct DeletePasswordStep1Request {
    /// OPAQUE login request proving the current password, Base64 URL-safe encoded without padding.
    pub password_request: String,
}

#[derive(utoipa::ToSchema)]
pub struct DeletePasswordStep1Response {
    pub operation_id: uuid::Uuid,
    /// OPAQUE credential response, Base64 URL-safe encoded without padding.
    pub password_response: String,
}

#[derive(utoipa::ToSchema)]
pub struct DeletePasskeyConfirmation {
    /// WebAuthn assertion returned by the browser.
    pub passkey_props: serde_json::Value,
    pub operation_id: uuid::Uuid,
}

#[derive(utoipa::ToSchema)]
pub struct DeletePasswordTotpConfirmation {
    /// OPAQUE credential finalization, Base64 URL-safe encoded without padding.
    pub password_upload: String,
    pub totp_code: String,
    pub operation_id: uuid::Uuid,
}

#[derive(utoipa::ToSchema)]
pub struct SecurityEventsResponse {
    pub events: Vec<SecurityEvent>,
}

#[derive(utoipa::ToSchema)]
pub struct SecurityEvent {
    pub username: String,
    pub id: uuid::Uuid,
    pub event_type: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub event_text: Option<String>,
    pub trace_id: Option<uuid::Uuid>,
    pub operation_id: Option<uuid::Uuid>,
    /// Event time in RFC 3339 format.
    #[schema(value_type = String, format = DateTime)]
    pub created_at: String,
}

#[derive(utoipa::ToSchema)]
pub struct PasskeyInfo {
    /// Credential ID encoded as lowercase hexadecimal.
    pub credential_id: String,
    pub keyname: String,
    #[schema(value_type = String, format = DateTime)]
    pub created_at: String,
    #[schema(value_type = String, format = DateTime)]
    pub last_used_at: String,
}

#[derive(utoipa::ToSchema)]
pub struct AddPasskeyStep2Request {
    pub operation_id: uuid::Uuid,
    /// User-facing label for this passkey.
    pub keyname: String,
    /// WebAuthn `PublicKeyCredential` registration response.
    pub passkey_props: serde_json::Value,
}

#[derive(utoipa::ToSchema)]
pub struct DeletePasskeyStep1Request {
    /// Credential ID from `GET /v1/security/passkeys` (hex encoded).
    pub credential_id: String,
}

#[derive(utoipa::ToSchema)]
pub struct DeletePasskeyStep1Response {
    pub operation_id: uuid::Uuid,
    pub credential_id: String,
    /// WebAuthn authentication request options.
    pub passkey_props: serde_json::Value,
}

#[derive(utoipa::ToSchema)]
pub struct DeletePasskeyStep2Request {
    pub operation_id: uuid::Uuid,
    /// Credential ID from the step 1 response.
    pub credential_id: String,
    /// WebAuthn `PublicKeyCredential` assertion response.
    pub passkey_props: serde_json::Value,
}

#[derive(utoipa::ToSchema)]
pub struct ChangePasswordPasskeyStep1Request {
    /// OPAQUE registration request for the new password, Base64 URL-safe encoded without padding.
    pub new_password_request: String,
}

#[derive(utoipa::ToSchema)]
pub struct ChangePasswordPasskeyStep1Response {
    pub operation_id: uuid::Uuid,
    /// WebAuthn assertion options for proving possession of a registered passkey.
    pub passkey_props: serde_json::Value,
    /// OPAQUE registration response for the new password, Base64 URL-safe encoded without padding.
    pub new_password_response: String,
}

#[derive(utoipa::ToSchema)]
pub struct ChangePasswordPasskeyStep2Request {
    pub operation_id: uuid::Uuid,
    /// WebAuthn assertion from step 1.
    pub passkey_props: serde_json::Value,
    /// OPAQUE registration upload for the new password, Base64 URL-safe encoded without padding.
    pub new_password_upload: String,
}

#[derive(utoipa::ToSchema)]
pub struct ChangePasswordTotpStep1Request {
    /// OPAQUE login request proving the current password, Base64 URL-safe encoded without padding.
    pub current_password_request: String,
    /// OPAQUE registration request for the new password, Base64 URL-safe encoded without padding.
    pub new_password_request: String,
}

#[derive(utoipa::ToSchema)]
pub struct ChangePasswordTotpStep1Response {
    pub operation_id: uuid::Uuid,
    /// OPAQUE login response for the current password, Base64 URL-safe encoded without padding.
    pub current_password_response: String,
    /// OPAQUE registration response for the new password, Base64 URL-safe encoded without padding.
    pub new_password_response: String,
}

#[derive(utoipa::ToSchema)]
pub struct ChangePasswordTotpStep2Request {
    pub operation_id: uuid::Uuid,
    /// OPAQUE login finalization for the current password, Base64 URL-safe encoded without padding.
    pub current_password_upload: String,
    /// OPAQUE registration upload for the new password, Base64 URL-safe encoded without padding.
    pub new_password_upload: String,
    pub totp_code: String,
}

#[derive(utoipa::ToSchema)]
pub struct ChangeTotpPasskeyStep1Response {
    pub operation_id: uuid::Uuid,
    /// WebAuthn assertion options for the registered passkey.
    pub passkey_props: serde_json::Value,
    /// New TOTP provisioning URI. Store it in an authenticator before step 2.
    pub totp_url: String,
}

#[derive(utoipa::ToSchema)]
pub struct ChangeTotpPasskeyStep2Request {
    pub operation_id: uuid::Uuid,
    /// WebAuthn assertion response from step 1.
    pub passkey_props: serde_json::Value,
    /// Current code for the newly provisioned TOTP secret.
    pub totp_code: String,
}

#[derive(utoipa::ToSchema)]
pub struct ChangeTotpPasswordStep1Request {
    /// OPAQUE login request for the current password, Base64 URL-safe encoded without padding.
    pub password_request: String,
}

#[derive(utoipa::ToSchema)]
pub struct ChangeTotpPasswordStep1Response {
    pub operation_id: uuid::Uuid,
    pub password_response: String,
    /// New TOTP provisioning URI. Store it in an authenticator before step 2.
    pub totp_url: String,
}

#[derive(utoipa::ToSchema)]
pub struct ChangeTotpPasswordStep2Request {
    pub operation_id: uuid::Uuid,
    /// OPAQUE login finalization for the current password, Base64 URL-safe encoded without padding.
    pub password_upload: String,
    pub totp_code: String,
}

#[derive(utoipa::ToSchema)]
pub struct BlobMetadata {
    /// BLAKE3 digest of the encrypted blob, encoded as lowercase hexadecimal.
    pub hash_blake3: String,
    pub version: i64,
    /// Blob length in bytes.
    pub size: i64,
    /// Last update time in RFC 3339 format.
    #[schema(value_type = String, format = DateTime)]
    pub updated_at: String,
}

#[derive(utoipa::ToSchema)]
#[schema(value_type = String, format = Binary)]
pub struct BinaryBlob(pub Vec<u8>);

#[cfg(test)]
mod tests {
    use super::ApiDoc;
    use utoipa::OpenApi;

    #[test]
    fn openapi_contains_every_route_and_auth_scheme() {
        let document = serde_json::to_value(ApiDoc::openapi())
            .expect("OpenAPI document should serialize to JSON");
        let paths = document["paths"]
            .as_object()
            .expect("OpenAPI paths should be an object");
        let operation_count = paths
            .values()
            .map(|path| {
                path.as_object()
                    .expect("path item should be an object")
                    .keys()
                    .filter(|method| {
                        matches!(
                            method.as_str(),
                            "get" | "post" | "put" | "delete" | "patch" | "head" | "options"
                        )
                    })
                    .count()
            })
            .sum::<usize>();

        assert_eq!(paths.len(), 30);
        assert_eq!(operation_count, 31);
        assert!(paths["/v1/blob"].get("get").is_some());
        assert!(paths["/v1/blob"].get("put").is_some());
        assert_eq!(
            document["components"]["schemas"]["BinaryBlob"]["format"],
            "binary"
        );
        assert_eq!(
            document["components"]["schemas"]["ErrorBody"]["properties"]["error"]["$ref"],
            "#/components/schemas/ErrorDetail"
        );
        assert!(
            document["components"]["schemas"]["ErrorBody"]["properties"]["trace_id"].is_object()
        );
        assert!(document["components"]["schemas"]["ErrorDetail"]["properties"]["code"].is_object());
        assert!(document["components"]["schemas"]["ErrorDetail"]["properties"]["text"].is_object());
        assert!(document["components"]["securitySchemes"]["bearer_auth"]["scheme"] == "bearer");
        for path in [
            "/v1/auth/refresh",
            "/v1/auth/logout",
            "/v1/account",
            "/v1/account/delete/with-passkey/step1",
            "/v1/account/delete/with-passkey/step2",
            "/v1/account/delete/with-passtotp/step1",
            "/v1/account/delete/with-passtotp/step2",
            "/v1/security/events",
            "/v1/security/passkeys",
            "/v1/security/manage-passkeys/add/step1",
            "/v1/security/manage-passkeys/add/step2",
            "/v1/security/manage-passkeys/delete/step1",
            "/v1/security/manage-passkeys/delete/step2",
            "/v1/security/changes/change-password/with-passkey/step1",
            "/v1/security/changes/change-password/with-passkey/step2",
            "/v1/security/changes/change-password/with-totp/step1",
            "/v1/security/changes/change-password/with-totp/step2",
            "/v1/security/changes/change-totp/with-passkey/step1",
            "/v1/security/changes/change-totp/with-passkey/step2",
            "/v1/security/changes/change-totp/with-password/step1",
            "/v1/security/changes/change-totp/with-password/step2",
            "/v1/blob/meta",
            "/v1/blob",
        ] {
            let operations = paths[path]
                .as_object()
                .expect("documented path should have operations");
            for operation in operations.values() {
                assert_eq!(
                    operation["security"][0]["bearer_auth"],
                    serde_json::json!([])
                );
            }
        }
    }
}
