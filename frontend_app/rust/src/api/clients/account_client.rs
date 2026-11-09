use crate::{
    api::{
        clients::request::{Request, RootOfTrust},
        types::{
            account::AccountInfo,
            errors::SdkError,
            flows::PasswordDeleteSession,
            master_key::CryptoKey,
            security::PasskeyChallenge,
        },
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flutter_rust_bridge::frb;
use opaque_ke::{ClientLogin, CredentialResponse};
use rand::rngs::OsRng;
use serde::Serialize;
use zeroize::Zeroizing;

#[frb(opaque)]
pub struct AccountClient {
    request: Request,
}

#[derive(Serialize)]
struct EmptyRequest {}

#[derive(Serialize)]
struct PasswordDeleteStep2Request {
    password_upload: String,
    totp_code: String,
    operation_id: String,
}

#[derive(Serialize)]
struct PasskeyDeleteStep2Request {
    passkey_props: serde_json::Value,
    operation_id: String,
}

impl AccountClient {
    pub fn new() -> Result<Self, SdkError> {
        Ok(Self {
            request: Request::new()?,
        })
    }

    pub fn with_base_url(base_url: String) -> Result<Self, SdkError> {
        Ok(Self {
            request: Request::with_base_url(base_url)?,
        })
    }

    pub fn new_with_root_of_trust(
        ssl_ca_pinned_cert: Option<Vec<u8>>,
    ) -> Result<Self, SdkError> {
        let root_of_trust = ssl_ca_pinned_cert
            .map(RootOfTrust::from_pem)
            .transpose()?;
        Ok(Self {
            request: Request::new_with_root_of_trust(root_of_trust)?,
        })
    }

    pub fn with_base_url_and_root_of_trust(
        base_url: String,
        ssl_ca_pinned_cert: Option<Vec<u8>>,
    ) -> Result<Self, SdkError> {
        let root_of_trust = ssl_ca_pinned_cert
            .map(RootOfTrust::from_pem)
            .transpose()?;
        Ok(Self {
            request: Request::with_base_url_and_root_of_trust(base_url, root_of_trust)?,
        })
    }

    pub async fn get_info(&self, access_token: String) -> Result<AccountInfo, SdkError> {
        self.request.get("/v1/account", Some(&access_token)).await
    }

    pub async fn delete_with_passkey_step1(
        &self,
        access_token: String,
    ) -> Result<PasskeyChallenge, SdkError> {
        #[derive(serde::Deserialize)]
        struct Response {
            operation_id: String,
            passkey_props: serde_json::Value,
        }

        let response: Response = self
            .request
            .post(
                "/v1/account/delete/with-passkey/step1",
                &EmptyRequest {},
                Some(&access_token),
            )
            .await?;
        Ok(PasskeyChallenge {
            operation_id: response.operation_id,
            passkey_props_json: response.passkey_props.to_string(),
        })
    }

    pub async fn delete_with_passkey_step2(
        &self,
        access_token: String,
        operation_id: String,
        passkey_props_json: String,
    ) -> Result<(), SdkError> {
        let request = PasskeyDeleteStep2Request {
            passkey_props: serde_json::from_str(&passkey_props_json).map_err(|error| {
                SdkError::Internal(format!("Invalid passkey response: {error}"))
            })?,
            operation_id,
        };
        self.request
            .delete_no_content(
                "/v1/account/delete/with-passkey/step2",
                Some(&request),
                Some(&access_token),
            )
            .await
    }

    pub async fn delete_with_passtotp_step1(
        &self,
        access_token: String,
        crypto_key: &CryptoKey,
    ) -> Result<PasswordDeleteSession, SdkError> {
        #[derive(serde::Deserialize)]
        struct Response {
            operation_id: String,
            password_response: String,
        }

        #[derive(Serialize)]
        struct Request {
            password_request: String,
        }

        let password = crypto_key.user_password_bytes();
        let mut rng = OsRng;
        let start = ClientLogin::<crate::internal_types::opaque_cipher_suite::OpaqueCipherSuite>::start(
            &mut rng,
            &password,
        )
        .map_err(|error| SdkError::Internal(format!("OPAQUE login failed: {error}")))?;
        let request = Request {
            password_request: URL_SAFE_NO_PAD.encode(start.message.serialize()),
        };
        let response: Response = self
            .request
            .post(
                "/v1/account/delete/with-passtotp/step1",
                &request,
                Some(&access_token),
            )
            .await?;
        Ok(PasswordDeleteSession {
            operation_id: response.operation_id,
            password,
            credential_response: Some(response.password_response),
            state: Some(start.state),
        })
    }

    pub async fn delete_with_passtotp_step2(
        &self,
        access_token: String,
        session: &mut PasswordDeleteSession,
        totp_code: String,
    ) -> Result<(), SdkError> {
        let state = session.state.take().ok_or_else(|| {
            SdkError::Internal("OPAQUE account deletion session is already completed".to_owned())
        })?;
        let password = std::mem::replace(&mut session.password, Zeroizing::new(Vec::new()));
        let response = session.credential_response.take().ok_or_else(|| {
            SdkError::Internal("OPAQUE account deletion response is missing".to_owned())
        })?;
        let response = URL_SAFE_NO_PAD
            .decode(response)
            .map_err(|error| SdkError::Internal(format!("Invalid OPAQUE response: {error}")))?;
        let response = CredentialResponse::<
            crate::internal_types::opaque_cipher_suite::OpaqueCipherSuite,
        >::deserialize(&response)
        .map_err(|error| SdkError::Internal(format!("Invalid OPAQUE response: {error}")))?;
        let mut rng = OsRng;
        let finish = state
            .finish(&mut rng, &password, response, Default::default())
            .map_err(|error| SdkError::Internal(format!("OPAQUE login failed: {error}")))?;
        drop(password);
        let request = PasswordDeleteStep2Request {
            password_upload: URL_SAFE_NO_PAD.encode(finish.message.serialize()),
            totp_code,
            operation_id: session.operation_id.clone(),
        };
        self.request
            .delete_no_content(
                "/v1/account/delete/with-passtotp/step2",
                Some(&request),
                Some(&access_token),
            )
            .await
    }
}
