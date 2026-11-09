use crate::{
    api::{
        clients::request::{Request, RootOfTrust},
        types::{
            auth::TokenPair,
            errors::SdkError,
            master_key::CryptoKey,
            flows::{LoginWithPasstotpFlow, RegistrationWithPasstotpFlow},
            security::PasskeyChallenge,
        },
    },
    internal_types::opaque_cipher_suite::OpaqueCipherSuite,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flutter_rust_bridge::frb;
use opaque_ke::{
    ClientLogin, ClientRegistration, CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[frb(opaque)]
pub struct LoginWithPasstotpClient {
    request: Request,
}

#[frb(opaque)]
pub struct RegistrationWithPasstotpClient {
    request: Request,
}

#[frb(opaque)]
pub struct LoginWithPasskeyClient {
    request: Request,
}

#[frb(opaque)]
pub struct TokenClient {
    request: Request,
}

#[derive(Serialize)]
struct RegistrationStep1Request {
    username: String,
    password_request: String,
}

#[derive(Deserialize)]
struct RegistrationStep1Response {
    password_response: String,
    totp_url: String,
    operation_id: String,
}

#[derive(Serialize)]
struct RegistrationStep2Request {
    username: String,
    password_upload: String,
    totp_code: String,
    operation_id: String,
}

#[derive(Serialize)]
struct LoginStep1Request {
    username: String,
    password_request: String,
}

#[derive(Deserialize)]
struct LoginStep1Response {
    password_response: String,
    operation_id: String,
}

#[derive(Serialize)]
struct LoginStep2Request {
    password_upload: String,
    totp_code: String,
    operation_id: String,
}

#[derive(Serialize)]
struct PasskeyLoginStep1Request {
    username: String,
}

#[derive(Deserialize)]
struct PasskeyLoginStep1Response {
    passkey_props: serde_json::Value,
    operation_id: String,
}

#[derive(Serialize)]
struct PasskeyLoginStep2Request {
    passkey_props: serde_json::Value,
    operation_id: String,
}

#[derive(Serialize)]
struct EmptyRequest {}

impl LoginWithPasstotpClient {
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
}

impl RegistrationWithPasstotpClient {
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
}

impl LoginWithPasskeyClient {
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
}

impl TokenClient {
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
}

impl LoginWithPasstotpClient {
    pub async fn step1(
        &self,
        username: String,
        crypto_key: &CryptoKey,
    ) -> Result<LoginWithPasstotpFlow, SdkError> {
        let password = crypto_key.user_password_bytes();
        let mut rng = OsRng;
        let start = ClientLogin::<OpaqueCipherSuite>::start(&mut rng, &password)
            .map_err(|error| SdkError::Internal(format!("OPAQUE login failed: {error}")))?;
        let request = LoginStep1Request {
            username,
            password_request: URL_SAFE_NO_PAD.encode(start.message.serialize()),
        };
        let response: LoginStep1Response = self
            .request
            .post("/v1/auth/login/with-passtotp/step1", &request, None)
            .await?;
        Ok(LoginWithPasstotpFlow {
            operation_id: response.operation_id,
            password,
            state: Some(start.state),
            credential_response: Some(response.password_response),
        })
    }

    pub async fn step2(
        &self,
        mut flow: LoginWithPasstotpFlow,
        totp_code: String,
    ) -> Result<(String, String), SdkError> {
        let state = flow.state.take().ok_or_else(|| {
            SdkError::Internal("OPAQUE login flow has already been completed".to_owned())
        })?;
        let password = std::mem::replace(&mut flow.password, Zeroizing::new(Vec::new()));
        let response = flow.credential_response.take().ok_or_else(|| {
            SdkError::Internal("OPAQUE login response is missing".to_owned())
        })?;
        let response = URL_SAFE_NO_PAD
            .decode(response)
            .map_err(|error| SdkError::Internal(format!("Invalid OPAQUE response: {error}")))?;
        let response = CredentialResponse::<OpaqueCipherSuite>::deserialize(&response)
            .map_err(|error| SdkError::Internal(format!("Invalid OPAQUE response: {error}")))?;
        let mut rng = OsRng;
        let finish = state
            .finish(&mut rng, &password, response, Default::default())
            .map_err(|error| SdkError::Internal(format!("OPAQUE login failed: {error}")))?;
        drop(password);
        let request = LoginStep2Request {
            password_upload: URL_SAFE_NO_PAD.encode(finish.message.serialize()),
            totp_code,
            operation_id: flow.operation_id,
        };
        let tokens: TokenPair = self
            .request
            .post("/v1/auth/login/with-passtotp/step2", &request, None)
            .await?;
        Ok((tokens.access_token, tokens.refresh_token))
    }
}

impl RegistrationWithPasstotpClient {
    pub async fn step1(
        &self,
        username: String,
        crypto_key: &CryptoKey,
    ) -> Result<RegistrationWithPasstotpFlow, SdkError> {
        let password = crypto_key.user_password_bytes();
        let mut rng = OsRng;
        let start = ClientRegistration::<OpaqueCipherSuite>::start(&mut rng, &password)
            .map_err(|error| {
                SdkError::Internal(format!("OPAQUE registration failed: {error}"))
            })?;
        let request = RegistrationStep1Request {
            username: username.clone(),
            password_request: URL_SAFE_NO_PAD.encode(start.message.serialize()),
        };
        let response: RegistrationStep1Response = self
            .request
            .post("/v1/auth/register/with-passtotp/step1", &request, None)
            .await?;
        Ok(RegistrationWithPasstotpFlow {
            operation_id: response.operation_id,
            username,
            password,
            state: Some(start.state),
            registration_response: Some(response.password_response),
            totp_url: response.totp_url,
        })
    }

    pub async fn step2(
        &self,
        mut flow: RegistrationWithPasstotpFlow,
        totp_code: String,
    ) -> Result<(String, String), SdkError> {
        let state = flow.state.take().ok_or_else(|| {
            SdkError::Internal("OPAQUE registration flow has already been completed".to_owned())
        })?;
        let password = std::mem::replace(&mut flow.password, Zeroizing::new(Vec::new()));
        let response = flow.registration_response.take().ok_or_else(|| {
            SdkError::Internal("OPAQUE registration response is missing".to_owned())
        })?;
        let response = URL_SAFE_NO_PAD
            .decode(response)
            .map_err(|error| SdkError::Internal(format!("Invalid OPAQUE response: {error}")))?;
        let response = RegistrationResponse::<OpaqueCipherSuite>::deserialize(&response)
            .map_err(|error| SdkError::Internal(format!("Invalid OPAQUE response: {error}")))?;
        let mut rng = OsRng;
        let finish = state
            .finish(&mut rng, &password, response, Default::default())
            .map_err(|error| {
                SdkError::Internal(format!("OPAQUE registration failed: {error}"))
            })?;
        drop(password);
        let request = RegistrationStep2Request {
            username: flow.username,
            password_upload: URL_SAFE_NO_PAD.encode(finish.message.serialize()),
            totp_code,
            operation_id: flow.operation_id,
        };
        let tokens: TokenPair = self
            .request
            .post("/v1/auth/register/with-passtotp/step2", &request, None)
            .await?;
        Ok((tokens.access_token, tokens.refresh_token))
    }
}

impl LoginWithPasskeyClient {
    pub async fn step1(&self, username: String) -> Result<PasskeyChallenge, SdkError> {
        let response: PasskeyLoginStep1Response = self
            .request
            .post(
                "/v1/auth/login/with-passkey/step1",
                &PasskeyLoginStep1Request { username },
                None,
            )
            .await?;
        Ok(PasskeyChallenge {
            operation_id: response.operation_id,
            passkey_props_json: response.passkey_props.to_string(),
        })
    }

    pub async fn step2(
        &self,
        operation_id: String,
        passkey_assertion_json: String,
    ) -> Result<(String, String), SdkError> {
        let request = PasskeyLoginStep2Request {
            passkey_props: serde_json::from_str(&passkey_assertion_json)
                .map_err(|error| SdkError::Internal(format!("Invalid passkey assertion: {error}")))?,
            operation_id,
        };
        let tokens: TokenPair = self
            .request
            .post("/v1/auth/login/with-passkey/step2", &request, None)
            .await?;
        Ok((tokens.access_token, tokens.refresh_token))
    }
}

impl TokenClient {
    pub async fn refresh(&self, refresh_token: String) -> Result<(String, String), SdkError> {
        let tokens: TokenPair = self
            .request
            .post_no_body("/v1/auth/refresh", Some(&refresh_token))
            .await?;
        Ok((tokens.access_token, tokens.refresh_token))
    }

    pub async fn logout(&self, access_token: String) -> Result<(), SdkError> {
        self.request
            .delete_no_content::<EmptyRequest>("/v1/auth/logout", None, Some(&access_token))
            .await
    }
}
