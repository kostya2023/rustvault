use crate::{
    internal_types::opaque_cipher_suite::OpaqueCipherSuite,
    api::{
        clients::request::{Request, RootOfTrust},
        types::{
            errors::SdkError,
            flows::{
                PasswordChangePasskeySession, PasswordChangeTotpSession,
                TotpChangePasswordSession,
            },
            master_key::CryptoKey,
            security::{
                DeletePasskeyChallenge, PasskeyChallenge, PasskeyInfo, SecurityEvent,
                SecurityEventsPage, TotpChangeChallenge,
            },
        },
    },
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
pub struct SecurityClient {
    request: Request,
}

#[derive(Serialize)]
struct EmptyRequest {}

#[derive(Serialize)]
struct DeletePasskeyStep1Request {
    credential_id: String,
}

#[derive(Serialize)]
struct DeletePasskeyStep2Request {
    operation_id: String,
    credential_id: String,
    passkey_props: serde_json::Value,
}

#[derive(Serialize)]
struct AddPasskeyStep2Request {
    operation_id: String,
    keyname: String,
    passkey_props: serde_json::Value,
}

#[derive(Serialize)]
struct ChangePasswordPasskeyStep2Request {
    operation_id: String,
    passkey_props: serde_json::Value,
    new_password_upload: String,
}

#[derive(Serialize)]
struct ChangePasswordTotpStep2Request {
    operation_id: String,
    current_password_upload: String,
    new_password_upload: String,
    totp_code: String,
}

#[derive(Serialize)]
struct ChangeTotpPasswordStep2Request {
    operation_id: String,
    password_upload: String,
    totp_code: String,
}

#[derive(Serialize)]
struct ChangeTotpPasskeyStep2Request {
    operation_id: String,
    passkey_props: serde_json::Value,
    totp_code: String,
}

#[derive(Deserialize)]
struct PasskeyPropsResponse {
    operation_id: String,
    passkey_props: serde_json::Value,
}

#[derive(Deserialize)]
struct DeletePasskeyResponse {
    operation_id: String,
    credential_id: String,
    passkey_props: serde_json::Value,
}

#[derive(Deserialize)]
struct PasswordChangePasskeyResponse {
    operation_id: String,
    passkey_props: serde_json::Value,
    new_password_response: String,
}

#[derive(Deserialize)]
struct TotpChangePasskeyResponse {
    operation_id: String,
    passkey_props: serde_json::Value,
    totp_url: String,
}

#[derive(Deserialize)]
struct TotpChangePasswordResponse {
    operation_id: String,
    password_response: String,
    totp_url: String,
}

#[derive(Serialize)]
struct ChangePasswordPasskeyStep1Request {
    new_password_request: String,
}

#[derive(Deserialize)]
struct ChangePasswordTotpStep1Response {
    operation_id: String,
    current_password_response: String,
    new_password_response: String,
}

#[derive(Serialize)]
struct ChangePasswordTotpStep1Request {
    current_password_request: String,
    new_password_request: String,
}

#[derive(Serialize)]
struct ChangeTotpPasswordStep1Request {
    password_request: String,
}

impl SecurityClient {
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
            .map(RootOfTrust::from_certificate_bytes)
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
            .map(RootOfTrust::from_certificate_bytes)
            .transpose()?;
        Ok(Self {
            request: Request::with_base_url_and_root_of_trust(base_url, root_of_trust)?,
        })
    }

    pub async fn get_events(
        &self,
        access_token: String,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SecurityEvent>, SdkError> {
        if !(1..=100).contains(&limit) || offset < 0 {
            return Err(SdkError::Internal(
                "Security event limit must be 1-100 and offset must be non-negative".to_owned(),
            ));
        }
        let response: SecurityEventsPage = self.request
            .get(
                &format!("/v1/security/events?limit={limit}&offset={offset}"),
                Some(&access_token),
            )
            .await?;
        Ok(response.events)
    }

    pub async fn get_passkeys(&self, access_token: String) -> Result<Vec<PasskeyInfo>, SdkError> {
        self.request
            .get("/v1/security/passkeys", Some(&access_token))
            .await
    }

    pub async fn add_passkey_step1(
        &self,
        access_token: String,
    ) -> Result<PasskeyChallenge, SdkError> {
        let response: PasskeyPropsResponse = self
            .request
            .post(
                "/v1/security/manage-passkeys/add/step1",
                &EmptyRequest {},
                Some(&access_token),
            )
            .await?;
        Ok(PasskeyChallenge {
            operation_id: response.operation_id,
            passkey_props_json: response.passkey_props.to_string(),
        })
    }

    pub async fn add_passkey_step2(
        &self,
        access_token: String,
        operation_id: String,
        keyname: String,
        passkey_props_json: String,
    ) -> Result<(), SdkError> {
        let request = AddPasskeyStep2Request {
            operation_id,
            keyname,
            passkey_props: serde_json::from_str(&passkey_props_json).map_err(|error| {
                SdkError::Internal(format!("Invalid passkey registration: {error}"))
            })?,
        };
        self.request
            .post_no_content(
                "/v1/security/manage-passkeys/add/step2",
                &request,
                Some(&access_token),
            )
            .await
    }

    pub async fn delete_passkey_step1(
        &self,
        access_token: String,
        credential_id: String,
    ) -> Result<DeletePasskeyChallenge, SdkError> {
        let request = DeletePasskeyStep1Request { credential_id };
        let response: DeletePasskeyResponse = self
            .request
            .post(
                "/v1/security/manage-passkeys/delete/step1",
                &request,
                Some(&access_token),
            )
            .await?;
        Ok(DeletePasskeyChallenge {
            operation_id: response.operation_id,
            credential_id: response.credential_id,
            passkey_props_json: response.passkey_props.to_string(),
        })
    }

    pub async fn delete_passkey_step2(
        &self,
        access_token: String,
        operation_id: String,
        credential_id: String,
        passkey_props_json: String,
    ) -> Result<(), SdkError> {
        let request = DeletePasskeyStep2Request {
            operation_id,
            credential_id,
            passkey_props: serde_json::from_str(&passkey_props_json).map_err(|error| {
                SdkError::Internal(format!("Invalid passkey assertion: {error}"))
            })?,
        };
        self.request
            .delete_no_content(
                "/v1/security/manage-passkeys/delete/step2",
                Some(&request),
                Some(&access_token),
            )
            .await
    }

    pub async fn change_password_with_passkey_step1(
        &self,
        access_token: String,
        new_crypto_key: &CryptoKey,
    ) -> Result<PasswordChangePasskeySession, SdkError> {
        let password = new_crypto_key.user_password_bytes();
        let mut rng = OsRng;
        let start = ClientRegistration::<OpaqueCipherSuite>::start(&mut rng, &password)
            .map_err(|error| {
                SdkError::Internal(format!("OPAQUE registration failed: {error}"))
            })?;
        let request = ChangePasswordPasskeyStep1Request {
            new_password_request: URL_SAFE_NO_PAD.encode(start.message.serialize()),
        };
        let response: PasswordChangePasskeyResponse = self
            .request
            .post(
                "/v1/security/changes/change-password/with-passkey/step1",
                &request,
                Some(&access_token),
            )
            .await?;
        Ok(PasswordChangePasskeySession {
            operation_id: response.operation_id,
            passkey_props_json: response.passkey_props.to_string(),
            password,
            registration_response: Some(response.new_password_response),
            state: Some(start.state),
        })
    }

    pub async fn change_password_with_passkey_step2(
        &self,
        access_token: String,
        session: &mut PasswordChangePasskeySession,
        passkey_assertion_json: String,
    ) -> Result<(), SdkError> {
        let state = session.state.take().ok_or_else(|| {
            SdkError::Internal("OPAQUE password change session is already completed".to_owned())
        })?;
        let password = std::mem::replace(&mut session.password, Zeroizing::new(Vec::new()));
        let response = session.registration_response.take().ok_or_else(|| {
            SdkError::Internal("OPAQUE password response is missing".to_owned())
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
                SdkError::Internal(format!("OPAQUE password change failed: {error}"))
            })?;
        drop(password);
        let request = ChangePasswordPasskeyStep2Request {
            operation_id: session.operation_id.clone(),
            passkey_props: serde_json::from_str(&passkey_assertion_json).map_err(|error| {
                SdkError::Internal(format!("Invalid passkey assertion: {error}"))
            })?,
            new_password_upload: URL_SAFE_NO_PAD.encode(finish.message.serialize()),
        };
        self.request
            .put_no_content(
                "/v1/security/changes/change-password/with-passkey/step2",
                &request,
                Some(&access_token),
            )
            .await
    }

    pub async fn change_password_with_totp_step1(
        &self,
        access_token: String,
        current_crypto_key: &CryptoKey,
        new_crypto_key: &CryptoKey,
    ) -> Result<PasswordChangeTotpSession, SdkError> {
        let current_password = current_crypto_key.user_password_bytes();
        let new_password = new_crypto_key.user_password_bytes();
        let mut rng = OsRng;
        let login = ClientLogin::<OpaqueCipherSuite>::start(&mut rng, &current_password)
            .map_err(|error| SdkError::Internal(format!("OPAQUE login failed: {error}")))?;
        let registration =
            ClientRegistration::<OpaqueCipherSuite>::start(&mut rng, &new_password).map_err(
                |error| SdkError::Internal(format!("OPAQUE registration failed: {error}")),
            )?;
        let request = ChangePasswordTotpStep1Request {
            current_password_request: URL_SAFE_NO_PAD.encode(login.message.serialize()),
            new_password_request: URL_SAFE_NO_PAD.encode(registration.message.serialize()),
        };
        let response: ChangePasswordTotpStep1Response = self.request
            .post(
                "/v1/security/changes/change-password/with-totp/step1",
                &request,
                Some(&access_token),
            )
            .await?;
        Ok(PasswordChangeTotpSession {
            operation_id: response.operation_id,
            current_password,
            new_password,
            current_password_response: Some(response.current_password_response),
            new_password_response: Some(response.new_password_response),
            login_state: Some(login.state),
            registration_state: Some(registration.state),
        })
    }

    pub async fn change_password_with_totp_step2(
        &self,
        access_token: String,
        session: &mut PasswordChangeTotpSession,
        totp_code: String,
    ) -> Result<(), SdkError> {
        let login_state = session.login_state.take().ok_or_else(|| {
            SdkError::Internal("Current-password OPAQUE session is already completed".to_owned())
        })?;
        let registration_state = session.registration_state.take().ok_or_else(|| {
            SdkError::Internal("New-password OPAQUE session is already completed".to_owned())
        })?;
        let current_password =
            std::mem::replace(&mut session.current_password, Zeroizing::new(Vec::new()));
        let new_password = std::mem::replace(&mut session.new_password, Zeroizing::new(Vec::new()));
        let current_response = session.current_password_response.take().ok_or_else(|| {
            SdkError::Internal("Current-password OPAQUE response is missing".to_owned())
        })?;
        let new_response = session.new_password_response.take().ok_or_else(|| {
            SdkError::Internal("New-password OPAQUE response is missing".to_owned())
        })?;
        let current_response = URL_SAFE_NO_PAD.decode(current_response).map_err(|error| {
            SdkError::Internal(format!("Invalid current-password OPAQUE response: {error}"))
        })?;
        let current_response = CredentialResponse::<OpaqueCipherSuite>::deserialize(
            &current_response,
        )
        .map_err(|error| {
            SdkError::Internal(format!("Invalid current-password OPAQUE response: {error}"))
        })?;
        let new_response = URL_SAFE_NO_PAD.decode(new_response).map_err(|error| {
            SdkError::Internal(format!("Invalid new-password OPAQUE response: {error}"))
        })?;
        let new_response = RegistrationResponse::<OpaqueCipherSuite>::deserialize(&new_response)
            .map_err(|error| {
                SdkError::Internal(format!("Invalid new-password OPAQUE response: {error}"))
            })?;
        let mut rng = OsRng;
        let current_finish = login_state
            .finish(
                &mut rng,
                &current_password,
                current_response,
                Default::default(),
            )
            .map_err(|error| SdkError::Internal(format!("OPAQUE login failed: {error}")))?;
        let new_finish = registration_state
            .finish(&mut rng, &new_password, new_response, Default::default())
            .map_err(|error| {
                SdkError::Internal(format!("OPAQUE registration failed: {error}"))
            })?;
        drop(current_password);
        drop(new_password);
        let request = ChangePasswordTotpStep2Request {
            operation_id: session.operation_id.clone(),
            current_password_upload: URL_SAFE_NO_PAD.encode(current_finish.message.serialize()),
            new_password_upload: URL_SAFE_NO_PAD.encode(new_finish.message.serialize()),
            totp_code,
        };
        self.request
            .put_no_content(
                "/v1/security/changes/change-password/with-totp/step2",
                &request,
                Some(&access_token),
            )
            .await
    }

    pub async fn change_totp_with_passkey_step1(
        &self,
        access_token: String,
    ) -> Result<TotpChangeChallenge, SdkError> {
        let response: TotpChangePasskeyResponse = self
            .request
            .post(
                "/v1/security/changes/change-totp/with-passkey/step1",
                &EmptyRequest {},
                Some(&access_token),
            )
            .await?;
        Ok(TotpChangeChallenge {
            operation_id: response.operation_id,
            totp_url: response.totp_url,
            password_response: None,
            passkey_props_json: Some(response.passkey_props.to_string()),
        })
    }

    pub async fn change_totp_with_passkey_step2(
        &self,
        access_token: String,
        operation_id: String,
        passkey_props_json: String,
        totp_code: String,
    ) -> Result<(), SdkError> {
        let request = ChangeTotpPasskeyStep2Request {
            operation_id,
            passkey_props: serde_json::from_str(&passkey_props_json).map_err(|error| {
                SdkError::Internal(format!("Invalid passkey assertion: {error}"))
            })?,
            totp_code,
        };
        self.request
            .put_no_content(
                "/v1/security/changes/change-totp/with-passkey/step2",
                &request,
                Some(&access_token),
            )
            .await
    }

    pub async fn change_totp_with_password_step1(
        &self,
        access_token: String,
        crypto_key: &CryptoKey,
    ) -> Result<TotpChangePasswordSession, SdkError> {
        let password = crypto_key.user_password_bytes();
        let mut rng = OsRng;
        let login = ClientLogin::<OpaqueCipherSuite>::start(&mut rng, &password)
            .map_err(|error| SdkError::Internal(format!("OPAQUE login failed: {error}")))?;
        let request = ChangeTotpPasswordStep1Request {
            password_request: URL_SAFE_NO_PAD.encode(login.message.serialize()),
        };
        let response: TotpChangePasswordResponse = self
            .request
            .post(
                "/v1/security/changes/change-totp/with-password/step1",
                &request,
                Some(&access_token),
            )
            .await?;
        Ok(TotpChangePasswordSession {
            operation_id: response.operation_id,
            totp_url: response.totp_url,
            password,
            credential_response: Some(response.password_response),
            state: Some(login.state),
        })
    }

    pub async fn change_totp_with_password_step2(
        &self,
        access_token: String,
        session: &mut TotpChangePasswordSession,
        totp_code: String,
    ) -> Result<(), SdkError> {
        let state = session.state.take().ok_or_else(|| {
            SdkError::Internal("OPAQUE TOTP update session is already completed".to_owned())
        })?;
        let password = std::mem::replace(&mut session.password, Zeroizing::new(Vec::new()));
        let response = session.credential_response.take().ok_or_else(|| {
            SdkError::Internal("OPAQUE password response is missing".to_owned())
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
        let request = ChangeTotpPasswordStep2Request {
            operation_id: session.operation_id.clone(),
            password_upload: URL_SAFE_NO_PAD.encode(finish.message.serialize()),
            totp_code,
        };
        self.request
            .put_no_content(
                "/v1/security/changes/change-totp/with-password/step2",
                &request,
                Some(&access_token),
            )
            .await
    }
}
