use flutter_rust_bridge::frb;
use zeroize::Zeroizing;

use crate::internal_types::opaque_cipher_suite::OpaqueCipherSuite;

#[frb(opaque)]
pub struct RegistrationWithPasstotpFlow {
    pub(crate) operation_id: String,
    pub(crate) username: String,
    pub(crate) password: Zeroizing<Vec<u8>>,
    pub(crate) state: Option<opaque_ke::ClientRegistration<OpaqueCipherSuite>>,
    pub(crate) registration_response: Option<String>,
    pub(crate) totp_url: String,
}

impl RegistrationWithPasstotpFlow {
    pub fn operation_id(&self) -> String {
        self.operation_id.clone()
    }

    pub fn totp_url(&self) -> String {
        self.totp_url.clone()
    }
}

#[frb(opaque)]
pub struct LoginWithPasstotpFlow {
    pub(crate) operation_id: String,
    pub(crate) password: Zeroizing<Vec<u8>>,
    pub(crate) state: Option<opaque_ke::ClientLogin<OpaqueCipherSuite>>,
    pub(crate) credential_response: Option<String>,
}

impl LoginWithPasstotpFlow {
    pub fn operation_id(&self) -> String {
        self.operation_id.clone()
    }
}

#[frb(opaque)]
pub struct PasswordDeleteSession {
    pub(crate) operation_id: String,
    pub(crate) password: Zeroizing<Vec<u8>>,
    pub(crate) credential_response: Option<String>,
    pub(crate) state: Option<opaque_ke::ClientLogin<OpaqueCipherSuite>>,
}

impl PasswordDeleteSession {
    pub fn operation_id(&self) -> String {
        self.operation_id.clone()
    }
}

#[frb(opaque)]
pub struct PasswordChangePasskeySession {
    pub(crate) operation_id: String,
    pub(crate) password: Zeroizing<Vec<u8>>,
    pub(crate) registration_response: Option<String>,
    pub(crate) passkey_props_json: String,
    pub(crate) state: Option<opaque_ke::ClientRegistration<OpaqueCipherSuite>>,
}

impl PasswordChangePasskeySession {
    pub fn operation_id(&self) -> String {
        self.operation_id.clone()
    }

    pub fn passkey_props_json(&self) -> String {
        self.passkey_props_json.clone()
    }
}

#[frb(opaque)]
pub struct PasswordChangeTotpSession {
    pub(crate) operation_id: String,
    pub(crate) current_password: Zeroizing<Vec<u8>>,
    pub(crate) new_password: Zeroizing<Vec<u8>>,
    pub(crate) current_password_response: Option<String>,
    pub(crate) new_password_response: Option<String>,
    pub(crate) login_state: Option<opaque_ke::ClientLogin<OpaqueCipherSuite>>,
    pub(crate) registration_state: Option<opaque_ke::ClientRegistration<OpaqueCipherSuite>>,
}

impl PasswordChangeTotpSession {
    pub fn operation_id(&self) -> String {
        self.operation_id.clone()
    }
}

#[frb(opaque)]
pub struct TotpChangePasswordSession {
    pub(crate) operation_id: String,
    pub(crate) password: Zeroizing<Vec<u8>>,
    pub(crate) credential_response: Option<String>,
    pub(crate) totp_url: String,
    pub(crate) state: Option<opaque_ke::ClientLogin<OpaqueCipherSuite>>,
}

impl TotpChangePasswordSession {
    pub fn operation_id(&self) -> String {
        self.operation_id.clone()
    }

    pub fn totp_url(&self) -> String {
        self.totp_url.clone()
    }
}
