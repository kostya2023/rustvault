use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub username: String,
    pub id: String,
    pub event_type: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub event_text: Option<String>,
    pub trace_id: Option<String>,
    pub operation_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyInfo {
    pub credential_id: String,
    pub keyname: String,
    pub created_at: String,
    pub last_used_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyChallenge {
    pub operation_id: String,
    pub passkey_props_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePasskeyChallenge {
    pub operation_id: String,
    pub credential_id: String,
    pub passkey_props_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpChangeChallenge {
    pub operation_id: String,
    pub totp_url: String,
    pub password_response: Option<String>,
    pub passkey_props_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventsPage {
    pub events: Vec<SecurityEvent>,
}
