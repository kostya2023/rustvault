use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub username: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_ttl: u64,
    pub refresh_token_ttl: u64,
}
