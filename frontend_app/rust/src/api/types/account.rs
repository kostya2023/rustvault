use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub username: String,
    pub created_at: String,
}
