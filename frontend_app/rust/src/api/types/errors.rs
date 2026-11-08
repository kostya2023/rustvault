use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error(
        "Server error: code='{code}', text='{text}', trace_id='{trace_id}'"
    )]
    Server {
        code: String,
        text: String,
        trace_id: String,
    },
}