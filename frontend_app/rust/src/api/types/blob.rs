use flutter_rust_bridge::frb;
use serde::{Deserialize, Serialize};
use crate::api::types::errors::SdkError;

#[frb(opaque)]
#[derive(Serialize, Deserialize)]
/// CBOR envelope containing encrypted blob bytes and their Ed25519 signature.
pub struct Blob {
    pub(crate) blob: Vec<u8>,
    pub(crate) sign: Vec<u8>,
}

impl Blob {
    pub fn new(blob: Vec<u8>, sign: Vec<u8>) -> Self {
        Self { blob, sign }
    }

    pub fn serialize_cbor(&self) -> Result<Vec<u8>, SdkError> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded)
            .map_err(|error| SdkError::Crypto(format!("Blob CBOR serialization failed: {error}")))?;
        Ok(encoded)
    }

    pub fn deserialize_cbor(encoded: Vec<u8>) -> Result<Self, SdkError> {
        ciborium::from_reader(encoded.as_slice())
            .map_err(|error| SdkError::Crypto(format!("Blob CBOR parsing failed: {error}")))
    }

    pub fn encrypted_bytes(&self) -> Vec<u8> {
        self.blob.clone()
    }

    pub fn signature(&self) -> Vec<u8> {
        self.sign.clone()
    }

    pub fn size(&self) -> u64 {
        self.blob.len() as u64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub hash_blake3: String,
    pub version: i64,
    pub size: i64,
    pub updated_at: String,
}
