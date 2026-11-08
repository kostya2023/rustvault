use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const BLOB_SALT_MAGIC: &[u8; 16] = b"RustVaultBlobV1!";
const BLOB_SALT_SIZE: usize = 32;

/// Raw blob prefix: 16-byte format magic followed by a 32-byte encryption salt.
pub(crate) struct BlobSalt {
    salt: [u8; BLOB_SALT_SIZE],
}

impl BlobSalt {
    pub(crate) const PREFIX_SIZE: usize = BLOB_SALT_MAGIC.len() + BLOB_SALT_SIZE;

    pub(crate) fn new(salt: [u8; BLOB_SALT_SIZE]) -> Self {
        Self { salt }
    }

    pub(crate) fn parse(blob: &[u8]) -> Result<Self, crate::api::types::errors::SdkError> {
        let prefix_size = Self::PREFIX_SIZE;
        if blob.len() < prefix_size || !blob.starts_with(BLOB_SALT_MAGIC) {
            return Err(crate::api::types::errors::SdkError::Crypto(
                "Blob has an unsupported salt block or magic value".to_owned(),
            ));
        }
        let salt = blob[BLOB_SALT_MAGIC.len()..prefix_size]
            .try_into()
            .map_err(|_| {
                crate::api::types::errors::SdkError::Crypto(
                    "Blob salt block has an invalid length".to_owned(),
                )
            })?;
        Ok(Self { salt })
    }

    pub(crate) fn salt(&self) -> &[u8; BLOB_SALT_SIZE] {
        &self.salt
    }

    pub(crate) fn to_prefix(&self) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(BLOB_SALT_MAGIC.len() + BLOB_SALT_SIZE);
        prefix.extend_from_slice(BLOB_SALT_MAGIC);
        prefix.extend_from_slice(&self.salt);
        prefix
    }

}

#[derive(Serialize, Deserialize)]
/// A single password entry serialized as part of the encrypted vault.
pub struct Key {
    pub service_name: String,
    pub password: String,
    pub username: String,
    pub user_comment: String,
}

impl Key {
    pub(crate) fn zeroize_password(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Serialize, Deserialize, Default)]
/// Collection of password entries stored in a vault.
pub struct Keys {
    pub keys: Vec<Key>,
}

#[derive(Serialize, Deserialize)]
/// Vault header metadata, including the salt used for signing-key derivation.
pub struct BlobHandler {
    pub salt_verify: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
/// The CBOR payload encrypted by `CryptoClient`.
pub struct TbsBlob {
    pub handler: BlobHandler,
    pub keys: Keys,
}

impl Keys {
    pub(crate) fn zeroize_passwords(&mut self) {
        for key in &mut self.keys {
            key.zeroize_password();
        }
    }
}

impl TbsBlob {
    pub(crate) fn zeroize_passwords(&mut self) {
        self.keys.zeroize_passwords();
    }
}
