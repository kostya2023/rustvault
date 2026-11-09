use crate::api::types::{
    blob::Blob,
    crypto::{BlobHandler, BlobSalt, Keys, TbsBlob},
    errors::SdkError,
    master_key::CryptoKey,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use flutter_rust_bridge::frb;
use poly1305::{Key as Poly1305Key, Poly1305};
use rand::{RngCore, rngs::OsRng};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const ENCRYPTION_KEY_INFO: &[u8] = b"RustVault Blob Encryption Key v1";
const AUTHENTICATION_KEY_INFO: &[u8] = b"RustVault Blob Poly1305 Key v1";

#[frb(opaque)]
pub struct CryptoClient {}

impl CryptoClient {
    pub fn new() -> Self {
        Self {}
    }

    pub fn encrypt_keys(
        &self,
        crypto_key: &CryptoKey,
        mut keys: Keys,
    ) -> Result<Blob, SdkError> {
        let mut plaintext = Zeroizing::new(Vec::new());
        let serialization_result = ciborium::into_writer(&keys, &mut *plaintext);
        keys.zeroize_passwords();
        serialization_result.map_err(|error| {
            SdkError::Crypto(format!("Keys CBOR serialization failed: {error}"))
        })?;

        let blob_salt = BlobSalt::new(random_bytes());
        let blob_key = crypto_key.derive_blob_key(blob_salt.salt(), BlobSalt::VERSION)?;
        let encryption_key =
            CryptoKey::derive_subkey(&blob_key, blob_salt.salt(), ENCRYPTION_KEY_INFO)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&encryption_key[..])
            .map_err(|error| SdkError::Crypto(error.to_string()))?;
        let nonce_bytes = random_bytes::<NONCE_SIZE>();
        let nonce = XNonce::from(nonce_bytes);
        let mut associated_data = blob_salt.to_prefix();
        associated_data.extend_from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &associated_data,
                },
            )
            .map_err(|error| SdkError::Crypto(error.to_string()))?;
        let mut encrypted_blob = associated_data;
        encrypted_blob.extend_from_slice(&ciphertext);
        let authentication_key =
            CryptoKey::derive_subkey(&blob_key, blob_salt.salt(), AUTHENTICATION_KEY_INFO)?;
        // The random blob salt provides a fresh one-time key for each Poly1305 tag.
        let tag = poly1305_tag(&authentication_key, &encrypted_blob);
        Ok(Blob::new(encrypted_blob, tag.to_vec()))
    }

    pub fn decrypt_keys(
        &self,
        crypto_key: &CryptoKey,
        blob: Blob,
    ) -> Result<Keys, SdkError> {
        if blob.tag.len() != TAG_SIZE {
            return Err(SdkError::Crypto(
                "Blob has an invalid Poly1305 authentication tag length".to_owned(),
            ));
        }

        let prefix_size = BlobSalt::PREFIX_SIZE + NONCE_SIZE;
        if blob.blob.len() < prefix_size + 16 {
            return Err(SdkError::Crypto(
                "Blob payload is truncated".to_owned(),
            ));
        }

        let blob_salt = BlobSalt::parse(&blob.blob)?;
        let nonce_start = BlobSalt::PREFIX_SIZE;
        let nonce_bytes: [u8; NONCE_SIZE] = blob.blob[nonce_start..prefix_size]
            .try_into()
            .map_err(|_| SdkError::Crypto("Blob nonce has an invalid length".to_owned()))?;
        let nonce = XNonce::from(nonce_bytes);
        let blob_key = crypto_key.derive_blob_key(blob_salt.salt(), BlobSalt::VERSION)?;
        let authentication_key =
            CryptoKey::derive_subkey(&blob_key, blob_salt.salt(), AUTHENTICATION_KEY_INFO)?;
        let expected_tag = poly1305_tag(&authentication_key, &blob.blob);
        if !bool::from(expected_tag.as_slice().ct_eq(blob.tag.as_slice())) {
            return Err(SdkError::Crypto(
                "Blob Poly1305 authentication failed".to_owned(),
            ));
        }

        let encryption_key =
            CryptoKey::derive_subkey(&blob_key, blob_salt.salt(), ENCRYPTION_KEY_INFO)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&encryption_key[..])
            .map_err(|error| SdkError::Crypto(error.to_string()))?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &blob.blob[prefix_size..],
                    aad: &blob.blob[..prefix_size],
                },
            )
            .map_err(|_| {
                SdkError::Crypto(
                    "Blob authentication failed; the key or blob may be incorrect".to_owned(),
                )
            })?;
        let plaintext = Zeroizing::new(plaintext);
        let keys: Keys = ciborium::from_reader(plaintext.as_slice()).map_err(|error| {
            SdkError::Crypto(format!("Keys CBOR parsing failed: {error}"))
        })?;
        Ok(keys)
    }

    #[doc(hidden)]
    pub fn encrypt(&self, crypto_key: &CryptoKey, mut tbs_blob: TbsBlob) -> Result<Blob, SdkError> {
        let keys = std::mem::take(&mut tbs_blob.keys);
        tbs_blob.zeroize_passwords();
        self.encrypt_keys(crypto_key, keys)
    }

    #[doc(hidden)]
    pub fn decrypt(&self, crypto_key: &CryptoKey, blob: Blob) -> Result<TbsBlob, SdkError> {
        Ok(TbsBlob {
            handler: BlobHandler {
                salt_verify: Vec::new(),
            },
            keys: self.decrypt_keys(crypto_key, blob)?,
        })
    }

    #[doc(hidden)]
    pub fn serialize_tbs_blob(
        &self,
        mut tbs_blob: TbsBlob,
    ) -> Result<Vec<u8>, SdkError> {
        let mut encoded = Zeroizing::new(Vec::new());
        let serialization_result = ciborium::into_writer(&tbs_blob, &mut *encoded);
        tbs_blob.zeroize_passwords();
        serialization_result.map_err(|error| {
            SdkError::Crypto(format!("TbsBlob CBOR serialization failed: {error}"))
        })?;
        Ok(encoded.to_vec())
    }

    #[doc(hidden)]
    pub fn parse_tbs_blob(&self, encoded: Vec<u8>) -> Result<TbsBlob, SdkError> {
        ciborium::from_reader(encoded.as_slice())
            .map_err(|error| SdkError::Crypto(format!("TbsBlob CBOR parsing failed: {error}")))
    }

    pub fn serialize_keys(&self, mut keys: Keys) -> Result<Vec<u8>, SdkError> {
        let mut encoded = Zeroizing::new(Vec::new());
        let serialization_result = ciborium::into_writer(&keys, &mut *encoded);
        keys.zeroize_passwords();
        serialization_result
            .map_err(|error| SdkError::Crypto(format!("Keys CBOR serialization failed: {error}")))?;
        Ok(encoded.to_vec())
    }

    pub fn parse_keys(&self, encoded: Vec<u8>) -> Result<Keys, SdkError> {
        ciborium::from_reader(encoded.as_slice())
            .map_err(|error| SdkError::Crypto(format!("Keys CBOR parsing failed: {error}")))
    }
}

fn poly1305_tag(key: &[u8; 32], message: &[u8]) -> poly1305::Tag {
    let key = Poly1305Key::from(*key);
    Poly1305::new(&key).compute_unpadded(message)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::crypto::{Key, Keys};
    use crate::api::types::master_key::UserPassword;

    #[test]
    fn encrypted_keys_roundtrip_and_reject_modified_poly1305_tag() {
        let client = CryptoClient::new();
        let crypto_key = CryptoKey::from_user_password(
            UserPassword::new("test-password".to_owned()),
            "test-user".to_owned(),
        );
        let keys = Keys {
            keys: vec![Key {
                service_name: "test-service".to_owned(),
                password: "secret".to_owned(),
                username: "test-login".to_owned(),
                user_comment: "test".to_owned(),
            }],
        };

        let blob = client.encrypt_keys(&crypto_key, keys).unwrap();
        assert_eq!(blob.authentication_tag().len(), TAG_SIZE);
        let decrypted = client
            .decrypt_keys(
                &crypto_key,
                Blob::new(blob.encrypted_bytes(), blob.authentication_tag()),
            )
            .unwrap();
        assert_eq!(decrypted.keys.len(), 1);
        assert_eq!(decrypted.keys[0].password, "secret");

        let mut modified_tag = blob.authentication_tag();
        modified_tag[0] ^= 1;
        assert!(
            client
                .decrypt_keys(
                    &crypto_key,
                    Blob::new(blob.encrypted_bytes(), modified_tag),
                )
                .is_err()
        );
    }
}
