use crate::api::types::{
    blob::Blob,
    crypto::{BlobSalt, Keys, TbsBlob},
    errors::SdkError,
    master_key::MasterKey,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flutter_rust_bridge::frb;
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 24;
const SALT_VERIFY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;
const ENCRYPTION_KEY_INFO: &[u8] = b"RustVault Blob Encryption Key v1";
const SIGNING_KEY_INFO: &[u8] = b"RustVault Blob Ed25519 Signing Key v1";

#[frb(opaque)]
pub struct CryptoClient {}

impl CryptoClient {
    pub fn new() -> Self {
        Self {}
    }

    pub fn encrypt(
        &self,
        master_key: &MasterKey,
        mut tbs_blob: TbsBlob,
    ) -> Result<Blob, SdkError> {
        let salt_verify = random_bytes::<SALT_VERIFY_SIZE>();
        tbs_blob.handler.salt_verify = salt_verify.to_vec();
        let mut plaintext = Zeroizing::new(Vec::new());
        let serialization_result = ciborium::into_writer(&tbs_blob, &mut *plaintext);
        tbs_blob.zeroize_passwords();
        serialization_result.map_err(|error| {
            SdkError::Crypto(format!("TbsBlob CBOR serialization failed: {error}"))
        })?;

        let blob_salt = BlobSalt::new(random_bytes());
        let encryption_key = derive_key(
            master_key,
            blob_salt.salt(),
            ENCRYPTION_KEY_INFO,
        )?;
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
        let signing_key = derive_signing_key(master_key, &salt_verify)?;
        let signature = signing_key.sign(&encrypted_blob);
        Ok(Blob::new(encrypted_blob, signature.to_bytes().to_vec()))
    }

    pub fn decrypt(
        &self,
        master_key: &MasterKey,
        blob: Blob,
    ) -> Result<TbsBlob, SdkError> {
        if blob.sign.len() != SIGNATURE_SIZE {
            return Err(SdkError::Crypto(
                "Blob has an invalid Ed25519 signature length".to_owned(),
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
        let encryption_key = derive_key(
            master_key,
            blob_salt.salt(),
            ENCRYPTION_KEY_INFO,
        )?;
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
        let mut tbs_blob: TbsBlob = ciborium::from_reader(plaintext.as_slice()).map_err(|error| {
            SdkError::Crypto(format!("TbsBlob CBOR parsing failed: {error}"))
        })?;

        let verification_result = (|| -> Result<(), SdkError> {
            let signing_key = derive_signing_key(master_key, &tbs_blob.handler.salt_verify)?;
            let verifying_key =
                VerifyingKey::from_bytes(&signing_key.verifying_key().to_bytes())
                    .map_err(|error| {
                        SdkError::Crypto(format!("Invalid Ed25519 public key: {error}"))
                    })?;
            let signature = Signature::from_slice(&blob.sign)
                .map_err(|error| SdkError::Crypto(format!("Invalid Ed25519 signature: {error}")))?;
            verifying_key.verify(&blob.blob, &signature).map_err(|_| {
                SdkError::Crypto("Blob Ed25519 signature verification failed".to_owned())
            })
        })();
        if let Err(error) = verification_result {
            tbs_blob.zeroize_passwords();
            return Err(error);
        }

        Ok(tbs_blob)
    }

    pub fn serialize_tbs_blob(&self, mut tbs_blob: TbsBlob) -> Result<Vec<u8>, SdkError> {
        let mut encoded = Zeroizing::new(Vec::new());
        let serialization_result = ciborium::into_writer(&tbs_blob, &mut *encoded);
        tbs_blob.zeroize_passwords();
        serialization_result.map_err(|error| {
            SdkError::Crypto(format!("TbsBlob CBOR serialization failed: {error}"))
        })?;
        Ok(encoded.to_vec())
    }

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

fn derive_key(
    master_key: &MasterKey,
    salt: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let input_key_material = master_key.opaque_password();
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &input_key_material);
    let mut derived_key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(info, &mut *derived_key)
        .map_err(|error| SdkError::Crypto(format!("Blob key derivation failed: {error}")))?;
    Ok(derived_key)
}

fn derive_signing_key(
    master_key: &MasterKey,
    salt_verify: &[u8],
) -> Result<SigningKey, SdkError> {
    if salt_verify.len() != SALT_VERIFY_SIZE {
        return Err(SdkError::Crypto(
            "Blob handler salt_verify must contain exactly 32 bytes".to_owned(),
        ));
    }
    let signing_seed = derive_key(master_key, salt_verify, SIGNING_KEY_INFO)?;
    Ok(SigningKey::from_bytes(&signing_seed))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
