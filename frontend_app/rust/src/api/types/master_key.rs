use crate::{api::types::errors::SdkError, internal_types::argoner::Argoner};
use flutter_rust_bridge::frb;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const KEY_SIZE: usize = 32;
const FINGERPRINT_SALT_DOMAIN: &[u8] = b"RustVault CryptoKey Fingerprint v1";

#[frb(opaque)]
pub struct UserPassword {
    password: Zeroizing<Vec<u8>>,
}

impl UserPassword {
    pub fn new(password: String) -> Self {
        Self {
            password: Zeroizing::new(password.into_bytes()),
        }
    }

    fn from_bytes(password: &[u8]) -> Self {
        Self {
            password: Zeroizing::new(password.to_vec()),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.password
    }
}

#[frb(opaque)]
pub struct CryptoKey {
    user_password: UserPassword,
    username: Zeroizing<Vec<u8>>,
}

impl CryptoKey {
    pub fn from_user_password(user_password: UserPassword, username: String) -> Self {
        Self {
            user_password,
            username: Zeroizing::new(username.into_bytes()),
        }
    }

    pub fn new(password: &[u8], username: &[u8]) -> Result<Self, SdkError> {
        Ok(Self {
            user_password: UserPassword::from_bytes(password),
            username: Zeroizing::new(username.to_vec()),
        })
    }

    pub fn fingerprint(&self) -> String {
        let mut salt = Zeroizing::new(Vec::with_capacity(
            self.username.len() + FINGERPRINT_SALT_DOMAIN.len(),
        ));
        salt.extend_from_slice(&self.username);
        salt.extend_from_slice(FINGERPRINT_SALT_DOMAIN);
        let key = Zeroizing::new(
            Argoner::derive(self.user_password.as_bytes(), &salt)
                .expect("fixed Argon2 parameters and non-empty fingerprint salt are valid"),
        );
        let fingerprint = blake3::derive_key("RustVault CryptoKey Fingerprint v1", &*key);
        hex::encode(&fingerprint[0..16])
    }

    pub(crate) fn user_password_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.user_password.as_bytes().to_vec())
    }

    pub(crate) fn derive_blob_key(
        &self,
        blob_salt: &[u8],
        blob_version: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_SIZE]>, SdkError> {
        let mut salt = Zeroizing::new(Vec::with_capacity(
            self.username.len() + blob_salt.len() + blob_version.len(),
        ));
        salt.extend_from_slice(&self.username);
        salt.extend_from_slice(blob_salt);
        salt.extend_from_slice(blob_version);

        Ok(Zeroizing::new(Argoner::derive(
            self.user_password.as_bytes(),
            &salt,
        )?))
    }

    pub(crate) fn derive_subkey(
        blob_key: &[u8; KEY_SIZE],
        blob_salt: &[u8],
        info: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_SIZE]>, SdkError> {
        let hkdf = Hkdf::<Sha256>::new(Some(blob_salt), blob_key);
        let mut derived_key = Zeroizing::new([0_u8; KEY_SIZE]);
        hkdf.expand(info, &mut *derived_key)
            .map_err(|error| SdkError::Crypto(format!("Blob key derivation failed: {error}")))?;
        Ok(derived_key)
    }

    pub fn zeroize(&mut self) {
        self.user_password.password.zeroize();
        self.username.zeroize();
    }
}

impl Drop for CryptoKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Keep the generated bridge's existing opaque type name until its codegen is updated.
#[doc(hidden)]
pub type MasterKey = CryptoKey;
