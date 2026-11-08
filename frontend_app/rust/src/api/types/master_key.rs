use flutter_rust_bridge::frb;
use zeroize::{Zeroize, Zeroizing};
use crate::{api::types::errors::SdkError, internal_types::argoner::Argoner};

#[frb(opaque)]
pub struct MasterKey {
    pub(crate) key: Zeroizing<[u8; 32]>,
}

impl MasterKey {
    pub fn new(password: &[u8], username: &[u8]) -> Result<Self, SdkError> {
        let password = Argoner::derive(password, username)?;
        Ok(MasterKey { key: Zeroizing::new(password) })
    }

    pub fn fingerprint(&self) -> String {
        let fingerprint = blake3::derive_key(
            "RustVault MasterKey Fingerprint v1", 
            & *self.key
        );
        hex::encode(&fingerprint[0..16])
    }

    pub(crate) fn opaque_password(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.key.to_vec())
    }

    pub fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}