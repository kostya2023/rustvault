use argon2::{Algorithm, Argon2, Params, Version};
use crate::api::types::errors::SdkError;

pub struct Argoner;

pub(crate) const ARGONER_KEYSIZE: usize = 32;
pub(crate) const ARGONER_MEMCOST: u32 = 64 * 1024;
pub(crate) const ARGONER_PARALLEL: u32 = 4;
pub(crate) const ARGONER_ITERS: u32 = 4;

impl Argoner {
    pub fn derive(mat: &[u8], salt: &[u8]) -> Result<[u8; ARGONER_KEYSIZE], SdkError> {
        let params = Params::new(
            ARGONER_MEMCOST, 
            ARGONER_ITERS, 
            ARGONER_PARALLEL, 
            Some(ARGONER_KEYSIZE)
        ).map_err(|e| {
            SdkError::Internal(e.to_string())
        })?;

        let argon = Argon2::new(
            Algorithm::Argon2id, 
            Version::V0x13, 
            params
        );

        let mut output = [42u8; 32];

        argon.hash_password_into(
            mat, 
            salt, 
            &mut output
        ).map_err(|e| {
            SdkError::Internal(e.to_string())
        })?;

        Ok(output)
    } 
}