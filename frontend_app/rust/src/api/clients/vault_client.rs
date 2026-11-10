use crate::{
    api::{
        clients::request::{Request, RootOfTrust},
        types::{
            blob::{Blob, BlobMetadata},
            errors::SdkError,
        },
    },
};
use flutter_rust_bridge::frb;

#[frb(opaque)]
pub struct VaultClient {
    request: Request,
}

impl VaultClient {
    pub fn new() -> Result<Self, SdkError> {
        Ok(Self {
            request: Request::new()?,
        })
    }

    pub fn with_base_url(base_url: String) -> Result<Self, SdkError> {
        Ok(Self {
            request: Request::with_base_url(base_url)?,
        })
    }

    pub fn new_with_root_of_trust(
        ssl_ca_pinned_cert: Option<Vec<u8>>,
    ) -> Result<Self, SdkError> {
        let root_of_trust = ssl_ca_pinned_cert
            .map(RootOfTrust::from_certificate_bytes)
            .transpose()?;
        Ok(Self {
            request: Request::new_with_root_of_trust(root_of_trust)?,
        })
    }

    pub fn with_base_url_and_root_of_trust(
        base_url: String,
        ssl_ca_pinned_cert: Option<Vec<u8>>,
    ) -> Result<Self, SdkError> {
        let root_of_trust = ssl_ca_pinned_cert
            .map(RootOfTrust::from_certificate_bytes)
            .transpose()?;
        Ok(Self {
            request: Request::with_base_url_and_root_of_trust(base_url, root_of_trust)?,
        })
    }

    pub async fn get_metadata(&self, access_token: String) -> Result<BlobMetadata, SdkError> {
        self.request
            .get("/v1/blob/meta", Some(&access_token))
            .await
    }

    pub async fn download(&self, access_token: String) -> Result<Blob, SdkError> {
        let encoded_blob = self.request.download_blob(&access_token).await?;
        Blob::deserialize_cbor(encoded_blob)
    }

    pub async fn upload(
        &self,
        access_token: String,
        blob: Blob,
        version: i64,
    ) -> Result<(), SdkError> {
        self.request
            .upload_blob(blob.serialize_cbor()?, version, &access_token)
            .await
    }
}
