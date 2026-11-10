use crate::{
    api::{
        clients::request::{Request, RootOfTrust},
        types::{errors::SdkError, health::HealthStatus},
    },
};
use flutter_rust_bridge::frb;

#[frb(opaque)]
pub struct HealthClient {
    request: Request,
}

impl HealthClient {
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

    pub async fn check(&self) -> Result<HealthStatus, SdkError> {
        self.request.get("/v1/healthz", None).await
    }
}
