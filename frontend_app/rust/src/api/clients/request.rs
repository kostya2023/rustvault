use crate::api::types::errors::SdkError;
use crate::internal_types::user_agent::get_user_agent;
use reqwest::{
    Client, Method, StatusCode, Url,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::net::IpAddr;

pub(crate) struct Request {
    pub(crate) client: Client,
    base_url: String,
}

/// Additional CA trust root for HTTPS connections. This augments, rather than replaces,
/// Reqwest's normal platform trust store.
pub(crate) struct RootOfTrust {
    certificate: reqwest::Certificate,
}

impl RootOfTrust {
    /// Parse one PEM- or DER-encoded CA certificate used as the only TLS trust root.
    pub(crate) fn from_certificate_bytes(ssl_ca_pinned_cert: Vec<u8>) -> Result<Self, SdkError> {
        let certificate = reqwest::Certificate::from_pem(&ssl_ca_pinned_cert)
            .or_else(|_| reqwest::Certificate::from_der(&ssl_ca_pinned_cert))
            .map_err(|error| {
                SdkError::Internal(format!(
                    "Invalid CA certificate: provide a PEM or DER encoded X.509 certificate: {error}"
                ))
            })?;
        Ok(Self { certificate })
    }
}

#[derive(serde::Deserialize)]
struct ErrorBody {
    error: ErrorDetail,
    trace_id: String,
}

#[derive(serde::Deserialize)]
struct ErrorDetail {
    code: String,
    text: String,
}

impl Request {
    pub(crate) fn new() -> Result<Self, SdkError> {
        Self::new_with_root_of_trust(None)
    }

    pub(crate) fn new_with_root_of_trust(
        root_of_trust: Option<RootOfTrust>,
    ) -> Result<Self, SdkError> {
        let base_url = std::env::var("RUSTVAULT_API_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned());
        Self::with_base_url_and_root_of_trust(base_url, root_of_trust)
    }

    pub(crate) fn with_base_url(base_url: String) -> Result<Self, SdkError> {
        Self::with_base_url_and_root_of_trust(base_url, None)
    }

    pub(crate) fn with_base_url_and_root_of_trust(
        base_url: String,
        root_of_trust: Option<RootOfTrust>,
    ) -> Result<Self, SdkError> {
        let parsed_url = Url::parse(&base_url)
            .map_err(|error| SdkError::Internal(format!("Invalid API base URL: {error}")))?;
        if !matches!(parsed_url.scheme(), "http" | "https")
            || parsed_url.query().is_some()
            || parsed_url.fragment().is_some()
        {
            return Err(SdkError::Internal(
                "API base URL must use HTTP or HTTPS and must not contain a query or fragment"
                    .to_owned(),
            ));
        }

        let is_loopback = parsed_url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        let user_agent = HeaderValue::from_str(&get_user_agent())
            .map_err(|error| SdkError::Internal(format!("Invalid SDK User-Agent: {error}")))?;
        let mut client_builder = Client::builder().user_agent(user_agent);
        if is_loopback {
            client_builder = client_builder.no_proxy();
        }
        if let Some(root_of_trust) = root_of_trust {
            client_builder = client_builder.tls_certs_only([root_of_trust.certificate]);
        }
        let client = client_builder
            .build()
            .map_err(|error| SdkError::Internal(format!("HTTP client initialization failed: {error}")))?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
        })
    }

    pub(crate) async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        access_token: Option<&str>,
    ) -> Result<T, SdkError> {
        self.request(Method::GET, path, Option::<&Value>::None, access_token)
            .await
    }

    pub(crate) async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        access_token: Option<&str>,
    ) -> Result<T, SdkError> {
        self.request(Method::POST, path, Some(body), access_token)
            .await
    }

    pub(crate) async fn post_no_body<T: DeserializeOwned>(
        &self,
        path: &str,
        access_token: Option<&str>,
    ) -> Result<T, SdkError> {
        self.request::<Value, T>(Method::POST, path, None, access_token)
            .await
    }

    pub(crate) async fn post_no_content<B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
        access_token: Option<&str>,
    ) -> Result<(), SdkError> {
        self.request_no_content(Method::POST, path, Some(body), access_token)
            .await
    }

    pub(crate) async fn put_no_content<B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
        access_token: Option<&str>,
    ) -> Result<(), SdkError> {
        self.request_no_content(Method::PUT, path, Some(body), access_token)
            .await
    }

    pub(crate) async fn delete_no_content<B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: Option<&B>,
        access_token: Option<&str>,
    ) -> Result<(), SdkError> {
        self.request_no_content(Method::DELETE, path, body, access_token)
            .await
    }

    pub(crate) async fn upload_blob(
        &self,
        encrypted_blob: Vec<u8>,
        version: i64,
        access_token: &str,
    ) -> Result<(), SdkError> {
        tracing::info!(operation = "upload_blob", version, bytes = encrypted_blob.len(), "API blob upload started");
        let response = self
            .client
            .put(self.url("/v1/blob"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .header("X-Blob-Version", version.to_string())
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(encrypted_blob)
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(operation = "upload_blob", "API blob upload failed at network layer");
                SdkError::Network(error.to_string())
            })?;
        tracing::debug!(operation = "upload_blob", status = response.status().as_u16(), "API blob upload response received");
        self.read_no_content(response).await
    }

    pub(crate) async fn download_blob(&self, access_token: &str) -> Result<Vec<u8>, SdkError> {
        tracing::info!(operation = "download_blob", "API blob download started");
        let response = self
            .client
            .get(self.url("/v1/blob"))
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(operation = "download_blob", "API blob download failed at network layer");
                SdkError::Network(error.to_string())
            })?;
        let status = response.status().as_u16();
        let bytes = self.read_bytes(response).await?;
        tracing::debug!(operation = "download_blob", status, bytes = bytes.len(), "API blob download completed");
        Ok(bytes)
    }

    async fn request<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        access_token: Option<&str>,
    ) -> Result<T, SdkError> {
        tracing::debug!(method = method.as_str(), path, "API request started");
        let mut request = self.client.request(method, self.url(path));
        if let Some(token) = access_token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|error| {
            tracing::warn!(path, "API request failed at network layer");
            SdkError::Network(error.to_string())
        })?;
        tracing::debug!(path, status = response.status().as_u16(), "API response received");
        let bytes = self.read_bytes(response).await?;
        serde_json::from_slice(&bytes)
            .map_err(|error| SdkError::Internal(format!("Invalid API response: {error}")))
    }

    async fn request_no_content<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        access_token: Option<&str>,
    ) -> Result<(), SdkError> {
        tracing::debug!(method = method.as_str(), path, "API request started");
        let mut request = self.client.request(method, self.url(path));
        if let Some(token) = access_token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|error| {
            tracing::warn!(path, "API request failed at network layer");
            SdkError::Network(error.to_string())
        })?;
        tracing::debug!(path, status = response.status().as_u16(), "API response received");
        self.read_no_content(response).await
    }

    async fn read_bytes(&self, response: reqwest::Response) -> Result<Vec<u8>, SdkError> {
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| SdkError::Network(error.to_string()))?
            .to_vec();
        if status.is_success() {
            Ok(bytes)
        } else {
            Err(Self::http_error(status, &bytes))
        }
    }

    async fn read_no_content(&self, response: reqwest::Response) -> Result<(), SdkError> {
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| SdkError::Network(error.to_string()))?
            .to_vec();
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::http_error(status, &bytes))
        }
    }

    fn http_error(status: StatusCode, body: &[u8]) -> SdkError {
        if let Ok(error) = serde_json::from_slice::<ErrorBody>(body) {
            tracing::warn!(
                code = %error.error.code,
                trace_id = %error.trace_id,
                "API request rejected by server"
            );
            return SdkError::Server {
                code: error.error.code,
                text: error.error.text,
                trace_id: error.trace_id,
            };
        }
        tracing::warn!(status = status.as_u16(), "API returned an unreadable error response");
        SdkError::Network(format!("HTTP {status}: {}", String::from_utf8_lossy(body)))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}
