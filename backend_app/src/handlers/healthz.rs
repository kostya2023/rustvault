use axum::Json;
use serde::{Deserialize, Serialize};

#[utoipa::path(
    get,
    path = "/v1/healthz",
    tag = "Health",
    summary = "Check service liveness",
    description = "Returns a small status document when the HTTP service is responding.",
    responses(
        (status = 200, description = "Service is alive", body = crate::api_docs::HealthResponse)
    )
)]
pub async fn healthz() -> Json<HealthzAnswer> {
    Json(HealthzAnswer {
        status: "ok-teapot".to_string(),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthzAnswer {
    pub status: String,
}
