pub mod account;
pub mod auth;
pub mod blob;
pub mod healthz;
pub mod security;

// // TEMPLATE!!!
// use std::sync::Arc;
// use axum::{Extension, Json, extract::State, http::HeaderMap};
// use serde::{Deserialize, Serialize};
// use uuid::Uuid;
// use crate::{services::jwtokens::{JWTAccessToken, JWTRefreshToken}, types::{app_state::AppState, errors::AppError}};

// pub async fn handler(
//     State(app_state): State<Arc<AppState>>,
//     Extension(trace_id): Extension<Uuid>,
//     Extension(jwt_access): Extension<JWTAccessToken>,
//     Extension(jwt_refresh): Extension<JWTRefreshToken>,
//     headers: HeaderMap,
//     Json(request): Json<TemplateRequest>,
// ) -> Result<Json<TemplateResponse>, AppError> {
//     // Duty...

//     Ok(Json(TemplateResponse { template: 1 }))
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct TemplateRequest {
//     pub template: i64,
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct TemplateResponse {
//     pub template: i64,
// }
