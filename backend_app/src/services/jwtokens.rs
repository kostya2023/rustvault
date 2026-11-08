use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::types::{
    app_resources::AppResources,
    errors::{AppError, InternalKind, UnauthorizedKind},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct JwtService {
    pub resources: AppResources,
}

impl JwtService {
    pub fn new(resources: AppResources) -> Self {
        Self { resources }
    }

    pub fn generate_pair(&self, username: &str) -> Result<(String, String), AppError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::Internal(InternalKind::GetTimeError(e.to_string())))?
            .as_secs();

        let jti_access = Uuid::new_v4();
        let jti_refresh = Uuid::new_v4();

        let access_claims = JWTAccessToken {
            jti: jti_access,
            jti_ref: jti_refresh,
            sub: username.to_string(),
            exp: now + self.resources.jwt_access_token_ttl,
            nbf: now,
        };

        let refresh_claims = JWTRefreshToken {
            jti: jti_refresh,
            jti_ref: jti_access,
            sub: username.to_string(),
            exp: now + self.resources.jwt_refresh_token_ttl,
            nbf: now,
        };

        let header = Header::new(Algorithm::EdDSA);
        let key = EncodingKey::from_ed_pem(&self.resources.jwt_private_key)
            .map_err(|e| AppError::Internal(InternalKind::JWTokenError(e.to_string())))?;

        let access_token = encode(&header, &access_claims, &key)
            .map_err(|e| AppError::Internal(InternalKind::JWTokenError(e.to_string())))?;
        let refresh_token = encode(&header, &refresh_claims, &key)
            .map_err(|e| AppError::Internal(InternalKind::JWTokenError(e.to_string())))?;

        // Добавляем префиксы, чтобы различать типы токенов на уровне строки
        Ok((format!("a{}", access_token), format!("r{}", refresh_token)))
    }

    pub async fn parse_access(&self, token: &str) -> Result<JWTAccessToken, AppError> {
        let token = token.strip_prefix('a').ok_or_else(|| {
            AppError::Unauthorized(UnauthorizedKind::JWTokenError(
                "Invalid access token prefix.".to_string(),
            ))
        })?;

        let key = DecodingKey::from_ed_pem(&self.resources.jwt_public_key)
            .map_err(|e| AppError::Internal(InternalKind::JWTokenError(e.to_string())))?;
        let claims = decode::<JWTAccessToken>(token, &key, &Self::validation())
            .map_err(|e| AppError::Unauthorized(UnauthorizedKind::JWTokenError(e.to_string())))?
            .claims;

        self.check_not_revoked(claims.jti, claims.jti_ref).await?;

        Ok(claims)
    }

    pub async fn parse_refresh(&self, token: &str) -> Result<JWTRefreshToken, AppError> {
        let token = token.strip_prefix('r').ok_or_else(|| {
            AppError::Unauthorized(UnauthorizedKind::JWTokenError(
                "Invalid refresh token prefix.".to_string(),
            ))
        })?;

        let key = DecodingKey::from_ed_pem(&self.resources.jwt_public_key)
            .map_err(|e| AppError::Internal(InternalKind::JWTokenError(e.to_string())))?;
        let claims = decode::<JWTRefreshToken>(token, &key, &Self::validation())
            .map_err(|e| AppError::Unauthorized(UnauthorizedKind::JWTokenError(e.to_string())))?
            .claims;

        self.check_not_revoked(claims.jti, claims.jti_ref).await?;

        Ok(claims)
    }

    pub async fn revoke_pair_access(&self, token: JWTAccessToken) -> Result<(), AppError> {
        self.revoke_token(token.jti, token.jti_ref, token.exp).await
    }

    pub async fn revoke_pair_refresh(&self, token: JWTRefreshToken) -> Result<(), AppError> {
        self.revoke_token(token.jti, token.jti_ref, token.exp).await
    }

    async fn revoke_token(&self, jti: Uuid, jti_ref: Uuid, exp: u64) -> Result<(), AppError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::Internal(InternalKind::GetTimeError(e.to_string())))?
            .as_secs();
        let ttl = exp.saturating_sub(now) + 30;
        let mut conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
        let key1 = format!("jwts:revoked:{jti}");
        let key2 = format!("jwts:revoked:{jti_ref}");
        redis::pipe()
            .atomic()
            .cmd("SETEX")
            .arg(&key1)
            .arg(ttl)
            .arg(1)
            .cmd("SETEX")
            .arg(&key2)
            .arg(ttl)
            .arg(1)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
        Ok(())
    }

    fn validation() -> Validation {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_nbf = true;
        validation.leeway = 30;
        validation.required_spec_claims = ["jti", "jti_ref", "sub"]
            .into_iter()
            .map(String::from)
            .collect::<HashSet<_>>();
        validation
    }

    async fn check_not_revoked(&self, jti: Uuid, jti_ref: Uuid) -> Result<(), AppError> {
        let mut conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let (revoked_jti, revoked_ref): (bool, bool) = redis::pipe()
            .exists(format!("jwts:revoked:{jti}"))
            .exists(format!("jwts:revoked:{jti_ref}"))
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        if revoked_jti || revoked_ref {
            return Err(AppError::Unauthorized(UnauthorizedKind::JWTokenError(
                "Token revoked.".to_string(),
            )));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTAccessToken {
    pub jti: Uuid,     // Token ID
    pub jti_ref: Uuid, // Refresh token ID
    pub sub: String,   // Username
    pub exp: u64,      // Not after
    pub nbf: u64,      // Not before
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTRefreshToken {
    pub jti: Uuid,     // Token ID
    pub jti_ref: Uuid, // Access token ID
    pub sub: String,   // Username
    pub exp: u64,      // Not after
    pub nbf: u64,      // Not before
}
