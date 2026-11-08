use crate::types::errors::{AppError, InternalKind};
use num_traits::PrimInt;
use std::str::FromStr;

// ============================================================================
// Environment variable names
// ============================================================================

// App
pub const APP_PORT: &str = "APP_PORT";

// Database
pub const DATABASE_HOST: &str = "DATABASE_HOST";
pub const DATABASE_PORT: &str = "DATABASE_PORT";
pub const DATABASE_DB: &str = "DATABASE_DB";
pub const DATABASE_USER: &str = "DATABASE_USER";
pub const DATABASE_PASSWORD: &str = "DATABASE_PASSWORD";
pub const DATABASE_MAX_CONNECTIONS: &str = "DATABASE_MAX_CONNECTIONS";
pub const DATABASE_ACQUIRE_TIMEOUT: &str = "DATABASE_ACQUIRE_TIMEOUT";

// Cache
pub const CACHE_HOST: &str = "CACHE_HOST";
pub const CACHE_PORT: &str = "CACHE_PORT";
pub const CACHE_PASSWORD: &str = "CACHE_PASSWORD";

// Blob
pub const BLOB_HOST: &str = "BLOB_HOST";
pub const BLOB_PORT: &str = "BLOB_PORT";
pub const BLOB_USER: &str = "BLOB_USER";
pub const BLOB_PASSWORD: &str = "BLOB_PASSWORD";
pub const BLOB_BUCKET: &str = "BLOB_BUCKET";
pub const BLOB_MAX_SIZE: &str = "BLOB_MAX_SIZE";

// JWT
pub const JWT_PRIVATE_KEY: &str = "JWT_PRIVATE_KEY";
pub const JWT_PUBLIC_KEY: &str = "JWT_PUBLIC_KEY";
pub const JWT_ACCESS_TOKEN_TTL: &str = "JWT_ACCESS_TOKEN_TTL";
pub const JWT_REFRESH_TOKEN_TTL: &str = "JWT_REFRESH_TOKEN_TTL";

// TOTP
pub const TOTP_CRYPT_KEY: &str = "TOTP_CRYPT_KEY";

// OPAQUE
pub const OPAQUE_SERVER_SETUP: &str = "OPAQUE_SERVER_SETUP";

// WebAuthn
pub const WEBAUTHN_RP_ID: &str = "WEBAUTHN_RP_ID";
pub const WEBAUTHN_RP_ORIGIN: &str = "WEBAUTHN_RP_ORIGIN";
pub const WEBAUTHN_RP_NAME: &str = "WEBAUTHN_RP_NAME";

// ============================================================================
// InitConfig
// ============================================================================

#[derive(Debug, Clone)]
pub struct InitConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub cache: CacheConfig,
    pub blob: BlobConfig,
    pub jwtoken: JWTokenConfig,
    pub totp: TotpConfig,
    pub opaque: OpaqueConfig,
    pub webauthn: WebauthnConfig,
}

impl InitConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            server: ServerConfig::from_env()?,
            database: DatabaseConfig::from_env()?,
            cache: CacheConfig::from_env()?,
            blob: BlobConfig::from_env()?,
            jwtoken: JWTokenConfig::from_env()?,
            totp: TotpConfig::from_env()?,
            opaque: OpaqueConfig::from_env()?,
            webauthn: WebauthnConfig::from_env()?,
        })
    }
}

// ============================================================================
// ServerConfig
// ============================================================================

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub port: u16,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            port: get_from_env_integer(APP_PORT)?,
        })
    }
}

// ============================================================================
// DatabaseConfig
// ============================================================================

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
    pub max_connections: u32,
    pub acquire_timeout: u64,
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            host: get_from_env(DATABASE_HOST)?,
            port: get_from_env_integer(DATABASE_PORT)?,
            database: get_from_env(DATABASE_DB)?,
            user: get_from_env(DATABASE_USER)?,
            password: get_from_env(DATABASE_PASSWORD)?,
            max_connections: get_from_env_integer(DATABASE_MAX_CONNECTIONS)?,
            acquire_timeout: get_from_env_integer(DATABASE_ACQUIRE_TIMEOUT)?,
        })
    }
}

// ============================================================================
// CacheConfig
// ============================================================================

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub host: String,
    pub port: u16,
    pub password: String,
}

impl CacheConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            host: get_from_env(CACHE_HOST)?,
            port: get_from_env_integer(CACHE_PORT)?,
            password: get_from_env(CACHE_PASSWORD)?,
        })
    }
}

// ============================================================================
// BlobConfig
// ============================================================================

#[derive(Debug, Clone)]
pub struct BlobConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub bucket: String,
    pub max_size: u64,
}

impl BlobConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            host: get_from_env(BLOB_HOST)?,
            port: get_from_env_integer(BLOB_PORT)?,
            user: get_from_env(BLOB_USER)?,
            password: get_from_env(BLOB_PASSWORD)?,
            bucket: get_from_env(BLOB_BUCKET)?,
            max_size: get_from_env_integer(BLOB_MAX_SIZE)?,
        })
    }
}

// ============================================================================
// JWTokenConfig
// ============================================================================

#[derive(Debug, Clone)]
pub struct JWTokenConfig {
    pub private_key: String,
    pub public_key: String,
    pub access_token_ttl: u64,
    pub refresh_token_ttl: u64,
}

impl JWTokenConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            private_key: get_from_env(JWT_PRIVATE_KEY)?,
            public_key: get_from_env(JWT_PUBLIC_KEY)?,
            access_token_ttl: get_from_env_integer(JWT_ACCESS_TOKEN_TTL)?,
            refresh_token_ttl: get_from_env_integer(JWT_REFRESH_TOKEN_TTL)?,
        })
    }
}

// ============================================================================
// TotpConfig
// ============================================================================

#[derive(Debug, Clone)]
pub struct TotpConfig {
    pub crypt_key: String,
}

impl TotpConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            crypt_key: get_from_env(TOTP_CRYPT_KEY)?,
        })
    }
}

// ============================================================================
// OpaqueConfig
// ============================================================================

#[derive(Debug, Clone)]
pub struct OpaqueConfig {
    pub server_setup: String,
}

impl OpaqueConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            server_setup: get_from_env(OPAQUE_SERVER_SETUP)?,
        })
    }
}

// ============================================================================
// WebauthnConfig
// ============================================================================

#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
}

impl WebauthnConfig {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Self {
            rp_id: get_from_env(WEBAUTHN_RP_ID)?,
            rp_origin: get_from_env(WEBAUTHN_RP_ORIGIN)?,
            rp_name: get_from_env(WEBAUTHN_RP_NAME)?,
        })
    }
}

// ============================================================================
// Environment helpers
// ============================================================================

fn get_from_env(key: &str) -> Result<String, AppError> {
    std::env::var(key).map_err(|error| {
        AppError::Internal(InternalKind::InitError(format!(
            "Failed to read environment variable {key}: {error}"
        )))
    })
}

fn get_from_env_integer<Integer>(key: &str) -> Result<Integer, AppError>
where
    Integer: PrimInt + FromStr,
    <Integer as FromStr>::Err: std::fmt::Display,
{
    let value = get_from_env(key)?;

    value.parse::<Integer>().map_err(|error| {
        AppError::Internal(InternalKind::InitError(format!(
            "Invalid integer value for environment variable {key}: {error}"
        )))
    })
}
