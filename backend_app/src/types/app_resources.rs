use crate::types::{
    errors::{AppError, InternalKind},
    init_config::InitConfig,
    opaque_cipher_suite::OpaqueCipherSuite,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use minio::s3::{MinioClient, creds::StaticProvider, http::BaseUrl};
use opaque_ke::ServerSetup;
use redis::Client as RedisClient;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::time::Duration;
use url::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder};

#[derive(Debug, Clone)]
pub struct AppResources {
    pub database: PgPool,
    pub cache: RedisClient,
    pub opaque: ServerSetup<OpaqueCipherSuite>,
    pub webauthn: Webauthn,
    pub blob: MinioClient,

    pub totp_crypt_key: Vec<u8>,
    pub jwt_private_key: Vec<u8>,
    pub jwt_public_key: Vec<u8>,
    pub jwt_access_token_ttl: u64,
    pub jwt_refresh_token_ttl: u64,

    pub blob_bucket_name: String,
    pub blob_max_size: u64,
}

impl AppResources {
    pub async fn from_init_config(config: &InitConfig) -> Result<Self, AppError> {
        // Setup db
        let db_options = PgConnectOptions::new()
            .host(&config.database.host)
            .port(config.database.port)
            .username(&config.database.user)
            .password(&config.database.password)
            .database(&config.database.database);
        let database = PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .acquire_timeout(Duration::from_secs(config.database.acquire_timeout))
            .connect_with(db_options)
            .await
            .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;

        // Redis
        let redis_url = format!(
            "redis://:{}@{}:{}/",
            config.cache.password, config.cache.host, config.cache.port
        );
        let cache = RedisClient::open(redis_url)
            .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;

        // Opaque setup
        let opaque = STANDARD
            .decode(&config.opaque.server_setup)
            .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;
        let opaque = ServerSetup::<OpaqueCipherSuite>::deserialize(&opaque)
            .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;

        // Webauthn
        let webauthn = WebauthnBuilder::new(
            &config.webauthn.rp_id,
            &config
                .webauthn
                .rp_origin
                .parse::<Url>()
                .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?,
        )
        .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?
        .rp_name(&config.webauthn.rp_name)
        .build()
        .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;

        // Minio
        let base_url = format!("http://{}:{}", config.blob.host, config.blob.port)
            .parse::<BaseUrl>()
            .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;
        let provider = StaticProvider::new(&config.blob.user, &config.blob.password, None);
        let blob = MinioClient::new(base_url, Some(provider), None, None)
            .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;

        // Consts
        let totp_crypt_key = STANDARD
            .decode(&config.totp.crypt_key)
            .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;
        let jwt_private_key = STANDARD
            .decode(&config.jwtoken.private_key)
            .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;
        let jwt_public_key = STANDARD
            .decode(&config.jwtoken.public_key)
            .map_err(|e| AppError::Internal(InternalKind::InitError(e.to_string())))?;
        let blob_bucket_name = config.blob.bucket.clone();
        let blob_max_size = config.blob.max_size;
        let jwt_access_token_ttl = config.jwtoken.access_token_ttl;
        let jwt_refresh_token_ttl = config.jwtoken.refresh_token_ttl;

        Ok(Self {
            database,
            cache,
            opaque,
            webauthn,
            blob,
            totp_crypt_key,
            jwt_private_key,
            jwt_public_key,
            jwt_access_token_ttl,
            jwt_refresh_token_ttl,
            blob_bucket_name,
            blob_max_size,
        })
    }
}
