use crate::types::{
    app_resources::AppResources,
    errors::{AppError, ForbiddenKind, InternalKind, NotFoundKind, UnauthorizedKind},
};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use sqlx::{Postgres, Transaction};
use totp_rs::Builder;
use totp_rs::{Algorithm, Secret, Totp};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TotpService {
    pub resources: AppResources,
}

impl TotpService {
    pub fn new(resources: AppResources) -> Self {
        Self { resources }
    }

    pub async fn register_totp_step1(
        &self,
        username: &str,
        operation_id: &Uuid,
    ) -> Result<String, AppError> {
        let mut random = [42u8; 64];
        rand::fill(&mut random);
        let secret = Secret::new(Box::new(random));

        let totp: Totp = Builder::new()
            .with_account_name(username)
            .with_algorithm(Algorithm::SHA1)
            .with_digits(8)
            .with_skew(1)
            .with_step_duration(30)
            .with_issuer(Some("RustVault"))
            .with_secret(secret)
            .build()
            .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

        let totp_url = totp
            .to_url()
            .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

        let encoded = encode_data(&self.resources.totp_crypt_key, totp_url.as_bytes())?;

        let key = format!("auth:register:totp:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(&key)
            .arg("username")
            .arg(username)
            .arg("totp")
            .arg(&encoded)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(300)
            .query_async::<()>(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        Ok(totp_url)
    }

    pub async fn register_totp_step2(
        &self,
        operation_id: &Uuid,
        totp_code: &str,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<String, AppError> {
        let key = format!("auth:register:totp:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let ((username, totp),): ((Option<String>, Option<Vec<u8>>),) = redis::pipe()
            .atomic()
            .cmd("HMGET")
            .arg(&key)
            .arg("username")
            .arg("totp")
            .cmd("DEL")
            .arg(&key)
            .ignore()
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let (username, totp_enc) = match (username, totp) {
            (Some(username), Some(totp)) => Ok((username, totp)),
            _ => Err(AppError::NotFound(NotFoundKind::UserOrTotpNotFoundError)),
        }?;

        let totp = decode_data(&self.resources.totp_crypt_key, &totp_enc)?;

        let totp_url = String::from_utf8(totp)
            .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;
        let totp = Totp::from_url(totp_url)
            .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

        totp.check_current(totp_code).ok_or(AppError::Unauthorized(
            UnauthorizedKind::VerifyTotpError("Test totp code invalid.".to_string()),
        ))?;

        sqlx::query("INSERT INTO user_totp (username, totp) VALUES ($1, $2)")
            .bind(&username)
            .bind(&totp_enc)
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        Ok(username)
    }

    pub async fn update_totp_step1(
        &self,
        username: &str,
        operation_id: &Uuid,
    ) -> Result<String, AppError> {
        let mut random = [42u8; 64];
        rand::fill(&mut random);
        let secret = Secret::new(Box::new(random));

        let totp: Totp = Builder::new()
            .with_account_name(username)
            .with_algorithm(Algorithm::SHA1)
            .with_digits(8)
            .with_skew(1)
            .with_step_duration(30)
            .with_issuer(Some("RustVault"))
            .with_secret(secret)
            .build()
            .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

        let totp_url = totp
            .to_url()
            .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

        let encoded = encode_data(&self.resources.totp_crypt_key, totp_url.as_bytes())?;

        let key = format!("totp:update:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(&key)
            .arg("username")
            .arg(username)
            .arg("totp")
            .arg(&encoded)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(300)
            .query_async::<()>(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        Ok(totp_url)
    }

    pub async fn update_totp_step2(
        &self,
        operation_id: &Uuid,
        totp_code: &str,
        username: &str,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), AppError> {
        let key = format!("totp:update:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let ((username_state, totp),): ((Option<String>, Option<Vec<u8>>),) = redis::pipe()
            .atomic()
            .cmd("HMGET")
            .arg(&key)
            .arg("username")
            .arg("totp")
            .cmd("DEL")
            .arg(&key)
            .ignore()
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let (username_state, totp_enc) = match (username_state, totp) {
            (Some(username), Some(totp)) => Ok((username, totp)),
            _ => Err(AppError::NotFound(NotFoundKind::UserOrTotpNotFoundError)),
        }?;

        if username != username_state {
            return Err(AppError::Forbidden(ForbiddenKind::ForeignTotpAuth));
        }

        let totp = decode_data(&self.resources.totp_crypt_key, &totp_enc)?;

        let totp_url = String::from_utf8(totp)
            .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;
        let totp = Totp::from_url(totp_url)
            .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

        totp.check_current(totp_code).ok_or(AppError::Unauthorized(
            UnauthorizedKind::VerifyTotpError("Test totp code invalid.".to_string()),
        ))?;

        let result = sqlx::query("UPDATE user_totp SET totp = $1 WHERE username = $2")
            .bind(&totp_enc)
            .bind(&username)
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        if result.rows_affected() != 1 {
            return Err(AppError::Internal(InternalKind::DatabaseError(format!(
                "Error while update totp in db. Rows affected: {}",
                result.rows_affected()
            ))));
        }

        Ok(())
    }

    pub async fn auth_login_totp(&self, username: &str, totp_code: &str) -> Result<(), AppError> {
        let totp: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT totp FROM user_totp WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.resources.database)
                .await
                .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        let totp = match totp {
            Some(totp) => Ok(totp),
            None => Err(AppError::NotFound(NotFoundKind::UserOrTotpNotFoundError)),
        }?;

        let totp_url = decode_data(&self.resources.totp_crypt_key, &totp)?;
        let totp_url = String::from_utf8(totp_url)
            .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;
        let totp = Totp::from_url(totp_url)
            .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

        totp.check_current(totp_code).ok_or(AppError::Unauthorized(
            UnauthorizedKind::VerifyTotpError("Test totp code invalid.".to_string()),
        ))?;

        Ok(())
    }
}

fn encode_data(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut nonce = [0u8; 24];
    rand::fill(&mut nonce);

    let nonce_object = XNonce::from(nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

    let ciphertext = cipher
        .encrypt(&nonce_object, plaintext)
        .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

    let mut result = Vec::with_capacity(24 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decode_data(key: &[u8], data: &[u8]) -> Result<Vec<u8>, AppError> {
    if data.len() < 40 {
        return Err(AppError::Internal(InternalKind::TotpError(format!(
            "Invalid ciphertext length. Expected >= 40, got: {}",
            data.len()
        ))));
    }

    let (nonce_bytes, ciphertext) = data.split_at(24);

    let nonce = XNonce::try_from(nonce_bytes)
        .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| AppError::Internal(InternalKind::TotpError(e.to_string())))?;

    Ok(plaintext)
}
