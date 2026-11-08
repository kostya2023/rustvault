use sqlx::{Postgres, Transaction};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
};

use crate::types::{
    app_resources::AppResources,
    errors::{
        AppError, ForbiddenKind, InternalKind, NotFoundKind, UnauthorizedKind,
        UnprocessableEntityKind,
    },
};

#[derive(Debug, Clone)]
pub struct PasskeysService {
    pub resources: AppResources,
}

impl PasskeysService {
    pub fn new(resources: AppResources) -> Self {
        Self { resources }
    }

    pub async fn register_passkey_step1(
        &self,
        username: &str,
        operation_id: &Uuid,
    ) -> Result<CreationChallengeResponse, AppError> {
        let exclude_credentials: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT credential_id FROM user_passkeys WHERE username = $1")
                .bind(username)
                .fetch_all(&self.resources.database)
                .await
                .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;
        let exclude_credentials: Vec<CredentialID> = exclude_credentials
            .into_iter()
            .map(CredentialID::from)
            .collect();

        let unique_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, username.as_bytes());
        let (challenge, state) = self
            .resources
            .webauthn
            .start_passkey_registration(unique_id, username, username, Some(exclude_credentials))
            .map_err(|e| AppError::Internal(InternalKind::WebauthnError(e.to_string())))?;
        let state = serde_json::to_vec(&state)
            .map_err(|e| AppError::Internal(InternalKind::SerdeSerializeError(e.to_string())))?;

        let key = format!("passkey:add:{operation_id}");
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
            .arg("webauthn")
            .arg(&state)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(300)
            .query_async::<()>(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        Ok(challenge)
    }

    pub async fn register_passkey_step2(
        &self,
        operation_id: &Uuid,
        response: &RegisterPublicKeyCredential,
        keyname: &str,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<String, AppError> {
        let key = format!("passkey:add:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let ((username, state),): ((Option<String>, Option<Vec<u8>>),) = redis::pipe()
            .atomic()
            .cmd("HMGET")
            .arg(&key)
            .arg("username")
            .arg("webauthn")
            .cmd("DEL")
            .arg(&key)
            .ignore()
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let (username, state) = match (username, state) {
            (Some(username), Some(state)) => Ok((username, state)),
            _ => Err(AppError::UnprocessableEntity(
                UnprocessableEntityKind::OperationNotFound,
            )),
        }?;

        let state: PasskeyRegistration = serde_json::from_slice(&state)
            .map_err(|e| AppError::Internal(InternalKind::SerdeDeserializeError(e.to_string())))?;

        let passkey = self
            .resources
            .webauthn
            .finish_passkey_registration(response, &state)
            .map_err(|e| {
                AppError::UnprocessableEntity(UnprocessableEntityKind::PasskeyRegistrationError(
                    e.to_string(),
                ))
            })?;
        let credential_id = passkey.cred_id();
        let passkey: serde_json::Value = serde_json::to_value(&passkey)
            .map_err(|e| AppError::Internal(InternalKind::SerdeSerializeError(e.to_string())))?;

        sqlx::query("INSERT INTO user_passkeys (username, credential_id, keyname, passkey) VALUES ($1, $2, $3, $4)")
        .bind(&username)
        .bind(credential_id.to_vec())
        .bind(keyname)
        .bind(passkey)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            AppError::Internal(InternalKind::DatabaseError(e.to_string()))
        })?;

        Ok(username)
    }

    pub async fn auth_login_passkey_step1(
        &self,
        username: &str,
        operation_id: &Uuid,
    ) -> Result<RequestChallengeResponse, AppError> {
        let creds: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT passkey FROM user_passkeys WHERE username = $1")
                .bind(username)
                .fetch_all(&self.resources.database)
                .await
                .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        if creds.is_empty() {
            return Err(AppError::NotFound(NotFoundKind::UserOrPasskeyNotFoundError));
        }

        let creds = creds
            .into_iter()
            .map(serde_json::from_value::<Passkey>)
            .collect::<Result<Vec<Passkey>, _>>()
            .map_err(|e| AppError::Internal(InternalKind::SerdeDeserializeError(e.to_string())))?;

        let (response, state) = self
            .resources
            .webauthn
            .start_passkey_authentication(&creds)
            .map_err(|e| AppError::Internal(InternalKind::WebauthnError(e.to_string())))?;

        let state = serde_json::to_vec(&state)
            .map_err(|e| AppError::Internal(InternalKind::SerdeSerializeError(e.to_string())))?;

        let key = format!("auth:login:passkey:{operation_id}");
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
            .arg("webauthn")
            .arg(state)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(300)
            .query_async::<()>(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
        Ok(response)
    }

    pub async fn auth_login_passkey_step2(
        &self,
        operation_id: &Uuid,
        response: &PublicKeyCredential,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<String, AppError> {
        let key = format!("auth:login:passkey:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let ((username, state),): ((Option<String>, Option<Vec<u8>>),) = redis::pipe()
            .atomic()
            .cmd("HMGET")
            .arg(&key)
            .arg("username")
            .arg("webauthn")
            .cmd("DEL")
            .arg(&key)
            .ignore()
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let (username, state) = match (username, state) {
            (Some(username), Some(state)) => Ok((username, state)),
            _ => Err(AppError::UnprocessableEntity(
                UnprocessableEntityKind::OperationNotFound,
            )),
        }?;

        let state: PasskeyAuthentication = serde_json::from_slice(&state)
            .map_err(|e| AppError::Internal(InternalKind::SerdeDeserializeError(e.to_string())))?;

        let result = self
            .resources
            .webauthn
            .finish_passkey_authentication(response, &state)
            .map_err(|e| {
                AppError::Unauthorized(UnauthorizedKind::LoginWithPasskeyError(e.to_string()))
            })?;

        let cred_id = result.cred_id();
        let passkey: serde_json::Value = sqlx::query_scalar(
            "SELECT passkey FROM user_passkeys WHERE credential_id = $1 AND username = $2 FOR UPDATE"
        ).bind(cred_id.as_slice())
        .bind(&username)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| {
            AppError::Internal(InternalKind::DatabaseError(e.to_string()))
        })?;

        let mut passkey: Passkey = serde_json::from_value(passkey)
            .map_err(|e| AppError::Internal(InternalKind::SerdeDeserializeError(e.to_string())))?;

        passkey.update_credential(&result);

        let passkey: serde_json::Value = serde_json::to_value(&passkey)
            .map_err(|e| AppError::Internal(InternalKind::SerdeSerializeError(e.to_string())))?;

        sqlx::query(
            "UPDATE user_passkeys SET passkey = $1, last_used_at = NOW() WHERE credential_id = $2 AND username = $3"
        ).bind(&passkey)
        .bind(cred_id.as_slice())
        .bind(&username)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            AppError::Internal(InternalKind::DatabaseError(e.to_string()))
        })?;

        Ok(username)
    }

    pub async fn get_auth_login_username(
        &self,
        operation_id: &Uuid,
    ) -> Result<Option<String>, AppError> {
        let key = format!("auth:login:passkey:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
        redis::cmd("HGET")
            .arg(key)
            .arg("username")
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))
    }

    pub async fn auth_passkey_step1(
        &self,
        username: &str,
        operation_id: &Uuid,
    ) -> Result<RequestChallengeResponse, AppError> {
        let creds: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT passkey FROM user_passkeys WHERE username = $1")
                .bind(username)
                .fetch_all(&self.resources.database)
                .await
                .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        if creds.is_empty() {
            return Err(AppError::NotFound(NotFoundKind::UserOrPasskeyNotFoundError));
        }

        let creds = creds
            .into_iter()
            .map(serde_json::from_value::<Passkey>)
            .collect::<Result<Vec<Passkey>, _>>()
            .map_err(|e| AppError::Internal(InternalKind::SerdeDeserializeError(e.to_string())))?;

        let (response, state) = self
            .resources
            .webauthn
            .start_passkey_authentication(&creds)
            .map_err(|e| AppError::Internal(InternalKind::WebauthnError(e.to_string())))?;

        let state = serde_json::to_vec(&state)
            .map_err(|e| AppError::Internal(InternalKind::SerdeSerializeError(e.to_string())))?;

        let key = format!("sudo:passkey:{operation_id}");
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
            .arg("webauthn")
            .arg(state)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(300)
            .query_async::<()>(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
        Ok(response)
    }

    pub async fn auth_passkey_step2(
        &self,
        operation_id: &Uuid,
        username: &str,
        response: &PublicKeyCredential,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), AppError> {
        let key = format!("sudo:passkey:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let ((username_cache, state),): ((Option<String>, Option<Vec<u8>>),) = redis::pipe()
            .atomic()
            .cmd("HMGET")
            .arg(&key)
            .arg("username")
            .arg("webauthn")
            .cmd("DEL")
            .arg(&key)
            .ignore()
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let (username_cache, state) = match (username_cache, state) {
            (Some(username), Some(state)) => Ok((username, state)),
            _ => Err(AppError::UnprocessableEntity(
                UnprocessableEntityKind::OperationNotFound,
            )),
        }?;

        if username != username_cache {
            return Err(AppError::Forbidden(ForbiddenKind::ForeignPasskeyAuth));
        }

        let state: PasskeyAuthentication = serde_json::from_slice(&state)
            .map_err(|e| AppError::Internal(InternalKind::SerdeDeserializeError(e.to_string())))?;

        let result = self
            .resources
            .webauthn
            .finish_passkey_authentication(response, &state)
            .map_err(|e| {
                AppError::Unauthorized(UnauthorizedKind::LoginWithPasskeyError(e.to_string()))
            })?;

        let cred_id = result.cred_id();
        let passkey: serde_json::Value = sqlx::query_scalar(
            "SELECT passkey FROM user_passkeys WHERE credential_id = $1 AND username = $2 FOR UPDATE"
        ).bind(cred_id.as_slice())
        .bind(&username)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| {
            AppError::Internal(InternalKind::DatabaseError(e.to_string()))
        })?;

        let mut passkey: Passkey = serde_json::from_value(passkey)
            .map_err(|e| AppError::Internal(InternalKind::SerdeDeserializeError(e.to_string())))?;

        passkey.update_credential(&result);

        let passkey: serde_json::Value = serde_json::to_value(&passkey)
            .map_err(|e| AppError::Internal(InternalKind::SerdeSerializeError(e.to_string())))?;

        sqlx::query(
            "UPDATE user_passkeys SET passkey = $1, last_used_at = NOW() WHERE credential_id = $2 AND username = $3"
        ).bind(&passkey)
        .bind(cred_id.as_slice())
        .bind(&username)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            AppError::Internal(InternalKind::DatabaseError(e.to_string()))
        })?;

        Ok(())
    }

    pub async fn delete_passkey(
        &self,
        username: &str,
        credential_id: &[u8],
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), AppError> {
        let result =
            sqlx::query("DELETE FROM user_passkeys WHERE username = $1 AND credential_id = $2")
                .bind(username)
                .bind(credential_id)
                .execute(&mut **tx)
                .await
                .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        if result.rows_affected() != 1 {
            return Err(AppError::NotFound(NotFoundKind::UserOrPasskeyNotFoundError));
        }
        Ok(())
    }
}
