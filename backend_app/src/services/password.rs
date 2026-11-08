use crate::types::{
    app_resources::AppResources,
    errors::{
        AppError, BadRequestKind, ForbiddenKind, InternalKind, NotFoundKind, UnauthorizedKind,
        UnprocessableEntityKind,
    },
    opaque_cipher_suite::OpaqueCipherSuite,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, rand::rngs::OsRng,
};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PasswordService {
    pub resources: AppResources,
}

impl PasswordService {
    pub fn new(resources: AppResources) -> Self {
        Self { resources }
    }

    pub async fn register_password_step1(
        &self,
        username: &str,
        password_request: &str,
        operation_id: &Uuid,
    ) -> Result<String, AppError> {
        let registration_request = URL_SAFE_NO_PAD
            .decode(&password_request)
            .map_err(|e| AppError::BadRequest(BadRequestKind::DecodeBase64Error(e.to_string())))?;

        let registration_request = RegistrationRequest::<OpaqueCipherSuite>::deserialize(
            &registration_request,
        )
        .map_err(|e| {
            AppError::BadRequest(BadRequestKind::DeserializeOpaqueStructError(e.to_string()))
        })?;

        let registration_response = ServerRegistration::start(
            &self.resources.opaque,
            registration_request,
            username.as_bytes(),
        )
        .map_err(|e| AppError::Internal(InternalKind::OpaqueError(e.to_string())))?;
        let registration_response = registration_response.message.serialize().to_vec();
        let registration_response = URL_SAFE_NO_PAD.encode(&registration_response);

        let key = format!("auth:register:opaque:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
        redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(&key)
            .arg(username)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(300)
            .query_async::<()>(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        Ok(registration_response)
    }

    pub async fn register_password_step2(
        &self,
        operation_id: &Uuid,
        password_upload: &str,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<String, AppError> {
        let key = format!("auth:register:opaque:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
        let (username, _): (Option<String>, i32) = redis::pipe()
            .atomic()
            .cmd("GET")
            .arg(&key)
            .cmd("DEL")
            .arg(&key)
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let username = match username {
            Some(username) => Ok(username),
            None => Err(AppError::UnprocessableEntity(
                UnprocessableEntityKind::OperationNotFound,
            )),
        }?;

        let password_upload = URL_SAFE_NO_PAD
            .decode(&password_upload)
            .map_err(|e| AppError::BadRequest(BadRequestKind::DecodeBase64Error(e.to_string())))?;
        let password_upload = RegistrationUpload::<OpaqueCipherSuite>::deserialize(
            &password_upload,
        )
        .map_err(|e| {
            AppError::BadRequest(BadRequestKind::DeserializeOpaqueStructError(e.to_string()))
        })?;

        let server_registration = ServerRegistration::<OpaqueCipherSuite>::finish(password_upload);
        let server_registration = server_registration.serialize().to_vec();

        sqlx::query("INSERT INTO user_opaque (username, password) VALUES ($1, $2)")
            .bind(&username)
            .bind(&server_registration)
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        Ok(username)
    }

    pub async fn update_password_step2(
        &self,
        operation_id: &Uuid,
        password_upload: &str,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<String, AppError> {
        let key = format!("auth:register:opaque:{operation_id}");
        let mut redis_conn = self
            .resources
            .cache
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
        let username: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;
        let username = username.ok_or(AppError::UnprocessableEntity(
            UnprocessableEntityKind::OperationNotFound,
        ))?;

        let password_upload = URL_SAFE_NO_PAD
            .decode(password_upload)
            .map_err(|e| AppError::BadRequest(BadRequestKind::DecodeBase64Error(e.to_string())))?;
        let password_upload = RegistrationUpload::<OpaqueCipherSuite>::deserialize(
            &password_upload,
        )
        .map_err(|e| {
            AppError::BadRequest(BadRequestKind::DeserializeOpaqueStructError(e.to_string()))
        })?;
        let password_file = ServerRegistration::<OpaqueCipherSuite>::finish(password_upload)
            .serialize()
            .to_vec();

        let result = sqlx::query("UPDATE user_opaque SET password = $1 WHERE username = $2")
            .bind(password_file)
            .bind(&username)
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;
        if result.rows_affected() != 1 {
            return Err(AppError::NotFound(NotFoundKind::UserOrOpaqueNotFoundError));
        }

        Ok(username)
    }

    pub async fn auth_login_password_step1(
        &self,
        username: &str,
        password_request: &str,
        operation_id: &Uuid,
    ) -> Result<String, AppError> {
        let login_request = URL_SAFE_NO_PAD
            .decode(&password_request)
            .map_err(|e| AppError::BadRequest(BadRequestKind::DecodeBase64Error(e.to_string())))?;

        let login_request = CredentialRequest::<OpaqueCipherSuite>::deserialize(&login_request)
            .map_err(|e| {
                AppError::BadRequest(BadRequestKind::DeserializeOpaqueStructError(e.to_string()))
            })?;

        let password_file: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT password FROM user_opaque WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.resources.database)
                .await
                .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        let password_file = match password_file {
            Some(file) => Ok(file),
            None => Err(AppError::NotFound(NotFoundKind::UserOrOpaqueNotFoundError)),
        }?;

        let password_file = ServerRegistration::<OpaqueCipherSuite>::deserialize(&password_file)
            .map_err(|e| AppError::Internal(InternalKind::OpaqueError(e.to_string())))?;

        let mut rng = OsRng;
        let login = ServerLogin::<OpaqueCipherSuite>::start(
            &mut rng,
            &self.resources.opaque,
            Some(password_file),
            login_request,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|e| AppError::Internal(InternalKind::OpaqueError(e.to_string())))?;

        let response = login.message.serialize().to_vec();
        let response = URL_SAFE_NO_PAD.encode(&response);
        let state = login.state.serialize().to_vec();

        let key = format!("auth:login:opaque:{operation_id}");
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
            .arg("opaque")
            .arg(state)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(300)
            .query_async::<()>(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        Ok(response)
    }

    pub async fn auth_login_password_step2(
        &self,
        password_upload: &str,
        operation_id: &Uuid,
    ) -> Result<String, AppError> {
        let key = format!("auth:login:opaque:{operation_id}");
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
            .arg("opaque")
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

        let state = ServerLogin::<OpaqueCipherSuite>::deserialize(&state)
            .map_err(|e| AppError::Internal(InternalKind::OpaqueError(e.to_string())))?;

        let password_upload = URL_SAFE_NO_PAD
            .decode(password_upload)
            .map_err(|e| AppError::BadRequest(BadRequestKind::DecodeBase64Error(e.to_string())))?;

        let password_upload = CredentialFinalization::<OpaqueCipherSuite>::deserialize(
            &password_upload,
        )
        .map_err(|e| {
            AppError::BadRequest(BadRequestKind::DeserializeOpaqueStructError(e.to_string()))
        })?;

        state
            .finish(password_upload, ServerLoginParameters::default())
            .map_err(|e| {
                AppError::Unauthorized(UnauthorizedKind::LoginWithPasswordError(e.to_string()))
            })?;

        Ok(username)
    }

    pub async fn get_auth_login_username(
        &self,
        operation_id: &Uuid,
    ) -> Result<Option<String>, AppError> {
        let key = format!("auth:login:opaque:{operation_id}");
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

    pub async fn auth_password_step1(
        &self,
        username: &str,
        password_request: &str,
        operation_id: &Uuid,
    ) -> Result<String, AppError> {
        let login_request = URL_SAFE_NO_PAD
            .decode(&password_request)
            .map_err(|e| AppError::BadRequest(BadRequestKind::DecodeBase64Error(e.to_string())))?;

        let login_request = CredentialRequest::<OpaqueCipherSuite>::deserialize(&login_request)
            .map_err(|e| {
                AppError::BadRequest(BadRequestKind::DeserializeOpaqueStructError(e.to_string()))
            })?;

        let password_file: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT password FROM user_opaque WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.resources.database)
                .await
                .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        let password_file = match password_file {
            Some(file) => Ok(file),
            None => Err(AppError::NotFound(NotFoundKind::UserOrOpaqueNotFoundError)),
        }?;

        let password_file = ServerRegistration::<OpaqueCipherSuite>::deserialize(&password_file)
            .map_err(|e| AppError::Internal(InternalKind::OpaqueError(e.to_string())))?;

        let mut rng = OsRng;
        let login = ServerLogin::<OpaqueCipherSuite>::start(
            &mut rng,
            &self.resources.opaque,
            Some(password_file),
            login_request,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|e| AppError::Internal(InternalKind::OpaqueError(e.to_string())))?;

        let response = login.message.serialize().to_vec();
        let response = URL_SAFE_NO_PAD.encode(&response);
        let state = login.state.serialize().to_vec();

        let key = format!("opaque:auth:{operation_id}");
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
            .arg("opaque")
            .arg(state)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(300)
            .query_async::<()>(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        Ok(response)
    }

    pub async fn auth_password_step2(
        &self,
        username: &str,
        password_upload: &str,
        operation_id: &Uuid,
    ) -> Result<(), AppError> {
        let key = format!("opaque:auth:{operation_id}");
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
            .arg("opaque")
            .cmd("DEL")
            .arg(&key)
            .ignore()
            .query_async(&mut redis_conn)
            .await
            .map_err(|e| AppError::Internal(InternalKind::CacheError(e.to_string())))?;

        let (username_cache, state) = match (username_cache, state) {
            (Some(username_cache), Some(state)) => Ok((username_cache, state)),
            _ => Err(AppError::UnprocessableEntity(
                UnprocessableEntityKind::OperationNotFound,
            )),
        }?;

        if username != username_cache {
            return Err(AppError::Forbidden(ForbiddenKind::ForeignPasswordAuth));
        }

        let state = ServerLogin::<OpaqueCipherSuite>::deserialize(&state)
            .map_err(|e| AppError::Internal(InternalKind::OpaqueError(e.to_string())))?;

        let password_upload = URL_SAFE_NO_PAD
            .decode(password_upload)
            .map_err(|e| AppError::BadRequest(BadRequestKind::DecodeBase64Error(e.to_string())))?;

        let password_upload = CredentialFinalization::<OpaqueCipherSuite>::deserialize(
            &password_upload,
        )
        .map_err(|e| {
            AppError::BadRequest(BadRequestKind::DeserializeOpaqueStructError(e.to_string()))
        })?;

        state
            .finish(password_upload, ServerLoginParameters::default())
            .map_err(|e| {
                AppError::Unauthorized(UnauthorizedKind::LoginWithPasswordError(e.to_string()))
            })?;

        Ok(())
    }
}
