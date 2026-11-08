use sqlx::{Postgres, Transaction};

use crate::types::{
    app_resources::AppResources,
    errors::{AppError, ConflictKind, InternalKind},
};

#[derive(Debug, Clone)]
pub struct AccountService {
    pub resources: AppResources,
}

impl AccountService {
    pub fn new(resources: AppResources) -> Self {
        Self { resources }
    }

    pub async fn check_user_exists(&self, username: &str) -> Result<bool, AppError> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)")
                .bind(username)
                .fetch_one(&self.resources.database)
                .await
                .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        Ok(exists)
    }

    pub async fn create_user(
        &self,
        username: &str,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), AppError> {
        if self.check_user_exists(username).await? {
            return Err(AppError::Conflict(ConflictKind::UserAlreadyExists));
        }

        sqlx::query("INSERT INTO users (username) VALUES ($1)")
            .bind(username)
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;
        Ok(())
    }

    pub async fn delete_user_cascade(
        &self,
        username: &str,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), AppError> {
        if !self.check_user_exists(username).await? {
            return Err(AppError::NotFound(
                crate::types::errors::NotFoundKind::UserNotFound,
            ));
        }

        let result = sqlx::query("DELETE FROM users WHERE username = $1")
            .bind(username)
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        if result.rows_affected() != 1 {
            return Err(AppError::NotFound(
                crate::types::errors::NotFoundKind::UserNotFound,
            ));
        }
        Ok(())
    }
}
