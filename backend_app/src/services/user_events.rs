use crate::types::{
    app_resources::AppResources,
    errors::{AppError, InternalKind, NotFoundKind, REQUEST_ERROR_CONTEXT},
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction, Type, prelude::FromRow};
use std::net::IpAddr;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UserEventService {
    pub resources: AppResources,
}

impl UserEventService {
    pub fn new(resources: AppResources) -> Self {
        Self { resources }
    }

    pub async fn record_event(
        &self,
        username: &str,
        event_type: EventType,
        trace_id: &Uuid,
        operation_id: Option<&Uuid>,
    ) -> Result<(), AppError> {
        let mut tx = self
            .resources
            .database
            .begin()
            .await
            .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        self.create_event(
            username,
            event_type,
            None,
            None,
            None,
            Some(trace_id),
            operation_id,
            &mut tx,
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;
        Ok(())
    }

    pub async fn record_failure(
        &self,
        username: &str,
        event_type: EventType,
        trace_id: &Uuid,
        operation_id: Option<&Uuid>,
        action_error: AppError,
    ) -> AppError {
        if let Err(event_error) = self
            .record_event(username, event_type, trace_id, operation_id)
            .await
        {
            tracing::error!(
                trace_id = %trace_id,
                username,
                error = ?event_error,
                "Failed to persist the failed-action user event"
            );
        }
        action_error
    }

    pub async fn get_events(
        &self,
        username: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserEvent>, AppError> {
        let events: Vec<UserEvent> = sqlx::query_as(
            "SELECT * FROM user_events WHERE username = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        ).bind(username)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.resources.database)
        .await
        .map_err(|e| {
            AppError::Internal(InternalKind::DatabaseError(e.to_string()))
        })?;

        Ok(events)
    }

    pub async fn create_event(
        &self,
        username: &str,
        event_type: EventType,
        ip_address: Option<&IpAddr>,
        user_agent: Option<&str>,
        event_text: Option<&str>,
        trace_id: Option<&Uuid>,
        operation_id: Option<&Uuid>,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), AppError> {
        let id = Uuid::new_v4();
        let (request_ip_address, request_user_agent) = REQUEST_ERROR_CONTEXT
            .try_with(|context| {
                (
                    *context.ip_address.borrow(),
                    context.user_agent.borrow().clone(),
                )
            })
            .unwrap_or((None, None));
        let ip_address = ip_address.or(request_ip_address.as_ref());
        let user_agent = user_agent.or(request_user_agent.as_deref());
        sqlx::query(
            "INSERT INTO user_events (username, id, event_type, ip_address, user_agent, event_text, trace_id, operation_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        ).bind(username)
        .bind(&id)
        .bind(event_type)
        .bind(ip_address)
        .bind(user_agent)
        .bind(event_text)
        .bind(trace_id)
        .bind(operation_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            AppError::Internal(InternalKind::DatabaseError(e.to_string()))
        })?;
        Ok(())
    }

    pub async fn delete_event(
        &self,
        username: &str,
        id: &Uuid,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM user_events WHERE username = $1 AND id = $2")
            .bind(username)
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        if result.rows_affected() != 1 {
            return Err(AppError::NotFound(NotFoundKind::UserEventNotFound));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserEvent {
    pub username: String,
    pub id: Uuid,
    pub event_type: EventType,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub event_text: Option<String>,
    pub trace_id: Option<Uuid>,
    pub operation_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "EVENTS", rename_all = "snake_case")]
pub enum EventType {
    // Account lifecycle
    SudoAccountCreated,
    SudoAccountDeletedWithPasskey,
    SudoAccountDeletedWithPasstotp,
    SudoAccountDeleteFailedWithPasskey,
    SudoAccountDeleteFailedWithPasstotp,

    // Authentication
    LoginWithPasskey,
    LoginWithPasstotp,
    LoginFailedWithPasskey,
    LoginFailedWithPasstotp,
    Logout,
    TokenRefresh,

    // Password management
    SudoPasswordUpdatedWithPasskey,
    SudoPasswordUpdatedWithTotp,
    SudoPasswordUpdateFailedWithPasskey,
    SudoPasswordUpdateFailedWithTotp,

    // TOTP management
    SudoTotpUpdatedWithPasskey,
    SudoTotpUpdatedWithPassword,
    SudoTotpUpdateFailedWithPasskey,
    SudoTotpUpdateFailedWithPassword,

    // Passkey management
    SudoPasskeyRegisteredWithTotp,
    SudoPasskeyRegisteredWithPassword,
    SudoPasskeyDeletedWithTotp,
    SudoPasskeyDeletedWithPassword,
    SudoPasskeyRegisterFailedWithTotp,
    SudoPasskeyRegisterFailedWithPassword,
    SudoPasskeyDeleteFailedWithTotp,
    SudoPasskeyDeleteFailedWithPassword,

    // Encrypted vault
    BlobCreated,
    BlobUpdated,
    BlobAccessed,
}
