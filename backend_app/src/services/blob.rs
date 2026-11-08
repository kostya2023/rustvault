use bytes::Bytes;
use minio::s3::{segmented_bytes::SegmentedBytes, types::S3Api};
use sqlx::{Postgres, Transaction};

use crate::types::{
    app_resources::AppResources, errors::{AppError, BadRequestKind, InternalKind, NotFoundKind, UnprocessableEntityKind},
};
use serde::Serialize;
use sqlx::FromRow;
use time::OffsetDateTime;

pub const BLOB_TEMPLATE: &[u8; 8] = b"TEMPLATE";

#[derive(Debug, Clone)]
pub struct BlobService {
    pub resources: AppResources,
}

impl BlobService {
    pub fn new(resources: AppResources) -> Self {
        Self { resources }
    }

    pub async fn check_bucket_exists(&self, bucket_name: &str) -> Result<bool, AppError> {
        let response = self
            .resources
            .blob
            .bucket_exists(bucket_name)
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?
            .build()
            .send()
            .await
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?;

        Ok(response.exists())
    }

    pub async fn create_bucket(&self, bucket_name: &str) -> Result<(), AppError> {
        let exists = self.check_bucket_exists(bucket_name).await?;
        if exists {
            return Err(AppError::Internal(InternalKind::BlobError(format!(
                "Bucket '{bucket_name} already exists.'"
            ))));
        }

        self.resources
            .blob
            .create_bucket(bucket_name)
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?
            .build()
            .send()
            .await
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?;

        Ok(())
    }

    pub async fn create_blob(
        &self,
        username: &str,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), AppError> {
        let blob_len = BLOB_TEMPLATE.len() as i64;
        let blob_hash = blake3::hash(BLOB_TEMPLATE);

        sqlx::query(
            "INSERT INTO user_blob (username, hash_blake3, version, size)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(username)
        .bind(blob_hash.as_bytes().as_slice())
        .bind(0_i32)
        .bind(blob_len)
        .execute(&mut **tx)
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        self.resources
            .blob
            .put_object(
                &self.resources.blob_bucket_name,
                username,
                SegmentedBytes::from(Bytes::from_static(BLOB_TEMPLATE)),
            )
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?
            .build()
            .send()
            .await
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?;

        Ok(())
    }

    pub async fn update_blob(
        &self,
        username: &str,
        blob: &[u8],
        version: i64,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), AppError> {
        // Validate blob size.
        let blob_len = i64::try_from(blob.len()).map_err(|_| {
            AppError::UnprocessableEntity(UnprocessableEntityKind::BlobVeryLargeError(
                self.resources.blob_max_size as i64,
                i64::MAX,
            ))
        })?;

        if blob.len() as u64 > self.resources.blob_max_size {
            return Err(AppError::UnprocessableEntity(
                UnprocessableEntityKind::BlobVeryLargeError(
                    self.resources.blob_max_size as i64,
                    blob_len,
                ),
            ));
        }

        // Validate requested version.
        if version < 0 {
            return Err(AppError::BadRequest(
                BadRequestKind::MissingOrInvalidBlobVersion,
            ));
        }

        // Lock the row until the caller commits or rolls back.
        let current_version: i64 = sqlx::query_scalar(
            "SELECT version
         FROM user_blob
         WHERE username = $1
         FOR UPDATE",
        )
        .bind(username)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?
        .ok_or_else(|| {
            AppError::Internal(InternalKind::DatabaseError(
                "Blob record does not exist.".to_owned(),
            ))
        })?;

        // Require a strictly increasing version.
        if version <= current_version {
            return Err(AppError::UnprocessableEntity(
                UnprocessableEntityKind::BlobVersionNotIncreasingError(current_version, version),
            ));
        }

        // Calculate BLAKE3 hash.
        let blob_hash = blake3::hash(blob);

        // Update metadata inside the caller's transaction.
        sqlx::query(
            "UPDATE user_blob
         SET hash_blake3 = $1,
             version = $2,
             size = $3
         WHERE username = $4",
        )
        .bind(blob_hash.as_bytes().as_slice())
        .bind(version)
        .bind(blob_len)
        .bind(username)
        .execute(&mut **tx)
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?;

        // Upload the new blob to MinIO.
        self.resources
            .blob
            .put_object(
                &self.resources.blob_bucket_name,
                username,
                SegmentedBytes::from(Bytes::copy_from_slice(blob)),
            )
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?
            .build()
            .send()
            .await
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?;

        Ok(())
    }

    pub async fn get_blob(&self, username: &str) -> Result<Vec<u8>, AppError> {
        let response = self
            .resources
            .blob
            .get_object(&self.resources.blob_bucket_name, username)
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?
            .build()
            .send()
            .await
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?;

        let bytes = response
            .content()
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?
            .to_segmented_bytes()
            .await
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?
            .to_bytes();

        Ok(bytes.to_vec())
    }

    pub async fn get_meta(&self, username: &str) -> Result<BlobMetadata, AppError> {
        let row: BlobMetadataRow = sqlx::query_as(
            "SELECT hash_blake3, version, size, updated_at
             FROM user_blob
             WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(&self.resources.database)
        .await
        .map_err(|e| AppError::Internal(InternalKind::DatabaseError(e.to_string())))?
        .ok_or_else(|| AppError::NotFound(NotFoundKind::BlobNotFound))?;

        let hash_blake3 = row
            .hash_blake3
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("");

        Ok(BlobMetadata {
            hash_blake3,
            version: row.version,
            size: row.size,
            updated_at: row.updated_at,
        })
    }

    pub async fn delete_blob(&self, username: &str) -> Result<(), AppError> {
        self.resources
            .blob
            .delete_object(&self.resources.blob_bucket_name, username)
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?
            .build()
            .send()
            .await
            .map_err(|e| AppError::Internal(InternalKind::BlobError(e.to_string())))?;
        Ok(())
    }
}

#[derive(Debug, FromRow)]
struct BlobMetadataRow {
    hash_blake3: Vec<u8>,
    version: i64,
    size: i64,
    updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct BlobMetadata {
    pub hash_blake3: String,
    pub version: i64,
    pub size: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}
