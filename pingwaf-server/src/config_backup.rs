//! Backup records, target credentials and bounded remote upload tasks.

use std::sync::{Arc, LazyLock};

use chrono::Utc;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    EntityTrait, QueryOrder, QuerySelect, Set,
};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::config_backup_crypto::{
    create_encrypted_backup, create_encrypted_backup_with_connection,
    BackupError,
};
use crate::config_backup_targets::{test_target, upload_to_target};
use crate::config_catalog::VersionScope;
use crate::models::{config_backup, config_backup_target};
use crate::notify::secretbox;

static UPLOAD_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(2)));

#[derive(Debug, Serialize)]
pub struct TargetView {
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub config: Value,
    pub enabled: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct BackupView {
    pub id: Uuid,
    pub scope: String,
    pub site_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    pub status: String,
    pub file_name: String,
    pub manifest: Value,
    pub checksum: String,
    pub error: String,
    pub actor: Option<String>,
    pub size_bytes: usize,
    pub created_at: chrono::DateTime<Utc>,
    pub completed_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, sea_orm::FromQueryResult)]
struct BackupMetadata {
    id: Uuid,
    scope: String,
    site_id: Option<Uuid>,
    target_id: Option<Uuid>,
    status: String,
    file_name: String,
    manifest: Value,
    checksum: String,
    error: String,
    actor: Option<String>,
    size_bytes: i32,
    created_at: chrono::DateTime<Utc>,
    completed_at: Option<chrono::DateTime<Utc>>,
}

fn secret_fields(config: &Value) -> bool {
    ["secret_access_key", "token"].iter().any(|field| {
        config
            .get(*field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    })
}

fn public_config(config: &Value) -> Value {
    let mut public = config.clone();
    if let Some(object) = public.as_object_mut() {
        for field in ["access_key_id", "secret_access_key", "token"] {
            object.remove(field);
        }
        object.insert(
            "has_credentials".to_string(),
            json!(secret_fields(config)),
        );
    }
    public
}

fn seal_target_config(config: &Value) -> Result<Value, BackupError> {
    if secret_fields(config) && !secretbox::encryption_enabled() {
        return Err(BackupError::Operation(
            "PINGWAF_SECRET_KEY is required before storing backup target credentials"
                .into(),
        ));
    }
    let mut sealed = config.clone();
    if let Some(object) = sealed.as_object_mut() {
        for field in ["secret_access_key", "token"] {
            if let Some(value) = object.get(field).and_then(Value::as_str) {
                object.insert(
                    field.to_string(),
                    json!(secretbox::seal_string(value)),
                );
            }
        }
    }
    Ok(sealed)
}

fn open_target_config(config: &Value) -> Result<Value, BackupError> {
    let mut opened = config.clone();
    if let Some(object) = opened.as_object_mut() {
        for field in ["secret_access_key", "token"] {
            if let Some(value) = object.get(field).and_then(Value::as_str) {
                let plain = secretbox::open_string(value).ok_or_else(|| {
                    BackupError::Operation(
                        "backup target credential cannot be decrypted".into(),
                    )
                })?;
                object.insert(field.to_string(), json!(plain));
            }
        }
    }
    Ok(opened)
}

fn target_view(row: config_backup_target::Model) -> TargetView {
    TargetView {
        id: row.id,
        kind: row.kind,
        name: row.name,
        config: public_config(&row.config),
        enabled: row.enabled,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn backup_metadata_view(row: BackupMetadata) -> BackupView {
    BackupView {
        id: row.id,
        scope: row.scope,
        site_id: row.site_id,
        target_id: row.target_id,
        status: row.status,
        file_name: row.file_name,
        manifest: row.manifest,
        checksum: row.checksum,
        error: row.error,
        actor: row.actor,
        size_bytes: usize::try_from(row.size_bytes).unwrap_or_default(),
        created_at: row.created_at,
        completed_at: row.completed_at,
    }
}

fn backup_view(row: config_backup::Model) -> BackupView {
    BackupView {
        id: row.id,
        scope: row.scope,
        site_id: row.site_id,
        target_id: row.target_id,
        status: row.status,
        file_name: row.file_name,
        manifest: row.manifest,
        checksum: row.checksum,
        error: row.error,
        actor: row.actor,
        size_bytes: row.payload.len(),
        created_at: row.created_at,
        completed_at: row.completed_at,
    }
}

pub async fn list_targets(
    db: &DatabaseConnection,
) -> Result<Vec<TargetView>, sea_orm::DbErr> {
    let rows = config_backup_target::Entity::find()
        .order_by_asc(config_backup_target::Column::Name)
        .all(db)
        .await?;
    Ok(rows.into_iter().map(target_view).collect())
}

pub async fn create_target(
    db: &DatabaseConnection,
    kind: &str,
    name: &str,
    config: Value,
    enabled: bool,
) -> Result<TargetView, BackupError> {
    if !matches!(kind, "s3" | "github") {
        return Err(BackupError::Format(
            "target kind must be s3 or github".into(),
        ));
    }
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(BackupError::Format(
            "target name must contain 1-128 characters".into(),
        ));
    }
    let now = Utc::now();
    let row = config_backup_target::ActiveModel {
        id: Set(Uuid::new_v4()),
        kind: Set(kind.to_string()),
        name: Set(name.to_string()),
        config: Set(seal_target_config(&config)?),
        enabled: Set(enabled),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await?;
    Ok(target_view(row))
}

pub async fn update_target(
    db: &DatabaseConnection,
    id: Uuid,
    name: Option<String>,
    config: Option<Value>,
    enabled: Option<bool>,
) -> Result<TargetView, BackupError> {
    let row = config_backup_target::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or_else(|| BackupError::Format("backup target not found".into()))?;
    let mut active: config_backup_target::ActiveModel = row.clone().into();
    if let Some(name) = name {
        let name = name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(BackupError::Format(
                "target name must contain 1-128 characters".into(),
            ));
        }
        active.name = Set(name.to_string());
    }
    if let Some(enabled) = enabled {
        active.enabled = Set(enabled);
    }
    if let Some(update) = config {
        let current = open_target_config(&row.config)?;
        let mut merged = current;
        crate::config_catalog::merge_shallow(&mut merged, &update);
        // Absent secret fields keep their current values; explicit empty
        // strings clear them, which the target validation can then reject.
        active.config = Set(seal_target_config(&merged)?);
    }
    active.updated_at = Set(Utc::now());
    let updated = active.update(db).await?;
    Ok(target_view(updated))
}

pub async fn delete_target(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<(), sea_orm::DbErr> {
    config_backup_target::Entity::delete_by_id(id)
        .exec(db)
        .await?;
    Ok(())
}

pub async fn test_backup_target(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<(), BackupError> {
    let row = config_backup_target::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or_else(|| BackupError::Format("backup target not found".into()))?;
    test_target(&row.kind, &open_target_config(&row.config)?).await
}

pub async fn list_backups(
    db: &DatabaseConnection,
) -> Result<Vec<BackupView>, sea_orm::DbErr> {
    // The list needs only metadata. Reading a hundred 32 MiB envelopes just to
    // compute their lengths would needlessly allocate gigabytes.
    let rows = config_backup::Entity::find()
        .select_only()
        .columns([
            config_backup::Column::Id,
            config_backup::Column::Scope,
            config_backup::Column::SiteId,
            config_backup::Column::TargetId,
            config_backup::Column::Status,
            config_backup::Column::FileName,
            config_backup::Column::Manifest,
            config_backup::Column::Checksum,
            config_backup::Column::Error,
            config_backup::Column::Actor,
            config_backup::Column::CreatedAt,
            config_backup::Column::CompletedAt,
        ])
        .column_as(Expr::cust("octet_length(payload)"), "size_bytes")
        .order_by_desc(config_backup::Column::CreatedAt)
        .limit(100)
        .into_model::<BackupMetadata>()
        .all(db)
        .await?;
    Ok(rows.into_iter().map(backup_metadata_view).collect())
}

pub async fn load_backup(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<config_backup::Model, BackupError> {
    config_backup::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or_else(|| BackupError::Format("backup not found".into()))
}

pub async fn load_backup_view(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<BackupView, BackupError> {
    load_backup(db, id).await.map(backup_view)
}

pub async fn create_backup_record(
    db: &DatabaseConnection,
    scope: VersionScope,
    password: &str,
    actor: Option<&str>,
    target_id: Option<Uuid>,
) -> Result<BackupView, BackupError> {
    if let Some(target_id) = target_id {
        let target = config_backup_target::Entity::find_by_id(target_id)
            .one(db)
            .await?
            .ok_or_else(|| {
                BackupError::Format("backup target not found".into())
            })?;
        if !target.enabled {
            return Err(BackupError::Operation(
                "the selected backup target is disabled".into(),
            ));
        }
    }
    let created = create_encrypted_backup(db, scope, password).await?;
    let uploading = target_id.is_some();
    let row =
        config_backup::ActiveModel {
            id: Set(Uuid::new_v4()),
            scope: Set(scope.as_str().to_string()),
            site_id: Set(scope.column_value()),
            target_id: Set(target_id),
            status: Set(
                if uploading { "created" } else { "completed" }.to_string()
            ),
            file_name: Set(created.file_name),
            manifest: Set(created.manifest),
            payload: Set(created.payload),
            checksum: Set(created.checksum),
            error: Set(String::new()),
            actor: Set(actor.map(str::to_string)),
            created_at: Set(Utc::now()),
            upload_started_at: Set(None),
            completed_at: Set(if uploading { None } else { Some(Utc::now()) }),
        }
        .insert(db)
        .await?;
    Ok(backup_view(row))
}

/// Creates the pre-restore backup inside the restore's own serializable
/// transaction. Its insert commits or rolls back with the configuration change.
pub async fn create_pre_restore_record_in_transaction(
    txn: &DatabaseTransaction,
    scope: VersionScope,
    password: &str,
    actor: Option<&str>,
) -> Result<BackupView, BackupError> {
    let created =
        create_encrypted_backup_with_connection(txn, scope, password).await?;
    let row = config_backup::ActiveModel {
        id: Set(Uuid::new_v4()),
        scope: Set(scope.as_str().to_string()),
        site_id: Set(scope.column_value()),
        target_id: Set(None),
        status: Set("completed".to_string()),
        file_name: Set(created.file_name),
        manifest: Set(created.manifest),
        payload: Set(created.payload),
        checksum: Set(created.checksum),
        error: Set(String::new()),
        actor: Set(actor.map(str::to_string)),
        created_at: Set(Utc::now()),
        upload_started_at: Set(None),
        completed_at: Set(Some(Utc::now())),
    }
    .insert(txn)
    .await?;
    Ok(backup_view(row))
}

pub async fn create_uploaded_backup_record(
    db: &DatabaseConnection,
    file_name: &str,
    manifest: Value,
    payload: Vec<u8>,
    actor: Option<&str>,
) -> Result<BackupView, BackupError> {
    let scope =
        manifest
            .get("scope")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                BackupError::Format("backup manifest has no scope".into())
            })?;
    let site_id = manifest
        .get("site_id")
        .and_then(Value::as_str)
        .map(|value| {
            Uuid::parse_str(value).map_err(|_| {
                BackupError::Format("invalid site id in manifest".into())
            })
        })
        .transpose()?;
    let scope = match scope {
        "deployment" => VersionScope::Deployment,
        "global" => VersionScope::Global,
        "site" => VersionScope::Site(site_id.ok_or_else(|| {
            BackupError::Format("site backup has no site id".into())
        })?),
        _ => return Err(BackupError::Format("unknown backup scope".into())),
    };
    let checksum = manifest
        .get("ciphertext_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| BackupError::Format("missing backup checksum".into()))?
        .to_string();
    let file_name: String = file_name
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '-' | '_' | '.')
        })
        .take(128)
        .collect();
    let file_name = if file_name.is_empty() {
        "uploaded-backup.pwb.json".to_string()
    } else {
        file_name
    };
    let row = config_backup::ActiveModel {
        id: Set(Uuid::new_v4()),
        scope: Set(scope.as_str().to_string()),
        site_id: Set(scope.column_value()),
        target_id: Set(None),
        status: Set("created".to_string()),
        file_name: Set(file_name),
        manifest: Set(manifest),
        payload: Set(payload),
        checksum: Set(checksum),
        error: Set(String::new()),
        actor: Set(actor.map(str::to_string)),
        created_at: Set(Utc::now()),
        upload_started_at: Set(None),
        completed_at: Set(None),
    }
    .insert(db)
    .await?;
    Ok(backup_view(row))
}

pub async fn enqueue_upload(
    db: &DatabaseConnection,
    backup_id: Uuid,
    target_id: Uuid,
) -> Result<(), BackupError> {
    let backup = load_backup(db, backup_id).await?;
    if backup.status == "uploading" {
        return Err(BackupError::Operation(
            "this backup is already being uploaded".into(),
        ));
    }
    let permit = UPLOAD_PERMITS.clone().try_acquire_owned().map_err(|_| {
        BackupError::Operation("backup upload queue is full".into())
    })?;
    let target = config_backup_target::Entity::find_by_id(target_id)
        .one(db)
        .await?
        .ok_or_else(|| BackupError::Format("backup target not found".into()))?;
    if !target.enabled {
        return Err(BackupError::Operation(
            "the selected backup target is disabled".into(),
        ));
    }
    // Atomic state transition: concurrent requests, including requests from
    // another control-plane instance, cannot all claim the same upload.
    let claimed = db
        .execute(sea_orm::Statement::from_sql_and_values(
            db.get_database_backend(),
            "UPDATE config_backups \
             SET target_id = $2, status = 'uploading', upload_started_at = $3, \
                 error = '', completed_at = NULL \
             WHERE id = $1 AND status <> 'uploading'",
            [backup_id.into(), target_id.into(), Utc::now().into()],
        ))
        .await?;
    if claimed.rows_affected() == 0 {
        return Err(BackupError::Operation(
            "this backup is already being uploaded".into(),
        ));
    }

    let upload_db = db.clone();
    tokio::spawn(async move {
        let result = upload_backup(&upload_db, backup_id, target_id).await;
        if let Err(error) = result {
            tracing::warn!(backup_id = %backup_id, error = %error, "backup upload failed");
        }
        drop(permit);
    });
    Ok(())
}

async fn upload_backup(
    db: &DatabaseConnection,
    backup_id: Uuid,
    target_id: Uuid,
) -> Result<(), BackupError> {
    let attempt = load_backup(db, backup_id).await?;
    let attempt_started_at = attempt.upload_started_at;
    let result = async {
        let backup = load_backup(db, backup_id).await?;
        let target = config_backup_target::Entity::find_by_id(target_id)
            .one(db)
            .await?
            .ok_or_else(|| {
                BackupError::Format("backup target not found".into())
            })?;
        if !target.enabled {
            return Err(BackupError::Operation(
                "the selected backup target is disabled".into(),
            ));
        }
        let config = open_target_config(&target.config)?;
        upload_to_target(
            &target.kind,
            &config,
            &backup.file_name,
            &backup.payload,
        )
        .await
    }
    .await;

    let (status, error) = match result {
        Ok(location) => {
            tracing::info!(backup_id = %backup_id, location = %location, "configuration backup uploaded");
            ("completed", String::new())
        },
        Err(error) => ("failed", error.to_string()),
    };
    // Fence on the exact lease claimed by this task. A late task from an older
    // attempt must not overwrite a newer retry's state.
    let changed = db
        .execute(sea_orm::Statement::from_sql_and_values(
            db.get_database_backend(),
            "UPDATE config_backups SET status = $1, error = $2, completed_at = $3 \
             WHERE id = $4 AND status = 'uploading' AND upload_started_at = $5",
            [
                status.into(),
                error.into(),
                Utc::now().into(),
                backup_id.into(),
                attempt_started_at.into(),
            ],
        ))
        .await?;
    if changed.rows_affected() == 0 {
        tracing::info!(backup_id = %backup_id, "ignored completion from an expired upload attempt");
    }
    Ok(())
}

/// Marks abandoned upload leases as failed so they can be retried. Called at
/// startup and periodically; a process crash cannot leave a record uploading
/// forever.
pub async fn reset_stale_uploads(
    db: &DatabaseConnection,
) -> Result<u64, sea_orm::DbErr> {
    let cutoff = Utc::now() - chrono::Duration::minutes(15);
    let result = db
        .execute(sea_orm::Statement::from_sql_and_values(
            db.get_database_backend(),
            "UPDATE config_backups SET status = 'failed', \
             error = 'upload lease expired', completed_at = $1 \
             WHERE status = 'uploading' \
                AND (upload_started_at IS NULL OR upload_started_at < $2)",
            [Utc::now().into(), cutoff.into()],
        ))
        .await?;
    Ok(result.rows_affected())
}

/// Applies the same age and per-scope bounds to backup records as to version
/// history. Pre-restore backups cannot accumulate without limit.
pub async fn prune_backups(
    db: &DatabaseConnection,
) -> Result<u64, sea_orm::DbErr> {
    let cutoff = Utc::now() - chrono::Duration::days(30);
    let result = db
        .execute(sea_orm::Statement::from_sql_and_values(
            db.get_database_backend(),
            "WITH ranked AS (\
                 SELECT id, ROW_NUMBER() OVER (\
                     PARTITION BY scope, site_id ORDER BY created_at DESC\
                 ) AS position FROM config_backups\
             )\
             DELETE FROM config_backups WHERE created_at < $1 \
                OR id IN (SELECT id FROM ranked WHERE position > 50)",
            [cutoff.into()],
        ))
        .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_target_config_never_contains_credentials() {
        let public = public_config(&json!({
            "bucket": "backups",
            "access_key_id": "key-id",
            "secret_access_key": "secret",
        }));
        assert!(public.get("access_key_id").is_none());
        assert!(public.get("secret_access_key").is_none());
        assert_eq!(public["has_credentials"], json!(true));
    }
}
