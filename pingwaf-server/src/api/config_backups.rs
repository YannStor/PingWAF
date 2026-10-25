//! Configuration backup targets, encrypted backup generation and downloads.

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::{header, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use sea_orm::TransactionTrait;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::config_backup::{self, BackupView, TargetView};
use crate::config_backup_crypto::{decrypt_backup, BackupError};
use crate::config_catalog::VersionScope;
use crate::config_history;
use crate::config_restore::{self, RestoreOptions};
use crate::grpc::{notify_all_config_changed, notify_config_changed};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/config-backup-targets",
            get(list_targets).post(create_target),
        )
        .route(
            "/config-backup-targets/{target_id}",
            put(update_target).delete(delete_target),
        )
        .route("/config-backup-targets/{target_id}/test", post(test_target))
        .route("/config-backups", get(list_backups).post(create_backup))
        .route(
            "/config-backups/upload",
            post(upload_backup_file)
                .layer(DefaultBodyLimit::max(32 * 1024 * 1024)),
        )
        .route("/config-backups/{backup_id}", get(show_backup))
        .route("/config-backups/{backup_id}/download", get(download_backup))
        .route("/config-backups/{backup_id}/upload", post(upload_backup))
        .route("/config-backups/{backup_id}/preview", post(preview_restore))
        .route("/config-backups/{backup_id}/restore", post(restore_backup))
}

fn backup_error(error: BackupError) -> ApiError {
    match error {
        BackupError::Database(error) => ApiError::from(error),
        other => ApiError::BadRequest(other.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct TargetCreateRequest {
    kind: String,
    name: String,
    config: Value,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize, Default)]
struct TargetUpdateRequest {
    name: Option<String>,
    config: Option<Value>,
    enabled: Option<bool>,
}

fn default_true() -> bool {
    true
}

async fn list_targets(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<Vec<TargetView>>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(config_backup::list_targets(&state.db).await?))
}

async fn create_target(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<TargetCreateRequest>,
) -> Result<Json<TargetView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let view = config_backup::create_target(
        &state.db,
        &payload.kind,
        &payload.name,
        payload.config,
        payload.enabled,
    )
    .await
    .map_err(backup_error)?;
    Ok(Json(view))
}

async fn update_target(
    State(state): State<AppState>,
    current: AuthUser,
    Path(target_id): Path<Uuid>,
    Json(payload): Json<TargetUpdateRequest>,
) -> Result<Json<TargetView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let view = config_backup::update_target(
        &state.db,
        target_id,
        payload.name,
        payload.config,
        payload.enabled,
    )
    .await
    .map_err(backup_error)?;
    Ok(Json(view))
}

async fn delete_target(
    State(state): State<AppState>,
    current: AuthUser,
    Path(target_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    config_backup::delete_target(&state.db, target_id).await?;
    Ok(Json(json!({"deleted": true})))
}

async fn test_target(
    State(state): State<AppState>,
    current: AuthUser,
    Path(target_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    config_backup::test_backup_target(&state.db, target_id)
        .await
        .map_err(backup_error)?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Debug, Deserialize)]
struct CreateBackupRequest {
    #[serde(default = "deployment_scope")]
    scope: String,
    site_id: Option<Uuid>,
    password: String,
    target_id: Option<Uuid>,
}

fn deployment_scope() -> String {
    "deployment".to_string()
}

fn parse_scope(
    scope: &str,
    site_id: Option<Uuid>,
) -> Result<VersionScope, ApiError> {
    match scope {
        "deployment" => Ok(VersionScope::Deployment),
        "global" => Ok(VersionScope::Global),
        "site" => site_id.map(VersionScope::Site).ok_or_else(|| {
            ApiError::BadRequest("site scope requires site_id".into())
        }),
        _ => Err(ApiError::BadRequest(
            "scope must be site, global or deployment".into(),
        )),
    }
}

async fn list_backups(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<Vec<BackupView>>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(config_backup::list_backups(&state.db).await?))
}

async fn create_backup(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<CreateBackupRequest>,
) -> Result<Json<BackupView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let scope = parse_scope(&payload.scope, payload.site_id)?;
    let backup = config_backup::create_backup_record(
        &state.db,
        scope,
        &payload.password,
        Some(&current.email),
        payload.target_id,
    )
    .await
    .map_err(backup_error)?;
    if let Some(target_id) = payload.target_id {
        config_backup::enqueue_upload(&state.db, backup.id, target_id)
            .await
            .map_err(backup_error)?;
    }
    Ok(Json(
        config_backup::load_backup_view(&state.db, backup.id)
            .await
            .map_err(backup_error)?,
    ))
}

async fn show_backup(
    State(state): State<AppState>,
    current: AuthUser,
    Path(backup_id): Path<Uuid>,
) -> Result<Json<BackupView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(
        config_backup::load_backup_view(&state.db, backup_id)
            .await
            .map_err(backup_error)?,
    ))
}

async fn download_backup(
    State(state): State<AppState>,
    current: AuthUser,
    Path(backup_id): Path<Uuid>,
) -> Result<Response<Body>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let backup = config_backup::load_backup(&state.db, backup_id)
        .await
        .map_err(backup_error)?;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", backup.file_name),
        )
        .header("x-content-type-options", "nosniff")
        .body(Body::from(backup.payload))
        .map_err(|error| ApiError::Internal(error.to_string()))
}

#[derive(Debug, Deserialize)]
struct UploadRequest {
    target_id: Uuid,
}

async fn upload_backup(
    State(state): State<AppState>,
    current: AuthUser,
    Path(backup_id): Path<Uuid>,
    Json(payload): Json<UploadRequest>,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    config_backup::enqueue_upload(&state.db, backup_id, payload.target_id)
        .await
        .map_err(backup_error)?;
    Ok(Json(json!({"status": "uploading"})))
}

fn restore_options(current: &AuthUser, scope: VersionScope) -> RestoreOptions {
    RestoreOptions {
        default_owner_id: Some(current.id),
        prune_sites: scope == VersionScope::Deployment,
        preserve_site_owners: false,
    }
}

async fn upload_backup_file(
    State(state): State<AppState>,
    current: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let mut file_name = "uploaded-backup.pwb.json".to_string();
    let mut payload = None;
    let mut password = None;
    let mut scope = "deployment".to_string();
    let mut site_id = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::BadRequest(error.to_string()))?
    {
        match field.name() {
            Some("file") => {
                file_name =
                    field.file_name().map(str::to_string).unwrap_or(file_name);
                payload = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|error| {
                            ApiError::BadRequest(error.to_string())
                        })?
                        .to_vec(),
                );
            },
            Some("password") => {
                password = Some(field.text().await.map_err(|error| {
                    ApiError::BadRequest(error.to_string())
                })?);
            },
            Some("scope") => {
                scope = field
                    .text()
                    .await
                    .map_err(|error| ApiError::BadRequest(error.to_string()))?;
            },
            Some("site_id") => {
                let raw = field
                    .text()
                    .await
                    .map_err(|error| ApiError::BadRequest(error.to_string()))?;
                site_id = Some(Uuid::parse_str(raw.trim()).map_err(|_| {
                    ApiError::BadRequest("site_id must be a UUID".into())
                })?);
            },
            _ => {},
        }
    }
    let payload = payload.ok_or_else(|| {
        ApiError::BadRequest("multipart field 'file' is required".into())
    })?;
    let password = password.ok_or_else(|| {
        ApiError::BadRequest("multipart field 'password' is required".into())
    })?;
    let scope = parse_scope(&scope, site_id)?;
    let (snapshot, manifest) = decrypt_backup(&payload, &password, scope)
        .await
        .map_err(backup_error)?;
    // Validate before recording anything: a rejected upload must not leave a
    // usable-looking `created` backup behind.
    let plan = config_restore::prepare_restore(
        &state.db,
        scope,
        &snapshot,
        restore_options(&current, scope),
    )
    .await?;
    let backup = config_backup::create_uploaded_backup_record(
        &state.db,
        &file_name,
        manifest,
        payload,
        Some(&current.email),
    )
    .await
    .map_err(backup_error)?;
    Ok(Json(json!({
        "backup": backup,
        "preview": config_restore::preview(&plan),
    })))
}

#[derive(Debug, Deserialize)]
struct RestorePasswordRequest {
    password: String,
}

async fn preview_restore(
    State(state): State<AppState>,
    current: AuthUser,
    Path(backup_id): Path<Uuid>,
    Json(payload): Json<RestorePasswordRequest>,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let backup = config_backup::load_backup(&state.db, backup_id)
        .await
        .map_err(backup_error)?;
    let scope = parse_scope(&backup.scope, backup.site_id)?;
    let (snapshot, _) =
        decrypt_backup(&backup.payload, &payload.password, scope)
            .await
            .map_err(backup_error)?;
    let plan = config_restore::prepare_restore(
        &state.db,
        scope,
        &snapshot,
        restore_options(&current, scope),
    )
    .await?;
    Ok(Json(config_restore::preview(&plan)))
}

async fn restore_backup(
    State(state): State<AppState>,
    current: AuthUser,
    Path(backup_id): Path<Uuid>,
    Json(payload): Json<RestorePasswordRequest>,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let backup = config_backup::load_backup(&state.db, backup_id)
        .await
        .map_err(backup_error)?;
    let scope = parse_scope(&backup.scope, backup.site_id)?;
    let (snapshot, _) =
        decrypt_backup(&backup.payload, &payload.password, scope)
            .await
            .map_err(backup_error)?;

    // Capture and restore in one serializable transaction. A concurrent edit
    // causes a serialization failure and a clean rollback instead of silently
    // disappearing from the pre-restore backup.
    let txn = state
        .db
        .begin_with_config(Some(sea_orm::IsolationLevel::Serializable), None)
        .await?;
    let pre_restore = config_backup::create_pre_restore_record_in_transaction(
        &txn,
        scope,
        &payload.password,
        Some(&format!("pre-restore:{backup_id}")),
    )
    .await
    .map_err(backup_error)?;
    let plan = config_restore::prepare_restore(
        &txn,
        scope,
        &snapshot,
        restore_options(&current, scope),
    )
    .await?;
    config_restore::apply_restore(&txn, plan).await?;
    txn.commit().await?;

    let mut post_warnings = Vec::new();
    match scope {
        VersionScope::Site(site_id) => {
            if let Err(error) =
                crate::api::sites::touch_site(&state, site_id).await
            {
                post_warnings
                    .push(format!("agent push preparation failed: {error}"));
            }
            notify_config_changed(&state, site_id, Some(&current.email)).await;
        },
        VersionScope::Global | VersionScope::Deployment => {
            notify_all_config_changed(&state, Some(&current.email)).await;
        },
    }
    if let Some(manager) = crate::notify::global() {
        manager.reload().await;
    }
    match crate::api::self_protection::refresh(&state.db).await {
        Ok(policy) => state.protection.store(policy),
        Err(error) => {
            post_warnings
                .push(format!("API protection refresh failed: {error}"));
        },
    }
    if scope == VersionScope::Deployment {
        if let Err(error) =
            crate::api::system_tls::load_active_certificate(&state).await
        {
            tracing::warn!(error = %error, "restored configuration but TLS reload failed");
            post_warnings.push(format!("TLS reload failed: {error}"));
        }
    }
    let new_version = config_history::record_version(
        &state.db,
        scope,
        "restore",
        Some(&current.email),
        "",
    )
    .await
    .unwrap_or_else(|error| {
        tracing::warn!(error = %error, "restore succeeded but its history row failed");
        None
    });

    Ok(Json(json!({
        "restored": true,
        "pre_restore_backup_id": pre_restore.id,
        "new_version": new_version,
        "warnings": post_warnings,
    })))
}
