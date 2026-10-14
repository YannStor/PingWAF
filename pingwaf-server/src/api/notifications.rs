//! Notification channels, alert settings and the dispatched-event history.
//!
//! Channels are the delivery targets (e-mail, WeCom, DingTalk, generic
//! webhook); the settings hold the resource thresholds and the dedup window.
//! Mutations ask the notification manager to reload so they take effect
//! immediately.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, Set,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::{
    channel_kind, event_type, notification_channel, notification_event,
    severity,
};
use crate::notify::NotificationSettings;

/// Config keys that must never leave the server in plain text. The stored
/// value is additionally sealed at rest (see [`crate::notify::secretbox`]).
use crate::notify::secretbox::SECRET_KEYS;
/// Placeholder a client sends back to keep the stored secret.
const REDACTED: &str = "__REDACTED__";

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/notifications/channels",
            get(list_channels).post(create_channel),
        )
        .route(
            "/notifications/channels/{channel_id}",
            get(show_channel).put(update_channel).delete(delete_channel),
        )
        .route(
            "/notifications/channels/{channel_id}/test",
            post(test_channel),
        )
        .route(
            "/notifications/settings",
            get(show_settings).put(update_settings),
        )
        .route("/notifications/events", get(list_events))
}

/// Validates the stored config for a channel kind, so a broken channel is
/// rejected at creation time instead of discovered at the first alert.
fn validate_config(kind: &str, config: &Value) -> Result<(), ApiError> {
    let get_url = || {
        config
            .get("url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .ok_or_else(|| {
                ApiError::BadRequest("config.url is required".to_string())
            })
    };
    match kind {
        channel_kind::EMAIL => {
            crate::notify::email::EmailConfig::from_json(config)
                .map_err(ApiError::BadRequest)?;
        },
        channel_kind::WECOM | channel_kind::DINGTALK => {
            get_url()?;
        },
        channel_kind::WEBHOOK => {
            get_url()?;
        },
        other => {
            return Err(ApiError::BadRequest(format!(
                "unknown channel kind '{other}' (expected one of: {})",
                channel_kind::ALL.join(", ")
            )));
        },
    }
    Ok(())
}

/// Validates the subscribed event types; an empty list subscribes to all.
fn validate_events(events: &Value) -> Result<(), ApiError> {
    let Some(list) = events.as_array() else {
        return Err(ApiError::BadRequest(
            "events must be an array of event types".to_string(),
        ));
    };
    for item in list {
        let Some(name) = item.as_str() else {
            return Err(ApiError::BadRequest(
                "events must contain strings".to_string(),
            ));
        };
        if !event_type::ALL.contains(&name) {
            return Err(ApiError::BadRequest(format!(
                "unknown event type '{name}' (expected one of: {})",
                event_type::ALL.join(", ")
            )));
        }
    }
    Ok(())
}

/// Replaces stored secrets with the placeholder in outgoing JSON.
fn redact(config: &mut Value) {
    let Some(object) = config.as_object_mut() else {
        return;
    };
    for key in SECRET_KEYS {
        if object
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        {
            object.insert(key.to_string(), json!(REDACTED));
        }
    }
}

/// Restores real secrets when the client echoed the placeholder back.
fn unredact(config: &mut Value, stored: &Value) {
    let (Some(object), Some(stored_object)) =
        (config.as_object_mut(), stored.as_object())
    else {
        return;
    };
    for key in SECRET_KEYS {
        let echoed_mask =
            object.get(key).and_then(Value::as_str) == Some(REDACTED);
        if !echoed_mask {
            continue;
        }
        if let Some(value) = stored_object.get(key) {
            object.insert(key.to_string(), value.clone());
        }
    }
}

/// The channel as the API returns it: config with secrets masked.
#[derive(Debug, Serialize)]
pub struct ChannelView {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub config: Value,
    pub events: Value,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<notification_channel::Model> for ChannelView {
    fn from(row: notification_channel::Model) -> Self {
        let mut config = row.config;
        redact(&mut config);
        Self {
            id: row.id,
            name: row.name,
            kind: row.kind,
            config,
            events: row.events,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ChannelRequest {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub config: Value,
    /// Event types to receive; empty or missing receives everything.
    #[serde(default)]
    pub events: Value,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// `GET /api/v1/notifications/channels` — administrators only.
async fn list_channels(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<Vec<ChannelView>>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let rows = notification_channel::Entity::find()
        .order_by_asc(notification_channel::Column::Name)
        .all(&state.db)
        .await?;
    Ok(Json(rows.into_iter().map(ChannelView::from).collect()))
}

/// `GET /api/v1/notifications/channels/{id}` — administrators only.
async fn show_channel(
    State(state): State<AppState>,
    current: AuthUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<ChannelView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let row = notification_channel::Entity::find_by_id(channel_id)
        .one(&state.db)
        .await?
        .ok_or(ApiError::NotFound("channel not found".to_string()))?;
    Ok(Json(ChannelView::from(row)))
}

/// `POST /api/v1/notifications/channels` — administrators only.
async fn create_channel(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<ChannelRequest>,
) -> Result<Json<ChannelView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let name = payload.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::BadRequest(
            "name must be 1-100 characters".to_string(),
        ));
    }
    validate_config(&payload.kind, &payload.config)?;
    validate_events(&payload.events)?;

    // Secrets are sealed before the row ever reaches the database; the
    // response re-masks whatever is stored, so the API contract is unchanged.
    let mut stored_config = payload.config;
    crate::notify::secretbox::seal_config(&mut stored_config);

    let now = Utc::now();
    let row = notification_channel::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(name.to_string()),
        kind: Set(payload.kind),
        config: Set(stored_config),
        events: Set(payload.events),
        enabled: Set(payload.enabled),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(actor = %current.email, channel = %row.name, "notification channel created");
    reload_channels();
    Ok(Json(ChannelView::from(row)))
}

/// `PUT /api/v1/notifications/channels/{id}` — administrators only.
async fn update_channel(
    State(state): State<AppState>,
    current: AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(payload): Json<ChannelRequest>,
) -> Result<Json<ChannelView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let row = notification_channel::Entity::find_by_id(channel_id)
        .one(&state.db)
        .await?
        .ok_or(ApiError::NotFound("channel not found".to_string()))?;
    let name = payload.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::BadRequest(
            "name must be 1-100 characters".to_string(),
        ));
    }
    let mut config = payload.config;
    // The client cannot echo a secret it never received; the placeholder
    // means "keep the stored value". The stored row holds sealed secrets,
    // so open them first — the unredacted values are then re-sealed below.
    let mut stored = row.config.clone();
    crate::notify::secretbox::open_config(&mut stored);
    unredact(&mut config, &stored);
    validate_config(&payload.kind, &config)?;
    validate_events(&payload.events)?;
    crate::notify::secretbox::seal_config(&mut config);

    let mut active: notification_channel::ActiveModel = row.into();
    active.name = Set(name.to_string());
    active.kind = Set(payload.kind);
    active.config = Set(config);
    active.events = Set(payload.events);
    active.enabled = Set(payload.enabled);
    active.updated_at = Set(Utc::now());
    let updated = active.update(&state.db).await?;

    tracing::info!(actor = %current.email, channel = %updated.name, "notification channel updated");
    reload_channels();
    Ok(Json(ChannelView::from(updated)))
}

/// `DELETE /api/v1/notifications/channels/{id}` — administrators only.
async fn delete_channel(
    State(state): State<AppState>,
    current: AuthUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let result = notification_channel::Entity::delete_by_id(channel_id)
        .exec(&state.db)
        .await?;
    if result.rows_affected == 0 {
        return Err(ApiError::NotFound("channel not found".to_string()));
    }
    tracing::info!(actor = %current.email, %channel_id, "notification channel deleted");
    reload_channels();
    Ok(Json(json!({ "deleted": true })))
}

/// `POST /api/v1/notifications/channels/{id}/test` — administrators only.
/// Sends a test alert through the channel and reports the delivery error, if
/// any, so the console can surface a broken SMTP password before an incident.
async fn test_channel(
    State(_state): State<AppState>,
    current: AuthUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let manager = crate::notify::global().ok_or_else(|| {
        ApiError::Internal("notifications are not running".to_string())
    })?;
    match manager.test_channel(channel_id).await {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(err) => Ok(Json(json!({ "ok": false, "error": err }))),
    }
}

/// `GET /api/v1/notifications/settings` — administrators only.
async fn show_settings(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<NotificationSettings>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(NotificationSettings::load(&state.db).await))
}

#[derive(Debug, Deserialize)]
pub struct UpdateSettingsRequest {
    pub cpu_percent: Option<u8>,
    pub memory_percent: Option<u8>,
    pub disk_percent: Option<u8>,
    pub dedup_window_secs: Option<u64>,
    /// Noise master switch: `false` stops channel delivery (history is
    /// still recorded).
    pub enabled: Option<bool>,
    pub notify_agent_offline: Option<bool>,
    pub notify_agent_online: Option<bool>,
    pub notify_agent_resource: Option<bool>,
    pub notify_control_plane_resource: Option<bool>,
    /// Gates `cert.expiring` and `cert.expired` together.
    pub notify_cert_expiry: Option<bool>,
    pub notify_cert_renewal_failed: Option<bool>,
    pub notify_config_sync_failed: Option<bool>,
    pub notify_site_failover_changed: Option<bool>,
    /// Gates `site.upstream_offline` and `site.upstream_abnormal` together.
    pub notify_site_upstream: Option<bool>,
    pub notify_auth_login_anomaly: Option<bool>,
    pub cert_expiry_warn_days: Option<u32>,
}

/// `PUT /api/v1/notifications/settings` — administrators only.
async fn update_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<UpdateSettingsRequest>,
) -> Result<Json<NotificationSettings>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let mut settings = NotificationSettings::load(&state.db).await;
    if let Some(value) = payload.cpu_percent {
        settings.cpu_percent = clamp_threshold(value);
    }
    if let Some(value) = payload.memory_percent {
        settings.memory_percent = clamp_threshold(value);
    }
    if let Some(value) = payload.disk_percent {
        settings.disk_percent = clamp_threshold(value);
    }
    if let Some(value) = payload.dedup_window_secs {
        settings.dedup_window_secs = value.min(86_400);
    }
    if let Some(value) = payload.enabled {
        settings.enabled = value;
    }
    if let Some(value) = payload.notify_agent_offline {
        settings.notify_agent_offline = value;
    }
    if let Some(value) = payload.notify_agent_online {
        settings.notify_agent_online = value;
    }
    if let Some(value) = payload.notify_agent_resource {
        settings.notify_agent_resource = value;
    }
    if let Some(value) = payload.notify_control_plane_resource {
        settings.notify_control_plane_resource = value;
    }
    if let Some(value) = payload.notify_cert_expiry {
        settings.notify_cert_expiry = value;
    }
    if let Some(value) = payload.notify_cert_renewal_failed {
        settings.notify_cert_renewal_failed = value;
    }
    if let Some(value) = payload.notify_config_sync_failed {
        settings.notify_config_sync_failed = value;
    }
    if let Some(value) = payload.notify_site_failover_changed {
        settings.notify_site_failover_changed = value;
    }
    if let Some(value) = payload.notify_site_upstream {
        settings.notify_site_upstream = value;
    }
    if let Some(value) = payload.notify_auth_login_anomaly {
        settings.notify_auth_login_anomaly = value;
    }
    if let Some(value) = payload.cert_expiry_warn_days {
        settings.cert_expiry_warn_days = value.clamp(1, 365);
    }
    settings.store(&state.db).await?;
    tracing::info!(actor = %current.email, "notification settings updated");
    reload_channels();
    Ok(Json(settings))
}

/// Thresholds below 5% would page on every request; keep them sane.
fn clamp_threshold(value: u8) -> u8 {
    value.clamp(5, 100)
}

#[derive(Debug, Deserialize)]
pub struct ListEventsQuery {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub event_type: Option<String>,
}

/// `GET /api/v1/notifications/events` — administrators only. The alert
/// history, newest first.
async fn list_events(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListEventsQuery>,
) -> Result<Json<Vec<notification_event::Model>>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);
    let mut db_query = notification_event::Entity::find()
        .order_by_desc(notification_event::Column::CreatedAt)
        .limit(limit)
        .offset(offset);
    if let Some(kind) = query
        .event_type
        .as_deref()
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
    {
        db_query =
            db_query.filter(notification_event::Column::EventType.eq(kind));
    }
    Ok(Json(db_query.all(&state.db).await?))
}

/// Nudges the notification manager to re-read channels and settings. A no-op
/// before the manager exists (unit tests); the periodic reload loop covers
/// everything else.
fn reload_channels() {
    // Deliberately detached: the handler must not block on the reload, and
    // the loop reconciles any missed state within a minute anyway.
    tokio::spawn(async {
        if let Some(manager) = crate::notify::global() {
            manager.reload().await;
        }
    });
}

/// Severity labels the console offers for the event history filter.
#[allow(dead_code)]
fn severities() -> [&'static str; 3] {
    severity::ALL
}
