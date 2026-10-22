//! Notification channels, alert settings and the dispatched-event history.
//!
//! Channels are the delivery targets (e-mail, WeCom, DingTalk, generic
//! webhook); the settings hold the resource thresholds and the dedup window.
//! Mutations ask the notification manager to reload so they take effect
//! immediately.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DeleteResult, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::common::{require_write, Page, Pagination};
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
        .route(
            "/notifications/events",
            get(list_events).delete(delete_events),
        )
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
    /// Deliver OIDC authentication alerts.
    #[serde(default)]
    pub notify_site_oidc_auth: Option<bool>,
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
    if let Some(value) = payload.notify_site_oidc_auth {
        settings.notify_site_oidc_auth = value;
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
    #[serde(flatten)]
    pub pagination: Pagination,
    pub event_type: Option<String>,
}

/// `GET /api/v1/notifications/events` — administrators only. The alert
/// history, newest first, one page at a time.
async fn list_events(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListEventsQuery>,
) -> Result<Json<Page<notification_event::Model>>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    // The shared default (50) is the documented one. Re-basing it on the value
    // alone made an explicit `page_size=50` silently return 20 rows.
    let pagination = query.pagination.normalise();
    let mut db_query = notification_event::Entity::find()
        // `id DESC` breaks ties between rows sharing a timestamp so pages
        // stay stable while history is written.
        .order_by_desc(notification_event::Column::CreatedAt)
        .order_by_desc(notification_event::Column::Id);
    if let Some(kind) = query
        .event_type
        .as_deref()
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
    {
        db_query =
            db_query.filter(notification_event::Column::EventType.eq(kind));
    }
    let paginator = db_query.paginate(&state.db, pagination.limit());
    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.index()).await?;
    Ok(Json(Page::new(items, total, pagination)))
}

#[derive(Debug, Deserialize)]
pub struct DeleteEventsQuery {
    /// `all=true` clears the whole history.
    pub all: Option<bool>,
    /// Deletes events strictly older than this many days.
    pub before_days: Option<u32>,
}

/// Validates the C4 cleanup query: `all` and `before_days` are mutually
/// exclusive and exactly one must be present.
///
/// `before_days` is rejected outside `1..=365` rather than silently clamped:
/// `0` would mean "older than now", i.e. the whole table, and a silent clamp
/// to one day would delete a different set than the caller asked for (`logs.rs`
/// rejects the same input for the same reason).
fn parse_delete_events_query(
    query: &DeleteEventsQuery,
) -> Result<Cleanup, ApiError> {
    match (query.all, query.before_days) {
        (Some(true), None) => Ok(Cleanup::All),
        (Some(false), None) => Err(ApiError::BadRequest(
            "all=false is meaningless; pass all=true or before_days=N"
                .to_string(),
        )),
        (None, Some(days)) if (1..=365).contains(&days) => {
            Ok(Cleanup::Before(days))
        },
        (None, Some(days)) => Err(ApiError::BadRequest(format!(
            "before_days must be between 1 and 365 (got {days})"
        ))),
        (Some(_), Some(_)) => Err(ApiError::BadRequest(
            "all and before_days are mutually exclusive: pass exactly one"
                .to_string(),
        )),
        (None, None) => Err(ApiError::BadRequest(
            "either all=true or before_days=N is required".to_string(),
        )),
    }
}

/// Rows removed per statement. A single unbounded `DELETE` holds locks for the
/// whole scan and blocks the alert writer; the loop below keeps each statement
/// short. Mirrors `logs::purge_logs`.
const EVENTS_PURGE_BATCH_SIZE: u64 = 2_000;

/// What [`delete_events`] was asked to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cleanup {
    All,
    Before(u32),
}

/// `DELETE /api/v1/notifications/events` — administrators only. Purges the
/// alert history, either entirely or strictly before `now() - N days`.
async fn delete_events(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<DeleteEventsQuery>,
) -> Result<Json<Value>, ApiError> {
    require_write(&current)?;
    let cleanup = parse_delete_events_query(&query)?;
    let cutoff = match cleanup {
        Cleanup::All => None,
        Cleanup::Before(days) => {
            Some(Utc::now() - Duration::days(i64::from(days)))
        },
    };
    // Delete in bounded batches: `?all=true` on a busy deployment can match
    // hundreds of thousands of rows, and a single `DELETE` would hold locks
    // for the whole scan while the alert writer waits behind it.
    let mut deleted = 0_u64;
    loop {
        let mut batch = notification_event::Entity::find()
            .select_only()
            .column(notification_event::Column::Id)
            .order_by_asc(notification_event::Column::Id)
            .limit(EVENTS_PURGE_BATCH_SIZE);
        if let Some(cutoff) = cutoff {
            batch =
                batch.filter(notification_event::Column::CreatedAt.lt(cutoff));
        }
        let result: DeleteResult = notification_event::Entity::delete_many()
            .filter(
                notification_event::Column::Id.in_subquery(batch.into_query()),
            )
            .exec(&state.db)
            .await?;
        deleted += result.rows_affected;
        if result.rows_affected < EVENTS_PURGE_BATCH_SIZE {
            break;
        }
    }
    tracing::info!(
        actor = %current.email,
        deleted,
        ?cleanup,
        "notification event history purged"
    );
    Ok(Json(json!({ "deleted": deleted })))
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

#[cfg(test)]
mod tests {
    use sea_orm::QueryTrait;

    use super::*;

    #[test]
    fn delete_query_requires_exactly_one_selector() {
        let err = parse_delete_events_query(&DeleteEventsQuery {
            all: None,
            before_days: None,
        })
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));

        let err = parse_delete_events_query(&DeleteEventsQuery {
            all: Some(true),
            before_days: Some(7),
        })
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn delete_query_rejects_all_false() {
        assert!(parse_delete_events_query(&DeleteEventsQuery {
            all: Some(false),
            before_days: None,
        })
        .is_err());
    }

    #[test]
    fn delete_query_rejects_out_of_range_days() {
        // `0` would mean "older than now" (the whole table) and a silent clamp
        // would delete a different set than the caller asked for.
        assert!(
            parse_delete_events_query(&DeleteEventsQuery {
                all: None,
                before_days: Some(0),
            })
            .is_err(),
            "before_days=0 must be rejected, not clamped"
        );
        assert!(
            parse_delete_events_query(&DeleteEventsQuery {
                all: None,
                before_days: Some(366),
            })
            .is_err(),
            "before_days above the cap must be rejected"
        );
        assert_eq!(
            parse_delete_events_query(&DeleteEventsQuery {
                all: None,
                before_days: Some(1),
            })
            .unwrap(),
            Cleanup::Before(1),
        );
        assert_eq!(
            parse_delete_events_query(&DeleteEventsQuery {
                all: None,
                before_days: Some(365),
            })
            .unwrap(),
            Cleanup::Before(365),
        );
        assert_eq!(
            parse_delete_events_query(&DeleteEventsQuery {
                all: Some(true),
                before_days: None,
            })
            .unwrap(),
            Cleanup::All,
        );
    }

    /// The purge must be strictly older (`created_at <`), never
    /// `<=`: an event written exactly at the cutoff stays.
    #[test]
    fn purge_filter_is_strictly_before_the_cutoff() {
        let query = notification_event::Entity::delete_many()
            .filter(
                notification_event::Column::CreatedAt
                    .lt(Utc::now() - Duration::days(30)),
            )
            .build(sea_orm::DbBackend::Postgres);
        assert!(
            query.sql.contains(r#""created_at" < "#),
            "expected a strict `<` bound, got: {}",
            query.sql
        );
        assert!(!query.sql.contains("<="), "{}", query.sql);

        // A full purge builds no WHERE clause at all.
        let query = notification_event::Entity::delete_many()
            .build(sea_orm::DbBackend::Postgres);
        assert!(!query.sql.to_uppercase().contains("WHERE"), "{}", query.sql);
    }

    #[test]
    fn list_events_query_uses_pagination() {
        let query: ListEventsQuery =
            serde_json::from_str(r#"{"page":"2","page_size":"50"}"#).unwrap();
        assert_eq!(query.pagination.page, 2);
        assert_eq!(query.pagination.page_size, 50);
        assert_eq!(query.event_type, None);

        // Page defaults to 1 and `page_size` keeps the shared default (50), so
        // an explicit `page_size=50` is honoured instead of being rewritten.
        let query: ListEventsQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(query.pagination.page, 1);
        assert_eq!(
            query.pagination.normalise().page_size,
            crate::api::common::DEFAULT_PAGE_SIZE
        );
        let explicit: ListEventsQuery =
            serde_json::from_str(r#"{"page_size":"50"}"#).unwrap();
        assert_eq!(
            explicit.pagination.normalise().page_size,
            crate::api::common::DEFAULT_PAGE_SIZE
        );

        let query: ListEventsQuery = serde_json::from_str(
            r#"{"event_type":"agent.offline","page_size":"1000"}"#,
        )
        .unwrap();
        assert_eq!(query.event_type.as_deref(), Some("agent.offline"));
        assert_eq!(query.pagination.normalise().page_size, 200);
    }
}
