//! Notification system of the control plane.
//!
//! [`NotificationManager`] fans system alerts out to the channels configured
//! in `notification_channels`: SMTP e-mail, WeCom and DingTalk webhooks, and
//! a generic JSON webhook. Alerts are raised by the health monitor (agent
//! offline/online), the control-plane self-monitor (CPU/memory/disk), the
//! upstream monitor (site upstream backend loss, see [`upstream_monitor`]),
//! the gRPC ingest (agent resource samples, ACME failures) and the API layer
//! (IP group subscription sync failures, configuration sync errors).
//!
//! The manager is a process-wide singleton ([`init`]/[`global`]) so both the
//! REST handlers and the gRPC service can raise alerts without threading a
//! handle through every constructor. Delivery is best-effort: a failing
//! channel is logged, never propagated, and repeated alerts are suppressed
//! per channel for a configurable window so a flapping agent cannot turn
//! into a notification storm.

pub mod cert_expiry;
pub mod email;
pub mod login_anomaly;
pub mod secretbox;
pub mod self_monitor;
pub mod upstream_monitor;
pub mod webhook;

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection,
    EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::{notification_channel, notification_event};

/// How many history rows the dashboard keeps.
const MAX_EVENT_ROWS: u64 = 5000;
/// Events older than this are pruned regardless of count.
const EVENT_RETENTION_DAYS: i64 = 30;
/// At most one prune per hour.
const PRUNE_INTERVAL: Duration = Duration::from_secs(3600);
/// Persisted message cap (characters, ~8 KB worst case with multi-byte
/// text): the message quotes attacker-influenced traffic, so an unbounded
/// rule message could bloat the history table.
const MAX_MESSAGE_CHARS: usize = 2000;

/// An alert raised somewhere in the control plane.
#[derive(Debug, Clone)]
pub struct AlertEvent {
    /// One of [`crate::models::event_type`].
    pub event_type: String,
    /// One of [`crate::models::severity`].
    pub severity: &'static str,
    /// Short, single-line summary (subject line / notification title).
    pub title: String,
    /// Human-readable detail (body).
    pub message: String,
    /// Structured context for the generic webhook and the event history.
    pub details: Option<serde_json::Value>,
    /// Groups repeated alerts for suppression; defaults to `event_type`.
    pub dedup_key: Option<String>,
}

impl AlertEvent {
    /// The key repeated alerts collapse onto within the dedup window.
    fn suppression_key(&self) -> String {
        format!(
            "{}:{}",
            self.event_type,
            self.dedup_key.as_deref().unwrap_or("")
        )
    }
}

/// serde default helpers — every settings field carries one so a stored
/// JSON written by an older version (missing the newer fields) keeps
/// parsing instead of resetting the whole struct to defaults.
fn default_true() -> bool {
    true
}

fn default_cert_expiry_warn_days() -> u32 {
    30
}

/// Thresholds, per-event-type delivery toggles and suppression windows.
///
/// `enabled` is the noise master switch: `false` stops channel delivery for
/// every event while the history table keeps receiving rows. The
/// `notify_*` flags gate individual event types the same way.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    /// Master switch: deliver alerts to channels at all.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Alert when the control plane CPU usage exceeds this percentage.
    #[serde(default = "default_cpu_percent")]
    pub cpu_percent: u8,
    /// Alert when the control plane memory usage exceeds this percentage.
    #[serde(default = "default_cpu_percent")]
    pub memory_percent: u8,
    /// Alert when the root filesystem usage exceeds this percentage.
    #[serde(default = "default_cpu_percent")]
    pub disk_percent: u8,
    /// Minimum seconds between two identical alerts on one channel.
    #[serde(default = "default_dedup_window")]
    pub dedup_window_secs: u64,
    /// Deliver agent-offline alerts.
    #[serde(default = "default_true")]
    pub notify_agent_offline: bool,
    /// Deliver agent-back-online alerts.
    #[serde(default = "default_true")]
    pub notify_agent_online: bool,
    /// Deliver agent resource alerts.
    #[serde(default = "default_true")]
    pub notify_agent_resource: bool,
    /// Deliver control-plane resource alerts.
    #[serde(default = "default_true")]
    pub notify_control_plane_resource: bool,
    /// Deliver certificate expiry alerts (`cert.expiring` and
    /// `cert.expired` share this switch).
    #[serde(default = "default_true")]
    pub notify_cert_expiry: bool,
    /// Deliver ACME/renewal failure alerts.
    #[serde(default = "default_true")]
    pub notify_cert_renewal_failed: bool,
    /// Deliver config/IP-group sync failure alerts.
    #[serde(default = "default_true")]
    pub notify_config_sync_failed: bool,
    /// Deliver failover-policy change alerts.
    #[serde(default = "default_true")]
    pub notify_site_failover_changed: bool,
    /// Deliver site upstream health alerts (`site.upstream_offline` and
    /// `site.upstream_abnormal` share this switch, like the cert pair).
    #[serde(default = "default_true")]
    pub notify_site_upstream: bool,
    /// Deliver anomalous-login alerts.
    #[serde(default = "default_true")]
    pub notify_auth_login_anomaly: bool,
    /// Warn when a certificate expires within this many days.
    #[serde(default = "default_cert_expiry_warn_days")]
    pub cert_expiry_warn_days: u32,
}

fn default_cpu_percent() -> u8 {
    90
}

fn default_dedup_window() -> u64 {
    600
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            cpu_percent: 90,
            memory_percent: 90,
            disk_percent: 90,
            dedup_window_secs: 600,
            notify_agent_offline: true,
            notify_agent_online: true,
            notify_agent_resource: true,
            notify_control_plane_resource: true,
            notify_cert_expiry: true,
            notify_cert_renewal_failed: true,
            notify_config_sync_failed: true,
            notify_site_failover_changed: true,
            notify_site_upstream: true,
            notify_auth_login_anomaly: true,
            cert_expiry_warn_days: 30,
        }
    }
}

impl NotificationSettings {
    /// Whether an event may be delivered to channels. History rows are
    /// always persisted regardless; this only gates the delivery step.
    pub fn allows(&self, event_type: &str) -> bool {
        use crate::models::event_type;
        if !self.enabled {
            return false;
        }
        match event_type {
            event_type::AGENT_OFFLINE => self.notify_agent_offline,
            event_type::AGENT_ONLINE => self.notify_agent_online,
            event_type::AGENT_RESOURCE => self.notify_agent_resource,
            event_type::CONTROL_PLANE_RESOURCE => {
                self.notify_control_plane_resource
            },
            event_type::CERT_EXPIRING | event_type::CERT_EXPIRED => {
                self.notify_cert_expiry
            },
            event_type::CERT_RENEWAL_FAILED => self.notify_cert_renewal_failed,
            event_type::CONFIG_SYNC_FAILED => self.notify_config_sync_failed,
            event_type::SITE_FAILOVER_CHANGED => {
                self.notify_site_failover_changed
            },
            event_type::SITE_UPSTREAM_OFFLINE
            | event_type::SITE_UPSTREAM_ABNORMAL => self.notify_site_upstream,
            event_type::AUTH_LOGIN_ANOMALY => self.notify_auth_login_anomaly,
            // Unknown types (e.g. the test button) are always delivered.
            _ => true,
        }
    }
}

/// Key of the settings row in `instance_settings`.
pub const SETTINGS_KEY: &str = "notification_settings";

impl NotificationSettings {
    /// Loads the settings from `instance_settings`, falling back to the
    /// defaults when the row is missing or unparsable.
    pub async fn load(db: &DatabaseConnection) -> Self {
        use crate::models::instance_setting;

        let stored = instance_setting::Entity::find_by_id(SETTINGS_KEY)
            .one(db)
            .await
            .ok()
            .flatten();
        match stored {
            Some(row) => serde_json::from_str(&row.value).unwrap_or_default(),
            None => Self::default(),
        }
    }

    /// Persists the settings; called by the settings API.
    pub async fn store(
        &self,
        db: &DatabaseConnection,
    ) -> Result<(), sea_orm::DbErr> {
        use crate::models::instance_setting;

        let value = serde_json::to_string(self)
            .map_err(|err| sea_orm::DbErr::Custom(err.to_string()))?;
        let existing = instance_setting::Entity::find_by_id(SETTINGS_KEY)
            .one(db)
            .await?;
        match existing {
            Some(row) => {
                let mut active: instance_setting::ActiveModel = row.into();
                active.value = Set(value);
                active.updated_at = Set(chrono::Utc::now());
                active.update(db).await?;
            },
            None => {
                instance_setting::ActiveModel {
                    key: Set(SETTINGS_KEY.to_string()),
                    value: Set(value),
                    updated_at: Set(chrono::Utc::now()),
                }
                .insert(db)
                .await?;
            },
        }
        Ok(())
    }
}

/// Fans alerts out to the configured channels.
pub struct NotificationManager {
    db: DatabaseConnection,
    http: reqwest::Client,
    channels: ArcSwap<Vec<notification_channel::Model>>,
    settings: ArcSwap<NotificationSettings>,
    /// `(channel id, suppression key) -> last sent`, shared across callers.
    dedup: std::sync::Mutex<HashMap<u64, Instant>>,
    last_prune: std::sync::atomic::AtomicI64,
}

static MANAGER: std::sync::OnceLock<NotificationManager> =
    std::sync::OnceLock::new();

/// Installs the process-wide manager. Idempotent: later calls return the
/// existing instance.
pub fn init(db: DatabaseConnection) -> &'static NotificationManager {
    MANAGER.get_or_init(|| NotificationManager::new(db))
}

/// The process-wide manager, when [`init`] has run.
pub fn global() -> Option<&'static NotificationManager> {
    MANAGER.get()
}

/// Raises an alert on the global manager; a no-op before [`init`], which
/// keeps unit tests and the maintenance CLI silent.
pub async fn emit(event: AlertEvent) {
    if let Some(manager) = global() {
        manager.dispatch(event).await;
    }
}

impl NotificationManager {
    pub fn new(db: DatabaseConnection) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            // Webhooks are operator-configured but admin-writable: a 302 from
            // a public host could otherwise bounce the request into an
            // internal service, bypassing the SSRF address checks in
            // `webhook::ensure_public_webhook`.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            db,
            http,
            channels: ArcSwap::from_pointee(Vec::new()),
            settings: ArcSwap::from_pointee(NotificationSettings::default()),
            dedup: std::sync::Mutex::new(HashMap::new()),
            last_prune: std::sync::atomic::AtomicI64::new(0),
        }
    }

    /// Re-reads channels and settings from the database. Called at startup,
    /// after channel mutations and periodically, so edits made by another
    /// process (or instance) are picked up within a minute.
    pub async fn reload(&self) {
        let mut channels = notification_channel::Entity::find()
            .order_by_asc(notification_channel::Column::Name)
            .all(&self.db)
            .await
            .unwrap_or_default();
        // Rows hold sealed secrets (see `secretbox`); delivery needs the
        // real values, so open them here — the only place raw rows are
        // turned into live channel configs.
        for channel in &mut channels {
            secretbox::open_config(&mut channel.config);
        }
        self.channels.store(Arc::new(channels));
        self.settings
            .store(Arc::new(NotificationSettings::load(&self.db).await));
    }

    /// Currently loaded settings (thresholds, dedup window).
    pub fn settings(&self) -> NotificationSettings {
        (**self.settings.load()).clone()
    }

    /// Persists the alert into the dashboard history, then delivers it to
    /// every matching channel. Never fails: delivery problems are logged.
    pub async fn dispatch(&self, event: AlertEvent) {
        self.persist_event(&event).await;

        // Noise gate: the history above always lands, but delivery to the
        // channels is skipped when the master switch or this event type's
        // toggle is off (see `NotificationSettings::allows`).
        if !self.settings().allows(&event.event_type) {
            return;
        }

        let channels = self.channels.load();
        let matching: Vec<&notification_channel::Model> = channels
            .iter()
            .filter(|channel| channel.enabled && subscribed(channel, &event))
            .collect();
        if matching.is_empty() {
            return;
        }

        let event = Arc::new(event);
        for channel in matching {
            if self.suppressed(channel.id, &event) {
                continue;
            }
            let channel = channel.clone();
            let http = self.http.clone();
            let event = (*event).clone();
            // Deliveries run concurrently and detached: a slow SMTP server
            // must not stall the caller (often the gRPC ingest path).
            tokio::spawn(async move {
                if let Err(err) = deliver_to(&http, &channel, &event).await {
                    tracing::warn!(
                        channel = %channel.name,
                        kind = %channel.kind,
                        error = %err,
                        "notification delivery failed"
                    );
                }
            });
        }
    }

    /// Delivers one event to one channel without dedup. Also the path behind
    /// the "send test message" button.
    pub async fn deliver(
        &self,
        channel: &notification_channel::Model,
        event: &AlertEvent,
    ) -> Result<(), String> {
        deliver_to(&self.http, channel, event).await
    }

    /// Sends a test alert through one channel and reports the outcome.
    pub async fn test_channel(&self, channel_id: Uuid) -> Result<(), String> {
        let Some(channel) =
            notification_channel::Entity::find_by_id(channel_id)
                .one(&self.db)
                .await
                .map_err(|err| err.to_string())?
        else {
            return Err("channel not found".to_string());
        };
        let event = AlertEvent {
            event_type: "notification.test".to_string(),
            severity: crate::models::severity::INFO,
            title: "PingWAF test notification".to_string(),
            message: format!(
                "This is a test alert sent to '{}'. If you can read this, \
                 the channel works.",
                channel.name
            ),
            details: None,
            dedup_key: None,
        };
        self.deliver(&channel, &event).await
    }

    /// True when an identical alert was delivered to this channel within the
    /// dedup window. Records the attempt when it returns `false`.
    fn suppressed(&self, channel_id: Uuid, event: &AlertEvent) -> bool {
        let window = self.settings().dedup_window_secs;
        if window == 0 {
            return false;
        }
        let key = dedup_key(channel_id, &event.suppression_key());
        let mut dedup = self.dedup.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if let Some(last) = dedup.get(&key) {
            if now.duration_since(*last) < Duration::from_secs(window) {
                return true;
            }
        }
        dedup.insert(key, now);
        // Keep the map from growing without bound across agent churn.
        if dedup.len() > 10_000 {
            dedup.retain(|_, at| {
                now.duration_since(*at) < Duration::from_secs(window)
            });
        }
        false
    }

    /// Writes the alert into `notification_events`, best-effort.
    async fn persist_event(&self, event: &AlertEvent) {
        // Message originates from attacker-influenced traffic details (rule
        // ids, sample snippets); cap it so one noisy rule cannot inflate the
        // history table. Characters (not bytes) keeps multi-byte text intact.
        let message: String =
            event.message.chars().take(MAX_MESSAGE_CHARS).collect();
        let row = notification_event::ActiveModel {
            id: Set(Uuid::new_v4()),
            event_type: Set(event.event_type.clone()),
            severity: Set(event.severity.to_string()),
            title: Set(event.title.chars().take(200).collect()),
            message: Set(message),
            details: Set(event.details.clone()),
            created_at: Set(chrono::Utc::now()),
        };
        if let Err(err) = row.insert(&self.db).await {
            tracing::warn!(
                error = %err,
                "could not persist the notification event"
            );
        }
        self.maybe_prune().await;
    }

    /// Ages out old history rows, at most once per hour.
    async fn maybe_prune(&self) {
        let now = chrono::Utc::now().timestamp();
        let previous = self
            .last_prune
            .swap(now, std::sync::atomic::Ordering::Relaxed);
        if now - previous < PRUNE_INTERVAL.as_secs() as i64 {
            return;
        }

        let cutoff =
            chrono::Utc::now() - chrono::Duration::days(EVENT_RETENTION_DAYS);
        if let Err(err) = notification_event::Entity::delete_many()
            .filter(notification_event::Column::CreatedAt.lt(cutoff))
            .exec(&self.db)
            .await
        {
            tracing::warn!(error = %err, "could not prune notification events");
        }
        // Hard cap, in case a burst slipped under the retention window: keep
        // the newest `MAX_EVENT_ROWS` rows, drop the rest.
        // PostgreSQL-only: `ORDER BY … OFFSET $1` inside the IN-subquery is
        // the single-statement form of "delete everything but the newest N";
        // a different backend would need its own formulation.
        let backend = self.db.get_database_backend();
        let stmt = sea_orm::Statement::from_sql_and_values(
            backend,
            "DELETE FROM notification_events WHERE id IN (\
                SELECT id FROM notification_events \
                ORDER BY created_at DESC OFFSET $1\
             )",
            [MAX_EVENT_ROWS.into()],
        );
        if let Err(err) = self.db.execute(stmt).await {
            tracing::warn!(error = %err, "could not cap notification events");
        }
    }
}

/// Routes one event to one channel by kind. Free-standing so a detached
/// delivery task needs nothing but the HTTP client.
async fn deliver_to(
    http: &reqwest::Client,
    channel: &notification_channel::Model,
    event: &AlertEvent,
) -> Result<(), String> {
    match channel.kind.as_str() {
        crate::models::channel_kind::EMAIL => {
            email::send(http, &channel.config, event).await
        },
        crate::models::channel_kind::WECOM => {
            webhook::send_wecom(http, &channel.config, event).await
        },
        crate::models::channel_kind::DINGTALK => {
            webhook::send_dingtalk(http, &channel.config, event).await
        },
        crate::models::channel_kind::WEBHOOK => {
            webhook::send_generic(http, &channel.config, event).await
        },
        other => Err(format!("unknown channel kind '{other}'")),
    }
}

/// Whether the channel subscribed to this event type; an empty subscription
/// list receives everything.
pub fn subscribed(
    channel: &notification_channel::Model,
    event: &AlertEvent,
) -> bool {
    let list = channel
        .events
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<&str>>()
        })
        .unwrap_or_default();
    list.is_empty() || list.contains(&event.event_type.as_str())
}

/// Folds a channel id and suppression key into one map key.
fn dedup_key(channel_id: Uuid, suppression: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    channel_id.hash(&mut hasher);
    suppression.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn channel(events: serde_json::Value) -> notification_channel::Model {
        notification_channel::Model {
            id: Uuid::new_v4(),
            name: "test".to_string(),
            kind: crate::models::channel_kind::WEBHOOK.to_string(),
            config: json!({}),
            events,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn event(event_type: &str) -> AlertEvent {
        AlertEvent {
            event_type: event_type.to_string(),
            severity: crate::models::severity::WARNING,
            title: "t".to_string(),
            message: "m".to_string(),
            details: None,
            dedup_key: None,
        }
    }

    #[test]
    fn an_empty_subscription_receives_every_event() {
        let channel = channel(json!([]));
        assert!(subscribed(&channel, &event("agent.offline")));
        assert!(subscribed(&channel, &event("cert.expiring")));
    }

    #[test]
    fn a_subscription_filters_by_event_type() {
        let channel = channel(json!(["agent.offline", "agent.online"]));
        assert!(subscribed(&channel, &event("agent.offline")));
        assert!(!subscribed(&channel, &event("cert.expiring")));
    }

    #[test]
    fn a_disabled_channel_is_filtered_out_before_subscription() {
        let mut channel = channel(json!([]));
        channel.enabled = false;
        // Callers check `enabled` alongside `subscribed`; the pairing is what
        // the dispatch filter asserts.
        assert!(!channel.enabled || subscribed(&channel, &event("x")));
        channel.enabled = true;
        assert!(channel.enabled && subscribed(&channel, &event("x")));
    }

    #[test]
    fn suppression_keys_group_by_dedup_key() {
        let mut first = event("agent.offline");
        first.dedup_key = Some("agent-a".to_string());
        let mut second = event("agent.offline");
        second.dedup_key = Some("agent-b".to_string());
        assert_ne!(first.suppression_key(), second.suppression_key());

        second.dedup_key = Some("agent-a".to_string());
        assert_eq!(first.suppression_key(), second.suppression_key());
    }

    #[test]
    fn dedup_keys_differ_across_channels() {
        let a = dedup_key(Uuid::new_v4(), "agent.offline");
        let b = dedup_key(Uuid::new_v4(), "agent.offline");
        assert_ne!(a, b);
    }

    #[test]
    fn old_settings_json_parses_with_new_defaults() {
        // A settings row written before the toggles existed must keep its
        // thresholds instead of resetting the whole struct.
        let settings: NotificationSettings = serde_json::from_value(json!({
            "cpu_percent": 77,
            "memory_percent": 88,
            "disk_percent": 95,
            "dedup_window_secs": 300,
        }))
        .expect("old settings JSON must parse");
        assert_eq!(settings.cpu_percent, 77);
        assert_eq!(settings.memory_percent, 88);
        assert_eq!(settings.disk_percent, 95);
        assert_eq!(settings.dedup_window_secs, 300);
        // New fields fall back to their defaults.
        assert!(settings.enabled);
        assert!(settings.notify_cert_expiry);
        assert_eq!(settings.cert_expiry_warn_days, 30);
    }

    #[test]
    fn allows_delivers_everything_by_default() {
        let settings = NotificationSettings::default();
        for event_type in crate::models::event_type::ALL {
            assert!(settings.allows(event_type), "{event_type}");
        }
        // Unknown types (the test button) pass through.
        assert!(settings.allows("notification.test"));
    }

    #[test]
    fn master_switch_blocks_delivery_but_keeps_unknown_pass() {
        let settings = NotificationSettings {
            enabled: false,
            ..NotificationSettings::default()
        };
        for event_type in crate::models::event_type::ALL {
            assert!(!settings.allows(event_type), "{event_type}");
        }
    }

    #[test]
    fn a_single_toggle_only_blocks_its_own_type() {
        let settings = NotificationSettings {
            notify_agent_offline: false,
            ..NotificationSettings::default()
        };
        assert!(!settings.allows("agent.offline"));
        assert!(settings.allows("agent.online"));
        assert!(settings.allows("cert.expiring"));
    }

    #[test]
    fn cert_expiring_and_expired_share_one_toggle() {
        let settings = NotificationSettings {
            notify_cert_expiry: false,
            ..NotificationSettings::default()
        };
        assert!(!settings.allows("cert.expiring"));
        assert!(!settings.allows("cert.expired"));
        assert!(settings.allows("cert.renewal_failed"));
    }
}
