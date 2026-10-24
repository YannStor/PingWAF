//! Agent health monitoring.
//!
//! This module provides a background task that periodically checks the
//! `last_heartbeat` timestamp of registered agents. If an agent has not sent
//! a heartbeat within 3× the configured interval, it is marked as offline
//! and an optional webhook notification is dispatched.
//!
//! The task runs inside the same tokio runtime as the control plane and shares
//! the database connection pool.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use serde::Serialize;

use crate::config::ServerConfig;
use crate::grpc::AgentRegistry;
use crate::models::{
    agent, agent_status, visitor_auth_state, visitor_passkey_state,
};

/// Payload sent to the webhook URL when an agent goes offline.
#[derive(Debug, Clone, Serialize)]
pub struct AgentOfflineEvent {
    /// Agent UUID.
    pub agent_id: String,
    /// Agent hostname.
    pub hostname: String,
    /// Agent IP address.
    pub ip_address: String,
    /// Site ID the agent is bound to (if any).
    pub site_id: Option<String>,
    /// Timestamp of the last heartbeat received.
    pub last_heartbeat: Option<String>,
    /// When the agent was marked offline.
    pub marked_offline_at: String,
    /// Event type discriminator.
    pub event: &'static str,
}

/// Payload sent to the webhook URL when an agent comes back online.
#[derive(Debug, Clone, Serialize)]
pub struct AgentOnlineEvent {
    /// Agent UUID.
    pub agent_id: String,
    /// Agent hostname.
    pub hostname: String,
    /// Agent IP address.
    pub ip_address: String,
    /// Site ID the agent is bound to (if any).
    pub site_id: Option<String>,
    /// When the agent was marked online.
    pub marked_online_at: String,
    /// Event type discriminator.
    pub event: &'static str,
}

/// Configuration for the health monitor.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// How often to check for stale agents (default: 30 seconds).
    pub check_interval: Duration,
    /// Multiplier of the heartbeat interval after which an agent is considered
    /// offline (default: 3).
    pub stale_multiplier: u32,
    /// Webhook URL for notifications. `None` disables notifications.
    pub webhook_url: Option<String>,
    /// HTTP client timeout for webhook posts.
    pub webhook_timeout: Duration,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            stale_multiplier: 3,
            webhook_url: None,
            webhook_timeout: Duration::from_secs(10),
        }
    }
}

impl MonitorConfig {
    /// Creates a monitor config from the server configuration.
    pub fn from_server_config(config: &ServerConfig) -> Self {
        let interval_secs = config.heartbeat_interval_seconds.max(5) as u64;
        Self {
            check_interval: Duration::from_secs(interval_secs),
            stale_multiplier: 3,
            webhook_url: std::env::var("PINGWAF_WEBHOOK_URL")
                .ok()
                .filter(|url| !url.is_empty()),
            webhook_timeout: Duration::from_secs(10),
        }
    }
}

/// Starts the background health monitor task.
///
/// This function spawns a tokio task that runs indefinitely until the process
/// shuts down. It returns the `JoinHandle` so the caller can optionally await
/// or abort it.
pub fn start_health_monitor(
    db: DatabaseConnection,
    config: Arc<ServerConfig>,
    monitor_config: MonitorConfig,
    registry: AgentRegistry,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(health_monitor_loop(db, config, monitor_config, registry))
}

/// Main loop: periodically scans for stale agents and updates their status.
async fn health_monitor_loop(
    db: DatabaseConnection,
    config: Arc<ServerConfig>,
    monitor_config: MonitorConfig,
    registry: AgentRegistry,
) {
    let stale_threshold = Duration::from_secs(
        (config.heartbeat_interval_seconds.max(1) as u64)
            * (monitor_config.stale_multiplier as u64),
    );

    let http_client = reqwest::Client::builder()
        .timeout(monitor_config.webhook_timeout)
        .build()
        .unwrap_or_default();

    tracing::info!(
        check_interval_secs = monitor_config.check_interval.as_secs(),
        stale_threshold_secs = stale_threshold.as_secs(),
        webhook = monitor_config.webhook_url.is_some(),
        "agent health monitor started"
    );

    loop {
        tokio::time::sleep(monitor_config.check_interval).await;

        if let Err(err) = check_stale_agents(
            &db,
            &registry,
            stale_threshold,
            &monitor_config,
            &http_client,
        )
        .await
        {
            tracing::warn!(error = %err, "health monitor check failed");
        }

        // The boot history is append-only and grows by one row per restart, so
        // a container in a restart loop would otherwise fill it. Same loop,
        // because it is already periodic and already holds the database.
        if let Err(err) = crate::boot_history::sweep_boots(&db).await {
            tracing::warn!(error = %err, "boot history sweep failed");
        }

        // Visitor login challenges and passkey ceremonies are written by
        // anonymous requests — anyone who loads a login page creates one — so
        // without this they accumulate forever. Expired rows are useless by
        // definition: a challenge past its expiry cannot be answered, and a
        // ceremony past its expiry cannot be finished.
        if let Err(err) = sweep_visitor_states(&db).await {
            tracing::warn!(error = %err, "visitor state sweep failed");
        }
    }
}

/// Drops expired visitor login challenges and passkey ceremony state.
///
/// Both tables are keyed by a random id and read once, so an expired row is
/// dead weight the moment it expires. They are swept here rather than by a
/// `cascade` because nothing owns them: a challenge belongs to no account
/// until it is answered.
async fn sweep_visitor_states(
    db: &DatabaseConnection,
) -> Result<u64, sea_orm::DbErr> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    let now = chrono::Utc::now();
    let challenges = visitor_auth_state::Entity::delete_many()
        .filter(visitor_auth_state::Column::ExpiresAt.lt(now))
        .exec(db)
        .await?
        .rows_affected;
    let ceremonies = visitor_passkey_state::Entity::delete_many()
        .filter(visitor_passkey_state::Column::ExpiresAt.lt(now))
        .exec(db)
        .await?
        .rows_affected;
    Ok(challenges + ceremonies)
}

/// Scans all agents marked as online and demotes those with stale heartbeats.
async fn check_stale_agents(
    db: &DatabaseConnection,
    registry: &AgentRegistry,
    stale_threshold: Duration,
    monitor_config: &MonitorConfig,
    http_client: &reqwest::Client,
) -> anyhow::Result<()> {
    let now = Utc::now();
    let cutoff = now
        - chrono::Duration::from_std(stale_threshold)
            .unwrap_or(chrono::Duration::seconds(90));

    // Find agents currently marked online whose last heartbeat is older than cutoff
    let stale_agents = agent::Entity::find()
        .filter(agent::Column::Status.eq(agent_status::ONLINE))
        .filter(agent::Column::LastHeartbeat.lt(cutoff))
        .all(db)
        .await?;

    for row in &stale_agents {
        // Skip if the agent has a live stream (heartbeat may lag behind the
        // in-memory connection state).
        if registry.is_connected(&row.id).await {
            continue;
        }

        // Update status in the database
        let mut active: agent::ActiveModel = row.clone().into();
        active.status = Set(agent_status::OFFLINE.to_string());
        active.update(db).await?;

        tracing::warn!(
            agent_id = %row.id,
            hostname = %row.hostname,
            ip = %row.ip_address,
            last_heartbeat = ?row.last_heartbeat,
            "agent marked offline (stale heartbeat)"
        );

        crate::notify::emit(crate::notify::AlertEvent {
            event_type: crate::models::event_type::AGENT_OFFLINE.to_string(),
            severity: crate::models::severity::CRITICAL,
            title: format!("Agent {} went offline", row.hostname),
            message: format!(
                "Agent '{}' ({}, {}) stopped sending heartbeats; the last \
                 one arrived {}. Sites bound to it run on their cached \
                 configuration until it reconnects.",
                row.hostname,
                row.id,
                row.ip_address,
                row.last_heartbeat
                    .map(|ts| ts.to_rfc3339())
                    .unwrap_or_else(|| "never".to_string()),
            ),
            details: Some(serde_json::json!({
                "agent_id": row.id,
                "hostname": row.hostname,
                "ip_address": row.ip_address,
                "site_id": row.site_id,
                "last_heartbeat": row.last_heartbeat,
            })),
            dedup_key: Some(row.id.to_string()),
        })
        .await;

        // Send webhook notification
        if let Some(url) = &monitor_config.webhook_url {
            let event = AgentOfflineEvent {
                agent_id: row.id.to_string(),
                hostname: row.hostname.clone(),
                ip_address: row.ip_address.clone(),
                site_id: row.site_id.map(|id| id.to_string()),
                last_heartbeat: row.last_heartbeat.map(|ts| ts.to_rfc3339()),
                marked_offline_at: now.to_rfc3339(),
                event: "agent.offline",
            };
            send_webhook(http_client, url, &event).await;
        }
    }

    // Also check for agents that were offline but have reconnected
    let offline_agents = agent::Entity::find()
        .filter(agent::Column::Status.eq(agent_status::OFFLINE))
        .all(db)
        .await?;

    for row in &offline_agents {
        if registry.is_connected(&row.id).await {
            let mut active: agent::ActiveModel = row.clone().into();
            active.status = Set(agent_status::ONLINE.to_string());
            active.update(db).await?;

            tracing::info!(
                agent_id = %row.id,
                hostname = %row.hostname,
                "agent marked online (reconnected)"
            );

            crate::notify::emit(crate::notify::AlertEvent {
                event_type: crate::models::event_type::AGENT_ONLINE.to_string(),
                severity: crate::models::severity::INFO,
                title: format!("Agent {} is back online", row.hostname),
                message: format!(
                    "Agent '{}' ({}, {}) reconnected to the control plane.",
                    row.hostname, row.id, row.ip_address
                ),
                details: Some(serde_json::json!({
                    "agent_id": row.id,
                    "hostname": row.hostname,
                    "ip_address": row.ip_address,
                    "site_id": row.site_id,
                })),
                dedup_key: Some(row.id.to_string()),
            })
            .await;

            if let Some(url) = &monitor_config.webhook_url {
                let event = AgentOnlineEvent {
                    agent_id: row.id.to_string(),
                    hostname: row.hostname.clone(),
                    ip_address: row.ip_address.clone(),
                    site_id: row.site_id.map(|id| id.to_string()),
                    marked_online_at: now.to_rfc3339(),
                    event: "agent.online",
                };
                send_webhook(http_client, url, &event).await;
            }
        }
    }

    Ok(())
}

/// Sends a JSON webhook notification. Failures are logged but not propagated.
async fn send_webhook<T: Serialize>(
    client: &reqwest::Client,
    url: &str,
    payload: &T,
) {
    match client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "PingWAF/monitoring")
        .json(payload)
        .send()
        .await
    {
        Ok(response) => {
            if !response.status().is_success() {
                tracing::warn!(
                    url = %url,
                    status = %response.status(),
                    "webhook returned non-success status"
                );
            }
        },
        Err(err) => {
            tracing::warn!(url = %url, error = %err, "failed to send webhook notification");
        },
    }
}
