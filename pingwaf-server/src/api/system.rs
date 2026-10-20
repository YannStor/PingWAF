//! Read-only process observation: CPU/memory snapshots and the module/method
//! attribution tables.
//!
//! This is the successor of the removed pprof endpoints. Two differences are
//! deliberate:
//!
//! * Nothing here samples stacks or writes profile files. `/system/metrics`
//!   reads counters the OS already keeps; `/system/profile` reads the
//!   accounting tables the data plane and control plane maintain themselves
//!   (`pingwaf-profiler`).
//! * Both are ordinary admin endpoints, so they work on every platform and
//!   in every build — there is no diagnostic-only image to deploy.
//!
//! `/system/nodes` is the fleet view built from the same material: this
//! process's counters plus one row per registered agent. It is what the
//! dashboard's node table renders, and the only endpoint that answers "how
//! loaded is the fleet" in one request.

use std::collections::HashMap;

use axum::extract::State;
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect,
};
use serde::Serialize;
use uuid::Uuid;

use crate::api::common::query_all;
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AdminUser;
use crate::models::{agent, api_key, site};

/// `GET /api/v1/system/metrics` — process/host CPU and memory snapshots.
#[derive(Debug, Serialize)]
pub struct SystemMetrics {
    /// Process and machine CPU usage.
    pub cpu: pingwaf_system::CpuLiveStats,
    /// Process RSS, host RAM and container memory accounting.
    pub memory: pingwaf_system::MemorySnapshot,
}

async fn metrics(_admin: AdminUser) -> Result<Json<SystemMetrics>, ApiError> {
    // Both snapshots touch /proc (or the platform equivalent): keep that off
    // the async workers.
    let (cpu, memory) = tokio::task::spawn_blocking(|| {
        (
            pingwaf_system::cpu_snapshot(),
            pingwaf_system::memory_snapshot(),
        )
    })
    .await
    .map_err(|err| ApiError::Internal(err.to_string()))?;
    Ok(Json(SystemMetrics { cpu, memory }))
}

/// `GET /api/v1/system/profile` — module and method CPU/memory attribution.
///
/// The response is bounded (seven module rows, at most
/// [`pingwaf_profiler::ProfileSnapshot::MAX_METHODS`] method rows) and
/// computed from atomics, so polling it is cheap.
async fn profile(
    _admin: AdminUser,
    State(_state): State<AppState>,
) -> Json<pingwaf_profiler::ProfileSnapshot> {
    Json(pingwaf_profiler::ProfileSnapshot::collect())
}

/// `GET /api/v1/system/nodes` — this process plus every registered agent.
///
/// One request answers what the dashboard's node view needs: the control
/// plane's own CPU/memory/attribution, and per agent its identity, status,
/// last heartbeat and the edge counters retained from that heartbeat.
#[derive(Debug, Serialize)]
pub struct NodesView {
    /// The control-plane process serving the request.
    pub control: ControlNode,
    /// Registered agents, ordered by hostname so the table does not reshuffle
    /// between polls.
    pub agents: Vec<AgentNode>,
}

/// Resource counters of the control-plane process itself.
#[derive(Debug, Serialize)]
pub struct ControlNode {
    /// CPU used by this process, in percent of one core (can exceed 100).
    pub process_cpu_percent: f32,
    /// Machine-wide CPU usage, in percent.
    pub host_cpu_percent: f32,
    /// Cores on the machine.
    pub cores: usize,
    /// Process RSS in bytes.
    pub rss_bytes: u64,
    /// Peak process RSS since start, in bytes (`0` where the OS does not
    /// expose it).
    pub rss_peak_bytes: u64,
    /// Requests the profiler attributed to the `control` module.
    pub requests: u64,
    /// Mean wall-clock time per attributed control request, in milliseconds.
    pub avg_elapsed_ms: f64,
}

/// One agent as the node view shows it.
///
/// Every field the control plane may not know yet is `null` rather than `0`:
/// a node that has never heartbeated reports no CPU, and rendering that as
/// "0 %" would read as an idle node instead of an unknown one.
#[derive(Debug, Serialize)]
pub struct AgentNode {
    pub id: Uuid,
    /// Display name. The inventory keeps one identity per node — its
    /// `hostname` — so that is what this carries.
    pub name: String,
    /// `online` / `offline` / `degraded`, as last reported.
    pub status: String,
    /// CPU load of the node, in percent. `None` = no sample retained.
    pub cpu_percent: Option<f64>,
    /// Memory in use on the node, in bytes. `None` = no sample retained.
    pub memory_bytes: Option<u64>,
    /// Connections currently handled by the edge process. `None` = never
    /// reported.
    pub connections: Option<u64>,
    /// Requests per second handled by the edge. `None` = never reported.
    ///
    /// The heartbeat carries this counter, but the control plane retains no
    /// per-agent copy of it, so the field is `null` for every node today. It
    /// stays in the contract because it is the one figure an operator asks
    /// for first; filling it needs the heartbeat counters to be kept (see
    /// the note in [`HeartbeatMetrics`]).
    pub rps: Option<u64>,
    /// Sites this agent serves: `1` for a bound agent, and for a global
    /// (unbound) agent every site of its API key's owner — the same
    /// visibility the config push uses.
    pub sites: u64,
    /// Last heartbeat, in server time. `None` = never heard from.
    pub last_seen: Option<DateTime<Utc>>,
}

/// Counter values the control plane retained from an agent's last heartbeat.
///
/// This is the single place that decides how an observed value becomes an
/// [`AgentNode`] field, so the mapping is testable without a database.
///
/// The heartbeat itself is not kept: the control plane folds it into
/// `host_samples` (CPU/memory) and `agent_metrics` (connection gauge) and
/// discards the rest, which is why `rps` has no source and stays `None`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HeartbeatMetrics {
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub connections: Option<u64>,
    pub rps: Option<u64>,
}

async fn nodes(
    _admin: AdminUser,
    State(state): State<AppState>,
) -> Result<Json<NodesView>, ApiError> {
    // The snapshots read /proc; keep that off the async workers (same reason
    // as `/system/metrics`).
    let (cpu, memory) = tokio::task::spawn_blocking(|| {
        (
            pingwaf_system::cpu_snapshot(),
            pingwaf_system::memory_snapshot(),
        )
    })
    .await
    .map_err(|err| ApiError::Internal(err.to_string()))?;
    let profile = pingwaf_profiler::ProfileSnapshot::collect();
    Ok(Json(NodesView {
        control: control_node(&cpu, &memory, &profile),
        agents: agent_nodes(&state.db).await?,
    }))
}

/// Projects the OS snapshots and the profiler's `control` row.
fn control_node(
    cpu: &pingwaf_system::CpuLiveStats,
    memory: &pingwaf_system::MemorySnapshot,
    profile: &pingwaf_profiler::ProfileSnapshot,
) -> ControlNode {
    // `ProfileSnapshot::collect` emits one row per module (`Module::ALL`), so
    // the `control` row exists even before the first request; the fallback
    // keeps the handler total instead of panicking if that ever changes.
    let control = profile.modules.iter().find(|row| row.module == "control");
    let (requests, avg_us) = control
        .map(|row| (row.calls, row.avg_us))
        .unwrap_or((0, 0.0));
    ControlNode {
        process_cpu_percent: cpu.process_cpu_percent,
        host_cpu_percent: cpu.host_cpu_percent,
        cores: cpu.cores,
        rss_bytes: memory.rss_bytes,
        rss_peak_bytes: memory.rss_peak_bytes,
        requests,
        avg_elapsed_ms: avg_us / 1000.0,
    }
}

/// Loads the fleet and joins the retained heartbeat counters onto each row.
async fn agent_nodes(
    db: &DatabaseConnection,
) -> Result<Vec<AgentNode>, ApiError> {
    let rows = agent::Entity::find()
        .order_by_asc(agent::Column::Hostname)
        .all(db)
        .await?;
    if rows.is_empty() {
        // No query below is meaningful without ids, and an empty fleet must
        // come back as `[]`, not as a list of ghost rows.
        return Ok(Vec::new());
    }

    let ids: Vec<Uuid> = rows.iter().map(|row| row.id).collect();

    let mut counters = latest_samples(db, &ids).await?;
    for (id, connections) in latest_connections(db, &ids).await? {
        counters.entry(id).or_default().connections = Some(connections);
    }
    let sites = agent_site_counts(db, &rows).await?;

    let unknown = HeartbeatMetrics::default();
    Ok(rows
        .iter()
        .map(|row| {
            agent_node(
                row,
                counters.get(&row.id).unwrap_or(&unknown),
                sites.get(&row.id).copied().unwrap_or(0),
            )
        })
        .collect())
}

/// Maps one inventory row plus its retained counters onto the response.
fn agent_node(
    row: &agent::Model,
    counters: &HeartbeatMetrics,
    sites: u64,
) -> AgentNode {
    AgentNode {
        id: row.id,
        name: row.hostname.clone(),
        status: row.status.clone(),
        // A NaN would serialise as `null` anyway; dropping it here keeps the
        // struct free of a value nothing can compare.
        cpu_percent: counters.cpu_percent.filter(|value| value.is_finite()),
        memory_bytes: counters.memory_bytes,
        connections: counters.connections,
        rps: counters.rps,
        sites,
        last_seen: row.last_heartbeat,
    }
}

/// Newest host probe sample per agent, in one round trip.
///
/// The probe is what the edge samples for `cpu_usage_percent` and
/// `memory_usage_bytes`: the heartbeat's own copies of those two are not
/// persisted, but the raw samples are, so the newest one is the same
/// measurement at most one heartbeat interval older. A node that has not been
/// sampled yet stays `None`.
async fn latest_samples(
    db: &DatabaseConnection,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, HeartbeatMetrics>, ApiError> {
    // `DISTINCT ON` is the cheapest "newest row per agent" on PostgreSQL and
    // rides the `(agent_id, sampled_at DESC)` index.
    const SQL: &str = "SELECT DISTINCT ON (agent_id) agent_id, \
                       cpu_usage_percent, memory_used_bytes \
                       FROM host_samples \
                       WHERE agent_id = ANY($1) \
                       ORDER BY agent_id, sampled_at DESC";
    let mut out = HashMap::with_capacity(ids.len());
    for row in latest_rows(db, SQL, ids).await? {
        let agent_id = required::<Uuid>(&row, "agent_id")?;
        let cpu_percent = optional::<f64>(&row, "cpu_usage_percent")?;
        // The column is a signed bigint; a negative count is a corrupt
        // sample, not a byte total, so it reads as unknown.
        let memory_bytes = optional::<i64>(&row, "memory_used_bytes")?
            .and_then(|bytes| u64::try_from(bytes).ok());
        out.insert(
            agent_id,
            HeartbeatMetrics {
                cpu_percent,
                memory_bytes,
                ..Default::default()
            },
        );
    }
    Ok(out)
}

/// Newest `pingwaf_active_connections` gauge per agent.
///
/// The agent publishes this counter on the metrics stream, and it is built
/// from the very value its heartbeat carries as `active_connections`. It is
/// the only place that number survives: the heartbeat itself is not stored.
/// A deployment that disables metric shipping leaves it `None`, which is why
/// the field is nullable.
async fn latest_connections(
    db: &DatabaseConnection,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, u64>, ApiError> {
    const SQL: &str = "SELECT DISTINCT ON (agent_id) agent_id, value \
                       FROM agent_metrics \
                       WHERE name = 'pingwaf_active_connections' \
                       AND agent_id = ANY($1) \
                       ORDER BY agent_id, recorded_at DESC";
    let mut out = HashMap::with_capacity(ids.len());
    for row in latest_rows(db, SQL, ids).await? {
        let agent_id = required::<Uuid>(&row, "agent_id")?;
        let value = required::<f64>(&row, "value")?;
        if let Some(connections) = gauge_to_u64(value) {
            out.insert(agent_id, connections);
        }
    }
    Ok(out)
}

/// Runs one of the two "newest row per agent" queries with the fleet bound as
/// a `uuid[]`, so the whole list costs one round trip.
async fn latest_rows(
    db: &DatabaseConnection,
    sql: &str,
    ids: &[Uuid],
) -> Result<Vec<sea_orm::QueryResult>, ApiError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    query_all(db, sql, vec![sea_orm::Value::from(ids.to_vec())]).await
}

/// Rounds a gauge to a whole count, refusing values no count can hold.
///
/// A brief underflow in the edge's connection counter is reported as a
/// negative gauge; rendering that as a wrapped `u64` would show ~1.8e19
/// connections.
fn gauge_to_u64(value: f64) -> Option<u64> {
    (value.is_finite() && value >= 0.0).then(|| value.round() as u64)
}

/// How many sites each agent serves.
///
/// A bound agent serves exactly its own site. An unbound ("global") agent
/// serves every site of its API key's owner — `agent_visible_site_ids` in the
/// config push applies the same rule, so the number here is what that agent
/// actually receives, not a fleet-wide total.
async fn agent_site_counts(
    db: &DatabaseConnection,
    rows: &[agent::Model],
) -> Result<HashMap<Uuid, u64>, ApiError> {
    // The common single-tenant fleet has no unbound agent at all: answer from
    // the binding and skip both queries.
    if rows.iter().all(|row| row.site_id.is_some()) {
        return Ok(rows.iter().map(|row| (row.id, 1)).collect());
    }

    let owners: Vec<Uuid> = site::Entity::find()
        .select_only()
        .column(site::Column::UserId)
        .into_tuple()
        .all(db)
        .await?;
    let mut per_owner: HashMap<Uuid, u64> = HashMap::new();
    for owner in owners {
        *per_owner.entry(owner).or_default() += 1;
    }

    let key_ids: Vec<Uuid> = rows
        .iter()
        .filter(|row| row.site_id.is_none())
        .filter_map(|row| row.api_key_id)
        .collect();
    let owner_of_key: HashMap<Uuid, Uuid> = if key_ids.is_empty() {
        HashMap::new()
    } else {
        api_key::Entity::find()
            .filter(api_key::Column::Id.is_in(key_ids))
            .select_only()
            .column(api_key::Column::Id)
            .column(api_key::Column::UserId)
            .into_tuple()
            .all(db)
            .await?
            .into_iter()
            .collect()
    };

    Ok(rows
        .iter()
        .map(|row| {
            let count = match row.site_id {
                Some(_) => 1,
                // An unbound agent whose key is gone owns nothing: the row is
                // still listed, its site count is honestly zero.
                None => row
                    .api_key_id
                    .and_then(|key_id| owner_of_key.get(&key_id).copied())
                    .and_then(|owner| per_owner.get(&owner).copied())
                    .unwrap_or(0),
            };
            (row.id, count)
        })
        .collect())
}

/// Reads a column the query always produces.
fn required<T>(row: &sea_orm::QueryResult, column: &str) -> Result<T, ApiError>
where
    T: sea_orm::TryGetable,
{
    row.try_get::<T>("", column)
        .map_err(ApiError::internal_generic)
}

/// Reads a nullable column.
fn optional<T>(
    row: &sea_orm::QueryResult,
    column: &str,
) -> Result<Option<T>, ApiError>
where
    T: sea_orm::TryGetable,
{
    row.try_get::<Option<T>>("", column)
        .map_err(ApiError::internal_generic)
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/system/metrics", get(metrics))
        .route("/system/profile", get(profile))
        .route("/system/nodes", get(nodes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The snapshot is a plain JSON value with the documented shape: module
    /// rows keyed by name and a bounded method list.
    #[test]
    fn profile_snapshot_shape() {
        let snapshot = pingwaf_profiler::ProfileSnapshot::collect();
        assert_eq!(snapshot.modules.len(), 7);
        assert!(
            snapshot.modules.iter().any(|row| row.module == "proxy"),
            "every module is present even before instrumentation runs"
        );
        assert!(
            snapshot.methods.len()
                <= pingwaf_profiler::ProfileSnapshot::MAX_METHODS
        );
        assert!(snapshot.collected_at_ms > 0);
    }

    fn inventory_row(
        hostname: &str,
        status: &str,
        last_heartbeat: Option<DateTime<Utc>>,
    ) -> agent::Model {
        agent::Model {
            id: Uuid::new_v4(),
            site_id: None,
            hostname: hostname.to_string(),
            ip_address: "10.0.0.5".to_string(),
            public_ip: None,
            private_ip: None,
            version: Some("0.28.1".to_string()),
            os_info: Some("linux x86_64".to_string()),
            cpu_cores: Some(4),
            memory_bytes: Some(8 << 30),
            status: status.to_string(),
            api_key_id: None,
            config_hash: None,
            last_heartbeat,
            last_config_sync_at: None,
            last_policy_sync_at: None,
            registered_at: Utc::now(),
        }
    }

    /// The endpoint the dashboard polls must answer an empty fleet with an
    /// empty list, not an error or a placeholder row.
    #[test]
    fn nodes_view_without_agents_serialises_an_empty_list() {
        let view = NodesView {
            control: control_node(
                &pingwaf_system::cpu_snapshot(),
                &pingwaf_system::memory_snapshot(),
                &pingwaf_profiler::ProfileSnapshot::collect(),
            ),
            agents: Vec::new(),
        };
        let json = serde_json::to_value(&view).expect("serialises");
        assert_eq!(json["agents"], serde_json::json!([]));
        assert!(json["control"].is_object());
    }

    /// The control block is a real reading, never a negative one, and its
    /// request figures come from the profiler's `control` row.
    #[test]
    fn control_block_reflects_the_profiler_and_the_process() {
        let snapshot = pingwaf_profiler::ProfileSnapshot::collect();
        let control = control_node(
            &pingwaf_system::cpu_snapshot(),
            &pingwaf_system::memory_snapshot(),
            &snapshot,
        );
        let row = snapshot
            .modules
            .iter()
            .find(|row| row.module == "control")
            .expect("the profiler always carries a control row");

        assert!(control.process_cpu_percent >= 0.0);
        assert!(control.host_cpu_percent >= 0.0);
        assert!(control.cores > 0);
        assert_eq!(control.requests, row.calls);
        assert!((control.avg_elapsed_ms - row.avg_us / 1000.0).abs() < 1e-9);
        assert!(control.avg_elapsed_ms >= 0.0);
    }

    /// A node that has reported everything maps field for field.
    #[test]
    fn agent_node_maps_the_last_heartbeat_counters() {
        let seen = Utc::now();
        let row = inventory_row("edge-1", "online", Some(seen));
        let counters = HeartbeatMetrics {
            cpu_percent: Some(12.5),
            memory_bytes: Some(3 << 30),
            connections: Some(17),
            rps: Some(42),
        };

        let node = agent_node(&row, &counters, 3);
        assert_eq!(node.id, row.id);
        assert_eq!(node.name, "edge-1");
        assert_eq!(node.status, "online");
        assert_eq!(node.cpu_percent, Some(12.5));
        assert_eq!(node.memory_bytes, Some(3 << 30));
        assert_eq!(node.connections, Some(17));
        assert_eq!(node.rps, Some(42));
        assert_eq!(node.sites, 3);
        assert_eq!(node.last_seen, Some(seen));

        let json = serde_json::to_value(&node).expect("serialises");
        assert_eq!(json["cpu_percent"], serde_json::json!(12.5));
        assert_eq!(json["memory_bytes"], serde_json::json!(3u64 << 30));
        assert_eq!(json["sites"], serde_json::json!(3));
        assert_eq!(
            json["last_seen"],
            serde_json::json!(
                seen.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
            ),
            "timestamps use RFC 3339 in UTC, the same encoding /agents emits"
        );
    }

    /// Unknown counters are `null`, never `0`: a node that has never
    /// heartbeated must not look like an idle one.
    #[test]
    fn agent_node_reports_unknown_counters_as_null() {
        let row = inventory_row("edge-2", "offline", None);
        let node = agent_node(&row, &HeartbeatMetrics::default(), 0);
        let json = serde_json::to_value(&node).expect("serialises");

        for field in [
            "cpu_percent",
            "memory_bytes",
            "connections",
            "rps",
            "last_seen",
        ] {
            assert!(json[field].is_null(), "{field} must be null, not 0");
        }
        assert_eq!(json["sites"], serde_json::json!(0));
    }

    /// A NaN sample (a platform whose CPU counters are unusable) is reported
    /// as unknown rather than as a number nothing can compare.
    #[test]
    fn non_finite_cpu_is_reported_as_unknown() {
        let row = inventory_row("edge-3", "online", None);
        let counters = HeartbeatMetrics {
            cpu_percent: Some(f64::NAN),
            ..Default::default()
        };
        assert_eq!(agent_node(&row, &counters, 0).cpu_percent, None);
    }

    /// The console reads these keys by name, so the JSON shape is a
    /// contract: the exact field set, nothing renamed and nothing nested.
    #[test]
    fn node_json_matches_the_console_contract() {
        let control = serde_json::to_value(control_node(
            &pingwaf_system::cpu_snapshot(),
            &pingwaf_system::memory_snapshot(),
            &pingwaf_profiler::ProfileSnapshot::collect(),
        ))
        .expect("serialises");
        let control_fields = [
            "process_cpu_percent",
            "host_cpu_percent",
            "cores",
            "rss_bytes",
            "rss_peak_bytes",
            "requests",
            "avg_elapsed_ms",
        ];
        let object = control.as_object().expect("object");
        assert_eq!(object.len(), control_fields.len());
        for field in control_fields {
            assert!(object.contains_key(field), "control.{field} is missing");
        }

        let row = inventory_row("edge-1", "online", Some(Utc::now()));
        let agent = serde_json::to_value(agent_node(
            &row,
            &HeartbeatMetrics::default(),
            1,
        ))
        .expect("serialises");
        let agent_fields = [
            "id",
            "name",
            "status",
            "cpu_percent",
            "memory_bytes",
            "connections",
            "rps",
            "sites",
            "last_seen",
        ];
        let object = agent.as_object().expect("object");
        assert_eq!(object.len(), agent_fields.len());
        for field in agent_fields {
            assert!(object.contains_key(field), "agents[].{field} is missing");
        }
    }

    /// The connection gauge is a rounded count, and the impossible values a
    /// broken edge could publish are dropped instead of wrapping.
    #[test]
    fn connection_gauge_is_bounded() {
        assert_eq!(gauge_to_u64(17.4), Some(17));
        assert_eq!(gauge_to_u64(0.0), Some(0));
        assert_eq!(gauge_to_u64(-3.0), None);
        assert_eq!(gauge_to_u64(f64::NAN), None);
        assert_eq!(gauge_to_u64(f64::INFINITY), None);
    }
}
