//! Agent inventory: which agents are registered, whether they are currently
//! connected, and the commands the dashboard can push at them.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use pingwaf_proto::control_plane::{
    BlockIpCommand, PurgeCacheCommand, RestartAgentCommand, ServerCommand,
};
use sea_orm::{
    ColumnTrait, Condition, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{
    load_site_read, non_empty, parse_optional_datetime, parse_uuid,
    require_write, scope_site, Page, Pagination,
};
use crate::api::error::ApiError;
use crate::api::keys::mint_key;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::config::now_timestamp;
use crate::models::{
    agent, agent_status, api_key, host_sample, permission, site,
};

/// `pingwaf.CommandType` values, spelled out so the control plane does not depend
/// on prost's enum variant naming.
pub mod command_type {
    pub const RULE_UPDATE: i32 = 1;
    pub const CONFIG_RELOAD: i32 = 2;
    pub const BLOCK_IP: i32 = 3;
    pub const UNBLOCK_IP: i32 = 4;
    pub const PURGE_CACHE: i32 = 5;
    pub const UPDATE_SITE: i32 = 6;
    pub const RESTART_AGENT: i32 = 7;
}

/// Agent row enriched with live connection information.
#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub id: Uuid,
    pub site_id: Option<Uuid>,
    pub site_domain: Option<String>,
    pub hostname: String,
    pub ip_address: String,
    /// Egress address as seen from the public internet, empty when unknown.
    pub public_ip: Option<String>,
    /// First LAN address that is not loopback or a container/bridge interface.
    pub private_ip: Option<String>,
    pub version: Option<String>,
    pub os_info: Option<String>,
    pub cpu_cores: Option<i32>,
    pub memory_bytes: Option<i64>,
    pub status: String,
    pub api_key_id: Option<Uuid>,
    pub config_hash: Option<String>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    /// When the agent last applied a full site config; null = never synced.
    pub last_config_sync_at: Option<DateTime<Utc>>,
    /// When the agent last applied a per-site rule bundle; null = never.
    pub last_policy_sync_at: Option<DateTime<Utc>>,
    pub registered_at: DateTime<Utc>,
    /// True while the agent holds an open heartbeat stream.
    pub connected: bool,
    /// Commands waiting for the agent to reconnect.
    pub pending_commands: usize,
    /// Whether the gRPC control plane the agents connect to serves TLS.
    /// `false` means plaintext traffic (degraded mode).
    pub grpc_tls: bool,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
    pub site_id: Option<String>,
    pub status: Option<String>,
    pub search: Option<String>,
}

/// Window and paging for the probe history endpoint.
#[derive(Debug, Deserialize)]
pub struct SamplesQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
    /// Inclusive lower bound, RFC 3339.
    pub from: Option<String>,
    /// Exclusive upper bound, RFC 3339.
    pub to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CommandRequest {
    /// One of `restart`, `purge_cache`, `block_ip`, `unblock_ip`, `reload`.
    pub command: String,
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub duration_seconds: Option<i64>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default = "default_graceful")]
    pub graceful: bool,
}

fn default_graceful() -> bool {
    true
}

/// Enrollment options. The minted key does not expire: a node is admitted as
/// long as the token is valid, and it is revoked by deleting the key.
#[derive(Debug, Deserialize, Default)]
pub struct EnrollRequest {
    /// Name recorded on the minted key, so it can be told apart in the key list.
    #[serde(default)]
    pub name: Option<String>,
}

/// Everything the operator needs to bring a node online: the key, the endpoint
/// to connect to, and the command that uses both.
#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    pub key_id: Uuid,
    /// Agent API key. Returned once — only its bcrypt hash is stored. It is
    /// already part of `install_command`; the console does not display it
    /// separately, but API callers may build their own command from it.
    pub token: String,
    /// gRPC endpoint the agent connects to.
    pub server_url: String,
    /// Installer one-liner: downloads the script, installs the node and
    /// starts its service.
    pub install_command: String,
}

/// Installer published with the repository root, fetched over HTTPS so a bare
/// host needs nothing but `curl`.
const INSTALL_SCRIPT_URL: &str =
    "https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh";

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/agents", get(list))
        .route("/agents/enroll", post(enroll))
        .route("/agents/{agent_id}", get(show).delete(remove))
        .route("/agents/{agent_id}/samples", get(samples))
        .route("/agents/{agent_id}/commands", post(send_command))
}

/// `POST /api/v1/agents/enroll` — mints an agent key and returns the command
/// line that installs and starts a node with it.
///
/// The agent registers itself over gRPC on first connect, so running the command
/// is all that is needed for the node to appear in the inventory.
async fn enroll(
    State(state): State<AppState>,
    current: AuthUser,
    headers: HeaderMap,
    Json(payload): Json<EnrollRequest>,
) -> Result<Response, ApiError> {
    require_write(&current)?;

    let name = non_empty(&payload.name).unwrap_or_else(|| {
        format!("agent-enrollment-{}", Utc::now().format("%Y%m%d-%H%M%S"))
    });
    if name.len() > 100 {
        return Err(ApiError::BadRequest(
            "name must be at most 100 characters".to_string(),
        ));
    }

    let (model, token) = mint_key(
        &state,
        current.id,
        name,
        vec![permission::AGENT.to_string(), permission::READ.to_string()],
        None,
    )
    .await?;

    let server_url = agent_server_url(&state, &headers);
    let install_command = format!(
        "curl -fsSL {INSTALL_SCRIPT_URL} | sudo bash -s -- --mode agent \
         --server-url {server_url} --api-key {token}"
    );

    tracing::info!(key_id = %model.id, requested_by = %current.id, "agent enrollment created");

    Ok((
        StatusCode::CREATED,
        Json(EnrollResponse {
            key_id: model.id,
            token,
            server_url,
            install_command,
        }),
    )
        .into_response())
}

/// Best-effort gRPC endpoint for the agent to dial.
///
/// The control plane only knows its bind address (`0.0.0.0:9090`), which is not
/// routable from another server, so the port is combined with the host the
/// operator reached the dashboard on.
fn agent_server_url(state: &AppState, headers: &HeaderMap) -> String {
    let port = state
        .config
        .grpc_addr
        .rsplit(':')
        .next()
        .filter(|raw| !raw.is_empty())
        .unwrap_or("9090");
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(host_without_port)
        .filter(|host| !host.is_empty() && *host != "localhost")
        .unwrap_or("localhost");
    format!("http://{host}:{port}")
}

/// Strips the port from a `Host` header value, keeping IPv6 literals intact.
fn host_without_port(raw: &str) -> &str {
    if let Some(end) = raw.find(']') {
        return &raw[..=end];
    }
    match raw.rsplit_once(':') {
        Some((host, _)) if !host.is_empty() => host,
        _ => raw,
    }
}

/// `GET /api/v1/agents`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<AgentResponse>>, ApiError> {
    let pagination = query.pagination.normalise();

    let site_filter = match non_empty(&query.site_id) {
        Some(raw) => Some(parse_uuid(&raw, "site id")?),
        None => None,
    };
    if let Some(id) = site_filter {
        // Enforces visibility even when the caller passes a site they cannot see.
        load_site_read(&state.db, id, &current).await?;
    }

    let mut condition = Condition::all();
    if !current.is_admin() {
        let owned: Vec<Uuid> = site::Entity::find()
            .filter(site::Column::UserId.eq(current.id))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect();
        // Agents are visible to their owner, mirroring the config-push
        // visibility (`agent_visible_site_ids`): a bound agent shows under the
        // site it is bound to, and an unbound one — which serves every site of
        // its API key's user — shows to that user as well.
        let key_ids: Vec<Uuid> = api_key::Entity::find()
            .filter(api_key::Column::UserId.eq(current.id))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|key| key.id)
            .collect();
        condition = condition.add(
            Condition::any()
                .add(agent::Column::SiteId.is_in(owned))
                .add(
                    Condition::all()
                        .add(agent::Column::SiteId.is_null())
                        .add(agent::Column::ApiKeyId.is_in(key_ids)),
                ),
        );
    }
    if let Some(id) = site_filter {
        condition = condition.add(agent::Column::SiteId.eq(id));
    }
    if let Some(status) = non_empty(&query.status) {
        if !agent_status::is_valid(&status) {
            return Err(ApiError::BadRequest(format!(
                "unknown agent status '{status}'"
            )));
        }
        condition = condition.add(agent::Column::Status.eq(status));
    }
    if let Some(search) = non_empty(&query.search) {
        let pattern = format!("%{}%", search.to_lowercase());
        condition = condition.add(
            Condition::any()
                .add(agent::Column::Hostname.like(&pattern))
                .add(agent::Column::IpAddress.like(&pattern)),
        );
    }

    let paginator = agent::Entity::find()
        .filter(condition)
        .order_by_desc(agent::Column::RegisteredAt)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    let items = enrich(&state, rows).await?;

    Ok(Json(Page::new(items, total, pagination)))
}

/// `GET /api/v1/agents/{agent_id}`
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentResponse>, ApiError> {
    let id = parse_uuid(&agent_id, "agent id")?;
    let row = load_agent(&state, id, &current).await?;
    let mut items = enrich(&state, vec![row]).await?;
    Ok(Json(items.remove(0)))
}

/// `GET /api/v1/agents/{agent_id}/samples` — host probe history, newest first.
///
/// Cumulative counters (network and disk totals) are returned raw; the caller
/// differences consecutive rows to obtain rates.
async fn samples(
    State(state): State<AppState>,
    current: AuthUser,
    Path(agent_id): Path<String>,
    Query(query): Query<SamplesQuery>,
) -> Result<Json<Page<host_sample::Model>>, ApiError> {
    let id = parse_uuid(&agent_id, "agent id")?;
    load_agent(&state, id, &current).await?;

    let pagination = query.pagination.normalise();
    let from = parse_optional_datetime(&query.from, "from")?;
    let to = parse_optional_datetime(&query.to, "to")?;

    let mut condition =
        Condition::all().add(host_sample::Column::AgentId.eq(id));
    if let Some(at) = from {
        condition = condition.add(host_sample::Column::SampledAt.gte(at));
    }
    if let Some(at) = to {
        condition = condition.add(host_sample::Column::SampledAt.lt(at));
    }

    let paginator = host_sample::Entity::find()
        .filter(condition)
        .order_by_desc(host_sample::Column::SampledAt)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let items = paginator.fetch_page(pagination.index()).await?;

    Ok(Json(Page::new(items, total, pagination)))
}

/// `DELETE /api/v1/agents/{agent_id}` — de-registers an agent.
async fn remove(
    State(state): State<AppState>,
    current: AuthUser,
    Path(agent_id): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&current)?;
    let id = parse_uuid(&agent_id, "agent id")?;
    load_agent(&state, id, &current).await?;

    agent::Entity::delete_by_id(id).exec(&state.db).await?;
    state.agents.disconnect(&id).await;

    tracing::info!(agent_id = %id, requested_by = %current.id, "agent de-registered");
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/v1/agents/{agent_id}/commands`
async fn send_command(
    State(state): State<AppState>,
    current: AuthUser,
    Path(agent_id): Path<String>,
    Json(payload): Json<CommandRequest>,
) -> Result<Response, ApiError> {
    require_write(&current)?;
    let id = parse_uuid(&agent_id, "agent id")?;
    load_agent(&state, id, &current).await?;

    let site_id = match non_empty(&payload.site_id) {
        Some(raw) => {
            let parsed = parse_uuid(&raw, "site id")?;
            load_site_read(&state.db, parsed, &current).await?;
            Some(parsed)
        },
        None => None,
    };

    let command = build_command(&payload, site_id)?;
    let delivered = state.agents.send_command(&id, command).await;

    tracing::info!(
        agent_id = %id,
        command = %payload.command,
        delivered,
        requested_by = %current.id,
        "command issued to agent"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "agent_id": id,
            "command": payload.command,
            "delivered": delivered,
            "queued": !delivered,
        })),
    )
        .into_response())
}

/// Loads an agent and checks that `current` may see it.
pub async fn load_agent(
    state: &AppState,
    id: Uuid,
    current: &AuthUser,
) -> Result<agent::Model, ApiError> {
    let row = agent::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("agent {id} not found")))?;

    if !current.is_admin() {
        if let Some(site_id) = row.site_id {
            // `load_site_read` hides sites owned by somebody else behind a 404.
            load_site_read(&state.db, site_id, current).await?;
        } else {
            // An unbound agent serves every site of its API key's owner —
            // visible only to that owner (mirrors `agent_visible_site_ids`).
            let owned_by_caller = match row.api_key_id {
                Some(key_id) => api_key::Entity::find_by_id(key_id)
                    .one(&state.db)
                    .await?
                    .map(|key| key.user_id == current.id)
                    .unwrap_or(false),
                None => false,
            };
            if !owned_by_caller {
                return Err(ApiError::NotFound(format!(
                    "agent {id} not found"
                )));
            }
        }
    }
    Ok(row)
}

/// Attaches live connection state and site domain to agent rows.
async fn enrich(
    state: &AppState,
    rows: Vec<agent::Model>,
) -> Result<Vec<AgentResponse>, ApiError> {
    let domains: std::collections::HashMap<Uuid, String> = {
        let ids: Vec<Uuid> =
            rows.iter().filter_map(|row| row.site_id).collect();
        if ids.is_empty() {
            Default::default()
        } else {
            site::Entity::find()
                .filter(site::Column::Id.is_in(ids))
                .all(&state.db)
                .await?
                .into_iter()
                .map(|row| (row.id, row.domain))
                .collect()
        }
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let connected = state.agents.is_connected(&row.id).await;
        out.push(AgentResponse {
            id: row.id,
            site_domain: row.site_id.and_then(|id| domains.get(&id).cloned()),
            site_id: row.site_id,
            hostname: row.hostname,
            ip_address: row.ip_address,
            public_ip: row.public_ip,
            private_ip: row.private_ip,
            version: row.version,
            os_info: row.os_info,
            cpu_cores: row.cpu_cores,
            memory_bytes: row.memory_bytes,
            status: row.status,
            api_key_id: row.api_key_id,
            config_hash: row.config_hash,
            last_heartbeat: row.last_heartbeat,
            last_config_sync_at: row.last_config_sync_at,
            last_policy_sync_at: row.last_policy_sync_at,
            registered_at: row.registered_at,
            connected,
            pending_commands: state.agents.pending_count(&row.id).await,
            grpc_tls: state.config.grpc_tls_enabled(),
        });
    }
    Ok(out)
}

/// Turns a dashboard command request into the protocol message.
pub fn build_command(
    payload: &CommandRequest,
    site_id: Option<Uuid>,
) -> Result<ServerCommand, ApiError> {
    let site = site_id.map(|id| id.to_string()).unwrap_or_default();
    let (kind, body) = match payload.command.as_str() {
        "restart" => (
            command_type::RESTART_AGENT,
            Some(server_command_payload::RestartAgent(RestartAgentCommand {
                reason: payload.reason.clone().unwrap_or_else(|| "requested from dashboard".to_string()),
                graceful: payload.graceful,
            })),
        ),
        "reload" => (command_type::CONFIG_RELOAD, None),
        "purge_cache" => (
            command_type::PURGE_CACHE,
            Some(server_command_payload::PurgeCache(PurgeCacheCommand {
                site_id: site.clone(),
                urls: payload.urls.clone(),
                tags: payload.tags.clone(),
            })),
        ),
        "block_ip" => {
            if payload.ip_addresses.is_empty() {
                return Err(ApiError::BadRequest(
                    "ip_addresses must not be empty".to_string(),
                ));
            }
            // Reuse the manual-block guard: every entry goes through the
            // same /16 (v4) and /32 (v6) ceiling as `POST /blocked-ips/block`,
            // so a command can never blanket-ban `0.0.0.0/0`, and each entry
            // is written back in its normalised (host bits truncated,
            // mapped-v6 collapsed) form so agents key on one canonical
            // string.
            let normalized: Vec<String> = payload
                .ip_addresses
                .iter()
                .map(|raw| {
                    crate::api::blocked_ips::parse_block_target(raw)
                        .map(|target| target.as_stored())
                })
                .collect::<Result<_, _>>()?;
            (
                command_type::BLOCK_IP,
                Some(server_command_payload::BlockIp(BlockIpCommand {
                    site_id: site.clone(),
                    ip_addresses: normalized,
                    duration_seconds: payload.duration_seconds.unwrap_or(0),
                    reason: payload
                        .reason
                        .clone()
                        .unwrap_or_else(|| "blocked from dashboard".to_string()),
                })),
            )
        }
        "unblock_ip" => {
            if payload.ip_addresses.is_empty() {
                return Err(ApiError::BadRequest(
                    "ip_addresses must not be empty".to_string(),
                ));
            }
            // No width guard here — unblocking must never be stricter than
            // blocking — but the same normalisation, so the key matches the
            // one the block was stored under and the agent's exact removal
            // hits.
            let normalized: Vec<String> = payload
                .ip_addresses
                .iter()
                .map(|raw| crate::api::blocked_ips::parse_unblock_target(raw))
                .collect::<Result<_, _>>()?;
            (
                command_type::UNBLOCK_IP,
                Some(server_command_payload::UnblockIp(
                    pingwaf_proto::control_plane::UnblockIpCommand {
                        site_id: site.clone(),
                        ip_addresses: normalized,
                    },
                )),
            )
        }
        other => {
            return Err(ApiError::BadRequest(format!(
                "unknown command '{other}'; expected restart, reload, purge_cache, block_ip \
                 or unblock_ip"
            )))
        }
    };

    Ok(ServerCommand {
        command_id: Uuid::new_v4().to_string(),
        r#type: kind,
        issued_at: now_timestamp(),
        payload: body,
    })
}

/// The generated `oneof payload` module of `ServerCommand`.
mod server_command_payload {
    pub use pingwaf_proto::control_plane::server_command::Payload::{
        BlockIp, PurgeCache, RestartAgent, UnblockIp,
    };
}

/// Filters a site scope for the log endpoints, shared with [`crate::api::logs`].
pub fn resolve_site_scope(
    requested: &Option<String>,
    current: &AuthUser,
) -> Result<Option<Uuid>, ApiError> {
    let parsed = match non_empty(requested) {
        Some(raw) => Some(parse_uuid(&raw, "site id")?),
        None => None,
    };
    scope_site(parsed, current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(command: &str) -> CommandRequest {
        CommandRequest {
            command: command.to_string(),
            site_id: None,
            ip_addresses: Vec::new(),
            urls: Vec::new(),
            tags: Vec::new(),
            duration_seconds: None,
            reason: None,
            graceful: true,
        }
    }

    #[test]
    fn known_commands_build_messages() {
        let site = Uuid::new_v4();
        let command = build_command(&request("restart"), Some(site)).unwrap();
        assert_eq!(command.r#type, command_type::RESTART_AGENT);
        assert!(!command.command_id.is_empty());

        let command = build_command(&request("reload"), None).unwrap();
        assert_eq!(command.r#type, command_type::CONFIG_RELOAD);
        assert!(command.payload.is_none());
    }

    #[test]
    fn ip_commands_require_addresses() {
        assert!(build_command(&request("block_ip"), None).is_err());
        assert!(build_command(&request("unblock_ip"), None).is_err());

        let mut with_ips = request("block_ip");
        with_ips.ip_addresses = vec!["10.0.0.1".to_string()];
        let command = build_command(&with_ips, None).unwrap();
        assert_eq!(command.r#type, command_type::BLOCK_IP);
    }

    #[test]
    fn unknown_commands_are_rejected() {
        assert!(build_command(&request("self-destruct"), None).is_err());
    }

    fn ips(command: &str, addresses: &[&str]) -> CommandRequest {
        let mut req = request(command);
        req.ip_addresses = addresses.iter().map(|s| s.to_string()).collect();
        req
    }

    fn block_payload(req: &CommandRequest) -> Vec<String> {
        match build_command(req, None).unwrap().payload.unwrap() {
            server_command_payload::BlockIp(cmd) => cmd.ip_addresses,
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    fn unblock_payload(req: &CommandRequest) -> Vec<String> {
        match build_command(req, None).unwrap().payload.unwrap() {
            server_command_payload::UnblockIp(cmd) => cmd.ip_addresses,
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn block_ip_rejects_cidrs_wider_than_the_manual_block_guard() {
        for raw in [
            "0.0.0.0/0",
            "::/0",
            "10.0.0.0/8",
            "2001:db8::/16",
            // /96 v6 numerically covers the whole IPv4-mapped space; it is
            // the mapped spelling of 0.0.0.0/0 and must hit the same guard.
            "::ffff:0:0/96",
        ] {
            let err = build_command(&ips("block_ip", &[raw]), None)
                .err()
                .unwrap_or_else(|| panic!("{raw} must be rejected"));
            assert!(err.to_string().contains("too broad"), "{raw}: {err}");
        }
    }

    #[test]
    fn block_ip_normalises_targets_like_the_manual_block_path() {
        assert_eq!(
            block_payload(&ips("block_ip", &["203.0.113.99/24"])),
            vec!["203.0.113.0/24".to_string()]
        );
        assert_eq!(
            block_payload(&ips("block_ip", &[" 203.0.113.7 "])),
            vec!["203.0.113.7".to_string()]
        );
        assert_eq!(
            block_payload(&ips(
                "block_ip",
                &["::ffff:203.0.113.0/120", "2001:db8::/32"]
            )),
            vec!["203.0.113.0/24".to_string(), "2001:db8::/32".to_string()]
        );
        // /104 on a mapped address maps to a v4 /8 — beyond the v4 ceiling.
        assert!(build_command(
            &ips("block_ip", &["::ffff:10.0.0.0/104"]),
            None
        )
        .is_err());
    }

    #[test]
    fn unblock_ip_is_normalised_but_not_width_guarded() {
        // Same normalisation as blocking, so the exact key matches.
        assert_eq!(
            unblock_payload(&ips(
                "unblock_ip",
                &["203.0.113.99/24", "::ffff:203.0.113.5"]
            )),
            vec!["203.0.113.0/24".to_string(), "203.0.113.5".to_string()]
        );
        // Invalid input is still rejected.
        assert!(build_command(&ips("unblock_ip", &["nonsense"]), None).is_err());
    }
}
