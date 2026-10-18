//! The tool registry shared by the hosted MCP endpoint and the built-in AI
//! assistant.
//!
//! Every tool is a thin, read-mostly window onto the control plane's own REST
//! data: sites, agents, certificates, logs, traffic aggregates and the
//! control-plane defense settings. Write tools mirror the corresponding REST
//! mutations (including the configuration push to the agents) and are only
//! exposed when the caller proved `write` capability *and* the operator
//! opted in.
//!
//! Handlers return plain JSON; the MCP layer wraps it into a text content
//! block and the AI layer feeds the same JSON to the model as a tool result,
//! so both surfaces stay in lockstep.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, Set,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::common::query_all;
use crate::api::logs::escape_like;
use crate::api::ssl::cert_status;
use crate::api::state::AppState;
use crate::api::{defense, self_protection, sites};
use crate::grpc::{notify_all_config_changed, notify_config_changed};
use crate::models::{
    access_log, agent, agent_status, control_plane_access_log,
    defense_settings, ip_groups, security_event, site, site_certificates,
    site_status,
};

/// Upper bound on rows any single tool returns.
const MAX_ROWS: u64 = 50;
/// Longest look-back window a tool accepts.
const MAX_WINDOW_HOURS: i64 = 168;
/// Default look-back window of the aggregate tools.
const DEFAULT_WINDOW_HOURS: i64 = 24;

/// Caller identity and capabilities for one tool invocation.
pub struct ToolContext<'a> {
    pub state: &'a AppState,
    /// Identity recorded in audit logs, e.g. `api key pwk_abcd (grafana)`.
    pub actor: &'a str,
    /// Whether write tools may be invoked.
    pub can_write: bool,
    /// Owning user id — used to narrow reads to the caller's own sites.
    pub subject: Uuid,
    /// Administrators see everything; everyone else is scoped to
    /// `site.user_id == subject` (mirrors `load_site_read` in the REST API).
    pub is_admin: bool,
}

/// Site ids the caller may read; `None` means "all sites" (admin only).
async fn visible_site_ids(
    ctx: &ToolContext<'_>,
) -> Result<Option<Vec<Uuid>>, String> {
    if ctx.is_admin {
        return Ok(None);
    }
    let ids = site::Entity::find()
        .select_only()
        .column(site::Column::Id)
        .filter(site::Column::UserId.eq(ctx.subject))
        .into_tuple::<Uuid>()
        .all(&ctx.state.db)
        .await
        .map_err(db_error)?;
    Ok(Some(ids))
}

/// Resolves a requested site filter against the caller's visible set.
///
/// Non-admins must name a site they own (same rule as the REST API's
/// `scope_site`); admins may omit it to cover every site. A site outside
/// the caller's set is reported as "not found" rather than "forbidden", so
/// the tool does not confirm that somebody else's site exists.
fn require_scoped_site(
    requested: Option<Uuid>,
    visible: Option<&Vec<Uuid>>,
) -> Result<Option<Uuid>, String> {
    match (requested, visible) {
        (Some(id), None) => Ok(Some(id)),
        (Some(id), Some(allowed)) if allowed.contains(&id) => Ok(Some(id)),
        (Some(_), Some(_)) => Err("site not found".to_string()),
        (None, None) => Ok(None),
        (None, Some(_)) => {
            Err("site_id is required for non-admin accounts".to_string())
        },
    }
}

/// Metadata for one tool, mirroring MCP's `tools/list` shape.
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    /// Write tools require `can_write` and are hidden from read-only callers.
    pub write: bool,
    pub schema: Value,
}

/// Every tool this server knows, read and write alike.
pub fn specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "list_sites",
            description: "List proxy sites (id, name, domain, status) with their online agent count. Use it to find a site id for the other tools.",
            write: false,
            schema: json!({
                "type": "object",
                "properties": {
                    "search": { "type": "string", "description": "Substring matched against name or domain" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "description": "Maximum rows (default 50)" }
                },
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: "list_agents",
            description: "List data-plane agents with status, version, last heartbeat and the site they serve.",
            write: false,
            schema: json!({
                "type": "object",
                "properties": {
                    "site_id": { "type": "string", "description": "Only agents bound to this site (UUID)" },
                    "status": { "type": "string", "enum": ["online", "offline", "degraded"] },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "description": "Maximum rows (default 50)" }
                },
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: "certificate_summary",
            description: "TLS certificate counts: total, active, pending, failed, expired and expiring within 30 days.",
            write: false,
            schema: json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        },
        ToolSpec {
            name: "query_access_logs",
            description: "Query recent proxied requests (status, latency, cache, upstream). The primary tool for diagnosing errors and slow responses.",
            write: false,
            schema: json!({
                "type": "object",
                "properties": {
                    "hours": { "type": "integer", "minimum": 1, "maximum": 168, "description": "Look-back window (default 1)" },
                    "site_id": { "type": "string", "description": "Restrict to one site (UUID)" },
                    "status_class": { "type": "integer", "minimum": 1, "maximum": 5, "description": "HTTP status class, e.g. 5 for 5xx" },
                    "method": { "type": "string", "description": "HTTP method" },
                    "client_ip": { "type": "string" },
                    "path": { "type": "string", "description": "Substring matched against the request path" },
                    "min_latency_ms": { "type": "integer", "description": "Only requests slower than this" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50, "description": "Maximum rows (default 20)" }
                },
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: "query_waf_events",
            description: "Query WAF detections: which rule fired, on which request, and the action taken.",
            write: false,
            schema: json!({
                "type": "object",
                "properties": {
                    "hours": { "type": "integer", "minimum": 1, "maximum": 168, "description": "Look-back window (default 24)" },
                    "site_id": { "type": "string", "description": "Restrict to one site (UUID)" },
                    "action": { "type": "string", "description": "Action filter, e.g. block or challenge" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50, "description": "Maximum rows (default 20)" }
                },
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: "get_traffic_summary",
            description: "Aggregate traffic for a window: requests, unique IPs, cache hit rate, latency, error counts and security events.",
            write: false,
            schema: json!({
                "type": "object",
                "properties": {
                    "hours": { "type": "integer", "minimum": 1, "maximum": 168, "description": "Look-back window (default 24)" },
                    "site_id": { "type": "string", "description": "Restrict to one site (UUID)" }
                },
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: "get_defense_status",
            description: "Current defense posture: observation mode and the control plane's own access log / IP allowlist / WAF settings.",
            write: false,
            schema: json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        },
        ToolSpec {
            name: "list_ip_groups",
            description: "List IP groups (shared allow/deny lists), their size, action, source and last sync state.",
            write: false,
            schema: json!({ "type": "object", "properties": {}, "additionalProperties": false }),
        },
        ToolSpec {
            name: "query_control_plane_logs",
            description: "Query the control plane's own access log (logins and API calls to port 9080), including allowlist/WAF verdicts.",
            write: false,
            schema: json!({
                "type": "object",
                "properties": {
                    "hours": { "type": "integer", "minimum": 1, "maximum": 168, "description": "Look-back window (default 24)" },
                    "action": { "type": "string", "enum": ["allowed", "blocked_allowlist", "blocked_waf", "observed_waf"] },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50, "description": "Maximum rows (default 20)" }
                },
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: "set_observation_mode",
            description: "Turn global observation mode on or off. On: every detection keeps running but only records what it would have blocked. Off: protections enforce again. The change is pushed to all agents immediately.",
            write: true,
            schema: json!({
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean", "description": "true enables observation mode, false restores enforcement" }
                },
                "required": ["enabled"],
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: "set_site_status",
            description: "Activate or pause one site. Paused sites keep serving detection but stop proxying. Identify the site by id or exact domain.",
            write: true,
            schema: json!({
                "type": "object",
                "properties": {
                    "site_id": { "type": "string", "description": "Site UUID (preferred)" },
                    "domain": { "type": "string", "description": "Exact primary domain, used when site_id is absent" },
                    "status": { "type": "string", "enum": ["active", "paused"] }
                },
                "required": ["status"],
                "additionalProperties": false
            }),
        },
    ]
}

/// `tools/list` payload; write tools are filtered out for read-only callers.
pub fn mcp_list(can_write: bool) -> Value {
    let tools: Vec<Value> = specs()
        .into_iter()
        .filter(|spec| can_write || !spec.write)
        .map(|spec| {
            json!({
                "name": spec.name,
                "description": spec.description,
                "inputSchema": spec.schema,
            })
        })
        .collect();
    json!({ "tools": tools })
}

/// The same catalogue in OpenAI `tools` format, for the AI assistant.
pub fn openai_tools(can_write: bool) -> Vec<Value> {
    specs()
        .into_iter()
        .filter(|spec| can_write || !spec.write)
        .map(|spec| {
            json!({
                "type": "function",
                "function": {
                    "name": spec.name,
                    "description": spec.description,
                    "parameters": spec.schema,
                }
            })
        })
        .collect()
}

/// True when the named tool exists and mutates state.
pub fn is_write_tool(name: &str) -> bool {
    specs().iter().any(|spec| spec.name == name && spec.write)
}

/// Gate applied before dispatch: unknown names and unauthorized writes fail
/// here, so the executor never sees them.
fn ensure_allowed(name: &str, can_write: bool) -> Result<(), String> {
    let spec = specs()
        .into_iter()
        .find(|spec| spec.name == name)
        .ok_or_else(|| format!("unknown tool '{name}'"))?;
    if spec.write && !can_write {
        return Err(format!(
            "tool '{name}' modifies the control plane and needs write permission"
        ));
    }
    Ok(())
}

/// Runs one tool and returns its JSON result.
pub async fn call(
    ctx: &ToolContext<'_>,
    name: &str,
    args: &Value,
) -> Result<Value, String> {
    ensure_allowed(name, ctx.can_write)?;
    match name {
        "list_sites" => list_sites(ctx, args).await,
        "list_agents" => list_agents(ctx, args).await,
        "certificate_summary" => certificate_summary(ctx).await,
        "query_access_logs" => query_access_logs(ctx, args).await,
        "query_waf_events" => query_waf_events(ctx, args).await,
        "get_traffic_summary" => get_traffic_summary(ctx, args).await,
        "get_defense_status" => get_defense_status(ctx).await,
        "list_ip_groups" => list_ip_groups(ctx).await,
        "query_control_plane_logs" => query_control_plane_logs(ctx, args).await,
        "set_observation_mode" => set_observation_mode(ctx, args).await,
        "set_site_status" => set_site_status(ctx, args).await,
        // `ensure_allowed` proved the name exists.
        _ => Err(format!("unknown tool '{name}'")),
    }
}

// ─────────────────────────────────────────────────────────────
// Argument helpers
// ─────────────────────────────────────────────────────────────

fn db_error(err: sea_orm::DbErr) -> String {
    tracing::error!(error = %err, "tool database query failed");
    "database query failed".to_string()
}

fn api_error(err: crate::api::ApiError) -> String {
    tracing::error!(error = %err, "tool operation failed");
    "the operation failed on the control plane".to_string()
}

fn arg_string(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn arg_uuid(args: &Value, key: &str) -> Result<Option<Uuid>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) if raw.trim().is_empty() => Ok(None),
        Some(Value::String(raw)) => Uuid::parse_str(raw.trim())
            .map(Some)
            .map_err(|_| format!("'{key}' must be a UUID")),
        Some(_) => Err(format!("'{key}' must be a UUID string")),
    }
}

fn arg_limit(args: &Value, default: u64) -> u64 {
    args.get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(default)
        .clamp(1, MAX_ROWS)
}

fn window_hours(args: &Value, default: i64) -> i64 {
    args.get("hours")
        .and_then(Value::as_i64)
        .unwrap_or(default)
        .clamp(1, MAX_WINDOW_HOURS)
}

fn contains_pattern(value: &str) -> String {
    format!("%{}%", escape_like(value))
}

/// `(id -> name-or-domain)` for the sites referenced by a result page.
async fn site_names(
    state: &AppState,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, String>, String> {
    let unique: Vec<Uuid> = ids
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if unique.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = site::Entity::find()
        .select_only()
        .column(site::Column::Id)
        .column(site::Column::Name)
        .column(site::Column::Domain)
        .filter(site::Column::Id.is_in(unique))
        .into_tuple::<(Uuid, String, String)>()
        .all(&state.db)
        .await
        .map_err(db_error)?;
    Ok(rows
        .into_iter()
        .map(|(id, name, domain)| {
            let label = if name.trim().is_empty() { domain } else { name };
            (id, label)
        })
        .collect())
}

// ─────────────────────────────────────────────────────────────
// Read tools
// ─────────────────────────────────────────────────────────────

async fn list_sites(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<Value, String> {
    let limit = arg_limit(args, 50);
    let mut condition = Condition::all();
    if let Some(search) = arg_string(args, "search") {
        let pattern = contains_pattern(&search);
        condition = condition.add(
            Condition::any()
                .add(site::Column::Name.like(pattern.clone()))
                .add(site::Column::Domain.like(pattern)),
        );
    }

    // Non-admins only see the sites they own (2026-10-18 audit: read
    // tools returned every site to any authenticated caller).
    if let Some(visible) = visible_site_ids(ctx).await? {
        condition = condition.add(site::Column::Id.is_in(visible));
    }

    let rows = site::Entity::find()
        .filter(condition)
        .order_by_desc(site::Column::CreatedAt)
        .limit(limit)
        .all(&ctx.state.db)
        .await
        .map_err(db_error)?;

    let online_ids = agent::Entity::find()
        .select_only()
        .column(agent::Column::SiteId)
        .filter(agent::Column::Status.eq(agent_status::ONLINE))
        .into_tuple::<Option<Uuid>>()
        .all(&ctx.state.db)
        .await
        .map_err(db_error)?;
    let mut online: HashMap<Uuid, i64> = HashMap::new();
    for id in online_ids.into_iter().flatten() {
        *online.entry(id).or_insert(0) += 1;
    }

    let sites: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "name": row.name,
                "domain": row.domain,
                "alternate_domains": row.alternate_domains,
                "status": row.status,
                "online_agents": online.get(&row.id).copied().unwrap_or(0),
            })
        })
        .collect();
    Ok(json!({ "count": sites.len(), "sites": sites }))
}

async fn list_agents(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<Value, String> {
    let limit = arg_limit(args, 50);
    let mut condition = Condition::all();
    if let Some(site_id) = arg_uuid(args, "site_id")? {
        condition = condition.add(agent::Column::SiteId.eq(site_id));
    }
    if let Some(status) = arg_string(args, "status") {
        if status != agent_status::ONLINE
            && status != agent_status::OFFLINE
            && status != agent_status::DEGRADED
        {
            return Err(format!("unknown agent status '{status}'"));
        }
        condition = condition.add(agent::Column::Status.eq(status));
    }
    if let Some(visible) = visible_site_ids(ctx).await? {
        condition = condition.add(agent::Column::SiteId.is_in(visible));
    }

    let rows = agent::Entity::find()
        .filter(condition)
        .order_by_desc(agent::Column::LastHeartbeat)
        .limit(limit)
        .all(&ctx.state.db)
        .await
        .map_err(db_error)?;

    let names = site_names(
        ctx.state,
        &rows
            .iter()
            .filter_map(|row| row.site_id)
            .collect::<Vec<_>>(),
    )
    .await?;

    let agents: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "hostname": row.hostname,
                "site": row.site_id.map(|id| names.get(&id).cloned().unwrap_or_else(|| id.to_string())),
                "ip_address": row.ip_address,
                "version": row.version,
                "status": row.status,
                "last_heartbeat": row.last_heartbeat,
                "registered_at": row.registered_at,
            })
        })
        .collect();
    Ok(json!({ "count": agents.len(), "agents": agents }))
}

async fn certificate_summary(ctx: &ToolContext<'_>) -> Result<Value, String> {
    let visible = visible_site_ids(ctx).await?;
    let mut query = site_certificates::Entity::find()
        .select_only()
        .column(site_certificates::Column::Status)
        .column(site_certificates::Column::ExpiresAt);
    if let Some(visible) = visible {
        query = query.filter(site_certificates::Column::SiteId.is_in(visible));
    }
    let rows = query
        .into_tuple::<(String, Option<DateTime<Utc>>)>()
        .all(&ctx.state.db)
        .await
        .map_err(db_error)?;

    let soon = Utc::now() + Duration::days(30);
    let mut total = 0_usize;
    let (mut active, mut pending, mut failed, mut expired, mut expiring) =
        (0_usize, 0_usize, 0_usize, 0_usize, 0_usize);
    for (status, expires_at) in &rows {
        total += 1;
        match status.as_str() {
            cert_status::ACTIVE => active += 1,
            cert_status::PENDING => pending += 1,
            cert_status::FAILED => failed += 1,
            cert_status::EXPIRED => expired += 1,
            _ => {},
        }
        if expires_at.is_some_and(|instant| instant <= soon) {
            expiring += 1;
        }
    }

    Ok(json!({
        "total": total,
        "active": active,
        "pending": pending,
        "failed": failed,
        "expired": expired,
        "expiring_soon": expiring,
    }))
}

async fn query_access_logs(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<Value, String> {
    let hours = window_hours(args, 1);
    let limit = arg_limit(args, 20);
    let from = Utc::now() - Duration::hours(hours);

    let visible = visible_site_ids(ctx).await?;
    let site_id =
        require_scoped_site(arg_uuid(args, "site_id")?, visible.as_ref())?;
    let mut condition =
        Condition::all().add(access_log::Column::Timestamp.gte(from));
    if let Some(site_id) = site_id {
        condition = condition.add(access_log::Column::SiteId.eq(site_id));
    }
    if let Some(class) = args.get("status_class").and_then(Value::as_i64) {
        if !(1..=5).contains(&class) {
            return Err("'status_class' must be between 1 and 5".to_string());
        }
        let base = (class * 100) as i32;
        condition = condition
            .add(access_log::Column::StatusCode.gte(base))
            .add(access_log::Column::StatusCode.lt(base + 100));
    }
    if let Some(method) = arg_string(args, "method") {
        condition = condition.add(access_log::Column::Method.eq(method));
    }
    if let Some(ip) = arg_string(args, "client_ip") {
        condition = condition.add(access_log::Column::ClientIp.eq(ip));
    }
    if let Some(path) = arg_string(args, "path") {
        condition = condition
            .add(access_log::Column::Path.like(contains_pattern(&path)));
    }
    if let Some(min) = args.get("min_latency_ms").and_then(Value::as_i64) {
        condition = condition.add(access_log::Column::TotalLatencyMs.gte(min));
    }

    let total = access_log::Entity::find()
        .filter(condition.clone())
        .count(&ctx.state.db)
        .await
        .map_err(db_error)?;
    let rows = access_log::Entity::find()
        .filter(condition)
        .order_by_desc(access_log::Column::Timestamp)
        .limit(limit)
        .all(&ctx.state.db)
        .await
        .map_err(db_error)?;

    let names = site_names(
        ctx.state,
        &rows
            .iter()
            .filter_map(|row| row.site_id)
            .collect::<Vec<_>>(),
    )
    .await?;
    let logs: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "timestamp": row.timestamp,
                "site": row.site_id.map(|id| names.get(&id).cloned().unwrap_or_else(|| id.to_string())),
                "client_ip": row.client_ip,
                "method": row.method,
                "host": row.host,
                "path": row.path,
                "status_code": row.status_code,
                "total_latency_ms": row.total_latency_ms,
                "upstream_addr": row.upstream_addr,
                "cache_status": row.cache_status,
            })
        })
        .collect();

    Ok(json!({
        "window_hours": hours,
        "total_matching": total,
        "returned": logs.len(),
        "logs": logs,
    }))
}

async fn query_waf_events(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<Value, String> {
    let hours = window_hours(args, DEFAULT_WINDOW_HOURS);
    let limit = arg_limit(args, 20);
    let from = Utc::now() - Duration::hours(hours);

    let visible = visible_site_ids(ctx).await?;
    let site_id =
        require_scoped_site(arg_uuid(args, "site_id")?, visible.as_ref())?;
    let mut condition =
        Condition::all().add(security_event::Column::Timestamp.gte(from));
    if let Some(site_id) = site_id {
        condition = condition.add(security_event::Column::SiteId.eq(site_id));
    }
    if let Some(action) = arg_string(args, "action") {
        condition = condition.add(security_event::Column::Action.eq(action));
    }

    let total = security_event::Entity::find()
        .filter(condition.clone())
        .count(&ctx.state.db)
        .await
        .map_err(db_error)?;
    let rows = security_event::Entity::find()
        .filter(condition)
        .order_by_desc(security_event::Column::Timestamp)
        .limit(limit)
        .all(&ctx.state.db)
        .await
        .map_err(db_error)?;

    let names = site_names(
        ctx.state,
        &rows
            .iter()
            .filter_map(|row| row.site_id)
            .collect::<Vec<_>>(),
    )
    .await?;
    let events: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "timestamp": row.timestamp,
                "site": row.site_id.map(|id| names.get(&id).cloned().unwrap_or_else(|| id.to_string())),
                "client_ip": row.client_ip,
                "method": row.method,
                "host": row.host,
                "path": row.path,
                "rule_id": row.rule_id,
                "rule_name": row.rule_name,
                "action": row.action,
                "score": row.score,
            })
        })
        .collect();

    Ok(json!({
        "window_hours": hours,
        "total_matching": total,
        "returned": events.len(),
        "events": events,
    }))
}

async fn get_traffic_summary(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<Value, String> {
    let hours = window_hours(args, DEFAULT_WINDOW_HOURS);
    let visible = visible_site_ids(ctx).await?;
    let site_id =
        require_scoped_site(arg_uuid(args, "site_id")?, visible.as_ref())?;
    let to = Utc::now();
    let from = to - Duration::hours(hours);

    let mut where_sql = "timestamp >= $1 AND timestamp < $2".to_string();
    let mut values: Vec<sea_orm::Value> = vec![from.into(), to.into()];
    if let Some(id) = site_id {
        where_sql.push_str(" AND site_id = $3");
        values.push(id.into());
    }

    let access_sql = format!(
        "SELECT COUNT(*) AS requests, \
                COUNT(DISTINCT client_ip) AS unique_ips, \
                COUNT(*) FILTER (WHERE cache_status = 'hit') AS cache_hits, \
                COALESCE(AVG(total_latency_ms), 0)::BIGINT AS avg_latency_ms, \
                COALESCE(MAX(total_latency_ms), 0)::BIGINT AS max_latency_ms, \
                COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS client_errors, \
                COUNT(*) FILTER (WHERE status_code >= 500) AS server_errors \
         FROM access_logs WHERE {where_sql}"
    );
    let access = query_all(&ctx.state.db, &access_sql, values)
        .await
        .map_err(api_error)?
        .into_iter()
        .next();

    let mut event_where = "timestamp >= $1 AND timestamp < $2".to_string();
    let mut event_values: Vec<sea_orm::Value> = vec![from.into(), to.into()];
    if let Some(id) = site_id {
        event_where.push_str(" AND site_id = $3");
        event_values.push(id.into());
    }
    let event_sql = format!(
        "SELECT COUNT(*) AS security_events, \
                COUNT(*) FILTER (WHERE action = 'block') AS blocked_requests, \
                COUNT(DISTINCT client_ip) AS distinct_attackers, \
                COUNT(DISTINCT rule_id) AS rules_triggered \
         FROM security_events WHERE {event_where}"
    );
    let events = query_all(&ctx.state.db, &event_sql, event_values)
        .await
        .map_err(api_error)?
        .into_iter()
        .next();

    let requests = read_i64(&access, "requests");
    let cache_hits = read_i64(&access, "cache_hits");
    let cache_hit_rate = if requests > 0 {
        (cache_hits as f64 / requests as f64 * 10_000.0).round() / 10_000.0
    } else {
        0.0
    };

    Ok(json!({
        "window_hours": hours,
        "site_id": site_id,
        "requests": requests,
        "unique_ips": read_i64(&access, "unique_ips"),
        "cache_hits": cache_hits,
        "cache_hit_rate": cache_hit_rate,
        "avg_latency_ms": read_i64(&access, "avg_latency_ms"),
        "max_latency_ms": read_i64(&access, "max_latency_ms"),
        "client_errors": read_i64(&access, "client_errors"),
        "server_errors": read_i64(&access, "server_errors"),
        "security_events": read_i64(&events, "security_events"),
        "blocked_requests": read_i64(&events, "blocked_requests"),
        "distinct_attackers": read_i64(&events, "distinct_attackers"),
        "rules_triggered": read_i64(&events, "rules_triggered"),
    }))
}

fn read_i64(row: &Option<sea_orm::QueryResult>, column: &str) -> i64 {
    row.as_ref()
        .and_then(|row| row.try_get::<i64>("", column).ok())
        .unwrap_or(0)
}

async fn get_defense_status(ctx: &ToolContext<'_>) -> Result<Value, String> {
    // Global control-plane defence settings: administrators only.
    if !ctx.is_admin {
        return Err("administrator role is required for this tool".to_string());
    }
    let defense = defense::load(&ctx.state.db).await.map_err(api_error)?;
    let settings = self_protection::load_settings(&ctx.state.db)
        .await
        .map_err(db_error)?;
    let allowlist =
        self_protection::effective_allowlist(&ctx.state.db, &settings)
            .await
            .map_err(db_error)?;

    Ok(json!({
        "observation_mode": defense.observation_mode,
        "observation_mode_updated_at": defense.updated_at,
        "control_plane": {
            "access_log_enabled": settings.access_log_enabled,
            "ip_allowlist_enabled": settings.ip_allowlist_enabled,
            "allowlist_entries": if settings.ip_allowlist_enabled { allowlist.len() } else { 0 },
            "waf_enabled": settings.waf_enabled,
            "waf_mode": settings.waf_mode,
        }
    }))
}

async fn list_ip_groups(ctx: &ToolContext<'_>) -> Result<Value, String> {
    let mut query = ip_groups::Entity::find();
    if !ctx.is_admin {
        // Site-bound groups belong to sites the caller may not own; only
        // the shared global groups are visible to everyone.
        query = query.filter(ip_groups::Column::IsGlobal.eq(true));
    }
    let rows = query
        .order_by_asc(ip_groups::Column::Name)
        .all(&ctx.state.db)
        .await
        .map_err(db_error)?;
    let groups: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "name": row.name,
                "description": row.description,
                "action": row.action,
                "is_global": row.is_global,
                "enabled": row.enabled,
                "entries": row.ip_ranges.len(),
                "source_url": row.source_url,
                "last_synced_at": row.last_synced_at,
                "last_sync_error": row.last_sync_error,
            })
        })
        .collect();
    Ok(json!({ "count": groups.len(), "groups": groups }))
}

async fn query_control_plane_logs(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<Value, String> {
    // Control-plane audit log: administrators only.
    if !ctx.is_admin {
        return Err("administrator role is required for this tool".to_string());
    }
    let hours = window_hours(args, DEFAULT_WINDOW_HOURS);
    let limit = arg_limit(args, 20);
    let from = Utc::now() - Duration::hours(hours);

    let mut condition = Condition::all()
        .add(control_plane_access_log::Column::Timestamp.gte(from));
    if let Some(action) = arg_string(args, "action") {
        condition =
            condition.add(control_plane_access_log::Column::Action.eq(action));
    }

    let total = control_plane_access_log::Entity::find()
        .filter(condition.clone())
        .count(&ctx.state.db)
        .await
        .map_err(db_error)?;
    let rows = control_plane_access_log::Entity::find()
        .filter(condition)
        .order_by_desc(control_plane_access_log::Column::Timestamp)
        .limit(limit)
        .all(&ctx.state.db)
        .await
        .map_err(db_error)?;

    let logs: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "timestamp": row.timestamp,
                "client_ip": row.client_ip,
                "method": row.method,
                "path": row.path,
                "status_code": row.status_code,
                "action": row.action,
                "user_email": row.user_email,
                "reason": row.reason,
            })
        })
        .collect();

    Ok(json!({
        "window_hours": hours,
        "total_matching": total,
        "returned": logs.len(),
        "logs": logs,
    }))
}

// ─────────────────────────────────────────────────────────────
// Write tools
// ─────────────────────────────────────────────────────────────

async fn set_observation_mode(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<Value, String> {
    let enabled = args
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| "'enabled' (boolean) is required".to_string())?;

    let row = defense::load(&ctx.state.db).await.map_err(api_error)?;
    let previous = row.observation_mode;
    if previous != enabled {
        let mut active: defense_settings::ActiveModel = row.into();
        active.observation_mode = Set(enabled);
        active.updated_at = Set(Utc::now());
        active.update(&ctx.state.db).await.map_err(db_error)?;
        notify_all_config_changed(ctx.state, Some(ctx.actor)).await;
        tracing::info!(
            actor = %ctx.actor,
            enabled,
            "observation mode changed by a tool call"
        );
    }

    Ok(json!({
        "observation_mode": enabled,
        "previous": previous,
        "config_pushed": previous != enabled,
    }))
}

async fn set_site_status(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<Value, String> {
    let status = arg_string(args, "status")
        .ok_or_else(|| "'status' (active|paused) is required".to_string())?;
    if !site_status::is_valid(&status) {
        return Err(format!("unknown site status '{status}'"));
    }

    let site_id = arg_uuid(args, "site_id")?;
    let domain = arg_string(args, "domain");
    let row = match (site_id, domain) {
        (Some(id), _) => site::Entity::find_by_id(id).one(&ctx.state.db).await,
        (None, Some(domain)) => {
            site::Entity::find()
                .filter(site::Column::Domain.eq(domain))
                .one(&ctx.state.db)
                .await
        },
        (None, None) => return Err("provide 'site_id' or 'domain'".to_string()),
    }
    .map_err(db_error)?
    .ok_or_else(|| "site not found".to_string())?;
    // Non-admins may only change the status of their own sites.
    if !ctx.is_admin && row.user_id != ctx.subject {
        return Err("site not found".to_string());
    }

    let id = row.id;
    let previous = row.status.clone();
    if previous != status {
        let mut active: site::ActiveModel = row.into();
        active.status = Set(status.clone());
        active.update(&ctx.state.db).await.map_err(db_error)?;
        sites::touch_site(ctx.state, id).await.map_err(api_error)?;
        notify_config_changed(ctx.state, id, Some(ctx.actor)).await;
        tracing::info!(
            actor = %ctx.actor,
            site_id = %id,
            status,
            "site status changed by a tool call"
        );
    }

    Ok(json!({
        "site_id": id,
        "status": status,
        "previous": previous,
        "config_pushed": previous != status,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_has_a_unique_name_and_a_descriptive_schema() {
        let specs = specs();
        assert!(specs.len() >= 10);
        let mut names: Vec<&str> = specs.iter().map(|s| s.name).collect();
        names.sort_unstable();
        let unique: std::collections::BTreeSet<&str> =
            names.iter().copied().collect();
        assert_eq!(unique.len(), names.len(), "duplicate tool name");
        for spec in &specs {
            assert_eq!(spec.schema["type"], "object", "{}", spec.name);
            assert!(
                spec.description.len() > 20,
                "{} needs a real description",
                spec.name
            );
        }
    }
}
