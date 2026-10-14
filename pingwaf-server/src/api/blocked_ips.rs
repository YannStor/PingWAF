//! Auto-blocked IP dashboard: lists the dynamic blocks the edge currently
//! enforces for a site (WAF/rate-limit auto-blocks and server-issued block
//! commands) and offers a one-click unblock that fans out to every agent
//! reporting the block.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::{agent, agent_blocked_ip, security_event, site};
use sea_orm::Set;

/// The narrowest CIDR a manual block may target, per family. Anything wider
/// (e.g. `0.0.0.0/0`, `10.0.0.0/8`, `2001:db8::/16`) is a fat-fingered
/// network-wide ban waiting to happen, so it is rejected at the API.
const MIN_IPV4_PREFIX: u8 = 16;
const MIN_IPV6_PREFIX: u8 = 32;

/// A validated block target: one address or one CIDR range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlockTarget {
    Single(std::net::IpAddr),
    Cidr(ipnet::IpNet),
}

impl BlockTarget {
    /// The canonical stored form: the input as typed for single addresses,
    /// the normalised `addr/pfx` for CIDRs.
    pub(crate) fn as_stored(&self) -> String {
        match self {
            Self::Single(ip) => ip.to_string(),
            Self::Cidr(net) => net.to_string(),
        }
    }

    /// Dashboard discriminator: `"single"` or `"cidr"`.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Single(_) => "single",
            Self::Cidr(_) => "cidr",
        }
    }
}

/// Collapses an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) into its IPv4
/// form, adjusting the prefix by the 96 mapped bits. `None` means the mapped
/// prefix does not leave room for a whole IPv4 address (`< /96`), which no
/// IPv4 CIDR can express.
fn unmap(addr: std::net::IpAddr, pfx: u8) -> Option<(std::net::IpAddr, u8)> {
    match addr {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) if pfx >= 96 => Some((std::net::IpAddr::V4(v4), pfx - 96)),
            Some(_) => None,
            None => Some((addr, pfx)),
        },
        v4 => Some((v4, pfx)),
    }
}

/// Parses the shape of a block/unblock target — a bare IP address or an
/// `addr/pfx` CIDR — normalising host bits and IPv4-mapped IPv6 input into
/// the plain IPv4 equivalent, with no width guard.
fn parse_target_shape(raw: &str) -> Result<BlockTarget, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(
            "invalid IP address or CIDR: ''".to_string(),
        ));
    }
    // ipnet's strict parser rejects `addr/pfx` with host bits set (e.g.
    // `203.0.113.99/24`); truncate those instead of bouncing the input, so
    // the stored entry and a later identical request always agree.
    if let Some((addr_raw, pfx_raw)) = trimmed.split_once('/') {
        let parsed = addr_raw
            .parse::<std::net::IpAddr>()
            .ok()
            .zip(pfx_raw.parse::<u8>().ok())
            .and_then(|(addr, pfx)| unmap(addr, pfx))
            .and_then(|(addr, pfx)| ipnet::IpNet::new(addr, pfx).ok())
            .map(|net| net.trunc());
        if let Some(net) = parsed {
            return Ok(BlockTarget::Cidr(net));
        }
    }
    match trimmed.parse::<std::net::IpAddr>() {
        // A bare `::ffff:a.b.c.d` is just the IPv4 address spelled in the
        // mapped form — store (and later unblock) it as the v4 literal so
        // both spellings refer to one entry.
        Ok(std::net::IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => Ok(BlockTarget::Single(std::net::IpAddr::V4(v4))),
            None => Ok(BlockTarget::Single(std::net::IpAddr::V6(v6))),
        },
        Ok(ip) => Ok(BlockTarget::Single(ip)),
        Err(_) => Err(ApiError::BadRequest(format!(
            "invalid IP address or CIDR: '{trimmed}'"
        ))),
    }
}

/// Parses a block target: a bare IP address or an `addr/pfx` CIDR.
/// CIDRs are capped at /16 (IPv4) and /32 (IPv6) so a whole-network ban
/// cannot be issued by accident; the returned value is normalised.
pub(crate) fn parse_block_target(raw: &str) -> Result<BlockTarget, ApiError> {
    let target = parse_target_shape(raw)?;
    if let BlockTarget::Cidr(net) = &target {
        let min = match net {
            ipnet::IpNet::V4(_) => MIN_IPV4_PREFIX,
            ipnet::IpNet::V6(_) => MIN_IPV6_PREFIX,
        };
        if net.prefix_len() < min {
            return Err(ApiError::BadRequest(format!(
                "CIDR prefix too broad: '{}' — the narrowest \
                 allowed range is /{min} for {}",
                raw.trim(),
                if min == MIN_IPV4_PREFIX {
                    "IPv4"
                } else {
                    "IPv6"
                }
            )));
        }
    }
    Ok(target)
}

/// Normalises an unblock target without the manual-block width guard:
/// unblocking must never be stricter than blocking, and the returned string
/// must match the form the block was stored under so the agent-side exact
/// key removal hits. Still rejects non-IP/CIDR input.
pub(crate) fn parse_unblock_target(raw: &str) -> Result<String, ApiError> {
    parse_target_shape(raw).map(|target| target.as_stored())
}

/// Classifies a stored `ip` value for the dashboard lists.
pub(crate) fn ip_kind(stored: &str) -> &'static str {
    if stored.parse::<ipnet::IpNet>().is_ok() {
        "cidr"
    } else {
        "single"
    }
}

/// Per-IP attack rollup over `security_events`, grouped by client IP.
#[derive(Debug, FromQueryResult)]
struct AttackStats {
    client_ip: String,
    attack_count: i64,
    last_attack_at: Option<DateTime<Utc>>,
}

/// One blocked IP as shown on the dashboard: the edge-side block merged with
/// the attack history that led to it. Multiple agents may enforce the same IP;
/// the counts and timestamps are folded into a single row.
#[derive(Debug, Serialize)]
pub struct BlockedIpResponse {
    pub ip: String,
    /// `"single"` for one address, `"cidr"` for a range.
    pub kind: &'static str,
    pub reason: Option<String>,
    pub blocked_at: DateTime<Utc>,
    /// None = permanent block (no automatic expiry).
    pub expires_at: Option<DateTime<Utc>>,
    pub agent_count: usize,
    pub attack_count: i64,
    pub last_attack_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct UnblockRequest {
    pub ip: String,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/blocked-ips", get(list))
        .route("/sites/{site_id}/blocked-ips/unblock", post(unblock))
        .route("/blocked-ips", get(global_list))
        .route("/blocked-ips/block", post(manual_block))
}

/// `GET /api/v1/sites/{site_id}/blocked-ips` — dynamic blocks in force,
/// newest first, each merged with its attack stats from `security_events`.
/// Lapsed blocks are hidden: the agent stops reporting them and the next
/// heartbeat reconciles the mirror, but a just-expired row may still be
/// visible between heartbeats.
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<BlockedIpResponse>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let now = Utc::now();
    let rows = agent_blocked_ip::Entity::find()
        .filter(agent_blocked_ip::Column::SiteId.eq(id))
        .filter(
            sea_orm::Condition::any()
                .add(agent_blocked_ip::Column::ExpiresAt.is_null())
                .add(agent_blocked_ip::Column::ExpiresAt.gt(now)),
        )
        .order_by_desc(agent_blocked_ip::Column::BlockedAt)
        .all(&state.db)
        .await?;

    let stats = security_event::Entity::find()
        .select_only()
        .column(security_event::Column::ClientIp)
        .column_as(security_event::Column::Id.count(), "attack_count")
        .column_as(security_event::Column::Timestamp.max(), "last_attack_at")
        .filter(security_event::Column::SiteId.eq(id))
        .group_by(security_event::Column::ClientIp)
        .into_model::<AttackStats>()
        .all(&state.db)
        .await?;
    let stat_map: std::collections::HashMap<String, AttackStats> = stats
        .into_iter()
        .map(|s| (s.client_ip.clone(), s))
        .collect();

    let mut by_ip: std::collections::HashMap<String, BlockedIpResponse> =
        std::collections::HashMap::new();
    for row in rows {
        let entry = by_ip.entry(row.ip.clone()).or_insert_with(|| {
            let stat = stat_map.get(&row.ip);
            BlockedIpResponse {
                ip: row.ip.clone(),
                kind: ip_kind(&row.ip),
                reason: row.reason.clone(),
                blocked_at: row.blocked_at,
                expires_at: row.expires_at,
                agent_count: 0,
                attack_count: stat.map_or(0, |s| s.attack_count),
                last_attack_at: stat.and_then(|s| s.last_attack_at),
            }
        });
        entry.agent_count += 1;
        // The most recent report wins for reason/timestamps; expiry shows the
        // soonest automatic unblock across enforcing agents.
        if row.blocked_at >= entry.blocked_at {
            entry.blocked_at = row.blocked_at;
            if row.reason.is_some() {
                entry.reason = row.reason.clone();
            }
        }
        entry.expires_at = match (entry.expires_at, row.expires_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (None, Some(b)) => Some(b),
            (a, None) => a,
        };
    }

    let mut out: Vec<BlockedIpResponse> = by_ip.into_values().collect();
    out.sort_by_key(|ip| std::cmp::Reverse(ip.blocked_at));
    Ok(Json(out))
}

/// `POST /api/v1/sites/{site_id}/blocked-ips/unblock` — lifts a dynamic block:
/// an `UnblockIp` command goes to every agent still enforcing it (queued when
/// disconnected) and the mirror rows are removed so the dashboard reflects
/// the unblock immediately.
async fn unblock(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UnblockRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;
    // Only the exact stored entry is lifted: unblocking a CIDR must not
    // remove the single-IP blocks it happens to cover.
    let target = parse_block_target(&payload.ip)?;
    let ip = target.as_stored();

    let rows = agent_blocked_ip::Entity::find()
        .filter(agent_blocked_ip::Column::SiteId.eq(id))
        .filter(agent_blocked_ip::Column::Ip.eq(&ip))
        .all(&state.db)
        .await?;
    let agent_ids: std::collections::BTreeSet<Uuid> =
        rows.iter().map(|row| row.agent_id).collect();

    let request = crate::api::agents::CommandRequest {
        command: "unblock_ip".to_string(),
        site_id: Some(id.to_string()),
        ip_addresses: vec![ip.clone()],
        urls: Vec::new(),
        tags: Vec::new(),
        duration_seconds: None,
        reason: Some("unblocked from dashboard".to_string()),
        graceful: true,
    };
    let mut delivered = 0usize;
    for agent_id in &agent_ids {
        let command = crate::api::agents::build_command(&request, Some(id))?;
        if state.agents.send_command(agent_id, command).await {
            delivered += 1;
        }
    }

    agent_blocked_ip::Entity::delete_many()
        .filter(agent_blocked_ip::Column::SiteId.eq(id))
        .filter(agent_blocked_ip::Column::Ip.eq(&ip))
        .exec(&state.db)
        .await?;

    tracing::info!(
        %id,
        %ip,
        agents = agent_ids.len(),
        delivered,
        requested_by = %current.id,
        "dynamic IP block lifted"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ip": ip,
            "agents": agent_ids.len(),
            "delivered": delivered,
        })),
    )
        .into_response())
}

// ── Global surfaces ────────────────────────────────────────────────────────

/// One (site, ip) dynamic block as shown on the global blacklist page.
#[derive(Debug, Serialize)]
pub struct GlobalBlockedIpResponse {
    pub ip: String,
    /// `"single"` for one address, `"cidr"` for a range.
    pub kind: &'static str,
    pub site_id: Uuid,
    pub site_name: String,
    pub reason: Option<String>,
    pub blocked_at: DateTime<Utc>,
    /// None = permanent block (no automatic expiry).
    pub expires_at: Option<DateTime<Utc>>,
    pub agent_count: usize,
    pub attack_count: i64,
    pub last_attack_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct GlobalListQuery {
    pub site_id: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ManualBlockRequest {
    pub site_id: String,
    pub ip: String,
    /// Seconds the block stays in force; 0/absent = permanent until unblocked.
    pub duration_seconds: Option<i64>,
    pub reason: Option<String>,
}

/// Per-(site, IP) attack rollup for the global view.
#[derive(Debug, FromQueryResult)]
struct GlobalAttackStats {
    site_id: Uuid,
    client_ip: String,
    attack_count: i64,
    last_attack_at: Option<DateTime<Utc>>,
}

/// `GET /api/v1/blocked-ips` — every dynamic block in force, merged across
/// agents and folded per (site, ip), with the site's display name. Admins
/// see all sites; other accounts only their own. Optional `site_id` and
/// `ip` (substring) filters narrow the result.
async fn global_list(
    State(state): State<AppState>,
    current: AuthUser,
    axum::extract::Query(query): axum::extract::Query<GlobalListQuery>,
) -> Result<Json<Vec<GlobalBlockedIpResponse>>, ApiError> {
    // Resolve the site ids the caller may see.
    let site_filter: Option<Vec<Uuid>> = if let Some(raw) = query
        .site_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let id = parse_uuid(raw, "site id")?;
        load_site_read(&state.db, id, &current).await?;
        Some(vec![id])
    } else if current.is_admin() {
        None
    } else {
        Some(
            site::Entity::find()
                .filter(site::Column::UserId.eq(current.id))
                .all(&state.db)
                .await?
                .into_iter()
                .map(|row| row.id)
                .collect(),
        )
    };

    let now = Utc::now();
    let mut select = agent_blocked_ip::Entity::find().filter(
        sea_orm::Condition::any()
            .add(agent_blocked_ip::Column::ExpiresAt.is_null())
            .add(agent_blocked_ip::Column::ExpiresAt.gt(now)),
    );
    if let Some(ids) = &site_filter {
        select =
            select.filter(agent_blocked_ip::Column::SiteId.is_in(ids.clone()));
    }
    if let Some(needle) = crate::api::common::non_empty(&query.ip) {
        select = select.filter(agent_blocked_ip::Column::Ip.contains(needle));
    }
    let rows = select
        .order_by_desc(agent_blocked_ip::Column::BlockedAt)
        .all(&state.db)
        .await?;

    let site_ids: std::collections::BTreeSet<Uuid> =
        rows.iter().map(|row| row.site_id).collect();
    let site_names: std::collections::HashMap<Uuid, String> =
        site::Entity::find()
            .filter(site::Column::Id.is_in(site_ids.iter().copied()))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|row| (row.id, row.name))
            .collect();

    let mut stats_select = security_event::Entity::find()
        .select_only()
        .column(security_event::Column::SiteId)
        .column(security_event::Column::ClientIp)
        .column_as(security_event::Column::Id.count(), "attack_count")
        .column_as(security_event::Column::Timestamp.max(), "last_attack_at")
        .group_by(security_event::Column::SiteId)
        .group_by(security_event::Column::ClientIp);
    if let Some(ids) = &site_filter {
        stats_select = stats_select
            .filter(security_event::Column::SiteId.is_in(ids.clone()));
    } else {
        stats_select = stats_select.filter(
            security_event::Column::SiteId.is_in(site_ids.iter().copied()),
        );
    }
    let stats = stats_select
        .into_model::<GlobalAttackStats>()
        .all(&state.db)
        .await?;
    let stat_map: std::collections::HashMap<(Uuid, String), GlobalAttackStats> =
        stats
            .into_iter()
            .map(|s| ((s.site_id, s.client_ip.clone()), s))
            .collect();

    let mut by_ip: std::collections::HashMap<
        (Uuid, String),
        GlobalBlockedIpResponse,
    > = std::collections::HashMap::new();
    for row in rows {
        let key = (row.site_id, row.ip.clone());
        let entry = by_ip.entry(key).or_insert_with(|| {
            let stat = stat_map.get(&(row.site_id, row.ip.clone()));
            GlobalBlockedIpResponse {
                ip: row.ip.clone(),
                kind: ip_kind(&row.ip),
                site_id: row.site_id,
                site_name: site_names
                    .get(&row.site_id)
                    .cloned()
                    .unwrap_or_default(),
                reason: row.reason.clone(),
                blocked_at: row.blocked_at,
                expires_at: row.expires_at,
                agent_count: 0,
                attack_count: stat.map_or(0, |s| s.attack_count),
                last_attack_at: stat.and_then(|s| s.last_attack_at),
            }
        });
        entry.agent_count += 1;
        if row.blocked_at >= entry.blocked_at {
            entry.blocked_at = row.blocked_at;
            if row.reason.is_some() {
                entry.reason = row.reason.clone();
            }
        }
        entry.expires_at = match (entry.expires_at, row.expires_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (None, Some(b)) => Some(b),
            (a, None) => a,
        };
    }

    let mut out: Vec<GlobalBlockedIpResponse> = by_ip.into_values().collect();
    out.sort_by_key(|ip| std::cmp::Reverse(ip.blocked_at));
    Ok(Json(out))
}

/// `POST /api/v1/blocked-ips/block` — a manual dynamic block: a `BlockIp`
/// command goes to every registered agent (queued for the offline ones) and
/// mirror rows are written so the dashboard reflects the block immediately;
/// the next heartbeat reconciles any drift. `duration_seconds = 0` blocks
/// permanently until unblocked.
async fn manual_block(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<ManualBlockRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(payload.site_id.trim(), "site id")?;
    load_site_write(&state.db, id, &current).await?;
    let target = parse_block_target(&payload.ip)?;
    let ip = target.as_stored();
    let duration = payload.duration_seconds.unwrap_or(0).max(0);
    let reason = payload
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("manual block from dashboard")
        .to_string();

    let agent_ids: Vec<Uuid> = agent::Entity::find()
        .all(&state.db)
        .await?
        .into_iter()
        .map(|row| row.id)
        .collect();

    let request = crate::api::agents::CommandRequest {
        command: "block_ip".to_string(),
        site_id: Some(id.to_string()),
        ip_addresses: vec![ip.clone()],
        urls: Vec::new(),
        tags: Vec::new(),
        duration_seconds: Some(duration),
        reason: Some(reason.clone()),
        graceful: true,
    };
    let mut delivered = 0usize;
    for agent_id in &agent_ids {
        let command = crate::api::agents::build_command(&request, Some(id))?;
        if state.agents.send_command(agent_id, command).await {
            delivered += 1;
        }
    }

    // Refresh the mirror rows in one shot: drop stale ones for this pair and
    // insert the current posture, so the dashboard agrees with the commands
    // even before the next heartbeat reconciles.
    let now = Utc::now();
    let expires_at =
        (duration > 0).then(|| now + chrono::Duration::seconds(duration));
    agent_blocked_ip::Entity::delete_many()
        .filter(agent_blocked_ip::Column::SiteId.eq(id))
        .filter(agent_blocked_ip::Column::Ip.eq(&ip))
        .exec(&state.db)
        .await?;
    let mut models = Vec::with_capacity(agent_ids.len());
    for agent_id in &agent_ids {
        models.push(agent_blocked_ip::ActiveModel {
            agent_id: Set(*agent_id),
            site_id: Set(id),
            ip: Set(ip.clone()),
            reason: Set(Some(reason.clone())),
            blocked_at: Set(now),
            expires_at: Set(expires_at),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        });
    }
    if !models.is_empty() {
        agent_blocked_ip::Entity::insert_many(models)
            .exec(&state.db)
            .await?;
    }

    tracing::info!(
        %id,
        %ip,
        duration,
        agents = agent_ids.len(),
        delivered,
        requested_by = %current.id,
        "manual dynamic IP block issued"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ip": ip,
            "kind": target.kind(),
            "site_id": id,
            "duration_seconds": duration,
            "agents": agent_ids.len(),
            "delivered": delivered,
        })),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Result<BlockTarget, ApiError> {
        parse_block_target(raw)
    }

    #[test]
    fn single_addresses_and_cidrs_parse_with_kind() {
        assert_eq!(
            parse("203.0.113.1").unwrap(),
            BlockTarget::Single("203.0.113.1".parse().unwrap())
        );
        assert_eq!(parse("2001:db8::1").unwrap().kind(), "single");
        assert_eq!(parse("203.0.113.0/24").unwrap().kind(), "cidr");
        assert_eq!(
            parse(" 2001:db8::/32 ").unwrap().as_stored(),
            "2001:db8::/32"
        );
    }

    #[test]
    fn cidrs_are_normalised_before_storage() {
        // Host bits set: ipnet truncates them, so the stored entry and a
        // later unblock request with the same input agree on one string.
        assert_eq!(
            parse("203.0.113.99/24").unwrap().as_stored(),
            "203.0.113.0/24"
        );
    }

    #[test]
    fn invalid_targets_are_rejected() {
        assert!(parse("").is_err());
        assert!(parse("not-an-ip").is_err());
        assert!(parse("203.0.113.0/8x").is_err());
    }

    #[test]
    fn broad_cidrs_are_rejected_with_a_clear_message() {
        let err = parse("0.0.0.0/0").unwrap_err().to_string();
        assert!(err.contains("prefix too broad"), "{err}");
        assert!(err.contains("/16"), "{err}");
        assert!(parse("10.0.0.0/8").is_err());
        assert!(parse("2001:db8::/16").is_err());
        // At the boundary: allowed.
        assert!(parse("10.0.0.0/16").is_ok());
        assert!(parse("2001:db8::/32").is_ok());
    }

    #[test]
    fn ip_kind_classifies_stored_values() {
        assert_eq!(ip_kind("203.0.113.1"), "single");
        assert_eq!(ip_kind("203.0.113.0/24"), "cidr");
        assert_eq!(ip_kind("2001:db8::/32"), "cidr");
        assert_eq!(ip_kind("garbage"), "single");
    }

    #[test]
    fn ipv4_mapped_cidrs_collapse_to_ipv4_and_inherit_its_guard() {
        // /96 on the mapped range is 0.0.0.0/0 in disguise — beyond /16.
        let err = parse("::ffff:0:0/96").unwrap_err().to_string();
        assert!(err.contains("too broad"), "{err}");
        assert!(err.contains("/16"), "{err}");
        // /104 maps to 10.0.0.0/8 — judged by the v4 ceiling, rejected.
        assert!(parse("::ffff:10.0.0.0/104").is_err());
        // Mapped /120 maps to a v4 /24: allowed, stored in v4 form.
        assert_eq!(
            parse("::ffff:203.0.113.0/120").unwrap().as_stored(),
            "203.0.113.0/24"
        );
        // Boundary: mapped /112 == v4 /16 is the narrowest allowed.
        assert!(parse("::ffff:10.0.0.0/112").is_ok());
    }

    #[test]
    fn bare_mapped_addresses_are_stored_as_ipv4() {
        assert_eq!(
            parse("::ffff:203.0.113.5").unwrap().as_stored(),
            "203.0.113.5"
        );
        assert_eq!(parse("::ffff:203.0.113.5").unwrap().kind(), "single");
        // Unblocking uses the same collapse, so the stored key matches.
        assert_eq!(
            parse_unblock_target("::ffff:203.0.113.0/120").unwrap(),
            "203.0.113.0/24"
        );
        // Non-mapped v6 is untouched.
        assert_eq!(parse_unblock_target("2001:db8::1").unwrap(), "2001:db8::1");
    }
}
