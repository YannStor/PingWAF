//! Log queries: security events produced by the WAF and the full access log.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::{DateTime, Duration, Utc};
use sea_orm::sea_query::{Alias, Expr, PostgresQueryBuilder};
use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, EntityTrait, FromQueryResult,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{
    load_site_read, non_empty, parse_optional_datetime, parse_uuid, query_all,
    scope_site, Page, Pagination,
};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::{access_log, security_event, site};

/// How far back a query may reach when the client does not say.
const DEFAULT_WINDOW_HOURS: i64 = 24;
/// Hard ceiling on the requested window, so a stray `from=1970` cannot scan the
/// whole table.
const MAX_WINDOW_DAYS: i64 = 90;
/// Upper bound on how many matching rows the log listings count exactly.
/// The count subquery stops after `COUNT_CAP + 1` id hits, so a broad
/// free-text search — whose leading-wildcard LIKE a btree cannot serve —
/// costs the same as a narrow one instead of draining every match in the
/// (up to 90-day) window. Beyond the cap the page reports
/// `total = COUNT_CAP` and sets `total_truncated`, which the console
/// renders as "10000+"; investigation flows refine the query rather
/// than paging through ten thousand rows.
const COUNT_CAP: u64 = 10_000;

#[derive(Debug, Deserialize)]
pub struct SecurityQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
    pub site_id: Option<String>,
    /// RFC 3339; defaults to 24 hours ago.
    pub from: Option<String>,
    /// RFC 3339; defaults to now.
    pub to: Option<String>,
    pub client_ip: Option<String>,
    pub action: Option<String>,
    pub rule_id: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub country_code: Option<String>,
    /// The authenticated caller's OIDC `sub`, exact match. This is the filter
    /// an investigation starts from: "what else did this account do".
    pub user_identity: Option<String>,
    /// Exact request id, e.g. when correlating with an `X-Request-ID` header.
    pub request_id: Option<String>,
    /// Protection type filter: `managed` / `waf` / `ip_geo` / `bot` /
    /// `rate_limit` / `challenge`. Untyped (pre-migration) rows never match.
    pub event_type: Option<String>,
    /// When true, matches only rows with no owning site — traffic that arrived
    /// without a `Host` header. Mutually exclusive with `site_id`.
    pub unassigned: Option<bool>,
    /// Free-text search over the request target and host (OR).
    pub q: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AccessQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
    pub site_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub status_code: Option<i32>,
    pub status_class: Option<i32>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub cache_status: Option<String>,
    pub country_code: Option<String>,
    /// The authenticated caller's OIDC `sub`, exact match.
    pub user_identity: Option<String>,
    pub min_latency_ms: Option<i64>,
    /// Exact request id, e.g. when correlating with an `X-Request-ID` header.
    pub request_id: Option<String>,
    /// When true, matches only rows with no owning site — traffic that arrived
    /// without a `Host` header. Mutually exclusive with `site_id`.
    pub unassigned: Option<bool>,
    /// Free-text search over the request target and host (OR).
    pub q: Option<String>,
}

/// Resolves the [`SecurityQuery::unassigned`] / [`AccessQuery::unassigned`]
/// flag: 400 when combined with an explicit site, otherwise the caller decides
/// what "no site" means for the table being queried.
fn check_unassigned(
    unassigned: Option<bool>,
    site_id: &Option<String>,
) -> Result<bool, ApiError> {
    if unassigned != Some(true) {
        return Ok(false);
    }
    if non_empty(site_id).is_some() {
        return Err(ApiError::BadRequest(
            "'unassigned' and 'site_id' are mutually exclusive".to_string(),
        ));
    }
    Ok(true)
}

/// Retention endpoint payload.
#[derive(Debug, Deserialize)]
pub struct PurgeQuery {
    pub site_id: Option<String>,
    /// Delete rows older than this many days; defaults to 30.
    #[serde(default = "default_retention_days")]
    pub older_than_days: i64,
}

fn default_retention_days() -> i64 {
    30
}

#[derive(Debug, Serialize)]
pub struct PurgeResult {
    pub deleted_security_events: u64,
    pub deleted_access_logs: u64,
    /// Rows removed from the control plane's own access log; `0` when the
    /// sweep was narrowed to one site.
    pub deleted_control_plane_logs: u64,
    pub cutoff: DateTime<Utc>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/logs/security", get(list_security))
        .route("/logs/access", get(list_access))
        .route("/logs/access/{id}", get(get_access))
        .route("/logs/purge", axum::routing::delete(purge))
}

/// Resolves the site filter and the caller's visibility at once.
///
/// Returns `Ok(None)` for an administrator that did not name a site (meaning "all
/// sites") and a list of allowed site ids otherwise.
async fn resolve_scope(
    db: &DatabaseConnection,
    requested: &Option<String>,
    current: &AuthUser,
) -> Result<Option<Vec<Uuid>>, ApiError> {
    let requested_id = match non_empty(requested) {
        Some(raw) => Some(parse_uuid(&raw, "site id")?),
        None => None,
    };
    // Errors out when a non-admin asks for "everything".
    scope_site(requested_id, current)?;

    if let Some(id) = requested_id {
        // `scope_site` only enforces "non-admins must name a site"; it does
        // not check ownership. Validate the site here the same way every
        // other site-scoped handler does, otherwise any viewer can read
        // another tenant's logs by naming its id.
        let site = load_site_read(db, id, current).await?;
        return Ok(Some(vec![site.id]));
    }
    if current.is_admin() {
        return Ok(None);
    }

    let owned: Vec<Uuid> = site::Entity::find()
        .filter(site::Column::UserId.eq(current.id))
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.id)
        .collect();
    Ok(Some(owned))
}

/// Applies the site scope to a condition. An empty allow-list yields a condition
/// that matches nothing, which keeps the query cheap and correct.
fn apply_scope(
    condition: Condition,
    scope: &Option<Vec<Uuid>>,
    column: impl ColumnTrait,
) -> Condition {
    match scope {
        None => condition,
        Some(ids) if ids.is_empty() => {
            condition.add(column.eq(Uuid::nil()).and(column.ne(Uuid::nil())))
        },
        Some(ids) => condition.add(column.is_in(ids.iter().copied())),
    }
}

/// Splits a comma-separated filter value (`a,b`) into its trimmed, non-empty
/// parts; the value is used verbatim when it holds no comma.
fn split_multi(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

/// Escapes LIKE metacharacters so a user-supplied value matches literally.
pub(crate) fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

/// Renders a value that may carry `*` wildcards as a LIKE pattern; `None` when
/// no wildcard is present, so the caller can match exactly instead.
fn like_pattern(value: &str) -> Option<String> {
    if !value.contains('*') {
        return None;
    }
    Some(escape_like(value).replace('*', "%"))
}

/// Builds the condition for one text filter: comma-separated values become an
/// IN list, `*` turns the match into a LIKE, and everything else is exact.
pub(crate) fn text_filter(column: impl ColumnTrait, raw: &str) -> Condition {
    let parts = split_multi(raw);
    if parts.is_empty() {
        // "`,`" and friends: match nothing rather than silently dropping the
        // filter, which would return rows the caller excluded.
        return Condition::all().add(column.eq("").and(column.ne("")));
    }
    let mut condition = Condition::any();
    for part in &parts {
        condition = match like_pattern(part) {
            Some(pattern) => condition.add(column.clone().like(pattern)),
            None => condition.add(column.clone().eq(part.clone())),
        };
    }
    condition
}

/// Free-text search: the needle must appear in the request target or host.
pub(crate) fn free_text_filter(
    path_column: impl ColumnTrait,
    host_column: impl ColumnTrait,
    needle: &str,
) -> Condition {
    let pattern = format!("%{}%", escape_like(needle));
    Condition::any()
        .add(path_column.like(pattern.clone()))
        .add(host_column.like(pattern))
}

/// Bounded `COUNT(*)` for one of the log listings. The caller supplies a
/// matching-ids query already limited to `COUNT_CAP + 1`; this counts it
/// inside the database, so the ids never travel to the application and
/// the scan stops early instead of visiting every match. Returns
/// `(total, truncated)` — `total` is capped at [`COUNT_CAP`] and
/// `truncated` tells the page envelope the true count is larger.
async fn capped_total(
    db: &DatabaseConnection,
    capped: sea_orm::sea_query::SelectStatement,
) -> Result<(u64, bool), ApiError> {
    let (sql, values) = sea_orm::sea_query::Query::select()
        .expr_as(Expr::cust("COUNT(*)"), Alias::new("count"))
        .from_subquery(capped, Alias::new("capped"))
        .build(PostgresQueryBuilder);
    let rows = query_all(db, &sql, values.0).await?;
    // COUNT(*) over a subquery returns exactly one row; a missing or
    // unreadable value means zero matches, not a failure.
    let count = rows
        .first()
        .and_then(|row| row.try_get::<i64>("", "count").ok())
        .unwrap_or_default()
        .max(0) as u64;
    Ok((count.min(COUNT_CAP), count > COUNT_CAP))
}

/// Resolves and validates the `from`/`to` window.
pub(crate) fn resolve_window(
    from: &Option<String>,
    to: &Option<String>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let end = match parse_optional_datetime(to, "to")? {
        Some(instant) => instant,
        None => Utc::now(),
    };
    let start = match parse_optional_datetime(from, "from")? {
        Some(instant) => instant,
        None => end - Duration::hours(DEFAULT_WINDOW_HOURS),
    };
    if start >= end {
        return Err(ApiError::BadRequest(
            "'from' must be earlier than 'to'".to_string(),
        ));
    }
    let floor = end - Duration::days(MAX_WINDOW_DAYS);
    if start < floor {
        return Err(ApiError::BadRequest(format!(
            "the query window may not exceed {MAX_WINDOW_DAYS} days"
        )));
    }
    Ok((start, end))
}

/// `GET /api/v1/logs/security`
async fn list_security(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<SecurityQuery>,
) -> Result<Json<Page<security_event::Model>>, ApiError> {
    let scope = resolve_scope(&state.db, &query.site_id, &current).await?;
    let (from, to) = resolve_window(&query.from, &query.to)?;
    let pagination = query.pagination.normalise();
    let unassigned = check_unassigned(query.unassigned, &query.site_id)?;

    let mut condition = Condition::all()
        .add(security_event::Column::Timestamp.gte(from))
        .add(security_event::Column::Timestamp.lt(to));
    condition = apply_scope(condition, &scope, security_event::Column::SiteId);
    if unassigned {
        // Unassigned rows carry no site, so scoped users (whose allow-list
        // never contains NULL) simply match nothing — the admin-only global
        // view is the one where this filter is meaningful.
        condition = condition.add(security_event::Column::SiteId.is_null());
    }

    if let Some(ip) = non_empty(&query.client_ip) {
        condition =
            condition.add(text_filter(security_event::Column::ClientIp, &ip));
    }
    if let Some(action) = non_empty(&query.action) {
        condition =
            condition.add(text_filter(security_event::Column::Action, &action));
    }
    if let Some(rule_id) = non_empty(&query.rule_id) {
        condition = condition
            .add(text_filter(security_event::Column::RuleId, &rule_id));
    }
    if let Some(host) = non_empty(&query.host) {
        condition =
            condition.add(text_filter(security_event::Column::Host, &host));
    }
    if let Some(path) = non_empty(&query.path) {
        condition = condition.add(security_event::Column::Path.contains(path));
    }
    if let Some(country) = non_empty(&query.country_code) {
        condition = condition.add(text_filter(
            security_event::Column::CountryCode,
            &country.to_uppercase(),
        ));
    }
    if let Some(identity) = non_empty(&query.user_identity) {
        // Exact match, not `text_filter`: an identity is one value, and the
        // `a,b` list semantics would make a `sub` containing a comma (which
        // some providers issue) unfilterable.
        condition =
            condition.add(security_event::Column::UserIdentity.eq(identity));
    }
    if let Some(request_id) = non_empty(&query.request_id) {
        condition =
            condition.add(security_event::Column::RequestId.eq(request_id));
    }
    if let Some(event_type) = non_empty(&query.event_type) {
        condition = condition.add(text_filter(
            security_event::Column::EventType,
            &event_type.to_lowercase(),
        ));
    }
    if let Some(q) = non_empty(&query.q) {
        condition = condition.add(free_text_filter(
            security_event::Column::Path,
            security_event::Column::Host,
            &q,
        ));
    }

    // Bounded count: the id-only subquery stops at the cap, so neither a
    // broad free-text search nor a wide window makes the count the most
    // expensive part of the listing.
    let capped = security_event::Entity::find()
        .filter(condition.clone())
        .select_only()
        .column(security_event::Column::Id)
        .limit(COUNT_CAP + 1)
        .into_query();
    let (total, total_truncated) = capped_total(&state.db, capped).await?;

    let rows = security_event::Entity::find()
        .filter(condition)
        .order_by_desc(security_event::Column::Timestamp)
        .offset(pagination.offset())
        .limit(pagination.limit())
        .all(&state.db)
        .await?;
    Ok(Json(Page::new_capped(
        rows,
        total,
        pagination,
        total_truncated,
    )))
}

/// Metadata-only access-log row served by the list endpoint.
///
/// The four heavy columns — request/response headers and bodies — are
/// excluded so a full page stays in the low-hundreds-of-kilobytes range;
/// clients that need them fetch one record via [`get_access`].
#[derive(Serialize, FromQueryResult)]
#[serde(rename_all = "snake_case")]
pub struct AccessLogSummary {
    pub id: i64,
    pub site_id: Option<Uuid>,
    pub agent_id: Option<Uuid>,
    pub request_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub method: String,
    pub host: Option<String>,
    pub path: Option<String>,
    pub query_string: Option<String>,
    pub status_code: Option<i32>,
    pub response_size: Option<i64>,
    pub upstream_addr: Option<String>,
    pub upstream_latency_ms: Option<i64>,
    pub total_latency_ms: Option<i64>,
    pub cache_status: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub country_code: Option<String>,
    pub tls_version: Option<String>,
    /// Who the request was made by, when the site authenticated them: the
    /// OIDC session's `sub`. `None` for anonymous traffic and for rows
    /// written before migration 000071.
    pub user_identity: Option<String>,
    pub request_body_size: Option<i64>,
    pub request_body_truncated: Option<bool>,
    pub scheme: Option<String>,
    pub protocol: Option<String>,
    pub response_body_size: Option<i64>,
    pub response_body_truncated: Option<bool>,
}

/// Columns backing [`AccessLogSummary`], kept next to the struct so the two
/// cannot drift: the summary is exactly these fields.
fn summary_columns() -> [access_log::Column; 27] {
    [
        access_log::Column::Id,
        access_log::Column::SiteId,
        access_log::Column::AgentId,
        access_log::Column::RequestId,
        access_log::Column::Timestamp,
        access_log::Column::ClientIp,
        access_log::Column::Method,
        access_log::Column::Host,
        access_log::Column::Path,
        access_log::Column::QueryString,
        access_log::Column::StatusCode,
        access_log::Column::ResponseSize,
        access_log::Column::UpstreamAddr,
        access_log::Column::UpstreamLatencyMs,
        access_log::Column::TotalLatencyMs,
        access_log::Column::CacheStatus,
        access_log::Column::UserAgent,
        access_log::Column::Referer,
        access_log::Column::CountryCode,
        access_log::Column::TlsVersion,
        access_log::Column::UserIdentity,
        access_log::Column::RequestBodySize,
        access_log::Column::RequestBodyTruncated,
        access_log::Column::Scheme,
        access_log::Column::Protocol,
        access_log::Column::ResponseBodySize,
        access_log::Column::ResponseBodyTruncated,
    ]
}

/// `GET /api/v1/logs/access`
async fn list_access(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<AccessQuery>,
) -> Result<Json<Page<AccessLogSummary>>, ApiError> {
    let scope = resolve_scope(&state.db, &query.site_id, &current).await?;
    let (from, to) = resolve_window(&query.from, &query.to)?;
    let pagination = query.pagination.normalise();
    let unassigned = check_unassigned(query.unassigned, &query.site_id)?;

    let mut condition = Condition::all()
        .add(access_log::Column::Timestamp.gte(from))
        .add(access_log::Column::Timestamp.lt(to));
    condition = apply_scope(condition, &scope, access_log::Column::SiteId);
    if unassigned {
        condition = condition.add(access_log::Column::SiteId.is_null());
    }

    if let Some(ip) = non_empty(&query.client_ip) {
        condition =
            condition.add(text_filter(access_log::Column::ClientIp, &ip));
    }
    if let Some(method) = non_empty(&query.method) {
        condition = condition.add(text_filter(
            access_log::Column::Method,
            &method.to_uppercase(),
        ));
    }
    if let Some(status) = query.status_code {
        if !(100..=599).contains(&status) {
            return Err(ApiError::BadRequest(
                "status_code must be between 100 and 599".to_string(),
            ));
        }
        condition = condition.add(access_log::Column::StatusCode.eq(status));
    }
    if let Some(class) = query.status_class {
        if ![1, 2, 3, 4, 5].contains(&class) {
            return Err(ApiError::BadRequest(
                "status_class must be one of 1, 2, 3, 4, 5".to_string(),
            ));
        }
        condition = condition
            .add(access_log::Column::StatusCode.gte(class * 100))
            .add(access_log::Column::StatusCode.lt((class + 1) * 100));
    }
    if let Some(host) = non_empty(&query.host) {
        condition = condition.add(text_filter(access_log::Column::Host, &host));
    }
    if let Some(path) = non_empty(&query.path) {
        condition = condition.add(access_log::Column::Path.contains(path));
    }
    if let Some(cache_status) = non_empty(&query.cache_status) {
        condition = condition.add(text_filter(
            access_log::Column::CacheStatus,
            &cache_status.to_lowercase(),
        ));
    }
    if let Some(country) = non_empty(&query.country_code) {
        condition = condition.add(text_filter(
            access_log::Column::CountryCode,
            &country.to_uppercase(),
        ));
    }
    if let Some(identity) = non_empty(&query.user_identity) {
        // Exact match, not `text_filter`: an identity is one value.
        condition =
            condition.add(access_log::Column::UserIdentity.eq(identity));
    }
    if let Some(min_latency) = query.min_latency_ms {
        condition =
            condition.add(access_log::Column::TotalLatencyMs.gte(min_latency));
    }
    if let Some(request_id) = non_empty(&query.request_id) {
        condition = condition.add(access_log::Column::RequestId.eq(request_id));
    }
    if let Some(q) = non_empty(&query.q) {
        condition = condition.add(free_text_filter(
            access_log::Column::Path,
            access_log::Column::Host,
            &q,
        ));
    }

    // Bounded count, same shape as the security-event listing.
    let capped = access_log::Entity::find()
        .filter(condition.clone())
        .select_only()
        .column(access_log::Column::Id)
        .limit(COUNT_CAP + 1)
        .into_query();
    let (total, total_truncated) = capped_total(&state.db, capped).await?;

    let rows = access_log::Entity::find()
        .filter(condition)
        .select_only()
        .columns(summary_columns())
        .order_by_desc(access_log::Column::Timestamp)
        .offset(pagination.offset())
        .limit(pagination.limit())
        .into_model::<AccessLogSummary>()
        .all(&state.db)
        .await?;
    Ok(Json(Page::new_capped(
        rows,
        total,
        pagination,
        total_truncated,
    )))
}

/// `GET /api/v1/logs/access/{id}` — one full access-log record.
///
/// The list endpoint returns [`AccessLogSummary`] rows; the detail view
/// (raw HTTP replay, curl export) fetches headers and bodies here.
async fn get_access(
    State(state): State<AppState>,
    current: AuthUser,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<access_log::Model>, ApiError> {
    let row = access_log::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("access log not found".into()))?;

    // Same visibility as the list endpoint: administrators see everything;
    // everyone else only rows belonging to sites they own, and "unassigned"
    // rows are an administrator-only concern.
    if !current.is_admin() {
        match row.site_id {
            Some(site_id) => {
                let owned = site::Entity::find()
                    .filter(site::Column::UserId.eq(current.id))
                    .filter(site::Column::Id.eq(site_id))
                    .one(&state.db)
                    .await?;
                if owned.is_none() {
                    return Err(ApiError::NotFound(
                        "access log not found".into(),
                    ));
                }
            },
            None => {
                return Err(ApiError::NotFound("access log not found".into()))
            },
        }
    }
    Ok(Json(row))
}

/// Rows deleted per statement by [`purge_logs`].
const PURGE_BATCH_SIZE: u64 = 10_000;

/// Outcome of one retention sweep.
#[derive(Debug, Clone, Copy)]
pub struct PurgeOutcome {
    pub deleted_security_events: u64,
    pub deleted_access_logs: u64,
    pub access_cutoff: DateTime<Utc>,
    pub security_cutoff: DateTime<Utc>,
}

/// Deletes rows older than the given windows, in bounded batches.
///
/// Both tables are append-heavy, so one `DELETE ... WHERE timestamp < cutoff`
/// can hold locks on millions of rows; each statement deletes through an id
/// subquery limited to [`PURGE_BATCH_SIZE`] rows and the loop drains the
/// backlog. Access logs and security events keep separate windows, and
/// `site_id` narrows the sweep to a single site. Shared by the manual purge
/// endpoint and the scheduled sweep.
pub async fn purge_logs(
    db: &DatabaseConnection,
    access_days: i64,
    security_days: i64,
    site_id: Option<Uuid>,
) -> Result<PurgeOutcome, ApiError> {
    let access_cutoff = Utc::now() - Duration::days(access_days);
    let security_cutoff = Utc::now() - Duration::days(security_days);

    let mut deleted_access = 0_u64;
    loop {
        let mut batch = access_log::Entity::find()
            .select_only()
            .column(access_log::Column::Id)
            .filter(access_log::Column::Timestamp.lt(access_cutoff))
            .limit(PURGE_BATCH_SIZE);
        if let Some(id) = site_id {
            batch = batch.filter(access_log::Column::SiteId.eq(id));
        }
        let deleted = access_log::Entity::delete_many()
            .filter(access_log::Column::Id.in_subquery(batch.into_query()))
            .exec(db)
            .await?;
        deleted_access += deleted.rows_affected;
        if deleted.rows_affected < PURGE_BATCH_SIZE {
            break;
        }
    }

    let mut deleted_security = 0_u64;
    loop {
        let mut batch = security_event::Entity::find()
            .select_only()
            .column(security_event::Column::Id)
            .filter(security_event::Column::Timestamp.lt(security_cutoff))
            .limit(PURGE_BATCH_SIZE);
        if let Some(id) = site_id {
            batch = batch.filter(security_event::Column::SiteId.eq(id));
        }
        let deleted = security_event::Entity::delete_many()
            .filter(security_event::Column::Id.in_subquery(batch.into_query()))
            .exec(db)
            .await?;
        deleted_security += deleted.rows_affected;
        if deleted.rows_affected < PURGE_BATCH_SIZE {
            break;
        }
    }

    Ok(PurgeOutcome {
        deleted_security_events: deleted_security,
        deleted_access_logs: deleted_access,
        access_cutoff,
        security_cutoff,
    })
}

/// `DELETE /api/v1/logs/purge` — retention sweep, administrators only.
async fn purge(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<PurgeQuery>,
) -> Result<Json<PurgeResult>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let days = query.older_than_days;
    if !(1..=3650).contains(&days) {
        return Err(ApiError::BadRequest(
            "older_than_days must be between 1 and 3650".to_string(),
        ));
    }
    let cutoff = Utc::now() - Duration::days(days);

    let site_filter = match non_empty(&query.site_id) {
        Some(raw) => Some(parse_uuid(&raw, "site id")?),
        None => None,
    };

    let outcome = purge_logs(&state.db, days, days, site_filter).await?;

    // Control plane log rows carry no site, so a site-scoped sweep leaves
    // them alone.
    let deleted_control = if site_filter.is_none() {
        crate::api::self_protection::purge_access_logs(&state.db, days)
            .await
            .map_err(ApiError::from)?
    } else {
        0
    };

    tracing::info!(
        cutoff = %cutoff,
        site_id = ?site_filter,
        security_events = outcome.deleted_security_events,
        access_logs = outcome.deleted_access_logs,
        control_plane_logs = deleted_control,
        requested_by = %current.id,
        "log retention sweep completed"
    );

    Ok(Json(PurgeResult {
        deleted_security_events: outcome.deleted_security_events,
        deleted_access_logs: outcome.deleted_access_logs,
        deleted_control_plane_logs: deleted_control,
        cutoff,
    }))
}

/// How long after boot the first scheduled sweep runs.
const SWEEP_STARTUP_DELAY: std::time::Duration =
    std::time::Duration::from_secs(60);
/// Gap between scheduled sweeps.
const SWEEP_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(6 * 60 * 60);

/// Launches the background retention sweeper.
///
/// The first sweep is delayed past startup instead of firing immediately, and
/// later sweeps run every six hours. Each one reads the settings row and
/// deletes rows older than the two configured windows, so changing the
/// settings takes effect without a restart. Deletion is idempotent, which is
/// why a sweep at any time is safe to run alongside the manual purge endpoint.
pub fn start_retention_scheduler(
    state: AppState,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(SWEEP_STARTUP_DELAY).await;
        loop {
            if let Err(err) = run_retention_sweep(&state).await {
                tracing::warn!(
                    error = %err,
                    "scheduled log retention sweep failed"
                );
            }
            tokio::time::sleep(SWEEP_INTERVAL).await;
        }
    })
}

/// One scheduled sweep: read the settings row, then delete what aged out.
async fn run_retention_sweep(state: &AppState) -> Result<(), ApiError> {
    let settings = crate::api::log_retention::load(&state.db).await?;
    let outcome = purge_logs(
        &state.db,
        i64::from(settings.access_log_retention_days),
        i64::from(settings.security_event_retention_days),
        None,
    )
    .await?;

    // The control plane's own access log keeps its own window.
    let protection = crate::api::self_protection::load_settings(&state.db)
        .await
        .map_err(ApiError::from)?;
    let deleted_control = crate::api::self_protection::purge_access_logs(
        &state.db,
        i64::from(protection.access_log_retention_days),
    )
    .await
    .map_err(ApiError::from)?;

    if outcome.deleted_access_logs == 0
        && outcome.deleted_security_events == 0
        && deleted_control == 0
    {
        tracing::debug!(
            "scheduled log retention sweep found nothing to delete"
        );
        return Ok(());
    }
    tracing::info!(
        access_logs = outcome.deleted_access_logs,
        security_events = outcome.deleted_security_events,
        control_plane_logs = deleted_control,
        access_days = settings.access_log_retention_days,
        security_days = settings.security_event_retention_days,
        "scheduled log retention sweep completed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_window_is_the_last_day() {
        let (from, to) = resolve_window(&None, &None).unwrap();
        let span = to - from;
        assert!(span >= Duration::hours(DEFAULT_WINDOW_HOURS - 1));
        assert!(span <= Duration::hours(DEFAULT_WINDOW_HOURS + 1));
    }

    #[test]
    fn explicit_windows_are_validated() {
        let from = "2024-01-01T00:00:00Z".to_string();
        let to = "2024-01-02T00:00:00Z".to_string();
        assert!(resolve_window(&Some(from.clone()), &Some(to.clone())).is_ok());
        // Reversed range.
        assert!(resolve_window(&Some(to.clone()), &Some(from.clone())).is_err());
        // Window far beyond the ceiling.
        assert!(resolve_window(
            &Some("1970-01-01T00:00:00Z".to_string()),
            &Some(to)
        )
        .is_err());
        // Unparsable input.
        assert!(resolve_window(&Some("yesterday".to_string()), &None).is_err());
    }

    #[test]
    fn retention_defaults_are_sane() {
        assert_eq!(default_retention_days(), 30);
    }

    #[test]
    fn unassigned_rejects_explicit_site() {
        let site = Some("01936b1a-0000-7000-8000-000000000000".to_string());
        assert!(check_unassigned(Some(true), &site).is_err());
        // The flag off (absent or false) never conflicts with a site filter.
        assert!(!check_unassigned(Some(false), &site).unwrap());
        assert!(!check_unassigned(None, &site).unwrap());
        // On its own, `unassigned` is valid and meaningful.
        assert!(check_unassigned(Some(true), &None).unwrap());
        assert!(!check_unassigned(None, &None).unwrap());
    }

    #[test]
    fn multi_value_filters_split_on_commas() {
        assert_eq!(
            vec!["10.0.0.1", "10.0.0.2"],
            split_multi("10.0.0.1, 10.0.0.2")
        );
        assert_eq!(vec!["xss"], split_multi(" xss "));
        // Blank parts are dropped; an all-blank value has none left.
        assert!(split_multi(" , ").is_empty());
    }

    #[test]
    fn wildcards_become_like_patterns() {
        assert_eq!(None, like_pattern("exact"));
        assert_eq!(Some("10.0.%"), like_pattern("10.0.*").as_deref());
        // LIKE metacharacters in user input stay literal.
        assert_eq!(Some(r"100\%\_x%"), like_pattern("100%_x*").as_deref());
        assert_eq!(r"50\%", escape_like("50%"));
        assert_eq!(r"%a\_b%", format!("%{}%", escape_like("a_b")));
    }
}
