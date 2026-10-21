//! Aggregation endpoints backing the dashboard charts: traffic over time, the
//! rules that fire most often, the loudest client IPs and the hottest paths.
//!
//! The queries are hand-written SQL because sea-query's builder cannot express
//! `FILTER (WHERE …)` aggregates or `date_trunc` bucketing without giving up
//! most of the readability.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::{DateTime, Duration, Utc};
use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, TryGetable,
    Value,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{
    load_site_read, non_empty, parse_optional_datetime, parse_uuid, query_all,
};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::site;

/// Default look-back window for every analytics endpoint.
const DEFAULT_WINDOW_HOURS: i64 = 24;
/// Analytics scans more rows than the log endpoints, so the ceiling is tighter.
const MAX_WINDOW_DAYS: i64 = 31;
/// Upper bound for the `limit` query parameter.
const MAX_LIMIT: i64 = 100;
/// Buckets returned by `requests-over-time` are capped so that a year-long
/// minute-granularity request cannot blow up the response.
const MAX_BUCKETS: i64 = 8 * 1024;

/// `date_trunc` fields the API accepts.
const INTERVALS: [&str; 4] = ["minute", "hour", "day", "week"];

/// Sites tracked by the per-site traffic chart.
const TOP_SITES_LIMIT: i64 = 8;
/// Upper bound on the site rows `GET /analytics/sites` loads for the
/// admin global view. The control plane realistically serves far fewer
/// sites; the cap turns an unbounded `site::find().all()` into a bounded
/// query (newest sites first) and the response's `truncated` flag says
/// the list was cut.
const SITES_OVERVIEW_CAP: usize = 500;

/// Fixed bucket widths (seconds) accepted by `/analytics/traffic`.
const TRAFFIC_STEPS: [i64; 8] = [5, 10, 30, 60, 300, 900, 3600, 86_400];

#[derive(Debug, Deserialize)]
pub struct RangeQuery {
    pub site_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    /// `minute`, `hour` (default), `day` or `week`.
    #[serde(default = "default_interval")]
    pub interval: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_interval() -> String {
    "hour".to_string()
}

fn default_limit() -> i64 {
    10
}

#[derive(Debug, Deserialize)]
pub struct TrafficQuery {
    pub site_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    /// Bucket width in seconds; one of [`TRAFFIC_STEPS`] (default 5).
    #[serde(default = "default_traffic_step")]
    pub step: i64,
}

fn default_traffic_step() -> i64 {
    5
}

/// Resolved query parameters shared by every endpoint below.
struct Resolved {
    /// `None` means "every site the caller may see" (administrators only).
    site_id: Option<Uuid>,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    interval: String,
    limit: i64,
}

impl Resolved {
    /// Builds the `WHERE` fragment plus its bound values.
    fn filter(&self, table: &str) -> (String, Vec<Value>) {
        let mut sql =
            format!("{table}.timestamp >= $1 AND {table}.timestamp < $2");
        let mut values: Vec<Value> = vec![self.from.into(), self.to.into()];
        if let Some(id) = self.site_id {
            sql.push_str(" AND site_id = $3");
            values.push(id.into());
        }
        (sql, values)
    }

    /// Index of the next free `$n` placeholder.
    fn next_placeholder(&self) -> usize {
        if self.site_id.is_some() {
            4
        } else {
            3
        }
    }

    /// The row cap, re-clamped and widened to `u64` here rather than at the
    /// call site so no caller can hand the query builder an unclamped or
    /// differently-typed value. `resolve` already clamps; this is the single
    /// place a `LIMIT` value can come from.
    fn bound_limit(&self) -> u64 {
        u64::try_from(self.limit.clamp(1, MAX_LIMIT)).unwrap_or(1)
    }
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub site_id: Option<Uuid>,
    pub requests: i64,
    pub unique_ips: i64,
    pub cache_hits: i64,
    pub cache_hit_rate: f64,
    /// Outbound bytes served straight from the edge cache
    /// (`SUM(response_size) FILTER (WHERE cache_status = 'hit')`) — the
    /// traffic the origin did not have to produce within the window.
    pub cache_saved_bytes: i64,
    pub avg_latency_ms: i64,
    pub max_latency_ms: i64,
    pub client_errors: i64,
    pub server_errors: i64,
    pub security_events: i64,
    pub blocked_requests: i64,
    pub distinct_attackers: i64,
    pub rules_triggered: i64,
}

#[derive(Debug, Serialize)]
pub struct TimeBucket {
    pub bucket: DateTime<Utc>,
    pub requests: i64,
    pub cache_hits: i64,
    pub cache_saved_bytes: i64,
    pub client_errors: i64,
    pub server_errors: i64,
    pub avg_latency_ms: i64,
    pub blocked: i64,
}

#[derive(Debug, Serialize)]
pub struct TopRule {
    pub rule_id: String,
    pub rule_name: String,
    pub action: String,
    pub hits: i64,
    pub unique_ips: i64,
}

#[derive(Debug, Serialize)]
pub struct TopIp {
    pub client_ip: String,
    pub country_code: Option<String>,
    pub requests: i64,
    pub blocked: i64,
    /// Site the IP most recently requested (the natural target for a
    /// one-click block/challenge from the dashboard's cross-site view);
    /// `None` when the log rows carry no resolvable site.
    pub top_site_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct TopPath {
    pub path: String,
    pub requests: i64,
    pub cache_hits: i64,
    pub avg_latency_ms: i64,
}

#[derive(Debug, Serialize)]
pub struct StatusCodeCount {
    pub status_code: i32,
    pub requests: i64,
}

#[derive(Debug, Serialize)]
pub struct SiteOverview {
    pub site_id: Uuid,
    pub name: String,
    pub domain: String,
    pub status: String,
    pub plan: String,
    pub requests: i64,
    pub blocked: i64,
}

#[derive(Debug, Serialize)]
pub struct SiteTrafficBucket {
    pub bucket: DateTime<Utc>,
    pub site_id: Uuid,
    pub site_domain: String,
    pub site_name: String,
    pub requests: i64,
}

#[derive(Debug, Serialize)]
pub struct TrafficBucket {
    pub bucket: DateTime<Utc>,
    pub bytes: i64,
}

/// Egress bandwidth for one window, bucketed at a fixed width. Only response
/// bytes sent to clients are counted — origin-pull traffic is never included.
#[derive(Debug, Serialize)]
pub struct Traffic {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub site_id: Option<Uuid>,
    pub step_seconds: i64,
    /// Sum of `bytes` across the whole window, i.e. the total egress.
    pub total_bytes: i64,
    pub buckets: Vec<TrafficBucket>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/analytics/summary", get(summary))
        .route("/analytics/requests-over-time", get(requests_over_time))
        .route("/analytics/traffic", get(traffic))
        .route("/analytics/sites-over-time", get(sites_over_time))
        .route("/analytics/top-rules", get(top_rules))
        .route("/analytics/top-ips", get(top_ips))
        .route("/analytics/top-paths", get(top_paths))
        .route("/analytics/status-codes", get(status_codes))
        .route("/analytics/sites", get(sites_overview))
        .route("/analytics/ai-crawlers", get(ai_crawlers))
}

/// One AI crawler family in the traffic panel.
#[derive(Debug, Serialize)]
pub struct AiCrawlerRow {
    pub bot_id: String,
    pub name: String,
    pub category: String,
    pub requests: i64,
    pub blocked: i64,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Response of `/analytics/ai-crawlers`.
#[derive(Debug, Serialize)]
pub struct AiCrawlerOverview {
    pub requests: i64,
    pub blocked: i64,
    /// share = AI requests / all requests in the window, 0.0–1.0.
    pub share: f64,
    pub families: i64,
    pub rows: Vec<AiCrawlerRow>,
}

/// `GET /api/v1/analytics/ai-crawlers`
///
/// Aggregates the AI crawler families the control plane knows by matching the
/// raw user agent recorded in `access_logs`. The predicates are constants
/// from the catalogue (never user input), and the site+time index still
/// bounds the scan.
async fn ai_crawlers(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<AiCrawlerOverview>, ApiError> {
    let resolved = resolve(&state, &current, &query).await?;

    let (case_sql, filter_sql) = ai_crawler_predicates();
    let (where_sql, mut values) = resolved.filter("access_logs");
    let limit_placeholder = resolved.next_placeholder();
    values.push(Value::from(resolved.limit));

    let sql = format!(
        "SELECT {case_sql} AS bot_id, \
                COUNT(*) AS requests, \
                MAX(timestamp) AS last_seen \
         FROM access_logs WHERE {where_sql} AND ({filter_sql}) \
         GROUP BY bot_id ORDER BY requests DESC LIMIT ${limit_placeholder}"
    );
    let rows = query_all(&state.db, &sql, values).await?;

    // Blocked counts come from the AI bot events the data plane emits, not
    // from every 403/429 an AI user agent happened to receive: an origin's
    // own 403 is not our block, and counting it would inflate the panel.
    let (event_where, event_values) = resolved.filter("security_events");
    let blocked_sql = format!(
        "SELECT rule_name, COUNT(*) AS blocked FROM security_events \
         WHERE {event_where} AND event_type = 'ai_bot' GROUP BY rule_name"
    );
    let blocked_rows = query_all(&state.db, &blocked_sql, event_values).await?;
    let mut blocked_by_bot: HashMap<String, i64> = HashMap::new();
    for row in &blocked_rows {
        let rule_name = get_value::<String>(row, "rule_name");
        // The data plane labels the event `AI crawler: <family id>`.
        let bot_id = rule_name
            .strip_prefix("AI crawler: ")
            .unwrap_or(&rule_name)
            .to_string();
        let count = get_value::<i64>(row, "blocked");
        *blocked_by_bot.entry(bot_id).or_insert(0) += count;
    }

    let mut total = 0i64;
    let mut blocked = 0i64;
    let mut by_family: Vec<AiCrawlerRow> = rows
        .iter()
        .map(|row| {
            let bot_id = get_value::<String>(row, "bot_id");
            let bot = crate::api::ai_crawl::find_bot(&bot_id);
            let requests = get_value::<i64>(row, "requests");
            let family_blocked =
                blocked_by_bot.get(&bot_id).copied().unwrap_or(0);
            total += requests;
            blocked += family_blocked;
            AiCrawlerRow {
                name: bot
                    .map_or_else(|| bot_id.clone(), |bot| bot.name.to_string()),
                category: bot.map_or_else(
                    || "other".to_string(),
                    |bot| bot.category.to_string(),
                ),
                bot_id,
                requests,
                blocked: family_blocked,
                last_seen: try_get::<DateTime<Utc>>(row, "last_seen"),
            }
        })
        .collect();

    // Share against every request in the same window, not just the matched
    // rows: "AI crawlers are 3% of traffic" is the number an operator acts on.
    let (all_where, all_values) = resolved.filter("access_logs");
    let all_sql = format!(
        "SELECT COUNT(*) AS requests FROM access_logs WHERE {all_where}"
    );
    let all_rows = query_all(&state.db, &all_sql, all_values).await?;
    let window_requests = all_rows
        .first()
        .map(|row| get_value::<i64>(row, "requests"))
        .unwrap_or(0);

    by_family.shrink_to_fit();
    Ok(Json(AiCrawlerOverview {
        requests: total,
        blocked,
        share: if window_requests == 0 {
            0.0
        } else {
            total as f64 / window_requests as f64
        },
        families: by_family.len() as i64,
        rows: by_family,
    }))
}

/// Builds the `CASE` that names a family and the `WHERE` that restricts the
/// scan to AI user agents.
fn ai_crawler_predicates() -> (String, String) {
    let mut case_sql = String::from("CASE");
    let mut filter_sql = String::new();
    for bot in crate::api::ai_crawl::AI_BOTS {
        for pattern in bot.ua_substrings {
            case_sql.push_str(&format!(
                " WHEN user_agent ILIKE '%{pattern}%' THEN '{}'",
                bot.id
            ));
            if !filter_sql.is_empty() {
                filter_sql.push_str(" OR ");
            }
            filter_sql.push_str(&format!("user_agent ILIKE '%{pattern}%'"));
        }
    }
    case_sql.push_str(" ELSE 'other' END");
    (case_sql, filter_sql)
}

/// Validates the incoming range and resolves tenant visibility.
async fn resolve(
    state: &AppState,
    current: &AuthUser,
    query: &RangeQuery,
) -> Result<Resolved, ApiError> {
    let site_id = match non_empty(&query.site_id) {
        Some(raw) => {
            let id = parse_uuid(&raw, "site id")?;
            // `load_site_read` returns 404 for sites the caller may not see.
            load_site_read(&state.db, id, current).await?;
            Some(id)
        },
        None if current.is_admin() => None,
        None => {
            // Non-admins may still see everything they own; pick the single site
            // when they only have one, otherwise require the parameter.
            let owned = site::Entity::find()
                .filter(site::Column::UserId.eq(current.id))
                .all(&state.db)
                .await?;
            match owned.len() {
                0 => {
                    return Err(ApiError::NotFound(
                        "this account does not own any site".to_string(),
                    ))
                }
                1 => Some(owned[0].id),
                _ => {
                    return Err(ApiError::BadRequest(
                        "site_id is required when the account owns more than one site".to_string(),
                    ))
                }
            }
        },
    };
    resolve_range(query, site_id)
}

/// Validates from/to/interval/limit. Site visibility is decided by the caller
/// so endpoints that aggregate across sites (rather than requiring one) can
/// reuse the same window checks.
fn resolve_range(
    query: &RangeQuery,
    site_id: Option<Uuid>,
) -> Result<Resolved, ApiError> {
    let to = match parse_optional_datetime(&query.to, "to")? {
        Some(instant) => instant,
        None => Utc::now(),
    };
    let from = match parse_optional_datetime(&query.from, "from")? {
        Some(instant) => instant,
        None => to - Duration::hours(DEFAULT_WINDOW_HOURS),
    };
    if from >= to {
        return Err(ApiError::BadRequest(
            "'from' must be earlier than 'to'".to_string(),
        ));
    }
    if from < to - Duration::days(MAX_WINDOW_DAYS) {
        return Err(ApiError::BadRequest(format!(
            "the analytics window may not exceed {MAX_WINDOW_DAYS} days"
        )));
    }

    let interval = query.interval.trim().to_lowercase();
    if !INTERVALS.contains(&interval.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "interval must be one of {}",
            INTERVALS.join(", ")
        )));
    }

    let limit = query.limit.clamp(1, MAX_LIMIT);

    Ok(Resolved {
        site_id,
        from,
        to,
        interval,
        limit,
    })
}

/// Seconds covered by one `date_trunc` bucket.
fn bucket_seconds(interval: &str) -> i64 {
    match interval {
        "minute" => 60,
        "hour" => 3_600,
        "day" => 86_400,
        _ => 604_800, // week
    }
}

/// `GET /api/v1/analytics/summary`
async fn summary(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<Summary>, ApiError> {
    let resolved = resolve(&state, &current, &query).await?;

    let (access_where, access_values) = resolved.filter("access_logs");
    let access_sql = format!(
        "SELECT COUNT(*) AS requests, \
                COUNT(DISTINCT client_ip) AS unique_ips, \
                COUNT(*) FILTER (WHERE cache_status = 'hit') AS cache_hits, \
                COUNT(*) FILTER (WHERE cache_status IN \
                    ('hit', 'miss', 'expired', 'stale', 'stale-updating', \
                     'revalidated', 'revalidated-nocache')) AS cache_participating, \
                COALESCE(SUM(response_size) FILTER (WHERE cache_status = 'hit'), 0)::BIGINT AS cache_saved_bytes, \
                COALESCE(AVG(total_latency_ms), 0)::BIGINT AS avg_latency_ms, \
                COALESCE(MAX(total_latency_ms), 0)::BIGINT AS max_latency_ms, \
                COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS client_errors, \
                COUNT(*) FILTER (WHERE status_code >= 500) AS server_errors \
         FROM access_logs WHERE {access_where}"
    );
    let access = query_all(&state.db, &access_sql, access_values)
        .await?
        .into_iter()
        .next();

    let (event_where, event_values) = resolved.filter("security_events");
    let event_sql = format!(
        "SELECT COUNT(*) AS security_events, \
                COUNT(*) FILTER (WHERE action = 'block') AS blocked_requests, \
                COUNT(DISTINCT client_ip) AS distinct_attackers, \
                COUNT(DISTINCT rule_id) AS rules_triggered \
         FROM security_events WHERE {event_where}"
    );
    let events = query_all(&state.db, &event_sql, event_values)
        .await?
        .into_iter()
        .next();

    let requests: i64 = read(&access, "requests");
    let cache_hits: i64 = read(&access, "cache_hits");
    // Hit rate over cache-participating requests only: traffic that never
    // consulted the cache (other sites, scanner noise, plugin answers,
    // cache disabled) would otherwise dilute the ratio toward zero.
    let cache_participating: i64 = read(&access, "cache_participating");
    let cache_hit_rate = if cache_participating > 0 {
        cache_hits as f64 / cache_participating as f64
    } else {
        0.0
    };

    Ok(Json(Summary {
        from: resolved.from,
        to: resolved.to,
        site_id: resolved.site_id,
        requests,
        unique_ips: read(&access, "unique_ips"),
        cache_hits,
        cache_hit_rate,
        cache_saved_bytes: read(&access, "cache_saved_bytes"),
        avg_latency_ms: read(&access, "avg_latency_ms"),
        max_latency_ms: read(&access, "max_latency_ms"),
        client_errors: read(&access, "client_errors"),
        server_errors: read(&access, "server_errors"),
        security_events: read(&events, "security_events"),
        blocked_requests: read(&events, "blocked_requests"),
        distinct_attackers: read(&events, "distinct_attackers"),
        rules_triggered: read(&events, "rules_triggered"),
    }))
}

/// `GET /api/v1/analytics/requests-over-time`
async fn requests_over_time(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<Vec<TimeBucket>>, ApiError> {
    let resolved = resolve(&state, &current, &query).await?;

    // Reject ranges that would produce an absurd number of buckets before
    // touching the database.
    let span = (resolved.to - resolved.from).num_seconds().max(1);
    if span / bucket_seconds(&resolved.interval) > MAX_BUCKETS {
        return Err(ApiError::BadRequest(format!(
            "the requested range would produce too many {0} buckets; widen the interval",
            resolved.interval
        )));
    }

    // The interval is validated against a fixed whitelist above, so it is safe
    // to inline; binding it would make PostgreSQL infer `unknown` for the type.
    let interval = resolved.interval.clone();
    let (where_sql, values) = resolved.filter("access_logs");
    let sql = format!(
        "SELECT date_trunc('{interval}', timestamp) AS bucket, \
                COUNT(*) AS requests, \
                COUNT(*) FILTER (WHERE cache_status = 'hit') AS cache_hits, \
                COALESCE(SUM(response_size) FILTER (WHERE cache_status = 'hit'), 0)::BIGINT AS cache_saved_bytes, \
                COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS client_errors, \
                COUNT(*) FILTER (WHERE status_code >= 500) AS server_errors, \
                COALESCE(AVG(total_latency_ms), 0)::BIGINT AS avg_latency_ms \
         FROM access_logs WHERE {where_sql} \
         GROUP BY bucket ORDER BY bucket ASC"
    );

    let rows = query_all(&state.db, &sql, values).await?;
    let mut buckets: Vec<TimeBucket> = Vec::with_capacity(rows.len());
    for row in &rows {
        buckets.push(TimeBucket {
            bucket: try_get::<DateTime<Utc>>(row, "bucket")
                .unwrap_or_else(Utc::now),
            requests: get_value::<i64>(row, "requests"),
            cache_hits: get_value::<i64>(row, "cache_hits"),
            cache_saved_bytes: get_value::<i64>(row, "cache_saved_bytes"),
            client_errors: get_value::<i64>(row, "client_errors"),
            server_errors: get_value::<i64>(row, "server_errors"),
            avg_latency_ms: get_value::<i64>(row, "avg_latency_ms"),
            blocked: 0,
        });
    }

    // Fold the blocked counts in from the security events table so the chart can
    // overlay attacks on traffic with a single request.
    let (event_where, event_values) = resolved.filter("security_events");
    let event_sql = format!(
        "SELECT date_trunc('{interval}', timestamp) AS bucket, COUNT(*) AS blocked \
         FROM security_events \
         WHERE {event_where} AND action <> 'allow' \
         GROUP BY bucket ORDER BY bucket ASC"
    );
    if let Ok(event_rows) = query_all(&state.db, &event_sql, event_values).await
    {
        for row in &event_rows {
            let Some(bucket) = try_get::<DateTime<Utc>>(row, "bucket") else {
                continue;
            };
            let blocked = get_value::<i64>(row, "blocked");
            if let Some(target) =
                buckets.iter_mut().find(|item| item.bucket == bucket)
            {
                target.blocked = blocked;
            }
        }
    }

    Ok(Json(buckets))
}

/// `GET /api/v1/analytics/traffic` — egress bytes per fixed-width bucket.
///
/// `response_size` records the bytes streamed to the client, so summing it
/// measures outbound traffic only; upstream (origin-pull) bytes are never
/// recorded and cannot leak into the totals.
async fn traffic(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<TrafficQuery>,
) -> Result<Json<Traffic>, ApiError> {
    // Site visibility and the from/to window are validated by `resolve`; the
    // interval/limit fields it also fills in do not apply to this endpoint.
    let range = RangeQuery {
        site_id: query.site_id,
        from: query.from,
        to: query.to,
        interval: default_interval(),
        limit: default_limit(),
    };
    let resolved = resolve(&state, &current, &range).await?;

    if !TRAFFIC_STEPS.contains(&query.step) {
        return Err(ApiError::BadRequest(format!(
            "step must be one of {}",
            TRAFFIC_STEPS.map(|s| s.to_string()).join(", ")
        )));
    }
    let span = (resolved.to - resolved.from).num_seconds().max(1);
    if span / query.step > MAX_BUCKETS {
        return Err(ApiError::BadRequest(format!(
            "the requested range would produce too many {0}s buckets; widen the step",
            query.step
        )));
    }

    // `step` comes from the validated whitelist above, so inlining it is safe.
    let (where_sql, values) = resolved.filter("access_logs");
    let sql = format!(
        "SELECT to_timestamp(floor(extract(epoch FROM timestamp) / {0}) * {0}) AS bucket, \
                COALESCE(SUM(response_size), 0)::BIGINT AS bytes \
         FROM access_logs WHERE {where_sql} \
         GROUP BY bucket ORDER BY bucket ASC",
        query.step
    );

    let rows = query_all(&state.db, &sql, values).await?;
    let mut total_bytes: i64 = 0;
    let mut buckets = Vec::with_capacity(rows.len());
    for row in &rows {
        let bytes = get_value::<i64>(row, "bytes");
        total_bytes += bytes;
        buckets.push(TrafficBucket {
            bucket: try_get::<DateTime<Utc>>(row, "bucket")
                .unwrap_or_else(Utc::now),
            bytes,
        });
    }

    Ok(Json(Traffic {
        from: resolved.from,
        to: resolved.to,
        site_id: resolved.site_id,
        step_seconds: query.step,
        total_bytes,
        buckets,
    }))
}

/// `GET /api/v1/analytics/sites-over-time` — request volume over time for the
/// busiest sites, one series per site, for the dashboard's multi-line chart.
///
/// Unlike the aggregate endpoints this one stays meaningful without a site
/// filter even for accounts owning several sites: no filter scopes to every
/// site the caller may see, restricted to the top [`TOP_SITES_LIMIT`] sites by
/// in-window traffic so the chart stays readable.
async fn sites_over_time(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<Vec<SiteTrafficBucket>>, ApiError> {
    let site_id = match non_empty(&query.site_id) {
        Some(raw) => {
            let id = parse_uuid(&raw, "site id")?;
            load_site_read(&state.db, id, &current).await?;
            Some(id)
        },
        None => None,
    };
    let resolved = resolve_range(&query, site_id)?;

    let span = (resolved.to - resolved.from).num_seconds().max(1);
    if span / bucket_seconds(&resolved.interval) > MAX_BUCKETS {
        return Err(ApiError::BadRequest(format!(
            "the requested range would produce too many {0} buckets; widen the interval",
            resolved.interval
        )));
    }

    let (mut where_sql, mut where_values) = resolved.filter("a");
    if resolved.site_id.is_none() && !current.is_admin() {
        // Non-admins only see their own sites.
        let user_placeholder = where_values.len() + 1;
        where_sql.push_str(&format!(" AND s.user_id = ${user_placeholder}"));
        where_values.push(current.id.into());
    }

    // Pass 1: the top sites by total in-window traffic.
    let limit_placeholder = where_values.len() + 1;
    let mut values = where_values.clone();
    values.push(TOP_SITES_LIMIT.into());
    let top_sql = format!(
        "SELECT a.site_id, s.domain AS site_domain, s.name AS site_name \
         FROM access_logs a JOIN sites s ON s.id = a.site_id \
         WHERE {where_sql} \
         GROUP BY a.site_id, s.domain, s.name \
         ORDER BY COUNT(*) DESC, s.domain ASC \
         LIMIT ${limit_placeholder}"
    );
    let top_rows = query_all(&state.db, &top_sql, values).await?;
    let top: Vec<(Uuid, String, String)> = top_rows
        .iter()
        .map(|row| {
            (
                get_value::<Uuid>(row, "site_id"),
                get_value::<String>(row, "site_domain"),
                get_value::<String>(row, "site_name"),
            )
        })
        .collect();
    if top.is_empty() {
        return Ok(Json(Vec::new()));
    }

    // Pass 2: the bucketed series for those sites only.
    let interval = resolved.interval.clone();
    let where_count = where_values.len();
    let mut in_clause = String::new();
    for index in 0..top.len() {
        if index > 0 {
            in_clause.push_str(", ");
        }
        in_clause.push_str(&format!("${}", where_count + index + 1));
    }
    let sql = format!(
        "SELECT date_trunc('{interval}', a.timestamp) AS bucket, \
                a.site_id, s.domain AS site_domain, s.name AS site_name, \
                COUNT(*) AS requests \
         FROM access_logs a JOIN sites s ON s.id = a.site_id \
         WHERE {where_sql} AND a.site_id IN ({in_clause}) \
         GROUP BY bucket, a.site_id, s.domain, s.name \
         ORDER BY bucket ASC"
    );
    let mut values = where_values;
    for (id, _, _) in &top {
        values.push((*id).into());
    }

    let rows = query_all(&state.db, &sql, values).await?;
    Ok(Json(
        rows.iter()
            .map(|row| SiteTrafficBucket {
                bucket: try_get::<DateTime<Utc>>(row, "bucket")
                    .unwrap_or_else(Utc::now),
                site_id: get_value::<Uuid>(row, "site_id"),
                site_domain: get_value::<String>(row, "site_domain"),
                site_name: get_value::<String>(row, "site_name"),
                requests: get_value::<i64>(row, "requests"),
            })
            .collect(),
    ))
}

/// Statement for `top-rules`.
///
/// D19: the row cap is a *bound parameter* (`LIMIT $n`), never interpolated
/// into the SQL text — `sea_orm::Statement::from_sql_and_values` (via
/// [`query_all`]) sends it out of band, so no code path can turn the limit
/// into SQL. `resolved.bound_limit()` is the only source of the value and it
/// clamps again, keeping the "value came from a query string" precondition
/// local to one function instead of relying on every caller's `format!`.
fn top_rules_sql(resolved: &Resolved) -> (String, Vec<Value>) {
    let (where_sql, mut values) = resolved.filter("security_events");
    let placeholder = resolved.next_placeholder();
    values.push(Value::from(resolved.bound_limit()));
    let sql = format!(
        "SELECT COALESCE(rule_id, 'unknown') AS rule_id, \
                COALESCE(rule_name, '') AS rule_name, \
                action, \
                COUNT(*) AS hits, \
                COUNT(DISTINCT client_ip) AS unique_ips \
         FROM security_events WHERE {where_sql} \
         GROUP BY rule_id, rule_name, action \
         ORDER BY hits DESC, rule_id ASC \
         LIMIT ${placeholder}"
    );
    (sql, values)
}

/// Statement for `top-paths`; see [`top_rules_sql`] for the bound-limit rule.
fn top_paths_sql(resolved: &Resolved) -> (String, Vec<Value>) {
    let (where_sql, mut values) = resolved.filter("access_logs");
    let placeholder = resolved.next_placeholder();
    values.push(Value::from(resolved.bound_limit()));
    let sql = format!(
        "SELECT COALESCE(path, '/') AS path, \
                COUNT(*) AS requests, \
                COUNT(*) FILTER (WHERE cache_status = 'hit') AS cache_hits, \
                COALESCE(AVG(total_latency_ms), 0)::BIGINT AS avg_latency_ms \
         FROM access_logs WHERE {where_sql} \
         GROUP BY path ORDER BY requests DESC LIMIT ${placeholder}"
    );
    (sql, values)
}

/// `GET /api/v1/analytics/top-rules`
async fn top_rules(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<Vec<TopRule>>, ApiError> {
    let resolved = resolve(&state, &current, &query).await?;
    let (sql, values) = top_rules_sql(&resolved);

    let rows = query_all(&state.db, &sql, values).await?;
    Ok(Json(
        rows.iter()
            .map(|row| TopRule {
                rule_id: get_value::<String>(row, "rule_id"),
                rule_name: get_value::<String>(row, "rule_name"),
                action: get_value::<String>(row, "action"),
                hits: get_value::<i64>(row, "hits"),
                unique_ips: get_value::<i64>(row, "unique_ips"),
            })
            .collect(),
    ))
}

/// `GET /api/v1/analytics/top-ips`
async fn top_ips(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<Vec<TopIp>>, ApiError> {
    let resolved = resolve(&state, &current, &query).await?;
    let (where_sql, mut values) = resolved.filter("access_logs");
    let limit_placeholder = resolved.next_placeholder();
    values.push(Value::from(resolved.limit));

    let sql = format!(
        "SELECT client_ip, \
                MAX(country_code) AS country_code, \
                COUNT(*) AS requests, \
                COUNT(*) FILTER (WHERE status_code = 403 OR status_code = 429) AS blocked, \
                (ARRAY_AGG(site_id ORDER BY timestamp DESC))[1] AS top_site_id \
         FROM access_logs WHERE {where_sql} \
         GROUP BY client_ip ORDER BY requests DESC LIMIT ${limit_placeholder}"
    );

    let rows = query_all(&state.db, &sql, values).await?;
    Ok(Json(
        rows.iter()
            .map(|row| TopIp {
                client_ip: get_value::<String>(row, "client_ip"),
                country_code: try_get::<String>(row, "country_code"),
                requests: get_value::<i64>(row, "requests"),
                blocked: get_value::<i64>(row, "blocked"),
                top_site_id: try_get::<Uuid>(row, "top_site_id"),
            })
            .collect(),
    ))
}

/// `GET /api/v1/analytics/top-paths`
async fn top_paths(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<Vec<TopPath>>, ApiError> {
    let resolved = resolve(&state, &current, &query).await?;
    let (sql, values) = top_paths_sql(&resolved);

    let rows = query_all(&state.db, &sql, values).await?;
    Ok(Json(
        rows.iter()
            .map(|row| TopPath {
                path: get_value::<String>(row, "path"),
                requests: get_value::<i64>(row, "requests"),
                cache_hits: get_value::<i64>(row, "cache_hits"),
                avg_latency_ms: get_value::<i64>(row, "avg_latency_ms"),
            })
            .collect(),
    ))
}

/// `GET /api/v1/analytics/status-codes`
async fn status_codes(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<Vec<StatusCodeCount>>, ApiError> {
    let resolved = resolve(&state, &current, &query).await?;
    let (where_sql, values) = resolved.filter("access_logs");

    let sql = format!(
        "SELECT status_code, COUNT(*) AS requests \
         FROM access_logs WHERE {where_sql} AND status_code IS NOT NULL \
         GROUP BY status_code ORDER BY status_code ASC"
    );

    let rows = query_all(&state.db, &sql, values).await?;
    Ok(Json(
        rows.iter()
            .map(|row| StatusCodeCount {
                status_code: get_value::<i32>(row, "status_code"),
                requests: get_value::<i64>(row, "requests"),
            })
            .collect(),
    ))
}

/// Response envelope of `GET /api/v1/analytics/sites`.
#[derive(Serialize)]
struct SitesOverviewResponse {
    sites: Vec<SiteOverview>,
    /// True when the global view listed more sites than
    /// [`SITES_OVERVIEW_CAP`]; only the newest sites are included.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    truncated: bool,
}

/// `GET /api/v1/analytics/sites` — traffic per site, used by the home page.
async fn sites_overview(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<SitesOverviewResponse>, ApiError> {
    let resolved = resolve(&state, &current, &query).await?;

    let mut sites = match resolved.site_id {
        Some(id) => vec![load_site_read(&state.db, id, &current).await?],
        None => {
            site::Entity::find()
                .order_by_desc(site::Column::CreatedAt)
                .limit(SITES_OVERVIEW_CAP as u64 + 1)
                .all(&state.db)
                .await?
        },
    };
    // One extra row fetched tells truncation apart from an exact fit
    // without a second (count) query.
    let truncated = sites.len() > SITES_OVERVIEW_CAP;
    if truncated {
        sites.truncate(SITES_OVERVIEW_CAP);
    }

    // Two grouped counts over the window — traffic from the access log and
    // blocked traffic from the security event log — merged onto the site list
    // in one pass, instead of a correlated subquery pair per site.
    let (access_where, access_values) = resolved.filter("access_logs");
    let access_sql = format!(
        "SELECT site_id, COUNT(*) AS requests \
         FROM access_logs WHERE {access_where} AND site_id IS NOT NULL \
         GROUP BY site_id"
    );
    let requests_by_site: std::collections::HashMap<Uuid, i64> =
        query_all(&state.db, &access_sql, access_values)
            .await?
            .into_iter()
            .map(|row| {
                (
                    get_value::<Uuid>(&row, "site_id"),
                    get_value::<i64>(&row, "requests"),
                )
            })
            .collect();

    let (event_where, event_values) = resolved.filter("security_events");
    let event_sql = format!(
        "SELECT site_id, COUNT(*) AS blocked \
         FROM security_events WHERE {event_where} AND action = 'block' \
             AND site_id IS NOT NULL \
         GROUP BY site_id"
    );
    let blocked_by_site: std::collections::HashMap<Uuid, i64> =
        query_all(&state.db, &event_sql, event_values)
            .await?
            .into_iter()
            .map(|row| {
                (
                    get_value::<Uuid>(&row, "site_id"),
                    get_value::<i64>(&row, "blocked"),
                )
            })
            .collect();

    let out = sites
        .into_iter()
        .map(|row| SiteOverview {
            site_id: row.id,
            name: row.name,
            domain: row.domain,
            status: row.status,
            plan: row.plan,
            requests: requests_by_site.get(&row.id).copied().unwrap_or(0),
            blocked: blocked_by_site.get(&row.id).copied().unwrap_or(0),
        })
        .collect();

    Ok(Json(SitesOverviewResponse {
        sites: out,
        truncated,
    }))
}

/// Reads a column, falling back to the type's default when the aggregate
/// produced no row (which happens for an empty window).
fn read<T>(row: &Option<sea_orm::QueryResult>, column: &str) -> T
where
    T: TryGetable + Default,
{
    match row {
        Some(row) => get_value::<T>(row, column),
        None => T::default(),
    }
}

/// Reads a column from a row that is guaranteed to exist.
fn get_value<T>(row: &sea_orm::QueryResult, column: &str) -> T
where
    T: TryGetable + Default,
{
    row.try_get::<T>("", column).unwrap_or_default()
}

/// Same as [`get_value`] but without the default fallback, for nullable columns.
fn try_get<T>(row: &sea_orm::QueryResult, column: &str) -> Option<T>
where
    T: TryGetable,
{
    row.try_get::<T>("", column).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(site_id: Option<Uuid>) -> Resolved {
        Resolved {
            site_id,
            from: Utc::now() - Duration::hours(1),
            to: Utc::now(),
            interval: "hour".to_string(),
            limit: 10,
        }
    }

    #[test]
    fn filter_placeholders_shift_with_the_site_scope() {
        let open = resolved(None);
        let (sql, values) = open.filter("access_logs");
        assert_eq!(
            sql,
            "access_logs.timestamp >= $1 AND access_logs.timestamp < $2"
        );
        assert_eq!(values.len(), 2);
        assert_eq!(open.next_placeholder(), 3);

        let scoped = resolved(Some(Uuid::new_v4()));
        let (sql, values) = scoped.filter("access_logs");
        assert!(sql.ends_with("AND site_id = $3"));
        assert_eq!(values.len(), 3);
        assert_eq!(scoped.next_placeholder(), 4);
    }

    /// D19: the `LIMIT` never appears as a literal in the SQL text — it is
    /// always a `$n` placeholder with the value bound separately. This is the
    /// regression guard for the `format!("LIMIT {limit}")` shape.
    #[test]
    fn top_endpoints_bind_the_limit_instead_of_interpolating_it() {
        for resolved in [resolved(None), resolved(Some(Uuid::new_v4()))] {
            for (sql, values) in
                [top_paths_sql(&resolved), top_rules_sql(&resolved)]
            {
                let placeholder =
                    format!("LIMIT ${}", resolved.next_placeholder());
                assert!(sql.ends_with(&placeholder), "{sql}");
                // No digit may follow `LIMIT `: that would be an interpolated
                // value rather than the bound parameter.
                let after_limit =
                    sql.rsplit("LIMIT ").next().unwrap_or_default();
                assert!(after_limit.starts_with('$'), "unbound LIMIT in {sql}");
                // The bound values cover the WHERE clause plus the cap, and
                // `$n` placeholders are 1-based, so the count of bound
                // values equals the index of the last placeholder.
                assert_eq!(values.len(), resolved.next_placeholder());
            }
        }
    }

    /// D19: the bound cap is clamped even if a caller hands `Resolved` an
    /// out-of-range `limit` directly, so an unbounded scan cannot be
    /// requested through this path.
    #[test]
    fn the_bound_limit_is_always_clamped() {
        let mut out_of_range = resolved(None);
        out_of_range.limit = i64::MAX;
        assert_eq!(out_of_range.bound_limit(), MAX_LIMIT as u64);

        let mut negative = resolved(None);
        negative.limit = -5;
        assert_eq!(negative.bound_limit(), 1);

        let mut zero = resolved(None);
        zero.limit = 0;
        assert_eq!(zero.bound_limit(), 1);

        let mut in_range = resolved(None);
        in_range.limit = 42;
        assert_eq!(in_range.bound_limit(), 42);
    }

    #[test]
    fn intervals_are_whitelisted() {
        assert!(INTERVALS.contains(&"hour"));
        assert!(INTERVALS.contains(&"week"));
        assert!(!INTERVALS.contains(&"1 hour; DROP TABLE users"));
        assert_eq!(default_interval(), "hour");
        assert_eq!(default_limit(), 10);
    }

    #[test]
    fn bucket_seconds_covers_every_interval() {
        for interval in INTERVALS {
            assert!(bucket_seconds(interval) > 0);
        }
        assert_eq!(bucket_seconds("minute"), 60);
        assert_eq!(bucket_seconds("week"), 604_800);
    }

    #[test]
    fn traffic_steps_are_whitelisted() {
        assert!(TRAFFIC_STEPS.contains(&5));
        assert!(TRAFFIC_STEPS.contains(&3_600));
        assert!(!TRAFFIC_STEPS.contains(&7));
        assert!(!TRAFFIC_STEPS.contains(&86_401));
        assert_eq!(default_traffic_step(), 5);
    }
}
