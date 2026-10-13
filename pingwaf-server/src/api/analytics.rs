//! Aggregation endpoints backing the dashboard charts: traffic over time, the
//! rules that fire most often, the loudest client IPs and the hottest paths.
//!
//! The queries are hand-written SQL because sea-query's builder cannot express
//! `FILTER (WHERE …)` aggregates or `date_trunc` bucketing without giving up
//! most of the readability.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::{DateTime, Duration, Utc};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TryGetable, Value};
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

/// `GET /api/v1/analytics/top-rules`
async fn top_rules(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<Vec<TopRule>>, ApiError> {
    let resolved = resolve(&state, &current, &query).await?;
    let (where_sql, mut values) = resolved.filter("security_events");
    let limit_placeholder = resolved.next_placeholder();
    values.push(Value::from(resolved.limit));

    let sql = format!(
        "SELECT COALESCE(rule_id, 'unknown') AS rule_id, \
                COALESCE(rule_name, '') AS rule_name, \
                action, \
                COUNT(*) AS hits, \
                COUNT(DISTINCT client_ip) AS unique_ips \
         FROM security_events WHERE {where_sql} \
         GROUP BY rule_id, rule_name, action \
         ORDER BY hits DESC, rule_id ASC \
         LIMIT ${limit_placeholder}"
    );

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
                COUNT(*) FILTER (WHERE status_code = 403 OR status_code = 429) AS blocked \
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
    let (where_sql, mut values) = resolved.filter("access_logs");
    let limit_placeholder = resolved.next_placeholder();
    values.push(Value::from(resolved.limit));

    let sql = format!(
        "SELECT COALESCE(path, '/') AS path, \
                COUNT(*) AS requests, \
                COUNT(*) FILTER (WHERE cache_status = 'hit') AS cache_hits, \
                COALESCE(AVG(total_latency_ms), 0)::BIGINT AS avg_latency_ms \
         FROM access_logs WHERE {where_sql} \
         GROUP BY path ORDER BY requests DESC LIMIT ${limit_placeholder}"
    );

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

/// `GET /api/v1/analytics/sites` — traffic per site, used by the home page.
async fn sites_overview(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<Vec<SiteOverview>>, ApiError> {
    let resolved = resolve(&state, &current, &query).await?;

    let sites = match resolved.site_id {
        Some(id) => vec![load_site_read(&state.db, id, &current).await?],
        None => site::Entity::find().all(&state.db).await?,
    };

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

    Ok(Json(out))
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
