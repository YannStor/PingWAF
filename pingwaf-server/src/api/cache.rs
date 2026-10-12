//! Edge cache rule management, usage reporting and purging.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use pingwaf_proto::control_plane::server_command::Payload as CommandPayload;
use pingwaf_proto::control_plane::{PurgeCacheCommand, ServerCommand};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::agents::command_type;
use crate::api::common::{
    load_site_read, load_site_write, non_empty, parse_uuid, scope_site, Page,
    Pagination,
};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::cache_status::SiteCacheStatus;
use crate::grpc::config::now_timestamp;
use crate::grpc::notify_config_changed;
use crate::models::{agent, cache_rules, site};

/// TTL bounds: agents refuse nonsensical values, so reject them at the source.
const MAX_TTL_SECONDS: i32 = 30 * 86_400;
const MAX_DISK_QUOTA_MB: i32 = 1_024 * 1024;
/// Cap on one purge request: a huge list is almost always a mistake, and every
/// URL is sent to every edge serving the site.
const MAX_PURGE_URLS: usize = 1000;

fn default_edge_ttl() -> i32 {
    3600
}

fn default_browser_ttl() -> i32 {
    300
}

fn default_disk_quota() -> i32 {
    1024
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub name: String,
    #[serde(default)]
    pub match_expression: String,
    #[serde(default = "default_edge_ttl")]
    pub edge_ttl_seconds: i32,
    #[serde(default = "default_browser_ttl")]
    pub browser_ttl_seconds: i32,
    #[serde(default = "default_disk_quota")]
    pub disk_quota_mb: i32,
    #[serde(default = "default_true")]
    pub cache_eligible: bool,
    #[serde(default = "default_true")]
    pub respect_origin: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub match_expression: Option<String>,
    #[serde(default)]
    pub edge_ttl_seconds: Option<i32>,
    #[serde(default)]
    pub browser_ttl_seconds: Option<i32>,
    #[serde(default)]
    pub disk_quota_mb: Option<i32>,
    #[serde(default)]
    pub cache_eligible: Option<bool>,
    #[serde(default)]
    pub respect_origin: Option<bool>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/cache-rules", get(list).post(create))
        .route(
            "/sites/{site_id}/cache-rules/{rule_id}",
            put(update).delete(remove),
        )
        .route("/sites/{site_id}/cache/defaults", post(seed_defaults))
        .route(
            "/sites/{site_id}/cache-settings",
            get(get_settings).put(update_settings),
        )
        // Flat aliases. The dashboard's cache page spans sites, so it needs
        // endpoints that are not nested under a single one: usage across every
        // site, a purge by site id, and rule CRUD addressed by rule id.
        .route("/cache/status", get(status_all))
        .route("/cache/status/{site_id}", get(status_site))
        .route("/cache/purge", post(purge))
        .route("/cache/rules", get(list_by_query).post(create_by_body))
        .route(
            "/cache/rules/{rule_id}",
            put(update_by_id).delete(remove_by_id),
        )
}

fn validate(
    name: &str,
    edge_ttl: i32,
    browser_ttl: i32,
    disk_quota_mb: i32,
) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 200 {
        return Err(ApiError::BadRequest(
            "name must be 1-200 characters".to_string(),
        ));
    }
    if !(0..=MAX_TTL_SECONDS).contains(&edge_ttl) {
        return Err(ApiError::BadRequest(format!(
            "edge_ttl_seconds must be between 0 and {MAX_TTL_SECONDS}"
        )));
    }
    if !(0..=MAX_TTL_SECONDS).contains(&browser_ttl) {
        return Err(ApiError::BadRequest(format!(
            "browser_ttl_seconds must be between 0 and {MAX_TTL_SECONDS}"
        )));
    }
    if !(0..=MAX_DISK_QUOTA_MB).contains(&disk_quota_mb) {
        return Err(ApiError::BadRequest(format!(
            "disk_quota_mb must be between 0 and {MAX_DISK_QUOTA_MB}"
        )));
    }
    Ok(())
}

/// `GET /api/v1/sites/{site_id}/cache-rules`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<cache_rules::Model>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    let pagination = query.pagination.normalise();

    let paginator = cache_rules::Entity::find()
        .filter(cache_rules::Column::SiteId.eq(id))
        .order_by_asc(cache_rules::Column::Name)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    Ok(Json(Page::new(rows, total, pagination)))
}

/// `POST /api/v1/sites/{site_id}/cache-rules`
async fn create(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreateRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    validate(
        &payload.name,
        payload.edge_ttl_seconds,
        payload.browser_ttl_seconds,
        payload.disk_quota_mb,
    )?;

    let model = cache_rules::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        name: Set(payload.name.trim().to_string()),
        match_expression: Set(payload.match_expression),
        edge_ttl_seconds: Set(payload.edge_ttl_seconds),
        browser_ttl_seconds: Set(payload.browser_ttl_seconds),
        disk_quota_mb: Set(payload.disk_quota_mb),
        cache_eligible: Set(payload.cache_eligible),
        respect_origin: Set(payload.respect_origin),
        enabled: Set(payload.enabled),
        created_at: Set(chrono::Utc::now()),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, rule_id = %model.id, "cache rule created");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// `PUT /api/v1/sites/{site_id}/cache-rules/{rule_id}`
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
    Json(payload): Json<UpdateRequest>,
) -> Result<Json<cache_rules::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "cache rule id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find(&state, id, target).await?;
    let mut active: cache_rules::ActiveModel = row.into();

    if let Some(name) = non_empty(&payload.name) {
        if name.len() > 200 {
            return Err(ApiError::BadRequest(
                "name must be at most 200 characters".to_string(),
            ));
        }
        active.name = Set(name);
    }
    if let Some(expression) = payload.match_expression {
        active.match_expression = Set(expression);
    }
    if let Some(edge_ttl) = payload.edge_ttl_seconds {
        if !(0..=MAX_TTL_SECONDS).contains(&edge_ttl) {
            return Err(ApiError::BadRequest(format!(
                "edge_ttl_seconds must be between 0 and {MAX_TTL_SECONDS}"
            )));
        }
        active.edge_ttl_seconds = Set(edge_ttl);
    }
    if let Some(browser_ttl) = payload.browser_ttl_seconds {
        if !(0..=MAX_TTL_SECONDS).contains(&browser_ttl) {
            return Err(ApiError::BadRequest(format!(
                "browser_ttl_seconds must be between 0 and {MAX_TTL_SECONDS}"
            )));
        }
        active.browser_ttl_seconds = Set(browser_ttl);
    }
    if let Some(quota) = payload.disk_quota_mb {
        if !(0..=MAX_DISK_QUOTA_MB).contains(&quota) {
            return Err(ApiError::BadRequest(format!(
                "disk_quota_mb must be between 0 and {MAX_DISK_QUOTA_MB}"
            )));
        }
        active.disk_quota_mb = Set(quota);
    }
    if let Some(eligible) = payload.cache_eligible {
        active.cache_eligible = Set(eligible);
    }
    if let Some(respect) = payload.respect_origin {
        active.respect_origin = Set(respect);
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, rule_id = %target, "cache rule updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated))
}

/// `DELETE /api/v1/sites/{site_id}/cache-rules/{rule_id}`
async fn remove(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "cache rule id")?;
    load_site_write(&state.db, id, &current).await?;
    find(&state, id, target).await?;

    cache_rules::Entity::delete_by_id(target)
        .exec(&state.db)
        .await?;

    tracing::info!(site_id = %id, rule_id = %target, "cache rule deleted");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn find(
    state: &AppState,
    site_id: Uuid,
    rule_id: Uuid,
) -> Result<cache_rules::Model, ApiError> {
    cache_rules::Entity::find_by_id(rule_id)
        .filter(cache_rules::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("cache rule {rule_id} not found"))
        })
}

/// Looks a rule up by id alone; the caller authorises through its `site_id`.
async fn find_by_id(
    state: &AppState,
    rule_id: Uuid,
) -> Result<cache_rules::Model, ApiError> {
    cache_rules::Entity::find_by_id(rule_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("cache rule {rule_id} not found"))
        })
}

// ─── Flat rule aliases ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct FlatListQuery {
    /// Site to list the rules of. Optional for administrators, required for
    /// every other role.
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct FlatCreateRequest {
    pub site_id: String,
    #[serde(flatten)]
    pub rule: CreateRequest,
}

/// `GET /api/v1/cache/rules?site_id=X`
async fn list_by_query(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<FlatListQuery>,
) -> Result<Json<Page<cache_rules::Model>>, ApiError> {
    let requested = match query.site_id.as_deref() {
        Some(raw) => Some(parse_uuid(raw, "site id")?),
        None => None,
    };
    let pagination = query.pagination.normalise();

    let mut condition = Condition::all();
    // Administrator without a filter: every rule in the system, so `None`
    // adds no condition.
    if let Some(id) = scope_site(requested, &current)? {
        load_site_read(&state.db, id, &current).await?;
        condition = condition.add(cache_rules::Column::SiteId.eq(id));
    }
    if !current.is_admin() && requested.is_none() {
        // `scope_site` already rejected this, but a non-admin listing every
        // rule must never fall through to the unfiltered query.
        return Err(ApiError::BadRequest(
            "site_id is required for non-admin accounts".to_string(),
        ));
    }

    let paginator = cache_rules::Entity::find()
        .filter(condition)
        .order_by_asc(cache_rules::Column::Name)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    Ok(Json(Page::new(rows, total, pagination)))
}

/// `POST /api/v1/cache/rules`
async fn create_by_body(
    state: State<AppState>,
    current: AuthUser,
    Json(payload): Json<FlatCreateRequest>,
) -> Result<Response, ApiError> {
    let site_id = payload.site_id.clone();
    create(state, current, Path(site_id), Json(payload.rule)).await
}

/// `PUT /api/v1/cache/rules/{rule_id}`
async fn update_by_id(
    state: State<AppState>,
    current: AuthUser,
    Path(rule_id): Path<String>,
    payload: Json<UpdateRequest>,
) -> Result<Json<cache_rules::Model>, ApiError> {
    let target = parse_uuid(&rule_id, "cache rule id")?;
    let row = find_by_id(&state, target).await?;
    // Authorisation still runs against the rule's own site.
    update(
        state,
        current,
        Path((row.site_id.to_string(), rule_id)),
        payload,
    )
    .await
}

/// `DELETE /api/v1/cache/rules/{rule_id}`
async fn remove_by_id(
    state: State<AppState>,
    current: AuthUser,
    Path(rule_id): Path<String>,
) -> Result<Response, ApiError> {
    let target = parse_uuid(&rule_id, "cache rule id")?;
    let row = find_by_id(&state, target).await?;
    remove(state, current, Path((row.site_id.to_string(), rule_id))).await
}

// ─── Site-wide cache settings ──────────────────────────────────────────────

/// Site-wide cache settings.
///
/// The disk budget belongs to the site, not to an individual rule: the agent
/// enforces one ceiling per hostname, and every hostname of a site shares the
/// same budget.
#[derive(Debug, Serialize)]
pub struct CacheSettingsResponse {
    pub site_id: Uuid,
    /// Disk budget, in MiB, the agents may use for this site's cache.
    pub quota_mb: i32,
    /// Site-level single-file cache cap in MiB; `None` follows the global
    /// ceiling (`global_max_file_size_mb`).
    pub max_file_size_mb: Option<i32>,
    /// Per-content-type single-file caps in MiB, keyed by
    /// `html/css/js/image/font/media/other`; a missing key follows
    /// `max_file_size_mb`.
    pub type_limits: Option<HashMap<String, i32>>,
    /// The global single-file ceiling every site-level value is clamped
    /// against — shown so the UI can state the effective limit.
    pub global_max_file_size_mb: i32,
    /// Resolved single-file cap this site actually enforces:
    /// `min(global, max_file_size_mb?)`.
    pub effective_max_file_size_mb: i32,
    /// Whether any cache rule of the site is enabled.
    pub cache_enabled: bool,
    pub rule_count: usize,
    pub enabled_rule_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCacheSettingsRequest {
    #[serde(default)]
    pub quota_mb: Option<i32>,
    /// Site-level single-file cap. Absent = unchanged; explicit `null` =
    /// follow the global ceiling again.
    #[serde(default)]
    pub max_file_size_mb: Option<Option<i32>>,
    /// Per-content-type single-file caps. Absent = unchanged; an empty map
    /// clears every override.
    #[serde(default)]
    pub type_limits: Option<Option<HashMap<String, i32>>>,
}

/// The content-type families a site may pin a per-type single-file cap for.
pub const CACHE_TYPE_KEYS: [&str; 7] =
    ["html", "css", "js", "image", "font", "media", "other"];

/// Validates a site-level single-file cap (1 MiB..=global) and a
/// per-type map (every key in [`CACHE_TYPE_KEYS`], every value
/// 1 MiB..=cap). `site_cap` is the cap the values are measured against —
/// the new site value when both change in one request.
fn validate_site_cache_limits(
    max_file_size_mb: i32,
    type_limits: Option<&HashMap<String, i32>>,
    global_max_file_size_mb: i32,
) -> Result<(), ApiError> {
    if !(1..=global_max_file_size_mb).contains(&max_file_size_mb) {
        return Err(ApiError::BadRequest(format!(
            "cache_max_file_size_mb must be between 1 and \
             {global_max_file_size_mb} (global single-file limit)"
        )));
    }
    if let Some(limits) = type_limits {
        for (key, value) in limits {
            if !CACHE_TYPE_KEYS.contains(&key.as_str()) {
                return Err(ApiError::BadRequest(format!(
                    "cache type limit key {key} is invalid, expected one of {}",
                    CACHE_TYPE_KEYS.join(", ")
                )));
            }
            if !(1..=max_file_size_mb).contains(value) {
                return Err(ApiError::BadRequest(format!(
                    "cache type limit for {key} must be between 1 and \
                     {max_file_size_mb}"
                )));
            }
        }
    }
    Ok(())
}

async fn settings_view(
    state: &AppState,
    model: &site::Model,
) -> Result<CacheSettingsResponse, ApiError> {
    let rules = cache_rules::Entity::find()
        .filter(cache_rules::Column::SiteId.eq(model.id))
        .all(&state.db)
        .await?;
    let global = crate::api::cache_settings::load(&state.db).await?;
    let type_limits: Option<HashMap<String, i32>> = model
        .cache_type_limits_mb
        .as_ref()
        .and_then(|value| serde_json::from_value(value.clone()).ok());
    Ok(CacheSettingsResponse {
        site_id: model.id,
        quota_mb: model.cache_quota_mb,
        max_file_size_mb: model.cache_max_file_size_mb,
        effective_max_file_size_mb: model
            .cache_max_file_size_mb
            .unwrap_or(global.max_file_size_mb),
        type_limits,
        global_max_file_size_mb: global.max_file_size_mb,
        cache_enabled: rules.iter().any(|rule| rule.enabled),
        rule_count: rules.len(),
        enabled_rule_count: rules.iter().filter(|rule| rule.enabled).count(),
    })
}

/// `GET /api/v1/sites/{site_id}/cache-settings`
async fn get_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<CacheSettingsResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let model = load_site_read(&state.db, id, &current).await?;
    Ok(Json(settings_view(&state, &model).await?))
}

/// `PUT /api/v1/sites/{site_id}/cache-settings`
async fn update_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateCacheSettingsRequest>,
) -> Result<Json<CacheSettingsResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let model = load_site_write(&state.db, id, &current).await?;
    let global = crate::api::cache_settings::load(&state.db).await?;

    if let Some(quota) = payload.quota_mb {
        if !(0..=MAX_DISK_QUOTA_MB).contains(&quota) {
            return Err(ApiError::BadRequest(format!(
                "quota_mb must be between 0 and {MAX_DISK_QUOTA_MB}"
            )));
        }
    }

    // Resolve the cap per-type values are measured against: the site value
    // submitted in this very request wins, then the stored one, then the
    // global ceiling.
    let requested_site_cap = payload
        .max_file_size_mb
        .unwrap_or(model.cache_max_file_size_mb);
    let cap_for_types = requested_site_cap.unwrap_or(global.max_file_size_mb);
    if let Some(limits) = payload.type_limits.as_ref().and_then(Option::as_ref)
    {
        validate_site_cache_limits(
            cap_for_types,
            Some(limits),
            global.max_file_size_mb,
        )?;
    }
    if let Some(site_cap) = payload.max_file_size_mb.flatten() {
        validate_site_cache_limits(site_cap, None, global.max_file_size_mb)?;
    }

    let mut changed = false;
    if let Some(quota) = payload.quota_mb {
        let mut active: site::ActiveModel = model.clone().into();
        active.cache_quota_mb = Set(quota);
        active.update(&state.db).await?;
        tracing::info!(site_id = %id, quota_mb = quota, "cache quota updated");
        changed = true;
    }
    if let Some(site_cap) = payload.max_file_size_mb {
        let mut active: site::ActiveModel = model.clone().into();
        active.cache_max_file_size_mb = Set(site_cap);
        active.update(&state.db).await?;
        tracing::info!(
            site_id = %id,
            max_file_size_mb = ?site_cap,
            "site cache file-size limit updated"
        );
        changed = true;
    }
    if let Some(type_limits) = payload.type_limits {
        let stored = type_limits.clone().map(|limits| {
            serde_json::to_value(limits).unwrap_or(serde_json::Value::Null)
        });
        let mut active: site::ActiveModel = model.clone().into();
        active.cache_type_limits_mb = Set(stored);
        active.update(&state.db).await?;
        tracing::info!(
            site_id = %id,
            type_limits = ?type_limits,
            "site cache type limits updated"
        );
        changed = true;
    }

    if changed {
        touch_site(&state, id).await?;
        notify_config_changed(&state, id, Some(&current.email)).await;
    }

    let refreshed = load_site_read(&state.db, id, &current).await?;
    Ok(Json(settings_view(&state, &refreshed).await?))
}

// ─── Usage reporting ───────────────────────────────────────────────────────

/// Cache usage and quota of one site.
///
/// `configured_*` comes from the database and is therefore always available;
/// everything else comes from the edges' heartbeats and stays zero until an
/// agent reports. `reporting_edges == 0` is how a caller tells those apart.
#[derive(Debug, Serialize)]
pub struct CacheStatusView {
    pub site_id: Uuid,
    pub domain: String,
    /// Disk budget of the site, in MiB — a site-wide setting, not a property
    /// of any single rule.
    pub configured_quota_mb: i32,
    pub enabled_rule_count: usize,
    /// Edges that reported this site.
    pub reporting_edges: usize,
    pub disk_bytes: u64,
    /// Ceiling per edge; the quota is enforced per domain per edge.
    pub quota_bytes_per_edge: u64,
    /// `quota_bytes_per_edge * reporting_edges`.
    pub quota_bytes_total: u64,
    pub items: u64,
    pub evictions_total: u64,
    pub usage_percent: f64,
    pub last_reported_at: Option<DateTime<Utc>>,
}

/// `(site quota in MB, number of enabled cache-eligible rules)` per site.
///
/// The quota is the site's own `cache_quota_mb`: the budget is site-wide, so a
/// rule never overrides it.
async fn rule_summary(
    state: &AppState,
    sites: &[site::Model],
) -> Result<HashMap<Uuid, (i32, usize)>, ApiError> {
    let mut out: HashMap<Uuid, (i32, usize)> = HashMap::new();
    if sites.is_empty() {
        return Ok(out);
    }
    let ids: Vec<Uuid> = sites.iter().map(|model| model.id).collect();
    for model in sites {
        out.insert(model.id, (model.cache_quota_mb, 0));
    }

    let rules = cache_rules::Entity::find()
        .filter(cache_rules::Column::SiteId.is_in(ids))
        .all(&state.db)
        .await?;
    for rule in rules {
        if !rule.enabled || !rule.cache_eligible {
            continue;
        }
        if let Some(entry) = out.get_mut(&rule.site_id) {
            entry.1 += 1;
        }
    }
    Ok(out)
}

fn status_view(
    model: &site::Model,
    configured: Option<(i32, usize)>,
    reported: Option<SiteCacheStatus>,
) -> CacheStatusView {
    let (configured_quota_mb, enabled_rule_count) =
        configured.unwrap_or((0, 0));
    match reported {
        Some(reported) => CacheStatusView {
            site_id: model.id,
            domain: model.domain.clone(),
            configured_quota_mb,
            enabled_rule_count,
            reporting_edges: reported.edges,
            disk_bytes: reported.disk_bytes,
            quota_bytes_per_edge: reported.quota_bytes_per_edge,
            quota_bytes_total: reported.quota_bytes_total,
            items: reported.items,
            evictions_total: reported.evictions_total,
            usage_percent: reported.usage_percent,
            last_reported_at: Some(reported.reported_at),
        },
        // No edge has reported yet: show what is configured and nothing else.
        None => CacheStatusView {
            site_id: model.id,
            domain: model.domain.clone(),
            configured_quota_mb,
            enabled_rule_count,
            reporting_edges: 0,
            disk_bytes: 0,
            quota_bytes_per_edge: 0,
            quota_bytes_total: 0,
            items: 0,
            evictions_total: 0,
            usage_percent: 0.0,
            last_reported_at: None,
        },
    }
}

/// `GET /api/v1/cache/status` — cache usage across every site the caller sees.
async fn status_all(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<Vec<CacheStatusView>>, ApiError> {
    let mut condition = Condition::all();
    if !current.is_admin() {
        condition = condition.add(site::Column::UserId.eq(current.id));
    }
    let sites = site::Entity::find()
        .filter(condition)
        .order_by_asc(site::Column::Domain)
        .all(&state.db)
        .await?;

    let configured = rule_summary(&state, &sites).await?;
    let reported = state.cache_status.all().await;

    let views = sites
        .iter()
        .map(|model| {
            status_view(
                model,
                configured.get(&model.id).copied(),
                reported
                    .iter()
                    .find(|item| item.site_id == model.id)
                    .cloned(),
            )
        })
        .collect();
    Ok(Json(views))
}

/// `GET /api/v1/cache/status/{site_id}` — cache usage for one site.
async fn status_site(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<CacheStatusView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let model = load_site_read(&state.db, id, &current).await?;
    let configured = rule_summary(&state, std::slice::from_ref(&model)).await?;
    let reported = state.cache_status.site(id).await;
    Ok(Json(status_view(
        &model,
        configured.get(&id).copied(),
        reported,
    )))
}

// ─── Purging ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PurgeRequest {
    pub site_id: String,
    /// Exact cache keys/urls to drop. Ignored when `purge_all` is set.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Drop everything cached for the site.
    #[serde(default)]
    pub purge_all: bool,
    // There is deliberately no `tags` field: `PurgeCacheCommand` reserves one,
    // but nothing tags a cached object yet (no origin header is read into the
    // ledger), so accepting tags here would only let a caller believe a purge
    // matched something. Add it together with the tagging, not before.
}

#[derive(Debug, Serialize)]
pub struct PurgeResponse {
    pub site_id: Uuid,
    pub purge_all: bool,
    pub urls: usize,
    /// Agents the command reached on a live stream.
    pub delivered: usize,
    /// Agents it was queued for, because they are offline or their channel is
    /// full; it is delivered on their next heartbeat.
    pub queued: usize,
}

/// Validates and normalises the url list of a purge request.
///
/// An empty result means "purge everything": the agent reads a missing list the
/// same way, so the wire format does not have to carry a separate flag.
fn normalize_purge_urls(
    payload: &PurgeRequest,
) -> Result<Vec<String>, ApiError> {
    if payload.purge_all {
        // Explicit: "everything" wins over a leftover list, which would
        // otherwise make the request ambiguous.
        return Ok(Vec::new());
    }
    let mut urls: Vec<String> = payload
        .urls
        .iter()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect();
    if urls.is_empty() {
        return Err(ApiError::BadRequest(
            "either urls or purge_all must be provided".to_string(),
        ));
    }
    if urls.len() > MAX_PURGE_URLS {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_PURGE_URLS} urls can be purged in one request"
        )));
    }
    // Every url is shipped to every edge serving the site, so a repeated one is
    // pure waste. Sorting is what lets `dedup` catch all of them rather than
    // only adjacent ones, and the order carries no meaning for a purge.
    urls.sort();
    urls.dedup();
    Ok(urls)
}

/// `POST /api/v1/cache/purge`
///
/// The control plane holds no cached content itself, so this fans the request
/// out to the agents serving the site over their heartbeat streams.
async fn purge(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<PurgeRequest>,
) -> Result<Json<PurgeResponse>, ApiError> {
    let id = parse_uuid(&payload.site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let urls = normalize_purge_urls(&payload)?;

    // Agents bound to this site, plus the ones bound to no single site: those
    // serve whichever sites their API key covers, so this one may be theirs.
    let targets = agent::Entity::find()
        .filter(
            Condition::any()
                .add(agent::Column::SiteId.eq(id))
                .add(agent::Column::SiteId.is_null()),
        )
        .all(&state.db)
        .await?;
    if targets.is_empty() {
        return Err(ApiError::NotFound(format!(
            "no agent is registered for site {id}"
        )));
    }

    let purge_all = urls.is_empty();
    let mut delivered = 0usize;
    for target in &targets {
        let command = ServerCommand {
            command_id: Uuid::new_v4().to_string(),
            r#type: command_type::PURGE_CACHE,
            issued_at: now_timestamp(),
            payload: Some(CommandPayload::PurgeCache(PurgeCacheCommand {
                site_id: id.to_string(),
                urls: urls.clone(),
                // Reserved for tag-based purging, which nothing populates yet.
                tags: Vec::new(),
            })),
        };
        if state.agents.send_command(&target.id, command).await {
            delivered += 1;
        }
    }

    tracing::info!(
        site_id = %id,
        purge_all,
        urls = urls.len(),
        agents = targets.len(),
        delivered,
        actor = %current.id,
        "cache purge requested"
    );

    Ok(Json(PurgeResponse {
        site_id: id,
        purge_all,
        urls: urls.len(),
        delivered,
        queued: targets.len() - delivered,
    }))
}

/// `POST /api/v1/sites/{site_id}/cache/defaults`
///
/// Re-adds any missing built-in cache rule, disabled, so the operator can turn
/// caching on with a single switch instead of writing rules from scratch.
async fn seed_defaults(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let inserted = crate::defaults::seed_cache_defaults(&state.db, id).await?;
    tracing::info!(site_id = %id, inserted, "built-in cache rules restored");

    if inserted > 0 {
        touch_site(&state, id).await?;
        notify_config_changed(&state, id, Some(&current.email)).await;
    }

    Ok(Json(serde_json::json!({
        "inserted": inserted,
        "total": crate::defaults::cache_rules_defaults().len(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_enforced() {
        assert!(validate("static", 3600, 300, 1024).is_ok());
        assert!(validate("static", -1, 300, 1024).is_err());
        assert!(validate("static", 3600, MAX_TTL_SECONDS + 1, 1024).is_err());
        assert!(validate("static", 3600, 300, MAX_DISK_QUOTA_MB + 1).is_err());
        assert!(validate("   ", 3600, 300, 1024).is_err());
    }

    #[test]
    fn defaults_match_the_schema() {
        assert_eq!(default_edge_ttl(), 3600);
        assert_eq!(default_browser_ttl(), 300);
        assert_eq!(default_disk_quota(), 1024);
        assert!(default_true());
    }

    fn limits(pairs: &[(&str, i32)]) -> HashMap<String, i32> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn site_file_cap_rejects_zero_and_global_exceedance() {
        let global = 16;
        assert!(validate_site_cache_limits(1, None, global).is_ok());
        assert!(validate_site_cache_limits(global, None, global).is_ok());
        assert!(validate_site_cache_limits(0, None, global).is_err());
        assert!(validate_site_cache_limits(global + 1, None, global).is_err());
    }

    #[test]
    fn type_limits_reject_unknown_keys_and_out_of_range_values() {
        let good = limits(&[("html", 4), ("image", 8)]);
        assert!(validate_site_cache_limits(8, Some(&good), 16).is_ok());

        let unknown = limits(&[("video", 4)]);
        let err = validate_site_cache_limits(8, Some(&unknown), 16)
            .expect_err("unknown key must be rejected");
        assert!(err.to_string().contains("invalid"), "{err}");

        let too_big = limits(&[("js", 9)]);
        let err = validate_site_cache_limits(8, Some(&too_big), 16)
            .expect_err("value above the site cap must be rejected");
        assert!(err.to_string().contains("between 1 and 8"), "{err}");

        let zero = limits(&[("css", 0)]);
        assert!(validate_site_cache_limits(8, Some(&zero), 16).is_err());
    }

    #[test]
    fn empty_type_map_clears_every_override() {
        assert!(
            validate_site_cache_limits(8, Some(&HashMap::new()), 16).is_ok()
        );
    }

    /// Axum panics while *building* a router whose paths overlap, so merely
    /// constructing it proves the flat aliases coexist with the nested ones.
    #[test]
    fn routes_register_without_conflicting() {
        let _ = routes();
    }

    fn purge(urls: &[&str], purge_all: bool) -> PurgeRequest {
        PurgeRequest {
            site_id: Uuid::new_v4().to_string(),
            urls: urls.iter().map(|url| (*url).to_string()).collect(),
            purge_all,
        }
    }

    #[test]
    fn purge_all_wins_over_a_leftover_url_list() {
        let urls = normalize_purge_urls(&purge(&["/a"], true)).expect("valid");
        assert!(urls.is_empty());
    }

    #[test]
    fn a_purge_with_nothing_to_purge_is_rejected() {
        let err =
            normalize_purge_urls(&purge(&[], false)).expect_err("invalid");
        assert!(matches!(err, ApiError::BadRequest(_)));
        // Blank entries are dropped before the emptiness check, so a list of
        // whitespace is the same mistake.
        let err = normalize_purge_urls(&purge(&["  ", "\t"], false))
            .expect_err("invalid");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn purge_urls_are_trimmed_deduplicated_and_capped() {
        let urls = normalize_purge_urls(&purge(
            &[" /a ", "/a", "/b", "", "/c"],
            false,
        ))
        .expect("valid");
        assert_eq!(vec!["/a", "/b", "/c"], urls);

        let too_many: Vec<&str> = (0..=MAX_PURGE_URLS).map(|_| "/x").collect();
        let err = normalize_purge_urls(&purge(&too_many, false))
            .expect_err("invalid");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}
