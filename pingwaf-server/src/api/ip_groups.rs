//! IP groups management: global or per-site IP blacklist/whitelist with
//! optional subscription source for dynamic updates.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait, Set,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::common::{
    load_site_write, non_empty, parse_uuid, require_write, Page, Pagination,
};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{
    bot_protection, ip_access_rules, ip_group_sites, ip_groups, site,
    site_routes,
};

/// Valid IP group actions.
pub mod ip_group_action {
    pub const BLOCK: &str = "block";
    pub const ALLOW: &str = "allow";

    pub fn is_valid(action: &str) -> bool {
        matches!(action, BLOCK | ALLOW)
    }
}

/// Subscription source kinds. `builtin` groups are seeded from the snapshots
/// compiled into the binary and can only be created by the seeder, `url`
/// groups fetch an operator-supplied source, and `None` means manual ranges.
pub mod subscription_kind {
    pub const BUILTIN: &str = "builtin";
    pub const URL: &str = "url";

    pub fn is_valid(kind: &str) -> bool {
        matches!(kind, BUILTIN | URL)
    }
}

fn default_action() -> String {
    ip_group_action::BLOCK.to_string()
}

/// `<= 0` (or the UI's "manual" choice) clears the interval; positive values
/// are kept as-is.
fn normalise_interval(minutes: Option<i32>) -> Option<i32> {
    minutes.filter(|minutes| *minutes > 0)
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
    pub action: Option<String>,
    pub is_global: Option<bool>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub ip_ranges: Vec<String>,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub is_global: bool,
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub sync_interval_minutes: Option<i32>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub subscription_enabled: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub ip_ranges: Option<Vec<String>>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub is_global: Option<bool>,
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub sync_interval_minutes: Option<i32>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub subscription_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SetSitesRequest {
    pub site_ids: Vec<String>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/ip-groups", get(list).post(create))
        .route(
            "/ip-groups/{group_id}",
            get(show).put(update).delete(remove),
        )
        .route(
            "/ip-groups/{group_id}/sites",
            get(list_sites).put(set_sites),
        )
        .route("/ip-groups/{group_id}/sync", post(sync_now))
}

/// Validates IP/CIDR ranges (basic format check).
fn validate_ip_ranges(ranges: &[String]) -> Result<Vec<String>, ApiError> {
    if ranges.len() > 10000 {
        return Err(ApiError::BadRequest(
            "an IP group may contain at most 10000 IP ranges".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(ranges.len());
    for range in ranges {
        let trimmed = range.trim();
        if trimmed.is_empty() {
            continue;
        }
        let base = trimmed.split('/').next().unwrap_or(trimmed);
        if base.parse::<std::net::IpAddr>().is_err() {
            return Err(ApiError::BadRequest(format!(
                "invalid IP address or CIDR: '{trimmed}'"
            )));
        }
        if !out.contains(&trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

fn validate_name(name: &str) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 200 {
        return Err(ApiError::BadRequest(
            "name must be 1-200 characters".to_string(),
        ));
    }
    Ok(())
}

/// Response type that includes the count of associated sites.
#[derive(Debug, serde::Serialize)]
pub struct IpGroupResponse {
    #[serde(flatten)]
    pub group: ip_groups::Model,
    pub site_count: usize,
}

/// `GET /api/v1/ip-groups`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<IpGroupResponse>>, ApiError> {
    let pagination = query.pagination.normalise();

    let mut condition = sea_orm::Condition::all();
    if !current.is_admin() {
        let user_site_ids = site::Entity::find()
            .filter(site::Column::UserId.eq(current.id))
            .select_only()
            .column(site::Column::Id)
            .into_query();

        let linked_group_ids = ip_group_sites::Entity::find()
            .filter(ip_group_sites::Column::SiteId.in_subquery(user_site_ids))
            .select_only()
            .column(ip_group_sites::Column::IpGroupId)
            .into_query();

        condition = condition.add(
            ip_groups::Column::IsGlobal
                .eq(true)
                .or(ip_groups::Column::Id.in_subquery(linked_group_ids)),
        );
    }
    if let Some(ref action) = non_empty(&query.action) {
        if !ip_group_action::is_valid(action) {
            return Err(ApiError::BadRequest(format!(
                "unknown action '{action}'"
            )));
        }
        condition =
            condition.add(ip_groups::Column::Action.eq(action.as_str()));
    }
    if let Some(is_global) = query.is_global {
        condition = condition.add(ip_groups::Column::IsGlobal.eq(is_global));
    }
    if let Some(enabled) = query.enabled {
        condition = condition.add(ip_groups::Column::Enabled.eq(enabled));
    }

    let paginator = ip_groups::Entity::find()
        .filter(condition)
        .order_by_desc(ip_groups::Column::IsGlobal)
        .order_by_asc(ip_groups::Column::Name)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;

    let group_ids: Vec<Uuid> = rows.iter().map(|g| g.id).collect();
    let site_counts: std::collections::HashMap<Uuid, usize> =
        if group_ids.is_empty() {
            std::collections::HashMap::new()
        } else {
            ip_group_sites::Entity::find()
                .filter(ip_group_sites::Column::IpGroupId.is_in(group_ids))
                .all(&state.db)
                .await?
                .into_iter()
                .fold(std::collections::HashMap::new(), |mut acc, assoc| {
                    *acc.entry(assoc.ip_group_id).or_insert(0usize) += 1;
                    acc
                })
        };

    let items: Vec<IpGroupResponse> = rows
        .into_iter()
        .map(|g| {
            let site_count = site_counts.get(&g.id).copied().unwrap_or(0);
            IpGroupResponse {
                group: g,
                site_count,
            }
        })
        .collect();
    Ok(Json(Page::new(items, total, pagination)))
}

/// `POST /api/v1/ip-groups`
async fn create(
    State(state): State<AppState>,
    _current: AuthUser,
    Json(payload): Json<CreateRequest>,
) -> Result<Response, ApiError> {
    require_write(&_current)?;
    validate_name(&payload.name)?;
    if !ip_group_action::is_valid(&payload.action) {
        return Err(ApiError::BadRequest(format!(
            "unknown action '{}'",
            payload.action
        )));
    }
    let ip_ranges = validate_ip_ranges(&payload.ip_ranges)?;
    let source_url = non_empty(&payload.source_url);
    if let Some(url) = &source_url {
        crate::subscription::validate_source_url(url)
            .map_err(ApiError::BadRequest)?;
    }

    let timestamp = chrono::Utc::now();
    // Groups created through the API are manual or URL subscriptions; the
    // `builtin` kind is reserved for the seeder's snapshot-backed groups.
    let subscription_kind = if source_url.is_some() {
        Some(subscription_kind::URL.to_string())
    } else {
        None
    };
    let model = ip_groups::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(payload.name.trim().to_string()),
        description: Set(non_empty(&payload.description)),
        ip_ranges: Set(ip_ranges),
        action: Set(payload.action),
        is_global: Set(payload.is_global),
        subscription_kind: Set(subscription_kind),
        subscription_enabled: Set(payload.subscription_enabled),
        source_url: Set(source_url),
        sync_interval_minutes: Set(normalise_interval(
            payload.sync_interval_minutes,
        )),
        last_synced_at: Set(None),
        last_sync_error: Set(None),
        enabled: Set(payload.enabled),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(group_id = %model.id, name = %model.name, "IP group created");

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// `GET /api/v1/ip-groups/{group_id}`
async fn show(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(group_id): Path<String>,
) -> Result<Json<IpGroupResponse>, ApiError> {
    let target = parse_uuid(&group_id, "IP group id")?;
    let group = find_group(&state, target).await?;
    let site_count = ip_group_sites::Entity::find()
        .filter(ip_group_sites::Column::IpGroupId.eq(target))
        .count(&state.db)
        .await? as usize;
    Ok(Json(IpGroupResponse { group, site_count }))
}

/// `PUT /api/v1/ip-groups/{group_id}`
async fn update(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(group_id): Path<String>,
    Json(payload): Json<UpdateRequest>,
) -> Result<Json<ip_groups::Model>, ApiError> {
    require_write(&_current)?;
    let target = parse_uuid(&group_id, "IP group id")?;
    let row = find_group(&state, target).await?;
    if row.subscription_kind.as_deref() == Some(subscription_kind::BUILTIN)
        && payload.source_url.is_some()
    {
        return Err(ApiError::BadRequest(
            "built-in subscription groups cannot change their source URL"
                .to_string(),
        ));
    }
    let mut active: ip_groups::ActiveModel = row.into();

    if let Some(name) = non_empty(&payload.name) {
        validate_name(&name)?;
        active.name = Set(name);
    }
    if let Some(desc) = payload.description {
        active.description = Set(non_empty(&Some(desc)));
    }
    if let Some(ranges) = payload.ip_ranges {
        active.ip_ranges = Set(validate_ip_ranges(&ranges)?);
    }
    if let Some(action) = non_empty(&payload.action) {
        if !ip_group_action::is_valid(&action) {
            return Err(ApiError::BadRequest(format!(
                "unknown action '{action}'"
            )));
        }
        active.action = Set(action);
    }
    if let Some(is_global) = payload.is_global {
        active.is_global = Set(is_global);
    }
    if let Some(url) = payload.source_url {
        let stored = non_empty(&Some(url));
        if let Some(url) = &stored {
            crate::subscription::validate_source_url(url)
                .map_err(ApiError::BadRequest)?;
        }
        // Clearing the source URL turns the group back into manual ranges.
        let kind = if stored.is_some() {
            Some(subscription_kind::URL.to_string())
        } else {
            None
        };
        active.subscription_kind = Set(kind);
        active.source_url = Set(stored);
    }
    if let Some(interval) = payload.sync_interval_minutes {
        active.sync_interval_minutes = Set(normalise_interval(Some(interval)));
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(sub_enabled) = payload.subscription_enabled {
        active.subscription_enabled = Set(sub_enabled);
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(group_id = %target, "IP group updated");
    propagate_group_change(&state, target, Some(&_current.email)).await;

    Ok(Json(updated))
}

/// `DELETE /api/v1/ip-groups/{group_id}`
async fn remove(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(group_id): Path<String>,
) -> Result<Response, ApiError> {
    require_write(&_current)?;
    let target = parse_uuid(&group_id, "IP group id")?;
    find_group(&state, target).await?;

    // The foreign key would reject the delete as well; checking first turns
    // the raw constraint error into something the operator can act on.
    let gating_routes = site_routes::Entity::find()
        .filter(site_routes::Column::IpGroupId.eq(target))
        .count(&state.db)
        .await?;
    if gating_routes > 0 {
        return Err(ApiError::BadRequest(format!(
            "IP group still gates {gating_routes} route(s); clear those route gates first"
        )));
    }

    ip_groups::Entity::delete_by_id(target)
        .exec(&state.db)
        .await?;

    tracing::info!(group_id = %target, "IP group deleted");
    propagate_group_change(&state, target, Some(&_current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Sites whose agent configuration embeds this group: explicitly associated
/// sites, sites whose access rules reference it, sites whose routes are
/// gated on it, sites trusting it for their proxy scope, and sites using it
/// as their verified-bot source. Used to push config updates after a group
/// mutation.
async fn affected_sites(
    db: &sea_orm::DatabaseConnection,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sea_orm::DbErr> {
    let associated = ip_group_sites::Entity::find()
        .filter(ip_group_sites::Column::IpGroupId.eq(group_id))
        .select_only()
        .column(ip_group_sites::Column::SiteId)
        .into_query();
    let referencing = ip_access_rules::Entity::find()
        .filter(ip_access_rules::Column::GroupId.eq(group_id))
        .select_only()
        .column(ip_access_rules::Column::SiteId)
        .into_query();
    let gating = site_routes::Entity::find()
        .filter(site_routes::Column::IpGroupId.eq(group_id))
        .select_only()
        .column(site_routes::Column::SiteId)
        .into_query();
    let bot_verified = bot_protection::Entity::find()
        .filter(bot_protection::Column::VerifiedIpGroupId.eq(group_id))
        .select_only()
        .column(bot_protection::Column::SiteId)
        .into_query();

    let mut ids: Vec<Uuid> = site::Entity::find()
        .filter(
            site::Column::Id
                .in_subquery(associated)
                .or(site::Column::Id.in_subquery(referencing))
                .or(site::Column::Id.in_subquery(gating))
                .or(site::Column::Id.in_subquery(bot_verified)),
        )
        .select_only()
        .column(site::Column::Id)
        .into_tuple()
        .all(db)
        .await?;

    // The trusted-proxy group references live in a uuid[] column, which has
    // no portable containment predicate; the table is small and this only
    // runs on group mutations, so scan it in the application instead.
    let trusting: Vec<(Uuid, Vec<Uuid>)> = site::Entity::find()
        .select_only()
        .column(site::Column::Id)
        .column(site::Column::TrustedProxyGroupIds)
        .into_tuple()
        .all(db)
        .await?;
    ids.extend(
        trusting
            .into_iter()
            .filter(|(_, group_ids)| group_ids.contains(&group_id))
            .map(|(site_id, _)| site_id),
    );

    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Touches and notifies every site affected by a group change. Best-effort:
/// the mutation itself already succeeded, so failures only warn.
async fn propagate_group_change(
    state: &AppState,
    group_id: Uuid,
    actor: Option<&str>,
) {
    let site_ids = match affected_sites(&state.db, group_id).await {
        Ok(ids) => ids,
        Err(err) => {
            tracing::warn!(
                group_id = %group_id,
                error = %err,
                "failed to resolve sites affected by IP group change"
            );
            return;
        },
    };
    for sid in site_ids {
        if let Err(err) = touch_site(state, sid).await {
            tracing::warn!(
                site_id = %sid,
                error = %err,
                "failed to touch site after IP group change"
            );
        }
        notify_config_changed(state, sid, actor).await;
    }
}

/// `GET /api/v1/ip-groups/{group_id}/sites`
async fn list_sites(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(group_id): Path<String>,
) -> Result<Json<Vec<site::Model>>, ApiError> {
    let target = parse_uuid(&group_id, "IP group id")?;
    find_group(&state, target).await?;

    let associations = ip_group_sites::Entity::find()
        .filter(ip_group_sites::Column::IpGroupId.eq(target))
        .all(&state.db)
        .await?;

    let site_ids: Vec<Uuid> = associations.iter().map(|a| a.site_id).collect();
    if site_ids.is_empty() {
        return Ok(Json(vec![]));
    }

    let sites = site::Entity::find()
        .filter(site::Column::Id.is_in(site_ids))
        .all(&state.db)
        .await?;

    Ok(Json(sites))
}

/// `PUT /api/v1/ip-groups/{group_id}/sites`
async fn set_sites(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(group_id): Path<String>,
    Json(payload): Json<SetSitesRequest>,
) -> Result<Response, ApiError> {
    require_write(&_current)?;
    let target = parse_uuid(&group_id, "IP group id")?;
    let group = find_group(&state, target).await?;

    if group.is_global {
        return Err(ApiError::BadRequest(
            "global IP groups cannot be associated with specific sites"
                .to_string(),
        ));
    }

    let site_ids: Vec<Uuid> = payload
        .site_ids
        .iter()
        .map(|s| parse_uuid(s, "site id"))
        .collect::<Result<Vec<_>, _>>()?;

    for sid in &site_ids {
        load_site_write(&state.db, *sid, &_current).await?;
    }

    let old_site_ids: Vec<Uuid> = ip_group_sites::Entity::find()
        .filter(ip_group_sites::Column::IpGroupId.eq(target))
        .select_only()
        .column(ip_group_sites::Column::SiteId)
        .into_tuple()
        .all(&state.db)
        .await?;

    ip_group_sites::Entity::delete_many()
        .filter(ip_group_sites::Column::IpGroupId.eq(target))
        .exec(&state.db)
        .await?;

    let timestamp = chrono::Utc::now();
    for sid in &site_ids {
        let assoc = ip_group_sites::ActiveModel {
            ip_group_id: Set(target),
            site_id: Set(*sid),
            created_at: Set(timestamp),
        };
        assoc.insert(&state.db).await?;
    }

    tracing::info!(
        group_id = %target,
        site_count = payload.site_ids.len(),
        "IP group sites updated"
    );

    // Sites losing the association need the same push as the ones gaining
    // it: their bundles change in both directions.
    let mut affected = old_site_ids;
    affected.extend_from_slice(&site_ids);
    affected.sort();
    affected.dedup();
    for sid in affected {
        touch_site(&state, sid).await?;
        notify_config_changed(&state, sid, Some(&_current.email)).await;
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/v1/ip-groups/{group_id}/sync` — trigger a manual sync from the
/// subscription source. On failure the previous ranges are kept and the
/// upstream error is recorded in `last_sync_error` (and returned here).
async fn sync_now(
    State(state): State<AppState>,
    _current: AuthUser,
    Path(group_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_write(&_current)?;
    let target = parse_uuid(&group_id, "IP group id")?;
    let group = find_group(&state, target).await?;

    let updated = sync_subscription(&state, group, Some(&_current.email))
        .await
        .map_err(|message| {
            tracing::warn!(
                group_id = %target,
                error = %message,
                "manual IP group subscription sync failed"
            );
            ApiError::BadGateway(message)
        })?;

    tracing::info!(group_id = %target, "IP group sync completed");
    Ok(Json(serde_json::json!({
        "id": updated.id,
        "synced_at": updated.last_synced_at,
        "ip_count": updated.ip_ranges.len(),
    })))
}

/// Fetches the group's subscription source and persists the result.
///
/// `builtin` groups resolve against the snapshots compiled into the binary;
/// everything else fetches its `source_url` over HTTP. A failed sync never
/// touches `ip_ranges`: the group keeps serving its previous ranges and only
/// `last_sync_error` records the failure.
async fn sync_subscription(
    state: &AppState,
    group: ip_groups::Model,
    actor: Option<&str>,
) -> Result<ip_groups::Model, String> {
    let fetched: Result<Vec<String>, String> = match group
        .subscription_kind
        .as_deref()
    {
        Some(subscription_kind::BUILTIN) => {
            match crate::subscription::builtin_snapshot(group.id) {
                Some(snapshot) => Ok(snapshot
                    .ranges
                    .iter()
                    .map(|range| range.to_string())
                    .collect()),
                None => {
                    Err("built-in subscription group has no matching snapshot"
                        .to_string())
                },
            }
        },
        _ => {
            let source_url = match &group.source_url {
                Some(url) => url.clone(),
                None => {
                    return Err(
                        "IP group has no subscription source URL".to_string()
                    )
                },
            };
            let client = crate::subscription::subscription_client();
            crate::subscription::fetch_subscription_ranges(&client, &source_url)
                .await
        },
    };

    let mut active: ip_groups::ActiveModel = group.clone().into();
    match fetched {
        Ok(ranges) => {
            let changed = ranges != group.ip_ranges;
            active.ip_ranges = Set(ranges);
            active.last_synced_at = Set(Some(chrono::Utc::now()));
            active.last_sync_error = Set(None);
            active.updated_at = Set(chrono::Utc::now());
            let updated = active
                .update(&state.db)
                .await
                .map_err(|err| err.to_string())?;
            if changed {
                propagate_group_change(state, group.id, actor).await;
            }
            tracing::info!(
                group_id = %group.id,
                ip_count = updated.ip_ranges.len(),
                "IP group subscription synced"
            );
            Ok(updated)
        },
        Err(message) => {
            active.last_sync_error = Set(Some(message.clone()));
            active.updated_at = Set(chrono::Utc::now());
            if let Err(err) = active.update(&state.db).await {
                tracing::warn!(
                    group_id = %group.id,
                    error = %err,
                    "failed to record the IP group sync error"
                );
            }
            // A stale allow/block list is a silent security drift: alert so
            // an expired subscription URL is noticed. The notification dedup
            // window keeps the periodic retry from repeating it.
            crate::notify::emit(crate::notify::AlertEvent {
                event_type: crate::models::event_type::CONFIG_SYNC_FAILED
                    .to_string(),
                severity: crate::models::severity::WARNING,
                title: format!(
                    "IP group '{}' subscription sync failed",
                    group.name
                ),
                message: format!(
                    "Refreshing the IP group '{}' from {} failed: \
                     {message}. The group keeps serving its previous \
                     ranges.",
                    group.name,
                    group
                        .source_url
                        .as_deref()
                        .unwrap_or("its built-in snapshot")
                ),
                details: Some(serde_json::json!({
                    "group_id": group.id,
                    "source_url": group.source_url,
                    "error": message,
                })),
                dedup_key: Some(group.id.to_string()),
            })
            .await;
            Err(message)
        },
    }
}

/// Launches the background scheduler that refreshes subscriptions.
///
/// Every 60 seconds it syncs every enabled group that carries a subscription
/// (built-in snapshot or source URL) and a positive `sync_interval_minutes`
/// (`NULL` means manual-only) whose `last_synced_at` is older than the
/// interval — or that has never synced. The first tick fires immediately, so
/// a freshly seeded subscription populates right after boot without blocking
/// startup.
pub fn start_subscription_sync_scheduler(
    state: AppState,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(err) = sync_due_groups(&state).await {
                tracing::warn!(
                    error = %err,
                    "IP group subscription sweep failed"
                );
            }
        }
    })
}

/// Syncs every subscription whose refresh interval has elapsed.
async fn sync_due_groups(state: &AppState) -> Result<(), sea_orm::DbErr> {
    let candidates = ip_groups::Entity::find()
        .filter(ip_groups::Column::Enabled.eq(true))
        .filter(ip_groups::Column::SubscriptionEnabled.eq(true))
        // The raw source_url check keeps pre-0.25 URL groups (whose
        // subscription_kind is NULL) syncing after the upgrade.
        .filter(
            ip_groups::Column::SubscriptionKind
                .is_in([subscription_kind::BUILTIN, subscription_kind::URL])
                .or(ip_groups::Column::SourceUrl.is_not_null()),
        )
        .filter(ip_groups::Column::SyncIntervalMinutes.is_not_null())
        .all(&state.db)
        .await?;

    for group in candidates {
        let interval = group.sync_interval_minutes.unwrap_or(0);
        if interval <= 0 {
            continue;
        }
        let due = match group.last_synced_at {
            None => true,
            Some(last) => {
                chrono::Utc::now()
                    >= last + chrono::Duration::minutes(i64::from(interval))
            },
        };
        if !due {
            continue;
        }
        tracing::info!(
            group_id = %group.id,
            name = %group.name,
            "syncing IP group subscription"
        );
        if let Err(message) = sync_subscription(state, group, None).await {
            tracing::warn!(
                error = %message,
                "scheduled IP group subscription sync failed"
            );
        }
    }
    Ok(())
}

async fn find_group(
    state: &AppState,
    group_id: Uuid,
) -> Result<ip_groups::Model, ApiError> {
    ip_groups::Entity::find_by_id(group_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("IP group {group_id} not found"))
        })
}

/// Seeds the built-in subscription groups (Google, Yandex) on startup.
///
/// Idempotent: rows that already exist are left untouched, so operator edits
/// to a built-in group (action, enabled, ranges) survive restarts. The
/// snapshot ships with the binary, so the seeded ranges are current at
/// insert time and `last_synced_at` starts "now" — the daily scheduler then
/// rebuilds the ranges from the same snapshot on every release.
pub async fn seed_builtin_groups(
    db: &sea_orm::DatabaseConnection,
) -> Result<(), sea_orm::DbErr> {
    for snapshot in crate::subscription::BUILTIN_SNAPSHOTS {
        if ip_groups::Entity::find_by_id(snapshot.group_id)
            .one(db)
            .await?
            .is_some()
        {
            continue;
        }
        let now = chrono::Utc::now();
        ip_groups::ActiveModel {
            id: Set(snapshot.group_id),
            name: Set(snapshot.name.to_string()),
            description: Set(Some(snapshot.description.to_string())),
            ip_ranges: Set(snapshot
                .ranges
                .iter()
                .map(|range| range.to_string())
                .collect()),
            // The action is a starting point only: the ranges are vendor
            // infrastructure, and whether they mean "allow" or "block" is
            // the operator's call once a rule or gate references the group.
            action: Set(ip_group_action::ALLOW.to_string()),
            is_global: Set(true),
            subscription_kind: Set(Some(
                subscription_kind::BUILTIN.to_string(),
            )),
            subscription_enabled: Set(true),
            source_url: Set(None),
            sync_interval_minutes: Set(Some(1440)),
            last_synced_at: Set(Some(now)),
            last_sync_error: Set(None),
            enabled: Set(true),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await?;
        tracing::info!(
            group_id = %snapshot.group_id,
            name = snapshot.name,
            ip_count = snapshot.ranges.len(),
            "seeded built-in IP group subscription"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::role;

    /// Read-only roles must be refused on every mutating ip-groups endpoint.
    /// Each write handler starts with `require_write`, which renders as 403.
    #[test]
    fn readonly_roles_are_refused_on_write_endpoints() {
        for role_name in [role::VIEWER, role::AUDITOR] {
            let user =
                AuthUser::new(Uuid::new_v4(), "ro@example.com", role_name);
            let err = require_write(&user).unwrap_err();
            assert!(matches!(err, ApiError::Forbidden(_)));
            assert_eq!(err.status(), axum::http::StatusCode::FORBIDDEN);
        }
        let admin = AuthUser::new(Uuid::new_v4(), "a@example.com", role::ADMIN);
        assert!(require_write(&admin).is_ok());
    }
}
