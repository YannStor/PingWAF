//! WAF rule management: rule groups and the rules inside them.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Json;
use axum::Router;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Set,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::common::{
    load_site_read, load_site_write, non_empty, parse_uuid, Page, Pagination,
};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{action, mode, rule, rule_groups};

/// Maximum number of rows a list endpoint returns.
const MAX_TAGS: usize = 32;
/// Phases a rule group may run in.
const PHASES: [&str; 3] = ["request", "response", "custom"];

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
    pub group_id: Option<String>,
    pub enabled: Option<bool>,
    pub search: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default = "default_phase")]
    pub phase: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_phase() -> String {
    "request".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateGroupRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub expression: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_severity")]
    pub severity: i32,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub priority: i32,
}

fn default_action() -> String {
    action::BLOCK.to_string()
}

fn default_severity() -> i32 {
    3
}

fn default_mode() -> String {
    mode::BLOCK.to_string()
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateRuleRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    /// Setting this to `null` explicitly detaches the rule from its group.
    #[serde(default)]
    pub clear_group: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub expression: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub severity: Option<i32>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub priority: Option<i32>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/sites/{site_id}/rule-groups",
            get(list_groups).post(create_group),
        )
        .route(
            "/sites/{site_id}/rule-groups/{group_id}",
            put(update_group).delete(delete_group),
        )
        .route("/sites/{site_id}/rules", get(list_rules).post(create_rule))
        .route(
            "/sites/{site_id}/rules/{rule_id}",
            get(show_rule).put(update_rule).delete(delete_rule),
        )
        .route(
            "/sites/{site_id}/waf/defaults",
            axum::routing::post(seed_defaults),
        )
}

/// `POST /api/v1/sites/{site_id}/waf/defaults`
///
/// Re-adds any built-in rule that is missing from the site. Rules the operator
/// edited or deleted are left as they are — only absent ones come back.
async fn seed_defaults(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let inserted = crate::defaults::seed_waf_defaults(&state.db, id).await?;
    tracing::info!(site_id = %id, inserted, "built-in WAF rules restored");

    if inserted > 0 {
        touch_site(&state, id).await?;
        notify_config_changed(&state, id, Some(&current.email)).await;
    }

    Ok(Json(serde_json::json!({
        "inserted": inserted,
        "total": crate::defaults::waf_rules().len(),
    })))
}

/// Validates and normalises a tag list.
fn normalise_tags(tags: &[String]) -> Result<Vec<String>, ApiError> {
    if tags.len() > MAX_TAGS {
        return Err(ApiError::BadRequest(format!(
            "a rule may carry at most {MAX_TAGS} tags"
        )));
    }
    let mut out = Vec::with_capacity(tags.len());
    for tag in tags {
        let trimmed = tag.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() > 64 {
            return Err(ApiError::BadRequest(
                "tags must be at most 64 characters".to_string(),
            ));
        }
        if !out.iter().any(|existing: &String| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

fn validate_group(name: &str, phase: &str) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 100 {
        return Err(ApiError::BadRequest(
            "group name must be 1-100 characters".to_string(),
        ));
    }
    if !PHASES.contains(&phase) {
        return Err(ApiError::BadRequest(format!(
            "unknown phase '{phase}'; expected one of request, response, custom"
        )));
    }
    Ok(())
}

/// Upper bound on a rule expression (bytes): rules are compiled per site
/// on the data plane, and an unbounded expression is both a parsing cost
/// and a memory lever.
const MAX_EXPRESSION_LEN: usize = 8 * 1024;

fn validate_rule(
    name: &str,
    expression: &str,
    rule_action: &str,
    rule_mode: &str,
    severity: i32,
) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 200 {
        return Err(ApiError::BadRequest(
            "rule name must be 1-200 characters".to_string(),
        ));
    }
    if expression.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "expression must not be empty".to_string(),
        ));
    }
    if expression.len() > MAX_EXPRESSION_LEN {
        return Err(ApiError::BadRequest(format!(
            "expression must be at most {MAX_EXPRESSION_LEN} bytes"
        )));
    }
    // Reject unparsable expressions at the API boundary: the data plane
    // silently drops a rule whose expression fails to parse, so without
    // this check a rule looks enabled in the console while enforcing
    // nothing (2026-10-18 audit, high).
    pingwaf_waf::rules::expression::parse_expression(expression).map_err(
        |err| ApiError::BadRequest(format!("expression is not valid: {err}")),
    )?;
    if !action::is_valid(rule_action) {
        return Err(ApiError::BadRequest(format!(
            "unknown action '{rule_action}'"
        )));
    }
    if !mode::is_valid(rule_mode) {
        return Err(ApiError::BadRequest(format!(
            "unknown mode '{rule_mode}'"
        )));
    }
    if !(1..=5).contains(&severity) {
        return Err(ApiError::BadRequest(
            "severity must be between 1 and 5".to_string(),
        ));
    }
    Ok(())
}

/// `GET /api/v1/sites/{site_id}/rule-groups`
async fn list_groups(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<rule_groups::Model>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    let pagination = query.pagination.normalise();

    let paginator = rule_groups::Entity::find()
        .filter(rule_groups::Column::SiteId.eq(id))
        .order_by_asc(rule_groups::Column::Priority)
        .order_by_asc(rule_groups::Column::Name)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    Ok(Json(Page::new(rows, total, pagination)))
}

/// `POST /api/v1/sites/{site_id}/rule-groups`
async fn create_group(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;
    validate_group(&payload.name, &payload.phase)?;

    let timestamp = chrono::Utc::now();
    let model = rule_groups::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        name: Set(payload.name.trim().to_string()),
        phase: Set(payload.phase),
        priority: Set(payload.priority),
        enabled: Set(payload.enabled),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, group_id = %model.id, "rule group created");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// `PUT /api/v1/sites/{site_id}/rule-groups/{group_id}`
async fn update_group(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, group_id)): Path<(String, String)>,
    Json(payload): Json<UpdateGroupRequest>,
) -> Result<Json<rule_groups::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&group_id, "group id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_group(&state, id, target).await?;
    let mut active: rule_groups::ActiveModel = row.into();
    if let Some(name) = non_empty(&payload.name) {
        active.name = Set(name);
    }
    if let Some(phase) = non_empty(&payload.phase) {
        if !PHASES.contains(&phase.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown phase '{phase}'"
            )));
        }
        active.phase = Set(phase);
    }
    if let Some(priority) = payload.priority {
        active.priority = Set(priority);
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, group_id = %target, "rule group updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated))
}

/// `DELETE /api/v1/sites/{site_id}/rule-groups/{group_id}`
async fn delete_group(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, group_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&group_id, "group id")?;
    load_site_write(&state.db, id, &current).await?;
    find_group(&state, id, target).await?;

    // Rules are cascade-deleted by `fk_rules_group_id`.
    rule_groups::Entity::delete_by_id(target)
        .exec(&state.db)
        .await?;

    tracing::info!(site_id = %id, group_id = %target, "rule group deleted");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v1/sites/{site_id}/rules`
async fn list_rules(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<rule::Model>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    let pagination = query.pagination.normalise();

    let mut condition = Condition::all().add(rule::Column::SiteId.eq(id));
    if let Some(group) = non_empty(&query.group_id) {
        condition = condition
            .add(rule::Column::GroupId.eq(parse_uuid(&group, "group id")?));
    }
    if let Some(enabled) = query.enabled {
        condition = condition.add(rule::Column::Enabled.eq(enabled));
    }
    if let Some(search) = non_empty(&query.search) {
        let pattern = format!("%{}%", search.to_lowercase());
        condition = condition.add(
            Condition::any()
                .add(rule::Column::Name.like(&pattern))
                .add(rule::Column::Expression.like(&pattern)),
        );
    }

    let paginator = rule::Entity::find()
        .filter(condition)
        .order_by_asc(rule::Column::Priority)
        .order_by_asc(rule::Column::Name)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    Ok(Json(Page::new(rows, total, pagination)))
}

/// `POST /api/v1/sites/{site_id}/rules`
async fn create_rule(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreateRuleRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    validate_rule(
        &payload.name,
        &payload.expression,
        &payload.action,
        &payload.mode,
        payload.severity,
    )?;
    let tags = normalise_tags(&payload.tags)?;
    let group_id = match non_empty(&payload.group_id) {
        Some(raw) => {
            let parsed = parse_uuid(&raw, "group id")?;
            find_group(&state, id, parsed).await?;
            Some(parsed)
        },
        None => None,
    };

    let timestamp = chrono::Utc::now();
    let model = rule::ActiveModel {
        id: Set(Uuid::new_v4()),
        group_id: Set(group_id),
        site_id: Set(id),
        name: Set(payload.name.trim().to_string()),
        description: Set(non_empty(&payload.description)),
        expression: Set(payload.expression),
        action: Set(payload.action),
        severity: Set(payload.severity),
        tags: Set(tags),
        enabled: Set(payload.enabled),
        mode: Set(payload.mode),
        priority: Set(payload.priority),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, rule_id = %model.id, "rule created");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// `GET /api/v1/sites/{site_id}/rules/{rule_id}`
async fn show_rule(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
) -> Result<Json<rule::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "rule id")?;
    load_site_read(&state.db, id, &current).await?;
    Ok(Json(find_rule(&state, id, target).await?))
}

/// `PUT /api/v1/sites/{site_id}/rules/{rule_id}`
async fn update_rule(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
    Json(payload): Json<UpdateRuleRequest>,
) -> Result<Json<rule::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "rule id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_rule(&state, id, target).await?;
    let mut active: rule::ActiveModel = row.into();

    if let Some(name) = non_empty(&payload.name) {
        if name.len() > 200 {
            return Err(ApiError::BadRequest(
                "rule name must be at most 200 characters".to_string(),
            ));
        }
        active.name = Set(name);
    }
    if let Some(description) = payload.description {
        active.description = Set(non_empty(&Some(description)));
    }
    if let Some(expression) = non_empty(&payload.expression) {
        active.expression = Set(expression);
    }
    if let Some(rule_action) = non_empty(&payload.action) {
        if !action::is_valid(&rule_action) {
            return Err(ApiError::BadRequest(format!(
                "unknown action '{rule_action}'"
            )));
        }
        active.action = Set(rule_action);
    }
    if let Some(severity) = payload.severity {
        if !(1..=5).contains(&severity) {
            return Err(ApiError::BadRequest(
                "severity must be between 1 and 5".to_string(),
            ));
        }
        active.severity = Set(severity);
    }
    if let Some(tags) = payload.tags {
        active.tags = Set(normalise_tags(&tags)?);
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(rule_mode) = non_empty(&payload.mode) {
        if !mode::is_valid(&rule_mode) {
            return Err(ApiError::BadRequest(format!(
                "unknown mode '{rule_mode}'"
            )));
        }
        active.mode = Set(rule_mode);
    }
    if let Some(priority) = payload.priority {
        active.priority = Set(priority);
    }
    if payload.clear_group == Some(true) {
        active.group_id = Set(None);
    } else if let Some(group) = non_empty(&payload.group_id) {
        let parsed = parse_uuid(&group, "group id")?;
        find_group(&state, id, parsed).await?;
        active.group_id = Set(Some(parsed));
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, rule_id = %target, "rule updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated))
}

/// `DELETE /api/v1/sites/{site_id}/rules/{rule_id}`
async fn delete_rule(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "rule id")?;
    load_site_write(&state.db, id, &current).await?;
    find_rule(&state, id, target).await?;

    rule::Entity::delete_by_id(target).exec(&state.db).await?;

    tracing::info!(site_id = %id, rule_id = %target, "rule deleted");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Loads a rule group scoped to a site.
async fn find_group(
    state: &AppState,
    site_id: Uuid,
    group_id: Uuid,
) -> Result<rule_groups::Model, ApiError> {
    rule_groups::Entity::find_by_id(group_id)
        .filter(rule_groups::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("rule group {group_id} not found"))
        })
}

/// Loads a rule scoped to a site.
async fn find_rule(
    state: &AppState,
    site_id: Uuid,
    rule_id: Uuid,
) -> Result<rule::Model, ApiError> {
    rule::Entity::find_by_id(rule_id)
        .filter(rule::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("rule {rule_id} not found")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_trimmed_and_deduplicated() {
        let tags = normalise_tags(&[
            " sqli ".into(),
            "sqli".into(),
            "".into(),
            "owasp".into(),
        ])
        .unwrap();
        assert_eq!(tags, vec!["sqli".to_string(), "owasp".to_string()]);
        assert!(normalise_tags(&vec!["x".to_string(); MAX_TAGS + 1]).is_err());
    }

    #[test]
    fn group_validation_rejects_unknown_phases() {
        assert!(validate_group("default", "request").is_ok());
        assert!(validate_group("default", "response").is_ok());
        assert!(validate_group("default", "pre-request").is_err());
        assert!(validate_group("   ", "request").is_err());
    }

    #[test]
    fn rule_validation_covers_every_field() {
        assert!(validate_rule(
            "r",
            r#"http.request.method eq "POST""#,
            "block",
            "block",
            3
        )
        .is_ok());
        // `==` is not part of the expression grammar: such a rule used to be
        // accepted here and then silently dropped by the data plane.
        assert!(validate_rule("r", "ip.src == 1.2.3.4", "block", "block", 3)
            .is_err());
        assert!(validate_rule("r", "  ", "block", "block", 3).is_err());
        assert!(validate_rule("r", "true", "nuke", "block", 3).is_err());
        assert!(validate_rule("r", "true", "block", "enforce", 3).is_err());
        assert!(validate_rule("r", "true", "block", "block", 9).is_err());
    }

    #[test]
    fn defaults_match_the_schema() {
        assert_eq!(default_action(), action::BLOCK);
        assert_eq!(default_mode(), mode::BLOCK);
        assert_eq!(default_severity(), 3);
        assert_eq!(default_phase(), "request");
        assert!(default_true());
    }
}
