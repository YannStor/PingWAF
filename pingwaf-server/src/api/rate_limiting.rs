//! Rate limiting rule management.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Json;
use axum::Router;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::common::{
    load_site_read, load_site_write, non_empty, parse_uuid, Page, Pagination,
};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::api::validation::validate_optional_expression;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{action, characteristic, rate_limit_rules};

/// Sensible bounds so that a typo cannot turn into a denial of service against
/// the agents' counter store.
const MIN_PERIOD_SECONDS: i32 = 1;
const MAX_PERIOD_SECONDS: i32 = 86_400;
const MIN_THRESHOLD: i32 = 1;
const MAX_THRESHOLD: i32 = 10_000_000;
const MAX_MITIGATION_SECONDS: i32 = 86_400;

fn default_characteristics() -> Vec<String> {
    vec![characteristic::IP.to_string()]
}

fn default_period() -> i32 {
    60
}

fn default_threshold() -> i32 {
    100
}

fn default_action() -> String {
    action::BLOCK.to_string()
}

fn default_mitigation() -> i32 {
    300
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
    pub expression: String,
    #[serde(default = "default_characteristics")]
    pub characteristics: Vec<String>,
    #[serde(default = "default_period")]
    pub period_seconds: i32,
    #[serde(default = "default_threshold")]
    pub threshold: i32,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_mitigation")]
    pub mitigation_timeout_seconds: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub expression: Option<String>,
    #[serde(default)]
    pub characteristics: Option<Vec<String>>,
    #[serde(default)]
    pub period_seconds: Option<i32>,
    #[serde(default)]
    pub threshold: Option<i32>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub mitigation_timeout_seconds: Option<i32>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub priority: Option<i32>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/rate-limit-rules", get(list).post(create))
        .route(
            "/sites/{site_id}/rate-limit-rules/{rule_id}",
            put(update).delete(remove),
        )
}

fn normalise_characteristics(raw: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::new();
    for value in raw {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Keep the parameter's case for cookie and query (their names match
        // case-sensitively at the edge); header names are matched
        // case-insensitively, so their parameter is lowercased to dedup.
        let (kind, param) = match trimmed.split_once(':') {
            Some((kind, param)) => {
                (kind.trim().to_lowercase(), Some(param.trim()))
            },
            None => (trimmed.to_lowercase(), None),
        };
        let candidate = match (kind.as_str(), param) {
            (characteristic::HEADER, Some(p)) if !p.is_empty() => {
                format!("{kind}:{}", p.to_lowercase())
            },
            (_, Some(p)) if !p.is_empty() => format!("{kind}:{p}"),
            _ => kind.clone(),
        };
        if matches!(candidate.as_str(), "header" | "cookie" | "query") {
            return Err(ApiError::BadRequest(format!(
                "characteristic '{candidate}' requires a parameter name \
                 (e.g. '{candidate}:lang')"
            )));
        }
        if !characteristic::is_valid(&candidate) {
            return Err(ApiError::BadRequest(format!(
                "unknown rate limit characteristic '{candidate}'"
            )));
        }
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    if out.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one characteristic is required".to_string(),
        ));
    }
    Ok(out)
}

fn validate(
    name: &str,
    rule_action: &str,
    period: i32,
    threshold: i32,
    mitigation: i32,
) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 200 {
        return Err(ApiError::BadRequest(
            "name must be 1-200 characters".to_string(),
        ));
    }
    if !action::is_valid(rule_action) {
        return Err(ApiError::BadRequest(format!(
            "unknown action '{rule_action}'"
        )));
    }
    if !(MIN_PERIOD_SECONDS..=MAX_PERIOD_SECONDS).contains(&period) {
        return Err(ApiError::BadRequest(format!(
            "period_seconds must be between {MIN_PERIOD_SECONDS} and {MAX_PERIOD_SECONDS}"
        )));
    }
    if !(MIN_THRESHOLD..=MAX_THRESHOLD).contains(&threshold) {
        return Err(ApiError::BadRequest(format!(
            "threshold must be between {MIN_THRESHOLD} and {MAX_THRESHOLD}"
        )));
    }
    if !(0..=MAX_MITIGATION_SECONDS).contains(&mitigation) {
        return Err(ApiError::BadRequest(format!(
            "mitigation_timeout_seconds must be between 0 and {MAX_MITIGATION_SECONDS}"
        )));
    }
    Ok(())
}

/// `GET /api/v1/sites/{site_id}/rate-limit-rules`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<rate_limit_rules::Model>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    let pagination = query.pagination.normalise();

    let paginator = rate_limit_rules::Entity::find()
        .filter(rate_limit_rules::Column::SiteId.eq(id))
        .order_by_asc(rate_limit_rules::Column::Priority)
        .order_by_asc(rate_limit_rules::Column::Name)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    Ok(Json(Page::new(rows, total, pagination)))
}

/// `POST /api/v1/sites/{site_id}/rate-limit-rules`
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
        &payload.action,
        payload.period_seconds,
        payload.threshold,
        payload.mitigation_timeout_seconds,
    )?;
    let characteristics = normalise_characteristics(&payload.characteristics)?;
    // A rate-limit expression is optional (blank = every request for the
    // site), but a present one is compiled on the data plane, which drops the
    // whole rule when it fails to parse — so it is validated here, the same way
    // the update path does (2026-10-19 audit, D05).
    validate_optional_expression(&payload.expression)?;

    let timestamp = chrono::Utc::now();
    let model = rate_limit_rules::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        name: Set(payload.name.trim().to_string()),
        expression: Set(payload.expression),
        characteristics: Set(characteristics),
        period_seconds: Set(payload.period_seconds),
        threshold: Set(payload.threshold),
        action: Set(payload.action),
        mitigation_timeout_seconds: Set(payload.mitigation_timeout_seconds),
        enabled: Set(payload.enabled),
        priority: Set(payload.priority),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, rule_id = %model.id, "rate limit rule created");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// `PUT /api/v1/sites/{site_id}/rate-limit-rules/{rule_id}`
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
    Json(payload): Json<UpdateRequest>,
) -> Result<Json<rate_limit_rules::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "rate limit rule id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find(&state, id, target).await?;
    let mut active: rate_limit_rules::ActiveModel = row.into();

    if let Some(name) = non_empty(&payload.name) {
        if name.len() > 200 {
            return Err(ApiError::BadRequest(
                "name must be at most 200 characters".to_string(),
            ));
        }
        active.name = Set(name);
    }
    if let Some(expression) = payload.expression {
        validate_optional_expression(&expression)?;
        active.expression = Set(expression);
    }
    if let Some(characteristics) = payload.characteristics {
        active.characteristics =
            Set(normalise_characteristics(&characteristics)?);
    }
    if let Some(period) = payload.period_seconds {
        if !(MIN_PERIOD_SECONDS..=MAX_PERIOD_SECONDS).contains(&period) {
            return Err(ApiError::BadRequest(format!(
                "period_seconds must be between {MIN_PERIOD_SECONDS} and {MAX_PERIOD_SECONDS}"
            )));
        }
        active.period_seconds = Set(period);
    }
    if let Some(threshold) = payload.threshold {
        if !(MIN_THRESHOLD..=MAX_THRESHOLD).contains(&threshold) {
            return Err(ApiError::BadRequest(format!(
                "threshold must be between {MIN_THRESHOLD} and {MAX_THRESHOLD}"
            )));
        }
        active.threshold = Set(threshold);
    }
    if let Some(rule_action) = non_empty(&payload.action) {
        if !action::is_valid(&rule_action) {
            return Err(ApiError::BadRequest(format!(
                "unknown action '{rule_action}'"
            )));
        }
        active.action = Set(rule_action);
    }
    if let Some(mitigation) = payload.mitigation_timeout_seconds {
        if !(0..=MAX_MITIGATION_SECONDS).contains(&mitigation) {
            return Err(ApiError::BadRequest(format!(
                "mitigation_timeout_seconds must be between 0 and {MAX_MITIGATION_SECONDS}"
            )));
        }
        active.mitigation_timeout_seconds = Set(mitigation);
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(priority) = payload.priority {
        active.priority = Set(priority);
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, rule_id = %target, "rate limit rule updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated))
}

/// `DELETE /api/v1/sites/{site_id}/rate-limit-rules/{rule_id}`
async fn remove(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, rule_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&rule_id, "rate limit rule id")?;
    load_site_write(&state.db, id, &current).await?;
    find(&state, id, target).await?;

    rate_limit_rules::Entity::delete_by_id(target)
        .exec(&state.db)
        .await?;

    tracing::info!(site_id = %id, rule_id = %target, "rate limit rule deleted");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn find(
    state: &AppState,
    site_id: Uuid,
    rule_id: Uuid,
) -> Result<rate_limit_rules::Model, ApiError> {
    rate_limit_rules::Entity::find_by_id(rule_id)
        .filter(rate_limit_rules::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("rate limit rule {rule_id} not found"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn characteristics_are_normalised() {
        let out = normalise_characteristics(&[
            "IP".into(),
            " ip ".into(),
            "path".into(),
        ])
        .unwrap();
        assert_eq!(out, vec!["ip".to_string(), "path".to_string()]);
        assert!(normalise_characteristics(&["unknown".into()]).is_err());
        assert!(normalise_characteristics(&[]).is_err());
    }

    #[test]
    fn parameterized_characteristics_keep_the_param_case() {
        let out = normalise_characteristics(&[
            "Header: X-Api-Key ".into(),
            "header:x-api-key".into(),
            "cookie:Session".into(),
        ])
        .unwrap();
        assert_eq!(
            out,
            vec!["header:x-api-key".to_string(), "cookie:Session".to_string()]
        );
        // Bare kinds carry no key to count on and are rejected.
        assert!(normalise_characteristics(&["header".into()]).is_err());
        assert!(normalise_characteristics(&["cookie:".into()]).is_err());
        assert!(normalise_characteristics(&["query:has space".into()]).is_err());
        assert!(normalise_characteristics(&["host:nope".into()]).is_err());
    }

    #[test]
    fn bounds_are_enforced() {
        assert!(validate("login", "block", 60, 100, 300).is_ok());
        assert!(validate("login", "block", 0, 100, 300).is_err());
        assert!(validate("login", "block", 60, 0, 300).is_err());
        assert!(validate("login", "block", 60, 100, -1).is_err());
        assert!(validate("login", "drop", 60, 100, 300).is_err());
        assert!(validate("", "block", 60, 100, 300).is_err());
    }

    #[test]
    fn defaults_match_the_schema() {
        assert_eq!(default_characteristics(), vec!["ip".to_string()]);
        assert_eq!(default_period(), 60);
        assert_eq!(default_threshold(), 100);
        assert_eq!(default_mitigation(), 300);
        assert_eq!(default_action(), action::BLOCK);
        assert!(default_true());
    }
}
