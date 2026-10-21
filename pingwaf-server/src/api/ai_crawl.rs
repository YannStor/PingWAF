//! AI crawler control: catalogue, per-site policy, and the generated
//! robots.txt / llms.txt bodies.
//!
//! Cloudflare's AI Crawl Control answers two questions for a site: which AI
//! crawlers fetch it, and what should happen to each one. PingWAF implements
//! the same model on the site it already knows:
//!
//! * the catalogue ([`AI_BOTS`]) is a control-plane constant — the data plane
//!   receives matching patterns with the rule bundle, so no crawler list is
//!   compiled into the agent;
//! * a per-site row holds the default action and the two generated files;
//! * a per-family row overrides the default for one crawler.
//!
//! The generated files are rendered here, at configuration-build time, and
//! pushed as text: the data plane answers `/robots.txt` and `/llms.txt` from
//! an exact-path `mock` location (see `src/pingwaf.rs`), so neither file costs
//! anything on the request path.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{
    load_site_read, load_site_write, non_empty, parse_uuid, require_write,
};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{
    site_ai_bot_policies as policy_model,
    site_ai_crawl_settings as settings_model,
};

/// Largest generated (or operator-supplied) file, in bytes.
pub const MAX_FILE_BYTES: usize = 64 * 1024;

/// One AI crawler family.
#[derive(Debug, Clone, Copy)]
pub struct AiBot {
    /// Stable id used in the API and the policy table.
    pub id: &'static str,
    /// Company that runs the crawler.
    pub operator: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// `training` / `search` / `agent` / `other`.
    pub category: &'static str,
    /// Lowercase UA substrings that identify it.
    pub ua_substrings: &'static [&'static str],
}

/// The crawler families PingWAF recognises.
///
/// A single source of truth: the dashboard lists it, the data plane receives
/// the patterns, and the generated files name the families from it.
pub const AI_BOTS: &[AiBot] = &[
    AiBot {
        id: "gptbot",
        operator: "OpenAI",
        name: "GPTBot",
        category: "training",
        ua_substrings: &["gptbot"],
    },
    AiBot {
        id: "oai-searchbot",
        operator: "OpenAI",
        name: "OAI-SearchBot",
        category: "search",
        ua_substrings: &["oai-searchbot"],
    },
    AiBot {
        id: "chatgpt-user",
        operator: "OpenAI",
        name: "ChatGPT-User",
        category: "agent",
        ua_substrings: &["chatgpt-user"],
    },
    AiBot {
        id: "claudebot",
        operator: "Anthropic",
        name: "ClaudeBot",
        category: "training",
        ua_substrings: &["claudebot"],
    },
    AiBot {
        id: "claude-user",
        operator: "Anthropic",
        name: "Claude-User",
        category: "agent",
        ua_substrings: &["claude-user"],
    },
    AiBot {
        id: "anthropic-ai",
        operator: "Anthropic",
        name: "anthropic-ai",
        category: "training",
        ua_substrings: &["anthropic-ai"],
    },
    AiBot {
        id: "perplexitybot",
        operator: "Perplexity",
        name: "PerplexityBot",
        category: "search",
        ua_substrings: &["perplexitybot"],
    },
    AiBot {
        id: "google-extended",
        operator: "Google",
        name: "Google-Extended",
        category: "training",
        ua_substrings: &["google-extended"],
    },
    AiBot {
        id: "applebot-extended",
        operator: "Apple",
        name: "Applebot-Extended",
        category: "training",
        ua_substrings: &["applebot-extended"],
    },
    AiBot {
        id: "ccbot",
        operator: "Common Crawl",
        name: "CCBot",
        category: "training",
        ua_substrings: &["ccbot"],
    },
    AiBot {
        id: "bytespider",
        operator: "ByteDance",
        name: "Bytespider",
        category: "training",
        ua_substrings: &["bytespider"],
    },
    AiBot {
        id: "amazonbot",
        operator: "Amazon",
        name: "Amazonbot",
        category: "search",
        ua_substrings: &["amazonbot"],
    },
    AiBot {
        id: "meta-externalagent",
        operator: "Meta",
        name: "Meta-ExternalAgent",
        category: "training",
        // `facebookexternalhit` is a link-preview fetcher, not a training
        // crawler: matching it here would block previews when an operator
        // blocks training. It is listed as its own `other` family so it can
        // be observed and allowed independently.
        ua_substrings: &["meta-externalagent"],
    },
    AiBot {
        id: "facebookexternalhit",
        operator: "Meta",
        name: "FacebookExternalHit",
        category: "other",
        ua_substrings: &["facebookexternalhit"],
    },
    AiBot {
        id: "cohere-ai",
        operator: "Cohere",
        name: "cohere-ai",
        category: "training",
        ua_substrings: &["cohere-ai"],
    },
    AiBot {
        id: "youbot",
        operator: "You.com",
        name: "YouBot",
        category: "search",
        ua_substrings: &["youbot"],
    },
    AiBot {
        id: "diffbot",
        operator: "Diffbot",
        name: "Diffbot",
        category: "other",
        ua_substrings: &["diffbot"],
    },
    AiBot {
        id: "imagesiftbot",
        operator: "ImageSift",
        name: "ImagesiftBot",
        category: "training",
        ua_substrings: &["imagesiftbot"],
    },
    AiBot {
        id: "timpibot",
        operator: "Timpi",
        name: "Timpibot",
        category: "training",
        ua_substrings: &["timpibot"],
    },
];

/// Looks a family up by id.
pub fn find_bot(id: &str) -> Option<&'static AiBot> {
    AI_BOTS.iter().find(|bot| bot.id == id)
}

const ACTIONS: [&str; 4] = ["inherit", "allow", "monitor", "block"];
const DEFAULT_ACTIONS: [&str; 3] = ["allow", "monitor", "block"];
const FILE_MODES: [&str; 2] = ["off", "generate"];

/// Catalogue row sent to the dashboard.
#[derive(Debug, Serialize)]
pub struct AiBotView {
    pub id: &'static str,
    pub operator: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub ua_substrings: &'static [&'static str],
}

impl From<&AiBot> for AiBotView {
    fn from(bot: &AiBot) -> Self {
        Self {
            id: bot.id,
            operator: bot.operator,
            name: bot.name,
            category: bot.category,
            ua_substrings: bot.ua_substrings,
        }
    }
}

/// Per-family override.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiBotPolicyView {
    pub bot_id: String,
    pub action: String,
}

/// Everything the dashboard needs to render the card.
#[derive(Debug, Serialize)]
pub struct AiCrawlSettingsResponse {
    pub enabled: bool,
    pub default_action: String,
    pub robots_mode: String,
    pub robots_body: String,
    pub llms_mode: String,
    pub llms_body: String,
    pub llms_include_routes: bool,
    pub cache_max_age: i32,
    pub content_signal_search: bool,
    pub content_signal_ai_train: bool,
    pub content_signal_ai_input: bool,
    pub policies: Vec<AiBotPolicyView>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateAiCrawlSettingsRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub default_action: Option<String>,
    #[serde(default)]
    pub robots_mode: Option<String>,
    #[serde(default)]
    pub robots_body: Option<String>,
    #[serde(default)]
    pub llms_mode: Option<String>,
    #[serde(default)]
    pub llms_body: Option<String>,
    #[serde(default)]
    pub llms_include_routes: Option<bool>,
    #[serde(default)]
    pub cache_max_age: Option<i32>,
    #[serde(default)]
    pub content_signal_search: Option<bool>,
    #[serde(default)]
    pub content_signal_ai_train: Option<bool>,
    #[serde(default)]
    pub content_signal_ai_input: Option<bool>,
    /// Replaces the whole override set when present.
    #[serde(default)]
    pub policies: Option<Vec<AiBotPolicyView>>,
}

#[derive(Debug, Deserialize)]
pub struct PreviewQuery {
    /// `robots` or `llms`.
    #[serde(default)]
    pub file: Option<String>,
}

/// The settings row with the defaults a site starts from.
#[derive(Debug, Clone)]
pub struct AiCrawlSettings {
    pub enabled: bool,
    pub default_action: String,
    pub robots_mode: String,
    pub robots_body: String,
    pub llms_mode: String,
    pub llms_body: String,
    pub llms_include_routes: bool,
    pub cache_max_age: i32,
    pub content_signal_search: bool,
    pub content_signal_ai_train: bool,
    pub content_signal_ai_input: bool,
}

impl Default for AiCrawlSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            default_action: "monitor".to_string(),
            robots_mode: "off".to_string(),
            robots_body: String::new(),
            llms_mode: "off".to_string(),
            llms_body: String::new(),
            llms_include_routes: true,
            cache_max_age: 3600,
            content_signal_search: true,
            content_signal_ai_train: false,
            content_signal_ai_input: false,
        }
    }
}

impl AiCrawlSettings {
    fn from_model(model: settings_model::Model) -> Self {
        Self {
            enabled: model.enabled,
            default_action: model.default_action,
            robots_mode: model.robots_mode,
            robots_body: model.robots_body,
            llms_mode: model.llms_mode,
            llms_body: model.llms_body,
            llms_include_routes: model.llms_include_routes,
            cache_max_age: model.cache_max_age,
            content_signal_search: model.content_signal_search,
            content_signal_ai_train: model.content_signal_ai_train,
            content_signal_ai_input: model.content_signal_ai_input,
        }
    }
}

/// Loads the site's policy row, or the defaults when it has none.
pub async fn load_settings<C: sea_orm::ConnectionTrait>(
    db: &C,
    site_id: Uuid,
) -> Result<AiCrawlSettings, ApiError> {
    let row = settings_model::Entity::find()
        .filter(settings_model::Column::SiteId.eq(site_id))
        .one(db)
        .await?;
    Ok(row.map(AiCrawlSettings::from_model)
        .unwrap_or_default())
}

/// Loads the per-family overrides.
pub async fn load_policies<C: sea_orm::ConnectionTrait>(
    db: &C,
    site_id: Uuid,
) -> Result<Vec<AiBotPolicyView>, ApiError> {
    let rows = policy_model::Entity::find()
        .filter(policy_model::Column::SiteId.eq(site_id))
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| AiBotPolicyView {
            bot_id: row.bot_id,
            action: row.action,
        })
        .collect())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/ai-crawl/catalog", get(catalog))
        .route(
            "/sites/{site_id}/ai-crawl",
            get(get_settings).put(update_settings),
        )
        .route("/sites/{site_id}/ai-crawl/preview", get(preview))
}

async fn catalog() -> Json<Vec<AiBotView>> {
    Json(AI_BOTS.iter().map(AiBotView::from).collect())
}

async fn get_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<AiCrawlSettingsResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    let settings = load_settings(&state.db, id).await?;
    let policies = load_policies(&state.db, id).await?;
    Ok(Json(AiCrawlSettingsResponse {
        enabled: settings.enabled,
        default_action: settings.default_action,
        robots_mode: settings.robots_mode,
        robots_body: settings.robots_body,
        llms_mode: settings.llms_mode,
        llms_body: settings.llms_body,
        llms_include_routes: settings.llms_include_routes,
        cache_max_age: settings.cache_max_age,
        content_signal_search: settings.content_signal_search,
        content_signal_ai_train: settings.content_signal_ai_train,
        content_signal_ai_input: settings.content_signal_ai_input,
        policies,
    }))
}

async fn update_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateAiCrawlSettingsRequest>,
) -> Result<Json<AiCrawlSettingsResponse>, ApiError> {
    require_write(&current)?;
    let id = parse_uuid(&site_id, "site id")?;
    // Write access and existence in one check; the row itself is not needed.
    load_site_write(&state.db, id, &current).await?;

    let mut next = load_settings(&state.db, id).await?;
    if let Some(value) = payload.enabled {
        next.enabled = value;
    }
    if let Some(raw) = non_empty(&payload.default_action) {
        if !DEFAULT_ACTIONS.contains(&raw.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown default_action '{raw}' (allowed: {})",
                DEFAULT_ACTIONS.join(", ")
            )));
        }
        next.default_action = raw;
    }
    if let Some(raw) = non_empty(&payload.robots_mode) {
        next.robots_mode = check_mode(&raw, "robots_mode")?;
    }
    if let Some(raw) = non_empty(&payload.llms_mode) {
        next.llms_mode = check_mode(&raw, "llms_mode")?;
    }
    if let Some(raw) = payload.robots_body {
        next.robots_body = check_body(&raw, "robots_body")?;
    }
    if let Some(raw) = payload.llms_body {
        next.llms_body = check_body(&raw, "llms_body")?;
    }
    if let Some(value) = payload.llms_include_routes {
        next.llms_include_routes = value;
    }
    if let Some(value) = payload.cache_max_age {
        if !(0..=86_400).contains(&value) {
            return Err(ApiError::BadRequest(
                "cache_max_age must be between 0 and 86400".to_string(),
            ));
        }
        next.cache_max_age = value;
    }
    if let Some(value) = payload.content_signal_search {
        next.content_signal_search = value;
    }
    if let Some(value) = payload.content_signal_ai_train {
        next.content_signal_ai_train = value;
    }
    if let Some(value) = payload.content_signal_ai_input {
        next.content_signal_ai_input = value;
    }

    let policies = match payload.policies {
        Some(items) => validate_policies(items)?,
        None => load_policies(&state.db, id).await?,
    };

    persist(&state, id, &next, &policies).await?;
    crate::api::sites::touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(AiCrawlSettingsResponse {
        enabled: next.enabled,
        default_action: next.default_action,
        robots_mode: next.robots_mode,
        robots_body: next.robots_body,
        llms_mode: next.llms_mode,
        llms_body: next.llms_body,
        llms_include_routes: next.llms_include_routes,
        cache_max_age: next.cache_max_age,
        content_signal_search: next.content_signal_search,
        content_signal_ai_train: next.content_signal_ai_train,
        content_signal_ai_input: next.content_signal_ai_input,
        policies,
    }))
}

async fn preview(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Query(query): Query<PreviewQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let site = load_site_read(&state.db, id, &current).await?;
    let settings = load_settings(&state.db, id).await?;
    let policies = load_policies(&state.db, id).await?;
    let routes = crate::models::site_routes::Entity::find()
        .filter(crate::models::site_routes::Column::SiteId.eq(id))
        .all(&state.db)
        .await
        .unwrap_or_default();

    let want_llms = query
        .file
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("llms"));
    let (mode, body) = if want_llms {
        (
            settings.llms_mode.clone(),
            render_llms(&settings, &policies, &site, &routes),
        )
    } else {
        (
            settings.robots_mode.clone(),
            render_robots(&settings, &policies, &site.domain),
        )
    };
    Ok(Json(serde_json::json!({
        "mode": mode,
        "content_type": "text/plain; charset=utf-8",
        "body": body,
    })))
}

/// Validates a file mode.
fn check_mode(raw: &str, field: &str) -> Result<String, ApiError> {
    if !FILE_MODES.contains(&raw) {
        return Err(ApiError::BadRequest(format!(
            "unknown {field} '{raw}' (allowed: {})",
            FILE_MODES.join(", ")
        )));
    }
    Ok(raw.to_string())
}

/// Trims a body to the storage ceiling and strips CR so the file cannot carry
/// a header injection into the `mock` response.
fn check_body(raw: &str, field: &str) -> Result<String, ApiError> {
    if raw.len() > MAX_FILE_BYTES {
        return Err(ApiError::BadRequest(format!(
            "{field} must be at most {MAX_FILE_BYTES} bytes"
        )));
    }
    Ok(raw.replace('\r', ""))
}

/// Validates the override set: known families only, one row per family.
fn validate_policies(
    items: Vec<AiBotPolicyView>,
) -> Result<Vec<AiBotPolicyView>, ApiError> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let bot_id = item.bot_id.trim().to_ascii_lowercase();
        if find_bot(&bot_id).is_none() {
            return Err(ApiError::BadRequest(format!(
                "unknown AI crawler '{bot_id}'"
            )));
        }
        if !ACTIONS.contains(&item.action.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown action '{}' (allowed: {})",
                item.action,
                ACTIONS.join(", ")
            )));
        }
        if !seen.insert(bot_id.clone()) {
            return Err(ApiError::BadRequest(format!(
                "duplicate policy for '{bot_id}'"
            )));
        }
        out.push(AiBotPolicyView {
            bot_id,
            action: item.action,
        });
    }
    Ok(out)
}

/// Upserts the settings row and replaces the override set in one transaction.
async fn persist(
    state: &AppState,
    site_id: Uuid,
    settings: &AiCrawlSettings,
    policies: &[AiBotPolicyView],
) -> Result<(), ApiError> {
    use sea_orm::TransactionTrait;
    let txn = state.db.begin().await?;
    let existing = settings_model::Entity::find()
        .filter(settings_model::Column::SiteId.eq(site_id))
        .one(&txn)
        .await?;
    match existing {
        Some(row) => {
            let mut active: settings_model::ActiveModel = row.into();
            active.enabled = Set(settings.enabled);
            active.default_action = Set(settings.default_action.clone());
            active.robots_mode = Set(settings.robots_mode.clone());
            active.robots_body = Set(settings.robots_body.clone());
            active.llms_mode = Set(settings.llms_mode.clone());
            active.llms_body = Set(settings.llms_body.clone());
            active.llms_include_routes = Set(settings.llms_include_routes);
            active.cache_max_age = Set(settings.cache_max_age);
            active.content_signal_search = Set(settings.content_signal_search);
            active.content_signal_ai_train =
                Set(settings.content_signal_ai_train);
            active.content_signal_ai_input =
                Set(settings.content_signal_ai_input);
            active.updated_at = Set(Utc::now());
            active.update(&txn).await?;
        },
        None => {
            let active = settings_model::ActiveModel {
                id: Set(Uuid::new_v4()),
                site_id: Set(site_id),
                enabled: Set(settings.enabled),
                default_action: Set(settings.default_action.clone()),
                robots_mode: Set(settings.robots_mode.clone()),
                robots_body: Set(settings.robots_body.clone()),
                llms_mode: Set(settings.llms_mode.clone()),
                llms_body: Set(settings.llms_body.clone()),
                llms_include_routes: Set(settings.llms_include_routes),
                cache_max_age: Set(settings.cache_max_age),
                content_signal_search: Set(settings.content_signal_search),
                content_signal_ai_train: Set(settings.content_signal_ai_train),
                content_signal_ai_input: Set(settings.content_signal_ai_input),
                created_at: Set(Utc::now()),
                updated_at: Set(Utc::now()),
            };
            active.insert(&txn).await?;
        },
    }

    // The override set is replaced wholesale: a removed family must stop
    // being enforced, and an upsert per row cannot express that.
    policy_model::Entity::delete_many()
        .filter(policy_model::Column::SiteId.eq(site_id))
        .exec(&txn)
        .await?;
    for item in policies {
        let active = policy_model::ActiveModel {
            id: Set(Uuid::new_v4()),
            site_id: Set(site_id),
            bot_id: Set(item.bot_id.clone()),
            action: Set(item.action.clone()),
            created_at: Set(Utc::now()),
        };
        active.insert(&txn).await?;
    }

    txn.commit().await?;
    Ok(())
}

/// The `User-agent` line a family is addressed by.
fn family_token(bot: &AiBot) -> &'static str {
    bot.name
}

/// Collapses control characters a route path or site name could carry, so a
/// rendered file keeps one entry per line (no forged list items or headings).
fn plain(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

/// Renders robots.txt: a block per overridden family, then the wildcard rule
/// and the Content Signals line.
pub fn render_robots(
    settings: &AiCrawlSettings,
    policies: &[AiBotPolicyView],
    domain: &str,
) -> String {
    let mut out = String::new();
    out.push_str("# Generated by PingWAF\n");
    out.push_str(&format!("# Site: {}\n\n", plain(domain)));

    for policy in policies {
        let Some(bot) = find_bot(&policy.bot_id) else {
            continue;
        };
        let action = if policy.action == "inherit" {
            settings.default_action.as_str()
        } else {
            policy.action.as_str()
        };
        out.push_str(&format!("User-agent: {}\n", family_token(bot)));
        match action {
            "block" => out.push_str("Disallow: /\n\n"),
            "allow" | "monitor" => out.push_str("Allow: /\n\n"),
            _ => out.push_str("Allow: /\n\n"),
        }
    }

    out.push_str("User-agent: *\n");
    match settings.default_action.as_str() {
        "block" => out.push_str("Disallow: /\n"),
        _ => out.push_str("Allow: /\n"),
    }
    if settings.content_signal_search
        || settings.content_signal_ai_train
        || settings.content_signal_ai_input
    {
        out.push_str(&format!(
            "\nContent-Signal: search={}, ai-train={}, ai-input={}\n",
            yes_no(settings.content_signal_search),
            yes_no(settings.content_signal_ai_train),
            yes_no(settings.content_signal_ai_input),
        ));
    }
    out
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Renders llms.txt: a title, a summary and the site's routes as links.
pub fn render_llms(
    settings: &AiCrawlSettings,
    policies: &[AiBotPolicyView],
    site: &crate::models::site::Model,
    routes: &[crate::models::site_routes::Model],
) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", plain(&site.name)));
    out.push_str(&format!(
        "> {} is served by {}. AI crawlers are governed by the site's \
         robots.txt and AI crawl policy.\n\n",
        plain(&site.domain),
        plain(&site.name)
    ));

    if !policies.is_empty() {
        out.push_str("## AI crawler policy\n\n");
        for policy in policies {
            if let Some(bot) = find_bot(&policy.bot_id) {
                let action = if policy.action == "inherit" {
                    settings.default_action.as_str()
                } else {
                    policy.action.as_str()
                };
                out.push_str(&format!(
                    "- {} ({}, {}): {action}\n",
                    bot.name, bot.operator, bot.category
                ));
            }
        }
        out.push('\n');
    }

    if settings.llms_include_routes {
        out.push_str("## Pages\n\n");
        let scheme = if site.domain.starts_with("http") {
            String::new()
        } else {
            "https://".to_string()
        };
        let mut seen = std::collections::HashSet::new();
        for route in routes.iter().filter(|route| route.enabled) {
            let path = if route.path.is_empty() {
                "/".to_string()
            } else {
                route.path.clone()
            };
            if !seen.insert(path.clone()) {
                continue;
            }
            let path = plain(&path);
            out.push_str(&format!(
                "- [{path}]({scheme}{}{path})\n",
                plain(&site.domain)
            ));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> AiCrawlSettings {
        AiCrawlSettings {
            enabled: true,
            ..AiCrawlSettings::default()
        }
    }

    #[test]
    fn catalogue_ids_and_patterns_are_unique() {
        let mut ids = std::collections::HashSet::new();
        let mut patterns = std::collections::HashSet::new();
        for bot in AI_BOTS {
            assert!(ids.insert(bot.id), "duplicate id {}", bot.id);
            assert!(!bot.ua_substrings.is_empty(), "{} has no pattern", bot.id);
            for pattern in bot.ua_substrings {
                assert_eq!(
                    *pattern,
                    pattern.to_ascii_lowercase(),
                    "patterns must be lowercase"
                );
                assert!(
                    patterns.insert(*pattern),
                    "duplicate pattern {pattern}"
                );
            }
        }
        assert!(AI_BOTS.len() >= 18, "the catalogue should cover the majors");
    }

    #[test]
    fn robots_blocks_overridden_families_and_states_content_signals() {
        let body = render_robots(
            &settings(),
            &[
                AiBotPolicyView {
                    bot_id: "gptbot".to_string(),
                    action: "block".to_string(),
                },
                AiBotPolicyView {
                    bot_id: "claudebot".to_string(),
                    action: "allow".to_string(),
                },
            ],
            "example.com",
        );
        assert!(body.contains("User-agent: GPTBot\nDisallow: /\n"));
        assert!(body.contains("User-agent: ClaudeBot\nAllow: /\n"));
        assert!(body.contains("Content-Signal: search=yes, ai-train=no"));
        assert!(body.contains("User-agent: *"));
    }

    #[test]
    fn policies_are_validated_against_the_catalogue() {
        assert!(
            validate_policies(vec![AiBotPolicyView {
                bot_id: "not-a-bot".to_string(),
                action: "block".to_string(),
            }])
            .is_err()
        );
        assert!(
            validate_policies(vec![
                AiBotPolicyView {
                    bot_id: "gptbot".to_string(),
                    action: "block".to_string(),
                },
                AiBotPolicyView {
                    bot_id: "gptbot".to_string(),
                    action: "allow".to_string(),
                },
            ])
            .is_err()
        );
    }

    #[test]
    fn bodies_are_bounded_and_cannot_carry_crlf() {
        let body = check_body("a\r\nb", "robots_body").expect("valid");
        assert_eq!("a\nb", body);
        assert!(check_body(&"x".repeat(MAX_FILE_BYTES + 1), "robots_body").is_err());
    }
}
