//! Site-level WAF grading settings: advanced mode, per-category/stack monitor
//! lists and the body-withholding window used by body inspection.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::waf_settings;

/// Attack categories a site can downgrade to monitor-only. Must stay in sync
/// with `CategorySet::parse_name` in `pingwaf-waf`.
pub const CATEGORIES: [&str; 9] = [
    "sqli", "xss", "rce", "lfi", "ssrf", "deser", "crlf", "xxe", "ssti",
];

/// Backend stacks a site can downgrade to monitor-only. Must stay in sync
/// with `StackSet::parse_name` in `pingwaf-waf`.
pub const STACKS: [&str; 4] = ["java", "php", "python", "node"];

/// Default (and maximum) number of seconds the data plane may withhold a
/// request body while inspecting it. Also the value reported for a site that
/// has no posture row yet, matching both the column default and the
/// data-plane default.
pub const DEFAULT_BODY_STAGE_TIMEOUT_SECS: i32 = 30;

/// Upper bound for the body-withholding window. Holding a body longer than
/// this turns a trickling client into a connection-exhaustion vector, so 30s
/// is the ceiling rather than a suggestion.
pub const MAX_BODY_STAGE_TIMEOUT_SECS: i32 = 30;

/// Clamps a stored/wire value into the accepted `1..=30` window. `0` (and any
/// other out-of-band value) is read as "unset" and maps to the default, so a
/// hand-edited row can neither disable the bound nor exceed it.
pub fn clamp_body_stage_timeout_secs(raw: i32) -> i32 {
    if raw <= 0 {
        return DEFAULT_BODY_STAGE_TIMEOUT_SECS;
    }
    raw.min(MAX_BODY_STAGE_TIMEOUT_SECS)
}

/// Validates the request field for the body-withholding window.
///
/// `0` is an accepted *input* meaning "reset to the default" and is normalised
/// to [`DEFAULT_BODY_STAGE_TIMEOUT_SECS`] here, so the stored row always holds
/// a value the data plane can run with. The proto comment, the dashboard and
/// the API therefore share one rule: `0` == "unset" == 30 seconds. Everything
/// outside `0..=30` is a bad request rather than a silent clamp, so a caller
/// that meant `5` and sent `50` finds out instead of quietly enforcing 30.
pub fn validate_body_stage_timeout_secs(raw: i32) -> Result<i32, ApiError> {
    if !(0..=MAX_BODY_STAGE_TIMEOUT_SECS).contains(&raw) {
        return Err(ApiError::BadRequest(format!(
            "body_stage_timeout_secs must be between 0 and \
             {MAX_BODY_STAGE_TIMEOUT_SECS} (0 resets to the default)"
        )));
    }
    Ok(clamp_body_stage_timeout_secs(raw))
}

/// Built-in managed rules a site can downgrade to monitor-only, by id.
/// Mirrors `pingwaf_waf::MANAGED_RULE_IDS` (whitelisted through the crate so
/// a new managed rule cannot be configured before the engine knows it).
pub const MANAGED_RULES: [&str; 15] = pingwaf_waf::MANAGED_RULE_IDS;

#[derive(Debug, Deserialize)]
pub struct UpdateWafSettingsRequest {
    #[serde(default)]
    pub waf_enabled: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub paranoia_level: Option<i32>,
    #[serde(default)]
    pub advanced_mode: Option<bool>,
    #[serde(default)]
    pub monitor_categories: Option<Vec<String>>,
    #[serde(default)]
    pub monitor_stacks: Option<Vec<String>>,
    #[serde(default)]
    pub monitor_managed_rules: Option<Vec<String>>,
    /// Seconds the data plane may withhold a request body while inspecting
    /// it; 1-30, or `0` to reset to the default (30). Anything else is a bad
    /// request.
    #[serde(default)]
    pub body_stage_timeout_secs: Option<i32>,
}

/// Dashboard-facing view of a `waf_settings` row.
///
/// Mirrors the model, with the body-withholding window normalised: a row that
/// predates the column (or carries an out-of-band `0`) reports the default
/// rather than a value the data plane would never run with. The raw model is
/// deliberately not serialised directly so that every response — including
/// the lazily created row — goes through that normalisation.
#[derive(Debug, serde::Serialize)]
pub struct WafSettingsResponse {
    pub waf_enabled: bool,
    pub mode: String,
    pub paranoia_level: i32,
    pub advanced_mode: bool,
    pub monitor_categories: Vec<String>,
    pub monitor_stacks: Vec<String>,
    pub monitor_managed_rules: Vec<String>,
    /// Seconds the data plane may withhold a request body while inspecting
    /// it (1-30). Defaults to 30.
    pub body_stage_timeout_secs: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<waf_settings::Model> for WafSettingsResponse {
    fn from(row: waf_settings::Model) -> Self {
        Self {
            waf_enabled: row.waf_enabled,
            mode: row.mode,
            paranoia_level: row.paranoia_level,
            advanced_mode: row.advanced_mode,
            monitor_categories: row.monitor_categories,
            monitor_stacks: row.monitor_stacks,
            monitor_managed_rules: row.monitor_managed_rules,
            body_stage_timeout_secs: clamp_body_stage_timeout_secs(
                row.body_stage_timeout_secs,
            ),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Dashboard-facing metadata for one built-in managed rule.
#[derive(serde::Serialize)]
pub struct ManagedRuleEntry {
    pub id: String,
    pub name: String,
    pub action: String,
    pub severity: u8,
    pub tags: Vec<String>,
    pub stacks: Vec<String>,
    /// Attack family (`sqli`/`xss`/`rce`) whose per-category downgrade also
    /// affects this rule, or `None` for policy/recon rules.
    pub category: Option<String>,
    pub strict_only: bool,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/sites/{site_id}/waf/settings",
            get(get_waf_settings).put(update_waf_settings),
        )
        .route("/sites/{site_id}/waf/posture", get(get_waf_posture))
        .route("/managed-rules", get(list_managed_rules))
}

/// `GET /api/v1/managed-rules` — catalogue of the built-in managed rules.
///
/// Listed at the Strict level so the strict-only rules (PINGWAF-1061 and
/// PINGWAF-1070) show too; a site running the Normal level simply never
/// matches them, and the `strict_only` flag tells the dashboard.
async fn list_managed_rules() -> Json<Vec<ManagedRuleEntry>> {
    Json(
        pingwaf_waf::managed_rule_catalogue(pingwaf_waf::WafLevel::Strict)
            .into_iter()
            .map(|rule| ManagedRuleEntry {
                id: rule.id,
                name: rule.name,
                action: rule.action,
                severity: rule.severity,
                tags: rule.tags,
                stacks: rule.stacks,
                category: rule.category,
                strict_only: rule.strict_only,
            })
            .collect(),
    )
}

/// `GET /api/v1/sites/{site_id}/waf/settings`
async fn get_waf_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<WafSettingsResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    Ok(Json(row.into()))
}

/// `PUT /api/v1/sites/{site_id}/waf/settings`
///
/// Patch semantics: omitted fields keep their current value.
async fn update_waf_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateWafSettingsRequest>,
) -> Result<Json<WafSettingsResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    let mut active: waf_settings::ActiveModel = row.into();

    if let Some(waf_enabled) = payload.waf_enabled {
        active.waf_enabled = Set(waf_enabled);
    }
    if let Some(mode) = payload.mode {
        let mode = normalise_mode(&mode)?;
        active.mode = Set(mode);
    }
    if let Some(paranoia_level) = payload.paranoia_level {
        if !(1..=4).contains(&paranoia_level) {
            return Err(ApiError::BadRequest(
                "paranoia_level must be between 1 and 4".to_string(),
            ));
        }
        active.paranoia_level = Set(paranoia_level);
    }
    if let Some(advanced) = payload.advanced_mode {
        active.advanced_mode = Set(advanced);
    }
    if let Some(categories) = payload.monitor_categories {
        active.monitor_categories = Set(normalise_list(
            &categories,
            &CATEGORIES,
            "monitor_categories",
        )?);
    }
    if let Some(stacks) = payload.monitor_stacks {
        active.monitor_stacks =
            Set(normalise_list(&stacks, &STACKS, "monitor_stacks")?);
    }
    if let Some(rules) = payload.monitor_managed_rules {
        active.monitor_managed_rules =
            Set(normalise_rule_ids(&rules, "monitor_managed_rules")?);
    }
    if let Some(secs) = payload.body_stage_timeout_secs {
        // `0` means "reset to the default" and lands in the row as 30, so the
        // stored value is always inside the 1..=30 window the data plane runs.
        active.body_stage_timeout_secs =
            Set(validate_body_stage_timeout_secs(secs)?);
    }
    // An update whose every field stays unchanged is silently dropped by
    // SeaORM; touching updated_at guarantees the row round-trips.
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, "waf settings updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated.into()))
}

/* ── Effective posture ────────────────────────────────────────────── */

/// The site's effective WAF posture: what the data plane actually enforces
/// right now, aggregated from the rules, settings and global switches.
#[derive(Debug, serde::Serialize)]
pub struct WafPosture {
    /// Explicit engine switch (`"on"` / `"off"`).
    pub engine: &'static str,
    pub detection: WafPostureDetection,
    pub enforcement: WafPostureEnforcement,
}

#[derive(Debug, serde::Serialize)]
pub struct WafPostureDetection {
    /// The managed ruleset is always loaded by the data plane.
    pub managed: bool,
    /// At least one enabled custom rule is active.
    pub custom: bool,
    /// Advanced mode: strict level + body deep inspection.
    pub deep_inspection: bool,
    /// Under Attack mode is on (challenge settings enabled and switched on).
    pub under_attack: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct WafPostureEnforcement {
    /// Explicit site-level enforcement mode (`off`/`monitor`/`block`).
    /// Falls back to the legacy rule derivation when no posture row exists.
    pub mode: String,
    /// Managed ruleset action per attack category (`sqli`, `xss`, ...):
    /// `"monitor"` when the category is downgraded, `"block"` otherwise.
    pub managed: std::collections::BTreeMap<String, String>,
    /// Aggregate custom-rule mode: block > monitor > off.
    pub custom_rules: String,
    /// Strongest action among enabled rate-limit rules, or `"off"`.
    pub cc: String,
    /// Bot protection action, or `"off"` when disabled/absent.
    pub bot: String,
    /// Global observation mode: protective actions become observe-only.
    pub observation_mode: bool,
}

/// Rate-limit actions ordered strongest-first; `allow` never mitigates and
/// is treated as `off`.
const CC_ACTION_STRENGTH: [&str; 4] =
    ["block", "challenge", "js_challenge", "log"];

/// `GET /api/v1/sites/{site_id}/waf/posture`
async fn get_waf_posture(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<WafPosture>, ApiError> {
    use crate::models::{
        bot_protection, challenge_settings, defense_settings, mode,
        rate_limit_rules, rule,
    };

    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let settings = waf_settings::Entity::find()
        .filter(waf_settings::Column::SiteId.eq(id))
        .one(&state.db)
        .await?;
    let engine_on = settings.as_ref().map(|s| s.waf_enabled).unwrap_or(true);

    let active_rules = rule::Entity::find()
        .filter(rule::Column::SiteId.eq(id))
        .filter(rule::Column::Enabled.eq(true))
        .all(&state.db)
        .await?;
    let custom_mode =
        if active_rules.iter().any(|rule| rule.mode == mode::BLOCK) {
            "block".to_string()
        } else if active_rules.iter().any(|rule| rule.mode == mode::MONITOR) {
            "monitor".to_string()
        } else {
            "off".to_string()
        };
    // The explicit site mode wins; the rule derivation is only the fallback
    // for a site that never got a posture row. The fallback floors at
    // `monitor` for the same reason `derive_site_mode` does: the data plane
    // treats "no posture row" as monitor, so reporting `off` here would show a
    // posture weaker than what the edge is actually running.
    let fallback_mode = if custom_mode == mode::OFF {
        mode::MONITOR.to_string()
    } else {
        custom_mode.clone()
    };
    let site_mode = settings
        .as_ref()
        .map(|s| s.mode.clone())
        .unwrap_or(fallback_mode);

    let rate_limits = rate_limit_rules::Entity::find()
        .filter(rate_limit_rules::Column::SiteId.eq(id))
        .filter(rate_limit_rules::Column::Enabled.eq(true))
        .all(&state.db)
        .await?;
    let cc = CC_ACTION_STRENGTH
        .iter()
        .find(|strongest| {
            rate_limits.iter().any(|rule| &rule.action == *strongest)
        })
        .map(|strongest| strongest.to_string())
        .unwrap_or_else(|| "off".to_string());

    let bot = bot_protection::Entity::find()
        .filter(bot_protection::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .filter(|row| row.enabled)
        .map(|row| row.action)
        .unwrap_or_else(|| "off".to_string());

    let under_attack = challenge_settings::Entity::find()
        .filter(challenge_settings::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .filter(|row| row.enabled)
        .is_some_and(|row| row.under_attack_mode);

    // A missing global row means observation mode was never switched on.
    let observation_mode = defense_settings::Entity::find_by_id(1)
        .one(&state.db)
        .await?
        .is_some_and(|row| row.observation_mode);

    let managed: std::collections::BTreeMap<String, String> = CATEGORIES
        .iter()
        .map(|category| {
            let action = if settings.as_ref().is_some_and(|s| {
                s.monitor_categories.iter().any(|m| m == category)
            }) {
                "monitor"
            } else {
                "block"
            };
            (category.to_string(), action.to_string())
        })
        .collect();

    Ok(Json(WafPosture {
        engine: if engine_on { "on" } else { "off" },
        detection: WafPostureDetection {
            managed: true,
            custom: !active_rules.is_empty(),
            deep_inspection: settings
                .as_ref()
                .map(|s| s.advanced_mode)
                .unwrap_or(false),
            under_attack,
        },
        enforcement: WafPostureEnforcement {
            mode: site_mode,
            managed,
            custom_rules: custom_mode,
            cc,
            bot,
            observation_mode,
        },
    }))
}

/// Trims and lowercase-validates the site enforcement mode.
///
/// The only accepted values are `off`, `monitor` and `block` — `block` is the
/// enforcing mode, there is no `enforce`/`prevention` alias. The error message
/// spells the whole enum out (and names the `block`/`enforce` confusion
/// explicitly) because the old one-word rejection sent operators guessing
/// which of the three words the API wanted.
fn normalise_mode(raw: &str) -> Result<String, ApiError> {
    use crate::models::mode;
    let value = raw.trim().to_ascii_lowercase();
    if !mode::is_valid(&value) {
        let hint = if matches!(
            value.as_str(),
            "enforce" | "enforcement" | "prevent" | "prevention"
        ) {
            " ('enforce' is not an API value: use 'block' to enforce)"
        } else {
            ""
        };
        return Err(ApiError::BadRequest(format!(
            "unknown mode value '{value}'; allowed: {}|{}|{}{hint}",
            mode::OFF,
            mode::MONITOR,
            mode::BLOCK
        )));
    }
    Ok(value)
}

/// Trims, lowercases, de-duplicates and whitelist-checks a monitor list.
fn normalise_list(
    raw: &[String],
    allowed: &[&str],
    field: &str,
) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for value in raw {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        if !allowed.contains(&value.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown {field} value '{value}'; allowed: {}",
                allowed.join(", ")
            )));
        }
        if !out.contains(&value) {
            out.push(value);
        }
    }
    Ok(out)
}

/// Trims, de-duplicates and whitelist-checks a managed-rule id list. Unlike
/// category/stack names, ids keep their case (`PINGWAF-1010`).
fn normalise_rule_ids(
    raw: &[String],
    field: &str,
) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for value in raw {
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }
        if !MANAGED_RULES.contains(&value.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown {field} value '{value}'; allowed: {}",
                MANAGED_RULES.join(", ")
            )));
        }
        if !out.contains(&value) {
            out.push(value);
        }
    }
    Ok(out)
}

/// Derives the legacy site mode from the site's enabled custom rules
/// (block > monitor, with **monitor as the floor**). Used exactly once when the
/// posture row is first created, so a lazy-created row matches what the data
/// plane is already doing; afterwards the stored explicit value wins.
///
/// The floor is monitor, not off: with no posture row the data plane already
/// falls back to monitor (`grpc::config::waf_config_to_proto`), so creating the
/// row as `off` here would silently weaken a site just because an operator
/// opened its settings page. `off` stays an explicit choice.
async fn derive_site_mode(
    db: &sea_orm::DatabaseConnection,
    site_id: Uuid,
) -> Result<String, ApiError> {
    use crate::models::{mode, rule};
    let active = rule::Entity::find()
        .filter(rule::Column::SiteId.eq(site_id))
        .filter(rule::Column::Enabled.eq(true))
        .all(db)
        .await?;
    let derived = if active.iter().any(|rule| rule.mode == mode::BLOCK) {
        mode::BLOCK
    } else {
        mode::MONITOR
    };
    Ok(derived.to_string())
}

/// Finds the waf_settings row for a site, creating a default (engine on, no
/// advanced mode) one if absent. The freshly created row seeds `mode` from the
/// site's enabled rules once, matching the legacy derivation the data plane
/// uses when the row is absent (block > monitor, never off).
async fn find_or_create(
    state: &AppState,
    site_id: Uuid,
) -> Result<waf_settings::Model, ApiError> {
    if let Some(row) = waf_settings::Entity::find()
        .filter(waf_settings::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
    {
        return Ok(row);
    }

    let now = chrono::Utc::now();
    let model = waf_settings::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site_id),
        waf_enabled: Set(true),
        // Fresh rows inherit the aggregate rule mode; a site with no rules
        // lands on monitor (see `derive_site_mode`), never off.
        mode: Set(derive_site_mode(&state.db, site_id).await?),
        paranoia_level: Set(2),
        advanced_mode: Set(false),
        monitor_categories: Set(Vec::new()),
        monitor_stacks: Set(Vec::new()),
        monitor_managed_rules: Set(Vec::new()),
        body_stage_timeout_secs: Set(DEFAULT_BODY_STAGE_TIMEOUT_SECS),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::error::ApiError;

    #[test]
    fn normalise_list_trims_lowercases_and_deduplicates() {
        let out = normalise_list(
            &[" SQLI ".into(), "sqli".into(), "SSTI".into(), "".into()],
            &CATEGORIES,
            "monitor_categories",
        )
        .unwrap();
        assert_eq!(out, vec!["sqli", "ssti"]);
    }

    #[test]
    fn normalise_rule_ids_keeps_case_and_validates() {
        let out = normalise_rule_ids(
            &[" PINGWAF-1010 ".into(), "PINGWAF-1010".into()],
            "monitor_managed_rules",
        )
        .unwrap();
        assert_eq!(out, vec!["PINGWAF-1010"]);

        let err = normalise_rule_ids(
            &["PINGWAF-9999".into()],
            "monitor_managed_rules",
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
        assert!(err.to_string().contains("PINGWAF-9999"));
    }

    #[test]
    fn normalise_list_rejects_unknown_values() {
        let err = normalise_list(
            &["sqli".into(), "bogus".into()],
            &CATEGORIES,
            "monitor_categories",
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn normalise_mode_trims_and_validates() {
        assert_eq!(normalise_mode(" Block ").unwrap(), "block");
        assert_eq!(normalise_mode("MONITOR").unwrap(), "monitor");
        assert_eq!(normalise_mode("off").unwrap(), "off");

        let err = normalise_mode("bogus").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
        assert!(err.to_string().contains("bogus"));
        // D25: the rejection names every legal value so a caller can fix the
        // request without reading the source.
        assert!(err.to_string().contains("off|monitor|block"), "{err}");
    }

    #[test]
    fn enforce_is_rejected_with_the_legal_enum() {
        // `enforce` is what the console copy calls the blocking mode; it was
        // never an API value. The 400 must say which value does the job.
        let err = normalise_mode("enforce").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
        let message = err.to_string();
        assert!(message.contains("off|monitor|block"), "{message}");
        assert!(message.contains("use 'block'"), "{message}");
    }

    fn row_with_timeout(secs: i32) -> waf_settings::Model {
        waf_settings::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::new_v4(),
            waf_enabled: true,
            mode: crate::models::mode::MONITOR.to_string(),
            paranoia_level: 2,
            advanced_mode: false,
            monitor_categories: Vec::new(),
            monitor_stacks: Vec::new(),
            monitor_managed_rules: Vec::new(),
            body_stage_timeout_secs: secs,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn body_stage_timeout_defaults_to_30() {
        // A row that predates the column (0 after a hand-rolled read) and a
        // lazily created row both report the data-plane default.
        assert_eq!(
            clamp_body_stage_timeout_secs(0),
            DEFAULT_BODY_STAGE_TIMEOUT_SECS
        );
        assert_eq!(DEFAULT_BODY_STAGE_TIMEOUT_SECS, 30);
        let response = WafSettingsResponse::from(row_with_timeout(0));
        assert_eq!(response.body_stage_timeout_secs, 30);
    }

    #[test]
    fn body_stage_timeout_zero_resets_to_the_default() {
        // H2: `0` is the documented "unset / reset to the default" input in the
        // proto comment, the dashboard and the API. Sending it must be a 200
        // that reports (and stores) 30, not a 400 that contradicts the docs.
        assert_eq!(
            validate_body_stage_timeout_secs(0).unwrap(),
            DEFAULT_BODY_STAGE_TIMEOUT_SECS
        );
        assert_eq!(validate_body_stage_timeout_secs(0).unwrap(), 30);
        // A row that carries the normalised 0 reports the default too.
        assert_eq!(
            WafSettingsResponse::from(row_with_timeout(
                validate_body_stage_timeout_secs(0).unwrap()
            ))
            .body_stage_timeout_secs,
            30
        );
    }

    #[test]
    fn body_stage_timeout_accepts_the_documented_range() {
        // Both in-range ends (1 and 30) are legal and stored verbatim.
        assert_eq!(validate_body_stage_timeout_secs(1).unwrap(), 1);
        assert_eq!(validate_body_stage_timeout_secs(30).unwrap(), 30);
        assert_eq!(
            WafSettingsResponse::from(row_with_timeout(1))
                .body_stage_timeout_secs,
            1
        );
        assert_eq!(
            WafSettingsResponse::from(row_with_timeout(30))
                .body_stage_timeout_secs,
            30
        );
    }

    #[test]
    fn body_stage_timeout_rejects_values_outside_the_range() {
        // Only `0..=30` is accepted; `31`/`-1` (and anything wilder) is a 400.
        for bad in [31, -1, -30, i32::MIN, i32::MAX] {
            let err = validate_body_stage_timeout_secs(bad).unwrap_err();
            assert!(
                matches!(err, ApiError::BadRequest(_)),
                "{bad} must be a bad request, got {err:?}"
            );
            let message = err.to_string();
            assert!(message.contains("between 0 and 30"), "{bad}: {message}");
            assert!(
                message.contains("0 resets to the default"),
                "{bad}: {message}"
            );
        }
    }

    #[test]
    fn body_stage_timeout_response_clamps_out_of_band_rows() {
        // The column is bounded by the API, but a row edited behind its back
        // must not report a window the data plane would never run with.
        assert_eq!(
            WafSettingsResponse::from(row_with_timeout(31))
                .body_stage_timeout_secs,
            30
        );
        assert_eq!(
            WafSettingsResponse::from(row_with_timeout(-1))
                .body_stage_timeout_secs,
            30
        );
    }

    #[test]
    fn the_whitelists_cover_every_engine_name() {
        // Every whitelisted name must be parseable by the engine, so a value
        // accepted by the API is never silently ignored by the data plane.
        for name in CATEGORIES {
            assert!(
                pingwaf_waf::CategorySet::parse_name(name).is_some(),
                "{name} not parseable by CategorySet"
            );
        }
        for name in STACKS {
            assert!(
                pingwaf_waf::StackSet::parse_name(name).is_some(),
                "{name} not parseable by StackSet"
            );
        }
    }
}
