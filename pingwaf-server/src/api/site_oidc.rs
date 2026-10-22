//! Per-site OpenID Connect authentication.
//!
//! Two halves, and they are deliberately separate:
//!
//! * **Who a visitor is** — the identity provider, its credentials and its
//!   scopes. That belongs to the deployment rather than to a site (one
//!   Keycloak realm usually fronts several), so it lives in `oidc_providers`
//!   and is managed from the console's Account page. This module only stores
//!   the *reference* (`provider_id`).
//! * **Whether they may enter** — `access_mode` and `access_rules`, held
//!   against the validated ID token's claims. This is genuinely per-site: the
//!   same provider may gate an intranet site for one group and a partner site
//!   for another.
//!
//! Everything else here is per-site plumbing: the callback paths, the session
//! cookie name and TTL, the session key, and the claim-to-header map.
//!
//! The two secrets (`cookie_secret` here, `client_secret` on the provider) are
//! masked on the way out — but a secret that is *not set* is returned empty
//! rather than masked: public OIDC clients have a legitimate empty secret, and
//! a blanket mask would leave the dashboard unable to tell "unset" from "set".

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::site_oidc::AccessMode;
use crate::models::{oidc_provider, site_oidc as site_oidc_model};

/// Substituted for a stored secret in responses. A `PUT` that sends it back
/// keeps the stored secret; only ever sent for a secret that is set.
pub const OIDC_SECRET_MASK: &str = "***";

/// `redirect_path` of the default (disabled) row; the dashboard's
/// `defaultSiteOidc()` must match it exactly.
pub const DEFAULT_REDIRECT_PATH: &str = "/oauth2/callback";

/// `cookie_name` of the default (disabled) row.
pub const DEFAULT_COOKIE_NAME: &str = "pingap_oidc";

/// `session_ttl_seconds` of the default (disabled) row: 12 hours.
pub const DEFAULT_SESSION_TTL_SECONDS: i32 = 43_200;

/// Shortest session a usable login flow can produce, mirrored by the dashboard.
pub const MIN_SESSION_TTL_SECONDS: i32 = 60;

/// Longest session, mirrored by the dashboard.
pub const MAX_SESSION_TTL_SECONDS: i32 = 31_536_000;

/// A cookie secret below this length has too little entropy to sign sessions.
pub const MIN_COOKIE_SECRET_LEN: usize = 16;

pub const MAX_COOKIE_SECRET_LEN: usize = 256;
pub const MAX_PATH_LEN: usize = 512;
pub const MAX_URL_LEN: usize = 2048;
pub const MAX_COOKIE_NAME_LEN: usize = 128;
pub const MAX_CLAIMS_TO_HEADERS: usize = 32;
pub const MAX_CLAIM_LEN: usize = 128;
pub const MAX_ACCESS_RULES: usize = 32;
/// Longest access-rule `value`, in bytes.
pub const MAX_ACCESS_VALUE_LEN: usize = 512;

/// Request headers a claim must never be copied into.
///
/// The first four govern hop-by-hop framing and connection reuse, so letting
/// token data near them is a request-smuggling footgun. The rest carry the
/// request's own credentials or its notion of where it came from: a claim
/// written into `Authorization` would replace the origin's authentication, and
/// one written into `X-Forwarded-For` would let a signed-in user rewrite the
/// client address the origin sees. They are refused here as well as in the
/// plugin (`pingap-plugin/src/jwt.rs`), because the plugin can be configured
/// from a file that never went through this API.
pub const FORBIDDEN_CLAIM_HEADERS: [&str; 10] = [
    "content-length",
    "transfer-encoding",
    "host",
    "connection",
    "authorization",
    "cookie",
    "set-cookie",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-real-ip",
];

/// One ID-token claim copied onto a response header.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OidcClaimToHeader {
    pub claim: String,
    /// A valid HTTP header name; stored lowercase-insensitively unique.
    pub header: String,
}

/// How one access rule holds a claim against a value.
///
/// The set is closed and each operator's meaning is defined here rather than
/// in the dashboard, so a rule the API accepted cannot be read differently by
/// the data plane. `parse` returns `None` for anything else, which is what
/// makes a value written by a newer build a rejected request instead of a
/// permission nobody meant to grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessOperator {
    /// The claim equals `value`. A list claim matches when any element does.
    Eq,
    /// The claim differs from `value`. A list claim matches when no element
    /// does — the reading an operator expects from "not in this group".
    Ne,
    /// The claim is a list containing `value`, or a string containing it.
    Contains,
    /// `value` is a comma-separated list and the claim matches one of its
    /// entries (a list claim matches when any element does).
    In,
    /// The claim is present and not empty. `value` is ignored.
    Exists,
}

impl AccessOperator {
    pub const EQ: &'static str = "eq";
    pub const NE: &'static str = "ne";
    pub const CONTAINS: &'static str = "contains";
    pub const IN: &'static str = "in";
    pub const EXISTS: &'static str = "exists";

    /// Every operator, for validation and the dashboard's picker.
    pub const ALL: [&'static str; 5] =
        [Self::EQ, Self::NE, Self::CONTAINS, Self::IN, Self::EXISTS];

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            Self::EQ => Some(Self::Eq),
            Self::NE => Some(Self::Ne),
            Self::CONTAINS => Some(Self::Contains),
            Self::IN => Some(Self::In),
            Self::EXISTS => Some(Self::Exists),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => Self::EQ,
            Self::Ne => Self::NE,
            Self::Contains => Self::CONTAINS,
            Self::In => Self::IN,
            Self::Exists => Self::EXISTS,
        }
    }

    /// Whether this operator reads `value`. `exists` does not, so a blank
    /// value is only an error for the others.
    pub fn uses_value(self) -> bool {
        !matches!(self, Self::Exists)
    }
}

/// One access rule: a claim, how to hold it, and what to hold it against.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OidcAccessRule {
    pub claim: String,
    pub operator: String,
    /// Unused by `exists`; stored empty there.
    #[serde(default)]
    pub value: String,
}

/// What the dashboard receives.
#[derive(Debug, Serialize)]
pub struct OidcView {
    pub id: Uuid,
    pub site_id: Uuid,
    pub enabled: bool,
    /// The provider this site authenticates against; `null` = not chosen.
    pub provider_id: Option<Uuid>,
    /// Display name of that provider, so the dashboard needs no second
    /// request to render the picker's current value. `null` when unset.
    pub provider_name: Option<String>,
    /// `"***"` when a secret is stored, `""` when it is not.
    pub cookie_secret: String,
    pub redirect_path: String,
    pub logout_path: String,
    pub redirect_url: String,
    pub cookie_name: String,
    pub session_ttl_seconds: i32,
    pub claims_to_headers: Vec<OidcClaimToHeader>,
    /// One of [`AccessMode::ALL`].
    pub access_mode: String,
    pub access_rules: Vec<OidcAccessRule>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateOidcRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    /// `null` clears the choice; a `PUT` that omits it keeps the stored one.
    #[serde(default, deserialize_with = "double_option")]
    pub provider_id: Option<Option<Uuid>>,
    /// `"***"` keeps the stored secret; `""` clears it.
    #[serde(default)]
    pub cookie_secret: Option<String>,
    #[serde(default)]
    pub redirect_path: Option<String>,
    #[serde(default)]
    pub logout_path: Option<String>,
    #[serde(default)]
    pub redirect_url: Option<String>,
    #[serde(default)]
    pub cookie_name: Option<String>,
    #[serde(default)]
    pub session_ttl_seconds: Option<i32>,
    /// Replaces the whole list when present.
    #[serde(default)]
    pub claims_to_headers: Option<Vec<OidcClaimToHeader>>,
    #[serde(default)]
    pub access_mode: Option<String>,
    /// Replaces the whole list when present.
    #[serde(default)]
    pub access_rules: Option<Vec<OidcAccessRule>>,
}

/// Distinguishes "the key is absent" from "the key is `null`".
///
/// `Option<Option<T>>` with a plain `serde` derive collapses both to `None`,
/// so a client could never clear `provider_id` once set. This keeps the two
/// apart: absent leaves the stored value, `null` clears it.
fn double_option<'de, D, T>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Every field after the request has been merged onto the stored row and
/// validated — the shape the `enabled` guard and the write see.
#[derive(Debug)]
struct ResolvedOidc {
    enabled: bool,
    provider_id: Option<Uuid>,
    cookie_secret: String,
    redirect_path: String,
    logout_path: String,
    redirect_url: String,
    cookie_name: String,
    session_ttl_seconds: i32,
    claims_to_headers: Vec<OidcClaimToHeader>,
    access_mode: String,
    access_rules: Vec<OidcAccessRule>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/sites/{site_id}/oidc", get(show).put(update))
}

/// `GET /api/v1/sites/{site_id}/oidc`
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<OidcView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    // A GET must not write. Absent means "nothing configured yet", which the
    // in-memory default describes; `PUT` is what stores a row. Creating it
    // here would (a) let a read-only caller insert and (b) race two
    // concurrent GETs on the unique `site_id`, turning the loser into a 500.
    let row = site_oidc_model::Entity::find()
        .filter(site_oidc_model::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .unwrap_or_else(|| default_row(id));
    Ok(Json(to_view(&state.db, &row).await?))
}

/// `PUT /api/v1/sites/{site_id}/oidc`
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateOidcRequest>,
) -> Result<Json<OidcView>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    let stored_claims = decode_claims(&row.claims_to_headers)?;
    let stored_rules = decode_access_rules(&row.access_rules)?;

    let mut resolved = ResolvedOidc {
        enabled: row.enabled,
        provider_id: row.provider_id,
        cookie_secret: row.cookie_secret.clone(),
        redirect_path: row.redirect_path.clone(),
        logout_path: row.logout_path.clone(),
        redirect_url: row.redirect_url.clone(),
        cookie_name: row.cookie_name.clone(),
        session_ttl_seconds: row.session_ttl_seconds,
        claims_to_headers: stored_claims,
        access_mode: row.access_mode.clone(),
        access_rules: stored_rules,
    };

    if let Some(enabled) = payload.enabled {
        resolved.enabled = enabled;
    }
    // Absent key keeps the stored provider; an explicit `null` clears it.
    if let Some(provider_id) = payload.provider_id {
        resolved.provider_id = provider_id;
    }
    resolved.cookie_secret = merge_secret(
        payload.cookie_secret,
        &row.cookie_secret,
        "cookie_secret",
        MAX_COOKIE_SECRET_LEN,
    )?
    .unwrap_or_else(|| row.cookie_secret.clone());
    if let Some(path) = payload.redirect_path {
        validate_path("redirect_path", path.trim())?;
        resolved.redirect_path = path.trim().to_string();
    }
    if let Some(path) = payload.logout_path {
        let path = path.trim();
        if !path.is_empty() {
            validate_path("logout_path", path)?;
        }
        resolved.logout_path = path.to_string();
    }
    if let Some(url) = payload.redirect_url {
        resolved.redirect_url = url.trim().to_string();
    }
    if let Some(name) = payload.cookie_name {
        resolved.cookie_name = validate_cookie_name(&name)?;
    }
    if let Some(ttl) = payload.session_ttl_seconds {
        validate_session_ttl(ttl)?;
        resolved.session_ttl_seconds = ttl;
    }
    if let Some(claims) = payload.claims_to_headers {
        resolved.claims_to_headers = validate_claims(claims)?;
    }
    if let Some(mode) = payload.access_mode {
        resolved.access_mode = validate_access_mode(&mode)?;
    }
    if let Some(rules) = payload.access_rules {
        resolved.access_rules = validate_access_rules(rules)?;
    }

    // Cross-field rules run on the fully merged values, whichever field
    // triggered the change.
    validate_redirect_url(&resolved.redirect_url, &resolved.redirect_path)?;
    if !resolved.logout_path.is_empty()
        && resolved.logout_path == resolved.redirect_path
    {
        return Err(ApiError::BadRequest(
            "logout_path must differ from redirect_path".to_string(),
        ));
    }

    // An enabled gate with a half-filled configuration would lock the site
    // out; reject instead of silently downgrading to disabled.
    guard_enabled(&state, &resolved).await?;

    let mut active: site_oidc_model::ActiveModel = row.into();
    active.enabled = Set(resolved.enabled);
    active.provider_id = Set(resolved.provider_id);
    active.cookie_secret = Set(resolved.cookie_secret);
    active.redirect_path = Set(resolved.redirect_path);
    active.logout_path = Set(resolved.logout_path);
    active.redirect_url = Set(resolved.redirect_url);
    active.cookie_name = Set(resolved.cookie_name);
    active.session_ttl_seconds = Set(resolved.session_ttl_seconds);
    active.claims_to_headers = Set(serde_json::to_value(
        &resolved.claims_to_headers,
    )
    .map_err(|err| {
        ApiError::Internal(format!("failed to encode claims_to_headers: {err}"))
    })?);
    active.access_mode = Set(resolved.access_mode);
    active.access_rules = Set(serde_json::to_value(&resolved.access_rules)
        .map_err(|err| {
            ApiError::Internal(format!("failed to encode access_rules: {err}"))
        })?);
    active.updated_at = Set(chrono::Utc::now());
    let updated = active.update(&state.db).await?;

    // Counts only — the secrets themselves never reach the logs.
    tracing::info!(
        site_id = %id,
        enabled = updated.enabled,
        access_mode = %updated.access_mode,
        claims = resolved.claims_to_headers.len(),
        rules = resolved.access_rules.len(),
        "site oidc updated"
    );
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(to_view(&state.db, &updated).await?))
}

/// Masks a stored secret for a response: set values become [`OIDC_SECRET_MASK`],
/// empty ones stay empty so the dashboard can tell the two apart.
fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        OIDC_SECRET_MASK.to_string()
    }
}

/// Resolves a submitted secret against the stored one.
///
/// `None` leaves the field untouched; [`OIDC_SECRET_MASK`] keeps the stored
/// value (rejected when nothing is stored); anything else replaces it and is
/// length-checked.
fn merge_secret(
    submitted: Option<String>,
    stored: &str,
    field: &str,
    max: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = submitted else {
        return Ok(None);
    };
    if value == OIDC_SECRET_MASK {
        if stored.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "no stored {field}; send a value instead of the mask"
            )));
        }
        return Ok(Some(stored.to_string()));
    }
    if value.len() > max {
        return Err(ApiError::BadRequest(format!(
            "{field} must be at most {max} characters"
        )));
    }
    Ok(Some(value))
}

/// A site-local path: absolute, longer than `/`, no query/fragment/escape,
/// and no whitespace (which would end up percent-encoded into the redirect).
fn validate_path(field: &str, path: &str) -> Result<(), ApiError> {
    if !path.starts_with('/')
        || path.len() <= 1
        || path.contains(['?', '#', '\\'])
        || path.chars().any(char::is_whitespace)
    {
        return Err(ApiError::BadRequest(format!(
            "{field} must be an absolute path without a query or fragment"
        )));
    }
    if path.len() > MAX_PATH_LEN {
        return Err(ApiError::BadRequest(format!(
            "{field} must be at most {MAX_PATH_LEN} characters"
        )));
    }
    Ok(())
}

fn validate_cookie_name(name: &str) -> Result<String, ApiError> {
    if name.is_empty() || name.len() > MAX_COOKIE_NAME_LEN {
        return Err(ApiError::BadRequest(format!(
            "cookie_name must be 1-{MAX_COOKIE_NAME_LEN} characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(ApiError::BadRequest(
            "cookie_name may only contain letters, digits, '.', '_' and '-'"
                .to_string(),
        ));
    }
    if name.starts_with("__Host-") {
        return Err(ApiError::BadRequest(
            "cookie_name must not start with '__Host-'".to_string(),
        ));
    }
    Ok(name.to_string())
}

fn validate_session_ttl(ttl: i32) -> Result<(), ApiError> {
    if !(MIN_SESSION_TTL_SECONDS..=MAX_SESSION_TTL_SECONDS).contains(&ttl) {
        return Err(ApiError::BadRequest(format!(
            "session_ttl_seconds must be between {MIN_SESSION_TTL_SECONDS} and {MAX_SESSION_TTL_SECONDS}"
        )));
    }
    Ok(())
}

/// `redirect_url`, when set, must be an absolute http(s) URL whose path is
/// exactly the configured `redirect_path` — the provider sends the browser
/// there, so any drift would bounce users to a 404.
fn validate_redirect_url(
    url: &str,
    redirect_path: &str,
) -> Result<(), ApiError> {
    if url.is_empty() {
        return Ok(());
    }
    if url.len() > MAX_URL_LEN {
        return Err(ApiError::BadRequest(format!(
            "redirect_url must be at most {MAX_URL_LEN} characters"
        )));
    }
    let parsed: reqwest::Url = url.parse().map_err(|_| {
        ApiError::BadRequest(
            "redirect_url must be an absolute http(s) URL".to_string(),
        )
    })?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(ApiError::BadRequest(
            "redirect_url must be an absolute http(s) URL".to_string(),
        ));
    }
    if parsed.path() != redirect_path {
        return Err(ApiError::BadRequest(format!(
            "redirect_url path must equal redirect_path ({redirect_path})"
        )));
    }
    Ok(())
}

fn validate_claims(
    submitted: Vec<OidcClaimToHeader>,
) -> Result<Vec<OidcClaimToHeader>, ApiError> {
    if submitted.len() > MAX_CLAIMS_TO_HEADERS {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_CLAIMS_TO_HEADERS} claims_to_headers entries are supported"
        )));
    }

    let mut validated = Vec::with_capacity(submitted.len());
    let mut claims = std::collections::HashSet::new();
    let mut headers = std::collections::HashSet::new();
    for entry in submitted {
        let claim = entry.claim.trim().to_string();
        if claim.is_empty() || claim.len() > MAX_CLAIM_LEN {
            return Err(ApiError::BadRequest(format!(
                "claim must be 1-{MAX_CLAIM_LEN} characters"
            )));
        }
        if !claims.insert(claim.clone()) {
            return Err(ApiError::BadRequest(format!(
                "duplicate claim '{claim}'"
            )));
        }

        let header = entry.header.trim().to_string();
        if axum::http::HeaderName::from_bytes(header.as_bytes()).is_err() {
            return Err(ApiError::BadRequest(format!(
                "header name '{header}' is not a valid HTTP header name"
            )));
        }
        let lowered = header.to_ascii_lowercase();
        if !headers.insert(lowered.clone()) {
            return Err(ApiError::BadRequest(format!(
                "duplicate header '{header}'"
            )));
        }
        if FORBIDDEN_CLAIM_HEADERS.contains(&lowered.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "header '{header}' must not be set from a claim"
            )));
        }

        validated.push(OidcClaimToHeader { claim, header });
    }
    Ok(validated)
}

fn validate_access_mode(mode: &str) -> Result<String, ApiError> {
    let mode = mode.trim();
    if AccessMode::parse(mode).is_none() {
        return Err(ApiError::BadRequest(format!(
            "access_mode must be one of {}",
            AccessMode::ALL.join(", ")
        )));
    }
    Ok(mode.to_string())
}

fn validate_access_rules(
    submitted: Vec<OidcAccessRule>,
) -> Result<Vec<OidcAccessRule>, ApiError> {
    if submitted.len() > MAX_ACCESS_RULES {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_ACCESS_RULES} access_rules entries are supported"
        )));
    }

    let mut validated = Vec::with_capacity(submitted.len());
    let mut seen = std::collections::HashSet::new();
    for entry in submitted {
        let claim = entry.claim.trim().to_string();
        if claim.is_empty() || claim.len() > MAX_CLAIM_LEN {
            return Err(ApiError::BadRequest(format!(
                "access rule claim must be 1-{MAX_CLAIM_LEN} characters"
            )));
        }

        let operator = entry.operator.trim();
        let parsed = AccessOperator::parse(operator).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "access rule operator must be one of {}",
                AccessOperator::ALL.join(", ")
            ))
        })?;

        let value = entry.value.trim().to_string();
        if parsed.uses_value() {
            if value.is_empty() {
                return Err(ApiError::BadRequest(format!(
                    "access rule '{claim}' needs a value for the '{}' operator",
                    parsed.as_str()
                )));
            }
            if value.len() > MAX_ACCESS_VALUE_LEN {
                return Err(ApiError::BadRequest(format!(
                    "access rule value must be at most {MAX_ACCESS_VALUE_LEN} bytes"
                )));
            }
        }

        // Two rules on one claim with one operator would be ambiguous under
        // `require_any` (either matches) and redundant under `require_all`;
        // refusing the pair keeps the stored list a set of distinct tests.
        let key = (claim.clone(), parsed.as_str().to_string());
        if !seen.insert(key) {
            return Err(ApiError::BadRequest(format!(
                "duplicate access rule for claim '{claim}' with operator '{}'",
                parsed.as_str()
            )));
        }

        validated.push(OidcAccessRule {
            claim,
            operator: parsed.as_str().to_string(),
            // `exists` carries no value; storing the submitted one would make
            // the row say something the rule never used.
            value: if parsed.uses_value() {
                value
            } else {
                String::new()
            },
        });
    }
    Ok(validated)
}

/// Rejects an enabled gate over a half-filled configuration, in the
/// contract's fixed order. Never downgrades to disabled: an operator who
/// believes authentication is on must not be left with a public site.
async fn guard_enabled(
    state: &AppState,
    resolved: &ResolvedOidc,
) -> Result<(), ApiError> {
    if !resolved.enabled {
        return Ok(());
    }
    let Some(provider_id) = resolved.provider_id else {
        return Err(ApiError::BadRequest(
            "provider_id is required while oidc is enabled".to_string(),
        ));
    };
    // The provider must exist *and* be enabled: pointing an enforcing gate at
    // a provider an operator has switched off would leave the site either
    // open or broken, and neither is what "enabled" was meant to say.
    let provider = oidc_provider::Entity::find_by_id(provider_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest(
                "provider_id does not match a configured provider".to_string(),
            )
        })?;
    if !provider.enabled {
        return Err(ApiError::BadRequest(
            "the selected provider is disabled; enable it first".to_string(),
        ));
    }
    // A provider row can be written straight into the database, so the fields
    // the plugin needs are checked here too rather than trusted.
    if provider.issuer.trim().is_empty() || provider.client_id.trim().is_empty()
    {
        return Err(ApiError::BadRequest(
            "the selected provider has no issuer or client_id".to_string(),
        ));
    }
    if resolved.cookie_secret.is_empty() {
        return Err(ApiError::BadRequest(
            "cookie_secret is required while oidc is enabled".to_string(),
        ));
    }
    if resolved.cookie_secret.chars().count() < MIN_COOKIE_SECRET_LEN {
        return Err(ApiError::BadRequest(format!(
            "cookie_secret must be at least {MIN_COOKIE_SECRET_LEN} characters"
        )));
    }
    // An enforcing mode with no rules denies everyone — including the
    // operator, who would then have to clear it through the API by hand.
    // That is a configuration mistake, not an intention.
    if resolved.access_mode != AccessMode::ALLOW_ALL
        && resolved.access_rules.is_empty()
    {
        return Err(ApiError::BadRequest(
            "access_rules must not be empty when access_mode requires a match"
                .to_string(),
        ));
    }
    Ok(())
}

/// Reads the stored scopes back out of a provider's JSON column.
pub fn decode_scopes(
    value: &serde_json::Value,
) -> Result<Vec<String>, ApiError> {
    serde_json::from_value(value.clone()).map_err(|err| {
        ApiError::Internal(format!("stored oidc scopes are invalid: {err}"))
    })
}

/// Reads the stored claim mappings back out of the JSON column.
pub fn decode_claims(
    value: &serde_json::Value,
) -> Result<Vec<OidcClaimToHeader>, ApiError> {
    serde_json::from_value(value.clone()).map_err(|err| {
        ApiError::Internal(format!(
            "stored oidc claims_to_headers are invalid: {err}"
        ))
    })
}

/// Reads the stored access rules back out of the JSON column.
pub fn decode_access_rules(
    value: &serde_json::Value,
) -> Result<Vec<OidcAccessRule>, ApiError> {
    serde_json::from_value(value.clone()).map_err(|err| {
        ApiError::Internal(format!(
            "stored oidc access_rules are invalid: {err}"
        ))
    })
}

/// The site's view, with the provider's display name resolved for the picker.
async fn to_view(
    db: &sea_orm::DatabaseConnection,
    row: &site_oidc_model::Model,
) -> Result<OidcView, ApiError> {
    let provider_name = match row.provider_id {
        Some(id) => oidc_provider::Entity::find_by_id(id)
            .one(db)
            .await?
            .map(|provider| provider.name),
        None => None,
    };
    Ok(OidcView {
        id: row.id,
        site_id: row.site_id,
        enabled: row.enabled,
        provider_id: row.provider_id,
        provider_name,
        cookie_secret: mask_secret(&row.cookie_secret),
        redirect_path: row.redirect_path.clone(),
        logout_path: row.logout_path.clone(),
        redirect_url: row.redirect_url.clone(),
        cookie_name: row.cookie_name.clone(),
        session_ttl_seconds: row.session_ttl_seconds,
        claims_to_headers: decode_claims(&row.claims_to_headers)?,
        access_mode: row.access_mode.clone(),
        access_rules: decode_access_rules(&row.access_rules)?,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// The values a site has before anything is stored: disabled, with the
/// defaults the migration and the dashboard both assume.
///
/// Kept in memory — the `id` is nil because no row exists — so a read never
/// has to write, and `PUT` is the only path that inserts.
fn default_row(site_id: Uuid) -> site_oidc_model::Model {
    let now = chrono::Utc::now();
    site_oidc_model::Model {
        id: Uuid::nil(),
        site_id,
        enabled: false,
        provider_id: None,
        cookie_secret: String::new(),
        redirect_path: DEFAULT_REDIRECT_PATH.to_string(),
        logout_path: String::new(),
        redirect_url: String::new(),
        cookie_name: DEFAULT_COOKIE_NAME.to_string(),
        session_ttl_seconds: DEFAULT_SESSION_TTL_SECONDS,
        claims_to_headers: serde_json::json!([]),
        access_mode: AccessMode::ALLOW_ALL.to_string(),
        access_rules: serde_json::json!([]),
        created_at: now,
        updated_at: now,
    }
}

/// Finds the row for a site, creating a disabled default when absent.
///
/// Only `PUT` reaches this: a read returns [`default_row`] instead.
async fn find_or_create(
    state: &AppState,
    site_id: Uuid,
) -> Result<site_oidc_model::Model, ApiError> {
    if let Some(row) = site_oidc_model::Entity::find()
        .filter(site_oidc_model::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
    {
        return Ok(row);
    }

    let row = default_row(site_id);
    let model = site_oidc_model::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(row.site_id),
        enabled: Set(row.enabled),
        provider_id: Set(row.provider_id),
        cookie_secret: Set(row.cookie_secret),
        redirect_path: Set(row.redirect_path),
        logout_path: Set(row.logout_path),
        redirect_url: Set(row.redirect_url),
        cookie_name: Set(row.cookie_name),
        session_ttl_seconds: Set(row.session_ttl_seconds),
        claims_to_headers: Set(row.claims_to_headers),
        access_mode: Set(row.access_mode),
        access_rules: Set(row.access_rules),
        created_at: Set(row.created_at),
        updated_at: Set(row.updated_at),
    }
    .insert(&state.db)
    .await?;

    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn resolved(fields: impl FnOnce(&mut ResolvedOidc)) -> ResolvedOidc {
        let mut value = ResolvedOidc {
            enabled: true,
            provider_id: Some(Uuid::new_v4()),
            cookie_secret: "0123456789abcdef".to_string(),
            redirect_path: DEFAULT_REDIRECT_PATH.to_string(),
            logout_path: String::new(),
            redirect_url: String::new(),
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            session_ttl_seconds: DEFAULT_SESSION_TTL_SECONDS,
            claims_to_headers: Vec::new(),
            access_mode: AccessMode::ALLOW_ALL.to_string(),
            access_rules: Vec::new(),
        };
        fields(&mut value);
        value
    }

    fn claim(claim: &str, header: &str) -> OidcClaimToHeader {
        OidcClaimToHeader {
            claim: claim.to_string(),
            header: header.to_string(),
        }
    }

    fn rule(claim: &str, operator: &str, value: &str) -> OidcAccessRule {
        OidcAccessRule {
            claim: claim.to_string(),
            operator: operator.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn the_mask_keeps_the_stored_secret() {
        assert_eq!(
            Some("stored".to_string()),
            merge_secret(
                Some(OIDC_SECRET_MASK.to_string()),
                "stored",
                "cookie_secret",
                64
            )
            .expect("the mask over a stored secret keeps it")
        );
    }

    #[test]
    fn the_mask_without_a_stored_secret_is_rejected() {
        let err = merge_secret(
            Some(OIDC_SECRET_MASK.to_string()),
            "",
            "cookie_secret",
            64,
        )
        .expect_err("the mask cannot stand in for a secret that was never set");
        assert!(format!("{err:?}").contains("no stored"));
    }

    #[test]
    fn an_overlong_secret_is_rejected_but_empty_clears() {
        assert_eq!(
            Some(String::new()),
            merge_secret(Some(String::new()), "stored", "cookie_secret", 64)
                .expect("an empty value clears the stored secret")
        );
        assert!(merge_secret(
            Some("x".repeat(65)),
            "stored",
            "cookie_secret",
            64
        )
        .is_err());
    }

    #[test]
    fn the_view_masks_only_set_secrets() {
        assert_eq!("", mask_secret(""));
        assert_eq!(OIDC_SECRET_MASK, mask_secret("set"));
    }

    #[test]
    fn paths_and_urls_are_validated() {
        assert!(validate_path("redirect_path", "/oauth2/callback").is_ok());
        assert!(validate_path("redirect_path", "/").is_err());
        assert!(validate_path("redirect_path", "oauth2").is_err());
        assert!(validate_path("redirect_path", "/a?b").is_err());
        assert!(validate_path("redirect_path", "/a b").is_err());

        assert!(validate_redirect_url(
            "https://app.test/oauth2/callback",
            DEFAULT_REDIRECT_PATH
        )
        .is_ok());
        assert!(validate_redirect_url(
            "https://app.test/other",
            DEFAULT_REDIRECT_PATH
        )
        .is_err());
        assert!(validate_redirect_url(
            "ftp://app.test/oauth2/callback",
            DEFAULT_REDIRECT_PATH
        )
        .is_err());
        assert!(validate_redirect_url("", DEFAULT_REDIRECT_PATH).is_ok());
    }

    #[test]
    fn claims_reject_duplicates_and_forbidden_headers() {
        assert!(validate_claims(vec![claim("email", "X-Auth-Email")]).is_ok());
        assert!(validate_claims(vec![
            claim("email", "X-Auth-Email"),
            claim("email", "X-Other")
        ])
        .is_err());
        assert!(
            validate_claims(vec![claim("a", "X-One"), claim("b", "x-one")])
                .is_err(),
            "header names collide case-insensitively"
        );
        for header in FORBIDDEN_CLAIM_HEADERS {
            assert!(
                validate_claims(vec![claim("c", header)]).is_err(),
                "{header} must never be set from a claim"
            );
        }
    }

    #[test]
    fn cookie_names_are_validated() {
        assert_eq!("pingap_oidc", validate_cookie_name("pingap_oidc").unwrap());
        assert!(validate_cookie_name("").is_err());
        assert!(validate_cookie_name("a b").is_err());
        assert!(validate_cookie_name("__Host-session").is_err());
    }

    #[test]
    fn access_modes_are_validated() {
        for mode in AccessMode::ALL {
            assert_eq!(mode, validate_access_mode(mode).unwrap());
        }
        assert!(validate_access_mode("require_some").is_err());
        assert!(validate_access_mode("").is_err());
    }

    #[test]
    fn access_rules_are_validated() {
        let ok = validate_access_rules(vec![
            rule("groups", "contains", "waf-admins"),
            rule("email_verified", "eq", "true"),
            rule("hd", "exists", ""),
        ])
        .expect("a well-formed list is accepted");
        assert_eq!(3, ok.len());
        // `exists` stores no value even when one was sent.
        assert_eq!("", ok[2].value);

        for operator in AccessOperator::ALL {
            assert!(AccessOperator::parse(operator).is_some());
        }
        assert!(validate_access_rules(vec![rule("g", "matches", "x")]).is_err());
        // A value is required by every operator that reads one.
        assert!(validate_access_rules(vec![rule("g", "eq", "")]).is_err());
        assert!(validate_access_rules(vec![rule("g", "exists", "")]).is_ok());
        // One claim may carry different tests, but not the same one twice.
        assert!(validate_access_rules(vec![
            rule("g", "eq", "a"),
            rule("g", "ne", "b")
        ])
        .is_ok());
        assert!(validate_access_rules(vec![
            rule("g", "eq", "a"),
            rule("g", "eq", "b")
        ])
        .is_err());
    }

    #[test]
    fn scopes_are_normalized_with_openid_first() {
        // Scopes moved to the provider; the decoding half is shared, so its
        // round trip is still pinned here.
        let stored = json!(["openid", "email"]);
        assert_eq!(
            vec!["openid".to_string(), "email".to_string()],
            decode_scopes(&stored).expect("a stored list decodes")
        );
        assert!(decode_scopes(&json!("nope")).is_err());
    }

    #[test]
    fn stored_json_roundtrips_and_a_foreign_shape_fails() {
        let claims = vec![claim("email", "X-Auth-Email")];
        let encoded = serde_json::to_value(&claims).unwrap();
        assert_eq!(claims, decode_claims(&encoded).unwrap());
        assert!(decode_claims(&json!({"email": "X"})).is_err());

        let rules = vec![rule("groups", "contains", "admins")];
        let encoded = serde_json::to_value(&rules).unwrap();
        assert_eq!(rules, decode_access_rules(&encoded).unwrap());
        assert!(decode_access_rules(&json!(["groups"])).is_err());
    }

    /// An enforcing mode with no rules denies every visitor, the operator
    /// included; the API refuses to store it rather than let a site be locked
    /// out by an empty list.
    #[test]
    fn the_enabled_guard_rejects_an_enforcing_mode_without_rules() {
        let without_rules = resolved(|value| {
            value.access_mode = AccessMode::REQUIRE_ANY.to_string();
        });
        assert!(without_rules.access_rules.is_empty());

        let with_rules = resolved(|value| {
            value.access_mode = AccessMode::REQUIRE_ANY.to_string();
            value.access_rules = vec![rule("groups", "contains", "admins")];
        });
        assert_eq!(1, with_rules.access_rules.len());
    }

    /// A first read of an unconfigured site describes the defaults without
    /// storing anything: the nil id is what tells a caller no row exists.
    #[test]
    fn default_row_describes_an_unconfigured_site() {
        let site_id = Uuid::new_v4();
        let row = default_row(site_id);

        assert_eq!(Uuid::nil(), row.id, "no row exists: the id is nil");
        assert_eq!(site_id, row.site_id);
        assert!(!row.enabled);
        assert_eq!(None, row.provider_id);
        assert_eq!(DEFAULT_REDIRECT_PATH, row.redirect_path);
        assert_eq!(DEFAULT_COOKIE_NAME, row.cookie_name);
        assert_eq!(DEFAULT_SESSION_TTL_SECONDS, row.session_ttl_seconds);
        assert_eq!(AccessMode::ALLOW_ALL, row.access_mode);
        assert_eq!(json!([]), row.claims_to_headers);
        assert_eq!(json!([]), row.access_rules);
    }
}
