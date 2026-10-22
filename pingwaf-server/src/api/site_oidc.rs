//! Per-site OpenID Connect authentication.
//!
//! Like basic auth, the gate itself is enforced on the data plane; this module
//! owns the stored provider configuration. The two secrets are masked on the
//! way out — but unlike basic auth, a secret that is *not set* is returned
//! empty rather than masked: public OIDC clients and no-logout setups have a
//! legitimate empty secret, and a blanket mask would leave the dashboard
//! unable to tell "unset" from "set".

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
use crate::models::site_oidc;

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

pub const MAX_ISSUER_LEN: usize = 512;
pub const MAX_CLIENT_ID_LEN: usize = 255;
pub const MAX_CLIENT_SECRET_LEN: usize = 1024;
pub const MAX_COOKIE_SECRET_LEN: usize = 256;
pub const MAX_PATH_LEN: usize = 512;
pub const MAX_URL_LEN: usize = 2048;
pub const MAX_COOKIE_NAME_LEN: usize = 128;
pub const MAX_SCOPES: usize = 32;
pub const MAX_SCOPE_LEN: usize = 128;
pub const MAX_CLAIMS_TO_HEADERS: usize = 32;
pub const MAX_CLAIM_LEN: usize = 128;

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

/// What the dashboard receives: secrets masked only when they are set.
#[derive(Debug, Serialize)]
pub struct OidcView {
    pub id: Uuid,
    pub site_id: Uuid,
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    /// `"***"` when a secret is stored, `""` when it is not.
    pub client_secret: String,
    /// `"***"` when a secret is stored, `""` when it is not.
    pub cookie_secret: String,
    pub redirect_path: String,
    pub logout_path: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub cookie_name: String,
    pub session_ttl_seconds: i32,
    pub claims_to_headers: Vec<OidcClaimToHeader>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateOidcRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// `"***"` keeps the stored secret; `""` clears it.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// `"***"` keeps the stored secret; `""` clears it.
    #[serde(default)]
    pub cookie_secret: Option<String>,
    #[serde(default)]
    pub redirect_path: Option<String>,
    #[serde(default)]
    pub logout_path: Option<String>,
    #[serde(default)]
    pub redirect_url: Option<String>,
    /// Replaces the whole list when present; normalized on write.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub cookie_name: Option<String>,
    #[serde(default)]
    pub session_ttl_seconds: Option<i32>,
    /// Replaces the whole list when present.
    #[serde(default)]
    pub claims_to_headers: Option<Vec<OidcClaimToHeader>>,
}

/// Every field after the request has been merged onto the stored row and
/// validated — the shape the `enabled` guard and the write see.
#[derive(Debug)]
struct ResolvedOidc {
    enabled: bool,
    issuer: String,
    client_id: String,
    client_secret: String,
    cookie_secret: String,
    redirect_path: String,
    logout_path: String,
    redirect_url: String,
    scopes: Vec<String>,
    cookie_name: String,
    session_ttl_seconds: i32,
    claims_to_headers: Vec<OidcClaimToHeader>,
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
    let row = site_oidc::Entity::find()
        .filter(site_oidc::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .unwrap_or_else(|| default_row(id));
    Ok(Json(to_view(&row)?))
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
    let stored_scopes = decode_scopes(&row.scopes)?;
    let stored_claims = decode_claims(&row.claims_to_headers)?;

    let mut resolved = ResolvedOidc {
        enabled: row.enabled,
        issuer: row.issuer.clone(),
        client_id: row.client_id.clone(),
        client_secret: row.client_secret.clone(),
        cookie_secret: row.cookie_secret.clone(),
        redirect_path: row.redirect_path.clone(),
        logout_path: row.logout_path.clone(),
        redirect_url: row.redirect_url.clone(),
        scopes: stored_scopes.clone(),
        cookie_name: row.cookie_name.clone(),
        session_ttl_seconds: row.session_ttl_seconds,
        claims_to_headers: stored_claims.clone(),
    };

    if let Some(issuer) = payload.issuer {
        resolved.issuer = validate_issuer(issuer.trim())?;
    }
    if let Some(client_id) = payload.client_id {
        resolved.client_id = validate_client_id(client_id.trim())?;
    }
    resolved.client_secret = merge_secret(
        payload.client_secret,
        &row.client_secret,
        "client_secret",
        MAX_CLIENT_SECRET_LEN,
    )?
    .unwrap_or_else(|| row.client_secret.clone());
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
    if let Some(scopes) = payload.scopes {
        resolved.scopes = normalize_scopes(scopes)?;
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

    // An enabled gate with a half-filled provider configuration would lock
    // the site out; reject instead of silently downgrading to disabled.
    guard_enabled(&resolved)?;

    let mut active: site_oidc::ActiveModel = row.into();
    active.enabled = Set(resolved.enabled);
    active.issuer = Set(resolved.issuer);
    active.client_id = Set(resolved.client_id);
    active.client_secret = Set(resolved.client_secret);
    active.cookie_secret = Set(resolved.cookie_secret);
    active.redirect_path = Set(resolved.redirect_path);
    active.logout_path = Set(resolved.logout_path);
    active.redirect_url = Set(resolved.redirect_url);
    active.scopes =
        Set(serde_json::to_value(&resolved.scopes).map_err(|err| {
            ApiError::Internal(format!("failed to encode scopes: {err}"))
        })?);
    active.cookie_name = Set(resolved.cookie_name);
    active.session_ttl_seconds = Set(resolved.session_ttl_seconds);
    active.claims_to_headers = Set(serde_json::to_value(
        &resolved.claims_to_headers,
    )
    .map_err(|err| {
        ApiError::Internal(format!("failed to encode claims_to_headers: {err}"))
    })?);
    active.updated_at = Set(chrono::Utc::now());
    let updated = active.update(&state.db).await?;

    // Counts only — the secrets themselves never reach the logs.
    tracing::info!(
        site_id = %id,
        enabled = updated.enabled,
        scopes = resolved.scopes.len(),
        claims = resolved.claims_to_headers.len(),
        "site oidc updated"
    );
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(to_view(&updated)?))
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

/// Validates a non-empty issuer and strips one trailing slash (silently).
fn validate_issuer(issuer: &str) -> Result<String, ApiError> {
    if !issuer.is_empty() {
        if !issuer.starts_with("http://") && !issuer.starts_with("https://") {
            return Err(ApiError::BadRequest(
                "issuer must be an absolute http(s) URL".to_string(),
            ));
        }
        if issuer.len() > MAX_ISSUER_LEN {
            return Err(ApiError::BadRequest(format!(
                "issuer must be at most {MAX_ISSUER_LEN} characters"
            )));
        }
    }
    Ok(issuer.strip_suffix('/').unwrap_or(issuer).to_string())
}

fn validate_client_id(client_id: &str) -> Result<String, ApiError> {
    if client_id.is_empty() || client_id.len() > MAX_CLIENT_ID_LEN {
        return Err(ApiError::BadRequest(format!(
            "client_id must be 1-{MAX_CLIENT_ID_LEN} characters"
        )));
    }
    Ok(client_id.to_string())
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
        return Err(ApiError::BadRequest(
            "redirect_url path must equal redirect_path".to_string(),
        ));
    }
    Ok(())
}

/// Drops empty scopes, dedupes the rest in order and pins `openid` first.
fn normalize_scopes(submitted: Vec<String>) -> Result<Vec<String>, ApiError> {
    if submitted.len() > MAX_SCOPES {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_SCOPES} scopes are supported"
        )));
    }
    let mut normalized: Vec<String> = Vec::with_capacity(submitted.len());
    for scope in submitted {
        let scope = scope.trim().to_string();
        if scope.is_empty() {
            continue;
        }
        if scope.len() > MAX_SCOPE_LEN {
            return Err(ApiError::BadRequest(format!(
                "scope must be 1-{MAX_SCOPE_LEN} characters"
            )));
        }
        if !normalized.contains(&scope) {
            normalized.push(scope);
        }
    }
    // `openid` is what makes the flow an OIDC flow; it always leads.
    if let Some(position) =
        normalized.iter().position(|scope| scope == "openid")
    {
        let openid = normalized.remove(position);
        normalized.insert(0, openid);
    } else {
        normalized.insert(0, "openid".to_string());
    }
    Ok(normalized)
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

/// Rejects an enabled gate over a half-filled provider configuration, in the
/// contract's fixed order. Never downgrades to disabled: an operator who
/// believes authentication is on must not be left with a public site.
fn guard_enabled(resolved: &ResolvedOidc) -> Result<(), ApiError> {
    if !resolved.enabled {
        return Ok(());
    }
    if resolved.issuer.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "issuer is required while oidc is enabled".to_string(),
        ));
    }
    if resolved.client_id.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "client_id is required while oidc is enabled".to_string(),
        ));
    }
    // No `client_secret` requirement: a public client (PKCE only, no secret)
    // is legitimate, and the plugin sends the `client_id` alone for it. The
    // dashboard's `blockedReason` mirrors this list, so the two must agree.
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
    Ok(())
}

/// Reads the stored scopes back out of the JSON column.
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

fn to_view(row: &site_oidc::Model) -> Result<OidcView, ApiError> {
    Ok(OidcView {
        id: row.id,
        site_id: row.site_id,
        enabled: row.enabled,
        issuer: row.issuer.clone(),
        client_id: row.client_id.clone(),
        client_secret: mask_secret(&row.client_secret),
        cookie_secret: mask_secret(&row.cookie_secret),
        redirect_path: row.redirect_path.clone(),
        logout_path: row.logout_path.clone(),
        redirect_url: row.redirect_url.clone(),
        scopes: decode_scopes(&row.scopes)?,
        cookie_name: row.cookie_name.clone(),
        session_ttl_seconds: row.session_ttl_seconds,
        claims_to_headers: decode_claims(&row.claims_to_headers)?,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// The values a site has before anything is stored: disabled, with the
/// defaults the migration and the dashboard both assume.
///
/// Kept in memory — the `id` is nil because no row exists — so a read never
/// has to write, and `PUT` is the only path that inserts.
fn default_row(site_id: Uuid) -> site_oidc::Model {
    let now = chrono::Utc::now();
    site_oidc::Model {
        id: Uuid::nil(),
        site_id,
        enabled: false,
        issuer: String::new(),
        client_id: String::new(),
        client_secret: String::new(),
        cookie_secret: String::new(),
        redirect_path: DEFAULT_REDIRECT_PATH.to_string(),
        logout_path: String::new(),
        redirect_url: String::new(),
        scopes: serde_json::json!(["openid"]),
        cookie_name: DEFAULT_COOKIE_NAME.to_string(),
        session_ttl_seconds: DEFAULT_SESSION_TTL_SECONDS,
        claims_to_headers: serde_json::json!([]),
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
) -> Result<site_oidc::Model, ApiError> {
    if let Some(row) = site_oidc::Entity::find()
        .filter(site_oidc::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
    {
        return Ok(row);
    }

    let row = default_row(site_id);
    let model = site_oidc::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(row.site_id),
        enabled: Set(row.enabled),
        issuer: Set(row.issuer),
        client_id: Set(row.client_id),
        client_secret: Set(row.client_secret),
        cookie_secret: Set(row.cookie_secret),
        redirect_path: Set(row.redirect_path),
        logout_path: Set(row.logout_path),
        redirect_url: Set(row.redirect_url),
        scopes: Set(row.scopes),
        cookie_name: Set(row.cookie_name),
        session_ttl_seconds: Set(row.session_ttl_seconds),
        claims_to_headers: Set(row.claims_to_headers),
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
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            cookie_secret: String::new(),
            redirect_path: DEFAULT_REDIRECT_PATH.to_string(),
            logout_path: String::new(),
            redirect_url: String::new(),
            scopes: vec!["openid".to_string()],
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            session_ttl_seconds: DEFAULT_SESSION_TTL_SECONDS,
            claims_to_headers: Vec::new(),
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

    /// A read of a site that never configured OIDC answers the defaults
    /// without storing anything: the nil id is what tells a caller no row
    /// exists. `PUT` is the only path that inserts, so a read-only account
    /// cannot write through a GET, and concurrent reads cannot race on the
    /// unique `site_id`.
    #[test]
    fn default_row_describes_an_unconfigured_site_without_storing_it() {
        let site_id = Uuid::new_v4();
        let row = default_row(site_id);

        assert_eq!(Uuid::nil(), row.id, "no row exists: the id is nil");
        assert_eq!(site_id, row.site_id);
        assert_eq!(false, row.enabled);
        assert_eq!(DEFAULT_REDIRECT_PATH, row.redirect_path);
        assert_eq!(DEFAULT_COOKIE_NAME, row.cookie_name);
        assert_eq!(DEFAULT_SESSION_TTL_SECONDS, row.session_ttl_seconds);
        assert_eq!(json!(["openid"]), row.scopes);
        assert_eq!(json!([]), row.claims_to_headers);

        // What the dashboard sees before anything is saved: no secret to mask.
        let view = to_view(&row).expect("the default row renders as a view");
        assert_eq!("", view.client_secret);
        assert_eq!("", view.cookie_secret);
        assert_eq!(Uuid::nil(), view.id);
    }

    #[test]
    fn the_mask_keeps_the_stored_secret() {
        assert_eq!(
            merge_secret(
                Some(OIDC_SECRET_MASK.to_string()),
                "hunter2",
                "client_secret",
                MAX_CLIENT_SECRET_LEN
            )
            .unwrap(),
            Some("hunter2".to_string())
        );
        // A real value replaces the stored one; absence leaves it alone.
        assert_eq!(
            merge_secret(
                Some("new".to_string()),
                "old",
                "client_secret",
                MAX_CLIENT_SECRET_LEN
            )
            .unwrap(),
            Some("new".to_string())
        );
        assert_eq!(
            merge_secret(None, "old", "client_secret", MAX_CLIENT_SECRET_LEN)
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_mask_without_a_stored_secret_is_rejected() {
        assert!(merge_secret(
            Some(OIDC_SECRET_MASK.to_string()),
            "",
            "client_secret",
            MAX_CLIENT_SECRET_LEN
        )
        .is_err());
    }

    #[test]
    fn an_overlong_secret_is_rejected_but_empty_clears() {
        let long = "x".repeat(MAX_CLIENT_SECRET_LEN + 1);
        assert!(merge_secret(
            Some(long),
            "old",
            "client_secret",
            MAX_CLIENT_SECRET_LEN
        )
        .is_err());
        assert_eq!(
            merge_secret(
                Some(String::new()),
                "old",
                "cookie_secret",
                MAX_COOKIE_SECRET_LEN
            )
            .unwrap(),
            Some(String::new())
        );
    }

    #[test]
    fn absent_fields_keep_stored_values() {
        // Merging is per-field: whatever the request omits stays as stored.
        assert_eq!(
            validate_issuer("https://idp.example.com/").unwrap(),
            "https://idp.example.com"
        );
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("set"), OIDC_SECRET_MASK);
    }

    #[test]
    fn the_enabled_guard_checks_in_contract_order() {
        let mut value = resolved(|r| {
            r.issuer = "https://idp.example.com".to_string();
            r.client_id = "client".to_string();
            r.client_secret = "secret".to_string();
            r.cookie_secret = "x".repeat(MIN_COOKIE_SECRET_LEN);
        });
        assert!(guard_enabled(&value).is_ok());

        // 1. issuer
        value.issuer = "  ".to_string();
        assert_eq!(
            guard_enabled(&value).unwrap_err().to_string(),
            "issuer is required while oidc is enabled"
        );
        value.issuer = "https://idp.example.com".to_string();
        // 2. client_id
        value.client_id = String::new();
        assert_eq!(
            guard_enabled(&value).unwrap_err().to_string(),
            "client_id is required while oidc is enabled"
        );
        value.client_id = "client".to_string();
        // 3. client_secret: an empty one is a public client, not an error.
        value.client_secret = String::new();
        assert!(
            guard_enabled(&value).is_ok(),
            "a public client has no secret and must still be enabled"
        );
        value.client_secret = "secret".to_string();
        // 4. cookie_secret
        value.cookie_secret = String::new();
        assert_eq!(
            guard_enabled(&value).unwrap_err().to_string(),
            "cookie_secret is required while oidc is enabled"
        );
        // 5. cookie_secret entropy
        value.cookie_secret = "short".to_string();
        assert_eq!(
            guard_enabled(&value).unwrap_err().to_string(),
            format!(
                "cookie_secret must be at least {MIN_COOKIE_SECRET_LEN} characters"
            )
        );
        // A disabled row passes no matter how empty it is.
        value.enabled = false;
        assert!(guard_enabled(&value).is_ok());
    }

    #[test]
    fn scopes_are_normalized_with_openid_first() {
        let scopes =
            normalize_scopes(vec!["email".into(), "profile".into()]).unwrap();
        assert_eq!(scopes, vec!["openid", "email", "profile"]);

        // Deduped in order; an existing openid moves to the front.
        let scopes = normalize_scopes(vec![
            "openid".into(),
            "email".into(),
            " email ".into(),
            "".into(),
        ])
        .unwrap();
        assert_eq!(scopes, vec!["openid", "email"]);

        assert!(normalize_scopes(vec!["x".repeat(MAX_SCOPE_LEN + 1)]).is_err());
        let many = vec!["s".to_string(); MAX_SCOPES + 1];
        assert!(normalize_scopes(many).is_err());
    }

    #[test]
    fn claims_reject_duplicates_and_forbidden_headers() {
        let ok = vec![claim("email", "X-Auth-Email")];
        assert_eq!(validate_claims(ok).unwrap().len(), 1);

        // Duplicate claim (exact match).
        assert!(validate_claims(vec![
            claim("email", "X-Auth-Email"),
            claim("email", "X-Other")
        ])
        .is_err());
        // Duplicate header, case-insensitive.
        assert!(validate_claims(vec![
            claim("email", "X-Auth-Email"),
            claim("sub", "x-auth-email")
        ])
        .is_err());
        // Framing headers must never come from token data.
        for header in FORBIDDEN_CLAIM_HEADERS {
            assert!(validate_claims(vec![claim("email", header)]).is_err());
        }
        // Nor the request's own credentials or its client address: a claim in
        // `Authorization` would replace the origin's authentication, and one
        // in `X-Forwarded-For` would rewrite the address the origin sees.
        for header in [
            "Authorization",
            "Cookie",
            "Set-Cookie",
            "X-Forwarded-For",
            "X-Forwarded-Proto",
            "X-Real-IP",
        ] {
            assert!(
                validate_claims(vec![claim("email", header)]).is_err(),
                "{header} must not be set from a claim"
            );
        }
        // Not a valid header name at all.
        assert!(validate_claims(vec![claim("email", "bad header!")]).is_err());
        // Empty / overlong claim.
        assert!(validate_claims(vec![claim("  ", "X-Auth")]).is_err());
        assert!(validate_claims(vec![claim(
            &"c".repeat(MAX_CLAIM_LEN + 1),
            "X-Auth"
        )])
        .is_err());
    }

    #[test]
    fn paths_and_urls_are_validated() {
        assert!(validate_path("redirect_path", "/cb").is_ok());
        assert!(validate_path("redirect_path", "/").is_err());
        assert!(validate_path("redirect_path", "cb").is_err());
        assert!(validate_path("redirect_path", "/cb?a=1").is_err());
        assert!(validate_path("redirect_path", "/cb#x").is_err());
        assert!(validate_path("redirect_path", "/cb\\x").is_err());
        assert!(validate_path("redirect_path", "/cb x").is_err());
        assert!(
            validate_path("redirect_path", &"/".repeat(MAX_PATH_LEN + 1))
                .is_err()
        );

        assert!(validate_issuer("").is_ok());
        assert!(validate_issuer("ftp://idp").is_err());
        assert!(validate_issuer(&"x".repeat(MAX_ISSUER_LEN + 1)).is_err());

        assert!(validate_client_id("").is_err());
        assert!(validate_cookie_name("good_name-1.2").is_ok());
        assert!(validate_cookie_name("bad name").is_err());
        assert!(validate_cookie_name("__Host-session").is_err());
        assert!(validate_session_ttl(59).is_err());
        assert!(validate_session_ttl(60).is_ok());
        assert!(validate_session_ttl(MAX_SESSION_TTL_SECONDS + 1).is_err());

        assert!(validate_redirect_url(
            "https://site/oauth2/callback",
            "/oauth2/callback"
        )
        .is_ok());
        assert!(validate_redirect_url("", "/x").is_ok());
        assert!(validate_redirect_url(
            "https://site/other",
            "/oauth2/callback"
        )
        .is_err());
        assert!(validate_redirect_url(
            "ftp://site/oauth2/callback",
            "/oauth2/callback"
        )
        .is_err());
    }

    #[test]
    fn stored_json_roundtrips_and_a_foreign_shape_fails() {
        let scopes = json!(["openid", "email"]);
        assert_eq!(decode_scopes(&scopes).unwrap().len(), 2);
        assert!(decode_scopes(&json!({ "nope": true })).is_err());

        let claims = json!([{ "claim": "email", "header": "X-Auth-Email" }]);
        let decoded = decode_claims(&claims).unwrap();
        assert_eq!(decoded[0].claim, "email");
        assert!(decode_claims(&json!([{ "claim": 1 }])).is_err());
    }

    #[test]
    fn the_view_masks_only_set_secrets() {
        let scopes = serde_json::json!(["openid"]);
        let mut row = site_oidc::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::new_v4(),
            enabled: false,
            issuer: String::new(),
            client_id: String::new(),
            client_secret: "secret".to_string(),
            cookie_secret: String::new(),
            redirect_path: DEFAULT_REDIRECT_PATH.to_string(),
            logout_path: String::new(),
            redirect_url: String::new(),
            scopes: scopes.clone(),
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            session_ttl_seconds: DEFAULT_SESSION_TTL_SECONDS,
            claims_to_headers: serde_json::json!([]),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let view = to_view(&row).unwrap();
        assert_eq!(view.client_secret, OIDC_SECRET_MASK);
        assert_eq!(view.cookie_secret, "");
        assert_eq!(view.scopes, vec!["openid".to_string()]);

        row.client_secret = String::new();
        row.cookie_secret = "set".to_string();
        let view = to_view(&row).unwrap();
        assert_eq!(view.client_secret, "");
        assert_eq!(view.cookie_secret, OIDC_SECRET_MASK);
    }
}
