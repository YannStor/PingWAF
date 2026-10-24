//! Identity providers for the console's Account page.
//!
//! An OIDC provider — its issuer, client credentials and scopes — belongs to
//! the deployment, not to a site: one Keycloak realm usually fronts several,
//! and storing its client secret once means rotating it is one edit rather
//! than one per site. Sites then reference a provider by id and carry only
//! what genuinely differs per site (see [`crate::api::site_oidc`]).
//!
//! `client_secret` is masked on every read path: `"***"` when set, `""` when
//! not, so the dashboard can tell "unset" from "set" (a public client has a
//! legitimate empty secret).
//!
//! Deleting a provider that sites still reference is refused: the foreign key
//! is `ON DELETE SET NULL`, so the delete would silently leave those sites
//! unconfigured — visible, but only if someone looks. A `409` that names the
//! sites is the failure an operator can act on.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use std::collections::HashMap;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AdminUser;
use crate::models::{oidc_provider, site_oidc};

/// Substituted for a stored secret in responses.
pub const OIDC_PROVIDER_SECRET_MASK: &str = "***";

pub const MAX_PROVIDER_NAME_LEN: usize = 128;
pub const MAX_ISSUER_LEN: usize = 512;
pub const MAX_CLIENT_ID_LEN: usize = 255;
pub const MAX_CLIENT_SECRET_LEN: usize = 1024;
pub const MAX_SCOPES: usize = 32;
pub const MAX_SCOPE_LEN: usize = 128;

/// What the dashboard receives. The secret is masked, never echoed.
#[derive(Debug, Serialize)]
pub struct ProviderView {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    /// `"***"` when a secret is stored, `""` when it is not.
    pub client_secret: String,
    pub scopes: Vec<String>,
    /// Sites whose gate points at this provider, so the dashboard can say
    /// what a delete or a disable would affect before it is attempted.
    pub site_count: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProviderRequest {
    pub name: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateProviderRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// `"***"` keeps the stored secret; `""` clears it.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Replaces the whole list when present.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/oidc/providers", get(list).post(create))
        .route(
            "/oidc/providers/{provider_id}",
            get(show).put(update).delete(destroy),
        )
}

/// `GET /api/v1/oidc/providers`
async fn list(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<ProviderView>>, ApiError> {
    let rows = oidc_provider::Entity::find()
        .order_by_asc(oidc_provider::Column::Name)
        .all(&state.db)
        .await?;
    // One query for every site reference rather than one per provider: the
    // count is shown on the Account page, which loads on every visit, and a
    // deployment with a dozen providers would otherwise answer it with a dozen
    // round trips.
    let referencing = site_oidc::Entity::find().all(&state.db).await?;
    let mut counts: HashMap<Uuid, u64> = HashMap::new();
    for row in referencing {
        if let Some(provider_id) = row.provider_id {
            *counts.entry(provider_id).or_default() += 1;
        }
    }
    let views = rows
        .into_iter()
        .map(|row| {
            let site_count = counts.get(&row.id).copied().unwrap_or_default();
            view_of(row, site_count)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(views))
}

/// The response shape, from a row and how many sites point at it.
fn view_of(
    row: oidc_provider::Model,
    site_count: u64,
) -> Result<ProviderView, ApiError> {
    Ok(ProviderView {
        id: row.id,
        name: row.name.clone(),
        enabled: row.enabled,
        issuer: row.issuer.clone(),
        client_id: row.client_id.clone(),
        client_secret: mask_secret(&row.client_secret),
        scopes: crate::api::site_oidc::decode_scopes(&row.scopes)?,
        site_count,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// `GET /api/v1/oidc/providers/{provider_id}`
async fn show(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(provider_id): Path<String>,
) -> Result<Json<ProviderView>, ApiError> {
    let id = parse_uuid(&provider_id)?;
    let row = load(&state, id).await?;
    Ok(Json(to_view(&state, &row).await?))
}

/// `POST /api/v1/oidc/providers`
async fn create(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(payload): Json<CreateProviderRequest>,
) -> Result<Json<ProviderView>, ApiError> {
    let name = validate_name(&payload.name)?;
    let issuer = validate_issuer(&payload.issuer)?;
    let client_id = validate_client_id(&payload.client_id)?;
    let scopes = normalize_scopes(payload.scopes.unwrap_or_default())?;
    let client_secret = payload.client_secret.unwrap_or_default();
    if client_secret.len() > MAX_CLIENT_SECRET_LEN {
        return Err(ApiError::BadRequest(format!(
            "client_secret must be at most {MAX_CLIENT_SECRET_LEN} characters"
        )));
    }

    // A name is the handle operators use in the site's picker, so it has to be
    // unique; the database would answer a 500 for the constraint, and this
    // says what actually happened.
    if oidc_provider::Entity::find()
        .filter(oidc_provider::Column::Name.eq(name.as_str()))
        .one(&state.db)
        .await?
        .is_some()
    {
        return Err(ApiError::BadRequest(format!(
            "a provider named '{name}' already exists"
        )));
    }

    let now = chrono::Utc::now();
    let model = oidc_provider::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(name),
        enabled: Set(payload.enabled.unwrap_or(true)),
        issuer: Set(issuer),
        client_id: Set(client_id),
        client_secret: Set(client_secret),
        scopes: Set(serde_json::to_value(&scopes).map_err(|err| {
            ApiError::Internal(format!("failed to encode scopes: {err}"))
        })?),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(
        provider_id = %model.id,
        by = %admin.email,
        scopes = scopes.len(),
        "oidc provider created"
    );
    Ok(Json(to_view(&state, &model).await?))
}

/// `PUT /api/v1/oidc/providers/{provider_id}`
async fn update(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(provider_id): Path<String>,
    Json(payload): Json<UpdateProviderRequest>,
) -> Result<Json<ProviderView>, ApiError> {
    let id = parse_uuid(&provider_id)?;
    let row = load(&state, id).await?;

    let mut name = row.name.clone();
    if let Some(submitted) = payload.name {
        let candidate = validate_name(&submitted)?;
        if candidate != row.name {
            let taken = oidc_provider::Entity::find()
                .filter(oidc_provider::Column::Name.eq(candidate.as_str()))
                .one(&state.db)
                .await?
                .is_some();
            if taken {
                return Err(ApiError::BadRequest(format!(
                    "a provider named '{candidate}' already exists"
                )));
            }
        }
        name = candidate;
    }

    let mut issuer = row.issuer.clone();
    if let Some(submitted) = payload.issuer {
        issuer = validate_issuer(&submitted)?;
    }
    let mut client_id = row.client_id.clone();
    if let Some(submitted) = payload.client_id {
        client_id = validate_client_id(&submitted)?;
    }

    let client_secret = match payload.client_secret {
        None => row.client_secret.clone(),
        Some(value) if value == OIDC_PROVIDER_SECRET_MASK => {
            if row.client_secret.is_empty() {
                return Err(ApiError::BadRequest(
                    "no stored client_secret; send a value instead of the mask"
                        .to_string(),
                ));
            }
            row.client_secret.clone()
        },
        Some(value) => {
            if value.len() > MAX_CLIENT_SECRET_LEN {
                return Err(ApiError::BadRequest(format!(
                    "client_secret must be at most {MAX_CLIENT_SECRET_LEN} characters"
                )));
            }
            value
        },
    };

    let scopes = match payload.scopes {
        Some(submitted) => normalize_scopes(submitted)?,
        None => crate::api::site_oidc::decode_scopes(&row.scopes)?,
    };

    let mut active: oidc_provider::ActiveModel = row.into();
    active.name = Set(name);
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    active.issuer = Set(issuer);
    active.client_id = Set(client_id);
    active.client_secret = Set(client_secret);
    active.scopes = Set(serde_json::to_value(&scopes).map_err(|err| {
        ApiError::Internal(format!("failed to encode scopes: {err}"))
    })?);
    active.updated_at = Set(chrono::Utc::now());
    let updated = active.update(&state.db).await?;

    tracing::info!(
        provider_id = %updated.id,
        by = %admin.email,
        enabled = updated.enabled,
        scopes = scopes.len(),
        "oidc provider updated"
    );

    // Sites that reference this provider now enforce with the new settings;
    // the data plane has to hear about it or they keep the old ones until the
    // next unrelated change.
    for site_id in referencing_sites(&state, updated.id).await? {
        crate::grpc::notify_config_changed(&state, site_id, Some(&admin.email))
            .await;
    }

    Ok(Json(to_view(&state, &updated).await?))
}

/// `DELETE /api/v1/oidc/providers/{provider_id}`
async fn destroy(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(provider_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_uuid(&provider_id)?;
    let row = load(&state, id).await?;

    // Refuse while sites still point here. The foreign key is `SET NULL`, so
    // the delete would succeed and leave each site silently unconfigured —
    // a state only someone who went looking would notice.
    let sites = referencing_sites(&state, id).await?;
    if !sites.is_empty() {
        return Err(ApiError::Conflict(format!(
            "{} site(s) still use this provider; point them elsewhere first",
            sites.len()
        )));
    }

    let name = row.name.clone();
    oidc_provider::Entity::delete_by_id(id)
        .exec(&state.db)
        .await?;
    tracing::info!(
        provider_id = %id,
        provider = %name,
        by = %admin.email,
        "oidc provider deleted"
    );
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// Site ids whose gate points at this provider, in a stable order.
async fn referencing_sites(
    state: &AppState,
    provider_id: Uuid,
) -> Result<Vec<Uuid>, ApiError> {
    let rows = site_oidc::Entity::find()
        .filter(site_oidc::Column::ProviderId.eq(provider_id))
        .order_by_asc(site_oidc::Column::SiteId)
        .all(&state.db)
        .await?;
    Ok(rows.into_iter().map(|row| row.site_id).collect())
}

async fn load(
    state: &AppState,
    id: Uuid,
) -> Result<oidc_provider::Model, ApiError> {
    oidc_provider::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("provider not found".to_string()))
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| {
        ApiError::BadRequest("provider id is not a uuid".to_string())
    })
}

async fn to_view(
    state: &AppState,
    row: &oidc_provider::Model,
) -> Result<ProviderView, ApiError> {
    let site_count = site_oidc::Entity::find()
        .filter(site_oidc::Column::ProviderId.eq(row.id))
        .count(&state.db)
        .await?;
    view_of(row.clone(), site_count)
}

fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        OIDC_PROVIDER_SECRET_MASK.to_string()
    }
}

fn validate_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_PROVIDER_NAME_LEN {
        return Err(ApiError::BadRequest(format!(
            "name must be 1-{MAX_PROVIDER_NAME_LEN} characters"
        )));
    }
    Ok(name.to_string())
}

/// An absolute http(s) issuer, without a trailing slash.
///
/// The slash is stripped rather than rejected: the discovery URL is built by
/// appending `/.well-known/openid-configuration`, and the plugin strips it
/// too, so accepting both spellings here keeps one form in the database.
fn validate_issuer(issuer: &str) -> Result<String, ApiError> {
    let issuer = issuer.trim();
    if issuer.is_empty() || issuer.len() > MAX_ISSUER_LEN {
        return Err(ApiError::BadRequest(format!(
            "issuer must be 1-{MAX_ISSUER_LEN} characters"
        )));
    }
    let parsed: reqwest::Url = issuer.parse().map_err(|_| {
        ApiError::BadRequest(
            "issuer must be an absolute http(s) URL".to_string(),
        )
    })?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(ApiError::BadRequest(
            "issuer must be an absolute http(s) URL".to_string(),
        ));
    }
    Ok(issuer.trim_end_matches('/').to_string())
}

fn validate_client_id(client_id: &str) -> Result<String, ApiError> {
    let client_id = client_id.trim();
    if client_id.is_empty() || client_id.len() > MAX_CLIENT_ID_LEN {
        return Err(ApiError::BadRequest(format!(
            "client_id must be 1-{MAX_CLIENT_ID_LEN} characters"
        )));
    }
    Ok(client_id.to_string())
}

/// Scopes, deduplicated, with `openid` first.
///
/// `openid` is what makes the response an OIDC one at all; asking for a
/// provider without it is a mistake, so it is added rather than validated
/// against.
fn normalize_scopes(submitted: Vec<String>) -> Result<Vec<String>, ApiError> {
    if submitted.len() > MAX_SCOPES {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_SCOPES} scopes are supported"
        )));
    }
    let mut scopes = vec!["openid".to_string()];
    for scope in submitted {
        let scope = scope.trim().to_string();
        if scope.is_empty() {
            continue;
        }
        if scope.len() > MAX_SCOPE_LEN {
            return Err(ApiError::BadRequest(format!(
                "scope must be at most {MAX_SCOPE_LEN} characters"
            )));
        }
        if scope.contains(char::is_whitespace) {
            return Err(ApiError::BadRequest(format!(
                "scope '{scope}' must not contain whitespace"
            )));
        }
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!("keycloak", validate_name("  keycloak  ").unwrap());
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(MAX_PROVIDER_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn issuers_must_be_absolute_http_urls_without_a_trailing_slash() {
        assert_eq!(
            "https://idp.test/realms/main",
            validate_issuer("https://idp.test/realms/main/").unwrap()
        );
        assert_eq!(
            "https://idp.test",
            validate_issuer("https://idp.test").unwrap()
        );
        assert!(validate_issuer("idp.test").is_err());
        assert!(validate_issuer("ftp://idp.test").is_err());
        assert!(validate_issuer("").is_err());
    }

    #[test]
    fn client_ids_are_required() {
        assert_eq!("pingap", validate_client_id(" pingap ").unwrap());
        assert!(validate_client_id("").is_err());
        assert!(validate_client_id(&"x".repeat(MAX_CLIENT_ID_LEN + 1)).is_err());
    }

    #[test]
    fn scopes_are_deduplicated_with_openid_first() {
        assert_eq!(
            vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string()
            ],
            normalize_scopes(vec![
                "email".to_string(),
                "openid".to_string(),
                "email".to_string(),
                " profile ".to_string(),
            ])
            .unwrap()
        );
        // An empty submission still asks for openid: that is what makes the
        // answer an OIDC one.
        assert_eq!(
            vec!["openid".to_string()],
            normalize_scopes(Vec::new()).unwrap()
        );
        assert!(normalize_scopes(vec!["a b".to_string()]).is_err());
        assert!(normalize_scopes(vec!["x".repeat(MAX_SCOPE_LEN + 1)]).is_err());
    }

    #[test]
    fn only_a_set_secret_is_masked() {
        assert_eq!("", mask_secret(""));
        assert_eq!(OIDC_PROVIDER_SECRET_MASK, mask_secret("s3cret"));
    }

    #[test]
    fn a_bad_provider_id_is_a_bad_request_not_a_panic() {
        assert!(parse_uuid("not-a-uuid").is_err());
        assert!(parse_uuid(&Uuid::new_v4().to_string()).is_ok());
    }
}
