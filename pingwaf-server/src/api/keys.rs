//! API key management.
//!
//! Agents authenticate with an API key rather than a user password. Keys are
//! stored as bcrypt hashes, so the plaintext value is only ever returned once —
//! at creation time — and the row keeps an 8 character prefix for display.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{
    non_empty, parse_datetime, parse_uuid, Page, Pagination,
};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::password::{hash_password_with_cost, verify_password};
use crate::auth::AuthUser;
use crate::models::{api_key, permission, role, user};

/// Human visible prefix length, matching the `key_prefix` column width.
pub const KEY_PREFIX_LENGTH: usize = 8;
/// bcrypt cost used for API keys. Keys are verified on every agent
/// registration, so this is deliberately lower than the interactive default.
const KEY_HASH_COST: u32 = 10;

/// Name of the all-in-one bootstrap key seeded at startup (`lib.rs`).
pub const BOOTSTRAP_KEY_NAME: &str = "_all-in-one-bootstrap";
/// Name prefix of the enrollment keys minted by `POST /agents/enroll`.
pub const AGENT_ENROLLMENT_PREFIX: &str = "agent-enrollment-";

/// True for keys the system mints on its own (bootstrap, agent enrollment).
/// The UI shows these as "system" instead of a creator account, and guards
/// their deletion: revoking them strands agent (re-)registration until a new
/// key is minted.
pub fn is_system_key(name: &str) -> bool {
    name == BOOTSTRAP_KEY_NAME || name.starts_with(AGENT_ENROLLMENT_PREFIX)
}

/// Key metadata; the hash itself is skipped by serde at the model level.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Owning account's email; `None` for system-minted keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    /// True when the key was minted by the system (bootstrap, enrollment).
    pub is_system: bool,
    /// Only populated by `POST /keys`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl From<api_key::Model> for ApiKeyResponse {
    fn from(model: api_key::Model) -> Self {
        Self {
            id: model.id,
            user_id: model.user_id,
            name: model.name,
            key_prefix: model.key_prefix,
            permissions: model.permissions,
            expires_at: model.expires_at,
            last_used_at: model.last_used_at,
            created_at: model.created_at,
            creator: None,
            is_system: false,
            key: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    #[serde(default = "default_permissions")]
    pub permissions: Vec<String>,
    /// RFC 3339 instant after which the key stops working; `None` = never.
    #[serde(default)]
    pub expires_at: Option<String>,
}

fn default_permissions() -> Vec<String> {
    vec![permission::AGENT.to_string(), permission::READ.to_string()]
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/keys", get(list).post(create))
        .route("/keys/{key_id}", axum::routing::delete(remove))
}

/// `GET /api/v1/keys`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<ApiKeyResponse>>, ApiError> {
    let pagination = query.pagination.normalise();
    let mut condition = Condition::all();
    if !current.is_admin() {
        condition = condition.add(api_key::Column::UserId.eq(current.id));
    }

    let paginator = api_key::Entity::find()
        .filter(condition)
        .order_by_desc(api_key::Column::CreatedAt)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;

    // Batch-resolve owners for the creator column. System-minted keys keep
    // `creator: None`: the attribution row is incidental (bootstrap lands on
    // the first admin), and the UI labels them "system" instead.
    let owner_ids: Vec<Uuid> = {
        let mut ids: Vec<Uuid> = rows.iter().map(|k| k.user_id).collect();
        ids.sort();
        ids.dedup();
        ids
    };
    let owners: std::collections::HashMap<Uuid, String> =
        if owner_ids.is_empty() {
            std::collections::HashMap::new()
        } else {
            user::Entity::find()
                .filter(user::Column::Id.is_in(owner_ids))
                .all(&state.db)
                .await?
                .into_iter()
                .map(|u| (u.id, u.email))
                .collect()
        };

    let items: Vec<ApiKeyResponse> = rows
        .into_iter()
        .map(|model| {
            let is_system = is_system_key(&model.name);
            let creator = if is_system {
                None
            } else {
                owners.get(&model.user_id).cloned()
            };
            let mut body = ApiKeyResponse::from(model);
            body.creator = creator;
            body.is_system = is_system;
            body
        })
        .collect();

    Ok(Json(Page::new(items, total, pagination)))
}

/// `POST /api/v1/keys`
async fn create(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<CreateKeyRequest>,
) -> Result<Response, ApiError> {
    // Every account may mint its own keys; the permissions granted are
    // capped at the caller's own power (see below).

    let name = payload.name.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::BadRequest(
            "key name must be 1-100 characters".to_string(),
        ));
    }

    let mut permissions = normalise_permissions(&payload.permissions)?;
    if permissions.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one permission is required".to_string(),
        ));
    }
    // Self-service keys for read-only roles never exceed read: agents need
    // the `agent` permission, which only admins may delegate.
    if !current.is_admin() {
        if current.must_change_password {
            return Err(ApiError::Forbidden(
                "change your password before creating API keys".to_string(),
            ));
        }
        permissions = vec![permission::READ.to_string()];
    }

    let expires_at = match non_empty(&payload.expires_at) {
        Some(raw) => {
            let instant = parse_datetime(&raw, "expires_at")?;
            if instant <= Utc::now() {
                return Err(ApiError::BadRequest(
                    "expires_at must be in the future".to_string(),
                ));
            }
            Some(instant)
        },
        None => None,
    };

    let (model, plaintext) =
        mint_key(&state, current.id, name, permissions, expires_at).await?;

    let mut body = ApiKeyResponse::from(model);
    // A user-minted key may borrow a system-looking name; surface what the
    // name implies so the strong-delete guard matches what the list shows.
    body.is_system = is_system_key(&body.name);
    if !body.is_system {
        body.creator = Some(current.email.clone());
    }
    body.key = Some(plaintext);
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// `DELETE /api/v1/keys/{key_id}`
async fn remove(
    State(state): State<AppState>,
    current: AuthUser,
    Path(key_id): Path<String>,
) -> Result<Response, ApiError> {
    // Any account may revoke its own keys; the filter below already restricts
    // non-admins to their own rows.
    let id = parse_uuid(&key_id, "key id")?;

    let mut query = api_key::Entity::delete_by_id(id);
    if !current.is_admin() {
        query = query.filter(api_key::Column::UserId.eq(current.id));
    }
    let result = query.exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(ApiError::NotFound(format!("API key {id} not found")));
    }

    tracing::info!(key_id = %id, "API key revoked");
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Generates a `pwk_…` key with 128 bits of entropy from two UUIDv4 payloads.
pub fn generate_key() -> String {
    format!("pwk_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Stores a new API key and hands back the plaintext, which the caller shows
/// once and nothing persists.
pub(crate) async fn mint_key(
    state: &AppState,
    user_id: Uuid,
    name: String,
    permissions: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(api_key::Model, String), ApiError> {
    let plaintext = generate_key();
    // bcrypt is deliberately slow; keep it off the async worker pool
    // (2026-10-18 audit: concurrent key creation/logins starved handlers).
    let plaintext_for_hash = plaintext.clone();
    let key_hash = tokio::task::spawn_blocking(move || {
        hash_password_with_cost(&plaintext_for_hash, KEY_HASH_COST)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        name: Set(name),
        key_hash: Set(key_hash),
        key_prefix: Set(plaintext[..KEY_PREFIX_LENGTH].to_string()),
        permissions: Set(permissions),
        expires_at: Set(expires_at),
        last_used_at: Set(None),
        created_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(key_id = %model.id, owner = %user_id, "API key created");
    Ok((model, plaintext))
}

/// Validates, de-duplicates and sorts the requested permission set.
fn normalise_permissions(raw: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::new();
    for value in raw {
        let trimmed = value.trim().to_lowercase();
        if trimmed.is_empty() {
            continue;
        }
        if !permission::is_valid(&trimmed) {
            return Err(ApiError::BadRequest(format!(
                "unknown permission '{trimmed}'"
            )));
        }
        if !out.contains(&trimmed) {
            out.push(trimmed);
        }
    }
    out.sort();
    Ok(out)
}

/// Resolves a raw API key to the key row and its owning user.
///
/// The key prefix narrows the candidate set (it is indexed) and each candidate is
/// then bcrypt-verified, which keeps the lookup constant-ish time and avoids
/// storing the plaintext or a reversible digest.
pub async fn authenticate_api_key(
    db: &DatabaseConnection,
    raw_key: &str,
) -> Result<(api_key::Model, user::Model), ApiError> {
    let raw_key = raw_key.trim();
    if raw_key.len() < KEY_PREFIX_LENGTH {
        return Err(ApiError::Unauthorized("invalid API key".to_string()));
    }

    let candidates = api_key::Entity::find()
        .filter(api_key::Column::KeyPrefix.eq(&raw_key[..KEY_PREFIX_LENGTH]))
        .all(db)
        .await?;

    for candidate in candidates {
        let raw = raw_key.to_string();
        let stored = candidate.key_hash.clone();
        let matches =
            tokio::task::spawn_blocking(move || verify_password(&raw, &stored))
                .await
                .map_err(|err| ApiError::Internal(err.to_string()))?
                .map_err(|err| ApiError::Internal(err.to_string()))?;
        if !matches {
            continue;
        }
        if let Some(expires_at) = candidate.expires_at {
            if expires_at <= Utc::now() {
                tracing::warn!(key_id = %candidate.id, "expired API key presented");
                return Err(ApiError::Unauthorized(
                    "API key has expired".to_string(),
                ));
            }
        }

        let owner = user::Entity::find_by_id(candidate.user_id)
            .one(db)
            .await?
            .ok_or_else(|| {
                ApiError::Unauthorized(
                    "API key owner no longer exists".to_string(),
                )
            })?;
        if owner.disabled {
            return Err(ApiError::Unauthorized(
                "API key owner is disabled".to_string(),
            ));
        }
        if !role::is_valid(&owner.role) {
            return Err(ApiError::Unauthorized(
                "API key owner has an unknown role".to_string(),
            ));
        }

        // Record usage without failing the request when the write races.
        let mut touched: api_key::ActiveModel = candidate.clone().into();
        touched.last_used_at = Set(Some(Utc::now()));
        if let Err(err) = touched.update(db).await {
            tracing::warn!(error = %err, key_id = %candidate.id, "could not record key usage");
        }

        return Ok((candidate, owner));
    }

    Err(ApiError::Unauthorized("invalid API key".to_string()))
}

/// True when the key is allowed to register agents and ship telemetry.
pub fn key_allows_agent(key: &api_key::Model) -> bool {
    key.permissions.is_empty()
        || key.permissions.iter().any(|p| p == permission::AGENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_have_a_stable_prefix() {
        let key = generate_key();
        assert!(key.starts_with("pwk_"));
        assert_eq!(key.len(), 4 + 64);
        assert_eq!(key[..KEY_PREFIX_LENGTH].len(), KEY_PREFIX_LENGTH);
        assert_ne!(generate_key(), key);
    }

    #[test]
    fn system_keys_are_recognised_by_name_convention() {
        assert!(is_system_key("_all-in-one-bootstrap"));
        assert!(is_system_key("agent-enrollment-20261012-091500"));
        // Ordinary operator-chosen names are not system keys, even when they
        // flirt with the conventions.
        assert!(!is_system_key("agent-enrollment"));
        assert!(!is_system_key("bootstrap"));
        assert!(!is_system_key("ci-deploy"));
        assert!(!is_system_key(""));
    }

    #[test]
    fn permissions_are_normalised() {
        let out = normalise_permissions(&[
            "AGENT".into(),
            " agent ".into(),
            "read".into(),
        ])
        .unwrap();
        assert_eq!(out, vec!["agent".to_string(), "read".to_string()]);
        assert!(normalise_permissions(&["admin-all".into()]).is_err());
        assert!(normalise_permissions(&[]).unwrap().is_empty());
    }

    #[test]
    fn agent_permission_check() {
        let key = api_key::Model {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "agent".into(),
            key_hash: String::new(),
            key_prefix: "pwk_abcd".into(),
            permissions: vec![permission::AGENT.to_string()],
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
        };
        assert!(key_allows_agent(&key));

        let mut read_only = key.clone();
        read_only.permissions = vec![permission::READ.to_string()];
        assert!(!key_allows_agent(&read_only));

        let mut empty = key.clone();
        empty.permissions = Vec::new();
        assert!(key_allows_agent(&empty));
    }
}
