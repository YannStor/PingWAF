//! Visitor accounts for the console's Account page.
//!
//! The accounts a protected site admits, managed by an operator. Distinct from
//! `users`, which holds *console operators*: a visitor never reaches the
//! console, and an operator never signs into a protected site through this
//! table. Keeping the two apart is what makes their credential stores
//! independently rotatable.
//!
//! # Where a visitor signs in
//!
//! Not here. The login page is rendered by the data plane, and the credential
//! check runs over gRPC (`grpc/visitor_auth.rs`) because the data plane has no
//! database. This module is the operator-facing half: create the account,
//! grant it sites, disable it.
//!
//! # Why the password is not echoed
//!
//! `POST` takes a password and stores a bcrypt hash; no read path ever returns
//! one, and there is no mask to send back the way `oidc_providers` has. An
//! operator who loses a visitor's password sets a new one — there is no
//! "keep the stored value" case, because the console is not the party that
//! signs in with it.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use std::collections::HashMap;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::password::{hash_password, MIN_PASSWORD_LENGTH};
use crate::auth::AdminUser;
use crate::models::{site, site_visitor, visitor_site_grant};

pub const MAX_VISITOR_NAME_LEN: usize = 128;
pub const MAX_VISITOR_EMAIL_LEN: usize = 255;

/// What the dashboard receives. Never a password or a hash.
#[derive(Debug, Serialize)]
pub struct VisitorView {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub disabled: bool,
    /// Sites this visitor may enter, so the dashboard can show the grants
    /// without a second request per row.
    pub site_ids: Vec<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateVisitorRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub disabled: Option<bool>,
    /// The sites to grant on creation, so a new account is usable in one call.
    #[serde(default)]
    pub site_ids: Option<Vec<Uuid>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateVisitorRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub disabled: Option<bool>,
    /// Sets a new password. Absent leaves the stored one.
    #[serde(default)]
    pub password: Option<String>,
    /// Replaces the whole grant list when present.
    #[serde(default)]
    pub site_ids: Option<Vec<Uuid>>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/visitors", get(list).post(create))
        .route(
            "/visitors/{visitor_id}",
            get(show).put(update).delete(destroy),
        )
}

/// `GET /api/v1/visitors`
async fn list(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<VisitorView>>, ApiError> {
    let rows = site_visitor::Entity::find()
        .order_by_asc(site_visitor::Column::Email)
        .all(&state.db)
        .await?;
    // Every grant in one query rather than one per visitor: the console opens
    // this list on the Account page, and a deployment with a few hundred
    // visitors would otherwise answer it with a few hundred round trips.
    let grants = visitor_site_grant::Entity::find()
        .order_by_asc(visitor_site_grant::Column::SiteId)
        .all(&state.db)
        .await?;
    let mut by_visitor: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for grant in grants {
        by_visitor
            .entry(grant.visitor_id)
            .or_default()
            .push(grant.site_id);
    }
    let views = rows
        .into_iter()
        .map(|row| {
            let site_ids = by_visitor.remove(&row.id).unwrap_or_default();
            view_of(row, site_ids)
        })
        .collect();
    Ok(Json(views))
}

/// The response shape, from a row and the sites it may enter.
fn view_of(row: site_visitor::Model, site_ids: Vec<Uuid>) -> VisitorView {
    VisitorView {
        id: row.id,
        email: row.email,
        name: row.name,
        disabled: row.disabled,
        site_ids,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// `GET /api/v1/visitors/{visitor_id}`
async fn show(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(visitor_id): Path<String>,
) -> Result<Json<VisitorView>, ApiError> {
    let row = load(&state, &visitor_id).await?;
    Ok(Json(to_view(&state, &row).await?))
}

/// `POST /api/v1/visitors`
async fn create(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(payload): Json<CreateVisitorRequest>,
) -> Result<Json<VisitorView>, ApiError> {
    let email = validate_email(&payload.email)?;
    let name = validate_name(payload.name.as_deref().unwrap_or_default())?;
    // `hash_password` enforces the same minimum length and 72-byte truncation
    // the console's own accounts use, so one policy governs both.
    let hash = hash_password(&payload.password).map_err(|error| {
        ApiError::BadRequest(format!(
            "password must be at least {MIN_PASSWORD_LENGTH} characters ({error})"
        ))
    })?;

    // A unique email is what makes a sign-in unambiguous; the database would
    // answer a 500 for the constraint, and this says what happened.
    if site_visitor::Entity::find()
        .filter(site_visitor::Column::Email.eq(email.as_str()))
        .one(&state.db)
        .await?
        .is_some()
    {
        return Err(ApiError::BadRequest(format!(
            "a visitor with the address '{email}' already exists"
        )));
    }

    let now = chrono::Utc::now();
    // One transaction for the account and its grants: the grants are validated
    // (an unknown site id is refused), and a refusal that left the account
    // behind would create a visitor the operator was told was not created —
    // which is exactly what a partial write did before this.
    let txn = state.db.begin().await?;
    let model = site_visitor::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email),
        password_hash: Set(hash),
        name: Set(name),
        disabled: Set(payload.disabled.unwrap_or(false)),
        token_version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&txn)
    .await?;

    if let Some(site_ids) = payload.site_ids {
        replace_grants(&txn, model.id, site_ids).await?;
    }
    txn.commit().await?;

    tracing::info!(
        visitor_id = %model.id,
        by = %admin.email,
        "visitor account created"
    );
    Ok(Json(to_view(&state, &model).await?))
}

/// `PUT /api/v1/visitors/{visitor_id}`
async fn update(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(visitor_id): Path<String>,
    Json(payload): Json<UpdateVisitorRequest>,
) -> Result<Json<VisitorView>, ApiError> {
    let row = load(&state, &visitor_id).await?;
    let mut active: site_visitor::ActiveModel = row.clone().into();
    let mut touched = false;

    if let Some(name) = payload.name {
        active.name = Set(validate_name(&name)?);
        touched = true;
    }
    if let Some(disabled) = payload.disabled {
        active.disabled = Set(disabled);
        // Disabling has to end the sessions the account is holding, not just
        // the next sign-in — that is the whole point of disabling someone. The
        // version bump is what does it: the session check compares versions,
        // and a mismatch ends the session.
        if disabled {
            active.token_version = Set(row.token_version + 1);
        }
        touched = true;
    }
    if let Some(password) = payload.password {
        let hash = hash_password(&password).map_err(|error| {
            ApiError::BadRequest(format!(
                "password must be at least {MIN_PASSWORD_LENGTH} characters ({error})"
            ))
        })?;
        active.password_hash = Set(hash);
        // Bumping the version invalidates every session already issued, which
        // is what makes an operator's password reset actually end the sessions
        // a visitor may be holding.
        active.token_version = Set(row.token_version + 1);
        touched = true;
    }
    // The same transaction boundary as `create`: a grant list that is refused
    // must not leave the account fields already written.
    let txn = state.db.begin().await?;
    if touched {
        active.updated_at = Set(chrono::Utc::now());
        active.update(&txn).await?;
    }
    if let Some(site_ids) = payload.site_ids {
        replace_grants(&txn, row.id, site_ids).await?;
    }
    txn.commit().await?;

    tracing::info!(visitor_id = %row.id, by = %admin.email, "visitor account updated");
    let refreshed = load(&state, &visitor_id).await?;
    Ok(Json(to_view(&state, &refreshed).await?))
}

/// `DELETE /api/v1/visitors/{visitor_id}`
async fn destroy(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(visitor_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = load(&state, &visitor_id).await?;
    // The grants and any passkeys cascade with the row: an account that no
    // longer exists must not leave a usable credential behind.
    site_visitor::Entity::delete_by_id(row.id)
        .exec(&state.db)
        .await?;
    tracing::info!(
        visitor_id = %row.id,
        email = %row.email,
        by = %admin.email,
        "visitor account deleted"
    );
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// Replaces a visitor's grants with exactly `site_ids`.
///
/// Replace rather than merge: the dashboard sends the whole set it wants, and
/// a merge would make "remove this site" impossible to express. Unknown site
/// ids are refused rather than silently skipped — a grant to a site that does
/// not exist would look like access that never works.
async fn replace_grants<C>(
    db: &C,
    visitor_id: Uuid,
    site_ids: Vec<Uuid>,
) -> Result<(), ApiError>
where
    C: sea_orm::ConnectionTrait,
{
    let unique: Vec<Uuid> = {
        let mut seen = std::collections::BTreeSet::new();
        site_ids.into_iter().filter(|id| seen.insert(*id)).collect()
    };
    if !unique.is_empty() {
        let found = site::Entity::find()
            .filter(site::Column::Id.is_in(unique.clone()))
            .all(db)
            .await?;
        if found.len() != unique.len() {
            return Err(ApiError::BadRequest(
                "site_ids contains a site that does not exist".to_string(),
            ));
        }
    }
    visitor_site_grant::Entity::delete_many()
        .filter(visitor_site_grant::Column::VisitorId.eq(visitor_id))
        .exec(db)
        .await?;
    let now = chrono::Utc::now();
    for site_id in unique {
        visitor_site_grant::ActiveModel {
            id: Set(Uuid::new_v4()),
            visitor_id: Set(visitor_id),
            site_id: Set(site_id),
            // Visible by default: a new grant is meant to be seen, and hiding
            // one is a deliberate tidy-up the visitor makes themselves.
            visible: Set(true),
            created_at: Set(now),
        }
        .insert(db)
        .await?;
    }
    Ok(())
}

async fn load(
    state: &AppState,
    visitor_id: &str,
) -> Result<site_visitor::Model, ApiError> {
    let id = Uuid::parse_str(visitor_id.trim()).map_err(|_| {
        ApiError::BadRequest("visitor id is not a uuid".to_string())
    })?;
    site_visitor::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("visitor not found".to_string()))
}

async fn to_view(
    state: &AppState,
    row: &site_visitor::Model,
) -> Result<VisitorView, ApiError> {
    let grants = visitor_site_grant::Entity::find()
        .filter(visitor_site_grant::Column::VisitorId.eq(row.id))
        .order_by_asc(visitor_site_grant::Column::SiteId)
        .all(&state.db)
        .await?;
    Ok(view_of(
        row.clone(),
        grants.into_iter().map(|grant| grant.site_id).collect(),
    ))
}

/// Lowercases and trims, the same normalisation the sign-in path applies, so
/// `A@b.test` and `a@b.test` are one account.
fn validate_email(raw: &str) -> Result<String, ApiError> {
    let email = raw.trim().to_ascii_lowercase();
    if email.is_empty() || email.len() > MAX_VISITOR_EMAIL_LEN {
        return Err(ApiError::BadRequest(format!(
            "email must be 1-{MAX_VISITOR_EMAIL_LEN} characters"
        )));
    }
    // Deliberately permissive: an address is whatever the provider accepts,
    // and a stricter check would reject valid addresses. The shape that
    // matters is that it has exactly one `@` with something on each side.
    let mut parts = email.split('@');
    let (Some(local), Some(domain), None) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(ApiError::BadRequest(
            "email must look like an address".to_string(),
        ));
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(ApiError::BadRequest(
            "email must look like an address".to_string(),
        ));
    }
    Ok(email)
}

fn validate_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.len() > MAX_VISITOR_NAME_LEN {
        return Err(ApiError::BadRequest(format!(
            "name must be at most {MAX_VISITOR_NAME_LEN} characters"
        )));
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sign-in path normalises the same way; a mismatch would mean an
    /// account created here could not be signed into.
    #[test]
    fn emails_are_normalised_the_same_way_as_sign_in() {
        assert_eq!("a@b.test", validate_email("  A@B.TEST ").expect("valid"));
        assert_eq!("a@b.test", validate_email("a@b.test").expect("valid"));
    }

    #[test]
    fn an_address_that_cannot_be_one_is_refused() {
        for bad in ["", "  ", "no-at-sign", "@b.test", "a@", "a@b", "a@@b.test"]
        {
            assert!(
                validate_email(bad).is_err(),
                "{bad:?} must not be accepted as an address"
            );
        }
    }

    #[test]
    fn a_name_is_trimmed_and_bounded() {
        assert_eq!("Ann", validate_name("  Ann  ").expect("valid"));
        assert_eq!("", validate_name("").expect("empty is allowed"));
        assert!(validate_name(&"x".repeat(MAX_VISITOR_NAME_LEN + 1)).is_err());
    }
}
