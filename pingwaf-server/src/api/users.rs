//! Dashboard user administration.
//!
//! Every route requires the `admin` role. Operators may create accounts,
//! change roles, and disable accounts; self-lockout is prevented (an admin
//! can neither disable nor downgrade themselves, and the last enabled
//! administrator can never lose admin access).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::auth::{create_user, normalise_email, UserResponse};
use crate::api::common::{parse_uuid, query_all, Page, Pagination};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::middleware::AdminUser;
use crate::auth::password::validate_password;
use crate::models::{role, user};

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Defaults to `viewer`.
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub name: Option<String>,
    /// The login name. Changing it revokes the account's outstanding tokens
    /// (their e-mail claim goes stale); no password confirmation is needed
    /// because only administrators reach this endpoint.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub disabled: Option<bool>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list).post(create))
        .route("/users/{user_id}", put(update))
}

/// `GET /api/v1/users`
async fn list(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<UserResponse>>, ApiError> {
    let pagination = query.pagination.normalise();
    let paginator = user::Entity::find()
        .order_by_asc(user::Column::CreatedAt)
        .paginate(&state.db, pagination.limit());
    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.page - 1).await?;

    // Most recent successful login per account, resolved from the login
    // history (both password and passkey logins are recorded there), so the
    // admin list can show "last seen" without denormalizing onto the user
    // row. Newest-first iteration keeps the first hit per user the latest.
    let ids: Vec<Uuid> = rows.iter().map(|u| u.id).collect();
    let mut latest: std::collections::HashMap<
        Uuid,
        (chrono::DateTime<chrono::Utc>, String),
    > = std::collections::HashMap::new();
    if !ids.is_empty() {
        // `DISTINCT ON` returns one (newest) row per account in a single
        // query. Fetching the whole history and keeping the first row per
        // user grew with the audit trail — one page could pull every login
        // ever recorded for up to 200 accounts.
        let placeholders = (1..=ids.len())
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT DISTINCT ON (user_id) user_id, created_at, ip \
             FROM login_history WHERE user_id IN ({placeholders}) \
             ORDER BY user_id, created_at DESC"
        );
        let values: Vec<sea_orm::Value> =
            ids.iter().map(|id| (*id).into()).collect();
        for row in query_all(&state.db, &sql, values).await? {
            let user_id: Uuid = row.try_get("", "user_id")?;
            let created_at: chrono::DateTime<chrono::Utc> =
                row.try_get("", "created_at")?;
            let ip: String = row.try_get("", "ip")?;
            latest.insert(user_id, (created_at, ip));
        }
    }

    let items = rows
        .into_iter()
        .map(|account| {
            let mut body = UserResponse::from(account);
            if let Some((at, ip)) = latest.get(&body.id) {
                body.last_login_at = Some(*at);
                body.last_login_ip = Some(ip.clone());
            }
            body
        })
        .collect();
    Ok(Json(Page::new(items, total, pagination)))
}

/// `POST /api/v1/users`
async fn create(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Response, ApiError> {
    let email = normalise_email(&payload.email)?;
    validate_password(&payload.password)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    let assigned_role = payload.role.as_deref().unwrap_or(role::VIEWER);
    if !role::is_valid(assigned_role) {
        return Err(ApiError::BadRequest(format!(
            "unknown role '{assigned_role}'"
        )));
    }

    let taken = user::Entity::find()
        .filter(user::Column::Email.eq(email.clone()))
        .one(&state.db)
        .await?;
    if taken.is_some() {
        return Err(ApiError::Conflict(format!(
            "an account for {email} already exists"
        )));
    }

    let account = create_user(
        &state.db,
        &email,
        &payload.password,
        payload.name.clone(),
        assigned_role,
    )
    .await?;

    tracing::info!(
        %email,
        user_id = %account.id,
        role = %account.role,
        "account created by administrator"
    );
    Ok(
        (StatusCode::CREATED, Json(UserResponse::from(account)))
            .into_response(),
    )
}

/// `PUT /api/v1/users/{user_id}`
async fn update(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(user_id): Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    let id = parse_uuid(&user_id, "user id")?;
    let account = user::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("user {id} not found")))?;

    // Self-service profile changes go through `/auth/me`; role and status
    // changes on the caller's own account could lock the operator out.
    if id == admin.id()
        && (payload.role.is_some() || payload.disabled.is_some())
    {
        return Err(ApiError::BadRequest(
            "cannot change your own role or disabled state".to_string(),
        ));
    }

    let new_role = match payload.role.as_deref() {
        Some(raw) if raw != account.role => {
            if !role::is_valid(raw) {
                return Err(ApiError::BadRequest(format!(
                    "unknown role '{raw}'"
                )));
            }
            Some(raw.to_string())
        },
        _ => None,
    };
    let new_email = match payload.email.as_deref() {
        Some(raw) => {
            let email = normalise_email(raw)?;
            (email != account.email).then_some(email)
        },
        None => None,
    };
    if let Some(email) = &new_email {
        let taken = user::Entity::find()
            .filter(user::Column::Email.eq(email.clone()))
            .filter(user::Column::Id.ne(id))
            .one(&state.db)
            .await?;
        if taken.is_some() {
            return Err(ApiError::Conflict(format!(
                "an account for {email} already exists"
            )));
        }
    }
    let disabling = payload.disabled.unwrap_or(false);
    // A role change, a disable or a login-name change revokes the account's
    // outstanding tokens; renames and re-enables do not.
    let revoking = new_role.is_some()
        || (disabling && !account.disabled)
        || new_email.is_some();
    let loses_admin = account.role == role::ADMIN
        && !account.disabled
        && ((new_role.is_some() && new_role.as_deref() != Some(role::ADMIN))
            || disabling);
    if loses_admin {
        ensure_other_enabled_admin(&state, id).await?;
    }

    let mut active: user::ActiveModel = account.into();
    if let Some(name) = payload.name {
        let trimmed = name.trim();
        if trimmed.len() > 100 {
            return Err(ApiError::BadRequest(
                "name must be at most 100 characters".to_string(),
            ));
        }
        active.name = Set(if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        });
    }
    if let Some(new_role) = new_role {
        active.role = Set(new_role);
    }
    if let Some(email) = new_email {
        active.email = Set(email);
        tracing::info!(user_id = %id, "login name changed by administrator");
    }
    if let Some(disabled) = payload.disabled {
        active.disabled = Set(disabled);
        if disabled {
            tracing::info!(user_id = %id, "account disabled by administrator");
        }
    }
    if revoking {
        active.token_version = Set(active.token_version.unwrap() + 1);
    }
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;
    Ok(Json(UserResponse::from(updated)))
}

/// Fails with `400` when `except` is the only enabled administrator left.
async fn ensure_other_enabled_admin(
    state: &AppState,
    except: Uuid,
) -> Result<(), ApiError> {
    let count = user::Entity::find()
        .filter(user::Column::Role.eq(role::ADMIN))
        .filter(user::Column::Disabled.eq(false))
        .filter(user::Column::Id.ne(except))
        .count(&state.db)
        .await?;
    if count == 0 {
        return Err(ApiError::BadRequest(
            "the last enabled administrator cannot be downgraded or disabled"
                .to_string(),
        ));
    }
    Ok(())
}
