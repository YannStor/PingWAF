//! Authentication endpoints: login, registration, token refresh and the
//! self-service profile routes the dashboard calls right after booting.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait,
    PaginatorTrait, QueryFilter, Set, TransactionError, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{non_empty, AppJson};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::middleware::AuthUser;
use crate::auth::password::{
    hash_password, validate_password, verify_password,
};
use crate::auth::token_version_valid;
use crate::auth::{create_refresh_token, create_token, verify_refresh_token};
use crate::models::{role, user};

/// Public information about a dashboard account. The password hash never leaves
/// the process (see [`crate::models::users`], which deliberately does not derive
/// `Serialize`).
#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub role: String,
    /// The console walks first-login accounts through a password change.
    pub must_change_password: bool,
    /// Disabled accounts cannot sign in; shown in the admin user list.
    pub disabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Most recent successful login (any method), resolved from the login
    /// history; `None` when the account has never signed in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_ip: Option<String>,
}

impl From<user::Model> for UserResponse {
    fn from(model: user::Model) -> Self {
        Self {
            id: model.id,
            email: model.email,
            name: model.name,
            role: model.role,
            must_change_password: model.must_change_password,
            disabled: model.disabled,
            created_at: model.created_at,
            updated_at: model.updated_at,
            // Resolved per query by the admin list endpoint (it joins the
            // login history); everywhere else the fields stay absent.
            last_login_at: None,
            last_login_ip: None,
        }
    }
}

/// Body returned by the token endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    /// Lifetime of `access_token` in seconds.
    pub expires_in: i64,
    pub user: UserResponse,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    #[serde(default)]
    pub name: Option<String>,
    /// The login name. Changing it requires `current_password` and revokes
    /// every outstanding token (their e-mail claim goes stale).
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub current_password: Option<String>,
}

/// Bootstrap status, consumed by the frontend before showing the login form.
#[derive(Debug, Serialize)]
pub struct AuthStatus {
    /// False when at least one account exists.
    pub needs_setup: bool,
    /// Whether `POST /auth/register` will accept new accounts.
    pub registration_open: bool,
    /// Whether the login form should offer a passkey.
    pub passkey_enabled: bool,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/status", get(status))
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .route("/auth/refresh", post(refresh))
        .route("/auth/me", get(me).put(update_profile))
        .route("/auth/password", put(change_password))
}

/// `GET /api/v1/auth/status`
async fn status(
    State(state): State<AppState>,
) -> Result<Json<AuthStatus>, ApiError> {
    let count = user::Entity::find().count(&state.db).await?;
    Ok(Json(AuthStatus {
        needs_setup: count == 0,
        registration_open: state.config.allow_registration || count == 0,
        // The runtime master switch (instance_settings KV) overrides the
        // static boot config, so the login form hides the passkey option as
        // soon as an operator turns it off - no restart needed.
        passkey_enabled: crate::api::passkeys::passkey_enabled(
            &state.db,
            state.config.passkey_enabled,
        )
        .await?,
    }))
}

/// `POST /api/v1/auth/login`
async fn login(
    State(state): State<AppState>,
    connect_info: Option<axum::Extension<crate::tls::ConnInfo>>,
    headers: axum::http::HeaderMap,
    AppJson(payload): AppJson<LoginRequest>,
) -> Result<Response, ApiError> {
    let email = normalise_email(&payload.email)?;
    if payload.password.is_empty() {
        return Err(ApiError::BadRequest("password is required".to_string()));
    }

    let found = user::Entity::find()
        .filter(user::Column::Email.eq(email.clone()))
        .one(&state.db)
        .await?;

    let Some(account) = found else {
        // Spend a bcrypt verification anyway so that the response time does not
        // reveal whether the e-mail exists. bcrypt is deliberately slow
        // (~50-300ms): running it on the async worker pool lets a burst of
        // logins starve every other control-plane request (2026-10-18 audit),
        // so it runs on the blocking pool.
        let password = payload.password.clone();
        let _ = tokio::task::spawn_blocking(move || {
            verify_password(&password, DUMMY_HASH)
        })
        .await;
        tracing::debug!(%email, "login failed: unknown account");
        return Err(ApiError::Unauthorized(INVALID_CREDENTIALS.to_string()));
    };

    let password = payload.password.clone();
    let stored_hash = account.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || {
        verify_password(&password, &stored_hash)
    })
    .await
    .map_err(|err| ApiError::Internal(err.to_string()))?
    .map_err(|err| ApiError::Internal(err.to_string()))?;
    if !valid {
        tracing::debug!(%email, "login failed: wrong password");
        return Err(ApiError::Unauthorized(INVALID_CREDENTIALS.to_string()));
    }
    if account.disabled {
        tracing::debug!(%email, "login failed: account disabled");
        return Err(ApiError::Unauthorized("account is disabled".to_string()));
    }

    tracing::info!(%email, user_id = %account.id, role = %account.role, "user logged in");

    // The login history + geo anomaly check runs detached: the response
    // must not wait on an online geo API. Only *successful* logins are
    // recorded — this is the audit baseline, not a brute-force log.
    let db = state.db.clone();
    let user_id = account.id;
    let login_email = account.email.clone();
    tokio::spawn(async move {
        crate::notify::login_anomaly::record_login(
            &db,
            user_id,
            &login_email,
            &headers,
            connect_info.map(|info| info.0.peer_addr.ip()),
            true,
        )
        .await;
    });

    issue_tokens(&state, account)
        .map(|body| (StatusCode::OK, Json(body)).into_response())
}

/// Advisory-lock key serialising first-account decisions across concurrent
/// registrations. Arbitrary but process-independent; two control planes on
/// the same database must agree on it, which a constant guarantees.
const REGISTER_ADVISORY_LOCK_KEY: i64 = 0x5069_6E67_5741_4601;

/// `POST /api/v1/auth/register`
async fn register(
    State(state): State<AppState>,
    AppJson(payload): AppJson<RegisterRequest>,
) -> Result<Response, ApiError> {
    let email = normalise_email(&payload.email)?;
    validate_password(&payload.password)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;

    // The "is this the first account" decision, the duplicate check and the
    // insert run inside one transaction guarded by an advisory lock: two
    // racing registrations must not both observe zero users and mint two
    // administrators. The lock releases with the transaction; the e-mail
    // unique constraint stays as the last line of defence.
    let allow_registration = state.config.allow_registration;
    let txn_email = email.clone();
    let password = payload.password;
    let name = non_empty(&payload.name);
    let account = state
        .db
        .transaction(|txn| {
            Box::pin(async move {
                txn.execute_unprepared(&format!(
                    "SELECT pg_advisory_xact_lock({REGISTER_ADVISORY_LOCK_KEY})"
                ))
                .await?;

                let existing = user::Entity::find().count(txn).await?;
                if existing > 0 && !allow_registration {
                    return Err(ApiError::Forbidden(
                        "registration is disabled on this server".to_string(),
                    ));
                }

                let taken = user::Entity::find()
                    .filter(user::Column::Email.eq(txn_email.clone()))
                    .one(txn)
                    .await?;
                if taken.is_some() {
                    return Err(ApiError::Conflict(format!(
                        "an account for {txn_email} already exists"
                    )));
                }

                // The very first account always becomes the administrator;
                // everybody else is a read-only viewer until an admin
                // promotes them.
                let assigned_role = if existing == 0 {
                    role::ADMIN
                } else {
                    role::VIEWER
                };

                create_user(txn, &txn_email, &password, name, assigned_role)
                    .await
            })
        })
        .await
        .map_err(|err| match err {
            TransactionError::Connection(db) => ApiError::from(db),
            TransactionError::Transaction(api) => api,
        })?;

    tracing::info!(
        %email,
        user_id = %account.id,
        role = %account.role,
        "account registered"
    );
    issue_tokens(&state, account)
        .map(|body| (StatusCode::CREATED, Json(body)).into_response())
}

/// `POST /api/v1/auth/refresh`
async fn refresh(
    State(state): State<AppState>,
    AppJson(payload): AppJson<RefreshRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let claims =
        verify_refresh_token(&payload.refresh_token, state.jwt_secret())
            .map_err(|err| ApiError::Unauthorized(err.to_string()))?;
    let user_id = claims
        .subject_id()
        .map_err(|err| ApiError::Unauthorized(err.to_string()))?;

    // Re-read the account so that a disabled/deleted user or a changed role is
    // reflected immediately.
    let account = user::Entity::find_by_id(user_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::Unauthorized("account no longer exists".to_string())
        })?;

    if account.disabled {
        return Err(ApiError::Unauthorized("account is disabled".to_string()));
    }
    if !token_version_valid(claims.ver, &account) {
        return Err(ApiError::Unauthorized(
            "session revoked: credentials changed since this token was issued"
                .to_string(),
        ));
    }
    if !role::is_valid(&account.role) {
        return Err(ApiError::Unauthorized(format!(
            "account has an unknown role '{}'",
            account.role
        )));
    }

    tracing::debug!(%user_id, "refreshed access token");
    Ok(Json(issue_tokens(&state, account)?))
}

/// `GET /api/v1/auth/me`
async fn me(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<UserResponse>, ApiError> {
    let account = user::Entity::find_by_id(current.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::Unauthorized("account no longer exists".to_string())
        })?;
    Ok(Json(account.into()))
}

/// `PUT /api/v1/auth/me`
async fn update_profile(
    State(state): State<AppState>,
    current: AuthUser,
    AppJson(payload): AppJson<UpdateProfileRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    let account = user::Entity::find_by_id(current.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("account not found".to_string()))?;

    let old_email = account.email.clone();
    let password_hash = account.password_hash.clone();
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
    if let Some(raw) = payload.email {
        let email = normalise_email(&raw)?;
        if email != old_email {
            // Changing the login name is a sensitive identity change: the
            // current password keeps a hijacked session from locking the
            // operator out, and the token bump invalidates every token whose
            // e-mail claim went stale — the console must sign in again.
            require_current_password(
                payload.current_password.as_deref().ok_or_else(|| {
                    ApiError::BadRequest(
                        "the current password is required to change the login name"
                            .to_string(),
                    )
                })?,
                &password_hash,
            )
            .await?;
            let taken = user::Entity::find()
                .filter(user::Column::Email.eq(email.clone()))
                .one(&state.db)
                .await?;
            if taken.is_some() {
                return Err(ApiError::Conflict(format!(
                    "an account for {email} already exists"
                )));
            }
            active.email = Set(email.clone());
            active.token_version = Set(active.token_version.unwrap() + 1);
            tracing::info!(
                user_id = %current.id,
                old_email = %old_email,
                new_email = %email,
                "login name changed"
            );
        }
    }
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;
    Ok(Json(updated.into()))
}

/// Checks a supplied current password against the stored hash.
///
/// A mismatch is a validation failure, not an authentication one: the caller is
/// already authenticated, and answering 401 makes the console treat the session
/// as dead and log the user out mid-form.
async fn require_current_password(
    supplied: &str,
    stored_hash: &str,
) -> Result<(), ApiError> {
    // bcrypt on the blocking pool — see the login handler for why.
    let supplied = supplied.to_string();
    let stored_hash = stored_hash.to_string();
    let valid = tokio::task::spawn_blocking(move || {
        verify_password(&supplied, &stored_hash)
    })
    .await
    .map_err(|err| ApiError::Internal(err.to_string()))?
    .map_err(|err| ApiError::Internal(err.to_string()))?;
    if !valid {
        return Err(ApiError::BadRequest(
            "current password is incorrect".to_string(),
        ));
    }
    Ok(())
}

/// `PUT /api/v1/auth/password`
async fn change_password(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Response, ApiError> {
    let account = user::Entity::find_by_id(current.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("account not found".to_string()))?;

    require_current_password(&payload.current_password, &account.password_hash)
        .await?;
    validate_password(&payload.new_password)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;

    let mut active: user::ActiveModel = account.into();
    let new_password = payload.new_password.clone();
    let new_hash =
        tokio::task::spawn_blocking(move || hash_password(&new_password))
            .await
            .map_err(|err| ApiError::Internal(err.to_string()))?
            .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    active.password_hash = Set(new_hash);
    // The first-login gate only demands one successful change.
    active.must_change_password = Set(false);
    // A password change revokes every token minted before it, including the
    // one this request was authenticated with.
    active.token_version = Set(active.token_version.unwrap() + 1);
    active.updated_at = Set(Utc::now());
    active.update(&state.db).await?;

    tracing::info!(user_id = %current.id, "password changed");
    Ok(StatusCode::NO_CONTENT.into_response())
}

const INVALID_CREDENTIALS: &str = "invalid e-mail or password";

/// A precomputed bcrypt hash that matches nothing; used to equalise the cost of
/// a failed login for unknown accounts.
const DUMMY_HASH: &str =
    "$2b$10$Q9V0Z7rQZ3h8YqQZQZQZQeQ9V0Z7rQZ3h8YqQZQZQZQZQZQZQZQZu";

/// Lower-cases and structurally validates an e-mail address.
pub(crate) fn normalise_email(raw: &str) -> Result<String, ApiError> {
    let email = raw.trim().to_lowercase();
    let (local, domain) = email.split_once('@').ok_or_else(|| {
        ApiError::BadRequest("invalid e-mail address".to_string())
    })?;
    if local.is_empty() || local.len() > 64 {
        return Err(ApiError::BadRequest("invalid e-mail address".to_string()));
    }
    if domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(ApiError::BadRequest("invalid e-mail address".to_string()));
    }
    Ok(email)
}

/// Inserts a new user row with a freshly hashed password.
///
/// Accepts any connection so the registration transaction can run it on its
/// own transaction handle.
pub async fn create_user(
    db: &impl ConnectionTrait,
    email: &str,
    password: &str,
    name: Option<String>,
    assigned_role: &str,
) -> Result<user::Model, ApiError> {
    if !role::is_valid(assigned_role) {
        return Err(ApiError::Internal(format!(
            "unknown role '{assigned_role}'"
        )));
    }
    let password_owned = password.to_string();
    let password_hash =
        tokio::task::spawn_blocking(move || hash_password(&password_owned))
            .await
            .map_err(|err| ApiError::Internal(err.to_string()))?
            .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    let timestamp = Utc::now();
    let active = user::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email.to_string()),
        password_hash: Set(password_hash),
        name: Set(name),
        role: Set(assigned_role.to_string()),
        disabled: Set(false),
        must_change_password: Set(false),
        token_version: Set(0),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    };
    active.insert(db).await.map_err(ApiError::from)
}

/// Mints an access/refresh pair for `account`.
///
/// Shared with the passkey login ceremony, which ends in the same session the
/// password flow issues.
pub(crate) fn issue_tokens(
    state: &AppState,
    account: user::Model,
) -> Result<TokenResponse, ApiError> {
    let secret = state.jwt_secret();
    let access = create_token(
        account.id,
        &account.email,
        &account.role,
        account.token_version,
        secret,
        state.jwt_expiration_hours(),
    )
    .map_err(|err| ApiError::Internal(err.to_string()))?;
    let refresh = create_refresh_token(
        account.id,
        &account.email,
        &account.role,
        account.token_version,
        secret,
        state.refresh_expiration_hours(),
    )
    .map_err(|err| ApiError::Internal(err.to_string()))?;

    Ok(TokenResponse {
        access_token: access,
        refresh_token: refresh,
        token_type: "Bearer",
        expires_in: state.jwt_expiration_hours() * 3600,
        user: account.into(),
    })
}

// Middleware that copies the [`AuthUser`] extractor result into request
// extensions is deliberately absent: handlers take [`AuthUser`] directly as an
// extractor, which keeps axum's rejection handling intact.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_normalised() {
        assert_eq!(
            normalise_email("  Ops@Example.COM ").unwrap(),
            "ops@example.com"
        );
        assert!(normalise_email("no-at-sign").is_err());
        assert!(normalise_email("@example.com").is_err());
        assert!(normalise_email("ops@example").is_err());
        assert!(normalise_email("ops@.example.com").is_err());
    }

    #[test]
    fn user_response_never_exposes_the_hash() {
        let model = user::Model {
            id: Uuid::new_v4(),
            email: "ops@example.com".into(),
            password_hash: "$2b$10$secret".into(),
            name: Some("Ops".into()),
            role: role::ADMIN.into(),
            disabled: false,
            must_change_password: false,
            token_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&UserResponse::from(model)).unwrap();
        assert!(!json.contains("secret"));
        assert!(json.contains("ops@example.com"));
    }

    #[tokio::test]
    async fn a_wrong_current_password_is_rejected_as_a_bad_request() {
        let hash = hash_password("correct horse battery").unwrap();
        assert!(require_current_password("correct horse battery", &hash)
            .await
            .is_ok());

        let err = require_current_password("staple", &hash).await.unwrap_err();
        // 401 would make the web client drop the session and log the user out.
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert_eq!(err.code(), "bad_request");
    }
}
