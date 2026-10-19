//! Axum extractors that turn a `Authorization: Bearer <jwt>` header into an
//! [`AuthUser`], plus role helpers used by the write endpoints.

use axum::extract::{FromRef, FromRequestParts, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use sea_orm::{DatabaseConnection, EntityTrait};

use crate::api::error::error_response;
use crate::api::state::AppState;
use crate::auth::jwt::{verify_user_token, Claims, JwtError};
use crate::models::{role, user};

/// Scheme prefix accepted in the `Authorization` header.
const BEARER_PREFIX: &str = "Bearer ";

/// Identity of the caller behind a request.
///
/// Resolved against the database on every request: disabled accounts are
/// refused immediately, and a role change takes effect without waiting for
/// the access token to expire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    /// The console forces a password (and name) change before any mutation.
    pub must_change_password: bool,
}

impl AuthUser {
    pub fn new(
        id: Uuid,
        email: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            id,
            email: email.into(),
            role: role.into(),
            must_change_password: false,
        }
    }

    pub fn is_admin(&self) -> bool {
        self.role == role::ADMIN
    }

    /// Fails with `403` unless the caller is an administrator.
    pub fn require_admin(&self) -> Result<(), AuthError> {
        if self.is_admin() {
            Ok(())
        } else {
            Err(AuthError::Forbidden(
                "administrator role required".to_string(),
            ))
        }
    }
}

/// Rejection returned by [`AuthUser`]; always renders as `401`/`403`.
#[derive(Debug)]
pub enum AuthError {
    /// No `Authorization` header at all.
    MissingCredentials,
    /// Header present but not a `Bearer` token.
    MalformedCredentials,
    /// Signature/claims problem.
    InvalidToken(String),
    /// `exp` in the past.
    ExpiredToken,
    /// Valid identity, insufficient role.
    Forbidden(String),
    /// Reading the account back from the database failed.
    Internal(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingCredentials => {
                f.write_str("missing authorization header")
            },
            AuthError::MalformedCredentials => {
                f.write_str("authorization header must use the Bearer scheme")
            },
            AuthError::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
            AuthError::ExpiredToken => f.write_str("token expired"),
            AuthError::Forbidden(msg) => write!(f, "forbidden: {msg}"),
            AuthError::Internal(msg) => write!(f, "storage error: {msg}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl AuthError {
    fn code(&self) -> &'static str {
        match self {
            AuthError::Forbidden(_) => "forbidden",
            AuthError::ExpiredToken => "token_expired",
            AuthError::Internal(_) => "internal",
            _ => "unauthorized",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            AuthError::Forbidden(_) => StatusCode::FORBIDDEN,
            AuthError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
}

impl From<JwtError> for AuthError {
    fn from(err: JwtError) -> Self {
        match err {
            JwtError::Expired => AuthError::ExpiredToken,
            other => AuthError::InvalidToken(other.to_string()),
        }
    }
}

impl From<AuthError> for crate::api::error::ApiError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::Forbidden(msg) => {
                crate::api::error::ApiError::Forbidden(msg)
            },
            other => {
                crate::api::error::ApiError::Unauthorized(other.to_string())
            },
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        let mut response = error_response(status, code, &self.to_string());
        // RFC 6750: tell the client which scheme we expect.
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static(
                "Bearer realm=\"pingwaf\", error=\"invalid_token\"",
            ),
        );
        response
    }
}

/// Endpoints a first-login account may still reach (D20).
///
/// Everything under `/api/v1/auth/` that a session needs in order to *become*
/// a normal session — status probe, login/refresh/logout, the password change
/// itself and the profile read the console makes on boot — stays reachable.
/// Every other authenticated endpoint is refused while
/// `must_change_password` is set.
const PASSWORD_CHANGE_EXEMPT_PREFIX: &str = "/api/v1/auth/";

/// Paths inside [`PASSWORD_CHANGE_EXEMPT_PREFIX`] that are *not* exempt.
///
/// `PUT /auth/me` can change the login e-mail, and the passkey registry lives
/// under the same prefix; both are ordinary account mutations that have no
/// business running before the shipped default password is replaced.
const PASSWORD_CHANGE_REQUIRES_CHANGE: &[&str] =
    &["/api/v1/auth/passkeys", "/api/v1/auth/passkey"];

/// Whether `path` may be used by a session that still owes a password change.
fn password_change_exempt(path: &str) -> bool {
    if !path.starts_with(PASSWORD_CHANGE_EXEMPT_PREFIX) {
        return false;
    }
    !PASSWORD_CHANGE_REQUIRES_CHANGE.iter().any(|blocked| {
        path == *blocked || path.starts_with(&format!("{blocked}/"))
    })
}

/// Refuses every authenticated request from an account that still carries the
/// initial password (D20).
///
/// `require_write` already blocks *mutations* for such an account, but the read
/// surface was wide open: the seeded `admin@pingwaf.local` / `pingwaf123` pair
/// ships in the repository, so until the password changes, anybody who reads
/// the source can enumerate sites, keys, logs and certificates. This middleware
/// closes the read side too, leaving only the endpoints the console needs to
/// finish the forced change.
///
/// The check runs *after* the bearer token is resolved, so an unauthenticated
/// request still gets its 401 and the reply never reveals whether an account
/// exists. A request without a token is passed through untouched — the
/// extractors downstream produce the usual rejection.
pub async fn require_password_change(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    if password_change_exempt(&path) {
        return next.run(request).await;
    }

    // Reuse the extractor so the middleware applies exactly the same
    // signature, revocation and role checks as the handlers behind it.
    let (mut parts, _body) = request.into_parts();
    let Ok(user) = AuthUser::from_request_parts(&mut parts, &state).await
    else {
        // No usable credential: let the handler answer with its own 401.
        let request = Request::from_parts(parts, _body);
        return next.run(request).await;
    };
    let request = Request::from_parts(parts, _body);
    if !user.must_change_password {
        return next.run(request).await;
    }

    error_response(
        StatusCode::FORBIDDEN,
        "password_change_required",
        "change the default password first",
    )
}

/// Pulls the raw bearer token out of the request headers.
pub fn bearer_token(parts: &Parts) -> Result<String, AuthError> {
    let header = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or(AuthError::MissingCredentials)?;
    let value = header
        .to_str()
        .map_err(|_| AuthError::MalformedCredentials)?
        .trim();
    let token = value
        .strip_prefix(BEARER_PREFIX)
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or(AuthError::MalformedCredentials)?
        .trim();
    if token.is_empty() {
        return Err(AuthError::MalformedCredentials);
    }
    Ok(token.to_string())
}

/// Resolves verified token claims against the account table: the token only
/// proves the identity; the account row is the source of truth for
/// existence, the disabled flag, the current role and the token version.
/// Shared by the REST extractors and the MCP endpoint so both enforce the
/// same database-level checks.
pub async fn authenticate_user(
    db: &DatabaseConnection,
    claims: &Claims,
) -> Result<AuthUser, AuthError> {
    let id = claims.subject_id().map_err(|err| {
        AuthError::InvalidToken(format!("subject is not a UUID: {err}"))
    })?;

    let account = user::Entity::find_by_id(id)
        .one(db)
        .await
        .map_err(|err| AuthError::Internal(err.to_string()))?
        .ok_or(AuthError::InvalidToken(
            "account no longer exists".to_string(),
        ))?;
    if account.disabled {
        return Err(AuthError::Forbidden("account is disabled".to_string()));
    }
    if !super::token_version_valid(claims.ver, &account) {
        return Err(AuthError::InvalidToken(
            "session revoked: credentials changed since this token was issued"
                .to_string(),
        ));
    }
    if !role::is_valid(&account.role) {
        return Err(AuthError::InvalidToken(format!(
            "account has an unknown role '{}'",
            account.role
        )));
    }

    Ok(AuthUser {
        id,
        email: account.email,
        role: account.role,
        must_change_password: account.must_change_password,
    })
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let token = bearer_token(parts)?;
        let claims = verify_user_token(&token, app_state.jwt_secret())?;
        authenticate_user(&app_state.db, &claims).await
    }
}

/// Extractor that additionally enforces the `admin` role.
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthUser);

impl AdminUser {
    pub fn id(&self) -> Uuid {
        self.0.id
    }
}

impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        user.require_admin()?;
        Ok(AdminUser(user))
    }
}

impl std::ops::Deref for AdminUser {
    type Target = AuthUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_check_rejects_viewers() {
        let viewer =
            AuthUser::new(Uuid::new_v4(), "v@example.com", role::VIEWER);
        assert!(!viewer.is_admin());
        assert!(viewer.require_admin().is_err());

        let admin = AuthUser::new(Uuid::new_v4(), "a@example.com", role::ADMIN);
        assert!(admin.is_admin());
        assert!(admin.require_admin().is_ok());
    }

    /// D20: only the endpoints a first-login account needs to finish the
    /// forced change stay reachable; everything else is refused.
    #[test]
    fn password_change_exemptions_cover_only_the_login_flow() {
        for path in [
            "/api/v1/auth/status",
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh",
            "/api/v1/auth/logout",
            "/api/v1/auth/password",
            "/api/v1/auth/me",
        ] {
            assert!(password_change_exempt(path), "{path} must stay reachable");
        }

        for path in [
            // Read surfaces the shipped default password would otherwise open.
            "/api/v1/sites",
            "/api/v1/sites/abc",
            "/api/v1/keys",
            "/api/v1/users",
            "/api/v1/logs",
            "/api/v1/login-history",
            "/api/v1/agents",
            "/api/v1/settings",
            "/api/v1/system/info",
            // MCP lives outside the API prefix entirely.
            "/mcp",
            // Not the auth namespace even though it starts with a similar
            // string — a prefix check must not be fooled by `auth` alone.
            "/api/v1/authority",
            // Ordinary account mutations hidden inside the auth prefix.
            "/api/v1/auth/passkeys",
            "/api/v1/auth/passkey/register/begin",
        ] {
            assert!(!password_change_exempt(path), "{path} must be refused");
        }
    }

    #[test]
    fn error_statuses() {
        assert_eq!(
            AuthError::MissingCredentials.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(AuthError::ExpiredToken.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            AuthError::Forbidden("nope".into()).status(),
            StatusCode::FORBIDDEN
        );
    }
}
