//! Authenticating an `/mcp` caller.
//!
//! Two credentials are accepted on the `Authorization: Bearer` header:
//!
//! - a console **API key** (`pwk_…`) — verified against `api_keys`, with the
//!   key's `read` / `write` permissions deciding what the session may call.
//!   `write` additionally requires the key's owner to be an administrator.
//! - a console **JWT** — the same tokens the dashboard uses; `admin` maps to
//!   read+write, `viewer` to read-only. Beyond the signature, the account
//!   row is re-checked on every request exactly like the REST API: disabled
//!   accounts, revoked sessions (token version) and the forced first-login
//!   password change all refuse access here too.
//!
//! Everything else (agent tokens, expired keys, unknown roles) is rejected
//! with `401`, matching the REST API.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::api::error::{error_response, ApiError};
use crate::api::keys::authenticate_api_key;
use crate::api::state::AppState;
use crate::auth::jwt::verify_user_token;
use crate::auth::middleware::{authenticate_user, AuthError, AuthUser};
use crate::models::{api_key, permission, role, user};

/// Identity behind an MCP request, with its effective capabilities.
#[derive(Debug, Clone)]
pub struct McpPrincipal {
    /// Owning user id (for API keys: the key's owner).
    pub subject: Uuid,
    pub email: String,
    /// Human-readable identity used in audit logs, e.g.
    /// `api key pwk_abcd (grafana)` or `alice@example.com`.
    pub label: String,
    /// Key id when the caller authenticated with an API key.
    pub key_id: Option<Uuid>,
    pub can_read: bool,
    pub can_write: bool,
    /// Administrator accounts see every site; everyone else is restricted
    /// to the sites they own (`site.user_id == subject`). MCP tools apply
    /// the same narrowing as the REST handlers (2026-10-18 audit: read
    /// tools returned every site's data to any authenticated caller).
    pub is_admin: bool,
}

/// Rejection of [`McpPrincipal`]; renders as `401`/`403`/`500` JSON.
#[derive(Debug)]
pub struct McpAuthError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl McpAuthError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: message.into(),
        }
    }
}

impl IntoResponse for McpAuthError {
    fn into_response(self) -> Response {
        let mut response =
            error_response(self.status, self.code, &self.message);
        if self.status == StatusCode::UNAUTHORIZED {
            // RFC 6750: MCP clients use this to discover that a bearer token
            // is what the endpoint wants.
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static(
                    "Bearer realm=\"pingwaf-mcp\", error=\"invalid_token\"",
                ),
            );
        }
        response
    }
}

/// Maps an API-key failure onto the MCP rejection.
fn map_key_error(err: ApiError) -> McpAuthError {
    match err {
        ApiError::Unauthorized(message) => McpAuthError::unauthorized(message),
        other => {
            tracing::error!(error = %other, "MCP API key validation failed");
            McpAuthError::internal("could not validate the API key")
        },
    }
}

/// Maps a REST auth failure onto the MCP rejection: policy rejections
/// (disabled account) keep their `403`, identity failures are `401`.
///
/// `AuthError::Internal` wraps the storage error verbatim — table names,
/// connection details. MCP still answers `401`, because that is what the
/// protocol tells a client to do with a credential it could not verify (and a
/// `500` would instead invite a retry loop), but the body carries a fixed
/// text: the detail is only ever logged.
fn map_auth_error(err: AuthError) -> McpAuthError {
    match err {
        AuthError::Forbidden(message) => McpAuthError::forbidden(message),
        AuthError::Internal(message) => {
            tracing::error!(error = %message, "MCP credential lookup failed");
            McpAuthError::unauthorized("could not verify the credentials")
        },
        other => McpAuthError::unauthorized(other.to_string()),
    }
}

/// Builds the principal for an API-key caller.
fn key_principal(
    key: &api_key::Model,
    owner: &user::Model,
) -> Result<McpPrincipal, McpAuthError> {
    let has_read = key.permissions.iter().any(|p| p == permission::READ);
    let has_write = key.permissions.iter().any(|p| p == permission::WRITE);
    if !has_read && !has_write {
        return Err(McpAuthError::forbidden(
            "this API key has no MCP permissions; grant it read or write",
        ));
    }
    Ok(McpPrincipal {
        subject: owner.id,
        email: owner.email.clone(),
        label: format!("api key {} ({})", key.key_prefix, key.name),
        key_id: Some(key.id),
        // A writer can always read; `write` keys are the broader grant.
        can_read: true,
        can_write: has_write && owner.role == role::ADMIN,
        is_admin: owner.role == role::ADMIN,
    })
}

/// Builds the principal for a JWT caller from the freshly loaded account.
fn jwt_principal(user: &AuthUser) -> Result<McpPrincipal, McpAuthError> {
    if user.must_change_password {
        return Err(McpAuthError::forbidden(
            "replace the initial password before using MCP",
        ));
    }
    Ok(McpPrincipal {
        subject: user.id,
        email: user.email.clone(),
        label: user.email.clone(),
        key_id: None,
        can_read: true,
        can_write: user.is_admin(),
        is_admin: user.is_admin(),
    })
}

impl<S> FromRequestParts<S> for McpPrincipal
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = McpAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let header = parts.headers.get(AUTHORIZATION).ok_or_else(|| {
            McpAuthError::unauthorized("missing authorization header")
        })?;
        let value = header.to_str().map_err(|_| {
            McpAuthError::unauthorized("malformed authorization header")
        })?;
        let token = value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                McpAuthError::unauthorized(
                    "authorization header must use the Bearer scheme",
                )
            })?;

        if token.starts_with("pwk_") {
            let (key, owner) = authenticate_api_key(&app_state.db, token)
                .await
                .map_err(map_key_error)?;
            return key_principal(&key, &owner);
        }

        let claims = verify_user_token(token, app_state.jwt_secret()).map_err(
            |err| McpAuthError::unauthorized(format!("invalid token: {err}")),
        )?;
        let user = authenticate_user(&app_state.db, &claims)
            .await
            .map_err(map_auth_error)?;
        jwt_principal(&user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn key(permissions: &[&str]) -> api_key::Model {
        api_key::Model {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "grafana".into(),
            key_hash: String::new(),
            key_prefix: "pwk_abcd".into(),
            permissions: permissions.iter().map(|p| p.to_string()).collect(),
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
        }
    }

    fn owner(role: &str) -> user::Model {
        user::Model {
            id: Uuid::new_v4(),
            email: "ops@example.com".into(),
            password_hash: String::new(),
            name: None,
            role: role.to_string(),
            disabled: false,
            must_change_password: false,
            token_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn read_keys_cannot_write() {
        let principal =
            key_principal(&key(&[permission::READ]), &owner(role::ADMIN))
                .unwrap();
        assert!(principal.can_read);
        assert!(!principal.can_write);
        assert!(principal.key_id.is_some());
    }

    #[test]
    fn write_needs_both_the_permission_and_an_admin_owner() {
        assert!(
            key_principal(&key(&[permission::WRITE]), &owner(role::ADMIN))
                .unwrap()
                .can_write
        );
        assert!(
            !key_principal(&key(&[permission::WRITE]), &owner(role::VIEWER))
                .unwrap()
                .can_write
        );
        // Write implies read.
        assert!(
            key_principal(&key(&[permission::WRITE]), &owner(role::ADMIN))
                .unwrap()
                .can_read
        );
    }

    #[test]
    fn agent_only_keys_are_refused() {
        let err =
            key_principal(&key(&[permission::AGENT]), &owner(role::ADMIN))
                .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn roles_map_onto_capabilities() {
        let admin =
            AuthUser::new(Uuid::new_v4(), "admin@example.com", role::ADMIN);
        assert!(jwt_principal(&admin).unwrap().can_write);

        let viewer =
            AuthUser::new(Uuid::new_v4(), "v@example.com", role::VIEWER);
        let viewer = jwt_principal(&viewer).unwrap();
        assert!(viewer.can_read);
        assert!(!viewer.can_write);
    }

    /// D06: the storage error used to be the 401 body, table names included.
    /// The `401` itself has to stay — without a `WWW-Authenticate: Bearer`
    /// challenge some MCP clients never send the key at all.
    #[test]
    fn storage_failures_answer_without_the_database_detail() {
        let err = map_auth_error(AuthError::Internal(
            "no such table: api_keys (postgres://pingwaf@10.0.0.2/pingwaf)"
                .to_string(),
        ));
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "unauthorized");
        assert_eq!(err.message, "could not verify the credentials");
    }

    /// The rejection of a bad credential still says *why* it was rejected.
    #[test]
    fn identity_failures_keep_their_reason() {
        let err = map_auth_error(AuthError::ExpiredToken);
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.message, "token expired");
    }

    #[test]
    fn forced_password_change_blocks_mcp() {
        let mut user =
            AuthUser::new(Uuid::new_v4(), "fresh@example.com", role::ADMIN);
        user.must_change_password = true;
        let err = jwt_principal(&user).unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }
}
