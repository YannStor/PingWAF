//! JWT issuing and verification for dashboard users and registered agents.

use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Value placed in the `iss` claim of every token minted here.
pub const ISSUER: &str = "pingwaf-server";

/// `typ` claim for dashboard (human) sessions.
pub const TOKEN_TYPE_DASHBOARD: &str = "dashboard";
/// `typ` claim for long-lived refresh tokens.
pub const TOKEN_TYPE_REFRESH: &str = "refresh";
/// `typ` claim for agent sessions; agents present these on the gRPC plane.
pub const TOKEN_TYPE_AGENT: &str = "agent";

/// Role carried by agent tokens. It is deliberately not one of
/// [`crate::models::role`] because agents never authenticate to the REST API.
pub const AGENT_ROLE: &str = "agent";

/// Payload of a PingWAF access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: the user id (dashboard) or agent id (gRPC), as a UUID string.
    pub sub: String,
    /// E-mail of the user; empty for agent tokens.
    pub email: String,
    /// `admin` / `viewer` for users, `agent` for agents.
    pub role: String,
    /// Expiration, seconds since the Unix epoch.
    pub exp: i64,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: i64,
    /// Issuer, always [`ISSUER`].
    #[serde(default)]
    pub iss: String,
    /// Token class, see [`TOKEN_TYPE_DASHBOARD`] / [`TOKEN_TYPE_AGENT`].
    #[serde(default)]
    pub typ: String,
    /// Account `token_version` at mint time. A mismatch against the account
    /// row means the token predates a credential change and is refused.
    /// Absent in tokens minted before the field existed, which deserialises
    /// as 0 — the pre-revocation epoch.
    #[serde(default)]
    pub ver: i64,
    /// Unique id of a refresh token, used to make it single-use. Absent on
    /// access/agent tokens and on refresh tokens minted before rotation
    /// existed (those keep working, for compatibility).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl Claims {
    /// Parses `sub` back into a [`Uuid`].
    pub fn subject_id(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.sub)
    }

    /// True when this token was minted for an agent rather than a dashboard
    /// user.
    pub fn is_agent(&self) -> bool {
        self.typ == TOKEN_TYPE_AGENT
    }

    /// True when this is a refresh token, which may only be exchanged at
    /// `POST /api/v1/auth/refresh`.
    pub fn is_refresh(&self) -> bool {
        self.typ == TOKEN_TYPE_REFRESH
    }

    /// True when the token has passed its `exp` instant.
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() >= self.exp
    }
}

/// Errors produced while minting or verifying tokens.
#[derive(Debug)]
pub enum JwtError {
    Expired,
    InvalidSignature,
    Malformed(String),
    Signing(String),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Expired => f.write_str("token expired"),
            JwtError::InvalidSignature => {
                f.write_str("invalid token signature")
            },
            JwtError::Malformed(msg) => write!(f, "malformed token: {msg}"),
            JwtError::Signing(msg) => write!(f, "token signing failed: {msg}"),
        }
    }
}

impl std::error::Error for JwtError {}

impl From<jsonwebtoken::errors::Error> for JwtError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match err.kind() {
            ErrorKind::ExpiredSignature => JwtError::Expired,
            ErrorKind::InvalidSignature => JwtError::InvalidSignature,
            // Every other kind (bad base64, unknown issuer, missing claims…)
            // is reported as a malformed token; `Debug` is always available on
            // `ErrorKind` regardless of the jsonwebtoken patch level.
            other => JwtError::Malformed(format!("{other:?}")),
        }
    }
}

/// Builds the claim set shared by dashboard and agent tokens.
fn build_claims(
    sub: String,
    email: String,
    role: String,
    typ: &str,
    token_version: i64,
    expiration_hours: i64,
) -> Claims {
    let now = Utc::now();
    // Clamp absurd/negative lifetimes into a sane window instead of panicking.
    let hours = expiration_hours.clamp(1, 24 * 365);
    let exp = now + Duration::hours(hours);
    Claims {
        sub,
        email,
        role,
        exp: exp.timestamp(),
        iat: now.timestamp(),
        iss: ISSUER.to_string(),
        typ: typ.to_string(),
        ver: token_version,
        jti: None,
    }
}

/// Mints a dashboard access token for `user_id`.
pub fn create_token(
    user_id: Uuid,
    email: &str,
    role: &str,
    token_version: i64,
    secret: &str,
    expiration_hours: i64,
) -> Result<String, JwtError> {
    create_token_with_type(
        user_id,
        email,
        role,
        TOKEN_TYPE_DASHBOARD,
        token_version,
        secret,
        expiration_hours,
    )
}

/// Mints a long-lived refresh token that can only be exchanged for a new access
/// token.
pub fn create_refresh_token(
    user_id: Uuid,
    email: &str,
    role: &str,
    token_version: i64,
    secret: &str,
    expiration_hours: i64,
) -> Result<String, JwtError> {
    create_token_with_type(
        user_id,
        email,
        role,
        TOKEN_TYPE_REFRESH,
        token_version,
        secret,
        expiration_hours,
    )
}

/// Mints a token for an agent that just completed registration.
pub fn create_agent_token(
    agent_id: Uuid,
    secret: &str,
    expiration_hours: i64,
) -> Result<String, JwtError> {
    create_token_with_type(
        agent_id,
        "",
        crate::auth::jwt::AGENT_ROLE,
        TOKEN_TYPE_AGENT,
        0,
        secret,
        expiration_hours,
    )
}

fn create_token_with_type(
    subject: Uuid,
    email: &str,
    role: &str,
    typ: &str,
    token_version: i64,
    secret: &str,
    expiration_hours: i64,
) -> Result<String, JwtError> {
    let mut claims = build_claims(
        subject.to_string(),
        email.to_string(),
        role.to_string(),
        typ,
        token_version,
        expiration_hours,
    );
    if typ == TOKEN_TYPE_REFRESH {
        // Single-use marker: the refresh handler remembers it until expiry.
        claims.jti = Some(Uuid::new_v4().to_string());
    }
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|err| JwtError::Signing(err.to_string()))
}

/// Verifies the signature, issuer and expiry of `token`.
pub fn verify_token(token: &str, secret: &str) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[ISSUER]);
    // PingWAF tokens carry no `aud` claim.
    validation.validate_aud = false;
    validation.leeway = 30;
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;
    Ok(data.claims)
}

/// Verifies a token and asserts it is a dashboard (non-agent, non-refresh)
/// access token.
pub fn verify_user_token(
    token: &str,
    secret: &str,
) -> Result<Claims, JwtError> {
    let claims = verify_token(token, secret)?;
    if claims.is_agent() {
        return Err(JwtError::Malformed(
            "agent tokens are not valid for dashboard access".to_string(),
        ));
    }
    if claims.is_refresh() {
        return Err(JwtError::Malformed(
            "refresh tokens cannot be used to call the API".to_string(),
        ));
    }
    Ok(claims)
}

/// Verifies a token and asserts it is a refresh token.
pub fn verify_refresh_token(
    token: &str,
    secret: &str,
) -> Result<Claims, JwtError> {
    let claims = verify_token(token, secret)?;
    if !claims.is_refresh() {
        return Err(JwtError::Malformed("not a refresh token".to_string()));
    }
    Ok(claims)
}

/// Verifies a token and asserts it was issued to an agent.
pub fn verify_agent_token(
    token: &str,
    secret: &str,
) -> Result<Claims, JwtError> {
    let claims = verify_token(token, secret)?;
    if !claims.is_agent() {
        return Err(JwtError::Malformed("not an agent token".to_string()));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::role;

    const SECRET: &str = "unit-test-secret-value";

    #[test]
    fn roundtrip_dashboard_token() {
        let id = Uuid::new_v4();
        let token =
            create_token(id, "ops@example.com", role::ADMIN, 0, SECRET, 1)
                .expect("token");
        let claims = verify_token(&token, SECRET).expect("verify");
        assert_eq!(claims.sub, id.to_string());
        assert_eq!(claims.email, "ops@example.com");
        assert_eq!(claims.role, role::ADMIN);
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.ver, 0);
        assert!(!claims.is_agent());
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let token =
            create_token(Uuid::new_v4(), "a@b.c", role::VIEWER, 0, SECRET, 1)
                .unwrap();
        assert!(matches!(
            verify_token(&token, "another-secret"),
            Err(JwtError::InvalidSignature | JwtError::Malformed(_))
        ));
    }

    #[test]
    fn agent_tokens_are_segregated() {
        let agent = create_agent_token(Uuid::new_v4(), SECRET, 1).unwrap();
        assert!(verify_agent_token(&agent, SECRET).is_ok());
        assert!(verify_user_token(&agent, SECRET).is_err());

        let user =
            create_token(Uuid::new_v4(), "a@b.c", role::ADMIN, 0, SECRET, 1)
                .unwrap();
        assert!(verify_user_token(&user, SECRET).is_ok());
        assert!(verify_agent_token(&user, SECRET).is_err());
        assert!(verify_refresh_token(&user, SECRET).is_err());
    }

    #[test]
    fn refresh_tokens_cannot_call_the_api() {
        let id = Uuid::new_v4();
        let refresh =
            create_refresh_token(id, "a@b.c", role::ADMIN, 3, SECRET, 24)
                .unwrap();
        assert!(verify_refresh_token(&refresh, SECRET).is_ok());
        assert!(verify_user_token(&refresh, SECRET).is_err());
        let claims = verify_token(&refresh, SECRET).unwrap();
        assert_eq!(claims.ver, 3);
        // Refresh tokens carry a single-use marker; access tokens do not.
        assert!(claims.jti.is_some());
        let access =
            create_token(id, "a@b.c", role::ADMIN, 3, SECRET, 1).unwrap();
        assert!(verify_token(&access, SECRET).unwrap().jti.is_none());
    }

    /// Tokens minted before `ver` existed deserialize as version 0, so a
    /// control plane upgrade does not invalidate every live session.
    #[test]
    fn legacy_tokens_without_ver_default_to_zero() {
        let legacy: Claims = serde_json::from_value(serde_json::json!({
            "sub": Uuid::new_v4().to_string(),
            "email": "old@example.com",
            "role": role::ADMIN,
            "exp": 4_102_444_800i64,
            "iat": 1_760_000_000i64,
            "iss": ISSUER,
            "typ": TOKEN_TYPE_DASHBOARD,
        }))
        .expect("legacy claim set");
        assert_eq!(legacy.ver, 0);
    }

    #[test]
    fn garbage_input_is_rejected() {
        assert!(matches!(
            verify_token("not-a-jwt", SECRET),
            Err(JwtError::Malformed(_))
        ));
    }
}
