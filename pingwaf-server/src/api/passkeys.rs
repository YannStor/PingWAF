//! Passkey (WebAuthn) endpoints: binding an authenticator to the signed-in
//! account, and signing in with one.
//!
//! The protocol work is delegated to `passkey-server`, which is storage
//! agnostic: its [`PasskeyStore`] trait is implemented for [`AppState`] at the
//! bottom of this module, so ceremonies read and write PostgreSQL through the
//! same pool as the rest of the API. Keeping the ceremony state in the database
//! (rather than in process memory) means a deployment that runs several
//! replicas does not need sticky sessions.
//!
//! Failures always surface as `400` rather than `401`: answering `401` to an
//! authenticated `register/finish` would make the web client treat the session
//! as dead and log the operator out mid-ceremony.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use passkey_server::error::{PasskeyError, Result as PasskeyResult};
use passkey_server::types::{
    LoginResponse, PasskeyConfig, PasskeyState,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
    RegistrationResponse, StoredPasskey,
};
use passkey_server::{
    finish_login, finish_registration, start_login, start_registration,
    PasskeyStore,
};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::host_without_port;
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::middleware::AuthUser;
use crate::models::{
    instance_setting, passkey_credential, passkey_state, role, user,
};

/// How long a ceremony's challenge stays valid, in seconds.
const STATE_TTL_SECONDS: i64 = 300;
/// Longest passkey label accepted from the dashboard.
const MAX_NAME_LENGTH: usize = 100;
/// Ceremonies one replica will start per minute, across all callers.
const CHALLENGES_PER_MINUTE: u32 = 120;

/// `instance_settings` key holding the runtime passkey master switch.
const PASSKEY_ENABLED_KEY: &str = "passkey_enabled";

/// Resolves the master switch from the stored KV row: an explicit `true` /
/// `false` wins; a missing row (or a legacy value) falls back to the boot
/// configuration.
fn enabled_from_stored(stored: Option<&str>, boot_default: bool) -> bool {
    match stored.map(str::trim) {
        Some("true") => true,
        Some("false") => false,
        _ => boot_default,
    }
}

/// Effective passkey master switch: the runtime KV overrides the static boot
/// config, so an operator can disable passkey logins without a restart.
pub async fn passkey_enabled(
    db: &sea_orm::DatabaseConnection,
    boot_default: bool,
) -> Result<bool, sea_orm::DbErr> {
    let row = instance_setting::Entity::find_by_id(PASSKEY_ENABLED_KEY)
        .one(db)
        .await?;
    Ok(enabled_from_stored(
        row.map(|row| row.value).as_deref(),
        boot_default,
    ))
}

/// Persists the runtime master switch.
async fn set_passkey_enabled(
    db: &sea_orm::DatabaseConnection,
    enabled: bool,
) -> Result<(), sea_orm::DbErr> {
    let existing = instance_setting::Entity::find_by_id(PASSKEY_ENABLED_KEY)
        .one(db)
        .await?;
    if let Some(row) = existing {
        let mut active: instance_setting::ActiveModel = row.into();
        active.value = Set(enabled.to_string());
        active.updated_at = Set(Utc::now());
        active.update(db).await?;
    } else {
        instance_setting::ActiveModel {
            key: Set(PASSKEY_ENABLED_KEY.to_string()),
            value: Set(enabled.to_string()),
            updated_at: Set(Utc::now()),
        }
        .insert(db)
        .await?;
    }
    Ok(())
}

/// Handler-side gate: every ceremony entry point refuses to run while the
/// master switch is off. `relying_party` keeps the static boot-config check
/// for tests and scheme resolution; this adds the runtime toggle on top.
async fn ensure_passkey_enabled(state: &AppState) -> Result<(), ApiError> {
    if !passkey_enabled(&state.db, state.config.passkey_enabled).await? {
        return Err(ApiError::NotImplemented(
            "passkeys are disabled on this deployment".to_string(),
        ));
    }
    Ok(())
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/passkeys", get(list_passkeys))
        .route("/auth/passkeys/{id}", patch(rename_passkey))
        .route("/auth/passkeys/{id}", delete(delete_passkey))
        .route("/auth/passkey/register/begin", post(register_begin))
        .route("/auth/passkey/register/finish", post(register_finish))
        .route("/auth/passkey/login/begin", post(login_begin))
        .route("/auth/passkey/login/finish", post(login_finish))
        .route(
            "/settings/passkeys",
            get(show_passkey_settings).put(update_passkey_settings),
        )
}

/// `GET /api/v1/settings/passkeys` — the effective master switch.
async fn show_passkey_settings(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<PasskeySettingsView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(PasskeySettingsView {
        enabled: passkey_enabled(&state.db, state.config.passkey_enabled)
            .await?,
    }))
}

/// `PUT /api/v1/settings/passkeys` — persists the runtime master switch.
///
/// Takes effect immediately: the next ceremony entry point re-reads the
/// switch, so disabling locks out new registrations and passkey logins
/// without a restart (already-bound credentials are kept for re-enabling).
async fn update_passkey_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<PasskeySettingsUpdate>,
) -> Result<Json<PasskeySettingsView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    set_passkey_enabled(&state.db, payload.enabled).await?;
    tracing::info!(
        actor = %current.id,
        enabled = payload.enabled,
        "passkey master switch updated"
    );
    Ok(Json(PasskeySettingsView {
        enabled: payload.enabled,
    }))
}

/// The passkey settings view for the dashboard.
#[derive(Debug, Serialize)]
pub struct PasskeySettingsView {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct PasskeySettingsUpdate {
    pub enabled: bool,
}

#[cfg(test)]
mod switch_tests {
    use super::enabled_from_stored;

    #[test]
    fn the_stored_switch_overrides_the_boot_config() {
        assert!(enabled_from_stored(Some("true"), false));
        assert!(!enabled_from_stored(Some("false"), true));

        // Missing row or a legacy/unknown value falls back to the boot config.
        assert!(enabled_from_stored(None, true));
        assert!(!enabled_from_stored(None, false));
        assert!(enabled_from_stored(Some(" true "), true));
        assert!(!enabled_from_stored(Some("bogus"), false));
        // An empty value is not a decision either way: fall back too.
        assert!(enabled_from_stored(Some(""), true));
    }
}

/// A passkey as the dashboard sees it. The credential id and public key stay
/// server side: the browser addresses a credential by its database id.
#[derive(Debug, Serialize)]
pub struct PasskeySummary {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

impl From<passkey_credential::Model> for PasskeySummary {
    fn from(model: passkey_credential::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            created_at: model.created_at,
            last_used_at: model.last_used_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RenameRequest {
    pub name: String,
}

/// `GET /api/v1/auth/passkeys`
async fn list_passkeys(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<Vec<PasskeySummary>>, ApiError> {
    let rows = passkey_credential::Entity::find()
        .filter(passkey_credential::Column::UserId.eq(current.id))
        .order_by_asc(passkey_credential::Column::CreatedAt)
        .all(&state.db)
        .await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

/// `PATCH /api/v1/auth/passkeys/{id}`
async fn rename_passkey(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<RenameRequest>,
) -> Result<Json<PasskeySummary>, ApiError> {
    let row = load_owned_passkey(&state, current.id, &id).await?;
    let name = validate_name(&payload.name)?;

    passkey_credential::Entity::update_many()
        .set(passkey_credential::ActiveModel {
            name: Set(name),
            ..Default::default()
        })
        .filter(passkey_credential::Column::Id.eq(row.id))
        .exec(&state.db)
        .await?;

    let updated = passkey_credential::Entity::find_by_id(row.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("passkey not found".to_string()))?;
    Ok(Json(updated.into()))
}

/// `DELETE /api/v1/auth/passkeys/{id}`
async fn delete_passkey(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let row = load_owned_passkey(&state, current.id, &id).await?;
    passkey_credential::Entity::delete_by_id(row.id)
        .exec(&state.db)
        .await?;
    tracing::info!(user_id = %current.id, passkey_id = %row.id, "passkey deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/auth/passkey/register/begin`
async fn register_begin(
    State(state): State<AppState>,
    current: AuthUser,
    headers: HeaderMap,
) -> Result<Json<PublicKeyCredentialCreationOptions>, ApiError> {
    ensure_passkey_enabled(&state).await?;
    let config = relying_party(&state, &headers)?;
    challenge_budget().consume()?;

    // The account is re-read rather than taken from the token so that the name
    // offered to the authenticator is current, and so that a deleted account
    // cannot start a ceremony.
    let account = user::Entity::find_by_id(current.id)
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::Unauthorized("account no longer exists".to_string())
        })?;
    let display_name = account
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&account.email)
        .to_string();

    let options = start_registration(
        &state,
        &account.id.to_string(),
        &account.email,
        &display_name,
        &config,
        Utc::now().timestamp_millis(),
    )
    .await
    .map_err(ceremony_error)?;

    state.purge_expired_states().await;
    Ok(Json(options))
}

/// `POST /api/v1/auth/passkey/register/finish`
///
/// The body is the credential the authenticator produced; its optional `name`
/// field carries the operator's label for it.
async fn register_finish(
    State(state): State<AppState>,
    current: AuthUser,
    headers: HeaderMap,
    Json(payload): Json<RegistrationResponse>,
) -> Result<Response, ApiError> {
    ensure_passkey_enabled(&state).await?;
    let config = relying_party(&state, &headers)?;
    let cred_id = payload.id.clone();

    let mut response = payload;
    response.name = Some(validate_name(
        response.name.as_deref().unwrap_or("Passkey"),
    )?);

    finish_registration(
        &state,
        &current.id.to_string(),
        &config,
        response,
        Utc::now().timestamp_millis(),
    )
    .await
    .map_err(ceremony_error)?;

    tracing::info!(user_id = %current.id, "passkey registered");
    let created = passkey_credential::Entity::find()
        .filter(passkey_credential::Column::CredId.eq(cred_id))
        .one(&state.db)
        .await?;
    Ok(match created {
        Some(row) => (StatusCode::CREATED, Json(PasskeySummary::from(row)))
            .into_response(),
        // A client that reported an `id` differing from the attested credential
        // still completed the ceremony, so report it as created.
        None => StatusCode::CREATED.into_response(),
    })
}

/// `POST /api/v1/auth/passkey/login/begin`
///
/// Unauthenticated: the caller does not have to know which account it will end
/// up as, because a passkey carries its own user handle.
async fn login_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PublicKeyCredentialRequestOptions>, ApiError> {
    ensure_passkey_enabled(&state).await?;
    let config = relying_party(&state, &headers)?;
    challenge_budget().consume()?;

    let options = start_login(&state, &config, Utc::now().timestamp_millis())
        .await
        .map_err(ceremony_error)?;

    state.purge_expired_states().await;
    Ok(Json(options))
}

/// `POST /api/v1/auth/passkey/login/finish`
async fn login_finish(
    State(state): State<AppState>,
    connect_info: Option<axum::Extension<crate::tls::ConnInfo>>,
    headers: HeaderMap,
    Json(response): Json<LoginResponse>,
) -> Result<Response, ApiError> {
    ensure_passkey_enabled(&state).await?;
    let config = relying_party(&state, &headers)?;

    let user_id =
        finish_login(&state, &config, response, Utc::now().timestamp_millis())
            .await
            .map_err(ceremony_error)?;

    let account = user::Entity::find_by_id(Uuid::parse_str(&user_id)?)
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::Unauthorized(
                "the account this passkey belongs to no longer exists"
                    .to_string(),
            )
        })?;

    // The ceremony only proves possession of the authenticator; the account
    // row is still the source of truth, exactly as for a password login. A
    // passkey bound before the administrator disabled the account (or before a
    // credential change bumped `token_version`) must not mint a fresh session.
    ensure_account_active(&account)?;

    tracing::info!(%user_id, "user logged in with a passkey");

    // Passkey logins join the history (the baseline for password-login
    // anomaly detection) but are never judged: the factor itself is
    // already stronger than a location heuristic.
    let db = state.db.clone();
    let login_user_id = account.id;
    let login_email = account.email.clone();
    tokio::spawn(async move {
        crate::notify::login_anomaly::record_login(
            &db,
            login_user_id,
            &login_email,
            &headers,
            connect_info.map(|info| info.0.peer_addr.ip()),
            false,
        )
        .await;
    });

    let tokens = crate::api::auth::issue_tokens(&state, account)?;
    Ok((StatusCode::OK, Json(tokens)).into_response())
}

/// Refuses a passkey login for an account the password flow would refuse.
///
/// A completed WebAuthn ceremony proves possession of the authenticator, not
/// that the account may still sign in: the disabled flag and the unknown-role
/// guard apply to every factor. The wording matches the password login
/// (`crate::api::auth`) so a caller cannot tell the two flows apart.
fn ensure_account_active(account: &user::Model) -> Result<(), ApiError> {
    if account.disabled {
        tracing::debug!(user_id = %account.id, "passkey login failed: account disabled");
        return Err(ApiError::Unauthorized("account is disabled".to_string()));
    }
    if !role::is_valid(&account.role) {
        return Err(ApiError::Unauthorized(format!(
            "account has an unknown role '{}'",
            account.role
        )));
    }
    Ok(())
}

/// Loads a credential the caller owns, or reports it as missing.
///
/// Scoping the lookup by `user_id` means one account can never rename or delete
/// another account's passkey, and a foreign id is indistinguishable from a
/// non-existent one.
async fn load_owned_passkey(
    state: &AppState,
    user_id: Uuid,
    id: &str,
) -> Result<passkey_credential::Model, ApiError> {
    let id = Uuid::parse_str(id.trim()).map_err(|_| {
        ApiError::BadRequest(format!("invalid passkey id '{id}'"))
    })?;
    passkey_credential::Entity::find()
        .filter(passkey_credential::Column::Id.eq(id))
        .filter(passkey_credential::Column::UserId.eq(user_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("passkey {id} not found")))
}

/// Trims and bounds an operator supplied label.
fn validate_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest(
            "a passkey name is required".to_string(),
        ));
    }
    if name.chars().count() > MAX_NAME_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "a passkey name may be at most {MAX_NAME_LENGTH} characters"
        )));
    }
    Ok(name.to_string())
}

/// Resolves the WebAuthn relying party for this request.
///
/// `rp_id` and `origin` both default to what the request itself says, which is
/// what a deployment reached under a single hostname wants; the config fields
/// exist for a dashboard behind a TLS-terminating proxy, where the control
/// plane only sees plain HTTP and cannot tell which scheme the browser used.
fn relying_party(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<PasskeyConfig, ApiError> {
    if !state.config.passkey_enabled {
        return Err(ApiError::NotImplemented(
            "passkeys are disabled on this deployment".to_string(),
        ));
    }

    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let rp_id = match &state.config.passkey_rp_id {
        Some(configured) => configured.clone(),
        None => {
            let host = host.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "the request carries no Host header; configure passkey_rp_id"
                        .to_string(),
                )
            })?;
            let domain = host_without_port(host);
            if domain.parse::<std::net::IpAddr>().is_ok() {
                return Err(ApiError::BadRequest(format!(
                    "passkeys need a hostname, but the console was reached at \
                     '{domain}'; use a domain name (localhost works for local \
                     testing) or configure passkey_rp_id and passkey_origin"
                )));
            }
            if domain.is_empty() {
                return Err(ApiError::BadRequest(
                    "could not derive a relying party id from the Host header"
                        .to_string(),
                ));
            }
            domain.to_string()
        },
    };

    let origin = match &state.config.passkey_origin {
        Some(configured) => configured.clone(),
        None => {
            let host = host.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "the request carries no Host header; configure passkey_origin"
                        .to_string(),
                )
            })?;
            format!("{}://{host}", request_scheme(state, headers))
        },
    };

    Ok(PasskeyConfig {
        rp_id,
        rp_name: state.config.passkey_rp_name.clone(),
        origin,
        state_ttl: STATE_TTL_SECONDS,
    })
}

/// The scheme the browser used, as far as the control plane can tell.
///
/// Only the explicit opt-in flag makes `X-Forwarded-Proto` believable; without
/// it a direct caller could claim an origin it never used. When the flag is off
/// the answer comes from how this process is deployed: a listener that
/// terminates TLS only serves handlers over HTTPS (cleartext requests are
/// redirected before they get here), so a request that reaches a handler on it
/// arrived over TLS.
fn request_scheme<'a>(state: &AppState, headers: &'a HeaderMap) -> &'a str {
    if state.config.passkey_trust_forwarded_proto {
        if let Some(value @ ("http" | "https")) = headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
        {
            return value;
        }
    }
    if state.control_tls.is_enabled() {
        return "https";
    }
    "http"
}

/// Maps a library error onto the API envelope.
///
/// Everything a client can get wrong is a bad request; storage and
/// serialisation faults are internal. The detailed reason is logged, because
/// several of them (a mismatched origin, most of all) are configuration
/// problems the operator has to see.
fn ceremony_error(err: PasskeyError) -> ApiError {
    match err {
        PasskeyError::DatabaseError(_)
        | PasskeyError::InternalError(_)
        | PasskeyError::SerializationError(_) => {
            ApiError::Internal(err.to_string())
        },
        PasskeyError::OriginMismatch { .. } => {
            tracing::warn!(
                error = %err,
                "passkey ceremony rejected: the browser origin does not match the configured one"
            );
            ApiError::BadRequest(err.to_string())
        },
        other => {
            tracing::debug!(error = %other, "passkey ceremony rejected");
            ApiError::BadRequest(other.to_string())
        },
    }
}

/// `passkey-server` appends the authenticator's AAGUID to the label it was
/// given; the dashboard shows the operator's own wording instead.
fn strip_aaguid_suffix(name: &str) -> &str {
    if name.len() > 37 {
        let (head, tail) = name.split_at(name.len() - 36);
        if head.ends_with('-') && Uuid::parse_str(tail).is_ok() {
            return head.trim_end_matches('-');
        }
    }
    name
}

/// Normalises a stored label into something the dashboard can show.
fn display_name(raw: &str) -> String {
    let name = strip_aaguid_suffix(raw.trim());
    if name.is_empty() {
        return "Passkey".to_string();
    }
    name.chars().take(MAX_NAME_LENGTH).collect()
}

fn millis_to_datetime(millis: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(millis).unwrap_or_else(Utc::now)
}

fn database_error(err: sea_orm::DbErr) -> PasskeyError {
    PasskeyError::DatabaseError(err.to_string())
}

fn parse_owner(user_id: &str) -> PasskeyResult<Uuid> {
    Uuid::parse_str(user_id).map_err(|err| {
        PasskeyError::InternalError(format!(
            "invalid user id '{user_id}': {err}"
        ))
    })
}

fn to_stored(model: passkey_credential::Model) -> StoredPasskey {
    StoredPasskey {
        user_id: model.user_id.to_string(),
        cred_id: model.cred_id,
        public_key: model.public_key,
        name: model.name,
        created_at: model.created_at.timestamp_millis(),
        last_used_at: model.last_used_at.timestamp_millis(),
        counter: model.counter,
    }
}

/// Process-wide budget for the unauthenticated challenge endpoints.
///
/// The control plane does not record the peer address, so the budget cannot be
/// per client: it is sized for the handful of operators a dashboard has, and
/// exists so that a flood cannot keep `passkey_states` growing.
fn challenge_budget() -> &'static ChallengeBudget {
    static BUDGET: OnceLock<ChallengeBudget> = OnceLock::new();
    BUDGET.get_or_init(ChallengeBudget::default)
}

/// Fixed-window counter behind [`challenge_budget`].
pub struct ChallengeBudget {
    limit: u32,
    window: Duration,
    current: Mutex<(Instant, u32)>,
}

impl ChallengeBudget {
    fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            current: Mutex::new((Instant::now(), 0)),
        }
    }

    /// Charges one ceremony to the current window, or fails with `429`.
    pub fn consume(&self) -> Result<(), ApiError> {
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (start, used) = &mut *current;
        if start.elapsed() >= self.window {
            *start = Instant::now();
            *used = 0;
        }
        if *used >= self.limit {
            return Err(ApiError::TooManyRequests(
                "too many passkey ceremonies, try again in a minute"
                    .to_string(),
            ));
        }
        *used += 1;
        Ok(())
    }
}

impl Default for ChallengeBudget {
    fn default() -> Self {
        Self::new(CHALLENGES_PER_MINUTE, Duration::from_secs(60))
    }
}

impl AppState {
    /// Drops ceremony state whose challenge has expired.
    async fn purge_expired_states(&self) {
        if let Err(err) = passkey_state::Entity::delete_many()
            .filter(passkey_state::Column::ExpiresAt.lt(Utc::now()))
            .exec(&self.db)
            .await
        {
            // Housekeeping only: an expired challenge is refused on read too.
            tracing::warn!(error = %err, "could not purge expired passkey states");
        }
    }
}

/// Database-backed [`PasskeyStore`] used by every ceremony endpoint.
#[async_trait::async_trait]
impl PasskeyStore for AppState {
    async fn create_passkey(
        &self,
        user_id: String,
        cred_id: &str,
        public_key: &str,
        name: &str,
        counter: i64,
        created_at: i64,
    ) -> PasskeyResult<()> {
        let timestamp = millis_to_datetime(created_at);
        let row = passkey_credential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(parse_owner(&user_id)?),
            cred_id: Set(cred_id.to_string()),
            public_key: Set(public_key.to_string()),
            name: Set(display_name(name)),
            counter: Set(counter),
            created_at: Set(timestamp),
            last_used_at: Set(timestamp),
        };
        row.insert(&self.db).await.map_err(database_error)?;
        Ok(())
    }

    async fn get_passkey(
        &self,
        cred_id: &str,
    ) -> PasskeyResult<Option<StoredPasskey>> {
        let found = passkey_credential::Entity::find()
            .filter(passkey_credential::Column::CredId.eq(cred_id))
            .one(&self.db)
            .await
            .map_err(database_error)?;
        Ok(found.map(to_stored))
    }

    async fn list_passkeys(
        &self,
        user_id: String,
    ) -> PasskeyResult<Vec<StoredPasskey>> {
        let rows = passkey_credential::Entity::find()
            .filter(
                passkey_credential::Column::UserId.eq(parse_owner(&user_id)?),
            )
            .order_by_asc(passkey_credential::Column::CreatedAt)
            .all(&self.db)
            .await
            .map_err(database_error)?;
        Ok(rows.into_iter().map(to_stored).collect())
    }

    async fn delete_passkey(
        &self,
        user_id: String,
        cred_id: &str,
    ) -> PasskeyResult<()> {
        passkey_credential::Entity::delete_many()
            .filter(
                passkey_credential::Column::UserId.eq(parse_owner(&user_id)?),
            )
            .filter(passkey_credential::Column::CredId.eq(cred_id))
            .exec(&self.db)
            .await
            .map_err(database_error)?;
        Ok(())
    }

    async fn update_passkey_counter(
        &self,
        cred_id: &str,
        new_counter: i64,
        last_used_at: i64,
    ) -> PasskeyResult<()> {
        passkey_credential::Entity::update_many()
            .set(passkey_credential::ActiveModel {
                counter: Set(new_counter),
                last_used_at: Set(millis_to_datetime(last_used_at)),
                ..Default::default()
            })
            .filter(passkey_credential::Column::CredId.eq(cred_id))
            .exec(&self.db)
            .await
            .map_err(database_error)?;
        Ok(())
    }

    async fn update_passkey_name(
        &self,
        cred_id: &str,
        new_name: &str,
    ) -> PasskeyResult<()> {
        passkey_credential::Entity::update_many()
            .set(passkey_credential::ActiveModel {
                name: Set(display_name(new_name)),
                ..Default::default()
            })
            .filter(passkey_credential::Column::CredId.eq(cred_id))
            .exec(&self.db)
            .await
            .map_err(database_error)?;
        Ok(())
    }

    async fn save_state(
        &self,
        id: &str,
        state_json: &str,
        expires_at: i64,
    ) -> PasskeyResult<()> {
        let row = passkey_state::ActiveModel {
            id: Set(id.to_string()),
            state_json: Set(state_json.to_string()),
            expires_at: Set(millis_to_datetime(expires_at)),
        };
        // A second `begin` for the same account reuses the registration state
        // id, so the row has to be replaced rather than inserted.
        passkey_state::Entity::insert(row)
            .on_conflict(
                OnConflict::column(passkey_state::Column::Id)
                    .update_columns([
                        passkey_state::Column::StateJson,
                        passkey_state::Column::ExpiresAt,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(&self.db)
            .await
            .map_err(database_error)?;
        Ok(())
    }

    async fn get_state(&self, id: &str) -> PasskeyResult<Option<PasskeyState>> {
        let found = passkey_state::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(database_error)?;
        Ok(found.and_then(|row| {
            if row.expires_at <= Utc::now() {
                return None;
            }
            Some(PasskeyState {
                id: row.id,
                state_json: row.state_json,
                expires_at: row.expires_at.timestamp_millis(),
            })
        }))
    }

    async fn delete_state(&self, id: &str) -> PasskeyResult<()> {
        passkey_state::Entity::delete_by_id(id.to_string())
            .exec(&self.db)
            .await
            .map_err(database_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn state_with(config: crate::config::ServerConfig) -> AppState {
        AppState::new(
            sea_orm::DatabaseConnection::Disconnected,
            config,
            crate::grpc::AgentRegistry::new(),
        )
    }

    #[test]
    fn the_scheme_follows_the_listener_and_the_forwarded_header() {
        let plain = state_with(crate::config::ServerConfig::default());
        let host = headers(&[("host", "waf.example.com:9080")]);
        assert_eq!(request_scheme(&plain, &host), "http");

        // A listener that terminates TLS serves every handler over https.
        let mut terminated = plain.clone();
        terminated.control_tls =
            std::sync::Arc::new(crate::tls::ControlPlaneTls::new(true));
        assert_eq!(request_scheme(&terminated, &host), "https");

        // Behind a proxy the header decides, but only when the operator opted
        // in; a bogus value is ignored rather than trusted.
        let mut behind_proxy = terminated.clone();
        behind_proxy.config =
            std::sync::Arc::new(crate::config::ServerConfig {
                passkey_trust_forwarded_proto: true,
                ..Default::default()
            });
        assert_eq!(
            request_scheme(
                &behind_proxy,
                &headers(&[("x-forwarded-proto", "https")])
            ),
            "https"
        );
        assert_eq!(
            request_scheme(
                &behind_proxy,
                &headers(&[("x-forwarded-proto", "http")])
            ),
            "http"
        );
        assert_eq!(request_scheme(&behind_proxy, &host), "https");
        assert_eq!(
            request_scheme(
                &behind_proxy,
                &headers(&[("x-forwarded-proto", "ftp")])
            ),
            "https"
        );
        // A list of proxies takes the first (client-facing) entry.
        assert_eq!(
            request_scheme(
                &behind_proxy,
                &headers(&[("x-forwarded-proto", "https, http")])
            ),
            "https"
        );

        // Without the flag the same header must not be believed.
        let mut untrusted = terminated.clone();
        untrusted.config = std::sync::Arc::new(crate::config::ServerConfig {
            tls_enabled: false,
            passkey_trust_forwarded_proto: false,
            ..Default::default()
        });
        untrusted.control_tls =
            std::sync::Arc::new(crate::tls::ControlPlaneTls::new(false));
        assert_eq!(
            request_scheme(
                &untrusted,
                &headers(&[("x-forwarded-proto", "https")])
            ),
            "http"
        );
    }

    #[test]
    fn ports_are_stripped_from_the_host_header() {
        assert_eq!(host_without_port("waf.example.com"), "waf.example.com");
        assert_eq!(
            host_without_port("waf.example.com:8443"),
            "waf.example.com"
        );
        assert_eq!(host_without_port("localhost:5173"), "localhost");
        assert_eq!(host_without_port("[::1]:9080"), "::1");
        assert_eq!(host_without_port("[::1]"), "::1");
        // A host that merely contains a colon but no numeric port is kept.
        assert_eq!(host_without_port("example.com:http"), "example.com:http");
    }

    #[test]
    fn aaguid_suffixes_are_dropped_from_labels() {
        let aaguid = "08987058-cadc-4b81-b6e1-30de50dcbe96";
        assert_eq!(
            display_name(&format!("YubiKey-{aaguid}")),
            "YubiKey".to_string()
        );
        assert_eq!(
            display_name(&format!("Passkey-{aaguid}")),
            "Passkey".to_string()
        );
        assert_eq!(display_name(" Touch ID "), "Touch ID");
        assert_eq!(display_name(""), "Passkey");
        // A label that only looks like it ends in a UUID is left alone.
        assert_eq!(
            display_name("laptop-not-a-uuid-but-long"),
            "laptop-not-a-uuid-but-long"
        );
    }

    #[test]
    fn labels_are_validated() {
        assert_eq!(validate_name("  MacBook  ").unwrap(), "MacBook");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LENGTH + 1)).is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LENGTH)).is_ok());
    }

    #[test]
    fn challenge_budget_is_a_fixed_window() {
        let budget = ChallengeBudget::new(2, Duration::from_secs(60));
        assert!(budget.consume().is_ok());
        assert!(budget.consume().is_ok());
        let err = budget.consume().unwrap_err();
        assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);

        // A window that has already elapsed refills the budget.
        let budget = ChallengeBudget::new(1, Duration::from_millis(0));
        assert!(budget.consume().is_ok());
        assert!(budget.consume().is_ok());
    }

    #[test]
    fn ceremony_failures_are_bad_requests() {
        assert_eq!(
            ceremony_error(PasskeyError::InvalidChallenge).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ceremony_error(PasskeyError::InvalidSignature("nope".into()))
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ceremony_error(PasskeyError::OriginMismatch {
                expected: "https://a".into(),
                got: "https://b".into(),
            })
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ceremony_error(PasskeyError::DatabaseError("gone".into())).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn milliseconds_round_trip() {
        let now = Utc::now();
        let millis = now.timestamp_millis();
        let round_tripped = millis_to_datetime(millis);
        assert_eq!(round_tripped.timestamp_millis(), millis);
        // `chrono` keeps sub-millisecond precision, so the only thing the
        // conversion may drop is the fraction below a millisecond.
        let lost = now.signed_duration_since(round_tripped);
        assert!(lost >= chrono::Duration::zero());
        assert!(lost < chrono::Duration::milliseconds(1));

        // An out-of-range instant falls back to "now" instead of panicking.
        let fallback = millis_to_datetime(i64::MAX);
        assert!(
            Utc::now().signed_duration_since(fallback)
                < chrono::Duration::seconds(5)
        );
    }

    #[test]
    fn relying_party_follows_the_request() {
        let state = state_with(crate::config::ServerConfig::default());

        let party = relying_party(
            &state,
            &headers(&[("host", "waf.example.com:8443")]),
        )
        .unwrap();
        assert_eq!(party.rp_id, "waf.example.com");
        assert_eq!(party.origin, "http://waf.example.com:8443");
        assert_eq!(party.state_ttl, STATE_TTL_SECONDS);

        // `localhost` is a valid relying party id, an IP address is not.
        assert!(
            relying_party(&state, &headers(&[("host", "localhost:5173")]))
                .is_ok()
        );
        let err = relying_party(&state, &headers(&[("host", "10.0.0.5:9080")]))
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);

        // Without a Host header there is nothing to derive from.
        assert!(relying_party(&state, &HeaderMap::new()).is_err());
    }

    #[test]
    fn explicit_configuration_wins_over_the_request() {
        let config = crate::config::ServerConfig {
            passkey_rp_id: Some("example.com".to_string()),
            passkey_origin: Some("https://waf.example.com".to_string()),
            ..Default::default()
        };
        let state = state_with(config);

        let party = relying_party(
            &state,
            &headers(&[("host", "internal.svc.cluster.local:9080")]),
        )
        .unwrap();
        assert_eq!(party.rp_id, "example.com");
        assert_eq!(party.origin, "https://waf.example.com");
    }

    #[test]
    fn forwarded_proto_is_only_believed_when_trusted() {
        let mut config = crate::config::ServerConfig::default();
        let request = headers(&[
            ("host", "waf.example.com"),
            ("x-forwarded-proto", "https"),
        ]);

        let state = state_with(config.clone());
        assert_eq!(
            relying_party(&state, &request).unwrap().origin,
            "http://waf.example.com"
        );

        config.passkey_trust_forwarded_proto = true;
        let state = state_with(config);
        assert_eq!(
            relying_party(&state, &request).unwrap().origin,
            "https://waf.example.com"
        );
    }

    #[test]
    fn disabled_passkeys_report_not_implemented() {
        let state = state_with(crate::config::ServerConfig {
            passkey_enabled: false,
            ..Default::default()
        });
        let err =
            relying_party(&state, &headers(&[("host", "waf.example.com")]))
                .unwrap_err();
        assert_eq!(err.status(), StatusCode::NOT_IMPLEMENTED);
    }

    /// A `users` row with the fields the login gate looks at.
    fn account(disabled: bool, role_name: &str) -> user::Model {
        user::Model {
            id: Uuid::new_v4(),
            email: "ops@example.com".into(),
            password_hash: "$2b$10$secret".into(),
            name: Some("Ops".into()),
            role: role_name.into(),
            disabled,
            must_change_password: false,
            token_version: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn a_disabled_account_cannot_finish_a_passkey_login() {
        // The passkey ceremony succeeded, but the administrator has since
        // disabled the account: minting tokens would resurrect the session.
        let err =
            ensure_account_active(&account(true, role::ADMIN)).unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        // Same wording as the password login, so the response does not reveal
        // which factor was used.
        assert!(err.to_string().contains("account is disabled"));
    }

    #[test]
    fn an_active_account_finishes_a_passkey_login() {
        assert!(ensure_account_active(&account(false, role::ADMIN)).is_ok());
        assert!(ensure_account_active(&account(false, role::VIEWER)).is_ok());
        assert!(ensure_account_active(&account(false, role::AUDITOR)).is_ok());
    }

    #[test]
    fn an_unknown_role_cannot_finish_a_passkey_login() {
        // Matches `authenticate_user`/`refresh`: a role no longer in the set
        // must not become a live session.
        let err =
            ensure_account_active(&account(false, "superuser")).unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }
}
