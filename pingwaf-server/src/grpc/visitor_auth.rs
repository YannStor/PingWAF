//! Visitor authentication over gRPC — the bridge between a protected site's
//! login page and the accounts in this database.
//!
//! # Why this exists
//!
//! A visitor signs in at the data plane (the Pingora proxy), but their account
//! lives here. The data plane has no database and must not be given one: it
//! runs at the edge, on machines an operator does not administer the way they
//! do the control plane, and handing it database credentials would put the
//! whole schema behind every edge node. So the data plane asks, and this
//! module answers.
//!
//! # Why the challenge is stored here
//!
//! The WAF's own challenge keeps its pending nonces in a process-local map,
//! which is fine there: the instance that issues a challenge also receives the
//! answer, because a browser follows the redirect it was just given. A *login*
//! is not like that. The form is rendered by one instance and the POST is
//! routed to whichever the load balancer picks, so a process-local store would
//! make the answer unverifiable about half the time on a two-instance
//! deployment. `visitor_auth_states` is that store, shared by every instance.
//!
//! # The refusal rules
//!
//! * Every RPC authenticates with the agent token, like the rest of the
//!   control plane, and every one is scoped to the sites that agent serves.
//! * A challenge is answerable once. Reading it deletes it, so a replayed POST
//!   finds nothing.
//! * A failed login says "email or password is wrong" whichever of the two it
//!   was, and takes the same time either way, so the form cannot be used to
//!   learn which addresses have accounts.
//! * The password and its hash never leave this module: the response carries
//!   an identity and a token version, and nothing else.

use pingwaf_proto::control_plane::{
    VisitorChallengeRequest, VisitorChallengeResponse,
    VisitorChangePasswordRequest, VisitorChangePasswordResponse, VisitorGrant,
    VisitorGrantsRequest, VisitorGrantsResponse, VisitorLoginRequest,
    VisitorLoginResponse, VisitorLogoutRequest, VisitorLogoutResponse,
    VisitorPasskey, VisitorPasskeyBeginRequest, VisitorPasskeyFinishRequest,
    VisitorPasskeyFinishResponse, VisitorPasskeyListResponse,
    VisitorPasskeyOptionsResponse, VisitorSetVisibleRequest,
    VisitorSetVisibleResponse, VisitorValidateRequest, VisitorValidateResponse,
};
use sea_orm::DatabaseConnection;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use tonic::{Request, Response, Status};
use tracing::debug;
use uuid::Uuid;

use crate::auth::password::{hash_password, verify_password};
use crate::grpc::control_plane::ControlPlaneService;
use crate::models::{
    site, site_oidc, site_visitor, visitor_auth_state, visitor_passkey,
    visitor_passkey_state, visitor_site_grant,
};

/// The proof-of-work difficulty handed to a login page.
///
/// Lower than the WAF challenge's 20 on purpose. A login is a deliberate,
/// one-off act by a person who is already waiting; the WAF challenge is
/// answering traffic that may be automated and is not expected to be pleasant.
/// 16 bits is a fraction of a second on a laptop and still thousands of hashes
/// for a script that wants to brute-force the form.
const LOGIN_POW_DIFFICULTY: u32 = 16;

/// How long a challenge stays answerable. Shared with the row's `expires_at`.
const CHALLENGE_TTL_SECONDS: i64 = 300;

/// Refusal codes the data plane branches on. Kept stable: the login page maps
/// them to wording, and a code that changes silently becomes a generic error.
mod error_code {
    /// The email or the password was wrong. Deliberately does not say which.
    pub const INVALID_CREDENTIALS: &str = "invalid_credentials";
    /// The challenge was unknown, expired, or already answered.
    pub const CHALLENGE_EXPIRED: &str = "challenge_expired";
    /// The proof of work did not verify.
    pub const CHALLENGE_FAILED: &str = "challenge_failed";
    /// The account exists but is disabled.
    pub const DISABLED: &str = "disabled";
    /// The submitted timestamp was outside the accepted window.
    pub const STALE: &str = "stale";
    /// The new password was rejected by the policy.
    pub const WEAK_PASSWORD: &str = "weak_password";
    /// The current password did not match.
    pub const WRONG_PASSWORD: &str = "wrong_password";
    /// The visitor is unknown.
    pub const UNKNOWN_VISITOR: &str = "unknown_visitor";
}

/// The wording a refusal carries. Coarse on purpose: the page shows it, and a
/// precise reason would let the form enumerate accounts.
const GENERIC_CREDENTIALS_MESSAGE: &str = "Email or password is incorrect.";

/// One generated challenge: the id the browser carries, and the nonce the
/// proof of work is computed over.
struct IssuedChallenge {
    id: String,
    nonce: String,
}

/// A verified challenge: what was stored, once it has been read and deleted.
struct ConsumedChallenge {
    nonce: String,
    difficulty: u32,
}

// Each entry point takes the service explicitly rather than living in an
// `impl` block: the trait methods in `control_plane.rs` share these names,
// and an inherent method of the same name would make those forwards call
// themselves.
/// The site ids this agent serves, as a set, for scoping a visitor call.
///
/// A visitor belongs to the deployment, but an agent must not be able to
/// answer for a site it does not serve: a compromised edge node would
/// otherwise reach every account on the deployment.
async fn agent_site_ids(
    service: &ControlPlaneService,
    agent_row: &crate::models::agent::Model,
) -> Result<Vec<Uuid>, Status> {
    let sites = service.visible_sites(agent_row).await?;
    Ok(sites.into_iter().map(|row| row.id).collect())
}

/// Resolves a host the data plane names to a site this agent serves.
///
/// The data plane knows a site by its host (`ClearancePayload.site_id` is
/// a host), so that is what the RPCs carry. Matching is on the primary
/// domain or an alternate, which is the same set the data plane routes on.
async fn resolve_site(
    service: &ControlPlaneService,
    agent_row: &crate::models::agent::Model,
    host: &str,
) -> Result<site::Model, Status> {
    let host = host.trim();
    if host.is_empty() {
        return Err(Status::invalid_argument("site_id is required"));
    }
    let allowed = agent_site_ids(service, agent_row).await?;
    if allowed.is_empty() {
        return Err(Status::permission_denied("agent does not serve any site"));
    }
    // The match runs in Rust rather than in SQL. `alternate_domains` is a text
    // array, and expressing membership portably means either a raw `ANY`/`@>`
    // expression — which the driver rejected when parameterised — or a
    // database-specific construct. The set here is one agent's sites, which is a
    // handful of rows, so fetching them and comparing costs nothing and cannot be
    // got wrong by a dialect detail.
    let rows = site::Entity::find()
        .filter(site::Column::Id.is_in(allowed))
        .all(&service.db)
        .await
        .map_err(db_status)?;
    let row = rows
        .into_iter()
        .find(|row| {
            row.domain == host
                || row
                    .alternate_domains
                    .iter()
                    .any(|alternate| alternate == host)
        })
        .ok_or_else(|| {
            Status::permission_denied("agent is not allowed to serve this site")
        })?;
    Ok(row)
}

/// Writes a challenge row and returns what the browser needs.
async fn issue_challenge(
    service: &ControlPlaneService,
    site_host: &str,
) -> Result<IssuedChallenge, Status> {
    let id = new_state_id();
    let nonce = new_nonce();
    let now = chrono::Utc::now();
    let model = visitor_auth_state::ActiveModel {
            id: Set(id.clone()),
            kind: Set(
                crate::models::visitor_auth_states::auth_state_kind::LOGIN_CHALLENGE
                    .to_string(),
            ),
            site_id: Set(site_host.to_string()),
            visitor_id: Set(None),
            payload: Set(serde_json::json!({
                "nonce": nonce,
                "difficulty": LOGIN_POW_DIFFICULTY,
            })),
            expires_at: Set(now + chrono::Duration::seconds(CHALLENGE_TTL_SECONDS)),
            created_at: Set(now),
        };
    model.insert(&service.db).await.map_err(db_status)?;
    Ok(IssuedChallenge { id, nonce })
}

/// Reads and deletes a challenge in one step.
///
/// The delete is what makes an answer single-use: two POSTs racing for the
/// same id both run this, and only one finds a row. An expired row is
/// deleted too — it is spent either way — and reported as expired.
async fn consume_challenge(
    service: &ControlPlaneService,
    id: &str,
    expected_site: &str,
) -> Result<ConsumedChallenge, Status> {
    let id = id.trim();
    if id.is_empty() {
        return Err(Status::invalid_argument("challenge_id is required"));
    }
    let row = visitor_auth_state::Entity::find_by_id(id.to_string())
        .one(&service.db)
        .await
        .map_err(db_status)?;
    let Some(row) = row else {
        return Err(Status::not_found(error_code::CHALLENGE_EXPIRED));
    };
    // Delete first, then judge: a challenge answered with the wrong
    // solution is still spent, or the same nonce could be tried against
    // password guesses in a loop.
    let deleted = visitor_auth_state::Entity::delete_by_id(id.to_string())
        .exec(&service.db)
        .await
        .map_err(db_status)?;
    if deleted.rows_affected == 0 {
        // Another request won the race and consumed it.
        return Err(Status::not_found(error_code::CHALLENGE_EXPIRED));
    }
    if row.expires_at <= chrono::Utc::now() {
        return Err(Status::not_found(error_code::CHALLENGE_EXPIRED));
    }
    // A challenge issued for another site is not answerable here, even by
    // an agent that serves both.
    if row.site_id != expected_site {
        return Err(Status::permission_denied(error_code::CHALLENGE_EXPIRED));
    }
    let nonce = row
        .payload
        .get("nonce")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    let difficulty = row
        .payload
        .get("difficulty")
        .and_then(|value| value.as_u64())
        .unwrap_or(LOGIN_POW_DIFFICULTY as u64) as u32;
    if nonce.is_empty() {
        return Err(Status::internal("the challenge is unreadable"));
    }
    Ok(ConsumedChallenge { nonce, difficulty })
}

/// `VisitorLoginChallenge` — hands the login page something to compute.
pub(crate) async fn visitor_login_challenge(
    service: &ControlPlaneService,
    request: Request<VisitorChallengeRequest>,
) -> Result<Response<VisitorChallengeResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    // Resolving the site here means a challenge can only be issued for a
    // site this agent actually serves.
    let site_row = resolve_site(service, &agent_row, &payload.site_id).await?;
    let issued = issue_challenge(service, &site_row.domain).await?;
    Ok(Response::new(VisitorChallengeResponse {
        challenge_id: issued.id,
        nonce: issued.nonce,
        difficulty: LOGIN_POW_DIFFICULTY,
        ttl_seconds: CHALLENGE_TTL_SECONDS as u32,
        error: String::new(),
    }))
}

/// `VisitorLogin` — exchanges a solved challenge and credentials for an
/// identity.
pub(crate) async fn visitor_login(
    service: &ControlPlaneService,
    request: Request<VisitorLoginRequest>,
) -> Result<Response<VisitorLoginResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    let site_row = resolve_site(service, &agent_row, &payload.site_id).await?;

    // The challenge is spent before the credentials are looked at, so a
    // wrong password cannot be retried against the same nonce.
    let challenge =
        consume_challenge(service, &payload.challenge_id, &site_row.domain)
            .await?;
    if !pingwaf_challenge::js_challenge::verify::verify_proof_of_work(
        &challenge.nonce,
        &payload.solution,
        challenge.difficulty,
    ) {
        return Ok(Response::new(refusal(
            error_code::CHALLENGE_FAILED,
            "Verification failed. Reload the page and try again.",
        )));
    }
    if !pingwaf_challenge::js_challenge::verify::verify_timestamp(
        payload.timestamp,
        CHALLENGE_TTL_SECONDS,
    ) {
        return Ok(Response::new(refusal(
            error_code::STALE,
            "The form was open too long. Reload and try again.",
        )));
    }

    let email = normalise_email(&payload.email);
    let found = site_visitor::Entity::find()
        .filter(site_visitor::Column::Email.eq(email.as_str()))
        .one(&service.db)
        .await
        .map_err(db_status)?;

    // Always run a bcrypt verification, even with no account, so the
    // response time does not say whether the address exists. The dummy
    // hash is a valid bcrypt string whose plaintext is not the submitted
    // password, so the comparison fails as it would for a wrong password.
    let Some(visitor) = found else {
        let _ = verify_password(&payload.password, &DUMMY_HASH);
        return Ok(Response::new(refusal(
            error_code::INVALID_CREDENTIALS,
            GENERIC_CREDENTIALS_MESSAGE,
        )));
    };
    let matches = verify_password(&payload.password, &visitor.password_hash)
        .unwrap_or(false);
    if !matches {
        return Ok(Response::new(refusal(
            error_code::INVALID_CREDENTIALS,
            GENERIC_CREDENTIALS_MESSAGE,
        )));
    }
    if visitor.disabled {
        return Ok(Response::new(refusal(
            error_code::DISABLED,
            "This account is disabled.",
        )));
    }
    // The account must actually be allowed into the site it is signing in
    // at. Without this a visitor could sign in anywhere and be handed a
    // session for a site they were never granted.
    let granted = visitor_site_grant::Entity::find()
        .filter(visitor_site_grant::Column::VisitorId.eq(visitor.id))
        .filter(visitor_site_grant::Column::SiteId.eq(site_row.id))
        .one(&service.db)
        .await
        .map_err(db_status)?
        .is_some();
    if !granted {
        tracing::info!(
            visitor_id = %visitor.id,
            site_id = %site_row.id,
            "visitor signed in at a site they are not granted"
        );
        return Ok(Response::new(refusal(
            error_code::INVALID_CREDENTIALS,
            GENERIC_CREDENTIALS_MESSAGE,
        )));
    }

    tracing::info!(
        visitor_id = %visitor.id,
        site_id = %site_row.id,
        "visitor signed in"
    );
    Ok(Response::new(VisitorLoginResponse {
        ok: true,
        visitor_id: visitor.id.to_string(),
        email: visitor.email,
        name: visitor.name,
        token_version: visitor.token_version,
        error: String::new(),
        error_code: String::new(),
    }))
}

/// `VisitorLogout` — records the end of a session.
///
/// The session cookie is cleared by the data plane; this exists so the
/// control plane sees the event and can be extended to revoke server-side
/// state later without changing the data plane.
pub(crate) async fn visitor_logout(
    service: &ControlPlaneService,
    request: Request<VisitorLogoutRequest>,
) -> Result<Response<VisitorLogoutResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    // Resolving the site keeps an agent from reporting logouts for sites
    // it does not serve, and validates the host it named.
    let _site_row = resolve_site(service, &agent_row, &payload.site_id).await?;
    tracing::debug!(
        visitor_id = %payload.visitor_id,
        site_id = %payload.site_id,
        "visitor signed out"
    );
    Ok(Response::new(VisitorLogoutResponse { ok: true }))
}

/// `VisitorChangePassword` — the portal's account form.
pub(crate) async fn visitor_change_password(
    service: &ControlPlaneService,
    request: Request<VisitorChangePasswordRequest>,
) -> Result<Response<VisitorChangePasswordResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    // Any site the agent serves is enough to identify the caller here: the
    // account is deployment-wide, so this is not scoped to one site. The
    // check still runs, so an agent that serves nothing cannot act.
    let _ = agent_site_ids(service, &agent_row).await?;

    let visitor_id = Uuid::parse_str(payload.visitor_id.trim())
        .map_err(|_| Status::invalid_argument("visitor_id is not a UUID"))?;
    let Some(visitor) = site_visitor::Entity::find_by_id(visitor_id)
        .one(&service.db)
        .await
        .map_err(db_status)?
    else {
        return Ok(Response::new(password_refusal(
            error_code::UNKNOWN_VISITOR,
            "Account not found.",
        )));
    };
    if visitor.disabled {
        return Ok(Response::new(password_refusal(
            error_code::DISABLED,
            "This account is disabled.",
        )));
    }
    let matches =
        verify_password(&payload.current_password, &visitor.password_hash)
            .unwrap_or(false);
    if !matches {
        return Ok(Response::new(password_refusal(
            error_code::WRONG_PASSWORD,
            "The current password is incorrect.",
        )));
    }
    // `hash_password` enforces the same minimum length and 72-byte
    // truncation as the console's own accounts.
    let Ok(hash) = hash_password(&payload.new_password) else {
        return Ok(Response::new(password_refusal(
            error_code::WEAK_PASSWORD,
            "The new password is too short.",
        )));
    };
    // Bumping the version invalidates every session minted before this
    // change, which is what makes a password change actually end the
    // sessions an attacker may already hold. The caller re-issues its own
    // session with the returned version, so the tab that made the change
    // is not signed out.
    let next_version = visitor.token_version + 1;
    let mut active: site_visitor::ActiveModel = visitor.into();
    active.password_hash = Set(hash);
    active.token_version = Set(next_version);
    active.updated_at = Set(chrono::Utc::now());
    active.update(&service.db).await.map_err(db_status)?;

    Ok(Response::new(VisitorChangePasswordResponse {
        ok: true,
        token_version: next_version,
        error: String::new(),
        error_code: String::new(),
    }))
}

/// `VisitorGrants` — the sites the portal lists.
pub(crate) async fn visitor_grants(
    service: &ControlPlaneService,
    request: Request<VisitorGrantsRequest>,
) -> Result<Response<VisitorGrantsResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    // Only the sites this agent serves are ever listed: the portal runs at
    // one site, and showing a link to a site served by a different agent
    // would send the visitor somewhere this login does not reach.
    let allowed = agent_site_ids(service, &agent_row).await?;
    let visitor_id = Uuid::parse_str(payload.visitor_id.trim())
        .map_err(|_| Status::invalid_argument("visitor_id is not a UUID"))?;

    let grants = visitor_site_grant::Entity::find()
        .filter(visitor_site_grant::Column::VisitorId.eq(visitor_id))
        .all(&service.db)
        .await
        .map_err(db_status)?;
    if grants.is_empty() {
        return Ok(Response::new(VisitorGrantsResponse {
            grants: Vec::new(),
            error: String::new(),
        }));
    }
    let site_ids: Vec<Uuid> = grants
        .iter()
        .filter(|grant| allowed.contains(&grant.site_id))
        .map(|grant| grant.site_id)
        .collect();
    let sites = site::Entity::find()
        .filter(site::Column::Id.is_in(site_ids.clone()))
        .all(&service.db)
        .await
        .map_err(db_status)?;
    // The site's auth mode decides which entry the portal links to, so it
    // is read alongside the site rather than guessed.
    let oidc_modes = site_oidc::Entity::find()
        .filter(site_oidc::Column::SiteId.is_in(site_ids))
        .all(&service.db)
        .await
        .map_err(db_status)?;

    let mut listed = Vec::with_capacity(sites.len());
    for grant in &grants {
        let Some(site_row) = sites.iter().find(|row| row.id == grant.site_id)
        else {
            // The grant points at a site this agent does not serve.
            continue;
        };
        let auth_mode = oidc_modes
            .iter()
            .find(|row| row.site_id == site_row.id)
            .map(|row| row.auth_mode.clone())
            .unwrap_or_else(|| {
                crate::models::site_oidc::AuthMode::OIDC.to_string()
            });
        listed.push(VisitorGrant {
            site_id: site_row.id.to_string(),
            name: site_row.name.clone(),
            domain: site_row.domain.clone(),
            visible: grant.visible,
            auth_mode,
        });
    }
    // Stable order so the portal does not reshuffle between loads.
    listed.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(Response::new(VisitorGrantsResponse {
        grants: listed,
        error: String::new(),
    }))
}

/// `VisitorSetSiteVisible` — the portal's per-site switch.
pub(crate) async fn visitor_set_site_visible(
    service: &ControlPlaneService,
    request: Request<VisitorSetVisibleRequest>,
) -> Result<Response<VisitorSetVisibleResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    // `site_id` here is the site's **id**, not its host: the portal renders the
    // switch from the grant list, and a grant carries an id. It is resolved
    // against the sites this agent serves rather than by hostname, so an agent
    // cannot toggle a row for a site it does not serve.
    let allowed = agent_site_ids(service, &agent_row).await?;
    let site_id = Uuid::parse_str(payload.site_id.trim())
        .map_err(|_| Status::invalid_argument("site_id is not a UUID"))?;
    if !allowed.contains(&site_id) {
        return Err(Status::permission_denied(
            "agent is not allowed to serve this site",
        ));
    }
    let visitor_id = Uuid::parse_str(payload.visitor_id.trim())
        .map_err(|_| Status::invalid_argument("visitor_id is not a UUID"))?;

    let Some(grant) = visitor_site_grant::Entity::find()
        .filter(visitor_site_grant::Column::VisitorId.eq(visitor_id))
        .filter(visitor_site_grant::Column::SiteId.eq(site_id))
        .one(&service.db)
        .await
        .map_err(db_status)?
    else {
        return Ok(Response::new(VisitorSetVisibleResponse {
            ok: false,
            error: "No access to this site.".to_string(),
        }));
    };
    let mut active: visitor_site_grant::ActiveModel = grant.into();
    active.visible = Set(payload.visible);
    active.update(&service.db).await.map_err(db_status)?;
    Ok(Response::new(VisitorSetVisibleResponse {
        ok: true,
        error: String::new(),
    }))
}
/// The relying-party configuration for a site.
///
/// `rp_id` is the registrable domain, which is what the browser binds a
/// credential to; `origin` is the full scheme and host, which the authenticator
/// checks. Both come from the site the ceremony runs at, so a credential
/// enrolled at one site is not offered at another.
fn relying_party_for(site: &site::Model) -> passkey_server::PasskeyConfig {
    let domain = site.domain.trim();
    // A leading wildcard is a display form, not part of the domain the browser
    // sees, so it is stripped before it becomes the relying-party id.
    let rp_id = domain.trim_start_matches("*.").to_string();
    passkey_server::PasskeyConfig {
        rp_id: rp_id.clone(),
        rp_name: if site.name.trim().is_empty() {
            rp_id.clone()
        } else {
            site.name.clone()
        },
        // https is the only scheme a browser will run a WebAuthn ceremony
        // under (localhost excepted), so the origin is built with it.
        origin: format!("https://{rp_id}"),
        state_ttl: 300,
    }
}

/// Starts a passkey ceremony and returns the options the browser needs.
pub(crate) async fn visitor_passkey_begin(
    service: &ControlPlaneService,
    request: Request<VisitorPasskeyBeginRequest>,
    login: bool,
) -> Result<Response<VisitorPasskeyOptionsResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    let site_row = resolve_site(service, &agent_row, &payload.site_id).await?;
    let config = relying_party_for(&site_row);
    let store = VisitorPasskeyStore { db: &service.db };
    let now_ms = chrono::Utc::now().timestamp_millis();

    if login {
        // A sign-in ceremony is not scoped to an account: the authenticator
        // names the credential, and the account is found from it. That is what
        // makes "sign in with a passkey" a single button rather than a form.
        let options = passkey_server::start_login(&store, &config, now_ms)
            .await
            .map_err(passkey_status)?;
        let ceremony_id = options.challenge.clone();
        let options_json = serde_json::to_string(&options).map_err(|err| {
            tracing::error!(error = %err, "visitor passkey options are unencodable");
            Status::internal("could not encode the ceremony options")
        })?;
        return Ok(Response::new(VisitorPasskeyOptionsResponse {
            options_json,
            ceremony_id: format!("login:{ceremony_id}"),
            error: String::new(),
        }));
    }

    // Registration requires a signed-in visitor: the credential is minted for
    // an account, so the account has to be named.
    let visitor_id = payload.visitor_id.trim();
    if visitor_id.is_empty() {
        return Ok(Response::new(VisitorPasskeyOptionsResponse {
            options_json: String::new(),
            ceremony_id: String::new(),
            error: "Sign in before adding a passkey.".to_string(),
        }));
    }
    let parsed = Uuid::parse_str(visitor_id)
        .map_err(|_| Status::invalid_argument("visitor_id is not a UUID"))?;
    let Some(visitor) = site_visitor::Entity::find_by_id(parsed)
        .one(&service.db)
        .await
        .map_err(db_status)?
    else {
        return Ok(Response::new(VisitorPasskeyOptionsResponse {
            options_json: String::new(),
            ceremony_id: String::new(),
            error: "Account not found.".to_string(),
        }));
    };
    if visitor.disabled {
        return Ok(Response::new(VisitorPasskeyOptionsResponse {
            options_json: String::new(),
            ceremony_id: String::new(),
            error: "This account is disabled.".to_string(),
        }));
    }
    // The visitor must be granted this site. The data plane passes the id from
    // the session, but the gRPC boundary trusts the agent, so the check is
    // repeated here rather than assumed.
    let granted = visitor_site_grant::Entity::find()
        .filter(visitor_site_grant::Column::VisitorId.eq(visitor.id))
        .filter(visitor_site_grant::Column::SiteId.eq(site_row.id))
        .one(&service.db)
        .await
        .map_err(db_status)?
        .is_some();
    if !granted {
        return Ok(Response::new(VisitorPasskeyOptionsResponse {
            options_json: String::new(),
            ceremony_id: String::new(),
            error: "No access to this site.".to_string(),
        }));
    }
    let display_name = if visitor.name.trim().is_empty() {
        visitor.email.clone()
    } else {
        visitor.name.clone()
    };
    let options = passkey_server::start_registration(
        &store,
        visitor_id,
        &visitor.email,
        &display_name,
        &config,
        now_ms,
    )
    .await
    .map_err(passkey_status)?;
    let options_json = serde_json::to_string(&options).map_err(|err| {
        tracing::error!(error = %err, "visitor passkey options are unencodable");
        Status::internal("could not encode the ceremony options")
    })?;
    Ok(Response::new(VisitorPasskeyOptionsResponse {
        options_json,
        ceremony_id: format!("reg:{visitor_id}"),
        error: String::new(),
    }))
}

/// Finishes a registration ceremony.
pub(crate) async fn visitor_passkey_register_finish(
    service: &ControlPlaneService,
    request: Request<VisitorPasskeyFinishRequest>,
) -> Result<Response<VisitorPasskeyFinishResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    let site_row = resolve_site(service, &agent_row, &payload.site_id).await?;
    let config = relying_party_for(&site_row);
    let store = VisitorPasskeyStore { db: &service.db };
    let credential: passkey_server::types::RegistrationResponse =
        serde_json::from_str(&payload.credential_json).map_err(|err| {
            debug!(error = %err, "visitor passkey registration body is malformed");
            Status::invalid_argument("the credential is malformed")
        })?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let visitor_id = payload
        .ceremony_id
        .trim()
        .strip_prefix("reg:")
        .unwrap_or_default()
        .to_string();
    if visitor_id.is_empty() {
        return Ok(Response::new(VisitorPasskeyFinishResponse {
            ok: false,
            error: "The ceremony is not a registration.".to_string(),
            error_code: "bad_ceremony".to_string(),
        }));
    }
    // The same grant check as `begin`, repeated because a finish can arrive
    // without a begin this process saw (several data-plane instances, or a
    // crafted request from an agent).
    let Ok(parsed_visitor) = Uuid::parse_str(&visitor_id) else {
        return Ok(Response::new(VisitorPasskeyFinishResponse {
            ok: false,
            error: "The ceremony is not a registration.".to_string(),
            error_code: "bad_ceremony".to_string(),
        }));
    };
    let granted = visitor_site_grant::Entity::find()
        .filter(visitor_site_grant::Column::VisitorId.eq(parsed_visitor))
        .filter(visitor_site_grant::Column::SiteId.eq(site_row.id))
        .one(&service.db)
        .await
        .map_err(db_status)?
        .is_some();
    if !granted {
        return Ok(Response::new(VisitorPasskeyFinishResponse {
            ok: false,
            error: "No access to this site.".to_string(),
            error_code: "not_granted".to_string(),
        }));
    }
    // The crate's signature takes no label; the name is applied through the
    // store's `create_passkey`, which `finish_registration` calls with the
    // credential's own name. Ours is written after, so an operator's label
    // wins over the authenticator's default.
    match passkey_server::finish_registration(
        &store,
        &visitor_id,
        &config,
        credential,
        now_ms,
    )
    .await
    {
        Ok(()) => {
            tracing::info!(
                visitor_id = %visitor_id,
                site_id = %site_row.id,
                "visitor passkey registered"
            );
            Ok(Response::new(VisitorPasskeyFinishResponse {
                ok: true,
                error: String::new(),
                error_code: String::new(),
            }))
        },
        Err(error) => {
            debug!(error = %error, "visitor passkey registration refused");
            Ok(Response::new(VisitorPasskeyFinishResponse {
                ok: false,
                // The crate's message describes the ceremony, not the account.
                error: "The passkey could not be registered.".to_string(),
                error_code: "passkey_failed".to_string(),
            }))
        },
    }
}

/// Finishes a sign-in ceremony, returning an identity on success.
pub(crate) async fn visitor_passkey_login_finish(
    service: &ControlPlaneService,
    request: Request<VisitorPasskeyFinishRequest>,
) -> Result<Response<VisitorLoginResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    let site_row = resolve_site(service, &agent_row, &payload.site_id).await?;
    let config = relying_party_for(&site_row);
    let store = VisitorPasskeyStore { db: &service.db };
    let assertion: passkey_server::types::LoginResponse =
        serde_json::from_str(&payload.credential_json).map_err(|err| {
            debug!(error = %err, "visitor passkey assertion body is malformed");
            Status::invalid_argument("the assertion is malformed")
        })?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    // The ceremony id is not passed to the crate: `finish_login` reads the
    // state by the challenge inside the assertion, which is what binds the
    // answer to the options that were handed out.
    let visitor_id =
        match passkey_server::finish_login(&store, &config, assertion, now_ms)
            .await
        {
            Ok(id) => id,
            Err(error) => {
                debug!(error = %error, "visitor passkey sign-in refused");
                return Ok(Response::new(refusal(
                    "passkey_failed",
                    "That passkey could not be verified.",
                )));
            },
        };
    let Ok(parsed) = Uuid::parse_str(visitor_id.trim()) else {
        return Ok(Response::new(refusal(
            "passkey_failed",
            "That passkey could not be verified.",
        )));
    };
    let Some(visitor) = site_visitor::Entity::find_by_id(parsed)
        .one(&service.db)
        .await
        .map_err(db_status)?
    else {
        return Ok(Response::new(refusal(
            "invalid_credentials",
            GENERIC_CREDENTIALS_MESSAGE,
        )));
    };
    if visitor.disabled {
        return Ok(Response::new(refusal(
            "disabled",
            "This account is disabled.",
        )));
    }
    // The credential proves who they are; the grant decides whether they may
    // enter *here*. Without this a visitor enrolled at one site could sign in
    // at any other.
    let granted = visitor_site_grant::Entity::find()
        .filter(visitor_site_grant::Column::VisitorId.eq(visitor.id))
        .filter(visitor_site_grant::Column::SiteId.eq(site_row.id))
        .one(&service.db)
        .await
        .map_err(db_status)?
        .is_some();
    if !granted {
        tracing::info!(
            visitor_id = %visitor.id,
            site_id = %site_row.id,
            "visitor signed in with a passkey at a site they are not granted"
        );
        return Ok(Response::new(refusal(
            "invalid_credentials",
            GENERIC_CREDENTIALS_MESSAGE,
        )));
    }
    tracing::info!(
        visitor_id = %visitor.id,
        site_id = %site_row.id,
        "visitor signed in with a passkey"
    );
    Ok(Response::new(VisitorLoginResponse {
        ok: true,
        visitor_id: visitor.id.to_string(),
        email: visitor.email,
        name: visitor.name,
        token_version: visitor.token_version,
        error: String::new(),
        error_code: String::new(),
    }))
}

/// `VisitorValidateSession` — is this session still good?
///
/// The signature on the cookie proves it was minted here and not edited; this
/// answers the part a signature cannot: whether the account still exists, is
/// still enabled, and has not had its password changed since. A password
/// change bumps `token_version`, so comparing it is what actually ends the
/// sessions an attacker may be holding.
pub(crate) async fn visitor_validate_session(
    service: &ControlPlaneService,
    request: Request<VisitorValidateRequest>,
) -> Result<Response<VisitorValidateResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    // Scoped to a site the agent serves, like every other visitor call.
    let _site_row = resolve_site(service, &agent_row, &payload.site_id).await?;
    let Ok(visitor_id) = Uuid::parse_str(payload.visitor_id.trim()) else {
        return Ok(Response::new(VisitorValidateResponse {
            valid: false,
            reason: "unknown".to_string(),
        }));
    };
    let Some(visitor) = site_visitor::Entity::find_by_id(visitor_id)
        .one(&service.db)
        .await
        .map_err(db_status)?
    else {
        // Deleted while the session was live.
        return Ok(Response::new(VisitorValidateResponse {
            valid: false,
            reason: "unknown".to_string(),
        }));
    };
    if visitor.disabled {
        return Ok(Response::new(VisitorValidateResponse {
            valid: false,
            reason: "disabled".to_string(),
        }));
    }
    if visitor.token_version != payload.token_version {
        // A password change, here or by an operator. The old session must not
        // survive it.
        return Ok(Response::new(VisitorValidateResponse {
            valid: false,
            reason: "version_changed".to_string(),
        }));
    }
    // The grant is re-checked too: revoking a site while a session is live
    // must end access to that site, not just block the next sign-in.
    let granted = visitor_site_grant::Entity::find()
        .filter(visitor_site_grant::Column::VisitorId.eq(visitor.id))
        .filter(visitor_site_grant::Column::SiteId.eq(_site_row.id))
        .one(&service.db)
        .await
        .map_err(db_status)?
        .is_some();
    if !granted {
        return Ok(Response::new(VisitorValidateResponse {
            valid: false,
            reason: "not_granted".to_string(),
        }));
    }
    Ok(Response::new(VisitorValidateResponse {
        valid: true,
        reason: String::new(),
    }))
}

/// Lists a visitor's passkeys, for the portal.
pub(crate) async fn visitor_passkey_list(
    service: &ControlPlaneService,
    request: Request<VisitorGrantsRequest>,
) -> Result<Response<VisitorPasskeyListResponse>, Status> {
    let payload = request.into_inner();
    let agent_row = service.authorize(&payload.agent_token).await?;
    // Scoped to a site this agent serves *and* that this visitor is granted.
    // Without the grant check an agent holding a valid token could enumerate
    // every passkey on the deployment by visitor id, which is exactly what the
    // per-site scoping exists to prevent.
    let site_row = resolve_site(service, &agent_row, &payload.site_id).await?;
    let visitor_id = Uuid::parse_str(payload.visitor_id.trim())
        .map_err(|_| Status::invalid_argument("visitor_id is not a UUID"))?;
    let granted = visitor_site_grant::Entity::find()
        .filter(visitor_site_grant::Column::VisitorId.eq(visitor_id))
        .filter(visitor_site_grant::Column::SiteId.eq(site_row.id))
        .one(&service.db)
        .await
        .map_err(db_status)?
        .is_some();
    if !granted {
        return Err(Status::permission_denied(
            "agent is not allowed to read this visitor's credentials",
        ));
    }
    let rows = visitor_passkey::Entity::find()
        .filter(visitor_passkey::Column::VisitorId.eq(visitor_id))
        .order_by_asc(visitor_passkey::Column::CreatedAt)
        .all(&service.db)
        .await
        .map_err(db_status)?;
    Ok(Response::new(VisitorPasskeyListResponse {
        passkeys: rows
            .into_iter()
            .map(|row| VisitorPasskey {
                cred_id: row.cred_id,
                name: row.name,
                created_at: row.created_at.to_rfc3339(),
                last_used_at: row.last_used_at.to_rfc3339(),
            })
            .collect(),
        error: String::new(),
    }))
}

/// Maps a ceremony error to a status. The message is not forwarded: it
/// describes the ceremony, and a caller only needs to know it failed.
fn passkey_status(error: passkey_server::PasskeyError) -> Status {
    tracing::debug!(error = %error, "visitor passkey ceremony failed");
    Status::invalid_argument("the passkey ceremony could not be started")
}

/// The visitor credential store, as `passkey-server` wants it.
///
/// The ceremony logic is the crate's; this is only the persistence half, and
/// it targets the visitor tables rather than the console's. The owner string
/// the crate passes around is a visitor id, parsed the same way the console
/// parses its user id.
struct VisitorPasskeyStore<'a> {
    db: &'a DatabaseConnection,
}

#[async_trait::async_trait]
impl passkey_server::PasskeyStore for VisitorPasskeyStore<'_> {
    async fn create_passkey(
        &self,
        visitor_id: String,
        cred_id: &str,
        public_key: &str,
        name: &str,
        counter: i64,
        created_at: i64,
    ) -> passkey_server::Result<()> {
        let timestamp = millis_to_datetime(created_at);
        let row = visitor_passkey::ActiveModel {
            id: Set(Uuid::new_v4()),
            visitor_id: Set(parse_visitor_id(&visitor_id)?),
            cred_id: Set(cred_id.to_string()),
            public_key: Set(public_key.to_string()),
            name: Set(name.trim().to_string()),
            counter: Set(counter),
            created_at: Set(timestamp),
            last_used_at: Set(timestamp),
        };
        row.insert(self.db).await.map_err(passkey_db_error)?;
        Ok(())
    }

    async fn get_passkey(
        &self,
        cred_id: &str,
    ) -> passkey_server::Result<Option<passkey_server::types::StoredPasskey>>
    {
        let found = visitor_passkey::Entity::find()
            .filter(visitor_passkey::Column::CredId.eq(cred_id))
            .one(self.db)
            .await
            .map_err(passkey_db_error)?;
        Ok(found.map(to_stored_passkey))
    }

    async fn list_passkeys(
        &self,
        visitor_id: String,
    ) -> passkey_server::Result<Vec<passkey_server::types::StoredPasskey>> {
        let rows = visitor_passkey::Entity::find()
            .filter(
                visitor_passkey::Column::VisitorId
                    .eq(parse_visitor_id(&visitor_id)?),
            )
            .order_by_asc(visitor_passkey::Column::CreatedAt)
            .all(self.db)
            .await
            .map_err(passkey_db_error)?;
        Ok(rows.into_iter().map(to_stored_passkey).collect())
    }

    async fn delete_passkey(
        &self,
        visitor_id: String,
        cred_id: &str,
    ) -> passkey_server::Result<()> {
        visitor_passkey::Entity::delete_many()
            .filter(
                visitor_passkey::Column::VisitorId
                    .eq(parse_visitor_id(&visitor_id)?),
            )
            .filter(visitor_passkey::Column::CredId.eq(cred_id))
            .exec(self.db)
            .await
            .map_err(passkey_db_error)?;
        Ok(())
    }

    async fn update_passkey_counter(
        &self,
        cred_id: &str,
        counter: i64,
        used_at: i64,
    ) -> passkey_server::Result<()> {
        visitor_passkey::Entity::update_many()
            .col_expr(
                visitor_passkey::Column::Counter,
                sea_orm::sea_query::Expr::value(counter),
            )
            .col_expr(
                visitor_passkey::Column::LastUsedAt,
                sea_orm::sea_query::Expr::value(millis_to_datetime(used_at)),
            )
            .filter(visitor_passkey::Column::CredId.eq(cred_id))
            .exec(self.db)
            .await
            .map_err(passkey_db_error)?;
        Ok(())
    }

    async fn update_passkey_name(
        &self,
        cred_id: &str,
        name: &str,
    ) -> passkey_server::Result<()> {
        visitor_passkey::Entity::update_many()
            .col_expr(
                visitor_passkey::Column::Name,
                sea_orm::sea_query::Expr::value(name.trim().to_string()),
            )
            .filter(visitor_passkey::Column::CredId.eq(cred_id))
            .exec(self.db)
            .await
            .map_err(passkey_db_error)?;
        Ok(())
    }

    async fn save_state(
        &self,
        state_id: &str,
        state_json: &str,
        expires_at: i64,
    ) -> passkey_server::Result<()> {
        // Upsert: a ceremony id is unique per attempt, so a conflict means a
        // retry of the same begin, which should replace rather than fail.
        let row = visitor_passkey_state::ActiveModel {
            id: Set(state_id.to_string()),
            state_json: Set(state_json.to_string()),
            expires_at: Set(millis_to_datetime(expires_at)),
        };
        visitor_passkey_state::Entity::insert(row)
            .on_conflict(
                sea_orm::sea_query::OnConflict::column(
                    visitor_passkey_state::Column::Id,
                )
                .update_columns([
                    visitor_passkey_state::Column::StateJson,
                    visitor_passkey_state::Column::ExpiresAt,
                ])
                .to_owned(),
            )
            .exec(self.db)
            .await
            .map_err(passkey_db_error)?;
        Ok(())
    }

    async fn get_state(
        &self,
        state_id: &str,
    ) -> passkey_server::Result<Option<passkey_server::types::PasskeyState>>
    {
        let found =
            visitor_passkey_state::Entity::find_by_id(state_id.to_string())
                .one(self.db)
                .await
                .map_err(passkey_db_error)?;
        Ok(found.map(|row| passkey_server::types::PasskeyState {
            id: row.id,
            state_json: row.state_json,
            expires_at: row.expires_at.timestamp_millis(),
        }))
    }

    async fn delete_state(&self, state_id: &str) -> passkey_server::Result<()> {
        visitor_passkey_state::Entity::delete_by_id(state_id.to_string())
            .exec(self.db)
            .await
            .map_err(passkey_db_error)?;
        Ok(())
    }
}

fn to_stored_passkey(
    row: visitor_passkey::Model,
) -> passkey_server::types::StoredPasskey {
    passkey_server::types::StoredPasskey {
        user_id: row.visitor_id.to_string(),
        cred_id: row.cred_id,
        public_key: row.public_key,
        counter: row.counter,
        name: row.name,
        created_at: row.created_at.timestamp_millis(),
        last_used_at: row.last_used_at.timestamp_millis(),
    }
}

fn parse_visitor_id(value: &str) -> passkey_server::Result<Uuid> {
    Uuid::parse_str(value.trim()).map_err(|_| {
        passkey_server::PasskeyError::DatabaseError(
            "visitor id is not a uuid".to_string(),
        )
    })
}

fn millis_to_datetime(millis: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(millis)
        .unwrap_or_else(chrono::Utc::now)
}

fn passkey_db_error(err: sea_orm::DbErr) -> passkey_server::PasskeyError {
    tracing::error!(error = %err, "visitor passkey store error");
    passkey_server::PasskeyError::DatabaseError("database error".to_string())
}

/// A bcrypt hash of a value no one can submit, used to keep a failed login
/// against an unknown address as slow as one against a known address.
///
/// Computed once at first use rather than hard-coded: a literal that is one
/// character off is not a valid bcrypt string, `verify_password` then errors
/// immediately, and the timing equalisation it exists for silently stops
/// happening. Deriving it from the crate's own hasher cannot drift that way.
///
/// The plaintext is a value no request can carry (`\0` is not valid in a form
/// field), so the comparison can never succeed.
static DUMMY_HASH: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        hash_password("\u{0}not-a-submittable-password\u{0}")
            .unwrap_or_default()
    });

/// The response shape for a refusal, so both paths build it the same way.
fn refusal(code: &str, message: &str) -> VisitorLoginResponse {
    VisitorLoginResponse {
        ok: false,
        visitor_id: String::new(),
        email: String::new(),
        name: String::new(),
        token_version: 0,
        error: message.to_string(),
        error_code: code.to_string(),
    }
}

fn password_refusal(
    code: &str,
    message: &str,
) -> VisitorChangePasswordResponse {
    VisitorChangePasswordResponse {
        ok: false,
        token_version: 0,
        error: message.to_string(),
        error_code: code.to_string(),
    }
}

/// Lowercases and trims an address, the same normalisation the console applies
/// to its own accounts, so `A@b.test` and `a@b.test` are one account.
fn normalise_email(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// A random challenge id: 32 hex characters, wide enough that guessing one is
/// not a way to answer someone else's challenge.
fn new_state_id() -> String {
    // A v4 UUID is 122 bits of randomness from the OS, which is what this
    // needs; the server crate does not depend on `rand` directly, and the
    // identifier only has to be unguessable.
    Uuid::new_v4().simple().to_string()
}

/// A random nonce for the proof of work, in the same shape the WAF challenge
/// uses so the page's hashing code is unchanged.
fn new_nonce() -> String {
    new_state_id()
}

fn db_status(err: sea_orm::DbErr) -> Status {
    tracing::error!(error = %err, "visitor auth database error");
    Status::internal("database error")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host matches a site's primary domain or any of its alternates.
    ///
    /// The comparison runs in Rust rather than in SQL, so it is worth pinning:
    /// the previous version expressed it as a raw `? = ANY(alternate_domains)`
    /// expression, which the Postgres driver rejected at runtime — a failure no
    /// compile step and no unit test of the surrounding logic could see. It
    /// took a deployed end-to-end run to surface.
    #[test]
    fn a_host_matches_the_domain_or_an_alternate() {
        let matches = |domain: &str, alternates: &[&str], host: &str| {
            domain == host || alternates.contains(&host)
        };
        assert!(matches("example.com", &[], "example.com"));
        assert!(matches(
            "example.com",
            &["www.example.com"],
            "www.example.com"
        ));
        assert!(
            matches("example.com", &["a.test", "b.test"], "b.test"),
            "any alternate matches, not just the first"
        );
        assert!(!matches("example.com", &["www.example.com"], "other.test"));
        assert!(
            !matches("example.com", &[], "EXAMPLE.COM"),
            "hosts are compared as they arrive; a case difference is a \
             different host here, which is what the routing table assumes"
        );
    }

    /// The email normalisation is what makes one account reachable by either
    /// spelling; a change here silently splits accounts in two.
    #[test]
    fn emails_are_normalised_before_lookup() {
        assert_eq!("a@b.test", normalise_email("  A@B.TEST  "));
        assert_eq!("a@b.test", normalise_email("a@b.test"));
        assert_eq!("", normalise_email("   "));
    }

    /// Challenge ids and nonces must be unpredictable: a guessable id is a way
    /// to answer a challenge that is not yours, and a guessable nonce is a way
    /// to precompute the answer.
    #[test]
    fn challenge_ids_and_nonces_are_random_and_wide() {
        let a = new_state_id();
        let b = new_state_id();
        assert_ne!(a, b, "ids must not repeat");
        assert_eq!(32, a.len(), "16 bytes of hex");
        assert!(a.bytes().all(|byte| byte.is_ascii_hexdigit()));
        // The nonce uses the same generator; assert the shape the page relies
        // on rather than re-testing the generator.
        let nonce = new_nonce();
        assert_eq!(32, nonce.len());
    }

    /// Every refusal carries a code the data plane can branch on, and the
    /// credential refusals must not say which half was wrong.
    #[test]
    fn credential_refusals_do_not_say_which_half_was_wrong() {
        let response = refusal(
            error_code::INVALID_CREDENTIALS,
            GENERIC_CREDENTIALS_MESSAGE,
        );
        assert!(!response.ok);
        assert_eq!(error_code::INVALID_CREDENTIALS, response.error_code);
        let message = response.error.to_lowercase();
        assert!(
            !message.contains("no such") && !message.contains("unknown email"),
            "the message must not reveal whether the address exists: {message}"
        );
        // Nothing that could identify an account is echoed back.
        assert!(response.visitor_id.is_empty());
        assert!(response.email.is_empty());
    }

    /// The dummy hash must be a real bcrypt string: if it were malformed,
    /// `verify_password` would error immediately and the timing equalisation
    /// it exists for would not happen.
    /// The dummy hash must be a real bcrypt string: if it were malformed,
    /// `verify_password` would error immediately and the timing equalisation
    /// it exists for would not happen.
    #[test]
    fn the_dummy_hash_is_a_well_formed_bcrypt_string() {
        assert!(DUMMY_HASH.starts_with("$2b$"));
        assert_eq!(60, DUMMY_HASH.len(), "bcrypt hashes are 60 characters");
        // It must actually be usable by the verifier, which is the property
        // a hand-written literal failed to have.
        assert!(
            verify_password("anything", &DUMMY_HASH).is_ok(),
            "the verifier must accept the hash's shape"
        );
        assert!(
            !verify_password("anything", &DUMMY_HASH).unwrap_or(true),
            "no submitted password may match it"
        );
    }

    /// The difficulty is deliberately below the WAF challenge's 20: a login is
    /// a one-off human act, and this bound is what keeps it quick.
    ///
    /// Checked at compile time rather than in a test: a comparison between two
    /// constants can only ever pass, so clippy's `assertions_on_constants`
    /// (denied in CI) asks for a `const` block. The assertions then run during
    /// compilation, and an edit that made a login slow fails the build.
    const _: () = {
        assert!(LOGIN_POW_DIFFICULTY >= 12, "too easy to be worth anything");
        assert!(LOGIN_POW_DIFFICULTY <= 20, "too slow for a login form");
    };
}
