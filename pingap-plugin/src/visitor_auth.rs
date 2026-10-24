//! The visitor login page and portal, rendered by the data plane.
//!
//! # What this is
//!
//! A protected site whose `auth_mode` includes `local` signs visitors in with
//! an account held by the control plane, rather than by sending them to an
//! identity provider. This module is the page half of that: the form, the
//! proof-of-work challenge the form carries, and the portal the visitor lands
//! on afterwards.
//!
//! The accounts themselves are not here. The data plane has no database; every
//! question about a visitor (`does this password match`, `which sites may they
//! enter`) goes to the control plane over gRPC, and a control plane that cannot
//! be reached is a refusal rather than a pass. See
//! `pingwaf-server/src/grpc/visitor_auth.rs`.
//!
//! # Why the challenge is the WAF's
//!
//! The proof of work is [`pingwaf_challenge::POW_JS`], the same block the WAF
//! challenge page runs, and the control plane verifies with the same
//! `verify_proof_of_work`. Sharing both halves is what keeps the answer and the
//! check in step; a private copy on either side would fail every login with a
//! message about the password.
//!
//! # The session
//!
//! A signed-in visitor carries an HMAC-signed cookie, the same shape the
//! clearance cookie uses: `base64url(payload).base64url(hmac)`. It is verified
//! locally, so a page view costs no control-plane round trip. The payload
//! carries the visitor, the site and an expiry, and the key is derived from the
//! site's own `cookie_secret` — a cookie minted for one site does not open
//! another.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dashmap::DashMap;
use http::header::SET_COOKIE;
use http::{HeaderName, HeaderValue, StatusCode};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HTTP_HEADER_CONTENT_HTML, HTTP_HEADER_NO_CACHE, HttpResponse, Plugin,
    PluginStep, RequestPluginResult, get_cookie_value, get_host,
};
use pingora::proxy::Session;
use pingwaf_agent::PingWafAgent;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use super::{Error, get_hash_key, get_step_conf, get_str_conf};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Log category, and the plugin's registered name.
const CATEGORY: &str = "visitor_auth";

/// Where the login form lives. Absolute so a rewrite cannot move it out from
/// under the plugin, the same reason the OIDC callback path is checked against
/// the original URI.
pub(crate) const LOGIN_PATH: &str = "/_pingwaf/login";

/// Ends the session and returns to the login page.
pub(crate) const LOGOUT_PATH: &str = "/_pingwaf/logout";

/// The portal a visitor lands on after signing in.
pub(crate) const PORTAL_PATH: &str = "/_pingwaf/portal";

/// The portal's per-site visibility switch.
pub(crate) const VISIBILITY_PATH: &str = "/_pingwaf/portal/visibility";

/// The portal's password form.
pub(crate) const PASSWORD_PATH: &str = "/_pingwaf/portal/password";

/// Starts and finishes a passkey registration.
pub(crate) const PASSKEY_REGISTER_PATH: &str =
    "/_pingwaf/portal/passkey/register";

/// Starts and finishes a passkey sign-in.
pub(crate) const PASSKEY_LOGIN_PATH: &str = "/_pingwaf/passkey/login";

/// Every path this plugin answers itself.
///
/// Checked before anything else in `handle_request`, so a site cannot route
/// these to its own origin by adding a location that matches.
pub(crate) fn owns_path(path: &str) -> bool {
    matches!(
        path,
        LOGIN_PATH
            | LOGOUT_PATH
            | PORTAL_PATH
            | VISIBILITY_PATH
            | PASSWORD_PATH
            | PASSKEY_REGISTER_PATH
            | PASSKEY_LOGIN_PATH
    )
}

/// Paths this plugin must leave to the OIDC plugin.
///
/// The provider entry is the one hole in the gate: a `both` site sends every
/// session-less navigation to the local login page, and that page's "continue
/// with the provider" link has to reach the OIDC plugin instead — otherwise
/// the link lands back on the page it came from.
pub(crate) fn is_delegated(path: &str) -> bool {
    path == crate::oidc::PROVIDER_ENTRY_PATH
}

/// Body cap for a form post. A login form is a few hundred bytes; anything
/// larger is not one.
const MAX_FORM_BODY: usize = 8 * 1024;

/// How long a session cookie lasts, in seconds.
///
/// The same default as the OIDC session, so a visitor cannot tell which way in
/// they used by how long it sticks.
const SESSION_TTL_SECONDS: i64 = 43_200;

/// The cookie the session lives in.
const SESSION_COOKIE: &str = "pingwaf_visitor";

/// A signed-in visitor, as carried in the cookie.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VisitorSession {
    /// The account, as the control plane knows it.
    visitor_id: String,
    /// The site the session was minted for. A cookie for one site does not
    /// open another, even though the account is deployment-wide.
    site_id: String,
    /// The account's token version when the session was issued. A password
    /// change bumps it, which is what ends the sessions minted before it.
    token_version: i64,
    /// Unix seconds.
    exp: i64,
}

/// Every form this module accepts, flattened.
///
/// One struct rather than one per form: the fields do not overlap, each form
/// uses the subset it needs, and the parser stays a single place that has to
/// be right. The names below say which form each field belongs to.
#[derive(Debug, Default)]
struct LoginForm {
    /// Login: the account.
    email: String,
    /// Login: the password. Portal password form: the *new* password.
    password: String,
    /// Login: the id the challenge was issued under.
    challenge_id: String,
    /// Login: the proof-of-work answer.
    solution: String,
    /// Login: when the browser submitted.
    timestamp: i64,
    /// Login: where to go afterwards — only ever a path of this site.
    next: String,
    /// Portal visibility: which site the switch belongs to.
    site_id: String,
    /// Portal password form: the current password.
    current_password: String,
    /// Portal password form: the confirmation.
    confirm_password: String,
}

/// The plugin, as configured for one site.
pub struct VisitorAuth {
    hash_value: String,
    plugin_step: PluginStep,
    /// Key the session cookie is signed with, derived from the site's
    /// `cookie_secret` so one site's cookie does not open another.
    key: [u8; 32],
}

impl VisitorAuth {
    /// Creates the plugin from its configuration.
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(category = CATEGORY, "new visitor auth plugin");
        Self::try_from(params)
    }

    /// The site's host, which is the identifier the control plane scopes by.
    fn site_host(session: &Session) -> Option<String> {
        get_host(session.req_header()).map(|host| host.to_string())
    }

    /// The agent, or `None` in standalone mode.
    ///
    /// Standalone has no control plane to ask, so there is no way to check a
    /// password; the caller treats that as a refusal rather than as a pass.
    fn agent() -> Option<std::sync::Arc<PingWafAgent>> {
        PingWafAgent::instance()
    }

    /// The session of a request, when it has one that still holds and was
    /// minted for this site.
    ///
    /// Signature only: this is the cheap check, and it is what a page view
    /// pays. Whether the account is still enabled, still granted this site,
    /// and has not had its password changed is answered by
    /// [`Self::session_is_live`], which asks the control plane and caches the
    /// answer.
    fn session(
        &self,
        session: &Session,
        site_host: &str,
        now: i64,
    ) -> Option<VisitorSession> {
        let cookie = get_cookie_value(session.req_header(), SESSION_COOKIE)?;
        let parsed = self.unseal::<VisitorSession>(cookie)?;
        if parsed.exp <= now {
            return None;
        }
        // A session minted at another site is not a session here. The account
        // is deployment-wide, but the grant is per site, so accepting a cookie
        // across sites would let a visitor skip the grant check.
        if parsed.site_id != site_host {
            return None;
        }
        Some(parsed)
    }

    /// Whether the control plane still considers this session good.
    ///
    /// A signature proves the cookie was minted here and not edited; it says
    /// nothing about whether the account was disabled or its password changed
    /// since. That is what this asks, and why it exists: without it, changing
    /// a password would not end the sessions an attacker already holds.
    ///
    /// The answer is cached for [`SESSION_CHECK_TTL_SECONDS`] per visitor and
    /// site, so the common case costs no round trip. A control plane that
    /// cannot be reached is treated as **valid** rather than invalid — the
    /// opposite of the login path, and deliberately so: a session that was
    /// already issued should not be torn down by a control-plane outage, or a
    /// blip would sign out every visitor on the fleet at once. The signature
    /// and the expiry still bound it.
    async fn session_is_live(&self, session_data: &VisitorSession) -> bool {
        let key = format!(
            "{}|{}|{}",
            session_data.site_id,
            session_data.visitor_id,
            session_data.token_version
        );
        if let Some(verdict) = live_cache_get(&key) {
            return verdict;
        }
        let Some(agent) = Self::agent() else {
            // Standalone mode has no control plane to ask; the signature is
            // all there is, and refusing here would break every session.
            return true;
        };
        let verdict = match agent
            .visitor_auth()
            .visitor_validate_session(
                &agent.agent_id(),
                &session_data.site_id,
                &session_data.visitor_id,
                session_data.token_version,
            )
            .await
        {
            Ok(response) => {
                if !response.valid {
                    debug!(
                        category = CATEGORY,
                        reason = response.reason,
                        visitor_id = %session_data.visitor_id,
                        "visitor session is no longer valid"
                    );
                }
                response.valid
            },
            Err(error) => {
                // Unreachable control plane: keep the session. See above.
                warn!(
                    category = CATEGORY,
                    error = %error,
                    "visitor: could not check a session; keeping it"
                );
                true
            },
        };
        live_cache_put(key, verdict);
        verdict
    }

    fn seal<T: Serialize>(&self, value: &T) -> Option<String> {
        let payload = serde_json::to_vec(value).ok()?;
        let encoded = URL_SAFE_NO_PAD.encode(&payload);
        let signature = sign(&self.key, &encoded);
        Some(format!("{encoded}.{signature}"))
    }

    fn unseal<T: for<'a> Deserialize<'a>>(&self, value: &str) -> Option<T> {
        let (encoded, signature) = value.split_once('.')?;
        let expected = sign(&self.key, encoded);
        // Constant-time comparison: a timing oracle on the signature would let
        // a forged cookie be refined byte by byte.
        if !constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
            return None;
        }
        let payload = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        serde_json::from_slice(&payload).ok()
    }

    /// Sets the session cookie and sends the browser to the portal.
    fn signed_in_response(
        &self,
        session: VisitorSession,
        secure: bool,
    ) -> HttpResponse {
        let Some(value) = self.seal(&session) else {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not start a session",
                "Please try again.",
            );
        };
        let cookie = session_cookie(&value, SESSION_TTL_SECONDS, secure);
        let mut response = match see_other(PORTAL_PATH) {
            Ok(response) => response,
            Err(error) => {
                warn!(error = %error, "visitor: could not build the redirect");
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not continue",
                    "Please try again.",
                );
            },
        };
        response.headers.get_or_insert_with(Vec::new).push(cookie);
        no_store(response)
    }

    /// Clears the session cookie.
    fn signed_out_response(&self, secure: bool) -> HttpResponse {
        let cookie = session_cookie("", 0, secure);
        let mut response = match see_other(LOGIN_PATH) {
            Ok(response) => response,
            Err(_) => {
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not sign out",
                    "Please try again.",
                );
            },
        };
        response.headers.get_or_insert_with(Vec::new).push(cookie);
        no_store(response)
    }
}

impl VisitorAuth {
    /// Renders the login form, with a fresh challenge when one can be issued.
    ///
    /// The challenge is fetched here rather than by the browser so the page is
    /// self-contained: the nonce arrives with the HTML, and the page's script
    /// has everything it needs to compute the answer.
    async fn login_page(
        &self,
        session: &Session,
        site_host: &str,
        error: &str,
        email: &str,
    ) -> HttpResponse {
        let (challenge_id, nonce, difficulty) = match self
            .issue_challenge(site_host)
            .await
        {
            Some(parts) => parts,
            None => {
                // Without a challenge there is no way to sign in, so the
                // page says so instead of offering a form that cannot
                // succeed.
                return error_page(
                    StatusCode::BAD_GATEWAY,
                    "Sign-in is unavailable",
                    "The login service could not be reached. Please try again shortly.",
                );
            },
        };
        let alert = if error.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="alert" role="alert">{}</div>"#,
                escape_html(error)
            )
        };
        // The `next` the visitor was headed for, confined to this site.
        let next = local_path(
            session
                .req_header()
                .uri
                .query()
                .and_then(|query| {
                    query.split('&').find_map(|pair| {
                        pair.strip_prefix("next=").map(|value| {
                            urlencoding::decode(value)
                                .map(|decoded| decoded.to_string())
                                .unwrap_or_default()
                        })
                    })
                })
                .as_deref()
                .unwrap_or("/"),
        )
        .to_string();
        let body = format!(
            r#"<div class="card">
  <div class="brand">PingWAF</div>
  <h1>Sign in to continue</h1>
  <p class="muted">{site}</p>
  {alert}
  <form method="post" action="{login}" id="login-form">
    <input type="hidden" name="challenge_id" value="{challenge_id}">
    <input type="hidden" name="solution" id="solution">
    <input type="hidden" name="timestamp" id="timestamp">
    <input type="hidden" name="next" value="{next}">
    <div class="field">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="username"
             required autofocus value="{email}">
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="current-password" required>
    </div>
    <div class="progress" id="progress">
      <div class="progress-track"><div class="progress-fill" id="bar"></div></div>
      <div class="progress-label"><span>Verifying you are human</span><span id="pct">0%</span></div>
    </div>
    <div class="check" id="done" style="display:none">
      <span class="dot">&#10003;</span><span>Verification complete</span>
    </div>
    <button type="submit" id="submit" disabled>Sign in</button>
  </form>
  {alternatives}
</div>
<script>
var CONFIG = {{ nonce: "{nonce}", difficulty: {difficulty} }};
var solution = "";
var submitted = false;
function updateProgress(pct) {{
  var bar = document.getElementById('bar');
  var label = document.getElementById('pct');
  if (bar) bar.style.width = Math.min(100, Math.round(pct)) + '%';
  if (label) label.textContent = Math.min(100, Math.round(pct)) + '%';
}}
{pow}
function finish() {{
  if (submitted) return;
  submitted = true;
  document.getElementById('solution').value = solution;
  document.getElementById('timestamp').value = Math.floor(Date.now() / 1000);
  document.getElementById('progress').style.display = 'none';
  document.getElementById('done').style.display = 'flex';
  document.getElementById('submit').disabled = false;
}}
// The proof of work runs on load and the button unlocks when it finishes, so
// the form cannot be submitted with an empty answer.
computeProofOfWork();
var wait = setInterval(function () {{
  if (solution !== "") {{ clearInterval(wait); updateProgress(100); finish(); }}
}}, 50);
</script>"#,
            site = escape_html(site_host),
            alert = alert,
            login = LOGIN_PATH,
            challenge_id = escape_html(&challenge_id),
            next = escape_html(&next),
            email = escape_html(email),
            nonce = escape_html(&nonce),
            difficulty = difficulty,
            pow = pow_script(),
            alternatives = self.login_alternatives(site_host),
        );
        HttpResponse::builder(StatusCode::OK)
            .body(page_shell("Sign in", &body))
            .header(HTTP_HEADER_CONTENT_HTML.clone())
            .no_store()
            .finish()
    }

    /// Asks the control plane for a challenge.
    ///
    /// `None` when there is no agent or the control plane did not answer — the
    /// caller shows an error rather than a form that cannot work.
    async fn issue_challenge(
        &self,
        site_host: &str,
    ) -> Option<(String, String, u32)> {
        let agent = Self::agent()?;
        match agent
            .visitor_auth()
            .visitor_login_challenge(&agent.agent_id(), site_host)
            .await
        {
            Ok(response) if !response.challenge_id.is_empty() => Some((
                response.challenge_id,
                response.nonce,
                response.difficulty,
            )),
            Ok(response) => {
                warn!(
                    category = CATEGORY,
                    error = response.error,
                    "visitor: the control plane issued no challenge"
                );
                None
            },
            Err(error) => {
                warn!(
                    category = CATEGORY,
                    error = %error,
                    "visitor: could not reach the control plane for a challenge"
                );
                None
            },
        }
    }

    /// Handles the submitted login form.
    async fn handle_login_post(
        &self,
        session: &mut Session,
        site_host: &str,
        secure: bool,
    ) -> pingora::Result<RequestPluginResult> {
        let Some(body) = read_form_body(session).await else {
            return Ok(RequestPluginResult::Respond(error_page(
                StatusCode::BAD_REQUEST,
                "Could not read the form",
                "The submitted form was too large or unreadable.",
            )));
        };
        let form = parse_form(&body);
        if form.email.is_empty() || form.password.is_empty() {
            return Ok(RequestPluginResult::Respond(
                self.login_page(
                    session,
                    site_host,
                    "Enter your email and password.",
                    &form.email,
                )
                .await,
            ));
        }
        let Some(agent) = Self::agent() else {
            return Ok(RequestPluginResult::Respond(error_page(
                StatusCode::BAD_GATEWAY,
                "Sign-in is unavailable",
                "The login service could not be reached. Please try again shortly.",
            )));
        };
        let response = agent
            .visitor_auth()
            .visitor_login(
                &agent.agent_id(),
                site_host,
                &form.challenge_id,
                &form.solution,
                form.timestamp,
                &form.email,
                &form.password,
            )
            .await;
        match response {
            Ok(result) if result.ok => {
                debug!(
                    category = CATEGORY,
                    site = site_host,
                    "visitor signed in"
                );
                let session_data = VisitorSession {
                    visitor_id: result.visitor_id,
                    site_id: site_host.to_string(),
                    token_version: result.token_version,
                    exp: now_secs() + SESSION_TTL_SECONDS,
                };
                Ok(RequestPluginResult::Respond(
                    self.signed_in_response(session_data, secure),
                ))
            },
            Ok(result) => {
                // The control plane already chose wording that does not say
                // which half was wrong; it is shown as-is.
                let message = if result.error.is_empty() {
                    "Sign-in failed.".to_string()
                } else {
                    result.error
                };
                debug!(
                    category = CATEGORY,
                    code = result.error_code,
                    site = site_host,
                    "visitor sign-in refused"
                );
                Ok(RequestPluginResult::Respond(
                    self.login_page(session, site_host, &message, &form.email)
                        .await,
                ))
            },
            Err(error) => {
                // The control plane could not be asked. Refusing is the only
                // safe direction: a login that cannot be checked is not a
                // login, and letting it through would hand anyone a session.
                warn!(
                    category = CATEGORY,
                    error = %error,
                    site = site_host,
                    "visitor: the control plane refused the sign-in request"
                );
                Ok(RequestPluginResult::Respond(error_page(
                    StatusCode::BAD_GATEWAY,
                    "Sign-in is unavailable",
                    "The login service could not be reached. Please try again shortly.",
                )))
            },
        }
    }

    /// Renders the portal: the sites this visitor may enter, the password
    /// form, and the passkey section.
    async fn portal_page(&self, session_data: &VisitorSession) -> HttpResponse {
        let (grants, error) = match Self::agent() {
            Some(agent) => {
                match agent
                    .visitor_auth()
                    .visitor_grants(
                        &agent.agent_id(),
                        &session_data.site_id,
                        &session_data.visitor_id,
                    )
                    .await
                {
                    Ok(response) if response.error.is_empty() => {
                        (response.grants, String::new())
                    },
                    Ok(response) => (Vec::new(), response.error),
                    Err(error) => {
                        warn!(
                            category = CATEGORY,
                            error = %error,
                            "visitor: could not load the site list"
                        );
                        (
                            Vec::new(),
                            "Your sites could not be loaded right now."
                                .to_string(),
                        )
                    },
                }
            },
            None => (
                Vec::new(),
                "Your sites could not be loaded right now.".to_string(),
            ),
        };

        let passkey_rows = self.passkey_rows(session_data).await;
        let mut rows = String::new();
        for grant in &grants {
            let entry = format!("https://{}", grant.domain);
            // The switch posts the opposite of what is currently stored, so a
            // click always flips it.
            rows.push_str(&format!(
                r#"<div class="row">
  <div>
    <div class="name">{name}</div>
    <div class="domain"><a href="{entry}">{domain}</a></div>
  </div>
  <form method="post" action="{visibility}" class="inline-form">
    <input type="hidden" name="site_id" value="{site_id}">
    <input type="hidden" name="visible" value="{next}">
    <label class="switch">
      <input type="checkbox" {checked} onchange="this.form.submit()">
      <span class="slider"></span>
    </label>
  </form>
</div>"#,
                name = escape_html(&grant.name),
                entry = escape_html(&entry),
                domain = escape_html(&grant.domain),
                visibility = VISIBILITY_PATH,
                site_id = escape_html(&grant.site_id),
                next = if grant.visible { "false" } else { "true" },
                checked = if grant.visible { "checked" } else { "" },
            ));
        }
        if rows.is_empty() {
            rows.push_str(
                r#"<p class="muted">No sites are assigned to this account yet.</p>"#,
            );
        }

        let alert = if error.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="alert" role="alert">{}</div>"#,
                escape_html(&error)
            )
        };
        let body = format!(
            r#"<div class="card wide">
  <div class="toolbar">
    <div>
      <div class="brand">PingWAF</div>
      <h1>Your account</h1>
    </div>
    <form method="post" action="{logout}" class="inline-form">
      <button class="link-button" type="submit">Sign out</button>
    </form>
  </div>
  {alert}
  <div class="section">
    <h2>Sites you can access</h2>
    {rows}
  </div>
  <div class="section">
    <h2>Change password</h2>
    <form method="post" action="{password}">
      <div class="field">
        <label for="current">Current password</label>
        <input id="current" name="current_password" type="password"
               autocomplete="current-password" required>
      </div>
      <div class="field">
        <label for="new">New password</label>
        <input id="new" name="new_password" type="password"
               autocomplete="new-password" required minlength="8">
      </div>
      <div class="field">
        <label for="confirm">Confirm new password</label>
        <input id="confirm" name="confirm_password" type="password"
               autocomplete="new-password" required minlength="8">
      </div>
      <button type="submit">Update password</button>
    </form>
  </div>
  <div class="section">
    <h2>Passkeys</h2>
    <p class="muted">A passkey signs you in without a password. It stays on
       this device.</p>
    {passkey_rows}
    <div class="field">
      <label for="passkey-name">Name this passkey</label>
      <input id="passkey-name" placeholder="e.g. this laptop">
    </div>
    <button type="button" id="passkey-add">Bind a passkey</button>
    <div class="alert" id="passkey-alert" role="alert" style="display:none"></div>
  </div>
</div>
<script>
{passkey_js}
</script>"#,
            logout = LOGOUT_PATH,
            alert = alert,
            rows = rows,
            password = PASSWORD_PATH,
            passkey_rows = passkey_rows,
            passkey_js = passkey_script(),
        );
        HttpResponse::builder(StatusCode::OK)
            .body(page_shell("Your account", &body))
            .header(HTTP_HEADER_CONTENT_HTML.clone())
            .no_store()
            .finish()
    }

    /// The other ways in, below the password form.
    ///
    /// A passkey is offered whenever the browser can use one — the button is
    /// harmless if the visitor has none bound, and hiding it would mean a visitor
    /// who bound one on another device cannot find it here. The provider link
    /// appears only in `both`, where the site offers two ways in: showing it in
    /// `local` would promise a route that the site does not serve.
    fn login_alternatives(&self, site_host: &str) -> String {
        let mut out = String::new();
        out.push_str(
            r#"<div class="section">
  <h2>Or use a passkey</h2>
  <button type="button" id="passkey-signin">Sign in with a passkey</button>
  <div class="alert" id="passkey-alert" role="alert" style="display:none"></div>
</div>"#,
        );
        let allows_oidc = PingWafAgent::instance()
            .and_then(|agent| agent.get_rules_for_domain(site_host))
            .and_then(|rules| {
                rules.oidc.as_ref().map(|oidc| oidc.auth_mode.clone())
            })
            .is_some_and(|mode| mode == "both");
        if allows_oidc {
            out.push_str(
                r#"<div class="section">
  <h2>Or sign in with your provider</h2>
  <p class="muted">Continue with the identity provider this site is
     registered with.</p>
  <a class="link-button" href="{provider_entry}">Continue with the provider</a>
</div>"#,
            );
        }
        out.push_str(&passkey_login_script());
        out.replace("{provider_entry}", crate::oidc::PROVIDER_ENTRY_PATH)
    }

    /// The bound passkeys, as rows for the portal.
    ///
    /// A failure here degrades to a note rather than taking the portal down:
    /// the site list and the password form still work, and a visitor who
    /// cannot list their passkeys can still sign in with a password.
    async fn passkey_rows(&self, session_data: &VisitorSession) -> String {
        let Some(agent) = Self::agent() else {
            return String::new();
        };
        let passkeys = match agent
            .visitor_auth()
            .visitor_passkey_list(
                &agent.agent_id(),
                &session_data.site_id,
                &session_data.visitor_id,
            )
            .await
        {
            Ok(response) if response.error.is_empty() => response.passkeys,
            Ok(_) => {
                return r#"<p class="muted">Your passkeys could not be listed right now.</p>"#
                    .to_string();
            },
            Err(error) => {
                warn!(
                    category = CATEGORY,
                    error = %error,
                    "visitor: could not list passkeys"
                );
                return r#"<p class="muted">Your passkeys could not be listed right now.</p>"#
                    .to_string();
            },
        };
        if passkeys.is_empty() {
            return r#"<p class="muted">No passkeys bound yet.</p>"#
                .to_string();
        }
        let mut rows = String::new();
        for passkey in &passkeys {
            let last = if passkey.last_used_at.is_empty() {
                "never used".to_string()
            } else {
                format!("last used {}", passkey.last_used_at)
            };
            rows.push_str(&format!(
                r#"<div class="row">
  <div>
    <div class="name">{name}</div>
    <div class="domain">{last}</div>
  </div>
</div>"#,
                name = escape_html(&passkey.name),
                last = escape_html(&last),
            ));
        }
        rows
    }

    /// Handles the portal's visibility switch.
    async fn handle_visibility_post(
        &self,
        session: &mut Session,
        session_data: &VisitorSession,
    ) -> pingora::Result<RequestPluginResult> {
        let Some(body) = read_form_body(session).await else {
            return Ok(RequestPluginResult::Respond(error_page(
                StatusCode::BAD_REQUEST,
                "Could not read the form",
                "The submitted form was unreadable.",
            )));
        };
        let form = parse_form(&body);
        let visible = form.next == "true";
        // The site id comes from the form, but the control plane re-checks the
        // grant, so a forged id cannot change another visitor's row.
        let site_id = form.site_id;
        if site_id.is_empty() {
            return Ok(RequestPluginResult::Respond(
                see_other(PORTAL_PATH).unwrap_or_else(|_| {
                    error_page(
                        StatusCode::BAD_REQUEST,
                        "Nothing to change",
                        "That request named no site.",
                    )
                }),
            ));
        }
        if let Some(agent) = Self::agent()
            && let Err(error) = agent
                .visitor_auth()
                .visitor_set_site_visible(
                    &agent.agent_id(),
                    &session_data.visitor_id,
                    &site_id,
                    visible,
                )
                .await
        {
            warn!(
                category = CATEGORY,
                error = %error,
                "visitor: could not update the site switch"
            );
        }
        Ok(RequestPluginResult::Respond(
            see_other(PORTAL_PATH).unwrap_or_else(|_| {
                error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not continue",
                    "Please try again.",
                )
            }),
        ))
    }

    /// Handles the passkey registration ceremony.
    ///
    /// Two steps in one endpoint, distinguished by the body: `begin` asks for
    /// options (no `credential`), `finish` submits the authenticator's answer.
    /// The browser drives both from the portal's inline script, so the plugin
    /// only relays — the ceremony itself runs in the control plane, which owns
    /// the credential store.
    async fn handle_passkey_register(
        &self,
        session: &mut Session,
        session_data: &VisitorSession,
    ) -> pingora::Result<RequestPluginResult> {
        let Some(body) = read_form_body(session).await else {
            return Ok(RequestPluginResult::Respond(json_error(
                StatusCode::BAD_REQUEST,
                "The request was unreadable.",
            )));
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        let Some(agent) = Self::agent() else {
            return Ok(RequestPluginResult::Respond(json_error(
                StatusCode::BAD_GATEWAY,
                "The service could not be reached.",
            )));
        };
        let credential = parsed
            .get("credential")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if credential.is_empty() {
            // `begin`
            let response = agent
                .visitor_auth()
                .visitor_passkey_register_begin(
                    &agent.agent_id(),
                    &session_data.visitor_id,
                    &session_data.site_id,
                )
                .await;
            return Ok(RequestPluginResult::Respond(match response {
                Ok(options) if options.error.is_empty() => {
                    json_ok(&serde_json::json!({
                        "options": options.options_json,
                        "ceremony_id": options.ceremony_id,
                    }))
                },
                Ok(options) => {
                    json_error(StatusCode::BAD_REQUEST, &options.error)
                },
                Err(error) => {
                    warn!(
                        category = CATEGORY,
                        error = %error,
                        "visitor: could not start a passkey registration"
                    );
                    json_error(
                        StatusCode::BAD_GATEWAY,
                        "The service could not be reached.",
                    )
                },
            }));
        }
        // `finish`
        let ceremony_id = parsed
            .get("ceremony_id")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let name = parsed
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let response = agent
            .visitor_auth()
            .visitor_passkey_register_finish(
                &agent.agent_id(),
                &session_data.site_id,
                ceremony_id,
                credential,
                name,
            )
            .await;
        Ok(RequestPluginResult::Respond(match response {
            Ok(result) if result.ok => {
                json_ok(&serde_json::json!({ "ok": true }))
            },
            Ok(result) => json_error(StatusCode::BAD_REQUEST, &result.error),
            Err(error) => {
                warn!(
                    category = CATEGORY,
                    error = %error,
                    "visitor: could not finish a passkey registration"
                );
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "The service could not be reached.",
                )
            },
        }))
    }

    /// Handles the passkey sign-in ceremony.
    ///
    /// Unlike registration this runs *before* a session exists, so it is
    /// handled ahead of the session check: the credential is what names the
    /// account.
    async fn handle_passkey_login(
        &self,
        session: &mut Session,
        site_host: &str,
        secure: bool,
    ) -> pingora::Result<RequestPluginResult> {
        let Some(body) = read_form_body(session).await else {
            return Ok(RequestPluginResult::Respond(json_error(
                StatusCode::BAD_REQUEST,
                "The request was unreadable.",
            )));
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        let Some(agent) = Self::agent() else {
            return Ok(RequestPluginResult::Respond(json_error(
                StatusCode::BAD_GATEWAY,
                "The service could not be reached.",
            )));
        };
        let credential = parsed
            .get("credential")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if credential.is_empty() {
            let response = agent
                .visitor_auth()
                .visitor_passkey_login_begin(&agent.agent_id(), site_host)
                .await;
            return Ok(RequestPluginResult::Respond(match response {
                Ok(options) if options.error.is_empty() => {
                    json_ok(&serde_json::json!({
                        "options": options.options_json,
                        "ceremony_id": options.ceremony_id,
                    }))
                },
                Ok(options) => {
                    json_error(StatusCode::BAD_REQUEST, &options.error)
                },
                Err(error) => {
                    warn!(
                        category = CATEGORY,
                        error = %error,
                        "visitor: could not start a passkey sign-in"
                    );
                    json_error(
                        StatusCode::BAD_GATEWAY,
                        "The service could not be reached.",
                    )
                },
            }));
        }
        let ceremony_id = parsed
            .get("ceremony_id")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let response = agent
            .visitor_auth()
            .visitor_passkey_login_finish(
                &agent.agent_id(),
                site_host,
                ceremony_id,
                credential,
            )
            .await;
        match response {
            Ok(result) if result.ok => {
                let session_data = VisitorSession {
                    visitor_id: result.visitor_id,
                    site_id: site_host.to_string(),
                    token_version: result.token_version,
                    exp: now_secs() + SESSION_TTL_SECONDS,
                };
                // A sign-in ends at the portal, the same as a password one:
                // the requirement is that the visitor lands on their account,
                // not on the site they came from.
                let mut response =
                    self.signed_in_response(session_data, secure);
                // The script asked for JSON, so it gets JSON — the cookie is
                // set on the same response either way.
                let body = br#"{"ok":true}"#.to_vec();
                response.body = body.into();
                Ok(RequestPluginResult::Respond(response))
            },
            Ok(result) => {
                let message = if result.error.is_empty() {
                    "That passkey could not be verified.".to_string()
                } else {
                    result.error
                };
                Ok(RequestPluginResult::Respond(json_error(
                    StatusCode::UNAUTHORIZED,
                    &message,
                )))
            },
            Err(error) => {
                warn!(
                    category = CATEGORY,
                    error = %error,
                    "visitor: could not finish a passkey sign-in"
                );
                Ok(RequestPluginResult::Respond(json_error(
                    StatusCode::BAD_GATEWAY,
                    "The service could not be reached.",
                )))
            },
        }
    }

    /// Handles the portal's password form.
    async fn handle_password_post(
        &self,
        session: &mut Session,
        session_data: &VisitorSession,
    ) -> pingora::Result<RequestPluginResult> {
        let Some(body) = read_form_body(session).await else {
            return Ok(RequestPluginResult::Respond(error_page(
                StatusCode::BAD_REQUEST,
                "Could not read the form",
                "The submitted form was unreadable.",
            )));
        };
        let form = parse_form(&body);
        // Both halves of the new password must match before anything is sent:
        // a typo that reaches the control plane would lock the visitor out of
        // an account whose password they no longer know.
        if form.password != form.confirm_password {
            return Ok(RequestPluginResult::Respond(error_page(
                StatusCode::BAD_REQUEST,
                "Passwords do not match",
                "The new password and its confirmation differ.",
            )));
        }
        let Some(agent) = Self::agent() else {
            return Ok(RequestPluginResult::Respond(error_page(
                StatusCode::BAD_GATEWAY,
                "Unavailable",
                "The service could not be reached. Please try again shortly.",
            )));
        };
        match agent
            .visitor_auth()
            .visitor_change_password(
                &agent.agent_id(),
                &session_data.visitor_id,
                &form.current_password,
                &form.password,
            )
            .await
        {
            Ok(result) if result.ok => {
                // Every session minted before this change is now invalid,
                // including this one. Drop the cached verdicts first: an entry
                // written under the old version still reads as "valid" for up
                // to a minute, which would keep an old cookie working past the
                // change that was meant to end it.
                live_cache_drop_visitor(&session_data.visitor_id);
                // Re-issue this session with the new version so the visitor is
                // not thrown out of the tab they just used.
                let renewed = VisitorSession {
                    token_version: result.token_version,
                    ..session_data.clone()
                };
                let Some(value) = self.seal(&renewed) else {
                    return Ok(RequestPluginResult::Respond(error_page(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Password changed",
                        "Your password was changed. Please sign in again.",
                    )));
                };
                // The cookie is re-issued with the same `Secure` policy the
                // request arrived under, so a TLS site keeps it.
                let secure = session
                    .req_header()
                    .uri
                    .scheme_str()
                    .is_some_and(|scheme| scheme == "https");
                let cookie =
                    session_cookie(&value, SESSION_TTL_SECONDS, secure);
                let mut response = match see_other(PORTAL_PATH) {
                    Ok(response) => response,
                    Err(_) => {
                        return Ok(RequestPluginResult::Respond(error_page(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Password changed",
                            "Your password was changed. Please sign in again.",
                        )));
                    },
                };
                response.headers.get_or_insert_with(Vec::new).push(cookie);
                Ok(RequestPluginResult::Respond(response))
            },
            Ok(result) => {
                let message = if result.error.is_empty() {
                    "Could not change the password.".to_string()
                } else {
                    result.error
                };
                Ok(RequestPluginResult::Respond(error_page(
                    StatusCode::BAD_REQUEST,
                    "Password not changed",
                    &message,
                )))
            },
            Err(error) => {
                warn!(
                    category = CATEGORY,
                    error = %error,
                    "visitor: could not change the password"
                );
                Ok(RequestPluginResult::Respond(error_page(
                    StatusCode::BAD_GATEWAY,
                    "Unavailable",
                    "The service could not be reached. Please try again shortly.",
                )))
            },
        }
    }
}

impl TryFrom<&PluginConf> for VisitorAuth {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        let plugin_step = get_step_conf(value, PluginStep::Request);
        if plugin_step != PluginStep::Request {
            return Err(invalid(
                "visitor auth plugin should be executed at request step"
                    .to_string(),
            ));
        }
        // The session cookie is signed with a key derived from the site's
        // `cookie_secret` — the same secret the OIDC session uses, so a site
        // has one secret to rotate rather than two. It is required: a cookie
        // signed with a guessable key is a forgeable session.
        let cookie_secret = get_str_conf(value, "cookie_secret");
        if cookie_secret.len() < 16 {
            return Err(invalid(
                "cookie_secret is required, 16 characters at least: the sessions are signed with it"
                    .to_string(),
            ));
        }
        let key: [u8; 32] = Sha256::new()
            .chain_update(cookie_secret.as_bytes())
            .chain_update([0])
            // A domain separator, so this key is not the OIDC one even when
            // both derive from the same secret.
            .chain_update(b"visitor-auth")
            .finalize()
            .into();
        Ok(Self {
            hash_value,
            plugin_step,
            key,
        })
    }
}

#[async_trait]
impl Plugin for VisitorAuth {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        let path = ctx
            .features
            .as_ref()
            .and_then(|features| features.original_uri.as_ref())
            .map(|uri| uri.path())
            .unwrap_or_else(|| session.req_header().uri.path())
            .to_string();
        let Some(site_host) = Self::site_host(session) else {
            return Ok(RequestPluginResult::Respond(error_page(
                StatusCode::BAD_REQUEST,
                "No site",
                "This request does not name a site.",
            )));
        };
        let now = now_secs();
        let method = session.req_header().method.clone();
        let secure = ctx.conn.tls_version.is_some();

        // The gate. A path this plugin does not own is the site's own content,
        // and a visitor without a session must not reach it — this plugin is
        // the only gate a `local` site has, so skipping the check here would
        // leave the site wide open.
        //
        // The OIDC plugin runs the equivalent check for the modes that use it;
        // in `both` this one is reached first and the two agree, because both
        // test the same thing (a session for this site).
        // The provider entry belongs to the OIDC plugin; stepping aside here is what
        // lets a `both` site reach it at all.
        if is_delegated(&path) {
            return Ok(RequestPluginResult::Skipped);
        }
        if !owns_path(&path) {
            if let Some(data) = self.session(session, &site_host, now)
                && self.session_is_live(&data).await
            {
                return Ok(RequestPluginResult::Continue);
            }
            // A browser is sent to the login page; anything that cannot follow
            // a redirect is told there is no session, the same split the OIDC
            // plugin makes.
            if !crate::oidc::is_navigation(session) {
                return Ok(RequestPluginResult::Respond(error_page(
                    StatusCode::UNAUTHORIZED,
                    "Login required",
                    "Sign in to continue.",
                )));
            }
            let next = session
                .req_header()
                .uri
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/");
            let location =
                format!("{}?next={}", LOGIN_PATH, urlencoding::encode(next),);
            return Ok(RequestPluginResult::Respond(
                HttpResponse::redirect(&location).unwrap_or_else(|_| {
                    error_page(
                        StatusCode::UNAUTHORIZED,
                        "Sign in required",
                        "Please sign in to continue.",
                    )
                }),
            ));
        }

        // Signing out works with or without a session, so a stale cookie can
        // always be cleared.
        if path == LOGOUT_PATH {
            return Ok(RequestPluginResult::Respond(
                self.signed_out_response(secure),
            ));
        }

        // A passkey sign-in happens before a session exists, so it is
        // answered here rather than after the session check below.
        if path == PASSKEY_LOGIN_PATH && method == http::Method::POST {
            return self
                .handle_passkey_login(session, &site_host, secure)
                .await;
        }

        if path == LOGIN_PATH {
            if method == http::Method::POST {
                return self
                    .handle_login_post(session, &site_host, secure)
                    .await;
            }
            return Ok(RequestPluginResult::Respond(
                self.login_page(session, &site_host, "", "").await,
            ));
        }

        // Everything below needs a session, and one the control plane still
        // considers good: a signed cookie says who minted it, not that the
        // account is still enabled.
        let Some(session_data) = self.session(session, &site_host, now) else {
            // A portal request without a session goes to the login page rather
            // than an error: the visitor's cookie expired, and signing in
            // again is what they want.
            return Ok(RequestPluginResult::Respond(
                see_other(LOGIN_PATH).unwrap_or_else(|_| {
                    error_page(
                        StatusCode::UNAUTHORIZED,
                        "Sign in required",
                        "Please sign in to continue.",
                    )
                }),
            ));
        };
        if !self.session_is_live(&session_data).await {
            // Disabled, deleted, or its password changed: the cookie goes and
            // the visitor signs in again.
            return Ok(RequestPluginResult::Respond(
                self.signed_out_response(secure),
            ));
        }

        if path == PORTAL_PATH {
            // The portal has no POST of its own: its two forms post to their
            // own paths, which are handled below.
            return Ok(RequestPluginResult::Respond(
                self.portal_page(&session_data).await,
            ));
        }
        if path == VISIBILITY_PATH && method == http::Method::POST {
            return self.handle_visibility_post(session, &session_data).await;
        }
        if path == PASSWORD_PATH && method == http::Method::POST {
            return self.handle_password_post(session, &session_data).await;
        }
        if path == PASSKEY_REGISTER_PATH && method == http::Method::POST {
            return self.handle_passkey_register(session, &session_data).await;
        }
        // Owned path, wrong method: say so rather than falling through to the
        // site.
        Ok(RequestPluginResult::Respond(error_page(
            StatusCode::METHOD_NOT_ALLOWED,
            "Not allowed",
            "That action is not available here.",
        )))
    }
}

/// The session cookie header.
fn session_cookie(
    value: &str,
    max_age: i64,
    secure: bool,
) -> (HeaderName, HeaderValue) {
    let secure = if secure { "; Secure" } else { "" };
    let header = format!(
        "{SESSION_COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"
    );
    (
        SET_COOKIE,
        HeaderValue::from_str(&header).unwrap_or_else(|_| {
            // Only reachable if the value carried a control character, which
            // `seal` cannot produce; an empty cookie is the safe fallback.
            HeaderValue::from_static("pingwaf_visitor=; Path=/; Max-Age=0")
        }),
    )
}

/// HMAC-SHA256 over `payload`, base64url.
fn sign(key: &[u8; 32], payload: &str) -> String {
    // `hmac_sha256` is the crate this workspace already uses for the same
    // job (the JWT plugin signs with it), so a signature here is verifiable
    // by the same primitives rather than by a second implementation.
    URL_SAFE_NO_PAD.encode(hmac_sha256::HMAC::mac(payload.as_bytes(), key))
}

/// Compares two byte strings without leaking where they first differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// The portal's passkey-binding script.
///
/// A thin client over the same JSON endpoints the console's own passkey card
/// uses, written against the browser's `navigator.credentials` rather than a
/// library: the data plane renders plain HTML and has no build step to pull
/// one in. The ceremony itself runs in the control plane, which owns the
/// credential store — this only relays the options and the answer.
fn passkey_script() -> String {
    PASSKEY_SCRIPT.replace("{register}", PASSKEY_REGISTER_PATH)
}

/// The login page's passkey sign-in script.
///
/// Mirrors the portal's binding script in the other direction: fetch the
/// options, ask the authenticator, send the assertion back. The control plane
/// verifies it and issues the session, so nothing here decides anything.
fn passkey_login_script() -> String {
    PASSKEY_LOGIN_SCRIPT.replace("{login}", PASSKEY_LOGIN_PATH)
}

const PASSKEY_LOGIN_SCRIPT: &str = r#"function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  var raw = atob(s), buf = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  var bytes = new Uint8Array(buf), s = '';
  for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function passkeyAlert(text) {
  var el = document.getElementById('passkey-alert');
  if (!el) return;
  el.textContent = text;
  el.style.display = 'block';
}
var pkBtn = document.getElementById('passkey-signin');
if (pkBtn) pkBtn.addEventListener('click', async function () {
  if (!window.PublicKeyCredential) { passkeyAlert('This browser does not support passkeys.'); return; }
  pkBtn.disabled = true;
  try {
    var begin = await fetch('{login}', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    var start = await begin.json();
    if (!begin.ok) { passkeyAlert(start.error || 'Could not start.'); return; }
    var opts = JSON.parse(start.options).publicKey;
    opts.challenge = b64urlToBuf(opts.challenge);
    if (opts.allowCredentials) opts.allowCredentials = opts.allowCredentials.map(function (c) {
      return Object.assign({}, c, { id: b64urlToBuf(c.id) });
    });
    var assertion = await navigator.credentials.get({ publicKey: opts });
    var payload = {
      ceremony_id: start.ceremony_id,
      credential: JSON.stringify({
        id: assertion.id,
        rawId: bufToB64url(assertion.rawId),
        type: assertion.type,
        response: {
          authenticatorData: bufToB64url(assertion.response.authenticatorData),
          clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
          signature: bufToB64url(assertion.response.signature),
          userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : null
        }
      })
    };
    var finish = await fetch('{login}', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    var done = await finish.json();
    if (finish.ok && done.ok) { location.href = done.redirect || '/_pingwaf/portal'; }
    else { passkeyAlert(done.error || 'That passkey could not be verified.'); }
  } catch (e) {
    passkeyAlert(e && e.name === 'NotAllowedError' ? 'Cancelled.' : 'That passkey could not be verified.');
  } finally { pkBtn.disabled = false; }
});"#;

/// The script body, with `{register}` standing in for the endpoint. Kept as a
/// constant so the path appears once, where the router already names it.
const PASSKEY_SCRIPT: &str = r#"function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  var raw = atob(s), buf = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  var bytes = new Uint8Array(buf), s = '';
  for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function show(text) {
  var el = document.getElementById('passkey-alert');
  if (!el) return;
  el.textContent = text;
  el.style.display = 'block';
}
var addBtn = document.getElementById('passkey-add');
if (addBtn) addBtn.addEventListener('click', async function () {
  if (!window.PublicKeyCredential) { show('This browser does not support passkeys.'); return; }
  addBtn.disabled = true;
  try {
    var begin = await fetch('{register}', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    var start = await begin.json();
    if (!begin.ok) { show(start.error || 'Could not start.'); return; }
    var opts = JSON.parse(start.options).publicKey;
    opts.challenge = b64urlToBuf(opts.challenge);
    if (opts.user && opts.user.id) opts.user.id = b64urlToBuf(opts.user.id);
    if (opts.excludeCredentials) opts.excludeCredentials = opts.excludeCredentials.map(function (c) {
      return Object.assign({}, c, { id: b64urlToBuf(c.id) });
    });
    var cred = await navigator.credentials.create({ publicKey: opts });
    var payload = {
      ceremony_id: start.ceremony_id,
      name: (document.getElementById('passkey-name') || {}).value || '',
      credential: JSON.stringify({
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        response: {
          attestationObject: bufToB64url(cred.response.attestationObject),
          clientDataJSON: bufToB64url(cred.response.clientDataJSON)
        }
      })
    };
    var finish = await fetch('{register}', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    var done = await finish.json();
    if (finish.ok && done.ok) { show('Passkey bound. Reloading...'); location.reload(); }
    else { show(done.error || 'That passkey could not be bound.'); }
  } catch (e) {
    show(e && e.name === 'NotAllowedError' ? 'Cancelled.' : 'That passkey could not be bound.');
  } finally { addBtn.disabled = false; }
});"#;

fn no_store(response: HttpResponse) -> HttpResponse {
    response
}

/// A redirect that tells the browser to **switch to GET**.
///
/// `HttpResponse::redirect` answers 307, which preserves the method and the
/// body: a browser following it re-sends the POST. That is right for the WAF
/// challenge, where the body is a proof of work worth repeating, and wrong
/// here — the body of the form we just answered carries the visitor's
/// **password**, and replaying it against the portal would put a credential in
/// a request the portal never expected. 303 is the status that means "the
/// answer is over there, ask for it with GET".
fn see_other(location: &str) -> pingora::Result<HttpResponse> {
    let value = HeaderValue::from_str(location).map_err(|error| {
        pingora::Error::because(
            pingora::ErrorType::InternalError,
            "location is not a header value",
            error,
        )
    })?;
    Ok(HttpResponse::builder(StatusCode::SEE_OTHER)
        .header((http::header::LOCATION, value))
        .header(HTTP_HEADER_NO_CACHE.clone())
        .finish())
}

/// A JSON body, for the endpoints the browser calls with `fetch`.
fn json_body(status: StatusCode, value: &serde_json::Value) -> HttpResponse {
    let body = serde_json::to_string(value)
        .unwrap_or_else(|_| r#"{"error":"serialisation failed"}"#.to_string());
    HttpResponse::builder(status)
        .body(body)
        .header((
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        ))
        .no_store()
        .finish()
}

fn json_ok(value: &serde_json::Value) -> HttpResponse {
    json_body(StatusCode::OK, value)
}

/// A refusal the calling script can read.
fn json_error(status: StatusCode, message: &str) -> HttpResponse {
    json_body(
        status,
        &serde_json::json!({ "error": message, "ok": false }),
    )
}

fn error_page(
    status: StatusCode,
    heading: &str,
    message: &str,
) -> HttpResponse {
    let body = page_shell(
        heading,
        &format!(
            r#"<div class="card"><h1>{}</h1><p class="muted">{}</p></div>"#,
            escape_html(heading),
            escape_html(message)
        ),
    );
    HttpResponse::builder(status)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .no_store()
        .finish()
}

fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// A path of this site and nothing else.
///
/// `//host` and `/\host` are other sites to a browser, so a `next` parameter
/// carrying one would turn the login page into an open redirect.
fn local_path(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'/')
        || matches!(bytes.get(1), Some(b'/') | Some(b'\\'))
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return "/";
    }
    value
}

/// The page chrome shared by every page this module renders.
fn page_shell(title: &str, body: &str) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{title}</title>
{style}
</head>
<body>
{body}
</body>
</html>"##,
        title = escape_html(title),
        style = PAGE_STYLE,
        body = body,
    )
}

/// Styles for the visitor pages.
///
/// Deliberately self-contained and close in spirit to the WAF's own pages —
/// the same dark palette and centred card — so a visitor who has seen a
/// challenge page recognises this one. No external font or script: a login page
/// that needs a CDN is a login page that breaks when the CDN does.
const PAGE_STYLE: &str = r##"<style>
:root{
  --bg:#0f172a;--card:#1e293b;--fg:#f8fafc;--muted:#94a3b8;--border:#334155;
  --accent:#3b82f6;--accent-2:#2563eb;--danger:#ef4444;--ok:#22c55e;
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:24px;color:var(--fg);background:var(--bg);
  background-image:
    radial-gradient(60rem 40rem at 12% 15%,rgba(59,130,246,.18),transparent 60%),
    radial-gradient(50rem 40rem at 88% 85%,rgba(37,99,235,.14),transparent 60%);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
}
.card{
  width:100%;max-width:520px;background:var(--card);border:1px solid var(--border);
  border-radius:18px;padding:36px 32px;box-shadow:0 24px 60px rgba(0,0,0,.45);
  animation:rise .4s cubic-bezier(.2,.8,.2,1) both;
}
.card.wide{max-width:760px}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
h1{margin:0 0 6px;font-size:22px;font-weight:600;letter-spacing:-.01em}
h2{margin:0 0 14px;font-size:16px;font-weight:600}
p{margin:0 0 18px;font-size:14px;line-height:1.55}
.muted{color:var(--muted)}
.brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--accent);margin-bottom:14px;font-weight:600}
label{display:block;font-size:13px;color:var(--muted);margin:0 0 6px}
input[type=email],input[type=password],input[type=text]{
  width:100%;padding:11px 13px;font-size:14px;color:var(--fg);background:#0b1220;
  border:1px solid var(--border);border-radius:10px;outline:none;transition:border-color .15s;
}
input:focus{border-color:var(--accent)}
.field{margin-bottom:16px}
button{
  width:100%;padding:12px;font-size:14px;font-weight:600;color:#fff;cursor:pointer;
  background:linear-gradient(180deg,var(--accent),var(--accent-2));border:0;border-radius:10px;
  transition:filter .15s,opacity .15s;
}
button:hover:not(:disabled){filter:brightness(1.08)}
button:disabled{opacity:.55;cursor:not-allowed}
.alert{
  padding:10px 12px;margin-bottom:16px;font-size:13px;border-radius:10px;
  background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:#fecaca;
}
.progress{margin:4px 0 18px}
.progress-track{height:6px;border-radius:999px;background:#0b1220;overflow:hidden}
.progress-fill{height:100%;width:0;background:var(--accent);transition:width .2s}
.progress-label{display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-top:6px}
.check{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--ok);margin:4px 0 18px}
.check .dot{width:18px;height:18px;border-radius:50%;background:rgba(34,197,94,.16);border:1px solid var(--ok);display:flex;align-items:center;justify-content:center;font-size:11px}
.row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:14px 0;border-top:1px solid var(--border)}
.row:first-of-type{border-top:0}
.row .name{font-size:14px;font-weight:500}
.row .domain{font-size:12px;color:var(--muted);margin-top:2px}
.row a{color:var(--accent);font-size:13px;text-decoration:none}
.row a:hover{text-decoration:underline}
.section{margin-bottom:26px}
.section:last-child{margin-bottom:0}
.switch{position:relative;display:inline-block;width:44px;height:26px;flex:0 0 auto}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;inset:0;background:#0b1220;border:1px solid var(--border);border-radius:999px;transition:.2s;cursor:pointer}
.slider:before{content:"";position:absolute;width:18px;height:18px;left:3px;top:3px;background:var(--muted);border-radius:50%;transition:.2s}
input:checked + .slider{background:var(--accent-2);border-color:var(--accent)}
input:checked + .slider:before{transform:translateX(18px);background:#fff}
.inline-form{display:inline}
.link-button{width:auto;padding:6px 10px;font-size:12px;background:transparent;border:1px solid var(--border);color:var(--muted)}
.link-button:hover{color:var(--fg)}
.toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}
.ok{color:var(--ok);font-size:13px;margin-bottom:14px}
@media(max-width:520px){.card{padding:26px 20px}}
</style>"##;

/// The proof-of-work block, shared verbatim with the WAF challenge page.
fn pow_script() -> &'static str {
    pingwaf_challenge::POW_JS
}

/// How long a "is this session still good" verdict is trusted.
///
/// A password change or a disable should take effect promptly, but not at the
/// cost of a control-plane round trip on every page view. A minute is the
/// balance: the worst case is that a revoked session survives that long, which
/// is far better than the alternative of never revoking it at all.
const SESSION_CHECK_TTL_SECONDS: u64 = 60;

/// The cap on cached verdicts, so a flood of distinct visitors cannot grow the
/// map without bound. Reaching it clears the map rather than evicting one
/// entry: a verdict is cheap to recompute, and an eviction policy would be
/// more code than the problem deserves.
const SESSION_CHECK_MAX_ENTRIES: usize = 8192;

/// `<verdict, checked_at>` per session, keyed by site, visitor and version.
///
/// Process-local on purpose: the answer is an optimisation, and a second
/// instance simply asks the control plane itself. Nothing here is
/// authoritative — the control plane is.
static LIVE_SESSIONS: LazyLock<DashMap<String, (bool, u64)>> =
    LazyLock::new(DashMap::new);

fn live_cache_get(key: &str) -> Option<bool> {
    let entry = LIVE_SESSIONS.get(key)?;
    let (verdict, checked_at) = *entry;
    // An expired entry is removed here rather than by a sweeper: the read is
    // what makes it stale, so the read is the right place to notice.
    if now_secs().saturating_sub(checked_at as i64)
        >= SESSION_CHECK_TTL_SECONDS as i64
    {
        drop(entry);
        LIVE_SESSIONS.remove(key);
        return None;
    }
    Some(verdict)
}

fn live_cache_put(key: String, verdict: bool) {
    if LIVE_SESSIONS.len() >= SESSION_CHECK_MAX_ENTRIES {
        LIVE_SESSIONS.clear();
    }
    LIVE_SESSIONS.insert(key, (verdict, now_secs().max(0) as u64));
}

/// Drops every cached verdict for a visitor.
///
/// Called when this process is the one that ended their sessions — a password
/// change here bumps the version, and the entry cached under the *old* version
/// still says "valid" for the rest of its minute. Without this, the visitor
/// who just changed their password (and anyone holding their old cookie) keeps
/// working until that entry expires, which is exactly the window the version
/// check exists to close.
///
/// Only this process's entries are dropped. Another instance still holds its
/// own copy until its minute runs out — that is the documented bound on the
/// cache, and it is why the check is advisory rather than authoritative.
fn live_cache_drop_visitor(visitor_id: &str) {
    LIVE_SESSIONS.retain(|key, _| !key.contains(visitor_id));
}

register_plugin!("visitor_auth", VisitorAuth);

/// Percent-decodes and splits a form body.
///
/// Written rather than pulled from a crate because it has to match what the
/// browser sends for a plain `application/x-www-form-urlencoded` form: `+` is
/// a space there (unlike a path), and a value may contain `=`.
fn parse_form(body: &str) -> LoginForm {
    let mut form = LoginForm::default();
    for pair in body.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let value = urlencoding::decode(&value.replace('+', " "))
            .map(|decoded| decoded.to_string())
            .unwrap_or_default();
        match key {
            "email" => form.email = value,
            "password" => form.password = value,
            "challenge_id" => form.challenge_id = value,
            "solution" => form.solution = value,
            "next" => form.next = value,
            "site_id" => form.site_id = value,
            // The visibility switch posts the state it wants next under
            // `visible`. It shares the `next` slot with the login form's
            // `next`, because both mean "the value that follows this request"
            // — one a path, one a boolean, and neither handler reads the
            // other's form.
            "visible" => form.next = value,
            "current_password" => form.current_password = value,
            // The password form names its fields `new_password` and
            // `confirm_password`; the login form names its password
            // `password`. Both land in `form.password`, because the two
            // handlers read it as "the password this form is about" — the one
            // to check on login, the one to set on change.
            "new_password" => form.password = value,
            "confirm_password" => form.confirm_password = value,
            "timestamp" => {
                form.timestamp = value.parse().unwrap_or_default();
            },
            // Unknown fields are ignored rather than rejected: a browser
            // autofill extension adding one must not break a sign-in.
            _ => {},
        }
    }
    form
}

/// Reads the request body of a form post, up to [`MAX_FORM_BODY`].
///
/// The body is read from the session, so the caller must have already decided
/// this is a POST it wants to handle.
async fn read_form_body(session: &mut Session) -> Option<String> {
    let mut body = Vec::new();
    loop {
        match session.read_request_body().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > MAX_FORM_BODY {
                    // Refuse rather than truncate: a truncated form would
                    // silently change a submitted value.
                    return None;
                }
                body.extend_from_slice(&chunk);
            },
            Ok(None) => break,
            Err(error) => {
                debug!(error = %error, "visitor: could not read the form body");
                return None;
            },
        }
    }
    String::from_utf8(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin() -> VisitorAuth {
        let conf: PluginConf = toml::from_str(
            "cookie_secret = \"0123456789abcdef0123456789abcdef\"\n",
        )
        .expect("a valid config");
        VisitorAuth::new(&conf).expect("the plugin builds")
    }

    /// Only the paths this plugin owns are answered; everything else must be
    /// left to the site, or a login page would shadow the whole origin.
    #[test]
    fn only_owned_paths_are_handled() {
        assert!(owns_path(LOGIN_PATH));
        assert!(owns_path(LOGOUT_PATH));
        assert!(owns_path(PORTAL_PATH));
        assert!(owns_path(VISIBILITY_PATH));
        assert!(owns_path(PASSWORD_PATH));
        assert!(!owns_path("/"));
        assert!(!owns_path("/dashboard"));
        assert!(!owns_path("/_pingwaf/login/extra"));
    }

    /// A sealed session round-trips, and a tampered one does not: the
    /// signature is what stops a visitor editing their own `visitor_id`.
    #[test]
    fn a_sealed_session_round_trips_and_rejects_tampering() {
        let plugin = plugin();
        let session = VisitorSession {
            visitor_id: "v-1".to_string(),
            site_id: "example.com".to_string(),
            token_version: 3,
            exp: now_secs() + 60,
        };
        let sealed = plugin.seal(&session).expect("seals");
        assert_eq!(
            Some(session.clone()),
            plugin.unseal::<VisitorSession>(&sealed)
        );

        // Editing the payload invalidates it.
        let (_, signature) = sealed.split_once('.').expect("two parts");
        let forged_payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&VisitorSession {
                visitor_id: "someone-else".to_string(),
                ..session.clone()
            })
            .expect("serialises"),
        );
        assert_eq!(
            None,
            plugin.unseal::<VisitorSession>(&format!(
                "{forged_payload}.{signature}"
            )),
            "a re-signed payload must not verify"
        );
        // So does editing the signature.
        assert_eq!(
            None,
            plugin.unseal::<VisitorSession>(&format!("{sealed}x")),
            "a mangled signature must not verify"
        );
        // And a value with no signature at all.
        assert_eq!(None, plugin.unseal::<VisitorSession>("garbage"));
    }

    /// Two sites with different secrets must not accept each other's cookies.
    #[test]
    fn a_session_from_another_secret_does_not_open_this_one() {
        let a: PluginConf = toml::from_str(
            "cookie_secret = \"0123456789abcdef0123456789abcdef\"\n",
        )
        .expect("a valid config");
        let b: PluginConf = toml::from_str(
            "cookie_secret = \"fedcba9876543210fedcba9876543210\"\n",
        )
        .expect("a valid config");
        let a = VisitorAuth::new(&a).expect("builds");
        let b = VisitorAuth::new(&b).expect("builds");
        let session = VisitorSession {
            visitor_id: "v-1".to_string(),
            site_id: "example.com".to_string(),
            token_version: 1,
            exp: now_secs() + 60,
        };
        let sealed = a.seal(&session).expect("seals");
        assert_eq!(
            None,
            b.unseal::<VisitorSession>(&sealed),
            "one site's session must not verify at another"
        );
    }

    /// A short secret is refused rather than silently weakening every session.
    #[test]
    fn a_short_cookie_secret_is_refused() {
        let conf: PluginConf =
            toml::from_str("cookie_secret = \"too-short\"\n")
                .expect("valid toml");
        assert!(VisitorAuth::new(&conf).is_err());
    }

    /// `next` may only ever name a path of this site: `//evil.test` and
    /// `/\evil.test` are other sites to a browser, so accepting one would turn
    /// the login page into an open redirect.
    #[test]
    fn next_is_confined_to_this_site() {
        assert_eq!("/dashboard", local_path("/dashboard"));
        assert_eq!("/a/b?c=d", local_path("/a/b?c=d"));
        assert_eq!("/", local_path("//evil.test"));
        assert_eq!("/", local_path("/\\evil.test"));
        assert_eq!("/", local_path("https://evil.test"));
        assert_eq!("/", local_path(""));
        assert_eq!("/", local_path("/a\r\nSet-Cookie: x=y"));
    }

    /// Every value a visitor can influence is escaped before it reaches the
    /// page; the login form echoes the email back, which is the one place a
    /// submitted value is reflected.
    #[test]
    fn user_values_are_escaped_in_the_page() {
        assert_eq!(
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            escape_html("<script>alert(1)</script>")
        );
        assert_eq!("&quot;x&quot;", escape_html("\"x\""));
        assert_eq!("&#39;", escape_html("'"));
        assert_eq!("a&amp;b", escape_html("a&b"));
    }

    /// The login page must carry the shared proof-of-work block, not a private
    /// copy: the control plane verifies with `verify_proof_of_work`, so a page
    /// computing anything else would fail every login.
    #[test]
    fn the_login_page_carries_the_shared_proof_of_work() {
        let html = page_shell("t", "<div></div>");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(pow_script().contains("function computeProofOfWork"));
        assert!(pow_script().contains("function sha256"));
        assert!(
            pow_script().contains("CONFIG.nonce + candidate"),
            "the answer is SHA-256(nonce + counter), which is what the \
             control plane's verifier hashes"
        );
    }

    /// The session cookie is `HttpOnly` and `SameSite=Lax`, and carries
    /// `Secure` when the site is reached over TLS — a session cookie without
    /// `HttpOnly` is readable by any script on the origin.
    #[test]
    fn the_session_cookie_is_hardened() {
        let (name, value) = session_cookie("abc", 60, true);
        assert_eq!(SET_COOKIE, name);
        let value = value.to_str().expect("ascii");
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
        assert!(value.contains("Secure"), "TLS sites get Secure: {value}");
        assert!(value.contains("Path=/"));
        // Without TLS the flag is absent rather than wrong: a `Secure` cookie
        // over plain http would simply be dropped by the browser.
        let (_, plain) = session_cookie("abc", 60, false);
        assert!(!plain.to_str().expect("ascii").contains("Secure"));
        // Clearing sets Max-Age=0 so the browser drops it immediately.
        let (_, cleared) = session_cookie("", 0, false);
        assert!(cleared.to_str().expect("ascii").contains("Max-Age=0"));
    }

    /// The comparison must not short-circuit on the first differing byte.
    #[test]
    fn the_signature_comparison_is_constant_time() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abcdef", b"abcde"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    /// The form parser must not be confused by a value containing `=`, and
    /// must not decode a `+` as a space in a field that is not a query string.
    #[test]
    fn the_form_parser_reads_what_the_browser_sends() {
        let form =
            parse_form("email=a%40b.test&password=p%3Dw%26x&next=%2Fdash");
        assert_eq!("a@b.test", form.email);
        assert_eq!("p=w&x", form.password);
        assert_eq!("/dash", form.next);
        // Absent fields are empty rather than a parse failure.
        let empty = parse_form("");
        assert!(empty.email.is_empty());
        assert!(empty.password.is_empty());
        assert_eq!(0, empty.timestamp);
    }

    /// Every field the portal's own forms post is one the parser reads.
    ///
    /// The two disagreed once: the password form posts `new_password` and the
    /// switch posts `visible`, and the parser knew neither — so changing a
    /// password answered 400 ("the passwords do not match", because the new
    /// one parsed as empty) and the switch could only ever be turned off. The
    /// names are asserted here as literals rather than derived, because the
    /// point is to notice when the HTML changes under them.
    #[test]
    fn the_parser_reads_every_field_the_portal_posts() {
        // The password form.
        let change = parse_form(
            "current_password=old&new_password=new-secret&confirm_password=new-secret",
        );
        assert_eq!("old", change.current_password);
        assert_eq!(
            "new-secret", change.password,
            "the password form's new_password must land in the field the \
             handler reads as the password to set"
        );
        assert_eq!("new-secret", change.confirm_password);

        // The visibility switch, both directions.
        let on = parse_form("site_id=abc&visible=true");
        assert_eq!("abc", on.site_id);
        assert_eq!(
            "true", on.next,
            "visible must reach the field it is read from"
        );
        let off = parse_form("site_id=abc&visible=false");
        assert_eq!("false", off.next);
    }
}
