// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Challenge plugin — CC protection / "5-second shield".
//!
//! Runs at [`PluginStep::EarlyRequest`]. For every request it either:
//! * serves the `/_pingwaf/challenge/verify` endpoint (solution submission), or
//! * asks the [`ChallengeEngine`] whether the visitor should be challenged and,
//!   if so, returns the JS challenge page (503) or a hard block (403).
//!
//! The WAF plugin delegates its `Challenge` verdicts here: both plugins share
//! the [`PENDING_CHALLENGES`] store so a challenge issued by one can be
//! verified by the other's verify endpoint.

use super::{
    Error, get_hash_key, get_int_conf_or_default, get_str_conf,
    get_str_slice_conf,
};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use http::header;
use http::{HeaderValue, StatusCode};
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HTTP_HEADER_CONTENT_HTML, HttpResponse, Plugin, PluginStep,
    ProxyTrust, RequestPluginResult, ensure_client_ip, get_cookie_value,
    get_host, get_req_header_value, resolve_client_ip_with_trust,
};
use pingora::proxy::Session;
use pingwaf_agent::PingWafAgent;
use pingwaf_agent::cache::{
    ChallengeConfig as CacheChallengeConfig,
    ChallengeLevel as CacheChallengeLevel,
};
use pingwaf_challenge::js_challenge::page::{
    ChallengePageParams, generate_interactive_challenge_html,
    generate_js_challenge_html, generate_managed_challenge_html,
};
use pingwaf_challenge::{
    ChallengeConfig, ChallengeDecision, ChallengeEngine, ChallengeRequest,
    ChallengeSubmission, ClearanceLevel, VerifyResult, generate_request_id,
};
use std::borrow::Cow;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Endpoint the challenge page POSTs its proof-of-work solution to.
pub(crate) const VERIFY_ENDPOINT: &str = "/_pingwaf/challenge/verify";

/// Maximum request-body size accepted on the verify endpoint (64 KiB).
const MAX_VERIFY_BODY: usize = 64 * 1024;

/// Sliding fixed-window (60s) length used for per-IP rate estimation.
const RATE_WINDOW_SECS: i64 = 60;

// ─────────────────────────────────────────────────────────────
// Shared pending-challenge store
// ─────────────────────────────────────────────────────────────

/// State kept server-side between issuing a challenge and verifying the
/// solution. The browser only echoes back `{request_id, solution,
/// fingerprint_json, timestamp}` — the nonce and site id never leave the edge,
/// so they are looked up here by request id.
pub(crate) struct PendingChallenge {
    pub nonce: String,
    pub site_id: String,
    pub original_url: String,
    pub created_at: i64,
}

/// Process-wide map of outstanding challenges, keyed by request id. Shared by
/// the WAF and Challenge plugins.
pub(crate) static PENDING_CHALLENGES: LazyLock<
    DashMap<String, PendingChallenge>,
> = LazyLock::new(DashMap::new);

/// How long an unverified challenge stays resolvable (5 minutes).
const PENDING_TTL_SECS: i64 = 300;

/// Process-wide fallback signing secret for standalone deployments with
/// neither an agent (whose cache dir persists a generated secret) nor a
/// configured `cookie_secret`. Random per process: clearance cookies simply
/// do not survive a restart, whereas the historical `"change-me"` fallback
/// was public knowledge and let anyone forge valid clearances.
pub(crate) static FALLBACK_COOKIE_SECRET: LazyLock<String> =
    LazyLock::new(|| {
        warn!(
            "no challenge cookie_secret configured and no agent cache dir; \
             using a per-process random key (clearances will not survive a \
             restart) — configure `cookie_secret` to persist them"
        );
        uuid::Uuid::new_v4().simple().to_string()
    });

#[inline]
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Restricts a client-supplied redirect target to a same-origin absolute
/// path. Anything that does not start with a single solidus (including
/// protocol-relative `//host` and `/\\host`, which browsers normalize to
/// `//host`) falls back to `/`.
fn safe_redirect_target(url: &str) -> &str {
    if url.starts_with('/') && !url.starts_with("//") && !url.starts_with("/\\")
    {
        url
    } else {
        "/"
    }
}

/// Generate a random 32-hex-char nonce (the challenge crate keeps its own
/// generator private).
fn generate_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Record a freshly issued challenge, opportunistically dropping stale ones.
pub(crate) fn store_pending(
    request_id: &str,
    site_id: &str,
    original_url: &str,
) -> String {
    let now = now_secs();
    // Cheap garbage collection so the map cannot grow without bound.
    if PENDING_CHALLENGES.len() > 1024 {
        PENDING_CHALLENGES
            .retain(|_, v| now.saturating_sub(v.created_at) < PENDING_TTL_SECS);
    }
    let nonce = generate_nonce();
    PENDING_CHALLENGES.insert(
        request_id.to_string(),
        PendingChallenge {
            nonce: nonce.clone(),
            site_id: site_id.to_string(),
            original_url: original_url.to_string(),
            created_at: now,
        },
    );
    nonce
}

/// Take (and remove) the pending challenge for a request id.
fn take_pending(request_id: &str) -> Option<PendingChallenge> {
    let pending = PENDING_CHALLENGES.remove(request_id).map(|(_, v)| v)?;
    if now_secs().saturating_sub(pending.created_at) >= PENDING_TTL_SECS {
        return None;
    }
    Some(pending)
}

/// Which challenge page to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChallengeKind {
    Js,
    Managed,
    Interactive,
}

/// Build a 503 challenge response, registering the pending challenge so the
/// verify endpoint can later resolve the nonce.
pub(crate) fn build_challenge_response(
    request_id: &str,
    original_url: &str,
    site_id: &str,
    difficulty: u32,
    kind: ChallengeKind,
) -> HttpResponse {
    let nonce = store_pending(request_id, site_id, original_url);
    let params = ChallengePageParams {
        request_id: request_id.to_string(),
        challenge_nonce: nonce,
        difficulty,
        verify_endpoint: VERIFY_ENDPOINT.to_string(),
        original_url: original_url.to_string(),
        brand_name: "PingWAF".to_string(),
    };
    let body = match kind {
        ChallengeKind::Js => generate_js_challenge_html(&params),
        ChallengeKind::Managed => generate_managed_challenge_html(&params),
        ChallengeKind::Interactive => {
            generate_interactive_challenge_html(&params)
        },
    };
    HttpResponse::builder(StatusCode::SERVICE_UNAVAILABLE)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header(edge_server_header())
        .header(mitigated_header(Mitigation::Challenge))
        .no_store()
        .finish()
}

// ─────────────────────────────────────────────────────────────
// Branded short-circuit pages
// ─────────────────────────────────────────────────────────────

/// The `Server` header every edge-generated response carries: visitors (and
/// site owners) can tell at a glance the response came through PingWAF, the
/// way `server: cloudflare` works.
pub(crate) fn edge_server_header() -> (header::HeaderName, HeaderValue) {
    (header::SERVER, HeaderValue::from_static("pingwaf"))
}

/// What kind of edge action produced the response, mirroring Cloudflare's
/// `cf-mitigated`: a visitor (or the site owner debugging a report) sees from
/// the header alone whether security intervened.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Mitigation {
    /// A WAF verdict or defense-mode IP block.
    Block,
    /// A challenge was issued and must be solved.
    Challenge,
}

impl Mitigation {
    fn value(self) -> &'static str {
        match self {
            Mitigation::Block => "block",
            Mitigation::Challenge => "challenge",
        }
    }
}

fn mitigated_header(
    mitigation: Mitigation,
) -> (header::HeaderName, HeaderValue) {
    (
        header::HeaderName::from_static("x-pingwaf-mitigated"),
        HeaderValue::from_static(mitigation.value()),
    )
}

/// Minimal HTML escaping for values embedded in brand pages. Reasons come
/// from rule descriptions today, but any future user-influenced text keeps
/// the page inert this way.
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

/// Wraps short-circuit page content in the same visual family as the
/// error_page plugin's built-in templates (shared `PW_STYLE` partial).
///
/// `details` rows are pre-built `<div class="row">…</div>` markup — callers
/// escape their values via [`escape_html`].
fn brand_page(
    title: &str,
    icon: &str,
    code_label: &str,
    heading: &str,
    message_html: &str,
    details: &str,
) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · PingWAF</title>
<style>{pw_style}</style>
</head>
<body>
<div class="card">
  <div class="icon"><svg viewBox="0 0 24 24">{icon}</svg></div>
  <div class="code">{code_label}</div>
  <h1>{heading}</h1>
  <p class="msg">{message_html}</p>
  <div class="details">{details}</div>
  <p class="brand">Protected by <b>PingWAF</b></p>
</div>
</body>
</html>"##,
        title = escape_html(title),
        icon = icon,
        code_label = escape_html(code_label),
        heading = escape_html(heading),
        message_html = message_html,
        details = details,
        pw_style = super::error_page::PW_STYLE,
    )
}

/// One `Request ID`/value pair for a brand page's details block.
fn detail_row(label: &str, value: &str) -> String {
    format!(
        r#"<div class="row"><span class="k">{label}</span><span class="v">{}</span></div>"#,
        escape_html(value)
    )
}

/// The shared block-page body: makes unmistakably clear that *PingWAF
/// Security* issued the block — the exact distinction that used to be lost
/// when origin errors borrowed a WAF-styled page.
fn block_body(request_id: &str, reason: &str) -> String {
    let details = format!(
        "{}{}{}",
        detail_row("Request ID", request_id),
        detail_row("Reason", reason),
        detail_row(
            "Time",
            &chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ),
    );
    brand_page(
        "Request Blocked",
        r#"<path d="M12 3l7 3v5.5c0 4.4-2.9 7.6-7 9-4.1-1.4-7-4.6-7-9V6z"/><path d="M9.6 9.6l4.8 4.8M14.4 9.6l-4.8 4.8"/>"#,
        "Error 403",
        "Request Blocked",
        "Your request was blocked by <b>PingWAF Security</b> before it reached \
the website. If you believe this is a mistake, contact the site \
administrator with the Request ID below.",
        &details,
    )
}

/// A 403 HTML block page.
pub(crate) fn block_page(request_id: &str, reason: &str) -> HttpResponse {
    HttpResponse::builder(StatusCode::FORBIDDEN)
        .body(block_body(request_id, reason))
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header(edge_server_header())
        .header(mitigated_header(Mitigation::Block))
        .no_store()
        .finish()
}

/// A 401 HTML page asking the client to authenticate, sent by the site-wide
/// basic auth gate and by access rules that require credentials.
pub(crate) fn basic_auth_page(
    request_id: &str,
    realm: &str,
    reason: &str,
) -> HttpResponse {
    let challenge = format!(r#"Basic realm="{realm}""#);
    let details = format!(
        "{}{}",
        detail_row("Request ID", request_id),
        detail_row("Reason", reason),
    );
    let body = brand_page(
        "Authentication Required",
        r#"<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>"#,
        "Error 401",
        "Authentication Required",
        "This resource requires basic authentication. Sign in with the \
credentials the site owner gave you to continue.",
        &details,
    );
    HttpResponse::builder(StatusCode::UNAUTHORIZED)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header((
            header::WWW_AUTHENTICATE,
            HeaderValue::from_str(&challenge).unwrap_or(
                HeaderValue::from_static("Basic realm=\"Restricted\""),
            ),
        ))
        .header(edge_server_header())
        .no_store()
        .finish()
}

/// A 503 maintenance page for a paused site. Sending a response instead of
/// dropping the site from the data-plane config keeps the certificate and the
/// log pipeline live, so the dashboard still shows the traffic.
pub(crate) fn paused_page(request_id: &str) -> HttpResponse {
    const RETRY_AFTER_SECS: &str = "3600";
    let details = detail_row("Request ID", request_id);
    let body = brand_page(
        "Site Paused",
        r#"<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>"#,
        "Error 503",
        "Site Temporarily Paused",
        "The site owner has paused this website. It should be back shortly — \
please try again later.",
        &details,
    );
    HttpResponse::builder(StatusCode::SERVICE_UNAVAILABLE)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header((
            header::RETRY_AFTER,
            HeaderValue::from_static(RETRY_AFTER_SECS),
        ))
        .header(edge_server_header())
        .no_store()
        .finish()
}

/// A 503 page served by edges configured to fail closed: the control plane
/// is unreachable and the site has no synced rules, so the request is refused
/// instead of proxied unprotected.
pub(crate) fn fail_closed_page(request_id: &str) -> HttpResponse {
    const RETRY_AFTER_SECS: &str = "30";
    let details = detail_row("Request ID", request_id);
    let body = brand_page(
        "Temporarily Unavailable",
        r#"<path d="M12 3l7 3v5.5c0 4.4-2.9 7.6-7 9-4.1-1.4-7-4.6-7-9V6z"/><path d="M12 8v4M12 15h.01"/>"#,
        "Error 503",
        "Temporarily Unavailable",
        "This site is protected by PingWAF in fail-closed mode. The edge node \
cannot reach its control plane right now, so requests are refused instead \
of proxied unprotected. Please retry in a moment.",
        &details,
    );
    HttpResponse::builder(StatusCode::SERVICE_UNAVAILABLE)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header((
            header::RETRY_AFTER,
            HeaderValue::from_static(RETRY_AFTER_SECS),
        ))
        .header(edge_server_header())
        .no_store()
        .finish()
}

/// A 429 HTML page for requests stopped by a rate limit rule, telling the
/// client when it may retry.
pub(crate) fn rate_limit_page(
    request_id: &str,
    reason: &str,
    retry_after_secs: u64,
) -> HttpResponse {
    let retry_hint = if retry_after_secs > 0 {
        format!("Please try again in about <b>{retry_after_secs}</b> seconds.")
    } else {
        "Please slow down and try again shortly.".to_string()
    };
    let mut details = format!(
        "{}{}",
        detail_row("Request ID", request_id),
        detail_row("Reason", reason),
    );
    if retry_after_secs > 0 {
        details.push_str(&detail_row(
            "Retry after",
            &format!("{retry_after_secs}s"),
        ));
    }
    let body = brand_page(
        "Rate Limit Exceeded",
        r#"<circle cx="12" cy="13" r="8"/><path d="M12 13V9M9 2h6"/>"#,
        "Error 429",
        "Rate Limit Exceeded",
        &format!(
            "You have sent too many requests in a short period of time. \
{retry_hint}"
        ),
        &details,
    );
    let mut response = HttpResponse::builder(StatusCode::TOO_MANY_REQUESTS)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header(edge_server_header())
        .header(mitigated_header(Mitigation::Block))
        .no_store();
    if retry_after_secs > 0 {
        response = response.header((
            header::RETRY_AFTER,
            HeaderValue::from_str(&retry_after_secs.to_string())
                .unwrap_or(HeaderValue::from_static("60")),
        ));
    }
    response.finish()
}

// ─────────────────────────────────────────────────────────────
// Per-IP fixed-window rate counter
// ─────────────────────────────────────────────────────────────

struct RateWindow {
    count: u32,
    window_start: i64,
}

// ─────────────────────────────────────────────────────────────
// Per-site decision engines (control-plane mode)
// ─────────────────────────────────────────────────────────────

/// A cached per-site decision engine plus the agent config fingerprint it was
/// built from.
struct CachedChallengeEngine {
    /// Config fingerprint the engine was built from. An `Arc` so the per
    /// request fingerprint check stays allocation-free.
    fingerprint: Arc<str>,
    engine: Option<Arc<ChallengeEngine>>,
}

/// Builds the decision engine for one site's challenge configuration. Every
/// engine shares the plugin's clearance-cookie secret so a cookie earned on
/// one site validates everywhere the plugin runs.
fn build_site_engine(
    cfg: &CacheChallengeConfig,
    cookie_secret: &str,
    cookie_name: &str,
    pow_difficulty: u32,
) -> ChallengeEngine {
    let default_level = match cfg.default_level {
        CacheChallengeLevel::None => ClearanceLevel::None,
        CacheChallengeLevel::NonInteractive => ClearanceLevel::NonInteractive,
        CacheChallengeLevel::Managed => ClearanceLevel::Managed,
        CacheChallengeLevel::Interactive => ClearanceLevel::Interactive,
    };
    let clearance_duration_secs = if cfg.clearance_duration_seconds == 0 {
        1800
    } else {
        i64::from(cfg.clearance_duration_seconds)
    };
    ChallengeEngine::new(ChallengeConfig {
        enabled: true,
        under_attack_mode: cfg.under_attack_mode,
        default_level,
        clearance_duration_secs,
        exempt_paths: cfg.exempt_paths.clone(),
        exempt_user_agents: Vec::new(),
        // A zero threshold from the control plane means rate-based
        // challenging is disabled; the engine would otherwise challenge
        // everything above zero requests.
        rate_threshold: if cfg.request_threshold == 0 {
            u32::MAX
        } else {
            cfg.request_threshold
        },
        browser_integrity_check: cfg.browser_integrity_check,
        tls_fingerprint_check: cfg.tls_fingerprint_check,
        cookie_secret: cookie_secret.to_string(),
        cookie_name: cookie_name.to_string(),
        pow_difficulty,
        submission_max_age_secs: 300,
    })
}

/// Resolves the clearance-cookie signing secret.
///
/// Standalone deployments take it from the plugin config. Under the PingWaf
/// agent the generated config carries no secret: one is generated on first
/// boot and persisted in the agent cache dir so clearance cookies survive
/// config reloads and process restarts.
pub(crate) fn resolve_cookie_secret(configured: &str) -> String {
    if !configured.is_empty() && configured != "change-me" {
        return configured.to_string();
    }
    let Some(agent) = PingWafAgent::instance() else {
        // Standalone: never fall back to a publicly-known key.
        return FALLBACK_COOKIE_SECRET.clone();
    };
    let dir = Path::new(&agent.config.cache_dir);
    let path = dir.join("challenge_cookie_secret");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let secret = uuid::Uuid::new_v4().simple().to_string();
    if std::fs::create_dir_all(dir).is_ok()
        && std::fs::write(&path, secret.as_bytes()).is_ok()
    {
        secret
    } else {
        // Keep the clearance system working even on a read-only cache dir;
        // cookies merely do not survive a restart.
        uuid::Uuid::new_v4().simple().to_string()
    }
}

/// Resolves the site-level proxy trust for `host` from the agent cache.
///
/// `None` when the site is not behind a trusted proxy, in which case the
/// default client-IP resolution applies.
fn site_proxy_trust(host: &str) -> Option<ProxyTrust> {
    let agent = PingWafAgent::instance()?;
    let site_rules = agent.get_rules_for_domain(host)?;
    let trust = &site_rules.proxy_trust;
    trust.enabled.then(|| {
        ProxyTrust::new(
            trust.enabled,
            trust.effective_header(),
            trust.last_hop_only,
            &trust.trusted_ranges,
        )
    })
}

// ─────────────────────────────────────────────────────────────
// ChallengePlugin
// ─────────────────────────────────────────────────────────────

/// CC protection / browser challenge plugin.
pub struct ChallengePlugin {
    plugin_step: PluginStep,
    /// Statically configured engine: the decision engine in standalone mode
    /// and the clearance-cookie signer everywhere (per-site engines share its
    /// secret, and only the nonce — which never depends on the engine — is
    /// needed to verify a submission).
    engine: Arc<ChallengeEngine>,
    hash_value: String,
    enabled: bool,
    cookie_name: String,
    cookie_secret: String,
    pow_difficulty: u32,
    /// Per-site decision engines built from agent rules, keyed by host.
    site_engines: DashMap<String, CachedChallengeEngine>,
    /// Per host+IP request counter used to feed `request_rate` to the engine.
    rates: DashMap<String, RateWindow>,
}

impl ChallengePlugin {
    /// Create a new plugin from configuration.
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new challenge plugin");
        Self::try_from(params)
    }

    /// Record a hit for `ip` and return its request count in the current
    /// 60-second window.
    fn record_rate(&self, ip: &str) -> u32 {
        let now = now_secs();
        let mut entry =
            self.rates.entry(ip.to_string()).or_insert(RateWindow {
                count: 0,
                window_start: now,
            });
        if now.saturating_sub(entry.window_start) >= RATE_WINDOW_SECS {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count = entry.count.saturating_add(1);
        let count = entry.count;
        drop(entry);
        // Opportunistic cleanup so the map does not grow unbounded.
        if self.rates.len() > 8192 {
            self.rates.retain(|_, w| {
                now.saturating_sub(w.window_start) < RATE_WINDOW_SECS * 2
            });
        }
        count
    }

    /// Resolves the decision engine for `host`: the per-site engine built
    /// from agent rules in control-plane mode, the statically configured
    /// engine in standalone mode. `None` means pass everything through.
    fn decision_engine(&self, host: &str) -> Option<Arc<ChallengeEngine>> {
        if PingWafAgent::instance().is_none() {
            return Some(Arc::clone(&self.engine));
        }
        if host.is_empty() {
            return None;
        }
        let agent = PingWafAgent::instance()?;
        let Some(site_rules) = agent.get_rules_for_domain(host) else {
            // The host no longer resolves in the cache (deleted or renamed
            // site): drop the compiled engine so the per-domain cache
            // cannot grow without bound across config churn.
            self.site_engines.remove(host);
            return None;
        };
        let cfg = site_rules
            .challenge_config
            .as_ref()
            .filter(|cfg| cfg.enabled)?;

        let fingerprint = agent.config_hash();
        if let Some(cached) = self.site_engines.get(host)
            && cached.fingerprint == fingerprint
        {
            return cached.engine.clone();
        }
        let engine = Arc::new(build_site_engine(
            cfg,
            &self.cookie_secret,
            &self.cookie_name,
            self.pow_difficulty,
        ));
        self.site_engines.insert(
            host.to_string(),
            CachedChallengeEngine {
                fingerprint,
                engine: Some(Arc::clone(&engine)),
            },
        );
        Some(engine)
    }

    /// Handle a POST to the verify endpoint: validate the proof-of-work and,
    /// on success, hand back a clearance cookie plus a redirect to the
    /// originally requested URL. The cookie's `Secure` attribute follows the
    /// connection's TLS state — browsers refuse to store a `Secure` cookie
    /// on a plain HTTP page, which would make the challenge unsolvable there.
    async fn handle_verify(
        &self,
        session: &mut Session,
        ctx: &Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        let mut buf = BytesMut::with_capacity(4096);
        while let Some(chunk) = session.read_request_body().await? {
            buf.put(chunk.as_ref());
            if buf.len() > MAX_VERIFY_BODY {
                break;
            }
        }

        let value: serde_json::Value = match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(_) => {
                return Ok(RequestPluginResult::Respond(block_page(
                    "-",
                    "malformed challenge submission",
                )));
            },
        };

        let request_id = value
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let solution = value
            .get("solution")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let fingerprint_json = value
            .get("fingerprint_json")
            .and_then(|v| v.as_str())
            .unwrap_or("{}")
            .to_string();
        let timestamp = value
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(now_secs);

        let Some(pending) = take_pending(&request_id) else {
            return Ok(RequestPluginResult::Respond(block_page(
                &request_id,
                "challenge expired or unknown, please retry",
            )));
        };

        let submission = ChallengeSubmission {
            request_id: request_id.clone(),
            challenge_nonce: pending.nonce,
            solution,
            fingerprint_json,
            timestamp,
            site_id: pending.site_id,
        };

        let result = self
            .engine
            .verify_solution(&submission, ctx.conn.tls_version.is_some());

        match result {
            VerifyResult::Success {
                cookie_value,
                cookie_attributes,
            } => {
                let set_cookie = format!(
                    "{}={}; {}",
                    self.cookie_name, cookie_value, cookie_attributes
                );
                // Redirect instead of echoing the URL into an inline script:
                // the original URL is client-controlled, and reflecting it
                // into a `javascript:` string is XSS. Only same-origin
                // absolute paths are honored; anything else falls back to
                // "/" (so `//evil.com` cannot become a protocol-relative
                // open redirect either).
                let target = safe_redirect_target(&pending.original_url);
                let location = HeaderValue::from_str(target)
                    .unwrap_or(HeaderValue::from_static("/"));
                let builder = HttpResponse::builder(StatusCode::SEE_OTHER)
                    .body(String::new())
                    .header((header::LOCATION, location));
                let mut builder = builder;
                if let Ok(hv) = HeaderValue::from_str(&set_cookie) {
                    builder = builder.header((header::SET_COOKIE, hv));
                }
                Ok(RequestPluginResult::Respond(builder.no_store().finish()))
            },
            VerifyResult::Failed { reason } => {
                warn!(request_id = %request_id, reason = %reason, "challenge verification failed");
                Ok(RequestPluginResult::Respond(block_page(
                    &request_id,
                    &reason,
                )))
            },
        }
    }
}

impl TryFrom<&PluginConf> for ChallengePlugin {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let category = PluginCategory::Challenge.to_string();

        // A challenge plugin that is added is meant to be active; only an
        // explicit `enabled = false` disables it.
        let enabled = value
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let under_attack_mode = value
            .get("under_attack_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let clearance_duration_secs =
            get_int_conf_or_default(value, "clearance_duration_secs", 1800);
        let rate_threshold =
            get_int_conf_or_default(value, "rate_threshold", 100) as u32;
        let pow_difficulty =
            get_int_conf_or_default(value, "pow_difficulty", 20) as u32;

        let mut cookie_secret =
            resolve_cookie_secret(&get_str_conf(value, "cookie_secret"));
        if cookie_secret.is_empty() {
            // Unreachable with the resolution above, but never sign with an
            // empty key.
            cookie_secret = FALLBACK_COOKIE_SECRET.clone();
        }
        let mut cookie_name = get_str_conf(value, "cookie_name");
        if cookie_name.is_empty() {
            cookie_name = "__pingwaf_clearance".to_string();
        }
        let exempt_paths = get_str_slice_conf(value, "exempt_paths");
        let exempt_user_agents =
            get_str_slice_conf(value, "exempt_user_agents");

        let plugin_step = match super::get_step_conf_in(
            value,
            "challenge",
            PluginStep::EarlyRequest,
            &[PluginStep::EarlyRequest, PluginStep::Request],
        ) {
            Ok(step) => step,
            Err(e) => {
                return Err(Error::Invalid {
                    category,
                    message: e.to_string(),
                });
            },
        };

        let config = ChallengeConfig {
            enabled,
            under_attack_mode,
            default_level: ClearanceLevel::NonInteractive,
            clearance_duration_secs,
            exempt_paths,
            exempt_user_agents,
            rate_threshold,
            browser_integrity_check: value
                .get("browser_integrity_check")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            tls_fingerprint_check: false,
            cookie_secret: cookie_secret.clone(),
            cookie_name: cookie_name.clone(),
            pow_difficulty,
            submission_max_age_secs: get_int_conf_or_default(
                value,
                "submission_max_age_secs",
                300,
            ),
        };

        Ok(Self {
            plugin_step,
            engine: Arc::new(ChallengeEngine::new(config)),
            hash_value,
            enabled,
            cookie_name,
            cookie_secret,
            pow_difficulty,
            site_engines: DashMap::new(),
            rates: DashMap::new(),
        })
    }
}

#[async_trait]
impl Plugin for ChallengePlugin {
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
        if !self.enabled {
            return Ok(RequestPluginResult::Skipped);
        }

        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.as_str().to_string();

        // The verify endpoint is always served, even if challenges would
        // otherwise be skipped for this path.
        if path == VERIFY_ENDPOINT && method == "POST" {
            return self.handle_verify(session, ctx).await;
        }

        let host = get_host(session.req_header())
            .unwrap_or_default()
            .to_string();
        // Sites behind a CDN/proxy derive the client IP from the trusted
        // forwarded header so challenge rate limiting keys on the real
        // visitor address.
        if let Some(trust) = site_proxy_trust(&host)
            && let Some(ip) = resolve_client_ip_with_trust(session, &trust)
        {
            ctx.conn.client_ip = Some(ip);
        }
        let client_ip = ensure_client_ip(session, ctx).to_string();
        let user_agent =
            get_req_header_value(session.req_header(), "user-agent")
                .unwrap_or_default()
                .to_string();

        let Some(engine) = self.decision_engine(&host) else {
            return Ok(RequestPluginResult::Continue);
        };

        // A clearance cookie issued for *this* host short-circuits
        // everything. Per-site engines share this engine's secret, so a valid
        // signature only says that some site in this deployment issued the
        // cookie — the site id inside it is what says which. Without the
        // comparison, solving the challenge on one site exempted every site
        // the deployment serves (the WAF's clearance path has always bound
        // the two; see `waf::clearance_valid`). The level is checked too, so
        // a JS clearance cannot stand in for an interactive one.
        if let Some(cookie) =
            get_cookie_value(session.req_header(), &self.cookie_name)
            && let Some(payload) = self.engine.validate_clearance(cookie)
            && payload.site_id == host
            && engine.clearance_level_sufficient(&payload)
        {
            return Ok(RequestPluginResult::Continue);
        }

        // Rate windows are per site so one domain's burst never charges
        // another's budget.
        let rate_key = if host.is_empty() {
            client_ip.clone()
        } else {
            format!("{host}:{client_ip}")
        };
        let request_rate = self.record_rate(&rate_key);
        let challenge_request = ChallengeRequest {
            path,
            method,
            client_ip,
            user_agent,
            cookies: Vec::new(),
            has_js_support: None,
            request_rate,
            // The host is this deployment's site id, on the issuing side and
            // the checking side alike: the challenge page is built with it
            // (see `build_challenge_response` below) and the cookie it issues
            // is bound to it.
            site_id: host,
        };

        let decision = engine.should_challenge(&challenge_request);

        if decision == ChallengeDecision::Pass {
            return Ok(RequestPluginResult::Continue);
        }
        if decision == ChallengeDecision::Block {
            let request_id = ctx
                .state
                .request_id
                .clone()
                .unwrap_or_else(generate_request_id);
            return Ok(RequestPluginResult::Respond(block_page(
                &request_id,
                "blocked by challenge policy",
            )));
        }

        // Any challenge flavour needs the original URL and a request id.
        let uri = &session.req_header().uri;
        let original_url = match uri.query() {
            Some(q) => format!("{}?{}", uri.path(), q),
            None => uri.path().to_string(),
        };
        // The same value the request was evaluated against, so the cookie
        // issued here is bound to exactly the site it was checked for.
        let site_id = challenge_request.site_id;
        let request_id = ctx
            .state
            .request_id
            .clone()
            .unwrap_or_else(generate_request_id);

        let kind = match decision {
            ChallengeDecision::ManagedChallenge => ChallengeKind::Managed,
            ChallengeDecision::InteractiveChallenge => {
                ChallengeKind::Interactive
            },
            _ => ChallengeKind::Js,
        };

        Ok(RequestPluginResult::Respond(build_challenge_response(
            &request_id,
            &original_url,
            &site_id,
            self.pow_difficulty,
            kind,
        )))
    }
}

register_plugin!("challenge", ChallengePlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_core::PluginStep;
    use pingora::proxy::Session;
    use tokio_test::io::Builder;

    /// Reads one response header value, case-insensitively.
    fn header_value(resp: &HttpResponse, name: &str) -> Option<String> {
        resp.headers
            .as_ref()?
            .iter()
            .find(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.to_str().unwrap_or_default().to_string())
    }

    #[test]
    fn block_page_is_branded_and_stamped() {
        let resp = block_page("req-abc", "SQLi rule matched");
        assert_eq!(StatusCode::FORBIDDEN, resp.status);
        let body = String::from_utf8_lossy(&resp.body).to_string();
        // The page must make clear *who* blocked the request, and carry the
        // identifiers a site owner needs to look the event up.
        assert!(body.contains("Request Blocked"), "body: {body}");
        assert!(body.contains("PingWAF Security"), "body: {body}");
        assert!(body.contains("req-abc"), "body: {body}");
        assert!(body.contains("SQLi rule matched"), "body: {body}");
        assert_eq!(Some("pingwaf"), header_value(&resp, "server").as_deref());
        assert_eq!(
            Some("block"),
            header_value(&resp, "x-pingwaf-mitigated").as_deref()
        );
    }

    #[test]
    fn block_page_escapes_reason_html() {
        let resp = block_page("req-1", r#"<script>alert("x")</script>"#);
        let body = String::from_utf8_lossy(&resp.body).to_string();
        assert!(!body.contains("<script>"), "body: {body}");
        assert!(body.contains("&lt;script&gt;"), "body: {body}");
    }

    #[test]
    fn challenge_response_carries_mitigation_headers() {
        let resp = build_challenge_response(
            "req-ch",
            "/original",
            "site-1",
            0,
            ChallengeKind::Js,
        );
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, resp.status);
        assert_eq!(Some("pingwaf"), header_value(&resp, "server").as_deref());
        assert_eq!(
            Some("challenge"),
            header_value(&resp, "x-pingwaf-mitigated").as_deref()
        );
    }

    #[test]
    fn status_pages_are_branded_edge_responses() {
        let paused = paused_page("req-p");
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, paused.status);
        let body = String::from_utf8_lossy(&paused.body).to_string();
        assert!(body.contains("Temporarily Paused"), "body: {body}");
        assert_eq!(Some("pingwaf"), header_value(&paused, "server").as_deref());
        // A paused site is a site-owner action, not a security mitigation:
        // no mitigated header, or dashboards would read it as a block.
        assert_eq!(None, header_value(&paused, "x-pingwaf-mitigated"));

        let rate = rate_limit_page("req-r", "over threshold", 30);
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, rate.status);
        let body = String::from_utf8_lossy(&rate.body).to_string();
        assert!(body.contains("Rate Limit Exceeded"), "body: {body}");
        assert_eq!(
            Some("block"),
            header_value(&rate, "x-pingwaf-mitigated").as_deref()
        );

        let auth = basic_auth_page("req-a", "restricted", "login required");
        assert_eq!(StatusCode::UNAUTHORIZED, auth.status);
        assert_eq!(Some("pingwaf"), header_value(&auth, "server").as_deref());

        let closed = fail_closed_page("req-f");
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, closed.status);
        assert_eq!(Some("pingwaf"), header_value(&closed, "server").as_deref());
    }

    #[test]
    fn safe_redirect_target_keeps_same_origin_paths_only() {
        assert_eq!(safe_redirect_target("/admin?id=1"), "/admin?id=1");
        assert_eq!(safe_redirect_target("/"), "/");
        // Protocol-relative and absolute URLs are open-redirect material.
        assert_eq!(safe_redirect_target("//evil.com"), "/");
        assert_eq!(safe_redirect_target("https://evil.com/x"), "/");
        // Backslash tricks browsers into treating this as scheme-relative.
        assert_eq!(safe_redirect_target("/\\evil.com"), "/");
    }

    #[test]
    fn fallback_cookie_secret_is_random_and_stable_per_process() {
        let first = FALLBACK_COOKIE_SECRET.clone();
        assert!(!first.is_empty());
        assert_ne!(first, "change-me");
        assert_eq!(first.len(), 32);
        assert_eq!(FALLBACK_COOKIE_SECRET.clone(), first);
    }

    #[test]
    fn test_challenge_params() {
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
enabled = true
under_attack_mode = true
clearance_duration_secs = 600
rate_threshold = 50
pow_difficulty = 0
cookie_secret = "test-secret"
cookie_name = "__test_clearance"
exempt_paths = ["/health"]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(plugin.enabled);
        assert_eq!("__test_clearance", plugin.cookie_name);
        assert_eq!(0, plugin.pow_difficulty);
        assert_eq!(PluginStep::EarlyRequest, plugin.plugin_step);
    }

    #[tokio::test]
    async fn test_under_attack_challenges() {
        // Standalone behaviour requires the agent paths to stay off, and a
        // sibling test may otherwise hold an installed agent.
        let _agent_lock = lock_agent().await;
        PingWafAgent::set_agent_instance(None);
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
under_attack_mode = true
pow_difficulty = 0
cookie_secret = "test-secret"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let input_header =
            "GET /dashboard HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = plugin
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("expected a challenge response");
        };
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, resp.status);
    }

    #[tokio::test]
    async fn test_exempt_path_passes() {
        let _agent_lock = lock_agent().await;
        PingWafAgent::set_agent_instance(None);
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
under_attack_mode = true
exempt_paths = ["/health"]
cookie_secret = "test-secret"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let input_header = "GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = plugin
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert!(result == RequestPluginResult::Continue);
    }

    // ── Control-plane mode (PingWafAgent installed) ──────────────

    use pingap_core::PluginStep as TestPluginStep;
    use pingora::proxy::Session as TestSession;

    use crate::waf::tests::lock_agent;
    use pingwaf_agent::cache::RuleCache;
    use pingwaf_agent::client::ControlPlaneClient;
    use pingwaf_agent::config::AgentConfig;
    use pingwaf_agent::heartbeat::MetricsCollector;
    use pingwaf_proto::control_plane as proto;

    /// Installs an agent whose site carries the given challenge config, plus
    /// a second site with none, to exercise per-site resolution.
    async fn install_challenge_agent(
        challenge: Option<proto::ChallengeConfig>,
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<PingWafAgent>,
        tempfile::TempDir,
    ) {
        let lock = lock_agent().await;
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            cache_dir: dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        let rule_cache =
            RuleCache::new(dir.path().to_path_buf(), "test-agent".to_string())
                .unwrap();
        let metrics = Arc::new(MetricsCollector::new());
        let client = Arc::new(ControlPlaneClient::new(
            config.clone(),
            Arc::clone(&rule_cache),
            Arc::clone(&metrics),
        ));
        let agent = Arc::new(PingWafAgent {
            config,
            client,
            rule_cache,
            metrics,
        });
        PingWafAgent::set_agent_instance(Some(Arc::clone(&agent)));

        agent
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![
                    proto::Site {
                        id: "site-1".to_string(),
                        name: "example".to_string(),
                        domain: "example.com".to_string(),
                        alternate_domains: Vec::new(),
                        status: 0,
                        rules: Some(proto::RuleBundle {
                            site_id: "site-1".to_string(),
                            config_hash: "hash-1".to_string(),
                            challenge: challenge.clone(),
                            ..Default::default()
                        }),
                        trust_proxy_headers: false,
                        trusted_header: String::new(),
                        trust_last_hop: false,
                        trusted_proxy_ranges: Vec::new(),
                    },
                    proto::Site {
                        id: "site-2".to_string(),
                        name: "bare".to_string(),
                        domain: "bare.example.com".to_string(),
                        alternate_domains: Vec::new(),
                        status: 0,
                        rules: Some(proto::RuleBundle {
                            site_id: "site-2".to_string(),
                            config_hash: "hash-1".to_string(),
                            ..Default::default()
                        }),
                        trust_proxy_headers: false,
                        trusted_header: String::new(),
                        trust_last_hop: false,
                        trusted_proxy_ranges: Vec::new(),
                    },
                ],
                config_hash: "hash-1".to_string(),
                updated_at: None,
            })
            .unwrap();
        (lock, agent, dir)
    }

    async fn run_challenge_request(
        plugin: &ChallengePlugin,
        host: &str,
        path: &str,
    ) -> RequestPluginResult {
        run_challenge_request_with_cookie(plugin, host, path, "").await
    }

    async fn run_challenge_request_with_cookie(
        plugin: &ChallengePlugin,
        host: &str,
        path: &str,
        cookie: &str,
    ) -> RequestPluginResult {
        let input_header = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = TestSession::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        plugin
            .handle_request(
                TestPluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap()
    }

    /// Under attack mode is enforced per site: the configured site gets the
    /// JS challenge, exempt paths pass, and a site without challenge config
    /// is never challenged.
    #[tokio::test]
    async fn test_agent_under_attack_mode_applies_per_site() {
        let (_guard, _agent, _dir) =
            install_challenge_agent(Some(proto::ChallengeConfig {
                enabled: true,
                under_attack_mode: true,
                default_level: proto::ChallengeLevel::ChallengeNonInteractive
                    as i32,
                clearance_duration_seconds: 1800,
                exempt_paths: vec!["/health".to_string()],
                request_threshold: 0,
                browser_integrity_check: true,
                tls_fingerprint_check: false,
            }))
            .await;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();

        let RequestPluginResult::Respond(resp) =
            run_challenge_request(&plugin, "example.com", "/dashboard").await
        else {
            panic!("expected under-attack mode to challenge");
        };
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, resp.status);

        assert!(
            run_challenge_request(&plugin, "example.com", "/health").await
                == RequestPluginResult::Continue
        );
        assert!(
            run_challenge_request(&plugin, "bare.example.com", "/dashboard")
                .await
                == RequestPluginResult::Continue
        );
    }

    /// A clearance solved on one site must not exempt another. Per-site
    /// engines share the signing secret, so a valid signature only proves
    /// that some site in this deployment issued the cookie; the site id
    /// inside it says which one, and the plugin has to compare that with the
    /// host it is serving. Without the comparison one solved challenge
    /// exempted every site — the cookie is portable because it is signed by a
    /// secret all of them share.
    #[tokio::test]
    async fn test_clearance_is_bound_to_the_site_that_issued_it() {
        let (_guard, _agent, _dir) =
            install_challenge_agent(Some(proto::ChallengeConfig {
                enabled: true,
                under_attack_mode: true,
                default_level: proto::ChallengeLevel::ChallengeNonInteractive
                    as i32,
                clearance_duration_seconds: 1800,
                exempt_paths: Vec::new(),
                request_threshold: 0,
                browser_integrity_check: false,
                tls_fingerprint_check: false,
            }))
            .await;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();
        // Same secret the plugin signs with, so both cookies below verify.
        let manager =
            pingwaf_challenge::CookieManager::new(b"test-secret", 1800);

        let mine = manager.issue_clearance(
            ClearanceLevel::NonInteractive,
            "example.com",
            "fingerprint",
        );
        assert!(
            run_challenge_request_with_cookie(
                &plugin,
                "example.com",
                "/dashboard",
                &format!("{}={mine}", plugin.cookie_name),
            )
            .await
                == RequestPluginResult::Continue
        );

        let foreign = manager.issue_clearance(
            ClearanceLevel::NonInteractive,
            "bare.example.com",
            "fingerprint",
        );
        let RequestPluginResult::Respond(resp) =
            run_challenge_request_with_cookie(
                &plugin,
                "example.com",
                "/dashboard",
                &format!("{}={foreign}", plugin.cookie_name),
            )
            .await
        else {
            panic!(
                "a clearance issued for another site must not exempt this one"
            );
        };
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, resp.status);
    }

    /// A site without challenge config is never challenged, and the verify
    /// endpoint stays reachable for challenges issued by other rules.
    #[tokio::test]
    async fn test_agent_verify_endpoint_is_served() {
        let (_guard, _agent, _dir) = install_challenge_agent(None).await;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();

        // Requests pass everywhere: no site has challenge config.
        assert!(
            run_challenge_request(&plugin, "example.com", "/").await
                == RequestPluginResult::Continue
        );

        // The verify endpoint answers (403 for a malformed body) instead of
        // falling through to the upstream.
        let input_header = "POST /_pingwaf/challenge/verify HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = TestSession::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = plugin
            .handle_request(
                TestPluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("expected the verify endpoint to answer");
        };
        assert_eq!(StatusCode::FORBIDDEN, resp.status);
    }
}
