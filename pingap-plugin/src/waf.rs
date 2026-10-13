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

//! WAF plugin — inspects every request against the PingWAF detection engine.
//!
//! Runs at [`PluginStep::EarlyRequest`], ahead of most other plugins. Rules are
//! resolved per request:
//! * When a [`PingWafAgent`] control-plane instance is running, site rules for
//!   the request's domain are used (cached per-domain and rebuilt when the
//!   agent's config hash changes).
//! * Otherwise (standalone pingap) the locally configured engine is used.
//!
//! Verdicts map onto the proxy pipeline: `Pass`/`Monitor` continue, `Block`
//! returns 403, and `Challenge` delegates to the challenge subsystem.

use super::{
    Error, get_bool_conf, get_hash_key, get_int_conf_or_default, get_str_conf,
    get_str_slice_conf,
};
use crate::bot_dns::{DnsVerdict, bot_dns_verifier, known_bot_family};
use crate::challenge::{
    ChallengeKind, VERIFY_ENDPOINT, basic_auth_page, block_page,
    build_challenge_response, fail_closed_page, paused_page, rate_limit_page,
    resolve_cookie_secret,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use ipnet::IpNet;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HTTP_HEADER_NAME_X_REQUEST_ID, HttpResponse, Plugin, PluginStep,
    ProxyTrust, RequestPluginResult, ResponseBodyPluginResult,
    ResponsePluginResult, constant_time_eq, ensure_client_ip, get_host,
    resolve_client_ip_with_trust,
};
use pingap_util::{IpRules, base64_decode};
use pingora::http::{ResponseHeader, Version};
use pingora::proxy::Session;
use pingwaf_agent::cache::{
    BasicAuthConfig as CacheBasicAuthConfig,
    BotProtectionConfig as CacheBotProtection, GeoConfig as CacheGeoConfig,
    IpAccessAction as CacheIpAccessAction, RateLimitRule as CacheRateLimitRule,
    SiteRules as CacheSiteRules, SslConfig as CacheSslConfig,
    WafAction as CacheWafAction, WafConfig as CacheWafConfig,
    WafMode as CacheWafMode,
};
use pingwaf_agent::{AccessLogEntry, PingWafAgent, SecurityEvent};
use pingwaf_challenge::{
    CLEARANCE_COOKIE_NAME, CookieManager, generate_request_id,
};
use pingwaf_waf::rules::{
    EvalContext, Expression, evaluate as evaluate_expression, parse_expression,
};
use pingwaf_waf::{
    CategorySet, CompiledRule, RequestData, RuleAction, ScoreBreakdown,
    StackSet, WafAction, WafEngine, WafEngineConfig, WafLevel, WafMode,
    WafVerdict,
};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tor_geoip::GeoipDb;
use tracing::{debug, warn};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Which engine handles the current request.
///
/// `Clone` so the request-body filter can snapshot the choice made in the
/// request phase and re-run the verdict on the completed body.
#[derive(Clone)]
enum EngineChoice {
    /// Locally configured engine (standalone mode).
    Base,
    /// Per-domain engine built from agent-supplied site rules.
    Site(Arc<WafEngine>),
    /// WAF explicitly disabled for this site by the control plane.
    Disabled,
    /// The edge is configured to fail closed (`fail_open = false`) and has
    /// lost its control plane: the host has no synced rules to protect it,
    /// so every request is refused before any rule runs.
    FailClosed,
}

/// Client certificate policy of a site, built from its SSL posture. The
/// listener verifies the chain against the union of every mTLS site's CA;
/// what is left per site is requiring a certificate at all, rejecting the
/// ones the dashboard revoked and pinning the organization.
struct MtlsPolicy {
    require_client_cert: bool,
    /// Organization every presented certificate must carry; empty skips the
    /// check.
    organization: String,
    /// Lowercase hex SHA-256 fingerprints of revoked certificates.
    revoked: HashSet<String>,
}

impl MtlsPolicy {
    /// `None` when the site does not use mTLS at all.
    fn build(ssl: Option<&CacheSslConfig>) -> Option<Self> {
        let ssl = ssl.filter(|ssl| ssl.mtls_enabled)?;
        Some(Self {
            require_client_cert: ssl.mtls_requires_cert(),
            organization: ssl.mtls_organization.trim().to_string(),
            revoked: ssl
                .mtls_revoked_fingerprints
                .iter()
                .map(|fingerprint| fingerprint.trim().to_lowercase())
                .filter(|fingerprint| !fingerprint.is_empty())
                .collect(),
        })
    }

    /// The reason this request is refused, `None` when the client
    /// certificate — or its absence — is acceptable.
    fn denial(&self, ctx: &Ctx) -> Option<&'static str> {
        let digest = ctx.conn.tls_peer_cert_digest.as_deref();
        let Some(digest) = digest else {
            return self
                .require_client_cert
                .then_some("client certificate required");
        };
        if self.revoked.contains(&digest.to_lowercase()) {
            return Some("client certificate revoked");
        }
        if !self.organization.is_empty()
            && ctx
                .conn
                .tls_peer_organization
                .as_deref()
                .is_none_or(|org| org != self.organization)
        {
            return Some("client certificate organization mismatch");
        }
        None
    }
}

/// The site's HTTP basic authentication credentials and gate.
///
/// The gate sits inside the WAF plugin, which runs ahead of the cache plugin
/// in the chain, so a stored response can never answer a request that has not
/// been authenticated. Credentials reach the data plane pre-encoded; the
/// request payload is decoded once and compared in constant time.
struct BasicAuthGate {
    /// The gate applies to every request, not only to the clients an access
    /// rule with the `basic_auth` action singles out.
    site_wide: bool,
    realm: String,
    /// Decoded `user:password` payloads.
    credentials: Vec<Vec<u8>>,
    delay: Option<std::time::Duration>,
    hide_credentials: bool,
}

/// Realm advertised when the site did not name one.
const DEFAULT_BASIC_REALM: &str = "Restricted";

/// Keeps a configured realm from breaking out of the `WWW-Authenticate`
/// header.
fn sanitise_realm(value: &str) -> String {
    let cleaned: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect();
    if cleaned.is_empty() {
        DEFAULT_BASIC_REALM.to_string()
    } else {
        cleaned
    }
}

impl BasicAuthGate {
    /// `None` when the site has no usable credential: without one nothing
    /// can pass, so the gate is left out and the operator sees the warning
    /// logged instead. The credentials serve both the site-wide gate and the
    /// `basic_auth` rule action, so they are compiled even while the
    /// site-wide switch is off.
    fn build(cfg: &CacheBasicAuthConfig) -> Option<Self> {
        let credentials: Vec<Vec<u8>> = cfg
            .credentials
            .iter()
            .filter_map(|credential| {
                match base64_decode(&credential.authorization) {
                    Ok(decoded) => Some(decoded),
                    Err(error) => {
                        warn!(
                            username = %credential.username,
                            error = %error,
                            "basic auth credential is not valid base64; entry ignored"
                        );
                        None
                    },
                }
            })
            .collect();
        if credentials.is_empty() {
            if cfg.enabled {
                warn!(
                    "basic auth is enabled without a usable credential; gate disabled"
                );
            }
            return None;
        }
        Some(Self {
            site_wide: cfg.enabled,
            realm: sanitise_realm(&cfg.realm),
            credentials,
            delay: (cfg.delay_seconds > 0).then(|| {
                std::time::Duration::from_secs(u64::from(cfg.delay_seconds))
            }),
            hide_credentials: cfg.hide_credentials,
        })
    }

    /// Whether the request carries a credential this gate accepts.
    fn verify(&self, headers: &[(String, String)]) -> bool {
        let Some(value) = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str())
        else {
            return false;
        };
        // The scheme is case-insensitive (RFC 7235).
        let Some((scheme, payload)) = value.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(decoded) = base64_decode(payload.trim()) else {
            return false;
        };
        self.credentials
            .iter()
            .any(|expected| constant_time_eq(expected, &decoded))
    }
}

/// Whether any enabled access rule asks for the basic auth gate.
fn access_rules_require_basic_auth(site_rules: &CacheSiteRules) -> bool {
    let ip_rule = site_rules.ip_access_rules.iter().any(|rule| {
        rule.enabled && matches!(rule.action, CacheIpAccessAction::BasicAuth)
    });
    let geo_rule = site_rules
        .geo_config
        .as_ref()
        .is_some_and(|geo| matches!(geo.action, CacheWafAction::BasicAuth));
    ip_rule || geo_rule
}

/// Site data resolved from the agent cache, compiled once per config
/// fingerprint: the WAF engine, the access restrictions and the custom rule
/// names used to label security events.
struct SiteContext {
    engine: Option<Arc<WafEngine>>,
    policy: AccessPolicy,
    /// Bot protection (UA classification); `None` when disabled.
    bot: Option<BotPolicy>,
    /// Rate limit rules; `None` when the site has none that are enforceable.
    rate_limits: Option<RateLimitPolicy>,
    /// mTLS enforcement; `None` when the site does not use mTLS.
    mtls: Option<MtlsPolicy>,
    /// Site-wide basic auth gate; `None` when the site has none, it is
    /// disabled, or it stores no usable credential.
    basic_auth: Option<BasicAuthGate>,
    /// Custom rule id → name.
    rule_names: HashMap<String, String>,
    /// Site paused from the dashboard: every request gets the maintenance page.
    paused: bool,
    /// Observation mode: every protection keeps detecting but only records —
    /// WAF, IP/geo rules, bot protection and rate limiting stop enforcing.
    /// Access control (mTLS, basic auth, a paused site) is never downgraded.
    observation_mode: bool,
    /// The site's engine mode. WAF auto-blocks produced while the site was
    /// in block mode are skipped once the site leaves it (monitor/off) so a
    /// mode switch is never overridden by stale edge refusals.
    waf_mode: Option<CacheWafMode>,
    /// Site-level deep body inspection (advanced mode): inspect request
    /// bodies even when the plugin-level `inspect_body` switch is off.
    inspect_body: bool,
    /// Sites behind a CDN/proxy: derive the client IP from a forwarded
    /// header instead of the TCP peer; IP rules, rate limits and logs all
    /// key on the resolved address.
    proxy_trust: ProxyTrust,
}

impl SiteContext {
    fn build(site_rules: &CacheSiteRules) -> Self {
        let waf_cfg = site_rules.waf_config.as_ref();
        let rate_limits = RateLimitPolicy::build(site_rules);
        let basic_auth = site_rules
            .basic_auth
            .as_ref()
            .and_then(BasicAuthGate::build);
        if basic_auth.is_none() && access_rules_require_basic_auth(site_rules) {
            warn!(
                site_id = %site_rules.site_id,
                "access rule requires basic auth but the site has no usable credentials; matching requests are refused"
            );
        }
        Self {
            engine: waf_cfg
                .filter(|cfg| cfg.enabled)
                .map(|cfg| Arc::new(build_site_engine(cfg))),
            policy: AccessPolicy::build(site_rules),
            bot: site_rules
                .bot_protection
                .as_ref()
                .filter(|cfg| cfg.enabled)
                .map(BotPolicy::build),
            rate_limits: (!rate_limits.rules.is_empty()).then_some(rate_limits),
            mtls: MtlsPolicy::build(site_rules.ssl_config.as_ref()),
            basic_auth,
            rule_names: waf_cfg
                .map(|cfg| {
                    cfg.custom_rules
                        .iter()
                        .map(|r| (r.id.clone(), r.name.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            paused: site_rules.is_paused(),
            observation_mode: site_rules.observation_mode,
            waf_mode: waf_cfg.map(|cfg| cfg.mode),
            inspect_body: waf_cfg
                .filter(|cfg| cfg.enabled)
                .is_some_and(|cfg| cfg.advanced_mode),
            proxy_trust: ProxyTrust::new(
                site_rules.proxy_trust.enabled,
                site_rules.proxy_trust.effective_header(),
                site_rules.proxy_trust.last_hop_only,
                &site_rules.proxy_trust.trusted_ranges,
            ),
        }
    }

    /// Resolves the engine choice for the rules this context was built from.
    fn choice(&self, site_rules: &CacheSiteRules) -> EngineChoice {
        match site_rules.waf_config.as_ref() {
            Some(cfg) if cfg.enabled => {
                self.engine.as_ref().map_or(EngineChoice::Base, |engine| {
                    EngineChoice::Site(Arc::clone(engine))
                })
            },
            Some(_) => EngineChoice::Disabled,
            None => EngineChoice::Base,
        }
    }
}

/// A cached per-domain context plus the fingerprint it was built from.
struct CachedSite {
    /// Config fingerprint the context was built from. An `Arc` so the per
    /// request fingerprint check stays allocation-free.
    fingerprint: Arc<str>,
    context: Arc<SiteContext>,
}

/// Everything resolved for one request target.
struct ResolvedSite {
    choice: EngineChoice,
    site_id: String,
    context: Option<Arc<SiteContext>>,
}

// ─────────────────────────────────────────────────────────────
// Access restrictions (IP rules and geo)
// ─────────────────────────────────────────────────────────────

/// Embedded GeoIP database backing country/ASN facts: it feeds geo
/// restrictions, the `ip.src.country` rule variable and the country reported
/// with access logs.
static GEO_DB: LazyLock<Arc<GeoipDb>> = LazyLock::new(GeoipDb::new_embedded);

/// Country code (ISO 3166-1 alpha-2) of `ip`, when the database knows it.
pub(crate) fn lookup_country(ip: &str) -> Option<String> {
    ip.parse().ok().and_then(lookup_country_addr)
}

/// Same as [`lookup_country`] for an already parsed address, so the request
/// hot path parses the client ip once for every consumer.
pub(crate) fn lookup_country_addr(addr: IpAddr) -> Option<String> {
    GEO_DB
        .lookup_country_code(addr)
        .map(|code| code.as_ref().to_string())
}

fn lookup_asn_addr(addr: IpAddr) -> Option<u32> {
    GEO_DB.lookup_asn(addr)
}

/// Parses a configured ASN, which operators write either bare or with an `AS`
/// prefix (`13335`, `AS13335`).
fn parse_asn(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("AS")
        .or_else(|| trimmed.strip_prefix("as"))
        .unwrap_or(trimmed);
    digits.parse::<u32>().ok()
}

/// What an IP access rule does when the client IP matches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpRuleAction {
    Allow,
    Challenge,
    Block,
    /// The matching client must pass the site's basic auth gate.
    BasicAuth,
}

/// One IP access rule with its ranges parsed once.
struct IpRule {
    id: String,
    name: String,
    action: IpRuleAction,
    ranges: IpRules,
}

/// Geo restrictions with the country and ASN lists normalised once.
struct GeoRule {
    enabled: bool,
    blocked_countries: HashSet<String>,
    allowed_countries: HashSet<String>,
    blocked_asns: HashSet<u32>,
    block_unknown: bool,
    challenge: bool,
    /// The policy answers with a basic auth prompt instead of a block page.
    basic_auth: bool,
}

/// Why a request was denied, and by which rule.
struct Denial {
    rule_id: String,
    rule_name: String,
    detail: String,
    challenge: bool,
    /// The request must pass the site's basic auth gate to proceed.
    basic_auth: bool,
}

/// What the access restrictions decided for one request.
enum PolicyOutcome {
    /// No rule matched; the request continues.
    NoMatch,
    /// An explicit `allow` rule matched: the client is trusted, so the
    /// site-wide basic auth gate is skipped along with the rules below it.
    Allowed,
    /// A rule stopped the request.
    Denied(Denial),
}

impl PolicyOutcome {
    /// The denial, when the request was stopped.
    fn denial(&self) -> Option<&Denial> {
        match self {
            Self::Denied(denial) => Some(denial),
            _ => None,
        }
    }
}

/// Access restrictions of one site: IP rules plus the geo policy.
///
/// IP rules are evaluated first-match-wins in the order the control plane sent
/// them (priority ascending), so an `Allow` rule placed above a catch-all
/// `Block` yields a whitelist and sits below a blacklist. An explicit `Allow`
/// match short-circuits every rule below it — and the site-wide basic auth
/// gate with them; when nothing matches, the request continues.
#[derive(Default)]
struct AccessPolicy {
    ip_rules: Vec<IpRule>,
    geo: Option<GeoRule>,
}

impl AccessPolicy {
    fn build(site_rules: &CacheSiteRules) -> Self {
        let ip_rules = site_rules
            .ip_access_rules
            .iter()
            .filter(|rule| rule.enabled && !rule.ip_ranges.is_empty())
            .map(|rule| IpRule {
                id: rule.id.clone(),
                name: rule.name.clone(),
                action: match rule.action {
                    CacheIpAccessAction::Allow => IpRuleAction::Allow,
                    CacheIpAccessAction::Challenge
                    | CacheIpAccessAction::JsChallenge => {
                        IpRuleAction::Challenge
                    },
                    CacheIpAccessAction::Block => IpRuleAction::Block,
                    CacheIpAccessAction::BasicAuth => IpRuleAction::BasicAuth,
                },
                ranges: IpRules::new(&rule.ip_ranges),
            })
            .collect();
        Self {
            ip_rules,
            geo: site_rules.geo_config.as_ref().map(GeoRule::build),
        }
    }

    /// Decides whether `ip` — and the country it resolves to — may proceed.
    /// `addr` is the same address already parsed by the caller; IP rules are
    /// skipped when it could not be parsed.
    fn evaluate(
        &self,
        ip: &str,
        addr: Option<IpAddr>,
        country: Option<&str>,
    ) -> PolicyOutcome {
        if let Some(addr) = addr {
            for rule in &self.ip_rules {
                if !rule.ranges.is_match_addr(&addr) {
                    continue;
                }
                return match rule.action {
                    IpRuleAction::Allow => PolicyOutcome::Allowed,
                    IpRuleAction::Block => PolicyOutcome::Denied(Denial {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        detail: format!(
                            "client ip {ip} matched block rule {}",
                            rule.id
                        ),
                        challenge: false,
                        basic_auth: false,
                    }),
                    IpRuleAction::Challenge => PolicyOutcome::Denied(Denial {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        detail: format!(
                            "client ip {ip} matched challenge rule {}",
                            rule.id
                        ),
                        challenge: true,
                        basic_auth: false,
                    }),
                    IpRuleAction::BasicAuth => PolicyOutcome::Denied(Denial {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        detail: format!(
                            "client ip {ip} matched basic auth rule {}",
                            rule.id
                        ),
                        challenge: false,
                        basic_auth: true,
                    }),
                };
            }
        }

        let Some(geo) = self.geo.as_ref().filter(|geo| geo.enabled) else {
            return PolicyOutcome::NoMatch;
        };
        let asn_denied = !geo.blocked_asns.is_empty()
            && addr.is_some_and(|addr| {
                lookup_asn_addr(addr)
                    .is_some_and(|asn| geo.blocked_asns.contains(&asn))
            });
        let country_denied = match country {
            Some(code) => {
                geo.blocked_countries.contains(code)
                    || (!geo.allowed_countries.is_empty()
                        && !geo.allowed_countries.contains(code))
            },
            None => geo.block_unknown,
        };
        if !asn_denied && !country_denied {
            return PolicyOutcome::NoMatch;
        }
        PolicyOutcome::Denied(Denial {
            rule_id: "geo_restriction".to_string(),
            rule_name: "Geo restriction".to_string(),
            detail: match (country, asn_denied) {
                (Some(code), true) => {
                    format!("country {code} and its network are restricted")
                },
                (Some(code), false) => {
                    format!("country {code} is restricted for this site")
                },
                (None, true) => "the client network is restricted".to_string(),
                (None, false) => {
                    "the country of the client could not be determined"
                        .to_string()
                },
            },
            challenge: geo.challenge,
            basic_auth: geo.basic_auth,
        })
    }
}

impl GeoRule {
    fn build(cfg: &CacheGeoConfig) -> Self {
        let country_set = |list: &[String]| -> HashSet<String> {
            list.iter()
                .map(|code| code.trim().to_uppercase())
                .filter(|code| !code.is_empty())
                .collect()
        };
        Self {
            enabled: cfg.enabled,
            blocked_countries: country_set(&cfg.blocked_countries),
            allowed_countries: country_set(&cfg.allowed_countries),
            blocked_asns: cfg
                .blocked_asns
                .iter()
                .filter_map(|asn| parse_asn(asn))
                .collect(),
            block_unknown: cfg.block_unknown,
            challenge: matches!(
                cfg.action,
                CacheWafAction::Challenge | CacheWafAction::JsChallenge
            ),
            basic_auth: matches!(cfg.action, CacheWafAction::BasicAuth),
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Bot protection (user-agent classification)
// ─────────────────────────────────────────────────────────────

/// What bot protection does with a non-browser user agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BotAction {
    Log,
    Challenge,
    Block,
}

/// Bot protection compiled from the site bundle: verified-bot user agent
/// substrings normalised for case-insensitive matching, trusted crawler IP
/// ranges, and the action for everything that does not look like a browser.
struct BotPolicy {
    whitelist: Vec<String>,
    action: BotAction,
    /// Client IPs inside any of these ranges count as verified bots without
    /// further inspection. The control plane expands the configured IP group
    /// and only fills this when IP verification is enabled.
    verified_ranges: Vec<IpNet>,
    /// When set, user agents claiming a well-known crawler family are only
    /// trusted after a DNS reverse + forward confirmation of the client IP.
    dns_verification: bool,
}

/// Outcome of classifying one request's user agent.
enum BotDecision {
    /// Verified bot or real browser: continue.
    Pass,
    /// Stop the request with the challenge or block page.
    Deny(Denial),
    /// Record a security event but let the request through.
    LogOnly(Denial),
}

impl BotPolicy {
    fn build(cfg: &CacheBotProtection) -> Self {
        let action = match cfg.action {
            CacheWafAction::Log => BotAction::Log,
            CacheWafAction::Challenge | CacheWafAction::JsChallenge => {
                BotAction::Challenge
            },
            _ => BotAction::Block,
        };
        Self {
            whitelist: cfg
                .known_bots_whitelist
                .iter()
                .map(|ua| ua.trim().to_lowercase())
                .filter(|ua| !ua.is_empty())
                .collect(),
            action,
            verified_ranges: cfg
                .verified_bot_ranges
                .iter()
                .filter_map(|range| {
                    let raw = range.trim();
                    raw.parse::<IpNet>()
                        .or_else(|_| raw.parse::<IpAddr>().map(IpNet::from))
                        .ok()
                })
                .collect(),
            dns_verification: cfg.dns_verification_enabled,
        }
    }

    fn denial(&self, detail: String) -> Denial {
        Denial {
            rule_id: "bot_protection".to_string(),
            rule_name: "Bot protection".to_string(),
            detail,
            challenge: self.action == BotAction::Challenge,
            basic_auth: false,
        }
    }

    fn decide(&self, denial: Denial) -> BotDecision {
        match self.action {
            BotAction::Log => BotDecision::LogOnly(denial),
            _ => BotDecision::Deny(denial),
        }
    }

    /// Classifies one request. Verified bots pass first — by trusted IP
    /// range, then by DNS-confirmed crawler family — followed by
    /// user-agent whitelisted bots and real browsers; everything else
    /// receives the configured action. User-agent matching is ASCII
    /// case-insensitive without lowercasing, so the common pass-through
    /// path allocates nothing.
    async fn evaluate(
        &self,
        client_ip: Option<IpAddr>,
        user_agent: &str,
    ) -> BotDecision {
        if let Some(ip) = client_ip
            && self.verified_ranges.iter().any(|range| range.contains(&ip))
        {
            return BotDecision::Pass;
        }
        // A claim of a well-known crawler family is only trusted when the
        // client IP proves it; a resolver outage degrades to the
        // user-agent-only verdict instead of blocking on it.
        if self.dns_verification
            && let Some(ip) = client_ip
            && let Some((token, _)) = known_bot_family(user_agent)
        {
            match bot_dns_verifier().verify(ip, token).await {
                DnsVerdict::Confirmed => return BotDecision::Pass,
                DnsVerdict::Refuted => {
                    return self.decide(self.denial(format!(
                        "user agent claims to be a '{token}' crawler but {ip} does not resolve to its network"
                    )));
                },
                DnsVerdict::Unknown => {},
            }
        }
        if self
            .whitelist
            .iter()
            .any(|bot| contains_ignore_case(user_agent, bot))
        {
            return BotDecision::Pass;
        }
        if is_browser_ua(user_agent) {
            return BotDecision::Pass;
        }
        let detail = if user_agent.is_empty() {
            "the request carries no user agent".to_string()
        } else {
            format!(
                "user agent '{user_agent}' is neither a verified bot nor a browser"
            )
        };
        self.decide(self.denial(detail))
    }
}

/// Loose fingerprint of a real browser user agent: browsers declare
/// `Mozilla/5.0` plus a concrete engine token, while scripting clients,
/// scanners and empty agents do not.
fn is_browser_ua(ua: &str) -> bool {
    contains_ignore_case(ua, "mozilla/5.0")
        && (contains_ignore_case(ua, "chrome/")
            || contains_ignore_case(ua, "safari/")
            || contains_ignore_case(ua, "firefox/")
            || contains_ignore_case(ua, "trident/")
            || contains_ignore_case(ua, "edg/")
            || contains_ignore_case(ua, "opr/")
            || contains_ignore_case(ua, "samsungbrowser/"))
}

/// ASCII case-insensitive `contains`: user agents are ASCII in practice, and
/// this spares the classification path a `to_lowercase` allocation per
/// request.
pub(crate) fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        })
}

// ─────────────────────────────────────────────────────────────
// Rate limiting (per-site rules over fixed-window counters)
// ─────────────────────────────────────────────────────────────

/// Counter key dimension of a rate limit rule. Rules that reference a
/// characteristic that cannot be keyed at the edge (e.g. ja3), or a
/// parameterized one without a name, are ignored at build time rather than
/// enforced with a degraded key.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RateChar {
    Ip,
    Host,
    Path,
    Asn,
    Country,
    /// Named request header, matched case-insensitively.
    Header(String),
    /// Named cookie from the `Cookie` header(s), matched case-sensitively.
    Cookie(String),
    /// Named query-string parameter, matched case-sensitively against the raw
    /// (undecoded) query.
    Query(String),
}

/// What an exhausted rate limit rule does to matching requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateAction {
    /// Record a security event only.
    Log,
    /// Serve the browser challenge; clients holding a valid clearance are
    /// exempt (they already proved a human is behind the traffic).
    Challenge,
    /// Reject with 429 for the mitigation window.
    Block,
}

/// One enabled rate limit rule compiled for evaluation. Rules keep the order
/// the control plane sent them in (priority ascending) and the first
/// enforcing rule to trip stops the request.
struct CompiledRateRule {
    id: String,
    name: String,
    /// Optional match condition; `None` applies to every request.
    expression: Option<Expression>,
    chars: Vec<RateChar>,
    period_secs: u64,
    threshold: u32,
    mitigation_secs: u64,
    action: RateAction,
}

impl CompiledRateRule {
    /// Compiles one control-plane rule; `None` when disabled, unenforceable
    /// (zero threshold or period, unsupported characteristic, allow action)
    /// or carrying an expression that fails to parse.
    fn build(rule: &CacheRateLimitRule) -> Option<Self> {
        if !rule.enabled || rule.threshold == 0 || rule.period_seconds == 0 {
            return None;
        }
        let mut chars = Vec::with_capacity(rule.characteristics.len());
        for (idx, raw) in rule.characteristics.iter().enumerate() {
            let lower = raw.trim().to_lowercase();
            let param = || {
                rule.characteristic_params
                    .get(idx)
                    .map(|p| p.trim())
                    .unwrap_or("")
            };
            let kind = match lower
                .strip_prefix("ratelimitchar")
                .unwrap_or(&lower)
            {
                "ip" | "ipnat" | "ip_nat" => RateChar::Ip,
                "host" => RateChar::Host,
                "path" => RateChar::Path,
                "asn" => RateChar::Asn,
                "country" => RateChar::Country,
                "header" => {
                    let name = param().to_lowercase();
                    if name.is_empty() {
                        debug!(
                            rule = %rule.id,
                            characteristic = %raw,
                            "header characteristic without a parameter name; rule ignored"
                        );
                        return None;
                    }
                    RateChar::Header(name)
                },
                "cookie" => {
                    let name = param().to_string();
                    if name.is_empty() {
                        debug!(
                            rule = %rule.id,
                            characteristic = %raw,
                            "cookie characteristic without a parameter name; rule ignored"
                        );
                        return None;
                    }
                    RateChar::Cookie(name)
                },
                "query" => {
                    let name = param().to_string();
                    if name.is_empty() {
                        debug!(
                            rule = %rule.id,
                            characteristic = %raw,
                            "query characteristic without a parameter name; rule ignored"
                        );
                        return None;
                    }
                    RateChar::Query(name)
                },
                _ => {
                    debug!(
                        rule = %rule.id,
                        characteristic = %raw,
                        "rate limit characteristic unsupported at the edge; rule ignored"
                    );
                    return None;
                },
            };
            chars.push(kind);
        }
        let expression = if rule.expression.trim().is_empty() {
            None
        } else {
            match parse_expression(&rule.expression) {
                Ok(expr) => Some(expr),
                Err(e) => {
                    debug!(
                        rule = %rule.id,
                        error = %e,
                        "rate limit expression failed to parse; rule ignored"
                    );
                    return None;
                },
            }
        };
        let action = match rule.action {
            CacheWafAction::Log => RateAction::Log,
            CacheWafAction::Challenge | CacheWafAction::JsChallenge => {
                RateAction::Challenge
            },
            CacheWafAction::Block => RateAction::Block,
            // Counting without consequence would only burn CPU, and basic
            // auth is not a rate limit outcome.
            CacheWafAction::Allow | CacheWafAction::BasicAuth => return None,
        };
        Some(Self {
            id: rule.id.clone(),
            name: rule.name.clone(),
            expression,
            chars,
            period_secs: u64::from(rule.period_seconds),
            threshold: rule.threshold,
            mitigation_secs: u64::from(rule.mitigation_timeout_seconds),
            action,
        })
    }

    /// Counter key for this rule and request: the rule id (a UUID, unique
    /// across sites) plus the value of every tracked characteristic. Requests
    /// missing a parameterized value (absent header/cookie/query) share the
    /// `-` bucket instead of bypassing the counter.
    fn counter_key(
        &self,
        request_data: &RequestData,
        host: &str,
        asn: Option<u32>,
    ) -> String {
        let mut key = String::with_capacity(64);
        key.push_str(&self.id);
        for c in &self.chars {
            key.push('\u{1f}');
            match c {
                RateChar::Ip => key.push_str(&request_data.client_ip),
                RateChar::Host => key.push_str(host),
                RateChar::Path => key.push_str(&request_data.path),
                RateChar::Country => key.push_str(
                    request_data.country_code.as_deref().unwrap_or("-"),
                ),
                RateChar::Asn => match asn {
                    Some(n) => key.push_str(&n.to_string()),
                    None => key.push('-'),
                },
                RateChar::Header(name) => key.push_str(
                    request_data
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.trim())
                        .unwrap_or("-"),
                ),
                RateChar::Cookie(name) => key.push_str(
                    request_data
                        .headers
                        .iter()
                        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                        .flat_map(|(_, v)| v.split(';'))
                        .find_map(|pair| {
                            let (n, v) = pair.trim().split_once('=')?;
                            (n == name.as_str()).then(|| v.trim())
                        })
                        .unwrap_or("-"),
                ),
                RateChar::Query(name) => key.push_str(
                    request_data
                        .query
                        .split('&')
                        .find_map(|pair| {
                            let (n, v) = pair.split_once('=')?;
                            (n == name.as_str()).then_some(v)
                        })
                        .unwrap_or("-"),
                ),
            }
        }
        key
    }
}

fn rate_tripped(rule: &CompiledRateRule, retry_after: u64) -> RateTripped {
    RateTripped {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        detail: format!(
            "rate limit rule '{}' exceeded {} requests per {}s",
            rule.name, rule.threshold, rule.period_secs
        ),
        challenge: rule.action == RateAction::Challenge,
        retry_after,
    }
}

/// A tripped rate limit rule.
struct RateTripped {
    rule_id: String,
    rule_name: String,
    detail: String,
    challenge: bool,
    /// Suggested Retry-After in seconds: the mitigation timeout, or the rest
    /// of the current window when no mitigation is configured.
    retry_after: u64,
}

/// What rate limiting decided for one request.
struct RateOutcome {
    /// First enforcing rule that tripped: the request must be stopped.
    deny: Option<RateTripped>,
    /// Log-only rules that tripped: recorded as events only.
    logged: Vec<RateTripped>,
}

/// Fixed-window counter state for one rate limit key.
#[derive(Debug)]
struct RateCounter {
    /// Current window index (`unix seconds / period`).
    window: u64,
    count: u32,
    /// Unix seconds until which the key stays blocked (0 = clear); only set
    /// while a mitigation timeout is running.
    blocked_until: u64,
    /// Unix seconds after which the entry becomes collectable.
    expires_at: u64,
}

/// Only pay for garbage collection above this many live counters.
const RATE_COUNTERS_GC_THRESHOLD: usize = 65_536;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// All rate limit rules of one site in evaluation order.
#[derive(Default)]
struct RateLimitPolicy {
    rules: Vec<CompiledRateRule>,
}

impl RateLimitPolicy {
    fn build(site_rules: &CacheSiteRules) -> Self {
        Self {
            rules: site_rules
                .rate_limit_rules
                .iter()
                .filter_map(CompiledRateRule::build)
                .collect(),
        }
    }

    /// Counts the request against every matching rule. Enforcement rules stop
    /// at the first one that trips; log-only rules accumulate events and let
    /// the request continue.
    fn evaluate(
        &self,
        counters: &DashMap<String, RateCounter>,
        request_data: &RequestData,
        host: &str,
        cleared: bool,
        client_addr: Option<IpAddr>,
    ) -> RateOutcome {
        let mut logged = Vec::new();
        if self.rules.is_empty() {
            return RateOutcome { deny: None, logged };
        }
        let now = unix_now();
        let asn = if self.rules.iter().any(|r| r.chars.contains(&RateChar::Asn))
        {
            client_addr.and_then(lookup_asn_addr)
        } else {
            None
        };
        let expression_state = self
            .rules
            .iter()
            .any(|r| r.expression.is_some())
            .then(|| ExpressionState::build(request_data));
        for rule in &self.rules {
            if let (Some(state), Some(expr)) =
                (expression_state.as_ref(), rule.expression.as_ref())
                && !evaluate_expression(
                    expr,
                    &state.eval(request_data, host, client_addr),
                )
            {
                continue;
            }
            // A client holding a valid clearance already solved a challenge;
            // challenge rules neither count nor stop it.
            if rule.action == RateAction::Challenge && cleared {
                continue;
            }
            let key = rule.counter_key(request_data, host, asn);
            if counters.len() > RATE_COUNTERS_GC_THRESHOLD {
                counters.retain(|_, entry| now < entry.expires_at);
            }
            let window = now / rule.period_secs;
            let mut entry = counters.entry(key).or_insert(RateCounter {
                window,
                count: 0,
                blocked_until: 0,
                expires_at: 0,
            });
            if entry.window != window {
                entry.window = window;
                entry.count = 0;
                // A mitigation ban outlives the window it was triggered in
                // (mitigation_secs may be much larger than period_secs);
                // resetting it here would let attackers ride out the ban by
                // waiting for the next window. Only expired bans are cleared.
                if now >= entry.blocked_until {
                    entry.blocked_until = 0;
                }
            }
            let retry_after = if rule.mitigation_secs > 0 {
                rule.mitigation_secs
            } else {
                (window + 1) * rule.period_secs - now
            };
            if now < entry.blocked_until {
                drop(entry);
                let tripped = rate_tripped(rule, retry_after);
                match rule.action {
                    RateAction::Log => logged.push(tripped),
                    _ => {
                        return RateOutcome {
                            deny: Some(tripped),
                            logged,
                        };
                    },
                }
                continue;
            }
            entry.count = entry.count.saturating_add(1);
            entry.expires_at =
                (window + 1) * rule.period_secs + rule.mitigation_secs;
            if entry.count > rule.threshold {
                if rule.mitigation_secs > 0 {
                    entry.blocked_until = now + rule.mitigation_secs;
                }
                drop(entry);
                let tripped = rate_tripped(rule, retry_after);
                match rule.action {
                    RateAction::Log => logged.push(tripped),
                    _ => {
                        return RateOutcome {
                            deny: Some(tripped),
                            logged,
                        };
                    },
                }
            }
        }
        RateOutcome { deny: None, logged }
    }
}

/// Owned per-request data rule expressions evaluate against: the
/// [`EvalContext`] borrows from this state plus the request data.
struct ExpressionState {
    full_uri: String,
    cookies: Vec<(String, String)>,
}

impl ExpressionState {
    fn build(request_data: &RequestData) -> Self {
        let full_uri = if request_data.query.is_empty() {
            request_data.path.clone()
        } else {
            format!("{}?{}", request_data.path, request_data.query)
        };
        Self {
            full_uri,
            cookies: parse_cookies(&request_data.headers),
        }
    }

    fn eval<'a>(
        &'a self,
        request_data: &'a RequestData,
        host: &'a str,
        parsed_ip: Option<IpAddr>,
    ) -> EvalContext<'a> {
        let user_agent = request_data
            .headers
            .iter()
            .find(|(k, _)| k == "user-agent")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        EvalContext {
            method: &request_data.method,
            path: &request_data.path,
            full_uri: &self.full_uri,
            host,
            user_agent,
            body: None,
            headers: &request_data.headers,
            cookies: &self.cookies,
            client_ip: &request_data.client_ip,
            parsed_ip,
            country_code: request_data.country_code.as_deref(),
            ssl: request_data.scheme.eq_ignore_ascii_case("https"),
            waf_score: 0,
            waf_score_sqli: 0,
            waf_score_xss: 0,
            waf_score_rce: 0,
        }
    }
}

/// Parses the `Cookie` header into name/value pairs.
fn parse_cookies(headers: &[(String, String)]) -> Vec<(String, String)> {
    let Some(raw) = headers
        .iter()
        .find(|(k, _)| k == "cookie")
        .map(|(_, v)| v.as_str())
    else {
        return Vec::new();
    };
    raw.split(';')
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

/// Extracts the clearance cookie value, if the client carries one.
fn clearance_cookie(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k == "cookie")
        .and_then(|(_, v)| {
            v.split(';').find_map(|pair| {
                let (name, value) = pair.trim().split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case(CLEARANCE_COOKIE_NAME)
                    .then(|| value.trim().to_string())
            })
        })
}

/// Clearance cookie manager of the challenge system, cached against the agent
/// cache dir it was resolved from so a rebuilt or replaced agent re-resolves
/// its secret instead of reusing a stale one. Holding the constructed manager
/// spares the hot path an HMAC key setup per validated request.
static CLEARANCE_MANAGER: RwLock<Option<(PathBuf, CookieManager)>> =
    RwLock::new(None);

/// Whether `value` (when present) is a valid clearance cookie issued for
/// `site_id`. A client that solved a site's challenge once is exempt from
/// that site's challenge-type actions; the cookie's embedded site id must
/// match so a clearance earned on one site cannot be replayed against
/// another. Standalone (no agent) has no shared secret to verify against
/// and stays exempt-free.
fn clearance_valid(value: Option<String>, site_id: &str) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(agent) = PingWafAgent::instance() else {
        return false;
    };
    let secret_path =
        Path::new(&agent.config.cache_dir).join("challenge_cookie_secret");
    {
        let cached =
            CLEARANCE_MANAGER.read().unwrap_or_else(|e| e.into_inner());
        if let Some((path, manager)) = cached.as_ref()
            && *path == secret_path
        {
            return manager
                .validate_clearance(&value)
                .is_ok_and(|payload| payload.site_id == site_id);
        }
    }
    let secret = resolve_cookie_secret("");
    let manager = CookieManager::new(secret.as_bytes(), 3600);
    let valid = manager
        .validate_clearance(&value)
        .is_ok_and(|payload| payload.site_id == site_id);
    *CLEARANCE_MANAGER.write().unwrap_or_else(|e| e.into_inner()) =
        Some((secret_path, manager));
    valid
}

// ─────────────────────────────────────────────────────────────
// Pending access log store
// ─────────────────────────────────────────────────────────────

/// Request facts captured before inspection and held until the response
/// (and, when captured, its body) allows the access log to be emitted.
struct PendingAccess {
    site_id: String,
    client_ip: String,
    method: String,
    scheme: String,
    protocol: String,
    host: String,
    path: String,
    query: String,
    user_agent: String,
    referer: String,
    tls_version: String,
    country_code: String,
    request_headers: Vec<(String, String)>,
    request_body: Option<Vec<u8>>,
    request_body_size: u64,
    request_body_truncated: bool,
    /// Body bytes the log keeps per direction, resolved from the agent
    /// config when the request arrived. 0 disables body capture.
    body_limit: usize,
    /// Response facts, present once `handle_response` held the entry back
    /// for body capture.
    response: Option<ResponseFacts>,
    start: Instant,
}

/// Response facts gathered before the access entry is emitted.
struct ResponseFacts {
    status_code: u32,
    upstream_addr: String,
    upstream_latency_ms: u64,
    headers: Vec<(String, String)>,
    /// Prefix kept for the log; `None` when body capture was skipped.
    body: Option<Vec<u8>>,
    /// Body bytes seen while streaming, or the announced content length when
    /// capture was skipped.
    body_size: u64,
    /// Content length announced by the response headers. Fallback for
    /// `body_size` when the body streamed no bytes (HEAD, 204/304, entries
    /// swept before the body filter ran).
    announced: u64,
    /// Whether the body prefix is worth keeping for the log, resolved once
    /// at the header phase. Byte counting is unconditional; this only gates
    /// storing body content.
    capture_body: bool,
    /// The stream never finished; whatever arrived is all there was to log.
    abandoned: bool,
    /// pingora cache phase for this response (`hit`/`miss`/…); empty when
    /// caching was not in play (plugin-generated answers, cache disabled).
    cache_status: String,
}

impl ResponseFacts {
    /// Facts for a response the plugin generated itself (block page,
    /// challenge, rate limit); no upstream and no captured body.
    fn generated(status_code: u32) -> Self {
        Self {
            status_code,
            upstream_addr: String::new(),
            upstream_latency_ms: 0,
            headers: Vec::new(),
            body: None,
            body_size: 0,
            announced: 0,
            capture_body: false,
            abandoned: false,
            // A plugin-generated answer never consulted the cache.
            cache_status: String::new(),
        }
    }

    /// Facts for a response the plugin answers with, taken from the response
    /// itself: a blocked request is then as replayable in the log as a
    /// proxied one. The body is kept up to `limit` bytes.
    fn from_generated(response: &HttpResponse, limit: usize) -> Self {
        let mut facts = Self::generated(response.status.as_u16() as u32);
        facts.headers =
            cap_headers(response.headers.iter().flatten().filter_map(
                |(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value))
                },
            ));
        facts.absorb(&response.body, limit);
        facts
    }

    /// Absorbs one streamed chunk, keeping at most `limit` bytes.
    fn absorb(&mut self, chunk: &[u8], limit: usize) {
        self.body_size += chunk.len() as u64;
        if limit == 0 {
            return;
        }
        let buf = self
            .body
            .get_or_insert_with(|| Vec::with_capacity(chunk.len().min(limit)));
        if buf.len() < limit {
            let room = limit - buf.len();
            buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
    }

    /// Whether the kept prefix is shorter than the body it came from.
    fn truncated(&self) -> bool {
        self.abandoned
            || self
                .body
                .as_ref()
                .is_some_and(|body| (body.len() as u64) < self.body_size)
    }
}

/// Hard ceiling for the configured per-entry body capture, so a bad value
/// cannot turn the log store into a bandwidth sink.
const MAX_LOG_BODY_LIMIT: usize = 64 * 1024;

/// Upper bounds for the header snapshot kept per access log entry.
const MAX_LOG_HEADERS: usize = 64;
const MAX_LOG_HEADERS_BYTES: usize = 8 * 1024;

/// Caps the header snapshot kept for logging so a pathological exchange
/// cannot bloat the log store: at most [`MAX_LOG_HEADERS`] entries totalling
/// at most [`MAX_LOG_HEADERS_BYTES`] bytes. Values are stored verbatim —
/// including cookies and credentials — because incident response needs to
/// replay traffic (see the security note in `docs/api.md`).
fn cap_headers<'a>(
    headers: impl Iterator<Item = (String, &'a str)>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut total = 0usize;
    for (name, value) in headers.take(MAX_LOG_HEADERS) {
        total += name.len() + value.len();
        if total > MAX_LOG_HEADERS_BYTES {
            break;
        }
        out.push((name, value.to_string()));
    }
    out
}

/// Accumulates the request-body prefix kept for logging: at most `limit`
/// bytes plus a flag telling whether the kept prefix is shorter than the
/// body the data plane read. The full byte count is tracked regardless of
/// the limit, so the log can report the real size even when truncated.
struct LogBodyPrefix {
    limit: usize,
    body: Option<Vec<u8>>,
    size: u64,
    truncated: bool,
}

impl LogBodyPrefix {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            body: None,
            size: 0,
            truncated: false,
        }
    }

    fn absorb(&mut self, chunk: &[u8]) {
        self.size += chunk.len() as u64;
        if self.limit == 0 {
            return;
        }
        let buf = self.body.get_or_insert_with(|| {
            Vec::with_capacity(chunk.len().min(self.limit))
        });
        // Overshoot is allowed here so a body of exactly `limit` bytes stays
        // untruncated; `finish` trims and flags afterwards.
        if buf.len() <= self.limit {
            buf.extend_from_slice(chunk);
        }
    }

    fn finish(mut self) -> (Option<Vec<u8>>, u64, bool) {
        if let Some(buf) = self.body.as_mut()
            && buf.len() > self.limit
        {
            buf.truncate(self.limit);
            self.truncated = true;
        }
        (self.body, self.size, self.truncated)
    }
}

/// How long a request may sit between `handle_request` and the end of its
/// response body before the pending entry counts as abandoned.
pub const PENDING_ACCESS_SWEEP_TTL: Duration = Duration::from_secs(45);
/// Orphaned entries (e.g. upstream connect failures that bypass
/// `handle_response`) are evicted once they outlive this window.
const PENDING_ACCESS_TTL: Duration = Duration::from_secs(60);

/// Default edge refusal window after a WAF block verdict: repeat requests
/// from the same client are dropped before the engine runs again.
const WAF_AUTO_BLOCK_SECS: u64 = 600;

/// Only pay for garbage collection above this many outstanding entries.
const PENDING_ACCESS_GC_THRESHOLD: usize = 65536;

static PENDING_ACCESS: LazyLock<DashMap<String, PendingAccess>> =
    LazyLock::new(DashMap::new);

fn register_pending_access(request_id: &str, pending: PendingAccess) {
    if PENDING_ACCESS.len() > PENDING_ACCESS_GC_THRESHOLD {
        PENDING_ACCESS.retain(|_, v| v.start.elapsed() < PENDING_ACCESS_TTL);
    }
    PENDING_ACCESS.insert(request_id.to_string(), pending);
}

/// Backfills the request-body facts of a pending access entry once the
/// request-body filter has seen the body. A no-op when the entry is gone
/// (the request was already answered or swept).
fn amend_pending_access_body(
    request_id: &str,
    body: Option<Vec<u8>>,
    size: u64,
    truncated: bool,
) {
    if let Some(mut entry) = PENDING_ACCESS.get_mut(request_id) {
        entry.request_body = body;
        entry.request_body_size = size;
        entry.request_body_truncated = truncated;
    }
}

/// What a completed (or capped) body inspection concluded, shared by the
/// request phase and the request-body filter.
enum VerdictOutcome {
    /// No engine ran for this request; proxying continues untouched.
    Skipped,
    /// The request passed (or the verdict was only recorded); proxying
    /// continues.
    Continue,
    /// The plugin answers the request itself (block or challenge page).
    Respond(HttpResponse),
}

/// The verdict context a deferred body needs once its bytes are complete:
/// snapshotted in the request phase, consumed by the request-body filter.
struct DeferredVerdict {
    choice: EngineChoice,
    context: Option<Arc<SiteContext>>,
    observe: bool,
    site_id: String,
    host: String,
    request_data: RequestData,
}

/// Per-request body staging: chunks the request-body filter withholds
/// from the upstream until the client is done, so the engine can inspect
/// the complete body before a single byte reaches the source. Entries
/// live in `DEFERRED_BODY` keyed by request id, are removed on completion
/// and swept when a request dies mid-exchange.
struct DeferredBody {
    /// Bytes withheld from the upstream so far.
    buffer: BytesMut,
    /// Once the staged body passed the inspection cap the rest flows
    /// upstream untouched (only the prefix is inspected) — the old retry
    /// buffer silently lost those bytes instead.
    passthrough: bool,
    /// Whether the engine runs on this body at completion; `false` for
    /// log-capture-only requests.
    inspect: bool,
    /// Access-log body prefix capture.
    log_prefix: LogBodyPrefix,
    /// `Some` for inspect entries: everything the completion-time verdict
    /// needs, snapshotted in the request phase.
    deferred: Option<DeferredVerdict>,
    created_at: Instant,
}

static DEFERRED_BODY: LazyLock<DashMap<String, DeferredBody>> =
    LazyLock::new(DashMap::new);

/// Decides what happens to one streaming body chunk. Pure so the staging
/// state machine is unit-testable without a proxy session.
///
/// * `Withhold` — the chunk was absorbed into `buffer` and must not reach
///   the upstream: the caller replaces the outgoing body with an empty
///   chunk (pingora skips empty chunks entirely — never `None`, which
///   signals end of body and would truncate the upstream request).
/// * `Flush(bytes)` — the cap was hit with this chunk: inspect `buffer`
///   (now holding the prefix plus this chunk) once, then hand these bytes
///   upstream and let the rest through.
/// * `PassThrough` — staging is off (log-capture-only entry, or already
///   past the cap): leave the chunk as-is.
fn stage_chunk(
    cap: usize,
    inspect: bool,
    passthrough: &mut bool,
    buffer: &mut BytesMut,
    chunk: Option<&[u8]>,
) -> StageAction {
    if !inspect || *passthrough {
        return StageAction::PassThrough;
    }
    if let Some(chunk) = chunk {
        buffer.extend_from_slice(chunk);
    }
    if buffer.len() > cap {
        *passthrough = true;
        StageAction::Flush(std::mem::take(buffer).freeze())
    } else {
        StageAction::Withhold
    }
}

/// The per-chunk decision [`stage_chunk`] returns.
enum StageAction {
    Withhold,
    Flush(Bytes),
    PassThrough,
}

/// Ships, or drops, entries whose exchange never completed: a client that
/// vanished mid-body (or an upstream that died before responding) would
/// otherwise leave its entry behind forever. Entries that already hold
/// response facts are logged with what arrived; the rest are dropped. Runs
/// off the data plane's periodic task.
pub fn sweep_stale_access(ttl: Duration) -> usize {
    let expired: Vec<String> = PENDING_ACCESS
        .iter()
        .filter(|entry| entry.value().start.elapsed() >= ttl)
        .map(|entry| entry.key().clone())
        .collect();
    let agent = PingWafAgent::instance();
    let mut swept = 0;
    for request_id in expired {
        let Some((_, mut pending)) = PENDING_ACCESS.remove(&request_id) else {
            continue;
        };
        swept += 1;
        let Some(agent) = agent.as_ref() else {
            continue;
        };
        if let Some(mut facts) = pending.response.take() {
            facts.abandoned = true;
            emit_access(agent, &request_id, pending, facts);
        }
    }
    // Body-staging entries abandoned mid-exchange — a client that vanished
    // while sending, or an upstream that answered before the body was fully
    // read — hold staged bytes hostage. Drop them on the same window.
    let before = DEFERRED_BODY.len();
    DEFERRED_BODY.retain(|_, v| v.created_at.elapsed() < ttl);
    swept + (before - DEFERRED_BODY.len())
}

/// Emit an access log entry, either when the response is complete or
/// immediately for plugin-generated responses (which never reach
/// `handle_response`).
fn emit_access(
    agent: &PingWafAgent,
    request_id: &str,
    pending: PendingAccess,
    response: ResponseFacts,
) {
    let total_latency_ms = pending.start.elapsed().as_millis() as u64;
    let response_body_truncated = response.truncated();
    // Streaming counts the real bytes; the announced content length only
    // fills in when nothing streamed (HEAD, 204/304, swept entries).
    let response_size = if response.body_size > 0 {
        response.body_size
    } else {
        response.announced
    };
    agent.log_access(AccessLogEntry {
        site_id: pending.site_id,
        request_id: request_id.to_string(),
        client_ip: pending.client_ip,
        method: pending.method,
        scheme: pending.scheme,
        host: pending.host,
        path: pending.path,
        query_string: pending.query,
        protocol: pending.protocol,
        status_code: response.status_code,
        response_size,
        upstream_addr: response.upstream_addr,
        upstream_latency_ms: response.upstream_latency_ms,
        total_latency_ms,
        cache_status: response.cache_status.clone(),
        user_agent: pending.user_agent,
        referer: pending.referer,
        tls_version: pending.tls_version,
        country_code: pending.country_code,
        request_headers: pending.request_headers,
        request_body: pending.request_body,
        request_body_size: pending.request_body_size,
        request_body_truncated: pending.request_body_truncated,
        response_headers: response.headers,
        response_body: response.body,
        response_body_size: response_size,
        response_body_truncated,
    });
}

/// Emits the access entry for a response the plugin answers with itself. The
/// entry records what the client is about to receive — status, headers and
/// truncated body — so a blocked or challenged request is as replayable in
/// the log as a proxied one.
fn emit_generated_access(
    agent: Option<&Arc<PingWafAgent>>,
    request_id: &str,
    response: &HttpResponse,
) {
    let Some(agent) = agent else {
        return;
    };
    let Some((_, pending)) = PENDING_ACCESS.remove(request_id) else {
        return;
    };
    let limit = pending.body_limit;
    emit_access(
        agent,
        request_id,
        pending,
        ResponseFacts::from_generated(response, limit),
    );
}

/// Content types whose bodies are text-like and thus worth storing.
fn is_textual_content_type(value: &str) -> bool {
    let mime = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime.starts_with("text/")
        || matches!(
            mime.as_str(),
            "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/x-www-form-urlencoded"
        )
        || mime.ends_with("+json")
        || mime.ends_with("+xml")
}

/// Whether the response body should be captured for the access log. Capture
/// is skipped when the outcome is knowable from the headers alone (HEAD,
/// bodyless statuses) or the bytes would not be replayable text (compressed
/// or binary payloads).
fn should_capture_response_body(
    method: &str,
    status: u16,
    response: &pingora::http::ResponseHeader,
) -> bool {
    if method == "HEAD" || status < 200 || status == 204 || status == 304 {
        return false;
    }
    if let Some(encoding) = response
        .headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        && !encoding.is_empty()
        && !encoding.eq_ignore_ascii_case("identity")
    {
        return false;
    }
    if let Some(length) = response
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        && length == 0
    {
        return false;
    }
    match response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => is_textual_content_type(value),
        // Unknown payload: capture, best effort.
        None => true,
    }
}

/// The response's announced body size, used when the body itself was not
/// captured.
fn announced_body_size(response: &pingora::http::ResponseHeader) -> u64 {
    response
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Body bytes kept per access log entry per direction, resolved from the
/// agent config; capped so a misconfiguration cannot bloat the log store.
fn log_body_limit() -> usize {
    PingWafAgent::instance()
        .map(|agent| agent.config.max_body_log_size.min(MAX_LOG_BODY_LIMIT))
        .unwrap_or(0)
}

/// Web Application Firewall plugin.
pub struct WafPlugin {
    plugin_step: PluginStep,
    /// Locally configured engine; shared and hot-reloadable.
    engine: Arc<RwLock<WafEngine>>,
    mode: WafMode,
    // TODO: parsed from config but not yet wired into WafEngine (detections/
    // ml_enabled/ml_threshold are currently ignored at runtime)
    #[allow(dead_code)]
    paranoia_level: u8,
    #[allow(dead_code)]
    anomaly_threshold: u32,
    #[allow(dead_code)]
    detections: Vec<String>,
    #[allow(dead_code)]
    ml_enabled: bool,
    #[allow(dead_code)]
    ml_threshold: f64,
    /// Inspect the full request body with the WAF engine. Off by default:
    /// scanning arbitrary bodies is expensive. Independent of this flag the
    /// first KiB of every body is captured for the access log.
    inspect_body: bool,
    max_body_size: usize,
    /// Proof-of-work difficulty used when delegating a `Challenge` verdict.
    pow_difficulty: u32,
    hash_value: String,
    /// Per-domain engines built from agent rules, keyed by host.
    site_contexts: DashMap<String, CachedSite>,
    /// Rate limit counters, keyed by rule id and characteristic values. Kept
    /// on the plugin so they survive per-site context rebuilds.
    rate_counters: DashMap<String, RateCounter>,
}

fn parse_mode(value: &str) -> WafMode {
    match value.to_lowercase().as_str() {
        "off" => WafMode::Off,
        "monitor" => WafMode::Monitor,
        "block" => WafMode::Block,
        // Fail close on a typo, but say so: a silently-blocking unknown
        // value looks like the site enforcing rules nobody configured.
        _ => {
            warn!(
                value = %value,
                "unknown waf plugin mode; enforcing as block"
            );
            WafMode::Block
        },
    }
}

fn action_str(action: &WafAction) -> &'static str {
    match action {
        WafAction::Pass => "pass",
        WafAction::Monitor => "monitor",
        WafAction::Block => "block",
        WafAction::Challenge => "challenge",
    }
}

/// Parses a site monitor list for attack categories; unknown names are
/// ignored with a warning so a stale control-plane value can never silently
/// re-enable enforcement of a category the operator turned off.
fn parse_monitor_categories(names: &[String]) -> CategorySet {
    let mut set = CategorySet::EMPTY;
    for name in names {
        match CategorySet::parse_name(name) {
            Some(category) => set = set.union(category),
            None => warn!(name = %name, "unknown monitor category; ignoring"),
        }
    }
    set
}

/// Parses a site monitor list for backend stacks. Starts from the empty set
/// (unlike [`StackSet::from_names`], which always includes GENERIC) because
/// language-agnostic detection must not be downgradable via stack switches.
fn parse_monitor_stacks(names: &[String]) -> StackSet {
    let mut set = StackSet::EMPTY;
    for name in names {
        match StackSet::parse_name(name) {
            Some(stack) => set = set.union(stack),
            None => warn!(name = %name, "unknown monitor stack; ignoring"),
        }
    }
    set
}

/// Parses a per-rule managed monitor list; unknown ids are ignored with a
/// warning (the rule may have been removed from the engine since the setting
/// was written).
fn parse_monitor_managed_rules(names: &[String]) -> HashSet<String> {
    let known = pingwaf_waf::MANAGED_RULE_IDS
        .iter()
        .copied()
        .collect::<HashSet<&str>>();
    names
        .iter()
        .filter(|id| {
            let keep = known.contains(id.as_str());
            if !keep {
                warn!(id = %id, "unknown managed rule id; ignoring");
            }
            keep
        })
        .cloned()
        .collect()
}

/// Build a [`WafEngine`] from control-plane site WAF config.
fn build_site_engine(cfg: &CacheWafConfig) -> WafEngine {
    let mode = match cfg.mode {
        CacheWafMode::Off => WafMode::Off,
        CacheWafMode::Monitor => WafMode::Monitor,
        CacheWafMode::Block => WafMode::Block,
    };
    // Per-rule monitor downgrade: a custom rule whose mode is monitor (or
    // off, which is treated the same — detected and logged, never enforced)
    // feeds the score and the event log but never carries its action. The
    // site-level engine mode stays the master switch on top of this.
    let monitor_custom_rules: std::collections::HashSet<String> = cfg
        .custom_rules
        .iter()
        .filter(|r| r.enabled && r.mode != CacheWafMode::Block)
        .map(|r| r.id.clone())
        .collect();
    let rules: Vec<CompiledRule> = cfg
        .custom_rules
        .iter()
        .filter(|r| r.enabled)
        .filter_map(|r| {
            let action = match r.action {
                CacheWafAction::Block => RuleAction::Block,
                CacheWafAction::Log => RuleAction::Log,
                CacheWafAction::Challenge => RuleAction::Challenge,
                CacheWafAction::JsChallenge => RuleAction::JsChallenge,
                CacheWafAction::Allow => RuleAction::Allow,
                // Not a custom-rule action; the control plane never sends
                // one, so the rule is dropped instead of guessed at.
                CacheWafAction::BasicAuth => {
                    warn!(
                        rule = %r.id,
                        "custom rule carries a non-rule action; rule skipped"
                    );
                    return None;
                },
            };
            CompiledRule::compile(
                r.id.clone(),
                r.name.clone(),
                &r.expression,
                action,
                r.severity as u8,
                r.tags.clone(),
            )
            .ok()
        })
        .collect();

    let engine_config = WafEngineConfig {
        mode,
        // Advanced mode turns on the strict rule set; a site without the
        // switch keeps the default level.
        level: if cfg.advanced_mode {
            WafLevel::Strict
        } else {
            WafLevel::default()
        },
        stacks: StackSet::default(),
        monitor_categories: parse_monitor_categories(&cfg.monitor_categories),
        monitor_stacks: parse_monitor_stacks(&cfg.monitor_stacks),
        monitor_managed_rules: parse_monitor_managed_rules(
            &cfg.monitor_managed_rules,
        ),
        monitor_custom_rules,
        threshold: if cfg.anomaly_threshold > 0 {
            cfg.anomaly_threshold
        } else {
            40
        },
        paranoia_level: (cfg.paranoia_level as u8).clamp(1, 4),
        max_decode_layers: 3,
        rules,
        enable_managed_rules: true,
        fast_path_block_on_critical: true,
    };
    WafEngine::new(&engine_config)
}

impl WafPlugin {
    /// Create a new plugin from configuration.
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new waf plugin");
        // Load the embedded GeoIP database here rather than on the first
        // request: the lookup is on the request path and its parse is not.
        LazyLock::force(&GEO_DB);
        Self::try_from(params)
    }

    /// Resolve the site data for `host`, consulting the agent rule cache when
    /// available and caching compiled contexts per domain.
    fn resolve_site(&self, host: &str) -> ResolvedSite {
        let Some(agent) = PingWafAgent::instance() else {
            // Standalone mode has no control plane to lose: the locally
            // configured engine always serves.
            return ResolvedSite {
                choice: EngineChoice::Base,
                site_id: host.to_string(),
                context: None,
            };
        };
        let fallback = |host: String| {
            // Without synced rules the request would be proxied by the base
            // engine alone. An edge that must fail closed refuses instead;
            // the decision is the site's own failover policy when the
            // registry knows the domain, else the control-plane-wide
            // default from the last sync, else the agent's local
            // `--fail-open` setting. A connected agent always keeps
            // serving, whatever the policies say.
            let choice =
                if agent.is_connected() || agent.effective_fail_open(&host) {
                    EngineChoice::Base
                } else {
                    EngineChoice::FailClosed
                };
            // The host no longer resolves in the cache (deleted or renamed
            // site): drop any compiled context so the per-domain cache
            // cannot grow without bound across config churn.
            self.site_contexts.remove(&host);
            ResolvedSite {
                choice,
                site_id: host,
                context: None,
            }
        };
        if host.is_empty() {
            return fallback(String::new());
        }
        let Some(site_rules) = agent.get_rules_for_domain(host) else {
            return fallback(host.to_string());
        };

        let fingerprint = agent.config_hash();
        let cached = self.site_contexts.get(host).map(|cached| {
            (cached.fingerprint.clone(), Arc::clone(&cached.context))
        });
        let context = match cached {
            Some((cached_fingerprint, context))
                if cached_fingerprint == fingerprint =>
            {
                context
            },
            _ => {
                let context = Arc::new(SiteContext::build(&site_rules));
                self.site_contexts.insert(
                    host.to_string(),
                    CachedSite {
                        fingerprint,
                        context: Arc::clone(&context),
                    },
                );
                context
            },
        };

        let choice = context.choice(&site_rules);
        ResolvedSite {
            choice,
            site_id: site_rules.site_id.clone(),
            context: Some(context),
        }
    }

    /// Which protection produced an engine-verdict event. Managed rules keep
    /// their own type so the dashboard can deep-link the built-in catalogue;
    /// every other engine hit is a site (custom) rule.
    fn engine_event_type(verdict: &WafVerdict) -> &'static str {
        match verdict.matched_rules.first() {
            Some(id) if id.starts_with("PINGWAF-") => "managed",
            _ => "waf",
        }
    }

    /// Ship a security event to the control plane (best effort, non-blocking).
    fn log_event(
        site_id: &str,
        request_id: &str,
        host: &str,
        request_data: &RequestData,
        verdict: &WafVerdict,
        rule_name: &str,
        event_type: &str,
    ) {
        let Some(agent) = PingWafAgent::instance() else {
            return;
        };
        let blocked =
            matches!(verdict.action, WafAction::Block | WafAction::Challenge);
        agent.record_request(blocked);
        let user_agent = request_data
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let response_status = match verdict.action {
            WafAction::Block => 403,
            WafAction::Challenge => 503,
            _ => 0,
        };
        agent.log_security_event(SecurityEvent {
            site_id: site_id.to_string(),
            request_id: request_id.to_string(),
            client_ip: request_data.client_ip.clone(),
            method: request_data.method.clone(),
            scheme: request_data.scheme.clone(),
            protocol: request_data.protocol.clone(),
            host: host.to_string(),
            path: request_data.path.clone(),
            query_string: request_data.query.clone(),
            rule_id: verdict.matched_rules.first().cloned().unwrap_or_default(),
            rule_name: rule_name.to_string(),
            event_type: event_type.to_string(),
            action: action_str(&verdict.action).to_string(),
            score: verdict.score as u32,
            details: verdict.details.clone(),
            response_status,
            user_agent,
            country_code: request_data.country_code.clone().unwrap_or_default(),
            matched_tags: verdict.matched_rules.clone(),
        });
    }

    /// Records an access restriction (IP/geo rule, bot or rate limit) that
    /// observation mode refused to enforce. The security event is written as a
    /// `monitor` verdict — nothing was actually blocked or challenged — while
    /// the server log names what enforcement would have done.
    #[allow(clippy::too_many_arguments)]
    fn log_observed(
        site_id: &str,
        request_id: &str,
        host: &str,
        request_data: &RequestData,
        would_have: WafAction,
        rule_id: &str,
        detail: &str,
        rule_name: &str,
        event_type: &str,
    ) {
        tracing::info!(
            site_id,
            request_id,
            rule = rule_id,
            would_have = ?would_have,
            "[observation] detection recorded without enforcing"
        );
        let verdict = WafVerdict {
            action: WafAction::Monitor,
            score: 0,
            matched_rules: (!rule_id.is_empty())
                .then(|| rule_id.to_string())
                .into_iter()
                .collect(),
            details: detail.to_string(),
            breakdown: ScoreBreakdown::clean(),
        };
        Self::log_event(
            site_id,
            request_id,
            host,
            request_data,
            &verdict,
            rule_name,
            event_type,
        );
    }

    /// Reports a fail-closed refusal. No rule produced this decision — the
    /// edge simply cannot protect the site without its control plane — so
    /// the event is written directly instead of through the verdict
    /// pipeline.
    fn log_fail_closed(
        agent: &PingWafAgent,
        site_id: &str,
        request_id: &str,
        host: &str,
        request_data: &RequestData,
    ) {
        agent.record_request(true);
        agent.log_security_event(SecurityEvent {
            site_id: site_id.to_string(),
            request_id: request_id.to_string(),
            client_ip: request_data.client_ip.clone(),
            method: request_data.method.clone(),
            scheme: request_data.scheme.clone(),
            protocol: request_data.protocol.clone(),
            host: host.to_string(),
            path: request_data.path.clone(),
            query_string: request_data.query.clone(),
            rule_id: String::new(),
            rule_name: String::new(),
            event_type: "fail_closed".to_string(),
            action: "block".to_string(),
            score: 0,
            details: "control plane unreachable and fail_open is disabled"
                .to_string(),
            response_status: 503,
            user_agent: request_data
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            country_code: request_data.country_code.clone().unwrap_or_default(),
            matched_tags: Vec::new(),
        });
    }

    /// Answers a request stopped by an access restriction: security event,
    /// access log with the real status, then the block page or the challenge.
    #[allow(clippy::too_many_arguments)]
    fn deny_request(
        agent: Option<&Arc<PingWafAgent>>,
        site_id: &str,
        request_id: &str,
        host: &str,
        request_data: &RequestData,
        denial: &Denial,
        original_url: &str,
        pow_difficulty: u32,
        event_type: &str,
    ) -> RequestPluginResult {
        let verdict = WafVerdict {
            action: if denial.challenge {
                WafAction::Challenge
            } else {
                WafAction::Block
            },
            score: 0,
            matched_rules: vec![denial.rule_id.clone()],
            details: denial.detail.clone(),
            breakdown: ScoreBreakdown::clean(),
        };
        Self::log_event(
            site_id,
            request_id,
            host,
            request_data,
            &verdict,
            &denial.rule_name,
            event_type,
        );
        let response = if denial.challenge {
            // A client holding a valid clearance for this site already
            // solved its challenge: re-issuing it would loop forever, so
            // let it pass.
            if clearance_valid(clearance_cookie(&request_data.headers), site_id)
            {
                return RequestPluginResult::Continue;
            }
            build_challenge_response(
                request_id,
                original_url,
                site_id,
                pow_difficulty,
                ChallengeKind::Js,
            )
        } else {
            block_page(request_id, &verdict.details)
        };
        emit_generated_access(agent, request_id, &response);
        RequestPluginResult::Respond(response)
    }

    /// Runs the detection engine for an assembled request and maps the
    /// verdict onto proxy behaviour. Shared by the request phase (headers
    /// only — the body has not arrived yet) and the request-body filter
    /// (complete body, or the staged prefix of an over-cap body).
    #[allow(clippy::too_many_arguments)]
    fn enforce_verdict(
        &self,
        agent: Option<&Arc<PingWafAgent>>,
        site_id: &str,
        request_id: &str,
        host: &str,
        request_data: &RequestData,
        choice: &EngineChoice,
        context: Option<&Arc<SiteContext>>,
        observe: bool,
    ) -> VerdictOutcome {
        match choice {
            EngineChoice::Disabled => {
                if let Some(agent) = agent {
                    agent.record_request(false);
                }
                return VerdictOutcome::Continue;
            },
            EngineChoice::Base if self.mode == WafMode::Off => {
                if let Some(agent) = agent {
                    agent.record_request(false);
                }
                return VerdictOutcome::Skipped;
            },
            _ => {},
        }
        let verdict = match choice {
            EngineChoice::Site(engine) => engine.inspect(request_data),
            EngineChoice::Base => {
                let guard =
                    self.engine.read().unwrap_or_else(|e| e.into_inner());
                guard.inspect(request_data)
            },
            EngineChoice::Disabled | EngineChoice::FailClosed => {
                unreachable!("handled above")
            },
        };

        // Custom rule ids carry no name of their own; the site context maps
        // the one that fired back to its configured name.
        let rule_name_of = |verdict: &WafVerdict| -> String {
            let Some(id) = verdict.matched_rules.first() else {
                return String::new();
            };
            context
                .and_then(|context| context.rule_names.get(id))
                .cloned()
                .unwrap_or_default()
        };

        if verdict.action == WafAction::Pass {
            if let Some(agent) = agent {
                agent.record_request(false);
            }
            return VerdictOutcome::Continue;
        }

        // Monitor: log the event but let the request through.
        if verdict.action == WafAction::Monitor {
            let rule_name = rule_name_of(&verdict);
            Self::log_event(
                site_id,
                request_id,
                host,
                request_data,
                &verdict,
                &rule_name,
                Self::engine_event_type(&verdict),
            );
            return VerdictOutcome::Continue;
        }

        // Observation mode: a Block/Challenge verdict is recorded as a
        // monitor event — nothing was actually blocked — and the request
        // proceeds.
        if observe {
            let rule_name = rule_name_of(&verdict);
            tracing::info!(
                site_id = %site_id,
                request_id = %request_id,
                path = %request_data.path,
                would_have = ?verdict.action,
                score = verdict.score,
                "[observation] WAF verdict recorded without enforcing"
            );
            let observed = WafVerdict {
                action: WafAction::Monitor,
                ..verdict.clone()
            };
            Self::log_event(
                site_id,
                request_id,
                host,
                request_data,
                &observed,
                &rule_name,
                Self::engine_event_type(&observed),
            );
            return VerdictOutcome::Continue;
        }

        // Block / Challenge: log the security event, then emit the access
        // entry with the real status — a Respond result never reaches
        // handle_response, so this is the only chance to log it.
        let rule_name = rule_name_of(&verdict);
        Self::log_event(
            site_id,
            request_id,
            host,
            request_data,
            &verdict,
            &rule_name,
            Self::engine_event_type(&verdict),
        );
        let response = if verdict.action == WafAction::Block {
            // Auto-block the client for a grace window: repeat requests are
            // refused at the edge (see the entry check above) instead of
            // running the engine every time.
            if let Some(agent) = agent {
                agent.block_ip(
                    site_id,
                    &request_data.client_ip,
                    Some(Duration::from_secs(WAF_AUTO_BLOCK_SECS)),
                    &format!("waf: {rule_name}"),
                );
            }
            block_page(request_id, &verdict.details)
        } else {
            // Challenge verdict. A client that already holds a valid
            // clearance for this site solved its challenge before: issuing
            // the same challenge again would loop forever, so let it
            // through.
            if clearance_valid(clearance_cookie(&request_data.headers), site_id)
            {
                if let Some(agent) = agent {
                    agent.record_request(false);
                }
                return VerdictOutcome::Continue;
            }
            // Challenge verdict — delegate to the challenge subsystem.
            let original_url = if request_data.query.is_empty() {
                request_data.path.clone()
            } else {
                format!("{}?{}", request_data.path, request_data.query)
            };
            build_challenge_response(
                request_id,
                &original_url,
                site_id,
                self.pow_difficulty,
                ChallengeKind::Js,
            )
        };
        emit_generated_access(agent, request_id, &response);
        VerdictOutcome::Respond(response)
    }
}

impl TryFrom<&PluginConf> for WafPlugin {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let category = PluginCategory::Waf.to_string();

        let mode = parse_mode(&get_str_conf(value, "mode"));
        let advanced_mode = get_bool_conf(value, "advanced_mode");
        let level = if advanced_mode {
            WafLevel::Strict
        } else {
            WafLevel::parse(&get_str_conf(value, "level")).unwrap_or_default()
        };
        let stack_names = get_str_slice_conf(value, "stacks");
        let stacks = if stack_names.is_empty() {
            StackSet::default()
        } else {
            StackSet::from_names(stack_names.iter().map(String::as_str))
        };
        let paranoia_level =
            (get_int_conf_or_default(value, "paranoia_level", 2) as u8)
                .clamp(1, 4);
        let anomaly_threshold =
            get_int_conf_or_default(value, "anomaly_threshold", 40) as u32;
        let detections = get_str_slice_conf(value, "detections");
        let monitor_categories = parse_monitor_categories(&get_str_slice_conf(
            value,
            "monitor_categories",
        ));
        let monitor_stacks =
            parse_monitor_stacks(&get_str_slice_conf(value, "monitor_stacks"));
        let monitor_managed_rules = parse_monitor_managed_rules(
            &get_str_slice_conf(value, "monitor_managed_rules"),
        );
        let ml_enabled = get_bool_conf(value, "ml_enabled");
        let ml_threshold = value
            .get("ml_threshold")
            .and_then(|v| v.as_float())
            .unwrap_or(0.5);
        let inspect_body =
            advanced_mode || get_bool_conf(value, "inspect_body");
        let max_body_size =
            get_int_conf_or_default(value, "max_body_size", 64 * 1024) as usize;
        let pow_difficulty =
            get_int_conf_or_default(value, "pow_difficulty", 20) as u32;

        let plugin_step = match super::get_step_conf_in(
            value,
            "waf",
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

        let engine_config = WafEngineConfig {
            mode,
            level,
            stacks,
            monitor_categories,
            monitor_stacks,
            monitor_managed_rules,
            // Standalone mode has no custom rules to downgrade.
            monitor_custom_rules: Default::default(),
            threshold: anomaly_threshold,
            paranoia_level,
            max_decode_layers: 3,
            rules: Vec::new(),
            enable_managed_rules: true,
            fast_path_block_on_critical: true,
        };

        Ok(Self {
            plugin_step,
            engine: Arc::new(RwLock::new(WafEngine::new(&engine_config))),
            mode,
            paranoia_level,
            anomaly_threshold,
            detections,
            ml_enabled,
            ml_threshold,
            inspect_body,
            max_body_size,
            pow_difficulty,
            hash_value,
            site_contexts: DashMap::new(),
            rate_counters: DashMap::new(),
        })
    }
}

#[async_trait]
impl Plugin for WafPlugin {
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

        // ── Extract immutable request facts (all borrowed data is cloned) ──
        let req_header = session.req_header();
        let method = req_header.method.as_str().to_string();
        let path = req_header.uri.path().to_string();
        let query = req_header.uri.query().unwrap_or_default().to_string();
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut user_agent = String::new();
        let mut referer = String::new();
        for (name, value) in req_header.headers.iter() {
            let Ok(v) = value.to_str() else {
                continue;
            };
            match name.as_str() {
                "user-agent" => user_agent = v.to_string(),
                "referer" => referer = v.to_string(),
                _ => {},
            }
            headers.push((name.as_str().to_string(), v.to_string()));
        }
        let host = get_host(req_header).unwrap_or_default().to_string();
        let scheme = if ctx.conn.tls_version.is_some() {
            "https".to_string()
        } else {
            "http".to_string()
        };
        // Matches http::Version's Debug output without the formatting
        // machinery on the hot path.
        let protocol = match req_header.version {
            Version::HTTP_09 => "HTTP/0.9",
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2.0",
            Version::HTTP_3 => "HTTP/3.0",
            // Hidden `__NonExhaustive` variant; never constructible here.
            _ => "HTTP/1.1",
        }
        .to_string();
        // ── Resolve the engine and access restrictions for this domain ──
        // Before the client IP: sites behind a CDN/proxy derive it from a
        // trusted forwarded header instead of the TCP peer, so IP access
        // rules, rate limiting and logs all key on the real visitor address.
        let resolved = self.resolve_site(&host);
        let site_id = resolved.site_id.clone();
        let context = resolved.context.clone();
        let choice = resolved.choice;
        if let Some(ip) = context.as_ref().and_then(|site| {
            site.proxy_trust
                .enabled
                .then(|| {
                    resolve_client_ip_with_trust(session, &site.proxy_trust)
                })
                .flatten()
        }) {
            ctx.conn.client_ip = Some(ip);
        }
        let client_ip = ensure_client_ip(session, ctx).to_string();
        let client_addr: Option<IpAddr> = client_ip.parse().ok();

        // Get or create the request id early so the access log, security
        // events and the X-Request-ID header all share one stable value.
        let request_id = match ctx.state.request_id.clone() {
            Some(id) => id,
            None => {
                let id = generate_request_id();
                ctx.state.request_id = Some(id.clone());
                let _ = session
                    .req_header_mut()
                    .insert_header(&HTTP_HEADER_NAME_X_REQUEST_ID, &id);
                id
            },
        };
        // Observation mode: detections keep running but nothing is enforced.
        // Access control (mTLS, basic auth, a paused site) is never downgraded.
        let observe =
            context.as_ref().is_some_and(|site| site.observation_mode);

        // Country of the client: it feeds geo restrictions, the
        // `ip.src.country` rule variable and the flag shown with the access
        // log, so it is only resolved when an agent consumes those facts.
        let agent = PingWafAgent::instance();
        let country = if agent.is_some() {
            client_addr.and_then(lookup_country_addr)
        } else {
            None
        };

        // ── Full-request log capture and body inspection moved to the
        // request-body filter: body bytes are no longer read here. Reading
        // on the hot path forced pingora's retry buffer (a hard 64 KB cap
        // whose overflow discarded the whole buffered prefix); now the
        // bytes stream through `handle_request_body`, which stages chunks
        // until the client is done, inspects the complete body once, and
        // then either flushes it intact or answers with a block page — a
        // blocked request never exposes a single body byte to the source,
        // and bodies beyond 64 KB forward complete again. This block only
        // snapshots what that stage needs. Requests the plugin answers in
        // the request phase (paused sites, IP/mTLS/access denials) never
        // reach the filter, so their access log carries no body prefix —
        // the refusal reason itself is logged regardless. ──
        let body_limit = log_body_limit();
        let log_headers = cap_headers(
            headers
                .iter()
                .map(|(name, value)| (name.clone(), value.as_str())),
        );
        // Advanced-mode sites ask for body inspection even when the plugin
        // switch is off; the plugin-level switch stays authoritative for the
        // truncation cap.
        let site_inspect_body =
            context.as_ref().is_some_and(|site| site.inspect_body);
        let should_inspect = self.inspect_body || site_inspect_body;
        // Log capture only matters when an agent consumes it; body inspection
        // works standalone — a static deployment blocks POST payloads just
        // the same. Skipped for the challenge verify endpoint, whose handler
        // consumes the body itself, and for requests that cannot carry a
        // body at all (the filter would only ever see the end-of-stream
        // call with no bytes behind it).
        let wants_body = (agent.is_some() && body_limit > 0) || should_inspect;
        let has_body = {
            let headers = &session.req_header().headers;
            headers.contains_key(http::header::TRANSFER_ENCODING.as_str())
                || headers
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_some_and(|len| len > 0)
        };

        // Track the request for access logging until the response phase —
        // including WAF-disabled sites, so traffic data stays complete.
        if agent.is_some() {
            register_pending_access(
                &request_id,
                PendingAccess {
                    site_id: site_id.clone(),
                    client_ip: client_ip.clone(),
                    method: method.clone(),
                    scheme: scheme.clone(),
                    protocol: protocol.clone(),
                    host: host.clone(),
                    path: path.clone(),
                    query: query.clone(),
                    user_agent: user_agent.clone(),
                    referer,
                    tls_version: ctx
                        .conn
                        .tls_version
                        .clone()
                        .unwrap_or_default()
                        .to_string(),
                    country_code: country.clone().unwrap_or_default(),
                    request_headers: log_headers,
                    // The body prefix is backfilled by the request-body
                    // filter (`amend_pending_access_body`) once the bytes
                    // have streamed through it.
                    request_body: None,
                    request_body_size: 0,
                    request_body_truncated: false,
                    body_limit,
                    response: None,
                    start: Instant::now(),
                },
            );
        }

        let request_data = RequestData {
            method,
            path: path.clone(),
            query: query.clone(),
            headers,
            body: None,
            client_ip,
            country_code: country,
            scheme,
            protocol,
        };

        // ── Paused sites answer with a maintenance page before any other
        // rule runs. TLS termination and the log pipeline stay untouched, so
        // the certificate keeps serving and the traffic remains visible. ──
        if context.as_ref().is_some_and(|site| site.paused) {
            let response = paused_page(&request_id);
            emit_generated_access(agent.as_ref(), &request_id, &response);
            return Ok(RequestPluginResult::Respond(response));
        }

        // ── Fail-closed edges: an agent configured with `fail_open = false`
        // that has lost its control plane refuses traffic it has no synced
        // rules for, instead of proxying it unprotected. Like the paused
        // page this keeps TLS and the log pipeline alive, and every refusal
        // is reported as a `fail_closed` security event. ──
        if matches!(choice, EngineChoice::FailClosed) {
            let response = fail_closed_page(&request_id);
            emit_generated_access(agent.as_ref(), &request_id, &response);
            if let Some(agent) = &agent {
                Self::log_fail_closed(
                    agent,
                    &site_id,
                    &request_id,
                    &host,
                    &request_data,
                );
            }
            return Ok(RequestPluginResult::Respond(response));
        }

        // ── Dynamic IP blocks: an IP the edge already refused (an auto-block
        // from an earlier WAF/rate-limit verdict or a server-issued block
        // command) is rejected before any rule runs. Like the paused-site
        // and mTLS denials this enforces an existing decision, so observation
        // mode never downgrades it — with one exception: a WAF auto-block is
        // an artifact of the engine's previous configuration. A site that has
        // since left block mode (monitor/off) or entered observation must not
        // keep refusing clients the engine would no longer block, so those
        // entries are skipped here and cleared on the next config sync.
        // Rate-limit and control-plane blocks keep enforcing regardless.
        // Unknown hosts carry no synced site id and therefore can never match
        // a block. ──
        if !site_id.is_empty()
            && let Some(agent) = &agent
        {
            let waf_blocks_suppressed = observe
                || context.as_ref().is_some_and(|site| {
                    site.waf_mode != Some(CacheWafMode::Block)
                });
            if let Some(reason) =
                agent.blocked_reason(&site_id, &request_data.client_ip)
                && !(waf_blocks_suppressed && reason.starts_with("waf: "))
            {
                let response = block_page(
                    &request_id,
                    "IP temporarily blocked by WAF defense",
                );
                emit_generated_access(Some(agent), &request_id, &response);
                return Ok(RequestPluginResult::Respond(response));
            }
        }

        // ── mTLS: a site that requires a client certificate refuses the
        // request before any other rule runs. Revoked certificates and
        // organization mismatches are refused here too, since the TLS layer
        // only proves the chain is trusted, not which site it was issued for.
        // The denial is logged as access only - it is not a WAF verdict. ──
        if let Some(mtls) = context.as_ref().and_then(|site| site.mtls.as_ref())
            && let Some(reason) = mtls.denial(ctx)
        {
            let response = block_page(&request_id, reason);
            emit_generated_access(agent.as_ref(), &request_id, &response);
            return Ok(RequestPluginResult::Respond(response));
        }

        // ── Access restrictions: IP rules and geo stop a request before the
        // WAF engine runs, and apply whether or not it is enabled. A rule
        // whose action is `basic_auth` is not an outright denial: it feeds
        // the gate below so the request continues once authenticated ──
        let mut access = PolicyOutcome::NoMatch;
        if let Some(site) = &context {
            access = site.policy.evaluate(
                &request_data.client_ip,
                client_addr,
                request_data.country_code.as_deref(),
            );
            if let Some(denial) =
                access.denial().filter(|denial| !denial.basic_auth)
            {
                if observe {
                    Self::log_observed(
                        &site_id,
                        &request_id,
                        &host,
                        &request_data,
                        if denial.challenge {
                            WafAction::Challenge
                        } else {
                            WafAction::Block
                        },
                        &denial.rule_id,
                        &denial.detail,
                        &denial.rule_name,
                        "ip_geo",
                    );
                } else {
                    let original_url = if query.is_empty() {
                        path
                    } else {
                        format!("{path}?{query}")
                    };
                    return Ok(Self::deny_request(
                        agent.as_ref(),
                        &site_id,
                        &request_id,
                        &host,
                        &request_data,
                        denial,
                        &original_url,
                        self.pow_difficulty,
                        "ip_geo",
                    ));
                }
            }
        }

        // ── Basic authentication: the site-wide gate and any access rule
        // with the `basic_auth` action share one credential set. It runs
        // before bot/rate/WAF checks and inside the WAF plugin, which sits
        // ahead of the cache plugin, so neither a cached response nor a
        // later verdict can skip it. An `allow` rule is the one exemption:
        // it means the client is trusted outright ──
        let gate = context.as_ref().and_then(|site| site.basic_auth.as_ref());
        let gate_required = match &access {
            PolicyOutcome::Allowed => false,
            PolicyOutcome::Denied(denial) => denial.basic_auth,
            PolicyOutcome::NoMatch => gate.is_some_and(|gate| gate.site_wide),
        };
        if gate_required {
            let authenticated =
                gate.is_some_and(|gate| gate.verify(&request_data.headers));
            if !authenticated {
                if let Some(delay) = gate.and_then(|gate| gate.delay) {
                    tokio::time::sleep(delay).await;
                }
                let realm = gate
                    .map(|gate| gate.realm.as_str())
                    .unwrap_or(DEFAULT_BASIC_REALM);
                let reason = access
                    .denial()
                    .map(|denial| {
                        format!("{}; authentication required", denial.detail)
                    })
                    .unwrap_or_else(|| {
                        "site-wide basic authentication".to_string()
                    });
                let response = basic_auth_page(&request_id, realm, &reason);
                emit_generated_access(agent.as_ref(), &request_id, &response);
                return Ok(RequestPluginResult::Respond(response));
            }
            if let Some(gate) = gate
                && gate.hide_credentials
            {
                session
                    .req_header_mut()
                    .remove_header(&http::header::AUTHORIZATION);
            }
        }

        // ── Bot protection: UA classification runs after IP/geo and before
        // the engine, applying whether or not the WAF engine is enabled ──
        if let Some(bot) = context.as_ref().and_then(|ctx| ctx.bot.as_ref()) {
            match bot.evaluate(client_addr, &user_agent).await {
                BotDecision::Pass => {},
                BotDecision::Deny(denial) => {
                    if observe {
                        Self::log_observed(
                            &site_id,
                            &request_id,
                            &host,
                            &request_data,
                            if denial.challenge {
                                WafAction::Challenge
                            } else {
                                WafAction::Block
                            },
                            &denial.rule_id,
                            &denial.detail,
                            &denial.rule_name,
                            "bot",
                        );
                    } else {
                        let original_url = if query.is_empty() {
                            path.clone()
                        } else {
                            format!("{path}?{query}")
                        };
                        return Ok(Self::deny_request(
                            agent.as_ref(),
                            &site_id,
                            &request_id,
                            &host,
                            &request_data,
                            &denial,
                            &original_url,
                            self.pow_difficulty,
                            "bot",
                        ));
                    }
                },
                BotDecision::LogOnly(denial) => {
                    let verdict = WafVerdict {
                        action: WafAction::Monitor,
                        score: 0,
                        matched_rules: vec![denial.rule_id.clone()],
                        details: denial.detail.clone(),
                        breakdown: ScoreBreakdown::clean(),
                    };
                    Self::log_event(
                        &site_id,
                        &request_id,
                        &host,
                        &request_data,
                        &verdict,
                        &denial.rule_name,
                        "bot",
                    );
                },
            }
        }

        // ── Rate limiting: fixed-window counters run after IP/geo/bot and
        // before the engine, applying whether or not the WAF engine is
        // enabled ──
        if let Some(rate) =
            context.as_ref().and_then(|c| c.rate_limits.as_ref())
        {
            let cleared =
                rate.rules.iter().any(|r| r.action == RateAction::Challenge)
                    && clearance_valid(
                        clearance_cookie(&request_data.headers),
                        &site_id,
                    );
            let outcome = rate.evaluate(
                &self.rate_counters,
                &request_data,
                &host,
                cleared,
                client_addr,
            );
            for tripped in &outcome.logged {
                let verdict = WafVerdict {
                    action: WafAction::Monitor,
                    score: 0,
                    matched_rules: vec![tripped.rule_id.clone()],
                    details: tripped.detail.clone(),
                    breakdown: ScoreBreakdown::clean(),
                };
                Self::log_event(
                    &site_id,
                    &request_id,
                    &host,
                    &request_data,
                    &verdict,
                    &tripped.rule_name,
                    "rate_limit",
                );
            }
            if let Some(tripped) = outcome.deny {
                if observe {
                    Self::log_observed(
                        &site_id,
                        &request_id,
                        &host,
                        &request_data,
                        if tripped.challenge {
                            WafAction::Challenge
                        } else {
                            WafAction::Block
                        },
                        &tripped.rule_id,
                        &tripped.detail,
                        &tripped.rule_name,
                        "rate_limit",
                    );
                } else {
                    let original_url = if query.is_empty() {
                        path.clone()
                    } else {
                        format!("{path}?{query}")
                    };
                    let verdict = WafVerdict {
                        action: if tripped.challenge {
                            WafAction::Challenge
                        } else {
                            WafAction::Block
                        },
                        score: 0,
                        matched_rules: vec![tripped.rule_id.clone()],
                        details: tripped.detail.clone(),
                        breakdown: ScoreBreakdown::clean(),
                    };
                    Self::log_event(
                        &site_id,
                        &request_id,
                        &host,
                        &request_data,
                        &verdict,
                        &tripped.rule_name,
                        "rate_limit",
                    );
                    // Defense in depth: refuse the client at the edge for the
                    // mitigation window so a repeat offender never reaches
                    // the counters (or the origin) again in that time.
                    if !tripped.challenge
                        && let Some(agent) = &agent
                    {
                        agent.block_ip(
                            &site_id,
                            &request_data.client_ip,
                            Some(Duration::from_secs(tripped.retry_after)),
                            &format!("rate limit: {}", tripped.rule_name),
                        );
                    }
                    let response = if tripped.challenge {
                        build_challenge_response(
                            &request_id,
                            &original_url,
                            &site_id,
                            self.pow_difficulty,
                            ChallengeKind::Js,
                        )
                    } else {
                        rate_limit_page(
                            &request_id,
                            &tripped.detail,
                            tripped.retry_after,
                        )
                    };
                    emit_generated_access(
                        agent.as_ref(),
                        &request_id,
                        &response,
                    );
                    return Ok(RequestPluginResult::Respond(response));
                }
            }
        }

        if matches!(choice, EngineChoice::Disabled) {
            if let Some(agent) = &agent {
                agent.record_request(false);
            }
            return Ok(RequestPluginResult::Continue);
        }
        if matches!(choice, EngineChoice::Base) && self.mode == WafMode::Off {
            if let Some(agent) = &agent {
                agent.record_request(false);
            }
            return Ok(RequestPluginResult::Skipped);
        }

        // ── Inspect ──
        // The request phase sees headers only: the body has not arrived
        // yet — it streams through `handle_request_body`, which re-runs
        // this verdict with the full body once the client is done.
        let outcome = self.enforce_verdict(
            agent.as_ref(),
            &site_id,
            &request_id,
            &host,
            &request_data,
            &choice,
            context.as_ref(),
            observe,
        );
        if let VerdictOutcome::Respond(response) = outcome {
            return Ok(RequestPluginResult::Respond(response));
        }

        // The request is on its way to the upstream: register the body
        // stage so the request-body filter can withhold and inspect the
        // incoming chunks. A request the plugin answered above never
        // reaches the filter and creates no entry.
        if wants_body
            && has_body
            && !(request_data.method == "POST"
                && request_data.path == VERIFY_ENDPOINT)
        {
            let engine_runs = match &choice {
                EngineChoice::Site(_) => true,
                EngineChoice::Base => self.mode != WafMode::Off,
                EngineChoice::Disabled | EngineChoice::FailClosed => false,
            };
            let inspect = should_inspect && engine_runs;
            DEFERRED_BODY.insert(
                request_id.clone(),
                DeferredBody {
                    buffer: BytesMut::new(),
                    passthrough: !inspect,
                    inspect,
                    log_prefix: LogBodyPrefix::new(body_limit),
                    deferred: inspect.then(|| DeferredVerdict {
                        choice: choice.clone(),
                        context: context.clone(),
                        observe,
                        site_id: site_id.clone(),
                        host: host.clone(),
                        request_data: request_data.clone(),
                    }),
                    created_at: Instant::now(),
                },
            );
        }

        Ok(match outcome {
            VerdictOutcome::Continue => RequestPluginResult::Continue,
            VerdictOutcome::Skipped => RequestPluginResult::Skipped,
            VerdictOutcome::Respond(_) => {
                unreachable!("handled above")
            },
        })
    }

    fn handle_request_body(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<Option<HttpResponse>> {
        let Some(request_id) = ctx.state.request_id.clone() else {
            return Ok(None);
        };
        // Take the entry out: every path below either completes it (and
        // leaves it out) or re-inserts it for the next chunk.
        let Some(mut entry) = DEFERRED_BODY.remove(&request_id).map(|e| e.1)
        else {
            return Ok(None);
        };
        if let Some(chunk) = body.as_deref() {
            entry.log_prefix.absorb(chunk);
        }

        if !end_of_stream {
            if let Some(chunk) = body.as_deref() {
                match stage_chunk(
                    self.max_body_size,
                    entry.inspect,
                    &mut entry.passthrough,
                    &mut entry.buffer,
                    Some(chunk),
                ) {
                    StageAction::Withhold => {
                        // An empty chunk: pingora skips it entirely, so
                        // the upstream stays byte-silent and keeps its
                        // end-of-body state. Never `None` — that would
                        // truncate the upstream request.
                        *body = Some(Bytes::new());
                    },
                    StageAction::Flush(staged) => {
                        // The cap was hit mid-body: what is staged (prefix
                        // plus this chunk) is inspected once, here, while
                        // the upstream still has no body byte; the rest of
                        // the body then flows through untouched.
                        if let Some(dv) = entry.deferred.as_mut() {
                            dv.request_data.body = Some(staged.to_vec());
                            let agent = PingWafAgent::instance();
                            let (log_body, log_body_size, log_truncated) =
                                entry.log_prefix.finish();
                            amend_pending_access_body(
                                &request_id,
                                log_body,
                                log_body_size,
                                log_truncated,
                            );
                            let outcome = self.enforce_verdict(
                                agent.as_ref(),
                                &dv.site_id,
                                &request_id,
                                &dv.host,
                                &dv.request_data,
                                &dv.choice,
                                dv.context.as_ref(),
                                dv.observe,
                            );
                            if let VerdictOutcome::Respond(response) = outcome {
                                return Ok(Some(response));
                            }
                            // The verdict passed: hand the staged bytes
                            // over and stop withholding. The entry is done
                            // — its log capture is amended and the rest of
                            // the body flows through — so it is dropped
                            // instead of re-inserted; later chunks (and the
                            // end-of-stream call) find no entry and pass
                            // through untouched.
                            *body = Some(staged);
                            return Ok(None);
                        }
                        // An inspect entry without a verdict snapshot
                        // cannot exist, but fall through to passthrough
                        // semantics if it ever does.
                        entry.passthrough = true;
                    },
                    StageAction::PassThrough => {},
                }
            } else if entry.inspect && !entry.passthrough {
                // A body chunk was expected but nothing arrived; keep
                // staging.
                *body = Some(Bytes::new());
            }
            DEFERRED_BODY.insert(request_id, entry);
            return Ok(None);
        }

        // Completion: the client is done sending. Log capture and — for
        // staged bodies — the full-body verdict run once, then the entry
        // is gone.
        let (log_body, log_body_size, log_body_truncated) =
            entry.log_prefix.finish();
        amend_pending_access_body(
            &request_id,
            log_body,
            log_body_size,
            log_body_truncated,
        );
        if entry.inspect && !entry.passthrough {
            if let Some(chunk) = body.as_deref() {
                entry.buffer.extend_from_slice(chunk);
            }
            let full = std::mem::take(&mut entry.buffer).freeze();
            let agent = PingWafAgent::instance();
            if let Some(dv) = entry.deferred.as_mut() {
                dv.request_data.body = Some(full.to_vec());
                let outcome = self.enforce_verdict(
                    agent.as_ref(),
                    &dv.site_id,
                    &request_id,
                    &dv.host,
                    &dv.request_data,
                    &dv.choice,
                    dv.context.as_ref(),
                    dv.observe,
                );
                // The block page goes back through the proxy; the
                // staged body is dropped with the aborted upstream
                // exchange — the source never saw a byte of it.
                if let VerdictOutcome::Respond(response) = outcome {
                    return Ok(Some(response));
                }
            }
            // Passed: hand the complete body upstream in one write, which
            // also carries the end-of-body flag.
            *body = Some(full);
            return Ok(None);
        }
        // Log-only or already-passthrough entries left the chunk (if any)
        // untouched.
        Ok(None)
    }

    async fn handle_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        let Some(request_id) = ctx.state.request_id.clone() else {
            return Ok(ResponsePluginResult::Unchanged);
        };
        // Without an agent nothing was registered at request time.
        let Some(agent) = PingWafAgent::instance() else {
            return Ok(ResponsePluginResult::Unchanged);
        };
        let status = upstream_response.status.as_u16();
        let upstream_latency_ms =
            ctx.timing.upstream_processing.unwrap_or(0).max(0) as u64;
        // Runs after `handle_cache_headers`, which stamped the same phase
        // into `x-cache-status`: the phase is final here, and this is the
        // only stage where the cache state is reachable (the body stage has
        // no cache accessor).
        let cache_status = if session.cache.enabled() {
            session.cache.phase().as_str().to_string()
        } else {
            String::new()
        };
        let headers = cap_headers(upstream_response.headers.iter().filter_map(
            |(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value))
            },
        ));

        // Body-less responses (204/304, HEAD) never stream: finish them here
        // with the announced content length. Everything else is held until
        // the body phase so the log records the bytes actually sent —
        // chunked responses announce no length at all.
        enum HeaderOutcome {
            /// Entry finished at the header phase; ship these facts now.
            Immediate(ResponseFacts),
            /// Entry held for the body phase to count streamed bytes.
            Held,
        }
        let outcome = {
            let Some(mut entry) = PENDING_ACCESS.get_mut(&request_id) else {
                return Ok(ResponsePluginResult::Unchanged);
            };
            let capture_body = entry.body_limit > 0
                && should_capture_response_body(
                    &entry.method,
                    status,
                    upstream_response,
                );
            let body_less = status == 204
                || status == 304
                || entry.method.eq_ignore_ascii_case("HEAD");
            if body_less {
                HeaderOutcome::Immediate(ResponseFacts {
                    status_code: status as u32,
                    upstream_addr: ctx.upstream.address.clone(),
                    upstream_latency_ms,
                    headers,
                    body: None,
                    body_size: announced_body_size(upstream_response),
                    announced: 0,
                    capture_body: false,
                    abandoned: false,
                    cache_status,
                })
            } else {
                entry.response = Some(ResponseFacts {
                    status_code: status as u32,
                    upstream_addr: ctx.upstream.address.clone(),
                    upstream_latency_ms,
                    headers,
                    body: None,
                    body_size: 0,
                    announced: announced_body_size(upstream_response),
                    capture_body,
                    abandoned: false,
                    cache_status,
                });
                HeaderOutcome::Held
            }
        };
        if let HeaderOutcome::Immediate(facts) = outcome {
            let Some((_, pending)) = PENDING_ACCESS.remove(&request_id) else {
                return Ok(ResponsePluginResult::Unchanged);
            };
            emit_access(&agent, &request_id, pending, facts);
        }
        Ok(ResponsePluginResult::Unchanged)
    }

    fn handle_response_body(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        let Some(request_id) = ctx.state.request_id.clone() else {
            return Ok(ResponseBodyPluginResult::Unchanged);
        };
        if end_of_stream {
            // The response is complete: take the entry and ship it.
            let Some((_, mut pending)) = PENDING_ACCESS.remove(&request_id)
            else {
                return Ok(ResponseBodyPluginResult::Unchanged);
            };
            let Some(agent) = PingWafAgent::instance() else {
                return Ok(ResponseBodyPluginResult::Unchanged);
            };
            let Some(mut facts) = pending.response.take() else {
                return Ok(ResponseBodyPluginResult::Unchanged);
            };
            // Body content is only kept when the header phase deemed it
            // worth capturing; byte counting happens regardless.
            let limit = if facts.capture_body {
                pending.body_limit
            } else {
                0
            };
            if let Some(chunk) = body.as_ref() {
                facts.absorb(chunk, limit);
            }
            emit_access(&agent, &request_id, pending, facts);
            return Ok(ResponseBodyPluginResult::Unchanged);
        }
        let Some(mut entry) = PENDING_ACCESS.get_mut(&request_id) else {
            return Ok(ResponseBodyPluginResult::Unchanged);
        };
        let entry_limit = entry.body_limit;
        let Some(facts) = entry.response.as_mut() else {
            return Ok(ResponseBodyPluginResult::Unchanged);
        };
        let limit = if facts.capture_body { entry_limit } else { 0 };
        if let Some(chunk) = body.as_ref() {
            facts.absorb(chunk, limit);
        }
        Ok(ResponseBodyPluginResult::Unchanged)
    }
}

register_plugin!("waf", WafPlugin);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use pingap_core::PluginStep;
    use pingap_util::base64_encode;
    use pingora::proxy::Session;
    use pingwaf_agent::cache::RuleCache;
    use pingwaf_agent::client::ControlPlaneClient;
    use pingwaf_agent::config::AgentConfig;
    use pingwaf_agent::heartbeat::MetricsCollector;
    use pingwaf_challenge::ClearanceLevel;
    use pingwaf_proto::control_plane as proto;
    use tokio_test::io::Builder;

    #[test]
    fn request_body_staging_withholds_until_the_cap() {
        let mut passthrough = false;
        let mut buffer = BytesMut::new();

        // Chunks accumulate in the buffer and are withheld from the
        // upstream (the caller replaces the outgoing chunk with an empty
        // one).
        assert!(matches!(
            stage_chunk(
                10,
                true,
                &mut passthrough,
                &mut buffer,
                Some(b"12345".as_slice())
            ),
            StageAction::Withhold
        ));
        assert!(matches!(
            stage_chunk(
                10,
                true,
                &mut passthrough,
                &mut buffer,
                Some(b"6789".as_slice())
            ),
            StageAction::Withhold
        ));
        assert_eq!(&buffer[..], b"123456789");
        assert!(!passthrough);

        // Crossing the cap flushes prefix plus current chunk as one piece
        // and switches the entry to passthrough.
        let StageAction::Flush(staged) = stage_chunk(
            10,
            true,
            &mut passthrough,
            &mut buffer,
            Some(b"0123".as_slice()),
        ) else {
            panic!("expected a flush once the cap is crossed");
        };
        assert_eq!(&staged[..], b"1234567890123");
        assert!(passthrough);
        assert!(buffer.is_empty());

        // Later chunks flow through untouched.
        assert!(matches!(
            stage_chunk(
                10,
                true,
                &mut passthrough,
                &mut buffer,
                Some(b"x".as_slice())
            ),
            StageAction::PassThrough
        ));
    }

    #[test]
    fn request_body_staging_is_skipped_for_log_only_entries() {
        let mut passthrough = false;
        let mut buffer = BytesMut::new();
        assert!(matches!(
            stage_chunk(
                10,
                false,
                &mut passthrough,
                &mut buffer,
                Some(b"data".as_slice())
            ),
            StageAction::PassThrough
        ));
        assert!(buffer.is_empty());
        assert!(!passthrough);
    }

    #[test]
    fn test_waf_params() {
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
mode = "block"
paranoia_level = 3
anomaly_threshold = 30
detections = ["sqli", "xss", "rce", "lfi", "ssrf"]
ml_enabled = true
ml_threshold = 0.75
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(WafMode::Block, plugin.mode);
        assert_eq!(3, plugin.paranoia_level);
        assert_eq!(30, plugin.anomaly_threshold);
        assert!(plugin.ml_enabled);
        assert_eq!(5, plugin.detections.len());
        assert_eq!(PluginStep::EarlyRequest, plugin.plugin_step);
    }

    fn cache_waf_config(
        advanced_mode: bool,
        monitor_categories: Vec<String>,
        monitor_stacks: Vec<String>,
    ) -> CacheWafConfig {
        CacheWafConfig {
            enabled: true,
            mode: CacheWafMode::Block,
            paranoia_level: 2,
            sqli_detection: true,
            xss_detection: true,
            rce_detection: true,
            lfi_detection: true,
            ssrf_detection: true,
            bot_detection: true,
            custom_rules: Vec::new(),
            managed_overrides: Vec::new(),
            ml_enabled: false,
            ml_model_path: String::new(),
            ml_threshold: 0.0,
            anomaly_threshold: 0,
            advanced_mode,
            monitor_categories,
            monitor_stacks,
            monitor_managed_rules: Vec::new(),
        }
    }

    fn probe(query: &str) -> RequestData {
        RequestData {
            method: "GET".into(),
            path: "/page".into(),
            query: query.into(),
            headers: vec![
                ("User-Agent".into(), "Mozilla/5.0".into()),
                ("Host".into(), "bench.example.net".into()),
            ],
            body: None,
            client_ip: "203.0.113.10".into(),
            country_code: None,
            scheme: "https".into(),
            protocol: "HTTP/1.1".into(),
        }
    }

    #[test]
    fn site_engine_advanced_mode_enables_strict_rules() {
        // The freemarker EL probe only fires at the strict level, so a block
        // on it proves the site switch reached the engine level knob.
        let query =
            r#"tpl=${"freemarker.template.utility.Execute"?new()("id")}"#;
        let plain =
            build_site_engine(&cache_waf_config(false, Vec::new(), Vec::new()));
        let advanced =
            build_site_engine(&cache_waf_config(true, Vec::new(), Vec::new()));
        assert_ne!(
            plain.inspect(&probe(query)).action,
            WafAction::Block,
            "details: {}",
            plain.inspect(&probe(query)).details
        );
        assert_eq!(advanced.inspect(&probe(query)).action, WafAction::Block);
    }

    #[test]
    fn site_engine_honours_monitor_managed_rules() {
        // The scanner UA only fires PINGWAF-1010; downgrading that one rule
        // id must turn the Block into a Monitor.
        let mut r = probe("/");
        r.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("User-Agent"));
        r.headers.push(("User-Agent".into(), "sqlmap/1.7".into()));
        let enforcing =
            build_site_engine(&cache_waf_config(false, Vec::new(), Vec::new()));
        assert_eq!(enforcing.inspect(&r).action, WafAction::Block);

        let mut cfg = cache_waf_config(false, Vec::new(), Vec::new());
        cfg.monitor_managed_rules =
            vec!["PINGWAF-1010".into(), "not-a-rule".into()];
        let downgraded = build_site_engine(&cfg);
        let v = downgraded.inspect(&r);
        assert_eq!(v.action, WafAction::Monitor, "details: {}", v.details);
        assert!(v.matched_rules.contains(&"PINGWAF-1010".to_string()));
    }

    #[test]
    fn engine_event_type_follows_matched_rule() {
        let verdict = |ids: Vec<String>| WafVerdict {
            action: WafAction::Block,
            score: 10,
            matched_rules: ids,
            details: String::new(),
            breakdown: ScoreBreakdown::clean(),
        };
        assert_eq!(
            WafPlugin::engine_event_type(&verdict(vec!["PINGWAF-1010".into()])),
            "managed"
        );
        assert_eq!(
            WafPlugin::engine_event_type(&verdict(vec![
                "site-rule-uuid".into()
            ])),
            "waf"
        );
        assert_eq!(WafPlugin::engine_event_type(&verdict(Vec::new())), "waf");
    }

    #[test]
    fn parse_monitor_managed_rules_drops_unknown_ids() {
        let parsed = parse_monitor_managed_rules(&[
            "PINGWAF-1010".to_string(),
            "PINGWAF-1002".to_string(),
            "PINGWAF-9999".to_string(),
            String::new(),
        ]);
        assert_eq!(
            parsed,
            ["PINGWAF-1010".to_string(), "PINGWAF-1002".to_string()]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn site_engine_monitor_categories_downgrade_to_monitor() {
        let engine = build_site_engine(&cache_waf_config(
            false,
            vec!["sqli".into()],
            Vec::new(),
        ));
        let v = engine.inspect(&probe("id=1' OR 1=1 --"));
        assert_eq!(v.action, WafAction::Monitor, "details: {}", v.details);
    }

    #[test]
    fn site_engine_toml_monitor_keys_flow_into_the_engine() {
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
mode = "block"
monitor_categories = ["sqli", "bogus"]
monitor_stacks = ["java"]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let engine = plugin.engine.read().unwrap_or_else(|e| e.into_inner());
        let sqli = engine.inspect(&probe("id=1' OR 1=1 --"));
        assert_eq!(
            sqli.action,
            WafAction::Monitor,
            "details: {}",
            sqli.details
        );
    }

    #[tokio::test]
    async fn toml_advanced_mode_enables_strict_rules_and_body() {
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
mode = "block"
advanced_mode = true
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(plugin.inspect_body, "advanced mode implies body inspection");
        let engine = plugin.engine.read().unwrap_or_else(|e| e.into_inner());
        let tpl = engine.inspect(&probe(
            r#"tpl=${"freemarker.template.utility.Execute"?new()("id")}"#,
        ));
        assert_eq!(
            tpl.action,
            WafAction::Block,
            "strict-only rules must be active, details: {}",
            tpl.details
        );
    }

    #[tokio::test]
    async fn test_blocks_sqli() {
        let _agent_lock = lock_agent().await;
        // Start from no instance: a leftover agent from a sibling test
        // would otherwise observe (and count) this request.
        PingWafAgent::set_agent_instance(None);
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let input_header = "GET /api/users?id=1'%20OR%201=1%20-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
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
            panic!("expected a block response");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
    }

    #[tokio::test]
    async fn test_passes_clean_request() {
        let _agent_lock = lock_agent().await;
        PingWafAgent::set_agent_instance(None);
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let input_header =
            "GET /api/users?page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
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

    #[tokio::test]
    async fn test_monitor_mode_does_not_block() {
        let _agent_lock = lock_agent().await;
        PingWafAgent::set_agent_instance(None);
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "monitor""###).unwrap(),
        )
        .unwrap();

        let input_header = "GET /api/users?id=1'%20OR%201=1%20-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
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

    #[tokio::test]
    async fn test_off_mode_skips() {
        let _agent_lock = lock_agent().await;
        PingWafAgent::set_agent_instance(None);
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "off""###).unwrap(),
        )
        .unwrap();

        let input_header = "GET /api/users?id=1'%20OR%201=1%20-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
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
        assert!(result == RequestPluginResult::Skipped);
    }

    /// Pushes a single-site config whose WAF engine runs in the given proto
    /// mode (0=off, 1=monitor, 2=block).
    async fn install_agent_with_site_mode(
        waf_mode: i32,
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<PingWafAgent>,
        tempfile::TempDir,
    ) {
        let installed = install_test_agent().await;
        installed
            .1
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        waf: Some(proto::WafConfig {
                            enabled: true,
                            mode: waf_mode,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                ..Default::default()
            })
            .unwrap();
        installed
    }

    /// A WAF auto-block is an artifact of the engine's block-mode
    /// configuration: once the site switches to monitor, the stale entry must
    /// not keep refusing clients. Rate-limit blocks keep enforcing.
    #[tokio::test]
    async fn test_waf_auto_block_skipped_in_site_monitor_mode() {
        let (_guard, agent, _dir) = install_agent_with_site_mode(1).await; // monitor
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        // Left over from the site's block-mode era: skipped now.
        agent.block_ip("site-1", "203.0.113.7", None, "waf: stale rule");
        assert!(
            run_request(&plugin, "203.0.113.7").await
                == RequestPluginResult::Continue
        );

        // A rate-limit block is its own policy: still enforced.
        agent.block_ip(
            "site-1",
            "203.0.113.8",
            None,
            "rate limit: login brute force",
        );
        let RequestPluginResult::Respond(resp) =
            run_request(&plugin, "203.0.113.8").await
        else {
            panic!("expected the rate-limit block to answer");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
    }

    /// Under observation mode the engine produces no new blocks, so WAF
    /// auto-blocks must not silently keep refusing clients either.
    #[tokio::test]
    async fn test_waf_auto_block_skipped_under_observation() {
        let (_guard, agent, _dir) = install_test_agent().await;
        agent
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        waf: Some(proto::WafConfig {
                            enabled: true,
                            mode: 2, // block
                            ..Default::default()
                        }),
                        observation_mode: true,
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                ..Default::default()
            })
            .unwrap();
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        agent.block_ip("site-1", "203.0.113.7", None, "waf: stale rule");
        assert!(
            run_request(&plugin, "203.0.113.7").await
                == RequestPluginResult::Continue
        );
    }

    /// In enforcing block mode a WAF auto-block keeps refusing the client at
    /// the edge — the behavior the previous two tests guard the downgrade
    /// against.
    #[tokio::test]
    async fn test_waf_auto_block_enforced_in_block_mode() {
        let (_guard, agent, _dir) = install_agent_with_site_mode(2).await; // block
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        agent.block_ip("site-1", "203.0.113.7", None, "waf: fresh rule");
        let RequestPluginResult::Respond(resp) =
            run_request(&plugin, "203.0.113.7").await
        else {
            panic!("expected the auto-block to answer");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
    }

    /// Builds one request with an explicit path and optional cookie header.
    async fn run_path_request(
        plugin: &WafPlugin,
        path: &str,
        cookie: Option<&str>,
    ) -> RequestPluginResult {
        let cookie_line = cookie
            .map(|value| format!("Cookie: {value}\r\n"))
            .unwrap_or_default();
        let input_header = format!(
            "GET {path} HTTP/1.1\r\nHost: example.com\r\n{cookie_line}\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        plugin
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap()
    }

    /// An engine Challenge verdict must not re-challenge a client that
    /// already holds a valid clearance: the challenge would loop forever.
    #[tokio::test]
    async fn test_engine_challenge_skipped_with_valid_clearance() {
        let (_guard, _agent, _dir) = install_test_agent().await;
        _agent
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        waf: Some(proto::WafConfig {
                            enabled: true,
                            mode: 2, // block
                            custom_rules: vec![proto::WafRule {
                                id: "challenge-admin".to_string(),
                                name: "challenge /admin".to_string(),
                                description: String::new(),
                                expression: r#"
                                    http.request.uri.path starts_with "/admin"
                                "#
                                .to_string(),
                                action: proto::WafAction::Challenge as i32,
                                severity: 1,
                                tags: vec!["custom".to_string()],
                                enabled: true,
                                mode: 2,
                                priority: 0,
                            }],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                ..Default::default()
            })
            .unwrap();
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        // Without a clearance the challenge page answers.
        let RequestPluginResult::Respond(resp) =
            run_path_request(&plugin, "/admin", None).await
        else {
            panic!("expected the challenge page");
        };
        assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);

        // With a valid clearance for this site the same request passes.
        let secret = resolve_cookie_secret("");
        let manager = CookieManager::new(secret.as_bytes(), 3600);
        let cookie = manager.issue_clearance(
            ClearanceLevel::NonInteractive,
            "site-1",
            "fingerprint",
        );
        assert!(
            run_path_request(
                &plugin,
                "/admin",
                Some(&format!("{CLEARANCE_COOKIE_NAME}={cookie}"))
            )
            .await
                == RequestPluginResult::Continue
        );

        // A clearance earned on another site must not exempt this one: the
        // cookie's site id is checked against the request's site.
        let other = manager.issue_clearance(
            ClearanceLevel::NonInteractive,
            "site-9",
            "fingerprint",
        );
        let RequestPluginResult::Respond(resp) = run_path_request(
            &plugin,
            "/admin",
            Some(&format!("{CLEARANCE_COOKIE_NAME}={other}")),
        )
        .await
        else {
            panic!("expected the cross-site clearance to be rejected");
        };
        assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);
    }

    /// The agent instance is a process-wide global, and cargo runs a
    /// binary's tests in parallel: any test reaching the plugin's agent
    /// paths while another has an agent installed records into that
    /// agent's metrics collector. Tests touching the instance therefore
    /// serialize on this lock.
    static AGENT_LOCK: tokio::sync::Mutex<()> =
        tokio::sync::Mutex::const_new(());

    pub(crate) async fn lock_agent() -> tokio::sync::MutexGuard<'static, ()> {
        AGENT_LOCK.lock().await
    }

    /// Install a never-connecting agent for the duration of one test,
    /// holding the agent lock so sibling tests stay off the global.
    pub(crate) async fn install_test_agent() -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<PingWafAgent>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            cache_dir: dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        install_test_agent_with(config, dir).await
    }

    /// Same, with a caller-supplied config. It should point `cache_dir` at
    /// `dir` so the temporary rules are cleaned up with it.
    pub(crate) async fn install_test_agent_with(
        config: AgentConfig,
        dir: tempfile::TempDir,
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<PingWafAgent>,
        tempfile::TempDir,
    ) {
        let lock = lock_agent().await;
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
        (lock, agent, dir)
    }

    /// Pushes site rules to the test agent: a whitelist allow rule above a
    /// catch-all block rule for `example.com`.
    async fn install_whitelist_agent() -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<PingWafAgent>,
        tempfile::TempDir,
    ) {
        let installed = install_test_agent().await;
        installed
            .1
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        ip_access_rules: vec![
                            proto::IpAccessRule {
                                id: "allow-office".to_string(),
                                name: "office egress".to_string(),
                                ip_ranges: vec!["10.1.1.1".to_string()],
                                action: proto::IpAccessAction::IpAccessAllow
                                    as i32,
                                note: String::new(),
                                enabled: true,
                            },
                            proto::IpAccessRule {
                                id: "block-all".to_string(),
                                name: "block everything else".to_string(),
                                ip_ranges: vec!["0.0.0.0/0".to_string()],
                                action: proto::IpAccessAction::IpAccessBlock
                                    as i32,
                                note: String::new(),
                                enabled: true,
                            },
                        ],
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                config_hash: "hash-1".to_string(),
                updated_at: None,
            })
            .unwrap();
        installed
    }

    /// Installs an agent whose only site is paused and carries a catch-all
    /// block rule, so the pause must win over the restriction.
    async fn install_paused_agent() -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<PingWafAgent>,
        tempfile::TempDir,
    ) {
        let installed = install_test_agent().await;
        installed
            .1
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 1, // SITE_STATUS_PAUSED
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        ip_access_rules: vec![proto::IpAccessRule {
                            id: "block-all".to_string(),
                            name: "block everything".to_string(),
                            ip_ranges: vec!["0.0.0.0/0".to_string()],
                            action: proto::IpAccessAction::IpAccessBlock as i32,
                            note: String::new(),
                            enabled: true,
                        }],
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                config_hash: "hash-1".to_string(),
                updated_at: None,
            })
            .unwrap();
        installed
    }

    /// A paused site answers with a 503 maintenance page (and a Retry-After
    /// hint) instead of proxying, while still producing an access log row.
    #[tokio::test]
    async fn test_paused_site_answers_maintenance_page() {
        let (_guard, agent, _dir) = install_paused_agent().await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let RequestPluginResult::Respond(resp) =
            run_request(&plugin, "203.0.113.7").await
        else {
            panic!("expected the paused site to answer");
        };
        assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);
        let retry_after = resp.headers.as_ref().and_then(|headers| {
            headers
                .iter()
                .find(|(name, _)| name.as_str() == "retry-after")
                .map(|(_, value)| {
                    value.to_str().unwrap_or_default().to_string()
                })
        });
        assert_eq!(Some("3600".to_string()), retry_after);

        // The access row ships immediately with the 503; the pause is not a
        // WAF decision, so no security event is queued.
        let entry = agent.client.pop_log().await.unwrap();
        assert_eq!(503, entry.response_status);
        assert_eq!("GET", entry.method);
        // The page the client receives is recorded, headers and body alike.
        assert_eq!(
            Some("text/html; charset=utf-8"),
            entry
                .response_headers
                .get("content-type")
                .map(String::as_str)
        );
        assert_eq!(
            Some("3600"),
            entry
                .response_headers
                .get("retry-after")
                .map(String::as_str)
        );
        let body = entry
            .response_body
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        assert!(body.contains("Temporarily Paused"), "body: {body}");
        assert_eq!(
            entry.response_body_size,
            body.len() as u64,
            "the recorded size is the body that was sent"
        );
        assert!(!entry.response_body_truncated);
        assert!(agent.client.pop_log().await.is_none());
    }

    /// An edge configured to fail closed refuses hosts without synced rules
    /// while its control plane is unreachable and reports each refusal;
    /// fail-open edges (the default) and hosts with synced rules are
    /// unaffected. The test agent never connects, so it stays permanently
    /// "disconnected".
    #[tokio::test]
    async fn test_fail_closed_when_disconnected() {
        // Baseline: the default fail-open agent is also permanently
        // disconnected, and the unknown host still falls through to the
        // base engine.
        {
            let (_guard, _agent, _dir) = install_test_agent().await;
            let plugin = WafPlugin::new(
                &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
            )
            .unwrap();
            assert!(
                run_request(&plugin, "203.0.113.7").await
                    == RequestPluginResult::Continue
            );
        }

        // Flipping to fail-closed turns the same miss into a refusal.
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            cache_dir: dir.path().to_string_lossy().to_string(),
            fail_open: false,
            ..Default::default()
        };
        let (_guard, agent, _dir) = install_test_agent_with(config, dir).await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let RequestPluginResult::Respond(resp) =
            run_request(&plugin, "203.0.113.7").await
        else {
            panic!("expected the fail-closed edge to refuse the request");
        };
        assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);
        let retry_after = resp.headers.as_ref().and_then(|headers| {
            headers
                .iter()
                .find(|(name, _)| name.as_str() == "retry-after")
                .map(|(_, value)| {
                    value.to_str().unwrap_or_default().to_string()
                })
        });
        assert_eq!(Some("30".to_string()), retry_after);

        // The refusal ships an access row plus a `fail_closed` security
        // event.
        let access = agent.client.pop_log().await.unwrap();
        assert_eq!(503, access.response_status);
        assert_eq!(String::new(), access.waf_event_type);
        let event = agent.client.pop_log().await.unwrap();
        assert_eq!("fail_closed", event.waf_event_type);
        assert_eq!("block", event.waf_action);
        assert_eq!("example.com", event.host);
        assert!(agent.client.pop_log().await.is_none());

        // Hosts the cache knows about keep their synced configuration: once
        // the site is synced the same request flows again.
        agent
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                config_hash: "hash-1".to_string(),
                updated_at: None,
            })
            .unwrap();
        assert!(
            run_request(&plugin, "203.0.113.7").await
                == RequestPluginResult::Continue
        );

        // Standalone edges have no control plane to lose and never refuse.
        PingWafAgent::set_agent_instance(None);
        assert!(
            run_request(&plugin, "203.0.113.7").await
                == RequestPluginResult::Continue
        );
    }

    #[tokio::test]
    async fn test_fail_closed_registry_overrides_the_local_fallback() {
        // Even with a fail-open local default, a site the registry marks
        // fail-closed is refused while disconnected; the global default
        // covers every other host.
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            cache_dir: dir.path().to_string_lossy().to_string(),
            fail_open: true,
            ..Default::default()
        };
        let (_guard, _agent, _dir) = install_test_agent_with(config, dir).await;
        let agent = PingWafAgent::instance().unwrap();
        agent
            .rule_cache
            .update_from_bundle(&proto::RuleBundle {
                site_id: "site-1".to_string(),
                config_hash: "hash-1".to_string(),
                site_policies: vec![proto::SitePolicy {
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    mode: proto::FailoverMode::FailoverClosed as i32,
                }],
                default_fail_open: Some(true),
                ..Default::default()
            })
            .unwrap();
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        // The registered host follows its own policy…
        let RequestPluginResult::Respond(resp) =
            run_request(&plugin, "203.0.113.7").await
        else {
            panic!("expected the registry-closed host to be refused");
        };
        assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);

        // …and once the registry no longer marks it closed, the global
        // default (fail open) applies again.
        agent
            .rule_cache
            .update_from_bundle(&proto::RuleBundle {
                site_id: "site-1".to_string(),
                config_hash: "hash-2".to_string(),
                site_policies: vec![proto::SitePolicy {
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    mode: proto::FailoverMode::FailoverOpen as i32,
                }],
                default_fail_open: Some(true),
                ..Default::default()
            })
            .unwrap();
        assert!(
            run_request(&plugin, "203.0.113.7").await
                == RequestPluginResult::Continue
        );

        PingWafAgent::set_agent_instance(None);
    }

    /// A blocked request logs the page the client received, so the dashboard
    /// can show what a denial looked like without replaying the request.
    #[tokio::test]
    async fn test_blocked_response_is_logged_with_its_body() {
        let (_guard, agent, _dir) = install_whitelist_agent().await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let RequestPluginResult::Respond(resp) =
            run_request(&plugin, "203.0.113.7").await
        else {
            panic!("expected the catch-all rule to answer");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

        // The security event ships first; the access entry follows with the
        // page the client received.
        let event = agent.client.pop_log().await.unwrap();
        assert_eq!("block", event.waf_action);
        let entry = agent.client.pop_log().await.unwrap();
        assert_eq!(event.request_id, entry.request_id);
        assert_eq!(403, entry.response_status);
        assert_eq!(
            Some("text/html; charset=utf-8"),
            entry
                .response_headers
                .get("content-type")
                .map(String::as_str)
        );
        let body = entry
            .response_body
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        assert!(
            body.contains("Request Blocked") && body.contains("PingWAF"),
            "body: {body}"
        );
        assert_eq!(entry.response_body_size, body.len() as u64);
        assert!(!entry.response_body_truncated);
    }

    /// Drives a clean request through `handle_request` and hands the
    /// session/ctx back for the response phases.
    async fn run_clean_request(
        plugin: &WafPlugin,
        input_header: &str,
    ) -> (Session, Ctx) {
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some("10.1.1.1".to_string());
        assert!(
            plugin
                .handle_request(
                    PluginStep::EarlyRequest,
                    &mut session,
                    &mut ctx
                )
                .await
                .unwrap()
                == RequestPluginResult::Continue
        );
        (session, ctx)
    }

    /// A chunked upstream response (no content-length) still lands its real
    /// byte count in the access log: the entry is held until the body phase
    /// has counted every chunk. Body content stays out of the log when the
    /// payload is not capturable, even with a generous body limit.
    #[tokio::test]
    async fn test_chunked_response_size_is_counted_without_body_capture() {
        let (_guard, agent, _dir) = install_test_agent().await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();
        let (mut session, mut ctx) = run_clean_request(
            &plugin,
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;

        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .insert_header("content-type", "application/octet-stream")
            .unwrap();
        plugin
            .handle_response(&mut session, &mut ctx, &mut response)
            .await
            .unwrap();

        let mut body = Some(bytes::Bytes::from_static(b"hello "));
        plugin
            .handle_response_body(&mut session, &mut ctx, &mut body, false)
            .unwrap();
        let mut body = Some(bytes::Bytes::from_static(b"chunked world"));
        plugin
            .handle_response_body(&mut session, &mut ctx, &mut body, true)
            .unwrap();

        let entry = agent.client.pop_log().await.unwrap();
        assert_eq!(200, entry.response_status);
        assert_eq!(19, entry.response_body_size);
        assert!(entry.response_body.is_none());
        assert!(!entry.response_body_truncated);
        assert!(agent.client.pop_log().await.is_none());
    }

    /// HEAD (and 204/304) never stream a body: the entry completes at the
    /// header phase with the announced content length.
    #[tokio::test]
    async fn test_head_response_completes_with_announced_size() {
        let (_guard, agent, _dir) = install_test_agent().await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();
        let (mut session, mut ctx) = run_clean_request(
            &plugin,
            "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;

        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("content-type", "text/html").unwrap();
        response.insert_header("content-length", "512").unwrap();
        plugin
            .handle_response(&mut session, &mut ctx, &mut response)
            .await
            .unwrap();

        let entry = agent.client.pop_log().await.unwrap();
        assert_eq!(200, entry.response_status);
        assert_eq!(512, entry.response_body_size);
        assert!(entry.response_body.is_none());
        assert!(agent.client.pop_log().await.is_none());
    }

    /// The announced content length fills in when the body streamed nothing
    /// at all — entries swept mid-exchange after the headers, for instance.
    #[tokio::test]
    async fn test_announced_size_fills_in_when_nothing_streamed() {
        let (_guard, agent, _dir) = install_test_agent().await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();
        let (mut session, mut ctx) = run_clean_request(
            &plugin,
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;

        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("content-type", "text/html").unwrap();
        response.insert_header("content-length", "7777").unwrap();
        plugin
            .handle_response(&mut session, &mut ctx, &mut response)
            .await
            .unwrap();

        // Simulate the sweep taking the entry before any body arrived.
        let request_id = ctx.state.request_id.clone().unwrap();
        let (_, mut pending) = PENDING_ACCESS.remove(&request_id).unwrap();
        let mut facts = pending.response.take().unwrap();
        facts.abandoned = true;
        emit_access(&agent, &request_id, pending, facts);

        let entry = agent.client.pop_log().await.unwrap();
        assert_eq!(200, entry.response_status);
        assert_eq!(7777, entry.response_body_size);
        assert!(entry.response_body.is_none());
    }

    /// Installs an agent whose only site enforces mTLS, revoking `revoked`
    /// and pinning the organization to `organization`.
    async fn install_mtls_agent(
        require_client_cert: bool,
        organization: &str,
        revoked: &[&str],
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<PingWafAgent>,
        tempfile::TempDir,
    ) {
        let installed = install_test_agent().await;
        // The per-domain context cache is keyed on the agent's config hash:
        // give each posture its own so a test that reinstalls the agent does
        // not reuse the previous context.
        let config_hash = format!(
            "hash-mtls-{require_client_cert}-{organization}-{}",
            revoked.join(",")
        );
        installed
            .1
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: config_hash.clone(),
                        ssl: Some(proto::SslConfig {
                            enabled: true,
                            mtls_enabled: true,
                            mtls_client_ca: "CA".to_string(),
                            mtls_organization: organization.to_string(),
                            mtls_require_client_cert: require_client_cert,
                            mtls_revoked_fingerprints: revoked
                                .iter()
                                .map(|f| f.to_string())
                                .collect(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                config_hash,
                updated_at: None,
            })
            .unwrap();
        installed
    }

    /// Builds one request carrying the client certificate facts the TLS layer
    /// would have put on the connection.
    async fn run_request_with_cert(
        plugin: &WafPlugin,
        digest: Option<&str>,
        organization: Option<&str>,
    ) -> RequestPluginResult {
        let input_header = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some("203.0.113.7".to_string());
        ctx.conn.tls_peer_cert_digest = digest.map(str::to_string);
        ctx.conn.tls_peer_organization = organization.map(str::to_string);
        plugin
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap()
    }

    /// A site that requires client certificates answers 403 without one —
    /// and without touching the WAF event stream — while a site that only
    /// trusts them still serves the request.
    #[tokio::test]
    async fn test_mtls_requires_a_client_certificate() {
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        {
            let (_guard, agent, _dir) = install_mtls_agent(true, "", &[]).await;
            let RequestPluginResult::Respond(resp) =
                run_request_with_cert(&plugin, None, None).await
            else {
                panic!("expected the missing certificate to be refused");
            };
            assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
            let entry = agent.client.pop_log().await.unwrap();
            assert_eq!(403, entry.response_status);
            // A denial, not a WAF verdict: nothing is queued as a security
            // event.
            assert!(agent.client.pop_log().await.is_none());
        }

        let (_guard, _agent, _dir) = install_mtls_agent(false, "", &[]).await;
        assert!(
            run_request_with_cert(&plugin, None, None).await
                == RequestPluginResult::Continue
        );
    }

    /// Revoked certificates and certificates issued for another organization
    /// are refused even though their chain verified at the TLS layer.
    #[tokio::test]
    async fn test_mtls_refuses_revoked_and_foreign_certificates() {
        let revoked = "0a1b2c3d";
        let (_guard, _agent, _dir) =
            install_mtls_agent(true, "Acme", &[revoked]).await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        // The certificate this site trusts passes.
        assert!(
            run_request_with_cert(&plugin, Some("00ff"), Some("Acme")).await
                == RequestPluginResult::Continue
        );

        let RequestPluginResult::Respond(resp) =
            run_request_with_cert(&plugin, Some(revoked), Some("Acme")).await
        else {
            panic!("expected the revoked certificate to be refused");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

        let RequestPluginResult::Respond(resp) =
            run_request_with_cert(&plugin, Some("00ff"), Some("Other")).await
        else {
            panic!("expected the foreign certificate to be refused");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

        let RequestPluginResult::Respond(_) =
            run_request_with_cert(&plugin, Some("00ff"), None).await
        else {
            panic!("expected a certificate without an organization to fail");
        };
    }

    /// Posture of a basic auth test agent.
    struct BasicAuthPosture {
        /// The site-wide gate is on: every request must authenticate.
        site_wide: bool,
        /// One enabled IP rule: the matched network and its action
        /// (3 = allow, 4 = basic auth).
        rule: Option<(&'static str, i32)>,
        hide_credentials: bool,
    }

    /// Installs an agent whose only site carries `credentials` and the given
    /// basic auth posture.
    async fn install_basic_auth_agent(
        credentials: &[(&str, &str)],
        posture: BasicAuthPosture,
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<PingWafAgent>,
        tempfile::TempDir,
    ) {
        let installed = install_test_agent().await;
        let ip_rules: Vec<proto::IpAccessRule> = posture
            .rule
            .iter()
            .map(|(network, action)| proto::IpAccessRule {
                id: "rule-1".to_string(),
                name: "example".to_string(),
                ip_ranges: vec![(*network).to_string()],
                action: *action,
                note: String::new(),
                enabled: true,
            })
            .collect();
        let config_hash = format!(
            "hash-basic-auth-{}-{:?}-{}",
            posture.site_wide, posture.rule, posture.hide_credentials
        );
        installed
            .1
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: config_hash.clone(),
                        ip_access_rules: ip_rules,
                        basic_auth: Some(proto::BasicAuthConfig {
                            enabled: posture.site_wide,
                            realm: "Restricted".to_string(),
                            credentials: credentials
                                .iter()
                                .map(|(username, password)| {
                                    proto::BasicAuthCredential {
                                        username: (*username).to_string(),
                                        authorization: base64_encode(format!(
                                            "{username}:{password}"
                                        )),
                                    }
                                })
                                .collect(),
                            delay_seconds: 0,
                            hide_credentials: posture.hide_credentials,
                        }),
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                config_hash,
                updated_at: None,
            })
            .unwrap();
        installed
    }

    /// Runs one request carrying an optional `Authorization` header, and
    /// reports whether the header was still there when the plugin finished.
    async fn run_request_with_auth(
        plugin: &WafPlugin,
        client_ip: &str,
        authorization: Option<&str>,
    ) -> (RequestPluginResult, bool) {
        let auth_header = authorization
            .map(|value| format!("Authorization: {value}\r\n"))
            .unwrap_or_default();
        let input_header =
            format!("GET / HTTP/1.1\r\nHost: example.com\r\n{auth_header}\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some(client_ip.to_string());
        let result = plugin
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap();
        let kept = session
            .req_header()
            .headers
            .contains_key(http::header::AUTHORIZATION);
        (result, kept)
    }

    /// The site-wide gate answers 401 with a challenge until the client
    /// presents a stored credential, and the attempt lands in the access log
    /// as a response the plugin generated itself.
    #[tokio::test]
    async fn test_basic_auth_gate_challenges_until_credentials_match() {
        let (_guard, agent, _dir) = install_basic_auth_agent(
            &[("alice", "hunter2")],
            BasicAuthPosture {
                site_wide: true,
                rule: None,
                hide_credentials: false,
            },
        )
        .await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let (result, _) =
            run_request_with_auth(&plugin, "203.0.113.7", None).await;
        let RequestPluginResult::Respond(resp) = result else {
            panic!("expected the gate to challenge the request");
        };
        assert_eq!(http::StatusCode::UNAUTHORIZED, resp.status);
        let challenge = resp.headers.as_ref().and_then(|headers| {
            headers
                .iter()
                .find(|(name, _)| name == http::header::WWW_AUTHENTICATE)
                .and_then(|(_, value)| value.to_str().ok())
        });
        assert_eq!(Some("Basic realm=\"Restricted\""), challenge);
        let entry = agent.client.pop_log().await.unwrap();
        assert_eq!(401, entry.response_status);
        // A denial, not a WAF verdict: nothing is queued as a security event.
        assert!(agent.client.pop_log().await.is_none());

        let wrong = format!("Basic {}", base64_encode("alice:nope"));
        let (result, _) =
            run_request_with_auth(&plugin, "203.0.113.7", Some(&wrong)).await;
        let RequestPluginResult::Respond(resp) = result else {
            panic!("expected the wrong password to be refused");
        };
        assert_eq!(http::StatusCode::UNAUTHORIZED, resp.status);

        let right = format!("Basic {}", base64_encode("alice:hunter2"));
        let (result, kept) =
            run_request_with_auth(&plugin, "203.0.113.7", Some(&right)).await;
        assert!(result == RequestPluginResult::Continue);
        // The gate keeps the header unless hiding it was configured.
        assert!(kept);
    }

    /// `hide_credentials` strips the `Authorization` header once the request
    /// is authenticated.
    #[tokio::test]
    async fn test_basic_auth_hide_credentials_strips_the_header() {
        let (_guard, _agent, _dir) = install_basic_auth_agent(
            &[("alice", "hunter2")],
            BasicAuthPosture {
                site_wide: true,
                rule: None,
                hide_credentials: true,
            },
        )
        .await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let right = format!("Basic {}", base64_encode("alice:hunter2"));
        let (result, kept) =
            run_request_with_auth(&plugin, "203.0.113.7", Some(&right)).await;
        assert!(result == RequestPluginResult::Continue);
        assert!(!kept);
    }

    /// An IP rule whose action is `basic_auth` gates only the clients it
    /// matches — the site-wide switch stays off — and lets them continue
    /// once authenticated.
    #[tokio::test]
    async fn test_basic_auth_rule_action_gates_matching_clients() {
        let (_guard, _agent, _dir) = install_basic_auth_agent(
            &[("alice", "hunter2")],
            BasicAuthPosture {
                site_wide: false,
                rule: Some(("10.1.1.0/24", 4)),
                hide_credentials: false,
            },
        )
        .await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        // A client the rule does not match passes untouched.
        let (result, _) =
            run_request_with_auth(&plugin, "203.0.113.7", None).await;
        assert!(result == RequestPluginResult::Continue);

        let (result, _) =
            run_request_with_auth(&plugin, "10.1.1.1", None).await;
        let RequestPluginResult::Respond(resp) = result else {
            panic!("expected the rule to require authentication");
        };
        assert_eq!(http::StatusCode::UNAUTHORIZED, resp.status);

        let right = format!("Basic {}", base64_encode("alice:hunter2"));
        let (result, _) =
            run_request_with_auth(&plugin, "10.1.1.1", Some(&right)).await;
        assert!(result == RequestPluginResult::Continue);
    }

    /// A rule that requires authentication while the site stores no
    /// credential refuses the matched client outright.
    #[tokio::test]
    async fn test_basic_auth_rule_without_credentials_refuses() {
        let (_guard, _agent, _dir) = install_basic_auth_agent(
            &[],
            BasicAuthPosture {
                site_wide: false,
                rule: Some(("10.1.1.0/24", 4)),
                hide_credentials: false,
            },
        )
        .await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let (result, _) =
            run_request_with_auth(&plugin, "10.1.1.1", None).await;
        let RequestPluginResult::Respond(resp) = result else {
            panic!("expected a refusal without credentials to verify");
        };
        assert_eq!(http::StatusCode::UNAUTHORIZED, resp.status);
    }

    /// An `allow` rule exempts its clients from the site-wide gate, so a
    /// monitoring range can keep polling a protected site.
    #[tokio::test]
    async fn test_ip_allow_rule_exempts_the_site_gate() {
        let (_guard, _agent, _dir) = install_basic_auth_agent(
            &[("alice", "hunter2")],
            BasicAuthPosture {
                site_wide: true,
                rule: Some(("10.1.1.0/24", 3)),
                hide_credentials: false,
            },
        )
        .await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let (result, _) =
            run_request_with_auth(&plugin, "10.1.1.1", None).await;
        assert!(result == RequestPluginResult::Continue);

        let (result, _) =
            run_request_with_auth(&plugin, "203.0.113.7", None).await;
        let RequestPluginResult::Respond(resp) = result else {
            panic!("expected the gate to challenge an unlisted client");
        };
        assert_eq!(http::StatusCode::UNAUTHORIZED, resp.status);
    }

    /// Builds one request against the plugin from `client_ip`.
    async fn run_request(
        plugin: &WafPlugin,
        client_ip: &str,
    ) -> RequestPluginResult {
        let input_header = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some(client_ip.to_string());
        plugin
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap()
    }

    /// An allow rule above a catch-all block rule yields a whitelist: the
    /// listed IP passes, everything else is answered with 403.
    #[tokio::test]
    async fn test_ip_access_rules_whitelist() {
        let (_guard, _agent, _dir) = install_whitelist_agent().await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        assert!(
            run_request(&plugin, "10.1.1.1").await
                == RequestPluginResult::Continue
        );

        let RequestPluginResult::Respond(resp) =
            run_request(&plugin, "203.0.113.7").await
        else {
            panic!("expected the catch-all rule to answer");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
    }

    /// A matching block rule is enforced even when the site has no WAF engine
    /// of its own: access restrictions are not gated on the managed rules.
    #[tokio::test]
    async fn test_ip_access_rule_applies_with_waf_disabled() {
        let (_guard, agent, _dir) = install_test_agent().await;
        agent
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        waf: Some(proto::WafConfig {
                            enabled: false,
                            ..Default::default()
                        }),
                        ip_access_rules: vec![proto::IpAccessRule {
                            id: "block-crawlers".to_string(),
                            name: "block crawlers".to_string(),
                            ip_ranges: vec!["192.0.2.0/24".to_string()],
                            action: proto::IpAccessAction::IpAccessChallenge
                                as i32,
                            note: String::new(),
                            enabled: true,
                        }],
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                config_hash: "hash-1".to_string(),
                updated_at: None,
            })
            .unwrap();
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let RequestPluginResult::Respond(resp) =
            run_request(&plugin, "192.0.2.9").await
        else {
            panic!("expected the challenge rule to answer");
        };
        assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);

        assert!(
            run_request(&plugin, "198.51.100.4").await
                == RequestPluginResult::Continue
        );
    }

    /// A geo policy denies a client whose country is on the blocked list, and
    /// the denial carries the country on the emitted security event.
    #[tokio::test]
    async fn test_geo_rule_blocks_listed_country() {
        LazyLock::force(&GEO_DB);
        let country = lookup_country_addr("8.8.8.8".parse().unwrap())
            .expect("embedded db resolves 8.8.8.8");

        let (_guard, agent, _dir) = install_test_agent().await;
        agent
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        geo: Some(proto::GeoConfig {
                            enabled: true,
                            blocked_countries: vec![country.clone()],
                            action: proto::WafAction::Block as i32,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                config_hash: "hash-1".to_string(),
                updated_at: None,
            })
            .unwrap();
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let RequestPluginResult::Respond(resp) =
            run_request(&plugin, "8.8.8.8").await
        else {
            panic!("expected the geo rule to answer");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

        let event = agent.client.pop_log().await.unwrap();
        assert_eq!(country, event.country_code);
        assert_eq!("geo_restriction", event.waf_rule_id);
    }

    #[tokio::test]
    async fn test_access_log_pipeline() {
        let (_guard, agent, _dir) = install_test_agent().await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        // ── Blocked request: security event + immediate access entry ──
        let input_header = "GET /api/users?id=1'%20OR%201=1%20-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        let result = plugin
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("expected a block response");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);
        assert_eq!(1, agent.metrics.requests_total());
        assert_eq!(1, agent.metrics.blocked_requests_total());

        // First shipped entry is the security event with the real scheme,
        // protocol and status (no more hardcoded https/HTTP/1.1/403 trio).
        let event = agent.client.pop_log().await.unwrap();
        assert_eq!("block", event.waf_action);
        assert_eq!(403, event.response_status);
        assert_eq!("http", event.scheme);
        assert_eq!("HTTP/1.1", event.protocol);

        // Second is the access entry, emitted at request time because a
        // Respond result never reaches handle_response.
        let blocked_id = event.request_id.clone();
        let entry = agent.client.pop_log().await.unwrap();
        assert_eq!(blocked_id, entry.request_id);
        assert_eq!(403, entry.response_status);
        assert_eq!("GET", entry.method);
        assert_eq!("/api/users", entry.path);
        assert_eq!("example.com", entry.host);
        assert_eq!("http", entry.scheme);
        assert_eq!("HTTP/1.1", entry.protocol);

        // The pending entry was consumed: handle_response must not re-send.
        let mut resp = ResponseHeader::build(200, None).unwrap();
        plugin
            .handle_response(&mut session, &mut ctx, &mut resp)
            .await
            .unwrap();
        assert!(agent.client.pop_log().await.is_none());

        // ── Passed request: metrics counted, access logged at response ──
        // A distinct client IP: the blocked request above auto-blocked its
        // own client at the edge, and this leg must stay reachable.
        let input_header =
            "GET /api/users?page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some("203.0.113.21".to_string());
        let result = plugin
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result == RequestPluginResult::Continue);
        assert_eq!(2, agent.metrics.requests_total());
        assert_eq!(1, agent.metrics.blocked_requests_total());

        // Nothing ships until the response arrives.
        assert!(agent.client.pop_log().await.is_none());

        let request_id = ctx.state.request_id.clone().unwrap();
        let mut resp = ResponseHeader::build(200, None).unwrap();
        plugin
            .handle_response(&mut session, &mut ctx, &mut resp)
            .await
            .unwrap();
        // A capturable payload holds the entry back until the body ends.
        assert!(agent.client.pop_log().await.is_none());
        plugin
            .handle_response_body(
                &mut session,
                &mut ctx,
                &mut Some(bytes::Bytes::from_static(b"page one")),
                true,
            )
            .unwrap();
        let entry = agent.client.pop_log().await.unwrap();
        assert_eq!(request_id, entry.request_id);
        assert_eq!(200, entry.response_status);
        assert_eq!("page=1", entry.query_string);
        assert_eq!(Some(b"page one".to_vec()), entry.response_body);
        // Consumed exactly once.
        assert!(agent.client.pop_log().await.is_none());
    }

    #[test]
    fn cap_headers_limits_size_and_count() {
        let headers: Vec<(String, String)> = (0..100)
            .map(|i| (format!("x-header-{i:03}"), format!("value-{i}")))
            .collect();
        let capped =
            cap_headers(headers.iter().map(|(n, v)| (n.clone(), v.as_str())));
        assert_eq!(MAX_LOG_HEADERS, capped.len());

        let huge: Vec<(String, String)> =
            vec![("x-big".to_string(), "a".repeat(MAX_LOG_HEADERS_BYTES))];
        let capped =
            cap_headers(huge.iter().map(|(n, v)| (n.clone(), v.as_str())));
        assert!(capped.is_empty());

        let mut big = vec![("x-ok".to_string(), "v".to_string())];
        big.push(("x-big".to_string(), "b".repeat(MAX_LOG_HEADERS_BYTES)));
        let capped =
            cap_headers(big.iter().map(|(n, v)| (n.clone(), v.as_str())));
        assert_eq!(1, capped.len());
    }

    #[test]
    fn cap_headers_keeps_credentials_verbatim() {
        // Cookies and authorization values must survive: incident response
        // replays the captured request, so the log keeps them.
        let headers = [
            ("Authorization".to_string(), "Bearer tok".to_string()),
            ("cookie".to_string(), "sid=secret".to_string()),
            ("Proxy-Authorization".to_string(), "Basic xyz".to_string()),
        ];
        let capped =
            cap_headers(headers.iter().map(|(n, v)| (n.clone(), v.as_str())));
        let value = |name: &str| {
            capped
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
                .unwrap()
        };
        assert_eq!("Bearer tok", value("Authorization"));
        assert_eq!("sid=secret", value("cookie"));
        assert_eq!("Basic xyz", value("Proxy-Authorization"));
    }

    #[test]
    fn log_body_prefix_keeps_configured_prefix() {
        // A body of exactly the cap arrives complete.
        let mut prefix = LogBodyPrefix::new(1024);
        prefix.absorb(&[b'a'; 1024]);
        let (body, size, truncated) = prefix.finish();
        assert_eq!(1024, body.unwrap().len());
        assert_eq!(1024, size);
        assert!(!truncated);

        // Anything longer is cut to the cap and flagged; the reported size
        // still counts every byte read.
        let mut prefix = LogBodyPrefix::new(1024);
        prefix.absorb(&[b'a'; 1024]);
        prefix.absorb(b"overflow");
        let (body, size, truncated) = prefix.finish();
        assert_eq!(1024, body.unwrap().len());
        assert_eq!(1024 + 8, size);
        assert!(truncated);

        // No body at all.
        let (body, size, truncated) = LogBodyPrefix::new(1024).finish();
        assert!(body.is_none());
        assert_eq!(0, size);
        assert!(!truncated);

        // Capture disabled: nothing kept, size still counted when the bytes
        // were read for another reason.
        let mut prefix = LogBodyPrefix::new(0);
        prefix.absorb(b"ignored");
        let (body, size, truncated) = prefix.finish();
        assert!(body.is_none());
        assert_eq!(7, size);
        assert!(!truncated);
    }

    #[test]
    fn response_capture_skips_bodiless_and_binary_payloads() {
        let build = |status: u16, headers: &[(&str, &str)]| {
            let mut response = ResponseHeader::build(status, None).unwrap();
            for (name, value) in headers {
                response.insert_header(name.to_string(), *value).unwrap();
            }
            response
        };

        // Textual payloads are captured.
        assert!(should_capture_response_body(
            "GET",
            200,
            &build(200, &[("content-type", "text/html; charset=utf-8")])
        ));
        // Unknown payload: best effort.
        assert!(should_capture_response_body("GET", 200, &build(200, &[])));

        // HEAD and bodyless statuses never stream a body.
        assert!(!should_capture_response_body(
            "HEAD",
            200,
            &build(200, &[("content-type", "text/html")])
        ));
        assert!(!should_capture_response_body("GET", 204, &build(204, &[])));
        assert!(!should_capture_response_body("GET", 304, &build(304, &[])));

        // Compressed payloads are not replayable text.
        assert!(!should_capture_response_body(
            "GET",
            200,
            &build(200, &[("content-encoding", "gzip")])
        ));
        // Binary payloads are not worth keeping.
        assert!(!should_capture_response_body(
            "GET",
            200,
            &build(200, &[("content-type", "image/png")])
        ));
        assert!(!should_capture_response_body(
            "GET",
            200,
            &build(200, &[("content-type", "application/octet-stream")])
        ));
        // An explicitly empty body needs no capture.
        assert!(!should_capture_response_body(
            "GET",
            200,
            &build(200, &[("content-length", "0")])
        ));
    }

    #[tokio::test]
    async fn test_access_log_captures_request_detail() {
        let (_guard, agent, _dir) = install_test_agent().await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let body = "username=admin&password=secret";
        let input = format!(
            "POST /login HTTP/1.1\r\nHost: example.com\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        let result = plugin
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap();
        assert!(result == RequestPluginResult::Continue);

        // The request body is captured when it streams through the
        // request-body filter — the request phase no longer reads it (the
        // headers arrive before any body byte).
        assert!(
            plugin
                .handle_request_body(
                    &mut session,
                    &mut ctx,
                    &mut Some(bytes::Bytes::from(body)),
                    true,
                )
                .unwrap()
                .is_none(),
            "the request was not blocked"
        );

        // The access entry only ships once the response arrives.
        assert!(agent.client.pop_log().await.is_none());
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "text/plain; charset=utf-8")
            .unwrap();
        plugin
            .handle_response(&mut session, &mut ctx, &mut resp)
            .await
            .unwrap();
        assert!(agent.client.pop_log().await.is_none());
        plugin
            .handle_response_body(
                &mut session,
                &mut ctx,
                &mut Some(bytes::Bytes::from_static(b"welcome back")),
                true,
            )
            .unwrap();
        let entry = agent.client.pop_log().await.unwrap();

        assert_eq!(
            body.as_bytes(),
            entry.request_body.as_deref().unwrap_or(&[])
        );
        assert!(!entry.request_body_truncated);
        assert_eq!(body.len() as u64, entry.request_body_size);
        assert_eq!(
            Some("example.com"),
            entry.request_headers.get("host").map(String::as_str)
        );
        assert_eq!(
            Some("application/x-www-form-urlencoded"),
            entry
                .request_headers
                .get("content-type")
                .map(String::as_str)
        );
        // The response side is captured alongside the request.
        assert_eq!(Some(b"welcome back".to_vec()), entry.response_body);
        assert_eq!(12, entry.response_body_size);
        assert!(!entry.response_body_truncated);
        assert_eq!(
            Some("text/plain; charset=utf-8"),
            entry
                .response_headers
                .iter()
                .find(|(name, _)| *name == "content-type")
                .map(|(_, value)| value.as_str())
        );
    }

    /// Builds one request with an explicit user agent header.
    async fn run_request_with_ua(
        plugin: &WafPlugin,
        client_ip: &str,
        user_agent: &str,
    ) -> RequestPluginResult {
        let input_header = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {user_agent}\r\n\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some(client_ip.to_string());
        plugin
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap()
    }

    /// Installs an agent whose site has bot protection enabled with the given
    /// action and a `Googlebot` whitelist entry, and no WAF engine.
    async fn install_bot_agent(
        action: proto::WafAction,
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<PingWafAgent>,
        tempfile::TempDir,
    ) {
        let installed = install_test_agent().await;
        installed
            .1
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        waf: Some(proto::WafConfig {
                            enabled: false,
                            ..Default::default()
                        }),
                        bot_protection: Some(proto::BotProtectionConfig {
                            enabled: true,
                            action: action as i32,
                            known_bots_whitelist: vec!["Googlebot".to_string()],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                config_hash: "hash-1".to_string(),
                updated_at: None,
            })
            .unwrap();
        installed
    }

    #[tokio::test]
    async fn bot_ua_classification() {
        let policy = BotPolicy::build(&CacheBotProtection {
            enabled: true,
            action: CacheWafAction::Block,
            known_bots_whitelist: vec!["Googlebot".to_string()],
            verified_bot_ranges: Vec::new(),
            dns_verification_enabled: false,
        });

        assert!(matches!(
            policy
                .evaluate(
                    None,
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
                )
                .await,
            BotDecision::Pass
        ));
        assert!(matches!(
            policy
                .evaluate(None, "Mozilla/5.0 (compatible; Googlebot/2.1)")
                .await,
            BotDecision::Pass
        ));
        assert!(matches!(
            policy.evaluate(None, "curl/8.4.0").await,
            BotDecision::Deny(_)
        ));
        assert!(matches!(
            policy.evaluate(None, "").await,
            BotDecision::Deny(_)
        ));
        assert!(matches!(
            policy.evaluate(None, "python-requests/2.31.0").await,
            BotDecision::Deny(_)
        ));
        // Matching is case-insensitive without lowercasing the agent.
        assert!(matches!(
            policy
                .evaluate(None, "mOzIlLa/5.0 (compatible; googlEBot/2.1)")
                .await,
            BotDecision::Pass
        ));
        assert!(matches!(
            policy
                .evaluate(None, "MOZILLA/5.0 (X11; Linux) FIREFOX/128.0")
                .await,
            BotDecision::Pass
        ));
    }

    /// Verified crawler IP ranges pass without any user-agent signal, and a
    /// miss falls through to the user-agent classification. Bare IPs compile
    /// into /32 host ranges; malformed entries are dropped at build time.
    #[tokio::test]
    async fn bot_ip_verification_range_hit_passes() {
        let policy = BotPolicy::build(&CacheBotProtection {
            enabled: true,
            action: CacheWafAction::Block,
            known_bots_whitelist: Vec::new(),
            verified_bot_ranges: vec![
                "203.0.113.0/24".to_string(),
                "2001:db8::/32".to_string(),
                "10.20.30.40".to_string(),
                "not-a-range".to_string(),
            ],
            dns_verification_enabled: false,
        });
        assert_eq!(policy.verified_ranges.len(), 3);

        // Inside the published range: a scripted client nobody whitelisted.
        assert!(matches!(
            policy
                .evaluate(Some("203.0.113.7".parse().unwrap()), "curl/8.4.0")
                .await,
            BotDecision::Pass
        ));
        // Bare IPs act as host ranges.
        assert!(matches!(
            policy
                .evaluate(Some("10.20.30.40".parse().unwrap()), "")
                .await,
            BotDecision::Pass
        ));
        assert!(matches!(
            policy
                .evaluate(
                    Some("2001:db8:1::5".parse().unwrap()),
                    "python-requests/2.31.0"
                )
                .await,
            BotDecision::Pass
        ));
        // Outside every range: back to the user-agent verdict.
        assert!(matches!(
            policy
                .evaluate(Some("198.51.100.9".parse().unwrap()), "curl/8.4.0")
                .await,
            BotDecision::Deny(_)
        ));
    }

    #[test]
    fn contains_ignore_case_matches_substrings_only() {
        assert!(contains_ignore_case("curl/8.4.0", "CURL/"));
        assert!(contains_ignore_case("Curl/8.4.0", "curl/"));
        assert!(!contains_ignore_case("curl/8.4.0", "wget/"));
        // Needle longer than haystack, and empty needle, are not matches.
        assert!(!contains_ignore_case("ab", "abc"));
        assert!(!contains_ignore_case("anything", ""));
    }

    /// A block action answers non-browser agents with 403 even with the WAF
    /// engine disabled; whitelisted bots and browsers pass.
    #[tokio::test]
    async fn test_bot_protection_blocks_non_browser() {
        let (_guard, _agent, _dir) =
            install_bot_agent(proto::WafAction::Block).await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let RequestPluginResult::Respond(resp) =
            run_request_with_ua(&plugin, "203.0.113.7", "curl/8.4.0").await
        else {
            panic!("expected bot protection to answer");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

        assert!(
            run_request_with_ua(
                &plugin,
                "203.0.113.7",
                "Mozilla/5.0 (compatible; Googlebot/2.1)"
            )
            .await
                == RequestPluginResult::Continue
        );
        assert!(
            run_request_with_ua(
                &plugin,
                "203.0.113.7",
                "Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0"
            )
            .await
                == RequestPluginResult::Continue
        );
    }

    /// The challenge action answers with the JS challenge (503).
    #[tokio::test]
    async fn test_bot_protection_challenge_action() {
        let (_guard, _agent, _dir) =
            install_bot_agent(proto::WafAction::Challenge).await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        let RequestPluginResult::Respond(resp) =
            run_request_with_ua(&plugin, "203.0.113.7", "wget/1.21").await
        else {
            panic!("expected bot protection to answer");
        };
        assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);
    }

    /// The log action records a security event but lets the request through.
    #[tokio::test]
    async fn test_bot_protection_log_action() {
        let (_guard, agent, _dir) =
            install_bot_agent(proto::WafAction::Log).await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        assert!(
            run_request_with_ua(&plugin, "203.0.113.7", "python/3.12").await
                == RequestPluginResult::Continue
        );
        let event = agent.client.pop_log().await.unwrap();
        assert_eq!("bot_protection", event.waf_rule_id);
        assert_eq!("monitor", event.waf_action);
    }

    /// Builds one rate limit rule for the tests.
    fn rate_rule(
        id: &str,
        chars: Vec<proto::RateLimitCharacteristics>,
        expression: &str,
        threshold: u32,
        action: proto::WafAction,
        mitigation: u32,
    ) -> proto::RateLimitRule {
        proto::RateLimitRule {
            id: id.to_string(),
            name: format!("rule-{id}"),
            expression: expression.to_string(),
            characteristics: chars.into_iter().map(|c| c as i32).collect(),
            characteristic_params: Vec::new(),
            period_seconds: 60,
            threshold,
            action: action as i32,
            mitigation_timeout_seconds: mitigation,
            enabled: true,
            priority: 0,
        }
    }

    /// Installs an agent whose site carries the given rate limit rules and no
    /// WAF engine.
    async fn install_rate_agent(
        rules: Vec<proto::RateLimitRule>,
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<PingWafAgent>,
        tempfile::TempDir,
    ) {
        let installed = install_test_agent().await;
        installed
            .1
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        waf: Some(proto::WafConfig {
                            enabled: false,
                            ..Default::default()
                        }),
                        rate_limit_rules: rules,
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                }],
                config_hash: "hash-1".to_string(),
                updated_at: None,
            })
            .unwrap();
        installed
    }

    /// Builds one GET request with an explicit path and optional cookie.
    async fn run_rate_request(
        plugin: &WafPlugin,
        client_ip: &str,
        path: &str,
        cookie: Option<&str>,
    ) -> RequestPluginResult {
        let cookie_line = cookie
            .map(|value| format!("Cookie: {value}\r\n"))
            .unwrap_or_default();
        let input_header = format!(
            "GET {path} HTTP/1.1\r\nHost: example.com\r\n{cookie_line}\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = Ctx::default();
        ctx.conn.client_ip = Some(client_ip.to_string());
        plugin
            .handle_request(PluginStep::EarlyRequest, &mut session, &mut ctx)
            .await
            .unwrap()
    }

    #[test]
    fn rate_rule_build_filters_unenforceable_rules() {
        let build = |rule: proto::RateLimitRule| {
            CompiledRateRule::build(&CacheRateLimitRule {
                id: rule.id,
                name: rule.name,
                expression: rule.expression,
                characteristics: rule
                    .characteristics
                    .iter()
                    .map(|c| {
                        format!(
                            "{:?}",
                            proto::RateLimitCharacteristics::try_from(*c)
                                .unwrap_or(
                                    proto::RateLimitCharacteristics::RateLimitCharIp
                                )
                        )
                    })
                    .collect(),
                characteristic_params: Vec::new(),
                period_seconds: rule.period_seconds,
                threshold: rule.threshold,
                action: CacheWafAction::from(rule.action),
                mitigation_timeout_seconds: rule.mitigation_timeout_seconds,
                enabled: rule.enabled,
                priority: rule.priority,
            })
        };

        // Zero threshold or period would never trip (or trip everything).
        assert!(
            build(rate_rule(
                "a",
                vec![proto::RateLimitCharacteristics::RateLimitCharIp],
                "",
                0,
                proto::WafAction::Block,
                60
            ))
            .is_none()
        );
        // Disabled rules are skipped.
        let mut disabled = rate_rule(
            "b",
            vec![proto::RateLimitCharacteristics::RateLimitCharIp],
            "",
            10,
            proto::WafAction::Block,
            0,
        );
        disabled.enabled = false;
        assert!(build(disabled).is_none());
        // Characteristics the edge cannot key on invalidate the whole rule.
        assert!(
            build(rate_rule(
                "c",
                vec![
                    proto::RateLimitCharacteristics::RateLimitCharIp,
                    proto::RateLimitCharacteristics::RateLimitCharJa3,
                ],
                "",
                10,
                proto::WafAction::Block,
                0
            ))
            .is_none()
        );
        // Allow actions do nothing meaningful on a counter.
        assert!(
            build(rate_rule(
                "d",
                vec![proto::RateLimitCharacteristics::RateLimitCharIp],
                "",
                10,
                proto::WafAction::Allow,
                0
            ))
            .is_none()
        );
        // A parse failure leaves the rule out rather than matching nothing.
        assert!(
            build(rate_rule(
                "e",
                vec![proto::RateLimitCharacteristics::RateLimitCharIp],
                "http.request.uri.path ~~~",
                10,
                proto::WafAction::Block,
                0
            ))
            .is_none()
        );
        // The prost debug name of ip_nat normalises to the plain IP key.
        let nat = build(rate_rule(
            "f",
            vec![proto::RateLimitCharacteristics::RateLimitCharIpNat],
            "",
            10,
            proto::WafAction::Block,
            0,
        ))
        .unwrap();
        assert_eq!(vec![RateChar::Ip], nat.chars);
    }

    #[test]
    fn rate_rule_build_accepts_parameterized_characteristics() {
        let build = |characteristics: &[&str], params: &[&str]| {
            CompiledRateRule::build(&CacheRateLimitRule {
                id: "p".to_string(),
                name: "rule-p".to_string(),
                expression: String::new(),
                characteristics: characteristics
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                characteristic_params: params
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                period_seconds: 60,
                threshold: 10,
                action: CacheWafAction::Block,
                mitigation_timeout_seconds: 0,
                enabled: true,
                priority: 0,
            })
        };

        // Header names are matched case-insensitively, so the stored name is
        // lowercased; cookie and query names stay as configured.
        let header = build(&["RateLimitCharHeader"], &["X-Api-Key"]).unwrap();
        assert_eq!(
            vec![RateChar::Header("x-api-key".to_string())],
            header.chars
        );
        let cookie_query = build(
            &["RateLimitCharCookie", "RateLimitCharQuery"],
            &["Session", "lang"],
        )
        .unwrap();
        assert_eq!(
            vec![
                RateChar::Cookie("Session".to_string()),
                RateChar::Query("lang".to_string())
            ],
            cookie_query.chars
        );
        // A parameterized kind without a name cannot key a counter.
        assert!(build(&["RateLimitCharHeader"], &[]).is_none());
        assert!(build(&["RateLimitCharQuery"], &["  "]).is_none());
    }

    #[test]
    fn rate_limit_keys_parameterized_characteristics() {
        let rule = CompiledRateRule {
            id: "rl-h".to_string(),
            name: "per-key".to_string(),
            expression: None,
            chars: vec![
                RateChar::Header("X-Api-Key".to_string()),
                RateChar::Cookie("Session".to_string()),
                RateChar::Query("lang".to_string()),
            ],
            period_secs: 60,
            threshold: 1,
            mitigation_secs: 0,
            action: RateAction::Block,
        };
        let request = |headers: Vec<(&str, &str)>, query: &str| RequestData {
            method: "GET".to_string(),
            path: "/".to_string(),
            query: query.to_string(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: None,
            client_ip: "1.1.1.1".to_string(),
            country_code: None,
            scheme: "http".to_string(),
            protocol: "HTTP/1.1".to_string(),
        };
        let sep = '\u{1f}';

        let full = request(
            vec![("x-api-key", "v1"), ("Cookie", "a=1; Session=abc; b=2")],
            "lang=en&page=2",
        );
        assert_eq!(
            format!("rl-h{sep}v1{sep}abc{sep}en"),
            rule.counter_key(&full, "s.test", None)
        );

        // Header matching is case-insensitive; a present-but-empty query
        // value keys as "" rather than the missing bucket.
        let mixed = request(vec![("X-API-KEY", "v1")], "lang=");
        assert_eq!(
            format!("rl-h{sep}v1{sep}-{sep}"),
            rule.counter_key(&mixed, "s.test", None)
        );

        // Requests missing every parameterized value share the '-' bucket
        // instead of bypassing the counter.
        let empty = request(Vec::new(), "page=2");
        assert_eq!(
            format!("rl-h{sep}-{sep}-{sep}-"),
            rule.counter_key(&empty, "s.test", None)
        );
    }

    #[test]
    fn rate_policy_counts_per_key_and_expires() {
        let policy = RateLimitPolicy {
            rules: vec![CompiledRateRule {
                id: "rl".to_string(),
                name: "per-ip".to_string(),
                expression: None,
                chars: vec![RateChar::Ip],
                period_secs: 60,
                threshold: 1,
                mitigation_secs: 0,
                action: RateAction::Block,
            }],
        };
        let counters: DashMap<String, RateCounter> = DashMap::new();
        let request = |ip: &str, path: &str| RequestData {
            method: "GET".to_string(),
            path: path.to_string(),
            query: String::new(),
            headers: Vec::new(),
            body: None,
            client_ip: ip.to_string(),
            country_code: None,
            scheme: "http".to_string(),
            protocol: "HTTP/1.1".to_string(),
        };

        assert!(
            policy
                .evaluate(
                    &counters,
                    &request("1.1.1.1", "/"),
                    "s.test",
                    false,
                    "1.1.1.1".parse().ok(),
                )
                .deny
                .is_none()
        );
        let outcome = policy.evaluate(
            &counters,
            &request("1.1.1.1", "/"),
            "s.test",
            false,
            "1.1.1.1".parse().ok(),
        );
        let deny = outcome.deny.expect("second request must trip");
        assert!(!deny.challenge);
        assert!(deny.retry_after > 0 && deny.retry_after <= 60);

        // A different key (IP or path dimension) keeps its own counter.
        assert!(
            policy
                .evaluate(
                    &counters,
                    &request("2.2.2.2", "/"),
                    "s.test",
                    false,
                    "2.2.2.2".parse().ok(),
                )
                .deny
                .is_none()
        );
    }

    /// A block action answers the third request over the threshold with 429
    /// while other IPs keep their own counters.
    #[tokio::test]
    async fn test_rate_limit_blocks_over_threshold() {
        let (_guard, _agent, _dir) = install_rate_agent(vec![rate_rule(
            "rl-block",
            vec![proto::RateLimitCharacteristics::RateLimitCharIp],
            "",
            2,
            proto::WafAction::Block,
            60,
        )])
        .await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        assert!(
            run_rate_request(&plugin, "203.0.113.9", "/", None).await
                == RequestPluginResult::Continue
        );
        assert!(
            run_rate_request(&plugin, "203.0.113.9", "/", None).await
                == RequestPluginResult::Continue
        );
        let RequestPluginResult::Respond(resp) =
            run_rate_request(&plugin, "203.0.113.9", "/", None).await
        else {
            panic!("expected the rate limit to answer");
        };
        assert_eq!(http::StatusCode::TOO_MANY_REQUESTS, resp.status);

        // Another client IP is unaffected.
        assert!(
            run_rate_request(&plugin, "203.0.113.10", "/", None).await
                == RequestPluginResult::Continue
        );
    }

    /// The path characteristic splits counters and the expression restricts
    /// which requests a rule counts at all.
    #[tokio::test]
    async fn test_rate_limit_path_and_expression() {
        let (_guard, _agent, _dir) = install_rate_agent(vec![rate_rule(
            "rl-api",
            vec![
                proto::RateLimitCharacteristics::RateLimitCharIp,
                proto::RateLimitCharacteristics::RateLimitCharPath,
            ],
            r#"http.request.uri.path starts_with "/api/""#,
            1,
            proto::WafAction::Block,
            0,
        )])
        .await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        // First hit counts, second trips, a different path keeps its own
        // counter and requests outside /api/ are never counted.
        assert!(
            run_rate_request(&plugin, "203.0.113.11", "/api/list", None).await
                == RequestPluginResult::Continue
        );
        let RequestPluginResult::Respond(resp) =
            run_rate_request(&plugin, "203.0.113.11", "/api/list", None).await
        else {
            panic!("expected the rate limit to answer");
        };
        assert_eq!(http::StatusCode::TOO_MANY_REQUESTS, resp.status);

        // The tripped client is refused at the edge for the retry window:
        // even an uncounted path is answered without reaching the counters.
        let RequestPluginResult::Respond(resp) =
            run_rate_request(&plugin, "203.0.113.11", "/other", None).await
        else {
            panic!("expected the edge block to answer");
        };
        assert_eq!(http::StatusCode::FORBIDDEN, resp.status);

        // A fresh client proves the path characteristic splits counters
        // (/api/detail keeps counting from zero) and the expression keeps
        // non-/api/ requests out of the rule entirely.
        assert!(
            run_rate_request(&plugin, "203.0.113.15", "/api/list", None).await
                == RequestPluginResult::Continue
        );
        assert!(
            run_rate_request(&plugin, "203.0.113.15", "/api/detail", None)
                .await
                == RequestPluginResult::Continue
        );
        assert!(
            run_rate_request(&plugin, "203.0.113.15", "/other", None).await
                == RequestPluginResult::Continue
        );
        assert!(
            run_rate_request(&plugin, "203.0.113.15", "/other", None).await
                == RequestPluginResult::Continue
        );
    }

    /// The log action ships a security event but lets the request continue.
    #[tokio::test]
    async fn test_rate_limit_log_action_records_event() {
        let (_guard, agent, _dir) = install_rate_agent(vec![rate_rule(
            "rl-log",
            vec![proto::RateLimitCharacteristics::RateLimitCharIp],
            "",
            1,
            proto::WafAction::Log,
            0,
        )])
        .await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        assert!(
            run_rate_request(&plugin, "203.0.113.12", "/", None).await
                == RequestPluginResult::Continue
        );
        assert!(
            run_rate_request(&plugin, "203.0.113.12", "/", None).await
                == RequestPluginResult::Continue
        );
        let event = agent.client.pop_log().await.unwrap();
        assert_eq!("rl-log", event.waf_rule_id);
        assert_eq!("monitor", event.waf_action);
    }

    /// The challenge action serves the JS challenge; a client holding a valid
    /// clearance cookie is exempt and keeps passing.
    #[tokio::test]
    async fn test_rate_limit_challenge_and_clearance() {
        let (_guard, _agent, _dir) = install_rate_agent(vec![rate_rule(
            "rl-challenge",
            vec![proto::RateLimitCharacteristics::RateLimitCharIp],
            "",
            1,
            proto::WafAction::Challenge,
            60,
        )])
        .await;
        let plugin = WafPlugin::new(
            &toml::from_str::<PluginConf>(r###"mode = "block""###).unwrap(),
        )
        .unwrap();

        // The second request trips and receives the challenge page.
        assert!(
            run_rate_request(&plugin, "203.0.113.13", "/", None).await
                == RequestPluginResult::Continue
        );
        let RequestPluginResult::Respond(resp) =
            run_rate_request(&plugin, "203.0.113.13", "/", None).await
        else {
            panic!("expected the challenge to answer");
        };
        assert_eq!(http::StatusCode::SERVICE_UNAVAILABLE, resp.status);

        // A solved clearance exempts the client: the rule neither counts nor
        // stops it, even though the counter is already over the threshold.
        let secret = resolve_cookie_secret("");
        let manager = CookieManager::new(secret.as_bytes(), 3600);
        let cookie = manager.issue_clearance(
            ClearanceLevel::NonInteractive,
            "site-1",
            "fingerprint",
        );
        assert!(
            run_rate_request(
                &plugin,
                "203.0.113.13",
                "/",
                Some(&format!("{CLEARANCE_COOKIE_NAME}={cookie}"))
            )
            .await
                == RequestPluginResult::Continue
        );
    }
}
