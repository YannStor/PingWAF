use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use pingap_cache::quota;
use pingap_core::normalize_host;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use pingwaf_proto::control_plane as proto;

mod persist;

use persist::{
    check_format_version, content_crc32, content_matches, write_atomic,
    CacheHealth, LoadSource, CACHE_FORMAT_VERSION,
};

// ─────────────────────────────────────────────────────────────
// Serializable cache types (local mirrors of proto types)
// ─────────────────────────────────────────────────────────────

/// Top-level cached state that is swapped atomically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRules {
    /// Site rules keyed by site_id
    ///
    /// The values are shared via `Arc` so the hot-path lookups
    /// (`get_site_rules`) return a pointer instead of deep-cloning every
    /// rule the site carries. Updates build a new map but reuse the
    /// `Arc`s of untouched sites.
    pub sites: HashMap<String, Arc<SiteRules>>,
    /// Domain → site_id index for fast lookup
    ///
    /// Keys and values are shared via `Arc<str>` so the copy-on-write
    /// snapshot in the `rcu` updates clones pointers instead of every
    /// domain string on the heap.
    pub domain_index: HashMap<Arc<str>, Arc<str>>,
    /// Domain → disconnected (failover) policy, covering every site the
    /// control plane knows about — including ones whose rule bundle this
    /// agent has not (yet) received. Consulted when a host has no synced
    /// rules, which is exactly when `sites` cannot answer.
    ///
    /// Behind an `Arc` because every bundle replaces the registry
    /// wholesale: an update swaps the pointer instead of re-cloning the
    /// whole map into the new snapshot.
    #[serde(default)]
    pub failover_registry: Arc<HashMap<String, FailoverMode>>,
    /// Control-plane-wide default for hosts absent from
    /// `failover_registry`. `None` when the server never sent it (old
    /// control plane), which makes the agent fall back to its local
    /// `config.fail_open`.
    #[serde(default)]
    pub global_fail_open: Option<bool>,
    /// Deployment-wide cache ceiling; `None` when the server never sent it
    /// (old control plane) — the generator and quota logic then fall back to
    /// their built-in defaults. Behind an `Arc` because bundles replace it
    /// wholesale, like [`Self::failover_registry`].
    #[serde(default)]
    pub global_cache: Option<Arc<GlobalCacheSettings>>,
    /// Deployment-wide default for verifying an origin's TLS certificate.
    /// `None` when the server never sent it (old control plane); the
    /// configuration generator then keeps its historical lenient default
    /// rather than switching every HTTPS origin to strict validation.
    #[serde(default)]
    pub origin_verify_cert: Option<bool>,
    /// When the cache was last updated from the server
    pub updated_at: DateTime<Utc>,
    /// Hash of the configuration (for delta sync). An `Arc` so the hot path
    /// reads it without a heap copy.
    pub config_hash: Arc<str>,
}

impl Default for CachedRules {
    fn default() -> Self {
        Self {
            sites: HashMap::new(),
            domain_index: HashMap::new(),
            failover_registry: Arc::new(HashMap::new()),
            global_fail_open: None,
            global_cache: None,
            origin_verify_cert: None,
            updated_at: Utc::now(),
            config_hash: Arc::from(""),
        }
    }
}

/// Rules for a single site/domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteRules {
    pub site_id: String,
    pub domain: String,
    pub alternate_domains: Vec<String>,
    /// Lifecycle status (`active`/`paused`/`pending`); caches written before
    /// the edge consumed it default to `active`.
    #[serde(default = "default_site_status")]
    pub status: String,
    pub waf_config: Option<WafConfig>,
    pub rate_limit_rules: Vec<RateLimitRule>,
    pub ip_access_rules: Vec<IpAccessRule>,
    pub geo_config: Option<GeoConfig>,
    pub cache_rules: Vec<CacheRule>,
    pub challenge_config: Option<ChallengeConfig>,
    pub rewrite_rules: Vec<RewriteRule>,
    pub error_pages: Vec<CustomErrorPage>,
    pub ssl_config: Option<SslConfig>,
    pub upstreams: Vec<UpstreamConfig>,
    /// Path routes to origin pools; empty for caches written before pools
    /// existed.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub bot_protection: Option<BotProtectionConfig>,
    /// Site-wide basic auth gate; `None` when the site has none configured.
    #[serde(default)]
    pub basic_auth: Option<BasicAuthConfig>,
    /// Site-level OIDC authentication; `None` when the site has none.
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    /// Observation mode: detections keep running but nothing is enforced —
    /// WAF, IP/geo rules, bot protection and rate limiting only record.
    #[serde(default)]
    pub observation_mode: bool,
    /// Site-level cache limits; `None` when the site overrides nothing and
    /// every limit follows the global ceiling.
    #[serde(default)]
    pub cache_settings: Option<SiteCacheSettings>,
    /// Forwarded-header client IP resolution; disabled when the site has no
    /// CDN / reverse proxy in front of it.
    #[serde(default)]
    pub proxy_trust: ProxyTrustConfig,
    /// Response body replacement policy, compiled into the site's
    /// `sub_filter` plugin. `None` when the site replaces nothing — and for
    /// every snapshot written before the policy existed.
    #[serde(default)]
    pub response_replace: Option<ResponseReplaceConfig>,
    /// AI crawler control: the rendered robots.txt / llms.txt bodies and the
    /// family actions. `None` for sites (and snapshots) without it.
    #[serde(default)]
    pub ai_crawl: Option<AiCrawlConfig>,
}

/// AI crawler control for one site.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AiCrawlConfig {
    /// Whether the family actions are enforced.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub default_action: String,
    /// Rendered bodies; empty means the file is not served.
    #[serde(default)]
    pub robots_body: String,
    #[serde(default)]
    pub llms_body: String,
    #[serde(default)]
    pub cache_max_age: u32,
    #[serde(default)]
    pub policies: Vec<AiBotPolicy>,
}

/// One AI crawler family the site distinguishes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AiBotPolicy {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub ua_substrings: Vec<String>,
    #[serde(default)]
    pub category: String,
    /// `allow` / `monitor` / `block`, inheritance already resolved.
    #[serde(default)]
    pub action: String,
}

/// One literal or regex replacement of a [`ResponseReplaceConfig`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResponseReplaceRule {
    /// Text (or regex when `is_regex`) the response body is searched for.
    pub pattern: String,
    /// Text substituted for every match.
    pub replacement: String,
    /// Compile `pattern` as a regular expression.
    #[serde(default)]
    pub is_regex: bool,
}

/// A site's response body replacement policy: what the data plane turns into
/// a `sub_filter` plugin instance for that site.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResponseReplaceConfig {
    /// Regex the request path must match; empty applies to every path.
    #[serde(default)]
    pub path: String,
    /// Status codes the replacement applies to; empty applies to all.
    #[serde(default)]
    pub status_codes: Vec<u32>,
    /// Replacements applied in order; empty is a no-op policy.
    #[serde(default)]
    pub rules: Vec<ResponseReplaceRule>,
}

impl ResponseReplaceConfig {
    /// Whether the policy would generate a plugin that can never fire.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Site-level forwarded-header trust: which header carries the real client
/// IP, whether only the nearest proxy's entry is believed, and which peers
/// are allowed to influence the resolution at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyTrustConfig {
    /// Trust forwarded headers at all.
    #[serde(default)]
    pub enabled: bool,
    /// Lower-case header name; empty means `x-forwarded-for`.
    #[serde(default)]
    pub header: String,
    /// Take the last XFF entry (added by the nearest proxy) instead of the
    /// first one, which the client can spoof.
    #[serde(default = "default_true")]
    pub last_hop_only: bool,
    /// CIDR ranges of proxies allowed to influence the resolved client IP.
    /// Empty = trust nothing (the TCP peer is always used).
    #[serde(default)]
    pub trusted_ranges: Vec<String>,
}

impl Default for ProxyTrustConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            header: String::new(),
            last_hop_only: true,
            trusted_ranges: Vec::new(),
        }
    }
}

impl ProxyTrustConfig {
    /// Effective header name; empty resolves to `x-forwarded-for`.
    pub fn effective_header(&self) -> &str {
        if self.header.is_empty() {
            "x-forwarded-for"
        } else {
            &self.header
        }
    }
}

fn default_true() -> bool {
    true
}

impl SiteRules {
    /// All domains this site responds to.
    pub fn all_domains(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.domain.as_str())
            .chain(self.alternate_domains.iter().map(|s| s.as_str()))
    }

    /// Whether the control plane has paused the site.
    pub fn is_paused(&self) -> bool {
        self.status == site_status::PAUSED
    }
}

/// How a host behaves while the control plane is unreachable and it has no
/// synced rule bundle. Local mirror of `proto::FailoverMode`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum FailoverMode {
    /// Follow the control-plane-wide `global_fail_open` default.
    #[default]
    Inherit,
    /// Keep proxying through the base engine.
    Open,
    /// Answer 503.
    Closed,
}

impl From<i32> for FailoverMode {
    fn from(value: i32) -> Self {
        match value {
            1 => FailoverMode::Open,
            2 => FailoverMode::Closed,
            0 => FailoverMode::Inherit,
            // A newer control plane may know modes this agent does not.
            // Failover is an availability switch, so degrade to the next
            // resolution layer instead of guessing a stricter behaviour.
            other => {
                warn!(
                    value = other,
                    "unknown failover mode from the control plane, treating as inherit"
                );
                FailoverMode::Inherit
            },
        }
    }
}

/// Folds the per-site policy registry of one bundle into a domain-keyed map,
/// covering primary and alternate domains alike. Keys are normalised
/// (lowercase) to match what `pingap_core::get_host` produces on the lookup
/// side, so a `EXAMPLE.com` entry in the control plane still resolves.
fn failover_registry_from(
    policies: &[proto::SitePolicy],
) -> HashMap<String, FailoverMode> {
    let mut registry = HashMap::with_capacity(policies.len());
    for policy in policies {
        let mode = FailoverMode::from(policy.mode);
        registry.insert(normalize_host(&policy.domain), mode);
        for alt in &policy.alternate_domains {
            registry.insert(normalize_host(alt), mode);
        }
    }
    registry
}

/// Exact lookup with wildcard fallback, mirroring the routing layer's
/// `HostSelector::Suffix` semantics: `*.example.com` covers strict
/// subdomains only, never the apex itself. `www.a.example.com` tries the
/// exact key first, then `*.a.example.com`, `*.example.com`, … — most
/// specific wildcard wins, so a wildcard site never shadows an exact one
/// and a longer wildcard beats a shorter one.
///
/// Exact hits cost a single lookup and no allocation; the wildcard walk
/// only runs on a miss and reuses one buffer.
fn lookup_with_wildcard<'a, K, V>(
    map: &'a HashMap<K, V>,
    domain: &str,
) -> Option<&'a V>
where
    K: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    if let Some(value) = map.get(domain) {
        return Some(value);
    }
    let mut buf = String::with_capacity(domain.len() + 2);
    let mut rest = domain;
    while let Some((_, suffix)) = rest.split_once('.') {
        if suffix.is_empty() {
            break;
        }
        buf.clear();
        buf.push_str("*.");
        buf.push_str(suffix);
        if let Some(value) = map.get(&buf) {
            return Some(value);
        }
        rest = suffix;
    }
    None
}

/// The site's effective WAF enforcement state: `(engine mode, observation)`.
/// A missing WAF config means the engine is off.
fn site_enforcement(site: Option<&SiteRules>) -> (WafMode, bool) {
    match site {
        Some(s) => (
            s.waf_config
                .as_ref()
                .map(|c| c.mode)
                .unwrap_or(WafMode::Off),
            s.observation_mode,
        ),
        None => (WafMode::Off, false),
    }
}

/// True when the state enforces WAF block verdicts (block mode without
/// observation), i.e. WAF auto-blocks may be produced.
fn waf_enforcing(state: (WafMode, bool)) -> bool {
    state.0 == WafMode::Block && !state.1
}

/// Persisted site status values, matching `models::sites::site_status` on the
/// control plane.
pub mod site_status {
    pub const ACTIVE: &str = "active";
    pub const PAUSED: &str = "paused";
    pub const PENDING: &str = "pending";
}

/// Default body-withholding window, matching the data-plane default.
fn default_body_stage_timeout() -> u32 {
    30
}

fn default_site_status() -> String {
    site_status::ACTIVE.to_string()
}

/// Maps a `pingwaf.SiteStatusEnum` value onto the persisted string form; the
/// control-plane counterpart is `grpc::config::site_status_proto`, which must
/// stay in sync.
pub fn site_status_str(value: i32) -> String {
    match value {
        1 => site_status::PAUSED,  // SITE_STATUS_PAUSED
        2 => site_status::PENDING, // SITE_STATUS_PENDING
        _ => site_status::ACTIVE,
    }
    .to_string()
}

// ─── WAF ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    pub enabled: bool,
    pub mode: WafMode,
    pub paranoia_level: u32,
    pub sqli_detection: bool,
    pub xss_detection: bool,
    pub rce_detection: bool,
    pub lfi_detection: bool,
    pub ssrf_detection: bool,
    pub bot_detection: bool,
    pub custom_rules: Vec<WafRule>,
    /// Missing on caches written before the override field existed; an old
    /// agent reading such a cache must default to "no overrides" instead of
    /// failing deserialisation.
    #[serde(default)]
    pub managed_overrides: Vec<RuleOverride>,
    pub ml_enabled: bool,
    pub ml_model_path: String,
    pub ml_threshold: f64,
    pub anomaly_threshold: u32,
    /// Seconds the data plane may withhold a body while inspecting it.
    /// Caches written before this field existed default to 30.
    #[serde(default = "default_body_stage_timeout")]
    pub body_stage_timeout_secs: u32,
    /// Site-level WAF grading. Defaults keep old on-disk caches (written
    /// before these fields existed) enforcing everything.
    #[serde(default)]
    pub advanced_mode: bool,
    #[serde(default)]
    pub monitor_categories: Vec<String>,
    #[serde(default)]
    pub monitor_stacks: Vec<String>,
    #[serde(default)]
    pub monitor_managed_rules: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Off,
    Monitor,
    Block,
}

impl From<i32> for WafMode {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Monitor,
            2 => Self::Block,
            0 => Self::Off,
            // A newer control plane may know modes this agent does not.
            // Silently treating the site as off would disable its WAF for
            // the whole upgrade window; enforcing (block) matches the
            // fail-close convention used by `WafAction`.
            unknown => {
                warn!(value = unknown, "unknown waf mode; enforcing as block");
                Self::Block
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub expression: String,
    pub action: WafAction,
    pub severity: u32,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub mode: WafMode,
    pub priority: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafAction {
    Block,
    Log,
    Challenge,
    JsChallenge,
    Allow,
    /// Only meaningful where the protocol allows it (the geo policy and the
    /// IP access rules); a WAF engine verdict never carries it.
    BasicAuth,
}

impl From<i32> for WafAction {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Log,
            2 => Self::Challenge,
            3 => Self::JsChallenge,
            4 => Self::Allow,
            5 => Self::BasicAuth,
            // 0 is the enum's own block value. Anything else comes from a
            // control plane newer than this data plane: warn instead of
            // enforcing an action we do not understand as a block.
            unknown => {
                if unknown != 0 {
                    warn!(
                        value = unknown,
                        "unknown waf action; enforcing as block"
                    );
                }
                Self::Block
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOverride {
    pub rule_id: String,
    pub tag: String,
    pub action: WafAction,
    pub enabled: bool,
}

// ─── Rate Limiting ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    pub id: String,
    pub name: String,
    pub expression: String,
    pub characteristics: Vec<String>,
    /// Parameter names for `RateLimitCharHeader/Cookie/Query` characteristics,
    /// parallel to `characteristics`. Older caches without this field load as
    /// empty.
    #[serde(default)]
    pub characteristic_params: Vec<String>,
    pub period_seconds: u32,
    pub threshold: u32,
    pub action: WafAction,
    pub mitigation_timeout_seconds: u32,
    pub enabled: bool,
    pub priority: u32,
}

// ─── IP Access ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAccessRule {
    pub id: String,
    pub name: String,
    pub ip_ranges: Vec<String>,
    pub action: IpAccessAction,
    pub note: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpAccessAction {
    Block,
    Challenge,
    JsChallenge,
    Allow,
    /// The matching client must pass the site's basic auth gate.
    BasicAuth,
}

impl From<i32> for IpAccessAction {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Challenge,
            2 => Self::JsChallenge,
            3 => Self::Allow,
            4 => Self::BasicAuth,
            // 0 is the enum's own block value. Anything else comes from a
            // control plane newer than this data plane: warn instead of
            // enforcing an action we do not understand as a block.
            unknown => {
                if unknown != 0 {
                    warn!(
                        value = unknown,
                        "unknown ip access action; enforcing as block"
                    );
                }
                Self::Block
            },
        }
    }
}

// ─── Geo ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConfig {
    pub enabled: bool,
    pub blocked_countries: Vec<String>,
    pub allowed_countries: Vec<String>,
    pub blocked_asns: Vec<String>,
    pub block_unknown: bool,
    pub action: WafAction,
}

// ─── Cache Rules ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRule {
    pub id: String,
    pub name: String,
    pub match_expression: String,
    pub edge_ttl_seconds: u32,
    pub browser_ttl_seconds: u32,
    pub disk_quota_mb: u32,
    pub cache_eligible: bool,
    pub cache_key_headers: Vec<String>,
    pub respect_origin_headers: bool,
    pub stale_while_revalidate_seconds: u32,
    pub enabled: bool,
}

/// Deployment-wide cache ceiling, mirrored from the control plane's
/// `cache_settings` row. Absent fields fall back to the built-in defaults
/// the agent used before the ceiling existed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GlobalCacheSettings {
    #[serde(default)]
    pub max_file_size_mb: Option<u32>,
    #[serde(default)]
    pub max_space_mb: Option<u32>,
    #[serde(default)]
    pub master_enabled: Option<bool>,
    #[serde(default)]
    pub default_edge_ttl_seconds: Option<u32>,
}

impl GlobalCacheSettings {
    /// Built-in default: the ceiling the configuration generator hardcoded
    /// before the setting existed.
    pub fn max_file_size_mb(&self) -> u32 {
        self.max_file_size_mb.unwrap_or(16)
    }

    /// `0` = unlimited (no `?max_size=` on the cache directory).
    pub fn max_space_mb(&self) -> u32 {
        self.max_space_mb.unwrap_or(0)
    }

    pub fn master_enabled(&self) -> bool {
        self.master_enabled.unwrap_or(true)
    }

    /// `0` = no fallback TTL for rules without an explicit one.
    pub fn default_edge_ttl_seconds(&self) -> u32 {
        self.default_edge_ttl_seconds.unwrap_or(0)
    }
}

/// Site-level cache limits, mirrored from the `sites` cache columns. `None`
/// fields fall back level by level: type limit → site cap → global cap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SiteCacheSettings {
    #[serde(default)]
    pub max_file_size_mb: Option<u32>,
    #[serde(default)]
    pub type_max_file_size_mb: HashMap<String, u32>,
    #[serde(default)]
    pub type_policy: Option<CacheTypePolicy>,
}

/// One content family of a site's extension-based cache policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CacheTypeCategory {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub edge_ttl_seconds: u32,
    #[serde(default)]
    pub browser_ttl_seconds: u32,
    #[serde(default)]
    pub extensions: Vec<String>,
}

/// Extension-based cache policy: five fixed content families an
/// administrator tunes per site. Compiled into cache rules behind the
/// site's custom rules in the data plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CacheTypePolicy {
    #[serde(default)]
    pub web_assets: Option<CacheTypeCategory>,
    #[serde(default)]
    pub image: Option<CacheTypeCategory>,
    #[serde(default)]
    pub media: Option<CacheTypeCategory>,
    #[serde(default)]
    pub other: Option<CacheTypeCategory>,
    #[serde(default)]
    pub html: Option<CacheTypeCategory>,
}

impl CacheTypePolicy {
    /// Iterates the present categories in evaluation order.
    pub fn iter(&self) -> impl Iterator<Item = &CacheTypeCategory> {
        [
            self.web_assets.as_ref(),
            self.image.as_ref(),
            self.media.as_ref(),
            self.other.as_ref(),
            self.html.as_ref(),
        ]
        .into_iter()
        .flatten()
    }
}

// ─── Challenge ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConfig {
    pub enabled: bool,
    pub under_attack_mode: bool,
    pub default_level: ChallengeLevel,
    pub clearance_duration_seconds: u32,
    pub exempt_paths: Vec<String>,
    pub request_threshold: u32,
    pub browser_integrity_check: bool,
    pub tls_fingerprint_check: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeLevel {
    None,
    NonInteractive,
    Managed,
    Interactive,
}

impl From<i32> for ChallengeLevel {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::NonInteractive,
            2 => Self::Managed,
            3 => Self::Interactive,
            0 => Self::None,
            // A newer control plane may know levels this agent does not.
            // Degrading to `None` would silently stop challenging; the
            // strongest level keeps the protection fail-close.
            unknown => {
                warn!(
                    value = unknown,
                    "unknown challenge level; enforcing as interactive"
                );
                Self::Interactive
            },
        }
    }
}

// ─── Bot Protection ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotProtectionConfig {
    pub enabled: bool,
    pub action: WafAction,
    pub known_bots_whitelist: Vec<String>,
    /// Expanded CIDR ranges of the configured verified-bot IP group; a
    /// client IP inside any of them counts as a verified bot.
    pub verified_bot_ranges: Vec<String>,
    /// Verify known crawler user agents by DNS reverse + forward lookups.
    pub dns_verification_enabled: bool,
}

// ─── Basic Auth ─────────────────────────────────────────────

/// Site-wide HTTP basic authentication, enforced by the WAF plugin before the
/// cache plugin can answer from a stored response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    pub enabled: bool,
    /// Realm advertised in `WWW-Authenticate`.
    pub realm: String,
    pub credentials: Vec<BasicAuthCredential>,
    /// Seconds a failed attempt is delayed before the 401 goes out.
    pub delay_seconds: u32,
    /// Strip the `Authorization` header once the request is authenticated.
    pub hide_credentials: bool,
}

/// One accepted credential, pre-encoded by the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthCredential {
    pub username: String,
    /// Base64 of `username:password`, the payload a client sends in the
    /// `Authorization: Basic …` header.
    pub authorization: String,
}

// ─── OIDC ───────────────────────────────────────────────────

/// Site-level OIDC (OpenID Connect) authentication, enforced before the
/// request reaches the origin. Mirrors `proto::OidcConfig` field-for-field.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Whether OIDC authentication is enforced.
    #[serde(default)]
    pub enabled: bool,
    /// Issuer URL; the well-known discovery document is read from
    /// `<issuer>/.well-known/openid-configuration`.
    #[serde(default)]
    pub issuer: String,
    /// OAuth2 client ID registered at the identity provider.
    #[serde(default)]
    pub client_id: String,
    /// OAuth2 client secret.
    #[serde(default)]
    pub client_secret: String,
    /// Secret used to encrypt the session cookie (e.g. base64 of 32 bytes).
    #[serde(default)]
    pub cookie_secret: String,
    /// Path the provider redirects back to after login.
    #[serde(default)]
    pub redirect_path: String,
    /// Path that clears the session and redirects to the provider's logout.
    #[serde(default)]
    pub logout_path: String,
    /// Absolute callback URL registered at the identity provider.
    #[serde(default)]
    pub redirect_url: String,
    /// Requested scopes, in addition to the defaults.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Name of the session cookie.
    #[serde(default)]
    pub cookie_name: String,
    /// Session lifetime in seconds.
    #[serde(default)]
    pub session_ttl_seconds: u32,
    /// Claims copied from the ID token into request headers.
    #[serde(default)]
    pub claims_to_headers: Vec<OidcHeaderClaim>,
    /// What a signed-in visitor must satisfy: `allow_all` (default),
    /// `require_any`, `require_all`. Authenticating proves who someone is;
    /// this is the half that says whether they may enter.
    #[serde(default)]
    pub access_mode: String,
    /// How a visitor signs in: `oidc` (default), `local` or `both`.
    /// `access_mode` decides who may enter once signed in; this decides how
    /// they sign in at all. Empty on a config written before the field
    /// existed, which the plugin reads as `oidc`.
    #[serde(default)]
    pub auth_mode: String,
    /// Rules [`Self::access_mode`] applies. Empty with an enforcing mode
    /// denies everyone, which is why the control plane refuses to ship it.
    #[serde(default)]
    pub access_rules: Vec<OidcAccessRule>,
}

/// One claim-to-header mapping for [`OidcConfig`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OidcHeaderClaim {
    /// Claim name in the ID token.
    pub claim: String,
    /// Header the claim value is copied into.
    pub header: String,
}

/// One access rule for [`OidcConfig`]: how a claim of the validated ID token
/// is held against `value`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OidcAccessRule {
    /// Claim name in the ID token, e.g. `groups`.
    pub claim: String,
    /// `eq` / `ne` / `contains` / `in` / `exists`.
    pub operator: String,
    /// What to compare against; unused by `exists`.
    #[serde(default)]
    pub value: String,
}

// ─── Rewrite ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRule {
    pub id: String,
    pub name: String,
    pub match_expression: String,
    pub direction: RewriteDirection,
    #[serde(default)]
    pub operations: Vec<RewriteOperation>,
    pub enabled: bool,
    pub priority: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteDirection {
    Request,
    Response,
}

impl From<i32> for RewriteDirection {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Response,
            _ => Self::Request,
        }
    }
}

/// One declarative rewrite operation mirroring the console's operations JSON:
/// `op_type` is one of set_header | add_header | remove_header | set_path |
/// regex_replace_path | set_query_param | remove_query_param | replace_body;
/// `name`/`value` semantics depend on the type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteOperation {
    #[serde(rename = "type")]
    pub op_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

// ─── Error Pages ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomErrorPage {
    pub id: String,
    pub status_code: u32,
    pub content_type: String,
    pub body_template: String,
    pub name: String,
    pub enabled: bool,
}

// ─── SSL ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslConfig {
    pub cert_pem: String,
    pub key_pem: String,
    pub acme_enabled: bool,
    pub acme_email: String,
    pub acme_challenge_type: String,
    pub acme_dns_provider: String,
    pub acme_dns_config: HashMap<String, String>,
    pub min_tls_version: String,
    pub hsts_enabled: bool,
    pub hsts_max_age: u32,
    pub always_use_https: bool,
    /// Whether the site serves HTTPS at all.
    pub enabled: bool,
    pub max_tls_version: String,
    /// The edge issues certificates on the fly instead of using `cert_pem`.
    pub self_signed: bool,
    pub mtls_enabled: bool,
    pub mtls_client_ca: String,
    /// Id of the `site_certificates` row this posture selects, when any.
    pub certificate_id: String,
    /// Lowercase-hex SHA-256 fingerprints of revoked client certificates.
    #[serde(default)]
    pub mtls_revoked_fingerprints: Vec<String>,
    /// Organization every client certificate must carry; empty skips the
    /// check.
    #[serde(default)]
    pub mtls_organization: String,
    /// Whether a client certificate is required. `None` means the cache
    /// predates the flag, when turning mTLS on always required one.
    #[serde(default)]
    pub mtls_require_client_cert: Option<bool>,
    /// Downstream protocol switches. `None` (a cache written by an older
    /// control plane) means both protocols stay on.
    #[serde(default)]
    pub http1_enabled: Option<bool>,
    #[serde(default)]
    pub http2_enabled: Option<bool>,
}

impl SslConfig {
    /// Whether clients must present a certificate.
    ///
    /// A site may instead only *trust* client certificates (optional mTLS),
    /// in which case a request without one still passes; caches written
    /// before the dedicated flag existed only stored `mtls_enabled`, which
    /// always meant enforcement.
    pub fn mtls_requires_cert(&self) -> bool {
        self.mtls_require_client_cert.unwrap_or(self.mtls_enabled)
    }
}

// ─── Upstream ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub peers: Vec<UpstreamPeer>,
    pub algorithm: String,
    pub health_check: Option<HealthCheckConfig>,
    pub connection_timeout_ms: u32,
    pub read_timeout_ms: u32,
    pub write_timeout_ms: u32,
    /// Origin pool identity; empty for caches written before pools existed.
    #[serde(default)]
    pub pool_id: String,
    /// Complete pingap LB spec (`round_robin` or `hash:<type>[:<key>]`),
    /// superseding `algorithm`.
    #[serde(default)]
    pub algo: String,
    /// Non-empty enables TLS to the origin and sets the SNI.
    #[serde(default)]
    pub sni: String,
    /// `None` means the pool has no opinion: the deployment-wide
    /// `origin_verify_cert` default applies. `Some(true)`/`Some(false)`
    /// pin this pool regardless of that switch.
    #[serde(default)]
    pub verify_cert: Option<bool>,
    /// Address family the data plane may resolve this pool's origin names to:
    /// `auto` (prefer IPv4, keep IPv6 only for a host without an A record),
    /// `ipv4` or `ipv6`. Defaulted so a `sites.json` written before the field
    /// existed still loads, and so does a bundle from a control plane that
    /// does not send it.
    #[serde(default = "default_address_family")]
    pub address_family: String,
    #[serde(default)]
    pub is_default: bool,
}

/// The family an upstream uses when nothing pins one. Same default the column
/// carries, so an upgraded agent and an un-upgraded control plane agree.
fn default_address_family() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamPeer {
    pub address: String,
    pub weight: u32,
    pub tls: bool,
}

/// A path-based route directing matching requests to an origin pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub id: String,
    pub name: String,
    /// prefix | exact | regex
    pub match_type: String,
    /// Raw path; the data plane adds the `=`/`~` marker.
    pub path: String,
    /// Manual location weight; `None` uses pingap's auto weight.
    pub priority: Option<i32>,
    pub enabled: bool,
    pub pool_id: String,
    /// CIDR ranges the client IP must fall into; empty matches every client.
    #[serde(default)]
    pub ip_ranges: Vec<String>,
    /// Strip the matched prefix `path` from the path sent upstream. Snapshots
    /// written before this field existed load with `false` (forward as is).
    #[serde(default)]
    pub strip_prefix: bool,
    /// Fixed path replacing the whole upstream path; empty disables it. Also
    /// defaulted so an old `sites.json` keeps loading.
    #[serde(default)]
    pub rewrite_path: String,
    /// `Host` header sent to the origin; empty keeps the client's Host. Again
    /// defaulted so a snapshot written before the field existed still loads.
    #[serde(default)]
    pub upstream_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub path: String,
    pub interval_seconds: u32,
    pub timeout_ms: u32,
    pub unhealthy_threshold: u32,
    pub healthy_threshold: u32,
}

// ─────────────────────────────────────────────────────────────
// Blocked IP tracking (with TTL)
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIpEntry {
    pub ip: String,
    pub site_id: String,
    pub reason: String,
    /// When the block was recorded; drives the control plane's list order.
    /// Files written before this field existed load with the epoch default.
    #[serde(default = "default_blocked_at")]
    pub blocked_at: DateTime<Utc>,
    /// None = permanent block
    pub expires_at: Option<DateTime<Utc>>,
}

fn default_blocked_at() -> DateTime<Utc> {
    DateTime::from_timestamp(0, 0).expect("epoch is a valid timestamp")
}

impl BlockedIpEntry {
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() >= exp,
            None => false,
        }
    }
}

/// One CIDR block entry in the per-site secondary index: the net is parsed
/// once at insert time so the lookup slow path never re-parses strings, and
/// `expires_at` is mirrored so expired entries can be skipped — and evicted
/// — without touching the main map.
#[derive(Debug, Clone)]
struct CidrEntry {
    /// The full `"site_id:ip"` key into `blocked_ips`.
    key: String,
    net: ipnet::IpNet,
    expires_at: Option<DateTime<Utc>>,
}

/// Collapses an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4
/// form so client addresses and stored CIDR entries are always compared in
/// one family, matching the control plane's normalised storage.
fn normalize_mapped(addr: std::net::IpAddr) -> std::net::IpAddr {
    match addr {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(addr),
        v4 => v4,
    }
}

/// Parses a stored block entry into its covering net, collapsing
/// IPv4-mapped IPv6 CIDRs (written before the control plane normalised
/// them) into the equivalent IPv4 net.
fn parse_entry_net(ip: &str) -> Option<ipnet::IpNet> {
    let net = ip.parse::<ipnet::IpNet>().ok()?;
    match net {
        ipnet::IpNet::V6(v6) => match v6.addr().to_ipv4_mapped() {
            Some(v4) => ipnet::IpNet::new(
                std::net::IpAddr::V4(v4),
                v6.prefix_len() - 96,
            )
            .ok(),
            // A real IPv6 range: keep it as-is.
            None => Some(net),
        },
        v4 => Some(v4),
    }
}

// ─────────────────────────────────────────────────────────────
// Disk persistence metadata
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMetadata {
    config_hash: String,
    updated_at: DateTime<Utc>,
    agent_id: String,
    version: u32,
    /// CRC32 of the exact `sites.json` bytes this metadata stamps. Absent in
    /// snapshots written before integrity checking existed; `None` means the
    /// load skips the CRC check but records why.
    #[serde(default)]
    sites_crc32: Option<u32>,
    /// Byte length of the stamped `sites.json` payload.
    #[serde(default)]
    sites_len: Option<u64>,
}

// ─────────────────────────────────────────────────────────────
// RuleCache — the main public interface
// ─────────────────────────────────────────────────────────────

/// Upper bound on dynamically blocked addresses and ranges (single IPs and
/// CIDR nets share the `blocked_ips` map). An attacker rotating unique source
/// IPs must not be able to grow this map — and the heartbeat snapshot that
/// clones all of it — without limit inside a memory-capped edge container.
const MAX_BLOCKED_IP_ENTRIES: usize = 100_000;

/// Headroom left below [`MAX_BLOCKED_IP_ENTRIES`] when eviction runs, so one
/// pass buys room for thousands of new blocks instead of firing per insert.
const BLOCKED_CAPACITY_HEADROOM: usize = 10_000;

/// Thread-safe local rule cache with disk persistence.
///
/// Uses `ArcSwap` for lock-free reads on the hot path and a separate
/// `DashMap` for dynamically-blocked IPs (which change more frequently
/// than rule bundles).
pub struct RuleCache {
    /// In-memory rule storage (fast, lock-free reads via ArcSwap)
    inner: ArcSwap<CachedRules>,
    /// Dynamically blocked IPs: key = "site_id:ip"
    blocked_ips: DashMap<String, BlockedIpEntry>,
    /// Secondary index over the CIDR entries of `blocked_ips`, keyed by site
    /// id, with the nets pre-parsed. The lookup slow path walks only this —
    /// per-site and parse-free — instead of scanning the whole map.
    cidr_index: DashMap<String, Vec<CidrEntry>>,
    /// Disk persistence directory
    cache_dir: PathBuf,
    /// Agent ID for metadata
    agent_id: String,
    /// Domains this agent currently holds a ceiling for.
    ///
    /// The ledger is shared with the `cache` plugins built from the static
    /// config, which set their own `disk_quota_mb`. Sweeping only what is
    /// recorded here is what keeps a bundle naming no site at all - the first
    /// one, before the control plane has answered - from wiping those.
    quota_domains: Mutex<HashSet<String>>,
    /// Unix seconds of the last successful full-config application; 0 = never.
    last_config_sync_at: AtomicI64,
    /// Unix seconds of the last successful single-site rule bundle
    /// application; 0 = never.
    last_policy_sync_at: AtomicI64,
    /// Serializes every persist path. Rule syncs, blocked-IP flushes and the
    /// shutdown hook can all fire concurrently; interleaved writes would
    /// stamp a sites.json whose CRC no longer matches metadata.json.
    persist_lock: Mutex<()>,
    /// Set whenever `blocked_ips` mutates. Block/unblock are request hot-path
    /// operations and each persist is a full serialize + fsync, so the write
    /// is debounced: mutation only sets this flag, a low-frequency background
    /// task flushes it to disk (see `flush_blocked_ips`), and shutdown
    /// persists through `persist_to_disk` as before.
    blocked_dirty: AtomicBool,
    /// Outcome of the latest disk load / persist cycle, reported by the
    /// heartbeat so a silently degraded cache is visible to the operator.
    health: CacheHealth,
}

impl RuleCache {
    /// Create a new rule cache, loading from disk if a previous cache exists.
    pub fn new(
        cache_dir: PathBuf,
        agent_id: String,
    ) -> anyhow::Result<Arc<Self>> {
        let cache = Arc::new(Self {
            inner: ArcSwap::new(Arc::new(CachedRules::default())),
            blocked_ips: DashMap::new(),
            cidr_index: DashMap::new(),
            cache_dir: cache_dir.clone(),
            agent_id,
            quota_domains: Mutex::new(HashSet::new()),
            last_config_sync_at: AtomicI64::new(0),
            last_policy_sync_at: AtomicI64::new(0),
            persist_lock: Mutex::new(()),
            health: CacheHealth::new(),
            blocked_dirty: AtomicBool::new(false),
        });

        // Ensure cache directory exists
        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            warn!(error = %e, "Failed to create cache directory, running without persistence");
        } else if let Err(e) = cache.load_from_disk() {
            // load_from_disk already logged the specific failure at the
            // right level and recorded the health outcome; this is just the
            // "keep going" note.
            debug!(error = %e, "Continuing without a disk-loaded rule cache");
        }

        // Quotas persisted with the rules take effect before the first push
        // from the control plane arrives.
        cache.apply_cache_quotas();

        Ok(cache)
    }

    /// Directory where the agent persists its state (rules, blocked IPs,
    /// and the ACME account/certificate store used by the data plane).
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Applies the `disk_quota_mb` of every enabled, cache-eligible rule to the
    /// edge's cache ledger, and drops the domains that are no longer
    /// configured.
    ///
    /// The ledger is the process-wide one the proxy's file cache writes
    /// through (`pingap_cache::global_disk_quota`), *not* a private copy: the
    /// cached objects live wherever the `cache` plugin's `directory` points,
    /// and a second ledger rooted elsewhere would only ever read zero and
    /// purge nothing. Because this runs as soon as the rules are known -
    /// possibly before the proxy has built that backend - the ceilings are
    /// parked and replayed by `pingap_cache::quota` once it exists.
    ///
    /// A site answers on several domains (primary plus alternates) while the
    /// rules are per site, so every domain of a site gets the largest ceiling
    /// configured for it. Several sites sharing a domain get the largest of
    /// theirs: the ledger accounts per domain, and the smaller ceiling would
    /// otherwise be unenforceable anyway.
    pub fn apply_cache_quotas(&self) {
        let rules = self.inner.load();
        // The global disk budget is the ceiling every site quota is clamped
        // against: an unlimited site (`0`) may use up to the budget, a
        // capped site is lowered to `min(site, global)`. No budget (`0`)
        // leaves the site quotas untouched.
        let global_space_mb = rules
            .global_cache
            .as_ref()
            .map(|g| u64::from(g.max_space_mb()))
            .unwrap_or(0);
        let mut tracked: HashMap<String, u64> = HashMap::new();
        for site in rules.sites.values() {
            let mut quota_mb = site
                .cache_rules
                .iter()
                .filter(|rule| rule.enabled && rule.cache_eligible)
                .map(|rule| u64::from(rule.disk_quota_mb))
                .max()
                .unwrap_or(0);
            if global_space_mb > 0 {
                quota_mb = if quota_mb == 0 {
                    global_space_mb
                } else {
                    quota_mb.min(global_space_mb)
                };
            }
            for domain in site.all_domains() {
                if domain.is_empty() {
                    continue;
                }
                let entry = tracked.entry(domain.to_string()).or_insert(0);
                *entry = (*entry).max(quota_mb);
            }
        }
        for (domain, quota_mb) in &tracked {
            quota::set_quota(domain, *quota_mb);
        }
        // Ceilings this agent set for a domain no rule names any more. Only
        // its own are swept: a `cache` plugin configured from the static file
        // keeps the ceiling it asked for, even when the control plane has
        // nothing to say about that namespace.
        let mut owned = self
            .quota_domains
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for domain in owned.iter() {
            if !tracked.contains_key(domain) {
                quota::forget_quota(domain);
            }
        }
        *owned = tracked.keys().cloned().collect();
        debug!(domains = owned.len(), "applied cache disk quotas");
    }

    /// Per-site cache disk usage for the heartbeat, so the control plane can
    /// answer `/api/v1/cache/status` without polling every edge.
    ///
    /// `cache_hits`/`cache_misses` stay at zero: this agent holds the rules, not
    /// the data path, so it has nothing to count. The control plane derives hit
    /// ratios from the access logs instead of trusting a constant zero here.
    pub fn cache_statuses(&self) -> Vec<proto::SiteStatus> {
        let rules = self.inner.load();
        // Usage comes from the shared ledger; before the proxy has built a
        // file cache backend there is none, and nothing on disk to report.
        // The configured ceiling is still reported, so the control plane can
        // show "0 of 512 MB" rather than "unconfigured" for a site whose quota
        // simply has not started filling yet.
        let ledger = pingap_cache::global_disk_quota();
        // Certificate state comes from the hosting process, which owns the
        // provider the ACME task writes into; without one every site reports
        // an empty status and the control plane leaves its rows alone.
        let ssl = crate::cert_status::snapshot();
        if !ssl.is_empty() {
            tracing::debug!(
                sites = rules.sites.len(),
                certificate_sites = ssl.len(),
                "certificate status snapshot for heartbeat"
            );
        }
        let mut out = Vec::with_capacity(rules.sites.len());
        for (site_id, site) in rules.sites.iter() {
            // A site answers on its primary domain and every alias, and the
            // ledger accounts each one separately. The ceiling is the largest
            // rather than the sum: `apply_cache_quotas` gives every hostname of
            // a site the same budget, so adding them would inflate it.
            let mut disk_bytes = 0u64;
            let mut items = 0u64;
            let mut evictions = 0u64;
            let mut quota_mb = 0u64;
            for domain in site.all_domains() {
                if domain.is_empty() {
                    continue;
                }
                if let Some(usage) = ledger.and_then(|l| l.get_usage(domain)) {
                    disk_bytes = disk_bytes.saturating_add(usage.current_bytes);
                    items = items.saturating_add(usage.item_count);
                    evictions = evictions.saturating_add(usage.evictions_total);
                }
                quota_mb = quota_mb
                    .max(quota::configured_quota_mb(domain).unwrap_or(0));
            }
            let status = ssl.get(site_id);
            out.push(proto::SiteStatus {
                site_id: site_id.clone(),
                domain: site.domain.clone(),
                requests_total: 0,
                requests_blocked: 0,
                cache_hits: 0,
                cache_misses: 0,
                ssl_status: status
                    .map(|status| status.status.to_string())
                    .unwrap_or_default(),
                ssl_expires_at: status.map(|status| prost_types::Timestamp {
                    seconds: status.expires_at,
                    nanos: 0,
                }),
                cache_disk_bytes: disk_bytes,
                cache_items: items,
                cache_evictions: evictions,
                cache_quota_bytes: quota_mb.saturating_mul(quota::BYTES_PER_MB),
            });
        }
        out
    }

    /// Purges this agent's edge cache for a site.
    ///
    /// An empty `urls` list purges the whole site (every domain it answers
    /// on); otherwise each entry is matched against the ledger keys. Returns
    /// the number of cache objects removed.
    pub async fn purge_site(
        &self,
        site_id: &str,
        urls: &[String],
    ) -> anyhow::Result<usize> {
        let domains: Vec<String> = {
            let rules = self.inner.load();
            match rules.sites.get(site_id) {
                Some(site) => site
                    .all_domains()
                    .filter(|domain| !domain.is_empty())
                    .map(str::to_string)
                    .collect(),
                None => Vec::new(),
            }
        };
        if domains.is_empty() {
            anyhow::bail!(
                "no cached rules for site {site_id}, nothing to purge"
            );
        }
        let Some(ledger) = pingap_cache::global_disk_quota() else {
            // Memory-only or not-yet-initialised edge: there is no disk cache
            // to delete from, which answers the purge rather than failing it.
            debug!(site_id, "no file cache backend, nothing to purge");
            return Ok(0);
        };
        let mut purged = 0;
        for domain in &domains {
            purged += if urls.is_empty() {
                ledger.purge_domain(domain).await.purged_count
            } else {
                ledger.purge_urls(domain, urls).await.purged_count
            };
        }
        info!(
            site_id,
            domains = domains.len(),
            purged,
            "purged edge cache for site"
        );
        Ok(purged)
    }

    /// Update the cache from a proto RuleBundle received from the control plane.
    pub fn update_from_bundle(
        &self,
        bundle: &proto::RuleBundle,
    ) -> anyhow::Result<()> {
        // Configuration sync is the agent's heaviest control-plane operation:
        // converting a bundle and rebuilding the domain index is accounted
        // separately from the proxy path.
        let _sync =
            pingwaf_profiler::timed_method(pingwaf_profiler::Method::AgentSync);
        let site_rules = Arc::new(Self::convert_bundle(bundle));
        let site_id = bundle.site_id.clone();
        let domain = site_rules.domain.clone();
        let alternate_domains = site_rules.alternate_domains.clone();

        // Capture the pre-sync enforcement state: leaving it (block mode,
        // observation off) invalidates the site's WAF auto-blocks.
        let previous = self
            .inner
            .load()
            .sites
            .get(&site_id)
            .map(|s| site_enforcement(Some(s)));

        // Built once here and shared into the snapshot by pointer: the rcu
        // closure can retry on contention, and a bundle push must not
        // rebuild the registry (or re-convert the cache settings) on every
        // retry.
        let failover_registry =
            Arc::new(failover_registry_from(&bundle.site_policies));
        let global_cache = bundle
            .global_cache
            .as_ref()
            .map(|gc| Arc::new(Self::convert_global_cache(gc)));

        // Swap in updated rules
        self.inner.rcu(|current| {
            let mut updated = (**current).clone();
            // Remove old domain index entries for this site. Removal keys
            // are normalised the same way as insertion keys below, so an
            // entry written as `EXAMPLE.com` is still findable for cleanup.
            if let Some(old_site) = updated.sites.get(&site_id) {
                updated
                    .domain_index
                    .remove(normalize_host(&old_site.domain).as_str());
                for alt in &old_site.alternate_domains {
                    updated.domain_index.remove(normalize_host(alt).as_str());
                }
            }
            // Insert new site. The site id is shared between the index
            // entries instead of duplicated per domain, and domain keys
            // are moved in from their Strings without a heap copy.
            let site_id_key: Arc<str> = Arc::from(site_id.as_str());
            updated.domain_index.insert(
                Arc::from(normalize_host(&domain)),
                Arc::clone(&site_id_key),
            );
            for alt in &alternate_domains {
                updated.domain_index.insert(
                    Arc::from(normalize_host(alt)),
                    Arc::clone(&site_id_key),
                );
            }
            updated
                .sites
                .insert(site_id.clone(), Arc::clone(&site_rules));
            // Every bundle carries the complete failover registry, so one
            // push refreshes it wholesale — including wholesale deletions
            // (an empty registry must replace a stale non-empty one).
            updated.failover_registry = Arc::clone(&failover_registry);
            if let Some(default_fail_open) = bundle.default_fail_open {
                updated.global_fail_open = Some(default_fail_open);
            }
            if let Some(cache) = &global_cache {
                updated.global_cache = Some(Arc::clone(cache));
            }
            if let Some(origin_verify_cert) = bundle.origin_verify_cert {
                updated.origin_verify_cert = Some(origin_verify_cert);
            }
            updated.config_hash = bundle.config_hash.as_str().into();
            updated.updated_at = Utc::now();
            Arc::new(updated)
        });

        info!(site_id = %site_id, domain = %domain, "Updated rule cache from bundle");

        // The bundle may have changed a site's cache rules, so the per-domain
        // ceilings have to follow before the next write is accounted.
        self.apply_cache_quotas();

        // The site left enforcing mode: drop its stale WAF auto-blocks so
        // monitor/observation mode is not silently overridden by blocks the
        // engine issued under the previous configuration.
        let current = self
            .inner
            .load()
            .sites
            .get(&site_id)
            .map(|s| site_enforcement(Some(s)));
        if previous.is_some_and(waf_enforcing)
            && !current.is_some_and(waf_enforcing)
        {
            self.clear_waf_auto_blocks(&site_id);
        }

        // Persist asynchronously (best effort)
        if let Err(e) = self.persist_to_disk() {
            warn!(error = %e, "Failed to persist rule cache to disk");
        }

        self.last_policy_sync_at
            .store(Utc::now().timestamp(), Ordering::Relaxed);

        Ok(())
    }

    /// Update cache from a full SiteConfig (used on initial registration).
    pub fn update_from_site_config(
        &self,
        config: &proto::SiteConfig,
    ) -> anyhow::Result<()> {
        // Pre-sync enforcement state per site, so leaving enforcing mode
        // (block → monitor/off, observation on) drops the site's stale
        // WAF auto-blocks after the swap.
        let previous: HashMap<String, (WafMode, bool)> = self
            .inner
            .load()
            .sites
            .iter()
            .map(|(id, s)| (id.clone(), site_enforcement(Some(s))))
            .collect();

        // The bundles embed the same registry in every site; one pass over
        // whichever bundle carries it is enough. Built once outside the
        // rcu closure so a retry under contention cannot rebuild the
        // registry or re-convert the cache settings. Replacement below is
        // unconditional so deleting the last policy also clears the
        // agent-side registry.
        let mut failover_registry = None;
        let mut global_fail_open = None;
        let mut global_cache = None;
        let mut origin_verify_cert = None;
        for site in &config.sites {
            if let Some(ref bundle) = site.rules {
                failover_registry = Some(Arc::new(failover_registry_from(
                    &bundle.site_policies,
                )));
                global_fail_open = bundle.default_fail_open;
                global_cache = bundle
                    .global_cache
                    .as_ref()
                    .map(|gc| Arc::new(Self::convert_global_cache(gc)));
                origin_verify_cert = bundle.origin_verify_cert;
                break;
            }
        }

        self.inner.rcu(|current| {
            let mut updated = (**current).clone();
            updated.config_hash = config.config_hash.as_str().into();
            updated.updated_at = Utc::now();

            if let Some(registry) = &failover_registry {
                updated.failover_registry = Arc::clone(registry);
            }
            if let Some(default_fail_open) = global_fail_open {
                updated.global_fail_open = Some(default_fail_open);
            }
            if let Some(cache) = &global_cache {
                updated.global_cache = Some(Arc::clone(cache));
            }
            if let Some(verify_cert) = origin_verify_cert {
                updated.origin_verify_cert = Some(verify_cert);
            }

            for site in &config.sites {
                if let Some(ref bundle) = site.rules {
                    let mut site_rules = Self::convert_bundle(bundle);
                    // Override domain from site-level field
                    if !site.domain.is_empty() {
                        // Remove old domain index
                        updated.domain_index.remove(
                            normalize_host(&site_rules.domain).as_str(),
                        );
                        site_rules.domain = site.domain.clone();
                    }
                    site_rules.site_id = site.id.clone();
                    site_rules.alternate_domains =
                        site.alternate_domains.clone();
                    site_rules.status = site_status_str(site.status);
                    site_rules.proxy_trust = ProxyTrustConfig {
                        enabled: site.trust_proxy_headers,
                        header: site.trusted_header.clone(),
                        last_hop_only: site.trust_last_hop,
                        trusted_ranges: site.trusted_proxy_ranges.clone(),
                    };

                    // Update domain index; the site id is shared between
                    // this site's entries instead of duplicated per
                    // domain.
                    let site_id_key: Arc<str> = Arc::from(site.id.as_str());
                    updated.domain_index.insert(
                        Arc::from(normalize_host(&site_rules.domain)),
                        Arc::clone(&site_id_key),
                    );
                    for alt in &site_rules.alternate_domains {
                        updated.domain_index.insert(
                            Arc::from(normalize_host(alt)),
                            Arc::clone(&site_id_key),
                        );
                    }
                    updated.sites.insert(site.id.clone(), Arc::new(site_rules));
                }
            }

            // A full site config is authoritative: sites the control plane
            // no longer lists are dropped here together with their domain
            // index entries, so a deleted site stops being served from
            // stale cached rules (they would otherwise survive every sync
            // and even a restart via the disk cache).
            let known: std::collections::HashSet<&String> =
                config.sites.iter().map(|s| &s.id).collect();
            let ghost_ids: Vec<String> = updated
                .sites
                .keys()
                .filter(|id| !known.contains(*id))
                .cloned()
                .collect();
            for id in &ghost_ids {
                if let Some(old) = updated.sites.remove(id) {
                    updated
                        .domain_index
                        .remove(normalize_host(&old.domain).as_str());
                    for alt in &old.alternate_domains {
                        updated
                            .domain_index
                            .remove(normalize_host(alt).as_str());
                    }
                }
            }

            Arc::new(updated)
        });

        info!(
            sites = self.inner.load().sites.len(),
            "Updated rule cache from full site config"
        );

        self.apply_cache_quotas();

        // Sites the control plane deleted lose every dynamic block — the
        // entries would otherwise linger until expiry and reload from disk.
        let current = self.inner.load();
        for id in previous.keys() {
            if !current.sites.contains_key(id) {
                self.clear_site_blocks(id);
            }
        }
        drop(current);

        // Sites that left enforcing mode lose their WAF auto-blocks, the
        // same way as on a single-bundle update.
        for site in config.sites.iter().filter(|s| !s.id.is_empty()) {
            let current = self
                .inner
                .load()
                .sites
                .get(&site.id)
                .map(|s| site_enforcement(Some(s)));
            if previous.get(&site.id).copied().is_some_and(waf_enforcing)
                && !current.is_some_and(waf_enforcing)
            {
                self.clear_waf_auto_blocks(&site.id);
            }
        }

        if let Err(e) = self.persist_to_disk() {
            warn!(error = %e, "Failed to persist rule cache to disk");
        }

        self.last_config_sync_at
            .store(Utc::now().timestamp(), Ordering::Relaxed);

        Ok(())
    }

    /// Look up site rules by domain name.
    ///
    /// Hot path: only the `Arc` is cloned, the rules themselves are shared
    /// with the cache.
    ///
    /// An exact-miss falls back to wildcard sites: `www.a.example.com`
    /// tries `*.a.example.com`, then `*.example.com`, and so on — the same
    /// semantics `pingap_location`'s `HostSelector::Suffix` uses for
    /// routing, so a wildcard site routed to a location no longer loses
    /// its WAF rules, cache policy, challenge and error pages.
    pub fn get_site_rules(&self, domain: &str) -> Option<Arc<SiteRules>> {
        let rules = self.inner.load();
        let site_id = lookup_with_wildcard(&rules.domain_index, domain)?;
        // The index values are `Arc<str>` site ids; the sites map keys are
        // `String`s, so borrow the id as a `str` for the lookup.
        rules.sites.get(site_id.as_ref()).cloned()
    }

    /// The site's disconnected policy for `domain`, when the control plane
    /// has one registered (primary or alternate domain match, including a
    /// wildcard match with the same fallback as [`Self::get_site_rules`]).
    pub fn failover_for_domain(&self, domain: &str) -> Option<FailoverMode> {
        let rules = self.inner.load();
        lookup_with_wildcard(&rules.failover_registry, domain).copied()
    }

    /// The control-plane-wide fail-open default, when it has ever been
    /// synced. `None` means the agent must fall back to its local setting.
    pub fn global_fail_open(&self) -> Option<bool> {
        self.inner.load().global_fail_open
    }

    /// Look up site rules by site ID.
    pub fn get_site_rules_by_id(
        &self,
        site_id: &str,
    ) -> Option<Arc<SiteRules>> {
        let rules = self.inner.load();
        rules.sites.get(site_id).cloned()
    }

    /// Get all cached site rules (snapshot).
    pub fn all_sites(&self) -> Arc<CachedRules> {
        self.inner.load_full()
    }

    /// Get current config hash for delta sync. Cheap: clones the `Arc`, not
    /// the string.
    pub fn config_hash(&self) -> Arc<str> {
        self.inner.load().config_hash.clone()
    }

    /// When a full site config was last applied successfully, for the
    /// heartbeat's sync report.
    pub fn config_synced_at(&self) -> Option<DateTime<Utc>> {
        self.sync_marker(&self.last_config_sync_at)
    }

    /// When a single-site rule bundle was last applied successfully.
    pub fn policy_synced_at(&self) -> Option<DateTime<Utc>> {
        self.sync_marker(&self.last_policy_sync_at)
    }

    fn sync_marker(&self, cell: &AtomicI64) -> Option<DateTime<Utc>> {
        let secs = cell.load(Ordering::Relaxed);
        if secs <= 0 {
            None
        } else {
            Utc.timestamp_opt(secs, 0).single()
        }
    }

    // ─── IP Blocking ────────────────────────────────────────

    /// Check if an IP is dynamically blocked for a given site.
    pub fn is_ip_blocked(&self, site_id: &str, ip: &str) -> bool {
        self.blocked_lookup(site_id, ip, |entry| entry.is_expired())
            .is_some()
    }

    /// The reason an IP is dynamically blocked for a site, or `None`. The
    /// reason prefix (`"waf: "` / `"rate limit: "`) identifies which policy
    /// produced the block so callers can downgrade WAF-originated blocks
    /// without touching rate-limit or control-plane-issued ones.
    pub fn blocked_reason(&self, site_id: &str, ip: &str) -> Option<String> {
        self.blocked_lookup(site_id, ip, |entry| entry.reason.clone())
    }

    /// The expiry of the dynamic block covering `ip` for a site. The outer
    /// `None` means not blocked; the inner `None` means permanent.
    pub fn blocked_expires_at(
        &self,
        site_id: &str,
        ip: &str,
    ) -> Option<Option<DateTime<Utc>>> {
        self.blocked_lookup(site_id, ip, |entry| entry.expires_at)
    }

    /// Resolve the dynamic block covering `ip` for a site.
    ///
    /// A block entry is either a single address (legacy and still the common
    /// case: WAF/rate-limit auto-blocks) or a CIDR range pushed by a
    /// control-plane block command. The exact `"site:ip"` key is probed first
    /// — O(1) and unchanged behaviour for single addresses — and only on a
    /// miss does the per-site CIDR index run: pre-parsed nets, no scan of the
    /// main map, so a never-blocked client pays nothing extra even while
    /// thousands of auto-blocks accumulate. Expired entries are evicted on
    /// sight.
    fn blocked_lookup<T>(
        &self,
        site_id: &str,
        ip: &str,
        extract: impl Fn(&BlockedIpEntry) -> T,
    ) -> Option<T> {
        // Fast path: an exact single-address (or exact CIDR-string) entry.
        let key = format!("{}:{}", site_id, ip);
        if let Some(entry) = self.blocked_ips.get(&key) {
            if entry.is_expired() {
                drop(entry);
                self.blocked_ips.remove(&key);
                self.index_remove_key(&key);
            } else {
                return Some(extract(&entry));
            }
        }

        // The control plane stores mapped-v6 client addresses collapsed to
        // their IPv4 form; probe that spelling too, so `::ffff:203.0.113.5`
        // hits the entry stored as `203.0.113.5`.
        let parsed = ip.parse::<std::net::IpAddr>().ok();
        if let Some(addr) = parsed.map(normalize_mapped) {
            let normalized = addr.to_string();
            if normalized != ip {
                let key = format!("{}:{}", site_id, normalized);
                if let Some(entry) = self.blocked_ips.get(&key) {
                    if entry.is_expired() {
                        drop(entry);
                        self.blocked_ips.remove(&key);
                        self.index_remove_key(&key);
                    } else {
                        return Some(extract(&entry));
                    }
                }
            }
        }

        // Slow path: any CIDR entry of this site covering the address.
        let addr = normalize_mapped(parsed?);
        let index = self.cidr_index.get(site_id)?;
        for entry in index.iter() {
            if let Some(exp) = entry.expires_at {
                if Utc::now() >= exp {
                    continue;
                }
            }
            if entry.net.contains(&addr) {
                let blocked = self.blocked_ips.get(&entry.key)?;
                return Some(extract(&blocked));
            }
        }
        None
    }

    /// Maintains the CIDR index for a blocked-IP insert: CIDR-shaped entries
    /// are indexed with their pre-parsed net (mapped-v6 collapsed to v4);
    /// single addresses are simply absent from the index.
    fn index_insert(&self, site_id: &str, key: &str, entry: &BlockedIpEntry) {
        let Some(net) = parse_entry_net(&entry.ip) else {
            return;
        };
        let mut index = self.cidr_index.entry(site_id.to_string()).or_default();
        if let Some(existing) = index.iter_mut().find(|e| e.key == key) {
            existing.net = net;
            existing.expires_at = entry.expires_at;
        } else {
            index.push(CidrEntry {
                key: key.to_string(),
                net,
                expires_at: entry.expires_at,
            });
        }
    }

    /// Removes one entry (given as its full `"site_id:ip"` key) from the
    /// CIDR index; a no-op for single-address entries.
    fn index_remove_key(&self, key: &str) {
        let Some((site_id, _)) = key.split_once(':') else {
            return;
        };
        if let Some(mut index) = self.cidr_index.get_mut(site_id) {
            index.retain(|e| e.key != key);
        }
    }

    /// Removes a whole site from the CIDR index.
    fn index_remove_site(&self, site_id: &str) {
        self.cidr_index.remove(site_id);
    }

    /// Block an IP for a site, optionally with a duration.
    pub fn block_ip(
        &self,
        site_id: &str,
        ip: &str,
        duration: Option<Duration>,
        reason: &str,
    ) {
        let key = format!("{}:{}", site_id, ip);
        let expires_at = duration.map(|d| {
            Utc::now()
                + chrono::Duration::from_std(d)
                    .unwrap_or(chrono::Duration::hours(1))
        });

        let entry = BlockedIpEntry {
            ip: ip.to_string(),
            site_id: site_id.to_string(),
            reason: reason.to_string(),
            blocked_at: Utc::now(),
            expires_at,
        };

        // Enforce the capacity ceiling before inserting: sweep expired
        // entries first, then evict the oldest blocks (D3).
        if self.blocked_ips.len() >= MAX_BLOCKED_IP_ENTRIES {
            self.enforce_blocked_capacity();
        }

        self.blocked_ips.insert(key.clone(), entry.clone());
        self.index_insert(site_id, &key, &entry);
        info!(site_id = %site_id, ip = %ip, reason = %reason, "Blocked IP");

        // Persistence is debounced off the hot path (D2): N rapid blocks
        // cost one fsync, not N × O(N).
        self.mark_blocked_dirty();
    }

    /// Unblock an IP for a site.
    pub fn unblock_ip(&self, site_id: &str, ip: &str) {
        let key = format!("{}:{}", site_id, ip);
        let removed = self.blocked_ips.remove(&key).is_some();
        self.index_remove_key(&key);
        if removed {
            info!(site_id = %site_id, ip = %ip, "Unblocked IP");
            self.mark_blocked_dirty();
        }
    }

    /// Drop every WAF auto-block (`"waf: "` reason) for a site, keeping
    /// rate-limit and control-plane-issued blocks. Returns the number of
    /// entries removed. Used when a site leaves enforcing mode (block →
    /// monitor/off, or observation mode switched on): the stale auto-blocks
    /// would otherwise keep refusing clients for up to the full window even
    /// though the engine no longer produces block verdicts.
    pub fn clear_waf_auto_blocks(&self, site_id: &str) -> usize {
        let prefix = format!("{site_id}:");
        let stale: Vec<String> = self
            .blocked_ips
            .iter()
            .filter(|e| {
                e.key().starts_with(&prefix)
                    && !e.value().is_expired()
                    && e.value().reason.starts_with("waf: ")
            })
            .map(|e| e.key().clone())
            .collect();
        let removed = stale.len();
        for key in &stale {
            self.blocked_ips.remove(key);
            self.index_remove_key(key);
        }
        if removed > 0 {
            info!(
                site_id = %site_id,
                removed,
                "cleared WAF auto-blocks after leaving enforcing mode"
            );
            self.mark_blocked_dirty();
        }
        removed
    }

    /// Drop every dynamic block for a site, regardless of origin. Used when
    /// the site itself is deleted: its entries would otherwise linger until
    /// their expiry (and be re-loaded from disk on restart).
    pub fn clear_site_blocks(&self, site_id: &str) -> usize {
        let prefix = format!("{site_id}:");
        let stale: Vec<String> = self
            .blocked_ips
            .iter()
            .filter(|e| e.key().starts_with(&prefix))
            .map(|e| e.key().clone())
            .collect();
        let removed = stale.len();
        for key in &stale {
            self.blocked_ips.remove(key);
        }
        self.index_remove_site(site_id);
        if removed > 0 {
            debug!(
                site_id = %site_id,
                removed,
                "cleared blocks for removed site"
            );
            self.mark_blocked_dirty();
        }
        removed
    }

    /// Clean up expired IP blocks.
    pub fn cleanup_expired_blocks(&self) {
        let mut expired_keys = Vec::new();
        for entry in self.blocked_ips.iter() {
            if entry.value().is_expired() {
                expired_keys.push(entry.key().clone());
            }
        }
        for key in &expired_keys {
            self.blocked_ips.remove(key);
            self.index_remove_key(key);
        }
        if !expired_keys.is_empty() {
            debug!(count = expired_keys.len(), "Cleaned up expired IP blocks");
            self.mark_blocked_dirty();
        }
    }

    /// Marks the blocked-IP map as changed. The disk write itself is
    /// debounced to a background flush (see [`RuleCache::flush_blocked_ips`]):
    /// a crash may lose the most recent few seconds of blocks, which is
    /// acceptable — blocks are transient defense state, re-propagated by the
    /// control plane on restart.
    fn mark_blocked_dirty(&self) {
        self.blocked_dirty.store(true, Ordering::Release);
    }

    /// Persists the blocked-IP map if it changed since the last flush.
    /// Called from a low-frequency background loop, which is what bounds the
    /// fsync rate; rule syncs and shutdown still write through directly.
    pub fn flush_blocked_ips(&self) {
        if !self.blocked_dirty.swap(false, Ordering::AcqRel) {
            return;
        }
        if let Err(e) = self.persist_blocked_ips() {
            // Keep the map marked so the next pass retries instead of
            // silently dropping the pending write.
            self.blocked_dirty.store(true, Ordering::Release);
            warn!(error = %e, "Failed to persist blocked IPs");
        }
    }

    /// Brings `blocked_ips` back under [`MAX_BLOCKED_IP_ENTRIES`]: expired
    /// entries are swept first, then the oldest blocks are evicted down to
    /// the headroom line. Under a rotating-source-IP attack the oldest
    /// blocks are the least valuable (they would have expired anyway).
    fn enforce_blocked_capacity(&self) {
        self.enforce_blocked_capacity_inner(
            MAX_BLOCKED_IP_ENTRIES,
            BLOCKED_CAPACITY_HEADROOM,
        );
    }

    /// Parameterized twin of [`RuleCache::enforce_blocked_capacity`] so tests
    /// can exercise the eviction policy without inserting six-figure entry
    /// counts. `limit` is the hard ceiling, `headroom` the post-eviction size.
    fn enforce_blocked_capacity_inner(&self, limit: usize, headroom: usize) {
        let expired: Vec<String> = self
            .blocked_ips
            .iter()
            .filter(|e| e.value().is_expired())
            .map(|e| e.key().clone())
            .collect();
        for key in &expired {
            self.blocked_ips.remove(key);
            self.index_remove_key(key);
        }

        let target = limit.saturating_sub(headroom).max(1);
        let remaining = self.blocked_ips.len();
        if remaining <= target {
            if !expired.is_empty() {
                debug!(
                    expired = expired.len(),
                    remaining,
                    "swept expired blocks after hitting the blocked-IP capacity ceiling"
                );
            }
            return;
        }

        let mut by_age: Vec<(String, DateTime<Utc>)> = self
            .blocked_ips
            .iter()
            .map(|e| (e.key().clone(), e.value().blocked_at))
            .collect();
        by_age.sort_by_key(|(_, blocked_at)| *blocked_at);
        let evict = remaining - target;
        for (key, _) in by_age.into_iter().take(evict) {
            self.blocked_ips.remove(&key);
            self.index_remove_key(&key);
        }
        warn!(
            expired = expired.len(),
            evicted = evict,
            remaining = target,
            limit,
            "blocked-IP map hit its capacity ceiling; swept expired and \
             evicted the oldest entries"
        );
    }

    /// Snapshot of every block currently in force, for the heartbeat report.
    /// Expired entries are dropped on read so a lapsed block is never
    /// re-propagated to the control plane.
    pub fn blocked_ips_snapshot(&self) -> Vec<BlockedIpEntry> {
        self.blocked_ips
            .iter()
            .filter(|e| !e.value().is_expired())
            .map(|e| e.value().clone())
            .collect()
    }

    // ─── Disk Persistence ───────────────────────────────────

    /// Outcome of the latest cache load, for the heartbeat report.
    pub fn health_status(&self) -> persist::CacheHealthStatus {
        self.health.status()
    }

    /// Rule-cache disk health for the heartbeat.
    pub fn cache_persist_healthy(&self) -> bool {
        self.health.status().healthy
    }

    /// Degraded-state detail for the heartbeat; empty when all is well.
    /// Truncated to keep heartbeat frames and control-plane logs bounded.
    pub fn cache_status_reason(&self) -> String {
        const MAX_CHARS: usize = 300;
        let reason = self.health.status().reason.unwrap_or_default();
        if reason.chars().count() <= MAX_CHARS {
            reason
        } else {
            let cut: String = reason.chars().take(MAX_CHARS).collect();
            format!("{cut}…")
        }
    }

    /// Persist current rules to disk, feeding the outcome back into the
    /// health signal. A failure marks the cache unhealthy; a success only
    /// clears the reason when the cache is already healthy — a load failure
    /// stays sticky until an actual successful *load* (next startup) clears
    /// it, so a persist that happens to work cannot mask the fact that the
    /// agent once came up on empty rules.
    pub fn persist_to_disk(&self) -> anyhow::Result<()> {
        let outcome = self.persist_to_disk_inner();
        let status = self.health.status();
        match &outcome {
            Ok(()) => {
                if status.healthy {
                    self.health.record(true, status.source, None);
                }
            },
            Err(err) => self.health.record(
                false,
                status.source,
                Some(format!("persist failed: {err:#}")),
            ),
        }
        outcome
    }

    /// The current snapshot is rolled to `sites.json.bak` before the
    /// overwrite — but only when it still parses, so a corrupt file can never
    /// evict the last known-good backup. Every file lands atomically (same-
    /// directory temp + fsync + rename), and metadata is stamped with the
    /// CRC32 of the exact sites payload written just before it, so the load
    /// path can detect a torn or partially applied persist. Caller holds
    /// `persist_lock` via the wrapper.
    fn persist_to_disk_inner(&self) -> anyhow::Result<()> {
        if !self.cache_dir.exists() {
            return Ok(());
        }
        let _guard = self
            .persist_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let rules = self.inner.load();
        let sites_path = self.cache_dir.join("sites.json");
        let metadata_path = self.cache_dir.join("metadata.json");

        let sites_json = serde_json::to_string_pretty(&**rules)?;
        self.roll_backup_if_valid(&sites_path)?;

        write_atomic(&sites_path, sites_json.as_bytes())?;

        let metadata = CacheMetadata {
            config_hash: rules.config_hash.to_string(),
            updated_at: rules.updated_at,
            agent_id: self.agent_id.clone(),
            version: CACHE_FORMAT_VERSION,
            sites_crc32: Some(content_crc32(sites_json.as_bytes())),
            sites_len: Some(sites_json.len() as u64),
        };
        let meta_json = serde_json::to_string_pretty(&metadata)?;
        write_atomic(&metadata_path, meta_json.as_bytes())?;

        // Caller holds the lock; the inner variant must not re-lock.
        self.persist_blocked_ips_inner()?;

        debug!("Persisted rule cache to disk");
        Ok(())
    }

    /// Copies `sites.json` and `metadata.json` to their `.bak` siblings
    /// before an overwrite, keeping the roll-over only when the current
    /// snapshot still parses — a corrupt primary must never destroy the last
    /// known-good backup.
    fn roll_backup_if_valid(&self, sites_path: &Path) -> anyhow::Result<()> {
        if !sites_path.exists() {
            return Ok(());
        }
        let metadata_path = self.cache_dir.join("metadata.json");
        // Full validation, not just a parse: a tampered-but-parseable
        // snapshot must never evict the last known-good backup.
        if self.read_snapshot(sites_path, &metadata_path).is_err() {
            debug!(
                file = %sites_path.display(),
                "current snapshot fails validation; keeping the previous backup instead of rolling it"
            );
            return Ok(());
        }
        let bytes = std::fs::read(sites_path)?;
        write_atomic(&sites_path.with_extension("json.bak"), &bytes)?;
        if metadata_path.exists() {
            let meta_bytes = std::fs::read(&metadata_path)?;
            write_atomic(
                &metadata_path.with_extension("json.bak"),
                &meta_bytes,
            )?;
        }
        Ok(())
    }

    /// Load rules from disk, falling back to the `.bak` snapshot when the
    /// primary fails validation.
    ///
    /// Every outcome is recorded in `health` and logged at a level matching
    /// its severity: a fresh node stays quiet, a backup restore warns, and a
    /// total failure warns loudly because the agent then runs on empty rules
    /// until the control plane re-pushes.
    pub fn load_from_disk(&self) -> anyhow::Result<()> {
        let sites_path = self.cache_dir.join("sites.json");
        let metadata_path = self.cache_dir.join("metadata.json");

        if !sites_path.exists() {
            self.health.record(true, LoadSource::Fresh, None);
            anyhow::bail!(
                "no cache file found at {:?} (fresh node)",
                sites_path
            );
        }

        match self.read_snapshot(&sites_path, &metadata_path) {
            Ok(cached) => {
                self.inner.store(Arc::new(cached));
                self.health.record(true, LoadSource::Disk, None);
                self.load_blocked_ips(&self.cache_dir.join("blocked_ips.json"));
                info!("Loaded rule cache from disk");
                Ok(())
            },
            Err(primary_err) => {
                let backup = sites_path.with_extension("json.bak");
                if backup.exists() {
                    match self.read_snapshot_unstamped(&backup) {
                        Ok(cached) => {
                            self.inner.store(Arc::new(cached));
                            let reason = format!(
                                "primary snapshot failed validation ({primary_err:#}); restored previous snapshot from backup"
                            );
                            warn!(reason = %reason, "Rule cache restored from sites.json.bak");
                            self.health.record(
                                true,
                                LoadSource::Backup,
                                Some(reason),
                            );
                            self.load_blocked_ips(
                                &self.cache_dir.join("blocked_ips.json"),
                            );
                            Ok(())
                        },
                        Err(backup_err) => {
                            let reason = format!(
                                "primary: {primary_err:#}; backup: {backup_err:#}"
                            );
                            warn!(
                                reason = %reason,
                                "Rule cache unusable; running with empty rules until the control plane re-pushes"
                            );
                            self.health.record(
                                false,
                                LoadSource::Fresh,
                                Some(reason),
                            );
                            Err(anyhow::anyhow!(
                                "cache snapshot and backup both failed validation"
                            ))
                        },
                    }
                } else {
                    warn!(
                        reason = %primary_err,
                        "Rule cache failed validation and no backup exists; running with empty rules until the control plane re-pushes"
                    );
                    self.health.record(
                        false,
                        LoadSource::Fresh,
                        Some(format!("{primary_err:#}")),
                    );
                    Err(primary_err)
                }
            },
        }
    }

    /// Reads and validates a primary snapshot: JSON parse, format version,
    /// and — when the metadata stamps them — the CRC32 + length of the
    /// payload. A missing or unreadable metadata file downgrades to parse
    /// validation only and says so, so pre-integrity snapshots still load.
    fn read_snapshot(
        &self,
        sites_path: &Path,
        metadata_path: &Path,
    ) -> anyhow::Result<CachedRules> {
        let bytes = std::fs::read(sites_path)?;
        if let Ok(meta_bytes) = std::fs::read(metadata_path) {
            match serde_json::from_slice::<CacheMetadata>(&meta_bytes) {
                Ok(metadata) => {
                    check_format_version(metadata.version)
                        .map_err(anyhow::Error::msg)?;
                    if let (Some(crc), Some(len)) =
                        (metadata.sites_crc32, metadata.sites_len)
                    {
                        if !content_matches(&bytes, crc, len) {
                            anyhow::bail!(
                                "sites.json failed its integrity check (crc32/length mismatch against metadata.json)"
                            );
                        }
                    }
                },
                Err(e) => {
                    debug!(
                        error = %e,
                        "metadata.json unreadable; loading sites.json with parse validation only"
                    );
                },
            }
        }
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {:?}", sites_path))
    }

    /// Backup validation: the JSON must parse. A slightly stale backup is
    /// still better than empty rules, so no integrity stamp is required.
    fn read_snapshot_unstamped(
        &self,
        path: &Path,
    ) -> anyhow::Result<CachedRules> {
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {:?}", path))
    }

    /// Loads blocked IPs, dropping entries that expired while persisted.
    fn load_blocked_ips(&self, blocked_path: &Path) {
        if !blocked_path.exists() {
            return;
        }
        let blocked_json = match std::fs::read_to_string(blocked_path) {
            Ok(json) => json,
            Err(e) => {
                warn!(error = %e, file = %blocked_path.display(), "Failed to read blocked IPs from disk");
                return;
            },
        };
        match serde_json::from_str::<Vec<BlockedIpEntry>>(&blocked_json) {
            Ok(blocked) => {
                let mut loaded = 0;
                for entry in blocked {
                    if !entry.is_expired() {
                        let key = format!("{}:{}", entry.site_id, entry.ip);
                        self.index_insert(&entry.site_id, &key, &entry);
                        self.blocked_ips.insert(key, entry);
                        loaded += 1;
                    }
                }
                debug!(count = loaded, "Loaded blocked IPs from disk");
            },
            Err(e) => {
                warn!(
                    error = %e,
                    file = %blocked_path.display(),
                    "Blocked IPs snapshot unreadable; dropping it and re-syncing from the control plane"
                );
            },
        }
    }

    /// Persist blocked IPs to disk (serialized with the other persist paths).
    fn persist_blocked_ips(&self) -> anyhow::Result<()> {
        if !self.cache_dir.exists() {
            return Ok(());
        }
        let _guard = self
            .persist_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.persist_blocked_ips_inner()
    }

    /// Persist blocked IPs; the caller must hold `persist_lock`.
    fn persist_blocked_ips_inner(&self) -> anyhow::Result<()> {
        let blocked_path = self.cache_dir.join("blocked_ips.json");
        let entries: Vec<BlockedIpEntry> = self
            .blocked_ips
            .iter()
            .filter(|e| !e.value().is_expired())
            .map(|e| e.value().clone())
            .collect();

        let json = serde_json::to_string_pretty(&entries)?;
        write_atomic(&blocked_path, json.as_bytes())?;
        Ok(())
    }

    // ─── Proto Conversion ───────────────────────────────────

    /// Convert a proto RuleBundle into local SiteRules.
    fn convert_bundle(bundle: &proto::RuleBundle) -> SiteRules {
        SiteRules {
            site_id: bundle.site_id.clone(),
            domain: String::new(), // Will be set from Site if available
            alternate_domains: Vec::new(),
            // Set from the owning `Site` in `update_from_site_config`.
            status: default_site_status(),
            waf_config: bundle.waf.as_ref().map(Self::convert_waf_config),
            rate_limit_rules: bundle
                .rate_limit_rules
                .iter()
                .map(Self::convert_rate_limit_rule)
                .collect(),
            ip_access_rules: bundle
                .ip_access_rules
                .iter()
                .map(Self::convert_ip_access_rule)
                .collect(),
            geo_config: bundle.geo.as_ref().map(Self::convert_geo_config),
            cache_rules: bundle
                .cache_rules
                .iter()
                .map(Self::convert_cache_rule)
                .collect(),
            challenge_config: bundle
                .challenge
                .as_ref()
                .map(Self::convert_challenge_config),
            rewrite_rules: bundle
                .rewrite_rules
                .iter()
                .map(Self::convert_rewrite_rule)
                .collect(),
            error_pages: bundle
                .error_pages
                .iter()
                .map(Self::convert_error_page)
                .collect(),
            ssl_config: bundle.ssl.as_ref().map(Self::convert_ssl_config),
            upstreams: bundle
                .upstreams
                .iter()
                .map(Self::convert_upstream_config)
                .collect(),
            routes: bundle
                .routes
                .iter()
                .map(Self::convert_route_config)
                .collect(),
            bot_protection: bundle
                .bot_protection
                .as_ref()
                .map(Self::convert_bot_protection),
            basic_auth: bundle
                .basic_auth
                .as_ref()
                .map(Self::convert_basic_auth),
            observation_mode: bundle.observation_mode,
            proxy_trust: ProxyTrustConfig::default(),
            cache_settings: bundle
                .cache_settings
                .as_ref()
                .map(Self::convert_site_cache_settings),
            response_replace: bundle
                .response_replace
                .as_ref()
                .map(Self::convert_response_replace),
            ai_crawl: bundle.ai_crawl.as_ref().map(Self::convert_ai_crawl),
            oidc: bundle.oidc.as_ref().map(Self::convert_oidc),
        }
    }

    fn convert_global_cache(
        g: &proto::GlobalCacheSettings,
    ) -> GlobalCacheSettings {
        GlobalCacheSettings {
            max_file_size_mb: g.max_file_size_mb,
            max_space_mb: g.max_space_mb,
            master_enabled: g.master_enabled,
            default_edge_ttl_seconds: g.default_edge_ttl_seconds,
        }
    }

    fn convert_site_cache_settings(
        s: &proto::SiteCacheSettings,
    ) -> SiteCacheSettings {
        SiteCacheSettings {
            max_file_size_mb: s.max_file_size_mb,
            type_max_file_size_mb: s.type_max_file_size_mb.clone(),
            type_policy: s.type_policy.as_ref().map(Self::convert_type_policy),
        }
    }

    fn convert_type_policy(p: &proto::CacheTypePolicy) -> CacheTypePolicy {
        let category = |c: &proto::CacheTypeCategory| CacheTypeCategory {
            enabled: c.enabled.unwrap_or(false),
            edge_ttl_seconds: c.edge_ttl_seconds.unwrap_or(0),
            browser_ttl_seconds: c.browser_ttl_seconds.unwrap_or(0),
            extensions: c.extensions.clone(),
        };
        CacheTypePolicy {
            web_assets: p.web_assets.as_ref().map(category),
            image: p.image.as_ref().map(category),
            media: p.media.as_ref().map(category),
            other: p.other.as_ref().map(category),
            html: p.html.as_ref().map(category),
        }
    }

    fn convert_waf_config(w: &proto::WafConfig) -> WafConfig {
        WafConfig {
            enabled: w.enabled,
            mode: WafMode::from(w.mode),
            paranoia_level: w.paranoia_level,
            sqli_detection: w.sqli_detection,
            xss_detection: w.xss_detection,
            rce_detection: w.rce_detection,
            lfi_detection: w.lfi_detection,
            ssrf_detection: w.ssrf_detection,
            bot_detection: w.bot_detection,
            custom_rules: w
                .custom_rules
                .iter()
                .map(|r| WafRule {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    description: r.description.clone(),
                    expression: r.expression.clone(),
                    action: WafAction::from(r.action),
                    severity: r.severity,
                    tags: r.tags.clone(),
                    enabled: r.enabled,
                    mode: WafMode::from(r.mode),
                    priority: r.priority,
                })
                .collect(),
            managed_overrides: w
                .managed_overrides
                .iter()
                .map(|o| RuleOverride {
                    rule_id: o.rule_id.clone(),
                    tag: o.tag.clone(),
                    action: WafAction::from(o.action),
                    enabled: o.enabled,
                })
                .collect(),
            ml_enabled: w.ml_enabled,
            ml_model_path: w.ml_model_path.clone(),
            ml_threshold: w.ml_threshold,
            anomaly_threshold: w.anomaly_threshold,
            // 0 means "unset" on the wire; keep the data-plane default.
            body_stage_timeout_secs: if w.body_stage_timeout_secs == 0 {
                30
            } else {
                w.body_stage_timeout_secs
            },
            advanced_mode: w.advanced_mode,
            monitor_categories: w.monitor_categories.clone(),
            monitor_stacks: w.monitor_stacks.clone(),
            monitor_managed_rules: w.monitor_managed_rules.clone(),
        }
    }

    fn convert_rate_limit_rule(r: &proto::RateLimitRule) -> RateLimitRule {
        RateLimitRule {
            id: r.id.clone(),
            name: r.name.clone(),
            expression: r.expression.clone(),
            characteristics: r
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
            characteristic_params: r.characteristic_params.clone(),
            period_seconds: r.period_seconds,
            threshold: r.threshold,
            action: WafAction::from(r.action),
            mitigation_timeout_seconds: r.mitigation_timeout_seconds,
            enabled: r.enabled,
            priority: r.priority,
        }
    }

    fn convert_ip_access_rule(r: &proto::IpAccessRule) -> IpAccessRule {
        IpAccessRule {
            id: r.id.clone(),
            name: r.name.clone(),
            ip_ranges: r.ip_ranges.clone(),
            action: IpAccessAction::from(r.action),
            note: r.note.clone(),
            enabled: r.enabled,
        }
    }

    fn convert_geo_config(g: &proto::GeoConfig) -> GeoConfig {
        GeoConfig {
            enabled: g.enabled,
            blocked_countries: g.blocked_countries.clone(),
            allowed_countries: g.allowed_countries.clone(),
            blocked_asns: g.blocked_asns.clone(),
            block_unknown: g.block_unknown,
            action: WafAction::from(g.action),
        }
    }

    fn convert_cache_rule(c: &proto::CacheRule) -> CacheRule {
        CacheRule {
            id: c.id.clone(),
            name: c.name.clone(),
            match_expression: c.match_expression.clone(),
            edge_ttl_seconds: c.edge_ttl_seconds,
            browser_ttl_seconds: c.browser_ttl_seconds,
            disk_quota_mb: c.disk_quota_mb,
            cache_eligible: c.cache_eligible,
            cache_key_headers: c.cache_key_headers.clone(),
            respect_origin_headers: c.respect_origin_headers,
            stale_while_revalidate_seconds: c.stale_while_revalidate_seconds,
            enabled: c.enabled,
        }
    }

    fn convert_challenge_config(c: &proto::ChallengeConfig) -> ChallengeConfig {
        ChallengeConfig {
            enabled: c.enabled,
            under_attack_mode: c.under_attack_mode,
            default_level: ChallengeLevel::from(c.default_level),
            clearance_duration_seconds: c.clearance_duration_seconds,
            exempt_paths: c.exempt_paths.clone(),
            request_threshold: c.request_threshold,
            browser_integrity_check: c.browser_integrity_check,
            tls_fingerprint_check: c.tls_fingerprint_check,
        }
    }

    fn convert_bot_protection(
        b: &proto::BotProtectionConfig,
    ) -> BotProtectionConfig {
        BotProtectionConfig {
            enabled: b.enabled,
            action: WafAction::from(b.action),
            known_bots_whitelist: b.known_bots_whitelist.clone(),
            verified_bot_ranges: b.verified_bot_ranges.clone(),
            dns_verification_enabled: b.dns_verification_enabled,
        }
    }

    fn convert_basic_auth(b: &proto::BasicAuthConfig) -> BasicAuthConfig {
        BasicAuthConfig {
            enabled: b.enabled,
            realm: b.realm.clone(),
            credentials: b
                .credentials
                .iter()
                .map(|credential| BasicAuthCredential {
                    username: credential.username.clone(),
                    authorization: credential.authorization.clone(),
                })
                .collect(),
            delay_seconds: b.delay_seconds,
            hide_credentials: b.hide_credentials,
        }
    }

    fn convert_oidc(c: &proto::OidcConfig) -> OidcConfig {
        OidcConfig {
            enabled: c.enabled,
            issuer: c.issuer.clone(),
            client_id: c.client_id.clone(),
            client_secret: c.client_secret.clone(),
            cookie_secret: c.cookie_secret.clone(),
            redirect_path: c.redirect_path.clone(),
            logout_path: c.logout_path.clone(),
            redirect_url: c.redirect_url.clone(),
            scopes: c.scopes.clone(),
            cookie_name: c.cookie_name.clone(),
            session_ttl_seconds: c.session_ttl_seconds,
            claims_to_headers: c
                .claims_to_headers
                .iter()
                .map(|claim| OidcHeaderClaim {
                    claim: claim.claim.clone(),
                    header: claim.header.clone(),
                })
                .collect(),
            access_mode: c.access_mode.clone(),
            access_rules: c
                .access_rules
                .iter()
                .map(|rule| OidcAccessRule {
                    claim: rule.claim.clone(),
                    operator: rule.operator.clone(),
                    value: rule.value.clone(),
                })
                .collect(),
            auth_mode: c.auth_mode.clone(),
        }
    }

    fn convert_rewrite_rule(r: &proto::RewriteRule) -> RewriteRule {
        RewriteRule {
            id: r.id.clone(),
            name: r.name.clone(),
            match_expression: r.match_expression.clone(),
            direction: RewriteDirection::from(r.direction),
            operations: r
                .operations
                .iter()
                .map(|o| RewriteOperation {
                    op_type: o.r#type.clone(),
                    name: o.name.clone(),
                    value: o.value.clone(),
                })
                .collect(),
            enabled: r.enabled,
            priority: r.priority,
        }
    }

    fn convert_error_page(e: &proto::CustomErrorPage) -> CustomErrorPage {
        CustomErrorPage {
            id: e.id.clone(),
            status_code: e.status_code,
            content_type: e.content_type.clone(),
            body_template: e.body_template.clone(),
            name: e.name.clone(),
            enabled: e.enabled,
        }
    }

    fn convert_ai_crawl(c: &proto::AiCrawlConfig) -> AiCrawlConfig {
        AiCrawlConfig {
            enabled: c.enabled,
            default_action: c.default_action.clone(),
            robots_body: c.robots_body.clone(),
            llms_body: c.llms_body.clone(),
            cache_max_age: c.cache_max_age,
            policies: c
                .policies
                .iter()
                .map(|policy| AiBotPolicy {
                    id: policy.id.clone(),
                    ua_substrings: policy
                        .ua_substrings
                        .iter()
                        .map(|pattern| pattern.to_lowercase())
                        .collect(),
                    category: policy.category.clone(),
                    action: policy.action.clone(),
                })
                .collect(),
        }
    }

    fn convert_ssl_config(s: &proto::SslConfig) -> SslConfig {
        SslConfig {
            cert_pem: s.cert_pem.clone(),
            key_pem: s.key_pem.clone(),
            acme_enabled: s.acme_enabled,
            acme_email: s.acme_email.clone(),
            acme_challenge_type: format!(
                "{:?}",
                proto::AcmeChallengeType::try_from(s.acme_challenge_type)
                    .unwrap_or(proto::AcmeChallengeType::AcmeHttp01)
            ),
            acme_dns_provider: s.acme_dns_provider.clone(),
            acme_dns_config: s.acme_dns_config.clone(),
            min_tls_version: s.min_tls_version.clone(),
            hsts_enabled: s.hsts_enabled,
            hsts_max_age: s.hsts_max_age,
            always_use_https: s.always_use_https,
            enabled: s.enabled,
            max_tls_version: s.max_tls_version.clone(),
            self_signed: s.self_signed,
            mtls_enabled: s.mtls_enabled,
            mtls_client_ca: s.mtls_client_ca.clone(),
            certificate_id: s.certificate_id.clone(),
            mtls_revoked_fingerprints: s
                .mtls_revoked_fingerprints
                .iter()
                .map(|f| f.to_lowercase())
                .collect(),
            mtls_organization: s.mtls_organization.clone(),
            mtls_require_client_cert: Some(s.mtls_require_client_cert),
            http1_enabled: s.http1_enabled,
            http2_enabled: s.http2_enabled,
        }
    }

    fn convert_upstream_config(u: &proto::UpstreamConfig) -> UpstreamConfig {
        UpstreamConfig {
            name: u.name.clone(),
            peers: u
                .peers
                .iter()
                .map(|p| UpstreamPeer {
                    address: p.address.clone(),
                    weight: p.weight,
                    tls: p.tls,
                })
                .collect(),
            // `algo` carries the full pingap spec; the legacy enum is kept for
            // caches that predate it.
            algo: if u.algo.is_empty() {
                format!(
                    "{:?}",
                    proto::LoadBalanceAlgorithm::try_from(u.algorithm)
                        .unwrap_or(proto::LoadBalanceAlgorithm::LbRoundRobin)
                )
                .to_lowercase()
            } else {
                u.algo.clone()
            },
            algorithm: format!(
                "{:?}",
                proto::LoadBalanceAlgorithm::try_from(u.algorithm)
                    .unwrap_or(proto::LoadBalanceAlgorithm::LbRoundRobin)
            ),
            health_check: u.health_check.as_ref().map(|h| HealthCheckConfig {
                enabled: h.enabled,
                path: h.path.clone(),
                interval_seconds: h.interval_seconds,
                timeout_ms: h.timeout_ms,
                unhealthy_threshold: h.unhealthy_threshold,
                healthy_threshold: h.healthy_threshold,
            }),
            connection_timeout_ms: u.connection_timeout_ms,
            read_timeout_ms: u.read_timeout_ms,
            write_timeout_ms: u.write_timeout_ms,
            pool_id: u.pool_id.clone(),
            sni: u.sni.clone(),
            // Kept tri-state: `null` reaches the control plane when a pool
            // has no opinion of its own, and the deployment-wide default is
            // applied once, in the configuration generator, against
            // `basic.origin_verify_cert`. Collapsing it to `Some(false)`
            // here would pin every pool to lenient and make the global
            // switch unreachable.
            verify_cert: u.verify_cert,
            // An older control plane sends nothing, and an empty string is
            // not a family: both fall back to the default instead of
            // reaching the data plane as an unparsable value.
            address_family: if u.address_family.is_empty() {
                default_address_family()
            } else {
                u.address_family.clone()
            },
            is_default: u.is_default,
        }
    }

    fn convert_route_config(r: &proto::RouteConfig) -> RouteConfig {
        RouteConfig {
            id: r.id.clone(),
            name: r.name.clone(),
            match_type: r.match_type.clone(),
            path: r.path.clone(),
            priority: r.priority,
            enabled: r.enabled,
            pool_id: r.pool_id.clone(),
            ip_ranges: r.ip_ranges.clone(),
            strip_prefix: r.strip_prefix,
            rewrite_path: r.rewrite_path.clone(),
            upstream_host: r.upstream_host.clone(),
        }
    }

    fn convert_response_replace(
        r: &proto::ResponseReplaceConfig,
    ) -> ResponseReplaceConfig {
        ResponseReplaceConfig {
            path: r.path.clone(),
            status_codes: r.status_codes.clone(),
            rules: r
                .rules
                .iter()
                .map(|rule| ResponseReplaceRule {
                    pattern: rule.pattern.clone(),
                    replacement: rule.replacement.clone(),
                    is_regex: rule.is_regex,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `sites.json` written before origin pools existed carries none of the
    /// new fields; it must still load.
    #[test]
    fn old_cache_format_still_deserializes() {
        let old = serde_json::json!({
            "sites": {
                "site-1": {
                    "site_id": "site-1",
                    "domain": "example.com",
                    "alternate_domains": [],
                    "rate_limit_rules": [],
                    "ip_access_rules": [],
                    "cache_rules": [],
                    "rewrite_rules": [],
                    "error_pages": [],
                    "upstreams": [
                        {
                            "name": "example.com",
                            "peers": [{"address": "10.0.0.1:80", "weight": 1, "tls": false}],
                            "algorithm": "LbRoundRobin",
                            "connection_timeout_ms": 0,
                            "read_timeout_ms": 0,
                            "write_timeout_ms": 0
                        }
                    ]
                }
            },
            "domain_index": {"example.com": "site-1"},
            "updated_at": "2026-01-01T00:00:00Z",
            "config_hash": "abc"
        });
        let cached: CachedRules =
            serde_json::from_str(&old.to_string()).expect("old format loads");
        let site = cached.sites.get("site-1").expect("site present");
        assert!(site.routes.is_empty());
        assert_eq!(site.upstreams.len(), 1);
        assert!(site.upstreams[0].pool_id.is_empty());
        assert!(!site.upstreams[0].is_default);
        // The failover fields default sensibly on a cache written before
        // they existed: an empty registry and an unsynced global default.
        assert!(cached.failover_registry.is_empty());
        assert_eq!(cached.global_fail_open, None);
        // Same for the response replacement policy: a snapshot written
        // before it existed must load as "replace nothing", not fail.
        assert!(site.response_replace.is_none());
    }

    /// A `sites.json` written before site-level OIDC existed has no `oidc`
    /// key; the `#[serde(default)]` `Option` must load it as `None` instead
    /// of failing (which would force a full cold-start refetch from the
    /// control plane). This is why `CACHE_FORMAT_VERSION` is not bumped.
    #[test]
    fn oidc_absent_in_old_snapshot_defaults_to_none() {
        let old = serde_json::json!({
            "sites": {
                "site-1": {
                    "site_id": "site-1",
                    "domain": "example.com",
                    "alternate_domains": [],
                    "rate_limit_rules": [],
                    "ip_access_rules": [],
                    "cache_rules": [],
                    "rewrite_rules": [],
                    "error_pages": [],
                    "upstreams": [],
                    "basic_auth": null
                }
            },
            "domain_index": {"example.com": "site-1"},
            "updated_at": "2026-01-01T00:00:00Z",
            "config_hash": "abc"
        });
        let cached: CachedRules = serde_json::from_str(&old.to_string())
            .expect("old snapshot without oidc loads");
        let site = cached.sites.get("site-1").expect("site present");
        assert!(site.oidc.is_none());
    }

    /// `convert_oidc` must carry every proto field over unchanged — a
    /// dropped field would silently change the edge's OIDC behaviour.
    #[test]
    fn convert_oidc_round_trips_every_field() {
        let proto_cfg = proto::OidcConfig {
            enabled: true,
            issuer: "https://idp.example.com".to_string(),
            client_id: "client-1".to_string(),
            client_secret: "secret".to_string(),
            cookie_secret: "cookie-secret".to_string(),
            redirect_path: "/_oidc/callback".to_string(),
            logout_path: "/logout".to_string(),
            redirect_url: "https://example.com/_oidc/callback".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
            cookie_name: "pw_oidc".to_string(),
            session_ttl_seconds: 3600,
            claims_to_headers: vec![proto::OidcHeaderClaim {
                claim: "email".to_string(),
                header: "X-Oidc-Email".to_string(),
            }],
            access_mode: "require_any".to_string(),
            access_rules: vec![proto::OidcAccessRule {
                claim: "groups".to_string(),
                operator: "contains".to_string(),
                value: "waf-admins".to_string(),
            }],
            auth_mode: "both".to_string(),
        };
        let converted = RuleCache::convert_oidc(&proto_cfg);
        assert!(converted.enabled);
        assert_eq!(converted.issuer, proto_cfg.issuer);
        assert_eq!(converted.client_id, proto_cfg.client_id);
        assert_eq!(converted.client_secret, proto_cfg.client_secret);
        assert_eq!(converted.cookie_secret, proto_cfg.cookie_secret);
        assert_eq!(converted.redirect_path, proto_cfg.redirect_path);
        assert_eq!(converted.logout_path, proto_cfg.logout_path);
        assert_eq!(converted.redirect_url, proto_cfg.redirect_url);
        assert_eq!(converted.scopes, proto_cfg.scopes);
        assert_eq!(converted.cookie_name, proto_cfg.cookie_name);
        assert_eq!(
            converted.session_ttl_seconds,
            proto_cfg.session_ttl_seconds
        );
        assert_eq!(converted.claims_to_headers.len(), 1);
        assert_eq!(converted.claims_to_headers[0].claim, "email");
        assert_eq!(converted.claims_to_headers[0].header, "X-Oidc-Email");
        assert_eq!(converted.access_mode, proto_cfg.access_mode);
        assert_eq!(converted.access_rules.len(), 1);
        assert_eq!(converted.access_rules[0].claim, "groups");
        assert_eq!(converted.access_rules[0].operator, "contains");
        assert_eq!(converted.access_rules[0].value, "waf-admins");
        assert_eq!(converted.auth_mode, proto_cfg.auth_mode);
    }

    /// Copy-on-write snapshot economics: cloning a `CachedRules` — what
    /// every rcu update does first — must share the registry and the
    /// cache settings by pointer and reuse the domain-index strings,
    /// not duplicate them. This is the regression guard for the
    /// "large-bundle swap transiently doubles memory" issue: the clone
    /// stays O(map headers + reference counts) regardless of how many
    /// domains and policies are registered.
    #[test]
    fn cached_rules_clone_shares_the_heavy_fields() {
        let rules = CachedRules {
            sites: HashMap::new(),
            domain_index: HashMap::from([
                (Arc::from("example.com"), Arc::from("site-1")),
                (Arc::from("*.example.net"), Arc::from("site-1")),
            ]),
            failover_registry: Arc::new(HashMap::from([(
                "example.com".to_string(),
                FailoverMode::Closed,
            )])),
            global_fail_open: None,
            global_cache: Some(Arc::new(GlobalCacheSettings {
                max_space_mb: Some(512),
                ..Default::default()
            })),
            origin_verify_cert: None,
            updated_at: Utc::now(),
            config_hash: Arc::from("abc"),
        };
        let clone = rules.clone();
        assert!(
            Arc::ptr_eq(&rules.failover_registry, &clone.failover_registry),
            "the registry must move by pointer, not by map copy"
        );
        assert!(
            rules
                .global_cache
                .as_ref()
                .zip(clone.global_cache.as_ref())
                .is_some_and(|(a, b)| Arc::ptr_eq(a, b)),
            "the cache settings must move by pointer"
        );
        for (key, value) in &rules.domain_index {
            assert!(
                clone
                    .domain_index
                    .get(key.as_ref())
                    .is_some_and(|cloned| Arc::ptr_eq(value, cloned)),
                "domain-index entries must be shared, not re-allocated"
            );
        }
    }

    #[test]
    fn failover_registry_covers_alternate_domains() {
        use proto::SitePolicy;
        let policies = [SitePolicy {
            domain: "example.com".to_string(),
            alternate_domains: vec!["m.example.com".to_string()],
            mode: proto::FailoverMode::FailoverClosed as i32,
        }];
        let registry = failover_registry_from(&policies);
        assert_eq!(registry.get("example.com"), Some(&FailoverMode::Closed));
        assert_eq!(registry.get("m.example.com"), Some(&FailoverMode::Closed));
        assert_eq!(registry.get("other.example.com"), None);
    }

    #[test]
    fn cidr_block_covers_member_addresses_including_ipv6() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        cache.block_ip("site-1", "203.0.113.0/24", None, "manual: range");
        cache.block_ip("site-1", "2001:db8::/32", None, "manual: v6 range");
        cache.block_ip("site-1", "198.51.100.7", None, "manual: single");

        // Members of the range match; neighbours do not.
        assert_eq!(
            cache.blocked_reason("site-1", "203.0.113.55").as_deref(),
            Some("manual: range")
        );
        assert_eq!(cache.blocked_reason("site-1", "203.0.114.55"), None);
        assert_eq!(cache.blocked_reason("site-1", "198.51.100.55"), None);
        // IPv6 CIDR matching.
        assert!(cache.is_ip_blocked("site-1", "2001:db8:dead::1"));
        assert!(!cache.is_ip_blocked("site-1", "2001:db9::1"));
        // Legacy single-address behaviour is unchanged.
        assert_eq!(
            cache.blocked_reason("site-1", "198.51.100.7").as_deref(),
            Some("manual: single")
        );
        // Another site is not affected by site-1's ranges.
        assert_eq!(cache.blocked_reason("site-2", "203.0.113.55"), None);
    }

    #[test]
    fn block_persist_is_debounced_until_flush() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        cache.block_ip("site-1", "203.0.113.7", None, "waf: sqli");
        // The map is authoritative immediately — enforcement needs no disk.
        assert_eq!(
            cache.blocked_reason("site-1", "203.0.113.7").as_deref(),
            Some("waf: sqli")
        );
        // ...but nothing was written: the hot path only marks dirty.
        assert!(!dir.path().join("blocked_ips.json").exists());

        // The flush task's unit of work persists the pending change.
        cache.flush_blocked_ips();
        let raw = std::fs::read(dir.path().join("blocked_ips.json"))
            .expect("flush wrote blocked_ips.json");
        let entries: Vec<BlockedIpEntry> =
            serde_json::from_slice(&raw).expect("flushed snapshot parses");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason, "waf: sqli");

        // Write the rule snapshot too so a reload takes the disk path, then
        // verify the flushed blocks are restored by a fresh cache.
        cache.persist_to_disk().unwrap();
        let reloaded =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();
        assert_eq!(
            reloaded.blocked_reason("site-1", "203.0.113.7").as_deref(),
            Some("waf: sqli")
        );

        // Unblock also only marks dirty; the next flush removes it on disk.
        cache.unblock_ip("site-1", "203.0.113.7");
        assert_eq!(cache.blocked_reason("site-1", "203.0.113.7"), None);
        cache.flush_blocked_ips();
        cache.persist_to_disk().unwrap();
        let reloaded =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();
        assert_eq!(reloaded.blocked_reason("site-1", "203.0.113.7"), None);
    }

    #[test]
    fn blocked_capacity_evicts_expired_then_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        // Fill to the (test) ceiling: first three entries are permanent,
        // the fourth is already-expiring, the fifth is the newest permanent.
        for i in 0..3 {
            cache.block_ip("site-1", &format!("10.0.0.{i}"), None, "waf: old");
        }
        cache.block_ip(
            "site-1",
            "10.0.1.1",
            Some(Duration::from_millis(1)),
            "waf: expiring",
        );
        std::thread::sleep(Duration::from_millis(50));
        cache.block_ip("site-1", "10.0.2.1", None, "waf: newest");

        // limit=5, headroom=2 → target=3: the expired entry is swept first
        // (4 remain), then the single oldest block is evicted.
        cache.enforce_blocked_capacity_inner(5, 2);

        assert_eq!(cache.blocked_reason("site-1", "10.0.1.1"), None);
        assert_eq!(cache.blocked_reason("site-1", "10.0.0.0"), None);
        assert_eq!(
            cache.blocked_reason("site-1", "10.0.0.1").as_deref(),
            Some("waf: old")
        );
        assert_eq!(
            cache.blocked_reason("site-1", "10.0.0.2").as_deref(),
            Some("waf: old")
        );
        assert_eq!(
            cache.blocked_reason("site-1", "10.0.2.1").as_deref(),
            Some("waf: newest")
        );
        assert!(cache.blocked_ips.len() <= 3);

        // A CIDR range evicted by capacity leaves no stale index rows:
        // covered addresses stop matching once the range is gone. Separate
        // cache so the eviction targets the range as the oldest entry.
        let dir2 = tempfile::tempdir().unwrap();
        let cache2 =
            RuleCache::new(dir2.path().to_path_buf(), "test".to_string())
                .unwrap();
        cache2.block_ip("site-1", "10.9.0.0/16", None, "waf: old range");
        std::thread::sleep(Duration::from_millis(10));
        cache2.block_ip("site-1", "10.9.1.1", None, "waf: newest");
        assert!(cache2.is_ip_blocked("site-1", "10.9.0.5"));
        // limit=2, headroom=1 → target=1: the oldest entry (the range) goes.
        cache2.enforce_blocked_capacity_inner(2, 1);
        assert!(!cache2.is_ip_blocked("site-1", "10.9.0.5"));
        assert!(cache2.is_ip_blocked("site-1", "10.9.1.1"));
    }

    #[test]
    fn unblock_removes_exactly_the_address_or_range_requested() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        cache.block_ip("site-1", "10.0.0.0/24", None, "manual: range");
        cache.block_ip("site-1", "10.0.0.7", None, "manual: single");

        // Unblocking the range must not lift the single-IP block it covers.
        cache.unblock_ip("site-1", "10.0.0.0/24");
        assert_eq!(
            cache.blocked_reason("site-1", "10.0.0.7").as_deref(),
            Some("manual: single")
        );

        // Unblocking the single IP leaves an identical range untouched
        // (re-add the range first).
        cache.block_ip("site-1", "10.0.0.0/24", None, "manual: range");
        cache.unblock_ip("site-1", "10.0.0.7");
        assert_eq!(
            cache.blocked_reason("site-1", "10.0.0.9").as_deref(),
            Some("manual: range")
        );
    }

    #[test]
    fn cidr_index_stays_consistent_across_block_unblock_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        cache.block_ip("site-1", "10.1.0.0/16", None, "manual: range");
        assert!(cache.is_ip_blocked("site-1", "10.1.2.3"));
        // The slow path reads the index, not the main map: an unrelated
        // non-CIDR entry in another site must not influence the result.
        cache.block_ip("site-2", "10.1.9.9", None, "single");
        assert!(!cache.is_ip_blocked("site-2", "10.1.2.3"));

        // Unblock removes the indexed net — the covered address is free.
        cache.unblock_ip("site-1", "10.1.0.0/16");
        assert!(!cache.is_ip_blocked("site-1", "10.1.2.3"));

        // Expired CIDR entries do not match and are dropped from the index.
        cache.block_ip(
            "site-1",
            "10.2.0.0/16",
            Some(Duration::from_millis(200)),
            "temporary",
        );
        assert!(cache.is_ip_blocked("site-1", "10.2.5.5"));
        std::thread::sleep(Duration::from_millis(400));
        assert!(!cache.is_ip_blocked("site-1", "10.2.5.5"));
        cache.cleanup_expired_blocks();
        assert!(!cache.is_ip_blocked("site-1", "10.2.5.5"));
    }

    #[test]
    fn cidr_index_is_rebuilt_from_the_persisted_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();
        cache.block_ip("site-1", "10.3.0.0/16", None, "manual: range");
        cache.persist_to_disk().unwrap();

        // A fresh cache loads the snapshot and rebuilds the index.
        let reloaded =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();
        assert!(reloaded.is_ip_blocked("site-1", "10.3.44.5"));
        assert_eq!(
            reloaded.blocked_reason("site-1", "10.3.44.5").as_deref(),
            Some("manual: range")
        );
        assert!(!reloaded.is_ip_blocked("site-1", "10.4.44.5"));

        // Unblocking the reloaded range removes it for good.
        reloaded.unblock_ip("site-1", "10.3.0.0/16");
        assert!(!reloaded.is_ip_blocked("site-1", "10.3.44.5"));
    }

    #[test]
    fn mapped_ipv6_clients_match_ipv4_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        cache.block_ip("site-1", "203.0.113.5", None, "single");
        cache.block_ip("site-1", "203.0.114.0/24", None, "range");
        assert!(cache.is_ip_blocked("site-1", "::ffff:203.0.113.5"));
        assert!(cache.is_ip_blocked("site-1", "::ffff:203.0.114.9"));
        assert!(!cache.is_ip_blocked("site-1", "::ffff:203.0.115.1"));
    }

    #[test]
    fn unknown_failover_modes_degrade_to_inherit() {
        assert_eq!(FailoverMode::from(0), FailoverMode::Inherit);
        assert_eq!(FailoverMode::from(1), FailoverMode::Open);
        assert_eq!(FailoverMode::from(2), FailoverMode::Closed);
        assert_eq!(FailoverMode::from(99), FailoverMode::Inherit);
    }

    #[test]
    fn clear_waf_auto_blocks_removes_only_waf_reasons() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        cache.block_ip("site-1", "203.0.113.1", None, "waf: sqli probe");
        cache.block_ip("site-1", "203.0.113.2", None, "rate limit: login");
        cache.block_ip("site-1", "203.0.113.3", None, "manual abuse");
        cache.block_ip("site-2", "203.0.113.1", None, "waf: other site");

        let removed = cache.clear_waf_auto_blocks("site-1");
        assert_eq!(removed, 1);
        assert_eq!(cache.blocked_reason("site-1", "203.0.113.1"), None);
        assert_eq!(
            cache.blocked_reason("site-1", "203.0.113.2").as_deref(),
            Some("rate limit: login")
        );
        assert_eq!(
            cache.blocked_reason("site-1", "203.0.113.3").as_deref(),
            Some("manual abuse")
        );
        // Another site's WAF auto-blocks are untouched.
        assert_eq!(
            cache.blocked_reason("site-2", "203.0.113.1").as_deref(),
            Some("waf: other site")
        );

        // Clearing again is a no-op.
        assert_eq!(cache.clear_waf_auto_blocks("site-1"), 0);
    }

    #[test]
    fn update_from_site_config_removes_deleted_sites() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        let site = |id: &str, domain: &str| proto::Site {
            id: id.to_string(),
            name: id.to_string(),
            domain: domain.to_string(),
            alternate_domains: Vec::new(),
            status: 0,
            rules: Some(proto::RuleBundle {
                site_id: id.to_string(),
                config_hash: "hash".to_string(),
                ..Default::default()
            }),
            trust_proxy_headers: false,
            trusted_header: String::new(),
            trust_last_hop: false,
            trusted_proxy_ranges: Vec::new(),
        };
        cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![
                    site("site-1", "a.example.com"),
                    site("site-2", "b.example.com"),
                ],
                ..Default::default()
            })
            .unwrap();
        assert!(cache.get_site_rules_by_id("site-2").is_some());
        cache.block_ip("site-2", "203.0.113.1", None, "waf: stale");

        // A sync without site-2 drops the site, its domain index entries
        // and its dynamic blocks — it must not keep serving from stale
        // cached rules.
        cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![site("site-1", "a.example.com")],
                ..Default::default()
            })
            .unwrap();
        assert!(cache.get_site_rules_by_id("site-2").is_none());
        assert!(cache.get_site_rules("b.example.com").is_none());
        assert_eq!(cache.blocked_reason("site-2", "203.0.113.1"), None);
        // The surviving site is untouched.
        assert!(cache.get_site_rules_by_id("site-1").is_some());
    }

    #[test]
    fn wildcard_sites_resolve_subdomains_via_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();

        let policies = vec![
            proto::SitePolicy {
                domain: "*.example.com".to_string(),
                alternate_domains: Vec::new(),
                mode: proto::FailoverMode::FailoverClosed as i32,
            },
            proto::SitePolicy {
                domain: "app.example.com".to_string(),
                alternate_domains: Vec::new(),
                mode: proto::FailoverMode::FailoverOpen as i32,
            },
        ];
        let site = |id: &str, domain: &str| proto::Site {
            id: id.to_string(),
            name: id.to_string(),
            domain: domain.to_string(),
            alternate_domains: Vec::new(),
            status: 0,
            rules: Some(proto::RuleBundle {
                site_id: id.to_string(),
                config_hash: "hash".to_string(),
                site_policies: policies.clone(),
                ..Default::default()
            }),
            trust_proxy_headers: false,
            trusted_header: String::new(),
            trust_last_hop: false,
            trusted_proxy_ranges: Vec::new(),
        };
        cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![
                    site("site-exact", "app.example.com"),
                    site("site-wild", "*.example.com"),
                    site("site-deep", "*.a.example.com"),
                ],
                ..Default::default()
            })
            .unwrap();

        let id_of = |domain: &str| {
            cache.get_site_rules(domain).map(|r| r.site_id.clone())
        };

        // An exact site always wins over any wildcard.
        assert_eq!(id_of("app.example.com").as_deref(), Some("site-exact"));
        // Direct subdomains fall back to the wildcard site — before this
        // fix a wildcard site lost its WAF rules, cache policy, challenge
        // and error pages entirely.
        assert_eq!(id_of("foo.example.com").as_deref(), Some("site-wild"));
        // The most specific wildcard wins for deeper names.
        assert_eq!(id_of("a.example.com").as_deref(), Some("site-wild"));
        assert_eq!(id_of("www.a.example.com").as_deref(), Some("site-deep"));
        // The apex itself is not covered by a wildcard — the same
        // semantics as `HostSelector::Suffix` in the routing layer.
        assert!(cache.get_site_rules("example.com").is_none());

        // The failover registry follows the same fallback, so a wildcard
        // site's disconnected policy actually applies to its subdomains.
        assert_eq!(
            cache.failover_for_domain("app.example.com"),
            Some(FailoverMode::Open)
        );
        assert_eq!(
            cache.failover_for_domain("foo.example.com"),
            Some(FailoverMode::Closed)
        );
        assert_eq!(cache.failover_for_domain("example.com"), None);
    }

    #[test]
    fn unknown_waf_mode_enforces_fail_close() {
        assert_eq!(WafMode::from(0), WafMode::Off);
        assert_eq!(WafMode::from(1), WafMode::Monitor);
        assert_eq!(WafMode::from(2), WafMode::Block);
        // An unknown enum value from a newer control plane must not switch
        // the site's WAF off for the upgrade window.
        assert_eq!(WafMode::from(7), WafMode::Block);
    }

    #[test]
    fn unknown_challenge_level_enforces_fail_close() {
        assert_eq!(ChallengeLevel::from(0), ChallengeLevel::None);
        assert_eq!(ChallengeLevel::from(3), ChallengeLevel::Interactive);
        // Degrading to None would silently stop challenging; the strongest
        // level keeps the protection.
        assert_eq!(ChallengeLevel::from(9), ChallengeLevel::Interactive);
    }

    #[test]
    fn new_format_roundtrips() {
        let cached = CachedRules {
            sites: [(
                "site-1".to_string(),
                Arc::new(SiteRules {
                    site_id: "site-1".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: site_status::PAUSED.to_string(),
                    waf_config: None,
                    rate_limit_rules: Vec::new(),
                    ip_access_rules: Vec::new(),
                    geo_config: None,
                    cache_rules: Vec::new(),
                    challenge_config: None,
                    rewrite_rules: Vec::new(),
                    error_pages: Vec::new(),
                    basic_auth: None,
                    oidc: None,
                    observation_mode: false,
                    proxy_trust: ProxyTrustConfig::default(),
                    cache_settings: None,
                    ssl_config: None,
                    upstreams: vec![UpstreamConfig {
                        name: "default".to_string(),
                        peers: Vec::new(),
                        algorithm: "LbRoundRobin".to_string(),
                        health_check: None,
                        connection_timeout_ms: 0,
                        read_timeout_ms: 0,
                        write_timeout_ms: 0,
                        pool_id: "pool-1".to_string(),
                        algo: "hash:header:x-user".to_string(),
                        sni: "origin.example.com".to_string(),
                        verify_cert: Some(false),
                        address_family: "auto".to_string(),
                        is_default: true,
                    }],
                    routes: vec![RouteConfig {
                        id: "route-1".to_string(),
                        name: "api".to_string(),
                        match_type: "exact".to_string(),
                        path: "/api".to_string(),
                        priority: Some(10),
                        enabled: true,
                        pool_id: "pool-1".to_string(),
                        ip_ranges: vec!["10.0.0.0/8".to_string()],
                        strip_prefix: true,
                        rewrite_path: "/v2".to_string(),
                        upstream_host: "origin.example.com".to_string(),
                    }],
                    bot_protection: None,
                    response_replace: Some(ResponseReplaceConfig {
                        path: "^/api/.*".to_string(),
                        status_codes: vec![200],
                        rules: vec![ResponseReplaceRule {
                            pattern: "Google".to_string(),
                            replacement: "PingWAF".to_string(),
                            is_regex: false,
                        }],
                    }),
                    ai_crawl: None,
                }),
            )]
            .into_iter()
            .collect(),
            domain_index: HashMap::new(),
            failover_registry: Arc::new(HashMap::from([(
                "example.com".to_string(),
                FailoverMode::Closed,
            )])),
            global_fail_open: Some(true),
            global_cache: None,
            origin_verify_cert: Some(false),
            updated_at: Utc::now(),
            config_hash: "abc".into(),
        };
        let json = serde_json::to_string(&cached).expect("serialize");
        let back: CachedRules =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            back.failover_registry.get("example.com"),
            Some(&FailoverMode::Closed)
        );
        assert_eq!(back.global_fail_open, Some(true));
        assert_eq!(back.origin_verify_cert, Some(false));
        let site = back.sites.get("site-1").expect("site present");
        assert_eq!(site.routes.len(), 1);
        assert_eq!(site.routes[0].path, "/api");
        assert_eq!(site.routes[0].ip_ranges, vec!["10.0.0.0/8"]);
        assert!(site.is_paused());
        assert_eq!(site.status, site_status::PAUSED);
        assert_eq!(site.upstreams[0].algo, "hash:header:x-user");
        assert_eq!(site.upstreams[0].sni, "origin.example.com");
    }

    #[test]
    fn old_cache_defaults_new_fields() {
        // A cache persisted before `status`/`ip_ranges`/mTLS extras existed.
        let old = serde_json::json!({
            "sites": {
                "site-1": {
                    "site_id": "site-1",
                    "domain": "example.com",
                    "alternate_domains": [],
                    "rate_limit_rules": [],
                    "ip_access_rules": [],
                    "cache_rules": [],
                    "rewrite_rules": [],
                    "error_pages": [],
                    "upstreams": [],
                    "routes": [{
                        "id": "route-1",
                        "name": "api",
                        "match_type": "prefix",
                        "path": "/api",
                        "priority": null,
                        "enabled": true,
                        "pool_id": "pool-1"
                    }],
                    "ssl_config": {
                        "cert_pem": "",
                        "key_pem": "",
                        "acme_enabled": false,
                        "acme_email": "",
                        "acme_challenge_type": "AcmeHttp01",
                        "acme_dns_provider": "",
                        "acme_dns_config": {},
                        "min_tls_version": "",
                        "hsts_enabled": false,
                        "hsts_max_age": 0,
                        "always_use_https": false,
                        "enabled": true,
                        "max_tls_version": "",
                        "self_signed": false,
                        "mtls_enabled": true,
                        "mtls_client_ca": "PEM",
                        "certificate_id": ""
                    }
                }
            },
            "domain_index": {"example.com": "site-1"},
            "updated_at": "2026-01-01T00:00:00Z",
            "config_hash": "abc"
        });
        let cached: CachedRules =
            serde_json::from_str(&old.to_string()).expect("old format loads");
        let site = cached.sites.get("site-1").expect("site present");
        assert_eq!(site.status, site_status::ACTIVE);
        assert!(!site.is_paused());
        assert!(site.routes[0].ip_ranges.is_empty());
        let ssl = site.ssl_config.as_ref().expect("ssl config");
        assert!(ssl.mtls_revoked_fingerprints.is_empty());
        assert!(ssl.mtls_organization.is_empty());
        assert!(ssl.mtls_requires_cert());
        // The cache ceiling fields default when a pre-ceiling cache loads.
        assert!(cached.global_cache.is_none());
        assert!(site.cache_settings.is_none());
    }

    #[test]
    fn global_space_clamps_site_quotas() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap();
        const DOMAIN: &str = "clamp-test.example.com";

        let site = |quota_mb: u32| {
            Arc::new(SiteRules {
                site_id: "site-1".to_string(),
                domain: DOMAIN.to_string(),
                alternate_domains: Vec::new(),
                status: site_status::ACTIVE.to_string(),
                waf_config: None,
                rate_limit_rules: Vec::new(),
                ip_access_rules: Vec::new(),
                geo_config: None,
                cache_rules: vec![CacheRule {
                    id: "r1".to_string(),
                    name: "static".to_string(),
                    match_expression: String::new(),
                    edge_ttl_seconds: 300,
                    browser_ttl_seconds: 60,
                    disk_quota_mb: quota_mb,
                    cache_eligible: true,
                    cache_key_headers: Vec::new(),
                    respect_origin_headers: true,
                    stale_while_revalidate_seconds: 0,
                    enabled: true,
                }],
                challenge_config: None,
                rewrite_rules: Vec::new(),
                error_pages: Vec::new(),
                ssl_config: None,
                upstreams: Vec::new(),
                routes: Vec::new(),
                bot_protection: None,
                basic_auth: None,
                oidc: None,
                observation_mode: false,
                proxy_trust: ProxyTrustConfig::default(),
                cache_settings: None,
                response_replace: None,
                ai_crawl: None,
            })
        };
        let store = |global_space_mb: Option<u32>, quota_mb: u32| {
            cache.inner.store(Arc::new(CachedRules {
                sites: [(DOMAIN.to_string(), site(quota_mb))]
                    .into_iter()
                    .collect(),
                domain_index: HashMap::new(),
                failover_registry: Arc::new(HashMap::new()),
                global_fail_open: None,
                global_cache: global_space_mb.map(|max_space_mb| {
                    Arc::new(GlobalCacheSettings {
                        max_space_mb: Some(max_space_mb),
                        ..Default::default()
                    })
                }),
                origin_verify_cert: None,
                updated_at: Utc::now(),
                config_hash: Arc::from(""),
            }));
        };

        // No budget: the site quota passes through untouched.
        store(None, 2048);
        cache.apply_cache_quotas();
        assert_eq!(quota::configured_quota_mb(DOMAIN), Some(2048));

        // A budget caps an explicit site quota.
        store(Some(1024), 2048);
        cache.apply_cache_quotas();
        assert_eq!(quota::configured_quota_mb(DOMAIN), Some(1024));

        // An unlimited site is capped at the budget.
        store(Some(1024), 0);
        cache.apply_cache_quotas();
        assert_eq!(quota::configured_quota_mb(DOMAIN), Some(1024));

        // No budget at all leaves unlimited as unlimited — parking 0 clears
        // the parked ceiling entirely (`configured_quota_mb` answers None).
        store(None, 0);
        cache.apply_cache_quotas();
        assert_eq!(quota::configured_quota_mb(DOMAIN), None);
    }

    #[test]
    fn proto_conversion_carries_status_and_new_fields() {
        let site = proto::Site {
            id: "site-1".to_string(),
            name: "Example".to_string(),
            domain: "example.com".to_string(),
            alternate_domains: Vec::new(),
            status: 1, // SITE_STATUS_PAUSED
            rules: Some(proto::RuleBundle {
                ssl: Some(proto::SslConfig {
                    mtls_enabled: true,
                    mtls_revoked_fingerprints: vec!["AB".to_string()],
                    mtls_organization: "acme".to_string(),
                    mtls_require_client_cert: true,
                    ..Default::default()
                }),
                routes: vec![proto::RouteConfig {
                    ip_ranges: vec!["10.0.0.0/8".to_string()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            trust_proxy_headers: false,
            trusted_header: String::new(),
            trust_last_hop: false,
            trusted_proxy_ranges: Vec::new(),
        };
        assert_eq!(site_status_str(site.status), site_status::PAUSED);
        let rules =
            RuleCache::convert_bundle(site.rules.as_ref().expect("bundle"));
        let ssl = rules.ssl_config.as_ref().expect("ssl config");
        assert_eq!(ssl.mtls_revoked_fingerprints, vec!["ab".to_string()]);
        assert_eq!(ssl.mtls_organization, "acme");
        assert!(ssl.mtls_requires_cert());
        assert_eq!(rules.routes[0].ip_ranges, vec!["10.0.0.0/8"]);
        assert_eq!(site_status_str(0), site_status::ACTIVE);
        assert_eq!(site_status_str(2), site_status::PENDING);
        assert_eq!(site_status_str(7), site_status::ACTIVE);
    }

    #[test]
    fn optional_mtls_does_not_require_a_client_certificate() {
        let site = proto::Site {
            id: "site-1".to_string(),
            name: "Example".to_string(),
            domain: "example.com".to_string(),
            alternate_domains: Vec::new(),
            status: 0,
            rules: Some(proto::RuleBundle {
                ssl: Some(proto::SslConfig {
                    mtls_enabled: true,
                    mtls_client_ca: "PEM".to_string(),
                    mtls_require_client_cert: false,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            trust_proxy_headers: false,
            trusted_header: String::new(),
            trust_last_hop: false,
            trusted_proxy_ranges: Vec::new(),
        };
        let rules =
            RuleCache::convert_bundle(site.rules.as_ref().expect("bundle"));
        let ssl = rules.ssl_config.as_ref().expect("ssl config");
        assert!(ssl.mtls_enabled);
        assert!(!ssl.mtls_requires_cert());
    }

    #[test]
    fn proto_algo_supersedes_legacy_algorithm() {
        let mut u = proto::UpstreamConfig {
            algorithm: 1, // LB_CONSISTENT_HASH
            ..Default::default()
        };
        let converted = RuleCache::convert_upstream_config(&u);
        assert_eq!(converted.algo, "lbconsistenthash");

        u.algo = "hash:cookie:session".to_string();
        let converted = RuleCache::convert_upstream_config(&u);
        assert_eq!(converted.algo, "hash:cookie:session");
    }

    /// The address family survives the wire, and both an older control plane
    /// (empty field) and a cache written before the field existed land on
    /// `auto` rather than on an unparsable empty string.
    #[test]
    fn proto_address_family_defaults_to_auto() {
        let mut u = proto::UpstreamConfig::default();
        assert_eq!(
            "auto",
            RuleCache::convert_upstream_config(&u).address_family
        );

        u.address_family = "ipv6".to_string();
        assert_eq!(
            "ipv6",
            RuleCache::convert_upstream_config(&u).address_family
        );
    }

    /// A pool cached before `address_family` existed must still load, and
    /// must come back as `auto` - the family that fixed the IPv6 503.
    #[test]
    fn cached_upstream_without_address_family_is_auto() {
        let json = r#"{
            "name": "default",
            "peers": [],
            "algorithm": "LbRoundRobin",
            "health_check": null,
            "connection_timeout_ms": 0,
            "read_timeout_ms": 0,
            "write_timeout_ms": 0
        }"#;
        let upstream: UpstreamConfig =
            serde_json::from_str(json).expect("an old cache entry must load");
        assert_eq!("auto", upstream.address_family);
    }

    // ─── Crash injection: torn writes, tampering, backup fallback ───

    /// A torn `sites.json` (crash in the middle of a direct write) must fall
    /// back to the rolled backup, and the restore must show up in health.
    #[test]
    fn torn_primary_falls_back_to_backup() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let cache = RuleCache::new(root.clone(), "test".to_string()).unwrap();
        cache.persist_to_disk().unwrap(); // first snapshot, no backup yet
        cache.persist_to_disk().unwrap(); // rolls snapshot #1 to .bak

        // Tear the primary the way a mid-write power cut would.
        let sites = root.join("sites.json");
        let bytes = std::fs::read(&sites).unwrap();
        std::fs::write(&sites, &bytes[..bytes.len() / 2]).unwrap();

        let reloaded = RuleCache::new(root, "test".to_string()).unwrap();
        let health = reloaded.health_status();
        assert_eq!(health.source, LoadSource::Backup);
        assert!(health.healthy, "backup restore keeps the agent functional");
        let reason = health.reason.unwrap_or_default();
        assert!(reason.contains("backup"), "unexpected reason: {reason}");
    }

    /// Valid JSON whose content differs from the metadata CRC stamp must be
    /// rejected — parse success alone is not integrity.
    #[test]
    fn tampered_primary_fails_crc_check() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let cache = RuleCache::new(root.clone(), "test".to_string()).unwrap();
        cache.persist_to_disk().unwrap();
        cache.persist_to_disk().unwrap(); // ensure a backup exists

        let sites = root.join("sites.json");
        let bytes = std::fs::read(&sites).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        value["config_hash"] = serde_json::Value::String("tampered".into());
        std::fs::write(&sites, serde_json::to_string(&value).unwrap()).unwrap();

        let reloaded = RuleCache::new(root, "test".to_string()).unwrap();
        let health = reloaded.health_status();
        assert_eq!(health.source, LoadSource::Backup);
        let reason = health.reason.unwrap_or_default();
        assert!(reason.contains("integrity"), "unexpected reason: {reason}");
    }

    /// Corrupt primary with no backup → the agent starts on empty rules,
    /// reports unhealthy with a reason, and keeps working (fail-open).
    #[test]
    fn corrupt_primary_without_backup_degrades_to_unhealthy() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let cache = RuleCache::new(root.clone(), "test".to_string()).unwrap();
        cache.persist_to_disk().unwrap(); // single snapshot, no backup

        std::fs::write(root.join("sites.json"), b"{not json").unwrap();

        let reloaded =
            RuleCache::new(root.clone(), "test".to_string()).unwrap();
        let health = reloaded.health_status();
        assert!(!health.healthy);
        assert_eq!(health.source, LoadSource::Fresh);
        assert!(health.reason.is_some());

        // Fail-open: the degraded cache still persists and serves.
        reloaded.persist_to_disk().unwrap();
        assert!(root.join("sites.json").exists());

        // The persist fixed the disk, but the load failure stays sticky:
        // health only clears on an actual successful load, never on a
        // successful persist.
        assert!(!reloaded.health_status().healthy);

        // The next process loads the freshly written snapshot cleanly.
        let third = RuleCache::new(root, "test".to_string()).unwrap();
        let health = third.health_status();
        assert_eq!(health.source, LoadSource::Disk);
        assert!(health.healthy);
    }

    /// A tampered (valid JSON, wrong CRC) primary must not be rolled into
    /// the backup: the persist keeps the previous good backup and writes a
    /// fresh primary over the tampered one.
    #[test]
    fn tampered_primary_does_not_evict_good_backup() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let cache = RuleCache::new(root.clone(), "test".to_string()).unwrap();
        cache.persist_to_disk().unwrap();
        cache.persist_to_disk().unwrap(); // backup now holds a good snapshot

        let bak_before = std::fs::read(root.join("sites.json.bak")).unwrap();

        let sites = root.join("sites.json");
        let bytes = std::fs::read(&sites).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        value["config_hash"] = serde_json::Value::String("tampered".into());
        std::fs::write(&sites, serde_json::to_string(&value).unwrap()).unwrap();

        // In-process: the roll skips the tampered snapshot, then writes a
        // fresh primary over it.
        cache.persist_to_disk().unwrap();

        assert_eq!(
            std::fs::read(root.join("sites.json.bak")).unwrap(),
            bak_before,
            "the good backup must survive the tampered roll"
        );

        let reloaded = RuleCache::new(root, "test".to_string()).unwrap();
        let health = reloaded.health_status();
        assert_eq!(health.source, LoadSource::Disk);
        assert!(health.healthy);
    }

    /// A metadata stamped with an unknown *higher* format version is treated
    /// as incompatible and rejected rather than misread.
    #[test]
    fn future_format_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let cache = RuleCache::new(root.clone(), "test".to_string()).unwrap();
        cache.persist_to_disk().unwrap();

        let meta_path = root.join("metadata.json");
        let mut meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&meta_path).unwrap())
                .unwrap();
        meta["version"] = serde_json::Value::from(CACHE_FORMAT_VERSION + 1);
        std::fs::write(&meta_path, serde_json::to_string(&meta).unwrap())
            .unwrap();

        let reloaded = RuleCache::new(root, "test".to_string()).unwrap();
        let health = reloaded.health_status();
        assert!(!health.healthy);
        let reason = health.reason.unwrap_or_default();
        assert!(reason.contains("version"), "unexpected reason: {reason}");
    }

    /// Snapshots written before integrity stamping (no CRC fields in
    /// metadata) still load, with parse validation only.
    #[test]
    fn legacy_metadata_without_crc_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let cache = RuleCache::new(root.clone(), "test".to_string()).unwrap();
        cache.persist_to_disk().unwrap();

        let meta_path = root.join("metadata.json");
        let mut meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&meta_path).unwrap())
                .unwrap();
        if let Some(obj) = meta.as_object_mut() {
            obj.remove("sites_crc32");
            obj.remove("sites_len");
        }
        std::fs::write(&meta_path, serde_json::to_string(&meta).unwrap())
            .unwrap();

        let reloaded = RuleCache::new(root, "test".to_string()).unwrap();
        let health = reloaded.health_status();
        assert_eq!(health.source, LoadSource::Disk);
        assert!(health.healthy);
    }

    /// Concurrent persist calls must not interleave: the lock serializes
    /// them and the final on-disk pair stays consistent.
    #[test]
    fn concurrent_persists_stay_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let cache = RuleCache::new(root.clone(), "test".to_string()).unwrap();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..5 {
                    cache.persist_to_disk().unwrap();
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        // The last persist must leave sites.json parseable and stamped by
        // the metadata currently on disk.
        let bytes = std::fs::read(root.join("sites.json")).unwrap();
        let meta: CacheMetadata = serde_json::from_slice(
            &std::fs::read(root.join("metadata.json")).unwrap(),
        )
        .unwrap();
        assert!(persist::content_matches(
            &bytes,
            meta.sites_crc32.unwrap(),
            meta.sites_len.unwrap()
        ));
        serde_json::from_slice::<CachedRules>(&bytes).unwrap();
    }
}
