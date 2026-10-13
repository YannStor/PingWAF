use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use pingap_cache::quota;
use pingap_core::normalize_host;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use pingwaf_proto::control_plane as proto;

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
    pub domain_index: HashMap<String, String>,
    /// Domain → disconnected (failover) policy, covering every site the
    /// control plane knows about — including ones whose rule bundle this
    /// agent has not (yet) received. Consulted when a host has no synced
    /// rules, which is exactly when `sites` cannot answer.
    #[serde(default)]
    pub failover_registry: HashMap<String, FailoverMode>,
    /// Control-plane-wide default for hosts absent from
    /// `failover_registry`. `None` when the server never sent it (old
    /// control plane), which makes the agent fall back to its local
    /// `config.fail_open`.
    #[serde(default)]
    pub global_fail_open: Option<bool>,
    /// Deployment-wide cache ceiling; `None` when the server never sent it
    /// (old control plane) — the generator and quota logic then fall back to
    /// their built-in defaults.
    #[serde(default)]
    pub global_cache: Option<GlobalCacheSettings>,
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
            failover_registry: HashMap::new(),
            global_fail_open: None,
            global_cache: None,
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
fn lookup_with_wildcard<'a, V>(
    map: &'a HashMap<String, V>,
    domain: &str,
) -> Option<&'a V> {
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
    pub managed_overrides: Vec<RuleOverride>,
    pub ml_enabled: bool,
    pub ml_model_path: String,
    pub ml_threshold: f64,
    pub anomaly_threshold: u32,
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
    /// `None` keeps the proxy default (verification on).
    #[serde(default)]
    pub verify_cert: Option<bool>,
    #[serde(default)]
    pub is_default: bool,
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

// ─────────────────────────────────────────────────────────────
// Disk persistence metadata
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMetadata {
    config_hash: String,
    updated_at: DateTime<Utc>,
    agent_id: String,
    version: u32,
}

// ─────────────────────────────────────────────────────────────
// RuleCache — the main public interface
// ─────────────────────────────────────────────────────────────

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
            cache_dir: cache_dir.clone(),
            agent_id,
            quota_domains: Mutex::new(HashSet::new()),
            last_config_sync_at: AtomicI64::new(0),
            last_policy_sync_at: AtomicI64::new(0),
        });

        // Ensure cache directory exists
        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            warn!(error = %e, "Failed to create cache directory, running without persistence");
        } else {
            // Try to load existing cache from disk
            if let Err(e) = cache.load_from_disk() {
                debug!(error = %e, "No existing cache found on disk or failed to load");
            } else {
                info!("Loaded rule cache from disk");
            }
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

        // Swap in updated rules
        self.inner.rcu(|current| {
            let mut updated = (**current).clone();
            // Remove old domain index entries for this site. Removal keys
            // are normalised the same way as insertion keys below, so an
            // entry written as `EXAMPLE.com` is still findable for cleanup.
            if let Some(old_site) = updated.sites.get(&site_id) {
                updated
                    .domain_index
                    .remove(&normalize_host(&old_site.domain));
                for alt in &old_site.alternate_domains {
                    updated.domain_index.remove(&normalize_host(alt));
                }
            }
            // Insert new site
            updated
                .domain_index
                .insert(normalize_host(&domain), site_id.clone());
            for alt in &alternate_domains {
                updated
                    .domain_index
                    .insert(normalize_host(alt), site_id.clone());
            }
            updated
                .sites
                .insert(site_id.clone(), Arc::clone(&site_rules));
            // Every bundle carries the complete failover registry, so one
            // push refreshes it wholesale — including wholesale deletions
            // (an empty registry must replace a stale non-empty one).
            updated.failover_registry =
                failover_registry_from(&bundle.site_policies);
            if let Some(default_fail_open) = bundle.default_fail_open {
                updated.global_fail_open = Some(default_fail_open);
            }
            if let Some(global_cache) = &bundle.global_cache {
                updated.global_cache =
                    Some(Self::convert_global_cache(global_cache));
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

        self.inner.rcu(|current| {
            let mut updated = (**current).clone();
            updated.config_hash = config.config_hash.as_str().into();
            updated.updated_at = Utc::now();

            // The bundles embed the same registry in every site; one pass
            // over whichever bundle carries it is enough. Replacement is
            // unconditional so deleting the last policy also clears the
            // agent-side registry.
            for site in &config.sites {
                if let Some(ref bundle) = site.rules {
                    updated.failover_registry =
                        failover_registry_from(&bundle.site_policies);
                    if let Some(default_fail_open) = bundle.default_fail_open {
                        updated.global_fail_open = Some(default_fail_open);
                    }
                    if let Some(global_cache) = &bundle.global_cache {
                        updated.global_cache =
                            Some(Self::convert_global_cache(global_cache));
                    }
                    break;
                }
            }

            for site in &config.sites {
                if let Some(ref bundle) = site.rules {
                    let mut site_rules = Self::convert_bundle(bundle);
                    // Override domain from site-level field
                    if !site.domain.is_empty() {
                        // Remove old domain index
                        updated
                            .domain_index
                            .remove(&normalize_host(&site_rules.domain));
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

                    // Update domain index
                    updated.domain_index.insert(
                        normalize_host(&site_rules.domain),
                        site.id.clone(),
                    );
                    for alt in &site_rules.alternate_domains {
                        updated
                            .domain_index
                            .insert(normalize_host(alt), site.id.clone());
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
                    updated.domain_index.remove(&normalize_host(&old.domain));
                    for alt in &old.alternate_domains {
                        updated.domain_index.remove(&normalize_host(alt));
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
        rules.sites.get(site_id).cloned()
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
        let key = format!("{}:{}", site_id, ip);
        match self.blocked_ips.get(&key) {
            Some(entry) => {
                if entry.is_expired() {
                    drop(entry);
                    self.blocked_ips.remove(&key);
                    false
                } else {
                    true
                }
            },
            None => false,
        }
    }

    /// The reason an IP is dynamically blocked for a site, or `None`. The
    /// reason prefix (`"waf: "` / `"rate limit: "`) identifies which policy
    /// produced the block so callers can downgrade WAF-originated blocks
    /// without touching rate-limit or control-plane-issued ones.
    pub fn blocked_reason(&self, site_id: &str, ip: &str) -> Option<String> {
        let key = format!("{}:{}", site_id, ip);
        match self.blocked_ips.get(&key) {
            Some(entry) => {
                if entry.is_expired() {
                    drop(entry);
                    self.blocked_ips.remove(&key);
                    None
                } else {
                    Some(entry.reason.clone())
                }
            },
            None => None,
        }
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

        self.blocked_ips.insert(key.clone(), entry);
        info!(site_id = %site_id, ip = %ip, reason = %reason, "Blocked IP");

        // Persist blocked IPs
        if let Err(e) = self.persist_blocked_ips() {
            warn!(error = %e, "Failed to persist blocked IPs");
        }
    }

    /// Unblock an IP for a site.
    pub fn unblock_ip(&self, site_id: &str, ip: &str) {
        let key = format!("{}:{}", site_id, ip);
        if self.blocked_ips.remove(&key).is_some() {
            info!(site_id = %site_id, ip = %ip, "Unblocked IP");
            if let Err(e) = self.persist_blocked_ips() {
                warn!(error = %e, "Failed to persist blocked IPs");
            }
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
        }
        if removed > 0 {
            info!(
                site_id = %site_id,
                removed,
                "cleared WAF auto-blocks after leaving enforcing mode"
            );
            if let Err(e) = self.persist_blocked_ips() {
                warn!(error = %e, "Failed to persist blocked IPs");
            }
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
        if removed > 0 {
            debug!(
                site_id = %site_id,
                removed,
                "cleared blocks for removed site"
            );
            if let Err(e) = self.persist_blocked_ips() {
                warn!(error = %e, "Failed to persist blocked IPs");
            }
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
        }
        if !expired_keys.is_empty() {
            debug!(count = expired_keys.len(), "Cleaned up expired IP blocks");
            let _ = self.persist_blocked_ips();
        }
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

    /// Persist current rules to disk.
    pub fn persist_to_disk(&self) -> anyhow::Result<()> {
        if !self.cache_dir.exists() {
            return Ok(());
        }

        let rules = self.inner.load();
        let sites_path = self.cache_dir.join("sites.json");
        let metadata_path = self.cache_dir.join("metadata.json");

        // Write sites
        let sites_json = serde_json::to_string_pretty(&**rules)?;
        std::fs::write(&sites_path, sites_json)?;

        // Write metadata
        let metadata = CacheMetadata {
            config_hash: rules.config_hash.to_string(),
            updated_at: rules.updated_at,
            agent_id: self.agent_id.clone(),
            version: 1,
        };
        let meta_json = serde_json::to_string_pretty(&metadata)?;
        std::fs::write(&metadata_path, meta_json)?;

        // Write blocked IPs
        self.persist_blocked_ips()?;

        debug!("Persisted rule cache to disk");
        Ok(())
    }

    /// Load rules from disk.
    pub fn load_from_disk(&self) -> anyhow::Result<()> {
        let sites_path = self.cache_dir.join("sites.json");
        let blocked_path = self.cache_dir.join("blocked_ips.json");

        if !sites_path.exists() {
            anyhow::bail!("No cache file found at {:?}", sites_path);
        }

        let sites_json = std::fs::read_to_string(&sites_path)?;
        let cached: CachedRules = serde_json::from_str(&sites_json)?;

        info!(
            sites = cached.sites.len(),
            config_hash = %cached.config_hash,
            "Loaded rule cache from disk"
        );

        self.inner.store(Arc::new(cached));

        // Load blocked IPs
        if blocked_path.exists() {
            let blocked_json = std::fs::read_to_string(&blocked_path)?;
            let blocked: Vec<BlockedIpEntry> =
                serde_json::from_str(&blocked_json)?;
            let mut loaded = 0;
            for entry in blocked {
                if !entry.is_expired() {
                    let key = format!("{}:{}", entry.site_id, entry.ip);
                    self.blocked_ips.insert(key, entry);
                    loaded += 1;
                }
            }
            debug!(count = loaded, "Loaded blocked IPs from disk");
        }

        Ok(())
    }

    /// Persist blocked IPs to disk.
    fn persist_blocked_ips(&self) -> anyhow::Result<()> {
        if !self.cache_dir.exists() {
            return Ok(());
        }

        let blocked_path = self.cache_dir.join("blocked_ips.json");
        let entries: Vec<BlockedIpEntry> = self
            .blocked_ips
            .iter()
            .filter(|e| !e.value().is_expired())
            .map(|e| e.value().clone())
            .collect();

        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(&blocked_path, json)?;
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
            // Verification is opt-in: an unset flag means lenient (do not
            // verify the origin certificate), matching the control plane's
            // default. Explicit true keeps strict validation.
            verify_cert: Some(u.verify_cert.unwrap_or(false)),
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
                    }],
                    bot_protection: None,
                }),
            )]
            .into_iter()
            .collect(),
            domain_index: HashMap::new(),
            failover_registry: HashMap::from([(
                "example.com".to_string(),
                FailoverMode::Closed,
            )]),
            global_fail_open: Some(true),
            global_cache: None,
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
                observation_mode: false,
                proxy_trust: ProxyTrustConfig::default(),
                cache_settings: None,
            })
        };
        let store = |global_space_mb: Option<u32>, quota_mb: u32| {
            cache.inner.store(Arc::new(CachedRules {
                sites: [(DOMAIN.to_string(), site(quota_mb))]
                    .into_iter()
                    .collect(),
                domain_index: HashMap::new(),
                failover_registry: HashMap::new(),
                global_fail_open: None,
                global_cache: global_space_mb.map(|max_space_mb| {
                    GlobalCacheSettings {
                        max_space_mb: Some(max_space_mb),
                        ..Default::default()
                    }
                }),
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
}
