//! Site management: CRUD for sites plus their origin servers and TLS material.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use sea_orm::sea_query::{Expr, Func};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DbErr,
    EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::api::common::{
    ensure_acme_wildcard_supported, ensure_domains_available, load_site_read,
    load_site_write, map_domain_conflict, non_empty, normalise_domain,
    normalise_domain_list, parse_uuid, require_write, AppJson, Page,
    Pagination,
};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::api::validation::validate_pem_bundle;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{
    acme_challenge, bot_protection, cache_rules, challenge_settings, geo_rules,
    ip_access_rules, ip_groups, rate_limit_rules, rewrite_rules,
    route_match_type, rule, rule_groups, site, site_ai_bot_policies,
    site_ai_crawl_settings, site_certificates, site_routes, site_ssl,
    site_status, site_upstream_pools, site_upstreams, tls_version,
    trusted_header, waf_settings, ResponseReplaceConfig, ResponseReplaceRule,
};

/// Longest accepted route `rewrite_path`, in **bytes**, mirroring
/// `pingap_config::MAX_REWRITE_PATH_LEN` — the data plane drops anything longer,
/// so storing it would only lose the route's rewrite later, on the agent side.
///
/// The rule has one implementation (`pingap_config::validate_rewrite_path`,
/// re-exported by `pingap-location`) that this crate cannot call: the control
/// plane does not depend on the pingap crates, and pulling their graph (pingora
/// included) into it for one predicate is not worth it. So the checks below are
/// a mirror, and `route_rewrite_fields_are_validated` keeps them honest.
const MAX_ROUTE_REWRITE_PATH_LEN: usize = 2048;

/// Public representation of a site.
#[derive(Debug, Clone, Serialize)]
pub struct SiteResponse {
    pub id: Uuid,
    pub name: String,
    pub domain: String,
    /// Extra hostnames served by the same site configuration.
    pub alternate_domains: Vec<String>,
    pub status: String,
    pub plan: String,
    /// Disk budget, in MiB, the agents may use for this site's cache.
    pub cache_quota_mb: i32,
    /// Site-level single-file cache cap in MiB; `None` follows the global
    /// ceiling.
    pub cache_max_file_size_mb: Option<i32>,
    /// Per-content-type single-file caps in MiB, keyed by
    /// `html/css/js/image/font/media/other`; missing keys follow
    /// `cache_max_file_size_mb`.
    pub cache_type_limits_mb: Option<HashMap<String, i32>>,
    /// Security features key on the forwarded-header client IP.
    pub trust_proxy_headers: bool,
    /// Lower-case forwarded header the client IP is read from.
    pub trusted_header: String,
    /// Trust the last XFF entry (nearest proxy) instead of the first.
    pub trust_last_hop: bool,
    /// CIDR ranges of proxies allowed to influence the resolved client IP;
    /// an empty list trusts nothing.
    pub trusted_proxy_ranges: Vec<String>,
    /// IP groups whose ranges are merged into `trusted_proxy_ranges` when
    /// the agent configuration is built.
    pub trusted_proxy_group_ids: Vec<Uuid>,
    /// Site-wide default for verifying an HTTPS origin's certificate;
    /// `None` means every pool without its own pin follows the
    /// deployment-wide `origin_settings.verify_cert`.
    pub origin_verify_cert: Option<bool>,
    /// Per-site downstream read/write timeout, in seconds.
    pub downstream_timeout_secs: u32,
    /// Response body replacement policy; `None` when the site replaces
    /// nothing and no `sub_filter` plugin is generated for it.
    pub response_replace: Option<ResponseReplaceConfig>,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<site::Model> for SiteResponse {
    fn from(model: site::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            domain: model.domain,
            alternate_domains: model.alternate_domains,
            status: model.status,
            plan: model.plan,
            cache_quota_mb: model.cache_quota_mb,
            cache_max_file_size_mb: model.cache_max_file_size_mb,
            cache_type_limits_mb: model
                .cache_type_limits_mb
                .and_then(|value| serde_json::from_value(value).ok()),
            trust_proxy_headers: model.trust_proxy_headers,
            trusted_header: model.trusted_header,
            trust_last_hop: model.trust_last_hop,
            trusted_proxy_ranges: model.trusted_proxy_ranges,
            trusted_proxy_group_ids: model.trusted_proxy_group_ids,
            origin_verify_cert: model.origin_verify_cert,
            downstream_timeout_secs:
                crate::defaults::normalize_site_downstream_timeout_secs(
                    model.downstream_timeout_secs,
                ),
            response_replace: model
                .response_replace
                .as_ref()
                .and_then(ResponseReplaceConfig::from_json),
            user_id: model.user_id,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

/// A site together with everything the dashboard shows on its detail page.
#[derive(Debug, Serialize)]
pub struct SiteDetail {
    pub site: SiteResponse,
    pub upstreams: Vec<site_upstreams::Model>,
    pub ssl: Option<SslResponse>,
    pub rule_count: u64,
    pub rule_group_count: u64,
    pub rate_limit_count: u64,
    pub cache_rule_count: u64,
}

/// TLS material as shown in the dashboard — never includes the private key.
#[derive(Debug, Serialize)]
pub struct SslResponse {
    pub id: Uuid,
    pub site_id: Uuid,
    pub domain: String,
    pub issuer: Option<String>,
    pub has_certificate: bool,
    pub has_private_key: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub auto_renew: bool,
    pub acme_email: Option<String>,
    pub acme_challenge_type: Option<String>,
    pub acme_dns_provider: Option<String>,
    pub acme_dns_config: Option<serde_json::Value>,
    pub https_enabled: bool,
    pub min_tls_version: String,
    pub max_tls_version: Option<String>,
    pub self_signed: bool,
    pub certificate_id: Option<Uuid>,
    pub mtls_enabled: bool,
    pub has_mtls_client_ca: bool,
    pub mtls_organization: Option<String>,
    pub mtls_require_client_cert: bool,
    pub hsts_enabled: bool,
    pub hsts_max_age: i32,
    pub always_use_https: bool,
    /// Downstream protocol switches, same names and semantics as
    /// `SslSettingsResponse` (C2/L4-003): `PUT /sites/{id}/ssl` writes them,
    /// `GET` reads them back.
    pub http1_enabled: bool,
    pub http2_enabled: bool,
    pub created_at: DateTime<Utc>,
}

impl From<site_ssl::Model> for SslResponse {
    fn from(model: site_ssl::Model) -> Self {
        Self {
            id: model.id,
            site_id: model.site_id,
            domain: model.domain,
            issuer: model.issuer,
            has_certificate: model
                .cert_pem
                .as_ref()
                .is_some_and(|v| !v.is_empty()),
            has_private_key: model
                .key_pem
                .as_ref()
                .is_some_and(|v| !v.is_empty()),
            expires_at: model.expires_at,
            auto_renew: model.auto_renew,
            acme_email: model.acme_email,
            acme_challenge_type: model.acme_challenge_type,
            acme_dns_provider: model.acme_dns_provider,
            acme_dns_config: model.acme_dns_config,
            https_enabled: model.https_enabled,
            min_tls_version: model.min_tls_version,
            max_tls_version: model.max_tls_version,
            self_signed: model.self_signed,
            certificate_id: model.certificate_id,
            mtls_enabled: model.mtls_enabled,
            has_mtls_client_ca: model
                .mtls_client_ca
                .as_ref()
                .is_some_and(|v| !v.is_empty()),
            mtls_organization: model.mtls_organization,
            mtls_require_client_cert: model.mtls_require_client_cert,
            hsts_enabled: model.hsts_enabled,
            hsts_max_age: model.hsts_max_age,
            always_use_https: model.always_use_https,
            http1_enabled: model.http1_enabled,
            http2_enabled: model.http2_enabled,
            created_at: model.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
    pub search: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSiteRequest {
    pub name: String,
    pub domain: String,
    /// Extra hostnames (wildcards allowed) the site also answers on.
    #[serde(default)]
    pub alternate_domains: Option<Vec<String>>,
    /// Origin the site proxies to — a CDN/WAF hostname or the application
    /// itself. Required: a site without an origin cannot serve traffic.
    pub upstream_address: String,
    // `upstream_name` was removed with the node-name API change; unknown
    // fields are ignored, so existing clients keep working.
    #[serde(default)]
    pub upstream_tls: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default = "default_site_downstream_timeout_secs")]
    pub downstream_timeout_secs: u32,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateSiteRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    /// Replaces the whole list; an empty array clears it.
    #[serde(default)]
    pub alternate_domains: Option<Vec<String>>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    /// Security features key on the forwarded-header client IP.
    #[serde(default)]
    pub trust_proxy_headers: Option<bool>,
    /// Lower-case forwarded header the client IP is read from; an empty
    /// string resets it to `x-forwarded-for`.
    #[serde(default)]
    pub trusted_header: Option<String>,
    /// Trust the last XFF entry (nearest proxy) instead of the first.
    #[serde(default)]
    pub trust_last_hop: Option<bool>,
    /// CIDR ranges of proxies allowed to influence the resolved client IP;
    /// an empty list trusts nothing. Entries are validated as CIDR (a bare
    /// IP expands to a /32 or /128).
    #[serde(default)]
    pub trusted_proxy_ranges: Option<Vec<String>>,
    /// IP groups whose ranges merge into the effective trusted-proxy scope.
    /// Every id must reference an existing IP group.
    #[serde(default)]
    pub trusted_proxy_group_ids: Option<Vec<Uuid>>,
    /// Site-wide origin certificate check for this site's HTTPS pools, as
    /// the middle tier of the pool → site → global cascade. The key being
    /// present with `null` clears the site's opinion (pools follow the
    /// global default again); `true`/`false` pins it for every pool that
    /// does not pin its own value. A missing key leaves the stored value
    /// alone.
    #[serde(default, deserialize_with = "deserialize_present_nullable")]
    pub origin_verify_cert: Option<Option<bool>>,
    /// Per-site downstream read/write timeout, in seconds. Absent keeps the
    /// stored value; 0 and values above 3600 are rejected.
    #[serde(default)]
    pub downstream_timeout_secs: Option<u32>,
    /// Response body replacement policy. Absent leaves the stored policy
    /// alone, an explicit `null` removes it, an object replaces it wholesale.
    /// A policy with an empty `rules` list also removes it: that is what a
    /// console sends after deleting the last rule row.
    #[serde(default, deserialize_with = "deserialize_present_nullable")]
    pub response_replace: Option<Option<ResponseReplaceConfig>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUpstreamRequest {
    /// Removed from the API (2026-10-19): the node name is not part of
    /// forwarding, load balancing or health checking, and a future
    /// "node group" feature owns node identity. Unknown fields are ignored,
    /// so old clients keep working.
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: i32,
    #[serde(default)]
    pub tls: bool,
    /// Target pool; defaults to the site's default pool.
    #[serde(default)]
    pub pool_id: Option<Uuid>,
}

fn default_weight() -> i32 {
    1
}

fn default_site_downstream_timeout_secs() -> u32 {
    crate::defaults::DEFAULT_SITE_DOWNSTREAM_TIMEOUT_SECS as u32
}

fn validate_site_downstream_timeout_secs(value: u32) -> Result<i32, ApiError> {
    let value = i32::try_from(value).unwrap_or(i32::MAX);
    if !(crate::defaults::MIN_SITE_DOWNSTREAM_TIMEOUT_SECS
        ..=crate::defaults::MAX_SITE_DOWNSTREAM_TIMEOUT_SECS)
        .contains(&value)
    {
        return Err(ApiError::BadRequest(
            "downstream_timeout_secs must be between 1 and 3600".to_string(),
        ));
    }
    Ok(value)
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateUpstreamRequest {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub weight: Option<i32>,
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default)]
    pub health_status: Option<String>,
    #[serde(default)]
    pub pool_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePoolRequest {
    pub name: String,
    #[serde(default = "default_lb_algorithm")]
    pub lb_algorithm: String,
    /// Non-empty enables TLS to the origin; empty means plain HTTP.
    #[serde(default)]
    pub sni: Option<String>,
    /// Origin certificate check for this pool. Omitted — the recommended
    /// value — leaves the pool following the deployment-wide
    /// `origin_settings.verify_cert`; `true`/`false` pin it.
    #[serde(default)]
    pub verify_cert: Option<bool>,
    /// Enable an active HTTP health check for this pool's nodes. Off keeps
    /// the agent's data plane on its default bare TCP probe.
    #[serde(default)]
    pub health_check_enabled: Option<bool>,
    /// Probe path; must start with `/`. Default `/`.
    #[serde(default)]
    pub health_check_path: Option<String>,
    /// Seconds between probe rounds (5-3600; the data plane aligns to 10s
    /// grid steps). Default 10.
    #[serde(default)]
    pub health_check_interval_seconds: Option<i32>,
    /// Probe connect/read timeout in milliseconds (100-30000). Default 3000.
    #[serde(default)]
    pub health_check_timeout_ms: Option<i32>,
    /// Consecutive failed probes before a node is marked unhealthy (1-10).
    /// Default 2.
    #[serde(default)]
    pub health_check_unhealthy_threshold: Option<i32>,
    /// Consecutive successful probes before a node is marked healthy (1-10).
    /// Default 1.
    #[serde(default)]
    pub health_check_healthy_threshold: Option<i32>,
    /// Address family the agent may resolve this pool's origin names to:
    /// `auto` (default) prefers IPv4, `ipv4`/`ipv6` pin one family.
    #[serde(default)]
    pub address_family: Option<String>,
}

fn default_lb_algorithm() -> String {
    "round_robin".to_string()
}

/// The `address_family` values the API accepts; mirrors the data plane's
/// `pingap_upstream::AddressFamily`.
const ADDRESS_FAMILY_AUTO: &str = "auto";
const ADDRESS_FAMILY_IPV4: &str = "ipv4";
const ADDRESS_FAMILY_IPV6: &str = "ipv6";

/// Validates and normalizes a pool's `address_family`.
///
/// `None` (field absent) means "keep what is stored", so create and update
/// share this: the caller passes the value it is about to persist.
fn normalize_address_family(
    value: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_ascii_lowercase();
    if ![
        ADDRESS_FAMILY_AUTO,
        ADDRESS_FAMILY_IPV4,
        ADDRESS_FAMILY_IPV6,
    ]
    .contains(&value.as_str())
    {
        return Err(ApiError::BadRequest(format!(
            "address_family '{value}' is invalid; expected auto, ipv4 or ipv6"
        )));
    }
    Ok(Some(value))
}

/// Deserializes a present-but-nullable field into `Option<Option<T>>`.
///
/// serde only calls this when the key is present, so the outer `Option`
/// separates "absent" (`None`) from a JSON `null` (`Some(None)`) — the
/// difference between "leave the column alone" and "clear it so the
/// deployment-wide default applies". A plain `Option<bool>` collapses both
/// into `None`, which would make the global switch impossible to opt into
/// through an update.
fn deserialize_present_nullable<'de, D, T>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdatePoolRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub lb_algorithm: Option<String>,
    /// `Some("")` clears the SNI (disables origin TLS); `None` leaves it.
    #[serde(default)]
    pub sni: Option<String>,
    /// Tri-state, because "leave it alone" and "follow the deployment
    /// default" are different intentions:
    /// * absent — leave the stored value untouched;
    /// * `null` — clear it, i.e. follow `origin_settings.verify_cert`;
    /// * `true`/`false` — pin this pool.
    #[serde(default, deserialize_with = "deserialize_present_nullable")]
    pub verify_cert: Option<Option<bool>>,
    #[serde(default)]
    pub health_check_enabled: Option<bool>,
    /// `Some("")` resets the probe path to `/`.
    #[serde(default)]
    pub health_check_path: Option<String>,
    #[serde(default)]
    pub health_check_interval_seconds: Option<i32>,
    #[serde(default)]
    pub health_check_timeout_ms: Option<i32>,
    #[serde(default)]
    pub health_check_unhealthy_threshold: Option<i32>,
    #[serde(default)]
    pub health_check_healthy_threshold: Option<i32>,
    /// `None` leaves the stored family alone; an empty or unknown value is
    /// rejected rather than treated as "unset", because "no family" is not a
    /// state the data plane can act on.
    #[serde(default)]
    pub address_family: Option<String>,
}

/// A pool plus its origin nodes, as `list_pools` returns them.
///
/// The members are inlined under `upstreams` so the console can render a
/// pool's nodes without a second request per pool; `flatten` keeps the
/// response shape a superset of the bare pool row the other endpoints return.
#[derive(Debug, Serialize)]
pub(crate) struct PoolWithMembers {
    #[serde(flatten)]
    pool: site_upstream_pools::Model,
    upstreams: Vec<site_upstreams::Model>,
}

/// A pool's health check posture with defaults applied, ready for storage
/// and protocol translation. `enabled = false` keeps the other values (they
/// ride along so flipping the switch later needs no re-entry).
#[derive(Debug, Clone)]
pub(crate) struct PoolHealthCheck {
    pub enabled: bool,
    pub path: String,
    pub interval_seconds: i32,
    pub timeout_ms: i32,
    pub unhealthy_threshold: i32,
    pub healthy_threshold: i32,
}

impl PoolHealthCheck {
    pub(crate) fn default_values() -> Self {
        Self {
            enabled: false,
            path: "/".to_string(),
            interval_seconds: 10,
            timeout_ms: 3000,
            unhealthy_threshold: 2,
            healthy_threshold: 1,
        }
    }

    /// Overlays the optional request fields onto `self`.
    pub(crate) fn apply_update(&mut self, payload: &UpdatePoolRequest) {
        if let Some(enabled) = payload.health_check_enabled {
            self.enabled = enabled;
        }
        if let Some(path) = non_empty(&payload.health_check_path) {
            self.path = path;
        }
        if let Some(v) = payload.health_check_interval_seconds {
            self.interval_seconds = v;
        }
        if let Some(v) = payload.health_check_timeout_ms {
            self.timeout_ms = v;
        }
        if let Some(v) = payload.health_check_unhealthy_threshold {
            self.unhealthy_threshold = v;
        }
        if let Some(v) = payload.health_check_healthy_threshold {
            self.healthy_threshold = v;
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        let path = &self.path;
        if !path.starts_with('/')
            || path.contains([' ', '?', '#'])
            || path.len() > 255
        {
            return Err(ApiError::BadRequest(
                "health_check_path must start with '/', without spaces, '?' \
                 or '#', and be at most 255 characters"
                    .to_string(),
            ));
        }
        let in_range = |name: &str, v: i32, min: i32, max: i32| {
            (min..=max).contains(&v).then_some(()).ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "health_check {name} must be between {min} and {max}"
                ))
            })
        };
        in_range("interval_seconds", self.interval_seconds, 5, 3600)?;
        in_range("timeout_ms", self.timeout_ms, 100, 30_000)?;
        in_range("unhealthy_threshold", self.unhealthy_threshold, 1, 10)?;
        in_range("healthy_threshold", self.healthy_threshold, 1, 10)?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateRouteRequest {
    pub name: String,
    pub match_type: String,
    pub path: String,
    /// Manual location weight; `None` uses the auto weight.
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub pool_id: Uuid,
    /// Gate the route on an IP group's ranges; `None` matches every client.
    #[serde(default)]
    pub ip_group_id: Option<Uuid>,
    /// Strip the matched `path` prefix from the request forwarded upstream, so
    /// a route on `/api` reaches an origin serving `/users`. Only a prefix
    /// route may strip; `false` (the default) forwards the path as is.
    #[serde(default)]
    pub strip_prefix: bool,
    /// Replace the whole path with this fixed value; wins over `strip_prefix`.
    /// The query string is preserved.
    #[serde(default)]
    pub rewrite_path: Option<String>,
    /// `Host` header the origin receives for this route — the knob a
    /// reverse-proxy route needs when the origin serves virtual hosts.
    /// `None` forwards the client's Host.
    #[serde(default)]
    pub upstream_host: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateRouteRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub match_type: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    /// `Some(0)` clears the priority back to the auto weight.
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub pool_id: Option<Uuid>,
    /// An empty string clears the gate; the field must be present to change it.
    #[serde(default)]
    pub ip_group_id: Option<Option<Uuid>>,
    /// `Some(false)` turns stripping off; absent leaves it untouched.
    #[serde(default)]
    pub strip_prefix: Option<bool>,
    /// Tri-state like `verify_cert`: absent leaves the stored replacement
    /// alone, `null` (or a blank string) clears it, a value sets it.
    #[serde(default, deserialize_with = "deserialize_present_nullable")]
    pub rewrite_path: Option<Option<String>>,
    /// Same tri-state: absent keeps the stored `Host` override, `null` (or a
    /// blank string) goes back to forwarding the client's Host.
    #[serde(default, deserialize_with = "deserialize_present_nullable")]
    pub upstream_host: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertSslRequest {
    pub domain: String,
    #[serde(default)]
    pub cert_pem: Option<String>,
    #[serde(default)]
    pub key_pem: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default = "default_true")]
    pub auto_renew: bool,
    #[serde(default)]
    pub acme_email: Option<String>,
    #[serde(default)]
    pub acme_challenge_type: Option<String>,
    #[serde(default)]
    pub acme_dns_provider: Option<String>,
    #[serde(default)]
    pub acme_dns_config: Option<serde_json::Value>,
    #[serde(flatten)]
    pub tls: TlsPostureRequest,
}

/// The TLS switches a site is served with. Shared by the certificate upload and
/// the SSL settings endpoints, which both edit the same `site_ssl` row.
#[derive(Debug, Deserialize, Default)]
pub struct TlsPostureRequest {
    #[serde(default)]
    pub https_enabled: Option<bool>,
    #[serde(default)]
    pub min_tls_version: Option<String>,
    #[serde(default)]
    pub max_tls_version: Option<String>,
    #[serde(default)]
    pub self_signed: Option<bool>,
    #[serde(default)]
    pub certificate_id: Option<Uuid>,
    #[serde(default)]
    pub mtls_enabled: Option<bool>,
    #[serde(default)]
    pub mtls_client_ca: Option<String>,
    #[serde(default)]
    pub mtls_organization: Option<String>,
    #[serde(default)]
    pub mtls_require_client_cert: Option<bool>,
    #[serde(default)]
    pub hsts_enabled: Option<bool>,
    #[serde(default)]
    pub hsts_max_age: Option<i32>,
    #[serde(default)]
    pub always_use_https: Option<bool>,
    /// Downstream protocol switches. Both default to on: a client that omits
    /// them keeps (or gains) HTTP/2 rather than being pinned to HTTP/1.1.
    #[serde(default)]
    pub http1_enabled: Option<bool>,
    #[serde(default)]
    pub http2_enabled: Option<bool>,
}

/// Largest HSTS lifetime accepted, in seconds (two years).
pub(crate) const MAX_HSTS_AGE: i32 = 63_072_000;

/// The effective TLS posture of a site, as stored on `site_ssl`.
#[derive(Debug, Clone)]
pub(crate) struct TlsPosture {
    pub https_enabled: bool,
    pub min_tls_version: String,
    pub max_tls_version: Option<String>,
    pub self_signed: bool,
    pub certificate_id: Option<Uuid>,
    pub mtls_enabled: bool,
    pub mtls_client_ca: Option<String>,
    pub mtls_organization: Option<String>,
    pub mtls_require_client_cert: bool,
    pub hsts_enabled: bool,
    pub hsts_max_age: i32,
    pub always_use_https: bool,
    pub http1_enabled: bool,
    pub http2_enabled: bool,
}

impl TlsPosture {
    /// Posture of a site that has no `site_ssl` row yet: plain HTTP, and ready
    /// for a certificate to be attached.
    pub(crate) fn unset() -> Self {
        Self {
            https_enabled: false,
            min_tls_version: tls_version::TLS_12.to_string(),
            max_tls_version: None,
            self_signed: false,
            certificate_id: None,
            mtls_enabled: false,
            mtls_client_ca: None,
            mtls_organization: None,
            mtls_require_client_cert: false,
            hsts_enabled: false,
            hsts_max_age: 0,
            always_use_https: false,
            // A fresh site serves both protocols; HTTP/2 is the faster one.
            http1_enabled: true,
            http2_enabled: true,
        }
    }

    pub(crate) fn from_model(model: &site_ssl::Model) -> Self {
        Self {
            https_enabled: model.https_enabled,
            min_tls_version: model.min_tls_version.clone(),
            max_tls_version: model.max_tls_version.clone(),
            self_signed: model.self_signed,
            certificate_id: model.certificate_id,
            mtls_enabled: model.mtls_enabled,
            mtls_client_ca: model.mtls_client_ca.clone(),
            mtls_organization: model.mtls_organization.clone(),
            mtls_require_client_cert: model.mtls_require_client_cert,
            hsts_enabled: model.hsts_enabled,
            hsts_max_age: model.hsts_max_age,
            always_use_https: model.always_use_https,
            http1_enabled: model.http1_enabled,
            http2_enabled: model.http2_enabled,
        }
    }

    /// Overlays the request's switches, rejecting combinations an agent could
    /// not serve.
    fn merged(&self, req: &TlsPostureRequest) -> Result<Self, ApiError> {
        let mut next = self.clone();
        if let Some(value) = req.https_enabled {
            next.https_enabled = value;
        }
        if let Some(value) = req.self_signed {
            next.self_signed = value;
        }
        if let Some(value) = req.certificate_id {
            next.certificate_id = Some(value);
        }
        if let Some(value) = req.mtls_enabled {
            next.mtls_enabled = value;
        }
        if let Some(value) = req.mtls_require_client_cert {
            next.mtls_require_client_cert = value;
        }
        if let Some(raw) = non_empty(&req.mtls_organization) {
            next.mtls_organization = Some(raw);
        }
        if let Some(value) = req.hsts_enabled {
            next.hsts_enabled = value;
        }
        if let Some(value) = req.always_use_https {
            next.always_use_https = value;
        }
        if let Some(value) = req.http1_enabled {
            next.http1_enabled = value;
        }
        if let Some(value) = req.http2_enabled {
            next.http2_enabled = value;
        }
        if let Some(raw) = non_empty(&req.min_tls_version) {
            next.min_tls_version = normalise_tls_version(&raw)?;
        }
        if let Some(raw) = non_empty(&req.max_tls_version) {
            next.max_tls_version = Some(normalise_tls_version(&raw)?);
        }
        if let Some(raw) = non_empty(&req.mtls_client_ca) {
            // The bundle is the only trust anchor an agent has: a string that
            // is not a PEM chain verifies nothing, yet `mtls_enabled` would
            // read as on. Validate it here rather than at handshake
            // (2026-10-19 audit, D08).
            validate_pem_bundle(&raw, "mtls_client_ca")?;
            next.mtls_client_ca = Some(raw);
        }
        if let Some(age) = req.hsts_max_age {
            if !(0..=MAX_HSTS_AGE).contains(&age) {
                return Err(ApiError::BadRequest(format!(
                    "hsts_max_age must be between 0 and {MAX_HSTS_AGE}"
                )));
            }
            next.hsts_max_age = age;
        }

        let Some(min) = tls_version::rank(&next.min_tls_version) else {
            return Err(ApiError::BadRequest(format!(
                "unsupported TLS version (supported: {})",
                tls_version::ALL.join(", ")
            )));
        };
        // An absent upper bound is the "no ceiling" default a fresh site_ssl
        // row carries: every version up to the newest one is acceptable.
        let max = match next.max_tls_version.as_deref() {
            None => tls_version::ALL.len() - 1,
            Some(raw) => tls_version::rank(raw).ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "unsupported TLS version (supported: {})",
                    tls_version::ALL.join(", ")
                ))
            })?,
        };
        if min > max {
            return Err(ApiError::BadRequest(format!(
                "min_tls_version {} is above max_tls_version {}",
                next.min_tls_version,
                next.max_tls_version.unwrap_or_default()
            )));
        }
        if next.mtls_enabled && next.mtls_client_ca.is_none() {
            return Err(ApiError::BadRequest(
                "mtls_enabled requires the client CA bundle".to_string(),
            ));
        }
        if !next.mtls_enabled {
            // Switching mTLS off must not leave checks armed behind it.
            next.mtls_require_client_cert = false;
            next.mtls_organization = None;
        }
        if next.self_signed {
            next.certificate_id = None;
            next.https_enabled = true;
        }
        // A site that speaks neither protocol is unreachable; reject it here
        // rather than pushing a listener an agent cannot build.
        if !next.http1_enabled && !next.http2_enabled {
            return Err(ApiError::BadRequest(
                "at least one of HTTP/1.1 and HTTP/2 must stay enabled"
                    .to_string(),
            ));
        }

        Ok(next)
    }

    pub(crate) fn apply_to(&self, active: &mut site_ssl::ActiveModel) {
        active.https_enabled = Set(self.https_enabled);
        active.min_tls_version = Set(self.min_tls_version.clone());
        active.max_tls_version = Set(self.max_tls_version.clone());
        active.self_signed = Set(self.self_signed);
        active.certificate_id = Set(self.certificate_id);
        active.mtls_enabled = Set(self.mtls_enabled);
        active.mtls_client_ca = Set(self.mtls_client_ca.clone());
        active.mtls_organization = Set(self.mtls_organization.clone());
        active.mtls_require_client_cert = Set(self.mtls_require_client_cert);
        active.hsts_enabled = Set(self.hsts_enabled);
        active.hsts_max_age = Set(self.hsts_max_age);
        active.always_use_https = Set(self.always_use_https);
        active.http1_enabled = Set(self.http1_enabled);
        active.http2_enabled = Set(self.http2_enabled);
    }
}

/// Applies a TLS posture request to the site's `site_ssl` row, creating the row
/// when the site has none. Returns the stored posture.
///
/// Takes the connection explicitly so callers can run it inside a transaction
/// (a certificate created with `activate` must not survive a failed posture).
pub(crate) async fn save_tls_posture<C: ConnectionTrait>(
    db: &C,
    site: &site::Model,
    req: &TlsPostureRequest,
) -> Result<TlsPosture, ApiError> {
    let existing = site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(site.id))
        .one(db)
        .await?;

    if let Some(cert_id) = req.certificate_id {
        let owned = site_certificates::Entity::find_by_id(cert_id)
            .filter(site_certificates::Column::SiteId.eq(site.id))
            .one(db)
            .await?
            .is_some();
        if !owned {
            return Err(ApiError::BadRequest(format!(
                "certificate {cert_id} does not belong to this site"
            )));
        }
    }

    let current = match &existing {
        Some(row) => TlsPosture::from_model(row),
        None => TlsPosture::unset(),
    };
    let next = current.merged(req)?;

    match existing {
        Some(row) => {
            let mut active: site_ssl::ActiveModel = row.into();
            next.apply_to(&mut active);
            active.update(db).await?;
        },
        None => {
            let mut active = site_ssl::ActiveModel {
                id: Set(Uuid::new_v4()),
                site_id: Set(site.id),
                cert_pem: Set(None),
                key_pem: Set(None),
                issuer: Set(None),
                domain: Set(site.domain.clone()),
                expires_at: Set(None),
                auto_renew: Set(true),
                acme_email: Set(None),
                acme_challenge_type: Set(None),
                acme_dns_provider: Set(None),
                acme_dns_config: Set(None),
                https_enabled: Set(false),
                min_tls_version: Set(tls_version::TLS_12.to_string()),
                max_tls_version: Set(None),
                self_signed: Set(false),
                certificate_id: Set(None),
                mtls_enabled: Set(false),
                mtls_client_ca: Set(None),
                mtls_organization: Set(None),
                mtls_require_client_cert: Set(false),
                hsts_enabled: Set(false),
                hsts_max_age: Set(0),
                always_use_https: Set(false),
                http1_enabled: Set(true),
                http2_enabled: Set(true),
                created_at: Set(Utc::now()),
            };
            next.apply_to(&mut active);
            active.insert(db).await?;
        },
    }

    Ok(next)
}

/// Reads the site's TLS posture, falling back to the defaults for a site that
/// has no `site_ssl` row yet.
pub(crate) async fn load_tls_posture(
    state: &AppState,
    site_id: Uuid,
) -> Result<TlsPosture, ApiError> {
    let row = site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?;
    Ok(match row {
        Some(row) => TlsPosture::from_model(&row),
        None => TlsPosture::unset(),
    })
}

fn normalise_tls_version(value: &str) -> Result<String, ApiError> {
    tls_version::normalise(value).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "unsupported TLS version '{value}' (supported: {})",
            tls_version::ALL.join(", ")
        ))
    })
}

fn default_true() -> bool {
    true
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites", get(list).post(create))
        .route("/sites/{site_id}", get(show).put(update).delete(remove))
        .route(
            "/sites/{site_id}/upstreams",
            get(list_upstreams).post(create_upstream),
        )
        .route(
            "/sites/{site_id}/upstreams/{upstream_id}",
            put(update_upstream).delete(delete_upstream),
        )
        .route(
            "/sites/{site_id}/upstream-pools",
            get(list_pools).post(create_pool),
        )
        .route(
            "/sites/{site_id}/upstream-pools/{pool_id}",
            put(update_pool).delete(delete_pool),
        )
        .route(
            "/sites/{site_id}/routes",
            get(list_routes).post(create_route),
        )
        .route(
            "/sites/{site_id}/routes/{route_id}",
            put(update_route).delete(delete_route),
        )
        .route(
            "/sites/{site_id}/ssl",
            get(show_ssl).put(upsert_ssl).delete(delete_ssl),
        )
        .route("/sites/{site_id}/clone", post(clone_site))
}

/// `GET /api/v1/sites`
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<SiteResponse>>, ApiError> {
    let pagination = query.pagination.normalise();

    let mut condition = Condition::all();
    if !current.is_admin() {
        condition = condition.add(site::Column::UserId.eq(current.id));
    }
    if let Some(status) = non_empty(&query.status) {
        if !site_status::is_valid(&status) {
            return Err(ApiError::BadRequest(format!(
                "unknown site status '{status}'"
            )));
        }
        condition = condition.add(site::Column::Status.eq(status));
    }
    if let Some(search) = non_empty(&query.search) {
        // `%` and `_` are wildcards in LIKE; escaping them keeps an operator's
        // literal search from turning into a full-table scan.
        let pattern = format!(
            "%{}%",
            crate::api::logs::escape_like(&search.to_lowercase())
        );
        condition = condition.add(
            Condition::any()
                .add(site::Column::Domain.like(&pattern))
                .add(site::Column::Name.like(&pattern)),
        );
    }

    let paginator = site::Entity::find()
        .filter(condition)
        .order_by_desc(site::Column::CreatedAt)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;

    Ok(Json(Page::new(
        rows.into_iter().map(SiteResponse::from).collect(),
        total,
        pagination,
    )))
}

/// `POST /api/v1/sites`
async fn create(
    State(state): State<AppState>,
    current: AuthUser,
    AppJson(payload): AppJson<CreateSiteRequest>,
) -> Result<Response, ApiError> {
    require_write(&current)?;

    let name = payload.name.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::BadRequest(
            "name must be 1-100 characters".to_string(),
        ));
    }
    let domain = normalise_domain(&payload.domain)?;
    let alternate_domains = normalise_domain_list(
        &domain,
        &payload.alternate_domains.unwrap_or_default(),
    )?;
    let mut all_domains = vec![domain.clone()];
    all_domains.extend(alternate_domains.iter().cloned());
    ensure_domains_available(&state.db, &all_domains, None).await?;

    let upstream_address = normalize_origin_address(&payload.upstream_address)?;
    validate_upstream(&upstream_address, default_weight())?;

    // New sites are live immediately; the dashboard toggles them between
    // active and paused afterwards.
    let status = payload
        .status
        .unwrap_or_else(|| site_status::ACTIVE.to_string());
    if !site_status::is_valid(&status) {
        return Err(ApiError::BadRequest(format!(
            "unknown site status '{status}'"
        )));
    }
    let plan = payload.plan.unwrap_or_else(|| "free".to_string());
    if plan.len() > 20 {
        return Err(ApiError::BadRequest(
            "plan must be at most 20 characters".to_string(),
        ));
    }
    let downstream_timeout_secs =
        validate_site_downstream_timeout_secs(payload.downstream_timeout_secs)?;

    let timestamp = Utc::now();
    let id = Uuid::new_v4();
    let model = site::ActiveModel {
        id: Set(id),
        user_id: Set(current.id),
        name: Set(name),
        domain: Set(domain.clone()),
        alternate_domains: Set(alternate_domains),
        status: Set(status),
        plan: Set(plan),
        cache_quota_mb: Set(crate::defaults::DEFAULT_CACHE_QUOTA_MB),
        cache_max_file_size_mb: Set(None),
        cache_type_limits_mb: Set(None),
        cache_type_policy: Set(None),
        trust_proxy_headers: Set(false),
        trusted_header: Set(crate::models::trusted_header::DEFAULT.to_string()),
        trust_last_hop: Set(true),
        failover_policy: Set("inherit".to_string()),
        trusted_proxy_ranges: Set(Vec::new()),
        trusted_proxy_group_ids: Set(Vec::new()),
        // New sites start with no opinion: pools follow the global default.
        origin_verify_cert: Set(None),
        downstream_timeout_secs: Set(downstream_timeout_secs),
        // Nothing is replaced until the operator configures a policy.
        response_replace: Set(None),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(&state.db)
    // The pre-check above is not atomic: a racing create can slip through it.
    // The unique index and the conflicts trigger on `sites` are the backstop.
    .await
    .map_err(map_domain_conflict)?;

    // Every site starts with a default origin pool; the first origin node
    // goes into it.
    let defaults = PoolHealthCheck::default_values();
    let pool = site_upstream_pools::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        name: Set("default".to_string()),
        lb_algorithm: Set(default_lb_algorithm()),
        sni: Set(payload
            .upstream_tls
            .filter(|tls| *tls)
            .map(|_| origin_host(&upstream_address).to_string())),
        // No opinion: the pool follows the deployment-wide origin
        // certificate check (`origin_settings.verify_cert`) until an
        // operator pins a value on it.
        verify_cert: Set(None),
        health_check_enabled: Set(defaults.enabled),
        health_check_path: Set(defaults.path.clone()),
        health_check_interval_seconds: Set(defaults.interval_seconds),
        health_check_timeout_ms: Set(defaults.timeout_ms),
        health_check_unhealthy_threshold: Set(defaults.unhealthy_threshold),
        health_check_healthy_threshold: Set(defaults.healthy_threshold),
        // The same default a pool created through the API gets: IPv4 first,
        // which is what makes a domain origin reachable on a host without an
        // IPv6 route.
        address_family: Set(ADDRESS_FAMILY_AUTO.to_string()),
        is_default: Set(true),
        created_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    site_upstreams::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        pool_id: Set(pool.id),
        // Kept for the upcoming node-group feature; mirrors the address.
        name: Set(upstream_name_placeholder(&upstream_address)),
        address: Set(upstream_address.clone()),
        weight: Set(default_weight()),
        tls: Set(payload.upstream_tls.unwrap_or(false)),
        health_status: Set("unknown".to_string()),
        created_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    // Built-in WAF (monitor mode) and cache rules ship with every new site.
    if let Err(err) = crate::defaults::seed_site_defaults(&state.db, id).await {
        tracing::error!(%id, error = %err, "failed to seed built-in rules");
    }

    // Every new site gets an SSL row with https enabled: without it the data
    // plane's `ssl.enabled` gate stays closed and a later ACME request would
    // sit pending forever - the user would have to know to flip a hidden
    // switch before certificate issuance can even start.
    site_ssl::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        cert_pem: Set(None),
        key_pem: Set(None),
        issuer: Set(None),
        domain: Set(domain.clone()),
        expires_at: Set(None),
        auto_renew: Set(true),
        acme_email: Set(None),
        acme_challenge_type: Set(None),
        acme_dns_provider: Set(None),
        acme_dns_config: Set(None),
        https_enabled: Set(true),
        min_tls_version: Set(tls_version::TLS_12.to_string()),
        max_tls_version: Set(None),
        self_signed: Set(false),
        certificate_id: Set(None),
        mtls_enabled: Set(false),
        mtls_client_ca: Set(None),
        mtls_organization: Set(None),
        mtls_require_client_cert: Set(false),
        hsts_enabled: Set(false),
        hsts_max_age: Set(0),
        always_use_https: Set(false),
        // New sites serve both protocols; HTTP/2 is what makes them faster.
        http1_enabled: Set(true),
        http2_enabled: Set(true),
        created_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(%id, %domain, upstream = %upstream_address, owner = %current.id, "site created");
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok((StatusCode::CREATED, Json(SiteResponse::from(model))).into_response())
}

/// `POST /api/v1/sites/{site_id}/clone`
///
/// Copies a site's configuration onto a new site id. The caller must supply
/// the new primary domain: every hostname has to stay unique, and reusing the
/// source's would collide with `uq_sites_domain` and the conflict trigger.
#[derive(Debug, Deserialize)]
pub struct CloneSiteRequest {
    pub domain: String,
    #[serde(default)]
    pub alternate_domains: Option<Vec<String>>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Copies every row of a site-scoped table, re-keying `id` and `site_id`.
///
/// Tables whose rows reference each other by another id (`site_upstreams` /
/// `site_routes` → `site_upstream_pools`) are copied by hand instead.
macro_rules! clone_site_rows {
    ($txn:expr, $entity:ident, $src:expr, $dst:expr) => {{
        let rows = $entity::Entity::find()
            .filter($entity::Column::SiteId.eq($src))
            .all($txn)
            .await?;
        for row in rows {
            let mut active: $entity::ActiveModel = row.into();
            active.id = Set(Uuid::new_v4());
            active.site_id = Set($dst);
            active.insert($txn).await?;
        }
    }};
}

/// Copies the source site's WAF rule groups and custom rules onto the clone
/// inside the caller's transaction (C4/L2-001). Groups are inserted first so
/// each rule's `group_id` can be remapped to the clone's own group rows,
/// keeping the same grouping semantics. Returns (groups, rules) copied.
async fn clone_site_rules<C>(
    txn: &C,
    source_id: Uuid,
    new_id: Uuid,
    timestamp: DateTime<Utc>,
) -> Result<(usize, usize), DbErr>
where
    C: ConnectionTrait,
{
    let mut group_ids: HashMap<Uuid, Uuid> = HashMap::new();
    let groups = rule_groups::Entity::find()
        .filter(rule_groups::Column::SiteId.eq(source_id))
        .all(txn)
        .await?;
    for row in groups {
        let old_id = row.id;
        let node = clone_rule_group_row(row, new_id, timestamp);
        let inserted = node.insert(txn).await?;
        group_ids.insert(old_id, inserted.id);
    }
    let source_rules = rule::Entity::find()
        .filter(rule::Column::SiteId.eq(source_id))
        .all(txn)
        .await?;
    let rule_count = source_rules.len();
    for row in source_rules {
        clone_rule_row(row, new_id, &group_ids, timestamp)
            .insert(txn)
            .await?;
    }
    Ok((group_ids.len(), rule_count))
}

/// Builds the clone's `rule_groups` row from the source row: new id, new site,
/// fresh timestamps, everything else identical.
fn clone_rule_group_row(
    row: rule_groups::Model,
    new_id: Uuid,
    timestamp: DateTime<Utc>,
) -> rule_groups::ActiveModel {
    let mut node: rule_groups::ActiveModel = row.into();
    node.id = Set(Uuid::new_v4());
    node.site_id = Set(new_id);
    node.created_at = Set(timestamp);
    node.updated_at = Set(timestamp);
    node
}

/// Builds the clone's `rules` row from the source row. `group_ids` maps the
/// source site's group ids to the clone's; a group the map does not know is
/// carried over as-is, never dropped to `None` (losing the group would change
/// the rule's evaluation semantics silently).
fn clone_rule_row(
    row: rule::Model,
    new_id: Uuid,
    group_ids: &HashMap<Uuid, Uuid>,
    timestamp: DateTime<Utc>,
) -> rule::ActiveModel {
    let old_group = row.group_id;
    let mut node: rule::ActiveModel = row.into();
    node.id = Set(Uuid::new_v4());
    node.site_id = Set(new_id);
    // A group the map does not know belongs to another site (or was deleted
    // between the two reads). Carrying its id over would attach the clone's
    // rule to a foreign group, and deleting that group would then cascade into
    // the clone — so the reference is dropped and logged instead.
    node.group_id = Set(old_group.and_then(|g| match group_ids.get(&g) {
        Some(new) => Some(*new),
        None => {
            tracing::warn!(
                group_id = %g,
                "clone: rule references a group outside the source site; dropping the reference"
            );
            None
        },
    }));
    node.created_at = Set(timestamp);
    node.updated_at = Set(timestamp);
    node
}

async fn clone_site(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CloneSiteRequest>,
) -> Result<Response, ApiError> {
    require_write(&current)?;
    let source_id = parse_uuid(&site_id, "site id")?;
    let source = load_site_write(&state.db, source_id, &current).await?;

    let domain = normalise_domain(&payload.domain)?;
    let alternate_domains = normalise_domain_list(
        &domain,
        &payload.alternate_domains.unwrap_or_default(),
    )?;
    let mut all_domains = vec![domain.clone()];
    all_domains.extend(alternate_domains.iter().cloned());
    ensure_domains_available(&state.db, &all_domains, None).await?;

    let user_name = payload
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{} copy", source.name));
    if user_name.len() > 100 {
        return Err(ApiError::BadRequest(
            "name must be 1-100 characters".to_string(),
        ));
    }

    let new_id = Uuid::new_v4();
    let timestamp = Utc::now();
    let txn = state.db.begin().await?;

    let mut active: site::ActiveModel = source.clone().into();
    active.id = Set(new_id);
    active.user_id = Set(current.id);
    active.name = Set(user_name);
    active.domain = Set(domain.clone());
    active.alternate_domains = Set(alternate_domains);
    // Paused: a clone that starts serving immediately would silently double
    // the traffic the source site receives.
    active.status = Set(site_status::PAUSED.to_string());
    // Forwarded-header trust is a property of where the site sits, not of its
    // rules: carrying it over would let the clone read an X-Forwarded-For the
    // source's proxy path supplies but the clone's does not, which spoofs the
    // client IP that access rules, rate limits and audit logs key on.
    active.trust_proxy_headers = Set(false);
    active.trusted_header =
        Set(crate::models::trusted_header::DEFAULT.to_string());
    active.trust_last_hop = Set(true);
    active.trusted_proxy_ranges = Set(Vec::new());
    active.trusted_proxy_group_ids = Set(Vec::new());
    active.created_at = Set(timestamp);
    let model = active.insert(&txn).await.map_err(map_domain_conflict)?;

    // Upstream pools first: nodes and routes reference them by id, so the
    // clone needs its own pool ids and a mapping from the source's.
    let mut pool_ids: HashMap<Uuid, Uuid> = HashMap::new();
    let pools = site_upstream_pools::Entity::find()
        .filter(site_upstream_pools::Column::SiteId.eq(source_id))
        .all(&txn)
        .await?;
    for row in pools {
        let old_id = row.id;
        let mut node: site_upstream_pools::ActiveModel = row.into();
        node.id = Set(Uuid::new_v4());
        node.site_id = Set(new_id);
        node.created_at = Set(timestamp);
        let inserted = node.insert(&txn).await?;
        pool_ids.insert(old_id, inserted.id);
    }

    let upstreams = site_upstreams::Entity::find()
        .filter(site_upstreams::Column::SiteId.eq(source_id))
        .all(&txn)
        .await?;
    for row in upstreams {
        let old_pool = row.pool_id;
        let mut node: site_upstreams::ActiveModel = row.into();
        node.id = Set(Uuid::new_v4());
        node.site_id = Set(new_id);
        node.pool_id =
            Set(pool_ids.get(&old_pool).copied().unwrap_or(old_pool));
        node.created_at = Set(timestamp);
        node.insert(&txn).await?;
    }

    let routes = site_routes::Entity::find()
        .filter(site_routes::Column::SiteId.eq(source_id))
        .all(&txn)
        .await?;
    for row in routes {
        let old_pool = row.pool_id;
        let mut node: site_routes::ActiveModel = row.into();
        node.id = Set(Uuid::new_v4());
        node.site_id = Set(new_id);
        node.pool_id =
            Set(pool_ids.get(&old_pool).copied().unwrap_or(old_pool));
        node.created_at = Set(timestamp);
        node.insert(&txn).await?;
    }

    // TLS material travels with the site: the clone serves the same
    // certificate and protocol switches until an operator changes them.
    if let Some(row) = site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(source_id))
        .one(&txn)
        .await?
    {
        let mut node: site_ssl::ActiveModel = row.into();
        node.id = Set(Uuid::new_v4());
        node.site_id = Set(new_id);
        node.domain = Set(domain.clone());
        node.created_at = Set(timestamp);
        node.insert(&txn).await?;
    }

    clone_site_rows!(&txn, waf_settings, source_id, new_id);
    clone_site_rows!(&txn, challenge_settings, source_id, new_id);
    clone_site_rows!(&txn, geo_rules, source_id, new_id);
    clone_site_rows!(&txn, bot_protection, source_id, new_id);
    // `site_oidc` is deliberately not cloned (and needs this even more than
    // basic auth):
    // 1. `redirect_url` — or the callback derived from the Host header — is
    //    bound to the source hostname. Copied to the new site, the IdP's
    //    registered callback still points at the source domain, so the
    //    provider redirects logins back to the source, not the clone.
    // 2. Two sites sharing the same `cookie_secret` + `cookie_name` across
    //    sibling subdomains covered by a wildcard `Domain` would share
    //    sessions: a login on one site authenticates the other (session
    //    cross-contamination).
    // 3. One client registered against two callback hosts is rejected outright
    //    by most identity providers.
    // The operator registers a fresh client per site instead.
    // `site_basic_auth` is deliberately not cloned: the row stores credentials
    // (masked in the API, plaintext at rest) and reusing them on a new host
    // would turn "a and b share a password" into a way to reach the clone with
    // a credential that has already circulated. The operator re-enters it.
    clone_site_rows!(&txn, rewrite_rules, source_id, new_id);
    clone_site_rows!(&txn, ip_access_rules, source_id, new_id);
    clone_site_rows!(&txn, cache_rules, source_id, new_id);
    clone_site_rows!(&txn, rate_limit_rules, source_id, new_id);
    clone_site_rows!(&txn, site_ai_crawl_settings, source_id, new_id);
    clone_site_rows!(&txn, site_ai_bot_policies, source_id, new_id);

    // WAF custom rules travel with the clone (C4/L2-001): without them the
    // clone runs with a weaker policy than the source and nothing in the API
    // surfaces the difference. Groups are copied first so each rule's
    // `group_id` can be remapped to the clone's own group rows, keeping the
    // same grouping semantics.
    clone_site_rules(&txn, source_id, new_id, timestamp).await?;

    txn.commit().await?;

    tracing::info!(
        site_id = %new_id,
        source = %source_id,
        %domain,
        owner = %current.id,
        "site cloned"
    );
    touch_site(&state, new_id).await?;
    notify_config_changed(&state, new_id, Some(&current.email)).await;

    Ok((StatusCode::CREATED, Json(SiteResponse::from(model))).into_response())
}

/// `GET /api/v1/sites/{site_id}`
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<SiteDetail>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let model = load_site_read(&state.db, id, &current).await?;

    let upstreams = site_upstreams::Entity::find()
        .filter(site_upstreams::Column::SiteId.eq(id))
        .order_by_desc(site_upstreams::Column::Weight)
        .all(&state.db)
        .await?;
    let ssl = site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .map(SslResponse::from);

    let rule_count = rule::Entity::find()
        .filter(rule::Column::SiteId.eq(id))
        .count(&state.db)
        .await?;
    let rule_group_count = rule_groups::Entity::find()
        .filter(rule_groups::Column::SiteId.eq(id))
        .count(&state.db)
        .await?;
    let rate_limit_count = rate_limit_rules::Entity::find()
        .filter(rate_limit_rules::Column::SiteId.eq(id))
        .count(&state.db)
        .await?;
    let cache_rule_count = cache_rules::Entity::find()
        .filter(cache_rules::Column::SiteId.eq(id))
        .count(&state.db)
        .await?;

    Ok(Json(SiteDetail {
        site: model.into(),
        upstreams,
        ssl,
        rule_count,
        rule_group_count,
        rate_limit_count,
        cache_rule_count,
    }))
}

/// `PUT /api/v1/sites/{site_id}`
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    AppJson(payload): AppJson<UpdateSiteRequest>,
) -> Result<Json<SiteResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let model = load_site_write(&state.db, id, &current).await?;
    let previous_domain = model.domain.clone();
    let previous_alternates = model.alternate_domains.clone();

    let mut active: site::ActiveModel = model.into();
    if let Some(name) = non_empty(&payload.name) {
        if name.len() > 100 {
            return Err(ApiError::BadRequest(
                "name must be at most 100 characters".to_string(),
            ));
        }
        active.name = Set(name);
    }
    let requested_domain = match non_empty(&payload.domain) {
        Some(domain) => Some(normalise_domain(&domain)?),
        None => None,
    };
    if requested_domain.is_some() || payload.alternate_domains.is_some() {
        let primary = requested_domain
            .clone()
            .unwrap_or_else(|| previous_domain.clone());
        let alternates_source = payload
            .alternate_domains
            .clone()
            .unwrap_or_else(|| previous_alternates.clone());
        let alternates = normalise_domain_list(&primary, &alternates_source)?;

        let mut all_domains = vec![primary.clone()];
        all_domains.extend(alternates.iter().cloned());
        ensure_domains_available(&state.db, &all_domains, Some(id)).await?;

        active.domain = Set(primary);
        active.alternate_domains = Set(alternates);
    }
    if let Some(status) = non_empty(&payload.status) {
        if !site_status::is_valid(&status) {
            return Err(ApiError::BadRequest(format!(
                "unknown site status '{status}'"
            )));
        }
        active.status = Set(status);
    }
    if let Some(plan) = non_empty(&payload.plan) {
        if plan.len() > 20 {
            return Err(ApiError::BadRequest(
                "plan must be at most 20 characters".to_string(),
            ));
        }
        active.plan = Set(plan);
    }
    if let Some(value) = payload.trust_proxy_headers {
        active.trust_proxy_headers = Set(value);
    }
    if let Some(header) = payload.trusted_header {
        let header = header.trim().to_ascii_lowercase();
        if !header.is_empty() && !trusted_header::is_valid(&header) {
            return Err(ApiError::BadRequest(format!(
                "unknown trusted header '{header}'"
            )));
        }
        active.trusted_header = Set(if header.is_empty() {
            trusted_header::DEFAULT.to_string()
        } else {
            header
        });
    }
    if let Some(value) = payload.trust_last_hop {
        active.trust_last_hop = Set(value);
    }
    if let Some(ranges) = &payload.trusted_proxy_ranges {
        let mut normalized = Vec::with_capacity(ranges.len());
        for range in ranges {
            match parse_proxy_range(range) {
                Some(parsed) => {
                    if !normalized.contains(&parsed) {
                        normalized.push(parsed);
                    }
                },
                None => {
                    return Err(ApiError::BadRequest(format!(
                        "'{range}' is not a valid IP or CIDR range"
                    )));
                },
            }
        }
        active.trusted_proxy_ranges = Set(normalized);
    }
    if let Some(group_ids) = &payload.trusted_proxy_group_ids {
        let mut normalized: Vec<Uuid> = Vec::with_capacity(group_ids.len());
        for group_id in group_ids {
            let exists = ip_groups::Entity::find_by_id(*group_id)
                .one(&state.db)
                .await?
                .is_some();
            if !exists {
                return Err(ApiError::BadRequest(format!(
                    "IP group {group_id} does not exist"
                )));
            }
            if !normalized.contains(group_id) {
                normalized.push(*group_id);
            }
        }
        active.trusted_proxy_group_ids = Set(normalized);
    }
    // Present-and-null clears the site's opinion (pools fall back to the
    // global default); present-and-bool pins it. A missing key is already
    // `None` and must not touch the stored value, hence the outer check.
    if let Some(verify_cert) = payload.origin_verify_cert {
        active.origin_verify_cert = Set(verify_cert);
    }
    if let Some(timeout) = payload.downstream_timeout_secs {
        active.downstream_timeout_secs =
            Set(validate_site_downstream_timeout_secs(timeout)?);
    }
    // Same tri-state: absent leaves the stored policy alone, `null` removes
    // it. The policy is validated before it is stored because the data plane
    // compiles it into the site's `sub_filter` plugin — a pattern that does not
    // parse costs the site its whole agent configuration, not just the
    // replacement.
    if let Some(policy) = payload.response_replace {
        active.response_replace =
            Set(normalise_response_replace(policy)?.map(|policy| {
                serde_json::to_value(policy).unwrap_or(serde_json::Value::Null)
            }));
    }
    active.updated_at = Set(Utc::now());

    let updated = active
        .update(&state.db)
        .await
        // Same backstop as create: the uniqueness check above is a pre-check,
        // the DB constraint decides under concurrency.
        .map_err(map_domain_conflict)?;
    tracing::info!(%id, "site updated");
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated.into()))
}

/// `DELETE /api/v1/sites/{site_id}`
async fn remove(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    // Verify ownership first so that the ON DELETE CASCADE rules never run for a
    // site the caller must not see.
    load_site_write(&state.db, id, &current).await?;
    site::Entity::delete_by_id(id).exec(&state.db).await?;

    tracing::info!(%id, owner = %current.id, "site deleted");
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v1/sites/{site_id}/upstreams`
async fn list_upstreams(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<site_upstreams::Model>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let rows = site_upstreams::Entity::find()
        .filter(site_upstreams::Column::SiteId.eq(id))
        .order_by_desc(site_upstreams::Column::Weight)
        .all(&state.db)
        .await?;
    Ok(Json(rows))
}

/// `POST /api/v1/sites/{site_id}/upstreams`
async fn create_upstream(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreateUpstreamRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let address = normalize_origin_address(&payload.address)?;
    validate_upstream(&address, payload.weight)?;
    let pool_id = resolve_pool(&state, id, payload.pool_id.as_ref()).await?;

    // The same origin twice in one pool balances every request onto it twice
    // and doubles its health-check load; the same address in another pool is a
    // legitimate setup, so the check is scoped to this pool only.
    let siblings =
        load_address_collisions(&state, id, pool_id, &address, None).await?;
    ensure_address_available(&address, &siblings)?;

    let model = site_upstreams::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        pool_id: Set(pool_id),
        // The column is kept for the upcoming node-group feature; nothing
        // reads it today, so it mirrors the address instead of an input.
        name: Set(upstream_name_placeholder(&address)),
        address: Set(address.clone()),
        weight: Set(payload.weight),
        tls: Set(payload.tls),
        health_status: Set("unknown".to_string()),
        created_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await
    // The check above is a read-then-write, so two concurrent creates can both
    // pass it; `idx_site_upstreams_pool_address` (migration 000062) rejects the
    // loser. Reporting that as the same 400 keeps a race from looking like a
    // server fault to the caller.
    .map_err(|err| map_upstream_conflict(err, &address))?;

    tracing::info!(site_id = %id, upstream = %model.id, pool = %pool_id, "upstream added");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// `PUT /api/v1/sites/{site_id}/upstreams/{upstream_id}`
async fn update_upstream(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, upstream_id)): Path<(String, String)>,
    Json(payload): Json<UpdateUpstreamRequest>,
) -> Result<Json<site_upstreams::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&upstream_id, "upstream id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = site_upstreams::Entity::find_by_id(target)
        .filter(site_upstreams::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("upstream {target} not found"))
        })?;

    // Validate the post-update state *before* anything is written: this used
    // to run `active.update()` first and `validate_upstream` on the returned
    // row, so a rejected weight stayed in the database while the caller saw a
    // 400 (2026-10-19 audit, D21). Both fields are validated here — the
    // effective address and the effective weight — because either half of the
    // pair alone is not enough to decide.
    let next_address = match non_empty(&payload.address) {
        Some(address) => normalize_origin_address(&address)?,
        None => row.address.clone(),
    };
    let next_weight = payload.weight.unwrap_or(row.weight);
    validate_upstream(&next_address, next_weight)?;

    // A changed address (or a move to another pool) must not collide with a
    // sibling there. The row itself is excluded, so re-sending the stored
    // address — which the console does on every unrelated edit — stays a no-op.
    let next_pool = payload.pool_id.unwrap_or(row.pool_id);
    if next_address != row.address || next_pool != row.pool_id {
        let siblings = load_address_collisions(
            &state,
            id,
            next_pool,
            &next_address,
            Some(target),
        )
        .await?;
        ensure_address_available(&next_address, &siblings)?;
    }

    let mut active: site_upstreams::ActiveModel = row.into();
    if payload
        .address
        .as_deref()
        .is_some_and(|a| !a.trim().is_empty())
    {
        active.address = Set(next_address.clone());
    }
    if let Some(weight) = payload.weight {
        active.weight = Set(weight);
    }
    if let Some(tls) = payload.tls {
        active.tls = Set(tls);
    }
    if let Some(pool_id) = payload.pool_id {
        ensure_pool_belongs_to_site(&state, id, pool_id).await?;
        active.pool_id = Set(pool_id);
    }
    if let Some(health) = non_empty(&payload.health_status) {
        if health.len() > 20 {
            return Err(ApiError::BadRequest(
                "health_status must be at most 20 characters".to_string(),
            ));
        }
        active.health_status = Set(health);
    }

    let updated = active
        .update(&state.db)
        .await
        // Same backstop as create: a racing update that lands on an address a
        // concurrent write already claimed is a 400, not a 500.
        .map_err(|err| map_upstream_conflict(err, &next_address))?;

    tracing::info!(site_id = %id, upstream = %target, "upstream updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated))
}

/// `DELETE /api/v1/sites/{site_id}/upstreams/{upstream_id}`
async fn delete_upstream(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, upstream_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&upstream_id, "upstream id")?;
    load_site_write(&state.db, id, &current).await?;

    let deleted = site_upstreams::Entity::delete_by_id(target)
        .filter(site_upstreams::Column::SiteId.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::NotFound(format!("upstream {target} not found")));
    }

    tracing::info!(site_id = %id, upstream = %target, "upstream removed");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v1/sites/{site_id}/upstream-pools`
async fn list_pools(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<PoolWithMembers>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let mut rows = site_upstream_pools::Entity::find()
        .filter(site_upstream_pools::Column::SiteId.eq(id))
        .order_by_desc(site_upstream_pools::Column::IsDefault)
        .order_by_asc(site_upstream_pools::Column::CreatedAt)
        .all(&state.db)
        .await?;
    // `ORDER BY is_default DESC` puts the default first on PostgreSQL; the
    // in-memory pass keeps that guarantee independent of SQL boolean order.
    rows.sort_by_key(|row| !row.is_default);

    // One `pool_id IN (...)` query for every pool's nodes rather than one
    // query per pool: a site with twelve pools would otherwise run thirteen
    // round trips to render a single page.
    let mut members: HashMap<Uuid, Vec<site_upstreams::Model>> = HashMap::new();
    if !rows.is_empty() {
        let pool_ids: Vec<Uuid> = rows.iter().map(|row| row.id).collect();
        let nodes = site_upstreams::Entity::find()
            .filter(site_upstreams::Column::PoolId.is_in(pool_ids))
            .order_by_asc(site_upstreams::Column::CreatedAt)
            .all(&state.db)
            .await?;
        for node in nodes {
            members.entry(node.pool_id).or_default().push(node);
        }
    }

    let payload = rows
        .into_iter()
        .map(|pool| {
            let upstreams = members.remove(&pool.id).unwrap_or_default();
            PoolWithMembers { pool, upstreams }
        })
        .collect();
    Ok(Json(payload))
}

/// `POST /api/v1/sites/{site_id}/upstream-pools`
async fn create_pool(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreatePoolRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let name = payload.name.trim().to_string();
    let lb_algorithm = payload.lb_algorithm.trim().to_string();
    let sni = non_empty(&payload.sni);
    // Omitted means `auto`: the family that fixes the IPv6-unreachable 503
    // without every existing pool having to opt in.
    let address_family =
        normalize_address_family(payload.address_family.as_deref())?
            .unwrap_or_else(|| ADDRESS_FAMILY_AUTO.to_string());
    validate_pool(&name, &lb_algorithm, sni.as_deref(), &address_family)?;

    let mut health_check = PoolHealthCheck::default_values();
    health_check.enabled = payload.health_check_enabled.unwrap_or(false);
    if let Some(path) = non_empty(&payload.health_check_path) {
        health_check.path = path;
    }
    if let Some(v) = payload.health_check_interval_seconds {
        health_check.interval_seconds = v;
    }
    if let Some(v) = payload.health_check_timeout_ms {
        health_check.timeout_ms = v;
    }
    if let Some(v) = payload.health_check_unhealthy_threshold {
        health_check.unhealthy_threshold = v;
    }
    if let Some(v) = payload.health_check_healthy_threshold {
        health_check.healthy_threshold = v;
    }
    health_check.validate()?;

    let model = site_upstream_pools::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        name: Set(name),
        lb_algorithm: Set(lb_algorithm),
        sni: Set(sni),
        // Omitted means "follow the deployment default", not "pin false":
        // the pool then tracks `origin_settings.verify_cert`, so an operator
        // who later turns verification on does not have to revisit every
        // pool that was created while it was off.
        verify_cert: Set(payload.verify_cert),
        health_check_enabled: Set(health_check.enabled),
        health_check_path: Set(health_check.path),
        health_check_interval_seconds: Set(health_check.interval_seconds),
        health_check_timeout_ms: Set(health_check.timeout_ms),
        health_check_unhealthy_threshold: Set(health_check.unhealthy_threshold),
        health_check_healthy_threshold: Set(health_check.healthy_threshold),
        address_family: Set(address_family),
        is_default: Set(false),
        created_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, pool = %model.id, "origin pool added");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// `PUT /api/v1/sites/{site_id}/upstream-pools/{pool_id}`
async fn update_pool(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, pool_id)): Path<(String, String)>,
    Json(payload): Json<UpdatePoolRequest>,
) -> Result<Json<site_upstream_pools::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&pool_id, "pool id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = site_upstream_pools::Entity::find_by_id(target)
        .filter(site_upstream_pools::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("pool {target} not found"))
        })?;

    // Overlay the patch on the current health-check configuration and
    // validate it before anything is written: a rejected update must not
    // persist a half-applied or invalid row.
    let mut health_check = PoolHealthCheck {
        enabled: row.health_check_enabled,
        path: row.health_check_path.clone(),
        interval_seconds: row.health_check_interval_seconds,
        timeout_ms: row.health_check_timeout_ms,
        unhealthy_threshold: row.health_check_unhealthy_threshold,
        healthy_threshold: row.health_check_healthy_threshold,
    };
    health_check.apply_update(&payload);
    health_check.validate()?;

    let mut active: site_upstream_pools::ActiveModel = row.into();
    if let Some(name) = non_empty(&payload.name) {
        active.name = Set(name);
    }
    if let Some(lb_algorithm) = non_empty(&payload.lb_algorithm) {
        active.lb_algorithm = Set(lb_algorithm.clone());
    }
    if let Some(sni) = payload.sni.as_deref() {
        // `Some("")` clears the SNI and disables origin TLS.
        active.sni = Set(non_empty(&Some(sni.to_string())));
    }
    if let Some(verify_cert) = payload.verify_cert {
        // `None` clears the column: the pool goes back to following the
        // deployment default.
        active.verify_cert = Set(verify_cert);
    }
    if let Some(address_family) =
        normalize_address_family(payload.address_family.as_deref())?
    {
        active.address_family = Set(address_family);
    }
    active.health_check_enabled = Set(health_check.enabled);
    active.health_check_path = Set(health_check.path);
    active.health_check_interval_seconds = Set(health_check.interval_seconds);
    active.health_check_timeout_ms = Set(health_check.timeout_ms);
    active.health_check_unhealthy_threshold =
        Set(health_check.unhealthy_threshold);
    active.health_check_healthy_threshold = Set(health_check.healthy_threshold);

    let updated = active.update(&state.db).await?;
    validate_pool(
        &updated.name,
        &updated.lb_algorithm,
        updated.sni.as_deref(),
        &updated.address_family,
    )?;

    tracing::info!(site_id = %id, pool = %target, "origin pool updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated))
}

/// `DELETE /api/v1/sites/{site_id}/upstream-pools/{pool_id}`
async fn delete_pool(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, pool_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&pool_id, "pool id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = site_upstream_pools::Entity::find_by_id(target)
        .filter(site_upstream_pools::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("pool {target} not found"))
        })?;
    if row.is_default {
        return Err(ApiError::BadRequest(
            "the default pool cannot be deleted".to_string(),
        ));
    }

    let referencing = site_routes::Entity::find()
        .filter(site_routes::Column::PoolId.eq(target))
        .count(&state.db)
        .await?;
    if referencing > 0 {
        return Err(ApiError::Conflict(
            "pool is still referenced by routes".to_string(),
        ));
    }

    let nodes = site_upstreams::Entity::find()
        .filter(site_upstreams::Column::PoolId.eq(target))
        .count(&state.db)
        .await?;
    if nodes > 0 {
        return Err(ApiError::Conflict(
            "pool still has origin nodes; remove them first".to_string(),
        ));
    }

    site_upstream_pools::Entity::delete_by_id(target)
        .exec(&state.db)
        .await?;

    tracing::info!(site_id = %id, pool = %target, "origin pool removed");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v1/sites/{site_id}/routes`
async fn list_routes(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<site_routes::Model>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let rows = site_routes::Entity::find()
        .filter(site_routes::Column::SiteId.eq(id))
        .order_by_desc(site_routes::Column::Priority)
        .order_by_asc(site_routes::Column::CreatedAt)
        .all(&state.db)
        .await?;
    Ok(Json(rows))
}

/// `POST /api/v1/sites/{site_id}/routes`
async fn create_route(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreateRouteRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let name = payload.name.trim().to_string();
    let match_type = payload.match_type.trim().to_string();
    let path = payload.path.trim().to_string();
    let rewrite_path = non_empty(&payload.rewrite_path);
    let upstream_host = non_empty(&payload.upstream_host);
    validate_route(
        &name,
        &match_type,
        &path,
        payload.priority,
        payload.strip_prefix,
        rewrite_path.as_deref(),
        upstream_host.as_deref(),
    )?;
    ensure_pool_can_serve(&state, id, payload.pool_id).await?;
    if let Some(group_id) = payload.ip_group_id {
        ensure_route_ip_group(&state, group_id).await?;
    }

    let model = site_routes::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        name: Set(name),
        match_type: Set(match_type),
        path: Set(path),
        priority: Set(payload.priority),
        enabled: Set(payload.enabled),
        pool_id: Set(payload.pool_id),
        ip_group_id: Set(payload.ip_group_id),
        strip_prefix: Set(payload.strip_prefix),
        rewrite_path: Set(rewrite_path),
        upstream_host: Set(upstream_host),
        created_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, route = %model.id, "route added");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok((StatusCode::CREATED, Json(model)).into_response())
}

/// `PUT /api/v1/sites/{site_id}/routes/{route_id}`
async fn update_route(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, route_id)): Path<(String, String)>,
    Json(payload): Json<UpdateRouteRequest>,
) -> Result<Json<site_routes::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&route_id, "route id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = site_routes::Entity::find_by_id(target)
        .filter(site_routes::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("route {target} not found"))
        })?;

    if let Some(pool_id) = payload.pool_id {
        ensure_pool_can_serve(&state, id, pool_id).await?;
    }
    if let Some(Some(group_id)) = payload.ip_group_id {
        ensure_route_ip_group(&state, group_id).await?;
    }

    // Merged over the stored row first, validated, and only then written: the
    // path-rewrite rules cross-check `strip_prefix` against `match_type`, and a
    // route that fails validation must never reach the agents' rule bundle. A
    // rejected shape persisted here would break the site's whole data-plane
    // configuration, not just this route.
    let name = non_empty(&payload.name).unwrap_or_else(|| row.name.clone());
    let match_type = non_empty(&payload.match_type)
        .unwrap_or_else(|| row.match_type.clone());
    let path = non_empty(&payload.path).unwrap_or_else(|| row.path.clone());
    let priority = payload
        .priority
        // `0` is outside the valid range and means "back to auto weight".
        .map(|priority| (priority > 0).then_some(priority))
        .unwrap_or(row.priority);
    let strip_prefix = payload.strip_prefix.unwrap_or(row.strip_prefix);
    let rewrite_path = match payload.rewrite_path.as_ref() {
        Some(value) => non_empty(value),
        None => row.rewrite_path.clone(),
    };
    // Same tri-state as `rewrite_path`: absent keeps the stored value, `null`
    // (or a blank string) clears it, a value replaces it.
    let upstream_host = match payload.upstream_host.as_ref() {
        Some(value) => non_empty(value),
        None => row.upstream_host.clone(),
    };
    validate_route(
        &name,
        &match_type,
        &path,
        priority,
        strip_prefix,
        rewrite_path.as_deref(),
        upstream_host.as_deref(),
    )?;

    let mut active: site_routes::ActiveModel = row.into();
    if payload.name.is_some() {
        active.name = Set(name);
    }
    if payload.match_type.is_some() {
        active.match_type = Set(match_type);
    }
    if payload.path.is_some() {
        active.path = Set(path);
    }
    if payload.priority.is_some() {
        active.priority = Set(priority);
    }
    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(pool_id) = payload.pool_id {
        active.pool_id = Set(pool_id);
    }
    if let Some(ip_group_id) = payload.ip_group_id {
        active.ip_group_id = Set(ip_group_id);
    }
    if payload.strip_prefix.is_some() {
        active.strip_prefix = Set(strip_prefix);
    }
    if payload.rewrite_path.is_some() {
        active.rewrite_path = Set(rewrite_path);
    }
    if payload.upstream_host.is_some() {
        active.upstream_host = Set(upstream_host);
    }

    let updated = active.update(&state.db).await?;

    tracing::info!(site_id = %id, route = %target, "route updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated))
}

/// `DELETE /api/v1/sites/{site_id}/routes/{route_id}`
async fn delete_route(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, route_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&route_id, "route id")?;
    load_site_write(&state.db, id, &current).await?;

    let deleted = site_routes::Entity::delete_by_id(target)
        .filter(site_routes::Column::SiteId.eq(id))
        .exec(&state.db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(ApiError::NotFound(format!("route {target} not found")));
    }

    tracing::info!(site_id = %id, route = %target, "route removed");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v1/sites/{site_id}/ssl`
async fn show_ssl(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Option<SslResponse>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let row = site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(id))
        .one(&state.db)
        .await?;
    Ok(Json(row.map(SslResponse::from)))
}

/// `PUT /api/v1/sites/{site_id}/ssl` — creates or replaces the site's TLS entry.
async fn upsert_ssl(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpsertSslRequest>,
) -> Result<Json<SslResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let site = load_site_write(&state.db, id, &current).await?;

    let domain = normalise_domain(&payload.domain)?;
    if let Some(challenge) = non_empty(&payload.acme_challenge_type) {
        if !acme_challenge::is_valid(&challenge) {
            return Err(ApiError::BadRequest(format!(
                "unknown ACME challenge type '{challenge}'"
            )));
        }
    }
    // An ACME order without an uploaded PEM is issued against the site's whole
    // hostname set, which a wildcard may not contain under http-01.
    let uploaded_cert = payload
        .cert_pem
        .as_deref()
        .is_some_and(|pem| !pem.trim().is_empty());
    if !uploaded_cert && non_empty(&payload.acme_email).is_some() {
        ensure_acme_wildcard_supported(
            &site,
            &[],
            payload.acme_challenge_type.as_deref(),
        )?;
    }
    let expires_at = match non_empty(&payload.expires_at) {
        Some(raw) => {
            Some(crate::api::common::parse_datetime(&raw, "expires_at")?)
        },
        None => None,
    };

    // Uploading a certificate turns HTTPS on unless the caller said otherwise:
    // a certificate nothing serves would otherwise look broken.
    let mut tls = payload.tls;
    if tls.https_enabled.is_none()
        && payload.cert_pem.is_some()
        && payload.key_pem.is_some()
    {
        tls.https_enabled = Some(true);
    }
    // The posture write and the ACME/certificate fields below hit the same
    // `site_ssl` row twice; a failure between the two writes must not leave a
    // half-applied posture behind, so both go through one transaction.
    let txn = state.db.begin().await?;
    let posture = save_tls_posture(&txn, &site, &tls).await?;

    let existing = site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(id))
        .one(&txn)
        .await?;

    let model = match existing {
        Some(row) => {
            let row_id = row.id;
            let mut active: site_ssl::ActiveModel = row.into();
            active.domain = Set(domain);
            if let Some(cert) = payload.cert_pem {
                active.cert_pem = Set(non_empty(&Some(cert)));
            }
            if let Some(key) = payload.key_pem {
                active.key_pem = Set(non_empty(&Some(key)));
            }
            active.issuer = Set(payload.issuer);
            active.expires_at = Set(expires_at);
            active.auto_renew = Set(payload.auto_renew);
            active.acme_email = Set(non_empty(&payload.acme_email));
            active.acme_challenge_type =
                Set(non_empty(&payload.acme_challenge_type));
            active.acme_dns_provider =
                Set(non_empty(&payload.acme_dns_provider));
            if let Some(config) = payload.acme_dns_config {
                active.acme_dns_config = Set(Some(config));
            }
            posture.apply_to(&mut active);
            let updated = active.update(&txn).await?;
            tracing::info!(site_id = %id, ssl = %row_id, "SSL configuration updated");
            updated
        },
        None => {
            let row_id = Uuid::new_v4();
            let mut active = site_ssl::ActiveModel {
                id: Set(row_id),
                site_id: Set(id),
                cert_pem: Set(non_empty(&payload.cert_pem)),
                key_pem: Set(non_empty(&payload.key_pem)),
                issuer: Set(non_empty(&payload.issuer)),
                domain: Set(domain),
                expires_at: Set(expires_at),
                auto_renew: Set(payload.auto_renew),
                acme_email: Set(non_empty(&payload.acme_email)),
                acme_challenge_type: Set(non_empty(
                    &payload.acme_challenge_type,
                )),
                acme_dns_provider: Set(non_empty(&payload.acme_dns_provider)),
                acme_dns_config: Set(payload.acme_dns_config),
                https_enabled: Set(false),
                min_tls_version: Set(tls_version::TLS_12.to_string()),
                max_tls_version: Set(None),
                self_signed: Set(false),
                certificate_id: Set(None),
                mtls_enabled: Set(false),
                mtls_client_ca: Set(None),
                mtls_organization: Set(None),
                mtls_require_client_cert: Set(false),
                hsts_enabled: Set(false),
                hsts_max_age: Set(0),
                always_use_https: Set(false),
                http1_enabled: Set(true),
                http2_enabled: Set(true),
                created_at: Set(Utc::now()),
            };
            posture.apply_to(&mut active);
            let inserted = active.insert(&txn).await?;
            tracing::info!(site_id = %id, ssl = %row_id, "SSL configuration created");
            inserted
        },
    };
    txn.commit().await?;

    // Bump the site so that agents notice the configuration changed.
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(model.into()))
}

/// `DELETE /api/v1/sites/{site_id}/ssl`
async fn delete_ssl(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    site_ssl::Entity::delete_many()
        .filter(site_ssl::Column::SiteId.eq(id))
        .exec(&state.db)
        .await?;

    tracing::info!(site_id = %id, "SSL configuration removed");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Canonicalizes an origin address to `host[:port]`.
///
/// Copy-pasting a URL is common, so a scheme is stripped. Anything beyond a
/// trailing slash is rejected: a path would be silently dropped by the edge
/// and would also poison the SNI derived from the host, which is worse than a
/// 400 at save time.
fn normalize_origin_address(raw: &str) -> Result<String, ApiError> {
    let mut address = raw.trim().to_string();
    for scheme in ["http://", "https://"] {
        if let Some(rest) = address.strip_prefix(scheme) {
            address = rest.to_string();
            break;
        }
    }
    while address.ends_with('/') {
        address.pop();
    }
    if address.is_empty() || address.len() > 255 {
        return Err(ApiError::BadRequest(
            "upstream address must be 1-255 characters".to_string(),
        ));
    }
    if address.contains('?') || address.contains('#') {
        return Err(ApiError::BadRequest(
            "upstream address must be host[:port] without query or fragment"
                .to_string(),
        ));
    }
    if address.contains('/') {
        return Err(ApiError::BadRequest(
            "upstream address must be host[:port] without a path".to_string(),
        ));
    }

    let Some((host, port)) = split_origin_host_port(&address) else {
        return Err(ApiError::BadRequest(
            "upstream address must be host[:port]".to_string(),
        ));
    };
    if port.is_some_and(|port| port.parse::<u16>().map_or(true, |p| p == 0)) {
        return Err(ApiError::BadRequest(
            "upstream port must be between 1 and 65535".to_string(),
        ));
    }
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || c == '.'
                || c == '-'
                || c == '_'
                || c == ':'
        });
    if !host_ok {
        return Err(ApiError::BadRequest(
            "upstream host must be an IP address or hostname".to_string(),
        ));
    }

    Ok(address)
}

/// Splits `host[:port]`, brackets included for IPv6. `None` when the address
/// has more than one colon outside brackets (`::1` without brackets).
fn split_origin_host_port(address: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = address.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        return match tail {
            "" => Some((host, None)),
            tail => Some((host, Some(tail.strip_prefix(':')?))),
        };
    }
    match address.split_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() => {
            Some((host, Some(port)))
        },
        Some(_) => None,
        None => Some((address, None)),
    }
}

/// Validates the fields shared by upstream create/update.
///
/// The address is expected to be canonical already — write paths run it
/// through [`normalize_origin_address`] first.
/// The `site_upstreams.name` column is `varchar(100)` and is no longer an
/// API field (kept for the upcoming node-group feature). Echo the address,
/// truncated to the column width: addresses may be 255 bytes, and writing
/// one verbatim used to fail the insert (2026-10-19 review).
fn upstream_name_placeholder(address: &str) -> String {
    address.chars().take(100).collect()
}

fn validate_upstream(address: &str, weight: i32) -> Result<(), ApiError> {
    if address.is_empty() || address.len() > 255 {
        return Err(ApiError::BadRequest(
            "upstream address must be 1-255 characters".to_string(),
        ));
    }
    if !(1..=10_000).contains(&weight) {
        return Err(ApiError::BadRequest(
            "upstream weight must be between 1 and 10000".to_string(),
        ));
    }
    Ok(())
}

/// Validates a pingap load-balancing spec: `round_robin`, `random`,
/// `least_connections`, or `hash:<type>` for ip/url/path and
/// `hash:<type>:<key>` for header/cookie/query.
fn is_valid_lb_algorithm(value: &str) -> bool {
    if matches!(value, "round_robin" | "random" | "least_connections") {
        return true;
    }
    let Some(rest) = value.strip_prefix("hash:") else {
        return false;
    };
    let parts: Vec<&str> = rest.split(':').collect();
    match parts.as_slice() {
        [kind] => matches!(*kind, "ip" | "url" | "path"),
        [kind, key] => {
            matches!(*kind, "header" | "cookie" | "query")
                && !key.is_empty()
                && value.len() <= 64
        },
        _ => false,
    }
}

/// Validates the fields shared by pool create/update.
fn validate_pool(
    name: &str,
    lb_algorithm: &str,
    sni: Option<&str>,
    address_family: &str,
) -> Result<(), ApiError> {
    // Rejects anything the data plane would have to guess at; a stored value
    // always passes because it was normalized on the way in (and the column
    // carries the same three-value CHECK constraint).
    normalize_address_family(Some(address_family))?;
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::BadRequest(
            "pool name must be 1-100 characters".to_string(),
        ));
    }
    if lb_algorithm.len() > 64 || !is_valid_lb_algorithm(lb_algorithm) {
        return Err(ApiError::BadRequest(format!(
            "lb_algorithm '{lb_algorithm}' is invalid; expected round_robin, \
             random, least_connections or hash:<type>[:<key>] with type in \
             ip/url/path/header/cookie/query"
        )));
    }
    if let Some(sni) = sni.filter(|s| !s.is_empty()) {
        if sni.len() > 255 {
            return Err(ApiError::BadRequest(
                "sni must be at most 255 characters".to_string(),
            ));
        }
        if sni == "$host" {
            return Err(ApiError::BadRequest(
                "sni cannot be '$host'; static origin pools need a concrete \
                 hostname"
                    .to_string(),
            ));
        }
        if sni.contains("://") || sni.contains(':') {
            return Err(ApiError::BadRequest(
                "sni must be a bare hostname without scheme or port"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// Validates the fields shared by route create/update.
fn validate_route(
    name: &str,
    match_type: &str,
    path: &str,
    priority: Option<i32>,
    strip_prefix: bool,
    rewrite_path: Option<&str>,
    upstream_host: Option<&str>,
) -> Result<(), ApiError> {
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::BadRequest(
            "route name must be 1-100 characters".to_string(),
        ));
    }
    if !route_match_type::is_valid(match_type) {
        return Err(ApiError::BadRequest(format!(
            "unknown route match type '{match_type}' (prefix, exact or regex)"
        )));
    }
    if path.is_empty() || path.len() > 512 {
        return Err(ApiError::BadRequest(
            "route path must be 1-512 characters".to_string(),
        ));
    }
    if match_type == route_match_type::REGEX {
        regex::Regex::new(path).map(|_| ()).map_err(|err| {
            ApiError::BadRequest(format!(
                "route path is not a valid regex: {err}"
            ))
        })?;
    } else {
        if !path.starts_with('/') {
            return Err(ApiError::BadRequest(
                "route path must start with '/'".to_string(),
            ));
        }
        if path.starts_with('=') || path.starts_with('~') {
            return Err(ApiError::BadRequest(
                "route path must not start with '=' or '~'".to_string(),
            ));
        }
        // `path = "/"` has nothing to strip: removing `/` from `/users` puts
        // the separator back, so the path sent upstream is the path received —
        // the flag would be a silent no-op. Name the flag rather than the
        // routing conflict the operator cannot see (a `/` prefix route is
        // refused by the check right below).
        if strip_prefix && path == "/" && match_type == route_match_type::PREFIX
        {
            return Err(ApiError::BadRequest(
                "strip_prefix has no effect on path '/', remove it or give \
                 the route a longer prefix"
                    .to_string(),
            ));
        }
        if match_type == route_match_type::PREFIX && path == "/" {
            return Err(ApiError::BadRequest(
                "a prefix route on '/' conflicts with the default pool \
                 fallback"
                    .to_string(),
            ));
        }
    }
    if let Some(priority) = priority {
        if !(1..=60_000).contains(&priority) {
            return Err(ApiError::BadRequest(
                "route priority must be between 1 and 60000".to_string(),
            ));
        }
    }
    // `rewrite_path` replaces the whole path, so it is only meaningful as an
    // absolute one; the client's query string is appended to it verbatim, which
    // is why `?`, `#`, whitespace and control characters are rejected rather
    // than escaped. Mirrors `pingap_config::validate_rewrite_path` — including
    // its blank rule and its byte ceiling — which guards the config file and
    // (via `pingap-location`) the data plane.
    if let Some(rewrite_path) = rewrite_path {
        // The handlers map a blank payload to `None`, so a blank reaching here
        // is a value already stored (or sent straight through by a caller of
        // this function): reject it instead of writing it again, because
        // "unset" is the only way to say "no rewrite".
        if rewrite_path.trim().is_empty() {
            return Err(ApiError::BadRequest(
                "route rewrite path must not be blank".to_string(),
            ));
        }
        if rewrite_path.len() > MAX_ROUTE_REWRITE_PATH_LEN {
            return Err(ApiError::BadRequest(format!(
                "route rewrite path must be at most \
                 {MAX_ROUTE_REWRITE_PATH_LEN} bytes"
            )));
        }
        // Same order as the shared function: a padded value is reported as the
        // whitespace it is rather than as a missing slash.
        if let Some(bad) = rewrite_path.chars().find(|c| {
            matches!(c, '?' | '#') || c.is_whitespace() || c.is_control()
        }) {
            return Err(ApiError::BadRequest(format!(
                "route rewrite path must not contain '{bad}' (query, fragment, \
                 whitespace and control characters are not allowed)"
            )));
        }
        if !rewrite_path.starts_with('/') {
            return Err(ApiError::BadRequest(
                "route rewrite path must start with '/'".to_string(),
            ));
        }
    }
    // Stripping needs a prefix to strip: an exact or regex route matches a
    // whole pattern, not a prefix, so `strip_prefix` there would be a silent
    // no-op. Rejecting it tells the operator instead of quietly forwarding the
    // full path.
    if strip_prefix && match_type != route_match_type::PREFIX {
        return Err(ApiError::BadRequest(format!(
            "strip_prefix needs a prefix route, '{match_type}' has no prefix \
             to strip"
        )));
    }
    validate_upstream_host(upstream_host)?;
    Ok(())
}

/// Validates a route's `upstream_host`: the bare host name written into the
/// origin request's `Host` header.
///
/// Mirrors `pingap_config::LocationConf::validate_with_upstream` — no scheme,
/// no path, no whitespace, at most 253 bytes — because that is the predicate
/// the data plane applies when it builds the location, and
/// `pingap-location` additionally runs the value through `HeaderValue::from_str`
/// (which refuses control characters). A value accepted here but rejected
/// there takes the site's whole agent configuration down with it, so the
/// stricter of the two rules is enforced at write time.
fn validate_upstream_host(host: Option<&str>) -> Result<(), ApiError> {
    let Some(host) = host else {
        return Ok(());
    };
    let host = host.trim();
    if host.is_empty()
        || host.len() > 253
        || host.contains('/')
        || host.contains("://")
        || host.chars().any(char::is_whitespace)
        || host.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(format!(
            "upstream_host '{host}' must be a bare host name (no scheme, path \
             or whitespace, at most 253 bytes)"
        )));
    }
    Ok(())
}

/// Largest accepted replacement pattern, in bytes.
const MAX_RESPONSE_REPLACE_PATTERN_LEN: usize = 512;

/// Largest accepted replacement text, in bytes.
const MAX_RESPONSE_REPLACE_REPLACEMENT_LEN: usize = 2048;

/// Largest number of rules one policy may carry.
const MAX_RESPONSE_REPLACE_RULES: usize = 20;

/// Validates and canonicalises a response replacement policy.
///
/// The policy is compiled into the site's `sub_filter` plugin
/// (`pingap-plugin/src/sub_filter.rs`), whose rule syntax is
/// `sub_filter '<pattern>' '<replacement>' [flags]` parsed with
/// `'([^']+)'`. Four consequences drive the checks below:
///
/// * a single quote in either side ends the quoted literal early, so the rule
///   does not parse and the plugin fails to build;
/// * the quoted groups require **at least one character**, so an empty
///   pattern or replacement is equally fatal;
/// * a regex that does not compile (`is_regex`, and `path` which is always a
///   regex) fails the same way;
/// * a rule is **one single line**, `sub_filter '<p>' '<r>' [flags]`, and the
///   generated document carries it as one string — a line break, carriage
///   return or tab has no representation there (the operands are delimited by
///   `'` and separated by whitespace), and every TOML/HCL/KDL round trip the
///   site's configuration goes through re-escapes it, so the rule that reaches
///   the agent is no longer the rule the operator wrote.
///
/// Any of those failures drops the entire generated configuration for the site,
/// which is why they are rejected here rather than discovered by an agent.
fn validate_response_replace(
    policy: &ResponseReplaceConfig,
) -> Result<(), ApiError> {
    if !policy.path.trim().is_empty() {
        regex::Regex::new(&policy.path).map_err(|err| {
            ApiError::BadRequest(format!(
                "response_replace path is not a valid regex: {err}"
            ))
        })?;
    }
    for code in &policy.status_codes {
        if !(100..=599).contains(code) {
            return Err(ApiError::BadRequest(format!(
                "response_replace status code {code} must be between 100 and \
                 599"
            )));
        }
    }
    if policy.rules.len() > MAX_RESPONSE_REPLACE_RULES {
        return Err(ApiError::BadRequest(format!(
            "response_replace accepts at most {MAX_RESPONSE_REPLACE_RULES} \
             rules"
        )));
    }
    for (index, rule) in policy.rules.iter().enumerate() {
        validate_response_replace_rule(index + 1, rule)?;
    }
    Ok(())
}

/// Characters a rule operand cannot carry: they break the single-line form the
/// data plane's rule syntax and the generated configuration both assume.
const FORBIDDEN_RULE_CHARS: [char; 3] = ['\n', '\r', '\t'];

/// Returns the first character of `value` that cannot appear in a rule operand.
///
/// `allow_backslash` exempts a `subs_filter` **pattern**, where a backslash is
/// the regex escape itself (`\d`, `\.`); in a literal `sub_filter` pattern and
/// in every replacement it is not a pattern-language construct, so it only
/// imitates an escape sequence in a string that is never unescaped.
fn forbidden_rule_char(value: &str, allow_backslash: bool) -> Option<char> {
    value.chars().find(|c| {
        FORBIDDEN_RULE_CHARS.contains(c) || (!allow_backslash && *c == '\\')
    })
}

/// Validates one replacement rule: size, delimiters, characters, and — for a
/// regex rule — that the pattern compiles.
fn validate_response_replace_rule(
    number: usize,
    rule: &ResponseReplaceRule,
) -> Result<(), ApiError> {
    if rule.pattern.is_empty()
        || rule.pattern.len() > MAX_RESPONSE_REPLACE_PATTERN_LEN
    {
        return Err(ApiError::BadRequest(format!(
            "response_replace rule {number} pattern must be 1-\
             {MAX_RESPONSE_REPLACE_PATTERN_LEN} bytes"
        )));
    }
    if rule.replacement.is_empty()
        || rule.replacement.len() > MAX_RESPONSE_REPLACE_REPLACEMENT_LEN
    {
        return Err(ApiError::BadRequest(format!(
            "response_replace rule {number} replacement must be 1-\
             {MAX_RESPONSE_REPLACE_REPLACEMENT_LEN} bytes"
        )));
    }
    if rule.pattern.contains('\'') || rule.replacement.contains('\'') {
        return Err(ApiError::BadRequest(format!(
            "response_replace rule {number} must not contain a single \
             quote; the data plane's rule syntax uses ' to delimit the \
             pattern and the replacement"
        )));
    }
    for (operand, value, allow_backslash) in [
        ("pattern", rule.pattern.as_str(), rule.is_regex),
        ("replacement", rule.replacement.as_str(), false),
    ] {
        if let Some(bad) = forbidden_rule_char(value, allow_backslash) {
            return Err(ApiError::BadRequest(format!(
                "response_replace rule {number} {operand} must not contain \
                 {bad:?}; a rule is one single-line `sub_filter '<pattern>' \
                 '<replacement>' [flags]` entry, and only a regex pattern may \
                 carry a backslash (its regex escape)"
            )));
        }
    }
    if rule.is_regex {
        regex::Regex::new(&rule.pattern).map_err(|err| {
            ApiError::BadRequest(format!(
                "response_replace rule {number} pattern is not a valid \
                 regex: {err}"
            ))
        })?;
    }
    Ok(())
}

/// Validates a payload policy and normalises "no rules" to "no policy".
///
/// A console that deletes the last rule row sends `rules: []`; storing that as
/// a policy would make the site read as configured while the data plane
/// generates a plugin that can never fire, so it clears the column instead.
///
/// Validation comes **first**: the empty-rule shortcut used to return before
/// `path` and `status_codes` were looked at, and the console sends `rules: []`
/// on every save of a site whose policy it never touched — so a broken policy
/// was re-accepted (and a duplicate status code re-stored) silently.
///
/// `status_codes` is sorted and deduplicated before the policy is returned: the
/// data plane joins the codes into the plugin's `status_codes` string, where the
/// same code twice is noise in the generated configuration and in the config
/// diff an operator has to read.
fn normalise_response_replace(
    policy: Option<ResponseReplaceConfig>,
) -> Result<Option<ResponseReplaceConfig>, ApiError> {
    let Some(mut policy) = policy else {
        return Ok(None);
    };
    validate_response_replace(&policy)?;
    if policy.rules.is_empty() {
        return Ok(None);
    }
    policy.status_codes.sort_unstable();
    policy.status_codes.dedup();
    Ok(Some(policy))
}

/// Rejects an origin address that already exists in the same pool.
///
/// Two identical nodes in one pool are never a load-balancing decision: pingap
/// keeps both as separate backends, so every request is balanced onto the same
/// server twice over and the duplicate only doubles the health-check load.
/// The same address in *another* pool stays allowed — pools are independent
/// upstreams, and mirroring one origin into two pools is a legitimate setup.
///
/// `siblings` is the caller's query result scoped to one pool and, on update,
/// excluding the row being changed — which is what makes re-sending an
/// unchanged address a no-op instead of a self-collision.
///
/// The comparison ignores ASCII case: a host name is not case-sensitive, so
/// `HOST:port` and `host:port` are the same origin and used to slip past a
/// plain `==`. Folding ASCII is exactly what the database does here — the
/// unique index `idx_site_upstreams_pool_address` is built on `lower(address)`,
/// and `normalize_origin_address` restricts the host to ASCII
/// (`[A-Za-z0-9._:-]`), where `eq_ignore_ascii_case` and PostgreSQL's `lower()`
/// agree.
fn ensure_address_available(
    address: &str,
    siblings: &[String],
) -> Result<(), ApiError> {
    if siblings
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(address))
    {
        return Err(ApiError::BadRequest(format!(
            "upstream {address} already exists in this pool"
        )));
    }
    Ok(())
}

/// Recognises the unique-index rejection a racing write gets.
///
/// [`ensure_address_available`] is a read-then-write, so two concurrent
/// requests can both see a free address and both write it. The decision belongs
/// to `idx_site_upstreams_pool_address` (migration 000062), and its violation
/// has to reach the caller as the same 400 a sequential duplicate produces.
///
/// `DbErr::RecordNotInserted` is matched too: it is the same "the write did not
/// produce a row" outcome reported without a constraint name, which is what a
/// driver that does not echo the PostgreSQL error text yields.
fn is_upstream_conflict(err: &DbErr) -> bool {
    if matches!(err, DbErr::RecordNotInserted) {
        return true;
    }
    let message = err.to_string();
    message.contains("idx_site_upstreams_pool_address")
        || message.contains("duplicate key")
}

/// Maps a duplicate-origin rejection to a 400, passing anything else through.
fn map_upstream_conflict(err: DbErr, address: &str) -> ApiError {
    if is_upstream_conflict(&err) {
        ApiError::BadRequest(format!(
            "upstream {address} already exists in this pool"
        ))
    } else {
        err.into()
    }
}

/// Loads the origin addresses of one pool of one site that collide with
/// `address`.
///
/// The predicate is `lower(address) = lower($1)` — the same expression
/// `idx_site_upstreams_pool_address` is built on — so the pre-check and the
/// constraint cannot disagree about what "the same origin" means, and on
/// PostgreSQL the planner can ride that index instead of reading the pool's
/// rows.
///
/// `exclude` drops a single row from the result — the node an update is
/// rewriting, so it cannot collide with itself. Only the addresses are read;
/// the duplicate check needs nothing else from the row.
async fn load_address_collisions(
    state: &AppState,
    site_id: Uuid,
    pool_id: Uuid,
    address: &str,
    exclude: Option<Uuid>,
) -> Result<Vec<String>, ApiError> {
    let mut query = site_upstreams::Entity::find()
        .filter(site_upstreams::Column::SiteId.eq(site_id))
        .filter(site_upstreams::Column::PoolId.eq(pool_id))
        .filter(
            Expr::expr(Func::lower(Expr::col(site_upstreams::Column::Address)))
                .eq(Func::lower(Expr::val(address))),
        );
    if let Some(exclude) = exclude {
        query = query.filter(site_upstreams::Column::Id.ne(exclude));
    }
    Ok(query
        .all(&state.db)
        .await?
        .into_iter()
        .map(|row| row.address)
        .collect())
}

/// Resolves the pool a new origin node belongs to: the given pool when
/// specified, otherwise the site's default pool.
async fn resolve_pool(
    state: &AppState,
    site_id: Uuid,
    pool_id: Option<&Uuid>,
) -> Result<Uuid, ApiError> {
    match pool_id {
        Some(pool_id) => {
            ensure_pool_belongs_to_site(state, site_id, *pool_id).await?;
            Ok(*pool_id)
        },
        None => {
            let row = site_upstream_pools::Entity::find()
                .filter(site_upstream_pools::Column::SiteId.eq(site_id))
                .filter(site_upstream_pools::Column::IsDefault.eq(true))
                .one(&state.db)
                .await?
                .ok_or_else(|| {
                    ApiError::BadRequest(
                        "site has no default origin pool".to_string(),
                    )
                })?;
            Ok(row.id)
        },
    }
}

/// Fails unless the pool exists and belongs to the site.
async fn ensure_pool_belongs_to_site(
    state: &AppState,
    site_id: Uuid,
    pool_id: Uuid,
) -> Result<(), ApiError> {
    let owned = site_upstream_pools::Entity::find_by_id(pool_id)
        .filter(site_upstream_pools::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
        .is_some();
    if !owned {
        return Err(ApiError::BadRequest(format!(
            "pool {pool_id} does not belong to this site"
        )));
    }
    Ok(())
}

/// Routes must target a pool that can actually receive traffic: a pool
/// without origin nodes would make the route vanish from the data plane.
async fn ensure_pool_can_serve(
    state: &AppState,
    site_id: Uuid,
    pool_id: Uuid,
) -> Result<(), ApiError> {
    ensure_pool_belongs_to_site(state, site_id, pool_id).await?;
    let peer_count = site_upstreams::Entity::find()
        .filter(site_upstreams::Column::PoolId.eq(pool_id))
        .count(&state.db)
        .await?;
    if peer_count == 0 {
        return Err(ApiError::BadRequest(format!(
            "pool {pool_id} has no origin nodes; add a node before routing traffic to it"
        )));
    }
    Ok(())
}

/// A route gated on an IP group only serves when the data plane can expand the
/// group: a missing, disabled or empty group would drop the gate entirely.
async fn ensure_route_ip_group(
    state: &AppState,
    group_id: Uuid,
) -> Result<(), ApiError> {
    let group = ip_groups::Entity::find_by_id(group_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest(format!("IP group {group_id} not found"))
        })?;
    if !group.enabled {
        return Err(ApiError::BadRequest(format!(
            "IP group '{}' is disabled; enable it or clear the route gate",
            group.name
        )));
    }
    if group.ip_ranges.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "IP group '{}' has no ranges; a route gated on it would never match",
            group.name
        )));
    }
    Ok(())
}

/// Host part of a `host:port` origin address, used to pre-fill the pool SNI.
fn origin_host(address: &str) -> &str {
    let host = match address.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => address,
    };
    host.trim_start_matches('[').trim_end_matches(']')
}

/// Normalizes a proxy-trust entry into its canonical CIDR form.
///
/// A bare IP becomes a host range (`/32` for IPv4, `/128` for IPv6), which is
/// what "trust exactly this proxy" reads like; a CIDR has its host bits
/// masked away (so `10.0.0.5/24` renders as `10.0.0.0/24`) and duplicates
/// collapse at the caller. `None` marks invalid input.
pub fn parse_proxy_range(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.contains('/') {
        value
            .parse::<ipnet::IpNet>()
            .ok()
            .map(|net| net.trunc().to_string())
    } else {
        value
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| ipnet::IpNet::from(ip).to_string())
    }
}

/// Updates `sites.updated_at` so agents see a fresh configuration fingerprint.
pub async fn touch_site(
    state: &AppState,
    site_id: Uuid,
) -> Result<(), ApiError> {
    site::Entity::update_many()
        .col_expr(
            site::Column::UpdatedAt,
            sea_orm::sea_query::Expr::value(Utc::now()),
        )
        .filter(site::Column::Id.eq(site_id))
        .exec(&state.db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests convert `ActiveModel`s back into `Model`s to assert field parity.
    use sea_orm::TryIntoModel;

    /// The three accepted families, their normalization, and a rejection for
    /// anything else - including the empty string, which must not silently
    /// mean "unset": the data plane has no address family for it.
    #[test]
    fn pool_address_family_accepts_three_values_only() {
        assert_eq!(
            Some("auto".to_string()),
            normalize_address_family(Some("auto")).expect("auto is valid")
        );
        assert_eq!(
            Some("ipv4".to_string()),
            normalize_address_family(Some(" IPv4 ")).expect("padding and case")
        );
        assert_eq!(
            Some("ipv6".to_string()),
            normalize_address_family(Some("ipv6")).expect("ipv6 is valid")
        );
        assert_eq!(None, normalize_address_family(None).expect("absent"));

        for invalid in ["", "dual", "ipv4_only", "6"] {
            let err = normalize_address_family(Some(invalid))
                .expect_err("must be rejected");
            assert!(
                matches!(err, ApiError::BadRequest(_)),
                "{invalid:?} must be a 400, got {err:?}"
            );
        }
    }

    /// A create request without the field keeps the column default, and an
    /// invalid value never reaches the insert.
    #[test]
    fn create_pool_request_address_family() {
        let absent: CreatePoolRequest =
            serde_json::from_str(r#"{"name":"origin"}"#)
                .expect("name is the only required field");
        assert_eq!(None, absent.address_family);
        // Absent is not a family the helper invents; `create_pool` turns it
        // into the column default, which is the same string.
        assert_eq!(
            None,
            normalize_address_family(absent.address_family.as_deref())
                .expect("absent is valid")
        );

        let invalid: CreatePoolRequest = serde_json::from_str(
            r#"{"name":"origin","address_family":"dual"}"#,
        )
        .expect("deserialization is not the validator");
        assert!(normalize_address_family(invalid.address_family.as_deref())
            .is_err());
    }

    /// `list_pools` returns each pool with its nodes inlined under
    /// `upstreams`, and the pool's own fields stay at the top level (the
    /// response is a superset of the bare pool row).
    #[test]
    fn pool_with_members_inlines_upstreams() {
        let pool_id = Uuid::new_v4();
        let payload = PoolWithMembers {
            pool: site_upstream_pools::Model {
                id: pool_id,
                site_id: Uuid::nil(),
                name: "origin".into(),
                lb_algorithm: "round_robin".into(),
                sni: None,
                verify_cert: None,
                health_check_enabled: false,
                health_check_path: "/".into(),
                health_check_interval_seconds: 10,
                health_check_timeout_ms: 3000,
                health_check_unhealthy_threshold: 2,
                health_check_healthy_threshold: 1,
                address_family: "ipv4".into(),
                is_default: true,
                created_at: Utc::now(),
            },
            upstreams: vec![site_upstreams::Model {
                id: Uuid::new_v4(),
                site_id: Uuid::nil(),
                pool_id,
                name: "node".into(),
                address: "127.0.0.1:8080".into(),
                weight: 1,
                tls: false,
                health_status: "unknown".into(),
                created_at: Utc::now(),
            }],
        };
        let json = serde_json::to_value(&payload).expect("serializes");
        // The pool's fields are at the top level, not nested under `pool`.
        assert_eq!(Some("origin"), json.get("name").and_then(|v| v.as_str()));
        assert_eq!(
            Some("ipv4"),
            json.get("address_family").and_then(|v| v.as_str())
        );
        assert_eq!(
            Some(true),
            json.get("is_default").and_then(|v| v.as_bool())
        );
        let upstreams = json
            .get("upstreams")
            .and_then(|v| v.as_array())
            .expect("members are inlined under `upstreams`");
        assert_eq!(1, upstreams.len());
        assert_eq!(
            Some("127.0.0.1:8080"),
            upstreams[0].get("address").and_then(|v| v.as_str())
        );
    }

    /// Three-state semantics of the nullable site field: a missing key must
    /// leave the stored value alone, a present `null` clears the site's
    /// opinion, and a bool pins it. Losing the outer `Some` in
    /// `Option<Option<bool>>` would silently turn `null` into "no change".
    #[test]
    fn origin_verify_cert_request_is_three_state() {
        let absent: UpdateSiteRequest =
            serde_json::from_str(r#"{}"#).expect("absent key");
        assert_eq!(absent.origin_verify_cert, None, "missing key = no change");

        let cleared: UpdateSiteRequest =
            serde_json::from_str(r#"{"origin_verify_cert": null}"#)
                .expect("present null");
        assert_eq!(
            cleared.origin_verify_cert,
            Some(None),
            "explicit null clears the site's opinion"
        );

        let pinned: UpdateSiteRequest =
            serde_json::from_str(r#"{"origin_verify_cert": false}"#)
                .expect("present bool");
        assert_eq!(pinned.origin_verify_cert, Some(Some(false)));

        // Wrong types must be rejected, not coerced.
        assert!(serde_json::from_str::<UpdateSiteRequest>(
            r#"{"origin_verify_cert": "false"}"#
        )
        .is_err());
    }

    #[test]
    fn proxy_ranges_normalize_to_canonical_cidr() {
        assert_eq!(
            parse_proxy_range("10.0.0.1").as_deref(),
            Some("10.0.0.1/32")
        );
        assert_eq!(
            parse_proxy_range(" 10.0.0.0/24 ").as_deref(),
            Some("10.0.0.0/24")
        );
        assert_eq!(
            parse_proxy_range("2001:db8::1").as_deref(),
            Some("2001:db8::1/128")
        );
        assert_eq!(
            parse_proxy_range("2001:db8::/32").as_deref(),
            Some("2001:db8::/32")
        );
        // A host bit set inside the prefix is masked away.
        assert_eq!(
            parse_proxy_range("10.0.0.5/24").as_deref(),
            Some("10.0.0.0/24")
        );
        assert!(parse_proxy_range("not-an-ip").is_none());
        assert!(parse_proxy_range("10.0.0.0/33").is_none());
        assert!(parse_proxy_range("").is_none());
    }

    #[test]
    fn origin_addresses_are_normalized_to_host_port() {
        assert_eq!(
            normalize_origin_address(" 10.0.0.1:8080 ").unwrap(),
            "10.0.0.1:8080"
        );
        assert_eq!(
            normalize_origin_address("https://origin.example.com").unwrap(),
            "origin.example.com"
        );
        assert_eq!(
            normalize_origin_address("http://origin.example.com:8080/")
                .unwrap(),
            "origin.example.com:8080"
        );
        assert_eq!(
            normalize_origin_address("[::1]:8443").unwrap(),
            "[::1]:8443"
        );
    }

    #[test]
    fn origin_addresses_reject_paths_and_bad_ports() {
        assert!(
            normalize_origin_address("https://origin.example.com/api").is_err()
        );
        assert!(normalize_origin_address("origin.example.com?x=1").is_err());
        assert!(normalize_origin_address("origin.example.com#frag").is_err());
        assert!(normalize_origin_address("origin.example.com:0").is_err());
        assert!(normalize_origin_address("origin.example.com:70000").is_err());
        assert!(normalize_origin_address("::1").is_err());
        assert!(normalize_origin_address("").is_err());
    }

    #[test]
    fn split_origin_host_port_handles_ipv6() {
        assert_eq!(
            split_origin_host_port("example.com"),
            Some(("example.com", None))
        );
        assert_eq!(
            split_origin_host_port("example.com:443"),
            Some(("example.com", Some("443")))
        );
        assert_eq!(
            split_origin_host_port("[::1]:443"),
            Some(("::1", Some("443")))
        );
        assert_eq!(split_origin_host_port("[::1]"), Some(("::1", None)));
        assert_eq!(split_origin_host_port("::1"), None);
    }

    #[test]
    fn pool_health_check_defaults_apply_and_validate() {
        // No fields: everything falls back to the documented defaults and
        // validates even while disabled.
        let mut hc = PoolHealthCheck::default_values();
        hc.validate().expect("defaults must validate");

        // Update overlay: only the given fields change; the path keeps the
        // caller's spelling and must still start with '/'.
        let payload = UpdatePoolRequest {
            health_check_enabled: Some(true),
            health_check_path: Some("/healthz".to_string()),
            health_check_interval_seconds: Some(30),
            ..Default::default()
        };
        hc.apply_update(&payload);
        assert!(hc.enabled);
        assert_eq!(hc.path, "/healthz");
        assert_eq!(hc.interval_seconds, 30);
        assert_eq!(hc.timeout_ms, 3000);
        assert_eq!(hc.unhealthy_threshold, 2);
        assert_eq!(hc.healthy_threshold, 1);
        hc.validate().expect("the overlaid posture must validate");

        // A path without the leading slash is rejected, not normalized.
        let mut hc = PoolHealthCheck::default_values();
        hc.apply_update(&UpdatePoolRequest {
            health_check_path: Some("healthz".to_string()),
            ..Default::default()
        });
        assert!(hc.validate().is_err());
    }

    #[test]
    fn pool_health_check_rejects_out_of_range_values() {
        let cases = [
            (
                PoolHealthCheck {
                    path: "no-slash".to_string(),
                    ..PoolHealthCheck::default_values()
                },
                "must start with '/'",
            ),
            (
                PoolHealthCheck {
                    path: "/a b".to_string(),
                    ..PoolHealthCheck::default_values()
                },
                "must start with '/'",
            ),
            (
                PoolHealthCheck {
                    path: "/a?b=1".to_string(),
                    ..PoolHealthCheck::default_values()
                },
                "must start with '/'",
            ),
            (
                PoolHealthCheck {
                    interval_seconds: 4,
                    ..PoolHealthCheck::default_values()
                },
                "interval_seconds must be between 5 and 3600",
            ),
            (
                PoolHealthCheck {
                    interval_seconds: 3601,
                    ..PoolHealthCheck::default_values()
                },
                "interval_seconds must be between 5 and 3600",
            ),
            (
                PoolHealthCheck {
                    timeout_ms: 99,
                    ..PoolHealthCheck::default_values()
                },
                "timeout_ms must be between 100 and 30000",
            ),
            (
                PoolHealthCheck {
                    timeout_ms: 30_001,
                    ..PoolHealthCheck::default_values()
                },
                "timeout_ms must be between 100 and 30000",
            ),
            (
                PoolHealthCheck {
                    unhealthy_threshold: 0,
                    ..PoolHealthCheck::default_values()
                },
                "unhealthy_threshold must be between 1 and 10",
            ),
            (
                PoolHealthCheck {
                    healthy_threshold: 11,
                    ..PoolHealthCheck::default_values()
                },
                "healthy_threshold must be between 1 and 10",
            ),
        ];
        for (hc, message) in cases {
            let err = hc
                .validate()
                .expect_err("expected the invalid posture to be rejected")
                .to_string();
            assert!(err.contains(message), "{message}: {err}");
        }
    }

    #[test]
    fn pool_health_check_accepts_documented_bounds() {
        let hc = PoolHealthCheck {
            enabled: true,
            path: "/healthz".to_string(),
            interval_seconds: 3600,
            timeout_ms: 30_000,
            unhealthy_threshold: 10,
            healthy_threshold: 10,
        };
        hc.validate().expect("upper bounds must validate");
    }

    /// C2/L4-003: the TLS protocol switches a `PUT /ssl` writes onto the
    /// `site_ssl` row must come back out of `SslResponse` under the same
    /// names — read/write symmetry, not a write-only field pair.
    #[test]
    fn ssl_response_reads_back_protocol_switches() {
        let model = site_ssl::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::new_v4(),
            cert_pem: None,
            key_pem: None,
            issuer: None,
            domain: "example.com".to_string(),
            expires_at: None,
            auto_renew: false,
            acme_email: None,
            acme_challenge_type: None,
            acme_dns_provider: None,
            acme_dns_config: None,
            https_enabled: true,
            min_tls_version: tls_version::TLS_12.to_string(),
            max_tls_version: None,
            self_signed: false,
            certificate_id: None,
            mtls_enabled: false,
            mtls_client_ca: None,
            mtls_organization: None,
            mtls_require_client_cert: false,
            hsts_enabled: false,
            hsts_max_age: 0,
            always_use_https: false,
            http1_enabled: true,
            http2_enabled: false,
            created_at: Utc::now(),
        };
        let response = SslResponse::from(model);
        assert!(response.http1_enabled);
        assert!(!response.http2_enabled);
    }

    /// C4/L2-001: cloning must copy every WAF rule, one for one (N 条 → N
    /// 条), carrying over the expression/action/mode/grouping and only
    /// replacing identity, site and timestamps — a rule left behind would run
    /// the clone with a weaker policy than the source.
    #[test]
    fn cloning_rules_copies_every_rule_one_for_one() {
        let now = Utc::now();
        let source_site = Uuid::new_v4();
        let new_site = Uuid::new_v4();
        let source_group = Uuid::new_v4();
        let new_group = Uuid::new_v4();
        let group_ids = HashMap::from([(source_group, new_group)]);

        let make_rule = |name: &str, group: Option<Uuid>| rule::Model {
            id: Uuid::new_v4(),
            group_id: group,
            site_id: source_site,
            name: name.to_string(),
            description: Some("custom".to_string()),
            expression: "http.request.uri.path contains \"/admin\"".to_string(),
            action: "block".to_string(),
            severity: 3,
            tags: vec!["custom".to_string()],
            enabled: true,
            mode: "block".to_string(),
            priority: 10,
            created_at: now,
            updated_at: now,
        };
        let source_rules = [
            make_rule("grouped", Some(source_group)),
            make_rule("ungrouped", None),
            make_rule("another", Some(source_group)),
        ];
        assert_eq!(3, source_rules.len(), "source has N rules");

        let clones: Vec<rule::ActiveModel> = source_rules
            .iter()
            .cloned()
            .map(|row| clone_rule_row(row, new_site, &group_ids, now))
            .collect();
        assert_eq!(
            source_rules.len(),
            clones.len(),
            "N source rules must produce N clone rows"
        );

        let clones: Vec<rule::Model> = clones
            .into_iter()
            .map(|row| row.try_into_model().expect("all fields are set"))
            .collect();

        for (source, clone) in source_rules.iter().zip(&clones) {
            assert_ne!(
                source.id, clone.id,
                "the clone row gets its own identity"
            );
            assert_eq!(clone.site_id, new_site);
            // Content (except id / site_id / timestamps) matches the source.
            assert_eq!(source.name, clone.name);
            assert_eq!(source.description, clone.description);
            assert_eq!(source.expression, clone.expression);
            assert_eq!(source.action, clone.action);
            assert_eq!(source.severity, clone.severity);
            assert_eq!(source.tags, clone.tags);
            assert_eq!(source.enabled, clone.enabled);
            assert_eq!(source.mode, clone.mode);
            assert_eq!(source.priority, clone.priority);
            // Group ids remap onto the clone's own group rows.
            let expected_group = source
                .group_id
                .map(|g| group_ids.get(&g).copied().unwrap_or(g));
            assert_eq!(expected_group, clone.group_id);
        }

        // Group semantics: a source group maps to the clone's own group row,
        // never to the source's id and never to None.
        let grouped = clones
            .iter()
            .find(|row| row.name == "grouped")
            .expect("grouped rule");
        assert_eq!(Some(new_group), grouped.group_id);
        let ungrouped = clones
            .iter()
            .find(|row| row.name == "ungrouped")
            .expect("ungrouped rule");
        assert_eq!(None, ungrouped.group_id);

        // Group rows are copied the same way: same name/phase/priority,
        // new identity and site.
        let group_row = clone_rule_group_row(
            rule_groups::Model {
                id: source_group,
                site_id: source_site,
                name: "admin".to_string(),
                phase: "request".to_string(),
                priority: 1,
                enabled: true,
                created_at: now,
                updated_at: now,
            },
            new_site,
            now,
        );
        let group_row = group_row.try_into_model().expect("all fields are set");
        assert_ne!(source_group, group_row.id, "new identity");
        assert_eq!(new_site, group_row.site_id);
        assert_eq!("admin", group_row.name);

        // A group id the map does not know belongs to another site: the
        // reference is dropped, never carried over. Keeping it would attach
        // the clone's rule to a foreign group, and deleting that group would
        // cascade into the clone.
        let orphan = clone_rule_row(
            make_rule("orphan", Some(Uuid::new_v4())),
            new_site,
            &HashMap::new(),
            now,
        );
        let orphan = orphan.try_into_model().expect("all fields are set");
        assert!(orphan.group_id.is_none());
    }

    #[test]
    fn merged_rejects_disabling_both_http_protocols() {
        let base = TlsPosture::unset();
        // A fresh site serves both protocols, HTTP/2 included.
        assert!(base.http1_enabled);
        assert!(base.http2_enabled);

        let err = base
            .merged(&TlsPostureRequest {
                http1_enabled: Some(false),
                http2_enabled: Some(false),
                ..Default::default()
            })
            .expect_err("a site must keep one protocol enabled");
        assert!(err.to_string().contains("at least one of HTTP/1.1"));

        // Turning HTTP/1.1 off alone is valid: the listener then advertises
        // h2 only.
        let h2_only = base
            .merged(&TlsPostureRequest {
                http1_enabled: Some(false),
                ..Default::default()
            })
            .expect("h2-only is a supported posture");
        assert!(!h2_only.http1_enabled);
        assert!(h2_only.http2_enabled);
    }

    #[test]
    fn merged_treats_missing_max_tls_version_as_unbounded() {
        let base = TlsPosture::unset();
        // A fresh site_ssl row carries no max_tls_version: that is the "no
        // ceiling" default and must not be rejected as unsupported.
        let merged = base
            .merged(&TlsPostureRequest {
                https_enabled: Some(true),
                ..Default::default()
            })
            .expect("an absent max_tls_version must validate");
        assert!(merged.https_enabled);
        assert_eq!(merged.max_tls_version, None);

        // The newest version as the floor with no ceiling is valid too.
        base.merged(&TlsPostureRequest {
            min_tls_version: Some("1.3".to_string()),
            ..Default::default()
        })
        .expect("min 1.3 with no ceiling must validate");

        // An explicit ceiling that is not a known version stays rejected.
        let err = base
            .merged(&TlsPostureRequest {
                max_tls_version: Some("9.9".to_string()),
                ..Default::default()
            })
            .expect_err("an unknown max_tls_version must be rejected");
        assert!(err.to_string().contains("unsupported TLS version"));

        // An explicit ceiling below the floor stays rejected.
        assert!(base
            .merged(&TlsPostureRequest {
                max_tls_version: Some("1.0".to_string()),
                ..Default::default()
            })
            .is_err());
    }

    /// A random string used to arm mTLS verifies nothing, so the posture
    /// merge must reject it with a 400 instead of storing it (D08).
    #[test]
    fn merged_rejects_a_client_ca_that_is_not_a_pem_bundle() {
        let base = TlsPosture::unset();
        let err = base
            .merged(&TlsPostureRequest {
                mtls_enabled: Some(true),
                mtls_client_ca: Some("not a certificate".to_string()),
                ..Default::default()
            })
            .expect_err("a non-PEM client CA must be rejected");
        assert_eq!(err.code(), "bad_request");
        assert!(
            err.to_string().contains("mtls_client_ca"),
            "the message must name the field: {err}"
        );

        // A real bundle is accepted, and a broken second block is not: the
        // agent verifies against every certificate in the anchor.
        let ca = crate::pki::tls::generate_self_signed(
            "Test CA",
            &["localhost".to_string()],
            30,
        )
        .expect("the test CA must generate");
        let merged = base
            .merged(&TlsPostureRequest {
                mtls_enabled: Some(true),
                mtls_client_ca: Some(ca.cert_pem.clone()),
                ..Default::default()
            })
            .expect("a PEM client CA must validate");
        assert!(merged.mtls_enabled);
        assert!(merged.mtls_client_ca.is_some());

        assert!(base
            .merged(&TlsPostureRequest {
                mtls_enabled: Some(true),
                mtls_client_ca: Some(format!(
                    "{}\n-----BEGIN CERTIFICATE-----\nnope",
                    ca.cert_pem
                )),
                ..Default::default()
            })
            .is_err());

        // Omitting the field keeps the previous value, so an existing mTLS
        // site is not reconfigured by an unrelated request.
        let err = TlsPosture::unset()
            .merged(&TlsPostureRequest {
                mtls_enabled: Some(true),
                ..Default::default()
            })
            .expect_err("mtls_enabled without a CA must still be rejected");
        assert!(err.to_string().contains("requires the client CA bundle"));
    }

    /// Mirrors `update_upstream`'s `payload.weight.unwrap_or(row.weight)`.
    fn effective_weight_for_test(requested: Option<i32>, stored: i32) -> i32 {
        requested.unwrap_or(stored)
    }

    /// D21 regression: the weight is validated against the effective
    /// post-update value *before* any write, so a rejected update leaves the
    /// stored row untouched. The database is not available in a unit test, so
    /// what is asserted here is the ordering contract the handler relies on:
    /// `validate_upstream` rejects the effective pair on its own.
    #[test]
    fn update_upstream_validates_the_effective_values_before_writing() {
        // What `update_upstream` computes for `{ "weight": 0 }` against a row
        // whose address is unchanged: `payload.weight.unwrap_or(row.weight)`.
        let row_address = "10.0.0.1:8080".to_string();
        let row_weight = 5;
        // The handler's expression, fed the `{ "weight": 0 }` payload.
        let next_weight = effective_weight_for_test(Some(0), row_weight);
        let err = validate_upstream(&row_address, next_weight)
            .expect_err("weight 0 is out of range");
        assert!(err.to_string().contains("between 1 and 10000"));

        // The same normalisation the handler runs before validating: a bad
        // address is rejected during normalisation, also before the write.
        assert!(
            normalize_origin_address("https://origin.example.com/api").is_err()
        );
        assert_eq!(
            normalize_origin_address("https://origin.example.com:8443/")
                .unwrap(),
            "origin.example.com:8443"
        );

        // A valid pair passes so the handler can proceed to the write.
        validate_upstream(&row_address, 10).expect("a valid pair must pass");

        // Nothing above touched the database: the checks are pure, which is
        // what lets the handler run them before `active.update()`.
    }

    /// The rewrite knobs are validated against the shape the data plane can
    /// apply, and `validate_route` rejects them before the write: these rows
    /// are what the agents turn into location config, so a value rejected only
    /// after storing breaks the site's whole data-plane config.
    #[test]
    fn route_rewrite_fields_are_validated() {
        let with_path = |path: &str,
                         match_type: &str,
                         strip: bool,
                         rewrite: Option<&str>| {
            validate_route("api", match_type, path, None, strip, rewrite, None)
                .map_err(|err| (err.code(), err.to_string()))
        };
        let check = |match_type: &str, strip: bool, rewrite: Option<&str>| {
            with_path("/api", match_type, strip, rewrite)
        };

        // Accepted: no rewrite at all, a prefix route stripping its prefix,
        // and a fixed replacement on any match type (it needs no prefix).
        assert_eq!(check("prefix", false, None), Ok(()));
        assert_eq!(check("prefix", true, None), Ok(()));
        assert_eq!(check("prefix", false, Some("/v2")), Ok(()));
        assert_eq!(check("exact", false, Some("/v2")), Ok(()));
        assert_eq!(check("regex", false, Some("/")), Ok(()));

        // Rejected shapes: relative, query, fragment, whitespace, newline.
        for bad in ["v2", "/v2?x=1", "/v2#frag", "/v 2", "/v\n2"] {
            let err = check("prefix", false, Some(bad))
                .expect_err("rewrite path must be rejected");
            assert_eq!("bad_request", err.0, "{bad} is a 400");
        }
        assert!(check("prefix", false, Some("/v2?x=1"))
            .unwrap_err()
            .1
            .contains("must not contain"));

        // Blank is not "unset": the handlers map a blank payload to `None`
        // before getting here, so a blank at this point is a stored value that
        // says nothing. It must be rejected, not written back.
        for blank in ["", " ", "   "] {
            let err = check("prefix", false, Some(blank))
                .expect_err("a blank rewrite path must be rejected");
            assert_eq!("bad_request", err.0);
            assert!(
                err.1.contains("must not be blank"),
                "{blank:?} must fail as blank, got: {}",
                err.1
            );
        }

        // The length ceiling matches the data plane's: 2048 **bytes**.
        let at_limit = format!("/{}", "a".repeat(2047));
        assert_eq!(check("prefix", false, Some(&at_limit)), Ok(()));
        let too_long = format!("/{}", "a".repeat(2048));
        assert!(check("prefix", false, Some(&too_long))
            .unwrap_err()
            .1
            .contains("at most 2048 bytes"));
        // 1025 characters but 2049 bytes: a character count would let it pass.
        let multibyte = format!("/{}", "é".repeat(1024));
        assert!(check("prefix", false, Some(&multibyte)).is_err());

        // Stripping needs a prefix to strip: exact and regex routes are
        // rejected rather than silently forwarding the full path.
        for match_type in ["exact", "regex"] {
            let err = check(match_type, true, None).expect_err("no prefix");
            assert_eq!("bad_request", err.0);
            assert!(err.1.contains("needs a prefix route"));
        }
    }

    /// `strip_prefix` on `path = "/"` is a silent no-op — stripping `/` from
    /// `/users` puts the separator back — so the pair is rejected with a
    /// message naming the flag. The `/` prefix route is refused on its own
    /// (it would swallow the default pool fallback), so the strip message has
    /// to come first to be the one the operator sees.
    #[test]
    fn strip_prefix_on_the_root_path_is_rejected() {
        let check = |path: &str, match_type: &str, strip: bool| {
            validate_route("api", match_type, path, None, strip, None, None)
                .map_err(|err| (err.code(), err.to_string()))
        };

        let err = check("/", "prefix", true).expect_err("strip on '/'");
        assert_eq!("bad_request", err.0, "a 400, not a stored no-op");
        assert!(
            err.1.contains("strip_prefix has no effect on path '/'"),
            "the message must name the flag: {}",
            err.1
        );

        // The same path without the flag keeps its own, more specific error:
        // the route itself is refused for the routing conflict.
        let err = check("/", "prefix", false).expect_err("'/' prefix route");
        assert!(err.1.contains("default pool fallback"), "{}", err.1);

        // A deeper prefix still strips, so the check must not reject it.
        assert_eq!(check("/api", "prefix", true), Ok(()));
        // An exact route on `/` is not a prefix at all: the generic
        // "needs a prefix route" rule stays the one reported for it.
        let err = check("/", "exact", true).expect_err("exact on '/'");
        assert!(err.1.contains("needs a prefix route"), "{}", err.1);
    }

    /// `update_route` merges the rewrite fields with the stored row, which is
    /// what makes "absent = no change" and an explicit clear distinguishable.
    #[test]
    fn update_route_rewrite_fields_are_three_state() {
        let absent: UpdateRouteRequest =
            serde_json::from_str(r#"{}"#).expect("absent keys");
        assert_eq!(absent.strip_prefix, None);
        assert_eq!(absent.rewrite_path, None);

        let cleared: UpdateRouteRequest =
            serde_json::from_str(r#"{"rewrite_path": null}"#)
                .expect("explicit null");
        assert_eq!(cleared.rewrite_path, Some(None), "null clears the field");

        let off: UpdateRouteRequest =
            serde_json::from_str(r#"{"strip_prefix": false}"#)
                .expect("explicit false");
        assert_eq!(off.strip_prefix, Some(false));

        let set: UpdateRouteRequest =
            serde_json::from_str(r#"{"rewrite_path": "  /v2  "}"#)
                .expect("value");
        // The handler normalises through `non_empty`, which trims.
        assert_eq!(non_empty(&set.rewrite_path.flatten()), Some("/v2".into()));

        // A blank string is "no replacement", not a replacement with "".
        let blank: UpdateRouteRequest =
            serde_json::from_str(r#"{"rewrite_path": "   "}"#)
                .expect("blank value");
        assert_eq!(non_empty(&blank.rewrite_path.flatten()), None);

        // Wrong types are rejected rather than coerced.
        assert!(serde_json::from_str::<UpdateRouteRequest>(
            r#"{"strip_prefix": "yes"}"#
        )
        .is_err());

        // Create defaults to forwarding the path unchanged.
        let create: CreateRouteRequest = serde_json::from_str(
            r#"{"name":"api","match_type":"prefix","path":"/api",
                "pool_id":"00000000-0000-0000-0000-000000000000"}"#,
        )
        .expect("create payload without the new fields");
        assert!(!create.strip_prefix);
        assert_eq!(create.rewrite_path, None);
        assert_eq!(create.upstream_host, None);
    }

    /// D-5: the route's `Host` override is validated with the data plane's
    /// rule. A value accepted here but rejected by `pingap-location` would
    /// drop the site's whole generated configuration, so the stricter rule is
    /// the one enforced at write time.
    #[test]
    fn route_upstream_host_matches_the_data_plane_rule() {
        let check = |host: Option<&str>| {
            validate_route(
                "mirror", "prefix", "/google", None, false, None, host,
            )
            .map_err(|err| (err.code(), err.to_string()))
        };

        // Absent keeps the client's Host: the historic behaviour, and what a
        // route that proxies a site's own origin wants.
        assert_eq!(check(None), Ok(()));
        // A bare host name, with or without an explicit port: the data plane
        // builds a HeaderValue out of either.
        assert_eq!(check(Some("www.google.com")), Ok(()));
        assert_eq!(check(Some("www.google.com:8443")), Ok(()));

        // The 253-byte ceiling is the one the config file enforces.
        let at_limit = "a".repeat(253);
        assert_eq!(check(Some(&at_limit)), Ok(()));
        let too_long = "a".repeat(254);
        assert!(check(Some(&too_long))
            .expect_err("254 bytes is over the ceiling")
            .1
            .contains("at most 253 bytes"));

        // Shapes an origin cannot use as a virtual host name. Interior
        // whitespace and control characters are in the list because
        // `HeaderValue::from_str` would refuse them when the location is
        // built.
        for bad in [
            "https://www.google.com",
            "www.google.com/",
            "/google",
            "www google.com",
            "www.goo\tdle.com",
        ] {
            let err = check(Some(bad)).expect_err("must be rejected");
            assert_eq!("bad_request", err.0, "{bad:?} must be a 400");
        }
        // Surrounding whitespace is trimmed, not rejected: the config-file
        // path trims too, and the handlers already map a blank payload to
        // "unset". A blank reaching this function directly is still refused
        // rather than written as an empty Host header.
        assert_eq!(check(Some("  www.google.com  ")), Ok(()));
        assert!(check(Some("   ")).is_err());
    }

    /// D-1: an identical origin already in the same pool is refused with a 400
    /// naming the address; the same address in *another* pool stays allowed,
    /// because the check is scoped to one pool's node list.
    #[test]
    fn duplicate_upstream_in_one_pool_is_rejected() {
        let pool_a = vec!["172.17.53.244:5000".to_string()];

        let err = ensure_address_available("172.17.53.244:5000", &pool_a)
            .expect_err("the same address twice in one pool must be a 400");
        assert_eq!(err.code(), "bad_request");
        assert!(
            err.to_string().contains(
                "upstream 172.17.53.244:5000 already exists in this pool"
            ),
            "the message must name the address and the pool: {err}"
        );

        // A second, distinct origin in the same pool is what a pool is for.
        assert!(ensure_address_available("172.17.53.245:5000", &pool_a).is_ok());

        // Another pool has its own node list — the handlers query per pool,
        // never per site — so the same address is free to appear again.
        let pool_b: Vec<String> = Vec::new();
        assert!(ensure_address_available("172.17.53.244:5000", &pool_b).is_ok());

        // An update that keeps the stored address excludes the row itself
        // (`load_address_collisions(.., Some(id))`), so the list it checks
        // holds only the siblings and the request is a no-op, not a
        // self-collision.
        let siblings_without_self = vec!["172.17.53.245:5000".to_string()];
        assert!(ensure_address_available(
            "172.17.53.244:5000",
            &siblings_without_self
        )
        .is_ok());
    }

    /// H1: a host name is not case-sensitive, so `HOST:port` and `host:port`
    /// are the same origin — the plain `==` this check used to run let the
    /// second form through, and the pool then balanced every request onto one
    /// server twice. The database enforces the same rule through the
    /// `lower(address)` unique index added by migration 000062.
    #[test]
    fn upstream_duplicate_check_ignores_ascii_case() {
        let stored = vec!["Origin.Example.COM:8080".to_string()];
        for candidate in [
            "origin.example.com:8080",
            "ORIGIN.EXAMPLE.COM:8080",
            "Origin.Example.COM:8080",
        ] {
            let err = ensure_address_available(candidate, &stored).expect_err(
                "a case-only difference must be the same origin, hence a 400",
            );
            assert_eq!(err.code(), "bad_request", "{candidate}");
            assert!(
                err.to_string().contains("already exists in this pool"),
                "{err}"
            );
        }
        // The port is not case-folded away: a different port is a different
        // origin, and so is a different host.
        assert!(ensure_address_available("origin.example.com:8081", &stored)
            .is_ok());
        assert!(
            ensure_address_available("other.example.com:8080", &stored).is_ok()
        );
    }

    /// H1: the pre-check is a read-then-write, so two concurrent requests can
    /// both pass it; `idx_site_upstreams_pool_address` rejects the loser and
    /// the caller must see the same 400 a sequential duplicate produces. The
    /// race itself cannot be reproduced in a unit test — it depends on the
    /// index — so this pins the error mapping it feeds.
    #[test]
    fn unique_index_violation_maps_to_bad_request() {
        let index_violation = DbErr::Custom(
            "error returned by database: duplicate key value violates unique \
             constraint \"idx_site_upstreams_pool_address\""
                .to_string(),
        );
        let bare_duplicate = DbErr::Custom(
            "error returned by database: duplicate key value violates unique \
             constraint"
                .to_string(),
        );
        for err in [index_violation, bare_duplicate, DbErr::RecordNotInserted] {
            match map_upstream_conflict(err, "api.example.com:8080") {
                ApiError::BadRequest(message) => assert!(
                    message.contains(
                        "upstream api.example.com:8080 already exists in this pool"
                    ),
                    "{message}"
                ),
                other => panic!("expected BadRequest, got {other:?}"),
            }
        }
        // Anything unrelated stays a server-side failure, not caller input.
        assert!(!matches!(
            map_upstream_conflict(
                DbErr::Custom("connection reset".to_string()),
                "api.example.com:8080"
            ),
            ApiError::BadRequest(_)
        ));
    }

    fn replace_rule(
        pattern: &str,
        replacement: &str,
        is_regex: bool,
    ) -> crate::models::ResponseReplaceRule {
        crate::models::ResponseReplaceRule {
            pattern: pattern.to_string(),
            replacement: replacement.to_string(),
            is_regex,
        }
    }

    /// D-6: the policy is compiled into the site's `sub_filter` plugin, whose
    /// rule parser (`'([^']+)'`) cannot express an empty side or a quote, and
    /// whose regex compiles at plugin build time. Every one of those failures
    /// would take down the site's whole agent configuration, so all of them are
    /// rejected here.
    #[test]
    fn response_replace_policy_is_validated() {
        let policy =
            |path: &str,
             status_codes: Vec<u16>,
             rules: Vec<crate::models::ResponseReplaceRule>| {
                ResponseReplaceConfig {
                    path: path.to_string(),
                    status_codes,
                    rules,
                }
            };
        let check = |policy: &ResponseReplaceConfig| {
            validate_response_replace(policy)
                .map_err(|err| (err.code(), err.to_string()))
        };

        // The documented shape, plus the "all paths / all statuses" form.
        assert_eq!(
            check(&policy(
                "^/.*",
                vec![200],
                vec![replace_rule("Google", "PingWAF", false)]
            )),
            Ok(())
        );
        assert_eq!(
            check(&policy(
                "",
                Vec::new(),
                vec![replace_rule("Google", "PingWAF", false)]
            )),
            Ok(())
        );

        // `path` is always a regex.
        let err = check(&policy(
            "^(/",
            Vec::new(),
            vec![replace_rule("Google", "PingWAF", false)],
        ))
        .expect_err("a broken path regex must be rejected");
        assert_eq!("bad_request", err.0);
        assert!(err.1.contains("path is not a valid regex"), "{}", err.1);

        // Status codes stay inside the HTTP range.
        for bad in [99u16, 600] {
            let err = check(&policy(
                "",
                vec![bad],
                vec![replace_rule("Google", "PingWAF", false)],
            ))
            .expect_err("an out-of-range status must be rejected");
            assert!(err.1.contains("must be between 100 and 599"), "{}", err.1);
        }

        // At most 20 rules.
        let many = vec![replace_rule("Google", "PingWAF", false); 21];
        let err = check(&policy("", Vec::new(), many))
            .expect_err("21 rules is over the cap");
        assert!(err.1.contains("at most 20 rules"), "{}", err.1);
        assert_eq!(
            check(&policy(
                "",
                Vec::new(),
                vec![replace_rule("Google", "PingWAF", false); 20]
            )),
            Ok(())
        );

        // The plugin's quoted groups need at least one character on both
        // sides, and its size ceilings mirror the task's contract.
        let err = check(&policy(
            "",
            Vec::new(),
            vec![replace_rule("", "PingWAF", false)],
        ))
        .expect_err("an empty pattern cannot be parsed by the plugin");
        assert!(err.1.contains("pattern must be 1-512 bytes"), "{}", err.1);

        let long_pattern = "a".repeat(513);
        let err = check(&policy(
            "",
            Vec::new(),
            vec![replace_rule(&long_pattern, "PingWAF", false)],
        ))
        .expect_err("a 513-byte pattern is over the cap");
        assert!(err.1.contains("pattern must be 1-512 bytes"), "{}", err.1);
        assert_eq!(
            check(&policy(
                "",
                Vec::new(),
                vec![replace_rule(&"a".repeat(512), "PingWAF", false)]
            )),
            Ok(())
        );

        let err = check(&policy(
            "",
            Vec::new(),
            vec![replace_rule("Google", "", false)],
        ))
        .expect_err("an empty replacement cannot be parsed by the plugin");
        assert!(
            err.1.contains("replacement must be 1-2048 bytes"),
            "{}",
            err.1
        );

        let long_replacement = "b".repeat(2049);
        let err = check(&policy(
            "",
            Vec::new(),
            vec![replace_rule("Google", &long_replacement, false)],
        ))
        .expect_err("a 2049-byte replacement is over the cap");
        assert!(
            err.1.contains("replacement must be 1-2048 bytes"),
            "{}",
            err.1
        );

        // A single quote ends the plugin's quoted literal early, so the rule
        // would not parse at all.
        for rule in [
            replace_rule("Goo'gle", "PingWAF", false),
            replace_rule("Google", "Ping'WAF", false),
        ] {
            let err = check(&policy("", Vec::new(), vec![rule]))
                .expect_err("a quote must be rejected");
            assert!(err.1.contains("single quote"), "{}", err.1);
        }

        // `is_regex` patterns compile at plugin build time.
        let err = check(&policy(
            "",
            Vec::new(),
            vec![replace_rule("Goo(gle", "PingWAF", true)],
        ))
        .expect_err("a broken rule regex must be rejected");
        assert!(err.1.contains("pattern is not a valid regex"), "{}", err.1);
        assert_eq!(
            check(&policy(
                "",
                Vec::new(),
                vec![replace_rule("Go+gle", "PingWAF", true)]
            )),
            Ok(())
        );
    }

    /// H2: a rule is emitted as one single-line
    /// `sub_filter '<pattern>' '<replacement>' [flags]` entry inside the site's
    /// generated configuration, so a line break, carriage return or tab in
    /// either operand has no representation there and a backslash only imitates
    /// an escape outside a regex pattern. All four are rejected at write time
    /// because the failure would take the site's whole agent configuration down
    /// with it.
    #[test]
    fn response_replace_rejects_multiline_operands_and_escapes() {
        let check = |rule: ResponseReplaceRule| {
            validate_response_replace(&ResponseReplaceConfig {
                path: String::new(),
                status_codes: Vec::new(),
                rules: vec![rule],
            })
            .map_err(|err| (err.code(), err.to_string()))
        };

        for (operand, rule) in [
            ("pattern", replace_rule("a\nb", "PingWAF", false)),
            ("pattern", replace_rule("a\rb", "PingWAF", false)),
            ("pattern", replace_rule("a\tb", "PingWAF", false)),
            ("pattern", replace_rule("a\\b", "PingWAF", false)),
            ("replacement", replace_rule("Google", "a\nb", false)),
            ("replacement", replace_rule("Google", "a\rb", false)),
            ("replacement", replace_rule("Google", "a\tb", false)),
            ("replacement", replace_rule("Google", "a\\b", false)),
            // A regex replacement has no escape language of its own either:
            // `$1` is the capture reference, never `\1`.
            ("replacement", replace_rule("Go+gle", "a\\b", true)),
        ] {
            let err = check(rule)
                .expect_err("control characters and escapes must be rejected");
            assert_eq!("bad_request", err.0, "{operand}");
            assert!(
                err.1.contains(operand) && err.1.contains("single-line"),
                "the message must name the operand and the rule form: {}",
                err.1
            );
        }

        // A regex pattern keeps its backslash: `\d` / `\.` are the regex
        // escapes, and refusing them would make `subs_filter` unusable.
        assert_eq!(check(replace_rule(r"\d+\.\d+", "PingWAF", true)), Ok(()));
        // A literal pattern and both sides of a plain rule are unaffected.
        assert_eq!(check(replace_rule("Google", "PingWAF", false)), Ok(()));
        assert_eq!(check(replace_rule("$1", "$2", false)), Ok(()));
    }

    /// A policy with no rules is "replace nothing", which is what a console
    /// sends after deleting the last row: it clears the column instead of
    /// storing a policy the data plane would turn into a dead plugin.
    #[test]
    fn response_replace_without_rules_clears_the_policy() {
        assert!(normalise_response_replace(None).unwrap().is_none());
        assert!(normalise_response_replace(Some(ResponseReplaceConfig {
            path: "^/.*".to_string(),
            status_codes: vec![200],
            rules: Vec::new(),
        }))
        .unwrap()
        .is_none());
        let kept = normalise_response_replace(Some(ResponseReplaceConfig {
            path: "^/.*".to_string(),
            status_codes: vec![200],
            rules: vec![replace_rule("Google", "PingWAF", false)],
        }))
        .unwrap();
        assert_eq!(kept.map(|policy| policy.rules.len()), Some(1));
        // An invalid policy is still rejected, not silently dropped.
        assert!(normalise_response_replace(Some(ResponseReplaceConfig {
            path: "^(/".to_string(),
            status_codes: Vec::new(),
            rules: vec![replace_rule("Google", "PingWAF", false)],
        }))
        .is_err());
    }

    /// M3: `rules: []` used to return before `path` / `status_codes` were
    /// looked at, and the console sends exactly that on every save of a site
    /// whose policy it never touched — so a broken policy was silently
    /// re-accepted instead of rejected.
    #[test]
    fn response_replace_validates_before_the_empty_rules_shortcut() {
        let broken_path =
            normalise_response_replace(Some(ResponseReplaceConfig {
                path: "^(/".to_string(),
                status_codes: Vec::new(),
                rules: Vec::new(),
            }))
            .expect_err("a broken path must be rejected even with no rules");
        assert_eq!("bad_request", broken_path.code());
        assert!(
            broken_path
                .to_string()
                .contains("path is not a valid regex"),
            "{broken_path}"
        );

        let bad_status =
            normalise_response_replace(Some(ResponseReplaceConfig {
                path: String::new(),
                status_codes: vec![42],
                rules: Vec::new(),
            }))
            .expect_err(
                "an out-of-range status must be rejected with no rules",
            );
        assert_eq!("bad_request", bad_status.code());
        assert!(
            bad_status
                .to_string()
                .contains("must be between 100 and 599"),
            "{bad_status}"
        );

        // A well-formed but empty policy still clears the column.
        assert!(normalise_response_replace(Some(ResponseReplaceConfig {
            path: "^/.*".to_string(),
            status_codes: vec![200],
            rules: Vec::new(),
        }))
        .unwrap()
        .is_none());
    }

    /// L5: the data plane joins the codes into the plugin's `status_codes`
    /// string, so the stored list is canonical — sorted, no repeats — and the
    /// generated configuration does not carry `200,200,201,200`.
    #[test]
    fn response_replace_status_codes_are_sorted_and_deduped() {
        let policy = normalise_response_replace(Some(ResponseReplaceConfig {
            path: String::new(),
            status_codes: vec![404, 200, 404, 201, 200],
            rules: vec![replace_rule("Google", "PingWAF", false)],
        }))
        .unwrap()
        .expect("a policy with rules is kept");
        assert_eq!(policy.status_codes, vec![200, 201, 404]);
        // The string the config builder joins matches the stored order.
        assert_eq!(
            policy
                .status_codes
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            "200,201,404"
        );
    }

    /// The site update keeps the same three-state contract as
    /// `origin_verify_cert`: absent = unchanged, `null` = cleared, an object =
    /// replaced.
    #[test]
    fn response_replace_request_is_three_state() {
        let absent: UpdateSiteRequest =
            serde_json::from_str(r#"{}"#).expect("absent key");
        assert_eq!(absent.response_replace, None, "missing key = no change");

        let cleared: UpdateSiteRequest =
            serde_json::from_str(r#"{"response_replace": null}"#)
                .expect("present null");
        assert_eq!(
            cleared.response_replace,
            Some(None),
            "explicit null removes the policy"
        );

        let set: UpdateSiteRequest = serde_json::from_str(
            r#"{"response_replace":{"path":"^/.*","status_codes":[200],
                "rules":[{"pattern":"Google","replacement":"PingWAF",
                          "is_regex":false}]}}"#,
        )
        .expect("present object");
        let policy = set.response_replace.flatten().expect("policy parsed");
        assert_eq!(policy.path, "^/.*");
        assert_eq!(policy.status_codes, vec![200]);
        assert_eq!(policy.rules.len(), 1);
        assert!(!policy.rules[0].is_regex);

        // Wrong types are rejected, not coerced.
        assert!(serde_json::from_str::<UpdateSiteRequest>(
            r#"{"response_replace":{"rules":[{"pattern":1}]}}"#
        )
        .is_err());
    }

    #[test]
    fn downstream_timeout_defaults_and_range_are_enforced() {
        let request: CreateSiteRequest = serde_json::from_str(
            r#"{"name":"site","domain":"example.com","upstream_address":"10.0.0.1:8080"}"#,
        )
        .expect("create request");
        assert_eq!(
            request.downstream_timeout_secs,
            crate::defaults::DEFAULT_SITE_DOWNSTREAM_TIMEOUT_SECS as u32
        );

        for bad in [0, 3601] {
            assert!(validate_site_downstream_timeout_secs(bad).is_err());
        }
        for good in [1, 60, 3600] {
            assert_eq!(
                validate_site_downstream_timeout_secs(good).unwrap(),
                good as i32
            );
        }
        assert_eq!(
            crate::defaults::normalize_site_downstream_timeout_secs(0),
            60
        );
        assert_eq!(
            crate::defaults::normalize_site_downstream_timeout_secs(4000),
            3600
        );
    }
}
