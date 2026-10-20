//! Site management: CRUD for sites plus their origin servers and TLS material.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::api::common::{
    ensure_acme_wildcard_supported, ensure_domains_available, load_site_read,
    load_site_write, map_domain_conflict, non_empty, normalise_domain,
    normalise_domain_list, parse_uuid, require_write, Page, Pagination,
};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::api::validation::validate_pem_bundle;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{
    acme_challenge, cache_rules, ip_groups, rate_limit_rules, route_match_type,
    rule, rule_groups, site, site_certificates, site_routes, site_ssl,
    site_status, site_upstream_pools, site_upstreams, tls_version,
    trusted_header,
};

/// Longest accepted route `rewrite_path`, matching
/// `pingap_config::MAX_REWRITE_PATH_LEN` — the data plane rejects anything
/// longer, so storing it would only fail later, on the agent side.
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
}

fn default_lb_algorithm() -> String {
    "round_robin".to_string()
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
        let pattern = format!("%{}%", search.to_lowercase());
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
    Json(payload): Json<CreateSiteRequest>,
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
        created_at: Set(timestamp),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(%id, %domain, upstream = %upstream_address, owner = %current.id, "site created");
    notify_config_changed(&state, id, Some(&current.email)).await;

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
    Json(payload): Json<UpdateSiteRequest>,
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

    let model = site_upstreams::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        pool_id: Set(pool_id),
        // The column is kept for the upcoming node-group feature; nothing
        // reads it today, so it mirrors the address instead of an input.
        name: Set(upstream_name_placeholder(&address)),
        address: Set(address),
        weight: Set(payload.weight),
        tls: Set(payload.tls),
        health_status: Set("unknown".to_string()),
        created_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

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

    let mut active: site_upstreams::ActiveModel = row.into();
    if payload
        .address
        .as_deref()
        .is_some_and(|a| !a.trim().is_empty())
    {
        active.address = Set(next_address);
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

    let updated = active.update(&state.db).await?;

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
) -> Result<Json<Vec<site_upstream_pools::Model>>, ApiError> {
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
    Ok(Json(rows))
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
    validate_pool(&name, &lb_algorithm, sni.as_deref())?;

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
    validate_route(
        &name,
        &match_type,
        &path,
        payload.priority,
        payload.strip_prefix,
        rewrite_path.as_deref(),
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
    validate_route(
        &name,
        &match_type,
        &path,
        priority,
        strip_prefix,
        rewrite_path.as_deref(),
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
) -> Result<(), ApiError> {
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
    // than escaped. Mirrors `validate_rewrite_path` in
    // `pingap-config/src/common.rs`, which guards the config-file path — this
    // crate cannot depend on that one.
    if let Some(rewrite_path) = rewrite_path {
        if !rewrite_path.starts_with('/') {
            return Err(ApiError::BadRequest(
                "route rewrite path must start with '/'".to_string(),
            ));
        }
        if rewrite_path.len() > MAX_ROUTE_REWRITE_PATH_LEN {
            return Err(ApiError::BadRequest(format!(
                "route rewrite path must be at most \
                 {MAX_ROUTE_REWRITE_PATH_LEN} characters"
            )));
        }
        if let Some(bad) = rewrite_path.chars().find(|c| {
            matches!(c, '?' | '#') || c.is_whitespace() || c.is_control()
        }) {
            return Err(ApiError::BadRequest(format!(
                "route rewrite path must not contain '{bad}' (query, fragment, \
                 whitespace and control characters are not allowed)"
            )));
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
    Ok(())
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
        let check = |match_type: &str, strip: bool, rewrite: Option<&str>| {
            validate_route("api", match_type, "/api", None, strip, rewrite)
                .map_err(|err| (err.code(), err.to_string()))
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

        // The length ceiling matches the data plane's (2048 bytes).
        let at_limit = format!("/{}", "a".repeat(2047));
        assert_eq!(check("prefix", false, Some(&at_limit)), Ok(()));
        let too_long = format!("/{}", "a".repeat(2048));
        assert!(check("prefix", false, Some(&too_long)).is_err());

        // Stripping needs a prefix to strip: exact and regex routes are
        // rejected rather than silently forwarding the full path.
        for match_type in ["exact", "regex"] {
            let err = check(match_type, true, None).expect_err("no prefix");
            assert_eq!("bad_request", err.0);
            assert!(err.1.contains("needs a prefix route"));
        }
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
    }
}
