//! Entities describing a protected site: the site row itself, its origin
//! servers and its TLS material.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Lifecycle of a site.
pub mod site_status {
    pub const ACTIVE: &str = "active";
    pub const PAUSED: &str = "paused";
    pub const PENDING: &str = "pending";

    pub fn is_valid(status: &str) -> bool {
        matches!(status, ACTIVE | PAUSED | PENDING)
    }
}

/// Forwarded headers accepted in `sites.trusted_header`.
pub mod trusted_header {
    pub const X_FORWARDED_FOR: &str = "x-forwarded-for";
    pub const X_REAL_IP: &str = "x-real-ip";
    pub const CF_CONNECTING_IP: &str = "cf-connecting-ip";
    pub const TRUE_CLIENT_IP: &str = "true-client-ip";

    pub const ALL: [&str; 4] =
        [X_FORWARDED_FOR, X_REAL_IP, CF_CONNECTING_IP, TRUE_CLIENT_IP];

    pub const DEFAULT: &str = X_FORWARDED_FOR;

    pub fn is_valid(value: &str) -> bool {
        ALL.contains(&value)
    }
}

/// `sites` — one protected site, served on one or more hostnames.
pub mod sites {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "sites")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub name: String,
        /// The primary hostname; it is the one certificate issuance and
        /// display default to.
        #[sea_orm(unique)]
        pub domain: String,
        /// Extra hostnames served by the same site, each with the same
        /// routing, WAF and cache configuration as `domain`.
        pub alternate_domains: Vec<String>,
        pub status: String,
        pub plan: String,
        /// Disk budget, in MiB, the agents may use for this site's cache.
        pub cache_quota_mb: i32,
        /// Site-level single-file cache cap, in MiB; `None` follows the
        /// global `cache_settings.max_file_size_mb`. Validated against the
        /// global ceiling at write time and clamped in the data plane.
        pub cache_max_file_size_mb: Option<i32>,
        /// Per-content-type single-file caps, in MiB, keyed by
        /// `html/css/js/image/font/media/other`; a missing key follows
        /// `cache_max_file_size_mb` (then the global ceiling). `None` when
        /// the site does not override any type.
        pub cache_type_limits_mb: Option<Json>,
        /// Extension-based cache type policy (five content families with
        /// toggle, TTLs and extension lists). `None` when unconfigured.
        pub cache_type_policy: Option<Json>,
        /// The site sits behind a CDN / reverse proxy: security features key
        /// on the forwarded-header client IP, not the direct TCP peer.
        pub trust_proxy_headers: bool,
        /// Lower-case forwarded header the client IP is read from.
        pub trusted_header: String,
        /// Take the last XFF entry (nearest proxy) instead of the first one,
        /// which the client can spoof.
        pub trust_last_hop: bool,
        /// Behaviour while the control plane is unreachable and the host has
        /// no synced rule bundle: `inherit` (follow the global default),
        /// `open` (keep proxying) or `closed` (answer 503).
        pub failover_policy: String,
        /// CIDR ranges of proxies allowed to influence the resolved client
        /// IP. Only connections from these peers read the forwarded header;
        /// an empty list trusts nothing.
        pub trusted_proxy_ranges: Vec<String>,
        /// IP groups whose ranges are merged into `trusted_proxy_ranges`
        /// when the agent configuration is built. Lets operators track
        /// vendor-published proxy networks (e.g. the built-in Cloudflare
        /// subscription) instead of pasting CIDRs by hand.
        pub trusted_proxy_group_ids: Vec<Uuid>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `site_upstreams` — origin servers the agents load balance across.
pub mod site_upstreams {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "site_upstreams")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub pool_id: Uuid,
        pub name: String,
        pub address: String,
        pub weight: i32,
        pub tls: bool,
        pub health_status: String,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `site_upstream_pools` — a group of origin nodes sharing one
/// load-balancing algorithm and origin TLS setting.
pub mod site_upstream_pools {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "site_upstream_pools")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub name: String,
        /// pingap LB spec: `round_robin` or `hash:<type>[:<key>]`.
        pub lb_algorithm: String,
        /// Non-empty enables TLS to the origin and sets the SNI.
        pub sni: Option<String>,
        /// `None` keeps the proxy default (verification on).
        pub verify_cert: Option<bool>,
        /// Active HTTP health check for this pool's nodes; `false` leaves the
        /// agent's data plane on its default bare TCP probe.
        pub health_check_enabled: bool,
        /// Probe path; always starts with `/`.
        pub health_check_path: String,
        /// Seconds between probe rounds. The data plane's scheduler aligns
        /// this to 10s grid steps, so values are effectively rounded up.
        pub health_check_interval_seconds: i32,
        /// Probe connect/read timeout in milliseconds.
        pub health_check_timeout_ms: i32,
        /// Consecutive failed probes before a node is marked unhealthy.
        pub health_check_unhealthy_threshold: i32,
        /// Consecutive successful probes before a node is marked healthy.
        pub health_check_healthy_threshold: i32,
        pub is_default: bool,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Route match types accepted in `site_routes.match_type`.
pub mod route_match_type {
    pub const PREFIX: &str = "prefix";
    pub const EXACT: &str = "exact";
    pub const REGEX: &str = "regex";

    pub fn is_valid(value: &str) -> bool {
        matches!(value, PREFIX | EXACT | REGEX)
    }
}

/// `site_routes` — maps request paths to an origin pool.
pub mod site_routes {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "site_routes")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub name: String,
        pub match_type: String,
        pub path: String,
        /// Manual location weight; `None` uses pingap's auto weight.
        pub priority: Option<i32>,
        pub enabled: bool,
        pub pool_id: Uuid,
        /// IP group whose ranges gate this route; `None` matches every client.
        pub ip_group_id: Option<Uuid>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `site_ssl` — uploaded certificate material or ACME settings.
///
/// `key_pem` is a private key; it is serialised nowhere (the API strips it) and
/// only leaves the control plane inside the gRPC config pushed to agents.
pub mod site_ssl {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "site_ssl")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(unique)]
        pub site_id: Uuid,
        pub cert_pem: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub key_pem: Option<String>,
        pub issuer: Option<String>,
        pub domain: String,
        pub expires_at: Option<DateTimeUtc>,
        pub auto_renew: bool,
        pub acme_email: Option<String>,
        pub acme_challenge_type: Option<String>,
        pub acme_dns_provider: Option<String>,
        #[sea_orm(column_type = "JsonBinary")]
        pub acme_dns_config: Option<Json>,
        /// Whether the domain is served over HTTPS at all.
        pub https_enabled: bool,
        pub min_tls_version: String,
        /// `None` means "up to whatever the agent's TLS stack supports".
        pub max_tls_version: Option<String>,
        /// Fall back to a generated certificate when none is configured.
        pub self_signed: bool,
        /// Certificate picked from `site_certificates` for this site.
        pub certificate_id: Option<Uuid>,
        pub mtls_enabled: bool,
        #[sea_orm(column_type = "Text")]
        pub mtls_client_ca: Option<String>,
        /// Organization a presented client certificate must carry; `None`
        /// accepts any organization.
        pub mtls_organization: Option<String>,
        /// Whether a request without a client certificate is rejected.
        pub mtls_require_client_cert: bool,
        pub hsts_enabled: bool,
        pub hsts_max_age: i32,
        pub always_use_https: bool,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// ACME challenge types accepted in `site_ssl.acme_challenge_type`.
pub mod acme_challenge {
    pub const HTTP_01: &str = "http-01";
    pub const DNS_01: &str = "dns-01";

    pub fn is_valid(challenge: &str) -> bool {
        matches!(challenge, HTTP_01 | DNS_01)
    }
}

/// TLS protocol versions accepted in `site_ssl.min_tls_version` and
/// `site_ssl.max_tls_version`.
pub mod tls_version {
    pub const TLS_10: &str = "1.0";
    pub const TLS_11: &str = "1.1";
    pub const TLS_12: &str = "1.2";
    pub const TLS_13: &str = "1.3";

    pub const ALL: [&str; 4] = [TLS_10, TLS_11, TLS_12, TLS_13];

    pub fn is_valid(value: &str) -> bool {
        ALL.contains(&value)
    }

    /// Position in `ALL`, used to check that a lower bound is not above the
    /// upper bound.
    pub fn rank(value: &str) -> Option<usize> {
        ALL.iter().position(|item| *item == value)
    }

    /// Canonicalises `TLSv1.2`, `tls1.2` and `1.2` to `1.2`.
    pub fn normalise(value: &str) -> Option<String> {
        let lower = value.trim().to_ascii_lowercase();
        let stripped = lower
            .strip_prefix("tlsv")
            .or_else(|| lower.strip_prefix("tls"))
            .unwrap_or(&lower);
        is_valid(stripped).then(|| stripped.to_string())
    }
}
