//! Translates database rows into the protocol messages agents consume.
//!
//! Everything the agents need — WAF rules, rate limits, cache policy, upstreams
//! and TLS material — is assembled here, which keeps the gRPC service layer free
//! of SQL and lets the REST API reuse the exact same builder when it pushes a
//! configuration update to a connected agent.

use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use pingwaf_proto::control_plane::{
    AiBotPolicy, AiCrawlConfig, BasicAuthConfig, BasicAuthCredential,
    BotProtectionConfig, CacheRule, CacheTypeCategory, CacheTypePolicy,
    ChallengeConfig, CustomErrorPage, FailoverMode, GeoConfig,
    GlobalCacheSettings, HealthCheckConfig, IpAccessRule, OidcAccessRule,
    OidcConfig, OidcHeaderClaim, RateLimitRule, ResponseReplaceConfig,
    ResponseReplaceRule, RewriteOperation, RewriteRule, RouteConfig,
    RuleBundle, RuleOverride, Site, SiteCacheSettings, SiteConfig, SitePolicy,
    SslConfig, UpstreamConfig, UpstreamPeer, WafConfig, WafRule,
};
use prost::Message;
use prost_types::Timestamp;
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait,
};
use uuid::Uuid;

use crate::api::challenge::challenge_level;
use crate::api::ip_rules::ip_action;
use crate::api::site_basic_auth as site_basic_auth_api;
use crate::api::site_oidc as site_oidc_api;
use crate::api::waf_settings::{
    clamp_body_stage_timeout_secs, DEFAULT_BODY_STAGE_TIMEOUT_SECS,
    MAX_BODY_STAGE_TIMEOUT_SECS,
};
use crate::models::{
    acme_challenge, action, bot_protection, cache_rules, challenge_settings,
    characteristic, client_cert_status, defense_settings, error_pages,
    geo_rules, ip_access_rules, ip_group_sites, ip_groups, mode,
    mtls_client_certificate, oidc_provider, rate_limit_rules, rewrite_rules,
    rule, rule_groups, site, site_basic_auth, site_certificates, site_oidc,
    site_oidc as site_oidc_model, site_routes, site_ssl, site_status,
    site_upstream_pools, site_upstreams, waf_settings,
};
use crate::pki::mtls::normalise_fingerprint;

/// `pingwaf.WafMode` values from control_plane.proto.
///
/// The numbers are spelled out instead of referencing the generated enum
/// variants: prost strips a value prefix that matches the enum name, and the
/// control plane should not depend on that naming rule.
// `off` is never *derived* any more (a site without a posture row floors at
// monitor); the value stays declared so the enum is complete and the tests can
// pin that only an explicit settings row produces it.
#[allow(dead_code)]
const WAF_MODE_OFF: i32 = 0;
const WAF_MODE_MONITOR: i32 = 1;
const WAF_MODE_BLOCK: i32 = 2;

/// Converts a `DateTime<Utc>` into the protocol's timestamp.
pub fn to_timestamp(value: DateTime<Utc>) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: value.timestamp(),
        nanos: value.timestamp_subsec_nanos() as i32,
    })
}

/// `to_timestamp` for "now".
pub fn now_timestamp() -> Option<Timestamp> {
    to_timestamp(Utc::now())
}

/// Converts a protocol timestamp back into a `DateTime<Utc>`, defaulting to the
/// current time when the agent omitted it.
pub fn from_timestamp(value: Option<&Timestamp>) -> DateTime<Utc> {
    match value {
        Some(ts) => Utc
            .timestamp_opt(ts.seconds, ts.nanos.max(0) as u32)
            .single()
            .unwrap_or_else(Utc::now),
        None => Utc::now(),
    }
}

/// Maps the persisted site status onto `pingwaf.SiteStatusEnum`.
///
/// The numeric values are used directly because prost's variant naming for
/// prefixed enum entries is not something the control plane should depend on.
pub fn site_status_proto(status: &str) -> i32 {
    match status {
        site_status::ACTIVE => 0,  // SITE_STATUS_ACTIVE
        site_status::PAUSED => 1,  // SITE_STATUS_PAUSED
        site_status::PENDING => 2, // SITE_STATUS_PENDING
        _ => 0,
    }
}

/// Maps the persisted ACME challenge type onto `pingwaf.AcmeChallengeType`.
pub fn acme_challenge_proto(challenge: Option<&str>) -> i32 {
    match challenge {
        Some(acme_challenge::DNS_01) => 1, // ACME_DNS_01
        _ => 0,                            // ACME_HTTP_01
    }
}

/// FNV-1a over 64 bits; used to fingerprint a configuration without pulling in
/// a hashing crate.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Stable 16-hex-character fingerprint of any protobuf message.
pub fn fingerprint<T: Message>(message: &T) -> String {
    let mut buf = Vec::with_capacity(message.encoded_len());
    // `encode` only fails when the buffer is too small, which cannot happen for
    // a `Vec` sized with `encoded_len()`.
    let _ = message.encode(&mut buf);
    format!("{:016x}", fnv1a64(&buf))
}

/// Flattens a JSON object into the `map<string, string>` shape the protocol
/// expects; non-object or non-string values are stringified.
fn json_to_string_map(
    value: &Option<serde_json::Value>,
) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(serde_json::Value::Object(object)) = value {
        for (key, raw) in object {
            let text = match raw {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            map.insert(key.clone(), text);
        }
    }
    map
}

/// Loads the WAF rule rows of a site, ordered by priority then name so that the
/// fingerprint does not change between otherwise identical configurations.
async fn load_rules(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<rule::Model>, sea_orm::DbErr> {
    rule::Entity::find()
        .filter(rule::Column::SiteId.eq(site_id))
        .order_by_asc(rule::Column::Priority)
        .order_by_asc(rule::Column::Name)
        .all(db)
        .await
}

async fn load_rule_groups(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<rule_groups::Model>, sea_orm::DbErr> {
    rule_groups::Entity::find()
        .filter(rule_groups::Column::SiteId.eq(site_id))
        .order_by_asc(rule_groups::Column::Priority)
        .all(db)
        .await
}

async fn load_rate_limits(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<rate_limit_rules::Model>, sea_orm::DbErr> {
    rate_limit_rules::Entity::find()
        .filter(rate_limit_rules::Column::SiteId.eq(site_id))
        .order_by_asc(rate_limit_rules::Column::Priority)
        .all(db)
        .await
}

async fn load_cache_rules(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<cache_rules::Model>, sea_orm::DbErr> {
    cache_rules::Entity::find()
        .filter(cache_rules::Column::SiteId.eq(site_id))
        .all(db)
        .await
}

async fn load_upstreams(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<site_upstreams::Model>, sea_orm::DbErr> {
    site_upstreams::Entity::find()
        .filter(site_upstreams::Column::SiteId.eq(site_id))
        .order_by_desc(site_upstreams::Column::Weight)
        .all(db)
        .await
}

async fn load_pools(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<site_upstream_pools::Model>, sea_orm::DbErr> {
    site_upstream_pools::Entity::find()
        .filter(site_upstream_pools::Column::SiteId.eq(site_id))
        .order_by_desc(site_upstream_pools::Column::IsDefault)
        .order_by_asc(site_upstream_pools::Column::CreatedAt)
        .all(db)
        .await
}

async fn load_routes(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<site_routes::Model>, sea_orm::DbErr> {
    site_routes::Entity::find()
        .filter(site_routes::Column::SiteId.eq(site_id))
        .order_by_desc(site_routes::Column::Priority)
        .order_by_asc(site_routes::Column::CreatedAt)
        .all(db)
        .await
}

async fn load_ssl(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<site_ssl::Model>, sea_orm::DbErr> {
    site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

async fn load_certificates(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<site_certificates::Model>, sea_orm::DbErr> {
    site_certificates::Entity::find()
        .filter(site_certificates::Column::SiteId.eq(site_id))
        .order_by_desc(site_certificates::Column::UpdatedAt)
        .all(db)
        .await
}

async fn load_ip_access_rules(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<ip_access_rules::Model>, sea_orm::DbErr> {
    ip_access_rules::Entity::find()
        .filter(ip_access_rules::Column::SiteId.eq(site_id))
        .filter(ip_access_rules::Column::Enabled.eq(true))
        .order_by_asc(ip_access_rules::Column::Priority)
        .all(db)
        .await
}

/// Loads enabled IP groups that apply to a site: all global groups plus any
/// non-global group explicitly linked to the site via `ip_group_sites`.
async fn load_ip_groups(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<ip_groups::Model>, sea_orm::DbErr> {
    let linked_ids = ip_group_sites::Entity::find()
        .filter(ip_group_sites::Column::SiteId.eq(site_id))
        .select_only()
        .column(ip_group_sites::Column::IpGroupId)
        .into_query();

    ip_groups::Entity::find()
        .filter(ip_groups::Column::Enabled.eq(true))
        .filter(
            ip_groups::Column::IsGlobal
                .eq(true)
                .or(ip_groups::Column::Id.in_subquery(linked_ids)),
        )
        .order_by_asc(ip_groups::Column::Name)
        .all(db)
        .await
}

/// Loads the enabled IP groups referenced by the given access rules.
///
/// Group-backed rules expand against these rows at bundle time, so a group
/// update reaches agents without touching the rules themselves.
async fn load_referenced_groups(
    db: &DatabaseConnection,
    rules: &[ip_access_rules::Model],
) -> Result<HashMap<Uuid, ip_groups::Model>, sea_orm::DbErr> {
    let ids: Vec<Uuid> = rules.iter().filter_map(|r| r.group_id).collect();
    load_enabled_groups(db, ids).await
}

/// Loads the enabled IP groups gating the given routes. A group that is
/// missing or disabled expands to nothing, which drops the route from the
/// pushed config — the API refuses such writes, so this only happens after an
/// out-of-band change.
async fn load_route_groups(
    db: &DatabaseConnection,
    routes: &[site_routes::Model],
) -> Result<HashMap<Uuid, ip_groups::Model>, sea_orm::DbErr> {
    let ids: Vec<Uuid> = routes.iter().filter_map(|r| r.ip_group_id).collect();
    load_enabled_groups(db, ids).await
}

async fn load_enabled_groups(
    db: &DatabaseConnection,
    ids: Vec<Uuid>,
) -> Result<HashMap<Uuid, ip_groups::Model>, sea_orm::DbErr> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = ip_groups::Entity::find()
        .filter(ip_groups::Column::Enabled.eq(true))
        .filter(ip_groups::Column::Id.is_in(ids))
        .all(db)
        .await?;
    Ok(rows.into_iter().map(|g| (g.id, g)).collect())
}

async fn load_geo_rules(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<geo_rules::Model>, sea_orm::DbErr> {
    geo_rules::Entity::find()
        .filter(geo_rules::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

async fn load_challenge_settings(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<challenge_settings::Model>, sea_orm::DbErr> {
    challenge_settings::Entity::find()
        .filter(challenge_settings::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

async fn load_waf_settings(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<waf_settings::Model>, sea_orm::DbErr> {
    waf_settings::Entity::find()
        .filter(waf_settings::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

async fn load_basic_auth(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<site_basic_auth::Model>, sea_orm::DbErr> {
    site_basic_auth::Entity::find()
        .filter(site_basic_auth::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

async fn load_oidc(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<site_oidc::Model>, sea_orm::DbErr> {
    site_oidc::Entity::find()
        .filter(site_oidc::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

/// The site's gate together with the provider it points at.
///
/// Two reads rather than a join: the provider is a single row by primary key
/// and this runs once per site per config push, so the second query is
/// cheaper than the machinery a join would add to the entity.
async fn load_oidc_with_provider(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<
    (Option<site_oidc::Model>, Option<oidc_provider::Model>),
    sea_orm::DbErr,
> {
    let row = load_oidc(db, site_id).await?;
    let provider = match row.as_ref().and_then(|row| row.provider_id) {
        Some(provider_id) => {
            oidc_provider::Entity::find_by_id(provider_id)
                .one(db)
                .await?
        },
        None => None,
    };
    Ok((row, provider))
}

async fn load_rewrite_rules(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Vec<rewrite_rules::Model>, sea_orm::DbErr> {
    rewrite_rules::Entity::find()
        .filter(rewrite_rules::Column::SiteId.eq(site_id))
        .filter(rewrite_rules::Column::Enabled.eq(true))
        .order_by_asc(rewrite_rules::Column::Priority)
        .all(db)
        .await
}

/// Loads the enabled global error pages.
///
/// Error pages are deployment-wide, so every site's bundle carries the same
/// list; the data plane picks the template matching the status code it is about
/// to return.
async fn load_error_pages(
    db: &DatabaseConnection,
) -> Result<Vec<error_pages::Model>, sea_orm::DbErr> {
    error_pages::Entity::find()
        .filter(error_pages::Column::Enabled.eq(true))
        .order_by_asc(error_pages::Column::StatusCode)
        .all(db)
        .await
}

/// Turns a stored WAF rule into its protocol representation.
pub fn rule_to_proto(row: &rule::Model) -> WafRule {
    WafRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        description: row.description.clone().unwrap_or_default(),
        expression: row.expression.clone(),
        action: action::to_proto(&row.action),
        severity: row.severity.max(0) as u32,
        tags: row.tags.clone(),
        enabled: row.enabled,
        mode: mode::to_proto(&row.mode),
        priority: row.priority.max(0) as u32,
    }
}

fn rate_limit_to_proto(row: &rate_limit_rules::Model) -> RateLimitRule {
    RateLimitRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        expression: row.expression.clone(),
        characteristics: row
            .characteristics
            .iter()
            .map(|value| characteristic::to_proto(value))
            .collect(),
        characteristic_params: row
            .characteristics
            .iter()
            .map(|value| characteristic::to_param(value))
            .collect(),
        period_seconds: row.period_seconds.max(0) as u32,
        threshold: row.threshold.max(0) as u32,
        action: action::to_proto(&row.action),
        mitigation_timeout_seconds: row.mitigation_timeout_seconds.max(0)
            as u32,
        enabled: row.enabled,
        priority: row.priority.max(0) as u32,
    }
}

/// Turns a stored cache rule into its protocol representation.
///
/// `site_quota_mb` is the disk budget the agent enforces for the site; it is
/// carried on every rule because the budget is site-wide, and the agent applies
/// what it reads per hostname.
fn cache_rule_to_proto(
    row: &cache_rules::Model,
    site_quota_mb: i32,
) -> CacheRule {
    CacheRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        match_expression: row.match_expression.clone(),
        edge_ttl_seconds: row.edge_ttl_seconds.max(0) as u32,
        browser_ttl_seconds: row.browser_ttl_seconds.max(0) as u32,
        disk_quota_mb: site_quota_mb.max(0) as u32,
        cache_eligible: row.cache_eligible,
        cache_key_headers: Vec::new(),
        respect_origin_headers: row.respect_origin,
        stale_while_revalidate_seconds: 0,
        enabled: row.enabled,
    }
}

/// Maps the site's cache-limit columns onto the proto message; `None` when
/// the site overrides nothing (no cap, no type map), which keeps old bundles
/// byte-identical.
fn site_cache_settings_to_proto(
    site: &site::Model,
) -> Option<SiteCacheSettings> {
    let type_limits: Option<std::collections::HashMap<String, u32>> = site
        .cache_type_limits_mb
        .as_ref()
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .map(|limits: std::collections::HashMap<String, i32>| {
            limits
                .into_iter()
                .map(|(key, value)| (key, value.max(0) as u32))
                .collect()
        });
    let type_policy: Option<CacheTypePolicy> = site
        .cache_type_policy
        .as_ref()
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .map(cache_type_policy_to_proto);
    if site.cache_max_file_size_mb.is_none()
        && type_limits.is_none()
        && type_policy.is_none()
    {
        return None;
    }
    Some(SiteCacheSettings {
        max_file_size_mb: site
            .cache_max_file_size_mb
            .map(|value| value.max(0) as u32),
        type_max_file_size_mb: type_limits.unwrap_or_default(),
        type_policy,
    })
}

/// Converts the stored policy JSON into its proto form. `None` categories
/// (a partial policy written by an older writer) are skipped — the data
/// plane then leaves that family unmanaged.
fn cache_type_policy_to_proto(
    policy: crate::api::cache::CacheTypePolicy,
) -> CacheTypePolicy {
    let category =
        |c: crate::api::cache::CacheTypeCategory| CacheTypeCategory {
            enabled: Some(c.enabled),
            edge_ttl_seconds: Some(c.edge_ttl_seconds),
            browser_ttl_seconds: Some(c.browser_ttl_seconds),
            extensions: c
                .extensions
                .into_iter()
                .map(|extension| extension.to_lowercase())
                .collect(),
        };
    CacheTypePolicy {
        web_assets: Some(category(policy.web_assets)),
        image: Some(category(policy.image)),
        media: Some(category(policy.media)),
        other: Some(category(policy.other)),
        html: Some(category(policy.html)),
    }
}

fn ssl_to_proto(
    row: &site_ssl::Model,
    certs: &[site_certificates::Model],
    mtls: &MtlsPush,
) -> SslConfig {
    // The posture row selects a certificate but does not copy its material:
    // the PEM of an uploaded certificate and every ACME setting (email,
    // challenge type, DNS provider config) live on the `site_certificates`
    // row only, so they are backfilled here for the agent.
    let selected = row
        .certificate_id
        .and_then(|id| certs.iter().find(|cert| cert.id == id));
    let uploaded_pem = row.cert_pem.as_deref().is_some_and(|p| !p.is_empty());
    let cert_pem = if uploaded_pem {
        row.cert_pem.clone().unwrap_or_default()
    } else {
        selected
            .and_then(|cert| cert.cert_pem.clone())
            .unwrap_or_default()
    };
    let uploaded_key = row.key_pem.as_deref().is_some_and(|p| !p.is_empty());
    let key_pem = if uploaded_key {
        row.key_pem.clone().unwrap_or_default()
    } else {
        selected
            .and_then(|cert| cert.key_pem.clone())
            .unwrap_or_default()
    };
    let acme_email = row
        .acme_email
        .clone()
        .or_else(|| selected.and_then(|cert| cert.acme_email.clone()))
        .unwrap_or_default();
    let auto_renew =
        row.auto_renew || selected.is_some_and(|cert| cert.auto_renew);
    let acme_enabled = auto_renew && !acme_email.is_empty();
    let acme_challenge_type = acme_challenge_proto(
        row.acme_challenge_type.as_deref().or_else(|| {
            selected
                .as_ref()
                .map(|cert| cert.acme_challenge_type.as_str())
        }),
    );
    let acme_dns_provider = row
        .acme_dns_provider
        .clone()
        .or_else(|| selected.and_then(|cert| cert.acme_dns_provider.clone()))
        .unwrap_or_default();
    let acme_dns_config =
        json_to_string_map(&row.acme_dns_config.clone().or_else(|| {
            selected.and_then(|cert| cert.acme_dns_config.clone())
        }));
    let certificate_id = row
        .certificate_id
        .or(selected.map(|cert| cert.id))
        .map(|id| id.to_string())
        .unwrap_or_default();
    SslConfig {
        cert_pem,
        key_pem,
        acme_enabled,
        acme_email,
        acme_challenge_type,
        acme_dns_provider,
        acme_dns_config,
        min_tls_version: row.min_tls_version.clone(),
        hsts_enabled: row.hsts_enabled,
        hsts_max_age: row.hsts_max_age.max(0) as u32,
        always_use_https: row.always_use_https,
        enabled: row.https_enabled,
        max_tls_version: row.max_tls_version.clone().unwrap_or_default(),
        self_signed: row.self_signed,
        mtls_enabled: row.mtls_enabled,
        mtls_client_ca: row.mtls_client_ca.clone().unwrap_or_default(),
        certificate_id,
        // Revocations and the expected organization come from the managed-CA
        // tables loaded by the caller.
        mtls_revoked_fingerprints: mtls.revoked_fingerprints.clone(),
        mtls_organization: row.mtls_organization.clone().unwrap_or_default(),
        // Turning mTLS on means clients must present a certificate.
        mtls_require_client_cert: row.mtls_enabled
            && row.mtls_require_client_cert,
        http1_enabled: Some(row.http1_enabled),
        http2_enabled: Some(row.http2_enabled),
    }
}

/// The mTLS material a site adds to the pushed configuration that is not stored
/// on `site_ssl`: the fingerprints the edge rejects.
///
/// The trust anchor itself travels as `SslConfig.mtls_client_ca`; the edge
/// unions the anchors of every mTLS site into the shared TLS listener.
#[derive(Debug, Default, Clone)]
pub struct MtlsPush {
    pub revoked_fingerprints: Vec<String>,
}

/// Loads the mTLS material pushed to agents for one site.
///
/// Only revoked certificates are pushed: the edge compares the fingerprint of
/// whatever the client presents against this list, so it stays small.
async fn load_mtls(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<MtlsPush, sea_orm::DbErr> {
    let revoked = mtls_client_certificate::Entity::find()
        .filter(mtls_client_certificate::Column::SiteId.eq(site_id))
        .filter(
            mtls_client_certificate::Column::Status
                .eq(client_cert_status::REVOKED),
        )
        .all(db)
        .await?;
    Ok(MtlsPush {
        revoked_fingerprints: revoked
            .into_iter()
            .map(|row| normalise_fingerprint(&row.fingerprint_sha256))
            .collect(),
    })
}

/// Turns origin pools into one `UpstreamConfig` per pool.
///
/// Pools without nodes are skipped: an empty upstream would make the agent
/// build a proxy with no peers to send traffic to.
fn pools_to_proto(
    pools: &[site_upstream_pools::Model],
    upstreams: &[site_upstreams::Model],
    site_default: Option<bool>,
) -> Vec<UpstreamConfig> {
    let mut configs = Vec::with_capacity(pools.len());
    for pool in pools {
        let peers: Vec<UpstreamPeer> = upstreams
            .iter()
            .filter(|row| row.pool_id == pool.id)
            .map(|row| UpstreamPeer {
                address: row.address.clone(),
                weight: row.weight.max(0) as u32,
                tls: row.tls,
            })
            .collect();
        if peers.is_empty() {
            continue;
        }
        // The agent synthesizes the data-plane probe URL from this message;
        // stored values are clamped so a bad row can never produce a
        // zero-frequency or zero-timeout probe.
        let health_check = if pool.health_check_enabled {
            Some(HealthCheckConfig {
                enabled: true,
                path: if pool.health_check_path.starts_with('/') {
                    pool.health_check_path.clone()
                } else {
                    "/".to_string()
                },
                interval_seconds: pool.health_check_interval_seconds.max(1)
                    as u32,
                timeout_ms: pool.health_check_timeout_ms.max(1) as u32,
                unhealthy_threshold: pool
                    .health_check_unhealthy_threshold
                    .max(1) as u32,
                healthy_threshold: pool.health_check_healthy_threshold.max(1)
                    as u32,
            })
        } else {
            None
        };
        configs.push(UpstreamConfig {
            name: pool.name.clone(),
            peers,
            // LB_ROUND_ROBIN — the legacy enum, superseded by `algo`.
            algorithm: 0,
            health_check,
            connection_timeout_ms: 0,
            read_timeout_ms: 0,
            write_timeout_ms: 0,
            pool_id: pool.id.to_string(),
            algo: pool.lb_algorithm.clone(),
            sni: pool.sni.clone().unwrap_or_default(),
            // Three-level cascade, resolved top-down: the pool's own pin
            // wins; a pool without one takes the site-wide default; when
            // both are unset the wire value stays `NULL` and the agent
            // fills in the deployment-wide default from
            // `RuleBundle.origin_verify_cert`.
            verify_cert: pool.verify_cert.or(site_default),
            is_default: pool.is_default,
            // Passed through verbatim: the column carries the same three
            // values the data plane parses, and the CHECK constraint keeps
            // anything else out of the row.
            address_family: pool.address_family.clone(),
        });
    }
    configs
}

/// Turns stored routes into their protocol representation, dropping routes
/// that are disabled or point at a pool without nodes (the agent would have
/// no upstream to serve them with). The path is passed through verbatim; the
/// data plane adds the `=`/`~` marker pingap's location syntax expects.
///
/// A route gated on an IP group carries the group's ranges; a gate that no
/// longer resolves (group deleted or disabled behind the API's back) drops the
/// route rather than turning it into a match-everything location.
fn routes_to_proto(
    routes: &[site_routes::Model],
    pools: &[site_upstream_pools::Model],
    upstreams: &[site_upstreams::Model],
    groups: &HashMap<Uuid, ip_groups::Model>,
) -> Vec<RouteConfig> {
    let served: HashSet<Uuid> = pools
        .iter()
        .filter(|pool| upstreams.iter().any(|row| row.pool_id == pool.id))
        .map(|pool| pool.id)
        .collect();
    routes
        .iter()
        .filter(|route| route.enabled && served.contains(&route.pool_id))
        .filter_map(|route| {
            let ip_ranges = match route.ip_group_id {
                Some(group_id) => match groups.get(&group_id) {
                    Some(group) => group.ip_ranges.clone(),
                    None => {
                        tracing::warn!(
                            route = %route.id,
                            group = %group_id,
                            "route IP group is missing or disabled; route dropped",
                        );
                        return None;
                    },
                },
                None => Vec::new(),
            };
            Some(RouteConfig {
                id: route.id.to_string(),
                name: route.name.clone(),
                match_type: route.match_type.clone(),
                path: route.path.clone(),
                priority: route.priority,
                enabled: route.enabled,
                pool_id: route.pool_id.to_string(),
                ip_ranges,
                strip_prefix: route.strip_prefix,
                rewrite_path: route.rewrite_path.clone().unwrap_or_default(),
                upstream_host: route.upstream_host.clone().unwrap_or_default(),
            })
        })
        .collect()
}

/// Builds the site's WAF configuration from the enabled rules, merged with
/// the site's `waf_settings` posture row when present. A missing row keeps
/// the historical behavior: the mode is derived from the rules and the
/// paranoia level stays at the default.
///
/// The engine switch is explicit (`waf_settings.waf_enabled`, default on);
/// the evaluation mode and paranoia level come from the posture row's
/// explicit columns. The rule-derived mode is only the legacy fallback for
/// sites whose posture row has not been created yet — and that fallback
/// **floors at monitor**, never `off` (see [`waf_config_to_proto`]).
fn waf_config_to_proto(
    rules: &[WafRule],
    groups: &[rule_groups::Model],
    settings: Option<&waf_settings::Model>,
) -> WafConfig {
    let active: Vec<&WafRule> = rules.iter().filter(|r| r.enabled).collect();

    // A posture row is the only source of `off`: without one, a site lands on
    // `monitor` at worst. The old derivation fell through to `off` when no
    // enabled rule carried an explicit mode, which made an unconfigured site
    // *weaker than monitor* — the engine returned `Pass` before evaluating
    // anything, so not even the always-loaded managed ruleset produced an
    // event. `off` is an operator decision (the `mode` column or
    // `waf_enabled`), never something to infer from an empty rule list.
    // `block` still wins when a rule asks for it.
    let derived_mode = if active.iter().any(|r| r.mode == WAF_MODE_BLOCK) {
        WAF_MODE_BLOCK
    } else {
        WAF_MODE_MONITOR
    };
    let mode = settings
        .map(|s| mode::to_proto(&s.mode))
        .unwrap_or(derived_mode);

    let has_tag = |needle: &str| {
        active.iter().any(|rule| {
            rule.tags
                .iter()
                .any(|tag| tag.to_ascii_lowercase().contains(needle))
        })
    };

    let any_group_enabled =
        groups.is_empty() || groups.iter().any(|group| group.enabled);

    let (
        waf_enabled,
        advanced_mode,
        paranoia_level,
        monitor_categories,
        monitor_stacks,
        monitor_managed_rules,
        body_stage_timeout_secs,
    ) = settings
        .map(|s| {
            (
                s.waf_enabled,
                s.advanced_mode,
                s.paranoia_level,
                s.monitor_categories.clone(),
                s.monitor_stacks.clone(),
                s.monitor_managed_rules.clone(),
                // A row written before the column existed (or edited
                // out of band) can carry 0 or exceed the ceiling; clamp it
                // here as well so the data plane never receives a window
                // outside 1-30, whatever the row says.
                clamp_body_stage_timeout_secs(s.body_stage_timeout_secs),
            )
        })
        .unwrap_or_else(|| {
            (
                true,
                false,
                2,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                DEFAULT_BODY_STAGE_TIMEOUT_SECS,
            )
        });

    // The engine switch is explicit; rules only feed the mode fallback and
    // the per-category switches below.
    let enabled = waf_enabled && any_group_enabled;

    WafConfig {
        enabled,
        mode,
        // Detection sensitivity is a site-level setting; it is deliberately
        // decoupled from rule severity.
        paranoia_level: paranoia_level.clamp(1, 4) as u32,
        sqli_detection: has_tag("sqli") || has_tag("sql-injection"),
        xss_detection: has_tag("xss"),
        rce_detection: has_tag("rce") || has_tag("command-injection"),
        lfi_detection: has_tag("lfi") || has_tag("file-inclusion"),
        ssrf_detection: has_tag("ssrf"),
        bot_detection: has_tag("bot"),
        custom_rules: rules.to_vec(),
        // Built-in managed rules travel as overrides, not `custom_rules`: the
        // data plane always loads the managed set, so a built-in rule switched
        // to `off` (or disabled) must be carried as an explicit override or it
        // would keep being evaluated and logged on the agent. Only built-in
        // ids (`PINGWAF-*`) land here; custom rules keep their `custom_rules`
        // path and are filtered engine-side.
        managed_overrides: rules
            .iter()
            .filter(|r| {
                r.id.starts_with("PINGWAF-")
                    && (!r.enabled || r.mode == WAF_MODE_OFF)
            })
            .map(|r| RuleOverride {
                rule_id: r.id.clone(),
                // `enabled = false` is the minimal "off" expression; the
                // override carries no monitor downgrade (that stays on
                // `monitor_managed_rules`).
                ..Default::default()
            })
            .collect(),
        ml_enabled: false,
        ml_model_path: String::new(),
        ml_threshold: 0.0,
        anomaly_threshold: 0,
        advanced_mode,
        monitor_categories,
        monitor_stacks,
        monitor_managed_rules,
        // The body-withholding window is a site-level WAF setting, not a
        // downstream connection timeout: it bounds how long a body may be
        // held while it is being inspected, which the listener cannot vary
        // per host.
        body_stage_timeout_secs: body_stage_timeout_secs
            .clamp(1, MAX_BODY_STAGE_TIMEOUT_SECS)
            as u32,
    }
}

/// Converts a stored IP access rule into its protocol representation.
///
/// Group-backed rules expand to the referenced group's live ranges while
/// keeping the rule's own action and note; rules with neither a resolvable
/// group nor their own ranges are skipped (they would match nothing).
fn ip_access_rule_to_proto(
    row: &ip_access_rules::Model,
    groups: &HashMap<Uuid, ip_groups::Model>,
) -> Option<IpAccessRule> {
    let mut ip_ranges = row.ip_ranges.clone();
    if let Some(group) = row.group_id.and_then(|gid| groups.get(&gid)) {
        ip_ranges = group.ip_ranges.clone();
    } else if ip_ranges.is_empty() {
        return None;
    }
    Some(IpAccessRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        ip_ranges,
        action: ip_action::to_proto(&row.action),
        note: row.note.clone().unwrap_or_default(),
        enabled: row.enabled,
    })
}

/// Converts an IP group row into the same `IpAccessRule` proto message so that
/// agents can apply group-level allow/block lists alongside per-site rules.
fn ip_group_to_proto(row: &ip_groups::Model) -> IpAccessRule {
    IpAccessRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        ip_ranges: row.ip_ranges.clone(),
        action: ip_action::to_proto(&row.action),
        note: row.description.clone().unwrap_or_default(),
        enabled: row.enabled,
    }
}

/// Converts stored geo rules into the protocol representation.
fn geo_to_proto(row: Option<&geo_rules::Model>) -> GeoConfig {
    match row {
        Some(g) => GeoConfig {
            enabled: g.enabled,
            blocked_countries: if g.mode == "block_list" {
                g.countries.clone()
            } else {
                Vec::new()
            },
            allowed_countries: if g.mode == "allow_list" {
                g.countries.clone()
            } else {
                Vec::new()
            },
            blocked_asns: g.blocked_asns.clone(),
            block_unknown: g.block_unknown,
            action: action::to_proto(&g.action),
        },
        None => GeoConfig {
            enabled: false,
            blocked_countries: Vec::new(),
            allowed_countries: Vec::new(),
            blocked_asns: Vec::new(),
            block_unknown: false,
            action: action::to_proto(action::BLOCK),
        },
    }
}

/// Converts stored challenge settings into the protocol representation.
fn challenge_to_proto(
    row: Option<&challenge_settings::Model>,
) -> ChallengeConfig {
    match row {
        Some(c) => ChallengeConfig {
            enabled: c.enabled,
            under_attack_mode: c.under_attack_mode,
            default_level: challenge_level::to_proto(&c.default_level),
            clearance_duration_seconds: c.clearance_duration_secs.max(0) as u32,
            exempt_paths: c.exempt_paths.clone(),
            request_threshold: c.rate_threshold.max(0) as u32,
            browser_integrity_check: c.browser_integrity_check,
            tls_fingerprint_check: c.tls_fingerprint_check,
        },
        None => ChallengeConfig {
            enabled: false,
            under_attack_mode: false,
            default_level: 0,
            clearance_duration_seconds: 0,
            exempt_paths: Vec::new(),
            request_threshold: 0,
            browser_integrity_check: false,
            tls_fingerprint_check: false,
        },
    }
}

/// Converts the site's basic auth row into the protocol representation.
///
/// The agent receives `Authorization` payloads the way a client would send
/// them — `Basic <base64(user:password)>` — so the password never has to be
/// encoded on the request path. A row that cannot be decoded ships disabled
/// rather than failing the whole bundle: an unreadable credential list must
/// not lock the site out.
fn basic_auth_to_proto(
    row: Option<&site_basic_auth::Model>,
) -> Option<BasicAuthConfig> {
    let row = row?;
    let credentials = match site_basic_auth_api::stored_credentials(row) {
        Ok(credentials) => credentials,
        Err(error) => {
            tracing::warn!(
                site_id = %row.site_id,
                error = %error,
                "basic auth credentials are unreadable; shipping the gate disabled"
            );
            Vec::new()
        },
    };
    let credentials: Vec<BasicAuthCredential> = credentials
        .iter()
        .map(|credential| BasicAuthCredential {
            username: credential.username.clone(),
            authorization: BASE64_STANDARD.encode(format!(
                "{}:{}",
                credential.username, credential.password
            )),
        })
        .collect();
    Some(BasicAuthConfig {
        enabled: row.enabled && !credentials.is_empty(),
        realm: row.realm.clone(),
        credentials,
        delay_seconds: row.delay_seconds.max(0) as u32,
        hide_credentials: row.hide_credentials,
    })
}

/// Reads the site's OIDC settings into their protocol shape.
///
/// A site without a row ships `None` rather than a disabled `OidcConfig`: the
/// bundle is fingerprinted over its own encoding, so emitting a defaulted
/// message for every site would change the hash of every site that has never
/// touched OIDC and push a full re-sync on upgrade. `enabled` is passed through
/// as stored — the API refuses to enable a gate with missing credentials, so
/// there is no second opinion to give here.
///
/// A row whose JSON columns cannot be decoded ships disabled with a warning,
/// matching `basic_auth_to_proto`: unreadable settings must not fail the whole
/// bundle and lock the site out.
fn oidc_to_proto(
    row: Option<&site_oidc::Model>,
    provider: Option<&oidc_provider::Model>,
) -> Option<OidcConfig> {
    let row = row?;
    let disabled = || {
        Some(OidcConfig {
            enabled: false,
            ..OidcConfig::default()
        })
    };
    // Which ways in the site offers. An unknown value is a row a newer build
    // wrote; refusing to guess is the safe reading, and it ships disabled.
    let auth_mode = match site_oidc_model::AuthMode::parse(&row.auth_mode) {
        Some(mode) => mode,
        None => {
            tracing::warn!(
                site_id = %row.site_id,
                auth_mode = %row.auth_mode,
                "oidc auth_mode is unknown; shipping the gate disabled"
            );
            return disabled();
        },
    };
    // The provider is only required by the modes that use it. A `local` site
    // signs visitors in against an account on this deployment, so a missing
    // provider is not an incomplete configuration there — and requiring one
    // would make the mode unusable.
    //
    // A missing provider that the mode *does* need means the site cannot
    // authenticate anyone at all (the row predates the choice, or the foreign
    // key was `SET NULL` by a delete), so the gate ships disabled rather than
    // half-built.
    if auth_mode.allows_oidc() && provider.is_none() {
        if row.enabled {
            tracing::warn!(
                site_id = %row.site_id,
                "oidc provider is missing; shipping the gate disabled"
            );
        }
        return disabled();
    }
    // The fields the provider contributes, empty when there is no provider —
    // the plugin only reads them on the flows that have one.
    let (scopes, provider_usable, issuer, client_id, client_secret) =
        match provider {
            Some(provider) => {
                let scopes = match site_oidc_api::decode_scopes(
                    &provider.scopes,
                ) {
                    Ok(scopes) => scopes,
                    Err(error) => {
                        tracing::warn!(
                            site_id = %row.site_id,
                            provider_id = %provider.id,
                            error = %error,
                            "oidc scopes are unreadable; shipping the gate disabled"
                        );
                        return disabled();
                    },
                };
                let usable = provider.enabled
                    && !provider.issuer.trim().is_empty()
                    && !provider.client_id.trim().is_empty();
                (
                    scopes,
                    usable,
                    provider.issuer.clone(),
                    provider.client_id.clone(),
                    provider.client_secret.clone(),
                )
            },
            None => (
                Vec::new(),
                true,
                String::new(),
                String::new(),
                String::new(),
            ),
        };
    let claims_to_headers = match site_oidc_api::decode_claims(
        &row.claims_to_headers,
    ) {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(
                site_id = %row.site_id,
                error = %error,
                "oidc claims_to_headers are unreadable; shipping the gate disabled"
            );
            return disabled();
        },
    };
    let access_rules = match site_oidc_api::decode_access_rules(
        &row.access_rules,
    ) {
        Ok(rules) => rules,
        Err(error) => {
            tracing::warn!(
                site_id = %row.site_id,
                error = %error,
                "oidc access_rules are unreadable; shipping the gate disabled"
            );
            return disabled();
        },
    };
    // The API refuses to enable a gate without its required fields, but a row
    // can also be written straight into the database (or predate a validation
    // rule). An enabled gate that the plugin cannot build would leave the site
    // with no authentication at all, which is worse than the outage it avoids,
    // so the same fields are checked here and a broken row ships disabled —
    // exactly what `basic_auth_to_proto` does with an undecodable credential
    // list.
    let cookie_secret_ok = row.cookie_secret.chars().count()
        >= site_oidc_api::MIN_COOKIE_SECRET_LEN;
    // The session key is needed by both flows (each seals its own session with
    // it), so it is required regardless of the mode.
    let usable = cookie_secret_ok && provider_usable;
    // An enforcing mode with no rules denies everyone; the API refuses to
    // store it, so reaching here means the row was written directly. Shipping
    // it would lock the site out with no way back through the dashboard.
    let mode = site_oidc_model::AccessMode::parse(&row.access_mode);
    let mode_is_usable = match mode {
        Some(site_oidc_model::AccessMode::AllowAll) => true,
        Some(_) => !access_rules.is_empty(),
        // An unknown mode is a value a newer build wrote. Enforcing nothing is
        // the safe reading: the alternative would be to guess at a permission.
        None => {
            tracing::warn!(
                site_id = %row.site_id,
                access_mode = %row.access_mode,
                "oidc access_mode is unknown; shipping the gate disabled"
            );
            false
        },
    };
    if row.enabled && !(usable && mode_is_usable) {
        tracing::warn!(
            site_id = %row.site_id,
            "oidc settings are incomplete; shipping the gate disabled"
        );
    }
    Some(OidcConfig {
        enabled: row.enabled && usable && mode_is_usable,
        issuer,
        client_id,
        client_secret,
        cookie_secret: row.cookie_secret.clone(),
        redirect_path: row.redirect_path.clone(),
        logout_path: row.logout_path.clone(),
        redirect_url: row.redirect_url.clone(),
        scopes,
        cookie_name: row.cookie_name.clone(),
        // The plugin rejects a session TTL under a minute and would then fail to
        // build, taking the whole gate down; a zero or negative stored value (only
        // reachable by writing the row directly) falls back to the default instead.
        session_ttl_seconds: if row.session_ttl_seconds
            < site_oidc_api::MIN_SESSION_TTL_SECONDS
        {
            site_oidc_api::DEFAULT_SESSION_TTL_SECONDS as u32
        } else {
            row.session_ttl_seconds as u32
        },
        claims_to_headers: claims_to_headers
            .into_iter()
            .map(|claim| OidcHeaderClaim {
                claim: claim.claim,
                header: claim.header,
            })
            .collect(),
        access_mode: row.access_mode.clone(),
        access_rules: access_rules
            .into_iter()
            .map(|rule| OidcAccessRule {
                claim: rule.claim,
                operator: rule.operator,
                value: rule.value,
            })
            .collect(),
        auth_mode: row.auth_mode.clone(),
    })
}

async fn load_bot_protection(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Option<bot_protection::Model>, sea_orm::DbErr> {
    bot_protection::Entity::find()
        .filter(bot_protection::Column::SiteId.eq(site_id))
        .one(db)
        .await
}

/// Expands the IP group referenced by the bot protection row into the CIDR
/// ranges the agent should treat as verified bot networks. Only enabled rows
/// with IP verification turned on produce ranges.
async fn load_verified_bot_ranges(
    db: &DatabaseConnection,
    row: Option<&bot_protection::Model>,
) -> Result<Vec<String>, sea_orm::DbErr> {
    let Some(gid) = row
        .filter(|row| row.ip_verification_enabled)
        .and_then(|row| row.verified_ip_group_id)
    else {
        return Ok(Vec::new());
    };
    let ranges = ip_groups::Entity::find_by_id(gid)
        .filter(ip_groups::Column::Enabled.eq(true))
        .one(db)
        .await?
        .map(|group| group.ip_ranges)
        .unwrap_or_default();
    Ok(ranges)
}

/// Converts stored bot protection settings into the protocol representation.
///
/// The whitelist is stored as a JSON array of strings; malformed entries are
/// skipped so a bad edit in the control plane can never break agent config.
fn bot_protection_to_proto(
    row: Option<&bot_protection::Model>,
    verified_bot_ranges: Vec<String>,
) -> BotProtectionConfig {
    let Some(row) = row else {
        return BotProtectionConfig {
            enabled: false,
            action: 0,
            known_bots_whitelist: Vec::new(),
            ip_verification_enabled: false,
            dns_verification_enabled: false,
            verified_bot_ranges,
        };
    };

    let known_bots_whitelist = row
        .known_bots_whitelist
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    BotProtectionConfig {
        enabled: row.enabled && row.ua_analysis,
        action: action::to_proto(&row.action),
        known_bots_whitelist,
        ip_verification_enabled: row.ip_verification_enabled,
        dns_verification_enabled: row.dns_verification_enabled,
        verified_bot_ranges,
    }
}

/// Converts a stored rewrite rule into its protocol representation.
fn rewrite_rule_to_proto(row: &rewrite_rules::Model) -> RewriteRule {
    RewriteRule {
        id: row.id.to_string(),
        name: row.name.clone(),
        match_expression: row.condition_expr.clone().unwrap_or_default(),
        direction: if row.direction == "response" { 1 } else { 0 },
        operations: parse_operations(&row.operations),
        enabled: row.enabled,
        priority: row.priority.max(0) as u32,
    }
}

/// Parses the stored operations JSON array into proto operations. The console
/// stores `{type, name, value}` objects whose semantics depend on the type
/// (pattern/replacement for `regex_replace_path` and `replace_body`); they
/// pass through verbatim so the data plane sees exactly what was configured.
fn parse_operations(ops: &serde_json::Value) -> Vec<RewriteOperation> {
    let Some(items) = ops.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let obj = item.as_object()?;
            let r#type = obj
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if r#type.is_empty() {
                return None;
            }
            Some(RewriteOperation {
                r#type,
                name: obj
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                value: obj
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect()
}

/// Converts a stored error page into its protocol representation.
fn error_page_to_proto(row: &error_pages::Model) -> CustomErrorPage {
    CustomErrorPage {
        id: row.id.to_string(),
        status_code: row.status_code.max(0) as u32,
        content_type: row.content_type.clone(),
        body_template: row.body_template.clone(),
        name: row.name.clone(),
        enabled: row.enabled,
    }
}

/// Builds the complete [`RuleBundle`] for one site.
pub async fn build_rule_bundle(
    db: &DatabaseConnection,
    site_row: &site::Model,
) -> Result<RuleBundle, sea_orm::DbErr> {
    let rules_rows = load_rules(db, site_row.id).await?;
    let groups = load_rule_groups(db, site_row.id).await?;
    let rate_limits = load_rate_limits(db, site_row.id).await?;
    let caches = load_cache_rules(db, site_row.id).await?;
    let upstreams = load_upstreams(db, site_row.id).await?;
    let pools = load_pools(db, site_row.id).await?;
    let routes = load_routes(db, site_row.id).await?;
    let route_groups = load_route_groups(db, &routes).await?;
    let ssl = load_ssl(db, site_row.id).await?;
    let ip_rules = load_ip_access_rules(db, site_row.id).await?;
    let ip_groups = load_ip_groups(db, site_row.id).await?;
    let referenced_groups = load_referenced_groups(db, &ip_rules).await?;
    let geo = load_geo_rules(db, site_row.id).await?;
    let challenge = load_challenge_settings(db, site_row.id).await?;
    let waf_settings = load_waf_settings(db, site_row.id).await?;
    let basic_auth = load_basic_auth(db, site_row.id).await?;
    let (oidc, oidc_provider_row) =
        load_oidc_with_provider(db, site_row.id).await?;
    let rewrites = load_rewrite_rules(db, site_row.id).await?;
    let err_pages = load_error_pages(db).await?;
    let certificates = load_certificates(db, site_row.id).await?;
    let bot = load_bot_protection(db, site_row.id).await?;
    let verified_bot_ranges =
        load_verified_bot_ranges(db, bot.as_ref()).await?;
    let ai_crawl = load_ai_crawl(db, site_row, &routes).await?;
    let mtls = load_mtls(db, site_row.id).await?;
    // A missing settings row means observation mode was never switched on, so
    // the data plane keeps enforcing; the failover default likewise falls
    // back to fail-open.
    let defense_row = defense_settings::Entity::find_by_id(1).one(db).await?;
    let observation_mode =
        defense_row.as_ref().is_some_and(|row| row.observation_mode);
    let default_fail_open =
        defense_row.as_ref().is_none_or(|row| row.default_fail_open);
    // Every bundle carries the complete domain → failover policy registry so
    // the agent can resolve a site's disconnected behaviour even for hosts
    // whose rule bundle was never synced.
    let site_policies = load_site_policies(db).await?;
    // Global cache ceiling + site-level cache limits; both optional so an
    // old row shape (or a read failure short of an error) degrades to the
    // agent-side defaults.
    let cache_settings_row = crate::api::cache_settings::load(db).await.ok();
    let global_cache =
        cache_settings_row.as_ref().map(|row| GlobalCacheSettings {
            max_file_size_mb: Some(row.max_file_size_mb.max(0) as u32),
            max_space_mb: Some(row.max_space_mb.max(0) as u32),
            master_enabled: Some(row.master_enabled),
            default_edge_ttl_seconds: Some(
                row.default_edge_ttl_seconds.max(0) as u32
            ),
        });
    let site_cache_settings = site_cache_settings_to_proto(site_row);
    // Deployment-wide origin certificate check. A read failure leaves the
    // field unset, which the agent reads as "keep the historical lenient
    // behaviour" — never as "verify strictly", because that would 502 every
    // HTTPS origin with a certificate outside the system trust store.
    let origin_verify_cert = crate::api::origin_settings::load(db)
        .await
        .ok()
        .map(|row| row.verify_cert);

    let custom_rules: Vec<WafRule> =
        rules_rows.iter().map(rule_to_proto).collect();

    let mut bundle = RuleBundle {
        site_id: site_row.id.to_string(),
        // Filled in below, once every other field is final.
        config_hash: String::new(),
        updated_at: to_timestamp(site_row.updated_at),
        waf: Some(waf_config_to_proto(
            &custom_rules,
            &groups,
            waf_settings.as_ref(),
        )),
        rate_limit_rules: rate_limits.iter().map(rate_limit_to_proto).collect(),
        ip_access_rules: ip_rules
            .iter()
            .filter_map(|row| ip_access_rule_to_proto(row, &referenced_groups))
            .chain(ip_groups.iter().map(ip_group_to_proto))
            .collect(),
        geo: Some(geo_to_proto(geo.as_ref())),
        cache_rules: caches
            .iter()
            .map(|row| cache_rule_to_proto(row, site_row.cache_quota_mb))
            .collect(),
        challenge: Some(challenge_to_proto(challenge.as_ref())),
        rewrite_rules: rewrites.iter().map(rewrite_rule_to_proto).collect(),
        error_pages: err_pages.iter().map(error_page_to_proto).collect(),
        ssl: ssl
            .as_ref()
            .map(|row| ssl_to_proto(row, &certificates, &mtls)),
        upstreams: pools_to_proto(
            &pools,
            &upstreams,
            site_row.origin_verify_cert,
        ),
        routes: routes_to_proto(&routes, &pools, &upstreams, &route_groups),
        bot_protection: Some(bot_protection_to_proto(
            bot.as_ref(),
            verified_bot_ranges,
        )),
        basic_auth: basic_auth_to_proto(basic_auth.as_ref()),
        observation_mode,
        site_policies,
        default_fail_open: Some(default_fail_open),
        global_cache,
        cache_settings: site_cache_settings,
        origin_verify_cert,
        response_replace: response_replace_to_proto(site_row),
        ai_crawl,
        oidc: oidc_to_proto(oidc.as_ref(), oidc_provider_row.as_ref()),
    };

    bundle.config_hash = fingerprint(&bundle);
    Ok(bundle)
}

/// Reads the site's AI crawler policy into its protocol shape.
///
/// The file bodies are rendered here — configuration-build time, once per
/// changed bundle — so neither file is assembled on the request path. A mode
/// of `off` sends empty bodies, which the data plane reads as "do not serve
/// the file".
async fn load_ai_crawl(
    db: &DatabaseConnection,
    site_row: &site::Model,
    routes: &[site_routes::Model],
) -> Result<Option<AiCrawlConfig>, DbErr> {
    let settings = crate::api::ai_crawl::load_settings(db, site_row.id)
        .await
        .map_err(|err| {
        DbErr::Custom(format!("ai_crawl settings: {err}"))
    })?;
    let policies = crate::api::ai_crawl::load_policies(db, site_row.id)
        .await
        .map_err(|err| {
        DbErr::Custom(format!("ai_crawl policies: {err}"))
    })?;

    let robots_body =
        render_ai_file(&settings.robots_mode, &settings.robots_body, || {
            crate::api::ai_crawl::render_robots(
                &settings,
                &policies,
                &site_row.domain,
            )
        });
    let llms_body =
        render_ai_file(&settings.llms_mode, &settings.llms_body, || {
            crate::api::ai_crawl::render_llms(
                &settings, &policies, site_row, routes,
            )
        });

    let policies = policies
        .iter()
        .filter_map(|policy| {
            let bot = crate::api::ai_crawl::find_bot(&policy.bot_id)?;
            Some(AiBotPolicy {
                id: bot.id.to_string(),
                ua_substrings: bot
                    .ua_substrings
                    .iter()
                    .map(|pattern| (*pattern).to_string())
                    .collect(),
                category: bot.category.to_string(),
                action: if policy.action == "inherit" {
                    settings.default_action.clone()
                } else {
                    policy.action.clone()
                },
            })
        })
        .collect();

    Ok(Some(AiCrawlConfig {
        enabled: settings.enabled,
        default_action: settings.default_action,
        robots_body,
        llms_body,
        cache_max_age: settings.cache_max_age.max(0) as u32,
        policies,
    }))
}

/// The body a generated file serves: empty when the mode is `off`, the
/// operator's text when they wrote one, the template otherwise.
fn render_ai_file(
    mode: &str,
    custom: &str,
    render: impl FnOnce() -> String,
) -> String {
    if mode != "generate" {
        return String::new();
    }
    let body = if custom.trim().is_empty() {
        render()
    } else {
        custom.to_string()
    };
    // A site with thousands of routes produces an llms.txt past the cap the
    // API enforces on hand-written bodies; truncate on a char boundary so the
    // pushed bundle never carries an oversized file.
    truncate_ai_body(body, crate::api::ai_crawl::MAX_FILE_BYTES)
}

/// Caps a generated file at `max` bytes without splitting a UTF-8 sequence.
fn truncate_ai_body(mut body: String, max: usize) -> String {
    if body.len() <= max {
        return body;
    }
    let mut cut = max;
    while cut > 0 && !body.is_char_boundary(cut) {
        cut -= 1;
    }
    body.truncate(cut);
    tracing::warn!(
        bytes = cut,
        "generated robots/llms body exceeded the size cap and was truncated"
    );
    body
}

/// Reads the site's response replacement policy into its protocol shape.
///
/// A row whose document does not parse contributes nothing: one malformed
/// policy must not cost the site every other rule in its bundle. The write path
/// validates the shape, so this only fires for hand-edited data.
fn response_replace_to_proto(
    site_row: &site::Model,
) -> Option<ResponseReplaceConfig> {
    let stored = site_row.response_replace.as_ref()?;
    // `ResponseReplaceConfig` is both the stored model and the protocol
    // message, so the model side is named explicitly here.
    let Some(parsed) = crate::models::ResponseReplaceConfig::from_json(stored)
    else {
        tracing::warn!(
            site = %site_row.domain,
            "response_replace is not a valid policy document; ignoring it"
        );
        return None;
    };
    if parsed.rules.is_empty() {
        return None;
    }
    Some(ResponseReplaceConfig {
        path: parsed.path,
        status_codes: parsed.status_codes.into_iter().map(u32::from).collect(),
        rules: parsed
            .rules
            .into_iter()
            .map(|rule| ResponseReplaceRule {
                pattern: rule.pattern,
                replacement: rule.replacement,
                is_regex: rule.is_regex,
            })
            .collect(),
    })
}

/// Maps a `sites.failover_policy` string onto the proto enum; unknown values
/// degrade to `inherit`, matching the agent-side fallback direction.
fn failover_mode_of(policy: &str) -> FailoverMode {
    match policy {
        "open" => FailoverMode::FailoverOpen,
        "closed" => FailoverMode::FailoverClosed,
        _ => FailoverMode::FailoverInherit,
    }
}

/// Builds the complete domain → failover-policy registry across all sites.
/// One lightweight query; the result rides in every `RuleBundle`.
async fn load_site_policies(
    db: &DatabaseConnection,
) -> Result<Vec<SitePolicy>, sea_orm::DbErr> {
    let rows = site::Entity::find()
        .order_by_asc(site::Column::Domain)
        .all(db)
        .await?;
    Ok(rows
        .iter()
        .map(|row| SitePolicy {
            domain: row.domain.clone(),
            alternate_domains: row.alternate_domains.clone(),
            mode: failover_mode_of(&row.failover_policy) as i32,
        })
        .collect())
}

/// Merges a site's hand-entered trusted-proxy ranges with the ranges of the
/// IP groups it references. Only enabled groups contribute (a disabled group
/// stops widening the trust scope); duplicates are removed. Agents receive
/// only the merged flat list, so the data plane stays group-agnostic.
fn merge_trusted_proxy_ranges(
    site_ranges: &[String],
    group_ids: &[Uuid],
    groups: &HashMap<Uuid, Vec<String>>,
) -> Vec<String> {
    let mut merged = site_ranges.to_vec();
    for group_id in group_ids {
        if let Some(ranges) = groups.get(group_id) {
            merged.extend(ranges.iter().cloned());
        }
    }
    merged.sort();
    merged.dedup();
    merged
}

/// Builds a [`SiteConfig`] for the given sites, or for every site when
/// `site_ids` is `None`.
pub async fn build_site_config(
    db: &DatabaseConnection,
    site_ids: Option<&[Uuid]>,
) -> Result<SiteConfig, sea_orm::DbErr> {
    let mut query = site::Entity::find().order_by_asc(site::Column::Domain);
    if let Some(ids) = site_ids {
        if ids.is_empty() {
            // Nothing requested: return an empty configuration instead of
            // accidentally serving every site.
            let mut config = SiteConfig {
                sites: Vec::new(),
                updated_at: to_timestamp(Utc.timestamp_opt(0, 0).unwrap()),
                config_hash: String::new(),
            };
            config.config_hash = fingerprint(&config);
            return Ok(config);
        }
        query = query.filter(site::Column::Id.is_in(ids.iter().copied()));
    }
    let rows = query.all(db).await?;

    // Resolve every trusted-proxy IP group the sites reference in one query;
    // disabled groups are skipped so they stop widening the trust scope.
    let mut group_ids: Vec<Uuid> = rows
        .iter()
        .flat_map(|row| row.trusted_proxy_group_ids.iter().copied())
        .collect();
    group_ids.sort();
    group_ids.dedup();
    let group_ranges: HashMap<Uuid, Vec<String>> = if group_ids.is_empty() {
        HashMap::new()
    } else {
        ip_groups::Entity::find()
            .filter(ip_groups::Column::Enabled.eq(true))
            .filter(ip_groups::Column::Id.is_in(group_ids))
            .all(db)
            .await?
            .into_iter()
            .map(|group| (group.id, group.ip_ranges))
            .collect()
    };

    let mut sites = Vec::with_capacity(rows.len());
    let mut updated_at = Utc.timestamp_opt(0, 0).unwrap();
    for row in &rows {
        let bundle = build_rule_bundle(db, row).await?;
        if row.updated_at > updated_at {
            updated_at = row.updated_at;
        }
        sites.push(Site {
            id: row.id.to_string(),
            name: row.name.clone(),
            domain: row.domain.clone(),
            alternate_domains: row.alternate_domains.clone(),
            status: site_status_proto(&row.status),
            rules: Some(bundle),
            trust_proxy_headers: row.trust_proxy_headers,
            trusted_header: row.trusted_header.clone(),
            trust_last_hop: row.trust_last_hop,
            trusted_proxy_ranges: merge_trusted_proxy_ranges(
                &row.trusted_proxy_ranges,
                &row.trusted_proxy_group_ids,
                &group_ranges,
            ),
        });
    }

    let mut config = SiteConfig {
        sites,
        updated_at: to_timestamp(updated_at),
        config_hash: String::new(),
    };
    config.config_hash = fingerprint(&config);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::route_match_type;

    #[test]
    fn timestamps_roundtrip() {
        let value = Utc::now();
        let ts = to_timestamp(value).expect("timestamp");
        let back = from_timestamp(Some(&ts));
        assert_eq!(back.timestamp(), value.timestamp());
        assert!(from_timestamp(None) <= Utc::now());
    }

    #[test]
    fn status_mappings_match_the_proto() {
        assert_eq!(site_status_proto(site_status::ACTIVE), 0);
        assert_eq!(site_status_proto(site_status::PAUSED), 1);
        assert_eq!(site_status_proto(site_status::PENDING), 2);
        assert_eq!(acme_challenge_proto(Some(acme_challenge::DNS_01)), 1);
        assert_eq!(acme_challenge_proto(Some(acme_challenge::HTTP_01)), 0);
        assert_eq!(acme_challenge_proto(None), 0);
    }

    #[test]
    fn fingerprints_are_stable_and_order_sensitive() {
        let bundle = RuleBundle {
            site_id: Uuid::nil().to_string(),
            ..Default::default()
        };
        assert_eq!(fingerprint(&bundle), fingerprint(&bundle));
        assert_eq!(fingerprint(&bundle).len(), 16);

        let mut other = bundle.clone();
        other.site_id = Uuid::new_v4().to_string();
        assert_ne!(fingerprint(&bundle), fingerprint(&other));
    }

    #[test]
    fn failover_fields_change_the_fingerprint() {
        let bundle = RuleBundle {
            site_id: Uuid::nil().to_string(),
            ..Default::default()
        };

        // A site switching its policy must re-push its bundle.
        let mut per_site = bundle.clone();
        per_site.site_policies = vec![SitePolicy {
            domain: "shop.example.com".to_string(),
            alternate_domains: vec!["m.shop.example.com".to_string()],
            mode: failover_mode_of("closed") as i32,
        }];
        assert_ne!(fingerprint(&bundle), fingerprint(&per_site));
        // INHERIT degrades to the same encoding as the field's absence, so a
        // no-op edit does not manufacture a spurious hash change.
        let mut inherit = bundle.clone();
        inherit.site_policies = vec![SitePolicy {
            domain: "shop.example.com".to_string(),
            alternate_domains: Vec::new(),
            mode: failover_mode_of("inherit") as i32,
        }];
        assert_ne!(fingerprint(&bundle), fingerprint(&inherit));

        // The global default is `optional`: set is encoded, unset is not.
        let mut default_open = bundle.clone();
        default_open.default_fail_open = Some(false);
        assert_ne!(fingerprint(&bundle), fingerprint(&default_open));
    }

    #[test]
    fn unknown_failover_policies_degrade_to_inherit() {
        assert_eq!(failover_mode_of("open"), FailoverMode::FailoverOpen);
        assert_eq!(failover_mode_of("closed"), FailoverMode::FailoverClosed);
        for policy in ["inherit", "", "bogus"] {
            assert_eq!(failover_mode_of(policy), FailoverMode::FailoverInherit);
        }
    }

    #[test]
    fn json_objects_become_string_maps() {
        let value = serde_json::json!({ "token": "abc", "retries": 3 });
        let map = json_to_string_map(&Some(value));
        assert_eq!(map.get("token").map(String::as_str), Some("abc"));
        assert_eq!(map.get("retries").map(String::as_str), Some("3"));
        assert!(json_to_string_map(&None).is_empty());
    }

    fn bot_row(enabled: bool, ua_analysis: bool) -> bot_protection::Model {
        bot_protection::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::nil(),
            enabled,
            ua_analysis,
            js_detection: true,
            tls_fingerprint: false,
            behavioral_analysis: false,
            action: "challenge".to_string(),
            known_bots_whitelist: serde_json::json!([
                "Googlebot",
                1,
                "bingbot"
            ]),
            verified_ip_group_id: None,
            ip_verification_enabled: false,
            dns_verification_enabled: false,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn bot_protection_proto_skips_malformed_whitelist_entries() {
        let row = bot_row(true, true);
        let proto = bot_protection_to_proto(Some(&row), Vec::new());
        assert!(proto.enabled);
        assert_eq!(proto.action, action::to_proto("challenge"));
        assert_eq!(
            proto.known_bots_whitelist,
            vec!["Googlebot".to_string(), "bingbot".to_string()]
        );

        // UA analysis disabled means the data plane has nothing to enforce.
        let row = bot_row(true, false);
        assert!(!bot_protection_to_proto(Some(&row), Vec::new()).enabled);

        // No row yet: disabled defaults.
        let proto = bot_protection_to_proto(None, Vec::new());
        assert!(!proto.enabled);
        assert!(proto.known_bots_whitelist.is_empty());
    }

    #[test]
    fn bot_protection_proto_carries_verification_flags() {
        let mut row = bot_row(true, true);
        row.ip_verification_enabled = true;
        row.dns_verification_enabled = true;
        let proto = bot_protection_to_proto(
            Some(&row),
            vec!["192.168.0.0/16".to_string()],
        );
        assert!(proto.ip_verification_enabled);
        assert!(proto.dns_verification_enabled);
        assert_eq!(
            proto.verified_bot_ranges,
            vec!["192.168.0.0/16".to_string()]
        );
    }

    #[test]
    fn waf_config_emits_off_overrides_for_builtin_rules_only() {
        let base = rule::Model {
            id: Uuid::new_v4(),
            group_id: None,
            site_id: Uuid::nil(),
            name: "r".into(),
            description: None,
            expression: "true".into(),
            action: action::BLOCK.into(),
            severity: 3,
            tags: vec!["sqli".into()],
            enabled: true,
            mode: mode::MONITOR.into(),
            priority: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // A built-in rule switched off emits a disable override, whether via
        // `mode = off` or `enabled = false`.
        let mut off_builtin = base.clone();
        off_builtin.id = Uuid::nil();
        off_builtin.name = "PINGWAF-1010".into();
        let proto = rule_to_proto(&off_builtin);
        let mut proto = proto;
        proto.id = "PINGWAF-1010".into();
        proto.mode = WAF_MODE_OFF;
        let config = waf_config_to_proto(
            &[proto.clone(), rule_to_proto(&base)],
            &[],
            None,
        );
        assert_eq!(config.managed_overrides.len(), 1);
        assert_eq!(config.managed_overrides[0].rule_id, "PINGWAF-1010");
        assert!(!config.managed_overrides[0].enabled);

        let mut disabled_builtin = proto.clone();
        disabled_builtin.mode = WAF_MODE_MONITOR;
        disabled_builtin.enabled = false;
        let config = waf_config_to_proto(&[disabled_builtin], &[], None);
        assert_eq!(config.managed_overrides.len(), 1);
        assert_eq!(config.managed_overrides[0].rule_id, "PINGWAF-1010");

        // Enabled built-in rules produce no override.
        let mut on_builtin = proto;
        on_builtin.enabled = true;
        on_builtin.mode = WAF_MODE_MONITOR;
        let config = waf_config_to_proto(&[on_builtin], &[], None);
        assert!(config.managed_overrides.is_empty());

        // A disabled custom rule never produces an override — custom rules
        // travel through `custom_rules` and are filtered engine-side.
        let mut off_custom = base.clone();
        off_custom.enabled = false;
        off_custom.mode = mode::OFF.into();
        let config =
            waf_config_to_proto(&[rule_to_proto(&off_custom)], &[], None);
        assert!(config.managed_overrides.is_empty());
        assert_eq!(config.custom_rules.len(), 1);
    }

    #[test]
    fn waf_mode_follows_the_strongest_rule() {
        let base = rule::Model {
            id: Uuid::new_v4(),
            group_id: None,
            site_id: Uuid::nil(),
            name: "r".into(),
            description: None,
            expression: "true".into(),
            action: action::BLOCK.into(),
            severity: 3,
            tags: vec!["sqli".into()],
            enabled: true,
            mode: mode::MONITOR.into(),
            priority: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let monitoring = vec![rule_to_proto(&base)];
        let config = waf_config_to_proto(&monitoring, &[], None);
        assert!(config.enabled);
        assert_eq!(config.mode, WAF_MODE_MONITOR);
        assert!(config.sqli_detection);
        // Without a posture row the paranoia level stays at the default
        // instead of riding on rule severity.
        assert_eq!(config.paranoia_level, 2);
        assert!(!config.advanced_mode);
        assert!(config.monitor_categories.is_empty());
        assert!(config.monitor_stacks.is_empty());

        let mut blocking = base.clone();
        blocking.mode = mode::BLOCK.into();
        let config =
            waf_config_to_proto(&[rule_to_proto(&blocking)], &[], None);
        assert_eq!(config.mode, WAF_MODE_BLOCK);

        let mut disabled = base.clone();
        disabled.enabled = false;
        let config =
            waf_config_to_proto(&[rule_to_proto(&disabled)], &[], None);
        // The engine switch is explicit now: a disabled rule only drops the
        // derived mode to its floor, the managed engine itself stays on. The
        // floor is monitor — a site without a posture row never loses
        // detection entirely just because nobody configured a rule.
        assert!(config.enabled);
        assert_eq!(config.mode, WAF_MODE_MONITOR);

        // An explicit off switch turns the config off regardless of rules.
        let mut off =
            waf_settings_row(Uuid::nil(), true, Vec::new(), Vec::new());
        off.waf_enabled = false;
        let config = waf_config_to_proto(&monitoring, &[], Some(&off));
        assert!(!config.enabled);
    }

    fn waf_settings_row(
        site_id: Uuid,
        advanced_mode: bool,
        categories: Vec<String>,
        stacks: Vec<String>,
    ) -> waf_settings::Model {
        waf_settings_row_with_rules(
            site_id,
            advanced_mode,
            categories,
            stacks,
            Vec::new(),
        )
    }

    fn waf_settings_row_with_rules(
        site_id: Uuid,
        advanced_mode: bool,
        categories: Vec<String>,
        stacks: Vec<String>,
        managed_rules: Vec<String>,
    ) -> waf_settings::Model {
        waf_settings::Model {
            id: Uuid::new_v4(),
            site_id,
            waf_enabled: true,
            mode: mode::OFF.into(),
            paranoia_level: 2,
            advanced_mode,
            monitor_categories: categories,
            monitor_stacks: stacks,
            monitor_managed_rules: managed_rules,
            body_stage_timeout_secs: DEFAULT_BODY_STAGE_TIMEOUT_SECS,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn waf_config_merges_site_settings() {
        let base = rule::Model {
            id: Uuid::new_v4(),
            group_id: None,
            site_id: Uuid::nil(),
            name: "r".into(),
            description: None,
            expression: "true".into(),
            action: action::BLOCK.into(),
            severity: 2,
            tags: vec!["sql-injection".into()],
            enabled: true,
            mode: mode::MONITOR.into(),
            priority: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let rules = vec![rule_to_proto(&base)];

        // A lone advanced-mode switch must still yield an enabled config so
        // the data plane spins up the strict managed engine.
        let advanced =
            waf_settings_row(Uuid::nil(), true, Vec::new(), Vec::new());
        let config = waf_config_to_proto(&rules, &[], Some(&advanced));
        assert!(config.enabled);
        assert!(config.advanced_mode);

        // Monitor lists flow through verbatim; the data plane ignores
        // unknown names.
        let monitored = waf_settings_row(
            Uuid::nil(),
            false,
            vec!["sqli".into(), "ssti".into()],
            vec!["java".into()],
        );
        let config = waf_config_to_proto(&rules, &[], Some(&monitored));
        assert!(config.enabled);
        assert!(!config.advanced_mode);
        assert_eq!(config.monitor_categories, vec!["sqli", "ssti"]);
        assert_eq!(config.monitor_stacks, vec!["java"]);

        // A per-rule managed downgrade alone also enables the config and
        // flows through verbatim.
        let per_rule = waf_settings_row_with_rules(
            Uuid::nil(),
            false,
            Vec::new(),
            Vec::new(),
            vec!["PINGWAF-1010".into()],
        );
        let config = waf_config_to_proto(&[], &[], Some(&per_rule));
        assert!(config.enabled);
        assert_eq!(config.monitor_managed_rules, vec!["PINGWAF-1010"]);

        // No rules and no settings row: the engine defaults to on — the
        // managed ruleset ships enabled for every site until switched off —
        // and the mode floors at monitor, not off.
        let config = waf_config_to_proto(&[], &[], None);
        assert!(config.enabled);
        assert_eq!(config.mode, WAF_MODE_MONITOR);
    }

    #[test]
    fn missing_settings_row_floors_at_monitor() {
        // D14: no posture row must never hand the data plane `off`. The engine
        // treats off as "return Pass immediately", so an unconfigured site
        // produced zero telemetry — weaker than monitor and impossible to
        // distinguish from a broken WAF.
        let disabled = rule::Model {
            id: Uuid::new_v4(),
            group_id: None,
            site_id: Uuid::nil(),
            name: "r".into(),
            description: None,
            expression: "true".into(),
            action: action::BLOCK.into(),
            severity: 3,
            tags: vec!["sqli".into()],
            enabled: false,
            mode: mode::BLOCK.into(),
            priority: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        // Empty rule list and "all rules disabled" both fall back to monitor.
        let empty: Vec<WafRule> = Vec::new();
        let all_disabled = vec![rule_to_proto(&disabled)];
        for rules in [&empty, &all_disabled] {
            let config = waf_config_to_proto(rules, &[], None);
            assert!(config.enabled, "engine must stay on");
            assert_eq!(config.mode, WAF_MODE_MONITOR, "rules: {rules:?}");
        }

        // An explicit row is still the only way to get `off`, and a row that
        // says block keeps winning over the fallback.
        let mut row =
            waf_settings_row(Uuid::nil(), false, Vec::new(), Vec::new());
        assert_eq!(
            waf_config_to_proto(&[], &[], Some(&row)).mode,
            WAF_MODE_OFF
        );
        row.mode = mode::MONITOR.into();
        assert_eq!(
            waf_config_to_proto(&[], &[], Some(&row)).mode,
            WAF_MODE_MONITOR
        );
        row.mode = mode::BLOCK.into();
        assert_eq!(
            waf_config_to_proto(&[], &[], Some(&row)).mode,
            WAF_MODE_BLOCK
        );
    }

    #[test]
    fn site_mode_and_paranoia_come_from_the_settings_row() {
        let blocking = rule::Model {
            id: Uuid::new_v4(),
            group_id: None,
            site_id: Uuid::nil(),
            name: "r".into(),
            description: None,
            expression: "true".into(),
            action: action::BLOCK.into(),
            severity: 5,
            tags: vec!["sqli".into()],
            enabled: true,
            mode: mode::BLOCK.into(),
            priority: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let rules = vec![rule_to_proto(&blocking)];

        // A settings row wins over the rule derivation: an explicit monitor
        // mode stays monitor even when every rule enforces block.
        let mut row =
            waf_settings_row(Uuid::nil(), false, Vec::new(), Vec::new());
        row.mode = mode::MONITOR.into();
        let config = waf_config_to_proto(&rules, &[], Some(&row));
        assert_eq!(config.mode, WAF_MODE_MONITOR);

        // A site without custom rules but with an explicit block mode runs
        // the engine in block — the mode no longer silently rides on the
        // rules (the legacy "no rules means off" trap).
        let mut row =
            waf_settings_row(Uuid::nil(), false, Vec::new(), Vec::new());
        row.mode = mode::BLOCK.into();
        let config = waf_config_to_proto(&[], &[], Some(&row));
        assert!(config.enabled);
        assert_eq!(config.mode, WAF_MODE_BLOCK);

        // Paranoia level is site-configured, not severity-derived: a
        // severity-5 rule no longer raises the sensitivity.
        let mut row =
            waf_settings_row(Uuid::nil(), false, Vec::new(), Vec::new());
        row.mode = mode::BLOCK.into();
        row.paranoia_level = 1;
        let config = waf_config_to_proto(&rules, &[], Some(&row));
        assert_eq!(config.paranoia_level, 1);

        // Out-of-range stored values are clamped to the protocol range.
        row.paranoia_level = 9;
        let config = waf_config_to_proto(&rules, &[], Some(&row));
        assert_eq!(config.paranoia_level, 4);
    }

    #[test]
    fn body_stage_timeout_defaults_to_30_without_a_settings_row() {
        // No posture row: the data plane's own default is the only sane
        // answer, and it must travel explicitly rather than as the wire's
        // "unset" 0 — the agent reads 0 as "use my default", which would
        // hide a control-plane/agent default mismatch.
        let config = waf_config_to_proto(&[], &[], None);
        assert_eq!(config.body_stage_timeout_secs, 30);

        // A row created by the API carries the same default.
        let row = waf_settings_row(Uuid::nil(), false, Vec::new(), Vec::new());
        let config = waf_config_to_proto(&[], &[], Some(&row));
        assert_eq!(config.body_stage_timeout_secs, 30);
    }

    #[test]
    fn body_stage_timeout_is_carried_and_clamped() {
        let mut row =
            waf_settings_row(Uuid::nil(), false, Vec::new(), Vec::new());

        // A site-level value flows through unchanged inside 1..=30.
        row.body_stage_timeout_secs = 1;
        let config = waf_config_to_proto(&[], &[], Some(&row));
        assert_eq!(config.body_stage_timeout_secs, 1);

        row.body_stage_timeout_secs = 30;
        let config = waf_config_to_proto(&[], &[], Some(&row));
        assert_eq!(config.body_stage_timeout_secs, 30);

        // Out-of-band rows (a hand-edited database, a row written before the
        // column existed) can never widen or zero the window: 0 reads as
        // unset, anything above the ceiling is clamped.
        row.body_stage_timeout_secs = 0;
        let config = waf_config_to_proto(&[], &[], Some(&row));
        assert_eq!(config.body_stage_timeout_secs, 30);

        row.body_stage_timeout_secs = -5;
        let config = waf_config_to_proto(&[], &[], Some(&row));
        assert_eq!(config.body_stage_timeout_secs, 30);

        row.body_stage_timeout_secs = 31;
        let config = waf_config_to_proto(&[], &[], Some(&row));
        assert_eq!(config.body_stage_timeout_secs, 30);

        row.body_stage_timeout_secs = 3600;
        let config = waf_config_to_proto(&[], &[], Some(&row));
        assert_eq!(config.body_stage_timeout_secs, 30);
    }

    fn pool_model(
        name: &str,
        lb_algorithm: &str,
        sni: Option<&str>,
        is_default: bool,
    ) -> site_upstream_pools::Model {
        site_upstream_pools::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::nil(),
            name: name.into(),
            lb_algorithm: lb_algorithm.into(),
            sni: sni.map(Into::into),
            verify_cert: None,
            health_check_enabled: false,
            health_check_path: "/".into(),
            health_check_interval_seconds: 10,
            health_check_timeout_ms: 3000,
            health_check_unhealthy_threshold: 2,
            health_check_healthy_threshold: 1,
            address_family: "auto".into(),
            is_default,
            created_at: Utc::now(),
        }
    }

    fn node_model(
        pool_id: Uuid,
        address: &str,
        weight: i32,
    ) -> site_upstreams::Model {
        site_upstreams::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::nil(),
            pool_id,
            name: "origin".into(),
            address: address.into(),
            weight,
            tls: false,
            health_status: "unknown".into(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn pools_group_their_nodes_and_skip_empty_ones() {
        let default_pool = pool_model("default", "round_robin", None, true);
        let tls_pool =
            pool_model("static", "hash:path", Some("cdn.example.com"), false);
        let empty_pool = pool_model("empty", "round_robin", None, false);

        let nodes = vec![
            node_model(default_pool.id, "10.0.0.1:8080", 3),
            node_model(default_pool.id, "10.0.0.2:8080", 1),
            node_model(tls_pool.id, "10.0.0.3:9090", 2),
        ];

        let configs = pools_to_proto(
            &[default_pool.clone(), tls_pool, empty_pool],
            &nodes,
            None,
        );
        assert_eq!(configs.len(), 2);

        assert_eq!(configs[0].name, "default");
        assert_eq!(configs[0].pool_id, default_pool.id.to_string());
        assert!(configs[0].is_default);
        assert_eq!(configs[0].algo, "round_robin");
        assert_eq!(configs[0].algorithm, 0);
        assert_eq!(configs[0].peers.len(), 2);
        assert_eq!(configs[0].peers[0].weight, 3);
        assert_eq!(configs[0].sni, "");

        assert_eq!(configs[1].name, "static");
        assert_eq!(configs[1].algo, "hash:path");
        assert_eq!(configs[1].sni, "cdn.example.com");
        assert_eq!(configs[1].peers.len(), 1);
        assert!(!configs[1].is_default);

        assert!(pools_to_proto(&[], &nodes, None).is_empty());
    }

    #[test]
    fn pools_pass_verify_cert_through() {
        let mut pool = pool_model("default", "round_robin", None, true);
        pool.verify_cert = Some(false);
        let nodes = vec![node_model(pool.id, "10.0.0.1:8080", 1)];
        let configs = pools_to_proto(&[pool], &nodes, None);
        assert_eq!(configs[0].verify_cert, Some(false));
    }

    /// The three-level certificate-verification cascade: a pool pin wins
    /// over the site default; a pool without one inherits the site value;
    /// when both are unset the wire value stays `NULL` (the agent fills in
    /// the deployment-wide default from `RuleBundle.origin_verify_cert`).
    #[test]
    fn site_origin_verify_cert_cascade() {
        let pinned_true = site_upstream_pools::Model {
            verify_cert: Some(true),
            ..pool_model(
                "pinned-true",
                "round_robin",
                Some("a.example.com"),
                false,
            )
        };
        let unpinned =
            pool_model("unpinned", "round_robin", Some("b.example.com"), false);
        let pinned_false = site_upstream_pools::Model {
            verify_cert: Some(false),
            ..pool_model(
                "pinned-false",
                "round_robin",
                Some("c.example.com"),
                false,
            )
        };
        let both_unset = pool_model(
            "both-unset",
            "round_robin",
            Some("d.example.com"),
            false,
        );
        // Pools without nodes are skipped, so each pool carries one node.
        let nodes = vec![
            node_model(pinned_true.id, "10.0.0.1:8080", 1),
            node_model(unpinned.id, "10.0.0.2:8080", 1),
            node_model(pinned_false.id, "10.0.0.3:8080", 1),
            node_model(both_unset.id, "10.0.0.4:8080", 1),
        ];

        // Strict site default: the explicit opt-out survives, everything
        // unpinned inherits the site's verify.
        let configs = pools_to_proto(
            &[
                pinned_true.clone(),
                unpinned.clone(),
                pinned_false.clone(),
                both_unset.clone(),
            ],
            &nodes,
            Some(true),
        );
        assert_eq!(configs[0].verify_cert, Some(true), "pool pin wins");
        assert_eq!(configs[1].verify_cert, Some(true), "site fills in");
        assert_eq!(
            configs[2].verify_cert,
            Some(false),
            "explicit opt-out survives a strict site"
        );
        assert_eq!(configs[3].verify_cert, Some(true), "site fills in");

        // Lenient site default: only the strict pin keeps verifying.
        let configs = pools_to_proto(
            &[pinned_true, unpinned, pinned_false, both_unset],
            &nodes,
            Some(false),
        );
        assert_eq!(configs[0].verify_cert, Some(true), "pool pin wins");
        assert_eq!(configs[1].verify_cert, Some(false), "site fills in");
        assert_eq!(
            configs[2].verify_cert,
            Some(false),
            "opt-out keeps skipping"
        );
        assert_eq!(configs[3].verify_cert, Some(false), "site fills in");

        // No site opinion: the wire value stays `NULL` and the agent falls
        // back to `RuleBundle.origin_verify_cert`.
        let unpinned =
            pool_model("unpinned", "round_robin", Some("e.example.com"), false);
        let nodes = vec![node_model(unpinned.id, "10.0.0.5:8080", 1)];
        let configs = pools_to_proto(&[unpinned], &nodes, None);
        assert_eq!(
            configs[0].verify_cert, None,
            "global fallback is the agent's job"
        );
    }

    #[test]
    fn pools_carry_health_check_only_when_enabled() {
        let nodes_of =
            |pool_id: Uuid| vec![node_model(pool_id, "10.0.0.1:8080", 1)];

        // Disabled: no health check message at all — the agent stays on its
        // default TCP probe.
        let pool = pool_model("plain", "round_robin", None, false);
        let nodes = nodes_of(pool.id);
        let configs = pools_to_proto(&[pool], &nodes, None);
        assert_eq!(configs[0].health_check, None);

        // Enabled: every knob rides through, normalized path included.
        let mut pool = pool_model("plain", "round_robin", None, false);
        let nodes = nodes_of(pool.id);
        pool.health_check_enabled = true;
        pool.health_check_path = "/healthz".into();
        pool.health_check_interval_seconds = 15;
        pool.health_check_timeout_ms = 2000;
        pool.health_check_unhealthy_threshold = 3;
        pool.health_check_healthy_threshold = 2;
        let configs = pools_to_proto(&[pool], &nodes, None);
        let hc = configs[0].health_check.as_ref().expect("health check");
        assert!(hc.enabled);
        assert_eq!(hc.path, "/healthz");
        assert_eq!(hc.interval_seconds, 15);
        assert_eq!(hc.timeout_ms, 2000);
        assert_eq!(hc.unhealthy_threshold, 3);
        assert_eq!(hc.healthy_threshold, 2);

        // A corrupt row (zeroes) is clamped instead of producing a
        // zero-timeout probe downstream.
        let mut pool = pool_model("corrupt", "round_robin", None, false);
        let nodes = nodes_of(pool.id);
        pool.health_check_enabled = true;
        pool.health_check_interval_seconds = 0;
        pool.health_check_timeout_ms = 0;
        pool.health_check_unhealthy_threshold = 0;
        pool.health_check_healthy_threshold = 0;
        let configs = pools_to_proto(&[pool], &nodes, None);
        let hc = configs[0].health_check.as_ref().expect("health check");
        assert_eq!(hc.interval_seconds, 1);
        assert_eq!(hc.timeout_ms, 1);
        assert_eq!(hc.unhealthy_threshold, 1);
        assert_eq!(hc.healthy_threshold, 1);
    }

    fn route_model(
        enabled: bool,
        priority: Option<i32>,
        pool_id: Uuid,
    ) -> site_routes::Model {
        site_routes::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::nil(),
            name: "r".into(),
            match_type: route_match_type::EXACT.into(),
            path: "/api".into(),
            priority,
            enabled,
            pool_id,
            ip_group_id: None,
            strip_prefix: false,
            rewrite_path: None,
            upstream_host: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn routes_skip_disabled_and_nodeless_pools() {
        let pool = pool_model("default", "round_robin", None, true);
        let empty = pool_model("empty", "round_robin", None, false);
        let nodes = vec![node_model(pool.id, "10.0.0.1:8080", 1)];

        let routes = vec![
            route_model(true, Some(10), pool.id),
            route_model(false, None, pool.id),
            route_model(true, None, empty.id),
        ];
        let protos = routes_to_proto(
            &routes,
            &[pool.clone(), empty.clone()],
            &nodes,
            &HashMap::new(),
        );
        assert_eq!(protos.len(), 1);
        assert_eq!(protos[0].pool_id, routes[0].pool_id.to_string());
        assert_eq!(protos[0].match_type, route_match_type::EXACT);
        assert_eq!(protos[0].path, "/api");
        assert_eq!(protos[0].priority, Some(10));

        // Losing the last node drops the route along with the pool.
        let protos =
            routes_to_proto(&routes, &[pool, empty], &[], &HashMap::new());
        assert!(protos.is_empty());
    }

    #[test]
    fn route_gates_expand_from_their_ip_group() {
        let pool = pool_model("default", "round_robin", None, true);
        let nodes = vec![node_model(pool.id, "10.0.0.1:8080", 1)];
        let group_id = Uuid::new_v4();
        let group = ip_groups::Model {
            id: group_id,
            name: "internal".into(),
            description: None,
            ip_ranges: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
            action: "allow".into(),
            is_global: false,
            subscription_kind: None,
            subscription_enabled: true,
            source_url: None,
            sync_interval_minutes: None,
            last_synced_at: None,
            last_sync_error: None,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mut gated = route_model(true, None, pool.id);
        gated.ip_group_id = Some(group_id);
        let open = route_model(true, None, pool.id);

        let groups: HashMap<Uuid, ip_groups::Model> =
            [(group_id, group)].into_iter().collect();
        let protos = routes_to_proto(
            &[gated.clone(), open],
            std::slice::from_ref(&pool),
            &nodes,
            &groups,
        );
        assert_eq!(protos.len(), 2);
        assert_eq!(
            protos[0].ip_ranges,
            vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
        );
        // An ungated route keeps matching every client.
        assert!(protos[1].ip_ranges.is_empty());

        // A gate the control plane can no longer resolve drops the route
        // instead of publishing it as match-everything.
        let protos = routes_to_proto(
            &[gated],
            std::slice::from_ref(&pool),
            &nodes,
            &HashMap::new(),
        );
        assert!(protos.is_empty());
    }

    #[test]
    fn trusted_proxy_ranges_merge_site_and_group_entries() {
        let group_id = Uuid::nil();
        let groups = HashMap::from([(
            group_id,
            vec!["10.0.0.0/8".to_string(), "203.0.113.0/24".to_string()],
        )]);
        let site = vec!["10.0.0.0/8".to_string(), "192.0.2.1/32".to_string()];

        // Site entries and group ranges union; duplicates collapse.
        let merged = merge_trusted_proxy_ranges(&site, &[group_id], &groups);
        assert_eq!(
            merged,
            vec![
                "10.0.0.0/8".to_string(),
                "192.0.2.1/32".to_string(),
                "203.0.113.0/24".to_string(),
            ]
        );

        // A group the loader skipped (disabled or deleted) widens nothing.
        let missing =
            merge_trusted_proxy_ranges(&site, &[Uuid::max()], &groups);
        assert_eq!(missing, site);
    }

    fn ip_rule_model(
        group_id: Option<Uuid>,
        ip_ranges: Vec<String>,
    ) -> ip_access_rules::Model {
        ip_access_rules::Model {
            id: Uuid::new_v4(),
            site_id: Uuid::nil(),
            name: "rule".into(),
            ip_ranges,
            action: "block".into(),
            note: None,
            enabled: true,
            priority: 0,
            group_id,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn ip_group_model(id: Uuid, ranges: &[&str]) -> ip_groups::Model {
        ip_groups::Model {
            id,
            name: "group".into(),
            description: None,
            ip_ranges: ranges.iter().map(|r| r.to_string()).collect(),
            action: "allow".into(),
            is_global: false,
            subscription_kind: None,
            subscription_enabled: true,
            source_url: None,
            sync_interval_minutes: None,
            last_synced_at: None,
            last_sync_error: None,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn group_backed_rules_expand_to_live_group_ranges() {
        let group_id = Uuid::new_v4();
        let group =
            ip_group_model(group_id, &["203.0.113.0/24", "198.51.100.7"]);

        // The rule keeps its own action; the ranges come from the group.
        let grouped = ip_rule_model(Some(group_id), Vec::new());
        let mut groups = HashMap::new();
        groups.insert(group_id, group.clone());
        let proto =
            ip_access_rule_to_proto(&grouped, &groups).expect("expands");
        assert_eq!(proto.ip_ranges, group.ip_ranges);
        assert_eq!(proto.action, ip_action::to_proto("block"));
        assert_eq!(proto.name, "rule");

        // A group-backed rule whose group is missing or disabled is skipped
        // when it has no ranges of its own.
        assert!(ip_access_rule_to_proto(&grouped, &HashMap::new()).is_none());

        // A manual rule keeps its own ranges and ignores groups entirely.
        let manual = ip_rule_model(None, vec!["10.0.0.0/8".to_string()]);
        let proto = ip_access_rule_to_proto(&manual, &groups).expect("manual");
        assert_eq!(proto.ip_ranges, vec!["10.0.0.0/8".to_string()]);

        // A rule with neither group nor ranges matches nothing and is skipped.
        let empty = ip_rule_model(None, Vec::new());
        assert!(ip_access_rule_to_proto(&empty, &groups).is_none());
    }
}
