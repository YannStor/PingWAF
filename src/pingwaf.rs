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

//! PingWAF mode startup logic.
//!
//! Handles the three operating modes: Server (control plane only),
//! Agent (data plane only), and AllInOne (both in a single process).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pingap_cache::new_storage_clear_service;

use crate::certificates::{new_certificate_provider, try_update_certificates};
use crate::cli::{
    AgentOpts, AllInOneOpts, CommonOpts, PingWafCli, PingWafCommand, ServerOpts,
};
use crate::config_manager::try_init_memory_config_manager;
use crate::locations::{new_location_provider, try_init_locations};
use crate::plugin::{new_plugin_provider, try_init_plugins};
use crate::server_locations::{
    new_server_locations_provider, try_init_server_locations,
};
use crate::upstreams::{new_upstream_provider, try_init_upstreams};
use pingap_acme::new_lets_encrypt_service;
use pingap_config::{
    BasicConf, CertificateConf, LocationConf, PingapConfig, PingapTomlConfig,
    PluginConf, ServerConf as PingapServerConf, UpstreamConf,
    normalize_dns_provider,
};
use pingap_core::BackgroundTaskService;
use pingap_proxy::{
    AppContext, Server as ProxyServer, ServerConf, parse_from_conf,
};
use pingap_upstream::new_upstream_health_check_task;
use pingora::server;
use pingora::server::configuration::Opt;
use pingora::services::background::background_service;
use pingwaf_agent::cache::{
    CachedRules, HealthCheckConfig, ResponseReplaceConfig, RuleCache, SslConfig,
};
use pingwaf_agent::config::AgentConfig;
use pingwaf_server::ServerConfig;
use tracing::{error, info, warn};

/// The operating mode for PingWAF.
pub enum RunMode {
    /// Control plane only: REST API + gRPC server + PostgreSQL
    Server(Box<ServerConfig>),
    /// Data plane only: connects to a remote control plane
    Agent(Box<AgentConfig>),
    /// Both control plane and data plane in a single process
    AllInOne(Box<ServerConfig>, Box<AgentConfig>),
}

/// Convert CLI server options into a `ServerConfig`.
fn server_config_from_opts(opts: &ServerOpts) -> ServerConfig {
    let mut config = ServerConfig::from_env();
    // CLI flags override environment
    config.db_url = opts.common.db_url.clone();
    config.http_addr = opts.common.admin_addr.clone();
    config.grpc_addr = opts.common.grpc_addr.clone();
    config.grpc_tls_cert = opts.common.grpc_tls_cert.clone();
    config.grpc_tls_key = opts.common.grpc_tls_key.clone();
    config.grpc_tls_mode = opts.common.grpc_tls_mode;
    config.jwt_secret = opts.jwt_secret.clone();
    config.default_admin_email = opts.admin_email.clone();
    config.default_admin_password = opts.admin_password.clone();
    config.serve_frontend = opts.serve_frontend;
    apply_tls_opts(&mut config, &opts.common);
    config
}

/// Convert CLI all-in-one options into a `ServerConfig`.
fn server_config_from_all_in_one(opts: &AllInOneOpts) -> ServerConfig {
    let mut config = ServerConfig::from_env();
    config.db_url = opts.common.db_url.clone();
    config.http_addr = opts.common.admin_addr.clone();
    config.grpc_addr = opts.common.grpc_addr.clone();
    config.grpc_tls_cert = opts.common.grpc_tls_cert.clone();
    config.grpc_tls_key = opts.common.grpc_tls_key.clone();
    config.grpc_tls_mode = opts.common.grpc_tls_mode;
    config.jwt_secret = opts.jwt_secret.clone();
    config.default_admin_email = opts.admin_email.clone();
    config.default_admin_password = opts.admin_password.clone();
    config.serve_frontend = opts.serve_frontend;
    apply_tls_opts(&mut config, &opts.common);
    config
}

/// Layers the shared TLS options onto a server config.
///
/// The SAN list is only replaced when the operator actually spelled one out,
/// so the built-in defaults survive an invocation without `--tls-sans`.
fn apply_tls_opts(config: &mut ServerConfig, opts: &CommonOpts) {
    config.tls_enabled = opts.tls_enabled;
    if !opts.tls_sans.is_empty() {
        config.tls_sans = opts.tls_sans.clone();
    }
    config.public_host = opts.public_host.clone();
}

/// Convert CLI agent options into an `AgentConfig`.
fn agent_config_from_opts(opts: &AgentOpts) -> AgentConfig {
    AgentConfig {
        server_url: opts.server_url.clone(),
        api_key: opts.api_key.clone(),
        agent_id: String::new(),
        server_ca_cert: opts.server_ca_cert.clone(),
        server_ca_pem: None,
        heartbeat_interval_secs: opts.heartbeat_interval_secs,
        cache_dir: opts.cache_dir.clone(),
        log_batch_size: opts.log_batch_size,
        log_flush_interval_secs: opts.log_flush_interval_secs,
        max_body_log_size: opts.max_body_log_size,
        reconnect_initial_delay_ms: 1000,
        reconnect_max_delay_ms: 60000,
        fail_open: opts.fail_open,
        probe_interval_secs: pingwaf_agent::probe::DEFAULT_INTERVAL_SECS,
        probe_disk_path: "/".to_string(),
        metrics_ship_interval_secs: opts.metrics_ship_interval_secs,
    }
}

/// Convert CLI all-in-one options into an `AgentConfig`.
///
/// In all-in-one mode the agent connects to the local server via loopback.
/// TLS is the default: the URL switches to `https://` and the CA is resolved
/// at boot (an explicitly configured certificate file is trusted directly;
/// otherwise `run` injects the self-signed control-plane certificate as
/// inline PEM once the database is reachable).
fn agent_config_from_all_in_one(opts: &AllInOneOpts) -> AgentConfig {
    // Derive the loopback gRPC URL from the configured gRPC address
    let port = extract_port(&opts.common.grpc_addr);
    let (server_url, server_ca_cert) =
        match (&opts.common.grpc_tls_cert, &opts.common.grpc_tls_key) {
            (Some(cert), Some(_)) => {
                (format!("https://127.0.0.1:{port}"), Some(cert.clone()))
            },
            _ => match opts.common.grpc_tls_mode {
                pingwaf_server::config::GrpcTlsMode::Off => {
                    (format!("http://127.0.0.1:{port}"), None)
                },
                pingwaf_server::config::GrpcTlsMode::Tls => {
                    (format!("https://127.0.0.1:{port}"), None)
                },
            },
        };
    AgentConfig {
        server_url,
        api_key: opts.api_key.clone(),
        agent_id: String::new(),
        server_ca_cert,
        server_ca_pem: None,
        heartbeat_interval_secs: opts.heartbeat_interval_secs,
        cache_dir: opts.cache_dir.clone(),
        log_batch_size: opts.log_batch_size,
        log_flush_interval_secs: opts.log_flush_interval_secs,
        max_body_log_size: opts.max_body_log_size,
        reconnect_initial_delay_ms: 1000,
        reconnect_max_delay_ms: 60000,
        fail_open: opts.fail_open,
        probe_interval_secs: pingwaf_agent::probe::DEFAULT_INTERVAL_SECS,
        probe_disk_path: "/".to_string(),
        metrics_ship_interval_secs: opts.metrics_ship_interval_secs,
    }
}

/// Extract port from an address string like "0.0.0.0:9090".
fn extract_port(addr: &str) -> &str {
    addr.rsplit(':').next().unwrap_or("9090")
}

/// Build the `RunMode` from the parsed CLI.
///
/// The maintenance commands never reach this: [`main`] routes them to
/// [`crate::admin::run`] before a run mode is built, and a panic here means
/// that routing was broken.
pub fn build_run_mode(cli: PingWafCli) -> RunMode {
    match cli.command {
        PingWafCommand::Server(ref opts) => {
            RunMode::Server(Box::new(server_config_from_opts(opts)))
        },
        PingWafCommand::Agent(ref opts) => {
            RunMode::Agent(Box::new(agent_config_from_opts(opts)))
        },
        PingWafCommand::AllInOne(ref opts) => {
            let server_config = server_config_from_all_in_one(opts);
            let agent_config = agent_config_from_all_in_one(opts);
            RunMode::AllInOne(Box::new(server_config), Box::new(agent_config))
        },
        PingWafCommand::User { .. }
        | PingWafCommand::Mode { .. }
        | PingWafCommand::Security { .. }
        | PingWafCommand::Config { .. } => {
            unreachable!("maintenance commands do not build a run mode")
        },
    }
}

/// Sanitize a control-plane LB algorithm into a pingap `algo` value.
///
/// pingap accepts `round_robin` (its default), `random`,
/// `least_connections` and `hash:<type>[:<key>]` with type in {ip, url,
/// path, header, cookie, query}; anything else — including legacy enum
/// Debug names such as `lbconsistenthash` — is a hard error at upstream
/// construction, so it must collapse to the default here.
fn sanitize_algo(algo: &str) -> Option<String> {
    let algo = algo.trim();
    if algo.is_empty() || algo == "round_robin" {
        return None;
    }
    if matches!(algo, "random" | "least_connections") {
        return Some(algo.to_string());
    }
    let spec = algo.strip_prefix("hash:")?;
    let hash_type = spec.split(':').next().unwrap_or_default();
    if matches!(
        hash_type,
        "ip" | "url" | "path" | "header" | "cookie" | "query"
    ) {
        Some(algo.to_string())
    } else {
        None
    }
}

/// Name under which the WAF plugin is registered and referenced from
/// every generated location.
const WAF_PLUGIN_NAME: &str = "pingwaf:waf";

/// Name under which the edge cache plugin is registered. One process-wide
/// instance serves every site: the plugin resolves each host's cache rules
/// from the agent's rule cache, so wiring it into the locations is all the
/// data plane needs to actually cache.
const CACHE_PLUGIN_NAME: &str = "pingwaf:cache";

/// Name under which the CC/challenge plugin is registered. Like the WAF and
/// cache plugins it resolves per-site settings from the agent's rule cache;
/// it also serves the challenge verify endpoint, which every site needs
/// whenever a WAF, IP or geo rule answers with a challenge.
const CHALLENGE_PLUGIN_NAME: &str = "pingwaf:challenge";

/// Name under which the rewrite plugin is registered. It rewrites request
/// and response headers/paths/bodies per the site's rewrite rules, resolved
/// from the agent's rule cache at request time.
const REWRITE_PLUGIN_NAME: &str = "pingwaf:rewrite";

/// Name under which the custom error page plugin is registered. It replaces
/// upstream error responses with the site's configured pages (falling back to
/// the built-in PingWAF pages); plugin-generated responses such as WAF blocks
/// answer early and never reach its response phase.
const ERROR_PAGE_PLUGIN_NAME: &str = "pingwaf:error_page";

/// Build a `PingapConfig` from the agent's cached site rules.
///
/// Each origin pool becomes one upstream keyed by its pool id (or the
/// legacy per-site name for caches written before pools existed). The
/// default pool — or the only pool, when no routes exist — receives the
/// site's `/` fallback location, and every enabled route becomes an
/// additional location carrying the pingap path marker for its match
/// type. All sites share a single server listening on ports 80 and 443
/// with TLS enabled via the global certificate store.
/// Builds the per-site plugins that enforce TLS postures outside the WAF
/// plugin, and returns their names in the order they should run.
///
/// Both postures are per-site settings, so each site gets its own plugin
/// instance; the instance name carries the site id to keep them apart.
fn site_posture_plugins(
    site_id: &str,
    ssl: Option<&SslConfig>,
    plugins: &mut HashMap<String, PluginConf>,
) -> Vec<String> {
    let mut names = Vec::new();
    let Some(ssl) = ssl.filter(|ssl| ssl.enabled) else {
        return names;
    };

    // `max-age=0` would tell browsers to stop honouring HSTS, which is the
    // opposite of what the switch means — treat it as "not configured".
    if ssl.hsts_enabled && ssl.hsts_max_age > 0 {
        let name = format!("{site_id}_hsts");
        let mut conf = PluginConf::new();
        conf.insert(
            "category".to_string(),
            toml::Value::String("response_headers".to_string()),
        );
        conf.insert(
            "add_headers".to_string(),
            toml::Value::Array(vec![toml::Value::String(format!(
                "Strict-Transport-Security: max-age={}",
                ssl.hsts_max_age
            ))]),
        );
        plugins.insert(name.clone(), conf);
        names.push(name);
    }

    // The redirect plugin compares the request's TLS state against the
    // desired one, so sharing a location between :80 and :443 is safe — only
    // the plaintext listener redirects.
    if ssl.always_use_https {
        let name = format!("{site_id}_https");
        let mut conf = PluginConf::new();
        conf.insert(
            "category".to_string(),
            toml::Value::String("redirect".to_string()),
        );
        conf.insert("http_to_https".to_string(), toml::Value::Boolean(true));
        conf.insert("status".to_string(), toml::Value::Integer(301));
        plugins.insert(name.clone(), conf);
        names.push(name);
    }

    names
}

/// Builds the site's `sub_filter` plugin — the data-plane half of the control
/// plane's `sites.response_replace` policy — and returns its name.
///
/// Deliberately not folded into [`site_posture_plugins`]: that function returns
/// early for a site without TLS, which would silently drop the replacement for
/// every plain-HTTP site.
///
/// The config keys are the ones `pingap-plugin/src/sub_filter.rs` reads:
/// `path` (regex the request path must match), `status_codes` (a
/// comma-separated list) and `filters` (rule strings, each
/// `sub_filter '<pattern>' '<replacement>' [flags]`). The `g` flag is always
/// stated so a body replacement applies to every occurrence — without it the
/// plugin replaces only the first one.
///
/// Known limitation: the plugin buffers and rewrites the body bytes without
/// decompressing them, so a response the origin sent with
/// `content-encoding: gzip` (or br/zstd) is inspected in its compressed form —
/// the pattern does not match, nothing is replaced, and the body is still
/// re-sent chunked because the plugin already dropped `Content-Length`. The
/// control plane cannot compensate for that from here.
fn site_response_replace_plugin(
    site_id: &str,
    policy: Option<&ResponseReplaceConfig>,
    plugins: &mut HashMap<String, PluginConf>,
) -> Vec<String> {
    let Some(policy) = policy.filter(|policy| !policy.rules.is_empty()) else {
        return Vec::new();
    };

    let filters: Vec<toml::Value> = policy
        .rules
        .iter()
        .map(|rule| {
            // `subs_filter` compiles the pattern as a regex, `sub_filter`
            // matches it literally — the two directives the plugin knows.
            let directive = if rule.is_regex {
                "subs_filter"
            } else {
                "sub_filter"
            };
            toml::Value::String(format!(
                "{directive} '{}' '{}' g",
                rule.pattern, rule.replacement
            ))
        })
        .collect();

    let mut conf = PluginConf::new();
    conf.insert(
        "category".to_string(),
        toml::Value::String("sub_filter".to_string()),
    );
    // An empty `path` in the plugin means "every path"; stating it anyway would
    // be misleading in the generated config, so it is left out.
    if !policy.path.trim().is_empty() {
        conf.insert(
            "path".to_string(),
            toml::Value::String(policy.path.trim().to_string()),
        );
    }
    // Same for the status filter: absent = all status codes.
    //
    // Sorted and deduplicated here as well as on the write path
    // (`api::sites::normalise_response_replace`): a policy stored before that
    // normalisation existed would otherwise render as `200,200,201` in the
    // generated config, and the agent keys its plugin instances on a hash of
    // this string, so the same policy would look like two different plugins.
    if !policy.status_codes.is_empty() {
        let mut codes = policy.status_codes.clone();
        codes.sort_unstable();
        codes.dedup();
        conf.insert(
            "status_codes".to_string(),
            toml::Value::String(
                codes
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        );
    }
    conf.insert("filters".to_string(), toml::Value::Array(filters));

    // One instance per site: the rules are the site's, so a shared instance
    // would apply one site's text to another's responses.
    let name = format!("{site_id}_sub_filter");
    plugins.insert(name.clone(), conf);
    vec![name]
}

/// Synthesizes the data-plane health check URL from the control plane's
/// per-pool [`HealthCheckConfig`]. The URL host is the upstream (pool) name —
/// pingap only uses it as the probe request's Host header, nothing resolves
/// it — and the query carries the tunables `pingap-health` understands
/// (`check_frequency`, `connection_timeout`/`read_timeout`, `failure`,
/// `success`). Values are clamped so a corrupt cache entry can never produce
/// a zero-timeout or zero-frequency probe.
fn health_check_url(upstream_name: &str, hc: &HealthCheckConfig) -> String {
    let path = if hc.path.is_empty() {
        "/".to_string()
    } else if hc.path.starts_with('/') {
        hc.path.clone()
    } else {
        format!("/{}", hc.path)
    };
    format!(
        "http://{upstream_name}{path}?check_frequency={}s&\
         connection_timeout={}ms&read_timeout={}ms&failure={}&success={}",
        hc.interval_seconds.max(1),
        hc.timeout_ms.max(1),
        hc.timeout_ms.max(1),
        hc.unhealthy_threshold.max(1),
        hc.healthy_threshold.max(1),
    )
}

/// Hard ceiling for the withheld-body stage. Mirrors
/// DEFERRED_BODY_MAX_STAGE_SECS in pingap-plugin/src/waf.rs: the plugin
/// clamps to this ceiling itself, so a configuration stating a larger value
/// would only hide the effective one.
const WAF_BODY_STAGE_MAX_SECS: u64 = 30;

/// Default withheld-body stage timeout, matching the plugin default so a
/// generated configuration and an operator-written one agree.
const WAF_BODY_STAGE_DEFAULT_SECS: u64 = 30;

/// Resolves the `body_stage_timeout_secs` value written into the generated
/// WAF plugin conf: `min(site downstream read timeout, 30s)`, with unset
/// meaning 30s. That is the rule the plugin applies when the key is absent
/// (pingap-plugin/src/waf.rs, the reader of `body_stage_timeout_secs`).
///
/// `site_read_timeout` is `None` for every site today: neither the `Site`
/// protocol message nor the agent site cache carries a downstream timeout,
/// and the generated listeners use pingap defaults. Keeping the resolver
/// separate means exposing a site-level setting later only changes the
/// argument, never the clamping rule.
///
/// The value is whole seconds and the lower bound is 1s, not 0: the plugin
/// reads 0 as "do not withhold the body at all", which is not the intended
/// meaning of a sub-second site timeout (audit R-06). A `Duration` below one
/// second therefore states 1s — the shortest stage the plugin can honour —
/// rather than silently switching body buffering off, and a zero timeout falls
/// into the same floor instead of disabling the WAF's body inspection.
fn waf_body_stage_timeout_secs(site_read_timeout: Option<Duration>) -> i64 {
    site_read_timeout
        .unwrap_or(Duration::from_secs(WAF_BODY_STAGE_DEFAULT_SECS))
        .as_secs()
        .clamp(1, WAF_BODY_STAGE_MAX_SECS) as i64
}

fn cached_rules_to_pingap_config(
    cached: &CachedRules,
    cache_dir: &Path,
) -> Option<PingapConfig> {
    if cached.sites.is_empty() {
        return None;
    }

    // The cache plugin carries no per-site settings of its own — rules,
    // namespaces and quotas all flow from the agent's rule cache at request
    // time. It only earns a slot in the config when some site actually has
    // cache rules; for the rest it would be dead weight.
    let has_cache_rules = cached
        .sites
        .values()
        .any(|site| site.cache_rules.iter().any(|rule| rule.enabled));

    let mut upstreams: HashMap<String, UpstreamConf> = HashMap::new();
    let mut locations: HashMap<String, LocationConf> = HashMap::new();
    let mut certificates: HashMap<String, CertificateConf> = HashMap::new();
    let mut location_names: Vec<String> = Vec::new();
    // PEM bundle of the CAs every mTLS-enabled site trusts. The listener
    // verifies client certificates as a whole, so the anchor is the union
    // across sites; pinning a certificate to its site is left to the WAF
    // plugin, which sees the request's SNI.
    let mut mtls_ca_bundle = String::new();
    // The WAF plugin is referenced from every location: this is what makes
    // the data plane enforce rules and emit access/security events.
    let mut plugins: HashMap<String, PluginConf> = HashMap::new();
    let mut waf_conf = PluginConf::new();
    waf_conf.insert(
        "category".to_string(),
        toml::Value::String("waf".to_string()),
    );
    // The withheld-body stage deadline sits on the request path, so the
    // generated configuration states it instead of leaving the value
    // implicit. 30s is the effective value today: the plugin mirrors the
    // site downstream_read_timeout but hard-caps it at 30s, and the control
    // plane exposes no site-level downstream timeout yet (the generated
    // listeners use pingap defaults). Exposing one later only has to feed
    // waf_body_stage_timeout_secs below.
    waf_conf.insert(
        "body_stage_timeout_secs".to_string(),
        toml::Value::Integer(waf_body_stage_timeout_secs(None)),
    );
    plugins.insert(WAF_PLUGIN_NAME.to_string(), waf_conf);
    plugins.insert(
        CHALLENGE_PLUGIN_NAME.to_string(),
        toml::from_str::<PluginConf>(r###"category = "challenge""###)
            .unwrap_or_default(),
    );
    plugins.insert(
        REWRITE_PLUGIN_NAME.to_string(),
        toml::from_str::<PluginConf>(r###"category = "rewrite""###)
            .unwrap_or_default(),
    );
    plugins.insert(
        ERROR_PAGE_PLUGIN_NAME.to_string(),
        toml::from_str::<PluginConf>(r###"category = "error_page""###)
            .unwrap_or_default(),
    );
    // The cache master switch gates everything: with it off the data plane
    // never sees a cache plugin, regardless of the rules any site carries.
    let global_cache = cached.global_cache.clone().unwrap_or_default();
    let cache_enabled = has_cache_rules && global_cache.master_enabled();
    if cache_enabled {
        let mut cache_conf = PluginConf::new();
        cache_conf.insert(
            "category".to_string(),
            toml::Value::String("cache".to_string()),
        );
        // The disk budget rides on the directory URL (`FileCacheParams`
        // parses `?max_size=`): pingora's `ensure_disk_space` then evicts by
        // LRU across every namespace sharing the backend. `0` = unlimited.
        let directory = match global_cache.max_space_mb() {
            0 => cache_dir.to_string_lossy().to_string(),
            space_mb => {
                format!("{}?max_size={space_mb}mb", cache_dir.to_string_lossy())
            },
        };
        cache_conf
            .insert("directory".to_string(), toml::Value::String(directory));
        // pingora's default 1MB ceiling silently refuses to cache anything
        // larger (the response header stage rejects it before the body ever
        // fills). Magento-style merged JS/CSS bundles run several MB and are
        // exactly the assets caching exists for, so the ceiling is raised
        // here. `ByteSize` parses decimal units — the 16 MiB default is
        // 16_000_000 bytes, comfortably above a ~10MB bundle. Actual disk
        // usage stays bounded by each site's `disk_quota_mb` and the LRU
        // eviction manager.
        cache_conf.insert(
            "max_file_size".to_string(),
            toml::Value::String(format!(
                "{}mb",
                global_cache.max_file_size_mb()
            )),
        );
        // A rule without an explicit edge TTL falls back to this floor;
        // `0` (the default) keeps the old behaviour of no fallback at all.
        let default_ttl = global_cache.default_edge_ttl_seconds();
        if default_ttl > 0 {
            cache_conf.insert(
                "max_ttl".to_string(),
                toml::Value::String(format!("{default_ttl}s")),
            );
        }
        plugins.insert(CACHE_PLUGIN_NAME.to_string(), cache_conf);
    }
    let mut location_plugins: Vec<String> = vec![
        WAF_PLUGIN_NAME.to_string(),
        CHALLENGE_PLUGIN_NAME.to_string(),
        REWRITE_PLUGIN_NAME.to_string(),
        ERROR_PAGE_PLUGIN_NAME.to_string(),
    ];
    if cache_enabled {
        location_plugins.push(CACHE_PLUGIN_NAME.to_string());
    }

    for (site_id, site) in &cached.sites {
        if site.domain.is_empty() {
            continue;
        }

        // One upstream per origin pool. Pools without peers are skipped:
        // an address-less upstream cannot be constructed.
        let mut pool_keys: Vec<String> = Vec::new();
        let mut default_key: Option<String> = None;
        for (i, up) in site.upstreams.iter().enumerate() {
            if up.peers.is_empty() {
                continue;
            }
            let name = if up.pool_id.is_empty() {
                if site.upstreams.len() == 1 {
                    format!("{site_id}_upstream")
                } else {
                    format!("{site_id}_upstream_{i}")
                }
            } else {
                up.pool_id.clone()
            };

            let addrs: Vec<String> = up
                .peers
                .iter()
                .map(|p| {
                    let addr = p
                        .address
                        .strip_prefix("https://")
                        .or_else(|| p.address.strip_prefix("http://"))
                        .unwrap_or(&p.address);
                    if p.weight > 1 {
                        format!("{} {}", addr, p.weight)
                    } else {
                        addr.to_string()
                    }
                })
                .collect();

            // Multi-node pools get request-level protection by default:
            // without backend stats the circuit breaker can never observe
            // failures, and the control plane exposes no knobs for either.
            // Single-node pools are left untouched — with no alternative
            // backend an open breaker only short-circuits into 503.
            let multi_peer = up.peers.len() > 1;
            let conf = UpstreamConf {
                addrs,
                algo: sanitize_algo(&up.algo),
                sni: if up.sni.is_empty() {
                    None
                } else {
                    Some(up.sni.clone())
                },
                // Passed through untouched on purpose: `null` means "follow
                // the deployment default", which `basic.origin_verify_cert`
                // below always states (the managed control plane's default is
                // "do not verify"). Resolving it here would erase the
                // distinction between "this pool opted out" and "this pool
                // never said", and the global switch could no longer reach a
                // pool that was created before it existed.
                verify_cert: up.verify_cert,
                // The pool's address family, in the only spelling
                // `UpstreamConf` has: `ipv4` pins IPv4, while `auto` and
                // `ipv6` leave it unset. `auto` then prefers IPv4 in the data
                // plane - which is what fixes the 503 on a host without an
                // IPv6 route. A true IPv6-only pin needs its own
                // `UpstreamConf` field; see the delivery note.
                ipv4_only: (up.address_family == "ipv4").then_some(true),
                // Keep the three-value spelling too: `ipv6` must reach the
                // data plane as a pin, and `auto` stays auto.
                address_family: Some(up.address_family.clone()),
                connection_timeout: if up.connection_timeout_ms > 0 {
                    Some(Duration::from_millis(up.connection_timeout_ms as u64))
                } else {
                    None
                },
                read_timeout: if up.read_timeout_ms > 0 {
                    Some(Duration::from_millis(up.read_timeout_ms as u64))
                } else {
                    None
                },
                write_timeout: if up.write_timeout_ms > 0 {
                    Some(Duration::from_millis(up.write_timeout_ms as u64))
                } else {
                    None
                },
                health_check: up
                    .health_check
                    .as_ref()
                    .filter(|h| h.enabled)
                    .map(|h| health_check_url(&name, h)),
                enable_backend_stats: multi_peer.then_some(true),
                circuit_break_max_consecutive_failures: multi_peer.then_some(5),
                circuit_break_max_failure_percent: multi_peer.then_some(50),
                circuit_break_min_requests_threshold: multi_peer.then_some(10),
                circuit_break_open_duration: multi_peer
                    .then_some(Duration::from_secs(10)),
                // With several origins, a misjudged health check or an
                // all-open breaker should degrade to the least-bad backend
                // instead of failing the site with instant 503s.
                enable_unhealthy_fallback: multi_peer.then_some(true),
                ..Default::default()
            };
            if up.is_default {
                default_key = Some(name.clone());
            }
            pool_keys.push(name.clone());
            upstreams.insert(name, conf);
        }

        // The `/` fallback location points at the default pool. Caches
        // written before pools existed mark nothing default, so the only
        // pool serves when no routes exist.
        let fallback_key = default_key.clone().or_else(|| {
            if site.routes.is_empty() {
                pool_keys.first().cloned()
            } else {
                None
            }
        });

        let host = if site.alternate_domains.is_empty() {
            site.domain.clone()
        } else {
            let mut hosts = vec![site.domain.clone()];
            hosts.extend(site.alternate_domains.clone());
            hosts.join(",")
        };

        let mut site_plugins = location_plugins.clone();
        site_plugins.extend(site_posture_plugins(
            site_id,
            site.ssl_config.as_ref(),
            &mut plugins,
        ));
        // Response body replacement: a separate instance per site, registered
        // only when the site actually configures a policy.
        site_plugins.extend(site_response_replace_plugin(
            site_id,
            site.response_replace.as_ref(),
            &mut plugins,
        ));

        if let Some(key) = fallback_key {
            let loc_name = format!("{site_id}_loc");
            locations.insert(
                loc_name.clone(),
                LocationConf {
                    upstream: Some(key),
                    host: Some(host.clone()),
                    path: Some("/".to_string()),
                    plugins: Some(site_plugins.clone()),
                    // The fallback must sort behind every route: with the
                    // auto weight (128) any route whose priority was 127 or
                    // less ranked below this catch-all `/` location and
                    // never matched. Pin it to the floor instead.
                    weight: Some(0),
                    ..Default::default()
                },
            );
            location_names.push(loc_name);
        }

        for route in &site.routes {
            if !route.enabled {
                continue;
            }
            // Route only to pools this site actually built — an empty pool
            // has no upstream to receive traffic. Fall back to the site's
            // default pool instead of silently dropping the route.
            let target = if pool_keys.contains(&route.pool_id) {
                route.pool_id.clone()
            } else {
                match default_key.clone().or_else(|| pool_keys.first().cloned())
                {
                    Some(fallback) => {
                        warn!(
                            site = %site.domain,
                            route = %route.id,
                            pool = %route.pool_id,
                            "route pool has no peers; falling back to the site default pool"
                        );
                        fallback
                    },
                    None => {
                        warn!(
                            site = %site.domain,
                            route = %route.id,
                            "route pool has no peers and the site has no usable upstream; route skipped"
                        );
                        continue;
                    },
                }
            };
            let path = match route.match_type.as_str() {
                "exact" => format!("={}", route.path),
                "regex" => format!("~{}", route.path),
                _ => route.path.clone(),
            };
            let loc_name = format!("{site_id}_route_{}", route.id);
            locations.insert(
                loc_name.clone(),
                LocationConf {
                    upstream: Some(target),
                    host: Some(host.clone()),
                    path: Some(path),
                    weight: route
                        .priority
                        .map(|p| p.clamp(1, u16::MAX as i32) as u16),
                    // A route may be gated on an IP group; the location only
                    // matches clients inside those ranges.
                    match_ip_ranges: (!route.ip_ranges.is_empty())
                        .then(|| route.ip_ranges.clone()),
                    // What the origin receives, when the route rewrites the
                    // path: an empty `rewrite_path` on the wire means "unset".
                    strip_prefix: route.strip_prefix.then_some(true),
                    rewrite_path: (!route.rewrite_path.trim().is_empty())
                        .then(|| route.rewrite_path.trim().to_string()),
                    // The `Host` the origin receives. An empty value on the
                    // wire means "unset" — keep the client's Host, which is
                    // what a route proxying the site's own origin wants. A
                    // mirror route points this at the mirrored site's name so
                    // its virtual host answers instead of 404ing.
                    upstream_host: (!route.upstream_host.trim().is_empty())
                        .then(|| route.upstream_host.trim().to_string()),
                    plugins: Some(site_plugins.clone()),
                    ..Default::default()
                },
            );
            location_names.push(loc_name);
        }

        // Convert SSL certificate: an uploaded PEM is served as-is, while a
        // site asking for ACME without one gets a certificate entry the
        // lets-encrypt task issues against — and later fills in — inside
        // this config.
        if let Some(ref ssl) = site.ssl_config
            && ssl.enabled
        {
            let domains = if site.alternate_domains.is_empty() {
                site.domain.clone()
            } else {
                let mut d = vec![site.domain.clone()];
                d.extend(site.alternate_domains.clone());
                d.join(",")
            };
            let cert = if !ssl.cert_pem.is_empty() {
                Some(CertificateConf {
                    domains: Some(domains),
                    tls_cert: Some(ssl.cert_pem.clone()),
                    tls_key: Some(ssl.key_pem.clone()),
                    ..Default::default()
                })
            } else if ssl.acme_enabled && !ssl.acme_email.is_empty() {
                acme_certificate_conf(ssl, domains)
            } else {
                None
            };
            if let Some(cert) = cert {
                certificates.insert(format!("{site_id}_cert"), cert);
            }
        }

        // A site that turns mTLS on contributes its trust anchor to the
        // shared listener.
        if let Some(ssl) = site.ssl_config.as_ref()
            && ssl.mtls_enabled
            && !ssl.mtls_client_ca.trim().is_empty()
        {
            mtls_ca_bundle.push_str(ssl.mtls_client_ca.trim());
            mtls_ca_bundle.push('\n');
        }
    }

    if location_names.is_empty() {
        return None;
    }

    // TLS is a per-server switch in pingap: `global_certificates` turns it
    // on for every address that server listens on, so 80 and 443 cannot
    // share one server — a merged listener ran plaintext HTTP through TLS
    // handshakes, which also broke ACME HTTP-01 validation on port 80.
    //
    // 443 is bound even before the first certificate exists: the listener
    // comes up with an empty provider and handshakes fail until issuance
    // completes, but the moment a certificate is issued or uploaded the
    // provider serves it — no restart, no listener rebuild. Binding 443
    // only once a certificate existed left fresh deployments with the port
    // closed until the whole process restarted.
    if certificates.is_empty() {
        warn!(
            "data plane: no certificates yet — TLS handshakes on 443 will \
             fail until one is issued or uploaded"
        );
    }
    let mut servers: HashMap<String, PingapServerConf> = HashMap::new();
    servers.insert(
        "pingwaf".to_string(),
        PingapServerConf {
            addr: "0.0.0.0:80".to_string(),
            locations: Some(location_names.clone()),
            global_certificates: Some(false),
            ..Default::default()
        },
    );
    servers.insert(
        "pingwaf_tls".to_string(),
        PingapServerConf {
            addr: "0.0.0.0:443".to_string(),
            locations: Some(location_names),
            global_certificates: Some(true),
            client_ca_pem: (!mtls_ca_bundle.is_empty())
                .then_some(mtls_ca_bundle),
            ..Default::default()
        },
    );

    Some(PingapConfig {
        basic: BasicConf {
            // Always a concrete value, never `None`: the pools that do not
            // state their own `verify_cert` (anything created before the
            // global switch existed, and anything that explicitly opted into
            // "follow the default") resolve against it, and a `None` here
            // would fall through to pingora's strict default and 502 every
            // self-signed origin. An agent that has not synced yet keeps the
            // historical lenient behaviour, which is also the control
            // plane's default.
            origin_verify_cert: Some(
                cached.origin_verify_cert.unwrap_or(false),
            ),
            ..Default::default()
        },
        upstreams,
        locations,
        servers,
        certificates,
        plugins,
        ..Default::default()
    })
}

/// Build a `PingapConfig` from the agent's cached rules.
fn build_pingap_config(rule_cache: &RuleCache) -> Option<PingapConfig> {
    cached_rules_to_pingap_config(
        &rule_cache.all_sites(),
        rule_cache.cache_dir(),
    )
}

/// Build the certificate entry a lets-encrypt issuance is driven by.
///
/// `acme` is only a marker (never parsed); the email keeps the convention
/// legacy pingap used so operators recognize it in a config dump. DNS-01
/// carries the provider plus credentials: the endpoint defaults to the
/// provider's API host and every `acme_dns_config` entry becomes a query
/// pair — the layout pingap's DNS tasks parse.
/// Returns `None` when the order cannot be issued and must be skipped:
/// a wildcard hostname only validates through DNS-01, so an entry that would
/// fall back to HTTP-01 is dropped (with an error log) instead of making the
/// lets-encrypt task retry a doomed order forever. The API refuses the same
/// combination, so this only fires for rows written before that check existed.
fn acme_certificate_conf(
    ssl: &SslConfig,
    domains: String,
) -> Option<CertificateConf> {
    let wildcard = domains
        .split(',')
        .any(|domain| domain.trim().starts_with("*."));
    let mut cert = CertificateConf {
        domains: Some(domains.clone()),
        acme: Some(format!("http://{}", ssl.acme_email)),
        ..Default::default()
    };
    if ssl.acme_challenge_type != "AcmeDns01" {
        if wildcard {
            error!(
                domains = %domains,
                "wildcard hostnames need the dns-01 ACME challenge; skipping issuance for the http-01 order"
            );
            return None;
        }
        return Some(cert);
    }
    let provider = match normalize_dns_provider(&ssl.acme_dns_provider) {
        // Unknown provider: stay on HTTP-01 rather than emit an entry the
        // config validation rejects outright.
        Some(provider) => provider,
        None if wildcard => {
            error!(
                domains = %domains,
                "wildcard hostnames need a configured DNS provider for dns-01; skipping issuance"
            );
            return None;
        },
        None => return Some(cert),
    };
    if provider == "manual" {
        // Manual mode renders no dns fields, i.e. the order falls back to
        // HTTP-01, which a wildcard can never pass.
        if wildcard {
            error!(
                domains = %domains,
                "the manual dns-01 provider cannot validate a wildcard automatically; skipping issuance"
            );
            return None;
        }
        return Some(cert);
    }
    cert.dns_challenge = Some(true);
    cert.dns_provider = Some(provider.to_string());
    if let Some(url) = acme_dns_service_url(provider, &ssl.acme_dns_config) {
        cert.dns_service_url = Some(url);
    }
    Some(cert)
}

/// The DNS provider endpoint with credentials appended as query pairs.
///
/// An explicit `endpoint` entry (full URL, or host getting the default
/// scheme) wins; `region` is only used to build the Huawei cloud host.
/// Without either, the provider's documented API host applies — Huawei has
/// per-region hosts and cannot have one. Every other entry becomes
/// `key=value` — names match what the provider task expects, e.g.
/// `access_key_id` / `access_key_secret` / `token`.
fn acme_dns_service_url(
    provider: &str,
    config: &HashMap<String, String>,
) -> Option<String> {
    let base = match config.get("endpoint").filter(|v| !v.is_empty()) {
        Some(v) if v.contains("://") => v.clone(),
        Some(v) => format!("https://{v}"),
        None => {
            if let Some(region) = config.get("region").filter(|r| !r.is_empty())
            {
                format!("https://dns.{region}.myhuaweicloud.com")
            } else if provider == "huawei" {
                warn!(
                    "acme dns-01: huawei needs a region or endpoint, \
                     issuance will need manual DNS"
                );
                return None;
            } else {
                // Providers accepted by acme_certificate_conf all have a
                // documented host; the tasks error out on an empty URL.
                let host = match provider {
                    "ali" => "alidns.aliyuncs.com",
                    "cf" => "api.cloudflare.com",
                    "tencent" => "dnspod.tencentcloudapi.com",
                    _ => {
                        warn!(
                            "acme dns-01: no endpoint configured for \
                             {provider}, issuance will need manual DNS"
                        );
                        return None;
                    },
                };
                format!("https://{host}")
            }
        },
    };
    let mut pairs: Vec<String> = config
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "endpoint" | "region"))
        .map(|(k, v)| {
            format!("{}={}", urlencoding::encode(k), urlencoding::encode(v))
        })
        .collect();
    pairs.sort();
    if pairs.is_empty() {
        return Some(base);
    }
    Some(format!("{base}?{}", pairs.join("&")))
}

/// The agent's ACME state file: the memory config manager mirrors every
/// write there, so issued certificates and challenge tokens survive a
/// restart (Let's Encrypt caps duplicate certificates per week, and a
/// stateless restart would burn that quota).
fn acme_state_path(rule_cache: &RuleCache) -> PathBuf {
    rule_cache.cache_dir().join("acme_state.toml")
}

/// Merge a freshly converted config with a previous one, carrying over the
/// state only the lets-encrypt task produces: issued PEMs (filled into
/// certificate entries the new config left empty) and the whole `storages`
/// section — challenge tokens and ACME account credentials. Uploads always
/// win: a new config that carries its own PEM is never overwritten.
fn merge_config_state(new_toml: &str, prev_toml: &str) -> String {
    if prev_toml.trim().is_empty() {
        return new_toml.to_string();
    }
    let Ok(mut doc) = new_toml.parse::<toml::Table>() else {
        return new_toml.to_string();
    };
    let Ok(prev) = prev_toml.parse::<toml::Table>() else {
        return new_toml.to_string();
    };

    if let Some(prev_certs) =
        prev.get("certificates").and_then(|v| v.as_table())
    {
        let certs = doc
            .entry("certificates")
            .or_insert(toml::Value::Table(toml::Table::new()));
        if let Some(certs) = certs.as_table_mut() {
            for (name, prev_cert) in prev_certs {
                let pem = prev_cert
                    .get("tls_cert")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if pem.is_empty() {
                    continue;
                }
                let Some(cert) = certs.get_mut(name) else {
                    continue;
                };
                let has_pem = cert
                    .get("tls_cert")
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| !v.is_empty());
                if has_pem {
                    continue;
                }
                if let Some(cert) = cert.as_table_mut() {
                    cert.insert(
                        "tls_cert".to_string(),
                        toml::Value::String(pem.to_string()),
                    );
                    if let Some(key) = prev_cert.get("tls_key") {
                        cert.insert("tls_key".to_string(), key.clone());
                    }
                }
            }
        }
    }

    if let Some(storages) = prev.get("storages") {
        doc.insert("storages".to_string(), storages.clone());
    }

    toml::to_string_pretty(&doc).unwrap_or_else(|_| new_toml.to_string())
}

/// Start the Pingora-based data plane proxy from the agent's cached rules.
///
/// Waits for the agent to receive its initial configuration from the
/// control plane, then builds a PingapConfig and starts the reverse proxy
/// on ports 80 and 443.
pub async fn start_data_plane(
    rule_cache: Arc<RuleCache>,
) -> anyhow::Result<()> {
    // Wait for the agent to receive initial config from the control plane
    for i in 0..30 {
        let cached = rule_cache.all_sites();
        if !cached.sites.is_empty() {
            break;
        }
        if i == 0 {
            info!("data plane: waiting for control plane configuration...");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let config = match build_pingap_config(&rule_cache) {
        Some(config) => config,
        None => {
            warn!("data plane: no sites configured, proxy not started");
            // Keep waiting — the agent may receive config later
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if let Some(config) = build_pingap_config(&rule_cache) {
                    break config;
                }
            }
        },
    };

    let site_count = config
        .servers
        .values()
        .flat_map(|s| s.locations.as_deref().unwrap_or_default())
        .count();
    info!(
        upstreams = config.upstreams.len(),
        locations = config.locations.len(),
        certificates = config.certificates.len(),
        "data plane: starting reverse proxy with {} site(s)",
        site_count,
    );

    // Serialize to TOML and create a memory-backed config manager. The
    // freshly converted config is merged with the ACME state left by the
    // previous run first, so already-issued certificates are served (and
    // not reordered) from the first request on.
    let toml_str = toml::to_string_pretty(&config).map_err(|e| {
        anyhow::anyhow!("failed to serialize proxy config: {}", e)
    })?;
    let acme_state = acme_state_path(&rule_cache);
    let toml_str = merge_config_state(
        &toml_str,
        &std::fs::read_to_string(&acme_state).unwrap_or_default(),
    );
    let config_manager =
        try_init_memory_config_manager(&toml_str, Some(acme_state)).map_err(
            |e| anyhow::anyhow!("failed to init config manager: {}", e),
        )?;

    // The lets-encrypt task scans current_config for certificates to issue,
    // so it must reflect the merged state; validation keeps a malformed
    // merge from taking the proxy down (falls back to the fresh config).
    let config = match PingapTomlConfig::from_toml(&toml_str)
        .and_then(|toml_config| toml_config.to_pingap_config(true))
    {
        Ok(merged) => merged,
        Err(e) => {
            warn!(
                error = %e,
                "data plane: merged config failed validation, using freshly converted config"
            );
            config
        },
    };
    config_manager.set_current_config(config.clone());

    // Initialize providers from the (merged) config
    try_init_upstreams(
        &config.upstreams,
        config.basic.origin_verify_cert,
        None,
    )
    .map_err(|e| anyhow::anyhow!("failed to init upstreams: {}", e))?;
    try_init_locations(&config.locations)
        .map_err(|e| anyhow::anyhow!("failed to init locations: {}", e))?;
    try_init_server_locations(&config.servers, &config.locations).map_err(
        |e| anyhow::anyhow!("failed to init server locations: {}", e),
    )?;

    // Activate the WAF plugin: without it the data plane forwards traffic
    // uninspected and no access/security events are ever emitted.
    let (updated_plugins, plugin_errors) = try_init_plugins(&config.plugins);
    if !updated_plugins.is_empty() {
        info!(
            plugins = updated_plugins.join(","),
            "data plane: plugins initialized"
        );
    }
    if !plugin_errors.is_empty() {
        error!(error = plugin_errors, "data plane: plugin init errors");
    }

    // Initialize certificates
    let cert_provider = new_certificate_provider();
    if !config.certificates.is_empty() {
        let (updated, errors) = try_update_certificates(&config.certificates);
        if !updated.is_empty() {
            info!(certs = updated.join(","), "data plane: certificates loaded");
        }
        if !errors.is_empty() {
            error!(error = errors, "data plane: certificate parse errors");
        }
    }

    // Let the agent report certificate state: the ACME task writes issued PEMs
    // into the provider below, and without this the control plane keeps showing
    // the certificate as pending forever. Certificates generated from site
    // config are named `{site_id}_cert`, which is how a status is attributed
    // back to its site.
    {
        let provider = cert_provider.clone();
        pingwaf_agent::cert_status::set_snapshot(Some(Arc::new(move || {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs() as i64)
                .unwrap_or_default();
            let mut statuses = HashMap::new();
            for cert in provider.list().values() {
                let Some(site_id) = cert
                    .name
                    .as_deref()
                    .and_then(|name| name.strip_suffix("_cert"))
                else {
                    continue;
                };
                let Some(info) = cert.info.as_ref() else {
                    continue;
                };
                if info.not_after == 0 {
                    continue;
                }
                let remaining = info.not_after - now;
                let status = if remaining <= 0 {
                    "expired"
                } else if remaining <= 2 * 24 * 3600 {
                    "expiring_soon"
                } else {
                    "valid"
                };
                // One certificate is listed under every domain it serves; the
                // entries agree, so the first one wins.
                statuses.entry(site_id.to_string()).or_insert(
                    pingwaf_agent::cert_status::CertStatus {
                        status,
                        expires_at: info.not_after,
                    },
                );
            }
            statuses
        })));
    }

    // Create the Pingora server
    let opt = Opt::default();
    let mut my_server = server::Server::new(Some(opt))?;
    let bootstrap_handle = my_server.bootstrap_as_a_service();

    // ACME (Let's Encrypt): issue and renew certificates for sites whose
    // SSL config carries no uploaded PEM. The task shares the config manager
    // with the proxy — the HTTP-01 challenge handler reads tokens from it,
    // and a renewed PEM lands in both the config and the certificate
    // provider below. PINGAP_DISABLE_ACME opts out entirely.
    let acme_enabled = !config.certificates.is_empty()
        && std::env::var("PINGAP_DISABLE_ACME")
            .unwrap_or_default()
            .is_empty();
    let mut background_tasks = BackgroundTaskService::new(
        "data_plane_background_tasks",
        Duration::from_secs(60),
        vec![],
    );
    background_tasks.set_immediately(true);
    background_tasks.set_initial_delay(Some(Duration::from_secs(3)));
    // A stalled ACME cycle is mirrored onto the `pingap::acme` target, which
    // the agent's certificate-event capture ships to the control plane — so
    // an issuance that hangs shows up in the panel's certificate log instead
    // of only in the data plane's own log file.
    background_tasks.set_on_stalled(Some(Box::new(|name, tasks, elapsed| {
        warn!(
            target: "pingap::acme",
            name,
            tasks,
            elapsed,
            "background tasks still running past the interval"
        );
    })));
    if acme_enabled {
        background_tasks.add_task(
            "lets_encrypt",
            new_lets_encrypt_service(
                config_manager.clone(),
                cert_provider.clone(),
                None,
            ),
        );
        info!("data plane: ACME certificate management enabled");
    }
    // Expired cache files have no other reclaimer on this entry point: the
    // periodic `storage_clear` service was registered only by the pingap
    // entry point, so all-in-one/agent deployments kept expired cache
    // files on disk forever (2026-10-18 audit).
    if let Some(task) = new_storage_clear_service() {
        background_tasks.add_task("storage_clear", task);
    }
    let background_tasks_name = background_tasks.name().to_string();
    my_server.add_service(background_service(
        &background_tasks_name,
        background_tasks,
    ));

    // Parse server configs and start proxy servers
    let server_conf_list: Vec<ServerConf> = parse_from_conf(config.clone());

    // One-shot startup warning for listeners without downstream timeouts:
    // pingora keeps a connection alive while the peer trickles bytes, so an
    // unset read/write timeout lets slow clients (or stalled uploads) occupy
    // connections indefinitely (2026-10-18 audit).
    let no_timeouts: Vec<&str> = server_conf_list
        .iter()
        .filter(|conf| {
            conf.downstream_read_timeout.is_none()
                || conf.downstream_write_timeout.is_none()
        })
        .map(|conf| conf.addr.as_str())
        .collect();
    if !no_timeouts.is_empty() {
        warn!(
            listeners = %no_timeouts.join(" | "),
            "downstream read/write timeouts are not configured; a slow client \
             can hold a connection open indefinitely (set downstream_read_timeout \
             / downstream_write_timeout in conf/config.toml)"
        );
    }

    for server_conf in server_conf_list {
        let ctx = AppContext {
            server_locations_provider: new_server_locations_provider(),
            location_provider: new_location_provider(),
            upstream_provider: new_upstream_provider(),
            plugin_provider: new_plugin_provider(),
            certificate_provider: cert_provider.clone(),
            config_manager: config_manager.clone(),
            logger: None,
        };
        let mut ps = ProxyServer::new(&server_conf, ctx)?;
        // The HTTP-01 challenge must be reachable on port 80, so every
        // data-plane server whose address list includes :80 intercepts
        // /.well-known/acme-challenge before proxying.
        if acme_enabled
            && server_conf
                .addr
                .split(',')
                .any(|addr| addr.trim().ends_with(":80"))
        {
            ps.enable_lets_encrypt();
        }
        let services = ps.run(my_server.configuration.clone())?;
        my_server
            .add_service(services.lb)
            .add_dependency(&bootstrap_handle);
    }

    info!(
        addrs = %config
            .servers
            .values()
            .map(|s| s.addr.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        "data plane: proxy server is running"
    );

    // Start the upstream health check background task.
    // This also drives periodic DNS discovery updates — without it,
    // DNS-based backends are never resolved and requests get 503.
    let upstream_health_check_task = new_upstream_health_check_task(
        new_upstream_provider(),
        Duration::from_secs(10),
        None,
    );
    let hc_name = upstream_health_check_task.name().to_string();
    info!(
        service_name = %hc_name,
        "data plane: registering upstream health check background service"
    );
    my_server
        .add_service(background_service(&hc_name, upstream_health_check_task));

    // Run Pingora in a dedicated OS thread. Do NOT join it here —
    // joining would block the tokio worker thread permanently and starve
    // the control-plane REST/gRPC servers (especially on small machines).
    // The thread exits when the process shuts down.
    std::thread::spawn(move || {
        my_server.run_forever();
    });

    // Access log entries are held until the response body completes so the
    // log can carry the response payload. A client that disconnects mid-body
    // never fires the end-of-stream callback, so stale entries are swept
    // periodically: they are still emitted (flagged truncated) so the request
    // never vanishes from the log, and the map cannot grow without bound.
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let swept = pingap_plugin::sweep_stale_access(
                pingap_plugin::PENDING_ACCESS_SWEEP_TTL,
            );
            if swept > 0 {
                info!(
                    count = swept,
                    "data plane: swept stale pending access entries"
                );
            }
        }
    });

    // Hot-reload watcher: poll the rule cache config hash and re-init the
    // ArcSwap providers when the control plane pushes new rules. The proxy
    // reads these providers per request, so no restart is needed. The config
    // manager itself is updated in place: on every reload the freshly
    // converted config is merged with the previous document (preserving
    // issued PEMs and ACME state such as challenge tokens and the account
    // key) and set as current, so the ACME renewal task keeps working.
    let watcher_cache = Arc::clone(&rule_cache);
    let watcher_config_manager = Arc::clone(&config_manager);
    let mut last_hash = watcher_cache.config_hash();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let hash = watcher_cache.config_hash();
            if hash == last_hash {
                continue;
            }
            info!(
                old = %last_hash,
                new = %hash,
                "data plane: rule change detected, reloading"
            );
            let Some(converted) = build_pingap_config(&watcher_cache) else {
                warn!(
                    "data plane: reload produced no usable config, keeping current"
                );
                last_hash = hash;
                continue;
            };
            let Ok(new_toml) = toml::to_string_pretty(&converted) else {
                error!(
                    "data plane: reload config serialization failed, keeping current"
                );
                last_hash = hash;
                continue;
            };
            // Fetch-merge-save must be atomic with respect to ACME's own
            // read-modify-write: an issuance completing while the reload was
            // reading a PEM-less snapshot used to be clobbered by the reload
            // save, dropping the certificate from storage (and then from the
            // SNI table on the next provider rebuild).
            let config = match watcher_config_manager
                .update_raw(|prev_toml| {
                    merge_config_state(&new_toml, &prev_toml)
                })
                .await
            {
                Ok(config) => config,
                Err(e) => {
                    warn!(
                        error = %e,
                        "data plane: merged reload config failed, using freshly converted config"
                    );
                    converted
                },
            };
            watcher_config_manager.set_current_config(config.clone());
            if let Err(e) = try_init_upstreams(
                &config.upstreams,
                config.basic.origin_verify_cert,
                None,
            ) {
                error!(error = %e, "data plane: reload upstreams failed");
            }
            if let Err(e) = try_init_locations(&config.locations) {
                error!(error = %e, "data plane: reload locations failed");
            }
            if let Err(e) =
                try_init_server_locations(&config.servers, &config.locations)
            {
                error!(error = %e, "data plane: reload server locations failed");
            }
            let (updated, errors) =
                try_update_certificates(&config.certificates);
            if !updated.is_empty() {
                info!(
                    certs = updated.join(","),
                    "data plane: certificates reloaded"
                );
            }
            if !errors.is_empty() {
                error!(error = errors, "data plane: certificate reload errors");
            }
            let (updated_plugins, plugin_errors) =
                try_init_plugins(&config.plugins);
            if !updated_plugins.is_empty() {
                info!(
                    plugins = updated_plugins.join(","),
                    "data plane: plugins reloaded"
                );
            }
            if !plugin_errors.is_empty() {
                error!(
                    error = plugin_errors,
                    "data plane: plugin reload errors"
                );
            }
            last_hash = hash;
        }
    });

    // Keep the async task alive until the tokio runtime shuts down.
    // The caller (run()) aborts this task on shutdown signal.
    std::future::pending::<()>().await;
    Ok(())
}

/// Run PingWAF in the specified mode.
///
/// This function blocks until shutdown is signalled (SIGINT / SIGTERM).
pub async fn run(mode: RunMode) -> anyhow::Result<()> {
    match mode {
        RunMode::Server(config) => {
            info!(
                http_addr = %config.http_addr,
                grpc_addr = %config.grpc_addr,
                "starting PingWAF in Server mode (control plane only)"
            );
            pingwaf_server::start_server(*config).await
        },
        RunMode::Agent(config) => {
            info!(
                server_url = %config.server_url,
                cache_dir = %config.cache_dir,
                "starting PingWAF in Agent mode (data plane only)"
            );
            let agent = pingwaf_agent::start_agent(*config).await?;
            info!("PingWAF agent is running, starting data plane proxy");

            // Start the data plane proxy in the background
            let rule_cache = Arc::clone(&agent.rule_cache);
            let proxy_handle = tokio::spawn(async move {
                if let Err(e) = start_data_plane(rule_cache).await {
                    error!(error = %e, "data plane proxy exited with error");
                }
            });

            // Wait for shutdown signal
            shutdown_signal().await;
            agent.shutdown().await;
            proxy_handle.abort();
            Ok(())
        },
        RunMode::AllInOne(server_config, mut agent_config) => {
            info!(
                http_addr = %server_config.http_addr,
                grpc_addr = %server_config.grpc_addr,
                "starting PingWAF in All-in-One mode (control plane + data plane)"
            );

            // Auto-provision a bootstrap API key when none is configured so the
            // embedded agent can authenticate with the local gRPC server.
            if agent_config.api_key.is_empty() {
                match bootstrap_agent_key(&server_config).await {
                    Ok(key) => {
                        agent_config.api_key = key;
                    },
                    Err(e) => {
                        error!(error = %e, "failed to create bootstrap API key for embedded agent");
                    },
                }
            }

            // Pin the gRPC listener certificate: all-in-one serves TLS by
            // default, so the embedded agent needs the console certificate
            // (or the explicitly configured one) as its trust anchor.
            match pingwaf_server::embedded_agent_ca_pem(&server_config).await {
                Ok(Some(pem)) => {
                    agent_config.server_ca_pem = Some(pem);
                },
                Ok(None) => {},
                Err(e) => {
                    error!(
                        error = %e,
                        "failed to resolve the gRPC CA for the embedded agent; \
                         it will fall back to its configured CA settings"
                    );
                },
            }

            // Start the agent in the background first.
            // It will retry connecting to the server until it comes up.
            let agent = match pingwaf_agent::start_agent(*agent_config).await {
                Ok(agent) => Some(agent),
                Err(e) => {
                    error!(error = %e, "failed to start agent, continuing with server only");
                    None
                },
            };

            // Start the data plane proxy if the agent is running
            let proxy_handle = if let Some(ref agent) = agent {
                let rule_cache = Arc::clone(&agent.rule_cache);
                Some(tokio::spawn(async move {
                    if let Err(e) = start_data_plane(rule_cache).await {
                        error!(error = %e, "data plane proxy exited with error");
                    }
                }))
            } else {
                None
            };

            // Run the server (blocks until shutdown signal)
            let result = pingwaf_server::start_server(*server_config).await;

            // Gracefully shut down the agent
            if let Some(agent) = agent {
                agent.shutdown().await;
            }
            if let Some(handle) = proxy_handle {
                handle.abort();
            }

            result
        },
    }
}

/// Connect to the database, run migrations, and create a bootstrap API key
/// for the embedded agent in all-in-one mode.
async fn bootstrap_agent_key(
    config: &pingwaf_server::ServerConfig,
) -> anyhow::Result<String> {
    pingwaf_server::bootstrap_and_seed_api_key(config).await
}

/// Wait for SIGINT or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .expect("failed to install SIGTERM handler")
        .recv()
        .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received SIGINT"),
        _ = terminate => info!("received SIGTERM"),
    }
}

/// Entry point called from main.rs when PingWAF mode is detected.
pub fn main() {
    // The dependency graph enables BOTH rustls crypto providers (ring via
    // pingwaf-server's rustls/tonic, aws-lc-rs via instant-acme/reqwest), so
    // rustls refuses to pick one implicitly and panics on first TLS use.
    // Install ring explicitly — the same provider the pingora rustls backend
    // uses. `install_default` returns Err when already installed; ignore it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Allocator retention policy (adaptive by memory ceiling, overridable
    // via env). This entry point bypasses main.rs, so apply it here too.
    crate::allocator_tune::apply();

    // Initialize tracing
    init_tracing();

    let cli = crate::cli::parse_pingwaf_cli();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    // Maintenance commands run against the database and exit; only the three
    // run modes start the long-running process.
    let is_maintenance = matches!(
        &cli.command,
        PingWafCommand::User { .. }
            | PingWafCommand::Mode { .. }
            | PingWafCommand::Security { .. }
    );
    let result = if is_maintenance {
        rt.block_on(crate::admin::run(cli))
    } else {
        rt.block_on(run(build_run_mode(cli)))
    };

    if let Err(e) = result {
        error!(error = %e, "PingWAF exited with error");
        eprintln!("PingWAF error: {e}");
        std::process::exit(1);
    }
}

/// Initialize tracing subscriber for PingWAF modes.
fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*};

    let filter = log_filter();

    // Siphons pingap's raw ACME events into the buffer the agent ships to the
    // control plane, so certificate-issuance logs show up on the admin panel.
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true))
        .with(pingwaf_agent::cert_events::AcmeCaptureLayer)
        .init();
}

/// The log filter for PingWAF modes.
///
/// `RUST_LOG` wins whenever it is set. The default asks for `info` while
/// keeping sqlx at `warn`, because sqlx logs the text and parameters of every
/// query at `INFO` and that buries the control plane's own messages. An
/// operator who names `sqlx` in `RUST_LOG` gets exactly what they asked for.
fn log_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::new(log_directives(
        std::env::var("RUST_LOG").ok().as_deref(),
    ))
}

/// The directives [`log_filter`] builds its filter from.
fn log_directives(rust_log: Option<&str>) -> String {
    let value = rust_log.unwrap_or_default().trim();
    if value.is_empty() {
        "info,sqlx=warn".to_string()
    } else if value.contains("sqlx") {
        value.to_string()
    } else {
        format!("{value},sqlx=warn")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingwaf_agent::cache::{
        CacheRule as AgentCacheRule, CachedRules, GlobalCacheSettings,
        ProxyTrustConfig, ResponseReplaceRule, RouteConfig, SiteRules,
        UpstreamConfig, UpstreamPeer,
    };

    #[test]
    fn log_directives_keep_sqlx_quiet_unless_named() {
        // Nothing set: the default, with sqlx kept out of the way.
        assert_eq!(log_directives(None), "info,sqlx=warn");
        assert_eq!(log_directives(Some("  ")), "info,sqlx=warn");

        // An operator level applies, but statements stay quiet.
        assert_eq!(log_directives(Some("debug")), "debug,sqlx=warn");
        assert_eq!(
            log_directives(Some("pingwaf=debug")),
            "pingwaf=debug,sqlx=warn"
        );

        // Naming sqlx is an explicit request for its logs.
        assert_eq!(log_directives(Some("sqlx=debug")), "sqlx=debug");
        assert_eq!(log_directives(Some("info,sqlx=trace")), "info,sqlx=trace");
    }

    fn site_rules(site_id: &str, domain: &str) -> SiteRules {
        SiteRules {
            site_id: site_id.to_string(),
            domain: domain.to_string(),
            alternate_domains: vec![],
            status: "active".to_string(),
            waf_config: None,
            rate_limit_rules: vec![],
            ip_access_rules: vec![],
            geo_config: None,
            cache_rules: vec![],
            challenge_config: None,
            rewrite_rules: vec![],
            error_pages: vec![],
            ssl_config: None,
            upstreams: vec![],
            routes: vec![],
            bot_protection: None,
            basic_auth: None,
            observation_mode: false,
            proxy_trust: ProxyTrustConfig::default(),
            cache_settings: None,
            response_replace: None,
        }
    }

    fn pool(pool_id: &str, peers: Vec<UpstreamPeer>) -> UpstreamConfig {
        UpstreamConfig {
            name: pool_id.to_string(),
            peers,
            algorithm: String::new(),
            health_check: None,
            connection_timeout_ms: 0,
            read_timeout_ms: 0,
            write_timeout_ms: 0,
            pool_id: pool_id.to_string(),
            algo: String::new(),
            sni: String::new(),
            verify_cert: None,
            address_family: "auto".to_string(),
            is_default: false,
        }
    }

    fn peer(address: &str) -> UpstreamPeer {
        UpstreamPeer {
            address: address.to_string(),
            weight: 1,
            tls: false,
        }
    }

    fn route(
        id: &str,
        match_type: &str,
        path: &str,
        pool_id: &str,
    ) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            name: id.to_string(),
            match_type: match_type.to_string(),
            path: path.to_string(),
            priority: None,
            enabled: true,
            pool_id: pool_id.to_string(),
            ip_ranges: vec![],
            strip_prefix: false,
            rewrite_path: String::new(),
            upstream_host: String::new(),
        }
    }

    fn one_site_cache(site: SiteRules) -> CachedRules {
        let mut cached = CachedRules::default();
        cached.sites.insert(site.site_id.clone(), Arc::new(site));
        cached
    }

    fn enabled_cache_rule(disk_quota_mb: u32) -> AgentCacheRule {
        AgentCacheRule {
            id: "rule-1".to_string(),
            name: "static".to_string(),
            match_expression: String::new(),
            edge_ttl_seconds: 300,
            browser_ttl_seconds: 60,
            disk_quota_mb,
            cache_eligible: true,
            cache_key_headers: Vec::new(),
            respect_origin_headers: true,
            stale_while_revalidate_seconds: 0,
            enabled: true,
        }
    }

    #[test]
    fn cache_plugin_conf_follows_global_settings() {
        // Defaults (no global_cache): the historical shape — 16 MiB cap, no
        // budget, no fallback TTL.
        let mut site = site_rules("site1", "a.example.com");
        site.cache_rules = vec![enabled_cache_rule(0)];
        site.upstreams = vec![pool("", vec![peer("10.0.0.1:8080")])];
        let mut cached = one_site_cache(site);
        let config = cached_rules_to_pingap_config(
            &cached,
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");
        let cache_conf =
            config.plugins.get(CACHE_PLUGIN_NAME).expect("cache plugin");
        assert_eq!(
            cache_conf.get("max_file_size").and_then(|v| v.as_str()),
            Some("16mb")
        );
        assert_eq!(
            cache_conf.get("directory").and_then(|v| v.as_str()),
            Some("/tmp/pingwaf-test-cache")
        );
        assert_eq!(cache_conf.get("max_ttl"), None);

        // Global settings: cap, budget and fallback TTL all land in the
        // generated configuration.
        cached.global_cache = Some(std::sync::Arc::new(GlobalCacheSettings {
            max_file_size_mb: Some(64),
            max_space_mb: Some(2048),
            master_enabled: Some(true),
            default_edge_ttl_seconds: Some(600),
        }));
        let config = cached_rules_to_pingap_config(
            &cached,
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");
        let cache_conf =
            config.plugins.get(CACHE_PLUGIN_NAME).expect("cache plugin");
        assert_eq!(
            cache_conf.get("max_file_size").and_then(|v| v.as_str()),
            Some("64mb")
        );
        assert_eq!(
            cache_conf.get("directory").and_then(|v| v.as_str()),
            Some("/tmp/pingwaf-test-cache?max_size=2048mb")
        );
        assert_eq!(
            cache_conf.get("max_ttl").and_then(|v| v.as_str()),
            Some("600s")
        );

        // Master switch off: no cache plugin at all, not even in locations.
        cached.global_cache = Some(std::sync::Arc::new(GlobalCacheSettings {
            master_enabled: Some(false),
            ..Default::default()
        }));
        let config = cached_rules_to_pingap_config(
            &cached,
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");
        assert!(!config.plugins.contains_key(CACHE_PLUGIN_NAME));
        for loc in config.locations.values() {
            let plugins = loc.plugins.as_deref().unwrap_or(&[]);
            assert!(
                !plugins.iter().any(|name| name == CACHE_PLUGIN_NAME),
                "master-off must drop the cache plugin from locations"
            );
        }
    }

    #[test]
    fn single_pool_without_routes_matches_legacy_layout() {
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![pool("", vec![peer("10.0.0.1:8080")])];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let upstream = config
            .upstreams
            .get("site1_upstream")
            .expect("legacy upstream key");
        assert_eq!(upstream.addrs, vec!["10.0.0.1:8080"]);
        assert_eq!(upstream.algo, None);

        let loc = config
            .locations
            .get("site1_loc")
            .expect("fallback location");
        assert_eq!(loc.path.as_deref(), Some("/"));
        assert_eq!(loc.upstream.as_deref(), Some("site1_upstream"));
        assert_eq!(loc.host.as_deref(), Some("a.example.com"));
        // The catch-all sorts behind every route: pinned to the floor so
        // even priority-1 routes match first (see
        // low_priority_routes_still_beat_the_site_fallback).
        assert_eq!(loc.weight, Some(0));
    }

    #[test]
    fn multi_peer_pool_defaults_to_stats_and_breaker() {
        // P0-2 (NODE-EVALUATION-REPORT-20261009): the control plane exposes
        // no knobs for backend stats or circuit breaking, so multi-node pools
        // must get request-level protection by default — otherwise a bad
        // origin is only caught by the 10s TCP probe and 5xx-style soft
        // failures are never accounted for.
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams =
            vec![pool("", vec![peer("10.0.0.1:8080"), peer("10.0.0.2:8080")])];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let upstream = config
            .upstreams
            .get("site1_upstream")
            .expect("legacy upstream key");
        assert_eq!(upstream.enable_backend_stats, Some(true));
        assert_eq!(upstream.circuit_break_max_consecutive_failures, Some(5));
        assert_eq!(upstream.circuit_break_max_failure_percent, Some(50));
        assert_eq!(upstream.circuit_break_min_requests_threshold, Some(10));
        assert_eq!(
            upstream.circuit_break_open_duration,
            Some(Duration::from_secs(10))
        );
        // A misjudged health check or an all-open breaker must degrade to
        // the least-bad origin instead of failing the site with 503s.
        assert_eq!(upstream.enable_unhealthy_fallback, Some(true));

        // Single-node pools stay untouched: with no alternative backend an
        // open breaker would only short-circuit requests into 503.
        let mut site = site_rules("site2", "b.example.com");
        site.upstreams = vec![pool("", vec![peer("10.0.0.3:8080")])];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let upstream = config
            .upstreams
            .get("site2_upstream")
            .expect("single upstream key");
        assert_eq!(upstream.enable_backend_stats, None);
        assert_eq!(upstream.circuit_break_max_consecutive_failures, None);
        assert_eq!(upstream.circuit_break_max_failure_percent, None);
        assert_eq!(upstream.enable_unhealthy_fallback, None);
    }

    #[test]
    fn health_check_url_synthesis() {
        let hc = HealthCheckConfig {
            enabled: true,
            path: "/healthz".to_string(),
            interval_seconds: 15,
            timeout_ms: 2000,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        };
        assert_eq!(
            health_check_url("site1_upstream", &hc),
            "http://site1_upstream/healthz?check_frequency=15s&\
             connection_timeout=2000ms&read_timeout=2000ms&failure=3&\
             success=2"
        );

        // Missing leading slash is normalized, empty path becomes "/".
        let mut hc = hc.clone();
        hc.path = "ping".to_string();
        assert!(health_check_url("u", &hc).contains("u/ping?"));
        hc.path = String::new();
        assert!(health_check_url("u", &hc).contains("u/?"));

        // Zeroes from a corrupt cache entry clamp to safe probe values.
        let corrupt = HealthCheckConfig {
            enabled: true,
            path: "/".to_string(),
            interval_seconds: 0,
            timeout_ms: 0,
            unhealthy_threshold: 0,
            healthy_threshold: 0,
        };
        let url = health_check_url("u", &corrupt);
        assert!(url.contains("check_frequency=1s&"));
        assert!(url.contains("connection_timeout=1ms&"));
        assert!(url.contains("failure=1&success=1"));
    }

    /// End-to-end over the config path: the server-side shape of a pool
    /// carrying a health check (proto message → agent cache struct) must
    /// survive the translation into a data-plane `UpstreamConf`, and the
    /// synthesized URL must be accepted by `pingap-health` when the data
    /// plane actually builds the upstream.
    #[test]
    fn health_check_flows_end_to_end_into_the_data_plane() {
        let mut up =
            pool("", vec![peer("10.0.0.1:8080"), peer("10.0.0.2:8080")]);
        up.health_check = Some(HealthCheckConfig {
            enabled: true,
            path: "/healthz".to_string(),
            interval_seconds: 15,
            timeout_ms: 2000,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        });
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![up];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let conf = config
            .upstreams
            .get("site1_upstream")
            .expect("multi-node upstream key");
        assert_eq!(
            conf.health_check.as_deref(),
            Some(
                "http://site1_upstream/healthz?check_frequency=15s&\
                 connection_timeout=2000ms&read_timeout=2000ms&failure=3&\
                 success=2"
            )
        );

        // Building the upstream parses the health check URL for real: a
        // malformed synthesis fails right here instead of at traffic time.
        pingap_upstream::Upstream::new("site1_upstream", conf, None)
            .expect("the synthesized health check URL must build");

        // A disabled check keeps the data plane on its TCP-probe default.
        let mut up = pool("", vec![peer("10.0.0.1:8080")]);
        up.health_check = Some(HealthCheckConfig {
            enabled: false,
            path: "/healthz".to_string(),
            interval_seconds: 15,
            timeout_ms: 2000,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        });
        let mut site = site_rules("site2", "b.example.com");
        site.upstreams = vec![up];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");
        let conf = config
            .upstreams
            .get("site2_upstream")
            .expect("single upstream key");
        assert_eq!(conf.health_check, None);
    }

    #[test]
    fn legacy_multi_pool_cache_falls_back_to_first_pool() {
        // Before pools existed each upstream entry overwrote the site's
        // single location; now the first pool deterministically serves.
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![
            pool("", vec![peer("10.0.0.1:8080")]),
            pool("", vec![peer("10.0.0.2:8080")]),
        ];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        assert!(config.upstreams.contains_key("site1_upstream_0"));
        assert!(config.upstreams.contains_key("site1_upstream_1"));
        let loc = config.locations.get("site1_loc").expect("location");
        assert_eq!(loc.upstream.as_deref(), Some("site1_upstream_0"));
        assert_eq!(config.locations.len(), 1);
    }

    #[test]
    fn pools_and_routes_build_separate_locations() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool(
            "pool-a",
            vec![
                peer("10.0.0.1:8080"),
                UpstreamPeer {
                    address: "10.0.0.2:8080".to_string(),
                    weight: 3,
                    tls: false,
                },
            ],
        );
        default_pool.is_default = true;
        let second_pool = pool("pool-b", vec![peer("10.0.0.3:9090")]);
        // Empty pools are skipped entirely.
        site.upstreams =
            vec![default_pool, second_pool, pool("pool-empty", vec![])];

        let mut r1 = route("r1", "prefix", "/api", "pool-b");
        r1.priority = Some(100);
        let r2 = route("r2", "exact", "/healthz", "pool-a");
        let r3 = route("r3", "regex", r"^/static/.*", "pool-b");
        let mut disabled = route("r4", "prefix", "/gone", "pool-b");
        disabled.enabled = false;
        // Route referencing the skipped empty pool falls back to the
        // site's default pool instead of disappearing.
        let orphan = route("r5", "prefix", "/orphan", "pool-empty");
        site.routes = vec![r1, r2, r3, disabled, orphan];

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        assert_eq!(config.upstreams.len(), 2);
        let default_upstream =
            config.upstreams.get("pool-a").expect("pool-a upstream");
        assert!(
            default_upstream
                .addrs
                .contains(&"10.0.0.2:8080 3".to_string())
        );

        let fallback = config
            .locations
            .get("site1_loc")
            .expect("default pool fallback location");
        assert_eq!(fallback.upstream.as_deref(), Some("pool-a"));
        assert_eq!(fallback.path.as_deref(), Some("/"));
        assert_eq!(fallback.weight, Some(0));

        let api = config
            .locations
            .get("site1_route_r1")
            .expect("prefix route location");
        assert_eq!(api.path.as_deref(), Some("/api"));
        assert_eq!(api.upstream.as_deref(), Some("pool-b"));
        assert_eq!(api.weight, Some(100));

        let healthz = config
            .locations
            .get("site1_route_r2")
            .expect("exact route location");
        assert_eq!(healthz.path.as_deref(), Some("=/healthz"));
        assert_eq!(healthz.upstream.as_deref(), Some("pool-a"));
        assert_eq!(healthz.weight, None);

        let static_route = config
            .locations
            .get("site1_route_r3")
            .expect("regex route location");
        assert_eq!(static_route.path.as_deref(), Some("~^/static/.*"));

        assert!(!config.locations.contains_key("site1_route_r4"));
        let orphan = config
            .locations
            .get("site1_route_r5")
            .expect("orphan route falls back to the default pool");
        assert_eq!(orphan.upstream.as_deref(), Some("pool-a"));
    }

    /// The route's path-rewrite knobs reach the location the data plane
    /// builds. An empty `rewrite_path` on the wire means "no replacement", so
    /// it must not become `Some("")` in the generated config.
    #[test]
    fn route_path_rewrite_reaches_the_location_config() {
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![pool("pool-a", vec![peer("10.0.0.1:8080")])];

        let mut strip = route("r1", "prefix", "/api", "pool-a");
        strip.strip_prefix = true;
        let mut replace = route("r2", "exact", "/legacy", "pool-a");
        replace.rewrite_path = "  /v2  ".to_string();
        let plain = route("r3", "prefix", "/static", "pool-a");
        let blank = route("r4", "prefix", "/blank", "pool-a");
        site.routes = vec![strip, replace, plain, blank];

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let loc = config
            .locations
            .get("site1_route_r1")
            .expect("strip route location");
        assert_eq!(loc.strip_prefix, Some(true));
        assert_eq!(loc.rewrite_path, None);

        let loc = config
            .locations
            .get("site1_route_r2")
            .expect("replace route location");
        // Only `rewrite_path` is set: stripping stays unset, not `Some(false)`,
        // so a config that never opted in keeps the historical behaviour.
        assert_eq!(loc.strip_prefix, None);
        assert_eq!(loc.rewrite_path.as_deref(), Some("/v2"));

        for name in ["site1_route_r3", "site1_route_r4"] {
            let loc = config.locations.get(name).expect("plain route location");
            assert_eq!(loc.strip_prefix, None, "{name} must not strip");
            assert_eq!(loc.rewrite_path, None, "{name} must not replace");
        }
    }

    /// D-5: the route's `Host` override reaches the generated location as
    /// `upstream_host`. An unset value stays `None`, i.e. the client's Host is
    /// forwarded — the behaviour every existing route relies on.
    #[test]
    fn route_upstream_host_reaches_the_location_config() {
        let mut site = site_rules("site1", "mirror.example.com");
        site.upstreams = vec![pool("pool-a", vec![peer("172.17.53.244:5000")])];

        let mut mirror = route("r1", "prefix", "/google", "pool-a");
        mirror.upstream_host = "  www.google.com  ".to_string();
        let plain = route("r2", "prefix", "/api", "pool-a");
        site.routes = vec![mirror, plain];

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let loc = config
            .locations
            .get("site1_route_r1")
            .expect("mirror route location");
        // Trimmed, so a padded value still builds a valid HeaderValue.
        assert_eq!(loc.upstream_host.as_deref(), Some("www.google.com"));

        let loc = config
            .locations
            .get("site1_route_r2")
            .expect("plain route location");
        assert_eq!(loc.upstream_host, None, "unset keeps the client's Host");
    }

    /// D-6: a site's response replacement policy becomes a `sub_filter` plugin
    /// instance wired into that site's locations, using the key names
    /// `pingap-plugin/src/sub_filter.rs` actually reads.
    #[test]
    fn site_response_replace_generates_a_sub_filter_plugin() {
        let mut site = site_rules("site1", "mirror.example.com");
        let mut default_pool = pool("pool-a", vec![peer("172.17.53.244:5000")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        // Deliberately no `ssl_config`: the plugin must appear for a
        // plain-HTTP site too, which is why it is not built inside
        // `site_posture_plugins` (that one returns early without TLS).
        assert!(site.ssl_config.is_none());
        site.response_replace = Some(ResponseReplaceConfig {
            path: "  ^/google/.*  ".to_string(),
            status_codes: vec![200, 404],
            rules: vec![
                ResponseReplaceRule {
                    pattern: "Google".to_string(),
                    replacement: "PingWAF".to_string(),
                    is_regex: false,
                },
                ResponseReplaceRule {
                    pattern: "Go+gle".to_string(),
                    replacement: "PingWAF".to_string(),
                    is_regex: true,
                },
            ],
        });

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site.clone()),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let conf = config
            .plugins
            .get("site1_sub_filter")
            .expect("per-site sub_filter plugin");
        let value = |key: &str| {
            conf.get(key)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        assert_eq!(value("category"), "sub_filter");
        assert_eq!(value("path"), "^/google/.*");
        assert_eq!(value("status_codes"), "200,404");
        let filters: Vec<&str> = conf
            .get("filters")
            .and_then(|v| v.as_array())
            .expect("filters array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        // `g` is always stated: without it the plugin replaces only the first
        // occurrence. `sub_filter` matches literally, `subs_filter` is the
        // regex directive.
        assert_eq!(
            filters,
            vec![
                "sub_filter 'Google' 'PingWAF' g",
                "subs_filter 'Go+gle' 'PingWAF' g",
            ]
        );

        let fallback = config
            .locations
            .get("site1_loc")
            .expect("fallback location");
        assert!(
            fallback
                .plugins
                .as_ref()
                .expect("plugins")
                .iter()
                .any(|name| name == "site1_sub_filter"),
            "the site's locations must reference the plugin"
        );

        // Without a policy nothing is generated: no dead plugin instance.
        let mut bare = site;
        bare.response_replace = None;
        let config = cached_rules_to_pingap_config(
            &one_site_cache(bare),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");
        assert!(!config.plugins.contains_key("site1_sub_filter"));
        assert!(
            config
                .locations
                .get("site1_loc")
                .expect("fallback location")
                .plugins
                .as_ref()
                .expect("plugins")
                .iter()
                .all(|name| name != "site1_sub_filter")
        );
    }

    #[test]
    fn sni_verify_cert_and_algo_pass_through() {
        let mut site = site_rules("site1", "a.example.com");
        let mut tls_pool = pool("pool-a", vec![peer("https://10.0.0.1:8443")]);
        tls_pool.is_default = true;
        tls_pool.sni = "origin.example.com".to_string();
        tls_pool.verify_cert = Some(false);
        tls_pool.algo = "hash:cookie:session".to_string();
        site.upstreams = vec![tls_pool];

        // A cache restored from the persisted snapshot carries `null`: the
        // default must be lenient, not pingora's strict.
        let mut snapshot_pool =
            pool("pool-c", vec![peer("https://10.0.0.3:8443")]);
        snapshot_pool.sni = "origin.example.com".to_string();
        snapshot_pool.verify_cert = None;
        site.upstreams.push(snapshot_pool);

        // Strict stays strict: an operator who opted in keeps it.
        let mut strict_pool =
            pool("pool-d", vec![peer("https://10.0.0.4:8443")]);
        strict_pool.sni = "origin.example.com".to_string();
        strict_pool.verify_cert = Some(true);
        site.upstreams.push(strict_pool);

        let mut legacy_pool = pool("pool-b", vec![peer("10.0.0.2:8080")]);
        legacy_pool.algo = "lbconsistenthash".to_string();
        site.upstreams.push(legacy_pool);

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let tls = config.upstreams.get("pool-a").expect("tls pool");
        assert_eq!(tls.sni.as_deref(), Some("origin.example.com"));
        assert_eq!(tls.verify_cert, Some(false));
        assert_eq!(
            tls.algo.as_deref(),
            Some("hash:cookie:session"),
            "valid hash algo passes through"
        );
        assert_eq!(
            tls.addrs,
            vec!["10.0.0.1:8443"],
            "scheme is stripped from peer addresses"
        );

        assert_eq!(
            config.upstreams.get("pool-b").unwrap().algo,
            None,
            "legacy enum debug names collapse to the round_robin default"
        );

        // A pool with no opinion of its own passes `null` through and is
        // resolved against the deployment default, which the generator
        // states explicitly; `None` here would mean "let pingora decide",
        // i.e. strict, and every self-signed origin would 502.
        assert_eq!(
            config.upstreams.get("pool-c").unwrap().verify_cert,
            None,
            "snapshot null follows the deployment default"
        );
        assert_eq!(
            config.basic.origin_verify_cert,
            Some(false),
            "the deployment default is always stated and defaults to lenient"
        );
        assert_eq!(
            config.upstreams.get("pool-d").unwrap().verify_cert,
            Some(true),
            "explicit opt-in keeps strict verification"
        );
    }

    /// The control plane's global switch reaches the generated config, so a
    /// pool that follows the default is verified without touching the pool.
    #[test]
    fn origin_verify_cert_flows_into_the_basic_conf() {
        let mut site = site_rules("site1", "a.example.com");
        let mut pool_a = pool("pool-a", vec![peer("https://10.0.0.1:8443")]);
        pool_a.sni = "origin.example.com".to_string();
        pool_a.verify_cert = None;
        site.upstreams = vec![pool_a];

        let mut cached = one_site_cache(site);
        cached.origin_verify_cert = Some(true);

        let config = cached_rules_to_pingap_config(
            &cached,
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        assert_eq!(config.basic.origin_verify_cert, Some(true));
        assert_eq!(
            config.upstreams.get("pool-a").unwrap().verify_cert,
            None,
            "the pool keeps following the default"
        );
    }

    #[test]
    fn sanitize_algo_rejects_unknown_names() {
        assert_eq!(sanitize_algo(""), None);
        assert_eq!(sanitize_algo("round_robin"), None);
        assert_eq!(
            sanitize_algo("least_connections"),
            Some("least_connections".to_string())
        );
        assert_eq!(sanitize_algo("random"), Some("random".to_string()));
        assert_eq!(sanitize_algo("lbconsistenthash"), None);
        assert_eq!(sanitize_algo("hash:"), None);
        assert_eq!(sanitize_algo("hash:bogus"), None);
        assert_eq!(sanitize_algo("hash:ip"), Some("hash:ip".to_string()));
        assert_eq!(sanitize_algo("hash:url"), Some("hash:url".to_string()));
        assert_eq!(sanitize_algo("hash:path"), Some("hash:path".to_string()));
        assert_eq!(
            sanitize_algo("hash:header:x-user"),
            Some("hash:header:x-user".to_string())
        );
        assert_eq!(
            sanitize_algo("hash:cookie:session_id"),
            Some("hash:cookie:session_id".to_string())
        );
        assert_eq!(
            sanitize_algo("hash:query:q"),
            Some("hash:query:q".to_string())
        );
    }

    #[test]
    fn empty_cache_and_empty_sites_produce_no_config() {
        assert!(
            cached_rules_to_pingap_config(
                &CachedRules::default(),
                Path::new("/tmp/pingwaf-test-cache")
            )
            .is_none()
        );

        let mut site = site_rules("site1", "");
        site.upstreams = vec![pool("", vec![peer("10.0.0.1:8080")])];
        assert!(
            cached_rules_to_pingap_config(
                &one_site_cache(site),
                Path::new("/tmp/pingwaf-test-cache")
            )
            .is_none()
        );
    }

    #[test]
    fn waf_plugin_is_injected_and_referenced_by_every_location() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        site.routes = vec![route("r1", "prefix", "/api", "pool1")];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let category = config
            .plugins
            .get("pingwaf:waf")
            .and_then(|c| c.get("category"))
            .and_then(|v| v.as_str());
        assert_eq!(category, Some("waf"));

        assert!(config.locations.contains_key("site1_loc"));
        assert!(config.locations.contains_key("site1_route_r1"));
        for (name, loc) in &config.locations {
            assert_eq!(
                loc.plugins.as_deref(),
                Some(
                    [
                        "pingwaf:waf".to_string(),
                        "pingwaf:challenge".to_string(),
                        "pingwaf:rewrite".to_string(),
                        "pingwaf:error_page".to_string(),
                    ]
                    .as_slice()
                ),
                "location {name} must reference the waf and challenge plugins"
            );
        }
    }

    /// The generated WAF plugin states the withheld-body stage timeout, so the
    /// value an operator reads is the one the plugin runs with. No site-level
    /// downstream timeout exists yet, so it is the 30s default.
    #[test]
    fn waf_plugin_states_the_body_stage_timeout() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let timeout = config
            .plugins
            .get("pingwaf:waf")
            .and_then(|conf| conf.get("body_stage_timeout_secs"))
            .and_then(|value| value.as_integer())
            .expect("the waf plugin must state body_stage_timeout_secs");

        assert_eq!(timeout, 30, "an unset site timeout means 30s");
        assert!(timeout <= 30, "the plugin hard-caps the stage at 30s");

        // Read the value back through the very function the WAF plugin uses
        // (pingap-plugin/src/waf.rs). The distinct fallback makes a typo in
        // the key name fail here instead of silently reverting to the default
        // on the data plane.
        let conf = config
            .plugins
            .get("pingwaf:waf")
            .expect("the waf plugin conf must exist");
        assert_eq!(
            pingap_plugin::get_int_conf_or_default(
                conf,
                "body_stage_timeout_secs",
                7
            ),
            30,
            "the generated key is exactly the one the waf plugin reads"
        );
    }

    /// The resolver mirrors the plugin rule: unset means 30s, a shorter site
    /// timeout wins, anything longer is clamped to the 30s ceiling.
    #[test]
    fn waf_body_stage_timeout_defaults_and_caps_at_30s() {
        assert_eq!(waf_body_stage_timeout_secs(None), 30);
        assert_eq!(
            waf_body_stage_timeout_secs(Some(Duration::from_secs(5))),
            5
        );
        assert_eq!(
            waf_body_stage_timeout_secs(Some(Duration::from_secs(30))),
            30
        );
        assert_eq!(
            waf_body_stage_timeout_secs(Some(Duration::from_secs(120))),
            30
        );
    }

    /// R-06: the resolver never states 0, because the plugin reads 0 as "do
    /// not withhold the body" rather than as the 30s default. A sub-second (or
    /// zero) site timeout therefore floors at the shortest real stage, 1s.
    #[test]
    fn waf_body_stage_timeout_never_states_zero() {
        assert_eq!(
            waf_body_stage_timeout_secs(Some(Duration::from_millis(500))),
            1,
            "a sub-second timeout must not round down to 0 (no withholding)"
        );
        assert_eq!(waf_body_stage_timeout_secs(Some(Duration::ZERO)), 1);
        assert_eq!(
            waf_body_stage_timeout_secs(Some(Duration::from_nanos(1))),
            1
        );
        assert_eq!(
            waf_body_stage_timeout_secs(Some(Duration::from_millis(1999))),
            1
        );
        // The floor does not leak into the other branches.
        assert_eq!(waf_body_stage_timeout_secs(None), 30);
        assert_eq!(
            waf_body_stage_timeout_secs(Some(Duration::from_secs(120))),
            30
        );
    }

    fn cache_rule(enabled: bool) -> pingwaf_agent::cache::CacheRule {
        pingwaf_agent::cache::CacheRule {
            id: "cr1".to_string(),
            name: "static assets".to_string(),
            match_expression: r#"path starts_with "/assets/""#.to_string(),
            edge_ttl_seconds: 300,
            browser_ttl_seconds: 60,
            disk_quota_mb: 0,
            cache_eligible: true,
            cache_key_headers: vec![],
            respect_origin_headers: true,
            stale_while_revalidate_seconds: 0,
            enabled,
        }
    }

    #[test]
    fn cache_plugin_is_wired_when_a_site_has_cache_rules() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        site.cache_rules = vec![cache_rule(true)];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/var/lib/pingwaf/cache"),
        )
        .expect("config should build");

        let conf = config
            .plugins
            .get("pingwaf:cache")
            .expect("cache plugin must be present");
        assert_eq!(
            conf.get("category").and_then(|v| v.as_str()),
            Some("cache")
        );
        assert_eq!(
            conf.get("directory").and_then(|v| v.as_str()),
            Some("/var/lib/pingwaf/cache")
        );
        for (name, loc) in &config.locations {
            assert_eq!(
                loc.plugins.as_deref(),
                Some(
                    [
                        "pingwaf:waf".to_string(),
                        "pingwaf:challenge".to_string(),
                        "pingwaf:rewrite".to_string(),
                        "pingwaf:error_page".to_string(),
                        "pingwaf:cache".to_string(),
                    ]
                    .as_slice()
                ),
                "location {name} must reference the cache plugin"
            );
        }
    }

    #[test]
    fn cache_plugin_is_absent_without_enabled_cache_rules() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        // Disabled rules must not pull the plugin in.
        site.cache_rules = vec![cache_rule(false)];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/var/lib/pingwaf/cache"),
        )
        .expect("config should build");

        assert!(!config.plugins.contains_key("pingwaf:cache"));
        for (name, loc) in &config.locations {
            assert_eq!(
                loc.plugins.as_deref(),
                Some(
                    [
                        "pingwaf:waf".to_string(),
                        "pingwaf:challenge".to_string(),
                        "pingwaf:rewrite".to_string(),
                        "pingwaf:error_page".to_string(),
                    ]
                    .as_slice()
                ),
                "location {name} must not reference the cache plugin"
            );
        }
    }

    #[test]
    fn certified_sites_split_plaintext_and_tls_servers() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        site.ssl_config = Some(acme_ssl());
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        assert_eq!(config.servers.len(), 2);
        let http = config.servers.get("pingwaf").expect("http server");
        assert_eq!(http.addr, "0.0.0.0:80");
        assert_eq!(http.global_certificates, Some(false));
        let tls = config.servers.get("pingwaf_tls").expect("tls server");
        assert_eq!(tls.addr, "0.0.0.0:443");
        assert_eq!(tls.global_certificates, Some(true));
        let names = tls.locations.as_deref().expect("tls locations");
        assert_eq!(names, http.locations.as_deref().expect("http locations"));
        assert!(names.contains(&"site1_loc".to_string()));
    }

    #[test]
    fn mtls_sites_contribute_their_ca_to_the_tls_listener() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        let mut ssl = acme_ssl();
        ssl.mtls_enabled = true;
        ssl.mtls_client_ca = "-----BEGIN CERTIFICATE-----\nCA1\n".to_string();
        site.ssl_config = Some(ssl);
        let mut second = site_rules("site2", "b.example.com");
        second.upstreams = vec![pool("pool2", vec![peer("10.0.0.2:8080")])];
        let mut second_ssl = acme_ssl();
        second_ssl.mtls_enabled = true;
        second_ssl.mtls_client_ca =
            "-----BEGIN CERTIFICATE-----\nCA2".to_string();
        second.ssl_config = Some(second_ssl);
        // A site with the plain TLS posture must not add an anchor.
        let mut plain = site_rules("site3", "c.example.com");
        plain.upstreams = vec![pool("pool3", vec![peer("10.0.0.3:8080")])];
        plain.ssl_config = Some(acme_ssl());

        let mut cache = one_site_cache(site);
        cache.sites.insert("site2".to_string(), Arc::new(second));
        cache.sites.insert("site3".to_string(), Arc::new(plain));
        let config = cached_rules_to_pingap_config(
            &cache,
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let tls = config.servers.get("pingwaf_tls").expect("tls server");
        let bundle = tls.client_ca_pem.as_deref().expect("client ca bundle");
        assert!(bundle.contains("CA1"), "{bundle}");
        assert!(bundle.contains("CA2"), "{bundle}");
        // The plaintext listener never verifies client certificates.
        let http = config.servers.get("pingwaf").expect("http server");
        assert_eq!(http.client_ca_pem, None);
    }

    #[test]
    fn sites_without_mtls_leave_client_verification_off() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        // mTLS disabled even though an anchor is on file.
        let mut ssl = acme_ssl();
        ssl.mtls_client_ca = "-----BEGIN CERTIFICATE-----\nCA1".to_string();
        site.ssl_config = Some(ssl);

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let tls = config.servers.get("pingwaf_tls").expect("tls server");
        assert_eq!(tls.client_ca_pem, None);
    }

    #[test]
    fn sites_without_certificates_still_bind_tls() {
        // 443 comes up even with an empty certificate provider: handshakes
        // fail until the first certificate lands, but the port is listening
        // and the certificate takes effect without a restart.
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        assert_eq!(config.servers.len(), 2);
        let server = config.servers.get("pingwaf").expect("server");
        assert_eq!(server.addr, "0.0.0.0:80");
        assert_eq!(server.global_certificates, Some(false));
        let tls = config.servers.get("pingwaf_tls").expect("tls server");
        assert_eq!(tls.addr, "0.0.0.0:443");
        assert_eq!(tls.global_certificates, Some(true));
    }

    #[test]
    fn low_priority_routes_still_beat_the_site_fallback() {
        // Regression: the fallback location used to carry the auto weight
        // (128), so a route with priority ≤ 127 sorted behind the catch-all
        // `/` location and never matched. The fallback now pins weight 0.
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        let mut routed_pool = pool("pool2", vec![peer("10.0.0.2:8080")]);
        routed_pool.is_default = false;
        site.upstreams.push(routed_pool);
        let mut r = route("r1", "prefix", "/api", "pool2");
        r.priority = Some(1);
        site.routes.push(r);

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let fallback = config
            .locations
            .get("site1_loc")
            .expect("fallback location");
        assert_eq!(fallback.weight, Some(0));
        let routed = config
            .locations
            .get("site1_route_r1")
            .expect("route location");
        assert_eq!(routed.weight, Some(1));
    }

    #[test]
    fn routes_fall_back_to_the_default_pool_when_theirs_is_empty() {
        let mut site = site_rules("site1", "a.example.com");
        let mut default_pool = pool("pool1", vec![peer("10.0.0.1:8080")]);
        default_pool.is_default = true;
        site.upstreams = vec![default_pool];
        let mut empty_pool = pool("pool2", vec![]);
        empty_pool.is_default = false;
        site.upstreams.push(empty_pool);
        site.routes.push(route("r1", "prefix", "/api", "pool2"));
        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let location = config
            .locations
            .get("site1_route_r1")
            .expect("route location should exist");
        assert_eq!(location.upstream.as_deref(), Some("pool1"));
    }

    #[test]
    fn hsts_and_https_redirect_are_wired_per_site() {
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![pool("pool1", vec![peer("10.0.0.1:8080")])];
        let mut ssl = acme_ssl();
        ssl.hsts_enabled = true;
        ssl.hsts_max_age = 15_552_000;
        ssl.always_use_https = true;
        site.ssl_config = Some(ssl);

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        let hsts = config.plugins.get("site1_hsts").expect("hsts plugin");
        assert_eq!(
            hsts.get("category").and_then(|v| v.as_str()),
            Some("response_headers")
        );
        let add_headers = hsts
            .get("add_headers")
            .and_then(|v| v.as_array())
            .expect("add_headers list");
        assert_eq!(
            add_headers[0].as_str(),
            Some("Strict-Transport-Security: max-age=15552000")
        );

        let redirect =
            config.plugins.get("site1_https").expect("redirect plugin");
        assert_eq!(
            redirect.get("category").and_then(|v| v.as_str()),
            Some("redirect")
        );
        assert_eq!(
            redirect.get("http_to_https").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            redirect.get("status").and_then(|v| v.as_integer()),
            Some(301)
        );

        let names = config
            .locations
            .get("site1_loc")
            .and_then(|loc| loc.plugins.clone())
            .unwrap_or_default();
        assert!(names.contains(&"site1_hsts".to_string()), "{names:?}");
        assert!(names.contains(&"site1_https".to_string()), "{names:?}");
    }

    #[test]
    fn hsts_and_redirect_plugins_are_absent_when_not_configured() {
        let mut site = site_rules("site1", "a.example.com");
        site.upstreams = vec![pool("pool1", vec![peer("10.0.0.1:8080")])];
        let mut ssl = acme_ssl();
        ssl.hsts_enabled = true;
        // A zero window means "send no header", not "pin max-age=0".
        ssl.hsts_max_age = 0;
        ssl.always_use_https = false;
        site.ssl_config = Some(ssl);

        let config = cached_rules_to_pingap_config(
            &one_site_cache(site),
            Path::new("/tmp/pingwaf-test-cache"),
        )
        .expect("config should build");

        assert!(!config.plugins.contains_key("site1_hsts"));
        assert!(!config.plugins.contains_key("site1_https"));
        let names = config
            .locations
            .get("site1_loc")
            .and_then(|loc| loc.plugins.clone())
            .unwrap_or_default();
        assert!(
            !names
                .iter()
                .any(|name| name.contains("_hsts") || name.contains("_https")),
            "{names:?}"
        );
    }

    fn acme_ssl() -> SslConfig {
        SslConfig {
            cert_pem: String::new(),
            key_pem: String::new(),
            acme_enabled: true,
            acme_email: "admin@example.com".to_string(),
            acme_challenge_type: "AcmeHttp01".to_string(),
            acme_dns_provider: String::new(),
            acme_dns_config: HashMap::new(),
            min_tls_version: String::new(),
            hsts_enabled: false,
            hsts_max_age: 0,
            always_use_https: false,
            enabled: true,
            max_tls_version: String::new(),
            self_signed: false,
            mtls_enabled: false,
            mtls_client_ca: String::new(),
            certificate_id: String::new(),
            mtls_revoked_fingerprints: vec![],
            mtls_organization: String::new(),
            mtls_require_client_cert: Some(false),
        }
    }

    #[test]
    fn acme_http01_conf_marks_acme_without_dns_fields() {
        let ssl = acme_ssl();
        let cert = acme_certificate_conf(&ssl, "a.example.com".to_string())
            .expect("plain hostnames issue over http-01");
        assert_eq!(cert.acme.as_deref(), Some("http://admin@example.com"));
        assert_eq!(cert.domains.as_deref(), Some("a.example.com"));
        assert_eq!(cert.dns_challenge, None);
        assert_eq!(cert.dns_provider, None);
    }

    #[test]
    fn acme_wildcards_are_skipped_unless_dns01_is_usable() {
        // http-01 cannot validate a wildcard: the order is dropped instead
        // of retried forever.
        let ssl = acme_ssl();
        assert!(
            acme_certificate_conf(&ssl, "*.example.com".to_string()).is_none()
        );
        assert!(
            acme_certificate_conf(
                &ssl,
                "example.com,*.example.com".to_string()
            )
            .is_none()
        );

        // dns-01 with a provider that resolves to no endpoint falls back to
        // http-01, so a wildcard is dropped there too.
        let mut ssl = acme_ssl();
        ssl.acme_challenge_type = "AcmeDns01".to_string();
        ssl.acme_dns_provider = "not-a-provider".to_string();
        assert!(
            acme_certificate_conf(&ssl, "*.example.com".to_string()).is_none()
        );

        // Manual mode renders no DNS challenge either.
        ssl.acme_dns_provider = "manual".to_string();
        assert!(
            acme_certificate_conf(&ssl, "*.example.com".to_string()).is_none()
        );

        // A real provider issues the wildcard through dns-01.
        ssl.acme_dns_provider = "ali".to_string();
        let cert = acme_certificate_conf(&ssl, "*.example.com".to_string())
            .expect("dns-01 issues wildcards");
        assert_eq!(cert.dns_challenge, Some(true));
        assert_eq!(cert.dns_provider.as_deref(), Some("ali"));

        // The unknown-provider fallback still serves plain hostnames.
        ssl.acme_challenge_type = "AcmeDns01".to_string();
        ssl.acme_dns_provider = "not-a-provider".to_string();
        assert!(
            acme_certificate_conf(&ssl, "a.example.com".to_string()).is_some()
        );
    }

    #[test]
    fn acme_dns01_conf_builds_provider_endpoint_with_credentials() {
        let mut ssl = acme_ssl();
        ssl.acme_challenge_type = "AcmeDns01".to_string();
        // "aliyun" is an accepted alias; the canonical name the config
        // carries is "ali".
        ssl.acme_dns_provider = "aliyun".to_string();
        ssl.acme_dns_config
            .insert("access_key_id".to_string(), "AK 1/2".to_string());
        ssl.acme_dns_config
            .insert("access_key_secret".to_string(), "s3cret".to_string());

        let cert = acme_certificate_conf(&ssl, "a.example.com".to_string())
            .expect("ali resolves to an endpoint");
        assert_eq!(cert.dns_challenge, Some(true));
        assert_eq!(cert.dns_provider.as_deref(), Some("ali"));
        let url = cert.dns_service_url.expect("service url");
        assert!(url.starts_with("https://alidns.aliyuncs.com?"), "{url}");
        assert!(url.contains("access_key_id=AK%201%2F2"), "{url}");
        assert!(url.contains("access_key_secret=s3cret"), "{url}");
    }

    #[test]
    fn acme_dns01_unknown_provider_stays_on_http01() {
        let mut ssl = acme_ssl();
        ssl.acme_challenge_type = "AcmeDns01".to_string();
        ssl.acme_dns_provider = "not-a-provider".to_string();

        let cert = acme_certificate_conf(&ssl, "a.example.com".to_string())
            .expect("unknown providers fall back to http-01");
        assert_eq!(cert.dns_challenge, None);
        assert_eq!(cert.dns_provider, None);
    }

    #[test]
    fn merge_config_state_empty_prev_is_identity() {
        let new_toml = "[certificates.c1]\ntls_key = \"k\"\n";
        assert_eq!(merge_config_state(new_toml, ""), new_toml);
    }

    #[test]
    fn merge_config_state_carries_issued_pems_and_storages() {
        let prev_toml = "\
[certificates.c1]
tls_cert = \"ISSUED\"
tls_key = \"KEY\"

[certificates.c2]
tls_cert = \"UPLOAD\"
tls_key = \"UPKEY\"

[storages.acme]
type = \"file\"
path = \"/tmp/acme\"
";
        let new_toml = "\
[certificates.c1]
acme = \"http://a@example.com\"

[certificates.c2]
tls_cert = \"NEWUPLOAD\"
tls_key = \"NEWKEY\"
";
        let merged = merge_config_state(new_toml, prev_toml)
            .parse::<toml::Table>()
            .expect("merged config must parse");

        let c1 = merged
            .get("certificates")
            .and_then(|v| v.get("c1"))
            .expect("c1 entry");
        assert_eq!(
            c1.get("tls_cert").and_then(|v| v.as_str()),
            Some("ISSUED"),
            "issued pem must be carried over"
        );
        assert_eq!(
            c1.get("tls_key").and_then(|v| v.as_str()),
            Some("KEY"),
            "issued key must be carried over"
        );

        let c2 = merged
            .get("certificates")
            .and_then(|v| v.get("c2"))
            .expect("c2 entry");
        assert_eq!(
            c2.get("tls_cert").and_then(|v| v.as_str()),
            Some("NEWUPLOAD"),
            "fresh upload must win over the previous pem"
        );

        let storages = merged.get("storages").expect("storages section");
        assert_eq!(
            storages
                .get("acme")
                .and_then(|v| v.get("path"))
                .and_then(|v| v.as_str()),
            Some("/tmp/acme")
        );
    }
}
