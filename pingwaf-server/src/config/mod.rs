//! Control plane configuration.
//!
//! [`ServerConfig`] is the single source of truth for everything the control
//! plane needs at runtime: the PostgreSQL DSN, the two listen addresses (HTTP
//! API and gRPC control plane), the JWT signing material and the credentials of
//! the administrator account that is seeded on first boot.
//!
//! Values come from a config file, `PINGWAF_*` environment variables or CLI
//! flags in the caller; [`ServerConfig::from_env`] layers the environment on top
//! of [`ServerConfig::default`] so a container can be started without a file.

use serde::{Deserialize, Serialize};

use crate::es::EsConfig;

/// Default PostgreSQL DSN used by the development docker-compose file.
pub const DEFAULT_DB_URL: &str =
    "postgres://pingwaf:pingwaf@localhost:5432/pingwaf";
/// Default address of the REST API / dashboard.
pub const DEFAULT_HTTP_ADDR: &str = "0.0.0.0:9080";
/// Default address of the gRPC control plane used by the agents.
pub const DEFAULT_GRPC_ADDR: &str = "0.0.0.0:9090";
/// Placeholder secret, rejected by [`ServerConfig::validate`] unless overridden.
pub const DEFAULT_JWT_SECRET: &str = "change-me-in-production";
/// Default administrator seeded on an empty database.
pub const DEFAULT_ADMIN_EMAIL: &str = "admin@pingwaf.local";
/// Default administrator password, only used to bootstrap the first account.
pub const DEFAULT_ADMIN_PASSWORD: &str = "pingwaf123";

/// How long an access token stays valid, in hours.
const DEFAULT_JWT_EXPIRATION_HOURS: i64 = 12;
/// How long a refresh token stays valid, in hours.
const DEFAULT_REFRESH_EXPIRATION_HOURS: i64 = 24 * 30;
/// Interval the agents are told to use for heartbeats, in seconds.
const DEFAULT_HEARTBEAT_INTERVAL_SECONDS: i64 = 15;
/// Size of the sqlx connection pool.
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 20;
/// Minimum number of pooled connections kept warm.
const DEFAULT_DB_MIN_CONNECTIONS: u32 = 1;
/// Batch size used when writing streamed agent logs to PostgreSQL.
const DEFAULT_LOG_BATCH_SIZE: usize = 500;
/// Days of edge-metric samples kept before the hourly sweep prunes them.
const DEFAULT_METRIC_RETENTION_DAYS: i64 = 7;
/// Name authenticators show when a passkey is created.
const DEFAULT_PASSKEY_RP_NAME: &str = "PingWAF";
/// Subject common name of the self-signed certificate the control plane
/// generates when no certificate has been uploaded yet.
pub const DEFAULT_TLS_COMMON_NAME: &str = "PingWAF Control Plane";

/// Transport security of the gRPC control plane listener.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize,
)]
pub enum GrpcTlsMode {
    /// TLS is on (the default): an explicitly configured certificate if one
    /// is set, otherwise the control plane's stored certificate — generated
    /// self-signed on first boot. Agents connect with `https://` URLs.
    #[default]
    #[serde(rename = "tls")]
    Tls,
    /// Plaintext, for isolated networks only. The deployment is marked
    /// degraded at startup and in the API responses.
    #[serde(rename = "off")]
    Off,
}

impl GrpcTlsMode {
    /// Parses a `PINGWAF_GRPC_TLS_MODE` value; unknown values fall back to
    /// the TLS default.
    pub fn from_env_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "false" | "disabled" | "plain" | "plaintext" => Self::Off,
            _ => Self::Tls,
        }
    }
}

impl std::str::FromStr for GrpcTlsMode {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_env_value(s))
    }
}

fn default_db_url() -> String {
    DEFAULT_DB_URL.to_string()
}

fn default_http_addr() -> String {
    DEFAULT_HTTP_ADDR.to_string()
}

fn default_grpc_addr() -> String {
    DEFAULT_GRPC_ADDR.to_string()
}

fn default_jwt_secret() -> String {
    DEFAULT_JWT_SECRET.to_string()
}

fn default_admin_email() -> String {
    DEFAULT_ADMIN_EMAIL.to_string()
}

fn default_admin_password() -> String {
    DEFAULT_ADMIN_PASSWORD.to_string()
}

fn default_jwt_expiration_hours() -> i64 {
    DEFAULT_JWT_EXPIRATION_HOURS
}

fn default_refresh_expiration_hours() -> i64 {
    DEFAULT_REFRESH_EXPIRATION_HOURS
}

fn default_heartbeat_interval_seconds() -> i64 {
    DEFAULT_HEARTBEAT_INTERVAL_SECONDS
}

fn default_db_max_connections() -> u32 {
    DEFAULT_DB_MAX_CONNECTIONS
}

fn default_db_min_connections() -> u32 {
    DEFAULT_DB_MIN_CONNECTIONS
}

fn default_log_batch_size() -> usize {
    DEFAULT_LOG_BATCH_SIZE
}

fn default_metric_retention_days() -> i64 {
    DEFAULT_METRIC_RETENTION_DAYS
}

fn default_passkey_rp_name() -> String {
    DEFAULT_PASSKEY_RP_NAME.to_string()
}

fn default_true() -> bool {
    true
}

/// Subject names a generated self-signed certificate is valid for when the
/// operator did not name any.
fn default_tls_sans() -> Vec<String> {
    vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ]
}

/// Runtime configuration of the PingWAF control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// PostgreSQL connection string, e.g.
    /// `postgres://user:pass@host:5432/pingwaf`.
    #[serde(default = "default_db_url")]
    pub db_url: String,
    /// Socket address the REST API (and dashboard) listens on.
    #[serde(default = "default_http_addr")]
    pub http_addr: String,
    /// Socket address the gRPC control plane listens on.
    #[serde(default = "default_grpc_addr")]
    pub grpc_addr: String,
    /// Optional PEM certificate enabling TLS on the gRPC listener. Both this
    /// and `grpc_tls_key` must be set; agents then connect with `https://`
    /// URLs. When absent, TLS (the default mode) reuses the control plane's
    /// stored certificate.
    #[serde(default)]
    pub grpc_tls_cert: Option<String>,
    /// Optional PEM private key for `grpc_tls_cert`.
    #[serde(default)]
    pub grpc_tls_key: Option<String>,
    /// Transport security of the gRPC listener: `tls` (the default) serves
    /// the explicitly configured certificate or, absent one, the control
    /// plane's stored certificate (self-signed on first boot); `off` serves
    /// plaintext and marks the deployment degraded.
    #[serde(default)]
    pub grpc_tls_mode: GrpcTlsMode,
    /// HMAC secret used to sign access, refresh and agent tokens.
    #[serde(default = "default_jwt_secret")]
    pub jwt_secret: String,
    /// Lifetime of an access token in hours.
    #[serde(default = "default_jwt_expiration_hours")]
    pub jwt_expiration_hours: i64,
    /// Lifetime of a refresh token in hours.
    #[serde(default = "default_refresh_expiration_hours")]
    pub refresh_token_expiration_hours: i64,
    /// Administrator account created when the `users` table is empty.
    #[serde(default = "default_admin_email")]
    pub default_admin_email: String,
    /// Password of the seeded administrator account.
    #[serde(default = "default_admin_password")]
    pub default_admin_password: String,
    /// Whether `POST /api/v1/auth/register` accepts new signups.
    #[serde(default = "default_true")]
    pub allow_registration: bool,
    /// Heartbeat interval handed to agents at registration, in seconds.
    #[serde(default = "default_heartbeat_interval_seconds")]
    pub heartbeat_interval_seconds: i64,
    /// Maximum pooled database connections.
    #[serde(default = "default_db_max_connections")]
    pub db_max_connections: u32,
    /// Minimum pooled database connections.
    #[serde(default = "default_db_min_connections")]
    pub db_min_connections: u32,
    /// Number of streamed log entries buffered before a batch insert.
    #[serde(default = "default_log_batch_size")]
    pub log_batch_size: usize,
    /// Days of edge-metric samples kept in `agent_metrics` before pruning.
    #[serde(default = "default_metric_retention_days")]
    pub metric_retention_days: i64,
    /// Elasticsearch log shipping. `None` (or a disabled config) keeps logs in
    /// PostgreSQL only.
    #[serde(default)]
    pub elasticsearch: Option<EsConfig>,
    /// Origins allowed by CORS; `*` keeps the permissive development default.
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// Whether the embedded dashboard SPA is served for non-API routes.
    #[serde(default = "default_true")]
    pub serve_frontend: bool,
    /// Whether passkey (WebAuthn) registration and login are offered.
    #[serde(default = "default_true")]
    pub passkey_enabled: bool,
    /// Relying party name shown by the authenticator when a passkey is created.
    #[serde(default = "default_passkey_rp_name")]
    pub passkey_rp_name: String,
    /// Relying party ID, i.e. the effective domain the passkey is scoped to.
    /// Derived from the request `Host` when unset, which is what a deployment
    /// that is reached under a single hostname wants.
    #[serde(default)]
    pub passkey_rp_id: Option<String>,
    /// Origin the dashboard is served from, e.g. `https://waf.example.com`.
    /// Derived from the request when unset.
    #[serde(default)]
    pub passkey_origin: Option<String>,
    /// Whether `X-Forwarded-Proto` may be believed when deriving the origin of a
    /// request. Off by default: with it on, any client that can reach the
    /// control plane directly could claim an `https` origin it did not use.
    #[serde(default)]
    pub passkey_trust_forwarded_proto: bool,
    /// Whether the REST API and the dashboard are served over TLS.
    ///
    /// On by default: browsers only offer passkeys on a secure origin, and a
    /// self-signed certificate is generated on first boot when nothing has been
    /// uploaded yet. Turn it off when a reverse proxy in front of the control
    /// plane terminates TLS (and configure `passkey_origin`, since the control
    /// plane then only sees plain HTTP).
    #[serde(default = "default_true")]
    pub tls_enabled: bool,
    /// Subject alternative names of the generated self-signed certificate.
    ///
    /// DNS names and IP addresses are both accepted; the host the dashboard is
    /// reached under has to appear here (or in an uploaded certificate) for the
    /// browser to accept the connection without a warning.
    #[serde(default = "default_tls_sans")]
    pub tls_sans: Vec<String>,
    /// Host (optionally with port) the dashboard is reached under from the
    /// outside, e.g. `waf.example.com` or `waf.example.com:9080`.
    ///
    /// Pinned into the cleartext-to-HTTPS redirect target; when unset the
    /// redirect reuses the request's `Host` header, which a reverse proxy in
    /// front of the control plane should be trusted to forward accurately.
    #[serde(default)]
    pub public_host: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            db_url: DEFAULT_DB_URL.to_string(),
            http_addr: DEFAULT_HTTP_ADDR.to_string(),
            grpc_addr: DEFAULT_GRPC_ADDR.to_string(),
            grpc_tls_cert: None,
            grpc_tls_key: None,
            grpc_tls_mode: GrpcTlsMode::default(),
            jwt_secret: DEFAULT_JWT_SECRET.to_string(),
            jwt_expiration_hours: DEFAULT_JWT_EXPIRATION_HOURS,
            refresh_token_expiration_hours: DEFAULT_REFRESH_EXPIRATION_HOURS,
            default_admin_email: DEFAULT_ADMIN_EMAIL.to_string(),
            default_admin_password: DEFAULT_ADMIN_PASSWORD.to_string(),
            allow_registration: true,
            heartbeat_interval_seconds: DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
            db_max_connections: DEFAULT_DB_MAX_CONNECTIONS,
            db_min_connections: DEFAULT_DB_MIN_CONNECTIONS,
            log_batch_size: DEFAULT_LOG_BATCH_SIZE,
            metric_retention_days: DEFAULT_METRIC_RETENTION_DAYS,
            elasticsearch: None,
            cors_origins: Vec::new(),
            serve_frontend: true,
            passkey_enabled: true,
            passkey_rp_name: DEFAULT_PASSKEY_RP_NAME.to_string(),
            passkey_rp_id: None,
            passkey_origin: None,
            passkey_trust_forwarded_proto: false,
            tls_enabled: true,
            tls_sans: default_tls_sans(),
            public_host: None,
        }
    }
}

impl ServerConfig {
    /// Default configuration with `PINGWAF_*` environment variables applied.
    ///
    /// Unknown or unparsable variables are ignored so a typo in the environment
    /// cannot prevent the control plane from booting; the effective values are
    /// logged by the caller.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(value) = std::env::var("PINGWAF_DB_URL") {
            config.db_url = value;
        }
        if let Ok(value) = std::env::var("DATABASE_URL") {
            // Honour the conventional name too, env var precedence: PINGWAF_*.
            if std::env::var("PINGWAF_DB_URL").is_err() {
                config.db_url = value;
            }
        }
        if let Ok(value) = std::env::var("PINGWAF_ADMIN_ADDR")
            .or_else(|_| std::env::var("PINGWAF_HTTP_ADDR"))
        {
            config.http_addr = value;
        }
        if let Ok(value) = std::env::var("PINGWAF_GRPC_ADDR") {
            config.grpc_addr = value;
        }
        if let Ok(value) = std::env::var("PINGWAF_GRPC_TLS_CERT") {
            config.grpc_tls_cert = non_empty_env(&value);
        }
        if let Ok(value) = std::env::var("PINGWAF_GRPC_TLS_KEY") {
            config.grpc_tls_key = non_empty_env(&value);
        }
        if let Ok(value) = std::env::var("PINGWAF_GRPC_TLS_MODE") {
            config.grpc_tls_mode = GrpcTlsMode::from_env_value(&value);
        }
        if let Ok(value) = std::env::var("PINGWAF_PUBLIC_HOST") {
            config.public_host = non_empty_env(&value);
        }
        if let Ok(value) = std::env::var("PINGWAF_JWT_SECRET") {
            config.jwt_secret = value;
        }
        if let Ok(value) = std::env::var("PINGWAF_JWT_EXPIRATION_HOURS") {
            if let Ok(hours) = value.parse::<i64>() {
                config.jwt_expiration_hours = hours;
            }
        }
        if let Ok(value) = std::env::var("PINGWAF_ADMIN_EMAIL") {
            config.default_admin_email = value;
        }
        if let Ok(value) = std::env::var("PINGWAF_ADMIN_PASSWORD") {
            config.default_admin_password = value;
        }
        if let Ok(value) = std::env::var("PINGWAF_ALLOW_REGISTRATION") {
            config.allow_registration = parse_bool(&value);
        }
        if let Ok(value) = std::env::var("PINGWAF_HEARTBEAT_INTERVAL") {
            if let Ok(seconds) = value.parse::<i64>() {
                config.heartbeat_interval_seconds = seconds;
            }
        }
        if let Ok(value) = std::env::var("PINGWAF_DB_MAX_CONNECTIONS") {
            if let Ok(max) = value.parse::<u32>() {
                config.db_max_connections = max;
            }
        }
        if let Ok(value) = std::env::var("PINGWAF_METRIC_RETENTION_DAYS") {
            if let Ok(days) = value.parse::<i64>() {
                config.metric_retention_days = days;
            }
        }
        if let Ok(value) = std::env::var("PINGWAF_CORS_ORIGINS") {
            config.cors_origins = value
                .split(',')
                .map(|origin| origin.trim().to_string())
                .filter(|origin| !origin.is_empty())
                .collect();
        }
        if let Ok(value) = std::env::var("PINGWAF_SERVE_FRONTEND") {
            config.serve_frontend = parse_bool(&value);
        }
        if let Ok(value) = std::env::var("PINGWAF_PASSKEY_ENABLED") {
            config.passkey_enabled = parse_bool(&value);
        }
        if let Ok(value) = std::env::var("PINGWAF_PASSKEY_RP_NAME") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                config.passkey_rp_name = trimmed.to_string();
            }
        }
        if let Ok(value) = std::env::var("PINGWAF_PASSKEY_RP_ID") {
            config.passkey_rp_id = non_empty_env(&value);
        }
        if let Ok(value) = std::env::var("PINGWAF_PASSKEY_ORIGIN") {
            config.passkey_origin = non_empty_env(&value);
        }
        if let Ok(value) =
            std::env::var("PINGWAF_PASSKEY_TRUST_FORWARDED_PROTO")
        {
            config.passkey_trust_forwarded_proto = parse_bool(&value);
        }
        if let Ok(value) = std::env::var("PINGWAF_TLS_ENABLED") {
            config.tls_enabled = parse_bool(&value);
        }
        if let Ok(value) = std::env::var("PINGWAF_TLS_SANS") {
            let sans: Vec<String> = value
                .split(',')
                .map(|san| san.trim().to_string())
                .filter(|san| !san.is_empty())
                .collect();
            if !sans.is_empty() {
                config.tls_sans = sans;
            }
        }
        apply_es_env(&mut config);
        config
    }

    /// Rejects configurations that cannot produce a working control plane.
    ///
    /// The bundled JWT secret is accepted (it keeps `cargo run` frictionless)
    /// but reported so the operator sees the warning at startup.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.db_url.trim().is_empty(),
            "db_url must not be empty"
        );
        anyhow::ensure!(
            !self.http_addr.trim().is_empty(),
            "http_addr must not be empty"
        );
        anyhow::ensure!(
            !self.grpc_addr.trim().is_empty(),
            "grpc_addr must not be empty"
        );
        anyhow::ensure!(
            self.jwt_secret.trim().len() >= 16,
            "jwt_secret must be at least 16 characters long"
        );
        anyhow::ensure!(
            self.jwt_expiration_hours > 0,
            "jwt_expiration_hours must be positive"
        );
        anyhow::ensure!(
            self.refresh_token_expiration_hours > self.jwt_expiration_hours,
            "refresh_token_expiration_hours must exceed jwt_expiration_hours"
        );
        anyhow::ensure!(
            self.heartbeat_interval_seconds > 0,
            "heartbeat_interval_seconds must be positive"
        );
        anyhow::ensure!(
            self.db_max_connections >= self.db_min_connections,
            "db_max_connections must be >= db_min_connections"
        );
        anyhow::ensure!(
            self.log_batch_size > 0,
            "log_batch_size must be positive"
        );
        anyhow::ensure!(
            self.metric_retention_days > 0,
            "metric_retention_days must be positive"
        );
        // Only an enabled Elasticsearch shipper has to be valid; a stored-but-
        // disabled config may be incomplete while an operator finishes setting
        // it up through the dashboard.
        if let Some(es) = &self.elasticsearch {
            if es.enabled {
                es.validate()?;
            }
        }
        Ok(())
    }

    /// True when a placeholder JWT secret is still in use.
    ///
    /// The placeholder prefix is public knowledge — it ships in the repository
    /// and in the docker-compose fallback — so any value starting with it is
    /// treated as "not configured" and replaced by a generated secret.
    pub fn uses_default_jwt_secret(&self) -> bool {
        self.jwt_secret.starts_with(DEFAULT_JWT_SECRET)
    }

    /// Subject names a generated self-signed certificate should carry.
    ///
    /// The configured list is widened with the machine's hostname and the
    /// configured passkey relying party, so a first boot produces a certificate
    /// the dashboard can be reached under in the common deployments.
    /// Whether the gRPC listener terminates TLS. `true` unless the operator
    /// explicitly opted out with `grpc_tls_mode = "off"`.
    pub fn grpc_tls_enabled(&self) -> bool {
        self.grpc_tls_mode == GrpcTlsMode::Tls
    }

    pub fn effective_tls_sans(&self) -> Vec<String> {
        // Trim and drop blanks: a half-written entry would otherwise reach the
        // certificate as an empty subject alternative name.
        let mut sans: Vec<String> = self
            .tls_sans
            .iter()
            .map(|san| san.trim().to_string())
            .filter(|san| !san.is_empty())
            .collect();
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            push_unique(&mut sans, hostname.trim());
        }
        if let Some(rp_id) = self.passkey_rp_id.as_deref() {
            push_unique(&mut sans, rp_id.trim());
        }
        push_unique(&mut sans, "localhost");
        push_unique(&mut sans, "127.0.0.1");
        sans
    }

    /// Redacted view of the DSN, safe to log.
    pub fn db_url_redacted(&self) -> String {
        redact_url(&self.db_url)
    }
}

/// Parses the usual truthy spellings used in environment files.
fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Environment values that are meaningful only when non-empty; an empty
/// variable reads as "unset" rather than as an empty override.
fn non_empty_env(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Appends a subject name unless it is blank or already present.
fn push_unique(sans: &mut Vec<String>, candidate: &str) {
    if candidate.is_empty() || sans.iter().any(|san| san == candidate) {
        return;
    }
    sans.push(candidate.to_string());
}

/// Layers `PINGWAF_ES_*` environment variables onto the Elasticsearch config.
///
/// Only the handful of settings an operator typically overrides at deploy time
/// are read here; the full shape is available through the config file and the
/// settings API. Presence of any `PINGWAF_ES_*` variable materialises the
/// config so a container can enable shipping purely from the environment.
fn apply_es_env(config: &mut ServerConfig) {
    let mut es = config.elasticsearch.clone().unwrap_or_default();
    let mut touched = false;

    if let Ok(value) = std::env::var("PINGWAF_ES_URLS") {
        es.urls = value
            .split(',')
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect();
        touched = true;
    }
    if let Ok(value) = std::env::var("PINGWAF_ES_ENABLED") {
        es.enabled = parse_bool(&value);
        touched = true;
    }
    if let Ok(value) = std::env::var("PINGWAF_ES_INDEX_PREFIX") {
        es.index_prefix = value;
        touched = true;
    }
    if let Ok(value) = std::env::var("PINGWAF_ES_USERNAME") {
        es.username = Some(value);
        touched = true;
    }
    if let Ok(value) = std::env::var("PINGWAF_ES_PASSWORD") {
        es.password = Some(value);
        touched = true;
    }
    if let Ok(value) = std::env::var("PINGWAF_ES_API_KEY") {
        es.api_key = Some(value);
        touched = true;
    }
    if let Ok(value) = std::env::var("PINGWAF_ES_MAX_BODY_SIZE") {
        if let Ok(size) = value.parse::<usize>() {
            es.max_body_size = size;
        }
        touched = true;
    }
    if let Ok(value) = std::env::var("PINGWAF_ES_BUFFER_DIR") {
        es.buffer_dir = Some(value);
        touched = true;
    }

    if touched {
        config.elasticsearch = Some(es);
    }
}

/// Replaces the password component of a DSN with `***`.
fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return "***".to_string();
    };
    let (scheme, rest) = url.split_at(scheme_end + 3);
    let Some(at) = rest.rfind('@') else {
        return format!("{scheme}***");
    };
    let credentials = &rest[..at];
    let host = &rest[at..];
    match credentials.split_once(':') {
        Some((user, _)) => format!("{scheme}{user}:***{host}"),
        None => format!("{scheme}***{host}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        ServerConfig::default().validate().expect("valid config");
    }

    #[test]
    fn rejects_short_secret() {
        let config = ServerConfig {
            jwt_secret: "short".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_refresh_shorter_than_access() {
        let config = ServerConfig {
            jwt_expiration_hours: 24,
            refresh_token_expiration_hours: 1,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn redacts_dsn_password() {
        assert_eq!(
            redact_url("postgres://pingwaf:secret@localhost:5432/pingwaf"),
            "postgres://pingwaf:***@localhost:5432/pingwaf"
        );
        assert_eq!(redact_url("not-a-url"), "***");
    }

    #[test]
    fn serde_defaults_fill_missing_fields() {
        let config: ServerConfig = serde_json::from_str(
            r#"{"jwt_secret":"a-very-long-secret-value"}"#,
        )
        .expect("missing fields fall back to defaults");
        assert_eq!(config.http_addr, DEFAULT_HTTP_ADDR);
        assert_eq!(config.metric_retention_days, DEFAULT_METRIC_RETENTION_DAYS);
        assert!(config.allow_registration);
        assert_eq!(config.heartbeat_interval_seconds, 15);
        // TLS is on by default so a fresh deployment can use passkeys.
        assert!(config.tls_enabled);
        assert!(config.tls_sans.contains(&"localhost".to_string()));
    }

    #[test]
    fn placeholder_secrets_are_treated_as_unconfigured() {
        assert!(ServerConfig::default().uses_default_jwt_secret());
        // The docker-compose fallback extends the built-in placeholder.
        let composed = ServerConfig {
            jwt_secret: format!("{DEFAULT_JWT_SECRET}-use-32-chars"),
            ..Default::default()
        };
        assert!(composed.uses_default_jwt_secret());
        let explicit = ServerConfig {
            jwt_secret: "a-very-long-secret-value".to_string(),
            ..Default::default()
        };
        assert!(!explicit.uses_default_jwt_secret());
    }

    #[test]
    fn effective_sans_are_unique_and_include_the_relying_party() {
        let config = ServerConfig {
            tls_sans: vec!["waf.example.com".to_string(), "  ".to_string()],
            passkey_rp_id: Some("waf.example.com".to_string()),
            ..Default::default()
        };
        let sans = config.effective_tls_sans();
        assert!(sans.contains(&"waf.example.com".to_string()));
        assert!(sans.contains(&"localhost".to_string()));
        assert!(!sans.iter().any(|san| san.trim().is_empty()));
        let unique: std::collections::BTreeSet<&String> = sans.iter().collect();
        assert_eq!(unique.len(), sans.len(), "subject names must be unique");
    }
}
