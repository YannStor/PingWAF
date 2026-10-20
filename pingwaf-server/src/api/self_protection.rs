//! Control plane self-protection: the 9080 listener's own access log, IP
//! allowlist and WAF.
//!
//! Three middlewares guard the console and REST API, outermost first:
//!
//! 1. [`access_log`] — records one row per request into
//!    `control_plane_access_logs` (when enabled) and stamps a request id on
//!    the response.
//! 2. [`ip_allowlist`] — refuses callers outside the configured ranges and
//!    the referenced `ip_groups` row.
//! 3. [`waf_guard`] — inspects the request with the embedded
//!    [`pingwaf_waf`] engine and blocks (or only records, in `monitor` mode).
//!
//! Health probes (`/healthz`, `/api/v1/health`) are exempt from all three so
//! container and load balancer probes keep working. The policy is loaded from
//! `api_protection_settings` at boot and refreshed by a background task, so a
//! change made through the API — or by the `pingwaf security` CLI on another
//! process — takes effect within [`REFRESH_INTERVAL`] without a restart.
//!
//! The middlewares never trust forwarding headers for the client address:
//! the allowlist and the log use the TCP peer. A console behind a reverse
//! proxy therefore sees the proxy's address, and the proxy's range must be
//! allowlisted.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Request, State};
use axum::http::header::{HeaderMap, AUTHORIZATION, HOST, REFERER, USER_AGENT};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
    QuerySelect, QueryTrait, Set,
};
use tokio::sync::mpsc;
use uuid::Uuid;

use pingwaf_waf::{
    CategorySet, RequestData, StackSet, WafAction, WafEngine, WafEngineConfig,
    WafLevel, WafMode,
};

use crate::api::error::error_response;
use crate::api::state::AppState;
use crate::auth::jwt::verify_user_token;
use crate::models::api_protection::{action, waf_mode};
use crate::models::{
    api_protection_setting, control_plane_access_log, ip_groups,
};
use crate::tls::ConnInfo;

/// Primary key of the single settings row.
const SETTINGS_ID: i32 = 1;

/// How often the background task re-reads the settings row.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(15);

/// Request-body prefix the WAF inspects. Bodies above this are refused with
/// `413` while the WAF is enabled, so a truncated body can never slip past
/// inspection.
const WAF_BODY_LIMIT: usize = 128 * 1024;

/// Queue depth of the access-log writer. Logging never blocks the request
/// path: a full queue drops records (with a warning) instead.
const LOG_QUEUE_CAPACITY: usize = 4096;

/// Upper bound on one insert statement.
const LOG_INSERT_BATCH: usize = 200;

/// Correlation header stamped on every response.
const REQUEST_ID_HEADER: &str = "x-request-id";

// ─────────────────────────────────────────────────────────────
// Policy
// ─────────────────────────────────────────────────────────────

/// The allowlist: parsed ranges plus a set of single addresses.
#[derive(Debug, Default)]
pub struct Allowlist {
    networks: Vec<IpNet>,
    addresses: HashSet<IpAddr>,
}

impl Allowlist {
    /// Parses every entry; entries that are neither an address nor a CIDR
    /// network are returned as errors (callers decide to refuse or skip).
    pub fn parse<I, S>(values: I) -> (Self, Vec<String>)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut networks = Vec::new();
        let mut addresses = HashSet::new();
        let mut invalid = Vec::new();
        for value in values {
            let value = value.as_ref().trim();
            if value.is_empty() {
                continue;
            }
            if let Ok(net) = IpNet::from_str(value) {
                networks.push(net);
            } else if let Ok(addr) = IpAddr::from_str(value) {
                addresses.insert(normalize_ip(&addr));
            } else {
                invalid.push(value.to_string());
            }
        }
        (
            Self {
                networks,
                addresses,
            },
            invalid,
        )
    }

    pub fn is_empty(&self) -> bool {
        self.networks.is_empty() && self.addresses.is_empty()
    }

    pub fn len(&self) -> usize {
        self.networks.len() + self.addresses.len()
    }

    /// Whether `ip` is covered. IPv4-mapped IPv6 peers are folded to IPv4
    /// first so `127.0.0.1` matches a `::ffff:127.0.0.1` connection, and an
    /// IPv6-mapped network (`::ffff:0:0/96`) matches an IPv4 peer.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let ip = normalize_ip(ip);
        self.addresses.contains(&ip)
            || self.networks.iter().any(|net| match (net, &ip) {
                (IpNet::V6(_), IpAddr::V4(v4)) => {
                    net.contains(&IpAddr::V6(v4.to_ipv6_mapped()))
                },
                _ => net.contains(&ip),
            })
    }
}

/// Folds IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) onto their IPv4 form.
pub fn normalize_ip(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(*v6)),
        other => *other,
    }
}

/// Everything the middlewares enforce, rebuilt whenever the settings change.
pub struct ProtectionPolicy {
    pub access_log_enabled: bool,
    pub allowlist_enabled: bool,
    pub allowlist: Allowlist,
    /// Built only when the WAF is enabled; `None` short-circuits the guard.
    pub waf: Option<Arc<WafEngine>>,
    /// True when the WAF answers blocks (vs. monitor mode).
    pub waf_blocking: bool,
    /// `updated_at` of the settings row this policy was built from.
    pub settings_updated_at: DateTime<Utc>,
}

impl Default for ProtectionPolicy {
    fn default() -> Self {
        Self {
            access_log_enabled: false,
            allowlist_enabled: false,
            allowlist: Allowlist::default(),
            waf: None,
            waf_blocking: false,
            settings_updated_at: DateTime::<Utc>::MIN_UTC,
        }
    }
}

/// Read-mostly handle shared through [`AppState`].
pub struct SelfProtection {
    policy: ArcSwap<ProtectionPolicy>,
    log_tx: mpsc::Sender<LogRecord>,
    /// Parked here until [`SelfProtection::spawn_writer`] runs; the struct
    /// itself only ever uses the sender.
    log_rx: Mutex<Option<mpsc::Receiver<LogRecord>>>,
}

impl SelfProtection {
    /// Creates the handle and the log channel. Call
    /// [`SelfProtection::spawn_writer`] from an async context to start
    /// persisting records; without it records queue up and are dropped.
    pub fn new() -> Self {
        let (log_tx, log_rx) = mpsc::channel(LOG_QUEUE_CAPACITY);
        Self {
            policy: ArcSwap::from_pointee(ProtectionPolicy::default()),
            log_tx,
            log_rx: Mutex::new(Some(log_rx)),
        }
    }

    pub fn policy(&self) -> Arc<ProtectionPolicy> {
        self.policy.load_full()
    }

    pub fn store(&self, policy: ProtectionPolicy) {
        self.policy.store(Arc::new(policy));
    }

    /// Queues one access-log record; never blocks. A full queue drops the
    /// record and says so — losing a log line beats stalling the request.
    pub fn record(&self, record: LogRecord) {
        if let Err(err) = self.log_tx.try_send(record) {
            tracing::warn!(
                error = %err,
                "control plane access log queue is full, dropping record"
            );
        }
    }

    /// Starts the background writer over the given database connection.
    /// A second call is a no-op.
    pub fn spawn_writer(&self, db: DatabaseConnection) {
        let rx = self.log_rx.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(rx) = rx {
            tokio::spawn(write_logs(db, rx));
        }
    }
}

impl Default for SelfProtection {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────
// Settings
// ─────────────────────────────────────────────────────────────

/// Reads the settings row, creating it with the defaults if it is missing.
pub async fn load_settings(
    db: &DatabaseConnection,
) -> Result<api_protection_setting::Model, DbErr> {
    if let Some(row) = api_protection_setting::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
    {
        return Ok(row);
    }

    let now = Utc::now();
    let insert = api_protection_setting::ActiveModel {
        id: Set(SETTINGS_ID),
        access_log_enabled: Set(true),
        access_log_retention_days: Set(
            crate::models::api_protection::DEFAULT_RETENTION_DAYS,
        ),
        ip_allowlist_enabled: Set(false),
        ip_allowlist_ranges: Set(Vec::new()),
        ip_allowlist_group_id: Set(None),
        waf_enabled: Set(false),
        waf_mode: Set(waf_mode::BLOCK.to_string()),
        updated_at: Set(now),
    };
    let ignore_conflict =
        OnConflict::column(api_protection_setting::Column::Id)
            .do_nothing()
            .to_owned();
    match api_protection_setting::Entity::insert(insert)
        .on_conflict(ignore_conflict)
        .exec(db)
        .await
    {
        Ok(_) | Err(DbErr::RecordNotInserted) => {},
        Err(err) => return Err(err),
    }

    api_protection_setting::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
        .ok_or_else(|| {
            DbErr::RecordNotFound(
                "api protection settings row vanished".to_string(),
            )
        })
}

/// The effective allowlist of a settings row: inline ranges plus the ranges
/// of the referenced group (when it exists and is enabled — a disabled group
/// is not deployed anywhere, so it contributes nothing here either).
pub async fn effective_allowlist(
    db: &DatabaseConnection,
    settings: &api_protection_setting::Model,
) -> Result<Allowlist, DbErr> {
    let mut ranges = settings.ip_allowlist_ranges.clone();
    if let Some(group_id) = settings.ip_allowlist_group_id {
        let group = ip_groups::Entity::find_by_id(group_id)
            .filter(ip_groups::Column::Enabled.eq(true))
            .one(db)
            .await?;
        match group {
            Some(group) => ranges.extend(group.ip_ranges),
            None => tracing::warn!(
                group_id = %group_id,
                "API allowlist references a missing or disabled ip group; only the inline ranges apply"
            ),
        }
    }
    let (allowlist, invalid) = Allowlist::parse(ranges);
    if !invalid.is_empty() {
        tracing::warn!(
            invalid = ?invalid,
            "ignoring invalid API allowlist entries"
        );
    }
    Ok(allowlist)
}

/// Builds the enforcement policy from the current settings row.
pub async fn refresh(
    db: &DatabaseConnection,
) -> Result<ProtectionPolicy, DbErr> {
    let settings = load_settings(db).await?;
    let allowlist = effective_allowlist(db, &settings).await?;
    let waf_blocking = settings.waf_mode == waf_mode::BLOCK;
    let waf = settings.waf_enabled.then(|| {
        Arc::new(WafEngine::new(&WafEngineConfig {
            mode: if waf_blocking {
                WafMode::Block
            } else {
                WafMode::Monitor
            },
            level: WafLevel::default(),
            stacks: StackSet::default(),
            monitor_categories: CategorySet::EMPTY,
            monitor_stacks: StackSet::EMPTY,
            monitor_managed_rules: std::collections::HashSet::new(),
            disabled_managed_rules: std::collections::HashSet::new(),
            monitor_custom_rules: std::collections::HashSet::new(),
            threshold: 40,
            paranoia_level: 2,
            max_decode_layers: 3,
            rules: Vec::new(),
            enable_managed_rules: true,
            fast_path_block_on_critical: true,
        }))
    });

    Ok(ProtectionPolicy {
        access_log_enabled: settings.access_log_enabled,
        allowlist_enabled: settings.ip_allowlist_enabled,
        allowlist,
        waf,
        waf_blocking,
        settings_updated_at: settings.updated_at,
    })
}

/// Background task: re-read the settings every [`REFRESH_INTERVAL`] and swap
/// the policy in when the row changed. Failures keep the previous policy.
pub fn start_refresh_task(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REFRESH_INTERVAL).await;
            match refresh(&state.db).await {
                Ok(policy) => {
                    let current = state.protection.policy();
                    if policy.settings_updated_at != current.settings_updated_at
                    {
                        tracing::info!(
                            allowlist_enabled = policy.allowlist_enabled,
                            allowlist_entries = policy.allowlist.len(),
                            waf_enabled = policy.waf.is_some(),
                            "control plane protection settings reloaded"
                        );
                        state.protection.store(policy);
                    }
                },
                Err(err) => tracing::warn!(
                    error = %err,
                    "could not reload control plane protection settings"
                ),
            }
        }
    })
}

// ─────────────────────────────────────────────────────────────
// Access log
// ─────────────────────────────────────────────────────────────

/// One pending access-log row.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub request_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub method: String,
    pub host: Option<String>,
    pub path: String,
    pub query_string: Option<String>,
    pub scheme: Option<String>,
    pub protocol: Option<String>,
    pub status_code: Option<i32>,
    pub latency_ms: Option<i64>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub user_id: Option<Uuid>,
    pub user_email: Option<String>,
    pub action: String,
    pub reason: Option<String>,
}

impl LogRecord {
    fn into_active(self) -> control_plane_access_log::ActiveModel {
        control_plane_access_log::ActiveModel {
            id: sea_orm::NotSet,
            request_id: Set(self.request_id),
            timestamp: Set(self.timestamp),
            client_ip: Set(self.client_ip),
            method: Set(self.method),
            host: Set(self.host),
            path: Set(self.path),
            query_string: Set(self.query_string),
            scheme: Set(self.scheme),
            protocol: Set(self.protocol),
            status_code: Set(self.status_code),
            latency_ms: Set(self.latency_ms),
            user_agent: Set(self.user_agent),
            referer: Set(self.referer),
            user_id: Set(self.user_id),
            user_email: Set(self.user_email),
            action: Set(self.action),
            reason: Set(self.reason),
        }
    }
}

/// Drains the channel into `control_plane_access_logs`, one insert per batch.
async fn write_logs(db: DatabaseConnection, mut rx: mpsc::Receiver<LogRecord>) {
    let mut batch: Vec<LogRecord> = Vec::with_capacity(LOG_INSERT_BATCH);
    loop {
        // Block for the first record, then take whatever else is queued.
        let Some(first) = rx.recv().await else {
            break;
        };
        batch.push(first);
        while batch.len() < LOG_INSERT_BATCH {
            match rx.try_recv() {
                Ok(record) => batch.push(record),
                Err(_) => break,
            }
        }
        let models: Vec<_> =
            batch.drain(..).map(LogRecord::into_active).collect();
        if let Err(err) = control_plane_access_log::Entity::insert_many(models)
            .exec(&db)
            .await
        {
            tracing::warn!(
                error = %err,
                "failed to write control plane access log batch"
            );
        }
    }
}

/// Marker the inner middlewares leave on the response, read back by
/// [`access_log`] once the response is on its way out.
#[derive(Debug, Clone)]
pub struct ProtectionOutcome {
    pub action: &'static str,
    pub reason: Option<String>,
}

/// Rows deleted per statement by [`purge_access_logs`].
const LOG_PURGE_BATCH_SIZE: u64 = 10_000;

/// Deletes control plane log rows older than the given window, in bounded
/// batches — the same shape as the site log sweep, so one statement never
/// holds locks on the whole table.
pub async fn purge_access_logs(
    db: &DatabaseConnection,
    older_than_days: i64,
) -> Result<u64, DbErr> {
    let cutoff = Utc::now() - chrono::Duration::days(older_than_days);
    let mut deleted_total = 0_u64;
    loop {
        let batch = control_plane_access_log::Entity::find()
            .select_only()
            .column(control_plane_access_log::Column::Id)
            .filter(control_plane_access_log::Column::Timestamp.lt(cutoff))
            .limit(LOG_PURGE_BATCH_SIZE);
        let deleted = control_plane_access_log::Entity::delete_many()
            .filter(
                control_plane_access_log::Column::Id
                    .in_subquery(batch.into_query()),
            )
            .exec(db)
            .await?;
        deleted_total += deleted.rows_affected;
        if deleted.rows_affected < LOG_PURGE_BATCH_SIZE {
            break;
        }
    }
    Ok(deleted_total)
}

/// `is_health_probe` decides exemption; shared so the middlewares agree with
/// the redirect layer.
fn exempt(path: &str) -> bool {
    crate::api::is_health_probe(path)
}

/// The peer address of the connection, when the serve layer provided one.
pub(crate) fn peer_addr(request: &Request) -> Option<std::net::SocketAddr> {
    request
        .extensions()
        .get::<ConnectInfo<ConnInfo>>()
        .map(|info| info.0.peer_addr)
}

/// Best-effort caller identity: a valid Bearer token on the request is
/// decoded for the log only. The handler performs the real authentication.
fn log_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> (Option<Uuid>, Option<String>) {
    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return (None, None);
    };
    match verify_user_token(token, state.jwt_secret()) {
        Ok(claims) => (claims.subject_id().ok(), Some(claims.email)),
        Err(_) => (None, None),
    }
}

fn header_text<K: axum::http::header::AsHeaderName>(
    headers: &HeaderMap,
    name: K,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

/// Middleware 1/3: request/response logging for the control plane itself.
pub async fn access_log(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    if exempt(request.uri().path()) {
        return next.run(request).await;
    }

    let started = Instant::now();
    let request_id = header_text(request.headers(), REQUEST_ID_HEADER)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }

    let enabled = state.protection.policy().access_log_enabled;
    // Identity is decoded before the request moves on; the body never needs
    // it, so this stays on the cheap side of the middleware.
    let (user_id, user_email) = if enabled {
        log_identity(&state, request.headers())
    } else {
        (None, None)
    };
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let query = request.uri().query().map(|value| value.to_string());
    let host = header_text(request.headers(), HOST);
    let user_agent = header_text(request.headers(), USER_AGENT);
    let referer = header_text(request.headers(), REFERER);
    let scheme = if request
        .extensions()
        .get::<ConnectInfo<ConnInfo>>()
        .is_some_and(|info| info.0.tls)
    {
        "https"
    } else {
        "http"
    };
    let protocol = format!("{:?}", request.version());
    let client_ip = peer_addr(&request)
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default();

    let mut response = next.run(request).await;

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }
    if !enabled {
        return response;
    }

    let outcome = response
        .extensions()
        .get::<ProtectionOutcome>()
        .cloned()
        .unwrap_or(ProtectionOutcome {
            action: action::ALLOWED,
            reason: None,
        });
    state.protection.record(LogRecord {
        request_id: Some(request_id),
        timestamp: Utc::now(),
        client_ip,
        method,
        host,
        path,
        query_string: query,
        scheme: Some(scheme.to_string()),
        protocol: Some(protocol),
        status_code: Some(response.status().as_u16() as i32),
        latency_ms: Some(started.elapsed().as_millis() as i64),
        user_agent,
        referer,
        user_id,
        user_email,
        action: outcome.action.to_string(),
        reason: outcome.reason,
    });
    response
}

// ─────────────────────────────────────────────────────────────
// IP allowlist
// ─────────────────────────────────────────────────────────────

/// Middleware 2/3: refuses callers outside the allowlist.
pub async fn ip_allowlist(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let policy = state.protection.policy();
    if !policy.allowlist_enabled || exempt(request.uri().path()) {
        return next.run(request).await;
    }

    let Some(addr) = peer_addr(&request) else {
        // No peer information means the serve layer was not wired with
        // connect info; refusing nothing would silently disable the gate, so
        // refuse the request and say why.
        tracing::error!(
            "IP allowlist is enabled but the connection carries no peer address"
        );
        let mut response = error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no_peer_address",
            "the control plane cannot determine your address",
        );
        response.extensions_mut().insert(ProtectionOutcome {
            action: action::BLOCKED_ALLOWLIST,
            reason: Some("peer address unavailable".to_string()),
        });
        return response;
    };

    if policy.allowlist.contains(&addr.ip()) {
        return next.run(request).await;
    }

    let ip = addr.ip();
    tracing::warn!(
        client_ip = %ip,
        path = %request.uri().path(),
        "control plane request refused by the IP allowlist"
    );
    let mut response = error_response(
        StatusCode::FORBIDDEN,
        "ip_not_allowed",
        "your address is not in the control plane allowlist",
    );
    response.extensions_mut().insert(ProtectionOutcome {
        action: action::BLOCKED_ALLOWLIST,
        reason: Some(format!("client ip {ip} is not allowlisted")),
    });
    response
}

// ─────────────────────────────────────────────────────────────
// WAF
// ─────────────────────────────────────────────────────────────

/// Middleware 3/3: inspects API requests with the embedded WAF engine.
pub async fn waf_guard(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let policy = state.protection.policy();
    let Some(engine) = policy.waf.clone() else {
        return next.run(request).await;
    };
    if exempt(request.uri().path()) {
        return next.run(request).await;
    }

    // Read the connection facts before the request is split: `Parts` is not
    // cloneable, so this is the last chance to look at the extensions.
    let client_ip = peer_addr(&request)
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default();
    let scheme = if request
        .extensions()
        .get::<ConnectInfo<ConnInfo>>()
        .is_some_and(|info| info.0.tls)
    {
        "https".to_string()
    } else {
        "http".to_string()
    };

    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, WAF_BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(error = %err, "control plane request body exceeded the WAF inspection limit");
            let mut response = error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_body_too_large",
                "request body exceeds the control plane WAF inspection limit",
            );
            response.extensions_mut().insert(ProtectionOutcome {
                action: action::BLOCKED_WAF,
                reason: Some(format!(
                    "body larger than {WAF_BODY_LIMIT} bytes was not inspected"
                )),
            });
            return response;
        },
    };

    let request_data = RequestData {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().unwrap_or_default().to_string(),
        headers: parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect(),
        body: (!bytes.is_empty()).then(|| bytes.to_vec()),
        client_ip,
        country_code: None,
        scheme,
        protocol: format!("{:?}", parts.version),
    };
    let verdict = engine.inspect(&request_data);

    let request = Request::from_parts(parts, axum::body::Body::from(bytes));
    let blocking = policy.waf_blocking
        && matches!(verdict.action, WafAction::Block | WafAction::Challenge);
    if blocking {
        tracing::warn!(
            client_ip = %request_data.client_ip,
            path = %request_data.path,
            score = verdict.score,
            rules = ?verdict.matched_rules,
            "control plane WAF blocked a request"
        );
        let mut response = error_response(
            StatusCode::FORBIDDEN,
            "blocked_by_waf",
            &format!(
                "request blocked by the control plane WAF: {}",
                verdict.details
            ),
        );
        response.extensions_mut().insert(ProtectionOutcome {
            action: action::BLOCKED_WAF,
            reason: Some(verdict.details.clone()),
        });
        return response;
    }

    let mut response = next.run(request).await;
    if verdict.action != WafAction::Pass {
        tracing::info!(
            client_ip = %request_data.client_ip,
            path = %request_data.path,
            score = verdict.score,
            rules = ?verdict.matched_rules,
            "control plane WAF match (not enforced)"
        );
        response.extensions_mut().insert(ProtectionOutcome {
            action: action::OBSERVED_WAF,
            reason: Some(format!(
                "{} ({})",
                verdict.details,
                if policy.waf_blocking {
                    "monitor verdict"
                } else {
                    "monitor mode"
                }
            )),
        });
    }
    response
}
