//! Implementation of the `pingwaf.ControlPlane` gRPC service.
//!
//! Authentication on this plane is API-key based for registration and JWT based
//! afterwards: `register_agent` trades a long-lived API key for an agent token,
//! and every other RPC verifies that token before touching the database.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use chrono::{DateTime, Utc};
use pingwaf_proto::control_plane::{
    control_plane_server::ControlPlane as ControlPlaneTrait, AgentHeartbeat,
    BlockedIp, CertEventAck, CertEventEntry, GetSiteConfigRequest, HostSample,
    LogAck, LogEntry, Metric, MetricAck, MetricBatch, RegisterAgentRequest,
    RegisterAgentResponse, RuleBundle, ServerCommand, SiteConfig, SiteStatus,
    SyncRulesRequest, UpstreamHealth,
};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use uuid::Uuid;

use crate::api::keys::{authenticate_api_key, key_allows_agent};
use crate::api::ssl::cert_status;
use crate::auth::jwt::{create_agent_token, verify_agent_token};
use crate::config::ServerConfig;
use crate::es::{
    AccessLogDocument, ElasticsearchClient, SecurityEventDocument,
};
use crate::grpc::cache_status::CacheStatusRegistry;
use crate::grpc::config::{
    build_rule_bundle, build_site_config, from_timestamp,
};
use crate::grpc::registry::{AgentRegistry, COMMAND_CHANNEL_CAPACITY};
use crate::models::{
    access_log, action, agent, agent_blocked_ip, agent_metric, agent_status,
    api_key, certificate_events, host_sample, security_event, site,
    site_certificates,
};

/// Stream type returned by the server-streaming RPCs.
type BoxedStream<T> =
    Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// gRPC status codes are deliberately coarse: agents must never learn whether an
/// API key exists but is wrong, or does not exist at all.
const INVALID_CREDENTIALS: &str = "invalid credentials";

/// Column widths from the migrations; longer values are truncated instead of
/// failing the whole batch.
const MAX_REQUEST_ID: usize = 36;
const MAX_CLIENT_IP: usize = 45;
const MAX_METHOD: usize = 10;
const MAX_HOST: usize = 255;
const MAX_RULE_ID: usize = 100;
const MAX_RULE_NAME: usize = 200;
const MAX_ACTION: usize = 30;
const MAX_COUNTRY: usize = 2;
const MAX_CACHE_STATUS: usize = 20;
const MAX_TLS_VERSION: usize = 10;
const MAX_UPSTREAM: usize = 255;
const MAX_METRIC_NAME: usize = 200;

/// Probe samples are kept for a day: at a 5-second cadence a single agent
/// writes roughly 17k rows a day, so expired rows are pruned while ingesting.
const HOST_SAMPLE_RETENTION_HOURS: i64 = 24;

/// Spacing enforced between persisted probe samples, per agent. The agent
/// probes every few seconds but only one row per interval is worth keeping:
/// the probe panel plots the newest points, and a minute of resolution covers
/// hours of history while cutting the table to a fraction of its raw volume.
const SAMPLE_PERSIST_INTERVAL_SECS: i64 = 60;

/// Last 60-second bucket persisted per agent, so downsampling holds across
/// heartbeat batches rather than restarting with each message. One entry per
/// agent ever seen; agents are few and the value is 8 bytes.
static LAST_PERSISTED_BUCKET: LazyLock<Mutex<HashMap<Uuid, i64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Agent rows offline for longer than this are dropped from the inventory:
/// decommissioned nodes and renamed hosts would otherwise survive as
/// permanently-offline ghosts on the dashboard.
const OFFLINE_AGENT_RETENTION_DAYS: i64 = 7;

/// Epoch seconds of the last retention sweep, so that a busy fleet does not
/// pay for a `DELETE` on every heartbeat.
static LAST_SAMPLE_SWEEP: AtomicI64 = AtomicI64::new(0);

/// Epoch seconds of the last offline-agent sweep, throttled the same way.
static LAST_AGENT_SWEEP: AtomicI64 = AtomicI64::new(0);

/// Epoch seconds of the last metric-retention sweep, throttled the same way.
static LAST_METRIC_SWEEP: AtomicI64 = AtomicI64::new(0);

/// The gRPC control plane service.
pub struct ControlPlaneService {
    db: DatabaseConnection,
    config: Arc<ServerConfig>,
    agents: AgentRegistry,
    /// Optional Elasticsearch shipper. When present, every streamed log entry is
    /// also indexed for full-text search and long-term retention; the
    /// PostgreSQL insert always remains the source of truth for recent logs.
    es: Option<Arc<ElasticsearchClient>>,
    /// Latest per-site edge cache usage, fed from the heartbeat stream and read
    /// by `/api/v1/cache/status`.
    cache_status: CacheStatusRegistry,
}

impl ControlPlaneService {
    pub fn new(
        db: DatabaseConnection,
        config: Arc<ServerConfig>,
        agents: AgentRegistry,
        es: Option<Arc<ElasticsearchClient>>,
        cache_status: CacheStatusRegistry,
    ) -> Self {
        Self {
            db,
            config,
            agents,
            es,
            cache_status,
        }
    }

    /// Verifies an agent token and returns the matching row.
    async fn authorize(&self, token: &str) -> Result<agent::Model, Status> {
        if token.trim().is_empty() {
            return Err(Status::unauthenticated(INVALID_CREDENTIALS));
        }
        let claims = verify_agent_token(token, &self.config.jwt_secret)
            .map_err(|err| Status::unauthenticated(err.to_string()))?;
        let agent_id = claims
            .subject_id()
            .map_err(|_| Status::unauthenticated(INVALID_CREDENTIALS))?;

        agent::Entity::find_by_id(agent_id)
            .one(&self.db)
            .await
            .map_err(db_status)?
            .ok_or_else(|| {
                Status::unauthenticated("agent is no longer registered")
            })
    }

    /// Reads the agent token from the `x-agent-token` request metadata, the
    /// transport-level credential for the client-streaming ship RPCs (their
    /// message bodies carry no token field).
    fn metadata_token<T>(request: &Request<T>) -> String {
        request
            .metadata()
            .get("x-agent-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    /// Sites this agent is allowed to see: its own binding, or every site owned
    /// by the user that issued its API key.
    async fn visible_sites(
        &self,
        row: &agent::Model,
    ) -> Result<Vec<site::Model>, Status> {
        if let Some(site_id) = row.site_id {
            let owned = site::Entity::find_by_id(site_id)
                .one(&self.db)
                .await
                .map_err(db_status)?;
            return Ok(owned.into_iter().collect());
        }

        let Some(key_id) = row.api_key_id else {
            return Ok(Vec::new());
        };
        let key = api_key::Entity::find_by_id(key_id)
            .one(&self.db)
            .await
            .map_err(db_status)?
            .ok_or_else(|| Status::unauthenticated("API key was revoked"))?;

        site::Entity::find()
            .filter(site::Column::UserId.eq(key.user_id))
            .all(&self.db)
            .await
            .map_err(db_status)
    }

    /// Builds the configuration an agent should be running right now.
    async fn site_config_for(
        &self,
        row: &agent::Model,
    ) -> Result<SiteConfig, Status> {
        let sites = self.visible_sites(row).await?;
        let ids: Vec<Uuid> = sites.iter().map(|site| site.id).collect();
        build_site_config(&self.db, Some(&ids))
            .await
            .map_err(db_status)
    }
}

#[tonic::async_trait]
impl ControlPlaneTrait for ControlPlaneService {
    async fn register_agent(
        &self,
        request: Request<RegisterAgentRequest>,
    ) -> Result<Response<RegisterAgentResponse>, Status> {
        let payload = request.into_inner();
        if payload.hostname.trim().is_empty() {
            return Err(Status::invalid_argument("hostname is required"));
        }

        // The API key is only ever presented here; everything afterwards uses the
        // agent token minted below.
        let (key, _owner) = authenticate_api_key(&self.db, &payload.api_key)
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, hostname = %payload.hostname, "agent registration rejected");
                Status::unauthenticated(INVALID_CREDENTIALS)
            })?;
        if !key_allows_agent(&key) {
            return Err(Status::permission_denied(
                "this API key is not allowed to register agents",
            ));
        }

        // Re-registering the same host updates the existing row instead of
        // creating a new one, so a restart does not inflate the inventory. The
        // match ignores the reported IP on purpose: an agent whose address
        // changed (DHCP, migration) must reclaim its row rather than orphan
        // the old one as a permanently-offline ghost.
        let existing = agent::Entity::find()
            .filter(agent::Column::Hostname.eq(payload.hostname.clone()))
            .filter(agent::Column::ApiKeyId.eq(Some(key.id)))
            .one(&self.db)
            .await
            .map_err(db_status)?;

        let now = Utc::now();
        let status = agent_status::ONLINE.to_string();
        // Agents are never auto-bound to a site: a binding narrows
        // `visible_sites` to that single site, so an agent registered while its
        // owner had one site silently stopped receiving every later site — the
        // new site's config push found no bound agent and was skipped, leaving
        // certificates pending with nothing on the edge to issue them. An
        // unbound agent serves all of the owner's sites; a future manual
        // binding API can narrow the scope explicitly.
        let site_id = None;

        let row = match existing {
            Some(row) => {
                let agent_id = row.id;
                let mut active: agent::ActiveModel = row.into();
                active.site_id = Set(site_id);
                active.version = Set(optional(&payload.version));
                active.os_info = Set(optional(&payload.os_info));
                active.cpu_cores = Set(positive_i32(payload.cpu_cores as i64));
                active.memory_bytes =
                    Set(positive_i64(payload.memory_bytes as i64));
                active.status = Set(status);
                active.api_key_id = Set(Some(key.id));
                active.ip_address = Set(payload.ip_address.clone());
                active.last_heartbeat = Set(Some(now));
                active.public_ip = Set(optional(&payload.public_ip));
                active.private_ip = Set(optional(&payload.private_ip));
                let updated =
                    active.update(&self.db).await.map_err(db_status)?;
                tracing::info!(%agent_id, hostname = %payload.hostname, "agent re-registered");
                updated
            },
            None => {
                let agent_id = Uuid::new_v4();
                let created = agent::ActiveModel {
                    id: Set(agent_id),
                    site_id: Set(site_id),
                    hostname: Set(payload.hostname.clone()),
                    ip_address: Set(payload.ip_address.clone()),
                    version: Set(optional(&payload.version)),
                    os_info: Set(optional(&payload.os_info)),
                    cpu_cores: Set(positive_i32(payload.cpu_cores as i64)),
                    memory_bytes: Set(positive_i64(
                        payload.memory_bytes as i64,
                    )),
                    status: Set(status),
                    api_key_id: Set(Some(key.id)),
                    config_hash: Set(None),
                    last_heartbeat: Set(Some(now)),
                    registered_at: Set(now),
                    last_config_sync_at: Set(None),
                    last_policy_sync_at: Set(None),
                    public_ip: Set(optional(&payload.public_ip)),
                    private_ip: Set(optional(&payload.private_ip)),
                }
                .insert(&self.db)
                .await
                .map_err(db_status)?;
                tracing::info!(%agent_id, hostname = %payload.hostname, "agent registered");
                created
            },
        };

        let token = create_agent_token(
            row.id,
            &self.config.jwt_secret,
            self.config.refresh_token_expiration_hours,
        )
        .map_err(|err| Status::internal(err.to_string()))?;

        let initial_config = self.site_config_for(&row).await?;

        Ok(Response::new(RegisterAgentResponse {
            agent_id: row.id.to_string(),
            agent_token: token,
            heartbeat_interval_seconds: self.config.heartbeat_interval_seconds,
            initial_config: Some(initial_config),
        }))
    }

    type HeartbeatStream = BoxedStream<ServerCommand>;

    async fn heartbeat(
        &self,
        request: Request<Streaming<AgentHeartbeat>>,
    ) -> Result<Response<Self::HeartbeatStream>, Status> {
        let mut inbound = request.into_inner();

        // The first message identifies the agent; refusing to open a stream
        // before authentication keeps unauthenticated peers cheap.
        let first = inbound.message().await?.ok_or_else(|| {
            Status::invalid_argument("heartbeat stream closed immediately")
        })?;

        let claims =
            verify_agent_token(&first.agent_token, &self.config.jwt_secret)
                .map_err(|err| Status::unauthenticated(err.to_string()))?;
        let agent_id = claims
            .subject_id()
            .map_err(|_| Status::unauthenticated(INVALID_CREDENTIALS))?;
        if !first.agent_id.is_empty() && first.agent_id != agent_id.to_string()
        {
            return Err(Status::permission_denied(
                "agent_id does not match the presented token",
            ));
        }
        if agent::Entity::find_by_id(agent_id)
            .one(&self.db)
            .await
            .map_err(db_status)?
            .is_none()
        {
            return Err(Status::unauthenticated(
                "agent is no longer registered",
            ));
        }

        let (sender, receiver) =
            mpsc::channel::<ServerCommand>(COMMAND_CHANNEL_CAPACITY);
        let queued = self.agents.connect(agent_id, sender).await;
        for command in queued {
            // The registry owns the sender now, so replay through it.
            self.agents.send_command(&agent_id, command).await;
        }

        let db = self.db.clone();
        let registry = self.agents.clone();
        let cache_status = self.cache_status.clone();
        // The opening message already carries metrics; recording it means a
        // freshly connected edge shows up before its second heartbeat.
        cache_status
            .record_heartbeat(agent_id, &first.site_statuses)
            .await;
        tokio::spawn(async move {
            persist_heartbeat(&db, agent_id, &first).await;
            persist_host_samples(&db, agent_id, &first.host_samples).await;
            persist_blocked_ips(&db, agent_id, &first.blocked_ips).await;
            record_upstream_health(&db, agent_id, &first.upstream_health).await;
            while let Some(message) = match inbound.message().await {
                Ok(Some(message)) => Some(message),
                Ok(None) => None,
                Err(err) => {
                    tracing::debug!(%agent_id, error = %err, "heartbeat stream error");
                    None
                },
            } {
                cache_status
                    .record_heartbeat(agent_id, &message.site_statuses)
                    .await;
                persist_heartbeat(&db, agent_id, &message).await;
                persist_host_samples(&db, agent_id, &message.host_samples)
                    .await;
                persist_blocked_ips(&db, agent_id, &message.blocked_ips).await;
                record_upstream_health(&db, agent_id, &message.upstream_health)
                    .await;
            }
            mark_offline(&db, agent_id).await;
            registry.disconnect(&agent_id).await;
            tracing::info!(%agent_id, "agent heartbeat stream ended");
        });

        tracing::info!(%agent_id, "agent heartbeat stream opened");
        Ok(Response::new(
            Box::pin(ReceiverStream::new(receiver).map(Ok))
                as Self::HeartbeatStream,
        ))
    }

    type SyncRulesStream = BoxedStream<RuleBundle>;

    async fn sync_rules(
        &self,
        request: Request<SyncRulesRequest>,
    ) -> Result<Response<Self::SyncRulesStream>, Status> {
        let payload = request.into_inner();
        let row = self.authorize(&payload.agent_token).await?;

        let sites = self.visible_sites(&row).await?;
        let requested = payload.site_id.trim();
        let selected: Vec<site::Model> = if requested.is_empty() {
            sites
        } else {
            let id = Uuid::parse_str(requested).map_err(|_| {
                Status::invalid_argument("site_id is not a UUID")
            })?;
            if !sites.iter().any(|site| site.id == id) {
                return Err(Status::permission_denied(
                    "agent is not allowed to sync this site",
                ));
            }
            sites.into_iter().filter(|site| site.id == id).collect()
        };

        let current_hash = payload.current_config_hash.trim().to_string();
        let mut bundles = Vec::with_capacity(selected.len());
        let mut skipped = 0usize;
        for site_row in &selected {
            match build_rule_bundle(&self.db, site_row).await {
                Ok(bundle) => {
                    // Delta sync: the agent already runs this exact configuration.
                    if !current_hash.is_empty()
                        && bundle.config_hash == current_hash
                    {
                        skipped += 1;
                        continue;
                    }
                    bundles.push(Ok(bundle));
                },
                Err(err) => {
                    tracing::error!(site_id = %site_row.id, error = %err, "could not build rule bundle");
                    crate::notify::emit(crate::notify::AlertEvent {
                        event_type:
                            crate::models::event_type::CONFIG_SYNC_FAILED
                                .to_string(),
                        severity: crate::models::severity::CRITICAL,
                        title: format!(
                            "Configuration sync failed for site {}",
                            site_row.domain
                        ),
                        message: format!(
                            "The rule bundle for site '{}' could not be \
                             built; agents keep running their last synced \
                             configuration. Error: {err}",
                            site_row.domain
                        ),
                        details: Some(serde_json::json!({
                            "site_id": site_row.id,
                            "domain": site_row.domain,
                            "agent_id": row.id,
                            "error": err.to_string(),
                        })),
                        dedup_key: Some(site_row.id.to_string()),
                    })
                    .await;
                    bundles.push(Err(Status::internal(format!(
                        "could not build the rule bundle for site {}: {err}",
                        site_row.id
                    ))));
                },
            }
        }

        tracing::info!(
            agent_id = %row.id,
            sites = selected.len(),
            delivered = bundles.len(),
            skipped,
            "rule sync served"
        );

        // Record the hash the agent claims to run so the dashboard can show drift.
        if !current_hash.is_empty() {
            let mut active: agent::ActiveModel = row.into();
            active.config_hash = Set(Some(current_hash));
            active.last_heartbeat = Set(Some(Utc::now()));
            if let Err(err) = active.update(&self.db).await {
                tracing::warn!(error = %err, "could not persist agent config hash");
            }
        }

        Ok(Response::new(
            Box::pin(tokio_stream::iter(bundles)) as Self::SyncRulesStream
        ))
    }

    async fn ship_logs(
        &self,
        request: Request<Streaming<LogEntry>>,
    ) -> Result<Response<LogAck>, Status> {
        let agent = self.authorize(&Self::metadata_token(&request)).await?;
        let authenticated_id = agent.id;
        let mut inbound = request.into_inner();
        let batch_size = self.config.log_batch_size.max(1);

        let mut received: u64 = 0;
        let mut access_batch: Vec<access_log::ActiveModel> =
            Vec::with_capacity(batch_size);
        let mut event_batch: Vec<security_event::ActiveModel> =
            Vec::with_capacity(batch_size);

        loop {
            let message = match inbound.message().await {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(err) => {
                    tracing::warn!(error = %err, received, "log stream aborted");
                    return Ok(Response::new(LogAck {
                        received_count: received,
                        success: false,
                        error_message: err.to_string(),
                    }));
                },
            };
            if !message.agent_id.is_empty()
                && message.agent_id != authenticated_id.to_string()
            {
                // A foreign stamp is dropped rather than persisted under the
                // authenticated identity; the rest of the batch continues.
                tracing::warn!(
                    claimed = %message.agent_id,
                    agent_id = %authenticated_id,
                    "log entry stamped with a foreign agent_id"
                );
                continue;
            }
            received += 1;

            let site_id = parse_optional_uuid(&message.site_id);
            let agent_id = parse_optional_uuid(&message.agent_id);
            let timestamp = from_timestamp(message.timestamp.as_ref());
            let waf_event = is_waf_event(&message);

            // WAF-decision entries are routed to `security_events` only: the
            // agent always emits a second, access-shaped entry for the same
            // request (at deny time or response time), so writing both would
            // duplicate every blocked or monitored request in `access_logs`.
            if !waf_event {
                access_batch.push(access_log_row(
                    &message, site_id, agent_id, timestamp,
                ));
            }
            if let Some(event) =
                security_event_row(&message, site_id, agent_id, timestamp)
            {
                event_batch.push(event);
            }

            // Mirror the entry into Elasticsearch for full-text search and long
            // retention. Both calls are non-blocking `try_send`s, so a slow or
            // down ES cluster can never apply back-pressure to the agent stream.
            if let Some(es) = &self.es {
                if !waf_event {
                    es.index_access_log(access_log_document(
                        es, &message, timestamp,
                    ));
                }
                if let Some(event) =
                    security_event_document(es, &message, timestamp)
                {
                    es.index_security_event(event);
                }
            }

            if access_batch.len() >= batch_size {
                flush(&self.db, &mut access_batch, &mut event_batch).await?;
            }
        }

        flush(&self.db, &mut access_batch, &mut event_batch).await?;

        tracing::debug!(received, "log batch persisted");
        Ok(Response::new(LogAck {
            received_count: received,
            success: true,
            error_message: String::new(),
        }))
    }

    async fn ship_cert_events(
        &self,
        request: Request<Streaming<CertEventEntry>>,
    ) -> Result<Response<CertEventAck>, Status> {
        let agent = self.authorize(&Self::metadata_token(&request)).await?;
        let authenticated_id = agent.id;
        let mut inbound = request.into_inner();
        let batch_size = self.config.log_batch_size.max(1);
        let mut received: u64 = 0;
        let mut batch: Vec<certificate_events::ActiveModel> =
            Vec::with_capacity(batch_size);

        loop {
            let message = match inbound.message().await {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        received,
                        "certificate event stream aborted"
                    );
                    return Ok(Response::new(CertEventAck {
                        received_count: received,
                        success: false,
                        error_message: err.to_string(),
                    }));
                },
            };
            if !message.agent_id.is_empty()
                && message.agent_id != authenticated_id.to_string()
            {
                tracing::warn!(
                    claimed = %message.agent_id,
                    agent_id = %authenticated_id,
                    "certificate event stamped with a foreign agent_id"
                );
                continue;
            }
            received += 1;
            // ACME failures surface as raw ERROR-level events: raise an
            // alert so a renewal that keeps failing is not discovered
            // through an expired certificate.
            if message.level.eq_ignore_ascii_case("error") {
                crate::notify::emit(crate::notify::AlertEvent {
                    event_type: crate::models::event_type::CERT_RENEWAL_FAILED
                        .to_string(),
                    severity: crate::models::severity::CRITICAL,
                    title: "Certificate renewal failed".to_string(),
                    message: if message.message.is_empty() {
                        "An ACME issuance or renewal attempt failed on the \
                         edge; see the certificate events for details."
                            .to_string()
                    } else {
                        message.message.clone()
                    },
                    details: Some(serde_json::json!({
                        "agent_id": message.agent_id,
                        "site_id": message.site_id,
                        "certificate_id": message.certificate_id,
                        "target": message.target,
                    })),
                    dedup_key: Some(format!(
                        "{}:{}",
                        message.site_id, message.target
                    )),
                })
                .await;
            }
            batch.push(certificate_events::ActiveModel {
                id: Set(Uuid::new_v4()),
                certificate_id: Set(parse_optional_uuid(
                    &message.certificate_id,
                )),
                site_id: Set(parse_optional_uuid(&message.site_id)),
                event_type: Set(if message.event_type.is_empty() {
                    "acme_raw".to_string()
                } else {
                    message.event_type.chars().take(30).collect()
                }),
                message: Set(message.message),
                details: Set(Some(serde_json::json!({
                    "level": message.level,
                    "target": message.target,
                    "agent_id": message.agent_id,
                }))),
                created_at: Set(from_timestamp(message.timestamp.as_ref())),
            });
            if batch.len() >= batch_size {
                flush_cert_events(&self.db, &mut batch).await?;
            }
        }

        flush_cert_events(&self.db, &mut batch).await?;
        tracing::debug!(received, "certificate events persisted");
        Ok(Response::new(CertEventAck {
            received_count: received,
            success: true,
            error_message: String::new(),
        }))
    }

    async fn ship_metrics(
        &self,
        request: Request<Streaming<MetricBatch>>,
    ) -> Result<Response<MetricAck>, Status> {
        let agent = self.authorize(&Self::metadata_token(&request)).await?;
        let authenticated_id = agent.id;
        let mut inbound = request.into_inner();
        let batch_size = self.config.log_batch_size.max(1);

        let mut received: u64 = 0;
        let mut metrics: u64 = 0;
        let mut rows: Vec<agent_metric::ActiveModel> =
            Vec::with_capacity(batch_size);

        while let Some(batch) = inbound.message().await? {
            received += 1;
            metrics += batch.metrics.len() as u64;
            let Some(agent_id) = parse_optional_uuid(&batch.agent_id) else {
                continue;
            };
            if agent_id != authenticated_id {
                tracing::warn!(
                    claimed = %batch.agent_id,
                    agent_id = %authenticated_id,
                    "metric batch stamped with a foreign agent_id"
                );
                continue;
            }

            // Metrics double as liveness proof: touching the heartbeat keeps an
            // agent that only ships metrics from being marked offline, and the
            // rows-affected check drops batches for unknown agents before they
            // reach the foreign key. Server time, not the agent-reported
            // timestamp: liveness thresholds compare against Utc::now(), so
            // trusting a skewed client clock would mark healthy agents offline.
            let known = agent::Entity::update_many()
                .col_expr(
                    agent::Column::LastHeartbeat,
                    sea_orm::sea_query::Expr::value(Utc::now()),
                )
                .filter(agent::Column::Id.eq(agent_id))
                .exec(&self.db)
                .await
                .map_err(db_status)?;
            if known.rows_affected == 0 {
                continue;
            }

            let now = Utc::now();
            let reported = from_timestamp(batch.timestamp.as_ref());
            let retention =
                chrono::Duration::days(self.config.metric_retention_days);
            let recorded_at = if reported <= now && reported > now - retention {
                reported
            } else {
                now
            };

            for metric in &batch.metrics {
                rows.push(metric_row(agent_id, metric, recorded_at));
            }
            if rows.len() >= batch_size {
                flush_metrics(&self.db, &mut rows).await?;
            }
        }

        flush_metrics(&self.db, &mut rows).await?;
        sweep_agent_metrics(&self.db, self.config.metric_retention_days).await;

        tracing::trace!(batches = received, metrics, "metrics persisted");
        Ok(Response::new(MetricAck {
            received_count: metrics,
            success: true,
        }))
    }

    async fn get_site_config(
        &self,
        request: Request<GetSiteConfigRequest>,
    ) -> Result<Response<SiteConfig>, Status> {
        let payload = request.into_inner();
        let row = self.authorize(&payload.agent_token).await?;

        let requested = payload.site_id.trim();
        let config = if requested.is_empty() {
            self.site_config_for(&row).await?
        } else {
            let id = Uuid::parse_str(requested).map_err(|_| {
                Status::invalid_argument("site_id is not a UUID")
            })?;
            let visible = self.visible_sites(&row).await?;
            if !visible.iter().any(|site| site.id == id) {
                return Err(Status::permission_denied(
                    "agent is not allowed to read this site",
                ));
            }
            build_site_config(&self.db, Some(&[id]))
                .await
                .map_err(db_status)?
        };

        tracing::debug!(
            agent_id = %row.id,
            sites = config.sites.len(),
            config_hash = %config.config_hash,
            "site configuration served"
        );

        // The caller echoed no hash here, but recording the served one lets the
        // dashboard detect drift on the next heartbeat.
        let mut active: agent::ActiveModel = row.into();
        active.config_hash = Set(Some(config.config_hash.clone()));
        active.last_heartbeat = Set(Some(Utc::now()));
        if let Err(err) = active.update(&self.db).await {
            tracing::warn!(error = %err, "could not persist served config hash");
        }

        Ok(Response::new(config))
    }
}

/// Feeds the per-upstream health report of one heartbeat into the
/// notification monitor. Absent on older agents — an empty report is a
/// no-op.
async fn record_upstream_health(
    db: &DatabaseConnection,
    agent_id: Uuid,
    health: &[UpstreamHealth],
) {
    if health.is_empty() {
        return;
    }
    let reports: Vec<_> = health
        .iter()
        .map(|entry| crate::notify::upstream_monitor::UpstreamReport {
            upstream_name: entry.upstream_name.clone(),
            healthy_backends: entry.healthy_backends,
            total_backends: entry.total_backends,
            unhealthy_backends: entry.unhealthy_backends.clone(),
        })
        .collect();
    crate::notify::upstream_monitor::record_heartbeat(db, agent_id, &reports)
        .await;
}

/// Persists the runtime counters of one heartbeat.
async fn persist_heartbeat(
    db: &DatabaseConnection,
    agent_id: Uuid,
    message: &AgentHeartbeat,
) {
    // Server time, not the agent's clock: liveness thresholds compare
    // `last_heartbeat` against Utc::now(), so trusting the reported timestamp
    // would let a skewed client clock mark healthy agents offline.
    let health = agent_status::from_proto_health(message.health);

    // Rule-cache disk health: absent on older agents (treat as healthy).
    // A false means the edge could not load any usable snapshot and runs on
    // empty rules until the next sync — surface it loudly, it is exactly the
    // fail-open state an operator must know about. A non-empty reason with
    // healthy=true is a backup restore worth a line, not an alarm.
    if let Some(cache_healthy) = message.cache_persist_healthy {
        if !cache_healthy {
            tracing::warn!(
                %agent_id,
                reason = %message.cache_status_reason,
                "agent rule cache is unhealthy; running on empty rules until the next sync"
            );
        } else if !message.cache_status_reason.is_empty() {
            tracing::info!(
                %agent_id,
                reason = %message.cache_status_reason,
                "agent restored its rule cache from backup"
            );
        }
    }

    let mut active = agent::ActiveModel {
        id: Set(agent_id),
        ..Default::default()
    };
    active.status = Set(health.to_string());
    active.last_heartbeat = Set(Some(Utc::now()));
    if !message.config_hash.trim().is_empty() {
        active.config_hash = Set(Some(message.config_hash.clone()));
    }
    if message.memory_usage_bytes > 0 {
        active.memory_bytes = Set(Some(message.memory_usage_bytes as i64));
    }
    // Sync timestamps come from the agent's own clock, but they only feed
    // the dashboard's "last synced" display, so a skewed clock cannot make
    // a healthy agent look offline.
    if let Some(ts) = message.last_config_sync_at {
        if let Some(at) =
            DateTime::from_timestamp(ts.seconds, ts.nanos.max(0) as u32)
        {
            active.last_config_sync_at = Set(Some(at));
        }
    }
    if let Some(ts) = message.last_policy_sync_at {
        if let Some(at) =
            DateTime::from_timestamp(ts.seconds, ts.nanos.max(0) as u32)
        {
            active.last_policy_sync_at = Set(Some(at));
        }
    }

    if let Err(err) = active.update(db).await {
        tracing::warn!(%agent_id, error = %err, "could not persist heartbeat");
    }

    persist_site_certificates(db, &message.site_statuses).await;

    sweep_stale_pending_certificates(db).await;

    sweep_offline_agents(db).await;
}

/// Writes the per-site certificate state reported by the edge back onto its
/// certificate rows.
///
/// Only rows without a PEM are touched: those are the ACME-managed ones, whose
/// issuance happens entirely on the edge — the control plane never sees the
/// certificate, so without this write-back the row would read "pending" with no
/// expiry forever, even after the certificate went live.
async fn persist_site_certificates(
    db: &DatabaseConnection,
    statuses: &[SiteStatus],
) {
    let now = Utc::now();
    for status in statuses {
        let row_status = match status.ssl_status.as_str() {
            "valid" | "expiring_soon" => cert_status::ACTIVE,
            "expired" => cert_status::EXPIRED,
            // "none" or empty: nothing has been issued yet, and an unreadable
            // site id cannot be attributed to a row.
            _ => continue,
        };
        let Ok(site_id) = Uuid::parse_str(&status.site_id) else {
            continue;
        };
        let Some(expires_at) = status
            .ssl_expires_at
            .and_then(|ts| DateTime::from_timestamp(ts.seconds, 0))
        else {
            continue;
        };

        // The guard keeps a steady fleet from writing the same values every
        // heartbeat: only rows whose status or expiry actually change match.
        // A live certificate also clears whatever failure the stale-pending
        // sweep recorded for the order that produced it.
        let result = site_certificates::Entity::update_many()
            .col_expr(
                site_certificates::Column::Status,
                Expr::value(row_status),
            )
            .col_expr(
                site_certificates::Column::ExpiresAt,
                Expr::value(expires_at),
            )
            .col_expr(
                site_certificates::Column::FailureReason,
                Expr::value(Option::<String>::None),
            )
            .col_expr(site_certificates::Column::UpdatedAt, Expr::value(now))
            .filter(site_certificates::Column::SiteId.eq(site_id))
            .filter(site_certificates::Column::CertPem.is_null())
            .filter(
                Condition::any()
                    .add(site_certificates::Column::Status.ne(row_status))
                    .add(site_certificates::Column::ExpiresAt.is_null())
                    .add(site_certificates::Column::ExpiresAt.ne(expires_at)),
            )
            .exec(db)
            .await;
        match result {
            Ok(result) if result.rows_affected > 0 => {
                tracing::info!(
                    %site_id,
                    status = row_status,
                    %expires_at,
                    "recorded edge certificate state"
                );
                notify_certificate_state(
                    site_id,
                    row_status,
                    expires_at,
                    now,
                    crate::notify::global()
                        .map(|manager| manager.settings().cert_expiry_warn_days)
                        .unwrap_or(30),
                )
                .await;
            },
            Ok(_) => {},
            Err(err) => {
                tracing::warn!(
                    %site_id,
                    error = %err,
                    "could not persist certificate state"
                );
            },
        }
    }
}

/// How long an ACME order may sit in `pending` with no sign of life before
/// the control plane gives up on it and marks the row `failed`.
const PENDING_CERTIFICATE_GRACE: chrono::Duration =
    chrono::Duration::minutes(30);

/// Marks ACME certificate rows `failed` when their order has been pending
/// longer than [`PENDING_CERTIFICATE_GRACE`], recording why.
///
/// Issuance runs entirely on the edge, so a wedged order — the CA
/// unreachable, a stalled DNS provider, a challenge that never validates —
/// otherwise leaves the row in `pending` forever and the dashboard spins
/// with no explanation. Only ACME rows (no stored PEM, an ACME email set)
/// are swept: an uploaded certificate can be marked pending by hand and is
/// not the control plane's to fail. `updated_at` is the last time anyone
/// touched the row — the request that (re)armed the order — which is what
/// the grace window is measured from.
async fn sweep_stale_pending_certificates(db: &DatabaseConnection) {
    let now = Utc::now();
    let cutoff = now - PENDING_CERTIFICATE_GRACE;
    let stale = match site_certificates::Entity::find()
        .filter(site_certificates::Column::Status.eq(cert_status::PENDING))
        .filter(site_certificates::Column::CertPem.is_null())
        .filter(site_certificates::Column::AcmeEmail.is_not_null())
        .filter(site_certificates::Column::UpdatedAt.lt(cutoff))
        .all(db)
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "could not sweep stale pending certificates"
            );
            return;
        },
    };

    for row in stale {
        let reason = format!(
            "ACME issuance did not finish within {} minutes of the last \
             request. The edge may be offline, the CA or DNS provider may \
             be unreachable, or the challenge never validated — see the \
             certificate events for the raw ACME log.",
            PENDING_CERTIFICATE_GRACE.num_minutes(),
        );
        let cert_id = row.id;
        let site_id = row.site_id;
        let mut active: site_certificates::ActiveModel = row.into();
        active.status = Set(cert_status::FAILED.to_string());
        active.failure_reason = Set(Some(reason.clone()));
        active.updated_at = Set(now);
        if let Err(err) = active.update(db).await {
            tracing::warn!(
                %cert_id,
                error = %err,
                "could not fail stale pending certificate"
            );
            continue;
        }
        tracing::info!(
            %cert_id,
            %site_id,
            "stale pending certificate marked failed"
        );
        // Best-effort, like every certificate event: recording must never
        // break the sweep.
        let event = certificate_events::ActiveModel {
            id: Set(Uuid::new_v4()),
            certificate_id: Set(Some(cert_id)),
            site_id: Set(Some(site_id)),
            event_type: Set("issuance_failed".to_string()),
            message: Set(reason),
            details: Set(None),
            created_at: Set(now),
        };
        if let Err(err) = event.insert(db).await {
            tracing::warn!(%err, "failed to write certificate event");
        }
    }
}

/// Raises certificate alerts when the edge reports a state transition:
/// expiry inside the configurable warning window, or a certificate that
/// has expired. Repeats are suppressed by the notification dedup.
async fn notify_certificate_state(
    site_id: Uuid,
    status: &str,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    warn_days: u32,
) {
    if status == cert_status::EXPIRED {
        crate::notify::emit(crate::notify::AlertEvent {
            event_type: crate::models::event_type::CERT_EXPIRED.to_string(),
            severity: crate::models::severity::CRITICAL,
            title: format!("Certificate for {site_id} has expired"),
            message: format!(
                "The certificate of site {site_id} expired at {expires_at}. \
                 Browsers will refuse connections until it is renewed."
            ),
            details: Some(serde_json::json!({
                "site_id": site_id,
                "expires_at": expires_at.to_rfc3339(),
            })),
            // Same shape as the hourly scanner's key, so a heartbeat and a
            // sweep describing the same expiry suppress each other.
            dedup_key: Some(format!("{site_id}:{}", expires_at.date_naive())),
        })
        .await;
        return;
    }

    let warn_from = now + chrono::Duration::days(i64::from(warn_days));
    if status == cert_status::ACTIVE && expires_at <= warn_from {
        let days_left = (expires_at - now).num_days().max(0);
        crate::notify::emit(crate::notify::AlertEvent {
            event_type: crate::models::event_type::CERT_EXPIRING.to_string(),
            severity: crate::models::severity::WARNING,
            title: format!(
                "Certificate for {site_id} expires in {days_left} day(s)"
            ),
            message: format!(
                "The certificate of site {site_id} expires on {expires_at} \
                 ({days_left} day(s) left). Check that automatic renewal is \
                 succeeding; a failed renewal leads to an outage."
            ),
            details: Some(serde_json::json!({
                "site_id": site_id,
                "expires_at": expires_at.to_rfc3339(),
                "days_left": days_left,
            })),
            // One alert per site and expiry date, not per heartbeat.
            dedup_key: Some(format!("{site_id}:{}", expires_at.date_naive())),
        })
        .await;
    }
}

/// Persists the probe samples carried by one heartbeat and prunes expired rows.
///
/// The agent samples every few seconds and buffers locally, so a single message
/// normally carries several points; only the first sample of each
/// [`SAMPLE_PERSIST_INTERVAL_SECS`] bucket survives (see the constant's docs).
async fn persist_host_samples(
    db: &DatabaseConnection,
    agent_id: Uuid,
    samples: &[HostSample],
) {
    if samples.is_empty() {
        return;
    }
    let now = Utc::now();
    let kept: Vec<&HostSample> = {
        let mut last_buckets = LAST_PERSISTED_BUCKET
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        samples
            .iter()
            .filter(|sample| {
                let at = sample_time(sample.ts_millis, now);
                let bucket = at.timestamp() / SAMPLE_PERSIST_INTERVAL_SECS;
                if last_buckets.get(&agent_id) == Some(&bucket) {
                    return false;
                }
                last_buckets.insert(agent_id, bucket);
                true
            })
            .collect()
    };
    let latest = kept.last().copied();
    let rows: Vec<host_sample::ActiveModel> = kept
        .into_iter()
        .map(|sample| host_sample::ActiveModel {
            agent_id: Set(agent_id),
            sampled_at: Set(sample_time(sample.ts_millis, now)),
            cpu_usage_percent: Set(Some(sample.cpu_usage_percent)),
            load1: Set(Some(sample.load1)),
            load5: Set(Some(sample.load5)),
            load15: Set(Some(sample.load15)),
            memory_total_bytes: Set(sample_i64(sample.memory_total_bytes)),
            memory_used_bytes: Set(sample_i64(sample.memory_used_bytes)),
            memory_available_bytes: Set(sample_i64(
                sample.memory_available_bytes,
            )),
            swap_total_bytes: Set(sample_i64(sample.swap_total_bytes)),
            swap_used_bytes: Set(sample_i64(sample.swap_used_bytes)),
            disk_total_bytes: Set(sample_i64(sample.disk_total_bytes)),
            disk_used_bytes: Set(sample_i64(sample.disk_used_bytes)),
            net_rx_bytes: Set(sample_i64(sample.net_rx_bytes)),
            net_tx_bytes: Set(sample_i64(sample.net_tx_bytes)),
            disk_read_bytes: Set(sample_i64(sample.disk_read_bytes)),
            disk_write_bytes: Set(sample_i64(sample.disk_write_bytes)),
            process_count: Set(i32::try_from(sample.process_count).ok()),
            tcp_connections: Set(i32::try_from(sample.tcp_connections).ok()),
            uptime_secs: Set(sample_i64(sample.uptime_secs)),
            created_at: Set(now),
            ..Default::default()
        })
        .collect();

    if rows.is_empty() {
        // Every sample landed in a bucket that already has its row.
        return;
    }

    if let Err(err) = host_sample::Entity::insert_many(rows).exec(db).await {
        tracing::warn!(%agent_id, error = %err, "could not persist host samples");
        return;
    }

    // Threshold check on the newest sample of the batch.
    if let Some(sample) = latest {
        check_agent_resources(agent_id, sample).await;
    }

    sweep_host_samples(db).await;
}

/// Consecutive over-threshold samples per agent and metric, so a single busy
/// moment does not page anyone. Two samples in a row must breach.
static RESOURCE_STRIKES: LazyLock<Mutex<HashMap<(Uuid, &'static str), u8>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Evaluates one agent sample against the notification thresholds and raises
/// `agent.resource` alerts for metrics that stayed over for two samples.
async fn check_agent_resources(agent_id: Uuid, sample: &HostSample) {
    let Some(manager) = crate::notify::global() else {
        return;
    };
    let settings = manager.settings();

    let memory_percent = if sample.memory_total_bytes > 0 {
        (sample.memory_used_bytes as f32 / sample.memory_total_bytes as f32)
            * 100.0
    } else {
        0.0
    };
    let disk_percent = if sample.disk_total_bytes > 0 {
        (sample.disk_used_bytes as f32 / sample.disk_total_bytes as f32) * 100.0
    } else {
        0.0
    };
    let metrics: [(&'static str, f32, u8); 3] = [
        ("cpu", sample.cpu_usage_percent as f32, settings.cpu_percent),
        ("memory", memory_percent, settings.memory_percent),
        ("disk", disk_percent, settings.disk_percent),
    ];

    for (metric, value, threshold) in metrics {
        let key = (agent_id, metric);
        let over = value >= f32::from(threshold);
        let strikes = {
            let mut map =
                RESOURCE_STRIKES.lock().unwrap_or_else(|e| e.into_inner());
            let entry = map.entry(key).or_insert(0);
            if over {
                *entry = entry.saturating_add(1);
            } else {
                *entry = 0;
            }
            *entry
        };
        if over && strikes == 2 {
            let severity = if value >= f32::from(threshold) + 5.0 {
                crate::models::severity::CRITICAL
            } else {
                crate::models::severity::WARNING
            };
            manager
                .dispatch(crate::notify::AlertEvent {
                    event_type: crate::models::event_type::AGENT_RESOURCE
                        .to_string(),
                    severity,
                    title: format!("Agent {agent_id}: {metric} usage high"),
                    message: format!(
                        "Agent {agent_id} reports {metric} usage at \
                         {value:.1}% (threshold {threshold}%)."
                    ),
                    details: Some(serde_json::json!({
                        "agent_id": agent_id,
                        "metric": metric,
                        "value_percent": format!("{value:.1}"),
                        "threshold_percent": threshold,
                    })),
                    dedup_key: Some(format!("{agent_id}:{metric}")),
                })
                .await;
        }
    }
}

/// Ages out samples past the retention window, at most once an hour.
async fn sweep_host_samples(db: &DatabaseConnection) {
    let now = Utc::now();
    let previous = LAST_SAMPLE_SWEEP.swap(now.timestamp(), Ordering::Relaxed);
    let swept_recently = DateTime::from_timestamp(previous, 0)
        .is_some_and(|at| at > now - chrono::Duration::hours(1));
    if swept_recently {
        return;
    }

    let cutoff = now - chrono::Duration::hours(HOST_SAMPLE_RETENTION_HOURS);
    match host_sample::Entity::delete_many()
        .filter(host_sample::Column::SampledAt.lt(cutoff))
        .exec(db)
        .await
    {
        Ok(result) if result.rows_affected > 0 => {
            tracing::info!(
                deleted = result.rows_affected,
                %cutoff,
                "pruned expired host samples"
            );
        },
        Ok(_) => {},
        Err(err) => {
            tracing::warn!(error = %err, "could not prune host samples");
        },
    }
}

/// Reconciles the control plane's mirror of one agent's dynamic IP blocks.
///
/// The heartbeat carries the agent's *complete* list, so the ingest replaces
/// rather than appends: rows the agent no longer reports are deleted, known
/// keys are refreshed in place, and new keys inserted. Entries whose site id
/// does not parse as a UUID are skipped — the edge only blocks synced sites.
async fn persist_blocked_ips(
    db: &DatabaseConnection,
    agent_id: Uuid,
    blocked_ips: &[BlockedIp],
) {
    use std::collections::HashSet;

    let now = Utc::now();
    let mut reported: HashSet<(Uuid, String)> = HashSet::new();
    let mut rows: Vec<agent_blocked_ip::ActiveModel> = Vec::new();
    for entry in blocked_ips {
        let Ok(site_id) = Uuid::parse_str(entry.site_id.trim()) else {
            continue;
        };
        if site_id.is_nil()
            || entry.ip.trim().is_empty()
            || !reported.insert((site_id, entry.ip.clone()))
        {
            continue;
        }
        rows.push(agent_blocked_ip::ActiveModel {
            agent_id: Set(agent_id),
            site_id: Set(site_id),
            ip: Set(entry.ip.trim().chars().take(MAX_CLIENT_IP).collect()),
            reason: Set(Some(
                entry.reason.trim().chars().take(500).collect::<String>(),
            )),
            blocked_at: Set(from_timestamp(entry.blocked_at.as_ref())),
            expires_at: Set(entry
                .expires_at
                .as_ref()
                .map(|exp| from_timestamp(Some(exp)))),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        });
    }

    let existing = match agent_blocked_ip::Entity::find()
        .filter(agent_blocked_ip::Column::AgentId.eq(agent_id))
        .all(db)
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(%agent_id, error = %err, "could not load blocked IPs");
            return;
        },
    };

    let stale: Vec<i64> = existing
        .iter()
        .filter(|row| !reported.contains(&(row.site_id, row.ip.clone())))
        .map(|row| row.id)
        .collect();
    if !stale.is_empty() {
        if let Err(err) = agent_blocked_ip::Entity::delete_many()
            .filter(agent_blocked_ip::Column::Id.is_in(stale))
            .exec(db)
            .await
        {
            tracing::warn!(%agent_id, error = %err, "could not prune blocked IPs");
        }
    }

    if rows.is_empty() {
        return;
    }
    if let Err(err) = agent_blocked_ip::Entity::insert_many(rows)
        .on_conflict(
            sea_orm::sea_query::OnConflict::columns([
                agent_blocked_ip::Column::AgentId,
                agent_blocked_ip::Column::SiteId,
                agent_blocked_ip::Column::Ip,
            ])
            .update_columns([
                agent_blocked_ip::Column::Reason,
                agent_blocked_ip::Column::BlockedAt,
                agent_blocked_ip::Column::ExpiresAt,
                agent_blocked_ip::Column::UpdatedAt,
            ])
            .to_owned(),
        )
        .exec(db)
        .await
    {
        tracing::warn!(%agent_id, error = %err, "could not persist blocked IPs");
    }
}

/// Builds one `agent_metrics` row from a streamed metric point.
fn metric_row(
    agent_id: Uuid,
    metric: &Metric,
    recorded_at: DateTime<Utc>,
) -> agent_metric::ActiveModel {
    agent_metric::ActiveModel {
        agent_id: Set(agent_id),
        name: Set(metric.name.trim().chars().take(MAX_METRIC_NAME).collect()),
        labels: Set(serde_json::Value::Object(
            metric
                .labels
                .iter()
                .map(|(key, value)| {
                    (key.clone(), serde_json::Value::String(value.clone()))
                })
                .collect(),
        )),
        value: Set(metric.value),
        metric_type: Set(metric.r#type),
        recorded_at: Set(recorded_at),
        created_at: Set(Utc::now()),
        ..Default::default()
    }
}

/// Writes the accumulated metric rows.
async fn flush_metrics(
    db: &DatabaseConnection,
    rows: &mut Vec<agent_metric::ActiveModel>,
) -> Result<(), Status> {
    if rows.is_empty() {
        return Ok(());
    }
    let rows = std::mem::take(rows);
    if let Err(err) = agent_metric::Entity::insert_many(rows).exec(db).await {
        tracing::error!(error = %err, "failed to persist agent metrics");
        return Err(db_status(err));
    }
    Ok(())
}

/// Ages out metric points past the retention window, at most once an hour.
async fn sweep_agent_metrics(db: &DatabaseConnection, retention_days: i64) {
    let now = Utc::now();
    let previous = LAST_METRIC_SWEEP.swap(now.timestamp(), Ordering::Relaxed);
    let swept_recently = DateTime::from_timestamp(previous, 0)
        .is_some_and(|at| at > now - chrono::Duration::hours(1));
    if swept_recently {
        return;
    }

    let cutoff = now - chrono::Duration::days(retention_days);
    match agent_metric::Entity::delete_many()
        .filter(agent_metric::Column::RecordedAt.lt(cutoff))
        .exec(db)
        .await
    {
        Ok(result) if result.rows_affected > 0 => {
            tracing::info!(
                deleted = result.rows_affected,
                %cutoff,
                "pruned expired agent metrics"
            );
        },
        Ok(_) => {},
        Err(err) => {
            tracing::warn!(error = %err, "could not prune agent metrics");
        },
    }
}

/// Deletes agent rows that have been offline beyond the retention window, at
/// most once an hour. Child rows are safe: host samples cascade, log rows
/// keep their agent_id only as a nullable reference.
async fn sweep_offline_agents(db: &DatabaseConnection) {
    let now = Utc::now();
    let previous = LAST_AGENT_SWEEP.swap(now.timestamp(), Ordering::Relaxed);
    let swept_recently = DateTime::from_timestamp(previous, 0)
        .is_some_and(|at| at > now - chrono::Duration::hours(1));
    if swept_recently {
        return;
    }

    let cutoff = now - chrono::Duration::days(OFFLINE_AGENT_RETENTION_DAYS);
    match agent::Entity::delete_many()
        .filter(agent::Column::Status.eq(agent_status::OFFLINE.to_string()))
        .filter(agent::Column::LastHeartbeat.lt(cutoff))
        .exec(db)
        .await
    {
        Ok(result) if result.rows_affected > 0 => {
            tracing::info!(
                deleted = result.rows_affected,
                %cutoff,
                "pruned long-offline agents"
            );
        },
        Ok(_) => {},
        Err(err) => {
            tracing::warn!(error = %err, "could not prune offline agents");
        },
    }
}

/// Timestamps come from the agent's own clock. Anything outside the retention
/// window — including a clock that runs ahead — is stored as `now`, so that the
/// row still ages out instead of becoming unprunable.
fn sample_time(ts_millis: i64, now: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ts_millis)
        .filter(|ts| {
            *ts <= now
                && *ts
                    > now - chrono::Duration::hours(HOST_SAMPLE_RETENTION_HOURS)
        })
        .unwrap_or(now)
}

/// Cumulative counters arrive as `u64`; zero means "not reported".
fn sample_i64(value: u64) -> Option<i64> {
    (value > 0).then(|| value.min(i64::MAX as u64) as i64)
}

/// Flips an agent to `offline` when its stream ends, unless a newer heartbeat has
/// already arrived (which happens when the agent reconnects quickly).
async fn mark_offline(db: &DatabaseConnection, agent_id: Uuid) {
    let row = match agent::Entity::find_by_id(agent_id).one(db).await {
        Ok(Some(row)) => row,
        Ok(None) => return,
        Err(err) => {
            tracing::warn!(%agent_id, error = %err, "could not load agent to mark offline");
            return;
        },
    };
    if row
        .last_heartbeat
        .is_some_and(|ts| ts > Utc::now() - chrono::Duration::seconds(2))
    {
        return;
    }
    let mut active: agent::ActiveModel = row.into();
    active.status = Set(agent_status::OFFLINE.to_string());
    if let Err(err) = active.update(db).await {
        tracing::warn!(%agent_id, error = %err, "could not mark agent offline");
    }
}

/// Writes the accumulated rows, clearing both buffers.
async fn flush(
    db: &DatabaseConnection,
    access: &mut Vec<access_log::ActiveModel>,
    events: &mut Vec<security_event::ActiveModel>,
) -> Result<(), Status> {
    if !access.is_empty() {
        let rows = std::mem::take(access);
        if let Err(err) = access_log::Entity::insert_many(rows).exec(db).await {
            tracing::error!(error = %err, "failed to persist access logs");
            return Err(db_status(err));
        }
    }
    if !events.is_empty() {
        let rows = std::mem::take(events);
        if let Err(err) =
            security_event::Entity::insert_many(rows).exec(db).await
        {
            tracing::error!(error = %err, "failed to persist security events");
            return Err(db_status(err));
        }
    }
    Ok(())
}

/// Persists one batch of certificate events. Failures are logged and dropped:
/// a transient database hiccup must not tear down the agent's stream.
async fn flush_cert_events(
    db: &DatabaseConnection,
    batch: &mut Vec<certificate_events::ActiveModel>,
) -> Result<(), Status> {
    if batch.is_empty() {
        return Ok(());
    }
    let rows = std::mem::take(batch);
    if let Err(err) =
        certificate_events::Entity::insert_many(rows).exec(db).await
    {
        tracing::error!(error = %err, "failed to persist certificate events");
    }
    Ok(())
}

/// Maps a shipped log entry onto the `access_logs` row.
fn access_log_row(
    entry: &LogEntry,
    site_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    timestamp: DateTime<Utc>,
) -> access_log::ActiveModel {
    access_log::ActiveModel {
        // Auto-increment primary key: leave it unset.
        site_id: Set(site_id),
        agent_id: Set(agent_id),
        request_id: Set(truncate(&entry.request_id, MAX_REQUEST_ID)),
        timestamp: Set(timestamp),
        client_ip: Set(truncate(&entry.client_ip, MAX_CLIENT_IP)
            .unwrap_or_else(|| "0.0.0.0".to_string())),
        method: Set(truncate(&entry.method, MAX_METHOD)
            .unwrap_or_else(|| "GET".to_string())),
        host: Set(truncate(&entry.host, MAX_HOST)),
        path: Set(optional(&entry.path)),
        query_string: Set(optional(&entry.query_string)),
        status_code: Set(if entry.response_status == 0 {
            None
        } else {
            Some(entry.response_status as i32)
        }),
        response_size: Set(positive_i64(entry.response_body_size as i64)),
        upstream_addr: Set(truncate(&entry.upstream_addr, MAX_UPSTREAM)),
        upstream_latency_ms: Set(positive_i64(
            entry.upstream_latency_ms as i64,
        )),
        total_latency_ms: Set(positive_i64(entry.total_latency_ms as i64)),
        cache_status: Set(truncate(&entry.cache_status, MAX_CACHE_STATUS)),
        user_agent: Set(optional(&entry.user_agent)),
        referer: Set(optional(&entry.referer)),
        country_code: Set(truncate(&entry.country_code, MAX_COUNTRY)),
        tls_version: Set(truncate(&entry.tls_version, MAX_TLS_VERSION)),
        request_headers: Set(headers_json(&entry.request_headers)),
        request_body: Set(body_text(&entry.request_body)),
        request_body_size: Set(positive_i64(entry.request_body_size as i64)),
        request_body_truncated: Set(Some(entry.request_body_truncated)),
        scheme: Set(optional(&entry.scheme)),
        protocol: Set(optional(&entry.protocol)),
        response_headers: Set(response_headers_json(&entry.response_headers)),
        response_body: Set(body_text(&entry.response_body)),
        response_body_size: Set(positive_i64(entry.response_body_size as i64)),
        response_body_truncated: Set(Some(entry.response_body_truncated)),
        ..Default::default()
    }
}

/// Lossily decodes a body prefix kept for the PostgreSQL row. The agent
/// already caps the payload at its configured limit; this is a defensive
/// second cap for older or misconfigured agents.
fn body_text(body: &[u8]) -> Option<String> {
    const MAX_STORED_BODY: usize = 65536;
    if body.is_empty() {
        return None;
    }
    let capped = &body[..body.len().min(MAX_STORED_BODY)];
    Some(String::from_utf8_lossy(capped).into_owned())
}

/// True when the entry carries a WAF decision and belongs in
/// `security_events`. The same condition gates every consumer (PostgreSQL and
/// Elasticsearch) so the two stores never disagree on routing.
fn is_waf_event(entry: &LogEntry) -> bool {
    !entry.waf_action.trim().is_empty()
        || entry.waf_score != 0
        || !entry.waf_rule_id.trim().is_empty()
}

/// Maps a shipped log entry onto a `security_events` row, or `None` when the
/// request was clean and produced no WAF decision.
fn security_event_row(
    entry: &LogEntry,
    site_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    timestamp: DateTime<Utc>,
) -> Option<security_event::ActiveModel> {
    if !is_waf_event(entry) {
        return None;
    }
    let waf_action = entry.waf_action.trim();

    Some(security_event::ActiveModel {
        site_id: Set(site_id),
        agent_id: Set(agent_id),
        request_id: Set(truncate(&entry.request_id, MAX_REQUEST_ID)),
        timestamp: Set(timestamp),
        client_ip: Set(truncate(&entry.client_ip, MAX_CLIENT_IP)
            .unwrap_or_else(|| "0.0.0.0".to_string())),
        method: Set(truncate(&entry.method, MAX_METHOD)
            .unwrap_or_else(|| "GET".to_string())),
        host: Set(truncate(&entry.host, MAX_HOST)),
        path: Set(optional(&entry.path)),
        rule_id: Set(truncate(&entry.waf_rule_id, MAX_RULE_ID)),
        rule_name: Set(truncate(&entry.waf_rule_name, MAX_RULE_NAME)),
        event_type: Set(optional(&entry.waf_event_type)),
        action: Set(truncate(waf_action, MAX_ACTION)
            .unwrap_or_else(|| action::LOG.to_string())),
        score: Set(if entry.waf_score == 0 {
            None
        } else {
            Some(entry.waf_score as i32)
        }),
        waf_details: Set(optional(&entry.waf_details)),
        country_code: Set(truncate(&entry.country_code, MAX_COUNTRY)),
        user_agent: Set(optional(&entry.user_agent)),
        created_at: Set(Utc::now()),
        ..Default::default()
    })
}

/// Maps a shipped log entry onto the Elasticsearch access log document.
///
/// Unlike the PostgreSQL row, this keeps the fields Postgres drops (bodies,
/// headers, JA3, city, ASN), because ES is the full-text/forensic store. Bodies
/// are re-truncated to the server's `max_body_size` and the agent's own
/// truncation flag is preserved so the two never contradict each other.
fn access_log_document(
    es: &ElasticsearchClient,
    entry: &LogEntry,
    timestamp: DateTime<Utc>,
) -> AccessLogDocument {
    let (request_body, mut request_body_truncated) =
        es.truncate_body_to_string(&entry.request_body);
    request_body_truncated |= entry.request_body_truncated;
    let (response_body, mut response_body_truncated) =
        es.truncate_body_to_string(&entry.response_body);
    response_body_truncated |= entry.response_body_truncated;

    AccessLogDocument {
        timestamp,
        site_id: entry.site_id.clone(),
        site_domain: entry.host.clone(),
        agent_id: entry.agent_id.clone(),
        request_id: entry.request_id.clone(),

        client_ip: entry.client_ip.clone(),
        method: entry.method.clone(),
        scheme: optional(&entry.scheme),
        host: entry.host.clone(),
        path: entry.path.clone(),
        query_string: optional(&entry.query_string),
        protocol: optional(&entry.protocol),
        request_headers: headers_json(&entry.request_headers),
        request_body,
        request_body_size: positive_u64(entry.request_body_size),
        request_body_truncated,

        response_status: if entry.response_status == 0 {
            None
        } else {
            Some(entry.response_status as u16)
        },
        response_headers: response_headers_json(&entry.response_headers),
        response_body,
        response_body_size: positive_u64(entry.response_body_size),
        response_body_truncated,

        upstream_addr: optional(&entry.upstream_addr),
        upstream_latency_ms: positive_u64(entry.upstream_latency_ms),

        waf_score: positive_u32(entry.waf_score),
        waf_action: optional(&entry.waf_action),
        waf_rule_id: optional(&entry.waf_rule_id),
        waf_details: optional(&entry.waf_details),

        total_latency_ms: positive_u64(entry.total_latency_ms),
        cache_status: optional(&entry.cache_status),

        tls_version: optional(&entry.tls_version),
        ja3_hash: optional(&entry.ja3_hash),
        country_code: optional(&entry.country_code),
        city: optional(&entry.city),
        asn: positive_u32(entry.asn),

        user_agent: optional(&entry.user_agent),
        referer: optional(&entry.referer),
    }
}

/// Maps a shipped log entry onto an Elasticsearch security event, or `None`
/// when the request produced no WAF decision — the same condition that gates the
/// PostgreSQL `security_events` row, so the two stores stay consistent.
fn security_event_document(
    es: &ElasticsearchClient,
    entry: &LogEntry,
    timestamp: DateTime<Utc>,
) -> Option<SecurityEventDocument> {
    if !is_waf_event(entry) {
        return None;
    }
    let waf_action = entry.waf_action.trim();

    let (request_body, mut request_body_truncated) =
        es.truncate_body_to_string(&entry.request_body);
    request_body_truncated |= entry.request_body_truncated;

    Some(SecurityEventDocument {
        timestamp,
        site_id: entry.site_id.clone(),
        site_domain: entry.host.clone(),
        agent_id: entry.agent_id.clone(),
        request_id: entry.request_id.clone(),

        client_ip: entry.client_ip.clone(),
        method: entry.method.clone(),
        host: entry.host.clone(),
        path: entry.path.clone(),
        query_string: optional(&entry.query_string),

        rule_id: entry.waf_rule_id.clone(),
        rule_name: optional(&entry.waf_rule_name),
        event_type: optional(&entry.waf_event_type),
        action: if waf_action.is_empty() {
            action::LOG.to_string()
        } else {
            waf_action.to_string()
        },
        score: entry.waf_score,
        attack_category: entry.waf_matched_tags.first().cloned(),
        details: optional(&entry.waf_details),
        severity: None,

        user_agent: optional(&entry.user_agent),
        country_code: optional(&entry.country_code),
        asn: positive_u32(entry.asn),

        request_headers: headers_json(&entry.request_headers),
        request_body,
        request_body_truncated,
    })
}

/// Response-header variant of [`headers_json`]: always drops
/// `content-security-policy-report-only` before the map is stored.
///
/// That header is produced by the upstream application (PingWAF never sets
/// it), is often kilobytes long, and has no forensic value for attack
/// tracing — its only effect here is log bloat. `cookie`/`set-cookie` are
/// deliberately kept: site-level logs need them for attack tracing (session
/// replay, hijack detection).
///
/// Note on the control plane's own traffic (9080): the console is a plain
/// Axum listener started by `start_server`, not a pingap service, so its
/// requests never enter the plugin log pipeline and are never shipped via
/// `ShipLogs`. Its access log (`control_plane_access_logs`, written by
/// `self_protection.rs`) stores only UA/referer — it has never stored
/// cookies — so no cookie stripping is needed for control-plane traffic.
fn response_headers_json(
    headers: &std::collections::HashMap<String, String>,
) -> Option<serde_json::Value> {
    const CSP_REPORT_ONLY: &str = "content-security-policy-report-only";
    // Single pass: drop the report-only CSP while building the map. An empty
    // result falls through to `headers_json`, which returns `None`.
    let filtered: std::collections::HashMap<String, String> = headers
        .iter()
        .filter(|(key, _)| !key.eq_ignore_ascii_case(CSP_REPORT_ONLY))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    headers_json(&filtered)
}

/// Converts a protocol header map into an indexable JSON object, or `None` when
/// empty. The ES mapping stores these as non-indexed objects, so arbitrary keys
/// cannot cause a mapping explosion.
fn headers_json(
    headers: &std::collections::HashMap<String, String>,
) -> Option<serde_json::Value> {
    if headers.is_empty() {
        return None;
    }
    let map = headers
        .iter()
        .map(|(key, value)| {
            (key.clone(), serde_json::Value::String(value.clone()))
        })
        .collect::<serde_json::Map<String, serde_json::Value>>();
    Some(serde_json::Value::Object(map))
}

fn positive_u64(value: u64) -> Option<u64> {
    if value > 0 {
        Some(value)
    } else {
        None
    }
}

fn positive_u32(value: u32) -> Option<u32> {
    if value > 0 {
        Some(value)
    } else {
        None
    }
}

/// Maps a SeaORM error onto `INTERNAL`, logging the detail server side.
fn db_status(err: sea_orm::DbErr) -> Status {
    tracing::error!(error = %err, "database error in the gRPC control plane");
    match err {
        sea_orm::DbErr::RecordNotFound(msg) => Status::not_found(msg),
        other => Status::internal(other.to_string()),
    }
}

fn parse_optional_uuid(raw: &str) -> Option<Uuid> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    match Uuid::parse_str(raw) {
        Ok(id) => Some(id),
        Err(err) => {
            tracing::debug!(value = %raw, error = %err, "ignoring malformed UUID in log entry");
            None
        },
    }
}

/// Blank protocol strings become SQL NULLs.
fn optional(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Same as [`optional`] but bounded by a column width.
fn truncate(value: &str, max: usize) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() <= max {
        return Some(trimmed.to_string());
    }
    let mut end = max;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    Some(trimmed[..end].to_string())
}

/// Zero and negative protocol integers become SQL NULLs.
fn positive_i64(value: i64) -> Option<i64> {
    if value > 0 {
        Some(value)
    } else {
        None
    }
}

fn positive_i32(value: i64) -> Option<i32> {
    if value > 0 {
        Some(value.min(i64::from(i32::MAX)) as i32)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_token_reads_the_x_agent_token_header() {
        let mut request = tonic::Request::new(());
        request
            .metadata_mut()
            .insert("x-agent-token", "abc.def.ghi".parse().unwrap());
        assert_eq!(
            ControlPlaneService::metadata_token(&request),
            "abc.def.ghi"
        );
        assert_eq!(
            ControlPlaneService::metadata_token(&tonic::Request::new(())),
            ""
        );
    }

    #[test]
    fn blanks_become_nulls() {
        assert_eq!(optional("  "), None);
        assert_eq!(optional(" x ").as_deref(), Some("x"));
        assert_eq!(truncate("", 10), None);
        assert_eq!(truncate("12345678", 4).as_deref(), Some("1234"));
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        // Each 'é' is two bytes: a four byte cap must not split one.
        let truncated = truncate(&"é".repeat(10), 5).unwrap();
        assert_eq!(truncated.len(), 4);
        assert_eq!(truncated, "éé");
    }

    #[test]
    fn zero_values_become_nulls() {
        assert_eq!(positive_i64(0), None);
        assert_eq!(positive_i64(-3), None);
        assert_eq!(positive_i64(42), Some(42));
        assert_eq!(positive_i32(0), None);
        assert_eq!(positive_i32(7), Some(7));
        assert_eq!(positive_i32(i64::MAX), Some(i32::MAX));
    }

    #[test]
    fn uuids_are_parsed_leniently() {
        assert_eq!(parse_optional_uuid(""), None);
        assert_eq!(parse_optional_uuid("nope"), None);
        let id = Uuid::new_v4();
        assert_eq!(parse_optional_uuid(&id.to_string()), Some(id));
    }

    #[test]
    fn response_headers_drop_csp_report_only_but_keep_cookies() {
        let headers = [
            ("content-type", "text/html"),
            ("Content-Security-Policy-Report-Only", "default-src 'self'"),
            ("set-cookie", "sid=abc"),
            ("cookie", "sid=abc"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<std::collections::HashMap<_, _>>();

        let json = response_headers_json(&headers).unwrap();
        let map = json.as_object().unwrap();
        assert!(!map.contains_key("content-security-policy-report-only"));
        assert!(!map.contains_key("Content-Security-Policy-Report-Only"));
        assert_eq!(
            map.get("set-cookie").and_then(|v| v.as_str()),
            Some("sid=abc")
        );
        assert_eq!(map.get("cookie").and_then(|v| v.as_str()), Some("sid=abc"));
        assert_eq!(
            map.get("content-type").and_then(|v| v.as_str()),
            Some("text/html")
        );

        // Request headers keep everything, including CSP report-only.
        assert!(headers_json(&headers).is_some());
    }

    #[test]
    fn response_headers_all_filtered_become_none() {
        let headers = [(
            "Content-Security-Policy-Report-Only".to_string(),
            "x".to_string(),
        )]
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(response_headers_json(&headers), None);
        assert_eq!(response_headers_json(&Default::default()), None);
    }

    #[test]
    fn clean_requests_produce_no_security_event() {
        let entry = LogEntry {
            agent_id: String::new(),
            site_id: String::new(),
            request_id: String::new(),
            timestamp: None,
            client_ip: "10.0.0.1".into(),
            method: "GET".into(),
            host: "example.com".into(),
            path: "/".into(),
            ..Default::default()
        };
        assert!(security_event_row(&entry, None, None, Utc::now()).is_none());
        assert!(access_log_row(&entry, None, None, Utc::now())
            .timestamp
            .is_set());

        let mut blocked = entry.clone();
        blocked.waf_action = action::BLOCK.into();
        blocked.waf_score = 42;
        blocked.waf_rule_id = "sqli-942100".into();
        blocked.waf_details = "matched rule".into();
        let event = security_event_row(&blocked, None, None, Utc::now())
            .expect("event");
        assert!(event.action.is_set());
        assert_eq!(event.score.unwrap(), Some(42));
    }

    #[test]
    fn waf_decisions_are_not_routed_to_access_logs() {
        // A blocked request arrives as two entries: the WAF decision (which
        // carries no request detail) and the access entry with detail and the
        // real status. Storing the decision in `access_logs` too would
        // duplicate every blocked or monitored request.
        let decision = LogEntry {
            waf_action: action::BLOCK.into(),
            waf_rule_id: "sqli-942100".into(),
            ..Default::default()
        };
        assert!(is_waf_event(&decision));

        let access = LogEntry {
            request_id: "abc".into(),
            ..Default::default()
        };
        assert!(!is_waf_event(&access));

        // Monitored requests carry no action, only a score or rule id.
        let monitored = LogEntry {
            waf_score: 7,
            ..Default::default()
        };
        assert!(is_waf_event(&monitored));
    }

    #[test]
    fn long_values_are_clamped_to_the_column_widths() {
        let entry = LogEntry {
            client_ip: "x".repeat(200),
            method: "GET".into(),
            country_code: "ZZZZ".into(),
            ..Default::default()
        };
        let row = access_log_row(&entry, None, None, Utc::now());
        assert_eq!(row.client_ip.clone().unwrap().len(), MAX_CLIENT_IP);
        assert_eq!(
            row.country_code.clone().unwrap().unwrap().len(),
            MAX_COUNTRY
        );
    }
}
