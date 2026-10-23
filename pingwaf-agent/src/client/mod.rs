use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tracing::{debug, error, info, warn};

use pingwaf_proto::control_plane::{
    self as proto, control_plane_client::ControlPlaneClient as ProtoClient,
};

use crate::cache::{BlockedIpEntry, RuleCache};
use crate::cert_events::{
    attribute_events, cert_event_buffer, CertAttribution,
};
use crate::config::AgentConfig;
use crate::heartbeat::{MetricsCollector, SystemMetrics};
use crate::probe::{self, HostSample, ProbeBuffer};

/// Log entry that can be queued for shipping to the control plane.
/// This is a simplified local type that gets converted to proto at send time.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub site_id: String,
    pub request_id: String,
    pub client_ip: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub query_string: String,
    pub protocol: String,
    pub request_headers: std::collections::HashMap<String, String>,
    pub request_body: Option<Vec<u8>>,
    pub request_body_size: u64,
    pub request_body_truncated: bool,
    pub response_status: u32,
    pub response_headers: std::collections::HashMap<String, String>,
    pub response_body: Option<Vec<u8>>,
    pub response_body_size: u64,
    pub response_body_truncated: bool,
    pub upstream_addr: String,
    pub upstream_latency_ms: u64,
    pub waf_score: u32,
    pub waf_action: String,
    pub waf_rule_id: String,
    /// Rule that actually enforced the verdict (L3-006); empty when the
    /// block came from the score gate rather than a specific rule.
    pub waf_enforced_rule_id: String,
    pub waf_rule_name: String,
    pub waf_event_type: String,
    pub waf_details: String,
    pub waf_matched_tags: Vec<String>,
    /// Who the request was made by, when the site authenticated them: the
    /// OIDC session's `sub`. Empty for an anonymous request. An identifier
    /// the provider issued, never a secret, so it is safe to store.
    pub user_identity: String,
    pub total_latency_ms: u64,
    pub cache_status: String,
    pub tls_version: String,
    pub ja3_hash: String,
    pub country_code: String,
    pub city: String,
    pub asn: u32,
    pub user_agent: String,
    pub referer: String,
}

/// Host callback invoked when the server requests a cache purge:
/// `(site_id, urls, tags)`.
type PurgeCacheFn = Box<dyn Fn(&str, &[String], &[String]) + Send + Sync>;

/// How often expired dynamic IP blocks are swept from the rule cache.
const BLOCK_SWEEP_INTERVAL_SECS: u64 = 60;

/// How often the debounced blocked-IP disk flush runs (see
/// `RuleCache::flush_blocked_ips`). Blocks take effect in memory instantly;
/// this only bounds how far a crash can set the disk copy back.
const BLOCK_FLUSH_INTERVAL_SECS: u64 = 5;

/// Callback types for server commands that affect the host application.
#[derive(Default)]
pub struct CommandHandlers {
    /// Called when the server requests a cache purge.
    pub on_purge_cache: Option<PurgeCacheFn>,
    /// Called when the server requests a config reload.
    pub on_config_reload: Option<Box<dyn Fn() + Send + Sync>>,
    /// Called when the server requests agent restart.
    pub on_restart: Option<Box<dyn Fn(bool) + Send + Sync>>,
}

/// The main gRPC client that manages the connection to the control plane server.
///
/// Responsibilities:
/// - Establish and maintain the gRPC channel
/// - Register the agent and keep the token fresh
/// - Send periodic heartbeats with system metrics
/// - Ship access/security logs in batches
/// - Receive and apply server commands (rule updates, IP blocks, etc.)
/// - Handle disconnection with exponential backoff reconnection
pub struct ControlPlaneClient {
    config: AgentConfig,
    /// Agent authentication token received during registration
    agent_token: ArcSwapOption<String>,
    /// Whether we are currently connected to the server
    connected: AtomicBool,
    /// Shutdown signal
    shutdown_signal: Arc<AtomicBool>,
    /// Shared rule cache
    rule_cache: Arc<RuleCache>,
    /// Shared metrics collector
    metrics: Arc<MetricsCollector>,
    /// Channel for queuing log entries (bounded to prevent memory exhaustion)
    log_sender: mpsc::Sender<LogEntry>,
    /// Log receiver (consumed by the log shipper task)
    log_receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<LogEntry>>>,
    /// Optional command handlers
    command_handlers: Arc<tokio::sync::RwLock<CommandHandlers>>,
    /// Buffered host probe samples, shipped with each heartbeat
    probe: Arc<ProbeBuffer>,
    /// Current reconnect backoff in milliseconds, shared between the
    /// connection loop and the registration path so a successful register
    /// can retire stale backoff immediately.
    retry_delay_ms: AtomicU64,
}

impl ControlPlaneClient {
    /// Create a new control plane client.
    ///
    /// The client does not connect immediately — call `connect()` or `start()` to begin.
    pub fn new(
        config: AgentConfig,
        rule_cache: Arc<RuleCache>,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        // Bounded on purpose: entries carry headers plus a body prefix
        // (8-64 KiB each), so 16384 entries could pin ~1 GB while the
        // control plane is unreachable (2026-10-17 audit). 2048 caps the
        // backlog in the tens of MB; the rest are dropped and counted by
        // the existing try_send warning path.
        let (log_tx, log_rx) = mpsc::channel(2048);
        let retry_delay_ms = AtomicU64::new(config.reconnect_initial_delay_ms);

        // A purge is actionable without the host application: the edge cache
        // and its quota ledger live in the rule cache, so the default handler
        // is wired here rather than left to `set_command_handlers`. An
        // application that does register handlers replaces this one.
        let purge_cache = Arc::clone(&rule_cache);
        let handlers = CommandHandlers {
            on_purge_cache: Some(Box::new(move |site_id, urls, tags| {
                let cache = Arc::clone(&purge_cache);
                let site_id = site_id.to_string();
                let urls = urls.to_vec();
                if !tags.is_empty() {
                    // Cached objects carry no tags, so there is nothing to
                    // match them against. Say so rather than report a purge
                    // that silently removed nothing.
                    warn!(site_id = %site_id, tags = tags.len(),
                        "cache purge by tag is not supported, ignoring tags");
                }
                // Off the command loop: a full-site purge walks the disk.
                tokio::spawn(async move {
                    if let Err(e) = cache.purge_site(&site_id, &urls).await {
                        error!(error = %e, site_id = %site_id, "cache purge failed");
                    }
                });
            })),
            ..CommandHandlers::default()
        };

        Self {
            config,
            agent_token: ArcSwapOption::empty(),
            connected: AtomicBool::new(false),
            shutdown_signal: Arc::new(AtomicBool::new(false)),
            rule_cache,
            metrics,
            log_sender: log_tx,
            log_receiver: Arc::new(tokio::sync::Mutex::new(log_rx)),
            command_handlers: Arc::new(tokio::sync::RwLock::new(handlers)),
            probe: Arc::new(ProbeBuffer::new()),
            retry_delay_ms,
        }
    }

    /// Check if the client is currently connected.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Set command handlers for server-initiated actions.
    pub async fn set_command_handlers(&self, handlers: CommandHandlers) {
        let mut h = self.command_handlers.write().await;
        *h = handlers;
    }

    /// Queue a log entry for shipping to the server (non-blocking).
    ///
    /// If the log buffer is full, the entry is dropped with a warning.
    pub fn send_log(&self, entry: LogEntry) {
        if let Err(e) = self.log_sender.try_send(entry) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    warn!("Log buffer full, dropping entry");
                },
                mpsc::error::TrySendError::Closed(_) => {
                    debug!("Log channel closed, dropping entry");
                },
            }
        }
    }

    /// Pop the next queued log entry without the shipper task running.
    /// Only compiled with the `test-util` feature.
    #[cfg(feature = "test-util")]
    pub async fn pop_log(&self) -> Option<LogEntry> {
        self.log_receiver.lock().await.try_recv().ok()
    }

    /// Establish the gRPC channel to the control plane server.
    async fn create_channel(&self) -> anyhow::Result<Channel> {
        let endpoint = Endpoint::from_shared(self.config.server_url.clone())
            .map_err(|e| anyhow::anyhow!("Invalid server URL: {}", e))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(300))
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .tcp_nodelay(true);
        let endpoint = apply_client_tls(
            endpoint,
            &self.config.server_url,
            &self.config.server_ca_cert,
            &self.config.server_ca_pem,
        )?;

        let channel = endpoint.connect().await?;
        Ok(channel)
    }

    /// Register this agent with the control plane.
    ///
    /// Returns the agent token and initial configuration if provided.
    async fn register(
        &self,
        channel: Channel,
    ) -> anyhow::Result<proto::RegisterAgentResponse> {
        let mut client = ProtoClient::new(channel);

        let hostname = get_hostname();
        let (cpu_cores, memory_bytes, os_info) = get_system_info();
        let addresses = self.probe.addresses();

        let request = proto::RegisterAgentRequest {
            api_key: self.config.api_key.clone(),
            hostname,
            ip_address: get_local_ip(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            os_info,
            cpu_cores,
            memory_bytes,
            public_ip: addresses.public_ip,
            private_ip: addresses.private_ip,
        };

        let response = client.register_agent(request).await?.into_inner();

        // Store the agent token
        self.agent_token
            .store(Some(Arc::new(response.agent_token.clone())));

        info!(
            agent_id = %response.agent_id,
            heartbeat_interval = response.heartbeat_interval_seconds,
            "Registered with control plane"
        );

        // Apply initial config if provided
        if let Some(ref site_config) = response.initial_config {
            if !site_config.sites.is_empty() {
                if let Err(e) =
                    self.rule_cache.update_from_site_config(site_config)
                {
                    error!(error = %e, "Failed to apply initial site config");
                }
            }
        }

        Ok(response)
    }

    /// Start the client: connect, register, and spawn background tasks.
    ///
    /// Returns join handles for the spawned tasks (heartbeat, log shipper, rule sync).
    pub async fn start(
        self: &Arc<Self>,
    ) -> anyhow::Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();

        // Host probe runs on its own thread: reading /proc and shelling out to
        // `df`/`ip` must never stall the async runtime.
        probe::spawn(
            Arc::clone(&self.probe),
            self.config.probe_interval_secs,
            self.config.probe_disk_path.clone(),
            Arc::clone(&self.shutdown_signal),
        );

        // Spawn the connection manager with reconnection logic
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            this.connection_loop().await;
        });
        handles.push(handle);

        // Expired dynamic IP blocks are dropped on read too, but sweeping on a
        // timer keeps the map, its disk copy and the heartbeat report in sync
        // even on agents that see no traffic for a while.
        let rule_cache = Arc::clone(&self.rule_cache);
        let shutdown = Arc::clone(&self.shutdown_signal);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(
                BLOCK_SWEEP_INTERVAL_SECS,
            ));
            interval.set_missed_tick_behavior(
                tokio::time::MissedTickBehavior::Delay,
            );
            loop {
                interval.tick().await;
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                rule_cache.cleanup_expired_blocks();
            }
        });
        handles.push(handle);

        // Blocked-IP persistence is debounced off the request hot path: each
        // persist serializes the whole map and fsyncs, so N rapid blocks
        // must not cost N×O(N) fsyncs. This loop writes the latest state out
        // every few seconds; shutdown still persists through
        // `persist_to_disk`.
        let rule_cache = Arc::clone(&self.rule_cache);
        let shutdown = Arc::clone(&self.shutdown_signal);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(
                BLOCK_FLUSH_INTERVAL_SECS,
            ));
            interval.set_missed_tick_behavior(
                tokio::time::MissedTickBehavior::Delay,
            );
            loop {
                interval.tick().await;
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                rule_cache.flush_blocked_ips();
            }
        });
        handles.push(handle);

        Ok(handles)
    }

    /// Retires backoff accumulated by earlier outages: registration just
    /// proved the connection healthy, so the next reconnect must start from
    /// the initial delay instead of paying for failures long past.
    fn retire_backoff(&self) {
        self.retry_delay_ms
            .store(self.config.reconnect_initial_delay_ms, Ordering::Relaxed);
    }

    /// Main connection loop with exponential backoff reconnection.
    ///
    /// The backoff lives in `retry_delay_ms` so that a successful
    /// registration (see `try_connect_and_run`) can reset it: backoff
    /// accumulated by past outages must not penalize the next reconnect
    /// after a healthy connection drops.
    async fn connection_loop(self: &Arc<Self>) {
        loop {
            if self.shutdown_signal.load(Ordering::Relaxed) {
                info!("Agent shutting down");
                break;
            }

            let retry_delay = Duration::from_millis(
                self.retry_delay_ms.load(Ordering::Relaxed),
            );

            match self.try_connect_and_run().await {
                Ok(()) => {
                    // Clean disconnect (server closed connection gracefully)
                    info!("Disconnected from control plane, will reconnect");
                },
                Err(e) => {
                    warn!(
                        error = %e,
                        delay_ms = retry_delay.as_millis() as u64,
                        "Connection to control plane failed"
                    );
                },
            }

            self.connected.store(false, Ordering::Relaxed);

            // Wait before reconnecting with exponential backoff
            tokio::time::sleep(retry_delay).await;
            let next = next_backoff(
                retry_delay.as_millis() as u64,
                self.config.reconnect_max_delay_ms,
            );
            self.retry_delay_ms.store(next, Ordering::Relaxed);
        }
    }

    /// Try to connect, register, and run the heartbeat + log shipper.
    /// Returns Ok(()) on clean disconnect, Err on connection failure.
    async fn try_connect_and_run(&self) -> anyhow::Result<()> {
        let channel = self.create_channel().await?;

        // Register
        let reg_response = self.register(channel.clone()).await?;
        self.retire_backoff();
        self.connected.store(true, Ordering::Relaxed);
        info!("Connected to control plane at {}", self.config.server_url);

        // The server owns the agent identity: the token it minted carries its
        // row ID as subject, and every stream is authenticated against that.
        // Outbound messages must present exactly this ID, not a local one.
        let agent_id = reg_response.agent_id.clone();

        // Run heartbeat and log shipping concurrently
        let heartbeat_fut = self.run_heartbeat(channel.clone(), &reg_response);
        let log_shipper_fut = self.run_log_shipper(channel.clone(), &agent_id);
        let cert_shipper_fut =
            self.run_cert_event_shipper(channel.clone(), &agent_id);
        let metric_shipper_fut = self.run_metric_shipper(channel, &agent_id);

        // Wait for either to complete (usually means disconnection)
        tokio::select! {
            result = heartbeat_fut => {
                if let Err(e) = result {
                    error!(error = %e, "Heartbeat stream ended");
                    return Err(e);
                }
            }
            result = log_shipper_fut => {
                if let Err(e) = result {
                    error!(error = %e, "Log shipper ended");
                    return Err(e);
                }
            }
            result = cert_shipper_fut => {
                if let Err(e) = result {
                    error!(error = %e, "Cert event shipper ended");
                    return Err(e);
                }
            }
            result = metric_shipper_fut => {
                if let Err(e) = result {
                    error!(error = %e, "Metric shipper ended");
                    return Err(e);
                }
            }
            _ = self.wait_for_shutdown() => {
                info!("Shutdown signal received");
            }
        }

        Ok(())
    }

    /// Run the periodic edge-metrics shipper.
    ///
    /// Samples the agent's process-wide counters and per-site cache gauges
    /// every `metrics_ship_interval_secs` (0 disables shipping) and pushes
    /// one `MetricBatch` per tick over the client-streaming `ShipMetrics`
    /// RPC. The control plane persists these for the analytics queries.
    async fn run_metric_shipper(
        &self,
        channel: Channel,
        agent_id: &str,
    ) -> anyhow::Result<()> {
        let interval_secs = self.config.metrics_ship_interval_secs;
        if interval_secs == 0 {
            // Shipping is disabled, but this future is part of the
            // `try_connect_and_run` select: returning would tear the session
            // down (reconnect storm, no commands). Park forever instead and
            // let the shutdown branch end the connection.
            debug!("Metric shipping disabled; idling shipper for the session");
            return metric_shipper_disabled().await;
        }
        let mut client = ProtoClient::new(channel);
        let agent_token = self.agent_token.load_full();

        let mut interval =
            tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = self.wait_for_shutdown() => break,
            }
            if self.shutdown_signal.load(Ordering::Relaxed) {
                break;
            }

            let batch = self.build_metric_batch(agent_id);
            let count = batch.metrics.len();
            let mut request = tonic::Request::new(tokio_stream::once(batch));
            attach_agent_token(&mut request, &agent_token);
            match client.ship_metrics(request).await {
                Ok(response) => {
                    let ack = response.into_inner();
                    debug!(
                        count,
                        received = ack.received_count,
                        "Shipped metrics to server"
                    );
                },
                Err(e) => {
                    // Transient failures are expected across reconnects; the
                    // next tick simply retries with fresh samples.
                    debug!(error = %e, "Metric ship failed");
                },
            }
        }

        Ok(())
    }

    /// Samples the current counters into one batch.
    fn build_metric_batch(&self, agent_id: &str) -> proto::MetricBatch {
        let metrics = &self.metrics;
        let mut metrics_list = vec![
            proto::Metric {
                name: "pingwaf_requests_total".to_string(),
                labels: HashMap::new(),
                value: metrics.requests_total() as f64,
                r#type: proto::MetricType::MetricCounter as i32,
            },
            proto::Metric {
                name: "pingwaf_blocked_requests_total".to_string(),
                labels: HashMap::new(),
                value: metrics.blocked_requests_total() as f64,
                r#type: proto::MetricType::MetricCounter as i32,
            },
            proto::Metric {
                name: "pingwaf_active_connections".to_string(),
                labels: HashMap::new(),
                value: metrics.active_connections() as f64,
                r#type: proto::MetricType::MetricGauge as i32,
            },
        ];
        for status in self.rule_cache.cache_statuses() {
            metrics_list.push(proto::Metric {
                name: "pingwaf_site_cache_used_bytes".to_string(),
                labels: HashMap::from([(
                    "site".to_string(),
                    status.domain.clone(),
                )]),
                value: status.cache_disk_bytes as f64,
                r#type: proto::MetricType::MetricGauge as i32,
            });
        }
        proto::MetricBatch {
            agent_id: agent_id.to_string(),
            timestamp: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
            metrics: metrics_list,
        }
    }

    /// Run the bidirectional heartbeat stream.
    ///
    /// Sends periodic heartbeats and processes server commands from the response stream.
    async fn run_heartbeat(
        &self,
        channel: Channel,
        reg_response: &proto::RegisterAgentResponse,
    ) -> anyhow::Result<()> {
        let mut client = ProtoClient::new(channel);

        // The control plane decides the heartbeat cadence — its staleness
        // thresholds are derived from the same value — so the interval it
        // handed down at registration wins; the local setting only applies
        // when the server did not send one.
        let heartbeat_interval = effective_heartbeat_interval(
            reg_response.heartbeat_interval_seconds,
            self.config.heartbeat_interval_secs,
        );

        // Create a channel for sending heartbeats to the stream
        let (hb_tx, hb_rx) = mpsc::channel::<proto::AgentHeartbeat>(4);
        let outbound = tokio_stream::wrappers::ReceiverStream::new(hb_rx);

        // Spawn the sender BEFORE opening the stream: the server does not
        // return response headers until it has read the first message (which
        // carries the auth token), so awaiting the call first would deadlock
        // both sides. The first interval tick fires immediately, sending the
        // opening message and unblocking the server.
        let agent_id = reg_response.agent_id.clone();
        let agent_token = self
            .agent_token
            .load_full()
            .map(|t| (*t).clone())
            .unwrap_or_default();
        let metrics = Arc::clone(&self.metrics);
        let rule_cache = Arc::clone(&self.rule_cache);
        let shutdown = Arc::clone(&self.shutdown_signal);
        let probe = Arc::clone(&self.probe);

        let sender_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(heartbeat_interval);
            interval.set_missed_tick_behavior(
                tokio::time::MissedTickBehavior::Delay,
            );

            loop {
                interval.tick().await;

                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                let system_metrics = metrics.collect();
                let addresses = probe.addresses();
                let hb = proto::AgentHeartbeat {
                    agent_id: agent_id.clone(),
                    agent_token: agent_token.clone(),
                    timestamp: Some(prost_types::Timestamp {
                        seconds: chrono::Utc::now().timestamp(),
                        nanos: 0,
                    }),
                    cpu_usage_percent: system_metrics.cpu_usage_percent,
                    memory_usage_bytes: system_metrics.memory_usage_bytes,
                    active_connections: system_metrics.active_connections,
                    requests_per_second: system_metrics.requests_per_second,
                    blocked_requests_total: system_metrics
                        .blocked_requests_total,
                    health: proto::AgentHealthStatus::AgentHealthHealthy as i32,
                    config_hash: rule_cache.config_hash().to_string(),
                    // Per-site edge cache disk usage, straight from the quota
                    // ledger; this is what the control plane's
                    // `/api/v1/cache/status` reports.
                    site_statuses: rule_cache.cache_statuses(),
                    // Everything sampled since the last heartbeat, oldest
                    // first; draining keeps each sample shipped exactly once.
                    host_samples: probe
                        .drain()
                        .iter()
                        .map(to_proto_sample)
                        .collect(),
                    public_ip: addresses.public_ip,
                    private_ip: addresses.private_ip,
                    // Dynamic IP blocks in force at this tick; the control
                    // plane reconciles its copy against every heartbeat.
                    blocked_ips: rule_cache
                        .blocked_ips_snapshot()
                        .iter()
                        .map(to_proto_blocked_ip)
                        .collect(),
                    last_config_sync_at: rule_cache.config_synced_at().map(
                        |at| prost_types::Timestamp {
                            seconds: at.timestamp(),
                            nanos: 0,
                        },
                    ),
                    last_policy_sync_at: rule_cache.policy_synced_at().map(
                        |at| prost_types::Timestamp {
                            seconds: at.timestamp(),
                            nanos: 0,
                        },
                    ),
                    // Rule-cache disk health; the control plane alerts on a
                    // false here because the edge is then running on empty
                    // rules until the next sync lands.
                    cache_persist_healthy: Some(
                        rule_cache.cache_persist_healthy(),
                    ),
                    cache_status_reason: rule_cache.cache_status_reason(),
                    // Per-upstream backend health from the load balancer's
                    // circuit breakers; the control plane turns sustained
                    // loss into site.upstream_* alerts.
                    upstream_health: crate::upstream_health::heartbeat_statuses(
                    ),
                };

                if hb_tx.send(hb).await.is_err() {
                    debug!("Heartbeat channel closed");
                    break;
                }
            }
        });

        // Start the bidirectional stream; on failure stop the sender so it
        // does not buffer heartbeats no one will ever read.
        let response = match client.heartbeat(outbound).await {
            Ok(response) => response,
            Err(e) => {
                sender_task.abort();
                return Err(e.into());
            },
        };
        let mut inbound = response.into_inner();

        // Process incoming server commands
        let rule_cache = Arc::clone(&self.rule_cache);
        let command_handlers = Arc::clone(&self.command_handlers);
        let shutdown = Arc::clone(&self.shutdown_signal);

        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            tokio::select! {
                msg = inbound.message() => {
                    match msg {
                        Ok(Some(command)) => {
                            Self::handle_server_command(
                                &command,
                                &rule_cache,
                                &command_handlers,
                            ).await;
                        }
                        Ok(None) => {
                            info!("Server closed heartbeat stream");
                            break;
                        }
                        Err(e) => {
                            error!(error = %e, "Heartbeat stream error");
                            return Err(e.into());
                        }
                    }
                }
                _ = self.wait_for_shutdown() => {
                    break;
                }
            }
        }

        sender_task.abort();
        Ok(())
    }

    /// Handle a server command received via the heartbeat stream.
    async fn handle_server_command(
        command: &proto::ServerCommand,
        rule_cache: &Arc<RuleCache>,
        command_handlers: &Arc<tokio::sync::RwLock<CommandHandlers>>,
    ) {
        let command_type = proto::CommandType::try_from(command.r#type)
            .unwrap_or(proto::CommandType::CommandUnknown);

        debug!(
            command_id = %command.command_id,
            command_type = ?command_type,
            "Received server command"
        );

        match &command.payload {
            Some(proto::server_command::Payload::RuleUpdate(update)) => {
                if let Some(ref bundle) = update.rules {
                    if let Err(e) = rule_cache.update_from_bundle(bundle) {
                        error!(error = %e, "Failed to apply rule update");
                    } else {
                        info!(site_id = %update.site_id, "Applied rule update from server");
                    }
                }
            },
            Some(proto::server_command::Payload::BlockIp(block)) => {
                let duration = if block.duration_seconds > 0 {
                    Some(Duration::from_secs(block.duration_seconds as u64))
                } else {
                    None
                };
                for ip in &block.ip_addresses {
                    rule_cache.block_ip(
                        &block.site_id,
                        ip,
                        duration,
                        &block.reason,
                    );
                }
            },
            Some(proto::server_command::Payload::UnblockIp(unblock)) => {
                for ip in &unblock.ip_addresses {
                    rule_cache.unblock_ip(&unblock.site_id, ip);
                }
            },
            Some(proto::server_command::Payload::ConfigReload(reload)) => {
                if let Some(ref config) = reload.config {
                    if let Err(e) = rule_cache.update_from_site_config(config) {
                        error!(error = %e, "Failed to apply config reload");
                    } else {
                        info!("Applied full config reload from server");
                    }
                }
                let handlers = command_handlers.read().await;
                if let Some(ref cb) = handlers.on_config_reload {
                    cb();
                }
            },
            Some(proto::server_command::Payload::PurgeCache(purge)) => {
                info!(
                    site_id = %purge.site_id,
                    urls = purge.urls.len(),
                    tags = purge.tags.len(),
                    "Received cache purge command"
                );
                let handlers = command_handlers.read().await;
                if let Some(ref cb) = handlers.on_purge_cache {
                    cb(&purge.site_id, &purge.urls, &purge.tags);
                }
            },
            Some(proto::server_command::Payload::UpdateSite(update)) => {
                if let Some(ref site_config) = update.site_config {
                    if let Err(e) =
                        rule_cache.update_from_site_config(site_config)
                    {
                        error!(error = %e, "Failed to apply site update");
                    }
                }
            },
            Some(proto::server_command::Payload::RestartAgent(restart)) => {
                warn!(
                    reason = %restart.reason,
                    graceful = restart.graceful,
                    "Server requested agent restart"
                );
                let handlers = command_handlers.read().await;
                if let Some(ref cb) = handlers.on_restart {
                    cb(restart.graceful);
                }
            },
            None => {
                debug!("Received server command with no payload");
            },
        }
    }

    /// Run the log shipping loop.
    ///
    /// Batches log entries and sends them to the server periodically or when
    /// the batch size threshold is reached.
    async fn run_log_shipper(
        &self,
        channel: Channel,
        agent_id: &str,
    ) -> anyhow::Result<()> {
        let mut client = ProtoClient::new(channel);
        let agent_token = self.agent_token.load_full();
        let mut receiver = self.log_receiver.lock().await;
        let mut batch: Vec<proto::LogEntry> =
            Vec::with_capacity(self.config.log_batch_size);

        let flush_interval =
            Duration::from_secs(self.config.log_flush_interval_secs.max(1));
        let mut interval = tokio::time::interval(flush_interval);
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            if self.shutdown_signal.load(Ordering::Relaxed) {
                // Flush remaining logs before shutdown
                if !batch.is_empty() {
                    Self::flush_logs(&mut client, &mut batch, &agent_token)
                        .await;
                }
                break;
            }

            tokio::select! {
                entry = receiver.recv() => {
                    match entry {
                        Some(log_entry) => {
                            let proto_entry =
                                Self::convert_log_entry(agent_id, &log_entry);
                            batch.push(proto_entry);

                            // Flush when batch is full
                            if batch.len() >= self.config.log_batch_size {
                                Self::flush_logs(
                                    &mut client,
                                    &mut batch,
                                    &agent_token,
                                )
                                .await;
                            }
                        }
                        None => {
                            // Channel closed
                            debug!("Log channel closed");
                            break;
                        }
                    }
                }
                _ = interval.tick() => {
                    // Periodic flush
                    if !batch.is_empty() {
                        Self::flush_logs(&mut client, &mut batch, &agent_token)
                            .await;
                    }
                }
                _ = self.wait_for_shutdown() => {
                    if !batch.is_empty() {
                        Self::flush_logs(&mut client, &mut batch, &agent_token)
                            .await;
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    /// Flush a batch of log entries to the server.
    async fn flush_logs(
        client: &mut ProtoClient<Channel>,
        batch: &mut Vec<proto::LogEntry>,
        agent_token: &Option<Arc<String>>,
    ) {
        if batch.is_empty() {
            return;
        }

        let entries = std::mem::take(batch);
        let count = entries.len();

        // Use client-streaming RPC for log shipping
        let mut request = tonic::Request::new(tokio_stream::iter(entries));
        attach_agent_token(&mut request, agent_token);
        match client.ship_logs(request).await {
            Ok(response) => {
                let ack = response.into_inner();
                if ack.success {
                    debug!(
                        count,
                        received = ack.received_count,
                        "Flushed logs to server"
                    );
                } else {
                    warn!(
                        error = %ack.error_message,
                        "Server rejected log batch"
                    );
                }
            },
            Err(e) => {
                error!(error = %e, count, "Failed to ship logs");
            },
        }
    }

    /// Run the certificate-event shipping loop.
    ///
    /// Drains the global ACME capture buffer on the same cadence as the log
    /// shipper. Errors are logged and swallowed: a control plane without the
    /// `ShipCertEvents` RPC must not tear down an otherwise healthy
    /// connection.
    async fn run_cert_event_shipper(
        &self,
        channel: Channel,
        agent_id: &str,
    ) -> anyhow::Result<()> {
        let mut client = ProtoClient::new(channel);
        let agent_token = self.agent_token.load_full();

        let flush_interval =
            Duration::from_secs(self.config.log_flush_interval_secs.max(1));
        let mut interval = tokio::time::interval(flush_interval);
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            if self.shutdown_signal.load(Ordering::Relaxed) {
                let entries = self.drain_cert_events(agent_id);
                if !entries.is_empty() {
                    Self::flush_cert_events(&mut client, entries, &agent_token)
                        .await;
                }
                break;
            }

            tokio::select! {
                _ = interval.tick() => {
                    let entries = self.drain_cert_events(agent_id);
                    if !entries.is_empty() {
                        Self::flush_cert_events(&mut client, entries, &agent_token)
                            .await;
                    }
                }
                _ = self.wait_for_shutdown() => {
                    let entries = self.drain_cert_events(agent_id);
                    if !entries.is_empty() {
                        Self::flush_cert_events(&mut client, entries, &agent_token)
                            .await;
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    /// Drain the capture buffer and stamp each event with its site and
    /// certificate, resolved against the current site rules: the tracing
    /// layer sees only log text, so attribution happens here, where the
    /// domain → site topology lives (see [`attribute_events`]).
    fn drain_cert_events(&self, agent_id: &str) -> Vec<proto::CertEventEntry> {
        let mut entries = cert_event_buffer().drain(agent_id);
        if entries.iter().any(|entry| entry.site_id.is_empty()) {
            let sites = self.rule_cache.all_sites();
            let attributions: Vec<CertAttribution> = sites
                .sites
                .values()
                .map(|site| {
                    let mut domains = vec![site.domain.to_lowercase()];
                    domains.extend(
                        site.alternate_domains
                            .iter()
                            .map(|domain| domain.to_lowercase()),
                    );
                    CertAttribution {
                        domains,
                        site_id: site.site_id.clone(),
                        certificate_id: site
                            .ssl_config
                            .as_ref()
                            .map(|ssl| ssl.certificate_id.clone())
                            .unwrap_or_default(),
                    }
                })
                .collect();
            attribute_events(&mut entries, &attributions);
        }
        entries
    }

    /// Flush a batch of certificate events to the server.
    async fn flush_cert_events(
        client: &mut ProtoClient<Channel>,
        entries: Vec<proto::CertEventEntry>,
        agent_token: &Option<Arc<String>>,
    ) {
        let count = entries.len();
        let mut request = tonic::Request::new(tokio_stream::iter(entries));
        attach_agent_token(&mut request, agent_token);
        match client.ship_cert_events(request).await {
            Ok(response) => {
                let ack = response.into_inner();
                if ack.success {
                    debug!(
                        count,
                        received = ack.received_count,
                        "Flushed cert events to server"
                    );
                } else {
                    warn!(
                        error = %ack.error_message,
                        "Server rejected cert event batch"
                    );
                }
            },
            Err(e) => {
                error!(error = %e, count, "Failed to ship cert events");
            },
        }
    }

    /// Convert a local LogEntry to the proto LogEntry type.
    fn convert_log_entry(agent_id: &str, entry: &LogEntry) -> proto::LogEntry {
        proto::LogEntry {
            agent_id: agent_id.to_string(),
            site_id: entry.site_id.clone(),
            request_id: entry.request_id.clone(),
            timestamp: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
            client_ip: entry.client_ip.clone(),
            method: entry.method.clone(),
            scheme: entry.scheme.clone(),
            host: entry.host.clone(),
            path: entry.path.clone(),
            query_string: entry.query_string.clone(),
            protocol: entry.protocol.clone(),
            request_headers: entry.request_headers.clone(),
            request_body: entry.request_body.clone().unwrap_or_default(),
            request_body_size: entry.request_body_size,
            request_body_truncated: entry.request_body_truncated,
            response_status: entry.response_status,
            response_headers: entry.response_headers.clone(),
            response_body: entry.response_body.clone().unwrap_or_default(),
            response_body_size: entry.response_body_size,
            response_body_truncated: entry.response_body_truncated,
            upstream_addr: entry.upstream_addr.clone(),
            upstream_latency_ms: entry.upstream_latency_ms,
            waf_score: entry.waf_score,
            waf_action: entry.waf_action.clone(),
            waf_rule_id: entry.waf_rule_id.clone(),
            waf_enforced_rule_id: entry.waf_enforced_rule_id.clone(),
            waf_rule_name: entry.waf_rule_name.clone(),
            waf_event_type: entry.waf_event_type.clone(),
            waf_details: entry.waf_details.clone(),
            waf_matched_tags: entry.waf_matched_tags.clone(),
            user_identity: entry.user_identity.clone(),
            total_latency_ms: entry.total_latency_ms,
            cache_status: entry.cache_status.clone(),
            tls_version: entry.tls_version.clone(),
            ja3_hash: entry.ja3_hash.clone(),
            country_code: entry.country_code.clone(),
            city: entry.city.clone(),
            asn: entry.asn,
            user_agent: entry.user_agent.clone(),
            referer: entry.referer.clone(),
        }
    }

    /// Wait until the shutdown signal is set.
    async fn wait_for_shutdown(&self) {
        let shutdown = Arc::clone(&self.shutdown_signal);
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Signal the client to shut down gracefully.
    pub fn shutdown(&self) {
        info!("Initiating agent shutdown");
        self.shutdown_signal.store(true, Ordering::Relaxed);
    }

    /// Get the current system metrics snapshot.
    ///
    /// This is a *read-only* sample on its own CPU baseline
    /// (`collect_snapshot`), not a heartbeat collection: `collect()` would
    /// consume the heartbeat's `LAST_CPU` baseline, and the two run on
    /// independent schedules, so a snapshot firing just before a heartbeat
    /// would leave it differencing over a near-zero interval.
    pub fn metrics_snapshot(&self) -> SystemMetrics {
        self.metrics.collect_snapshot()
    }
}

// ─────────────────────────────────────────────────────────────
// Helper functions for system information
// ─────────────────────────────────────────────────────────────

/// Future that never resolves: the value a disabled metric shipper parks on
/// so it neither ships nor completes the surrounding select. Tested with a
/// timeout — the contract is "does not complete".
async fn metric_shipper_disabled() -> anyhow::Result<()> {
    std::future::pending::<anyhow::Result<()>>().await
}

/// Attaches the agent token as `x-agent-token` metadata — the transport-level
/// credential the control plane authenticates the shipping streams with (the
/// ship message bodies carry no token field).
fn attach_agent_token<T>(
    request: &mut tonic::Request<T>,
    token: &Option<Arc<String>>,
) {
    if let Some(token) = token {
        if let Ok(value) = token.parse() {
            request.metadata_mut().insert("x-agent-token", value);
        }
    }
}

/// How long a visitor-auth call may take before it is treated as a refusal.
///
/// Short on purpose. A login is a person waiting at a form, and a control
/// plane that has not answered in this long is not going to answer usefully.
/// The data plane turns the timeout into "login is unavailable" rather than
/// letting the request hang, which is the fail-closed direction.
const VISITOR_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// The visitor-authentication calls, on the same channel the rest of the
/// agent uses.
///
/// Every method here returns `Err` when the control plane cannot be reached.
/// The caller must treat that as a refusal — a login that cannot be checked is
/// not a login — rather than falling back to anything local.
impl ControlPlaneClient {
    /// Opens a client for one visitor-auth call.
    ///
    /// A fresh channel per call rather than a cached one: logins are rare
    /// (a person signing in, not a per-request path), and the connection
    /// machinery the long-lived streams use would otherwise need a second
    /// reconnect loop to keep alive. The cost is a TCP+HTTP/2 handshake on a
    /// login, which is the same order as the bcrypt verification that follows
    /// it.
    async fn visitor_auth_client(
        &self,
    ) -> anyhow::Result<ProtoClient<Channel>> {
        let channel = self.create_channel().await?;
        Ok(ProtoClient::new(channel))
    }

    /// The agent token, or an error when the agent has not registered yet.
    ///
    /// Every visitor RPC authenticates with it, so a call before registration
    /// cannot succeed and says so rather than sending an empty credential.
    fn require_agent_token(&self) -> anyhow::Result<String> {
        self.agent_token
            .load_full()
            .map(|token| token.as_ref().clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "agent is not registered with the control plane"
                )
            })
    }

    /// Asks for a proof-of-work challenge for a site's login form.
    pub async fn visitor_login_challenge(
        &self,
        agent_id: &str,
        site_id: &str,
    ) -> anyhow::Result<proto::VisitorChallengeResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorChallengeRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_login_challenge(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Exchanges a solved challenge and credentials for an identity.
    ///
    /// The password is passed through and never logged or retained here.
    #[allow(clippy::too_many_arguments)]
    pub async fn visitor_login(
        &self,
        agent_id: &str,
        site_id: &str,
        challenge_id: &str,
        solution: &str,
        timestamp: i64,
        email: &str,
        password: &str,
    ) -> anyhow::Result<proto::VisitorLoginResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorLoginRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            site_id: site_id.to_string(),
            challenge_id: challenge_id.to_string(),
            solution: solution.to_string(),
            timestamp,
            email: email.to_string(),
            password: password.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_login(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Reports the end of a visitor session.
    pub async fn visitor_logout(
        &self,
        agent_id: &str,
        visitor_id: &str,
        site_id: &str,
    ) -> anyhow::Result<()> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorLogoutRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            site_id: site_id.to_string(),
        };
        tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_logout(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(())
    }

    /// Changes a visitor's password, returning the new token version.
    pub async fn visitor_change_password(
        &self,
        agent_id: &str,
        visitor_id: &str,
        current_password: &str,
        new_password: &str,
    ) -> anyhow::Result<proto::VisitorChangePasswordResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorChangePasswordRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            current_password: current_password.to_string(),
            new_password: new_password.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_change_password(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// The sites a visitor may enter, for the portal.
    pub async fn visitor_grants(
        &self,
        agent_id: &str,
        site_id: &str,
        visitor_id: &str,
    ) -> anyhow::Result<proto::VisitorGrantsResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorGrantsRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_grants(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Starts a passkey registration for a signed-in visitor.
    pub async fn visitor_passkey_register_begin(
        &self,
        agent_id: &str,
        visitor_id: &str,
        site_id: &str,
    ) -> anyhow::Result<proto::VisitorPasskeyOptionsResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorPasskeyBeginRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_passkey_register_begin(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Finishes a passkey registration.
    pub async fn visitor_passkey_register_finish(
        &self,
        agent_id: &str,
        site_id: &str,
        ceremony_id: &str,
        credential_json: &str,
        name: &str,
    ) -> anyhow::Result<proto::VisitorPasskeyFinishResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorPasskeyFinishRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            site_id: site_id.to_string(),
            ceremony_id: ceremony_id.to_string(),
            credential_json: credential_json.to_string(),
            name: name.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_passkey_register_finish(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Starts a passkey sign-in.
    pub async fn visitor_passkey_login_begin(
        &self,
        agent_id: &str,
        site_id: &str,
    ) -> anyhow::Result<proto::VisitorPasskeyOptionsResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorPasskeyBeginRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: String::new(),
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_passkey_login_begin(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Finishes a passkey sign-in, returning the identity on success.
    pub async fn visitor_passkey_login_finish(
        &self,
        agent_id: &str,
        site_id: &str,
        ceremony_id: &str,
        credential_json: &str,
    ) -> anyhow::Result<proto::VisitorLoginResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorPasskeyFinishRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            site_id: site_id.to_string(),
            ceremony_id: ceremony_id.to_string(),
            credential_json: credential_json.to_string(),
            name: String::new(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_passkey_login_finish(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Lists a visitor's passkeys, for the portal.
    pub async fn visitor_passkey_list(
        &self,
        agent_id: &str,
        site_id: &str,
        visitor_id: &str,
    ) -> anyhow::Result<proto::VisitorPasskeyListResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorGrantsRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_passkey_list(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Checks that a session is still valid.
    ///
    /// The data plane caches the answer briefly, so this is called at most
    /// once per cache window per session rather than on every request.
    pub async fn visitor_validate_session(
        &self,
        agent_id: &str,
        site_id: &str,
        visitor_id: &str,
        token_version: i64,
    ) -> anyhow::Result<proto::VisitorValidateResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorValidateRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            site_id: site_id.to_string(),
            visitor_id: visitor_id.to_string(),
            token_version,
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_validate_session(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Toggles the portal's per-site "show this here" switch.
    pub async fn visitor_set_site_visible(
        &self,
        agent_id: &str,
        visitor_id: &str,
        site_id: &str,
        visible: bool,
    ) -> anyhow::Result<proto::VisitorSetVisibleResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorSetVisibleRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            site_id: site_id.to_string(),
            visible,
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_set_site_visible(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }
}

/// Enables TLS for `https://` server URLs.
///
/// `Endpoint::from_shared` does not do this on its own — without the explicit
/// config the agent would speak cleartext h2 into a TLS port. With inline CA
/// PEM (all-in-one) or a configured CA file that material is the only trust
/// anchor; otherwise the bundled webpki roots apply.
fn apply_client_tls(
    endpoint: Endpoint,
    server_url: &str,
    ca_cert_path: &Option<String>,
    ca_cert_pem: &Option<String>,
) -> anyhow::Result<Endpoint> {
    if !server_url.starts_with("https://") {
        return Ok(endpoint);
    }
    let mut tls = ClientTlsConfig::new();
    if let Some(pem) = ca_cert_pem {
        tls = tls.ca_certificate(Certificate::from_pem(pem));
    } else if let Some(path) = ca_cert_path {
        let pem = std::fs::read_to_string(path).map_err(|err| {
            anyhow::anyhow!(
                "failed to read server CA certificate {path}: {err}"
            )
        })?;
        tls = tls.ca_certificate(Certificate::from_pem(pem));
    } else {
        tls = tls.with_enabled_roots();
    }
    Ok(endpoint.tls_config(tls)?)
}

/// Doubles the current reconnect backoff, capped at the configured maximum,
/// then shrinks it to a random point in the lower half of that value.
///
/// The jitter stops a fleet of agents that lost the control plane together —
/// a deploy, a network blip — from reconnecting in a lockstep burst every
/// `reconnect_max_delay_ms`.
fn next_backoff(current_ms: u64, max_ms: u64) -> u64 {
    let capped = current_ms.saturating_mul(2).min(max_ms);
    let factor = 0.5 + rand::random::<f64>() * 0.5;
    ((capped as f64 * factor) as u64).max(1)
}

/// The cadence the heartbeat sender ticks at.
///
/// The server-sent interval wins whenever the control plane handed one down
/// (a positive value; its config validation guarantees one in practice),
/// otherwise the agent's local configuration applies. Either way the result
/// is clamped so a pathological value cannot silence liveness reporting.
fn effective_heartbeat_interval(server_secs: i64, local_secs: u64) -> Duration {
    let secs = if server_secs > 0 {
        server_secs as u64
    } else {
        local_secs
    };
    Duration::from_secs(secs.max(5))
}

/// Convert a probe sample into its wire representation.
fn to_proto_sample(sample: &HostSample) -> proto::HostSample {
    proto::HostSample {
        ts_millis: sample.ts_millis,
        cpu_usage_percent: sample.cpu_usage_percent,
        load1: sample.load1,
        load5: sample.load5,
        load15: sample.load15,
        memory_total_bytes: sample.memory_total_bytes,
        memory_used_bytes: sample.memory_used_bytes,
        memory_available_bytes: sample.memory_available_bytes,
        swap_total_bytes: sample.swap_total_bytes,
        swap_used_bytes: sample.swap_used_bytes,
        disk_total_bytes: sample.disk_total_bytes,
        disk_used_bytes: sample.disk_used_bytes,
        net_rx_bytes: sample.net_rx_bytes,
        net_tx_bytes: sample.net_tx_bytes,
        disk_read_bytes: sample.disk_read_bytes,
        disk_write_bytes: sample.disk_write_bytes,
        process_count: sample.process_count,
        tcp_connections: sample.tcp_connections,
        uptime_secs: sample.uptime_secs,
    }
}

/// Convert a dynamic IP block into its wire representation.
fn to_proto_blocked_ip(entry: &BlockedIpEntry) -> proto::BlockedIp {
    proto::BlockedIp {
        ip: entry.ip.clone(),
        site_id: entry.site_id.clone(),
        reason: entry.reason.clone(),
        blocked_at: Some(prost_types::Timestamp {
            seconds: entry.blocked_at.timestamp(),
            nanos: 0,
        }),
        expires_at: entry.expires_at.map(|exp| prost_types::Timestamp {
            seconds: exp.timestamp(),
            nanos: 0,
        }),
    }
}

fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| {
            std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "unknown".to_string())
        })
}

fn get_local_ip() -> String {
    // Attempt to determine local IP by connecting to a public address
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("8.8.8.8:80")?;
            socket.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn get_system_info() -> (u32, u64, String) {
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);

    let memory_bytes = get_total_memory();

    let os_info =
        format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);

    (cpu_cores, memory_bytes, os_info)
}

fn get_total_memory() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("MemTotal:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|kb| kb * 1024)
            })
            .unwrap_or(0)
    }
    #[cfg(target_os = "macos")]
    {
        // Use sysctl to get total memory on macOS
        std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
            .unwrap_or(0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_agent_token_sets_the_metadata() {
        let mut request = tonic::Request::new(());
        attach_agent_token(&mut request, &None);
        assert!(request.metadata().get("x-agent-token").is_none());
        let token = Some(Arc::new("abc.def.ghi".to_string()));
        attach_agent_token(&mut request, &token);
        assert_eq!(
            request.metadata().get("x-agent-token").unwrap(),
            "abc.def.ghi"
        );
    }

    // A disabled metric shipper must never complete: inside
    // `try_connect_and_run`'s select a completed future tears the whole
    // gRPC session down, causing a reconnect storm and lost commands.
    #[tokio::test]
    async fn disabled_metric_shipper_never_completes() {
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            metric_shipper_disabled(),
        )
        .await;
        assert!(result.is_err(), "disabled shipper resolved too early");
    }

    #[test]
    fn plaintext_urls_skip_tls_config() {
        let endpoint = Endpoint::from_shared("http://localhost:9090").unwrap();
        assert!(apply_client_tls(
            endpoint,
            "http://localhost:9090",
            &None,
            &None
        )
        .is_ok());
    }

    #[test]
    fn https_without_ca_uses_bundled_roots() {
        let endpoint =
            Endpoint::from_shared("https://waf.example.com:9090").unwrap();
        assert!(apply_client_tls(
            endpoint,
            "https://waf.example.com:9090",
            &None,
            &None
        )
        .is_ok());
    }

    #[test]
    fn https_with_missing_ca_file_fails_early() {
        let endpoint =
            Endpoint::from_shared("https://waf.example.com:9090").unwrap();
        let err = apply_client_tls(
            endpoint,
            "https://waf.example.com:9090",
            &Some("/nonexistent/ca.pem".to_string()),
            &None,
        )
        .expect_err("a missing CA file must fail before connecting");
        assert!(err.to_string().contains("/nonexistent/ca.pem"));
    }

    #[test]
    fn inline_ca_pem_wins_over_the_file() {
        let endpoint = Endpoint::from_shared("https://127.0.0.1:9090").unwrap();
        // `Certificate::from_pem` is lazy — validity is checked at handshake —
        // so an unusable inline PEM still configures successfully. The point
        // of the test: the (missing) CA file is never read, proving the inline
        // material takes precedence.
        assert!(apply_client_tls(
            endpoint,
            "https://127.0.0.1:9090",
            &Some("/nonexistent/ca.pem".to_string()),
            &Some("not a pem".to_string()),
        )
        .is_ok());
    }

    fn test_client(initial_ms: u64, max_ms: u64) -> Arc<ControlPlaneClient> {
        test_client_at("http://127.0.0.1:1", initial_ms, max_ms)
    }

    fn test_client_at(
        server_url: &str,
        initial_ms: u64,
        max_ms: u64,
    ) -> Arc<ControlPlaneClient> {
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            server_url: server_url.to_string(),
            api_key: "test-key".to_string(),
            reconnect_initial_delay_ms: initial_ms,
            reconnect_max_delay_ms: max_ms,
            ..AgentConfig::default()
        };
        let rule_cache = RuleCache::new(
            dir.path().to_path_buf(),
            config.resolved_agent_id(),
        )
        .unwrap();
        Arc::new(ControlPlaneClient::new(
            config,
            rule_cache,
            Arc::new(MetricsCollector::new()),
        ))
    }

    #[test]
    fn backoff_doubles_is_capped_and_jittered() {
        // Each step lands in [50%, 100%] of the doubled-and-capped value —
        // still exponential, but a fleet of agents never reconnects in
        // lockstep.
        for _ in 0..100 {
            let next = next_backoff(100, 60_000);
            assert!((100..=200).contains(&next), "{next}");

            let capped = next_backoff(50_000, 60_000);
            assert!((30_000..=60_000).contains(&capped), "{capped}");

            // A pathological current value must neither overflow nor stall at
            // zero.
            let overflow = next_backoff(u64::MAX, 1_000);
            assert!((500..=1_000).contains(&overflow), "{overflow}");
        }
    }

    #[test]
    fn heartbeat_interval_prefers_the_server_value() {
        // A registered interval wins over the local default.
        assert_eq!(
            effective_heartbeat_interval(15, 30),
            Duration::from_secs(15)
        );
        // Servers that do not send one (0) fall back to the local config.
        assert_eq!(
            effective_heartbeat_interval(0, 30),
            Duration::from_secs(30)
        );
        assert_eq!(
            effective_heartbeat_interval(-5, 30),
            Duration::from_secs(30)
        );
        // Either source is clamped to the reporting minimum.
        assert_eq!(effective_heartbeat_interval(1, 30), Duration::from_secs(5));
        assert_eq!(effective_heartbeat_interval(0, 2), Duration::from_secs(5));
    }

    #[test]
    fn retire_backoff_restores_initial_delay() {
        let client = test_client(1_000, 60_000);
        client.retry_delay_ms.store(60_000, Ordering::Relaxed);
        client.retire_backoff();
        assert_eq!(
            client.retry_delay_ms.load(Ordering::Relaxed),
            1_000,
            "a successful registration must retire accumulated backoff"
        );
    }

    #[test]
    fn metric_batch_carries_global_counters() {
        let client = test_client(1_000, 60_000);
        let batch = client.build_metric_batch("agent-1");
        assert_eq!(batch.agent_id, "agent-1");
        assert!(batch.timestamp.is_some());

        let names: Vec<&str> =
            batch.metrics.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"pingwaf_requests_total"));
        assert!(names.contains(&"pingwaf_blocked_requests_total"));
        assert!(names.contains(&"pingwaf_active_connections"));
        for metric in &batch.metrics {
            assert!(
                metric.labels.is_empty(),
                "global counters carry no labels"
            );
            assert!(metric.value.is_finite());
        }
    }

    #[tokio::test]
    async fn connection_loop_backs_off_against_dead_endpoint() {
        // Bind and drop a listener so the endpoint reliably refuses
        // connections, then let the loop exhaust its short backoff budget.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let client =
            test_client_at(&format!("http://127.0.0.1:{port}"), 10, 80);

        let this = Arc::clone(&client);
        let handle = tokio::spawn(async move { this.connection_loop().await });
        tokio::time::sleep(Duration::from_millis(1_000)).await;

        let observed = client.retry_delay_ms.load(Ordering::Relaxed);
        assert!(
            (40..=80).contains(&observed),
            "repeated failures must grow backoff into the jittered top half, got {observed}"
        );

        client.shutdown_signal.store(true, Ordering::Relaxed);
        handle.await.unwrap();
        let observed = client.retry_delay_ms.load(Ordering::Relaxed);
        assert!(
            (40..=80).contains(&observed),
            "no registration happened, so backoff must stay in the jittered top half, got {observed}"
        );
    }
}
