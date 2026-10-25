//! PingWAF control plane server.
//!
//! This crate provides the central management plane for PingWAF:
//! - A REST API (Axum) consumed by the React dashboard
//! - A gRPC service (tonic) consumed by the edge agents
//! - PostgreSQL persistence via SeaORM with automatic migrations
//!
//! The public entry point is [`start_server`], which boots both listeners and
//! blocks until a shutdown signal is received.

pub mod ai;
pub mod api;
pub mod auth;
pub mod boot_history;
pub mod config;
pub mod config_backup;
pub mod config_backup_crypto;
pub mod config_backup_targets;
pub mod config_catalog;
pub mod config_history;
pub mod config_restore;
pub mod defaults;
pub mod es;
pub mod frontend;
pub mod grpc;
pub mod mcp;
pub mod migration;
pub mod models;
pub mod monitoring;
pub mod notify;
pub mod pki;
pub mod subscription;
pub mod tls;

pub use config::ServerConfig;

use std::net::SocketAddr;
use std::sync::Arc;

use pingwaf_proto::control_plane::control_plane_server::ControlPlaneServer;
use sea_orm::{ConnectOptions, Database};
use sea_orm_migration::MigratorTrait;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

use crate::api::state::AppState;
use crate::es::{ensure_index_template, ElasticsearchClient};
use crate::grpc::{AgentRegistry, ControlPlaneService};
use crate::migration::Migrator;
use crate::models::{instance_setting, role, user};

/// Starts the PingWAF control plane server.
///
/// This function:
/// 1. Validates the configuration
/// 2. Connects to PostgreSQL
/// 3. Runs pending schema migrations
/// 4. Seeds the default administrator account when the database is empty
/// 5. Boots the HTTP REST API and gRPC control plane in parallel
/// 6. Blocks until `SIGINT` / `SIGTERM`
pub async fn start_server(mut config: ServerConfig) -> anyhow::Result<()> {
    // ── 1. Validate ──────────────────────────────────────────────────────────
    config.validate()?;

    tracing::info!(
        http_addr = %config.http_addr,
        grpc_addr = %config.grpc_addr,
        db = %config.db_url_redacted(),
        "starting PingWAF control plane"
    );

    // ── 2. Connect to PostgreSQL ─────────────────────────────────────────────
    let mut opts = ConnectOptions::new(config.db_url.as_str());
    opts.max_connections(config.db_max_connections)
        .min_connections(config.db_min_connections)
        .sqlx_logging(true);

    let db = Database::connect(opts).await.map_err(|err| {
        anyhow::anyhow!("failed to connect to PostgreSQL: {err}")
    })?;
    tracing::info!("database connection established");

    // ── 3. Run migrations ────────────────────────────────────────────────────
    Migrator::up(&db, None)
        .await
        .map_err(|err| anyhow::anyhow!("migration failed: {err}"))?;
    tracing::info!("schema migrations applied");

    // Apply retention at startup as well as in the daily monitor: a scope that
    // has not produced a new version recently must not keep expired rows.
    match config_history::prune_expired(&db).await {
        Ok(deleted) if deleted > 0 => {
            tracing::info!(
                deleted,
                "expired configuration versions pruned at startup"
            );
        },
        Ok(_) => {},
        Err(error) => {
            tracing::warn!(error = %error, "startup configuration-version prune failed");
        },
    }

    if let Err(error) = config_backup::reset_stale_uploads(&db).await {
        tracing::warn!(error = %error, "stale backup-upload recovery failed at startup");
    }
    if let Err(error) = config_backup::prune_backups(&db).await {
        tracing::warn!(error = %error, "startup backup-record prune failed");
    }

    // ── 3a. Record this start ───────────────────────────────────────────────
    // The control plane cannot announce its own death (an OOM kill runs no
    // code), so each start writes a row and the gap to the previous row is the
    // previous process's uptime. Best-effort: a control plane that cannot
    // record its own boot still has to serve traffic.
    // Kept for the stop row written at shutdown: the uptime it reports is the
    // gap between this timestamp and the moment the process is asked to leave.
    let started_at = chrono::Utc::now();
    match boot_history::record_boot(&db, boot_history::version(), &hostname())
        .await
    {
        Ok(row) => tracing::info!(
            booted_at = %row.booted_at,
            reason = %row.reason,
            previous_uptime_secs = ?row.previous_uptime_seconds,
            "control plane boot recorded"
        ),
        Err(err) => tracing::warn!(
            error = %err,
            "could not record the control plane boot"
        ),
    }

    // ── 3b. Pin the JWT secret for the life of the instance ────────────────
    resolve_jwt_secret(&db, &mut config).await?;

    // ── 4. Seed default admin ────────────────────────────────────────────────
    seed_admin(&db, &config).await?;
    // Best-effort like every seed: boot must not fail over the default group.
    if let Err(err) = defaults::seed_ip_group_defaults(&db).await {
        tracing::warn!(
            error = %err,
            "could not seed the built-in Cloudflare IP group"
        );
    }

    // ── 5. Parse addresses early (before config moves into Arc) ─────────────
    let http_addr: SocketAddr = config.http_addr.parse().map_err(|e| {
        anyhow::anyhow!("invalid http_addr '{}': {e}", config.http_addr)
    })?;
    let grpc_addr: SocketAddr = config.grpc_addr.parse().map_err(|e| {
        anyhow::anyhow!("invalid grpc_addr '{}': {e}", config.grpc_addr)
    })?;

    // ── 6. Build shared state ────────────────────────────────────────────────
    let agents = AgentRegistry::new();
    let shared_config = Arc::new(config);

    // ── 6b. Optional Elasticsearch log shipper ──────────────────────────────
    // Started only when configured and enabled. Any failure here is logged and
    // swallowed: the control plane must boot (PostgreSQL-only) even if ES is
    // down or misconfigured.
    let es_client = match shared_config.elasticsearch.as_ref() {
        Some(es_config) if es_config.is_active() => {
            match ElasticsearchClient::new(es_config.clone()).await {
                Ok(client) => {
                    let client = Arc::new(client);
                    if let Err(err) = ensure_index_template(&client).await {
                        tracing::warn!(
                            error = %err,
                            "could not install the elasticsearch index template"
                        );
                    }
                    Some(client)
                },
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "failed to start the elasticsearch shipper, continuing without it"
                    );
                    None
                },
            }
        },
        _ => None,
    };

    // Shared by the gRPC service (which fills it from agent heartbeats) and the
    // REST API (which serves `/api/v1/cache/status` from it).
    let cache_status = crate::grpc::CacheStatusRegistry::new();

    // ── 6c. Control plane HTTPS ─────────────────────────────────────────────
    // The dashboard is served over TLS so browsers treat it as a secure origin
    // (WebAuthn passkeys refuse plain http outside localhost). The certificate
    // is stored in the database and handed to the listener here, before it
    // starts accepting; a later upload swaps it in place.
    let control_tls =
        Arc::new(tls::ControlPlaneTls::new(shared_config.tls_enabled));

    let state = AppState {
        db: db.clone(),
        config: shared_config.clone(),
        agents: agents.clone(),
        es: es_client.clone(),
        cache_status: cache_status.clone(),
        control_tls: control_tls.clone(),
        protection: Arc::new(api::self_protection::SelfProtection::new()),
    };

    // ── 6d. Control plane self-protection ───────────────────────────────────
    // Load the initial policy (access log, IP allowlist, WAF), start the log
    // writer and the background refresher; the latter is what picks up edits
    // made by another process, e.g. the `pingwaf security` CLI.
    match api::self_protection::refresh(&db).await {
        Ok(policy) => {
            tracing::info!(
                access_log_enabled = policy.access_log_enabled,
                allowlist_enabled = policy.allowlist_enabled,
                waf_enabled = policy.waf.is_some(),
                "control plane self-protection loaded"
            );
            state.protection.store(policy);
        },
        Err(err) => tracing::warn!(
            error = %err,
            "could not load control plane protection settings; starting with protection disabled"
        ),
    }
    state.protection.spawn_writer(db.clone());
    let _protection_handle =
        api::self_protection::start_refresh_task(state.clone());

    // ── 6e. Observation mode watcher ────────────────────────────────────────
    // Picks up `defense_settings` edits made by another process (the
    // `pingwaf mode` CLI) and fans them out to the agents.
    let _defense_watch_handle =
        api::defense::start_watch_task(state.clone()).await;

    // ── 6f. Notification system ─────────────────────────────────────────────
    // Installed once so REST handlers and the gRPC ingest can raise alerts
    // without threading a handle through every constructor. The reload loop
    // picks up channel edits (including from another instance), and the
    // self-monitor watches the control plane host's own resources.
    let notify_manager = notify::init(db.clone());
    notify_manager.reload().await;
    let _notify_reload_handle = start_notify_reload_loop(state.clone());
    let _self_monitor_handle = notify::self_monitor::start(state.clone());

    if control_tls.is_enabled() {
        match api::system_tls::load_active_certificate(&state).await {
            Ok(Some(certificate)) => tracing::info!(
                subject = %certificate.subject_dn,
                expires = %certificate.not_after,
                "control plane HTTPS enabled with the stored certificate"
            ),
            Ok(None) => {
                let certificate =
                    api::system_tls::bootstrap_self_signed(&state).await?;
                tracing::warn!(
                    subject = %certificate.subject_dn,
                    "control plane HTTPS enabled with a freshly generated \
                     self-signed certificate; upload a real one from \
                     Settings → Control plane HTTPS"
                );
            },
            Err(err) => {
                // A stored certificate that cannot be loaded must not take the
                // console down: generate a fresh self-signed pair (the old row
                // is kept for inspection) and say so loudly.
                tracing::error!(
                    error = %err,
                    "the stored control plane certificate could not be loaded, \
                     falling back to a self-signed one"
                );
                api::system_tls::bootstrap_self_signed(&state).await?;
            },
        }
    } else {
        tracing::warn!(
            "control plane HTTPS is disabled; passkeys require a secure origin, \
             so terminate TLS in front of this listener"
        );
    }

    // ── 7. HTTP (Axum) ───────────────────────────────────────────────────────
    let http_listener = TcpListener::bind(http_addr).await.map_err(|err| {
        anyhow::anyhow!("failed to bind HTTP address {http_addr}: {err}")
    })?;
    let router = api::build_router(state.clone());
    if control_tls.is_enabled() {
        tracing::info!(%http_addr, "REST API and dashboard listening (HTTPS)");
    } else {
        tracing::info!(%http_addr, "REST API and dashboard listening (HTTP)");
    }

    // ── 8. gRPC (tonic) ──────────────────────────────────────────────────────
    let grpc_listener = TcpListener::bind(grpc_addr).await.map_err(|err| {
        anyhow::anyhow!("failed to bind gRPC address {grpc_addr}: {err}")
    })?;

    let mut grpc_builder = tonic::transport::Server::builder();
    if shared_config.grpc_tls_enabled() {
        match (&shared_config.grpc_tls_cert, &shared_config.grpc_tls_key) {
            (Some(cert_path), Some(key_path)) => {
                let cert =
                    std::fs::read_to_string(cert_path).map_err(|err| {
                        anyhow::anyhow!(
                        "failed to read gRPC TLS certificate {cert_path}: {err}"
                    )
                    })?;
                let key = std::fs::read_to_string(key_path).map_err(|err| {
                    anyhow::anyhow!(
                        "failed to read gRPC TLS key {key_path}: {err}"
                    )
                })?;
                grpc_builder = configure_grpc_tls(grpc_builder, &cert, &key)?;
                tracing::info!(
                    %grpc_addr,
                    "gRPC control plane listening (TLS, configured certificate)"
                );
            },
            (None, None) => {
                // Default TLS mode without explicit certificate files: serve the
                // certificate the console uses, generating a self-signed pair on
                // first boot. Agents pin it through `server_ca_cert` (or the CA
                // the all-in-one mode injects inline).
                let row = match api::system_tls::load_active_certificate(&state)
                    .await
                {
                    Ok(Some(row)) => Some(row),
                    Ok(None) => None,
                    Err(err) => {
                        // A stored certificate that cannot be loaded must not
                        // take the control plane down: a fresh self-signed
                        // pair replaces it (the old row stays for inspection).
                        tracing::error!(
                            error = %err,
                            "the stored control plane certificate could not \
                             be loaded for gRPC, falling back to a self-signed one"
                        );
                        None
                    },
                };
                let row = match row {
                    Some(row) => row,
                    None => {
                        api::system_tls::bootstrap_self_signed(&state).await?
                    },
                };
                let source = row.source.clone();
                grpc_builder = configure_grpc_tls(
                    grpc_builder,
                    &row.cert_pem,
                    &row.key_pem,
                )?;
                tracing::info!(
                    %grpc_addr,
                    certificate_source = %source,
                    "gRPC control plane listening (TLS)"
                );
            },
            _ => {
                return Err(anyhow::anyhow!(
                    "grpc_tls_cert and grpc_tls_key must be configured together"
                ));
            },
        }
    } else {
        tracing::warn!(
            %grpc_addr,
            "gRPC control plane is running without TLS (degraded); \
             agent traffic is plaintext — set grpc_tls_mode = \"tls\" to encrypt it"
        );
    }

    let control_plane_service = ControlPlaneService::new(
        db.clone(),
        shared_config.clone(),
        agents.clone(),
        es_client.clone(),
        cache_status,
    );
    let grpc_server = ControlPlaneServer::new(control_plane_service);

    // ── 9. Start agent health monitor ───────────────────────────────────────
    let monitor_config =
        monitoring::MonitorConfig::from_server_config(&shared_config);
    let _monitor_handle = monitoring::start_health_monitor(
        db.clone(),
        shared_config.clone(),
        monitor_config,
        agents.clone(),
    );

    // ── 9b. Start the IP group subscription scheduler ───────────────────────
    // Seed the built-in snapshot groups first so a fresh install boots with
    // current Google/Yandex ranges; failures are non-fatal (logged).
    if let Err(err) = api::ip_groups::seed_builtin_groups(&db).await {
        tracing::warn!(
            error = %err,
            "failed to seed built-in IP group subscriptions"
        );
    }
    let _sync_handle =
        api::ip_groups::start_subscription_sync_scheduler(state.clone());

    // ── 9c. Start the log retention sweeper ─────────────────────────────────
    let _retention_handle = api::logs::start_retention_scheduler(state.clone());

    // ── 9d. Start the certificate expiry scanner ────────────────────────────
    let _cert_expiry_handle = notify::cert_expiry::start(db.clone());

    // ── 10. Spawn and wait for shutdown ─────────────────────────────────────
    tokio::select! {
        result = serve_http(http_listener, router, control_tls.clone()) => {
            if let Err(err) = result {
                tracing::error!(error = %err, "HTTP server error");
            }
        }
        result = grpc_builder
            .add_service(grpc_server)
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(grpc_listener),
                shutdown_signal(),
            ) =>
        {
            if let Err(err) = result {
                tracing::error!(error = %err, "gRPC server error");
            }
        }
    }

    // ── 10a. Record the clean stop ──────────────────────────────────────────
    // Written *before* the rest of the shutdown so a slow Elasticsearch flush
    // cannot cost the row. This is what tells the next start that this process
    // was asked to stop rather than killed: the gap between two boots cannot
    // say, because a redeploy and a crash are both followed by a start seconds
    // later. Best-effort — a control plane that cannot write it still exits.
    if let Err(err) =
        boot_history::record_stop(&db, &hostname(), started_at).await
    {
        tracing::warn!(error = %err, "could not record the clean shutdown");
    }

    // ── 11. Graceful Elasticsearch shutdown ─────────────────────────────────
    // Flush any buffered documents and stop the background tasks before exit.
    if let Some(client) = es_client {
        if let Err(err) = client.shutdown().await {
            tracing::warn!(error = %err, "elasticsearch shipper did not shut down cleanly");
        }
    }

    tracing::info!("PingWAF control plane shut down");
    Ok(())
}

/// Reloads the notification channels and settings every minute, so edits made
/// outside this process (the CLI, another instance) are picked up.
/// The machine this control plane is running on, as `/etc/hostname` reports
/// it, falling back to `HOSTNAME` / `COMPUTERNAME`.
///
/// Same resolution the agent uses, so a control plane and an agent on one host
/// agree on its name. Recorded with each boot so a move between hosts is
/// visible in the history rather than implied.
fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

fn start_notify_reload_loop(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            if let Some(manager) = notify::global() {
                manager.reload().await;
            }
            let _ = &state;
        }
    })
}

/// Pins the JWT signing secret for the lifetime of the instance.
///
/// The project is open source, so the built-in default secret is public and
/// must never secure a real deployment. When the operator did not configure a
/// secret, a random one is generated on first boot and persisted in
/// `instance_settings`; every later boot reuses it. Explicit configuration
/// always wins.
async fn resolve_jwt_secret(
    db: &sea_orm::DatabaseConnection,
    config: &mut ServerConfig,
) -> anyhow::Result<()> {
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};

    const JWT_SECRET_KEY: &str = "jwt_secret";

    if !config.uses_default_jwt_secret() {
        return Ok(());
    }

    tracing::warn!(
        "JWT secret is the public placeholder; a random secret is persisted \
         and used instead"
    );

    let existing = instance_setting::Entity::find_by_id(JWT_SECRET_KEY)
        .one(db)
        .await?;
    if let Some(row) = existing {
        config.jwt_secret = row.value;
        tracing::info!("reusing the JWT secret generated on first boot");
        return Ok(());
    }

    // 256 bits of entropy from two UUIDv4 payloads, the same generator the
    // API keys use.
    let secret = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    instance_setting::ActiveModel {
        key: Set(JWT_SECRET_KEY.to_string()),
        value: Set(secret.clone()),
        updated_at: Set(chrono::Utc::now()),
    }
    .insert(db)
    .await?;
    config.jwt_secret = secret;
    tracing::info!("generated and persisted a random JWT secret (first boot)");
    Ok(())
}

/// Seeds the default administrator account if the users table is empty.
async fn seed_admin(
    db: &sea_orm::DatabaseConnection,
    config: &ServerConfig,
) -> anyhow::Result<()> {
    use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

    let count = user::Entity::find().count(db).await?;
    if count > 0 {
        tracing::debug!(users = count, "users already exist, skipping seed");
        return Ok(());
    }

    // Check if the configured admin already exists (idempotent restart).
    let existing = user::Entity::find()
        .filter(user::Column::Email.eq(&config.default_admin_email))
        .one(db)
        .await?;
    if existing.is_some() {
        return Ok(());
    }

    let password_hash = auth::hash_password(&config.default_admin_password)
        .map_err(|err| {
            anyhow::anyhow!("failed to hash admin password: {err}")
        })?;

    let now = chrono::Utc::now();
    let admin = user::ActiveModel {
        id: sea_orm::Set(uuid::Uuid::new_v4()),
        email: sea_orm::Set(config.default_admin_email.clone()),
        password_hash: sea_orm::Set(password_hash),
        name: sea_orm::Set(Some("Administrator".to_string())),
        role: sea_orm::Set(role::ADMIN.to_string()),
        disabled: sea_orm::Set(false),
        // The default password ships in the repository: force a change on
        // first login.
        must_change_password: sea_orm::Set(true),
        token_version: sea_orm::Set(0),
        created_at: sea_orm::Set(now),
        updated_at: sea_orm::Set(now),
    };

    use sea_orm::ActiveModelTrait;
    admin.insert(db).await?;

    if config.default_admin_password == config::DEFAULT_ADMIN_PASSWORD {
        tracing::warn!(
            email = %config.default_admin_email,
            "default administrator credentials are active; the dashboard \
             forces a password change at first login"
        );
    }

    tracing::info!(
        email = %config.default_admin_email,
        "default administrator account created"
    );
    Ok(())
}

/// Full bootstrap for all-in-one mode: connect to the database, run
/// migrations, seed the admin user, and create a bootstrap API key.
/// Returns the plaintext API key for the embedded agent.
pub async fn bootstrap_and_seed_api_key(
    config: &ServerConfig,
) -> anyhow::Result<String> {
    let mut opts = ConnectOptions::new(config.db_url.as_str());
    opts.max_connections(2).sqlx_logging(false);

    let db = Database::connect(opts).await.map_err(|err| {
        anyhow::anyhow!("bootstrap: failed to connect to PostgreSQL: {err}")
    })?;

    Migrator::up(&db, None)
        .await
        .map_err(|err| anyhow::anyhow!("bootstrap: migration failed: {err}"))?;

    seed_admin(&db, config).await?;
    seed_bootstrap_api_key(&db).await
}

/// Resolves the CA PEM the embedded agent pins for the local gRPC listener.
///
/// All-in-one mode serves gRPC over TLS by default with the certificate the
/// console uses, so the agent needs that certificate as its trust anchor.
/// Explicit certificate files win; otherwise the stored control plane
/// certificate is used, generating (and persisting) a self-signed pair on
/// first boot — `start_server` later picks the same row up. Returns `None`
/// when the gRPC listener runs without TLS.
pub async fn embedded_agent_ca_pem(
    config: &ServerConfig,
) -> anyhow::Result<Option<String>> {
    if !config.grpc_tls_enabled() {
        return Ok(None);
    }
    if let Some(cert_path) = &config.grpc_tls_cert {
        let pem = std::fs::read_to_string(cert_path).map_err(|err| {
            anyhow::anyhow!(
                "failed to read gRPC TLS certificate {cert_path}: {err}"
            )
        })?;
        return Ok(Some(pem));
    }

    let mut opts = ConnectOptions::new(config.db_url.as_str());
    opts.max_connections(2).sqlx_logging(false);
    let db = Database::connect(opts).await.map_err(|err| {
        anyhow::anyhow!("bootstrap: failed to connect to PostgreSQL: {err}")
    })?;

    use crate::models::{control_plane_certificate, tls_source};
    use sea_orm::{
        ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
        Set,
    };

    match control_plane_certificate::Entity::find()
        .filter(control_plane_certificate::Column::IsActive.eq(true))
        .order_by_desc(control_plane_certificate::Column::CreatedAt)
        .one(&db)
        .await?
    {
        Some(row) => Ok(Some(row.cert_pem)),
        None => {
            let sans = config.effective_tls_sans();
            let material = crate::pki::tls::generate_self_signed(
                config::DEFAULT_TLS_COMMON_NAME,
                &sans,
                crate::api::system_tls::DEFAULT_SELF_SIGNED_DAYS,
            )
            .map_err(|err| anyhow::anyhow!("{err}"))?;
            let key_pem = material.key_pem.clone().ok_or_else(|| {
                anyhow::anyhow!("the generated key is missing")
            })?;
            let meta = &material.meta;
            control_plane_certificate::ActiveModel {
                id: Set(uuid::Uuid::new_v4()),
                source: Set(tls_source::SELF_SIGNED.to_string()),
                cert_pem: Set(material.cert_pem.clone()),
                key_pem: Set(key_pem),
                subject_dn: Set(meta.subject_dn.clone()),
                common_name: Set(meta.common_name.clone()),
                sans: Set(serde_json::json!(sans)),
                serial: Set(meta.serial.clone()),
                fingerprint_sha256: Set(meta.fingerprint_sha256.clone()),
                not_before: Set(crate::api::mtls::to_utc(meta.not_before)),
                not_after: Set(crate::api::mtls::to_utc(meta.not_after)),
                is_active: Set(true),
                created_by: Set(None),
                created_at: Set(chrono::Utc::now()),
            }
            .insert(&db)
            .await?;
            tracing::info!(
                "generated the first self-signed control plane certificate \
                 (all-in-one bootstrap)"
            );
            Ok(Some(material.cert_pem))
        },
    }
}

use crate::api::keys::BOOTSTRAP_KEY_NAME;
const BOOTSTRAP_KEY_FILE: &str = "/var/lib/pingwaf/bootstrap_api_key";

/// Seeds a bootstrap API key for all-in-one mode.
///
/// The plaintext is persisted in the data dir and reused across restarts:
/// agent rows are re-identified by (hostname, api_key_id), so rotating the
/// key on every startup would strand the previous agent row as an offline
/// ghost. Rotation only happens when the key file and the database row
/// disagree (first boot, row deleted from the UI, restored database).
/// Returns the plaintext key value.
pub async fn seed_bootstrap_api_key(
    db: &sea_orm::DatabaseConnection,
) -> anyhow::Result<String> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    use crate::api::keys::generate_key;
    use crate::auth::password::{hash_password_with_cost, verify_password};
    use crate::models::{api_key, user};

    const KEY_HASH_COST: u32 = 10;

    let admin = user::Entity::find()
        .filter(user::Column::Role.eq("admin"))
        .one(db)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("no admin user found for bootstrap key")
        })?;

    let existing = api_key::Entity::find()
        .filter(api_key::Column::Name.eq(BOOTSTRAP_KEY_NAME))
        .one(db)
        .await?;

    if let Some(row) = &existing {
        if let Ok(saved) = std::fs::read_to_string(BOOTSTRAP_KEY_FILE) {
            let saved = saved.trim();
            if !saved.is_empty()
                && verify_password(saved, &row.key_hash).unwrap_or(false)
            {
                tracing::debug!(
                    key_id = %row.id,
                    "reusing persisted bootstrap API key"
                );
                return Ok(saved.to_string());
            }
        }
    }

    if let Some(existing) = existing {
        api_key::Entity::delete_by_id(existing.id).exec(db).await?;
        tracing::debug!(old_key_id = %existing.id, "rotated bootstrap API key");
    }

    let plaintext = generate_key();
    let key_hash = hash_password_with_cost(&plaintext, KEY_HASH_COST)
        .map_err(|e| anyhow::anyhow!("failed to hash bootstrap key: {e}"))?;

    let model = api_key::ActiveModel {
        id: sea_orm::Set(uuid::Uuid::new_v4()),
        user_id: sea_orm::Set(admin.id),
        name: sea_orm::Set(BOOTSTRAP_KEY_NAME.to_string()),
        key_hash: sea_orm::Set(key_hash),
        key_prefix: sea_orm::Set(plaintext[..8].to_string()),
        permissions: sea_orm::Set(vec!["agent".to_string()]),
        expires_at: sea_orm::Set(None),
        last_used_at: sea_orm::Set(None),
        created_at: sea_orm::Set(chrono::Utc::now()),
    };

    use sea_orm::ActiveModelTrait;
    model.insert(db).await?;

    if let Err(e) = persist_bootstrap_key(plaintext.as_str()) {
        tracing::warn!(
            error = %e,
            path = BOOTSTRAP_KEY_FILE,
            "failed to persist bootstrap API key; the embedded agent will get a fresh key and agent identity on every restart"
        );
    }

    tracing::info!("bootstrap API key created for all-in-one agent");
    Ok(plaintext)
}

/// Writes the bootstrap key plaintext to a root-owned file (0600) inside the
/// persistent data dir.
fn persist_bootstrap_key(plaintext: &str) -> std::io::Result<()> {
    use std::io::Write;

    let path = std::path::Path::new(BOOTSTRAP_KEY_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(plaintext.as_bytes())?;
    Ok(())
}

/// Wires a PEM certificate pair into the gRPC server builder.
fn configure_grpc_tls(
    builder: tonic::transport::Server,
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<tonic::transport::Server> {
    let tls = tonic::transport::server::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(cert_pem, key_pem));
    builder
        .tls_config(tls)
        .map_err(|err| anyhow::anyhow!("failed to configure gRPC TLS: {err}"))
}

/// Returns a future that resolves when the process receives SIGINT or SIGTERM.
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
        _ = ctrl_c => tracing::info!("received SIGINT"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
}

/// Helper: a future that resolves on shutdown signal (used by axum's
/// `with_graceful_shutdown`).
async fn shutdown_wait() {
    shutdown_signal().await;
}

/// Serves the REST API and the dashboard, over TLS when it is enabled.
///
/// The TLS case uses a mixed listener so cleartext probes still get an HTTP
/// answer; connecting the listener to `ConnInfo` is what lets the redirect
/// middleware tell the two kinds of connection apart.
async fn serve_http(
    listener: TcpListener,
    router: axum::Router,
    control_tls: Arc<tls::ControlPlaneTls>,
) -> std::io::Result<()> {
    if control_tls.is_enabled() {
        let listener =
            tls::MixedListener::new(listener, control_tls.acceptor());
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<tls::ConnInfo>(),
        )
        .with_graceful_shutdown(shutdown_wait())
        .await
    } else {
        // Connect info is wired here too: the self-protection middlewares
        // need the TCP peer even when TLS is handled elsewhere.
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<tls::ConnInfo>(),
        )
        .with_graceful_shutdown(shutdown_wait())
        .await
    }
}
