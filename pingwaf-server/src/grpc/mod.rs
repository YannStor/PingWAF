//! gRPC control plane service, agent registry and configuration builder.
//!
//! This module exposes three submodules:
//! - [`config`] — builds protocol messages from database rows
//! - [`control_plane`] — implements the `ControlPlane` gRPC service
//! - [`registry`] — in-memory map of live agent heartbeat streams
//!
//! The key integration point for the REST API is [`notify_config_changed`], which
//! pushes a fresh `SiteConfig` to every agent that serves the changed site.

pub mod cache_status;
pub mod config;
pub mod control_plane;
pub mod registry;
pub mod visitor_auth;

pub use cache_status::{CacheStatusRegistry, SiteCacheStatus};
pub use control_plane::ControlPlaneService;
pub use registry::{AgentRegistry, ConnectedAgent, COMMAND_CHANNEL_CAPACITY};

use pingwaf_proto::control_plane::{
    server_command::Payload, ServerCommand, SiteConfig, UpdateSiteCommand,
};
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
};
use std::collections::HashMap;
use uuid::Uuid;

use crate::api::agents::command_type;
use crate::api::state::AppState;
use crate::config_history::{self, VersionScope};
use crate::grpc::config::{build_site_config, now_timestamp};
use crate::models::{agent, api_key, config_version, site};

/// The sites an agent serves: its binding when it has one, otherwise every
/// site owned by its API key's user. Mirrors the gRPC `visible_sites`, and is
/// what an `UpdateSite` payload must carry — the agent applies the payload
/// authoritatively, dropping any cached site the payload does not list.
async fn agent_visible_site_ids(
    db: &DatabaseConnection,
    agent_row: &agent::Model,
) -> Result<Vec<Uuid>, DbErr> {
    if let Some(site_id) = agent_row.site_id {
        return Ok(vec![site_id]);
    }
    let Some(key_id) = agent_row.api_key_id else {
        return Ok(Vec::new());
    };
    let Some(key) = api_key::Entity::find_by_id(key_id).one(db).await? else {
        return Ok(Vec::new());
    };
    let sites = site::Entity::find()
        .filter(site::Column::UserId.eq(key.user_id))
        .all(db)
        .await?;
    Ok(sites.iter().map(|row| row.id).collect())
}

/// Builds the `UpdateSite` payload one agent should receive for a change on
/// `site_id`: its bound site's bundle, or the full visible bundle for an
/// unbound agent. `None` when the agent does not serve the site.
async fn update_payload_for_agent(
    db: &DatabaseConnection,
    changed_site_config: &SiteConfig,
    agent_row: &agent::Model,
    site_id: Uuid,
) -> Result<Option<SiteConfig>, DbErr> {
    let visible = agent_visible_site_ids(db, agent_row).await?;
    if !visible.contains(&site_id) {
        return Ok(None);
    }
    if agent_row.site_id.is_some() {
        return Ok(Some(changed_site_config.clone()));
    }
    // An unbound agent runs every site its owner has: the payload must list
    // them all or the agent would drop the sites it does not carry.
    let config = build_site_config(db, Some(&visible)).await?;
    Ok(Some(config))
}

/// Notifies every connected agent that the configuration for `site_id` changed.
///
/// This is a best-effort operation: it logs failures but never propagates them
/// to the caller. The REST API handler has already committed the change; a push
/// failure merely means the agent will pick it up on the next `sync_rules`.
///
/// A successful build also records a configuration version (unless the latest
/// version already carries this fingerprint), which is what makes the console
/// and the `pingwaf config` CLI able to list and roll back changes.
pub async fn notify_config_changed(
    state: &AppState,
    site_id: Uuid,
    actor: Option<&str>,
) {
    // Build the new configuration. If the database is unhappy there is nothing
    // worth sending, so bail out with a warning.
    let site_config = match build_site_config(&state.db, Some(&[site_id])).await
    {
        Ok(config) => config,
        Err(err) => {
            tracing::warn!(%site_id, error = %err, "failed to build site config for push");
            return;
        },
    };

    // Record the version before the push: the database is already committed,
    // so the snapshot must land even if no agent is connected to receive it.
    // The ~19-table capture is best-effort and off the request path (same
    // detached-task pattern as notification delivery): a slow capture must
    // not stretch every API mutation. Hash-based dedup happens inside
    // record_version, so repeat pushes stay cheap even when two spawns race.
    let db = state.db.clone();
    let config_hash = site_config.config_hash.clone();
    let actor = actor.map(str::to_string);
    tokio::spawn(async move {
        if let Err(err) = config_history::record_version(
            &db,
            VersionScope::Site(site_id),
            config_version::source::API,
            actor.as_deref(),
            &config_hash,
        )
        .await
        {
            tracing::warn!(%site_id, error = %err, "could not record the configuration version");
        }
    });

    // Deliver to every agent that serves this site: agents bound to it, and
    // unbound agents of the owning user (they run all of the owner's sites).
    let agents = match agent::Entity::find().all(&state.db).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(%site_id, error = %err, "failed to list agents for config push");
            return;
        },
    };

    let mut delivered = 0usize;
    for row in &agents {
        let payload = match update_payload_for_agent(
            &state.db,
            &site_config,
            row,
            site_id,
        )
        .await
        {
            Ok(payload) => payload,
            Err(err) => {
                tracing::warn!(
                    agent_id = %row.id,
                    %site_id,
                    error = %err,
                    "failed to build the config payload for an agent"
                );
                continue;
            },
        };
        let Some(site_config_for_agent) = payload else {
            continue;
        };
        let command = ServerCommand {
            command_id: Uuid::new_v4().to_string(),
            r#type: command_type::UPDATE_SITE,
            issued_at: now_timestamp(),
            payload: Some(Payload::UpdateSite(UpdateSiteCommand {
                site_config: Some(site_config_for_agent),
            })),
        };
        if state.agents.send_command(&row.id, command).await {
            delivered += 1;
        }
    }

    if delivered == 0 {
        // A skipped push leaves the edge running stale configuration — an
        // agent-side task (like ACME issuance) that depends on this config
        // then never fires and the dashboard shows a wedged state. Surface
        // it loudly instead of at debug: this exact silence used to hide
        // agents auto-bound to a single site never learning about later
        // ones.
        tracing::warn!(
            %site_id,
            total = agents.len(),
            "no agent served this site, config change was not pushed — it \
             stays in the database until an agent syncs it"
        );
    } else {
        tracing::info!(
            %site_id,
            total = agents.len(),
            delivered,
            "config change pushed to agents"
        );
    }
}

/// Notifies every registered agent that a deployment-wide setting changed.
///
/// Meant for changes that land in *every* site's bundle (the global error
/// pages today): calling [`notify_config_changed`] per site would rebuild one
/// site at a time and fan a single edit out into as many database passes as
/// there are sites. Instead the affected site ids are collected from the agent
/// table and built in one pass; each agent then receives only its own site, the
/// same payload a normal push carries, so an agent's cache never grows beyond
/// the site it is bound to.
pub async fn notify_all_config_changed(state: &AppState, actor: Option<&str>) {
    let agents = match agent::Entity::find().all(&state.db).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(error = %err, "failed to list agents for config push");
            return;
        },
    };

    // The union of every agent's visible sites feeds the version snapshot.
    let mut visible_per_agent: HashMap<String, Vec<Uuid>> = HashMap::new();
    let mut all_site_ids: std::collections::HashSet<Uuid> =
        std::collections::HashSet::new();
    for row in &agents {
        match agent_visible_site_ids(&state.db, row).await {
            Ok(ids) => {
                all_site_ids.extend(ids.iter().copied());
                visible_per_agent.insert(row.id.to_string(), ids);
            },
            Err(err) => {
                tracing::warn!(
                    agent_id = %row.id,
                    error = %err,
                    "failed to resolve the sites of an agent"
                );
            },
        };
    }
    let site_ids: Vec<Uuid> = all_site_ids.into_iter().collect();
    let config = match build_site_config(&state.db, Some(&site_ids)).await {
        Ok(config) => config,
        Err(err) => {
            tracing::warn!(error = %err, "failed to build site config for push");
            return;
        },
    };

    // Global settings (defense mode, error pages) get their own version,
    // snapshotted from the tables that feed every site's bundle. Recorded
    // before the empty-registry bail-out: the change is committed either way.
    // Detached like the per-site path — the push must not wait on the
    // snapshot capture.
    let db = state.db.clone();
    let config_hash = config.config_hash.clone();
    let actor = actor.map(str::to_string);
    tokio::spawn(async move {
        if let Err(err) = config_history::record_version(
            &db,
            VersionScope::Global,
            config_version::source::API,
            actor.as_deref(),
            &config_hash,
        )
        .await
        {
            tracing::warn!(error = %err, "could not record the global configuration version");
        }
    });

    if agents.is_empty() {
        tracing::debug!("no agents registered, skipping config push");
        return;
    }

    // One bundle per distinct visibility set: unbound agents of one owner all
    // share the same payload, so it is built once.
    let mut bundle_cache: HashMap<Vec<Uuid>, SiteConfig> = HashMap::new();
    let mut delivered = 0usize;
    for row in &agents {
        let Some(visible) = visible_per_agent.get(&row.id.to_string()) else {
            continue;
        };
        if visible.is_empty() {
            // An agent with no sites has no bundle to receive.
            continue;
        }
        let payload = match bundle_cache.get(visible) {
            Some(config) => config.clone(),
            None => {
                let agent_config = match build_site_config(
                    &state.db,
                    Some(visible),
                )
                .await
                {
                    Ok(config) => config,
                    Err(err) => {
                        tracing::warn!(
                            agent_id = %row.id,
                            error = %err,
                            "failed to build the config payload for an agent"
                        );
                        continue;
                    },
                };
                bundle_cache.insert(visible.clone(), agent_config.clone());
                agent_config
            },
        };
        let command = ServerCommand {
            command_id: Uuid::new_v4().to_string(),
            r#type: command_type::UPDATE_SITE,
            issued_at: now_timestamp(),
            payload: Some(Payload::UpdateSite(UpdateSiteCommand {
                site_config: Some(payload),
            })),
        };
        if state.agents.send_command(&row.id, command).await {
            delivered += 1;
        }
    }

    tracing::info!(
        sites = site_ids.len(),
        total = agents.len(),
        delivered,
        "global config change pushed to agents"
    );
}
