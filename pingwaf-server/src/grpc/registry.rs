//! In-memory registry of agents that currently hold an open `Heartbeat` stream.
//!
//! The control plane pushes commands to agents over the bidirectional heartbeat
//! stream, so the REST API needs a way to reach a live stream from a handler
//! that knows nothing about gRPC. [`AgentRegistry`] is that bridge: the gRPC
//! service registers a sender when a stream opens, and API handlers call
//! [`AgentRegistry::send_command`].
//!
//! Agents that are not connected get their commands queued (bounded) and
//! drained on the next heartbeat, so a rule change issued from the dashboard is
//! never silently lost as long as the agent reconnects.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use pingwaf_proto::control_plane::ServerCommand;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

/// Buffer depth of the per-agent command channel.
pub const COMMAND_CHANNEL_CAPACITY: usize = 64;
/// Maximum number of commands retained for an agent that is currently offline.
pub const PENDING_COMMAND_LIMIT: usize = 64;

struct Connection {
    sender: mpsc::Sender<ServerCommand>,
    connected_at: DateTime<Utc>,
    /// Monotonic per-registry stream id. Teardown only removes the entry
    /// when this id still matches, so a stale stream finishing after the
    /// agent reconnected cannot delete the live connection (2026-10-18
    /// audit: the old stream used to mark the new one offline).
    generation: u64,
}

#[derive(Default)]
struct Inner {
    connected: HashMap<Uuid, Connection>,
    pending: HashMap<Uuid, VecDeque<ServerCommand>>,
    next_generation: u64,
}

/// Cheap-to-clone handle to the live agent connections.
#[derive(Clone, Default)]
pub struct AgentRegistry {
    inner: Arc<RwLock<Inner>>,
}

/// Snapshot of one live connection, used by the `/api/v1/agents` endpoints.
#[derive(Debug, Clone)]
pub struct ConnectedAgent {
    pub id: Uuid,
    pub connected_at: DateTime<Utc>,
    pub queued_commands: usize,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches a freshly opened heartbeat stream and returns everything that
    /// was queued while the agent was away.
    pub async fn connect(
        &self,
        agent_id: Uuid,
        sender: mpsc::Sender<ServerCommand>,
    ) -> (u64, VecDeque<ServerCommand>) {
        let mut inner = self.inner.write().await;
        inner.next_generation = inner.next_generation.wrapping_add(1);
        let generation = inner.next_generation;
        inner.connected.insert(
            agent_id,
            Connection {
                sender,
                connected_at: Utc::now(),
                generation,
            },
        );
        let drained = inner.pending.remove(&agent_id).unwrap_or_default();
        if !drained.is_empty() {
            tracing::info!(
                %agent_id,
                queued = drained.len(),
                "delivering commands queued while the agent was offline"
            );
        }
        (generation, drained)
    }

    /// Drops the connection when a heartbeat stream ends. Only the stream
    /// that owns the current generation may remove it (see [`Connection`]).
    pub async fn disconnect(&self, agent_id: &Uuid, generation: u64) {
        let mut inner = self.inner.write().await;
        let current = inner
            .connected
            .get(agent_id)
            .map(|connection| connection.generation);
        match current {
            Some(current) if current == generation => {
                inner.connected.remove(agent_id);
                tracing::debug!(%agent_id, "agent heartbeat stream closed");
            },
            Some(_) => {
                tracing::debug!(
                    %agent_id,
                    "stale heartbeat stream closed; keeping the live connection"
                );
            },
            None => {},
        }
    }

    /// Unconditionally drops the connection (REST-triggered disconnect, where
    /// the caller has no stream generation). The stream's own teardown then
    /// sees no matching entry and does nothing.
    pub async fn force_disconnect(&self, agent_id: &Uuid) {
        let mut inner = self.inner.write().await;
        if inner.connected.remove(agent_id).is_some() {
            tracing::debug!(%agent_id, "agent connection closed by request");
        }
    }

    /// Forgets queued commands for agents that no longer exist. Called by
    /// the offline-agent sweep so `pending` cannot outlive the rows it
    /// belongs to.
    pub async fn forget(&self, agent_ids: &[Uuid]) {
        if agent_ids.is_empty() {
            return;
        }
        let mut inner = self.inner.write().await;
        let mut dropped = 0usize;
        for agent_id in agent_ids {
            if inner.pending.remove(agent_id).is_some() {
                dropped += 1;
            }
        }
        if dropped > 0 {
            tracing::info!(
                agents = dropped,
                "dropped queued commands for pruned agents"
            );
        }
    }

    /// True when the agent currently holds an open stream.
    pub async fn is_connected(&self, agent_id: &Uuid) -> bool {
        self.inner.read().await.connected.contains_key(agent_id)
    }

    /// Number of agents with a live stream.
    pub async fn connected_count(&self) -> usize {
        self.inner.read().await.connected.len()
    }

    /// Live connections with their queue depth.
    pub async fn snapshot(&self) -> Vec<ConnectedAgent> {
        let inner = self.inner.read().await;
        let mut out: Vec<ConnectedAgent> = inner
            .connected
            .iter()
            .map(|(id, conn)| ConnectedAgent {
                id: *id,
                connected_at: conn.connected_at,
                queued_commands: inner
                    .pending
                    .get(id)
                    .map(|q| q.len())
                    .unwrap_or(0),
            })
            .collect();
        out.sort_by_key(|agent| agent.connected_at);
        out
    }

    /// Sends a command immediately when the agent is connected, otherwise queues
    /// it for the next heartbeat.
    ///
    /// Returns `true` when the command was delivered on a live stream.
    pub async fn send_command(
        &self,
        agent_id: &Uuid,
        command: ServerCommand,
    ) -> bool {
        // Grab the sender while holding the read lock only: `send().await`
        // must not block other registry operations.
        let sender = {
            let inner = self.inner.read().await;
            inner.connected.get(agent_id).map(|c| c.sender.clone())
        };

        if let Some(sender) = sender {
            match sender.try_send(command) {
                Ok(()) => {
                    tracing::debug!(%agent_id, "command pushed to agent");
                    return true;
                },
                Err(mpsc::error::TrySendError::Full(command)) => {
                    tracing::warn!(%agent_id, "agent command channel full, queueing instead");
                    self.enqueue(agent_id, command).await;
                    return false;
                },
                Err(mpsc::error::TrySendError::Closed(command)) => {
                    tracing::debug!(%agent_id, "agent stream closed, queueing command");
                    self.enqueue(agent_id, command).await;
                    return false;
                },
            }
        }

        self.enqueue(agent_id, command).await;
        false
    }

    /// Pushes a command to every connected agent, queueing for the offline ones.
    ///
    /// Returns how many agents received it live.
    pub async fn broadcast(
        &self,
        build: impl Fn(Uuid) -> ServerCommand,
    ) -> usize {
        let ids: Vec<Uuid> = {
            let inner = self.inner.read().await;
            inner.connected.keys().copied().collect()
        };
        let mut delivered = 0;
        for id in ids {
            if self.send_command(&id, build(id)).await {
                delivered += 1;
            }
        }
        delivered
    }

    /// Number of commands waiting for an offline agent.
    pub async fn pending_count(&self, agent_id: &Uuid) -> usize {
        self.inner
            .read()
            .await
            .pending
            .get(agent_id)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    async fn enqueue(&self, agent_id: &Uuid, command: ServerCommand) {
        let mut inner = self.inner.write().await;
        let queue = inner.pending.entry(*agent_id).or_default();
        if queue.len() >= PENDING_COMMAND_LIMIT {
            // Drop the oldest command rather than growing without bound.
            queue.pop_front();
        }
        queue.push_back(command);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingwaf_proto::control_plane::RestartAgentCommand;

    fn restart(reason: &str) -> ServerCommand {
        ServerCommand {
            command_id: Uuid::new_v4().to_string(),
            r#type: 7, // COMMAND_RESTART_AGENT
            issued_at: None,
            payload: Some(pingwaf_proto::control_plane::server_command::Payload::RestartAgent(
                RestartAgentCommand {
                    reason: reason.to_string(),
                    graceful: true,
                },
            )),
        }
    }

    #[tokio::test]
    async fn commands_are_queued_while_offline_and_drained_on_connect() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();

        registry.send_command(&agent, restart("a")).await;
        assert_eq!(registry.pending_count(&agent).await, 1);

        let (tx, mut rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (generation, drained) = registry.connect(agent, tx).await;
        assert_eq!(drained.len(), 1);
        assert_eq!(registry.pending_count(&agent).await, 0);
        assert!(registry.is_connected(&agent).await);

        assert!(registry.send_command(&agent, restart("b")).await);
        assert!(rx.try_recv().is_ok());

        registry.disconnect(&agent, generation).await;
        assert!(!registry.is_connected(&agent).await);

        // A stale stream (older generation) must not remove a live one.
        let (tx, _rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (new_generation, _) = registry.connect(agent, tx).await;
        registry.disconnect(&agent, generation).await;
        assert!(registry.is_connected(&agent).await);
        registry.disconnect(&agent, new_generation).await;
        assert!(!registry.is_connected(&agent).await);
    }

    #[tokio::test]
    async fn pending_queue_is_bounded() {
        let registry = AgentRegistry::new();
        let agent = Uuid::new_v4();
        for i in 0..(PENDING_COMMAND_LIMIT + 10) {
            registry
                .send_command(&agent, restart(&format!("cmd-{i}")))
                .await;
        }
        assert_eq!(registry.pending_count(&agent).await, PENDING_COMMAND_LIMIT);
    }
}
