//! Site upstream health alerts, fed by the upstream-health section of
//! agent heartbeats.
//!
//! Every heartbeat carries the per-upstream backend counts as seen by that
//! edge's load balancer (circuit-breaker state, not an active probe). A
//! single blip — one backend probe timing out while the breaker resets —
//! must not page anyone, so a degrade or recovery is only confirmed after
//! [`SUSTAINED_SAMPLES`] consecutive heartbeats classify the same way, the
//! same debounce `self_monitor` uses for its thresholds. The channel-level
//! dedup window then guards against repeats after a control-plane restart.
//!
//! The first report for an (agent, upstream) pair initializes the tracker
//! without alerting: at startup every upstream would otherwise look like a
//! fresh transition. Upstreams that stop being reported (removed from the
//! config) are dropped silently — there is no comparable signal.
//!
//! Classification:
//! * `total == 0` — not observed, skipped.
//! * `healthy == 0` — [`UpstreamState::Offline`]: all backends down,
//!   `site.upstream_offline` (critical).
//! * `healthy < total` — [`UpstreamState::Abnormal`]: reduced capacity but
//!   traffic still flows, `site.upstream_abnormal` (warning).
//! * otherwise — [`UpstreamState::Healthy`]; a transition *into* healthy
//!   from a degraded state is the recovery event, reported as
//!   `site.upstream_offline` with `info` severity so one subscription
//!   covers the whole lifecycle.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use sea_orm::EntityTrait;
use uuid::Uuid;

use super::AlertEvent;
use crate::models::{event_type, severity};

/// Consecutive same-classification heartbeats before a transition is
/// confirmed and an alert is raised. 2 = one degraded heartbeat never
/// pages; the second one does.
const SUSTAINED_SAMPLES: u32 = 2;

/// Classified health of one upstream on one agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamState {
    /// All backends passing health checks.
    Healthy,
    /// Some backends failing; capacity reduced.
    Abnormal,
    /// Every backend failing; the site cannot be served from this agent.
    Offline,
}

impl UpstreamState {
    /// Lowercase wire label used in event details.
    fn label(self) -> &'static str {
        match self {
            UpstreamState::Healthy => "healthy",
            UpstreamState::Abnormal => "abnormal",
            UpstreamState::Offline => "offline",
        }
    }

    /// Maps a heartbeat report to a state; `None` when the upstream has no
    /// backends to judge (nothing to report, nothing to alert on).
    fn classify(healthy: u32, total: u32) -> Option<Self> {
        if total == 0 {
            return None;
        }
        if healthy == 0 {
            Some(UpstreamState::Offline)
        } else if healthy < total {
            Some(UpstreamState::Abnormal)
        } else {
            Some(UpstreamState::Healthy)
        }
    }
}

/// One upstream as reported by one heartbeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamReport {
    pub upstream_name: String,
    pub healthy_backends: u32,
    pub total_backends: u32,
    pub unhealthy_backends: Vec<String>,
}

/// Tracker entry per (agent, upstream).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tracked {
    state: UpstreamState,
    /// State the pending run is converging to.
    pending_state: UpstreamState,
    /// Consecutive heartbeats classifying as `pending_state`.
    pending_count: u32,
    unhealthy_backends: Vec<String>,
}

/// A confirmed transition worth alerting on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub upstream_name: String,
    pub from: UpstreamState,
    pub to: UpstreamState,
    pub healthy_backends: u32,
    pub total_backends: u32,
    pub unhealthy_backends: Vec<String>,
}

/// Folds heartbeats into confirmed transitions. Pure below the `Mutex` —
/// the DB and notification side effects live in [`record_heartbeat`].
pub struct UpstreamMonitor {
    tracked: Mutex<HashMap<(Uuid, String), Tracked>>,
}

impl Default for UpstreamMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamMonitor {
    pub fn new() -> Self {
        Self {
            tracked: Mutex::new(HashMap::new()),
        }
    }

    /// Folds one agent's heartbeat reports into the tracker and returns
    /// the transitions confirmed by this beat.
    pub fn observe(
        &self,
        agent_id: Uuid,
        reports: &[UpstreamReport],
    ) -> Vec<Transition> {
        let mut tracked = self
            .tracked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut transitions = Vec::new();

        for report in reports {
            let Some(observed) = UpstreamState::classify(
                report.healthy_backends,
                report.total_backends,
            ) else {
                continue;
            };
            let key = (agent_id, report.upstream_name.clone());
            let Some(entry) = tracked.get_mut(&key) else {
                // First sight: adopt the state without alerting so a
                // restart of the agent or the control plane is not a
                // fleet-wide "down" storm.
                tracked.insert(
                    key,
                    Tracked {
                        state: observed,
                        pending_state: observed,
                        pending_count: 0,
                        unhealthy_backends: report.unhealthy_backends.clone(),
                    },
                );
                continue;
            };

            entry.unhealthy_backends = report.unhealthy_backends.clone();
            if entry.state == observed {
                // Steady: any pending run is voided by the flip-flop.
                entry.pending_count = 0;
                entry.pending_state = observed;
                continue;
            }
            if entry.pending_state == observed {
                entry.pending_count += 1;
            } else {
                entry.pending_state = observed;
                entry.pending_count = 1;
            }
            if entry.pending_count >= SUSTAINED_SAMPLES {
                transitions.push(Transition {
                    upstream_name: report.upstream_name.clone(),
                    from: entry.state,
                    to: observed,
                    healthy_backends: report.healthy_backends,
                    total_backends: report.total_backends,
                    unhealthy_backends: report.unhealthy_backends.clone(),
                });
                entry.state = observed;
                entry.pending_count = 0;
                entry.pending_state = observed;
            }
        }

        // Upstreams that vanished from the report no longer exist on the
        // edge; dropping them keeps the map bounded by what is actually
        // configured. Only this agent's rows are pruned — other agents'
        // trackers are untouched.
        let seen: std::collections::HashSet<String> = reports
            .iter()
            .filter(|r| r.total_backends > 0)
            .map(|r| r.upstream_name.clone())
            .collect();
        tracked.retain(|(tracked_agent, name), _| {
            *tracked_agent != agent_id || seen.contains(name)
        });

        transitions
    }
}

/// Process-wide monitor; one entry per (agent, upstream) pair actually
/// reporting health.
static MONITOR: OnceLock<UpstreamMonitor> = OnceLock::new();

fn monitor() -> &'static UpstreamMonitor {
    MONITOR.get_or_init(UpstreamMonitor::new)
}

/// Folds one heartbeat into the global monitor and emits an
/// [`AlertEvent`] per confirmed transition. Best-effort: enrichment
/// failures are logged and the alert is still emitted without the site
/// names.
pub async fn record_heartbeat(
    db: &sea_orm::DatabaseConnection,
    agent_id: Uuid,
    reports: &[UpstreamReport],
) {
    let transitions = monitor().observe(agent_id, reports);
    if transitions.is_empty() {
        return;
    }

    let agent_name = crate::models::agent::Entity::find_by_id(agent_id)
        .one(db)
        .await
        .ok()
        .flatten()
        .map(|row| row.hostname)
        .unwrap_or_else(|| agent_id.to_string());

    for transition in transitions {
        // Which sites route to this upstream, for the message body.
        let site_names = site_names_for_upstream(db, &transition.upstream_name)
            .await
            .unwrap_or_default();

        let upstream_name = &transition.upstream_name;
        let offline = transition.to == UpstreamState::Offline;
        let recovery = transition.to == UpstreamState::Healthy;
        let (event_type, sev) = if recovery {
            (event_type::SITE_UPSTREAM_OFFLINE, severity::INFO)
        } else if offline {
            (event_type::SITE_UPSTREAM_OFFLINE, severity::CRITICAL)
        } else {
            (event_type::SITE_UPSTREAM_ABNORMAL, severity::WARNING)
        };
        let what = if recovery {
            "recovered"
        } else if offline {
            "offline"
        } else {
            "degraded"
        };
        let sites_note = if site_names.is_empty() {
            "no site mapping".to_string()
        } else {
            site_names.join(", ")
        };
        let title = format!(
            "Upstream '{upstream_name}' is {what} on agent '{agent_name}'"
        );
        let message = if recovery {
            format!(
                "Upstream '{upstream_name}' is back to full capacity on \
                 agent '{agent_name}' (all {total} backends healthy). \
                 Sites: {sites_note}.",
                total = transition.total_backends,
            )
        } else {
            format!(
                "Upstream '{upstream_name}' on agent '{agent_name}': \
                 {healthy} of {total} backends healthy, failing: \
                 [{failing}]. Sites: {sites_note}.",
                healthy = transition.healthy_backends,
                total = transition.total_backends,
                failing = transition.unhealthy_backends.join(", "),
            )
        };
        let details = serde_json::json!({
            "upstream_name": transition.upstream_name,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "sites": site_names,
            "previous_state": transition.from.label(),
            "current_state": transition.to.label(),
            "healthy_backends": transition.healthy_backends,
            "total_backends": transition.total_backends,
            "unhealthy_backends": transition.unhealthy_backends,
        });
        super::emit(AlertEvent {
            event_type: event_type.to_string(),
            severity: sev,
            title,
            message,
            details: Some(details),
            dedup_key: Some(format!(
                "{agent_id}:{upstream_name}",
                upstream_name = transition.upstream_name
            )),
        })
        .await;
    }
}

/// Domains of the sites whose upstream list contains `upstream_name`.
/// Best-effort: an empty list still produces a useful alert naming the
/// upstream and agent.
async fn site_names_for_upstream(
    db: &sea_orm::DatabaseConnection,
    upstream_name: &str,
) -> Result<Vec<String>, sea_orm::DbErr> {
    use crate::models::{site, site_upstreams};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    let rows = site_upstreams::Entity::find()
        .filter(site_upstreams::Column::Name.eq(upstream_name))
        .all(db)
        .await?;
    let site_ids: Vec<Uuid> = rows.iter().map(|row| row.site_id).collect();
    if site_ids.is_empty() {
        return Ok(Vec::new());
    }
    let site_rows = site::Entity::find()
        .filter(site::Column::Id.is_in(site_ids))
        .all(db)
        .await?;
    Ok(site_rows.iter().map(|row| row.domain.clone()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(name: &str, healthy: u32, total: u32) -> UpstreamReport {
        UpstreamReport {
            upstream_name: name.to_string(),
            healthy_backends: healthy,
            total_backends: total,
            unhealthy_backends: (0..total.saturating_sub(healthy))
                .map(|i| format!("10.0.0.{i}:80"))
                .collect(),
        }
    }

    #[test]
    fn first_sight_initializes_without_alerting() {
        let monitor = UpstreamMonitor::new();
        let agent = Uuid::new_v4();
        // A brand-new agent reporting an already-dead upstream must not
        // page on its first heartbeat: it would storm after every
        // restart.
        let transitions = monitor.observe(agent, &[report("primary", 0, 2)]);
        assert!(transitions.is_empty());
    }

    #[test]
    fn offline_confirmed_after_sustained_samples() {
        let monitor = UpstreamMonitor::new();
        let agent = Uuid::new_v4();
        // Beat 1 initializes as healthy.
        assert!(monitor
            .observe(agent, &[report("primary", 2, 2)])
            .is_empty());
        // Beat 2: first degraded sample — pending, no alert.
        assert!(monitor
            .observe(agent, &[report("primary", 0, 2)])
            .is_empty());
        // Beat 3: second consecutive degraded sample — confirmed.
        let transitions = monitor.observe(agent, &[report("primary", 0, 2)]);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].from, UpstreamState::Healthy);
        assert_eq!(transitions[0].to, UpstreamState::Offline);
        assert_eq!(transitions[0].healthy_backends, 0);
        assert_eq!(transitions[0].unhealthy_backends.len(), 2);
    }

    #[test]
    fn single_blip_does_not_alert() {
        let monitor = UpstreamMonitor::new();
        let agent = Uuid::new_v4();
        assert!(monitor
            .observe(agent, &[report("primary", 2, 2)])
            .is_empty());
        // One bad beat...
        assert!(monitor
            .observe(agent, &[report("primary", 0, 2)])
            .is_empty());
        // ...then healthy again: the pending run is voided, steady state.
        assert!(monitor
            .observe(agent, &[report("primary", 2, 2)])
            .is_empty());
        // A single further bad beat still holds.
        assert!(monitor
            .observe(agent, &[report("primary", 0, 2)])
            .is_empty());
        assert!(monitor
            .observe(agent, &[report("primary", 2, 2)])
            .is_empty());
    }

    #[test]
    fn partial_loss_is_abnormal_not_offline() {
        let monitor = UpstreamMonitor::new();
        let agent = Uuid::new_v4();
        assert!(monitor.observe(agent, &[report("pool", 3, 3)]).is_empty());
        assert!(monitor.observe(agent, &[report("pool", 1, 3)]).is_empty());
        let transitions = monitor.observe(agent, &[report("pool", 1, 3)]);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].to, UpstreamState::Abnormal);
    }

    #[test]
    fn recovery_confirmed_after_sustained_samples() {
        let monitor = UpstreamMonitor::new();
        let agent = Uuid::new_v4();
        for _ in 0..3 {
            monitor.observe(agent, &[report("primary", 0, 2)]);
        }
        // Two healthy beats confirm the recovery.
        assert!(monitor
            .observe(agent, &[report("primary", 2, 2)])
            .is_empty());
        let transitions = monitor.observe(agent, &[report("primary", 2, 2)]);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].from, UpstreamState::Offline);
        assert_eq!(transitions[0].to, UpstreamState::Healthy);
    }

    #[test]
    fn zero_total_upstreams_are_ignored_and_dropped() {
        let monitor = UpstreamMonitor::new();
        let agent = Uuid::new_v4();
        assert!(monitor.observe(agent, &[report("empty", 0, 0)]).is_empty());
        // A zero-total report never initializes tracking, and a previously
        // tracked upstream whose total collapses to zero is dropped
        // rather than misclassified as offline.
        assert!(monitor.observe(agent, &[report("gone", 2, 2)]).is_empty());
        assert!(monitor.observe(agent, &[report("gone", 0, 0)]).is_empty());
        // The zero-total beat dropped "gone" from the map: the next
        // real report re-initializes instead of transitioning.
        assert!(monitor.observe(agent, &[report("gone", 0, 2)]).is_empty());
    }

    #[test]
    fn agents_are_tracked_independently() {
        let monitor = UpstreamMonitor::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        // Agent A's upstream dies; agent B's copy stays healthy and must
        // not inherit the transition.
        monitor.observe(a, &[report("primary", 2, 2)]);
        monitor.observe(b, &[report("primary", 2, 2)]);
        monitor.observe(a, &[report("primary", 0, 2)]);
        assert!(monitor.observe(b, &[report("primary", 2, 2)]).is_empty());
        let transitions = monitor.observe(a, &[report("primary", 0, 2)]);
        assert_eq!(transitions.len(), 1);
    }

    #[test]
    fn classification_boundaries() {
        assert_eq!(UpstreamState::classify(0, 0), None);
        assert_eq!(
            UpstreamState::classify(2, 3),
            Some(UpstreamState::Abnormal)
        );
        assert_eq!(UpstreamState::classify(0, 3), Some(UpstreamState::Offline));
        assert_eq!(UpstreamState::classify(3, 3), Some(UpstreamState::Healthy));
    }
}
