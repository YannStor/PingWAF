//! Upstream backend health reporting for the heartbeat.
//!
//! The proxy's upstream provider is owned by the binary that wires the
//! proxy and the agent together; the agent crate only needs read access to
//! the load balancer's circuit-breaker state. The binary registers the
//! provider here after startup (mirroring
//! `pingap_performance::set_metrics_upstream_provider`), and every
//! heartbeat translates [`UpstreamProvider::healthy_status`] into the
//! proto message the control plane alerts on.

use std::sync::{Arc, OnceLock};

use pingap_upstream::UpstreamProvider;
use pingwaf_proto::control_plane as proto;

/// Process-wide upstream provider, installed by the host binary.
static UPSTREAM_PROVIDER: OnceLock<Arc<dyn UpstreamProvider>> = OnceLock::new();

/// Registers the process-wide upstream provider so heartbeats can report
/// per-backend health. Idempotent: the first call wins, matching the
/// `pingap_performance` pattern.
pub fn set_upstream_provider(provider: Arc<dyn UpstreamProvider>) {
    let _ = UPSTREAM_PROVIDER.set(provider);
}

/// Builds the per-upstream health report for the heartbeat. Empty when no
/// provider is installed (standalone mode) or the upstream map is empty,
/// which older control planes treat as "nothing to report".
pub fn heartbeat_statuses() -> Vec<proto::UpstreamHealth> {
    let Some(provider) = UPSTREAM_PROVIDER.get() else {
        return Vec::new();
    };
    provider
        .healthy_status()
        .into_iter()
        .map(|(name, status)| proto::UpstreamHealth {
            upstream_name: name,
            healthy_backends: status.healthy,
            total_backends: status.total,
            unhealthy_backends: status.unhealthy_backends,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_upstream::{Upstream, UpstreamHealthyStatus};
    use std::collections::HashMap;

    /// A provider with a fixed status map; keeps the test off the real
    /// balancer and lets each test install fresh state via a new provider
    /// value (the global slot is first-set-wins, so tests run serially).
    struct FixedProvider {
        status: HashMap<String, UpstreamHealthyStatus>,
    }

    impl UpstreamProvider for FixedProvider {
        fn get(&self, _name: &str) -> Option<Arc<Upstream>> {
            None
        }
        fn list(&self) -> Vec<(String, Arc<Upstream>)> {
            Vec::new()
        }
        fn healthy_status(&self) -> HashMap<String, UpstreamHealthyStatus> {
            self.status.clone()
        }
    }

    // OnceLock is first-set-wins and process-global; to make repeated
    // installs observable we assert on the *output*, installing only once
    // per process — the guard serializes the tests through one provider.
    fn install_once(
        provider: Arc<dyn UpstreamProvider>,
    ) -> &'static Arc<dyn UpstreamProvider> {
        match UPSTREAM_PROVIDER.set(provider) {
            Ok(()) => UPSTREAM_PROVIDER.get().expect("just set"),
            Err(_) => UPSTREAM_PROVIDER.get().expect("set by prior test"),
        }
    }

    #[test]
    fn heartbeat_statuses_map_provider_state_into_proto() {
        let mut status = HashMap::new();
        status.insert(
            "primary".to_string(),
            UpstreamHealthyStatus {
                healthy: 1,
                total: 3,
                unhealthy_backends: vec![
                    "10.0.0.2:80".to_string(),
                    "10.0.0.3:80".to_string(),
                ],
            },
        );
        let provider: Arc<dyn UpstreamProvider> =
            Arc::new(FixedProvider { status });
        install_once(provider);

        let statuses = heartbeat_statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].upstream_name, "primary");
        assert_eq!(statuses[0].healthy_backends, 1);
        assert_eq!(statuses[0].total_backends, 3);
        assert_eq!(statuses[0].unhealthy_backends.len(), 2);
        assert!(statuses[0].unhealthy_backends[0].contains("10.0.0.2"));
    }
}
