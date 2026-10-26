//! Control plane self-monitoring: periodic CPU / memory / disk sampling with
//! threshold alerts through the notification system.
//!
//! The checks run in a background task started by [`start_server`]. An alert
//! only fires after the metric has been over its threshold for two
//! consecutive samples, so a single busy minute does not page anyone; the
//! notification dedup window stops a sustained breach from repeating.

use sysinfo::System;

use super::AlertEvent;
use crate::api::state::AppState;
use crate::models::{event_type, severity};

/// How often the control plane samples itself.
const SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// Consecutive over-threshold samples before an alert is raised.
const SUSTAINED_SAMPLES: u8 = 2;

/// One self-monitoring sample.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub cpu_percent: f32,
    pub memory_percent: f32,
    /// Root filesystem usage; `None` when no mounted filesystem reports a
    /// mount point that resolves to `/`.
    pub disk_percent: Option<f32>,
}

/// Samples the current CPU, memory and root-disk utilisation.
///
/// CPU usage is a delta between two refreshes, so the call takes a short
/// pause between them; the monitor invokes it through `spawn_blocking` so the
/// pause never occupies a Tokio runtime worker.
pub fn sample() -> Sample {
    let mut system = System::new();
    system.refresh_cpu_usage();
    system.refresh_memory();
    std::thread::sleep(std::time::Duration::from_millis(250));
    system.refresh_cpu_usage();

    let cpu_percent = system.global_cpu_usage();
    let total = system.total_memory();
    let memory_percent = if total > 0 {
        (system.used_memory() as f32 / total as f32) * 100.0
    } else {
        0.0
    };
    let disk_percent = root_disk_percent();

    Sample {
        cpu_percent,
        memory_percent,
        disk_percent,
    }
}

/// Usage percentage of the filesystem mounted at `/`.
fn root_disk_percent() -> Option<f32> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    for disk in disks.list() {
        let mounted = disk.mount_point();
        let is_root = mounted == std::path::Path::new("/")
            || mounted
                .canonicalize()
                .map(|path| path == std::path::Path::new("/"))
                .unwrap_or(false);
        if is_root {
            let total = disk.total_space();
            if total > 0 {
                let used = total.saturating_sub(disk.available_space());
                return Some((used as f32 / total as f32) * 100.0);
            }
            return None;
        }
    }
    None
}

/// A metric over its threshold, with the severity it should carry.
struct Breach {
    label: &'static str,
    value: f32,
    threshold: u8,
}

impl Breach {
    fn severity(&self) -> &'static str {
        if self.value >= f32::from(self.threshold) + 5.0 {
            severity::CRITICAL
        } else {
            severity::WARNING
        }
    }

    fn event(&self, dedup_key: &str) -> AlertEvent {
        AlertEvent {
            event_type: event_type::CONTROL_PLANE_RESOURCE.to_string(),
            severity: self.severity(),
            title: format!("Control plane {} usage high", self.label),
            message: format!(
                "Control plane {} usage is {:.1}% (threshold {}%). \
                 Check the control plane host before it affects the \
                 dashboard or the agent sync.",
                self.label, self.value, self.threshold
            ),
            details: Some(serde_json::json!({
                "metric": self.label,
                "value_percent": format!("{:.1}", self.value),
                "threshold_percent": self.threshold,
            })),
            dedup_key: Some(dedup_key.to_string()),
        }
    }
}

/// Metrics over their thresholds in one sample.
fn breaches(
    sample: Sample,
    settings: &super::NotificationSettings,
) -> Vec<Breach> {
    let mut found = Vec::new();
    if sample.cpu_percent >= f32::from(settings.cpu_percent) {
        found.push(Breach {
            label: "CPU",
            value: sample.cpu_percent,
            threshold: settings.cpu_percent,
        });
    }
    if sample.memory_percent >= f32::from(settings.memory_percent) {
        found.push(Breach {
            label: "memory",
            value: sample.memory_percent,
            threshold: settings.memory_percent,
        });
    }
    if let Some(disk) = sample.disk_percent {
        if disk >= f32::from(settings.disk_percent) {
            found.push(Breach {
                label: "disk",
                value: disk,
                threshold: settings.disk_percent,
            });
        }
    }
    found
}

/// Starts the self-monitoring loop.
pub fn start(_state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("control plane self-monitor started");
        let mut strikes: std::collections::HashMap<&'static str, u8> =
            std::collections::HashMap::new();
        loop {
            tokio::time::sleep(SAMPLE_INTERVAL).await;
            let Some(manager) = super::global() else {
                continue;
            };
            // `sample()` deliberately sleeps 250ms between CPU refreshes.
            // Run it on the blocking pool so that pause never parks a Tokio
            // worker that the control-plane listener needs.
            let current = match tokio::task::spawn_blocking(sample).await {
                Ok(sample) => sample,
                Err(err) => {
                    tracing::warn!(error = %err, "control plane self-monitor sample failed");
                    continue;
                },
            };
            let found = breaches(current, &manager.settings());

            for breach in &found {
                let count =
                    strikes.entry(breach.label).or_insert(0).saturating_add(1);
                strikes.insert(breach.label, count);
                // Fires once per sustained breach; repeats inside the window
                // are suppressed by the channel dedup.
                if count == SUSTAINED_SAMPLES {
                    let event = breach.event(breach.label);
                    manager.dispatch(event).await;
                }
            }
            // A metric that dropped below its threshold starts counting afresh.
            for label in ["CPU", "memory", "disk"] {
                if !found.iter().any(|breach| breach.label == label) {
                    strikes.remove(label);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breaches_respect_the_thresholds() {
        let settings = super::super::NotificationSettings {
            cpu_percent: 80,
            memory_percent: 90,
            disk_percent: 95,
            ..Default::default()
        };
        let found = breaches(
            Sample {
                cpu_percent: 85.0,
                memory_percent: 50.0,
                disk_percent: Some(96.0),
            },
            &settings,
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].label, "CPU");
        assert_eq!(found[1].label, "disk");
    }

    #[test]
    fn severe_breaches_escalate_to_critical() {
        let settings = super::super::NotificationSettings::default();
        let found = breaches(
            Sample {
                cpu_percent: 99.0,
                memory_percent: 10.0,
                disk_percent: None,
            },
            &settings,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity(), severity::CRITICAL);

        let found = breaches(
            Sample {
                cpu_percent: 90.5,
                memory_percent: 10.0,
                disk_percent: None,
            },
            &settings,
        );
        assert_eq!(found[0].severity(), severity::WARNING);
    }

    #[test]
    fn a_missing_disk_sample_is_not_a_breach() {
        let found = breaches(
            Sample {
                cpu_percent: 0.0,
                memory_percent: 0.0,
                disk_percent: None,
            },
            &super::super::NotificationSettings {
                disk_percent: 0,
                ..Default::default()
            },
        );
        assert!(found.is_empty());
    }
}
