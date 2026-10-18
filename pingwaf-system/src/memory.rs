//! Process and host memory snapshot for the dashboard.
//!
//! Three scopes are reported side by side so a small container reading is
//! never mistaken for host usage (or the other way round):
//!
//! * `process` — this binary's RSS/virtual bytes (`memory-stats`).
//! * `system` — the machine's total/used memory (sysinfo).
//! * container — the cgroup accounting, present only under a memory-limited
//!   cgroup.

use std::time::{SystemTime, UNIX_EPOCH};

use bytesize::ByteSize;
use serde::Serialize;

use crate::cgroup;

/// Memory usage of this process and the machine.
#[derive(Debug, Clone, Serialize)]
pub struct MemorySnapshot {
    /// Process RSS in bytes.
    pub rss_bytes: u64,
    /// Process virtual memory in bytes.
    pub virtual_bytes: u64,
    /// Machine (or cgroup) total memory in bytes.
    pub total_memory_bytes: u64,
    /// Machine used memory in bytes.
    pub used_memory_bytes: u64,
    /// Human-readable RSS.
    pub rss: String,
    /// Human-readable machine total.
    pub total_memory: String,
    /// Human-readable machine used.
    pub used_memory: String,
    /// Unix epoch milliseconds at which the snapshot was taken.
    pub collected_at_ms: u64,
    /// Scope label of `used_memory` (`"system"`).
    pub used_memory_scope: &'static str,
    /// Scope label of `rss` (`"process"`).
    pub process_memory_scope: &'static str,
    /// Container usage in bytes, when a cgroup limit applies.
    pub container_memory_used_bytes: Option<u64>,
    /// Container limit in bytes, when one is set.
    pub container_memory_limit_bytes: Option<u64>,
    /// Human-readable container usage.
    pub container_memory_used: Option<String>,
    /// Human-readable container limit.
    pub container_memory_limit: Option<String>,
    /// Which cgroup version produced the container numbers.
    pub container_memory_scope: Option<&'static str>,
}

/// Collects a [`MemorySnapshot`]. Cheap enough for a polling dashboard.
pub fn memory_snapshot() -> MemorySnapshot {
    let (rss_bytes, virtual_bytes) = match memory_stats::memory_stats() {
        Some(stats) => (stats.physical_mem as u64, stats.virtual_mem as u64),
        None => (0, 0),
    };
    let kind = sysinfo::MemoryRefreshKind::nothing().with_ram();
    let mut sys = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing().with_memory(kind),
    );
    sys.refresh_memory();
    let container = cgroup::container_memory();
    let collected_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default();
    MemorySnapshot {
        rss_bytes,
        virtual_bytes,
        total_memory_bytes: sys.total_memory(),
        used_memory_bytes: sys.used_memory(),
        rss: ByteSize(rss_bytes).to_string(),
        total_memory: ByteSize(sys.total_memory()).to_string(),
        used_memory: ByteSize(sys.used_memory()).to_string(),
        collected_at_ms,
        used_memory_scope: "system",
        process_memory_scope: "process",
        container_memory_used_bytes: container.as_ref().map(|c| c.used_bytes),
        container_memory_limit_bytes: container.and_then(|c| c.limit_bytes),
        container_memory_used: container
            .as_ref()
            .map(|c| ByteSize(c.used_bytes).to_string()),
        container_memory_limit: container
            .and_then(|c| c.limit_bytes)
            .map(|limit| ByteSize(limit).to_string()),
        container_memory_scope: container.map(|c| c.version.scope_label()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_is_plausible() {
        let snapshot = memory_snapshot();
        assert!(snapshot.collected_at_ms > 0);
        assert!(snapshot.rss_bytes > 0, "process RSS should be visible");
        assert!(!snapshot.rss.is_empty());
        // A container limit may be absent, but when present it is positive.
        if let Some(limit) = snapshot.container_memory_limit_bytes {
            assert!(limit > 0);
        }
    }
}
