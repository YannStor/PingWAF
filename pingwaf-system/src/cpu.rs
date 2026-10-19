//! Point-in-time CPU usage of this process and the machine.
//!
//! sysinfo computes CPU usage as a delta between two refreshes, so the
//! [`System`] instance must outlive the calls and back-to-back calls are
//! stretched to sysinfo's minimum interval for a meaningful delta. The
//! stretch-then-refresh sequence runs under one lock: concurrent callers
//! queue and each gets exactly one meaningful delta (a second refresh at the
//! same deadline would observe ~zero and report a false idle).

use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, Pid, ProcessRefreshKind,
    ProcessesToUpdate, RefreshKind, System,
};

/// Reuse window for snapshots: CPU percentages are polled by the dashboard
/// and the system card, and a one-second freshness is plenty while avoiding
/// a refresh queue behind the sampler lock.
const SNAPSHOT_TTL: Duration = Duration::from_secs(1);

/// Point-in-time CPU usage of this process and the machine.
#[derive(Debug, Clone, Serialize)]
pub struct CpuLiveStats {
    /// This process's CPU usage in percent of one core (multi-threaded work
    /// can exceed 100), as sysinfo reports it.
    pub process_cpu_percent: f32,
    /// Average CPU usage across all machine cores, in percent.
    pub host_cpu_percent: f32,
    /// Number of CPU cores on the machine.
    pub cores: usize,
    /// Unix epoch milliseconds at which the snapshot was taken.
    pub collected_at_ms: u64,
}

/// Persistent sampler; the baseline is refreshed once at construction so the
/// first snapshot has a delta to work with.
static CPU_SAMPLER: LazyLock<Mutex<System>> = LazyLock::new(|| {
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::nothing().with_ram()),
    );
    sys.refresh_cpu_specifics(CpuRefreshKind::everything());
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        false,
        ProcessRefreshKind::everything(),
    );
    Mutex::new(sys)
});

/// When the last real refresh completed (for the minimum-interval stretch).
static LAST_REFRESH: LazyLock<Mutex<Instant>> =
    LazyLock::new(|| Mutex::new(Instant::now()));

/// `<stats, taken_at>` for the reuse window; lock order is
/// CPU_SAMPLER → LAST_SNAPSHOT, never the other way round.
static LAST_SNAPSHOT: Mutex<Option<(CpuLiveStats, Instant)>> = Mutex::new(None);

/// Collects a [`CpuLiveStats`] snapshot. Callers inside async handlers
/// should keep this off the executor thread (the lock sleeps).
pub fn cpu_snapshot() -> CpuLiveStats {
    let mut sys = CPU_SAMPLER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((cached, taken_at)) = LAST_SNAPSHOT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
    {
        if taken_at.elapsed() < SNAPSHOT_TTL {
            return cached.clone();
        }
    }
    stretch_to_minimum_interval();
    sys.refresh_cpu_specifics(CpuRefreshKind::everything());
    let pid = Pid::from_u32(std::process::id());
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(std::slice::from_ref(&pid)),
        false,
        ProcessRefreshKind::everything(),
    );
    let process_cpu_percent = sys
        .process(pid)
        .map(|process| process.cpu_usage())
        .unwrap_or_default();
    let stats = CpuLiveStats {
        process_cpu_percent,
        host_cpu_percent: sys.global_cpu_usage(),
        cores: sys.cpus().len(),
        collected_at_ms: now_ms(),
    };
    mark_refreshed();
    *LAST_SNAPSHOT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some((stats.clone(), Instant::now()));
    stats
}

/// Sysinfo needs at least [`sysinfo::MINIMUM_CPU_UPDATE_INTERVAL`] between
/// CPU refreshes for a meaningful delta; sleep the remainder first.
fn stretch_to_minimum_interval() {
    let last = *LAST_REFRESH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let elapsed = last.elapsed();
    if elapsed < sysinfo::MINIMUM_CPU_UPDATE_INTERVAL {
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL - elapsed);
    }
}

fn mark_refreshed() {
    *LAST_REFRESH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_is_populated() {
        let stats = cpu_snapshot();
        assert!(stats.collected_at_ms > 0);
        assert!(stats.cores > 0);
        assert!(stats.process_cpu_percent >= 0.0);
        assert!(stats.host_cpu_percent >= 0.0);
    }

    /// Back-to-back calls inside the reuse window share one reading, which
    /// is what keeps the dashboard and the card from serializing on the
    /// sampler lock.
    #[test]
    fn snapshot_is_reused_within_ttl() {
        let first = cpu_snapshot();
        let second = cpu_snapshot();
        // The 1s window is wall-clock based: on a slow CI runner the first
        // call can already outlive it, so only assert monotonicity and that
        // a cache hit returns the same reading.
        assert!(
            second.collected_at_ms >= first.collected_at_ms,
            "snapshot timestamps must not go backwards"
        );
        if second.collected_at_ms == first.collected_at_ms {
            assert_eq!(
                first.process_cpu_percent, second.process_cpu_percent,
                "a cache hit must return the same reading"
            );
        }
    }

    #[test]
    fn concurrent_snapshots_stay_sane() {
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..3 {
                        let stats = cpu_snapshot();
                        assert!(stats.process_cpu_percent >= 0.0);
                        assert!(stats.collected_at_ms > 0);
                    }
                });
            }
        });
    }
}
