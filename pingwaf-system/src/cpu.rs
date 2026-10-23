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
    /// This process's CPU usage as a share of the whole machine, in percent.
    ///
    /// `sysinfo::Process::cpu_usage` reports *per core*, so a multi-threaded
    /// process on an eight-core box reads up to 800. Every consumer of this
    /// value displays it as a percentage next to the machine-wide
    /// [`Self::host_cpu_percent`], so the two are put on the same scale here
    /// — divided by the core count and clamped to 0-100 — rather than left
    /// for each caller to reinterpret. The dashboard showing "500%" beside
    /// "12%" was exactly that mistake.
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

/// A per-core CPU reading as a share of the whole machine, in percent.
///
/// `sysinfo::Process::cpu_usage` counts one core as 100, so a process using
/// four cores reports 400. Dividing by the core count puts it on the same
/// scale as `System::global_cpu_usage`, which is what every caller displays
/// it beside. Clamped at both ends: a process pinned across every core can
/// round past 100, and a counter that moved backwards can go negative.
fn whole_machine_percent(per_core: f32, cores: usize) -> f32 {
    let share = if cores > 0 {
        per_core / cores as f32
    } else {
        // No cores reported: the reading cannot be rescaled, so pass it
        // through and let the clamp below bound it.
        per_core
    };
    share.clamp(0.0, 100.0)
}

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
    let cores = sys.cpus().len();
    let process_cpu_percent = sys
        .process(pid)
        .map(|process| whole_machine_percent(process.cpu_usage(), cores))
        .unwrap_or_default();
    let stats = CpuLiveStats {
        process_cpu_percent,
        // Already machine-wide: `global_cpu_usage` averages the cores. Only
        // the clamp is wanted here, which `whole_machine_percent` applies
        // with `cores = 1` (no division).
        host_cpu_percent: whole_machine_percent(sys.global_cpu_usage(), 1),
        cores,
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

    /// The two CPU readings share one scale, and neither can read past 100.
    ///
    /// This is the regression guard for the dashboard showing "500%": the
    /// process figure used to be per core and unbounded, so a busy
    /// multi-threaded process rendered as several hundred percent next to a
    /// machine-wide figure in the low tens.
    #[test]
    fn both_cpu_readings_are_a_share_of_the_whole_machine() {
        let stats = cpu_snapshot();
        assert!(
            stats.process_cpu_percent <= 100.0,
            "process CPU must be a whole-machine share, got {}",
            stats.process_cpu_percent
        );
        assert!(
            stats.host_cpu_percent <= 100.0,
            "host CPU must not exceed 100%, got {}",
            stats.host_cpu_percent
        );
    }

    /// A per-core reading is divided by the core count, and a process spread
    /// across every core lands at 100 rather than several hundred.
    #[test]
    fn per_core_usage_is_scaled_and_clamped() {
        // Four cores busy to the limit: 400 per core → 100 machine-wide.
        assert_eq!(100.0, whole_machine_percent(400.0, 4));
        // Half of one core out of four: 50 per core → 12.5 machine-wide.
        assert_eq!(12.5, whole_machine_percent(50.0, 4));
        // Idle stays idle.
        assert_eq!(0.0, whole_machine_percent(0.0, 8));
        // A rounding overshoot on every core still reads 100, not 100.4.
        assert_eq!(100.0, whole_machine_percent(100.4, 1));
        // A machine that reports no cores must not divide by zero.
        assert_eq!(42.0, whole_machine_percent(42.0, 0));
        // A negative reading (a counter that moved backwards) floors at 0.
        assert_eq!(0.0, whole_machine_percent(-5.0, 4));
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
