use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use crate::probe;

/// Machine-wide CPU counters of the previous heartbeat, as `(busy, total)`
/// jiffies.
///
/// The heartbeat reports the usage over the interval since the previous one —
/// the same derivation the probe ships — instead of the average since boot,
/// which is what operators used to see here. One baseline per agent process,
/// like the collector itself.
static LAST_CPU: LazyLock<Mutex<Option<(u64, u64)>>> =
    LazyLock::new(|| Mutex::new(None));

/// CPU counters of the previous *ad-hoc* metrics sample, as `(busy, total)`
/// jiffies.
///
/// This baseline is deliberately separate from [`LAST_CPU`]: `cpu_percent_since`
/// consumes (overwrites) the baseline it is handed. The heartbeat and
/// `MetricsCollector::metrics_snapshot()` fire on independent schedules, so
/// sharing one baseline would let either caller steal the other's interval —
/// a heartbeat right after a metrics snapshot would difference over a
/// near-zero window and report a meaningless spike. Two baselines keep both
/// intervals intact.
static LAST_METRICS_CPU: LazyLock<Mutex<Option<(u64, u64)>>> =
    LazyLock::new(|| Mutex::new(None));

/// The `(count, time)` pair a rate calculation differences against.
#[derive(Debug)]
struct RpsState {
    count: u64,
    time: Instant,
}

impl Default for RpsState {
    fn default() -> Self {
        Self {
            count: 0,
            time: Instant::now(),
        }
    }
}

/// The heartbeat's RPS baseline: requests and timestamp of the previous
/// `collect()`. Owned by the collector, on its own schedule. of the previous *ad-hoc* metrics sample.
///
/// This baseline is deliberately separate from the collector's heartbeat
/// fields: a rate calculation consumes (overwrites) the baseline it is
/// handed. The heartbeat and `MetricsCollector::metrics_snapshot()` fire on
/// independent schedules, so sharing one baseline would let either caller
/// steal the other's interval — a heartbeat right after an ad-hoc snapshot
/// would difference over a near-zero window and report a meaningless spike.
/// Two baselines keep both intervals intact.
static LAST_RPS_SNAPSHOT: LazyLock<Mutex<RpsState>> =
    LazyLock::new(|| Mutex::new(RpsState::default()));

/// Collected system metrics for heartbeat reporting.
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub active_connections: u64,
    pub requests_per_second: u64,
    pub blocked_requests_total: u64,
    pub requests_total: u64,
}

/// Collects system and application metrics for the agent heartbeat.
///
/// Uses lock-free atomic counters for the hot path (request recording)
/// and periodic system reads for CPU/memory.
pub struct MetricsCollector {
    /// Total requests seen
    requests_total: AtomicU64,
    /// Total requests blocked by WAF
    blocked_requests_total: AtomicU64,
    /// Current active connections (can go negative briefly during cleanup)
    active_connections: AtomicI64,
    /// The heartbeat's RPS baseline (see `LAST_RPS_SNAPSHOT` for why this
    /// is not shared with the ad-hoc snapshot path).
    rps_state: std::sync::Mutex<RpsState>,
    /// Last calculated RPS value
    cached_rps: AtomicU64,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    pub fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            blocked_requests_total: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            rps_state: std::sync::Mutex::new(RpsState::default()),
            cached_rps: AtomicU64::new(0),
        }
    }

    /// Record a request (called on every proxied request).
    ///
    /// This is on the hot path and must be extremely fast — only atomic ops.
    #[inline]
    pub fn record_request(&self, blocked: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if blocked {
            self.blocked_requests_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Track active connection count changes.
    #[inline]
    pub fn record_connection(&self, delta: i64) {
        self.active_connections.fetch_add(delta, Ordering::Relaxed);
    }

    /// Get current active connections.
    #[inline]
    pub fn active_connections(&self) -> u64 {
        let val = self.active_connections.load(Ordering::Relaxed);
        if val < 0 {
            0
        } else {
            val as u64
        }
    }

    /// Get total requests.
    #[inline]
    pub fn requests_total(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }

    /// Get total blocked requests.
    #[inline]
    pub fn blocked_requests_total(&self) -> u64 {
        self.blocked_requests_total.load(Ordering::Relaxed)
    }

    /// Collect a full metrics snapshot (called periodically for heartbeat).
    ///
    /// This recalculates RPS and reads system metrics. Not on the hot path,
    /// so it's okay to be slightly more expensive.
    pub fn collect(&self) -> SystemMetrics {
        // Calculate RPS
        let rps = self.calculate_rps();

        // Read system metrics
        let (cpu_usage, memory_usage) = read_system_metrics();

        SystemMetrics {
            cpu_usage_percent: cpu_usage,
            memory_usage_bytes: memory_usage,
            active_connections: self.active_connections(),
            requests_per_second: rps,
            blocked_requests_total: self.blocked_requests_total(),
            requests_total: self.requests_total(),
        }
    }

    /// Collect a metrics snapshot for ad-hoc readers (`metrics_snapshot()`).
    ///
    /// Differs from [`Self::collect`] only in the baselines: it uses
    /// `LAST_METRICS_CPU` and `LAST_RPS_SNAPSHOT` instead of the heartbeat's
    /// `LAST_CPU` and `rps_state`, because those baselines are consumed by
    /// the calculations that difference against them and the two run on
    /// independent schedules. See `LAST_METRICS_CPU`'s and
    /// `LAST_RPS_SNAPSHOT`'s doc comments for why the baselines must not be
    /// shared.
    pub fn collect_snapshot(&self) -> SystemMetrics {
        let rps = {
            let mut state = LAST_RPS_SNAPSHOT
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            self.calculate_rps_with(&mut state)
        };
        let (cpu_usage, memory_usage) =
            (read_cpu_percent_snapshot(), read_memory_usage());
        SystemMetrics {
            cpu_usage_percent: cpu_usage,
            memory_usage_bytes: memory_usage,
            active_connections: self.active_connections(),
            requests_per_second: rps,
            blocked_requests_total: self.blocked_requests_total(),
            requests_total: self.requests_total(),
        }
    }

    /// Calculate requests per second since last heartbeat collection.
    fn calculate_rps(&self) -> u64 {
        let mut state =
            self.rps_state.lock().unwrap_or_else(|err| err.into_inner());
        self.calculate_rps_with(&mut state)
    }

    /// Differences the request counter against `state` and advances it.
    /// Both the heartbeat (`rps_state`) and the ad-hoc snapshot
    /// (`LAST_RPS_SNAPSHOT`) run this with their own baseline, so neither
    /// steals the other's interval.
    fn calculate_rps_with(&self, state: &mut RpsState) -> u64 {
        let current_count = self.requests_total.load(Ordering::Relaxed);
        let previous_count = state.count;
        state.count = current_count;

        let now = Instant::now();
        let elapsed = now.duration_since(state.time).as_secs_f64();
        state.time = now;

        if elapsed > 0.0 {
            let rps = ((current_count.saturating_sub(previous_count)) as f64
                / elapsed) as u64;
            self.cached_rps.store(rps, Ordering::Relaxed);
            return rps;
        }
        self.cached_rps.load(Ordering::Relaxed)
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// CPU usage and memory in use, read for one heartbeat.
fn read_system_metrics() -> (f64, u64) {
    (read_cpu_percent(), read_memory_usage())
}

/// CPU usage over the interval since the previous heartbeat, in percent.
///
/// The counters and the arithmetic are the probe's
/// ([`probe::cpu_percent_since`]), so both panels show the same measurement.
/// The first heartbeat after start — and one after a reboot or a counter reset
/// — has no baseline and reports the since-boot average; see that function for
/// why a non-null first sample matters.
///
/// `None` from the probe means the platform exposes no `/proc/stat` counters:
/// the platform reading is kept there so the field stays non-null.
fn read_cpu_percent() -> f64 {
    let mut previous = LAST_CPU.lock().unwrap_or_else(|err| err.into_inner());
    probe::cpu_percent_since(&mut previous).unwrap_or_else(platform_cpu_percent)
}

/// CPU usage for an ad-hoc read-only sample (see
/// [`MetricsCollector::collect_snapshot`]), differenced against its own
/// baseline so the heartbeat's [`LAST_CPU`] interval is untouched.
fn read_cpu_percent_snapshot() -> f64 {
    let mut previous = LAST_METRICS_CPU
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    probe::cpu_percent_since(&mut previous).unwrap_or_else(platform_cpu_percent)
}

/// Memory in use, in bytes.
fn read_memory_usage() -> u64 {
    #[cfg(target_os = "linux")]
    {
        read_linux_memory().unwrap_or(0)
    }
    #[cfg(target_os = "macos")]
    {
        read_macos_memory().unwrap_or(0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

/// CPU reading on a platform whose counters the probe cannot difference.
#[cfg(target_os = "macos")]
fn platform_cpu_percent() -> f64 {
    read_macos_cpu().unwrap_or(0.0)
}

/// CPU reading on a platform whose counters the probe cannot difference.
#[cfg(not(target_os = "macos"))]
fn platform_cpu_percent() -> f64 {
    0.0
}

#[cfg(target_os = "linux")]
fn read_linux_memory() -> Option<u64> {
    // Read /proc/meminfo for memory usage
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut mem_total: u64 = 0;
    let mut mem_available: u64 = 0;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            mem_total = parse_meminfo_value(line)?;
        } else if line.starts_with("MemAvailable:") {
            mem_available = parse_meminfo_value(line)?;
        }
    }

    if mem_total > 0 {
        Some((mem_total - mem_available) * 1024) // Convert kB to bytes
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn parse_meminfo_value(line: &str) -> Option<u64> {
    line.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(target_os = "macos")]
fn read_macos_cpu() -> Option<f64> {
    // Use `top` command for a quick CPU sample
    let output = std::process::Command::new("top")
        .args(["-l", "1", "-n", "0"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("CPU usage:") {
            // Parse "CPU usage: 5.26% user, 10.52% sys, 84.21% idle"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let user: f64 = parts[2].trim_end_matches('%').parse().ok()?;
                let sys: f64 = parts[4].trim_end_matches('%').parse().ok()?;
                return Some(user + sys);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn read_macos_memory() -> Option<u64> {
    // Use vm_stat for memory usage
    let output = std::process::Command::new("vm_stat").output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut page_size: u64 = 4096; // Default macOS page size
    let mut active_pages: u64 = 0;
    let mut wired_pages: u64 = 0;
    let mut compressed_pages: u64 = 0;

    for line in stdout.lines() {
        if line.starts_with("Mach Virtual Memory Statistics:") {
            // Try to extract page size from "(page size of X bytes)"
            if let Some(start) = line.find("page size of ") {
                let rest = &line[start + 13..];
                if let Some(end) = rest.find(" bytes") {
                    page_size = rest[..end].parse().unwrap_or(4096);
                }
            }
        } else if line.starts_with("Pages active:") {
            active_pages = parse_vm_stat_value(line).unwrap_or(0);
        } else if line.starts_with("Pages wired down:") {
            wired_pages = parse_vm_stat_value(line).unwrap_or(0);
        } else if line.starts_with("Pages occupied by compressor:") {
            compressed_pages = parse_vm_stat_value(line).unwrap_or(0);
        }
    }

    let used_bytes =
        (active_pages + wired_pages + compressed_pages) * page_size;
    if used_bytes > 0 {
        Some(used_bytes)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn parse_vm_stat_value(line: &str) -> Option<u64> {
    // Format: "Pages active:                          123456."
    let value_str = line.split(':').nth(1)?.trim().trim_end_matches('.');
    value_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::debug;

    #[test]
    fn test_metrics_collector_basic() {
        let collector = MetricsCollector::new();

        assert_eq!(collector.requests_total(), 0);
        assert_eq!(collector.blocked_requests_total(), 0);
        assert_eq!(collector.active_connections(), 0);

        collector.record_request(false);
        collector.record_request(true);
        collector.record_request(false);

        assert_eq!(collector.requests_total(), 3);
        assert_eq!(collector.blocked_requests_total(), 1);
    }

    #[test]
    fn test_connection_tracking() {
        let collector = MetricsCollector::new();

        collector.record_connection(1);
        collector.record_connection(1);
        assert_eq!(collector.active_connections(), 2);

        collector.record_connection(-1);
        assert_eq!(collector.active_connections(), 1);
    }

    /// The heartbeat reports the same bounded percentage the probe does, on
    /// every read: the first one (no baseline) and the one that differences
    /// against it.
    #[test]
    fn heartbeat_cpu_is_a_bounded_percentage() {
        let (first, _) = read_system_metrics();
        assert!(first.is_finite(), "cpu must be a real number, got {first}");
        assert!((0.0..=100.0).contains(&first), "cpu out of range: {first}");
        let (second, _) = read_system_metrics();
        assert!(
            (0.0..=100.0).contains(&second),
            "cpu out of range: {second}"
        );
    }

    #[test]
    fn test_collect_returns_metrics() {
        let collector = MetricsCollector::new();
        collector.record_request(false);

        let metrics = collector.collect();
        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.blocked_requests_total, 0);
        // CPU and memory may be 0 in test environments
        debug!("Collected metrics: {:?}", metrics);
    }

    /// An ad-hoc snapshot must not compress the heartbeat's RPS window: the
    /// two paths difference against separate baselines, so a snapshot between
    /// heartbeats leaves the heartbeat interval intact and both callers can
    /// report the full request delta they observed.
    #[test]
    fn snapshot_rps_does_not_steal_the_heartbeat_window() {
        let collector = MetricsCollector::new();

        // Both baselines start empty; the first read of each is a 0 over a
        // ~zero window and seeds its own baseline.
        let _ = collector.collect();
        let _ = collector.collect_snapshot();

        // 10 requests reach the heartbeat only (its window is untouched by
        // the snapshot in between).
        for _ in 0..10 {
            collector.record_request(false);
        }
        let heartbeat = collector.collect();
        assert_eq!(10, heartbeat.requests_total);

        let heartbeat_state = collector
            .rps_state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The heartbeat's baseline holds the current total, not a total
        // some snapshot already consumed.
        assert_eq!(10, heartbeat_state.count);
        assert!(heartbeat.requests_per_second > 0);
    }
}
