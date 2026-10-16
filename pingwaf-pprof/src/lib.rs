//! Built-in pprof-style profiling for PingWAF processes.
//!
//! CPU sampling wraps the `pprof` crate and is exposed by both planes as
//! three endpoints:
//!
//! * `.../pprof/profile` — gzip-compressed pprof protobuf, understood by
//!   `go tool pprof` and speedscope
//! * `.../pprof/flamegraph` — SVG flamegraph rendered by inferno, viewable
//!   directly in a browser
//! * `.../pprof/cpu/dashboard.svg` — self-contained SVG dashboard (usage,
//!   task distribution, key metrics, status badge) rendered by
//!   [`cpu_svg`], optionally with an embedded live-refresh script
//! * `.../pprof/memory` — JSON snapshot of process RSS and system memory
//!
//! Sampling is process-global: `pprof` installs a single signal handler and
//! one shared collector, so a second concurrent session is rejected with
//! [`ProfileError::AlreadyActive`] rather than corrupting the first.
//!
//! CPU sampling only works on Linux: there the `pprof` signal handler unwinds
//! with its own signal-safe DWARF walker. On other platforms (macOS in
//! particular) unwinding goes through libunwind, which is not async-signal-safe
//! and can abort the process from inside the handler (tikv/pprof-rs#36), so
//! [`start_session`] fails with [`ProfileError::UnsupportedPlatform`] there
//! instead of risking the process. [`memory_snapshot`] works everywhere.
//!
//! Frames are resolved from the binary's symbol table. The default
//! `release` profile strips symbols, so profile a `release-perf` build
//! (`--profile release-perf`, which keeps `debug = 1`) to get readable
//! flame graphs; on a stripped build most frames show up as `Unknown`.

use bytesize::ByteSize;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod cgroup;
pub mod cpu_svg;

pub use cpu_svg::{
    cpu_snapshot, render_cpu_dashboard_svg, CpuCaptureSummary, CpuLiveStats,
    CpuStatus, DashboardSvgOpts, TopFrame,
};

#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
use std::io::Write;

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "linux")]
use pprof::ProfilerGuard;

/// Sampling frequency used when the request does not specify one. 99 rather
/// than a round 100 so the sampler does not synchronise with periodically
/// scheduled work.
pub const DEFAULT_FREQUENCY: i32 = 99;
/// Upper bound accepted for the `frequency` query parameter. The sampler
/// allocates inside its signal handler (a known pprof-rs design limit), so
/// the ceiling is deliberately modest: frequency multiplies both the
/// sampling overhead and the worst-case memory growth under load (see
/// `GUARD_MAX_CPU_PERCENT`).
pub const MAX_FREQUENCY: i32 = 250;
/// Default capture window in seconds.
pub const DEFAULT_SECONDS: u64 = 15;
/// Upper bound accepted for the `seconds` query parameter — the capture
/// window is the other axis of the worst-case memory growth. Keep short: a
/// busy process profiled for a full minute has no diagnostic value that
/// justifies the risk.
pub const MAX_SECONDS: u64 = 60;

/// Process CPU usage (percent of one core) above which captures are
/// refused outright.
///
/// The sampler's SIGPROF handler allocates from the global allocator while
/// every thread is being unwound — a known pprof-rs design limit that is
/// harmless on an idle process but catastrophic under load: on the demo
/// instance, a 30s capture started during a request storm grew RSS from
/// 122MB to 1GB+ within 90 seconds and was OOM-killed (2026-10-16). Idle
/// captures measured a peak of only 79MB, hence a threshold well above the
/// idle band (~1-2%) yet far below saturation. `capture_allowed_at` is the
/// single decision point so HTTP and MCP callers cannot drift.
pub const GUARD_MAX_CPU_PERCENT: f32 = 40.0;

/// Whether a CPU capture may start at the given process CPU usage (percent
/// of one core, as `CpuLiveStats::process_cpu_percent` reports). The percent
/// is the average over the sampler's refresh interval, not an instantaneous
/// value — a momentary spike between refreshes is not seen by the guard.
pub fn capture_allowed_at(process_cpu_percent: f32) -> bool {
    process_cpu_percent <= GUARD_MAX_CPU_PERCENT
}

/// Whether CPU captures are enabled on this deployment:
/// `PINGWAF_PPROF_ENABLED=0` (or `false`/`off`/`no`, case-insensitive)
/// turns them off. The read-only memory and live-metrics snapshots are not
/// affected — they are the diagnostic views needed precisely when captures
/// are off. Single source of truth shared by the control-plane endpoints,
/// the data-plane admin plugin and the MCP tool.
pub fn captures_enabled() -> bool {
    match std::env::var("PINGWAF_PPROF_ENABLED") {
        Ok(value) => !matches!(
            value.to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

/// Records a capture that was refused **before** a session started (load
/// guard or deployment switch). These never increment `total_started` — no
/// session began — but appear as `last.outcome` so the live endpoint can
/// answer "why is my capture not running?".
pub fn record_prestart_outcome(outcome: &str) {
    record_capture(0.0, outcome);
}

/// The profiler is a process-global singleton, so only one sampling session
/// may exist at a time. `pprof` itself would fail the second start anyway;
/// this flag turns that failure into a clean "already active" answer.
#[cfg(target_os = "linux")]
static SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Cumulative count of sampling sessions started in this process.
static TOTAL_SESSIONS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// The most recently finished (or abandoned) session.
static LAST_CAPTURE: std::sync::Mutex<Option<CaptureRecord>> =
    std::sync::Mutex::new(None);

/// Outcome of one profiling capture, surfaced via [`capture_stats`].
///
/// This exists so operators can answer "who profiled, when, and what came of
/// it" from the live endpoint alone — the historical record the demo needed
/// when correlating memory spikes with capture activity.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureRecord {
    /// Unix epoch milliseconds when the capture ended.
    pub finished_at_ms: u64,
    /// Wall-clock duration of the capture window in seconds.
    pub duration_secs: f64,
    /// `"ok"` when a profile was produced; otherwise a short machine tag:
    /// `"idle"`, `"no_samples"`, `"report_error"`, `"abandoned"` (session
    /// dropped before finishing), `"unsupported"`, or — for captures
    /// refused before a session started — `"load_guard"` (busy process) or
    /// `"switch_off"` (PINGWAF_PPROF_ENABLED=0).
    pub outcome: String,
}

/// Cumulative capture statistics for this process lifetime.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureStats {
    /// Sessions started since process start, including ones that later
    /// failed or were abandoned.
    pub total_started: u64,
    /// The most recently finished (or abandoned) session, if any.
    pub last: Option<CaptureRecord>,
}

/// Snapshot of [`TOTAL_SESSIONS`] and [`LAST_CAPTURE`].
pub fn capture_stats() -> CaptureStats {
    let last = LAST_CAPTURE
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or(None);
    CaptureStats {
        total_started: TOTAL_SESSIONS
            .load(std::sync::atomic::Ordering::Relaxed),
        last,
    }
}

/// Records a finished capture, overwriting the previous `last` entry. A
/// poisoned mutex is ignored: the stats are advisory, never load-bearing.
fn record_capture(duration_secs: f64, outcome: &str) {
    let record = CaptureRecord {
        finished_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        duration_secs,
        outcome: outcome.to_string(),
    };
    if let Ok(mut last) = LAST_CAPTURE.lock() {
        *last = Some(record);
    }
}

/// Short machine tag for a failed capture, for [`CaptureRecord::outcome`].
#[cfg(target_os = "linux")]
fn error_tag(err: &ProfileError) -> &'static str {
    match err {
        ProfileError::AlreadyActive => "already_active",
        ProfileError::UnsupportedPlatform => "unsupported",
        ProfileError::Start(_) => "start_error",
        ProfileError::NoSamples => "no_samples",
        ProfileError::Idle => "idle",
        ProfileError::Report(_) => "report_error",
    }
}

/// Failures surfaced to the profiling endpoints.
#[derive(Debug)]
pub enum ProfileError {
    /// Another session is already sampling in this process (HTTP 409).
    AlreadyActive,
    /// CPU sampling is unavailable on this platform (HTTP 501); only Linux
    /// has a signal-safe unwinder for the sampling handler.
    UnsupportedPlatform,
    /// The profiler failed to start (unsupported platform, resource limits).
    Start(String),
    /// Zero samples were captured: the profiled process was idle for the
    /// whole window. The sampler fires on process CPU time (`SIGPROF` via
    /// `ITIMER_PROF`), so a process doing no work yields nothing (HTTP 409).
    NoSamples,
    /// CPU time grew by less than 1% of the wall-clock window, meaning the
    /// process was essentially idle; the capture is refused rather than
    /// returned as a misleading near-empty profile (HTTP 409).
    Idle,
    /// Collecting, symbolising or encoding the report failed.
    Report(String),
}

/// Wall-clock fraction below which a session counts as idle. This must stay
/// well below the signal handler's own CPU overhead at 99 Hz (roughly
/// 0.5–2% of one core), or genuinely idle processes get misclassified as
/// active; zero-sample captures are still rejected separately via
/// `ProfileError::NoSamples`.
#[cfg(target_os = "linux")]
const IDLE_CPU_FRACTION: f64 = 0.001;

impl std::error::Error for ProfileError {}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::AlreadyActive => f.write_str(
                "a profiling session is already active in this process",
            ),
            ProfileError::UnsupportedPlatform => f.write_str(
                "CPU sampling is only supported on Linux; the macOS unwinder is not signal-safe",
            ),
            ProfileError::Start(msg) => {
                write!(f, "failed to start profiler: {msg}")
            },
            ProfileError::NoSamples => f.write_str(
                "no samples were captured during the profiling window: \
                 the profiled process appeared idle — the sampler is \
                 CPU-time based and needs active traffic; retry under load \
                 or use the memory snapshot",
            ),
            ProfileError::Idle => f.write_str(
                "the process spent almost no CPU time during the \
                 profiling window (<1% of the wall clock), so the profile \
                 would be nearly empty; retry under load",
            ),
            ProfileError::Report(msg) => {
                write!(f, "failed to build profile report: {msg}")
            },
        }
    }
}

#[cfg(target_os = "linux")]
fn report_err(err: pprof::Error) -> ProfileError {
    ProfileError::Report(err.to_string())
}

/// An in-flight CPU sampling session. Sampling runs until one of the
/// `finish_*` methods consumes the session or it is dropped.
pub struct ProfilingSession {
    /// Whether a `finish_*` method already recorded this session's outcome
    /// (a plain drop afterwards must not record `"abandoned"`).
    finished: bool,
    #[cfg(target_os = "linux")]
    guard: Option<ProfilerGuard<'static>>,
    #[cfg(target_os = "linux")]
    started_at: Instant,
    #[cfg(target_os = "linux")]
    start_cpu_ticks: Option<u64>,
}

/// Starts CPU sampling at `frequency` Hz (values outside `1..=MAX_FREQUENCY`
/// are clamped).
///
/// The caller decides how long to sample: start the session, wait, then call
/// [`ProfilingSession::finish_pprof`] or
/// [`ProfilingSession::finish_flamegraph`].
#[cfg(target_os = "linux")]
pub fn start_session(frequency: i32) -> Result<ProfilingSession, ProfileError> {
    if SESSION_ACTIVE.swap(true, Ordering::SeqCst) {
        return Err(ProfileError::AlreadyActive);
    }
    // Blocking the unwinder's own libraries avoids deadlocks inside
    // `_Unwind_Backtrace`, and `vdso` carries broken DWARF on some
    // distributions (both per the pprof-rs documentation).
    let started = pprof::ProfilerGuardBuilder::default()
        .frequency(frequency.clamp(1, MAX_FREQUENCY))
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build();
    match started {
        Ok(guard) => {
            TOTAL_SESSIONS.fetch_add(1, Ordering::Relaxed);
            Ok(ProfilingSession {
                finished: false,
                guard: Some(guard),
                started_at: Instant::now(),
                start_cpu_ticks: process_cpu_ticks(),
            })
        },
        Err(err) => {
            SESSION_ACTIVE.store(false, Ordering::SeqCst);
            Err(ProfileError::Start(err.to_string()))
        },
    }
}

/// Off-Linux the sampling handler would unwind through libunwind, which can
/// abort the process from inside the signal handler, so captures are refused
/// outright.
#[cfg(not(target_os = "linux"))]
pub fn start_session(
    _frequency: i32,
) -> Result<ProfilingSession, ProfileError> {
    Err(ProfileError::UnsupportedPlatform)
}

impl ProfilingSession {
    /// Stops sampling and returns the samples as a gzip-compressed pprof
    /// protobuf - the same wire format `go tool pprof` accepts.
    #[cfg(target_os = "linux")]
    pub fn finish_pprof(mut self) -> Result<Vec<u8>, ProfileError> {
        let result = self.finish_pprof_inner();
        self.record(&result);
        result
    }

    #[cfg(target_os = "linux")]
    fn finish_pprof_inner(&mut self) -> Result<Vec<u8>, ProfileError> {
        let report = self.take_report()?;
        self.reject_idle(&report)?;
        let profile = report.pprof().map_err(report_err)?;
        let raw = pprof::protos::Message::encode_to_vec(&profile);
        let mut encoder = flate2::write::GzEncoder::new(
            Vec::with_capacity(raw.len() / 4 + 256),
            flate2::Compression::default(),
        );
        encoder
            .write_all(&raw)
            .and_then(|_| encoder.finish())
            .map_err(|e| ProfileError::Report(e.to_string()))
    }

    /// Unreachable off-Linux: `start_session` never hands out a session there.
    #[cfg(not(target_os = "linux"))]
    pub fn finish_pprof(mut self) -> Result<Vec<u8>, ProfileError> {
        self.record("unsupported");
        Err(ProfileError::UnsupportedPlatform)
    }

    /// Stops sampling and returns the samples as an inferno flamegraph SVG.
    #[cfg(target_os = "linux")]
    pub fn finish_flamegraph(mut self) -> Result<String, ProfileError> {
        let result = self.finish_flamegraph_inner();
        self.record(&result);
        result
    }

    #[cfg(target_os = "linux")]
    fn finish_flamegraph_inner(&mut self) -> Result<String, ProfileError> {
        let report = self.take_report()?;
        self.reject_idle(&report)?;
        let mut svg = Vec::new();
        report.flamegraph(&mut svg).map_err(report_err)?;
        String::from_utf8(svg).map_err(|e| ProfileError::Report(e.to_string()))
    }

    /// Unreachable off-Linux: `start_session` never hands out a session there.
    #[cfg(not(target_os = "linux"))]
    pub fn finish_flamegraph(mut self) -> Result<String, ProfileError> {
        self.record("unsupported");
        Err(ProfileError::UnsupportedPlatform)
    }

    /// Stops sampling and returns a [`CpuCaptureSummary`] describing the
    /// capture — the input for the SVG dashboard and the MCP `profile_cpu`
    /// tool. Unlike the report finishers, an idle capture is not rejected
    /// here: the summary simply carries [`CpuStatus::Idle`] so the
    /// dashboard can annotate it instead of failing the request.
    #[cfg(target_os = "linux")]
    pub fn finish_summary(mut self) -> Result<CpuCaptureSummary, ProfileError> {
        let result = self.finish_summary_inner();
        self.record(&result);
        result
    }

    #[cfg(target_os = "linux")]
    fn finish_summary_inner(
        &mut self,
    ) -> Result<CpuCaptureSummary, ProfileError> {
        let report = self.take_report()?;
        let cpu_secs = match (self.start_cpu_ticks, process_cpu_ticks()) {
            (Some(start), Some(end)) => {
                end.saturating_sub(start) as f64 / ticks_per_second() as f64
            },
            // `/proc` unreadable (seccomp filter): the window share is
            // reported as zero rather than refusing the whole capture.
            _ => 0.0,
        };
        let wall_secs = self.started_at.elapsed().as_secs_f64();
        Ok(cpu_svg::summarize_report(&report, wall_secs, cpu_secs))
    }

    /// Unreachable off-Linux: `start_session` never hands out a session
    /// there.
    #[cfg(not(target_os = "linux"))]
    pub fn finish_summary(mut self) -> Result<CpuCaptureSummary, ProfileError> {
        self.record("unsupported");
        Err(ProfileError::UnsupportedPlatform)
    }

    /// Marks the session as recorded and appends its outcome to the
    /// process-wide capture stats.
    #[cfg(target_os = "linux")]
    fn record<T>(&mut self, result: &Result<T, ProfileError>) {
        self.finished = true;
        let outcome = match result {
            Ok(_) => "ok".to_string(),
            Err(err) => error_tag(err).to_string(),
        };
        record_capture(self.started_at.elapsed().as_secs_f64(), &outcome);
    }

    /// Off-Linux sessions never carry a start time; record a zero duration.
    #[cfg(not(target_os = "linux"))]
    fn record(&mut self, outcome: &str) {
        self.finished = true;
        record_capture(0.0, outcome);
    }

    #[cfg(target_os = "linux")]
    fn take_report(&mut self) -> Result<pprof::Report, ProfileError> {
        let Some(guard) = self.guard.as_ref() else {
            return Err(ProfileError::Report(
                "profiling session already finished".to_string(),
            ));
        };
        let report = guard.report().build().map_err(report_err)?;
        // Sampling stops here; symbolising and encoding below is idle time.
        self.guard = None;
        Ok(report)
    }

    /// Rejects a capture that would be useless because the process did not
    /// burn CPU during the window: zero samples, or CPU time below 1% of the
    /// wall-clock duration.
    ///
    /// The CPU-time read comes from `/proc/self/stat` (utime+stime in clock
    /// ticks); when that is unavailable (non-Linux, seccomp filter) the idle
    /// check is skipped and only the empty-report guard applies.
    #[cfg(target_os = "linux")]
    fn reject_idle(&self, report: &pprof::Report) -> Result<(), ProfileError> {
        if report.data.is_empty() {
            return Err(ProfileError::NoSamples);
        }
        if let Some(start_ticks) = self.start_cpu_ticks {
            let Some(end_ticks) = process_cpu_ticks() else {
                return Ok(());
            };
            let cpu_secs = end_ticks.saturating_sub(start_ticks) as f64
                / ticks_per_second() as f64;
            let wall_secs = self.started_at.elapsed().as_secs_f64();
            if cpu_secs < wall_secs * IDLE_CPU_FRACTION {
                return Err(ProfileError::Idle);
            }
        }
        Ok(())
    }
}

/// Process CPU time since start, in clock ticks (`utime + stime` from
/// `/proc/self/stat`). Linux-only; `None` when unreadable. The comm field may
/// contain spaces, so parsing starts after its closing parenthesis.
#[cfg(target_os = "linux")]
fn process_cpu_ticks() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rest = stat.rsplit_once(')')?.1;
    // After the comm field the remaining fields start at `state` (field 3);
    // utime (14) and stime (15) are therefore items 11 and 12 here.
    let mut fields = rest.split_whitespace();
    let utime = fields.nth(11)?.parse::<u64>().ok()?;
    let stime = fields.next()?.parse::<u64>().ok()?;
    Some(utime.saturating_add(stime))
}

/// The userspace-visible clock-tick rate for `/proc` fields, always 100.
#[cfg(target_os = "linux")]
fn ticks_per_second() -> u64 {
    100
}

#[cfg(target_os = "linux")]
impl Drop for ProfilingSession {
    fn drop(&mut self) {
        self.guard = None;
        if !self.finished {
            // The request died before any finisher ran (client disconnect,
            // panic in the handler): record that, so the stats show why a
            // capture has no artifact.
            record_capture(
                self.started_at.elapsed().as_secs_f64(),
                "abandoned",
            );
        }
        SESSION_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// Point-in-time memory usage of this process and the machine, for the
/// `.../pprof/memory` endpoint.
#[derive(Debug, Serialize)]
pub struct MemorySnapshot {
    /// Resident set size of this process in bytes.
    pub rss_bytes: u64,
    /// Virtual memory size of this process in bytes.
    pub virtual_bytes: u64,
    /// Total physical RAM of the machine in bytes.
    pub total_memory_bytes: u64,
    /// Physical RAM in use across the machine in bytes.
    pub used_memory_bytes: u64,
    /// `rss_bytes` rendered human-readable, e.g. "120.3 MB".
    pub rss: String,
    /// `total_memory_bytes` rendered human-readable.
    pub total_memory: String,
    /// `used_memory_bytes` rendered human-readable.
    pub used_memory: String,
    /// Unix epoch milliseconds at which the snapshot was taken.
    pub collected_at_ms: u64,
    /// Scope of `used_memory_bytes`/`total_memory_bytes`: always `"system"`
    /// today — sysinfo reports host RAM, which in a container is the host's
    /// or VM's total, *not* the container limit. Client code that wants the
    /// process footprint must use `rss_bytes`, never `used_memory_bytes`.
    pub used_memory_scope: &'static str,
    /// Scope of `rss_bytes`/`virtual_bytes`: always `"process"` — this is
    /// this process's own footprint (`statm` via `memory-stats`).
    pub process_memory_scope: &'static str,
    /// Container memory in use, as reported by the cgroup filesystem
    /// (cgroup v2 `memory.current`, v1 `memory.usage_in_bytes`) — the same
    /// figure `docker stats` shows. `None` when the process is not inside a
    /// memory-limited cgroup (bare metal, unlimited container, non-Linux).
    pub container_memory_used_bytes: Option<u64>,
    /// Container memory limit (v2 `memory.max`, v1 `memory.limit_in_bytes`);
    /// `None` when the cgroup has no limit set or the container fields are
    /// absent. Inside a limited container this is what `docker stats`
    /// prints in the LIMIT column.
    pub container_memory_limit_bytes: Option<u64>,
    /// `container_memory_used_bytes` rendered human-readable.
    pub container_memory_used: Option<String>,
    /// `container_memory_limit_bytes` rendered human-readable.
    pub container_memory_limit: Option<String>,
    /// Scope of the container fields: `"cgroup_v1"` or `"cgroup_v2"`, or
    /// `None` when they are absent. When present, prefer these numbers over
    /// `used/total_memory_bytes` — the host fields report the machine's
    /// RAM, which inside a container is not the container's budget.
    pub container_memory_scope: Option<&'static str>,
}

/// Collects a [`MemorySnapshot`]. Process memory comes from `memory-stats`,
/// system totals from sysinfo with only RAM refresh enabled.
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
    // Container numbers (what `docker stats` reports) take priority in the
    // dashboard; absent outside a memory-limited cgroup.
    let container = cgroup::container_memory();
    let collected_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
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
            .map(|l| ByteSize(l).to_string()),
        container_memory_scope: container.map(|c| c.version.scope_label()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use pretty_assertions::assert_eq;

    /// Burns CPU for `ms` so the sampler has something to catch.
    #[cfg(target_os = "linux")]
    fn burn(ms: u64) {
        let start = std::time::Instant::now();
        let mut acc = 0u64;
        while start.elapsed().as_millis() < ms as u128 {
            acc =
                acc.wrapping_add(std::hint::black_box(acc.count_ones() as u64));
        }
        assert!(acc < u64::MAX);
    }

    // All sampling paths share one process-global profiler, so they must run
    // sequentially inside a single test.
    #[cfg(target_os = "linux")]
    #[test]
    fn sampling_sessions() {
        let session = start_session(DEFAULT_FREQUENCY).expect("first start");
        burn(300);
        let profile = session.finish_pprof().expect("pprof bytes");
        // gzip magic: the output is a valid gzip stream for go tool pprof.
        assert_eq!(profile[0], 0x1f);
        assert_eq!(profile[1], 0x8b);

        let session = start_session(DEFAULT_FREQUENCY).expect("second start");
        assert!(matches!(
            start_session(DEFAULT_FREQUENCY),
            Err(ProfileError::AlreadyActive)
        ));
        burn(200);
        let svg = session.finish_flamegraph().expect("flamegraph svg");
        assert!(svg.contains("<svg"));

        // Dropping a session releases the process-global slot.
        let session = start_session(DEFAULT_FREQUENCY).expect("third start");
        drop(session);
        let session = start_session(DEFAULT_FREQUENCY).expect("fourth start");
        drop(session);

        // The summary finisher feeds the SVG dashboard and the MCP tool:
        // it keeps idle captures instead of rejecting them. The 2-second
        // burn gives shared CI runners enough wall clock to deliver
        // SIGPROF samples even when the matrix is contending for the
        // kernel scheduler.
        let session = start_session(DEFAULT_FREQUENCY).expect("fifth start");
        burn(2000);
        let summary = session.finish_summary().expect("capture summary");
        assert!(
            summary.total_samples > 0,
            "CPU sampler produced no samples across a 2s busy window"
        );
        assert_eq!(summary.frequency, DEFAULT_FREQUENCY);
        assert!(!summary.top_frames.is_empty());
        // The burn loop is CPU-bound, so the capture cannot be idle; the
        // exact badge (NORMAL vs HIGH LOAD) depends on how much of the
        // wall clock the runner granted us, so only rule out IDLE.
        assert_ne!(summary.status, CpuStatus::Idle);
        let svg = render_cpu_dashboard_svg(
            &summary,
            None,
            &DashboardSvgOpts::default(),
        );
        assert!(svg.contains("<svg"));
        assert!(svg.contains("TASK DISTRIBUTION"));
    }

    // Sampling the process via SIGPROF is unsafe off-Linux (see
    // `start_session`); the endpoints must fail cleanly instead of crashing.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sampling_rejected_off_linux() {
        assert!(matches!(
            start_session(DEFAULT_FREQUENCY),
            Err(ProfileError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn memory_snapshot_is_populated() {
        let snapshot = memory_snapshot();
        assert!(snapshot.rss_bytes > 0);
        assert!(snapshot.total_memory_bytes > 0);
        assert!(snapshot.used_memory_bytes > 0);
        assert!(snapshot.collected_at_ms > 0);
        // Scope annotations: the totals are the machine's RAM, not the
        // process footprint — frontend cards rely on these markers.
        assert_eq!(snapshot.used_memory_scope, "system");
        assert_eq!(snapshot.process_memory_scope, "process");
    }

    /// The container fields are all-or-nothing: either the cgroup numbers
    /// are present together (used + limit + scope, like `docker stats`),
    /// or they are all absent. A partially populated group would break the
    /// dashboard's "prefer container numbers" rule.
    #[test]
    fn memory_snapshot_container_fields_are_consistent() {
        let snapshot = memory_snapshot();
        match (
            snapshot.container_memory_used_bytes,
            snapshot.container_memory_scope,
        ) {
            (Some(used), Some(scope)) => {
                assert!(used > 0);
                assert!(scope == "cgroup_v1" || scope == "cgroup_v2");
                assert!(snapshot.container_memory_limit_bytes.is_some());
                assert!(snapshot
                    .container_memory_limit_bytes
                    .is_some_and(|l| l >= used));
                assert_eq!(
                    snapshot.container_memory_used,
                    Some(ByteSize(used).to_string())
                );
            },
            (None, None) => {
                assert_eq!(snapshot.container_memory_used_bytes, None);
                assert_eq!(snapshot.container_memory_limit_bytes, None);
                assert_eq!(snapshot.container_memory_used, None);
                assert_eq!(snapshot.container_memory_limit, None);
            },
            _ => panic!("container fields must be populated together"),
        }
    }

    // The idle guard reads the process CPU clock; on Linux this must always
    // resolve for our own process. Shared CI runners can fail to deliver
    // any ticks during a short busy loop (the matrix is contending for the
    // same kernel scheduler), so we accumulate ticks across three burns of
    // growing length instead of panicking on a single short one.
    #[cfg(target_os = "linux")]
    #[test]
    fn process_cpu_ticks_is_readable() {
        let mut total = 0u64;
        for ms in [50u64, 200, 1000] {
            burn(ms);
            if let Some(ticks) = process_cpu_ticks() {
                total = total.saturating_add(ticks);
            }
        }
        assert!(
            total > 0,
            "process never accumulated any CPU ticks across 1.25s of burn"
        );
    }

    // Empty-capture errors carry the guidance admins need to self-serve.
    #[test]
    fn empty_capture_errors_explain_themselves() {
        assert!(ProfileError::NoSamples
            .to_string()
            .contains("no samples were captured"));
        assert!(ProfileError::Idle.to_string().contains("almost no CPU"));
    }

    /// The load guard admits idle processes and refuses busy ones at the
    /// documented threshold; the boundary itself is inclusive.
    #[test]
    fn capture_guard_threshold() {
        assert!(capture_allowed_at(0.0));
        assert!(capture_allowed_at(1.5), "idle band must be admitted");
        assert!(capture_allowed_at(GUARD_MAX_CPU_PERCENT));
        assert!(!capture_allowed_at(GUARD_MAX_CPU_PERCENT + 0.5));
        assert!(!capture_allowed_at(100.0));
    }

    /// Capture stats reflect the recorded outcome. The stats mutex is held
    /// across the whole assertion so the (Linux-only) sequential sampling
    /// test cannot interleave and overwrite `last` mid-check.
    #[test]
    fn capture_stats_reflect_recorded_outcomes() {
        {
            let mut last = LAST_CAPTURE.lock().expect("stats lock");
            *last = Some(CaptureRecord {
                finished_at_ms: 42,
                duration_secs: 0.25,
                outcome: "idle".to_string(),
            });
            let stats = CaptureStats {
                total_started: TOTAL_SESSIONS
                    .load(std::sync::atomic::Ordering::Relaxed),
                last: last.clone(),
            };
            let recorded = stats.last.expect("last capture recorded");
            assert_eq!(recorded.outcome, "idle");
            assert!((recorded.duration_secs - 0.25).abs() < 1e-9);
            assert_eq!(recorded.finished_at_ms, 42);
            // Leave a clean slate for the sequential sampling test. The
            // post-reset read below is intentionally folded into the same
            // critical section: a parallel Linux sampling test could
            // otherwise record between the reset and the re-lock and flake
            // this assertion.
            *last = None;
            let stats = CaptureStats {
                total_started: TOTAL_SESSIONS
                    .load(std::sync::atomic::Ordering::Relaxed),
                last: last.clone(),
            };
            assert!(stats.last.is_none());
        }
    }
}
