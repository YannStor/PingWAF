//! CPU capture summaries and the self-contained SVG dashboard rendered
//! from them.
//!
//! Two consumers share this module:
//!
//! * the MCP `profile_cpu` tool — returns the SVG inline in its JSON result
//!   so an operator (or an LLM relay) can view or save it,
//! * the control-plane REST endpoint
//!   `GET /api/v1/debug/pprof/cpu/dashboard.svg` — serves the same SVG,
//!   optionally with an embedded script that polls the live metrics
//!   endpoint and refreshes the readout while the file is open in a
//!   browser.
//!
//! The dashboard shows the process CPU share over the capture window
//! (`utime+stime` delta), the inclusive sample distribution across the
//! hottest functions, the key capture metrics and a color-coded status
//! badge ([`CpuStatus`]). All dynamic strings are XML-escaped; the
//! optional refresh script only embeds values that pass [`cdata_safe`].

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{LazyLock, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sysinfo::{
    CpuRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, System,
    MINIMUM_CPU_UPDATE_INTERVAL,
};

/// How many of the hottest functions the task-distribution panel shows.
const TOP_FRAMES: usize = 10;

// ─────────────────────────────────────────────────────────────
// Last-capture summary cache (feeds /cpu/summary and MCP)
// ─────────────────────────────────────────────────────────────

/// The most recent capture summary, kept so that the `/cpu/summary`
/// endpoint and the MCP tools can answer "what did the last capture show"
/// without re-running a capture. Only the latest one is retained — the
/// cache is a single `Option`, bounded at one summary (KB-scale).
static LAST_SUMMARY: Mutex<Option<CpuCaptureSummary>> = Mutex::new(None);

/// Returns the most recent capture summary, if any capture has completed
/// (successfully or as an idle capture) since process start.
pub fn cached_summary() -> Option<CpuCaptureSummary> {
    LAST_SUMMARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Stores (or replaces) the last capture summary. A poisoned lock is
/// recovered the same way as the sampler above: the cache carries no
/// invariants beyond "some instance". Only compiled where captures can
/// actually store one (Linux; plus tests, which exercise it on every
/// platform) — elsewhere nothing ever calls it.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn store_summary(summary: CpuCaptureSummary) {
    *LAST_SUMMARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(summary);
}
/// Process CPU share of the capture window at which the badge flips from
/// `NORMAL` to `HIGH LOAD`. One busy core of the control plane is already
/// an anomaly worth flagging.
const HIGH_LOAD_FRACTION: f64 = 0.8;
/// Dashboard canvas width; the height follows the number of rows.
const WIDTH: f64 = 760.0;
/// Left/right canvas padding.
const PAD: f64 = 16.0;

// ─────────────────────────────────────────────────────────────
// Live CPU statistics (works on every platform)
// ─────────────────────────────────────────────────────────────

/// Point-in-time CPU usage of this process and the machine. The numbers
/// come from sysinfo's delta between the previous refresh and this one;
/// the persistent sampler below keeps that baseline alive across calls,
/// so back-to-back calls are stretched to sysinfo's minimum interval for
/// a meaningful delta.
#[derive(Debug, Clone, Serialize)]
pub struct CpuLiveStats {
    /// This process's CPU usage in percent of one core (multi-threaded
    /// work can exceed 100), as sysinfo reports it.
    pub process_cpu_percent: f32,
    /// Average CPU usage across all machine cores, in percent.
    pub host_cpu_percent: f32,
    /// Number of CPU cores on the machine.
    pub cores: usize,
    /// Unix epoch milliseconds at which the snapshot was taken.
    pub collected_at_ms: u64,
    /// Cumulative profiling capture statistics for this process: how many
    /// sessions started and how the most recent one ended.
    pub profiling: crate::CaptureStats,
}

/// Persistent sysinfo sampler. sysinfo computes CPU usage as a delta
/// between refreshes, so the `System` must outlive every call; the
/// baseline is refreshed once at construction to seed the first delta.
static CPU_SAMPLER: LazyLock<Mutex<System>> = LazyLock::new(|| {
    let mut sys = System::new();
    sys.refresh_cpu_specifics(CpuRefreshKind::everything());
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        false,
        ProcessRefreshKind::everything(),
    );
    Mutex::new(sys)
});

/// When the sampler last refreshed; calls closer together than sysinfo's
/// minimum interval are stretched apart.
static LAST_REFRESH: LazyLock<Mutex<Instant>> =
    LazyLock::new(|| Mutex::new(Instant::now()));

/// Collects a [`CpuLiveStats`] snapshot.
///
/// sysinfo needs at least [`MINIMUM_CPU_UPDATE_INTERVAL`] between CPU
/// refreshes for a meaningful delta; back-to-back calls sleep the
/// remainder of that interval first. Callers inside async handlers should
/// keep this off the executor thread (it may block briefly).
pub fn cpu_snapshot() -> CpuLiveStats {
    // `into_inner` over a poisoned lock is fine here: neither static
    // carries invariants beyond "some instance".
    stretch_to_minimum_interval();
    let mut sys = CPU_SAMPLER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        profiling: crate::capture_stats(),
    };
    mark_refreshed();
    stats
}

/// Sleeps until the last refresh is at least one minimum CPU interval
/// old, so the next refresh yields a meaningful usage delta.
fn stretch_to_minimum_interval() {
    let last = *LAST_REFRESH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let elapsed = last.elapsed();
    if elapsed < MINIMUM_CPU_UPDATE_INTERVAL {
        std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL - elapsed);
    }
}

/// Records that a refresh just happened.
fn mark_refreshed() {
    *LAST_REFRESH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
}

// ─────────────────────────────────────────────────────────────
// Capture summary
// ─────────────────────────────────────────────────────────────

/// Color-coded verdict printed on the dashboard badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuStatus {
    /// Samples were captured and the process stayed under the
    /// [`HIGH_LOAD_FRACTION`] share of one core.
    Normal,
    /// Samples were captured and the process burned at or above
    /// [`HIGH_LOAD_FRACTION`] of one core during the window.
    HighLoad,
    /// No samples: the process did no CPU work during the window.
    Idle,
    /// CPU sampling is unavailable on this platform (non-Linux); the
    /// dashboard renders from [`CpuLiveStats`] instead.
    PlatformLimited,
}

impl CpuStatus {
    /// Uppercase label printed inside the badge.
    pub fn label(self) -> &'static str {
        match self {
            CpuStatus::Normal => "NORMAL",
            CpuStatus::HighLoad => "HIGH LOAD",
            CpuStatus::Idle => "IDLE",
            CpuStatus::PlatformLimited => "PLATFORM-LIMITED",
        }
    }

    /// Badge fill color, dark-theme palette. Idle and platform-limited
    /// share the muted slate; high load is the only amber, normal the
    /// only green.
    pub fn badge_fill(self) -> &'static str {
        match self {
            CpuStatus::Normal => "#16a34a",
            CpuStatus::HighLoad => "#d97706",
            CpuStatus::Idle | CpuStatus::PlatformLimited => "#64748b",
        }
    }
}

/// One row of the task-distribution panel.
#[derive(Debug, Clone, Serialize)]
pub struct TopFrame {
    /// Resolved symbol name of the function.
    pub name: String,
    /// Inclusive sample count: every stack the function appeared in.
    pub samples: u64,
    /// `samples / total_samples`, in `0..=1`.
    pub share: f64,
}

/// Everything the dashboard (and the MCP tool result) needs to describe
/// one CPU capture.
#[derive(Debug, Clone, Serialize)]
pub struct CpuCaptureSummary {
    /// Sum of the weights of every captured stack.
    pub total_samples: u64,
    /// Effective sampling frequency in Hz.
    pub frequency: i32,
    /// Requested capture window in seconds.
    pub window_secs: u64,
    /// Process CPU time (`utime+stime`) burned during the window.
    pub cpu_secs: f64,
    /// `cpu_secs / window_secs`; can exceed 1 with multi-core work.
    pub process_cpu_fraction: f64,
    /// The hottest functions, most samples first.
    pub top_frames: Vec<TopFrame>,
    /// Overall verdict, also printed as the badge.
    pub status: CpuStatus,
    /// Unix epoch milliseconds at which the summary was built.
    pub collected_at_ms: u64,
}

impl CpuCaptureSummary {
    /// Classifies the capture: no samples means idle, at or above
    /// [`HIGH_LOAD_FRACTION`] of one core means high load, otherwise
    /// normal.
    fn classify(total_samples: u64, process_cpu_fraction: f64) -> CpuStatus {
        if total_samples == 0 {
            CpuStatus::Idle
        } else if process_cpu_fraction >= HIGH_LOAD_FRACTION {
            CpuStatus::HighLoad
        } else {
            CpuStatus::Normal
        }
    }

    /// Builds a summary from aggregated sample counts. Sample weights
    /// are inclusive: every function on a captured stack is credited
    /// with that stack's count once (the caller deduplicates per stack,
    /// so recursion does not inflate a single sample).
    ///
    /// Split out from the pprof-specific extraction (Linux-only, see the
    /// `finish_summary` session method) so that the classification,
    /// top-frame selection and rendering stay testable on every
    /// platform.
    pub(crate) fn from_counts(
        total_samples: u64,
        per_frame: HashMap<String, u64>,
        window_secs: f64,
        cpu_secs: f64,
        frequency: i32,
    ) -> Self {
        let mut top_frames: Vec<TopFrame> = per_frame
            .into_iter()
            .map(|(name, samples)| {
                let share = if total_samples > 0 {
                    samples as f64 / total_samples as f64
                } else {
                    0.0
                };
                TopFrame {
                    name,
                    samples,
                    share,
                }
            })
            .collect();
        top_frames.sort_by(|a, b| {
            b.samples.cmp(&a.samples).then_with(|| a.name.cmp(&b.name))
        });
        top_frames.truncate(TOP_FRAMES);

        let process_cpu_fraction = if window_secs > 0.0 {
            cpu_secs / window_secs
        } else {
            0.0
        };
        CpuCaptureSummary {
            total_samples,
            frequency,
            window_secs: window_secs.round() as u64,
            cpu_secs,
            process_cpu_fraction,
            top_frames,
            status: CpuCaptureSummary::classify(
                total_samples,
                process_cpu_fraction,
            ),
            collected_at_ms: now_ms(),
        }
    }

    /// A platform-limited summary rendered from live statistics when CPU
    /// sampling is unavailable (non-Linux). The dashboard then shows the
    /// current readout with a `PLATFORM-LIMITED` badge instead of a
    /// capture. The window/fraction pair is chosen so the usage panel
    /// mirrors the live readout; the idle classification that
    /// zero samples would normally produce is overridden, because "no
    /// samples" here means "no sampler", not "no work".
    pub fn platform_limited(live: &CpuLiveStats) -> Self {
        let fraction = f64::from(live.process_cpu_percent) / 100.0;
        let mut summary =
            Self::from_counts(0, HashMap::new(), 1.0, fraction, 0);
        summary.status = CpuStatus::PlatformLimited;
        summary
    }
}

/// Builds a summary from a symbolized pprof report by aggregating
/// inclusive per-function sample counts. Linux-only, like the sampling
/// itself; [`CpuCaptureSummary::from_counts`] is the platform-independent
/// half that classifies and selects the top frames.
#[cfg(target_os = "linux")]
pub(crate) fn summarize_report(
    report: &pprof::Report,
    window_secs: f64,
    cpu_secs: f64,
) -> CpuCaptureSummary {
    let mut total_samples = 0_u64;
    let mut per_frame: HashMap<String, u64> = HashMap::new();
    for (frames, count) in &report.data {
        // The collector only stores positive counts; clamp defensively.
        let count = (*count).max(0) as u64;
        if count == 0 {
            continue;
        }
        total_samples += count;
        let mut seen = std::collections::HashSet::new();
        for depth in &frames.frames {
            for symbol in depth {
                let name = symbol.name();
                if name.is_empty() || !seen.insert(name.clone()) {
                    continue;
                }
                *per_frame.entry(name).or_insert(0) += count;
            }
        }
    }
    // When no samples were collected the pprof report's `timing.frequency`
    // falls back to `1` (a crate default for empty captures), which the
    // dashboard would then render as "at 1 Hz" — misleading operators who
    // asked for 99 Hz. The reported frequency is trustworthy only when we
    // have at least one sample to derive a period from; otherwise fall
    // back to the default the request actually asked for.
    let frequency = if total_samples > 0 && report.timing.frequency > 0 {
        report.timing.frequency
    } else {
        crate::DEFAULT_FREQUENCY
    };
    CpuCaptureSummary::from_counts(
        total_samples,
        per_frame,
        window_secs,
        cpu_secs,
        frequency,
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────
// SVG dashboard rendering
// ─────────────────────────────────────────────────────────────

/// Options for the optional live-refresh script embedded in the SVG.
///
/// When `refresh_url` is set the SVG carries a `<script>` that polls that
/// URL every `refresh_seconds` and updates the live readout. The URL
/// points at the control-plane metrics endpoint, which is Bearer-only —
/// browsers opened from a saved file cannot attach the header
/// themselves, so `refresh_token` (the caller's own token, opt-in,
/// echoed back into the body only) lets the poll authenticate. Both
/// strings must pass [`cdata_safe`] or the script is dropped.
#[derive(Debug, Clone, Default)]
pub struct DashboardSvgOpts {
    /// Live-metrics URL polled by the embedded script; `None` renders a
    /// static dashboard.
    pub refresh_url: Option<String>,
    /// Poll interval in seconds; clamped to at least one second.
    pub refresh_seconds: u32,
    /// Bearer token inlined into the poll's `Authorization` header.
    pub refresh_token: Option<String>,
}

/// Renders the self-contained dashboard SVG for one capture.
///
/// The output is a single dark-theme `<svg>` document: a status badge,
/// the process CPU share over the window, an optional live readout
/// (kept fresh by the embedded script), the task-distribution bars and
/// the key metrics. All dynamic text is XML-escaped, so symbol names
/// from the capture cannot break out of the document.
pub fn render_cpu_dashboard_svg(
    summary: &CpuCaptureSummary,
    live: Option<&CpuLiveStats>,
    opts: &DashboardSvgOpts,
) -> String {
    // Vertical layout, computed top-down so the canvas height follows
    // the number of task rows.
    let usage_label_y = 64.0;
    let usage_number_y = 92.0;
    let usage_bar_y = 102.0;
    let task_title_y = 132.0;
    let task_rows_y = 148.0;
    let task_rows_height = if summary.top_frames.is_empty() {
        18.0
    } else {
        summary.top_frames.len() as f64 * 20.0
    };
    let metrics_title_y = task_rows_y + task_rows_height + 24.0;
    let metrics_height = 18.0 + 4.0 * 16.0;
    let live_y = metrics_title_y + metrics_height + 22.0;
    let has_live = live.is_some() || opts.refresh_url.is_some();
    let live_height = if has_live { 18.0 } else { 0.0 };
    let footer_y = live_y + live_height + 22.0;
    let height = footer_y + 16.0;

    let mut svg = String::with_capacity(8 * 1024);
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{WIDTH}\" \
         height=\"{height:.0}\" viewBox=\"0 0 {WIDTH} {height:.0}\" \
         font-family=\"ui-monospace, 'SF Mono', Menlo, monospace\">\n"
    ));
    svg.push_str("<rect width=\"100%\" height=\"100%\" fill=\"#0f172a\"/>\n");

    // Header: title, badge, timestamp.
    svg.push_str(&format!(
        "<text x=\"{PAD}\" y=\"36\" fill=\"#e2e8f0\" font-size=\"17\" \
         font-weight=\"bold\">PingWAF CPU Profile</text>\n"
    ));
    let badge_width = 24.0 + summary.status.label().len() as f64 * 7.6;
    let badge_x = WIDTH - PAD - badge_width;
    svg.push_str(&format!(
        "<rect x=\"{badge_x:.1}\" y=\"18\" width=\"{badge_width:.1}\" \
         height=\"22\" rx=\"5\" fill=\"{}\"/>\n",
        summary.status.badge_fill()
    ));
    svg.push_str(&format!(
        "<text x=\"{:.1}\" y=\"34\" fill=\"#0f172a\" font-size=\"12\" \
         font-weight=\"bold\" text-anchor=\"middle\">{}</text>\n",
        badge_x + badge_width / 2.0,
        summary.status.label()
    ));
    svg.push_str(&format!(
        "<text x=\"{:.1}\" y=\"36\" fill=\"#94a3b8\" font-size=\"11\" \
         text-anchor=\"end\">collected {}</text>\n",
        badge_x - 12.0,
        iso8601(summary.collected_at_ms),
    ));

    // CPU usage panel: big share-of-window number plus a bar.
    let percent = summary.process_cpu_fraction * 100.0;
    svg.push_str(&format!(
        "<text x=\"{PAD}\" y=\"{usage_label_y:.0}\" fill=\"#e2e8f0\" \
         font-size=\"11\" fill-opacity=\"0.7\">PROCESS CPU OVER THE \
         WINDOW</text>\n"
    ));
    svg.push_str(&format!(
        "<text x=\"{PAD}\" y=\"{usage_number_y:.0}\" fill=\"#38bdf8\" \
         font-size=\"26\" font-weight=\"bold\">{percent:.1}%</text>\n"
    ));
    if summary.process_cpu_fraction > 0.0 {
        let cores = (summary.process_cpu_fraction).max(0.05);
        svg.push_str(&format!(
            "<text x=\"{:.0}\" y=\"{usage_number_y:.0}\" fill=\"#94a3b8\" \
             font-size=\"11\">(≈{cores:.1} core{})</text>\n",
            PAD + format!("{percent:.1}").len() as f64 * 15.0 + 10.0,
            if summary.process_cpu_fraction >= 2.0 {
                "s"
            } else {
                ""
            }
        ));
    }
    // Usage bar, scaled so four busy cores fill the track.
    let track_width = WIDTH - 2.0 * PAD;
    let fill =
        (summary.process_cpu_fraction / 4.0).clamp(0.0, 1.0) * track_width;
    svg.push_str(&format!(
        "<rect x=\"{PAD}\" y=\"{usage_bar_y:.0}\" width=\"{track_width:.0}\" \
         height=\"6\" rx=\"3\" fill=\"#1e293b\"/>\n\
         <rect x=\"{PAD}\" y=\"{usage_bar_y:.0}\" width=\"{fill:.0}\" \
         height=\"6\" rx=\"3\" fill=\"#38bdf8\"/>\n"
    ));

    // Task distribution panel.
    svg.push_str(&format!(
        "<text x=\"{PAD}\" y=\"{task_title_y:.0}\" fill=\"#e2e8f0\" \
         font-size=\"11\" fill-opacity=\"0.7\">TASK DISTRIBUTION — TOP \
         FUNCTIONS (INCLUSIVE SHARE OF SAMPLES)</text>\n"
    ));
    let max_share = summary
        .top_frames
        .iter()
        .map(|frame| frame.share)
        .fold(0.0_f64, f64::max);
    let name_width = 330.0;
    let bar_x = PAD + name_width + 8.0;
    let bar_max = WIDTH - bar_x - PAD - 52.0;
    if summary.top_frames.is_empty() {
        svg.push_str(&format!(
            "<text x=\"{PAD}\" y=\"{task_rows_y:.0}\" fill=\"#64748b\" \
             font-size=\"11\">(no samples — the process was idle during \
             the window)</text>\n"
        ));
    } else {
        for (index, frame) in summary.top_frames.iter().enumerate() {
            let row_y = task_rows_y + index as f64 * 20.0;
            svg.push_str(&format!(
                "<text x=\"{PAD}\" y=\"{row_y:.0}\" fill=\"#cbd5e1\" \
                 font-size=\"11\">{}</text>\n",
                xml_escape(&truncate_middle(&frame.name, 52))
            ));
            let bar_width = if max_share > 0.0 {
                (frame.share / max_share) * bar_max
            } else {
                0.0
            };
            svg.push_str(&format!(
                "<rect x=\"{bar_x:.0}\" y=\"{row_y:.0}\" width=\"\
                 {bar_width:.0}\" height=\"9\" fill=\"#f59e0b\" \
                 fill-opacity=\"0.85\" transform=\"translate(0,-9)\"/>\n"
            ));
            svg.push_str(&format!(
                "<text x=\"{WIDTH:.0}\" y=\"{row_y:.0}\" fill=\"#fbbf24\" \
                 font-size=\"11\" text-anchor=\"end\">{:.1}%</text>\n",
                frame.share * 100.0
            ));
        }
    }

    // Key metrics panel.
    svg.push_str(&format!(
        "<text x=\"{PAD}\" y=\"{metrics_title_y:.0}\" fill=\"#e2e8f0\" \
         font-size=\"11\" fill-opacity=\"0.7\">KEY METRICS</text>\n"
    ));
    let hotspot = summary
        .top_frames
        .first()
        .map(|frame| truncate_middle(&frame.name, 40))
        .unwrap_or_else(|| "—".to_string());
    let metrics = [
        format!(
            "capture window: {}s at {} Hz — {} samples",
            summary.window_secs, summary.frequency, summary.total_samples
        ),
        format!(
            "process CPU time in window: {:.1}s ({percent:.1}% of one core)",
            summary.cpu_secs
        ),
        format!("hottest function: {hotspot}"),
        format!(
            "status: {} — sampling via SIGPROF (Linux only)",
            summary.status.label()
        ),
    ];
    for (index, line) in metrics.iter().enumerate() {
        svg.push_str(&format!(
            "<text x=\"{PAD}\" y=\"{:.0}\" fill=\"#94a3b8\" font-size=\"11\">\
             {}</text>\n",
            metrics_title_y + 18.0 + index as f64 * 16.0,
            xml_escape(line)
        ));
    }

    // Live readout strip, optionally kept fresh by the embedded script.
    if has_live {
        svg.push_str(&format!(
            "<text x=\"{PAD}\" y=\"{live_y:.0}\" fill=\"#94a3b8\" \
             font-size=\"11\">live: process <tspan \
             id=\"live-process-cpu\">{}</tspan> · host <tspan \
             id=\"live-host-cpu\">{}</tspan> · <tspan \
             id=\"live-updated\">{}</tspan></text>\n",
            live.map(|stats| format!("{:.1}%", stats.process_cpu_percent))
                .unwrap_or_else(|| "—".to_string()),
            live.map(|stats| format!("{:.1}%", stats.host_cpu_percent))
                .unwrap_or_else(|| "—".to_string()),
            live.map(|stats| iso8601(stats.collected_at_ms))
                .unwrap_or_else(|| "—".to_string()),
        ));
    }

    // Footer.
    svg.push_str(&format!(
        "<text x=\"{PAD}\" y=\"{footer_y:.0}\" fill=\"#475569\" \
         font-size=\"10\">PingWAF built-in profiler — symbols resolve from \
         the binary's symbol table; profile a release-perf build for \
         readable names.</text>\n"
    ));

    // Optional embedded live-refresh script.
    let script = refresh_script(opts);
    if script.is_some() && opts.refresh_token.is_some() {
        // The poller carries the caller's own token so it can
        // authenticate from inside the file; anyone the file is shared
        // with gets that token, so the footer says so.
        svg.push_str(&format!(
            "<text x=\"{PAD}\" y=\"{:.0}\" fill=\"#b45309\" font-size=\"10\">\
             this file embeds a temporary credential for live refresh — \
             do not share it</text>\n",
            footer_y + 13.0
        ));
    }
    if let Some(script) = script {
        svg.push_str(&script);
    }

    svg.push_str("</svg>\n");
    svg
}

/// The embedded poller, or `None` when the options do not request one or
/// carry values that cannot be embedded safely.
fn refresh_script(opts: &DashboardSvgOpts) -> Option<String> {
    let url = opts.refresh_url.as_deref()?;
    if !cdata_safe(url) || url.contains('"') {
        return None;
    }
    let token = match opts.refresh_token.as_deref() {
        None => None,
        Some(token) if cdata_safe(token) && !token.contains('"') => Some(token),
        // A token that cannot be embedded safely must not silently
        // disable the whole script; poll unauthenticated instead.
        Some(_) => None,
    };
    let seconds = opts.refresh_seconds.clamp(1, 60);
    let mut script = String::with_capacity(1024);
    script.push_str(
        "<script type=\"text/javascript\"><![CDATA[\n\
         (function () {\n\
         \"use strict\";\n\
         var INTERVAL_MS = ",
    );
    // `write!` into a String cannot fail; `ok()?` only satisfies clippy's
    // must_use by branching on an infallible operation.
    write!(script, "{}", seconds * 1000).ok()?;
    script.push_str(";\nvar METRICS_URL = \"");
    script.push_str(url);
    script.push_str("\";\n");
    if let Some(token) = token {
        script.push_str("var AUTH = \"Bearer ");
        script.push_str(token);
        script.push_str("\";\n");
    } else {
        script.push_str("var AUTH = null;\n");
    }
    script.push_str(
        "function setText(id, value) {\n\
           var el = document.getElementById(id);\n\
           if (el) { el.textContent = value; }\n\
         }\n\
         function poll() {\n\
           fetch(METRICS_URL, AUTH ? { headers: { Authorization: AUTH } } : {})\n\
             .then(function (r) { return r.ok ? r.json() : null; })\n\
             .then(function (data) {\n\
               if (!data) { return; }\n\
               setText(\"live-process-cpu\", data.process_cpu_percent.toFixed(1) + \"%\");\n\
               setText(\"live-host-cpu\", data.host_cpu_percent.toFixed(1) + \"%\");\n\
               setText(\"live-updated\", new Date(data.collected_at_ms).toISOString());\n\
             })\n\
             .catch(function () {});\n\
         }\n\
         setInterval(poll, INTERVAL_MS);\n\
         poll();\n\
         })();\n\
         ]]></script>\n",
    );
    Some(script)
}

/// True when `value` can be embedded inside a CDATA section without
/// terminating it early, injecting control characters — or breaking out
/// of the script under an HTML parser, which treats CDATA as a bogus
/// comment and stops the script at the first `</script>`; angle brackets
/// are therefore rejected even though the XML parser would tolerate
/// them.
fn cdata_safe(value: &str) -> bool {
    !value.contains("]]>")
        && !value.contains('<')
        && !value.chars().any(char::is_control)
}

/// Escapes the five XML metacharacters.
fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Middle-truncates long symbol names, keeping both the crate prefix and
/// the trailing function name, which is where the identity lives.
fn truncate_middle(name: &str, max: usize) -> String {
    let char_count = name.chars().count();
    if char_count <= max {
        return name.to_string();
    }
    let head = max * 2 / 3;
    let tail = max - head;
    let head_str: String = name.chars().take(head).collect();
    let tail_str: String =
        name.chars().skip(char_count.saturating_sub(tail)).collect();
    format!("{head_str}…{tail_str}")
}

/// Renders epoch milliseconds as a sortable UTC timestamp.
fn iso8601(epoch_ms: u64) -> String {
    let secs = (epoch_ms / 1000) as i64;
    let millis = epoch_ms % 1000;
    // Civil-from-days algorithm (Howard Hinnant), no chrono dependency
    // needed for one timestamp on a dashboard.
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}\
         .{millis:03}Z"
    )
}

/// Converts days since the Unix epoch to `(year, month, day)`.
fn civil_from_days(days: i64) -> (i64, u64, u64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u64, d as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_summary() -> CpuCaptureSummary {
        CpuCaptureSummary {
            total_samples: 120,
            frequency: 99,
            window_secs: 10,
            cpu_secs: 2.5,
            process_cpu_fraction: 0.25,
            top_frames: vec![
                TopFrame {
                    name: "evil<func> & \"quotes\"".to_string(),
                    samples: 100,
                    share: 100.0 / 120.0,
                },
                TopFrame {
                    name: "b_function".to_string(),
                    samples: 20,
                    share: 20.0 / 120.0,
                },
            ],
            status: CpuStatus::Normal,
            collected_at_ms: 1_760_000_000_000,
        }
    }

    #[test]
    fn live_snapshot_is_populated() {
        let stats = cpu_snapshot();
        assert!(stats.collected_at_ms > 0);
        assert!(stats.cores > 0);
        assert!(
            stats.process_cpu_percent >= 0.0,
            "cpu usage is never negative"
        );
        assert!(stats.host_cpu_percent >= 0.0);
    }

    #[test]
    fn platform_limited_summary_carries_the_live_readout() {
        let stats = cpu_snapshot();
        let summary = CpuCaptureSummary::platform_limited(&stats);
        assert_eq!(summary.status, CpuStatus::PlatformLimited);
        assert_eq!(summary.total_samples, 0);
        assert!(summary.top_frames.is_empty());
        assert!(
            (summary.process_cpu_fraction
                - f64::from(stats.process_cpu_percent) / 100.0)
                .abs()
                < 1e-9
        );
    }

    #[test]
    fn status_labels_and_badges_are_distinct() {
        let labels = [
            CpuStatus::Normal.label(),
            CpuStatus::HighLoad.label(),
            CpuStatus::Idle.label(),
            CpuStatus::PlatformLimited.label(),
        ];
        let unique: std::collections::BTreeSet<&str> =
            labels.iter().copied().collect();
        assert_eq!(unique.len(), labels.len());
        assert_eq!(CpuStatus::Normal.badge_fill(), "#16a34a");
        assert_eq!(CpuStatus::HighLoad.badge_fill(), "#d97706");
    }

    #[test]
    fn classification_follows_samples_and_share() {
        assert_eq!(CpuCaptureSummary::classify(0, 0.0), CpuStatus::Idle);
        assert_eq!(
            CpuCaptureSummary::classify(10, HIGH_LOAD_FRACTION),
            CpuStatus::HighLoad
        );
        assert_eq!(
            CpuCaptureSummary::classify(10, HIGH_LOAD_FRACTION * 0.99),
            CpuStatus::Normal
        );
    }

    #[test]
    fn dashboard_renders_panels_and_escapes_symbols() {
        let svg = render_cpu_dashboard_svg(
            &sample_summary(),
            None,
            &DashboardSvgOpts::default(),
        );
        assert!(svg.contains("<svg"));
        assert!(svg.contains("PingWAF CPU Profile"));
        assert!(svg.contains(">NORMAL<"));
        assert!(svg.contains("25.0%"));
        assert!(svg.contains("TASK DISTRIBUTION"));
        assert!(svg.contains("evil&lt;func&gt;"));
        assert!(svg.contains("&quot;quotes&quot;"));
        // No raw metacharacters from the frame name survive.
        assert!(!svg.contains("<func>"));
        assert!(!svg.contains("</script"), "no script by default");
        assert!(svg.ends_with("</svg>\n"));
    }

    #[test]
    fn idle_capture_renders_the_placeholder_row() {
        let summary = CpuCaptureSummary {
            total_samples: 0,
            frequency: 99,
            window_secs: 10,
            cpu_secs: 0.0,
            process_cpu_fraction: 0.0,
            top_frames: Vec::new(),
            status: CpuStatus::Idle,
            collected_at_ms: 1_760_000_000_000,
        };
        let svg = render_cpu_dashboard_svg(
            &summary,
            None,
            &DashboardSvgOpts::default(),
        );
        assert!(svg.contains("IDLE"));
        assert!(svg.contains("(no samples"));
    }

    #[test]
    fn refresh_script_is_embedded_only_with_a_safe_url() {
        let summary = CpuCaptureSummary::platform_limited(&cpu_snapshot());
        let mut opts = DashboardSvgOpts {
            refresh_url: Some("/api/v1/debug/pprof/cpu/metrics".to_string()),
            refresh_seconds: 0, // clamped to one second
            refresh_token: Some("jwt.not_unsafe".to_string()),
        };
        let svg = render_cpu_dashboard_svg(&summary, None, &opts);
        assert!(svg.contains("<script"));
        assert!(svg.contains("INTERVAL_MS = 1000"));
        assert!(svg.contains("Bearer jwt.not_unsafe"));
        assert!(svg.contains("id=\"live-process-cpu\""));

        // A URL that would terminate the CDATA section drops the script.
        opts.refresh_url = Some("]]><evil>".to_string());
        let svg = render_cpu_dashboard_svg(&summary, None, &opts);
        assert!(!svg.contains("<script"), "unsafe URL must drop the script");

        // A token that would terminate the CDATA section keeps the
        // script but polls unauthenticated instead.
        opts.refresh_url = Some("/api/v1/debug/pprof/cpu/metrics".to_string());
        opts.refresh_token = Some("bad]]>token".to_string());
        let svg = render_cpu_dashboard_svg(&summary, None, &opts);
        assert!(svg.contains("var AUTH = null;"));

        // Angle brackets are rejected too: an HTML parser stops the
        // script at the first `</script>`, so `<` must never get in.
        opts.refresh_token = Some("safe</script>token".to_string());
        let svg = render_cpu_dashboard_svg(&summary, None, &opts);
        assert!(svg.contains("var AUTH = null;"));
    }

    #[test]
    fn truncation_keeps_head_and_tail() {
        let name = "a".repeat(80);
        let cut = truncate_middle(&name, 52);
        assert!(cut.starts_with('a'));
        assert!(cut.contains('…'));
        assert!(cut.chars().count() <= 53);
        assert_eq!(truncate_middle("short", 52), "short");
        // Multi-byte characters must not panic the cutter.
        assert!(truncate_middle("中文测试", 3).contains('…'));
    }

    #[test]
    fn iso8601_matches_known_instants() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        // 2025-10-15T00:00:00Z = 1760486400s.
        assert_eq!(iso8601(1_760_486_400_123), "2025-10-15T00:00:00.123Z");
        // Leap-year boundary: 2024-02-29T12:00:00Z = 1709208000s.
        assert_eq!(iso8601(1_709_208_000_000), "2024-02-29T12:00:00.000Z");
    }

    /// The last-capture cache stores and replaces atomically; reading back
    /// through `cached_summary` must reflect the newest entry. The mutex is
    /// held across the assertions so a parallel capture test cannot
    /// interleave (the sampling test only writes via take_report on Linux).
    #[test]
    fn summary_cache_stores_and_replaces() {
        {
            let mut last = LAST_SUMMARY.lock().expect("summary cache lock");
            let mut first = sample_summary();
            first.collected_at_ms = 1;
            store_summary(first);
            assert_eq!(cached_summary().expect("stored").collected_at_ms, 1);

            let mut second = sample_summary();
            second.collected_at_ms = 2;
            store_summary(second);
            assert_eq!(cached_summary().expect("replaced").collected_at_ms, 2);

            // Leave a clean slate for other tests.
            *last = None;
        }
        assert!(cached_summary().is_none());
    }

    /// Top-frame selection is bounded by the panel budget: extra frames
    /// below the cut are folded away, keeping the summary KB-scale.
    #[test]
    fn from_counts_is_bounded_to_the_panel_budget() {
        let mut per_frame = HashMap::new();
        for index in 0..(TOP_FRAMES * 10) {
            per_frame.insert(format!("f{index}"), 100 - index as u64);
        }
        let summary =
            CpuCaptureSummary::from_counts(10_000, per_frame, 1.0, 0.0, 99);
        assert_eq!(summary.top_frames.len(), TOP_FRAMES);
        // Sorted hottest-first.
        assert!(summary.top_frames[0].samples >= summary.top_frames[1].samples);
    }
}
