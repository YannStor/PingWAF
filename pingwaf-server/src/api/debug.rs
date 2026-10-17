//! Built-in pprof-style profiling endpoints (admin only).
//!
//! * `GET /api/v1/debug/pprof/profile?seconds=30&frequency=99` — CPU samples
//!   as a gzip-compressed pprof protobuf, consumable by `go tool pprof`
//! * `GET /api/v1/debug/pprof/flamegraph?seconds=30` — SVG flamegraph
//! * `GET /api/v1/debug/pprof/cpu/dashboard.svg` — self-contained SVG
//!   dashboard (usage, task distribution, key metrics, status badge),
//!   optionally with an embedded script that polls `cpu/metrics` and
//!   refreshes the live readout while the file is open in a browser
//! * `GET /api/v1/debug/pprof/cpu/metrics` — cheap live CPU snapshot
//!   (process and host usage) polled by the dashboard's refresh script
//! * `GET /api/v1/debug/pprof/memory` — JSON memory snapshot
//!
//! CPU sampling is process-global: while a capture is running, further
//! requests are answered with `409 Conflict`. Sampling requires Linux (the
//! only platform with a signal-safe unwinder); elsewhere the capture
//! endpoints answer `501 Not Implemented` and the memory snapshot still
//! works. The CPU dashboard degrades instead of failing: off-Linux it
//! renders a `PLATFORM-LIMITED` board from the live snapshot.
//!
//! Symbols are resolved from the binary's symbol table; the default
//! `release` profile strips them, so profile a `release-perf` build for
//! readable flame graphs.

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AdminUser;
use axum::extract::Query;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use pingwaf_pprof::{
    start_session, DashboardSvgOpts, ProfileError, ProfilingSession,
    MAX_SECONDS,
};
use serde::Deserialize;
use std::time::Duration;

/// Default capture window for a dashboard render.
///
/// Five seconds is enough to capture a representative busy slice on a
/// reasonably busy process, and the dashboard returns in roughly the same
/// time a user expects from a "now" tab in any monitoring tool. Operators
/// who want a more precise profile can pass `?seconds=N` (clamped to
/// `1..=MAX_SECONDS`) at the cost of a longer first response.
const DEFAULT_CAPTURE_SECONDS: u64 = 5;

/// Query parameters accepted by both capture endpoints.
#[derive(Debug, Default, Deserialize)]
pub struct ProfileQuery {
    /// Capture window; clamped to `1..=MAX_SECONDS`, default
    /// [`DEFAULT_CAPTURE_SECONDS`].
    pub seconds: Option<u64>,
    /// Sampling frequency in Hz; clamped by the profiling crate, default 99.
    pub frequency: Option<i32>,
    /// Poll interval in seconds for the dashboard's embedded live-refresh
    /// script; clamped to `1..=60`. Absent renders a static dashboard.
    pub refresh: Option<u32>,
    /// Generate light in-process load during the capture window. The CPU
    /// sampler is time-based and records nothing on an idle process, so a
    /// quiet instance needs this (or real traffic) to produce a profile.
    pub selfload: Option<bool>,
}

/// Maps profiling finish errors: an empty capture is not a server fault —
/// the client asked to profile an idle process — so it is a `409 Conflict`
/// with guidance, not a `500`.
fn finish_err(err: ProfileError) -> ApiError {
    match err {
        ProfileError::NoSamples | ProfileError::Idle => {
            ApiError::Conflict(err.to_string())
        },
        // The watchdog aborted the sampler mid-window.
        ProfileError::MemoryPressure => {
            ApiError::ServiceUnavailable(err.to_string())
        },
        other => ApiError::Internal(other.to_string()),
    }
}

/// The 503 returned when the load guard refuses a capture. Self-serving on
/// purpose: measured value, limit, and the expected action in one message.
fn load_guard_error(process_cpu_percent: f32) -> ApiError {
    ApiError::ServiceUnavailable(format!(
        "the process is busy (CPU {:.0}% of one core, limit {:.0}%); \
         profiling under load risks an out-of-memory kill — retry when \
         the load drops",
        process_cpu_percent,
        pingwaf_pprof::GUARD_MAX_CPU_PERCENT
    ))
}

async fn begin_session(
    endpoint: &str,
    query: &ProfileQuery,
) -> Result<ProfilingSession, ApiError> {
    // Load guard first: the sampler allocates inside its signal handler,
    // which is harmless on an idle process but can balloon RSS to an OOM
    // kill within the capture window when the process is busy (measured:
    // 122MB -> 1GB in 90s on the demo instance). cpu_snapshot sleeps out a
    // minimum refresh interval, so it stays off the executor thread.
    let live = tokio::task::spawn_blocking(pingwaf_pprof::cpu_snapshot)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if !pingwaf_pprof::capture_allowed_at(live.process_cpu_percent) {
        // Recorded into the capture stats too: the metrics endpoint must be
        // able to answer "why is my capture not running?" without grepping
        // logs. No session started, so total_started stays untouched.
        pingwaf_pprof::record_prestart_outcome("load_guard");
        log_capture(endpoint, "load_guard");
        return Err(load_guard_error(live.process_cpu_percent));
    }
    let frequency = query.frequency.unwrap_or_default();
    start_session(frequency)
        .map_err(|err| {
            log_capture(endpoint, reject_tag(&err));
            match err {
                ProfileError::AlreadyActive => {
                    ApiError::Conflict(err.to_string())
                },
                ProfileError::UnsupportedPlatform => {
                    ApiError::NotImplemented(err.to_string())
                },
                // Admission/watchdog: host memory below the floor — the
                // encode phase would push the box into an OOM kill.
                ProfileError::MemoryPressure => {
                    ApiError::ServiceUnavailable(err.to_string())
                },
                other => ApiError::Internal(other.to_string()),
            }
        })
        .inspect(|session| {
            spawn_watchdog(session, capture_seconds(query));
        })
}

/// Spawns the mid-window memory watchdog for a freshly started capture:
/// if available memory crosses the soft floor while sampling, the sampler
/// is aborted and the pending `finish_*` answers with `MemoryPressure`.
#[cfg(target_os = "linux")]
fn spawn_watchdog(session: &ProfilingSession, seconds: u64) {
    pingwaf_pprof::spawn_memory_watchdog(
        session.abort_handle(),
        std::time::Duration::from_secs(seconds.saturating_add(1)),
    );
}

#[cfg(not(target_os = "linux"))]
fn spawn_watchdog(_session: &ProfilingSession, _seconds: u64) {}

fn capture_seconds(query: &ProfileQuery) -> u64 {
    query
        .seconds
        .unwrap_or(DEFAULT_CAPTURE_SECONDS)
        .clamp(1, MAX_SECONDS)
}

/// Light in-process load for `?selfload=true` captures.
///
/// The CPU sampler is time-based (ITIMER_PROF) and records nothing on an
/// idle process, so a quiet instance cannot produce a flame graph without
/// traffic. Two tokio tasks doing short spin bursts between yields give the
/// sampler frames to catch, at a bounded CPU cost, for exactly the capture
/// window. Honest limitation: the profile shows the async runtime and this
/// workload, not site handlers — for attribution of *memory* use the heap
/// endpoint (`/debug/pprof/heap`, `mem-prof` builds) is the right tool.
async fn run_selfload(seconds: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let task = |deadline: tokio::time::Instant| async move {
        let mut acc = 0u64;
        while tokio::time::Instant::now() < deadline {
            for _ in 0..20_000 {
                acc = acc.wrapping_add(std::hint::black_box(
                    acc.count_ones() as u64
                ));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let _ = std::hint::black_box(acc);
    };
    let (a, b) = tokio::join!(
        tokio::spawn(task(deadline)),
        tokio::spawn(task(deadline))
    );
    let _ = (a, b);
}

/// Spawns the selfload workload when the request opted in; the tasks stop
/// themselves at the window deadline, so no abort plumbing is needed.
fn maybe_start_selfload(query: &ProfileQuery) {
    if query.selfload.unwrap_or(false) {
        // +1s so the workload still covers the tail of the capture window
        // under scheduler jitter; the tasks self-terminate at the deadline.
        tokio::spawn(run_selfload(capture_seconds(query).saturating_add(1)));
    }
}

/// Whether CPU-capture endpoints accept work — single source of truth in
/// `pingwaf_pprof::captures_enabled`, shared with the data-plane admin
/// plugin and the MCP tool.
fn capture_enabled() -> bool {
    pingwaf_pprof::captures_enabled()
}

fn capture_disabled_error() -> ApiError {
    ApiError::ServiceUnavailable(
        "CPU profiling captures are disabled on this deployment \
         (config [basic] pprof_enabled = false, or legacy env \
         PINGWAF_PPROF_ENABLED=0); the memory and live-metrics snapshots \
         remain available"
            .to_string(),
    )
}

/// Post-capture audit line: which endpoint ran, how it ended, and the RSS
/// right afterwards. Manual captures are rare, so the snapshot cost is
/// irrelevant next to the evidence value when correlating memory spikes
/// with capture activity (demo OOM investigation, 2026-10-16).
fn log_capture(endpoint: &str, outcome: &str) {
    let rss = pingwaf_pprof::memory_snapshot().rss;
    tracing::info!(endpoint, outcome, rss = %rss, "profiling capture finished");
}

/// Short tag for a rejected capture, mirroring `finish_err`'s mapping.
fn reject_tag(err: &ProfileError) -> &'static str {
    match err {
        ProfileError::NoSamples => "no_samples",
        ProfileError::Idle => "idle",
        ProfileError::AlreadyActive => "already_active",
        ProfileError::UnsupportedPlatform => "unsupported",
        _ => "error",
    }
}

/// `GET /api/v1/debug/pprof/profile`
async fn profile_cpu(
    admin: AdminUser,
    Query(query): Query<ProfileQuery>,
) -> Result<Response, ApiError> {
    let _ = admin;
    profile_cpu_impl(axum::extract::Query(query)).await
}

pub(crate) async fn profile_cpu_impl(
    Query(query): Query<ProfileQuery>,
) -> Result<Response, ApiError> {
    if !capture_enabled() {
        return Err(capture_disabled_error());
    }
    let session = begin_session("profile", &query).await?;
    maybe_start_selfload(&query);
    tokio::time::sleep(Duration::from_secs(capture_seconds(&query))).await;
    let bytes = tokio::task::spawn_blocking(move || session.finish_pprof())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|err| {
            log_capture("profile", reject_tag(&err));
            finish_err(err)
        })?;
    log_capture("profile", "ok");

    // The body is already gzip: `Content-Encoding` states that fact and
    // keeps the compression middleware from encoding it a second time.
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (header::CONTENT_ENCODING, HeaderValue::from_static("gzip")),
            // Capture output is only valid for the instant it was produced.
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static(
                    "attachment; filename=\"pingwaf-cpu.pb.gz\"",
                ),
            ),
        ],
        bytes,
    )
        .into_response())
}

/// `GET /api/v1/debug/pprof/flamegraph`
async fn profile_flamegraph(
    admin: AdminUser,
    Query(query): Query<ProfileQuery>,
) -> Result<Response, ApiError> {
    let _ = admin;
    profile_flamegraph_impl(axum::extract::Query(query)).await
}

pub(crate) async fn profile_flamegraph_impl(
    Query(query): Query<ProfileQuery>,
) -> Result<Response, ApiError> {
    if !capture_enabled() {
        return Err(capture_disabled_error());
    }
    let session = begin_session("flamegraph", &query).await?;
    maybe_start_selfload(&query);
    tokio::time::sleep(Duration::from_secs(capture_seconds(&query))).await;
    let svg = tokio::task::spawn_blocking(move || session.finish_flamegraph())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|err| {
            log_capture("flamegraph", reject_tag(&err));
            finish_err(err)
        })?;
    log_capture("flamegraph", "ok");

    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml"),
            ),
            // The SVG is attacker-influenceable markup rendered by an admin's
            // browser: force a download and stop MIME sniffing.
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static(
                    "attachment; filename=\"flamegraph.svg\"",
                ),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            // Capture output is only valid for the instant it was produced.
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        svg,
    )
        .into_response())
}

/// `GET /api/v1/debug/pprof/cpu/metrics` — the cheap live snapshot the
/// dashboard's embedded refresh script polls. Sampling sysinfo may sleep
/// out its minimum interval, so it stays off the executor thread.
async fn cpu_metrics(
    admin: AdminUser,
) -> Result<Json<pingwaf_pprof::CpuLiveStats>, ApiError> {
    let _ = admin;
    cpu_metrics_impl().await
}

pub(crate) async fn cpu_metrics_impl(
) -> Result<Json<pingwaf_pprof::CpuLiveStats>, ApiError> {
    let stats = tokio::task::spawn_blocking(pingwaf_pprof::cpu_snapshot)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(stats))
}

/// `GET /api/v1/debug/pprof/cpu/dashboard.svg`
///
/// Captures a CPU profile and renders the self-contained SVG dashboard.
/// Unlike the raw capture endpoints this degrades off-Linux: without a
/// signal-safe unwinder there is nothing to sample, so the board renders
/// from the live snapshot with a `PLATFORM-LIMITED` badge instead of
/// answering `501`.
///
/// With `?refresh=<seconds>` the SVG additionally embeds a script that
/// polls `cpu/metrics` and refreshes the live readout while the file is
/// open in a browser. The metrics endpoint is Bearer-only and a saved file
/// cannot attach headers, so the caller's own token (from the
/// `Authorization` header of this very request) is inlined into the poll —
/// opt-in, returned only to the caller, `no-store`, and flagged with a
/// warning printed on the dashboard itself.
async fn cpu_dashboard(
    admin: AdminUser,
    headers: HeaderMap,
    Query(query): Query<ProfileQuery>,
) -> Result<Response, ApiError> {
    let _ = admin;
    cpu_dashboard_impl(headers, axum::extract::Query(query)).await
}

pub(crate) async fn cpu_dashboard_impl(
    headers: HeaderMap,
    Query(query): Query<ProfileQuery>,
) -> Result<Response, ApiError> {
    if !capture_enabled() {
        return Err(capture_disabled_error());
    }
    let summary = match begin_session("cpu-dashboard", &query).await {
        Ok(session) => {
            // After begin_session: selfload only runs when the capture is
            // actually happening (not on guard/409 refusals, and the
            // off-Linux degrade below needs no synthetic load either).
            maybe_start_selfload(&query);
            tokio::time::sleep(Duration::from_secs(capture_seconds(&query)))
                .await;
            tokio::task::spawn_blocking(move || {
                let result = session.finish_summary();
                match &result {
                    Ok(_) => log_capture("cpu-dashboard", "ok"),
                    Err(err) => log_capture("cpu-dashboard", reject_tag(err)),
                }
                result.map_err(finish_err)
            })
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))??
        },
        // Off-Linux there is no signal-safe unwinder to sample with;
        // degrade to the live readout instead of failing the admin.
        Err(ApiError::NotImplemented(_)) => {
            let live = tokio::task::spawn_blocking(pingwaf_pprof::cpu_snapshot)
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            pingwaf_pprof::CpuCaptureSummary::platform_limited(&live)
        },
        Err(other) => return Err(other),
    };

    let live = tokio::task::spawn_blocking(pingwaf_pprof::cpu_snapshot)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let opts = match query.refresh {
        Some(seconds) => DashboardSvgOpts {
            refresh_url: Some("/api/v1/debug/pprof/cpu/metrics".to_string()),
            refresh_seconds: seconds.clamp(1, 60),
            refresh_token: bearer_token(&headers),
        },
        None => DashboardSvgOpts::default(),
    };
    let svg =
        pingwaf_pprof::render_cpu_dashboard_svg(&summary, Some(&live), &opts);

    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/svg+xml"),
            ),
            // Inline (not attachment): the refresh script must run when
            // the file is opened directly. All dynamic content is
            // XML-escaped by the renderer, the endpoint is admin-only and
            // the response is never cached.
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static(
                    "inline; filename=\"cpu-dashboard.svg\"",
                ),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            // The `?refresh=` path inlines a self-refreshing script; the
            // global CSP only allows `script-src 'self'`, so this SVG
            // needs to opt back into `unsafe-inline`. The token and the
            // SVG itself are both admin-only and `no-store` — the trade
            // is acceptable and narrower than letting the global CSP
            // carry `unsafe-inline` for the whole console.
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("script-src 'unsafe-inline'"),
            ),
        ],
        svg,
    )
        .into_response())
}

/// The Bearer token of the incoming request, if the dashboard's refresh
/// script should inherit it. Mirrors the prefix parsing of the auth
/// middleware so the inlined value is exactly what a browser replay of
/// this request would send.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// `GET /api/v1/debug/pprof/memory`
async fn memory(admin: AdminUser) -> Result<Response, ApiError> {
    let _ = admin;
    memory_impl().await
}

pub(crate) async fn memory_impl() -> Result<Response, ApiError> {
    Ok((
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(pingwaf_pprof::memory_snapshot()),
    )
        .into_response())
}

/// `GET /debug/pprof/heap` — jeprof-format heap profile (`mem-prof`
/// diagnostic builds only; anything else answers `501`).
///
/// Triggers `prof.dump`, which writes every live allocation path with its
/// retained byte count — the answer to "which function holds memory".
/// Render with `jeprof --svg <binary> <dump>` (jeprof ships with gperftools;
/// any build of the same revision works for symbolisation). Requires the
/// process to run with `MALLOC_CONF` containing `prof:true` — heap
/// profiling is sampled and off by default.
///
/// Read-only like the memory snapshot (no sampling session), but gated by
/// the debug-capture switch: a deployment that turned captures off does not
/// want heap dumps downloaded either.
#[cfg(feature = "mem-prof")]
async fn heap(admin: AdminUser) -> Result<Response, ApiError> {
    let _ = admin;
    heap_impl().await
}

#[cfg(feature = "mem-prof")]
pub(crate) async fn heap_impl() -> Result<Response, ApiError> {
    if !capture_enabled() {
        return Err(capture_disabled_error());
    }
    // prof.dump walks the whole heap and writes the dump file — blocking
    // work that must stay off the async executor (same discipline as the
    // CPU-capture finishers above).
    let bytes = tokio::task::spawn_blocking(|| -> Result<Vec<u8>, ApiError> {
        // jemalloc IS the global allocator in mem-prof builds, and
        // tikv_jemalloc_sys::mallctl is the prefix-aware binding to it —
        // a hand-written extern "C" mallctl would fail to link because the
        // tikv build exports `__rjem_mallctl`.
        let dump_path = std::env::temp_dir()
            .join(format!("pingwaf-heap.{}.prof", std::process::id()));
        let cpath =
            std::ffi::CString::new(dump_path.to_string_lossy().as_bytes())
                .map_err(|e| ApiError::Internal(e.to_string()))?;
        let rc = unsafe {
            tikv_jemalloc_sys::mallctl(
                b"prof.dump\0".as_ptr().cast(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                cpath.as_ptr() as *const core::ffi::c_char
                    as *mut core::ffi::c_void,
                cpath.as_bytes_with_nul().len(),
            )
        };
        if rc != 0 {
            return Err(ApiError::Internal(format!(
                "prof.dump failed (rc {rc}, path {dump_path:?}) — heap \
                 profiling must be active: run this diagnostic build with \
                 MALLOC_CONF=prof:true"
            )));
        }
        let bytes = std::fs::read(&dump_path)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let _ = std::fs::remove_file(&dump_path);
        Ok(bytes)
    })
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))??;

    let disposition =
        HeaderValue::from_str("attachment; filename=\"pingwaf-heap.prof\"")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (header::CONTENT_DISPOSITION, disposition),
            // A dump is only valid for the instant it was taken.
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        bytes,
    )
        .into_response())
}

/// Off-`mem-prof` stub: the standard allocator cannot attribute heap usage.
#[cfg(not(feature = "mem-prof"))]
async fn heap(admin: AdminUser) -> Result<Response, ApiError> {
    let _ = admin;
    heap_impl().await
}

#[cfg(not(feature = "mem-prof"))]
pub(crate) async fn heap_impl() -> Result<Response, ApiError> {
    Err(ApiError::NotImplemented(
        "the heap profiler requires a mem-prof diagnostic build \
         (cargo build --features mem-prof, run with MALLOC_CONF=prof:true); \
         use /debug/pprof/memory for aggregate usage"
            .to_string(),
    ))
}

/// `GET /debug/pprof/cpu/summary` — the bounded profiling summary the
/// console and MCP consume: the live CPU/memory snapshot plus the most
/// recent capture's TopN frames (KB-scale JSON, no file downloads).
///
/// `?capture=true` runs a fresh capture first (subject to the switch, the
/// 40% load guard and the audit trail, exactly like every capture);
/// without it the endpoint answers from the last-capture cache — zero
/// sampling cost, and the natural "what's happening right now" view.
#[derive(Debug, Default, Deserialize)]
pub struct SummaryQuery {
    /// Run a fresh capture instead of returning the cached summary.
    pub capture: Option<bool>,
    /// Generate light in-process load during a `capture=true` window.
    pub selfload: Option<bool>,
    /// Capture window seconds for `capture=true`.
    pub seconds: Option<u64>,
    /// Sampling frequency for `capture=true`.
    pub frequency: Option<i32>,
}

/// Live snapshot plus the last capture's bounded summary.
#[derive(serde::Serialize)]
pub struct ProfilingSnapshot {
    pub live: pingwaf_pprof::CpuLiveStats,
    pub last_capture: Option<pingwaf_pprof::CpuCaptureSummary>,
}

async fn cpu_summary(
    admin: AdminUser,
    Query(query): Query<SummaryQuery>,
) -> Result<Json<ProfilingSnapshot>, ApiError> {
    let _ = admin;
    cpu_summary_impl(axum::extract::Query(query)).await
}

pub(crate) async fn cpu_summary_impl(
    Query(query): Query<SummaryQuery>,
) -> Result<Json<ProfilingSnapshot>, ApiError> {
    let last_capture = if query.capture.unwrap_or(false) {
        // Same debug-mode gate as every capture entry point: a deployment
        // with the switch off must not be able to start a sampling session
        // through this endpoint either.
        if !capture_enabled() {
            return Err(capture_disabled_error());
        }
        let profile_query = ProfileQuery {
            seconds: query.seconds,
            frequency: query.frequency,
            refresh: None,
            selfload: query.selfload,
        };
        let session = begin_session("summary", &profile_query).await?;
        maybe_start_selfload(&profile_query);
        tokio::time::sleep(Duration::from_secs(capture_seconds(
            &profile_query,
        )))
        .await;
        let summary =
            tokio::task::spawn_blocking(move || session.finish_summary())
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?
                .map_err(finish_err)?;
        log_capture("summary", "ok");
        Some(summary)
    } else {
        pingwaf_pprof::cached_summary()
    };
    let live = tokio::task::spawn_blocking(pingwaf_pprof::cpu_snapshot)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(ProfilingSnapshot { live, last_capture }))
}

/// `POST /debug/pprof/cpu/summary/import` — decodes an existing pprof
/// protobuf body (the format `/debug/pprof/profile` exports) into the same
/// bounded summary, so previously downloaded profiling files stay
/// analysable in the console and via MCP without external tools.
async fn import_summary(
    admin: AdminUser,
    body: axum::body::Bytes,
) -> Result<Json<pingwaf_pprof::CpuCaptureSummary>, ApiError> {
    let _ = admin;
    import_summary_impl(body).await
}

pub(crate) async fn import_summary_impl(
    body: axum::body::Bytes,
) -> Result<Json<pingwaf_pprof::CpuCaptureSummary>, ApiError> {
    // The window is unknown for legacy files; use 1s so the CPU-fraction
    // panel stays neutral and per-frame shares remain proportional.
    let summary =
        pingwaf_pprof::summary_from_pprof_bytes(&body, 1.0).map_err(|err| {
            log_capture("summary-import", reject_tag(&err));
            finish_err(err)
        })?;
    Ok(Json(summary))
}

/// Loopback-only diagnostic routes: the same handlers **without** the
/// AdminUser requirement. Only ever mounted on a 127.0.0.1-bound listener
/// (the loopback interface is the trust boundary), so `go tool pprof` /
/// `jeprof` can consume the endpoints without exchanging a Bearer token.
pub fn loopback_routes() -> Router<AppState> {
    Router::new()
        .route("/debug/pprof/profile", get(profile_cpu_impl))
        .route("/debug/pprof/flamegraph", get(profile_flamegraph_impl))
        .route("/debug/pprof/heap", get(heap_impl))
        .route("/debug/pprof/cpu/metrics", get(cpu_metrics_impl))
        .route("/debug/pprof/cpu/dashboard.svg", get(cpu_dashboard_impl))
        .route("/debug/pprof/cpu/summary", get(cpu_summary_impl))
        .route("/debug/pprof/cpu/summary/import", post(import_summary_impl))
        .route("/debug/pprof/memory", get(memory_impl))
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/debug/pprof/profile", get(profile_cpu))
        .route("/debug/pprof/flamegraph", get(profile_flamegraph))
        .route("/debug/pprof/heap", get(heap))
        .route("/debug/pprof/cpu/metrics", get(cpu_metrics))
        .route("/debug/pprof/cpu/dashboard.svg", get(cpu_dashboard))
        .route("/debug/pprof/cpu/summary", get(cpu_summary))
        .route("/debug/pprof/cpu/summary/import", post(import_summary))
        .route("/debug/pprof/memory", get(memory))
}

#[cfg(test)]
mod tests {
    use super::{capture_enabled, load_guard_error};

    /// The deployment switch honours the shared parser in pingwaf-pprof;
    /// with no configuration and no env var (the case in tests) captures
    /// default to OFF.
    #[test]
    fn capture_switch_defaults_to_off() {
        assert!(!capture_enabled());
    }

    /// The load-guard 503 tells the operator the measured CPU value, the
    /// limit and that a retry is expected — enough to self-serve.
    #[test]
    fn load_guard_error_is_self_serving() {
        let err = load_guard_error(73.4);
        assert_eq!(err.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let message = err.to_string();
        assert!(message.contains("of one core"));
        assert!(message.contains("73%"));
        assert!(message.contains("40%"));
        assert!(message.contains("retry when the load drops"));
    }
}
