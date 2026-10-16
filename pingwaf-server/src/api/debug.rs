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
use axum::routing::get;
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
}

/// Maps profiling finish errors: an empty capture is not a server fault —
/// the client asked to profile an idle process — so it is a `409 Conflict`
/// with guidance, not a `500`.
fn finish_err(err: ProfileError) -> ApiError {
    match err {
        ProfileError::NoSamples | ProfileError::Idle => {
            ApiError::Conflict(err.to_string())
        },
        other => ApiError::Internal(other.to_string()),
    }
}

fn begin_session(
    endpoint: &str,
    query: &ProfileQuery,
) -> Result<ProfilingSession, ApiError> {
    let frequency = query.frequency.unwrap_or_default();
    start_session(frequency).map_err(|err| {
        log_capture(endpoint, reject_tag(&err));
        match err {
            ProfileError::AlreadyActive => ApiError::Conflict(err.to_string()),
            ProfileError::UnsupportedPlatform => {
                ApiError::NotImplemented(err.to_string())
            },
            other => ApiError::Internal(other.to_string()),
        }
    })
}

fn capture_seconds(query: &ProfileQuery) -> u64 {
    query
        .seconds
        .unwrap_or(DEFAULT_CAPTURE_SECONDS)
        .clamp(1, MAX_SECONDS)
}

/// Whether CPU-capture endpoints accept work: `PINGWAF_PPROF_ENABLED=0`
/// (or `false`/`off`/`no`, case-insensitive) disables the three capture
/// endpoints and the MCP `profile_cpu` tool. The memory and live-metrics
/// snapshots stay available — they are the cheap, read-only views an
/// operator needs precisely when captures are turned off.
pub(crate) fn capture_enabled_from(raw: Option<&str>) -> bool {
    match raw {
        Some(value) => !matches!(
            value.to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        None => true,
    }
}

fn capture_enabled() -> bool {
    capture_enabled_from(std::env::var("PINGWAF_PPROF_ENABLED").ok().as_deref())
}

/// Shared entry point for every caller that must honour the capture switch
/// (HTTP endpoints and the MCP tool alike), so the env lookup cannot drift
/// between them.
pub(crate) fn captures_enabled() -> bool {
    capture_enabled()
}

fn capture_disabled_error() -> ApiError {
    ApiError::ServiceUnavailable(
        "CPU profiling captures are disabled on this deployment \
         (PINGWAF_PPROF_ENABLED=0); the memory and live-metrics snapshots \
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
    _admin: AdminUser,
    Query(query): Query<ProfileQuery>,
) -> Result<Response, ApiError> {
    if !capture_enabled() {
        return Err(capture_disabled_error());
    }
    let session = begin_session("profile", &query)?;
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
    _admin: AdminUser,
    Query(query): Query<ProfileQuery>,
) -> Result<Response, ApiError> {
    if !capture_enabled() {
        return Err(capture_disabled_error());
    }
    let session = begin_session("flamegraph", &query)?;
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
    _admin: AdminUser,
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
    _admin: AdminUser,
    headers: HeaderMap,
    Query(query): Query<ProfileQuery>,
) -> Result<Response, ApiError> {
    if !capture_enabled() {
        return Err(capture_disabled_error());
    }
    let summary = match begin_session("cpu-dashboard", &query) {
        Ok(session) => {
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
async fn memory(_admin: AdminUser) -> Result<Response, ApiError> {
    Ok((
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(pingwaf_pprof::memory_snapshot()),
    )
        .into_response())
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/debug/pprof/profile", get(profile_cpu))
        .route("/debug/pprof/flamegraph", get(profile_flamegraph))
        .route("/debug/pprof/cpu/metrics", get(cpu_metrics))
        .route("/debug/pprof/cpu/dashboard.svg", get(cpu_dashboard))
        .route("/debug/pprof/memory", get(memory))
}

#[cfg(test)]
mod tests {
    use super::capture_enabled_from;

    /// The switch defaults to on and only an explicit off-value turns the
    /// capture endpoints away.
    #[test]
    fn capture_toggle_parsing() {
        assert!(capture_enabled_from(None));
        assert!(capture_enabled_from(Some("1")));
        assert!(capture_enabled_from(Some("true")));
        assert!(capture_enabled_from(Some("")));
        assert!(!capture_enabled_from(Some("0")));
        assert!(!capture_enabled_from(Some("false")));
        assert!(!capture_enabled_from(Some("OFF")));
        assert!(!capture_enabled_from(Some("no")));
    }
}
