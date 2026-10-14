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
    DEFAULT_SECONDS, MAX_SECONDS,
};
use serde::Deserialize;
use std::time::Duration;

/// Query parameters accepted by both capture endpoints.
#[derive(Debug, Default, Deserialize)]
pub struct ProfileQuery {
    /// Capture window; clamped to `1..=MAX_SECONDS`, default 30.
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

fn begin_session(query: &ProfileQuery) -> Result<ProfilingSession, ApiError> {
    let frequency = query.frequency.unwrap_or_default();
    start_session(frequency).map_err(|err| match err {
        ProfileError::AlreadyActive => ApiError::Conflict(err.to_string()),
        ProfileError::UnsupportedPlatform => {
            ApiError::NotImplemented(err.to_string())
        },
        other => ApiError::Internal(other.to_string()),
    })
}

fn capture_seconds(query: &ProfileQuery) -> u64 {
    query
        .seconds
        .unwrap_or(DEFAULT_SECONDS)
        .clamp(1, MAX_SECONDS)
}

/// `GET /api/v1/debug/pprof/profile`
async fn profile_cpu(
    _admin: AdminUser,
    Query(query): Query<ProfileQuery>,
) -> Result<Response, ApiError> {
    let session = begin_session(&query)?;
    tokio::time::sleep(Duration::from_secs(capture_seconds(&query))).await;
    let bytes = tokio::task::spawn_blocking(move || session.finish_pprof())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(finish_err)?;

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
    let session = begin_session(&query)?;
    tokio::time::sleep(Duration::from_secs(capture_seconds(&query))).await;
    let svg = tokio::task::spawn_blocking(move || session.finish_flamegraph())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(finish_err)?;

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
    let summary = match begin_session(&query) {
        Ok(session) => {
            tokio::time::sleep(Duration::from_secs(capture_seconds(&query)))
                .await;
            tokio::task::spawn_blocking(move || session.finish_summary())
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?
                .map_err(finish_err)?
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
