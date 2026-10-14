//! Built-in pprof-style profiling endpoints (admin only).
//!
//! * `GET /api/v1/debug/pprof/profile?seconds=30&frequency=99` — CPU samples
//!   as a gzip-compressed pprof protobuf, consumable by `go tool pprof`
//! * `GET /api/v1/debug/pprof/flamegraph?seconds=30` — SVG flamegraph
//! * `GET /api/v1/debug/pprof/memory` — JSON memory snapshot
//!
//! CPU sampling is process-global: while a capture is running, further
//! requests are answered with `409 Conflict`. Sampling requires Linux (the
//! only platform with a signal-safe unwinder); elsewhere the capture
//! endpoints answer `501 Not Implemented` and the memory snapshot still
//! works.
//!
//! Symbols are resolved from the binary's symbol table; the default
//! `release` profile strips them, so profile a `release-perf` build for
//! readable flame graphs.

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AdminUser;
use axum::extract::Query;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use pingwaf_pprof::{
    start_session, ProfileError, ProfilingSession, DEFAULT_SECONDS, MAX_SECONDS,
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
        .route("/debug/pprof/memory", get(memory))
}
