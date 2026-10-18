//! Read-only process observation: CPU/memory snapshots and the module/method
//! attribution tables.
//!
//! This is the successor of the removed pprof endpoints. Two differences are
//! deliberate:
//!
//! * Nothing here samples stacks or writes profile files. `/system/metrics`
//!   reads counters the OS already keeps; `/system/profile` reads the
//!   accounting tables the data plane and control plane maintain themselves
//!   (`pingwaf-profiler`).
//! * Both are ordinary admin endpoints, so they work on every platform and
//!   in every build — there is no diagnostic-only image to deploy.

use axum::extract::State;
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde::Serialize;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AdminUser;

/// `GET /api/v1/system/metrics` — process/host CPU and memory snapshots.
#[derive(Debug, Serialize)]
pub struct SystemMetrics {
    /// Process and machine CPU usage.
    pub cpu: pingwaf_system::CpuLiveStats,
    /// Process RSS, host RAM and container memory accounting.
    pub memory: pingwaf_system::MemorySnapshot,
}

async fn metrics(_admin: AdminUser) -> Result<Json<SystemMetrics>, ApiError> {
    // Both snapshots touch /proc (or the platform equivalent): keep that off
    // the async workers.
    let (cpu, memory) = tokio::task::spawn_blocking(|| {
        (
            pingwaf_system::cpu_snapshot(),
            pingwaf_system::memory_snapshot(),
        )
    })
    .await
    .map_err(|err| ApiError::Internal(err.to_string()))?;
    Ok(Json(SystemMetrics { cpu, memory }))
}

/// `GET /api/v1/system/profile` — module and method CPU/memory attribution.
///
/// The response is bounded (seven module rows, at most
/// [`pingwaf_profiler::ProfileSnapshot::MAX_METHODS`] method rows) and
/// computed from atomics, so polling it is cheap.
async fn profile(
    _admin: AdminUser,
    State(_state): State<AppState>,
) -> Json<pingwaf_profiler::ProfileSnapshot> {
    Json(pingwaf_profiler::ProfileSnapshot::collect())
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/system/metrics", get(metrics))
        .route("/system/profile", get(profile))
}

#[cfg(test)]
mod tests {
    /// The snapshot is a plain JSON value with the documented shape: module
    /// rows keyed by name and a bounded method list.
    #[test]
    fn profile_snapshot_shape() {
        let snapshot = pingwaf_profiler::ProfileSnapshot::collect();
        assert_eq!(snapshot.modules.len(), 7);
        assert!(
            snapshot.modules.iter().any(|row| row.module == "proxy"),
            "every module is present even before instrumentation runs"
        );
        assert!(
            snapshot.methods.len()
                <= pingwaf_profiler::ProfileSnapshot::MAX_METHODS
        );
        assert!(snapshot.collected_at_ms > 0);
    }
}
