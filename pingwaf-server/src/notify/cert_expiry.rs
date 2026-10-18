//! Periodic certificate expiry scanner.
//!
//! The heartbeat-driven alerts in `grpc::control_plane::notify_certificate_state`
//! only fire when an agent reports a certificate status *change*. This task
//! closes the gap: once an hour it sweeps `site_certificates` and raises
//! `cert.expired` / `cert.expiring` for any row whose `expires_at` says so —
//! covering manually uploaded PEMs and agents that went silent. It is
//! strictly read-only: the `status` column stays owned by the ingest path.

use std::collections::HashSet;
use std::time::Duration;

use chrono::Utc;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::task::JoinHandle;

use crate::models::{certificates::site_certificates, event_type, severity};
use crate::notify::{self, AlertEvent};

/// One scan per hour; the first sweep is delayed by the same interval so a
/// restart does not burst notifications for long-known states.
const SCAN_INTERVAL: Duration = Duration::from_secs(3600);

/// Process-level memory of already-raised alerts, keyed
/// `{site_id}:{expires_date}`. The channel-level dedup window (default
/// 600s) is far shorter than the scan interval, so without this set every
/// sweep would re-notify. Process restarts replay one alert per pending
/// certificate — acceptable for a daily-scale signal.
static ALERTED: std::sync::LazyLock<std::sync::Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashSet::new()));

/// Hard cap on the dedup set. The set only grows with distinct
/// `{site}:{expiry-date}` pairs; clearing at the cap costs at most one
/// duplicate alert per pending certificate, not lost alerts.
const ALERTED_MAX_ENTRIES: usize = 4096;

/// Spawns the hourly scanner; the handle is detached by the caller.
pub fn start(db: DatabaseConnection) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SCAN_INTERVAL).await;
            scan(&db).await;
            prune_login_history(&db).await;
        }
    })
}

/// One sweep over the certificate table. Errors are logged, never fatal.
async fn scan(db: &DatabaseConnection) {
    let warn_days = notify::global()
        .map(|manager| manager.settings().cert_expiry_warn_days)
        .unwrap_or(30);
    let now = Utc::now();

    let rows = match site_certificates::Entity::find()
        .filter(site_certificates::Column::ExpiresAt.is_not_null())
        .all(db)
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(error = %err, "certificate expiry scan failed");
            return;
        },
    };

    for row in rows {
        let Some(expires_at) = row.expires_at else {
            continue;
        };
        let Some(kind) = classify(expires_at, now, warn_days) else {
            continue;
        };
        let key = alert_key(row.site_id, expires_at);
        if ALERTED
            .lock()
            .map(|mut set| {
                if set.len() >= ALERTED_MAX_ENTRIES {
                    set.clear();
                }
                !set.insert(key)
            })
            .unwrap_or(true)
        {
            continue;
        }
        match kind {
            "expired" => {
                notify::emit(AlertEvent {
                    event_type: event_type::CERT_EXPIRED.to_string(),
                    severity: severity::CRITICAL,
                    title: format!(
                        "Certificate for '{}' has expired",
                        row.domain
                    ),
                    message: format!(
                        "The certificate for '{}' (site {}) expired at {}. \
                     Renew it or replace it to keep TLS working.",
                        row.domain,
                        row.site_id,
                        expires_at.format("%Y-%m-%d %H:%M UTC"),
                    ),
                    details: Some(serde_json::json!({
                        "site_id": row.site_id.to_string(),
                        "domain": row.domain,
                        "expires_at": expires_at.to_rfc3339(),
                    })),
                    dedup_key: Some(alert_key(row.site_id, expires_at)),
                })
                .await
            },
            _ => {
                notify::emit(AlertEvent {
                    event_type: event_type::CERT_EXPIRING.to_string(),
                    severity: severity::WARNING,
                    title: format!(
                        "Certificate for '{}' expires within {warn_days} days",
                        row.domain
                    ),
                    message: format!(
                        "The certificate for '{}' (site {}) expires at {}. \
                     Renewal should happen automatically; verify it works.",
                        row.domain,
                        row.site_id,
                        expires_at.format("%Y-%m-%d %H:%M UTC"),
                    ),
                    details: Some(serde_json::json!({
                        "site_id": row.site_id.to_string(),
                        "domain": row.domain,
                        "expires_at": expires_at.to_rfc3339(),
                        "warn_days": warn_days,
                    })),
                    dedup_key: Some(alert_key(row.site_id, expires_at)),
                })
                .await
            },
        }
    }
}

/// `"expired"` when the date is past, `"expiring"` when inside the warning
/// window, `None` otherwise. Pure so the boundary behaviour is testable.
fn classify(
    expires_at: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
    warn_days: u32,
) -> Option<&'static str> {
    if expires_at <= now {
        return Some("expired");
    }
    let warn_from = now + chrono::Duration::days(i64::from(warn_days));
    (expires_at <= warn_from).then_some("expiring")
}

/// The dedup/suppression key for one certificate expiry state.
fn alert_key(site_id: uuid::Uuid, expires_at: chrono::DateTime<Utc>) -> String {
    format!("{}:{}", site_id, expires_at.date_naive())
}

/// Ages login history rows out (90 days), piggybacking on the hourly tick
/// so no extra task is needed.
async fn prune_login_history(db: &DatabaseConnection) {
    const LOGIN_HISTORY_RETENTION_DAYS: i64 = 90;
    let cutoff =
        Utc::now() - chrono::Duration::days(LOGIN_HISTORY_RETENTION_DAYS);
    if let Err(err) = crate::models::login_history::Entity::delete_many()
        .filter(crate::models::login_history::Column::CreatedAt.lt(cutoff))
        .exec(db)
        .await
    {
        tracing::warn!(error = %err, "could not prune login history");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(days: i64, hours: i64) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 9, 12, 0, 0).unwrap()
            + chrono::Duration::days(days)
            + chrono::Duration::hours(hours)
    }

    #[test]
    fn past_dates_are_expired() {
        let now = at(0, 0);
        assert_eq!(classify(at(-1, 0), now, 30), Some("expired"));
        assert_eq!(classify(now, now, 30), Some("expired"));
    }

    #[test]
    fn dates_inside_the_window_are_expiring() {
        let now = at(0, 0);
        assert_eq!(classify(at(29, 12), now, 30), Some("expiring"));
        assert_eq!(classify(at(30, 0), now, 30), Some("expiring"));
    }

    #[test]
    fn dates_outside_the_window_are_ignored() {
        let now = at(0, 0);
        assert_eq!(classify(at(30, 1), now, 30), None);
        assert_eq!(classify(at(90, 0), now, 30), None);
    }

    #[test]
    fn the_window_follows_the_configured_days() {
        let now = at(0, 0);
        assert_eq!(classify(at(7, 0), now, 7), Some("expiring"));
        assert_eq!(classify(at(7, 1), now, 7), None);
        assert_eq!(classify(at(6, 23), now, 7), Some("expiring"));
    }
}
