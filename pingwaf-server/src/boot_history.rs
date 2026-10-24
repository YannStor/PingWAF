//! Recording control-plane starts, and reading them back for the console.
//!
//! The control plane has no way to announce its own death: an OOM kill, a
//! crash or a `docker kill` runs no code. The one moment it can speak is
//! startup, so every start writes a row and the *gap* between two rows is the
//! previous process's uptime. A container that restarts in a loop shows up as
//! several boots a few minutes apart.
//!
//! This module owns both halves:
//!
//! * [`record_boot`] — called once from `lib.rs`, before the listeners open.
//!   It never fails the startup: a control plane that cannot write its own
//!   boot row still has to serve traffic, so a database error is logged and
//!   swallowed.
//! * [`recent_boots`] — the newest rows, for `GET /api/v1/system/nodes`.
//! * [`sweep_boots`] — keeps the table at [`MAX_BOOT_ROWS`] rows.
//!
//! # Replicas
//!
//! A deployment may run several control-plane replicas against one database
//! (see `docs/deployment.md`). They share this table, so every read and write
//! here is scoped by `hostname`: the predecessor of a boot is the previous
//! boot **of the same host**, never another replica's. The console lists the
//! newest rows across all hosts — that is what shows a fleet rolling — but the
//! uptime and reason of each row only ever describe its own host.

use chrono::Utc;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect, Set,
};

use crate::models::{control_plane_boot, control_plane_stop};

/// Rows kept. The console shows five; the rest is headroom for an operator
/// scrolling back, without the table growing forever on a restart loop.
pub const MAX_BOOT_ROWS: u64 = 100;

/// Boots the console renders. Enough to see a restart loop at a glance
/// without turning the card into a log viewer. Defined here rather than in the
/// API so the two constants cannot drift.
pub const BOOTS_SHOWN: u64 = 5;

/// How recent the previous boot must be for this one to be judged unclean.
///
/// A planned stop and start — a redeploy, a config change — takes seconds to
/// minutes; a process that died on its own is replaced just as fast, so time
/// alone cannot tell the two apart. What *can* be told is whether the previous
/// process had a chance to shut down: a graceful `SIGTERM` writes nothing
/// today, so this threshold is deliberately conservative and only classifies
/// the clearest case — a boot within this window of the last one means the
/// previous process lived less than this long, which no planned maintenance
/// would do repeatedly.
///
/// The console shows the uptime next to the reason, so an operator can judge a
/// borderline case themselves; the label never has to be the last word.
pub const UNCLEAN_BOOT_WINDOW_SECS: i64 = 60;

/// Why a process believes it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootReason {
    /// No previous boot on record — a first run, or a history that was cleared.
    Fresh,
    /// The previous process shut down cleanly. Told apart from a kill by the
    /// stop row it wrote, not by the clock.
    AfterStop,
    /// The previous boot is recent enough that the previous process was almost
    /// certainly killed without shutting down.
    Unclean,
}

impl BootReason {
    /// The wire value stored in the column and sent to the console.
    pub fn as_str(self) -> &'static str {
        match self {
            BootReason::Fresh => "fresh",
            BootReason::AfterStop => "after_stop",
            BootReason::Unclean => "unclean",
        }
    }
}

/// Classifies a boot from the gap to the previous one, and from whether the
/// previous process was seen to stop.
///
/// `previous_age` is how long ago the last boot was, in seconds. `None` means
/// there is no previous boot. A negative age (a clock that moved backwards
/// between the two starts) is treated as "no previous boot" rather than as a
/// very short uptime, because the arithmetic is meaningless and reporting a
/// negative uptime as a crash would be worse than admitting ignorance.
///
/// `previous_stopped` is whether the previous process wrote a stop row before
/// it went away. That is the distinction time cannot make: a `docker compose
/// restart` and a `kill -9` are both followed by a start seconds later, and
/// before stop rows existed both were labelled `unclean` — which is what made
/// an ordinary redeploy look like a crash loop. A recorded stop settles it
/// regardless of the gap.
pub fn classify_boot(
    previous_age: Option<i64>,
    previous_stopped: bool,
) -> (BootReason, Option<i64>) {
    match previous_age {
        None | Some(..=0) => (BootReason::Fresh, None),
        Some(age) if previous_stopped => (BootReason::AfterStop, Some(age)),
        Some(age) if age < UNCLEAN_BOOT_WINDOW_SECS => {
            (BootReason::Unclean, Some(age))
        },
        Some(age) => (BootReason::AfterStop, Some(age)),
    }
}

/// Writes this process's boot row, returning what it recorded.
///
/// Errors are returned rather than logged so the caller decides: `lib.rs`
/// logs and continues, because a control plane that cannot record its own
/// start still has to come up.
pub async fn record_boot(
    db: &DatabaseConnection,
    version: &str,
    hostname: &str,
) -> Result<control_plane_boot::Model, DbErr> {
    let now = Utc::now();
    // Scoped to this hostname: several replicas share one table, and another
    // replica starting five seconds later is not *this* process's predecessor.
    // Without the filter a second replica would be labelled `unclean` and
    // report a bogus five-second uptime.
    let previous = control_plane_boot::Entity::find()
        .filter(control_plane_boot::Column::Hostname.eq(hostname))
        .order_by_desc(control_plane_boot::Column::BootedAt)
        .order_by_desc(control_plane_boot::Column::Id)
        .one(db)
        .await?;

    // `previous` is an owned `Option<Model>`; borrowing it for the arithmetic
    // keeps it available for the insert below.
    let age = previous.as_ref().map(|row: &control_plane_boot::Model| {
        (now - row.booted_at).num_seconds()
    });

    // Was that process seen to stop? A stop row written *after* the previous
    // boot and *before* now belongs to it.
    //
    // Both bounds matter. The lower one keeps a stop from two restarts ago from
    // being read as this one's; the upper one keeps a row written *later* —
    // by a second process sharing this hostname, by a restored dump, by a
    // clock that ran fast — from certifying a boot it never described. Without
    // it, a crash could be labelled a planned stop, which is the one direction
    // this whole mechanism must not fail in.
    let previous_stopped = match previous.as_ref() {
        Some(row) => control_plane_stop::Entity::find()
            .filter(control_plane_stop::Column::Hostname.eq(hostname))
            .filter(control_plane_stop::Column::StoppedAt.gte(row.booted_at))
            .filter(control_plane_stop::Column::StoppedAt.lte(now))
            .order_by_desc(control_plane_stop::Column::StoppedAt)
            .one(db)
            .await?
            .is_some(),
        None => false,
    };

    let (reason, previous_uptime_seconds) =
        classify_boot(age, previous_stopped);

    let model = control_plane_boot::ActiveModel {
        id: Set(uuid::Uuid::new_v4()),
        booted_at: Set(now),
        reason: Set(reason.as_str().to_string()),
        version: Set(version.to_string()),
        hostname: Set(hostname.to_string()),
        previous_uptime_seconds: Set(previous_uptime_seconds),
        created_at: Set(now),
    };
    control_plane_boot::Entity::insert(model)
        .exec_with_returning(db)
        .await
}

/// Records that this process is shutting down cleanly.
///
/// Called once, on the way out, when a `SIGTERM` or `SIGINT` was received. This
/// is the only way a planned restart can be told from a crash: both are
/// followed by a start seconds later, so the gap between two boots says nothing
/// about *why* the previous process went away.
///
/// Best-effort, like [`record_boot`]: a control plane that cannot write this
/// row must still exit, so the error is returned for the caller to log rather
/// than raised into the shutdown path. The cost of a failure is a restart
/// mislabelled `unclean`, which is what it was before this existed.
pub async fn record_stop(
    db: &DatabaseConnection,
    hostname: &str,
    started_at: chrono::DateTime<Utc>,
) -> Result<(), DbErr> {
    let now = Utc::now();
    // A clock that moved backwards makes the arithmetic meaningless; the column
    // is nullable precisely so this can say "unknown" rather than a negative.
    let uptime = (now - started_at).num_seconds();
    let model = control_plane_stop::ActiveModel {
        id: Set(uuid::Uuid::new_v4()),
        stopped_at: Set(now),
        hostname: Set(hostname.to_string()),
        uptime_seconds: Set((uptime > 0).then_some(uptime)),
        created_at: Set(now),
    };
    control_plane_stop::Entity::insert(model).exec(db).await?;
    Ok(())
}

/// The newest `limit` boots across every host, newest first.
///
/// Deliberately not host-scoped: the console shows the fleet's recent starts,
/// and each row carries its own `hostname` so a roll-out is readable. What is
/// host-scoped is the *interpretation* — `reason` and `previous_uptime_seconds`
/// were computed against the same host when the row was written.
pub async fn recent_boots(
    db: &DatabaseConnection,
    limit: u64,
) -> Result<Vec<control_plane_boot::Model>, DbErr> {
    control_plane_boot::Entity::find()
        .order_by_desc(control_plane_boot::Column::BootedAt)
        .order_by_desc(control_plane_boot::Column::Id)
        .limit(limit)
        .all(db)
        .await
}

/// Keeps the newest [`MAX_BOOT_ROWS`] rows **per host** and deletes the rest.
///
/// Called from the health monitor's periodic sweep, so the table cannot grow
/// without bound on a container that restarts in a loop.
///
/// The bound is per `hostname`, not per table. A global bound lets one host in
/// a restart loop push another host's rows out — the replica that is fine loses
/// the history an operator would read to see that it is fine. Each host gets
/// its own window, which is also the unit the console reads in.
pub async fn sweep_boots<C: ConnectionTrait>(db: &C) -> Result<u64, DbErr> {
    // Every host that has rows, so each is trimmed to its own bound.
    let hosts = control_plane_boot::Entity::find()
        .select_only()
        .column(control_plane_boot::Column::Hostname)
        .distinct()
        .into_tuple::<String>()
        .all(db)
        .await?;

    let mut deleted = 0;
    for hostname in hosts {
        deleted += sweep_host_boots(db, &hostname).await?;
    }

    // A stop row is read exactly once — by the start that follows it — so
    // anything older than the oldest boot *any* host still keeps can never be
    // consulted again.
    let oldest_kept = control_plane_boot::Entity::find()
        .order_by_asc(control_plane_boot::Column::BootedAt)
        .limit(1)
        .one(db)
        .await?;
    if let Some(oldest) = oldest_kept {
        deleted += control_plane_stop::Entity::delete_many()
            .filter(control_plane_stop::Column::StoppedAt.lt(oldest.booted_at))
            .exec(db)
            .await?
            .rows_affected;
    }

    Ok(deleted)
}

/// Trims one host's boot rows to [`MAX_BOOT_ROWS`], newest first.
async fn sweep_host_boots<C: ConnectionTrait>(
    db: &C,
    hostname: &str,
) -> Result<u64, DbErr> {
    // Find the row at this host's retention boundary; everything older goes.
    let boundary = control_plane_boot::Entity::find()
        .filter(control_plane_boot::Column::Hostname.eq(hostname))
        .order_by_desc(control_plane_boot::Column::BootedAt)
        .order_by_desc(control_plane_boot::Column::Id)
        .offset(MAX_BOOT_ROWS - 1)
        .limit(1)
        .one(db)
        .await?;
    let Some(boundary) = boundary else {
        return Ok(0);
    };
    let result = control_plane_boot::Entity::delete_many()
        .filter(control_plane_boot::Column::Hostname.eq(hostname))
        .filter(
            sea_orm::Condition::any()
                .add(
                    control_plane_boot::Column::BootedAt.lt(boundary.booted_at),
                )
                .add(
                    sea_orm::Condition::all()
                        .add(
                            control_plane_boot::Column::BootedAt
                                .eq(boundary.booted_at),
                        )
                        .add(control_plane_boot::Column::Id.lt(boundary.id)),
                ),
        )
        .exec(db)
        .await?;
    Ok(result.rows_affected)
}

/// The version string this build reports, from `CARGO_PKG_VERSION`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The retention boundary and the console window are both constants, so their
/// relationship is checked at compile time rather than in a test that could
/// only ever pass. `const { … }` is what clippy's `assertions_on_constants`
/// asks for: the assertions run during compilation, and an edit that made the
/// window exceed what is retained fails the build instead of a test run.
const _: () = {
    // `offset(MAX_BOOT_ROWS - 1)` reads the last row kept (0-indexed), and
    // everything older is deleted — so the subtraction must not underflow.
    assert!(MAX_BOOT_ROWS >= 1);

    // The console's five must sit inside the retained window, or a restart
    // loop could push the visible rows out of the table before anyone reads
    // them.
    assert!(BOOTS_SHOWN > 0);
    assert!(BOOTS_SHOWN < MAX_BOOT_ROWS);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_first_boot_is_fresh_with_no_uptime() {
        assert_eq!((BootReason::Fresh, None), classify_boot(None, false));
    }

    #[test]
    fn a_boot_inside_the_window_is_unclean() {
        assert_eq!(
            (BootReason::Unclean, Some(5)),
            classify_boot(Some(5), false)
        );
        assert_eq!(
            (BootReason::Unclean, Some(59)),
            classify_boot(Some(59), false)
        );
    }

    #[test]
    fn a_boot_outside_the_window_is_a_planned_stop() {
        assert_eq!(
            (BootReason::AfterStop, Some(60)),
            classify_boot(Some(60), false)
        );
        assert_eq!(
            (BootReason::AfterStop, Some(86_400)),
            classify_boot(Some(86_400), false)
        );
    }

    /// A recorded stop settles it whatever the gap was.
    ///
    /// This is the fix for a planned restart being reported as a crash: a
    /// `docker compose restart` is followed by a start two seconds later, which
    /// time alone reads as `unclean`. The stop row the outgoing process wrote
    /// is the evidence time cannot provide.
    #[test]
    fn a_recorded_stop_beats_the_clock() {
        // Two seconds apart, which without the stop row is `unclean`.
        assert_eq!(
            (BootReason::Unclean, Some(2)),
            classify_boot(Some(2), false),
            "without a stop row a quick restart still looks like a crash"
        );
        assert_eq!(
            (BootReason::AfterStop, Some(2)),
            classify_boot(Some(2), true),
            "a recorded stop must win regardless of how short the gap was"
        );
        // And it does not turn a genuine crash into a clean stop: the flag is
        // only ever set from a row this host wrote after its own previous boot.
        assert_eq!(
            (BootReason::Unclean, Some(1)),
            classify_boot(Some(1), false)
        );
    }

    /// A clock that moved backwards between two starts makes the gap
    /// meaningless: reporting a negative uptime as a crash would be a lie, so
    /// the boot is reported as fresh with no uptime at all.
    #[test]
    fn a_backwards_clock_is_not_a_crash() {
        assert_eq!((BootReason::Fresh, None), classify_boot(Some(-30), false));
        assert_eq!((BootReason::Fresh, None), classify_boot(Some(0), false));
        // Even with a stop row: there is no uptime to report.
        assert_eq!((BootReason::Fresh, None), classify_boot(Some(-30), true));
    }

    #[test]
    fn reason_strings_are_the_wire_values() {
        assert_eq!("fresh", BootReason::Fresh.as_str());
        assert_eq!("after_stop", BootReason::AfterStop.as_str());
        assert_eq!("unclean", BootReason::Unclean.as_str());
    }
}
