//! An `agent_metrics` index the fleet node view can actually ride.
//!
//! `GET /api/v1/system/nodes` reads one gauge per agent on every poll
//! (the dashboard refreshes it every 15s):
//!
//! ```sql
//! SELECT DISTINCT ON (agent_id) agent_id, value FROM agent_metrics
//! WHERE agent_id = ANY($1) AND name = $2
//! ORDER BY agent_id, recorded_at DESC, id DESC
//! ```
//!
//! Migration 000015's `idx_agent_metrics_agent_name_time (agent_id, name,
//! recorded_at)` cannot order that result. Both equality columns already lead
//! the index, and `name` being a pseudoconstant leaves `(agent_id, recorded_at)`
//! as the ordering pair — but a b-tree only yields that pair all-ASC (forward
//! scan) or all-DESC (backward scan), and the statement asks for the mixed
//! `agent_id ASC, recorded_at DESC`. Neither direction matches, so the planner
//! falls back to a `Sort` over every retained row of that metric name —
//! `agent_metrics` is append-only, batch-written, and swept only after
//! `metric_retention_days` (7 by default).
//!
//! The index added here declares the direction the statement wants, so the same
//! query becomes an ordered index scan:
//!
//! ```text
//! Unique                          <- DISTINCT ON (agent_id)
//!   ->  Sort (id DESC)            <- M6 tie-breaker, one row per agent
//!         ->  Index Scan using idx_agent_metrics_agent_name_time_desc
//!               Index Cond: (agent_id = ANY($1) AND name = $2)
//! ```
//!
//! `id DESC` is resolved by that small sort (or an incremental sort inside each
//! `(agent_id, recorded_at)` tie group), never over the table: the index suffix
//! `(recorded_at DESC)` is a prefix of the requested order.
//!
//! The old ASC index is kept. It still serves ascending range scans on
//! `recorded_at` for one `(agent_id, name)`, and dropping it is a separate
//! decision from fixing this query; note that `agent_metrics` is a high-write
//! table, so the pair costs one extra b-tree insert per row. `CREATE INDEX`
//! (not `CONCURRENTLY`) is in line with the other migrations — it runs inside
//! the migrator's transaction, which takes a write lock for the build.

use sea_orm_migration::prelude::*;

/// The index this migration owns; `system.rs` names it in the comment that
/// explains the query shape.
pub const INDEX_NAME: &str = "idx_agent_metrics_agent_name_time_desc";

/// Column order and direction must match [`INDEX_NAME`]'s consumers —
/// `system::LATEST_CONNECTIONS_SQL` is the only one today.
pub const CREATE_SQL: &str = "CREATE INDEX IF NOT EXISTS \
     idx_agent_metrics_agent_name_time_desc \
     ON agent_metrics (agent_id, name, recorded_at DESC)";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(CREATE_SQL)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&format!("DROP INDEX IF EXISTS {INDEX_NAME}"))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DDL is the contract with the query: equality columns first (so the
    /// index also covers the `name` predicate) and the time column descending
    /// (so `ORDER BY agent_id, recorded_at DESC` needs no sort). "Fixing" the
    /// direction back to ASC would silently restore the full sort this
    /// migration exists to remove.
    #[test]
    fn index_ddl_matches_the_query_it_serves() {
        assert!(CREATE_SQL.contains(INDEX_NAME), "{CREATE_SQL}");
        assert!(
            CREATE_SQL.contains("(agent_id, name, recorded_at DESC)"),
            "{CREATE_SQL}"
        );
        assert!(CREATE_SQL.contains("IF NOT EXISTS"), "{CREATE_SQL}");
        // A partial index or an extra column would change the plan this was
        // written for; the tuple above is the whole definition.
        assert!(!CREATE_SQL.contains("WHERE"), "{CREATE_SQL}");
    }
}
