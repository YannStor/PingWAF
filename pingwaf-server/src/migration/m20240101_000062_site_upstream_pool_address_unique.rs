//! Makes "one origin address per pool" a database invariant.
//!
//! `create_upstream` / `update_upstream` (`api/sites.rs`) reject a duplicate
//! with a read-then-write pre-check, so two concurrent requests could both pass
//! it and insert the same address twice. A pool holding one origin twice is
//! never a load-balancing decision: pingap keeps both as separate backends, so
//! every request is balanced onto that server twice over and its health-check
//! load doubles.
//!
//! The pre-check also compared addresses with `==`, which made `HOST:port` and
//! `host:port` two different origins even though a host name is
//! case-insensitive. The duplicate rule is therefore `lower(address)`:
//!
//! ```sql
//! CREATE UNIQUE INDEX idx_site_upstreams_pool_address
//!     ON site_upstreams (pool_id, lower(address))
//! ```
//!
//! PostgreSQL supports the expression index (`lower(text)` is immutable), and
//! the API's pre-check queries with the same predicate, so the check and the
//! constraint cannot disagree about what "the same origin" is.
//!
//! Existing duplicates are **not** deleted: the migration aborts with a message
//! naming the pool and the address instead. Which of the two rows to keep (and
//! with which weight and health status) is an operator decision, and silently
//! dropping one changes a pool's capacity. Remove the duplicate — or correct it
//! to its real, distinct address — and restart the control plane; the migration
//! then applies on the next startup.
//!
//! PostgreSQL-only, like the rest of this migration set (`gen_random_uuid`,
//! `DO $$` blocks).

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Fails the migration when one pool already holds the same address twice,
/// ignoring case.
const DUPLICATE_CHECK_SQL: &str = r#"
DO $$
DECLARE
    conflict_pool uuid;
    conflict_address text;
BEGIN
    SELECT pool_id, lower(address) INTO conflict_pool, conflict_address
    FROM site_upstreams
    GROUP BY pool_id, lower(address)
    HAVING count(*) > 1
    LIMIT 1;
    IF conflict_pool IS NOT NULL THEN
        RAISE EXCEPTION 'origin address "%" appears more than once (ignoring case) in pool % — remove the duplicate before upgrading', conflict_address, conflict_pool;
    END IF;
END
$$;
"#;

/// The backstop the application-level pre-check documents. `lower(address)`
/// rather than a plain column list so `HOST:port` collides with `host:port`.
const UNIQUE_INDEX_UP_SQL: &str = "CREATE UNIQUE INDEX IF NOT EXISTS \
     idx_site_upstreams_pool_address \
     ON site_upstreams (pool_id, lower(address))";

const UNIQUE_INDEX_DOWN_SQL: &str =
    "DROP INDEX IF EXISTS idx_site_upstreams_pool_address";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(DUPLICATE_CHECK_SQL).await?;
        conn.execute_unprepared(UNIQUE_INDEX_UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(UNIQUE_INDEX_DOWN_SQL)
            .await?;
        Ok(())
    }
}
