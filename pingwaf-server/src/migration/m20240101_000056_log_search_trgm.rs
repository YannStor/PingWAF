//! Trigram indexes for the free-text log searches.
//!
//! The `q` (path + host) and `path` filters compile to leading-wildcard
//! LIKE predicates (`LIKE '%needle%'`), which a btree cannot serve: every
//! listing carrying one degraded to a sequential scan over the (up to
//! 90-day) window — once for the page and once for the count. pg_trgm's
//! GIN indexes answer exactly those predicates from the index, so both
//! the page fetch and the bounded count in `api::logs` stay
//! index-driven.
//!
//! Trade-off: GIN maintenance adds per-row write cost on two columns of
//! the highest-write tables. Accepted because the log tables are the
//! primary investigation surface, and the bounded count caps the
//! remaining worst case regardless.
//!
//! pg_trgm is a trusted extension since Postgres 13, so a plain database
//! owner can `CREATE EXTENSION` it — no superuser required on stock
//! images.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared("CREATE EXTENSION IF NOT EXISTS pg_trgm")
            .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_access_logs_path_trgm \
             ON access_logs USING gin (path gin_trgm_ops)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_access_logs_host_trgm \
             ON access_logs USING gin (host gin_trgm_ops)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_security_events_path_trgm \
             ON security_events USING gin (path gin_trgm_ops)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_security_events_host_trgm \
             ON security_events USING gin (host gin_trgm_ops)",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The extension itself is left installed: other consumers may
        // depend on it, and dropping the indexes fully reverses the
        // write-cost side of this migration.
        let conn = manager.get_connection();
        for index in [
            "idx_access_logs_path_trgm",
            "idx_access_logs_host_trgm",
            "idx_security_events_path_trgm",
            "idx_security_events_host_trgm",
        ] {
            conn.execute_unprepared(&format!("DROP INDEX IF EXISTS {index}"))
                .await?;
        }
        Ok(())
    }
}
