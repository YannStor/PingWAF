//! Per-site downstream read/write timeout.
//!
//! Stored as seconds so the API, proto and UI share one integer contract.
//! A constant default lets PostgreSQL add the column without rewriting the
//! table; the CHECK keeps the data plane's Duration conversion bounded even
//! for rows written outside the API.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP_SQL: &str = "\
    ALTER TABLE sites \
    ADD COLUMN IF NOT EXISTS downstream_timeout_secs integer NOT NULL DEFAULT 60; \
    ALTER TABLE sites \
    DROP CONSTRAINT IF EXISTS sites_downstream_timeout_secs_check; \
    ALTER TABLE sites \
    ADD CONSTRAINT sites_downstream_timeout_secs_check \
    CHECK (downstream_timeout_secs BETWEEN 1 AND 3600)";

const DOWN_SQL: &str = "\
    ALTER TABLE sites \
    DROP CONSTRAINT IF EXISTS sites_downstream_timeout_secs_check; \
    ALTER TABLE sites DROP COLUMN IF EXISTS downstream_timeout_secs";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // One simple-query call: a failure in the CHECK leaves the column
        // rollback-able instead of a half-applied schema that the next boot
        // cannot re-enter.
        manager.get_connection().execute_unprepared(UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(DOWN_SQL)
            .await?;
        Ok(())
    }
}
