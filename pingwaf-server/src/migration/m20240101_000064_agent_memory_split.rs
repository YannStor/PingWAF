//! Splits the agent memory figure into capacity and usage.
//!
//! `agents.memory_bytes` has carried two different measurements: the RAM the
//! node has, reported once at registration (`client::register` sends
//! `get_total_memory()`), and then — from the first heartbeat on — the RAM *in
//! use* (`AgentHeartbeat::memory_usage_bytes`). `/agents` and `/system/nodes`
//! therefore rendered a capacity for a freshly enrolled row and a usage for a
//! heartbeating one, with no way to tell which figure was on screen.
//!
//! One column per meaning fixes that:
//!
//! * `total_memory_bytes` — RAM the node has, written at registration;
//! * `used_memory_bytes` — RAM in use, written from the heartbeat.
//!
//! `memory_bytes` stays and is still written by both paths exactly as before,
//! so a reader that has not been updated keeps seeing what it saw. Usage is not
//! backfilled: the newest probe sample can be hours old for an offline node,
//! and every connected agent overwrites `used_memory_bytes` on its next
//! heartbeat. Capacity is backfilled from the probe's own `MemTotal` reading,
//! so the fleet does not have to restart before the column means something.
//!
//! PostgreSQL-only, like the rest of this migration set.

use sea_orm_migration::prelude::*;

/// Copies the newest `host_samples.memory_total_bytes` of every agent onto its
/// row. Same reading, same source (`/proc/meminfo:MemTotal`) as registration,
/// and `host_samples` is already indexed `(agent_id, sampled_at DESC)`.
const BACKFILL_TOTAL_MEMORY_SQL: &str = "UPDATE agents AS a \
     SET total_memory_bytes = newest.memory_total_bytes \
     FROM ( \
         SELECT DISTINCT ON (agent_id) agent_id, memory_total_bytes \
         FROM host_samples \
         WHERE memory_total_bytes IS NOT NULL AND memory_total_bytes > 0 \
         ORDER BY agent_id, sampled_at DESC, id DESC \
     ) AS newest \
     WHERE a.id = newest.agent_id AND a.total_memory_bytes IS NULL";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .add_column(
                        ColumnDef::new(Agents::TotalMemoryBytes)
                            .big_integer()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Agents::UsedMemoryBytes)
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(BACKFILL_TOTAL_MEMORY_SQL)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .drop_column(Agents::TotalMemoryBytes)
                    .drop_column(Agents::UsedMemoryBytes)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Agents {
    Table,
    TotalMemoryBytes,
    UsedMemoryBytes,
}
