//! Control-plane boot history (`control_plane_boots`).
//!
//! The control plane is a single process with no persistent identity: when it
//! is killed — an OOM kill, a `docker restart`, a crash — nothing in the
//! database records that it happened. The only moment it can speak for itself
//! is **at startup**, because a process that has been `SIGKILL`ed never runs
//! its shutdown path.
//!
//! So each start writes one row here. Two adjacent rows then say how long the
//! previous process lived, which is what tells an operator whether the
//! container is being killed in a loop: a site that normally runs for days and
//! suddenly shows three boots in ten minutes is restarting, not merely
//! redeployed.
//!
//! Why not a "stopped" row: a graceful `SIGTERM` could write one, but an OOM
//! kill cannot, so the absence of a shutdown row would be indistinguishable
//! from a crash — and a table that silently omits the case it exists to catch
//! is worse than one that infers it. The boot row carries everything needed.
//!
//! The retention sweep in [`crate::monitoring`] keeps the newest
//! [`MAX_BOOT_ROWS`] rows; the console reads the newest five.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ControlPlaneBoots::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ControlPlaneBoots::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    // Server time, not process time: two processes must be
                    // comparable, and a container clock can be wrong.
                    .col(
                        ColumnDef::new(ControlPlaneBoots::BootedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    // Why this process started, as far as it can tell:
                    // `fresh` (no previous boot), `after_stop` (the last boot
                    // is old enough that a graceful stop fits between) or
                    // `unclean` (the last boot was too recent for a planned
                    // stop, so the previous process died without stopping).
                    .col(
                        ColumnDef::new(ControlPlaneBoots::Reason)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneBoots::Version)
                            .string_len(32)
                            .not_null(),
                    )
                    // The machine the control plane came up on, so a move
                    // between hosts is visible rather than implied.
                    .col(
                        ColumnDef::new(ControlPlaneBoots::Hostname)
                            .string_len(255)
                            .not_null(),
                    )
                    // Seconds the previous process is known to have lived, or
                    // null when it could not be told (no previous boot, or the
                    // gap spans a clock the control plane cannot trust).
                    .col(
                        ColumnDef::new(
                            ControlPlaneBoots::PreviousUptimeSeconds,
                        )
                        .big_integer(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneBoots::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Newest-first reads are the only ones the console and the sweep make.
        manager
            .create_index(
                Index::create()
                    .name("idx_control_plane_boots_booted_at")
                    .table(ControlPlaneBoots::Table)
                    .col(ControlPlaneBoots::BootedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ControlPlaneBoots::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ControlPlaneBoots {
    Table,
    Id,
    BootedAt,
    Reason,
    Version,
    Hostname,
    PreviousUptimeSeconds,
    CreatedAt,
}
