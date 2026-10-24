//! `control_plane_stops` — one row per *clean* control-plane shutdown.
//!
//! The boot table records starts because a killed process runs no code and
//! cannot announce its own death. A process that *is* given a chance to shut
//! down can say so, and that turns out to be the only way to tell an ordinary
//! redeploy from a crash loop: `docker compose restart` and `kill -9` are both
//! followed by a start seconds later, so the gap between two boots cannot
//! distinguish them, and every planned restart was reported as `unclean`.
//!
//! This table is deliberately separate from `control_plane_boots` rather than a
//! nullable column on it. A stop is not part of a boot row — it belongs to the
//! process that is going away, which has its own boot row further back — and
//! joining the two by "the newest boot on this host" is exactly what
//! [`crate::boot_history::record_boot`] does when it reads them.
//!
//! Rows are swept alongside the boot table, to the same bound: a stop is only
//! ever read once, by the start that follows it.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ControlPlaneStops::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ControlPlaneStops::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneStops::StoppedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    // The host it was serving as, so a stop is matched to the
                    // boot of the same host rather than to another replica's.
                    .col(
                        ColumnDef::new(ControlPlaneStops::Hostname)
                            .string_len(255)
                            .not_null(),
                    )
                    // How long the process ran, for the console and for an
                    // operator reading the row directly. Nullable because a
                    // stop is written on the way out, when the start time is
                    // known but a clock that moved backwards makes the
                    // arithmetic meaningless.
                    .col(
                        ColumnDef::new(ControlPlaneStops::UptimeSeconds)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ControlPlaneStops::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Newest-first by host is the only read: "did *this* host stop
        // cleanly, and when".
        manager
            .create_index(
                Index::create()
                    .name("idx_control_plane_stops_hostname_stopped_at")
                    .table(ControlPlaneStops::Table)
                    .col(ControlPlaneStops::Hostname)
                    .col(ControlPlaneStops::StoppedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ControlPlaneStops::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum ControlPlaneStops {
    Table,
    Id,
    StoppedAt,
    Hostname,
    UptimeSeconds,
    CreatedAt,
}
