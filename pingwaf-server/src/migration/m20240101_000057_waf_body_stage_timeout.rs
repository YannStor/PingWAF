//! Per-site body-withholding window for WAF body inspection.
//!
//! When a site runs with deep inspection enabled the data plane buffers the
//! request body before handing it to the WAF. How long it may hold that body
//! (waiting for a slow client, or for a large upload to complete) is a
//! per-site trade-off: too short and a slow-but-legitimate upload is broken,
//! too long and a trickling client ties up a connection. It is therefore a
//! site setting rather than a listener constant, capped at 30 seconds because
//! holding a body longer than that turns every slowloris-style client into an
//! effective connection-exhaustion vector.
//!
//! The default matches the data-plane default, so an existing site keeps the
//! behavior it has today.
//!
//! Upgrading note: the column is added `NOT NULL DEFAULT 30`. PostgreSQL
//! (11+, where `ADD COLUMN ... DEFAULT` no longer rewrites the table) still
//! **materialises** 30 into every existing `waf_settings` row, so after this
//! migration no row is left NULL/0 and no row can be told apart as "had no
//! value" versus "operator chose 30". That is accepted rather than worked
//! around: 30 *is* the documented default (`DEFAULT_BODY_STAGE_TIMEOUT_SECS`),
//! so the backfilled rows behave exactly like rows that were never touched,
//! and an operator who wants a shorter window sets it explicitly (1–29) in the
//! site's WAF settings. The API keeps accepting `0` as "reset to the default"
//! — it just stores 30 rather than a sentinel, which is why the read path
//! cannot (and does not need to) distinguish the two.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WafSettings::Table)
                    .add_column(
                        ColumnDef::new(WafSettings::BodyStageTimeoutSecs)
                            .integer()
                            .not_null()
                            .default(30),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WafSettings::Table)
                    .drop_column(WafSettings::BodyStageTimeoutSecs)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum WafSettings {
    Table,
    BodyStageTimeoutSecs,
}
