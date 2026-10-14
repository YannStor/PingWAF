//! Per-site origin certificate verification default.
//!
//! `sites.origin_verify_cert` is the middle tier of the three-level
//! certificate-verification cascade: a pool that pins its own
//! `verify_cert` always wins; a pool that leaves it `NULL` follows the
//! site's value; a site that leaves it `NULL` follows the deployment-wide
//! `origin_settings.verify_cert`. The column is nullable on purpose —
//! `NULL` means "no opinion", so existing sites keep their behaviour
//! without any data migration.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sites::Table)
                    .add_column(
                        ColumnDef::new(Sites::OriginVerifyCert).boolean(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sites::Table)
                    .drop_column(Sites::OriginVerifyCert)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    OriginVerifyCert,
}
