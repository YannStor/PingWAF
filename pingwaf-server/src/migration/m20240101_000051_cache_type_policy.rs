//! Per-site cache type policy: five extension-based content families
//! (web assets, images, media, other, HTML) an administrator configures
//! with a cache toggle, edge/browser TTLs, and the file extensions each
//! family covers.
//!
//! The policy is stored as a single nullable JSONB column on `sites` —
//! NULL means "no policy", the site then relies solely on its
//! `cache_rules`. The JSON shape is validated on write (extension tokens,
//! TTL bounds, no cross-category duplicates) and compiled into additional
//! cache rules in the data plane behind the site's custom rules.

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
                        ColumnDef::new(Sites::CacheTypePolicy).json_binary(),
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
                    .drop_column(Sites::CacheTypePolicy)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    CacheTypePolicy,
}
