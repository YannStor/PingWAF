//! Global cache settings (`cache_settings`) and per-site cache limits.
//!
//! The settings table follows the single-row pattern of `defense_settings`:
//! one global row (id = 1) holding the deployment-wide cache ceiling — the
//! largest single cacheable object, the total disk budget every site's quota
//! is clamped against, the cache master switch, and the default edge TTL a
//! rule without an explicit TTL falls back to.
//!
//! Two nullable columns land on `sites`: a site-level single-file cap and a
//! JSONB map of per-content-type single-file caps. NULL means "follow the
//! global setting"; a value is validated against the global ceiling at write
//! time and additionally clamped in the data plane, so lowering the global
//! limit later tightens every site automatically.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CacheSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CacheSettings::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CacheSettings::MaxFileSizeMb)
                            .integer()
                            .not_null()
                            .default(16),
                    )
                    .col(
                        ColumnDef::new(CacheSettings::MaxSpaceMb)
                            .integer()
                            .not_null()
                            .default(10240),
                    )
                    .col(
                        ColumnDef::new(CacheSettings::MasterEnabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(CacheSettings::DefaultEdgeTtlSeconds)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(CacheSettings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Seed the default row so the first read does not have to handle a
        // missing row (the API also creates it lazily, this keeps direct SQL
        // readers honest).
        manager
            .get_connection()
            .execute_unprepared(
                "INSERT INTO cache_settings (id, max_file_size_mb, \
                 max_space_mb, master_enabled, default_edge_ttl_seconds, \
                 updated_at) VALUES (1, 16, 10240, true, 0, now()) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sites::Table)
                    .add_column(
                        ColumnDef::new(Sites::CacheMaxFileSizeMb).integer(),
                    )
                    .add_column(
                        ColumnDef::new(Sites::CacheTypeLimitsMb).json_binary(),
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
                    .drop_column(Sites::CacheTypeLimitsMb)
                    .drop_column(Sites::CacheMaxFileSizeMb)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(CacheSettings::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum CacheSettings {
    Table,
    Id,
    MaxFileSizeMb,
    MaxSpaceMb,
    MasterEnabled,
    DefaultEdgeTtlSeconds,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    CacheMaxFileSizeMb,
    CacheTypeLimitsMb,
}
