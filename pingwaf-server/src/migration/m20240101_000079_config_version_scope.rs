//! Distinguish global and full-deployment version histories, and index retention.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ConfigVersions::Table)
                    .add_column(
                        ColumnDef::new(ConfigVersions::Scope)
                            .text()
                            .not_null()
                            .default("site"),
                    )
                    .to_owned(),
            )
            .await?;
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "UPDATE config_versions SET scope = 'global' WHERE site_id IS NULL",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_config_versions_scope_site_id_id \
             ON config_versions (scope, site_id, id)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_config_versions_created_at \
             ON config_versions (created_at)",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_config_versions_created_at",
        )
        .await?;
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_config_versions_scope_site_id_id",
        )
        .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ConfigVersions::Table)
                    .drop_column(ConfigVersions::Scope)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ConfigVersions {
    Table,
    Scope,
}
