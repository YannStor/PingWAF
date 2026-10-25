//! Add a lease timestamp to remote backup uploads.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ConfigBackups::Table)
                    .add_column(
                        ColumnDef::new(ConfigBackups::UploadStartedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX IF NOT EXISTS idx_config_backups_upload_lease \
                 ON config_backups (status, upload_started_at)",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "DROP INDEX IF EXISTS idx_config_backups_upload_lease",
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ConfigBackups::Table)
                    .drop_column(ConfigBackups::UploadStartedAt)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ConfigBackups {
    Table,
    UploadStartedAt,
}
