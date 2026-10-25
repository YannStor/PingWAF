//! Remote backup targets and encrypted backup records.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ConfigBackupTargets::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ConfigBackupTargets::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ConfigBackupTargets::Kind)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigBackupTargets::Name)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigBackupTargets::Config)
                            .json_binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigBackupTargets::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(ConfigBackupTargets::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(ConfigBackupTargets::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(ConfigBackups::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ConfigBackups::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ConfigBackups::Scope).text().not_null())
                    .col(ColumnDef::new(ConfigBackups::SiteId).uuid().null())
                    .col(ColumnDef::new(ConfigBackups::TargetId).uuid().null())
                    .col(
                        ColumnDef::new(ConfigBackups::Status).text().not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigBackups::FileName)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigBackups::Manifest)
                            .json_binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigBackups::Payload)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigBackups::Checksum)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ConfigBackups::Error)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(ColumnDef::new(ConfigBackups::Actor).text().null())
                    .col(
                        ColumnDef::new(ConfigBackups::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(ConfigBackups::CompletedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_config_backups_target")
                            .from(ConfigBackups::Table, ConfigBackups::TargetId)
                            .to(
                                ConfigBackupTargets::Table,
                                ConfigBackupTargets::Id,
                            )
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_config_backups_scope_site_id_id \
             ON config_backups (scope, site_id, id)",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_config_backups_target_id \
             ON config_backups (target_id)",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_config_backups_target_id",
        )
        .await?;
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_config_backups_scope_site_id_id",
        )
        .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(ConfigBackups::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(ConfigBackupTargets::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ConfigBackupTargets {
    Table,
    Id,
    Kind,
    Name,
    Config,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum ConfigBackups {
    Table,
    Id,
    Scope,
    SiteId,
    TargetId,
    Status,
    FileName,
    Manifest,
    Payload,
    Checksum,
    Error,
    Actor,
    CreatedAt,
    CompletedAt,
}
