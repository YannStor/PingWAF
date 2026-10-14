//! Removes the dead `challenge_settings.cookie_secret` column.
//!
//! The field was never sent to agents (`challenge_to_proto` does not map it)
//! and the console never consumed it; the challenge plugin derives its
//! clearance-cookie key from its own plugin config instead. Dropping the
//! column keeps the model and the schema aligned.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ChallengeSettings::Table)
                    .drop_column(ChallengeSettings::CookieSecret)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ChallengeSettings::Table)
                    .add_column(
                        // Matches the original column definition in
                        // m20240101_000006: string_len(255), nullable.
                        ColumnDef::new(ChallengeSettings::CookieSecret)
                            .string_len(255)
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ChallengeSettings {
    Table,
    CookieSecret,
}
