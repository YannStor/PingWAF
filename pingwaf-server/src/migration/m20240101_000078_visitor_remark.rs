//! Add an operator-facing remark to visitor accounts.
//!
//! The value helps collaborators recognise an account in the console. It is
//! deliberately absent from the visitor sign-in and session paths.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteVisitors::Table)
                    .add_column(
                        ColumnDef::new(SiteVisitors::Remark)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteVisitors::Table)
                    .drop_column(SiteVisitors::Remark)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteVisitors {
    Table,
    Remark,
}
