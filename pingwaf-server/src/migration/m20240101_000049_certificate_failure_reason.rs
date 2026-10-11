//! Add `failure_reason` to `site_certificates`.
//!
//! An ACME order that never completes used to sit in `pending` forever with
//! no explanation: the issuance happens on the edge and nothing wrote back a
//! terminal failure. The column records why the control plane last gave up on
//! a certificate (e.g. the stale-pending sweep), so the dashboard can show the
//! reason instead of an eternal spinner. It is cleared as soon as issuance is
//! retried or the edge reports the certificate live.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteCertificates::Table)
                    .add_column(
                        ColumnDef::new(SiteCertificates::FailureReason).text(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteCertificates::Table)
                    .drop_column(SiteCertificates::FailureReason)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteCertificates {
    Table,
    FailureReason,
}
