//! Per-route `Host` header sent to the origin.
//!
//! A route that proxies a third-party site (the `google.com` mirror case) must
//! present *that* site's name in the `Host` header, otherwise the origin
//! answers for the wrong virtual host — usually its own 404. `sni` on the pool
//! only fixes TLS; the HTTP `Host` stayed the client's, which is the client's
//! view of the mirror, not the origin's.
//!
//! Nullable on purpose: `NULL` means "keep the client's Host", the historic
//! behaviour, so existing routes keep forwarding unchanged and no data
//! migration is needed. The value is a bare host name
//! (`pingap_config::LocationConf::upstream_host`), validated at write time with
//! the same rule the config-file path applies.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteRoutes::Table)
                    .add_column(
                        ColumnDef::new(SiteRoutes::UpstreamHost).text().null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteRoutes::Table)
                    .drop_column(SiteRoutes::UpstreamHost)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteRoutes {
    Table,
    UpstreamHost,
}
