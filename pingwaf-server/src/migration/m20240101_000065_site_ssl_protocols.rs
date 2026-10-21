//! Per-site downstream protocol switches.
//!
//! `site_ssl` described the TLS posture (versions, HSTS, mTLS) but had no say
//! in which HTTP protocols the site answers. The 443 listener is shared by
//! every site and `enabled_h2` is a listener-level switch in pingap, so the
//! control plane had no way to turn HTTP/2 on at all — the data plane never
//! set `enabled_h2`, leaving every site on HTTP/1.1.
//!
//! Two columns make the choice explicit:
//!
//! * `http1_enabled` — defaults to `TRUE`: every existing site keeps working;
//! * `http2_enabled` — defaults to `FALSE`: it matches what those sites were
//!   actually served before (HTTP/1.1 only), so an upgrade does not silently
//!   change the protocol on live traffic. New sites are created with both
//!   switches on.
//!
//! PostgreSQL-only, like the rest of this migration set.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteSsl::Table)
                    .add_column(
                        ColumnDef::new(SiteSsl::Http1Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .add_column(
                        ColumnDef::new(SiteSsl::Http2Enabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteSsl::Table)
                    .drop_column(SiteSsl::Http1Enabled)
                    .drop_column(SiteSsl::Http2Enabled)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteSsl {
    Table,
    Http1Enabled,
    Http2Enabled,
}
