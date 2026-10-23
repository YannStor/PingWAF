//! Which sites a visitor may enter (`visitor_site_grants`).
//!
//! A visitor account is global (see `m20240101_000072_visitor_accounts`), so
//! the permission to enter a particular site is a separate row. One account,
//! several sites — which is what lets the portal show "the sites you can
//! reach" as a list.
//!
//! `visible` is the portal's per-site "show this here" switch. It is
//! deliberately **not** the same as the grant itself: hiding a site only
//! tidies the portal, it does not revoke access, and an operator looking at
//! the grants table should not have to guess which of the two a row means.
//! The API keeps them apart for the same reason.
//!
//! Both foreign keys cascade. A deleted visitor's grants are meaningless, and
//! so are a deleted site's — unlike `site_oidc.provider_id`, where `SET NULL`
//! was right because the row carried configuration worth keeping visible.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(VisitorSiteGrants::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(VisitorSiteGrants::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(VisitorSiteGrants::VisitorId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VisitorSiteGrants::SiteId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VisitorSiteGrants::Visible)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(VisitorSiteGrants::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_visitor_site_grants_visitor_id")
                            .from(
                                VisitorSiteGrants::Table,
                                VisitorSiteGrants::VisitorId,
                            )
                            .to(SiteVisitors::Table, SiteVisitors::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_visitor_site_grants_site_id")
                            .from(
                                VisitorSiteGrants::Table,
                                VisitorSiteGrants::SiteId,
                            )
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // One grant per (visitor, site): a second row for the same pair could
        // only contradict the first, and `visible` would then be ambiguous.
        manager
            .create_index(
                Index::create()
                    .name("idx_visitor_site_grants_visitor_site")
                    .table(VisitorSiteGrants::Table)
                    .col(VisitorSiteGrants::VisitorId)
                    .col(VisitorSiteGrants::SiteId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // The portal lists a visitor's sites by visitor id; the console lists
        // a site's visitors by site id.
        manager
            .create_index(
                Index::create()
                    .name("idx_visitor_site_grants_site_id")
                    .table(VisitorSiteGrants::Table)
                    .col(VisitorSiteGrants::SiteId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(VisitorSiteGrants::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum VisitorSiteGrants {
    Table,
    Id,
    VisitorId,
    SiteId,
    Visible,
    CreatedAt,
}

#[derive(DeriveIden)]
enum SiteVisitors {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}
