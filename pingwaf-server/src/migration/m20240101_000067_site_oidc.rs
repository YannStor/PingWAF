//! Per-site OpenID Connect authentication (`site_oidc`).
//!
//! One row per site, like the basic-auth and challenge settings next to it.
//! Both JSON columns are `jsonb` with explicit defaults so pre-existing
//! snapshots and the API's `find_or_create` default row agree word for word.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SiteOidc::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteOidc::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::SiteId)
                            .uuid()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::Enabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::Issuer)
                            .string_len(512)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::ClientId)
                            .string_len(255)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::ClientSecret)
                            .string_len(1024)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::CookieSecret)
                            .string_len(256)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::RedirectPath)
                            .string_len(512)
                            .not_null()
                            .default("/oauth2/callback"),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::LogoutPath)
                            .string_len(512)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::RedirectUrl)
                            .string_len(2048)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::Scopes)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'[\"openid\"]'::jsonb")),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::CookieName)
                            .string_len(128)
                            .not_null()
                            .default("pingap_oidc"),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::SessionTtlSeconds)
                            .integer()
                            .not_null()
                            .default(43_200),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::ClaimsToHeaders)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'[]'::jsonb")),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteOidc::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_oidc_site_id")
                            .from(SiteOidc::Table, SiteOidc::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop().table(SiteOidc::Table).if_exists().to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteOidc {
    Table,
    Id,
    SiteId,
    Enabled,
    Issuer,
    ClientId,
    ClientSecret,
    CookieSecret,
    RedirectPath,
    LogoutPath,
    RedirectUrl,
    Scopes,
    CookieName,
    SessionTtlSeconds,
    ClaimsToHeaders,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}
