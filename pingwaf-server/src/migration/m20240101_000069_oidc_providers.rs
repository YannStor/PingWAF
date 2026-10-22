//! Global OIDC identity providers (`oidc_providers`).
//!
//! An identity provider — its issuer, client credentials and session key — is
//! a property of the *deployment*, not of any one site: the same Keycloak
//! realm usually fronts several sites, and storing its client secret once
//! means rotating it is one edit rather than one per site. This table is what
//! the console's Account page manages.
//!
//! `site_oidc` then points at a row here (`provider_id`) and carries only what
//! genuinely differs per site: the callback paths, the session cookie name,
//! the claim-to-header map, and the access rules that decide which signed-in
//! users may pass. See `m20240101_000070_site_oidc_access` for that half.
//!
//! `client_secret` and `cookie_secret` are stored as they were in `site_oidc`
//! (plaintext, the same convention as the basic-auth credentials next to it)
//! and masked on every read path; only a `PUT` that sends the mask keeps the
//! stored value.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OidcProviders::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OidcProviders::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    // Shown in the site's provider picker and in error
                    // messages, so it is unique: two providers with one name
                    // would be indistinguishable where it matters most.
                    .col(
                        ColumnDef::new(OidcProviders::Name)
                            .string_len(128)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(OidcProviders::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(OidcProviders::Issuer)
                            .string_len(512)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OidcProviders::ClientId)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OidcProviders::ClientSecret)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(OidcProviders::Scopes)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'[\"openid\"]'::jsonb")),
                    )
                    .col(
                        ColumnDef::new(OidcProviders::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OidcProviders::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(OidcProviders::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum OidcProviders {
    Table,
    Id,
    Name,
    Enabled,
    Issuer,
    ClientId,
    ClientSecret,
    Scopes,
    CreatedAt,
    UpdatedAt,
}
