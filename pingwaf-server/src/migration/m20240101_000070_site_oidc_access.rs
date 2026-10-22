//! Site-level OIDC: a provider reference and access rules.
//!
//! Two changes to `site_oidc`, both about moving a decision to the layer it
//! belongs to.
//!
//! **The provider moves out.** `issuer`, `client_id`, `client_secret` and
//! `scopes` describe the identity provider, which several sites usually share;
//! they now live once in `oidc_providers` (migration 000069) and a site points
//! at a row with `provider_id`. What stays is genuinely per-site: the callback
//! and logout paths, the redirect URL override, the session cookie name and
//! TTL, the session key, and the claim-to-header map.
//!
//! `provider_id` is nullable because the column is added to a table that may
//! already hold rows; a row without one is a site whose gate is not fully
//! configured, and the API refuses to enable it (rather than silently
//! enforcing nothing).
//!
//! **Access rules are added.** Authenticating proves *who* a visitor is; it
//! does not say whether they may enter. `access_mode` and `access_rules` add
//! that half: `allow_all` (the default, and what the previous behaviour was)
//! admits every signed-in user, while `require_any` / `require_all` hold the
//! session's claims against the rules and answer `403` when they do not match.
//!
//! The foreign key is `ON DELETE SET NULL` rather than `CASCADE`: deleting a
//! provider must not silently delete a site's gate configuration along with
//! the access rules an operator wrote — it leaves the site visibly
//! unconfigured, which is the failure an operator can act on.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteOidc::Table)
                    .add_column(
                        ColumnDef::new(SiteOidc::ProviderId).uuid().null(),
                    )
                    .to_owned(),
            )
            .await?;

        // What the site may admit. `allow_all` keeps the pre-existing
        // behaviour for every row that already exists.
        manager
            .alter_table(
                Table::alter()
                    .table(SiteOidc::Table)
                    .add_column(
                        ColumnDef::new(SiteOidc::AccessMode)
                            .string_len(16)
                            .not_null()
                            .default("allow_all"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SiteOidc::Table)
                    .add_column(
                        ColumnDef::new(SiteOidc::AccessRules)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'[]'::jsonb")),
                    )
                    .to_owned(),
            )
            .await?;

        // The provider columns are gone from here: they live in
        // `oidc_providers` now. Dropping rather than leaving them unused keeps
        // one source of truth for a credential.
        for column in [
            SiteOidc::Issuer,
            SiteOidc::ClientId,
            SiteOidc::ClientSecret,
            SiteOidc::Scopes,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(SiteOidc::Table)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_site_oidc_provider_id")
                    .from(SiteOidc::Table, SiteOidc::ProviderId)
                    .to(OidcProviders::Table, OidcProviders::Id)
                    .on_delete(ForeignKeyAction::SetNull)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk_site_oidc_provider_id")
                    .table(SiteOidc::Table)
                    .to_owned(),
            )
            .await?;

        for (column, definition) in [
            (
                SiteOidc::Issuer,
                ColumnDef::new(SiteOidc::Issuer)
                    .string_len(512)
                    .not_null()
                    .default(""),
            ),
            (
                SiteOidc::ClientId,
                ColumnDef::new(SiteOidc::ClientId)
                    .string_len(255)
                    .not_null()
                    .default(""),
            ),
            (
                SiteOidc::ClientSecret,
                ColumnDef::new(SiteOidc::ClientSecret)
                    .text()
                    .not_null()
                    .default(""),
            ),
            (
                SiteOidc::Scopes,
                ColumnDef::new(SiteOidc::Scopes)
                    .json_binary()
                    .not_null()
                    .default(Expr::cust("'[\"openid\"]'::jsonb")),
            ),
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(SiteOidc::Table)
                        .add_column(definition)
                        .to_owned(),
                )
                .await?;
            let _ = column;
        }

        for column in [
            SiteOidc::AccessRules,
            SiteOidc::AccessMode,
            SiteOidc::ProviderId,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(SiteOidc::Table)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SiteOidc {
    Table,
    ProviderId,
    AccessMode,
    AccessRules,
    Issuer,
    ClientId,
    ClientSecret,
    Scopes,
}

#[derive(DeriveIden)]
enum OidcProviders {
    Table,
    Id,
}
