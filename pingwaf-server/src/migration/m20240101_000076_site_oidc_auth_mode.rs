//! How a protected site signs its visitors in (`site_oidc.auth_mode`).
//!
//! Until now a site with OIDC enabled had exactly one way in: the provider's
//! authorization-code flow. This column adds the other half — visitors who hold
//! a local account on this deployment — and lets a site offer both.
//!
//! The default is `oidc`, and that is the whole compatibility story: every row
//! that already exists keeps doing exactly what it did, and a site only leaves
//! the old behaviour when an operator says so. Nothing here changes what an
//! already-configured site does on upgrade.
//!
//! Stored as text rather than an enum column, matching `access_mode` next to
//! it: an unrecognised value written by a newer build is read as "not a mode
//! this build knows", which the plugin treats as a configuration error rather
//! than as a permission.

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
                        ColumnDef::new(SiteOidc::AuthMode)
                            .string_len(16)
                            .not_null()
                            .default("oidc"),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteOidc::Table)
                    .drop_column(SiteOidc::AuthMode)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteOidc {
    Table,
    AuthMode,
}
