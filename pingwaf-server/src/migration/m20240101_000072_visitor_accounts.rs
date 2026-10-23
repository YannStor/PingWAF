//! Visitor accounts (`site_visitors`): the people a protected site lets in.
//!
//! Distinct from `users`, which holds *operators* of the console. A visitor is
//! a person visiting a site this deployment protects; they never reach the
//! console, and an operator never signs into a protected site through this
//! table. Keeping them apart is what makes the two credential stores
//! independently rotatable — a leaked visitor password cannot become a console
//! session, and disabling an operator cannot lock a site's visitors out.
//!
//! The account is **global** rather than per-site: one person may be granted
//! several sites, and the visitor portal lists exactly those. A per-site
//! account could not express that, and would make a person hold N passwords
//! for N sites on one deployment.
//!
//! `password_hash` is bcrypt, the same as `users.password_hash`, so the two
//! stores share one verifier and one cost policy.
//!
//! `token_version` mirrors `users.token_version`: bumping it invalidates every
//! session already issued, which is how a password change or a disable takes
//! effect on sessions that were minted before it.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SiteVisitors::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteVisitors::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    // The sign-in handle. Unique so a login cannot be ambiguous
                    // between two accounts.
                    .col(
                        ColumnDef::new(SiteVisitors::Email)
                            .string_len(255)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(SiteVisitors::PasswordHash)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteVisitors::Name)
                            .string_len(128)
                            .not_null()
                            .default(""),
                    )
                    // A disabled account keeps its rows and its grants; it just
                    // cannot sign in. Deleting is the destructive option and is
                    // reserved for a deliberate removal.
                    .col(
                        ColumnDef::new(SiteVisitors::Disabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(SiteVisitors::TokenVersion)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(SiteVisitors::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteVisitors::UpdatedAt)
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
                    .table(SiteVisitors::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum SiteVisitors {
    Table,
    Id,
    Email,
    PasswordHash,
    Name,
    Disabled,
    TokenVersion,
    CreatedAt,
    UpdatedAt,
}
