//! Route-level path rewriting for origin traffic.
//!
//! A route's `path` only decides *matching*: until now the request was
//! forwarded with its path untouched, so a route on `/api` pointing at an
//! origin that serves `/users` answered 404 for `/api/users`. These two columns
//! let a route say what the origin should receive:
//!
//! - `strip_prefix` — remove the matched prefix (`/api/users` → `/users`).
//!   `NOT NULL DEFAULT FALSE` so existing routes keep forwarding the full
//!   path, and the backfilled default is indistinguishable from a route that
//!   never opts in.
//! - `rewrite_path` — replace the whole path with a fixed value. Nullable on
//!   purpose: `NULL` means "no replacement", which is not the same as a
//!   replacement with the empty path, and PostgreSQL would not let an empty
//!   string mean the former without a sentinel.

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
                        ColumnDef::new(SiteRoutes::StripPrefix)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(SiteRoutes::RewritePath).text().null(),
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
                    .drop_column(SiteRoutes::StripPrefix)
                    .drop_column(SiteRoutes::RewritePath)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteRoutes {
    Table,
    StripPrefix,
    RewritePath,
}
