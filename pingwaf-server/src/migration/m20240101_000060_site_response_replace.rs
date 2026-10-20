//! Site-level response body replacement.
//!
//! `sites.response_replace` holds the whole policy as one JSONB document:
//!
//! ```json
//! {
//!   "path": "^/.*",
//!   "status_codes": [200],
//!   "rules": [
//!     { "pattern": "Google", "replacement": "PingWAF", "is_regex": false }
//!   ]
//! }
//! ```
//!
//! It is the control-plane source of the data plane's `sub_filter` plugin
//! instance: the JSON is validated on write and compiled into a per-site
//! `PluginConf` when the agent configuration is generated. `NULL` means "no
//! replacement", so a site that never opts in contributes no plugin at all.
//!
//! Stored on `sites` rather than in a table of its own because it is a
//! single-site posture, like `cache_type_policy` — the `site_rules` table this
//! was originally sketched for does not exist in this schema.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sites::Table)
                    .add_column(
                        ColumnDef::new(Sites::ResponseReplace).json_binary(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sites::Table)
                    .drop_column(Sites::ResponseReplace)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    ResponseReplace,
}
