//! `config_versions` — snapshot history of the WAF configuration.
//!
//! Each row is a complete, restorable snapshot of one configuration scope:
//! `site_id = NULL` covers the deployment-wide settings (defense mode,
//! global error pages), a site UUID covers that site's whole policy. The
//! snapshot JSON maps table names to their serialized rows, which
//! [`crate::config_history`] captures and restores.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "config_versions")]
pub struct Model {
    /// Monotonic version number; also the primary key.
    #[sea_orm(primary_key)]
    pub id: i64,
    /// `None` for deployment-wide snapshots, the site for site policies.
    pub site_id: Option<Uuid>,
    /// `site`, `global` or `deployment`; prevents the two NULL-site scopes
    /// from sharing one history, dedup window and retention policy.
    pub scope: String,
    /// Config fingerprint the agents compare (`""` when unknown).
    pub config_hash: String,
    /// Where the change came from: `api`, `cli` or `rollback`.
    pub source: String,
    /// Operator e-mail when known (rollbacks); `None` for routine edits.
    pub actor: Option<String>,
    /// Per-table row counts, so the console can summarise without loading
    /// the whole snapshot.
    #[sea_orm(column_type = "JsonBinary")]
    pub summary: Option<Json>,
    /// `{ "schema": 1, "site": {...}?, "tables": { name: [rows...] } }`.
    #[sea_orm(column_type = "JsonBinary")]
    pub snapshot: Json,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Where a version was recorded from.
pub mod source {
    pub const API: &str = "api";
    pub const CLI: &str = "cli";
    pub const ROLLBACK: &str = "rollback";
}
