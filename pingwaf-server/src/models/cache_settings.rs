//! `cache_settings` — one global row holding the deployment-wide cache
//! ceiling.
//!
//! Four knobs: the largest single cacheable object (`max_file_size_mb`,
//! enforced per response by the data plane), the total disk budget every
//! site's quota is clamped against (`max_space_mb`, `0` = unlimited), the
//! cache master switch (`master_enabled`), and the edge TTL a cache rule
//! without an explicit TTL falls back to (`default_edge_ttl_seconds`, `0` =
//! no fallback).

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "cache_settings")]
pub struct Model {
    /// Always `1`: the settings are global, not per-site.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    /// Largest single cacheable object, in megabytes.
    pub max_file_size_mb: i32,
    /// Total disk budget across all sites, in megabytes; `0` = unlimited.
    pub max_space_mb: i32,
    /// Master switch: when false the data plane generates no cache plugin.
    pub master_enabled: bool,
    /// Edge TTL (seconds) used when a rule does not configure one; `0` =
    /// no fallback, an unconfigured rule simply does not get a TTL floor.
    pub default_edge_ttl_seconds: i32,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
