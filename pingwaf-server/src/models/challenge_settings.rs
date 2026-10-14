//! `challenge_settings` — per-site challenge/CC protection configuration.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "challenge_settings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub site_id: Uuid,
    pub enabled: bool,
    pub under_attack_mode: bool,
    pub default_level: String,
    pub clearance_duration_secs: i32,
    pub rate_threshold: i32,
    pub exempt_paths: Vec<String>,
    pub browser_integrity_check: bool,
    pub tls_fingerprint_check: bool,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
