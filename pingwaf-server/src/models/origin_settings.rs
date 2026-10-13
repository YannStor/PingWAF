//! `origin_settings` — one global row holding the origin TLS defaults.
//!
//! A single knob today: `verify_cert`, the deployment-wide default for
//! verifying an origin's TLS certificate. It reaches the data plane as
//! `BasicConf::origin_verify_cert` and is applied to every origin pool that
//! does not pin `verify_cert` itself.
//!
//! `false` — accept any origin certificate — is the default, matching what
//! the control plane has always written per pool and what self-signed
//! origins require. `true` requires a chain that validates against the
//! system trust store (or the pool's private `ca`).

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "origin_settings")]
pub struct Model {
    /// Always `1`: the settings are global, not per-site.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    /// When true, an origin pool that does not state its own `verify_cert`
    /// must present a certificate that validates against the system trust
    /// store.
    pub verify_cert: bool,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
