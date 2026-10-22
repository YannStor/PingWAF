//! `site_oidc` — per-site OpenID Connect authentication.
//!
//! One row per site, like the basic-auth and challenge settings next to it.
//! The `scopes` and `claims_to_headers` columns are JSON arrays kept in the
//! insertion order: `scopes` is the list sent to the identity provider
//! (`openid` is always first) and `claims_to_headers` maps ID-token claims
//! onto response headers.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "site_oidc")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub site_id: Uuid,
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub cookie_secret: String,
    pub redirect_path: String,
    pub logout_path: String,
    pub redirect_url: String,
    /// JSON array of scope strings, in the order sent to the provider.
    #[sea_orm(column_type = "JsonBinary")]
    pub scopes: Json,
    pub cookie_name: String,
    pub session_ttl_seconds: i32,
    /// JSON array of `{claim, header}` objects.
    #[sea_orm(column_type = "JsonBinary")]
    pub claims_to_headers: Json,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
