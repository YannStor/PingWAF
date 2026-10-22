//! `oidc_providers` — the deployment's identity providers.
//!
//! Managed from the console's Account page, referenced by `site_oidc`. See
//! migration `m20240101_000069_oidc_providers` for why the credentials live
//! here rather than per site.
//!
//! The table lives in an inner module — the shape `DeriveEntityModel`
//! generates — re-exported under its singular name from [`super`].

pub mod oidc_providers {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "oidc_providers")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        /// Unique display name, shown in the site's provider picker.
        pub name: String,
        /// A disabled provider cannot be selected by a site, and a site that
        /// already points at it stops enforcing the gate.
        pub enabled: bool,
        /// Issuer URL, absolute http(s), without a trailing slash.
        pub issuer: String,
        pub client_id: String,
        /// Empty for a public client (PKCE only).
        pub client_secret: String,
        /// JSON array of scope strings; always contains `openid`.
        #[sea_orm(column_type = "JsonBinary")]
        pub scopes: Json,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
