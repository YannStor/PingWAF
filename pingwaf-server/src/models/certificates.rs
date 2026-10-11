//! `site_certificates` — SSL/TLS certificates per site, supporting both manual
//! upload and ACME automated issuance.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

pub mod site_certificates {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "site_certificates")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub domain: String,
        #[sea_orm(column_type = "Text")]
        pub cert_pem: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub key_pem: Option<String>,
        pub issuer: Option<String>,
        pub not_before: Option<DateTimeUtc>,
        pub expires_at: Option<DateTimeUtc>,
        pub auto_renew: bool,
        pub acme_email: Option<String>,
        pub acme_challenge_type: String,
        pub acme_dns_provider: Option<String>,
        #[sea_orm(column_type = "JsonBinary")]
        pub acme_dns_config: Option<Json>,
        pub status: String,
        /// Why the control plane last gave up on an ACME issuance; set when a
        /// `pending` order goes stale, cleared on retry or success.
        pub failure_reason: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
