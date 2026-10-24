//! Entities for the two append-only log tables.
//!
//! Both are written in batches by the gRPC log shipper and read back through
//! the dashboard API, so the models carry `Serialize` but never `Deserialize`
//! (rows are always constructed server side from protocol messages).

use sea_orm::entity::prelude::*;
use serde::Serialize;

/// `security_events` — one row per WAF decision that produced an event.
pub mod security_events {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "security_events")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub site_id: Option<Uuid>,
        pub agent_id: Option<Uuid>,
        pub request_id: Option<String>,
        pub timestamp: DateTimeUtc,
        pub client_ip: String,
        pub method: String,
        pub host: Option<String>,
        pub path: Option<String>,
        pub rule_id: Option<String>,
        pub rule_name: Option<String>,
        /// Which protection produced the event: `managed` / `waf` /
        /// `ip_geo` / `bot` / `rate_limit` / `challenge`. NULL on rows
        /// recorded before the column existed.
        pub event_type: Option<String>,
        pub action: String,
        pub score: Option<i32>,
        #[sea_orm(column_type = "Text")]
        pub waf_details: Option<String>,
        pub country_code: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub user_agent: Option<String>,
        /// Who the request was made by, when the site authenticated them: the
        /// OIDC session's `sub`. NULL for an anonymous request (the ordinary
        /// case) and for every row written before migration 000071 — an empty
        /// string would claim the caller was identified and turned out to be
        /// nobody.
        pub user_identity: Option<String>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `access_logs` — full request/response metadata for every proxied request.
///
/// In a production deployment this table is partitioned by day; the schema here
/// is a plain table so that a single-node install works without extra setup.
pub mod access_logs {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "access_logs")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub site_id: Option<Uuid>,
        pub agent_id: Option<Uuid>,
        pub request_id: Option<String>,
        pub timestamp: DateTimeUtc,
        pub client_ip: String,
        pub method: String,
        pub host: Option<String>,
        pub path: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub query_string: Option<String>,
        pub status_code: Option<i32>,
        pub response_size: Option<i64>,
        pub upstream_addr: Option<String>,
        pub upstream_latency_ms: Option<i64>,
        pub total_latency_ms: Option<i64>,
        pub cache_status: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub user_agent: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub referer: Option<String>,
        pub country_code: Option<String>,
        pub tls_version: Option<String>,
        /// Snapshot of the request headers (capped by the agent).
        #[sea_orm(column_type = "JsonBinary")]
        pub request_headers: Option<Json>,
        /// Body prefix as sent by the agent (≤1 KiB, lossily decoded).
        #[sea_orm(column_type = "Text")]
        pub request_body: Option<String>,
        pub request_body_size: Option<i64>,
        pub request_body_truncated: Option<bool>,
        pub scheme: Option<String>,
        pub protocol: Option<String>,
        /// Snapshot of the response headers (capped by the agent).
        #[sea_orm(column_type = "JsonBinary")]
        pub response_headers: Option<Json>,
        /// Body prefix as sent by the agent (capped by the agent config).
        #[sea_orm(column_type = "Text")]
        pub response_body: Option<String>,
        pub response_body_size: Option<i64>,
        pub response_body_truncated: Option<bool>,
        /// Who the request was made by, when the site authenticated them: the
        /// OIDC session's `sub`. NULL for an anonymous request and for rows
        /// written before migration 000071.
        pub user_identity: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
