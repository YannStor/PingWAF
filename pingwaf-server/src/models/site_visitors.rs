//! `site_visitors` — the accounts a protected site admits.
//!
//! Distinct from `users` (console operators); see migration
//! `m20240101_000072_visitor_accounts` for why the two stores are separate.
//!
//! The table lives in an inner module — the shape `DeriveEntityModel`
//! generates — re-exported under its singular name from [`super`].

pub mod site_visitors {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "site_visitors")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        /// Sign-in handle; unique, so a login cannot be ambiguous.
        pub email: String,
        /// bcrypt, same verifier and cost policy as `users.password_hash`.
        pub password_hash: String,
        pub name: String,
        /// A disabled account keeps its grants and cannot sign in.
        pub disabled: bool,
        /// Bumping this invalidates every session already issued, which is
        /// how a password change reaches sessions minted before it.
        pub token_version: i64,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// How long a visitor session may live, in seconds, when a site does not say.
///
/// Deliberately the same default as the OIDC session TTL: a visitor should not
/// be able to tell which of the two ways in they used by how long it lasts.
pub const DEFAULT_VISITOR_SESSION_TTL_SECONDS: i64 = 43_200;

/// Shortest session a site may configure, matching the OIDC floor.
pub const MIN_VISITOR_SESSION_TTL_SECONDS: i64 = 60;

/// Longest session a site may configure, matching the OIDC ceiling.
pub const MAX_VISITOR_SESSION_TTL_SECONDS: i64 = 31_536_000;
