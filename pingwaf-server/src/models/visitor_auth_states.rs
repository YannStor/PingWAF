//! `visitor_auth_states` — short-lived visitor authentication state.
//!
//! This is what makes a proof-of-work login work across more than one
//! data-plane instance; see migration `m20240101_000075_visitor_auth_states`
//! for the reasoning. Consumption is a delete, which is what makes an answer
//! single-use.

pub mod visitor_auth_states {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "visitor_auth_states")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        /// `login_challenge` / `passkey_reg` / `passkey_login`.
        pub kind: String,
        /// The host the login was started from, so a challenge answered at
        /// another site is refused.
        pub site_id: String,
        /// Set only for the kinds that have an account in hand.
        pub visitor_id: Option<Uuid>,
        /// The JSON blob each kind needs.
        #[sea_orm(column_type = "JsonBinary")]
        pub payload: Json,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// The `kind` values. Kept as constants rather than an enum column so a newer
/// build can add one without a migration on the old one.
pub mod auth_state_kind {
    /// A proof-of-work nonce and its difficulty, waiting for an answer.
    pub const LOGIN_CHALLENGE: &str = "login_challenge";
    /// A WebAuthn registration ceremony.
    pub const PASSKEY_REG: &str = "passkey_reg";
    /// A WebAuthn assertion ceremony.
    pub const PASSKEY_LOGIN: &str = "passkey_login";
}

/// How long a login challenge stays answerable.
///
/// Matches the WAF challenge's window: long enough for a slow browser to
/// finish the proof of work, short enough that a captured nonce is not worth
/// replaying later.
pub const VISITOR_CHALLENGE_TTL_SECONDS: i64 = 300;

/// How long a passkey ceremony may stay open. Matches the console's.
pub const VISITOR_PASSKEY_STATE_TTL_SECONDS: i64 = 300;
