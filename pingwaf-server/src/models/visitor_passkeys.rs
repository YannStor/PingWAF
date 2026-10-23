//! `visitor_passkeys` / `visitor_passkey_states` — a visitor's passkeys.
//!
//! A parallel pair to `passkey_credentials` / `passkey_states`, which belong to
//! console operators; the columns match because the same `passkey-server` crate
//! verifies both, but the owner column differs. See migration
//! `m20240101_000074_visitor_passkeys` for why one table with a discriminator
//! was rejected.

pub mod visitor_passkeys {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "visitor_passkeys")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub visitor_id: Uuid,
        /// Base64url credential id, unique across every visitor.
        pub cred_id: String,
        #[sea_orm(column_type = "Text")]
        pub public_key: String,
        /// Visitor-facing label; renaming does not invalidate the credential.
        pub name: String,
        /// Signature counter reported by the authenticator, used to spot clones.
        pub counter: i64,
        pub created_at: DateTimeUtc,
        pub last_used_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod visitor_passkey_states {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "visitor_passkey_states")]
    pub struct Model {
        /// `reg:<visitor_id>` for a registration, `login:<challenge>` for an
        /// assertion.
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_type = "Text")]
        pub state_json: String,
        pub expires_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
