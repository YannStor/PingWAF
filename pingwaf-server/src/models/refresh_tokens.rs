//! `refresh_tokens` — single-use markers for dashboard refresh tokens.
//!
//! The row is inserted when a refresh token is exchanged; a second exchange
//! of the same `jti` conflicts and is refused. Rows are pruned once their
//! token has expired, so the table stays proportional to live sessions.

use sea_orm::entity::prelude::*;

/// `refresh_tokens`
pub mod refresh_token {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "refresh_tokens")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub jti: String,
        pub user_id: Uuid,
        pub expires_at: DateTimeUtc,
        /// When the token was exchanged; a row exists only after use.
        pub used_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
