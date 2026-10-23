//! `visitor_site_grants` — which sites a visitor may enter.
//!
//! A visitor account is global, so the permission is a separate row. See
//! migration `m20240101_000073_visitor_site_grants` for why `visible` is kept
//! apart from the grant itself.

pub mod visitor_site_grants {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "visitor_site_grants")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub visitor_id: Uuid,
        pub site_id: Uuid,
        /// The portal's per-site "show this here" switch. Hiding a site tidies
        /// the portal; it does not revoke access.
        pub visible: bool,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
