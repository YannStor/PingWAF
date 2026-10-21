//! SeaORM entities for the AI crawler control tables.
//!
//! Two inner modules, one per table, matching SeaORM's `DeriveEntityModel`
//! shape; `models/mod.rs` re-exports them as `site_ai_crawl_settings` and
//! `site_ai_bot_policies`.

/// `site_ai_crawl_settings` — one row per site.
pub mod site_ai_crawl_settings {
    use chrono::{DateTime, Utc};
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "site_ai_crawl_settings")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(unique)]
        pub site_id: Uuid,
        /// Whether the AI crawler policy is enforced at all.
        pub enabled: bool,
        /// Action for a family with no override: `allow` / `monitor` / `block`.
        pub default_action: String,
        /// `off` or `generate` (the control plane renders the body and the
        /// edge serves it instead of the origin's file).
        pub robots_mode: String,
        /// Operator-supplied body; empty means "render from the template".
        pub robots_body: String,
        pub llms_mode: String,
        pub llms_body: String,
        /// Include the site's routes as links in the generated llms.txt.
        pub llms_include_routes: bool,
        /// `Cache-Control: max-age` for the generated files.
        pub cache_max_age: i32,
        /// Content Signals advertised in the generated robots.txt.
        pub content_signal_search: bool,
        pub content_signal_ai_train: bool,
        pub content_signal_ai_input: bool,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `site_ai_bot_policies` — per-family override.
pub mod site_ai_bot_policies {
    use chrono::{DateTime, Utc};
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "site_ai_bot_policies")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        /// Stable family id from `api::ai_crawl::AI_BOTS` (e.g. `gptbot`).
        pub bot_id: String,
        /// `inherit` / `allow` / `monitor` / `block`.
        pub action: String,
        pub created_at: DateTime<Utc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
