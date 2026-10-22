//! `control_plane_boots` — one row per control-plane start.
//!
//! Written once, at startup, before the listeners open. Read newest-first by
//! the console (`/system/nodes`) and by the retention sweep. See migration
//! `m20240101_000068_control_plane_boots` for why a start is recorded instead
//! of a stop.
//!
//! The table lives in an inner module — the shape `DeriveEntityModel`
//! generates — re-exported under its singular name from [`super`].

pub mod control_plane_boots {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "control_plane_boots")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        /// Server time of the start.
        pub booted_at: DateTimeUtc,
        /// `fresh` / `after_stop` / `unclean` — why this process believes it
        /// started. See [`crate::boot_history::BootReason`].
        pub reason: String,
        /// The control plane's version at that start.
        pub version: String,
        /// The machine it came up on.
        pub hostname: String,
        /// How long the previous process lived, in seconds, when that could be
        /// told. `None` for the first boot, and when the gap between the two
        /// timestamps is negative (a clock moved backwards).
        pub previous_uptime_seconds: Option<i64>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
