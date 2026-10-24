//! `control_plane_stops` — one row per clean control-plane shutdown.
//!
//! Written on the way out, by the process that is going away. Read once, by the
//! start that follows it, to tell a planned restart from a crash. See migration
//! `m20240101_000077_control_plane_stops` for why this is separate from the
//! boot table.
//!
//! The table lives in an inner module — the shape `DeriveEntityModel`
//! generates — re-exported under its singular name from [`super`].

pub mod control_plane_stops {
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "control_plane_stops")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        /// Server time of the shutdown, recorded as the process exits.
        pub stopped_at: DateTimeUtc,
        /// The machine it was serving as, so a stop matches the boot of the
        /// same host rather than another replica's.
        pub hostname: String,
        /// How long the process ran. `None` when a backwards clock made the
        /// arithmetic meaningless.
        pub uptime_seconds: Option<i64>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
