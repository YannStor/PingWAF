//! Metadata and ciphertext for one configuration backup.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "config_backups")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// `site`, `global` or `deployment`.
    pub scope: String,
    pub site_id: Option<Uuid>,
    /// Destination used for the last upload, if any. Kept nullable so a target
    /// can be deleted without deleting backup history.
    pub target_id: Option<Uuid>,
    /// `created`, `uploading`, `completed` or `failed`.
    pub status: String,
    pub file_name: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub manifest: Json,
    /// The self-contained backup envelope. It contains ciphertext only.
    #[serde(skip)]
    pub payload: Vec<u8>,
    pub checksum: String,
    pub error: String,
    pub actor: Option<String>,
    pub created_at: DateTimeUtc,
    /// When the current upload attempt began; stale uploads are recovered.
    pub upload_started_at: Option<DateTimeUtc>,
    pub completed_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
