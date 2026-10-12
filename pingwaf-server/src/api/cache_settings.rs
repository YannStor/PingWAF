//! Global cache settings: the deployment-wide cache ceiling.
//!
//! Four knobs live in the single-row `cache_settings` table: the largest
//! single cacheable object, the total disk budget every site's quota is
//! clamped against, the cache master switch, and the default edge TTL a rule
//! without an explicit TTL falls back to. Everything rides inside each
//! `RuleBundle`, so saving here pushes the new configuration to the agents
//! immediately.

use axum::extract::State;
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::Utc;
use sea_orm::ActiveModelTrait;
use sea_orm::ColumnTrait;
use sea_orm::EntityTrait;
use sea_orm::QueryFilter;
use sea_orm::Set;
use serde::Deserialize;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_all_config_changed;
use crate::models::cache_settings;

/// Primary key of the single row.
const SETTINGS_ID: i32 = 1;

/// Hard ceiling for [`UpdateCacheSettingsRequest::max_file_size_mb`]: a
/// single cached object never exceeds 1 GiB.
pub const MAX_CACHE_FILE_SIZE_MB: i32 = 1024;

/// Hard ceiling for [`UpdateCacheSettingsRequest::max_space_mb`]: 1 TiB of
/// disk budget; `0` means unlimited.
pub const MAX_CACHE_SPACE_MB: i32 = 1024 * 1024;

/// Hard ceiling for [`UpdateCacheSettingsRequest::default_edge_ttl_seconds`];
/// `0` means "no fallback" (matches the site rule validation range).
pub const MAX_DEFAULT_EDGE_TTL_SECONDS: i32 = 30 * 24 * 3600;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/settings/cache", get(show).put(update))
}

#[derive(Debug, Deserialize)]
pub struct UpdateCacheSettingsRequest {
    /// When present, sets the largest single cacheable object (MiB).
    #[serde(default)]
    pub max_file_size_mb: Option<i32>,
    /// When present, sets the total disk budget (MiB); `0` = unlimited.
    #[serde(default)]
    pub max_space_mb: Option<i32>,
    /// When present, sets the cache master switch.
    #[serde(default)]
    pub master_enabled: Option<bool>,
    /// When present, sets the fallback edge TTL for rules without an
    /// explicit TTL (seconds); `0` = no fallback.
    #[serde(default)]
    pub default_edge_ttl_seconds: Option<i32>,
}

/// `GET /api/v1/settings/cache` — administrators only.
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<cache_settings::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(load(&state.db).await?))
}

/// `PUT /api/v1/settings/cache` — administrators only.
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<UpdateCacheSettingsRequest>,
) -> Result<Json<cache_settings::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    if payload.max_file_size_mb.is_none()
        && payload.max_space_mb.is_none()
        && payload.master_enabled.is_none()
        && payload.default_edge_ttl_seconds.is_none()
    {
        return Err(ApiError::BadRequest(
            "provide max_file_size_mb, max_space_mb, master_enabled or \
             default_edge_ttl_seconds"
                .to_string(),
        ));
    }

    if let Some(value) = payload.max_file_size_mb {
        if !(1..=MAX_CACHE_FILE_SIZE_MB).contains(&value) {
            return Err(ApiError::BadRequest(format!(
                "max_file_size_mb must be between 1 and \
                 {MAX_CACHE_FILE_SIZE_MB}"
            )));
        }
    }
    if let Some(value) = payload.max_space_mb {
        if !(0..=MAX_CACHE_SPACE_MB).contains(&value) {
            return Err(ApiError::BadRequest(format!(
                "max_space_mb must be between 0 (unlimited) and \
                 {MAX_CACHE_SPACE_MB}"
            )));
        }
    }
    if let Some(value) = payload.default_edge_ttl_seconds {
        if !(0..=MAX_DEFAULT_EDGE_TTL_SECONDS).contains(&value) {
            return Err(ApiError::BadRequest(format!(
                "default_edge_ttl_seconds must be between 0 (no fallback) \
                 and {MAX_DEFAULT_EDGE_TTL_SECONDS}"
            )));
        }
    }

    // A lowered ceiling must not strand site-level overrides that now exceed
    // it: the write-time validation keeps stored values inside the current
    // limits, so tightening the global row requires checking the sites that
    // pinned an explicit value.
    if let Some(new_file_cap) = payload.max_file_size_mb {
        let violating = crate::models::site::Entity::find()
            .filter(
                crate::models::site::Column::CacheMaxFileSizeMb
                    .gt(new_file_cap),
            )
            .one(&state.db)
            .await?;
        if violating.is_some() {
            return Err(ApiError::BadRequest(format!(
                "max_file_size_mb cannot be lowered to {new_file_cap}: at \
                 least one site pins a higher site-level single-file limit; \
                 raise those site limits first"
            )));
        }
    }

    let row = load(&state.db).await?;
    let mut active: cache_settings::ActiveModel = row.into();
    if let Some(value) = payload.max_file_size_mb {
        active.max_file_size_mb = Set(value);
    }
    if let Some(value) = payload.max_space_mb {
        active.max_space_mb = Set(value);
    }
    if let Some(value) = payload.master_enabled {
        active.master_enabled = Set(value);
    }
    if let Some(value) = payload.default_edge_ttl_seconds {
        active.default_edge_ttl_seconds = Set(value);
    }
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(
        actor = %current.id,
        max_file_size_mb = updated.max_file_size_mb,
        max_space_mb = updated.max_space_mb,
        master_enabled = updated.master_enabled,
        default_edge_ttl_seconds = updated.default_edge_ttl_seconds,
        "cache settings updated"
    );

    // The values ride inside every rule bundle, so each site's fingerprint
    // changes; push the new configuration now instead of waiting for the
    // next periodic sync.
    notify_all_config_changed(&state, None).await;

    Ok(Json(updated))
}

/// Reads the settings row, creating it with the defaults if it is missing.
///
/// Shared with the gRPC layer, which stamps the ceiling onto every rule
/// bundle it builds, and with the site cache-settings validation.
pub async fn load(
    db: &sea_orm::DatabaseConnection,
) -> Result<cache_settings::Model, ApiError> {
    if let Some(row) = cache_settings::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
    {
        return Ok(row);
    }

    let insert = cache_settings::ActiveModel {
        id: Set(SETTINGS_ID),
        max_file_size_mb: Set(16),
        max_space_mb: Set(10240),
        master_enabled: Set(true),
        default_edge_ttl_seconds: Set(0),
        updated_at: Set(Utc::now()),
    };
    use sea_orm::sea_query::OnConflict;
    let ignore_conflict = OnConflict::column(cache_settings::Column::Id)
        .do_nothing()
        .to_owned();
    match cache_settings::Entity::insert(insert)
        .on_conflict(ignore_conflict)
        .exec(db)
        .await
    {
        Ok(_) | Err(sea_orm::DbErr::RecordNotInserted) => {},
        Err(err) => return Err(err.into()),
    }

    cache_settings::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
        .ok_or_else(|| {
            ApiError::Internal("cache settings row vanished".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        max_file_size_mb: Option<i32>,
        max_space_mb: Option<i32>,
        default_edge_ttl_seconds: Option<i32>,
    ) -> UpdateCacheSettingsRequest {
        UpdateCacheSettingsRequest {
            max_file_size_mb,
            max_space_mb,
            master_enabled: None,
            default_edge_ttl_seconds,
        }
    }

    #[test]
    fn file_size_bounds_match_the_documented_matrix() {
        // 1..=1024 accepted is enforced by the handler; these constants are
        // the contract the frontend mirrors.
        assert_eq!(MAX_CACHE_FILE_SIZE_MB, 1024);
        assert_eq!(MAX_CACHE_SPACE_MB, 1024 * 1024);
        assert_eq!(MAX_DEFAULT_EDGE_TTL_SECONDS, 2_592_000);
        let _ = request(Some(1), Some(0), Some(0));
    }
}
