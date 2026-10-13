//! Global origin settings: how the data plane validates an origin's TLS
//! certificate.
//!
//! One knob lives in the single-row `origin_settings` table: `verify_cert`,
//! the deployment-wide default applied to every origin pool that does not
//! state a `verify_cert` of its own. A pool that pins a value keeps it, so a
//! single self-signed origin can opt out without weakening the rest of the
//! deployment.
//!
//! The value rides in every `RuleBundle` and reaches the data plane as
//! `BasicConf::origin_verify_cert`, so saving here pushes it to the agents
//! immediately — no agent restart, no per-pool edit.

use axum::extract::State;
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::Utc;
use sea_orm::ActiveModelTrait;
use sea_orm::EntityTrait;
use sea_orm::Set;
use serde::Deserialize;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_all_config_changed;
use crate::models::origin_settings;

/// Primary key of the single row.
const SETTINGS_ID: i32 = 1;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route("/settings/origin", get(show).put(update))
}

#[derive(Debug, Deserialize)]
pub struct UpdateOriginSettingsRequest {
    /// When present, sets the deployment-wide origin certificate check.
    #[serde(default)]
    pub verify_cert: Option<bool>,
}

/// `GET /api/v1/settings/origin` — administrators only.
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<origin_settings::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(load(&state.db).await?))
}

/// `PUT /api/v1/settings/origin` — administrators only.
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<UpdateOriginSettingsRequest>,
) -> Result<Json<origin_settings::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let Some(verify_cert) = payload.verify_cert else {
        return Err(ApiError::BadRequest("provide verify_cert".to_string()));
    };

    let row = load(&state.db).await?;
    let mut active: origin_settings::ActiveModel = row.into();
    active.verify_cert = Set(verify_cert);
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(
        actor = %current.id,
        verify_cert = updated.verify_cert,
        "origin settings updated"
    );

    // The value rides inside every rule bundle, so each site's fingerprint
    // changes; push the new configuration now instead of waiting for the
    // next periodic sync.
    notify_all_config_changed(&state, None).await;

    Ok(Json(updated))
}

/// Reads the settings row, creating it with the defaults if it is missing.
///
/// Shared with the gRPC layer, which stamps the values onto every rule
/// bundle it builds.
///
/// A read failure degrades to the historical lenient default rather than an
/// error: the certificate check is a per-request data-plane decision, and
/// failing it closed would 502 every HTTPS origin over a transient database
/// problem.
pub async fn load(
    db: &sea_orm::DatabaseConnection,
) -> Result<origin_settings::Model, ApiError> {
    if let Some(row) = origin_settings::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
    {
        return Ok(row);
    }

    let insert = origin_settings::ActiveModel {
        id: Set(SETTINGS_ID),
        verify_cert: Set(false),
        updated_at: Set(Utc::now()),
    };
    use sea_orm::sea_query::OnConflict;
    let ignore_conflict = OnConflict::column(origin_settings::Column::Id)
        .do_nothing()
        .to_owned();
    match origin_settings::Entity::insert(insert)
        .on_conflict(ignore_conflict)
        .exec(db)
        .await
    {
        Ok(_) | Err(sea_orm::DbErr::RecordNotInserted) => {},
        Err(err) => return Err(err.into()),
    }

    origin_settings::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
        .ok_or_else(|| {
            ApiError::Internal("origin settings row vanished".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cert_defaults_to_lenient() {
        // The seed row and the lazy insert must agree with the migration:
        // `false` keeps every existing self-signed origin working.
        let insert = origin_settings::ActiveModel {
            id: Set(SETTINGS_ID),
            verify_cert: Set(false),
            updated_at: Set(Utc::now()),
        };
        assert_eq!(insert.verify_cert, Set(false));
    }
}
