//! Configuration version history: list, inspect and roll back.
//!
//! Versions are recorded by the configuration push path
//! ([`crate::grpc::notify_config_changed`]); this module only reads them and
//! restores a chosen snapshot through [`crate::config_history::rollback`].

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::config_history::{self, VersionScope};
use crate::grpc::{notify_all_config_changed, notify_config_changed};
use crate::models::{config_version, site};

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/config-versions", get(list_versions))
        .route("/config-versions/{version_id}", get(show_version))
        .route(
            "/config-versions/{version_id}/rollback",
            post(rollback_version),
        )
}

/// One row of the version list: everything except the snapshot payload.
#[derive(Debug, Serialize)]
pub struct VersionSummary {
    pub id: i64,
    pub site_id: Option<Uuid>,
    /// The site's domain, resolved for display.
    pub site_domain: Option<String>,
    pub config_hash: String,
    pub source: String,
    pub actor: Option<String>,
    /// Per-table row counts captured with the version.
    pub summary: Option<Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ListVersionsQuery {
    /// `"global"` selects deployment-wide versions, a site UUID that site's.
    pub site_id: Option<String>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

/// `GET /api/v1/config-versions` — administrators only.
async fn list_versions(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListVersionsQuery>,
) -> Result<Json<Vec<VersionSummary>>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let ListVersionsQuery {
        site_id,
        limit,
        offset,
    } = query;
    let limit = limit.unwrap_or(50).clamp(1, 200);
    let offset = offset.unwrap_or(0);
    let mut query = config_version::Entity::find()
        .order_by_desc(config_version::Column::Id)
        .limit(limit)
        .offset(offset);
    query = match site_id.as_deref() {
        None => query,
        Some("global") => {
            query.filter(config_version::Column::SiteId.is_null())
        },
        Some(raw) => {
            let site_id = Uuid::parse_str(raw.trim()).map_err(|_| {
                ApiError::BadRequest(
                    "site_id must be a UUID or 'global'".to_string(),
                )
            })?;
            query.filter(config_version::Column::SiteId.eq(site_id))
        },
    };

    let rows = query.all(&state.db).await?;

    // Resolve the domains of the referenced sites in one query.
    let referenced: Vec<Uuid> =
        rows.iter().filter_map(|row| row.site_id).collect();
    let domains: std::collections::HashMap<Uuid, String> =
        if referenced.is_empty() {
            std::collections::HashMap::new()
        } else {
            site::Entity::find()
                .filter(site::Column::Id.is_in(referenced))
                .all(&state.db)
                .await?
                .into_iter()
                .map(|row| (row.id, row.domain))
                .collect()
        };

    let summaries = rows
        .into_iter()
        .map(|row| {
            let site_domain =
                row.site_id.and_then(|id| domains.get(&id).cloned());
            VersionSummary {
                id: row.id,
                site_id: row.site_id,
                site_domain,
                config_hash: row.config_hash,
                source: row.source,
                actor: row.actor,
                summary: row.summary,
                created_at: row.created_at,
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// `GET /api/v1/config-versions/{id}` — administrators only. Returns the
/// full snapshot; the console uses it for the JSON preview and the CLI for
/// offline inspection.
async fn show_version(
    State(state): State<AppState>,
    current: AuthUser,
    Path(version_id): Path<i64>,
) -> Result<Json<config_version::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let row = config_version::Entity::find_by_id(version_id)
        .one(&state.db)
        .await?
        .ok_or(ApiError::NotFound(format!(
            "version {version_id} not found"
        )))?;
    Ok(Json(row))
}

/// `POST /api/v1/config-versions/{id}/rollback` — administrators only.
///
/// Restores the snapshot inside a transaction, then pushes the restored
/// configuration to the agents like any other change. The rollback itself is
/// recorded as a new version attributed to the operator.
async fn rollback_version(
    State(state): State<AppState>,
    current: AuthUser,
    Path(version_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    // A missing snapshot surfaces through `From<DbErr>`, which answers a 404
    // with the generic "not found" text: `RecordNotFound` carries the lookup
    // string, and echoing it named the table to the caller.
    let outcome =
        config_history::rollback(&state.db, version_id, Some(&current.email))
            .await?;

    match outcome.scope {
        VersionScope::Site(site_id) => {
            touch_site(&state, site_id).await?;
            notify_config_changed(&state, site_id, Some(&current.email)).await;
        },
        VersionScope::Global => {
            // The restored global settings ride in every bundle.
            notify_all_config_changed(&state, Some(&current.email)).await;
        },
    }

    tracing::info!(
        actor = %current.email,
        restored = outcome.restored_version,
        new_version = ?outcome.new_version,
        "configuration rolled back from the console"
    );

    Ok(Json(serde_json::json!({
        "restored_version": outcome.restored_version,
        "new_version": outcome.new_version,
        "scope": match outcome.scope {
            VersionScope::Site(site_id) => site_id.to_string(),
            VersionScope::Global => "global".to_string(),
        },
    })))
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use sea_orm::DbErr;

    use super::*;

    /// R-04: a rollback target that no longer exists reaches the caller as the
    /// shared 404 envelope. `config_history::rollback` reports it as
    /// `DbErr::RecordNotFound("site not found")`, whose text named the table,
    /// so the handler must not build its own `ApiError::NotFound` around it.
    #[tokio::test]
    async fn a_missing_rollback_target_answers_the_generic_not_found() {
        let err = ApiError::from(DbErr::RecordNotFound(
            "sites: no row for id 7".to_string(),
        ));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "error": { "code": "not_found", "message": "not found" }
            })
        );
    }
}
