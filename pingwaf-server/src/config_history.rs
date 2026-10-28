//! Configuration version capture, retention and rollback.
//!
//! The public surface stays small for the REST, CLI and gRPC callers. Snapshot
//! layout and table coverage live in `config_catalog`; validation and the
//! transactional write live in `config_restore`.

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr,
    EntityTrait, IsolationLevel, QueryFilter, QueryOrder, QuerySelect, Set,
    TransactionTrait,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::config_catalog::{self, rows_for};
use crate::config_restore::{self, RestoreOptions};
use crate::models::{config_version, site};

pub use crate::config_catalog::VersionScope;

pub const MAX_VERSIONS_PER_SCOPE: u64 = 50;
pub const VERSION_RETENTION_DAYS: i64 = 30;
pub const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RollbackOutcome {
    pub restored_version: i64,
    pub scope: VersionScope,
    pub new_version: Option<i64>,
    pub pre_rollback_version: Option<i64>,
}

/// Captures one scope. `include_secrets` is only for an encrypted backup; the
/// ordinary, API-readable version history always uses `false`.
pub async fn capture_snapshot(
    db: &DatabaseConnection,
    scope: VersionScope,
    include_secrets: bool,
) -> Result<Value, DbErr> {
    config_catalog::capture(db, scope, include_secrets).await
}

pub async fn capture_site_snapshot(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Value, DbErr> {
    capture_snapshot(db, VersionScope::Site(site_id), false).await
}

pub async fn capture_global_snapshot(
    db: &DatabaseConnection,
) -> Result<Value, DbErr> {
    capture_snapshot(db, VersionScope::Global, false).await
}

pub async fn capture_deployment_snapshot(
    db: &DatabaseConnection,
    include_secrets: bool,
) -> Result<Value, DbErr> {
    capture_snapshot(db, VersionScope::Deployment, include_secrets).await
}

pub fn summarise(snapshot: &Value) -> Value {
    let mut summary = serde_json::Map::new();
    let schema = snapshot.get("schema").and_then(Value::as_i64).unwrap_or(1);
    if let Some(tables) = snapshot.get("tables").and_then(Value::as_object) {
        let tables: std::collections::BTreeMap<String, Value> = tables
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        for name in tables.keys() {
            if let Ok(Some(rows)) = rows_for(schema, &tables, name) {
                if !rows.is_empty() {
                    summary.insert(name.clone(), json!(rows.len()));
                }
            }
        }
    }
    if schema == 1 && snapshot.get("site").is_some_and(Value::is_object) {
        summary.insert("sites".to_string(), json!(1));
    }
    Value::Object(summary)
}

pub async fn record_version(
    db: &DatabaseConnection,
    scope: VersionScope,
    source: &str,
    actor: Option<&str>,
    config_hash: &str,
) -> Result<Option<i64>, DbErr> {
    // Every table in one snapshot comes from the same PostgreSQL view. The
    // previous sequence of independent reads could mix two concurrent edits.
    // Read-write: the snapshot and its insert now share this transaction.
    let txn = db
        .begin_with_config(Some(IsolationLevel::RepeatableRead), None)
        .await?;
    let recorded =
        record_version_in(&txn, scope, source, actor, config_hash).await?;
    txn.commit().await?;
    Ok(recorded)
}

/// [`record_version`] on a caller-owned connection or transaction.
///
/// Rollback uses this to record its pre-rollback snapshot inside the same
/// transaction that holds the advisory lock, so the archived version and the
/// restore cannot observe different states.
async fn record_version_in<C: ConnectionTrait>(
    db: &C,
    scope: VersionScope,
    source: &str,
    actor: Option<&str>,
    config_hash: &str,
) -> Result<Option<i64>, DbErr> {
    if let Some(latest) = latest_version(db, scope).await? {
        if !config_hash.is_empty() && latest.config_hash == config_hash {
            return Ok(None);
        }
    }

    let snapshot = config_catalog::capture(db, scope, false).await?;

    let snapshot_bytes = serde_json::to_vec(&snapshot)
        .map(|bytes| bytes.len())
        .unwrap_or_default();
    if snapshot_bytes > MAX_SNAPSHOT_BYTES {
        tracing::warn!(
            scope = %scope.describe(),
            bytes = snapshot_bytes,
            threshold = MAX_SNAPSHOT_BYTES,
            "configuration snapshot exceeds the expected size"
        );
    }
    let summary = summarise(&snapshot);
    let row = config_version::ActiveModel {
        id: Default::default(),
        site_id: Set(scope.column_value()),
        scope: Set(scope.as_str().to_string()),
        config_hash: Set(config_hash.to_string()),
        source: Set(source.to_string()),
        actor: Set(actor.map(str::to_string)),
        summary: Set(Some(summary)),
        snapshot: Set(snapshot),
        created_at: Set(Utc::now()),
    }
    .insert(db)
    .await?;

    prune_scope(db, scope).await;
    tracing::info!(
        version = row.id,
        scope = %scope.describe(),
        %source,
        "configuration version recorded"
    );
    Ok(Some(row.id))
}

pub async fn latest_version<C: ConnectionTrait>(
    db: &C,
    scope: VersionScope,
) -> Result<Option<config_version::Model>, DbErr> {
    let mut query = config_version::Entity::find()
        .filter(config_version::Column::Scope.eq(scope.as_str()))
        .order_by_desc(config_version::Column::Id)
        .limit(1);
    query = match scope.column_value() {
        Some(site_id) => {
            query.filter(config_version::Column::SiteId.eq(site_id))
        },
        None => query.filter(config_version::Column::SiteId.is_null()),
    };
    query.one(db).await
}

/// Applies the retention policy to every scope: drop rows older than 30 days
/// and keep only the newest 50 rows per `(scope, site_id)` partition.
///
/// Used at startup, by the daily monitor and by the manual prune endpoint, so
/// a scope that has not changed recently is cleaned too.
pub async fn prune_expired(db: &DatabaseConnection) -> Result<u64, DbErr> {
    let cutoff = Utc::now() - chrono::Duration::days(VERSION_RETENTION_DAYS);
    let stmt = sea_orm::Statement::from_sql_and_values(
        db.get_database_backend(),
        "WITH ranked AS (\
             SELECT id, ROW_NUMBER() OVER (\
                 PARTITION BY scope, site_id ORDER BY id DESC\
             ) AS position FROM config_versions\
         )\
         DELETE FROM config_versions WHERE created_at < $1 \
            OR id IN (SELECT id FROM ranked WHERE position > $2)",
        [cutoff.into(), MAX_VERSIONS_PER_SCOPE.into()],
    );
    let result = db.execute(stmt).await?;
    Ok(result.rows_affected())
}

async fn prune_scope<C: ConnectionTrait>(db: &C, scope: VersionScope) {
    let cutoff = Utc::now() - chrono::Duration::days(VERSION_RETENTION_DAYS);
    let sql = "\
        DELETE FROM config_versions \
        WHERE scope = $1 AND site_id IS NOT DISTINCT FROM $2 \
          AND (created_at < $3 \
               OR id NOT IN (\
                   SELECT id FROM config_versions \
                   WHERE scope = $1 AND site_id IS NOT DISTINCT FROM $2 \
                   ORDER BY id DESC LIMIT $4))";
    let stmt = sea_orm::Statement::from_sql_and_values(
        db.get_database_backend(),
        sql,
        [
            scope.as_str().into(),
            scope.column_value().into(),
            cutoff.into(),
            MAX_VERSIONS_PER_SCOPE.into(),
        ],
    );
    if let Err(err) = db.execute(stmt).await {
        tracing::warn!(error = %err, "could not prune config versions");
    }
}

/// Restores a stored version. History recording after the commit is best
/// effort: it must never prevent the caller from pushing the restored config.
pub async fn rollback(
    db: &DatabaseConnection,
    version_id: i64,
    actor: Option<&str>,
) -> Result<RollbackOutcome, DbErr> {
    let version = config_version::Entity::find_by_id(version_id)
        .one(db)
        .await?
        .ok_or_else(|| {
            DbErr::RecordNotFound(format!("version {version_id} not found"))
        })?;
    let scope = match version.site_id {
        Some(site_id) => VersionScope::Site(site_id),
        None if version.scope == VersionScope::Deployment.as_str() => {
            VersionScope::Deployment
        },
        None => VersionScope::Global,
    };

    let txn = db.begin().await?;
    // Serialise rollbacks per scope: a second rollback waits here instead of
    // recording and applying against a state the first one is about to
    // replace. The lock is released when the transaction ends.
    txn.execute(sea_orm::Statement::from_sql_and_values(
        txn.get_database_backend(),
        "SELECT pg_advisory_xact_lock(hashtext($1))",
        [scope.describe().to_string().into()],
    ))
    .await?;

    // Archive the live state before changing it, inside the locked
    // transaction: the archived "before" snapshot and the restore then see
    // the same state. If this fails, the rollback stops here rather than
    // proceeding without a way back.
    let before_hash = config_hash_after(db, scope).await.unwrap_or_default();
    let pre_rollback_version =
        record_version_in(&txn, scope, "pre-rollback", actor, &before_hash)
            .await?;
    let plan = config_restore::prepare_restore(
        &txn,
        scope,
        &version.snapshot,
        RestoreOptions::default(),
    )
    .await?;
    config_restore::apply_restore(&txn, plan).await?;
    txn.commit().await?;

    tracing::info!(
        restored = version.id,
        scope = %scope.describe(),
        actor = actor.unwrap_or("unknown"),
        "configuration rolled back"
    );

    let hash = config_hash_after(db, scope).await.unwrap_or_default();
    let new_version = match record_version(
        db,
        scope,
        config_version::source::ROLLBACK,
        actor,
        &hash,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(error = %error, "rollback succeeded but its history row failed");
            None
        },
    };

    Ok(RollbackOutcome {
        restored_version: version.id,
        scope,
        new_version,
        pre_rollback_version,
    })
}

async fn config_hash_after(
    db: &DatabaseConnection,
    scope: VersionScope,
) -> Option<String> {
    let VersionScope::Site(site_id) = scope else {
        return None;
    };
    let site_row = site::Entity::find_by_id(site_id)
        .one(db)
        .await
        .ok()
        .flatten()?;
    let bundle = crate::grpc::config::build_rule_bundle(db, &site_row)
        .await
        .ok()?;
    Some(bundle.config_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries_count_arrays_and_v1_singletons() {
        let snapshot = json!({
            "schema": 1,
            "site": null,
            "tables": {
                "rules": [{"id": "1"}, {"id": "2"}],
                "defense_settings": {"id": 1},
                "origin_settings": null,
                "rule_groups": [],
            }
        });
        let summary = summarise(&snapshot);
        assert_eq!(summary["rules"], json!(2));
        assert_eq!(summary["defense_settings"], json!(1));
        assert!(summary.get("origin_settings").is_none());
        assert!(summary.get("rule_groups").is_none());
    }

    #[test]
    fn scopes_have_stable_persisted_names() {
        let id = Uuid::new_v4();
        assert_eq!(VersionScope::Site(id).column_value(), Some(id));
        assert_eq!(VersionScope::Global.column_value(), None);
        assert_eq!(VersionScope::Deployment.as_str(), "deployment");
        assert_eq!(crate::config_catalog::SNAPSHOT_SCHEMA, 2);
    }
}
