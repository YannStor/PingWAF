//! Configuration versioning: capture, list and restore WAF config snapshots.
//!
//! Every configuration change that is pushed to the agents goes through
//! [`crate::grpc::notify_config_changed`] or
//! [`crate::grpc::notify_all_config_changed`], which is where a snapshot is
//! recorded. Each `config_versions` row holds the complete policy of one
//! scope at one point in time:
//!
//! - **Site scope** — the `sites` row plus every per-site policy table the
//!   agents receive in a `RuleBundle` (rules, groups, rate limits, caching,
//!   upstreams, routes, TLS, certificates, IP rules, WAF/challenge/bot/geo
//!   settings, basic auth, rewrites, mTLS).
//! - **Global scope** (`site_id IS NULL`) — `defense_settings`,
//!   `origin_settings` and the global `error_pages`.
//!
//! Restoring a snapshot replaces the rows of that scope inside one
//! transaction and bumps `sites.updated_at`, so the agents pick the restored
//! configuration up like any other change. Snapshots are stored as
//! serialized `sea_orm` models (`{ table: [rows] }`), and unknown keys of an
//! older snapshot are filled from the live row, which keeps old versions
//! restorable after a schema migration adds columns.

use std::collections::BTreeMap;

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr,
    EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::models::{
    bot_protection, cache_rules, challenge_settings, config_version,
    defense_settings, error_pages, geo_rules, ip_access_rules, ip_group_sites,
    mtls_ca, mtls_client_certificate, origin_settings, rate_limit_rules,
    rewrite_rules, rule, rule_groups, site, site_ai_bot_policies,
    site_ai_crawl_settings, site_basic_auth, site_certificates, site_routes,
    site_ssl, site_upstream_pools, site_upstreams, waf_settings,
};

/// Schema marker inside the snapshot document; bumped when the layout changes.
pub const SNAPSHOT_SCHEMA: i64 = 1;
/// Versions kept per scope (site or global) before the oldest are pruned.
pub const MAX_VERSIONS_PER_SCOPE: u64 = 50;
/// Versions older than this are pruned regardless of count.
pub const VERSION_RETENTION_DAYS: i64 = 30;
/// Expected snapshot size ceiling (2 MB). Only a warning threshold — large
/// certificate chains are legitimate, but growth past this point signals a
/// pathological payload worth investigating (see `record_version`).
pub const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

/// Site tables whose rows carry private key material. Snapshots store these
/// rows **without** the `key_pem` column — a version snapshot is API-readable
/// and long-retained, and private keys must never enter either. Restoring
/// re-arms the keys from the live rows (see `restore_site_rows`).
pub const PRIVATE_KEY_TABLES: [&str; 3] =
    ["site_ssl", "mtls_cas", "mtls_client_certificates"];

/// Removes the `key_pem` column from every row of the private-key tables in a
/// captured snapshot document.
fn strip_private_keys(tables: &mut BTreeMap<String, Value>) {
    for name in PRIVATE_KEY_TABLES {
        if let Some(rows) = tables.get_mut(name).and_then(Value::as_array_mut) {
            for row in rows.iter_mut() {
                if let Some(object) = row.as_object_mut() {
                    object.remove("key_pem");
                }
            }
        }
    }
}

/// The scope a version covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionScope {
    /// One site's whole policy.
    Site(Uuid),
    /// Deployment-wide settings (`site_id IS NULL`).
    Global,
}

impl VersionScope {
    /// SQL predicate value for `site_id`.
    fn column_value(self) -> Option<Uuid> {
        match self {
            VersionScope::Site(id) => Some(id),
            VersionScope::Global => None,
        }
    }

    /// Human-readable label for logs and CLI output.
    pub fn describe(self) -> String {
        match self {
            VersionScope::Site(id) => format!("site {id}"),
            VersionScope::Global => "the global settings".to_string(),
        }
    }
}

/// What a rollback restored.
#[derive(Debug, Clone)]
pub struct RollbackOutcome {
    /// The version that was restored.
    pub restored_version: i64,
    /// The scope of that version.
    pub scope: VersionScope,
    /// The new version recorded for the rollback itself.
    pub new_version: Option<i64>,
}

// ─────────────────────────────────────────────────────────────
// Capture
// ─────────────────────────────────────────────────────────────

macro_rules! snapshot_table {
    ($db:expr, $map:expr, $module:ident, $order:ident, $name:literal, $site_id:expr) => {{
        let rows = $module::Entity::find()
            .filter($module::Column::SiteId.eq($site_id))
            .order_by_asc($module::Column::$order)
            .all($db)
            .await?;
        let value = serde_json::to_value(&rows)
            .map_err(|err| DbErr::Custom(err.to_string()))?;
        $map.insert($name.to_string(), value);
    }};
}

/// Captures the complete configuration of one site.
pub async fn capture_site_snapshot(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<Value, DbErr> {
    let site_row = site::Entity::find_by_id(site_id)
        .one(db)
        .await?
        .ok_or_else(|| DbErr::RecordNotFound("site not found".to_string()))?;

    let mut tables = BTreeMap::new();
    snapshot_table!(db, tables, rule_groups, Id, "rule_groups", site_id);
    snapshot_table!(db, tables, rule, Id, "rules", site_id);
    snapshot_table!(
        db,
        tables,
        rate_limit_rules,
        Id,
        "rate_limit_rules",
        site_id
    );
    snapshot_table!(db, tables, cache_rules, Id, "cache_rules", site_id);
    snapshot_table!(
        db,
        tables,
        site_upstream_pools,
        Id,
        "site_upstream_pools",
        site_id
    );
    snapshot_table!(db, tables, site_upstreams, Id, "site_upstreams", site_id);
    snapshot_table!(db, tables, site_routes, Id, "site_routes", site_id);
    snapshot_table!(db, tables, site_ssl, Id, "site_ssl", site_id);
    snapshot_table!(
        db,
        tables,
        site_certificates,
        Id,
        "site_certificates",
        site_id
    );
    snapshot_table!(
        db,
        tables,
        ip_access_rules,
        Id,
        "ip_access_rules",
        site_id
    );
    snapshot_table!(
        db,
        tables,
        ip_group_sites,
        IpGroupId,
        "ip_group_sites",
        site_id
    );
    snapshot_table!(db, tables, waf_settings, Id, "waf_settings", site_id);
    snapshot_table!(
        db,
        tables,
        challenge_settings,
        Id,
        "challenge_settings",
        site_id
    );
    snapshot_table!(db, tables, bot_protection, Id, "bot_protection", site_id);
    snapshot_table!(db, tables, geo_rules, Id, "geo_rules", site_id);
    snapshot_table!(
        db,
        tables,
        site_basic_auth,
        Id,
        "site_basic_auth",
        site_id
    );
    snapshot_table!(db, tables, rewrite_rules, Id, "rewrite_rules", site_id);
    snapshot_table!(
        db,
        tables,
        site_ai_crawl_settings,
        Id,
        "site_ai_crawl_settings",
        site_id
    );
    snapshot_table!(
        db,
        tables,
        site_ai_bot_policies,
        Id,
        "site_ai_bot_policies",
        site_id
    );
    snapshot_table!(db, tables, mtls_ca, Id, "mtls_cas", site_id);
    snapshot_table!(
        db,
        tables,
        mtls_client_certificate,
        Id,
        "mtls_client_certificates",
        site_id
    );
    // Private keys never enter a snapshot: the column is dropped here and
    // re-filled from the live rows on restore.
    strip_private_keys(&mut tables);

    let site_value = serde_json::to_value(&site_row)
        .map_err(|err| DbErr::Custom(err.to_string()))?;
    Ok(json!({
        "schema": SNAPSHOT_SCHEMA,
        "site": site_value,
        "tables": tables,
    }))
}

/// Captures the deployment-wide settings.
pub async fn capture_global_snapshot(
    db: &DatabaseConnection,
) -> Result<Value, DbErr> {
    let defense = defense_settings::Entity::find_by_id(1).one(db).await?;
    let origin = origin_settings::Entity::find_by_id(1).one(db).await?;
    let pages = error_pages::Entity::find()
        .order_by_asc(error_pages::Column::StatusCode)
        .all(db)
        .await?;

    let mut tables = BTreeMap::new();
    tables.insert(
        "defense_settings".to_string(),
        serde_json::to_value(&defense)
            .map_err(|err| DbErr::Custom(err.to_string()))?,
    );
    tables.insert(
        "origin_settings".to_string(),
        serde_json::to_value(&origin)
            .map_err(|err| DbErr::Custom(err.to_string()))?,
    );
    tables.insert(
        "error_pages".to_string(),
        serde_json::to_value(&pages)
            .map_err(|err| DbErr::Custom(err.to_string()))?,
    );
    Ok(json!({
        "schema": SNAPSHOT_SCHEMA,
        "site": Value::Null,
        "tables": tables,
    }))
}

/// Per-table row counts of a snapshot document, for cheap listing.
pub fn summarise(snapshot: &Value) -> Value {
    let mut summary = serde_json::Map::new();
    if let Some(tables) = snapshot.get("tables").and_then(Value::as_object) {
        for (name, rows) in tables {
            let count =
                rows.as_array().map(|rows| rows.len()).unwrap_or_default();
            if count > 0 {
                summary.insert(name.clone(), json!(count));
            }
        }
    }
    Value::Object(summary)
}

// ─────────────────────────────────────────────────────────────
// Record
// ─────────────────────────────────────────────────────────────

/// Records a new version for `scope`, unless the latest version of that
/// scope already carries `config_hash` (no-op edits from touch-and-notify
/// sequences). Returns the new version id, or `None` when deduplicated.
pub async fn record_version(
    db: &DatabaseConnection,
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

    let snapshot = match scope {
        VersionScope::Site(site_id) => {
            capture_site_snapshot(db, site_id).await?
        },
        VersionScope::Global => capture_global_snapshot(db).await?,
    };
    // Size guard: TLS certificate chains and full rule sets legitimately
    // make snapshots large (private keys are stripped since the P0 fix —
    // they are refilled from live rows on restore). PostgreSQL TOAST
    // compresses the JSONB column automatically, so no explicit handling is
    // needed; this only surfaces pathological growth before it turns into a
    // slow INSERT on every mutation.
    let snapshot_bytes = serde_json::to_vec(&snapshot)
        .map(|bytes| bytes.len())
        .unwrap_or_default();
    if snapshot_bytes > MAX_SNAPSHOT_BYTES {
        tracing::warn!(
            scope = %scope.describe(),
            bytes = snapshot_bytes,
            threshold = MAX_SNAPSHOT_BYTES,
            "configuration snapshot exceeds the expected size; \
             investigate the site's rule or certificate payload"
        );
    }
    let summary = summarise(&snapshot);

    let row = config_version::ActiveModel {
        id: Default::default(),
        site_id: Set(scope.column_value()),
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

/// The newest version of a scope, if any.
pub async fn latest_version(
    db: &DatabaseConnection,
    scope: VersionScope,
) -> Result<Option<config_version::Model>, DbErr> {
    let mut query = config_version::Entity::find()
        .order_by_desc(config_version::Column::Id)
        .limit(1);
    query = match scope {
        VersionScope::Site(site_id) => {
            query.filter(config_version::Column::SiteId.eq(site_id))
        },
        VersionScope::Global => {
            query.filter(config_version::Column::SiteId.is_null())
        },
    };
    query.one(db).await
}

/// Keeps the newest [`MAX_VERSIONS_PER_SCOPE`] versions of a scope within the
/// retention window and drops the rest. Best-effort: failures are logged.
/// Drops versions beyond the retention window and the per-scope cap.
///
/// PostgreSQL-only by design: `IS NOT DISTINCT FROM` matches the NULL
/// `site_id` of global-scope rows (a plain `= $1` would silently prune
/// nothing for the global scope), and the `NOT IN (… ORDER BY … LIMIT …)`
/// subquery is the cheapest way to express "keep the newest N" in one
/// statement. If a second database backend is ever supported, rewrite both
/// constructs for it before touching anything else here.
async fn prune_scope(db: &DatabaseConnection, scope: VersionScope) {
    let cutoff = Utc::now() - chrono::Duration::days(VERSION_RETENTION_DAYS);
    let sql = "\
        DELETE FROM config_versions \
        WHERE site_id IS NOT DISTINCT FROM $1 \
          AND (created_at < $2 \
               OR id NOT IN (\
                   SELECT id FROM config_versions \
                   WHERE site_id IS NOT DISTINCT FROM $1 \
                   ORDER BY id DESC LIMIT $3))";
    let stmt = sea_orm::Statement::from_sql_and_values(
        db.get_database_backend(),
        sql,
        [
            scope.column_value().into(),
            cutoff.into(),
            MAX_VERSIONS_PER_SCOPE.into(),
        ],
    );
    if let Err(err) = db.execute(stmt).await {
        tracing::warn!(error = %err, "could not prune config versions");
    }
}

// ─────────────────────────────────────────────────────────────
// Restore
// ─────────────────────────────────────────────────────────────

macro_rules! delete_site_table {
    ($txn:expr, $module:ident, $site_id:expr) => {{
        $module::Entity::delete_many()
            .filter($module::Column::SiteId.eq($site_id))
            .exec($txn)
            .await?;
    }};
}

/// Reads one site-scoped table's live rows into the decode underlay, keyed by
/// the JSON `id` field (tables without an `id` column get an empty underlay,
/// so their rows decode exactly as stored).
macro_rules! collect_live_rows {
    ($txn:expr, $map:expr, $module:ident, $name:literal, $site_id:expr) => {{
        let rows = $module::Entity::find()
            .filter($module::Column::SiteId.eq($site_id))
            .all($txn)
            .await?;
        let mut by_id = std::collections::HashMap::new();
        for row in rows {
            let value = serde_json::to_value(&row)
                .map_err(|err| DbErr::Custom(err.to_string()))?;
            by_id.insert(value.get("id").cloned(), value);
        }
        $map.insert($name, by_id);
    }};
}

macro_rules! restore_site_table {
    ($txn:expr, $tables:expr, $live:expr, $module:ident, $name:literal) => {{
        if let Some(rows) = $tables.get($name).and_then(Value::as_array) {
            for row in rows {
                // The live row (when the row still exists) is the decode
                // underlay: fields the snapshot predates — and private keys
                // stripped at capture time — are filled from it, so old
                // snapshots stay restorable across schema growth.
                let underlay = row.get("id").cloned().and_then(|id| {
                    $live.get($name).and_then(|by_id| by_id.get(&Some(id)))
                });
                let merged = match underlay {
                    Some(base) => {
                        let mut merged = base.clone();
                        merge_objects(&mut merged, row);
                        merged
                    },
                    None => row.clone(),
                };
                let model: $module::Model = serde_json::from_value(merged)
                    .map_err(|err| {
                        DbErr::Custom(format!(
                            "cannot decode {} row: {err}",
                            $name
                        ))
                    })?;
                <$module::ActiveModel>::from(model).insert($txn).await?;
            }
        }
    }};
}

/// Restores a site snapshot inside one transaction: children first on the
/// way down, parents first on the way back up, to respect the foreign keys.
async fn restore_site_rows(
    txn: &sea_orm::DatabaseTransaction,
    site_id: Uuid,
    snapshot: &Value,
) -> Result<(), DbErr> {
    let tables = snapshot
        .get("tables")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| DbErr::Custom("snapshot has no tables".to_string()))?;

    // The live rows are read before the deletes below and become the decode
    // underlay for every restored row.
    let mut live: std::collections::HashMap<
        &'static str,
        std::collections::HashMap<Option<Value>, Value>,
    > = std::collections::HashMap::new();
    collect_live_rows!(txn, live, rule_groups, "rule_groups", site_id);
    collect_live_rows!(txn, live, rule, "rules", site_id);
    collect_live_rows!(
        txn,
        live,
        rate_limit_rules,
        "rate_limit_rules",
        site_id
    );
    collect_live_rows!(txn, live, cache_rules, "cache_rules", site_id);
    collect_live_rows!(txn, live, site_routes, "site_routes", site_id);
    collect_live_rows!(txn, live, site_upstreams, "site_upstreams", site_id);
    collect_live_rows!(
        txn,
        live,
        site_upstream_pools,
        "site_upstream_pools",
        site_id
    );
    collect_live_rows!(txn, live, site_ssl, "site_ssl", site_id);
    collect_live_rows!(
        txn,
        live,
        site_certificates,
        "site_certificates",
        site_id
    );
    collect_live_rows!(txn, live, ip_access_rules, "ip_access_rules", site_id);
    collect_live_rows!(txn, live, ip_group_sites, "ip_group_sites", site_id);
    collect_live_rows!(txn, live, waf_settings, "waf_settings", site_id);
    collect_live_rows!(
        txn,
        live,
        challenge_settings,
        "challenge_settings",
        site_id
    );
    collect_live_rows!(txn, live, bot_protection, "bot_protection", site_id);
    collect_live_rows!(txn, live, geo_rules, "geo_rules", site_id);
    collect_live_rows!(txn, live, site_basic_auth, "site_basic_auth", site_id);
    collect_live_rows!(txn, live, rewrite_rules, "rewrite_rules", site_id);
    collect_live_rows!(
        txn,
        live,
        site_ai_crawl_settings,
        "site_ai_crawl_settings",
        site_id
    );
    collect_live_rows!(
        txn,
        live,
        site_ai_bot_policies,
        "site_ai_bot_policies",
        site_id
    );
    collect_live_rows!(txn, live, mtls_ca, "mtls_cas", site_id);
    collect_live_rows!(
        txn,
        live,
        mtls_client_certificate,
        "mtls_client_certificates",
        site_id
    );

    // Down (children first).
    delete_site_table!(txn, rule, site_id);
    delete_site_table!(txn, rule_groups, site_id);
    delete_site_table!(txn, rate_limit_rules, site_id);
    delete_site_table!(txn, cache_rules, site_id);
    delete_site_table!(txn, site_routes, site_id);
    delete_site_table!(txn, site_upstreams, site_id);
    delete_site_table!(txn, site_upstream_pools, site_id);
    delete_site_table!(txn, site_ssl, site_id);
    delete_site_table!(txn, site_certificates, site_id);
    delete_site_table!(txn, ip_access_rules, site_id);
    delete_site_table!(txn, ip_group_sites, site_id);
    delete_site_table!(txn, waf_settings, site_id);
    delete_site_table!(txn, challenge_settings, site_id);
    delete_site_table!(txn, bot_protection, site_id);
    delete_site_table!(txn, geo_rules, site_id);
    delete_site_table!(txn, site_basic_auth, site_id);
    delete_site_table!(txn, rewrite_rules, site_id);
    delete_site_table!(txn, site_ai_bot_policies, site_id);
    delete_site_table!(txn, site_ai_crawl_settings, site_id);
    delete_site_table!(txn, mtls_client_certificate, site_id);
    delete_site_table!(txn, mtls_ca, site_id);

    // Up (parents first).
    restore_site_table!(txn, tables, live, rule_groups, "rule_groups");
    restore_site_table!(txn, tables, live, rule, "rules");
    restore_site_table!(
        txn,
        tables,
        live,
        rate_limit_rules,
        "rate_limit_rules"
    );
    restore_site_table!(txn, tables, live, cache_rules, "cache_rules");
    restore_site_table!(
        txn,
        tables,
        live,
        site_upstream_pools,
        "site_upstream_pools"
    );
    restore_site_table!(txn, tables, live, site_upstreams, "site_upstreams");
    restore_site_table!(txn, tables, live, site_routes, "site_routes");
    restore_site_table!(txn, tables, live, site_ssl, "site_ssl");
    restore_site_table!(
        txn,
        tables,
        live,
        site_certificates,
        "site_certificates"
    );
    restore_site_table!(txn, tables, live, ip_access_rules, "ip_access_rules");
    restore_site_table!(txn, tables, live, ip_group_sites, "ip_group_sites");
    restore_site_table!(txn, tables, live, waf_settings, "waf_settings");
    restore_site_table!(
        txn,
        tables,
        live,
        challenge_settings,
        "challenge_settings"
    );
    restore_site_table!(txn, tables, live, bot_protection, "bot_protection");
    restore_site_table!(txn, tables, live, geo_rules, "geo_rules");
    restore_site_table!(txn, tables, live, site_basic_auth, "site_basic_auth");
    restore_site_table!(txn, tables, live, rewrite_rules, "rewrite_rules");
    restore_site_table!(
        txn,
        tables,
        live,
        site_ai_crawl_settings,
        "site_ai_crawl_settings"
    );
    restore_site_table!(
        txn,
        tables,
        live,
        site_ai_bot_policies,
        "site_ai_bot_policies"
    );
    restore_site_table!(txn, tables, live, mtls_ca, "mtls_cas");
    restore_site_table!(
        txn,
        tables,
        live,
        mtls_client_certificate,
        "mtls_client_certificates"
    );

    // The site row itself: overlay the snapshot onto the live row so columns
    // added after the snapshot keep their current values.
    if let Some(saved) = snapshot.get("site").filter(|site| site.is_object()) {
        let live = site::Entity::find_by_id(site_id)
            .one(txn)
            .await?
            .ok_or_else(|| {
                DbErr::RecordNotFound("site vanished during rollback".into())
            })?;
        let mut merged = serde_json::to_value(&live)
            .map_err(|err| DbErr::Custom(err.to_string()))?;
        merge_objects(&mut merged, saved);
        let mut model: site::Model =
            serde_json::from_value(merged).map_err(|err| {
                DbErr::Custom(format!("cannot decode the site snapshot: {err}"))
            })?;
        model.updated_at = Utc::now();
        site::ActiveModel::from(model).update(txn).await?;
    }
    Ok(())
}

/// Recursively overlays `snapshot` onto `base` (objects only; arrays and
/// scalars replace).
fn merge_objects(base: &mut Value, snapshot: &Value) {
    let (Some(base_obj), Some(snapshot_obj)) =
        (base.as_object_mut(), snapshot.as_object())
    else {
        return;
    };
    for (key, value) in snapshot_obj {
        match (base_obj.get_mut(key), value) {
            (Some(child), Value::Object(_))
                if child.is_object() && value.is_object() =>
            {
                merge_objects(child, value);
            },
            _ => {
                base_obj.insert(key.clone(), value.clone());
            },
        }
    }
}

/// Restores the deployment-wide settings inside one transaction.
async fn restore_global_rows(
    txn: &sea_orm::DatabaseTransaction,
    snapshot: &Value,
) -> Result<(), DbErr> {
    let tables = snapshot
        .get("tables")
        .and_then(Value::as_object)
        .ok_or_else(|| DbErr::Custom("snapshot has no tables".to_string()))?;

    if let Some(rows) = tables.get("defense_settings").and_then(Value::as_array)
    {
        if let Some(row) = rows.first() {
            let model: defense_settings::Model =
                serde_json::from_value(row.clone()).map_err(|err| {
                    DbErr::Custom(format!(
                        "cannot decode the defense settings snapshot: {err}"
                    ))
                })?;
            let mut active = defense_settings::ActiveModel::from(model);
            // The settings always live in row 1, whatever the snapshot says.
            active.id = Set(1);
            active.updated_at = Set(Utc::now());
            if defense_settings::Entity::find_by_id(1)
                .one(txn)
                .await?
                .is_some()
            {
                active.update(txn).await?;
            } else {
                active.insert(txn).await?;
            }
        }
    }

    // A snapshot taken before the origin TLS switch existed simply has no
    // entry here; the live row is then left alone rather than reset.
    if let Some(rows) = tables.get("origin_settings").and_then(Value::as_array)
    {
        if let Some(row) = rows.first() {
            let model: origin_settings::Model =
                serde_json::from_value(row.clone()).map_err(|err| {
                    DbErr::Custom(format!(
                        "cannot decode the origin settings snapshot: {err}"
                    ))
                })?;
            let mut active = origin_settings::ActiveModel::from(model);
            // The settings always live in row 1, whatever the snapshot says.
            active.id = Set(1);
            active.updated_at = Set(Utc::now());
            if origin_settings::Entity::find_by_id(1)
                .one(txn)
                .await?
                .is_some()
            {
                active.update(txn).await?;
            } else {
                active.insert(txn).await?;
            }
        }
    }

    if let Some(rows) = tables.get("error_pages").and_then(Value::as_array) {
        error_pages::Entity::delete_many().exec(txn).await?;
        for row in rows {
            let model: error_pages::Model = serde_json::from_value(row.clone())
                .map_err(|err| {
                    DbErr::Custom(format!(
                        "cannot decode an error page snapshot: {err}"
                    ))
                })?;
            error_pages::ActiveModel::from(model).insert(txn).await?;
        }
    }
    Ok(())
}

/// Restores `version_id` and records the rollback as a new version. The
/// caller is responsible for pushing the change to the agents
/// ([`crate::grpc::notify_config_changed`] from the API; the CLI prints a
/// hint instead).
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
        None => VersionScope::Global,
    };

    let txn = db.begin().await?;
    match scope {
        VersionScope::Site(site_id) => {
            restore_site_rows(&txn, site_id, &version.snapshot).await?;
        },
        VersionScope::Global => {
            restore_global_rows(&txn, &version.snapshot).await?;
        },
    }
    txn.commit().await?;

    tracing::info!(
        restored = version.id,
        scope = %scope.describe(),
        actor = actor.unwrap_or("unknown"),
        "configuration rolled back"
    );

    // The restored configuration becomes a new version, so the history shows
    // the rollback as a first-class change and the dedup window does not
    // hide it.
    let hash = config_hash_after(db, scope).await.unwrap_or_default();
    let new_version = record_version(
        db,
        scope,
        config_version::source::ROLLBACK,
        actor,
        &hash,
    )
    .await?;

    Ok(RollbackOutcome {
        restored_version: version.id,
        scope,
        new_version,
    })
}

/// Fingerprint of a scope's configuration after a restore, matching what the
/// agents compare. Empty string when it cannot be computed (e.g. global
/// scope, which has no per-site bundle).
async fn config_hash_after(
    db: &DatabaseConnection,
    scope: VersionScope,
) -> Option<String> {
    match scope {
        VersionScope::Global => None,
        VersionScope::Site(site_id) => {
            let site_row = site::Entity::find_by_id(site_id)
                .one(db)
                .await
                .ok()
                .flatten()?;
            let bundle = crate::grpc::config::build_rule_bundle(db, &site_row)
                .await
                .ok()?;
            Some(bundle.config_hash)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_overlays_snapshot_fields_and_keeps_newer_ones() {
        let mut base = json!({
            "id": "abc",
            "name": "live-name",
            "cache_quota_mb": 10,
            "added_later": "keep-me",
            "nested": { "a": 1, "b": 2 },
        });
        let snapshot = json!({
            "name": "snapshot-name",
            "cache_quota_mb": 42,
            "nested": { "a": 99 },
        });
        merge_objects(&mut base, &snapshot);
        assert_eq!(base["name"], json!("snapshot-name"));
        assert_eq!(base["cache_quota_mb"], json!(42));
        // Column the snapshot predates: the live value survives.
        assert_eq!(base["added_later"], json!("keep-me"));
        // Nested objects merge field by field.
        assert_eq!(base["nested"]["a"], json!(99));
        assert_eq!(base["nested"]["b"], json!(2));
        assert_eq!(base["id"], json!("abc"));
    }

    #[test]
    fn merge_replaces_arrays_and_scalars() {
        let mut base = json!({ "domains": ["a"], "n": 1 });
        merge_objects(&mut base, &json!({ "domains": ["b", "c"], "n": 2 }));
        assert_eq!(base["domains"], json!(["b", "c"]));
        assert_eq!(base["n"], json!(2));
    }

    #[test]
    fn summaries_count_rows_per_table() {
        let snapshot = json!({
            "schema": 1,
            "site": null,
            "tables": {
                "rules": [ { "id": "1" }, { "id": "2" } ],
                "rule_groups": [],
            },
        });
        let summary = summarise(&snapshot);
        assert_eq!(summary["rules"], json!(2));
        // Empty tables are omitted to keep the summary readable.
        assert!(summary.get("rule_groups").is_none());
    }

    #[test]
    fn scopes_map_to_their_column_value() {
        let id = Uuid::new_v4();
        assert_eq!(VersionScope::Site(id).column_value(), Some(id));
        assert_eq!(VersionScope::Global.column_value(), None);
    }

    #[test]
    fn strip_private_keys_removes_pem_from_all_private_tables() {
        let mut tables = BTreeMap::from([
            (
                "site_ssl".to_string(),
                json!([ { "id": "1", "key_pem": "PRIVATE", "cert_pem": "CERT" } ]),
            ),
            (
                "mtls_cas".to_string(),
                json!([ { "id": "2", "key_pem": "CA-KEY" } ]),
            ),
            (
                "mtls_client_certificates".to_string(),
                json!([
                    { "id": "3", "key_pem": "K1" },
                    { "id": "4", "key_pem": "K2" },
                ]),
            ),
            // Non-private tables are untouched, including same-named fields.
            (
                "site_routes".to_string(),
                json!([ { "id": "5", "key_pem": "NOT-A-KEY" } ]),
            ),
        ]);
        strip_private_keys(&mut tables);
        assert!(tables["site_ssl"][0].get("key_pem").is_none());
        assert_eq!(tables["site_ssl"][0]["cert_pem"], json!("CERT"));
        assert!(tables["mtls_cas"][0].get("key_pem").is_none());
        assert!(tables["mtls_client_certificates"][0]
            .get("key_pem")
            .is_none());
        assert!(tables["mtls_client_certificates"][1]
            .get("key_pem")
            .is_none());
        // Only the three private tables are stripped.
        assert_eq!(tables["site_routes"][0]["key_pem"], json!("NOT-A-KEY"));
    }

    #[test]
    fn strip_private_keys_handles_missing_or_non_array_tables() {
        let mut tables = BTreeMap::from([
            ("mtls_cas".to_string(), json!(null)),
            ("site_ssl".to_string(), json!("not-an-array")),
        ]);
        // Must not panic on absent or malformed shapes.
        strip_private_keys(&mut tables);
        assert_eq!(tables["mtls_cas"], json!(null));
        assert_eq!(tables["site_ssl"], json!("not-an-array"));
    }

    #[test]
    fn underlay_lookup_falls_back_when_row_is_absent() {
        // Mirrors the underlay resolution inside restore_site_table!: a row
        // deleted since the snapshot has no live underlay and must decode
        // exactly as stored.
        let mut by_id = std::collections::HashMap::new();
        by_id.insert(
            Some(json!("kept")),
            json!({ "id": "kept", "key_pem": "LIVE" }),
        );
        let live: BTreeMap<&str, std::collections::HashMap<_, _>> =
            BTreeMap::from([("site_ssl", by_id)]);

        let deleted_row = json!({ "id": "deleted", "name": "gone" });
        let underlay = deleted_row.get("id").cloned().and_then(|id| {
            live.get("site_ssl").and_then(|by_id| by_id.get(&Some(id)))
        });
        assert!(underlay.is_none());

        let kept_row = json!({ "id": "kept", "name": "renamed" });
        let underlay = kept_row.get("id").cloned().and_then(|id| {
            live.get("site_ssl").and_then(|by_id| by_id.get(&Some(id)))
        });
        assert!(underlay.is_some());
        let mut merged = underlay.unwrap().clone();
        merge_objects(&mut merged, &kept_row);
        // Stripped key comes back from the live row; snapshot fields win.
        assert_eq!(merged["key_pem"], json!("LIVE"));
        assert_eq!(merged["name"], json!("renamed"));
    }
}
