//! Restore planning and transactional application for configuration snapshots.
//!
//! Preparation performs every read and validation before a single row is
//! deleted. Application then uses `jsonb_populate_recordset`, so every restored
//! column is actually written and new database columns follow the same path.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbErr, Statement, Value as DbValue,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::config_catalog::{
    merge_shallow, normalise_tables, query_rows, rows_for, spec_for,
    tables_for, Filter, TableSpec, VersionScope, INSTANCE_SETTING_KEYS,
};

#[derive(Debug, Clone)]
pub struct RestoreOptions {
    /// Used only when a restored site refers to an owner that no longer exists.
    pub default_owner_id: Option<Uuid>,
    /// Full deployment restore may remove sites absent from the snapshot.
    /// Ordinary site/global rollback never enables this.
    pub prune_sites: bool,
    /// Ordinary same-instance rollback keeps the current owner. A full backup
    /// restore clears this so the snapshot's ownership is restored when the
    /// original user still exists.
    pub preserve_site_owners: bool,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            default_owner_id: None,
            prune_sites: false,
            preserve_site_owners: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TableChange {
    pub before: usize,
    pub after: usize,
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
}

#[derive(Debug)]
pub struct PreparedTable {
    pub spec: &'static TableSpec,
    pub rows: Vec<Value>,
    pub change: TableChange,
}

#[derive(Debug)]
pub struct RestorePlan {
    pub scope: VersionScope,
    pub tables: Vec<PreparedTable>,
    pub prune_site_ids: Vec<Uuid>,
    pub owner_changes: Vec<Value>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default)]
pub struct RestoreReport {
    pub rows_by_table: BTreeMap<String, usize>,
    pub warnings: Vec<String>,
}

fn quote_ident(identifier: &str) -> String {
    format!("\"{identifier}\"")
}

fn statement<C: ConnectionTrait>(
    db: &C,
    sql: impl Into<String>,
    values: Vec<DbValue>,
) -> Statement {
    Statement::from_sql_and_values(
        db.get_database_backend(),
        sql.into(),
        values,
    )
}

#[derive(Debug, Clone)]
struct ColumnInfo {
    nullable: bool,
    default: Option<Value>,
}

async fn columns_for<C: ConnectionTrait>(
    db: &C,
    table: &str,
) -> Result<BTreeMap<String, ColumnInfo>, DbErr> {
    let rows = db
        .query_all(statement(
            db,
            "SELECT column_name, is_nullable, column_default \
             FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = $1 \
             ORDER BY ordinal_position",
            vec![table.into()],
        ))
        .await?;
    if rows.is_empty() {
        return Err(DbErr::Custom(format!(
            "configuration table {table} does not exist"
        )));
    }
    let mut columns = BTreeMap::new();
    for row in rows {
        let name = row.try_get::<String>("", "column_name")?;
        let nullable = row.try_get::<String>("", "is_nullable")? == "YES";
        let expression = row.try_get::<Option<String>>("", "column_default")?;
        let default = match expression {
            Some(expression) if !expression.starts_with("NULL::") => {
                // The expression comes from PostgreSQL's own catalog, not from
                // the uploaded document, and is evaluated to a JSON value of
                // the correct type (bool, number, string, jsonb or timestamp).
                let value = db
                    .query_one(statement(
                        db,
                        format!("SELECT to_jsonb({expression}) AS value"),
                        Vec::new(),
                    ))
                    .await?
                    .ok_or_else(|| {
                        DbErr::Custom(
                            "default expression returned no row".into(),
                        )
                    })?
                    .try_get::<Value>("", "value")?;
                Some(value)
            },
            _ => None,
        };
        columns.insert(name, ColumnInfo { nullable, default });
    }
    Ok(columns)
}

fn json_key(row: &Value, key: &str) -> Option<String> {
    row.get(key).map(|value| match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    })
}

fn required_secret(table: &str, field: &str, row: &Value) -> bool {
    match (table, field) {
        ("site_basic_auth", "credentials")
        | ("site_oidc", "cookie_secret")
        | ("site_visitors", "password_hash")
        | ("notification_channels", "config")
        | ("oidc_providers", "client_secret")
        | ("site_certificates", "key_pem")
        | ("control_plane_certificates", "key_pem") => true,
        ("site_ssl", "key_pem") => row.get("cert_pem").is_some(),
        _ => false,
    }
}

fn is_certificate_table(table: &str) -> bool {
    matches!(
        table,
        "site_ssl"
            | "site_certificates"
            | "mtls_cas"
            | "mtls_client_certificates"
            | "control_plane_certificates"
    )
}

async fn user_exists<C: ConnectionTrait>(
    db: &C,
    id: Uuid,
) -> Result<bool, DbErr> {
    Ok(db
        .query_one(statement(
            db,
            "SELECT 1 AS present FROM users WHERE id = $1",
            vec![id.into()],
        ))
        .await?
        .is_some())
}

fn uuid_field(row: &Value, field: &str) -> Option<Uuid> {
    row.get(field)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
}

async fn merge_row<C: ConnectionTrait>(
    db: &C,
    spec: &TableSpec,
    schema: i64,
    mut row: Value,
    live: &HashMap<String, Value>,
    options: &RestoreOptions,
    columns: &BTreeMap<String, ColumnInfo>,
) -> Result<Value, DbErr> {
    let base = spec
        .key
        .and_then(|key| json_key(&row, key))
        .and_then(|key| live.get(&key));

    for field in spec.secrets {
        let explicitly_null = row.get(*field).is_some_and(Value::is_null);
        // `key_pem` is nullable on certificate tables: an explicit null can
        // mean "this certificate has no private key", which is a valid state
        // to restore. Non-nullable key columns are still rejected by the
        // column validation below.
        if explicitly_null && *field == "key_pem" {
            continue;
        }
        if explicitly_null && required_secret(spec.name, field, &row) {
            return Err(DbErr::Custom(format!(
                "{}.{field} cannot be restored as an explicit null secret",
                spec.name
            )));
        }
        let missing = row.get(*field).is_none_or(Value::is_null);
        if !missing {
            continue;
        }
        if base.is_none() && required_secret(spec.name, field, &row) {
            return Err(DbErr::Custom(format!(
                "{}.{} cannot be restored without its secret; use an encrypted backup",
                spec.name, field
            )));
        }
        if is_certificate_table(spec.name) {
            let snapshot_cert = row.get("cert_pem").and_then(Value::as_str);
            let live_cert = base
                .and_then(|value| value.get("cert_pem"))
                .and_then(Value::as_str);
            if snapshot_cert.is_some() && snapshot_cert != live_cert {
                return Err(DbErr::Custom(format!(
                    "{} cannot reuse a live private key for a different certificate",
                    spec.name
                )));
            }
        }
    }

    if schema == 1 {
        if spec.name == "site_upstreams" && row.get("name").is_none() {
            row["name"] = json!("");
        }
        if spec.name == "cache_rules" && row.get("disk_quota_mb").is_none() {
            row["disk_quota_mb"] = json!(0);
        }
    }

    let mut merged = base.cloned().unwrap_or_else(|| json!({}));
    merge_shallow(&mut merged, &row);
    for (field, info) in columns {
        if merged.get(field).is_none() && schema == 1 {
            if let Some(default) = &info.default {
                merged[field] = default.clone();
            }
        }
        if merged.get(field).is_none_or(Value::is_null) && !info.nullable {
            return Err(DbErr::Custom(format!(
                "{}.{field} is required and has no safe restored value",
                spec.name
            )));
        }
    }

    match spec.name {
        "sites" => {
            let id = uuid_field(&merged, "id").ok_or_else(|| {
                DbErr::Custom("a restored site has no valid id".into())
            })?;
            if let Some(base) = base.filter(|_| options.preserve_site_owners) {
                merged["user_id"] = base["user_id"].clone();
            } else {
                let original = uuid_field(&merged, "user_id");
                let owner = match original {
                    Some(id) if user_exists(db, id).await? => Some(id),
                    _ => options.default_owner_id,
                };
                let Some(owner) = owner else {
                    return Err(DbErr::Custom(format!(
                        "site {id} needs an explicit owner mapping"
                    )));
                };
                if !user_exists(db, owner).await? {
                    return Err(DbErr::Custom(
                        "the selected default site owner does not exist".into(),
                    ));
                }
                merged["user_id"] = json!(owner);
            }
        },
        "control_plane_certificates" => {
            if let Some(base) = base {
                merged["created_by"] = base["created_by"].clone();
            } else if let Some(created_by) = uuid_field(&merged, "created_by") {
                if !user_exists(db, created_by).await? {
                    merged["created_by"] = Value::Null;
                }
            }
        },
        "site_visitors" => {
            if let Some(previous) = base
                .and_then(|value| value.get("token_version"))
                .and_then(Value::as_i64)
            {
                let restored = merged
                    .get("token_version")
                    .and_then(Value::as_i64)
                    .unwrap_or_default();
                merged["token_version"] = json!(previous.max(restored));
            }
        },
        "visitor_passkeys" => {
            if let Some(previous) = base
                .and_then(|value| value.get("counter"))
                .and_then(Value::as_i64)
            {
                let restored = merged
                    .get("counter")
                    .and_then(Value::as_i64)
                    .unwrap_or_default();
                merged["counter"] = json!(previous.max(restored));
            }
        },
        "site_upstreams" => {
            if let Some(base) = base {
                merged["health_status"] = base["health_status"].clone();
            } else {
                merged["health_status"] = json!("unknown");
            }
        },
        "ip_groups" => {
            if let Some(base) = base {
                for field in ["last_synced_at", "last_sync_error"] {
                    if base.get(field).is_some() {
                        merged[field] = base[field].clone();
                    }
                }
            }
        },
        _ => {},
    }
    Ok(merged)
}

fn prepared_ids(
    tables: &[PreparedTable],
    table: &str,
    field: &str,
) -> BTreeSet<String> {
    tables
        .iter()
        .find(|prepared| prepared.spec.name == table)
        .map(|prepared| {
            prepared
                .rows
                .iter()
                .filter_map(|row| row.get(field).map(Value::to_string))
                .collect()
        })
        .unwrap_or_default()
}

async fn reference_exists<C: ConnectionTrait>(
    db: &C,
    tables: &[PreparedTable],
    table: &str,
    id: &Value,
) -> Result<bool, DbErr> {
    let wanted = match id {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    if prepared_ids(tables, table, "id").contains(&wanted) {
        return Ok(true);
    }
    if tables.iter().any(|prepared| prepared.spec.name == table) {
        // The parent table is itself being replaced, so a row that exists only
        // in the live database cannot validate a reference into the new state.
        return Ok(false);
    }
    let Some(id) = id.as_str().and_then(|raw| Uuid::parse_str(raw).ok()) else {
        return Ok(false);
    };
    let spec = spec_for(table).ok_or_else(|| {
        DbErr::Custom(format!("unknown referenced table {table}"))
    })?;
    Ok(db
        .query_one(statement(
            db,
            format!(
                "SELECT 1 AS present FROM {} WHERE id = $1",
                quote_ident(spec.name)
            ),
            vec![id.into()],
        ))
        .await?
        .is_some())
}

async fn validate_references<C: ConnectionTrait>(
    db: &C,
    tables: &[PreparedTable],
) -> Result<(), DbErr> {
    for prepared in tables {
        for row in &prepared.rows {
            let mut refs = Vec::new();
            match prepared.spec.name {
                "site_oidc" => refs.push(("provider_id", "oidc_providers")),
                "visitor_site_grants" => {
                    refs.push(("visitor_id", "site_visitors"));
                    refs.push(("site_id", "sites"));
                },
                "visitor_passkeys" => {
                    refs.push(("visitor_id", "site_visitors"))
                },
                "ip_group_sites" => refs.push(("ip_group_id", "ip_groups")),
                "site_ssl" => {
                    refs.push(("certificate_id", "site_certificates"))
                },
                "rules" => refs.push(("group_id", "rule_groups")),
                "site_upstreams" => {
                    refs.push(("pool_id", "site_upstream_pools"))
                },
                "site_routes" => {
                    refs.push(("pool_id", "site_upstream_pools"));
                    refs.push(("ip_group_id", "ip_groups"));
                },
                "mtls_client_certificates" => refs.push(("ca_id", "mtls_cas")),
                "ip_access_rules" => refs.push(("group_id", "ip_groups")),
                "api_protection_settings" => {
                    refs.push(("ip_allowlist_group_id", "ip_groups"));
                },
                "bot_protection" => {
                    refs.push(("verified_ip_group_id", "ip_groups"))
                },
                _ => {},
            }
            for (field, table) in refs {
                let Some(id) = row.get(field).filter(|value| !value.is_null())
                else {
                    continue;
                };
                if !reference_exists(db, tables, table, id).await? {
                    return Err(DbErr::Custom(format!(
                        "{}.{field} refers to a missing {table} row",
                        prepared.spec.name
                    )));
                }
            }
            if prepared.spec.name == "sites" {
                if let Some(groups) =
                    row.get("trusted_proxy_group_ids").and_then(Value::as_array)
                {
                    for id in groups {
                        if !reference_exists(db, tables, "ip_groups", id)
                            .await?
                        {
                            return Err(DbErr::Custom(
                                "sites.trusted_proxy_group_ids refers to a missing IP group"
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn compute_change(
    spec: &TableSpec,
    live: &[Value],
    restored: &[Value],
) -> TableChange {
    let key = |row: &Value| {
        spec.key
            .and_then(|key| json_key(row, key))
            .unwrap_or_else(|| row.to_string())
    };
    let live_by_key: HashMap<String, &Value> =
        live.iter().map(|row| (key(row), row)).collect();
    let restored_by_key: HashMap<String, &Value> =
        restored.iter().map(|row| (key(row), row)).collect();
    let added = restored_by_key
        .keys()
        .filter(|key| !live_by_key.contains_key(*key))
        .count();
    let removed = live_by_key
        .keys()
        .filter(|key| !restored_by_key.contains_key(*key))
        .count();
    let changed = restored_by_key
        .keys()
        .filter(|key| {
            match (live_by_key.get(*key), restored_by_key.get(*key)) {
                (Some(live), Some(restored)) => live != restored,
                _ => false,
            }
        })
        .count();
    TableChange {
        before: live.len(),
        after: restored.len(),
        added,
        removed,
        changed,
    }
}

pub async fn prepare_restore<C: ConnectionTrait>(
    db: &C,
    scope: VersionScope,
    snapshot: &Value,
    options: RestoreOptions,
) -> Result<RestorePlan, DbErr> {
    let (schema, tables) = normalise_tables(snapshot, scope)?;
    if scope == VersionScope::Deployment && schema >= 2 {
        let missing: Vec<_> = tables_for(scope)
            .into_iter()
            .filter(|spec| !tables.contains_key(spec.name))
            .map(|spec| spec.name)
            .collect();
        if !missing.is_empty() {
            return Err(DbErr::Custom(format!(
                "deployment snapshot is incomplete; missing tables: {}",
                missing.join(", ")
            )));
        }
    }
    let site_id = scope.column_value();
    let snapshot_site_ids = rows_for(schema, &tables, "sites")?
        .unwrap_or_default()
        .iter()
        .filter_map(|row| json_key(row, "id"))
        .collect::<BTreeSet<_>>();
    let sites_spec = spec_for("sites")
        .ok_or_else(|| DbErr::Custom("sites is not catalogued".into()))?;
    let live_sites = if scope == VersionScope::Deployment {
        query_rows(db, sites_spec, None).await?
    } else {
        Vec::new()
    };
    let retained_site_ids: BTreeSet<Uuid> = if options.prune_sites {
        BTreeSet::new()
    } else {
        live_sites
            .iter()
            .filter_map(|row| uuid_field(row, "id"))
            .filter(|id| !snapshot_site_ids.contains(&id.to_string()))
            .collect()
    };
    let mut prepared = Vec::new();
    let mut owner_changes = Vec::new();
    let mut columns = HashMap::new();

    for spec in tables_for(scope) {
        let Some(rows) = rows_for(schema, &tables, spec.name)? else {
            continue;
        };
        let valid_columns = match columns.get(spec.name) {
            Some(columns) => columns,
            None => {
                let loaded = columns_for(db, spec.name).await?;
                columns.insert(spec.name, loaded);
                columns.get(spec.name).ok_or_else(|| {
                    DbErr::Custom("column cache was not populated".into())
                })?
            },
        };
        for row in &rows {
            let object = row.as_object().ok_or_else(|| {
                DbErr::Custom(format!(
                    "{} contains a non-object row",
                    spec.name
                ))
            })?;
            if let Some(unknown) = object
                .keys()
                .find(|field| !valid_columns.contains_key(*field))
            {
                return Err(DbErr::Custom(format!(
                    "{spec_name} contains unknown column {unknown}",
                    spec_name = spec.name
                )));
            }
            if let Some(id) = site_id {
                match spec.filter {
                    Filter::SiteRoot => {
                        if uuid_field(row, "id") != Some(id) {
                            return Err(DbErr::Custom(
                                "snapshot site root does not match its scope"
                                    .into(),
                            ));
                        }
                    },
                    Filter::SiteId
                        if uuid_field(row, "site_id") != Some(id) =>
                    {
                        return Err(DbErr::Custom(format!(
                            "{} contains a row from another site",
                            spec.name
                        )));
                    },
                    _ => {},
                }
            }
            if spec.filter == Filter::InstanceKeys {
                let key =
                    row.get("key").and_then(Value::as_str).unwrap_or_default();
                if !INSTANCE_SETTING_KEYS.contains(&key) {
                    return Err(DbErr::Custom(format!(
                        "instance_settings key {key} is not restorable configuration"
                    )));
                }
            }
        }

        let live_rows = query_rows(db, spec, site_id).await?;
        let live: HashMap<String, Value> = spec
            .key
            .map(|key| {
                live_rows
                    .iter()
                    .filter_map(|row| {
                        json_key(row, key).map(|id| (id, row.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut merged = Vec::with_capacity(rows.len());
        for row in rows {
            let restored = merge_row(
                db,
                spec,
                schema,
                row,
                &live,
                &options,
                valid_columns,
            )
            .await?;
            if spec.name == "sites" {
                let before = spec
                    .key
                    .and_then(|key| json_key(&restored, key))
                    .and_then(|key| live.get(&key))
                    .and_then(|row| uuid_field(row, "user_id"));
                let after = uuid_field(&restored, "user_id");
                if before != after {
                    owner_changes.push(json!({
                        "site_id": restored["id"].clone(),
                        "from": before,
                        "to": after,
                    }));
                }
            }
            merged.push(restored);
        }
        if spec.filter == Filter::SiteId && !retained_site_ids.is_empty() {
            // A site retained outside an ordinary rollback keeps its complete
            // configuration too, not merely its `sites` root row. These live
            // rows are therefore retained in the replacement plan as well.
            merged.extend(
                live_rows
                    .iter()
                    .filter(|row| {
                        uuid_field(row, "site_id")
                            .is_some_and(|id| retained_site_ids.contains(&id))
                    })
                    .cloned(),
            );
        }
        let change = compute_change(spec, &live_rows, &merged);
        prepared.push(PreparedTable {
            spec,
            rows: merged,
            change,
        });
    }

    validate_references(db, &prepared).await?;

    let mut warnings = Vec::new();
    let mut prune_site_ids = Vec::new();
    if scope == VersionScope::Deployment {
        for row in live_sites {
            if !snapshot_site_ids
                .contains(&json_key(&row, "id").unwrap_or_default())
            {
                if let Some(id) = uuid_field(&row, "id") {
                    if options.prune_sites {
                        prune_site_ids.push(id);
                    } else {
                        warnings.push(format!(
                            "site {id} is absent from the snapshot and was retained"
                        ));
                    }
                }
            }
        }
    }

    Ok(RestorePlan {
        scope,
        tables: prepared,
        prune_site_ids,
        owner_changes,
        warnings,
    })
}

async fn delete_rows(
    txn: &DatabaseTransaction,
    prepared: &PreparedTable,
    site_id: Option<Uuid>,
) -> Result<(), DbErr> {
    let spec = prepared.spec;
    if spec.name == "sites" {
        return Ok(());
    }
    if spec.filter == Filter::Singleton && !prepared.rows.is_empty() {
        // Singleton rows are upserted below; deleting them would lose their
        // identity and any live fields a v1 snapshot needs.
        if spec.name != "api_protection_settings" {
            return Ok(());
        }
    }
    let table = quote_ident(spec.name);
    let mut values = Vec::new();
    let scope_sql = match (spec.filter, site_id) {
        (Filter::SiteId, Some(id)) => {
            values.push(id.into());
            " WHERE site_id = $1"
        },
        (Filter::Singleton, _) => " WHERE id = 1",
        (Filter::InstanceKeys, _) => {
            let keys = INSTANCE_SETTING_KEYS
                .iter()
                .map(|key| format!("'{key}'"))
                .collect::<Vec<_>>()
                .join(",");
            &format!(" WHERE key IN ({keys})")
        },
        _ => "",
    };
    if spec.name == "site_certificates" {
        // Preserve the excluded audit history when replacing certificates.
        let sql = format!(
            "UPDATE certificate_events SET certificate_id = NULL \
             WHERE certificate_id IN (SELECT id FROM {table}{scope_sql})"
        );
        txn.execute(statement(txn, sql, values.clone())).await?;
    }
    txn.execute(statement(
        txn,
        format!("DELETE FROM {table}{scope_sql}"),
        values,
    ))
    .await?;
    Ok(())
}

async fn insert_rows(
    txn: &DatabaseTransaction,
    spec: &TableSpec,
    rows: &[Value],
) -> Result<(), DbErr> {
    if rows.is_empty() {
        return Ok(());
    }
    let table = quote_ident(spec.name);
    txn.execute(statement(
        txn,
        format!(
            "INSERT INTO {table} SELECT * FROM \
             jsonb_populate_recordset(NULL::{table}, $1::jsonb)"
        ),
        vec![Value::Array(rows.to_vec()).into()],
    ))
    .await?;
    Ok(())
}

async fn upsert_rows(
    txn: &DatabaseTransaction,
    spec: &TableSpec,
    rows: &[Value],
) -> Result<(), DbErr> {
    if rows.is_empty() {
        return Ok(());
    }
    let key = spec.key.ok_or_else(|| {
        DbErr::Custom(format!("{} has no upsert key", spec.name))
    })?;
    let columns = columns_for(txn, spec.name).await?;
    let table = quote_ident(spec.name);
    let conflict = quote_ident(key);
    let assignments = columns
        .keys()
        .filter(|column| *column != key)
        .map(|column| {
            let quoted = quote_ident(column);
            format!("{quoted} = EXCLUDED.{quoted}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO {table} SELECT * FROM \
         jsonb_populate_recordset(NULL::{table}, $1::jsonb) \
         ON CONFLICT ({conflict}) DO UPDATE SET {assignments}"
    );
    txn.execute(statement(
        txn,
        sql,
        vec![Value::Array(rows.to_vec()).into()],
    ))
    .await?;
    Ok(())
}

pub async fn apply_restore(
    txn: &DatabaseTransaction,
    plan: RestorePlan,
) -> Result<RestoreReport, DbErr> {
    let site_id = plan.scope.column_value();
    let mut by_layer = plan.tables.iter().collect::<Vec<_>>();
    by_layer.sort_by_key(|prepared| std::cmp::Reverse(prepared.spec.layer));
    for prepared in by_layer {
        delete_rows(txn, prepared, site_id).await?;
    }
    for id in &plan.prune_site_ids {
        txn.execute(statement(
            txn,
            "DELETE FROM sites WHERE id = $1",
            vec![(*id).into()],
        ))
        .await?;
    }

    let mut report = RestoreReport {
        rows_by_table: BTreeMap::new(),
        warnings: plan.warnings.clone(),
    };
    let mut by_layer = plan.tables.iter().collect::<Vec<_>>();
    by_layer.sort_by_key(|prepared| prepared.spec.layer);
    for prepared in by_layer {
        let singleton = prepared.spec.filter == Filter::Singleton;
        let upsert = prepared.spec.name == "sites"
            || prepared.spec.name == "instance_settings"
            || (singleton && !prepared.rows.is_empty());
        if upsert {
            upsert_rows(txn, prepared.spec, &prepared.rows).await?;
        } else {
            insert_rows(txn, prepared.spec, &prepared.rows).await?;
        }
        report
            .rows_by_table
            .insert(prepared.spec.name.to_string(), prepared.rows.len());
    }
    Ok(report)
}

pub fn preview(plan: &RestorePlan) -> Value {
    json!({
        "scope": plan.scope.as_str(),
        "tables": plan.tables.iter().map(|prepared| {
            json!({
                "table": prepared.spec.name,
                "before": prepared.change.before,
                "after": prepared.change.after,
                "added": prepared.change.added,
                "removed": prepared.change.removed,
                "changed": prepared.change.changed,
            })
        }).collect::<Vec<_>>(),
        "sites_to_remove": plan.prune_site_ids,
        "owner_changes": plan.owner_changes,
        "warnings": plan.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_secrets_fail_closed_for_new_rows() {
        assert!(required_secret("site_oidc", "cookie_secret", &json!({})));
        assert!(required_secret(
            "site_visitors",
            "password_hash",
            &json!({})
        ));
        assert!(required_secret(
            "oidc_providers",
            "client_secret",
            &json!({})
        ));
        assert!(required_secret(
            "site_ssl",
            "key_pem",
            &json!({"cert_pem": "cert"})
        ));
        assert!(!required_secret("site_ssl", "key_pem", &json!({})));
    }

    #[test]
    fn uuid_keys_are_raw_strings_not_json_quoted() {
        let id = Uuid::new_v4();
        assert_eq!(json_key(&json!({"id": id}), "id"), Some(id.to_string()));
    }

    #[test]
    fn certificate_tables_are_the_only_key_match_checks() {
        assert!(is_certificate_table("site_certificates"));
        assert!(!is_certificate_table("visitor_passkeys"));
    }
}
