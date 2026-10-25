//! The single catalogue of configuration that may be captured and restored.
//!
//! Snapshots are built with PostgreSQL's `to_jsonb`, not model serialization:
//! every database column is present, including columns an API model deliberately
//! skips. Restoring uses the same table list, so a newly catalogued table cannot
//! silently become write-only.

use std::collections::{BTreeMap, BTreeSet};

use sea_orm::{ConnectionTrait, DbErr, Statement, Value as DbValue};
use serde_json::{json, Value};
use uuid::Uuid;

pub const SNAPSHOT_SCHEMA: i64 = 2;
pub const INSTANCE_SETTING_KEYS: [&str; 3] =
    ["notification_settings", "login_security", "passkey_enabled"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionScope {
    Site(Uuid),
    Global,
    Deployment,
}

impl VersionScope {
    pub fn column_value(self) -> Option<Uuid> {
        match self {
            Self::Site(id) => Some(id),
            Self::Global | Self::Deployment => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Site(_) => "site",
            Self::Global => "global",
            Self::Deployment => "deployment",
        }
    }

    pub fn describe(self) -> String {
        match self {
            Self::Site(id) => format!("site {id}"),
            Self::Global => "the global settings".to_string(),
            Self::Deployment => "the deployment configuration".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    Site,
    Global,
    Deployment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    SiteRoot,
    SiteId,
    All,
    Singleton,
    InstanceKeys,
}

#[derive(Debug)]
pub struct TableSpec {
    pub name: &'static str,
    pub scopes: &'static [ScopeKind],
    pub filter: Filter,
    pub layer: u8,
    pub key: Option<&'static str>,
    pub order: &'static str,
    pub secrets: &'static [&'static str],
}

const SD: &[ScopeKind] = &[ScopeKind::Site, ScopeKind::Deployment];
const GD: &[ScopeKind] = &[ScopeKind::Global, ScopeKind::Deployment];
const D: &[ScopeKind] = &[ScopeKind::Deployment];

const fn site(name: &'static str, layer: u8, order: &'static str) -> TableSpec {
    TableSpec {
        name,
        scopes: SD,
        filter: Filter::SiteId,
        layer,
        key: Some("id"),
        order,
        secrets: &[],
    }
}

const fn global(name: &'static str, order: &'static str) -> TableSpec {
    TableSpec {
        name,
        scopes: GD,
        filter: Filter::All,
        layer: 1,
        key: Some("id"),
        order,
        secrets: &[],
    }
}

const fn deployment(
    name: &'static str,
    layer: u8,
    order: &'static str,
) -> TableSpec {
    TableSpec {
        name,
        scopes: D,
        filter: Filter::All,
        layer,
        key: Some("id"),
        order,
        secrets: &[],
    }
}

pub static SITE_TABLES: &[TableSpec] = &[
    TableSpec {
        name: "sites",
        scopes: SD,
        filter: Filter::SiteRoot,
        layer: 2,
        key: Some("id"),
        order: "id",
        secrets: &[],
    },
    site("rule_groups", 3, "id"),
    site("rules", 4, "id"),
    site("rate_limit_rules", 3, "id"),
    site("cache_rules", 3, "id"),
    site("site_upstream_pools", 3, "id"),
    site("site_upstreams", 4, "id"),
    site("site_routes", 4, "id"),
    TableSpec {
        secrets: &["key_pem", "acme_dns_config"],
        ..site("site_certificates", 3, "id")
    },
    TableSpec {
        secrets: &["key_pem", "acme_dns_config"],
        ..site("site_ssl", 4, "id")
    },
    site("ip_access_rules", 3, "id"),
    TableSpec {
        name: "ip_group_sites",
        scopes: SD,
        filter: Filter::SiteId,
        layer: 3,
        key: None,
        order: "ip_group_id",
        secrets: &[],
    },
    site("waf_settings", 3, "id"),
    site("challenge_settings", 3, "id"),
    site("bot_protection", 3, "id"),
    site("geo_rules", 3, "id"),
    TableSpec {
        secrets: &["credentials"],
        ..site("site_basic_auth", 3, "id")
    },
    TableSpec {
        secrets: &["cookie_secret"],
        ..site("site_oidc", 3, "id")
    },
    site("rewrite_rules", 3, "id"),
    site("site_ai_crawl_settings", 3, "id"),
    site("site_ai_bot_policies", 4, "id"),
    TableSpec {
        secrets: &["key_pem"],
        ..site("mtls_cas", 3, "id")
    },
    TableSpec {
        secrets: &["key_pem"],
        ..site("mtls_client_certificates", 4, "id")
    },
    site("visitor_site_grants", 3, "id"),
];

pub static GLOBAL_TABLES: &[TableSpec] = &[
    TableSpec {
        name: "defense_settings",
        scopes: GD,
        filter: Filter::Singleton,
        layer: 1,
        key: Some("id"),
        order: "id",
        secrets: &[],
    },
    TableSpec {
        name: "origin_settings",
        scopes: GD,
        filter: Filter::Singleton,
        layer: 1,
        key: Some("id"),
        order: "id",
        secrets: &[],
    },
    TableSpec {
        name: "cache_settings",
        scopes: GD,
        filter: Filter::Singleton,
        layer: 1,
        key: Some("id"),
        order: "id",
        secrets: &[],
    },
    global("error_pages", "status_code"),
];

pub static DEPLOYMENT_ONLY_TABLES: &[TableSpec] = &[
    TableSpec {
        secrets: &["source_url"],
        ..deployment("ip_groups", 1, "id")
    },
    TableSpec {
        secrets: &["client_secret"],
        ..deployment("oidc_providers", 1, "id")
    },
    TableSpec {
        secrets: &["password_hash"],
        ..deployment("site_visitors", 1, "email")
    },
    deployment("visitor_passkeys", 2, "id"),
    TableSpec {
        secrets: &["config"],
        ..deployment("notification_channels", 1, "id")
    },
    TableSpec {
        name: "ai_settings",
        scopes: D,
        filter: Filter::Singleton,
        layer: 1,
        key: Some("id"),
        order: "id",
        secrets: &["api_key"],
    },
    TableSpec {
        name: "api_protection_settings",
        scopes: D,
        filter: Filter::Singleton,
        layer: 2,
        key: Some("id"),
        order: "id",
        secrets: &[],
    },
    TableSpec {
        name: "log_retention_settings",
        scopes: D,
        filter: Filter::Singleton,
        layer: 1,
        key: Some("id"),
        order: "id",
        secrets: &[],
    },
    TableSpec {
        secrets: &["key_pem"],
        ..deployment("control_plane_certificates", 1, "id")
    },
    TableSpec {
        name: "instance_settings",
        scopes: D,
        filter: Filter::InstanceKeys,
        layer: 1,
        key: Some("key"),
        order: "key",
        secrets: &[],
    },
];

pub fn tables_for(scope: VersionScope) -> Vec<&'static TableSpec> {
    let mut tables: Vec<_> = match scope {
        VersionScope::Site(_) => SITE_TABLES.iter().collect(),
        VersionScope::Global => GLOBAL_TABLES.iter().collect(),
        VersionScope::Deployment => SITE_TABLES
            .iter()
            .chain(GLOBAL_TABLES)
            .chain(DEPLOYMENT_ONLY_TABLES)
            .collect(),
    };
    tables.sort_by_key(|table| table.layer);
    tables
}

pub fn spec_for(name: &str) -> Option<&'static TableSpec> {
    SITE_TABLES
        .iter()
        .chain(GLOBAL_TABLES)
        .chain(DEPLOYMENT_ONLY_TABLES)
        .find(|table| table.name == name)
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

pub(crate) async fn query_rows<C: ConnectionTrait>(
    db: &C,
    spec: &TableSpec,
    site_id: Option<Uuid>,
) -> Result<Vec<Value>, DbErr> {
    let table = quote_ident(spec.name);
    let order = quote_ident(spec.order);
    let mut sql = format!(
        "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.{order}), \
         '[]'::jsonb) AS rows FROM {table} t"
    );
    let mut values = Vec::new();
    match (spec.filter, site_id) {
        (Filter::SiteRoot, Some(id)) => {
            sql.push_str(" WHERE t.id = $1");
            values.push(id.into());
        },
        (Filter::SiteId, Some(id)) => {
            sql.push_str(" WHERE t.site_id = $1");
            values.push(id.into());
        },
        (Filter::Singleton, _) => sql.push_str(" WHERE t.id = 1"),
        (Filter::InstanceKeys, _) => {
            let keys = INSTANCE_SETTING_KEYS
                .iter()
                .map(|key| format!("'{key}'"))
                .collect::<Vec<_>>()
                .join(",");
            sql.push_str(&format!(" WHERE t.key IN ({keys})"));
        },
        _ => {},
    }
    let result =
        db.query_one(statement(db, sql, values))
            .await?
            .ok_or_else(|| {
                DbErr::Custom("snapshot query returned no row".into())
            })?;
    let value: Value = result.try_get("", "rows")?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| DbErr::Custom("snapshot rows were not an array".into()))
}

pub async fn capture<C: ConnectionTrait>(
    db: &C,
    scope: VersionScope,
    include_secrets: bool,
) -> Result<Value, DbErr> {
    let site_id = scope.column_value();
    let mut tables = BTreeMap::new();
    for spec in tables_for(scope) {
        let rows = query_rows(db, spec, site_id).await?;
        let rows = if include_secrets {
            rows
        } else {
            strip_row_secrets(spec, rows)
        };
        tables.insert(spec.name.to_string(), Value::Array(rows));
    }
    Ok(json!({
        "schema": SNAPSHOT_SCHEMA,
        "scope": scope.as_str(),
        "site_id": site_id,
        "secret_policy": if include_secrets { "encrypted_payload" } else { "live_only" },
        "tables": tables,
    }))
}

fn strip_row_secrets(spec: &TableSpec, rows: Vec<Value>) -> Vec<Value> {
    rows.into_iter()
        .map(|mut row| {
            if let Some(object) = row.as_object_mut() {
                for field in spec.secrets {
                    object.remove(*field);
                }
            }
            row
        })
        .collect()
}

/// A snapshot safe for the ordinary version-detail API and CLI output.
/// Historical v1 rows are sanitized too: they may predate secret stripping.
pub fn sanitize_snapshot_for_output(snapshot: &Value) -> Value {
    let mut output = snapshot.clone();
    if let Some(tables) =
        output.get_mut("tables").and_then(Value::as_object_mut)
    {
        for (name, rows) in tables.iter_mut() {
            let Some(spec) = spec_for(name) else {
                continue;
            };
            let sanitized = match rows.clone() {
                Value::Array(items) => {
                    Value::Array(strip_row_secrets(spec, items))
                },
                Value::Object(object) => {
                    strip_row_secrets(spec, vec![Value::Object(object)])
                        .into_iter()
                        .next()
                        .unwrap_or(Value::Null)
                },
                other => other,
            };
            *rows = sanitized;
        }
    }
    // `site` is the v1 site root and carries no secret fields.
    output
}

pub fn normalise_tables(
    snapshot: &Value,
    scope: VersionScope,
) -> Result<(i64, BTreeMap<String, Value>), DbErr> {
    let schema = snapshot.get("schema").and_then(Value::as_i64).unwrap_or(1);
    if !(1..=SNAPSHOT_SCHEMA).contains(&schema) {
        return Err(DbErr::Custom(format!(
            "unsupported snapshot schema {schema}"
        )));
    }
    if scope == VersionScope::Deployment && schema < 2 {
        return Err(DbErr::Custom(
            "deployment restore requires the complete schema-2 snapshot".into(),
        ));
    }
    if schema >= 2 {
        let documented = snapshot.get("scope").and_then(Value::as_str);
        if documented.is_some_and(|value| value != scope.as_str()) {
            return Err(DbErr::Custom(
                "snapshot scope does not match the restore scope".into(),
            ));
        }
        let documented_site =
            snapshot.get("site_id").cloned().unwrap_or(Value::Null);
        if documented_site != json!(scope.column_value()) {
            return Err(DbErr::Custom(
                "snapshot site_id does not match the restore scope".into(),
            ));
        }
    }
    let mut tables = snapshot
        .get("tables")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| DbErr::Custom("snapshot has no tables".into()))?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    if schema == 1 && scope.column_value().is_some() {
        if let Some(site) = snapshot.get("site").filter(|site| site.is_object())
        {
            tables
                .entry("sites".to_string())
                .or_insert_with(|| Value::Array(vec![site.clone()]));
        }
    }
    let allowed: BTreeSet<_> = tables_for(scope)
        .into_iter()
        .map(|table| table.name)
        .collect();
    if let Some(unknown) =
        tables.keys().find(|name| !allowed.contains(name.as_str()))
    {
        return Err(DbErr::Custom(format!(
            "snapshot contains unknown table {unknown}"
        )));
    }
    Ok((schema, tables))
}

pub fn rows_for(
    schema: i64,
    tables: &BTreeMap<String, Value>,
    name: &str,
) -> Result<Option<Vec<Value>>, DbErr> {
    let Some(value) = tables.get(name) else {
        return Ok(None);
    };
    match value {
        Value::Array(rows) => Ok(Some(rows.clone())),
        Value::Object(_) if schema == 1 => Ok(Some(vec![value.clone()])),
        Value::Null if schema == 1 => Ok(Some(Vec::new())),
        _ => Err(DbErr::Custom(format!(
            "table {name} is not an array of rows"
        ))),
    }
}

pub fn merge_shallow(base: &mut Value, overlay: &Value) {
    let (Some(base), Some(overlay)) =
        (base.as_object_mut(), overlay.as_object())
    else {
        return;
    };
    for (key, value) in overlay {
        base.insert(key.clone(), value.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_covers_the_confirmed_configuration() {
        assert_eq!(SITE_TABLES.len(), 24);
        assert_eq!(GLOBAL_TABLES.len(), 4);
        assert_eq!(DEPLOYMENT_ONLY_TABLES.len(), 10);
        assert_eq!(tables_for(VersionScope::Deployment).len(), 38);
        let names: BTreeSet<_> = tables_for(VersionScope::Deployment)
            .into_iter()
            .map(|table| table.name)
            .collect();
        assert_eq!(names.len(), 38, "table names must be unique");
    }

    #[test]
    fn v1_singleton_objects_and_nulls_are_readable() {
        let tables = BTreeMap::from([
            ("defense_settings".into(), json!({"id": 1})),
            ("origin_settings".into(), Value::Null),
        ]);
        assert_eq!(
            rows_for(1, &tables, "defense_settings")
                .unwrap()
                .unwrap()
                .len(),
            1
        );
        assert!(rows_for(1, &tables, "origin_settings")
            .unwrap()
            .unwrap()
            .is_empty());
        assert!(rows_for(2, &tables, "defense_settings").is_err());
    }

    #[test]
    fn missing_tables_are_not_empty_tables() {
        let tables = BTreeMap::new();
        assert_eq!(rows_for(2, &tables, "rules").unwrap(), None);
        let tables = BTreeMap::from([("rules".into(), json!([]))]);
        assert_eq!(rows_for(2, &tables, "rules").unwrap(), Some(vec![]));
    }

    #[test]
    fn output_sanitizer_covers_private_keys_and_credentials() {
        let snapshot = json!({"tables": {
            "site_certificates": [{"id": "a", "key_pem": "PRIVATE", "acme_dns_config": {"token": "x"}}],
            "site_basic_auth": [{"credentials": [{"username": "a", "password": "b"}]}],
            "oidc_providers": {"id": "p", "client_secret": "secret"}
        }});
        let output = sanitize_snapshot_for_output(&snapshot).to_string();
        assert!(!output.contains("PRIVATE"));
        assert!(!output.contains("password"));
        assert!(!output.contains("secret"));
    }

    #[test]
    fn jwt_secret_is_not_an_instance_configuration_key() {
        assert!(!INSTANCE_SETTING_KEYS.contains(&"jwt_secret"));
    }
}
