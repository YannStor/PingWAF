//! Elasticsearch index template management.
//!
//! [`ensure_index_template`] installs a composable index template (plus a
//! best-effort ILM retention policy) so every daily index the shipper creates
//! gets the right mappings and settings without any manual setup. It is called
//! once at control-plane startup; failures are logged but never fatal, because
//! ES will still accept documents via dynamic mapping.

use super::client::ElasticsearchClient;

/// Installs (or updates) the index template and the retention policy.
///
/// Idempotent: `PUT _index_template/…` replaces any existing template of the
/// same name, so calling this on every boot keeps the mappings in sync with the
/// current document models.
pub async fn ensure_index_template(
    client: &ElasticsearchClient,
) -> anyhow::Result<()> {
    let prefix = client.config().index_prefix.clone();

    // 1. Retention policy — best effort. ILM ships with the free Basic licence,
    //    but a managed ES service may forbid it; a failure here must not stop the
    //    template (and therefore the shipper) from working.
    //
    //    The delete phase is a fixed 360 days on purpose: Elasticsearch is an
    //    archive that survives the PostgreSQL sweeps, so its window is longer
    //    and independent of the configurable retention in the dashboard.
    let ilm_name = format!("{prefix}-logs-retention");
    let ilm_body = serde_json::json!({
        "policy": {
            "phases": {
                "hot": { "min_age": "0ms", "actions": {} },
                "delete": { "min_age": "360d", "actions": { "delete": {} } }
            }
        }
    });
    if let Err(err) = client
        .request_json(
            reqwest::Method::PUT,
            &format!("/_ilm/policy/{ilm_name}"),
            Some(ilm_body),
        )
        .await
    {
        tracing::warn!(
            policy = %ilm_name,
            error = %err,
            "could not install the ES retention policy, indices will not auto-expire"
        );
    }

    // 2. Composable index template covering both index families.
    let template_name = format!("{prefix}-logs");
    let body = index_template_body(&prefix, &ilm_name);
    client
        .request_json(
            reqwest::Method::PUT,
            &format!("/_index_template/{template_name}"),
            Some(body),
        )
        .await?;

    tracing::info!(template = %template_name, "elasticsearch index template installed");
    Ok(())
}

/// Builds the template payload. Exposed for tests and for the settings API to
/// show what would be applied.
pub fn index_template_body(
    prefix: &str,
    ilm_policy: &str,
) -> serde_json::Value {
    serde_json::json!({
        "index_patterns": [format!("{prefix}-access-*"), format!("{prefix}-security-*")],
        "priority": 200,
        "template": {
            "settings": index_settings(ilm_policy),
            "mappings": mappings(),
        }
    })
}

fn index_settings(ilm_policy: &str) -> serde_json::Value {
    serde_json::json!({
        "number_of_shards": 1,
        "number_of_replicas": 1,
        "refresh_interval": "5s",
        "index.lifecycle.name": ilm_policy,
    })
}

/// Field mappings shared by both document families.
///
/// Bodies and header maps are the interesting choices:
/// - `request_headers` / `response_headers` are `object` with `enabled: false`,
///   stored verbatim in `_source` but not indexed, so arbitrary header keys can
///   never cause a mapping explosion.
/// - `*_body` are `text` (already truncated by the shipper) so security analysts
///   can full-text search payloads.
fn mappings() -> serde_json::Value {
    // Built from several small `json!` chunks rather than one giant literal: a
    // single macro this large blows the default recursion limit.
    let mut props = serde_json::Map::new();
    for chunk in [
        identity_props(),
        request_props(),
        response_props(),
        performance_props(),
        waf_props(),
        geo_props(),
        client_props(),
    ] {
        if let serde_json::Value::Object(map) = chunk {
            for (key, value) in map {
                props.insert(key, value);
            }
        }
    }

    serde_json::json!({
        "dynamic": "false",
        "properties": serde_json::Value::Object(props),
    })
}

/// `text` with a `keyword` sub-field, for values that are both searched and
/// filtered/aggregated on.
fn keyword_text() -> serde_json::Value {
    serde_json::json!({
        "type": "text",
        "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 } }
    })
}

fn identity_props() -> serde_json::Value {
    serde_json::json!({
        "timestamp": { "type": "date" },
        "site_id": { "type": "keyword" },
        "site_domain": { "type": "keyword" },
        "agent_id": { "type": "keyword" },
        "request_id": { "type": "keyword" },
    })
}

fn request_props() -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in serde_json::json!({
        "client_ip": { "type": "ip" },
        "method": { "type": "keyword" },
        "scheme": { "type": "keyword" },
        "protocol": { "type": "keyword" },
        "host": { "type": "keyword" },
        "query_string": { "type": "text" },
        "request_headers": { "type": "object", "enabled": false },
        "request_body": { "type": "text" },
        "request_body_size": { "type": "long" },
        "request_body_truncated": { "type": "boolean" },
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
    {
        map.insert(key, value);
    }
    map.insert("path".to_string(), keyword_text());
    serde_json::Value::Object(map)
}

fn response_props() -> serde_json::Value {
    serde_json::json!({
        "response_status": { "type": "integer" },
        "response_headers": { "type": "object", "enabled": false },
        "response_body": { "type": "text" },
        "response_body_size": { "type": "long" },
        "response_body_truncated": { "type": "boolean" },
    })
}

fn performance_props() -> serde_json::Value {
    serde_json::json!({
        "upstream_addr": { "type": "keyword" },
        "upstream_latency_ms": { "type": "long" },
        "total_latency_ms": { "type": "long" },
        "cache_status": { "type": "keyword" },
    })
}

fn waf_props() -> serde_json::Value {
    serde_json::json!({
        "waf_score": { "type": "integer" },
        "waf_action": { "type": "keyword" },
        "waf_rule_id": { "type": "keyword" },
        "waf_details": { "type": "text" },
        "rule_id": { "type": "keyword" },
        "rule_name": { "type": "keyword" },
        "action": { "type": "keyword" },
        "score": { "type": "integer" },
        "attack_category": { "type": "keyword" },
        "details": { "type": "text" },
        "severity": { "type": "short" },
    })
}

fn geo_props() -> serde_json::Value {
    serde_json::json!({
        "tls_version": { "type": "keyword" },
        "ja3_hash": { "type": "keyword" },
        "country_code": { "type": "keyword" },
        "city": { "type": "keyword" },
        "asn": { "type": "long" },
    })
}

fn client_props() -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("user_agent".to_string(), keyword_text());
    // The authenticated caller, when there is one. A keyword so it can be
    // filtered and aggregated exactly ("everything this account did") rather
    // than tokenised, and capped like the column it mirrors so one oversized
    // `sub` cannot bloat the index.
    map.insert(
        "user_identity".to_string(),
        serde_json::json!({ "type": "keyword", "ignore_above": 256 }),
    );
    map.insert(
        "referer".to_string(),
        serde_json::json!({ "type": "keyword", "ignore_above": 2048 }),
    );
    serde_json::Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_covers_both_index_families() {
        let body = index_template_body("pingwaf", "pingwaf-logs-retention");
        let patterns = body["index_patterns"].as_array().unwrap();
        assert!(patterns.iter().any(|p| p == "pingwaf-access-*"));
        assert!(patterns.iter().any(|p| p == "pingwaf-security-*"));

        let settings = &body["template"]["settings"];
        assert_eq!(settings["number_of_shards"], 1);
        assert_eq!(settings["number_of_replicas"], 1);
        assert_eq!(settings["index.lifecycle.name"], "pingwaf-logs-retention");
    }

    #[test]
    fn headers_are_stored_but_not_indexed() {
        let body = index_template_body("pingwaf", "ilm");
        let props = &body["template"]["mappings"]["properties"];
        assert_eq!(props["request_headers"]["enabled"], false);
        assert_eq!(props["response_headers"]["enabled"], false);
        assert_eq!(props["request_body"]["type"], "text");
        assert_eq!(props["client_ip"]["type"], "ip");
    }
}
