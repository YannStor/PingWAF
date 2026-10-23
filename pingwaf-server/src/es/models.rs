//! Elasticsearch document models.
//!
//! These are the wire shapes indexed into ES. They intentionally mirror the
//! gRPC `LogEntry` protocol closely so the mapping in the control plane stays a
//! field-for-field copy, but they are serialised with `skip_serializing_if` so
//! sparse documents (the overwhelmingly common case) do not carry a trail of
//! `null`s into the index.
//!
//! Bodies are always pre-truncated strings; the `*_truncated` flags record that
//! truncation happened so the dashboard can render a "body truncated" badge and
//! never imply completeness.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Full access log document indexed into `{prefix}-access-YYYY.MM.DD`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogDocument {
    pub timestamp: DateTime<Utc>,
    pub site_id: String,
    pub site_domain: String,
    pub agent_id: String,
    pub request_id: String,

    // ── Request ───────────────────────────────────────────────────────────
    pub client_ip: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    pub host: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_string: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_headers: Option<serde_json::Value>,
    /// Truncated request body, decoded lossily to UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_size: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub request_body_truncated: bool,

    // ── Response ──────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<serde_json::Value>,
    /// Truncated response body, decoded lossily to UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_size: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub response_body_truncated: bool,

    // ── Upstream ──────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_latency_ms: Option<u64>,

    // ── WAF ───────────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf_score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf_rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf_details: Option<String>,

    // ── Performance ───────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_status: Option<String>,

    // ── TLS & Geo ─────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,

    // ── Client ────────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
}

/// Security event document indexed into `{prefix}-security-YYYY.MM.DD`.
///
/// One is produced per WAF decision that yielded an action, score or rule id —
/// the same condition the PostgreSQL `security_events` table uses, so the two
/// stores never disagree about what counts as an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventDocument {
    pub timestamp: DateTime<Utc>,
    pub site_id: String,
    pub site_domain: String,
    pub agent_id: String,
    pub request_id: String,

    pub client_ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_string: Option<String>,

    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    /// Which protection produced the event (`managed`/`waf`/`ip_geo`/`bot`/
    /// `rate_limit`/`challenge`); absent on pre-0.21 documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    pub action: String,
    pub score: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Who the request was made by, when the site authenticated them: the
    /// OIDC session's `sub`. Absent for anonymous traffic, which is most of
    /// it, and for documents indexed before the field existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,

    // Full request payload, retained for forensics (body truncated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_headers: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub request_body_truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_documents_omit_nulls() {
        let doc = AccessLogDocument {
            timestamp: Utc::now(),
            site_id: "s".into(),
            site_domain: "example.com".into(),
            agent_id: "a".into(),
            request_id: "r".into(),
            client_ip: "10.0.0.1".into(),
            method: "GET".into(),
            scheme: None,
            host: "example.com".into(),
            path: "/".into(),
            query_string: None,
            protocol: None,
            request_headers: None,
            request_body: None,
            request_body_size: None,
            request_body_truncated: false,
            response_status: Some(200),
            response_headers: None,
            response_body: None,
            response_body_size: None,
            response_body_truncated: false,
            upstream_addr: None,
            upstream_latency_ms: None,
            waf_score: None,
            waf_action: None,
            waf_rule_id: None,
            waf_details: None,
            total_latency_ms: Some(12),
            cache_status: None,
            tls_version: None,
            ja3_hash: None,
            country_code: None,
            city: None,
            asn: None,
            user_agent: None,
            referer: None,
        };
        let value = serde_json::to_value(&doc).unwrap();
        let obj = value.as_object().unwrap();
        // Absent optionals must not appear as null keys.
        assert!(!obj.contains_key("request_body"));
        assert!(!obj.contains_key("ja3_hash"));
        // `false` flags are skipped too (serde default), keeping docs small.
        assert!(!obj.contains_key("request_body_truncated"));
        assert!(obj.contains_key("response_status"));
    }
}
