//! Entities holding the security policy of a site: WAF rule groups and rules,
//! rate limit rules and cache rules.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Actions a rule may take, mirroring `pingwaf::WafAction` in the protocol.
pub mod action {
    pub const BLOCK: &str = "block";
    pub const LOG: &str = "log";
    pub const CHALLENGE: &str = "challenge";
    pub const JS_CHALLENGE: &str = "js_challenge";
    pub const ALLOW: &str = "allow";
    /// Requires the site's basic auth credentials instead of answering with a
    /// block page. Only the geo policy exposes it.
    pub const BASIC_AUTH: &str = "basic_auth";

    /// Actions a custom WAF rule may take.
    pub const ALL: [&str; 5] = [BLOCK, LOG, CHALLENGE, JS_CHALLENGE, ALLOW];

    /// Actions the geo policy accepts: `log` has no geo enforcement meaning
    /// and `allow` would contradict the match itself, so neither is offered.
    pub const GEO_ALL: [&str; 4] = [BLOCK, CHALLENGE, JS_CHALLENGE, BASIC_AUTH];

    pub fn is_valid(action: &str) -> bool {
        ALL.contains(&action)
    }

    pub fn is_valid_geo(action: &str) -> bool {
        GEO_ALL.contains(&action)
    }

    /// `pingwaf::WafAction` enum values as defined in control_plane.proto.
    pub fn to_proto(action: &str) -> i32 {
        match action {
            BLOCK => 0,
            LOG => 1,
            CHALLENGE => 2,
            JS_CHALLENGE => 3,
            ALLOW => 4,
            BASIC_AUTH => 5,
            _ => 0,
        }
    }
}

/// Evaluation mode of a rule: disabled, log only, or enforcing.
pub mod mode {
    pub const OFF: &str = "off";
    pub const MONITOR: &str = "monitor";
    pub const BLOCK: &str = "block";

    pub fn is_valid(mode: &str) -> bool {
        matches!(mode, OFF | MONITOR | BLOCK)
    }

    /// `pingwaf::WafMode` enum values as defined in control_plane.proto.
    pub fn to_proto(mode: &str) -> i32 {
        match mode {
            OFF => 0,
            MONITOR => 1,
            BLOCK => 2,
            _ => 0,
        }
    }
}

/// `rule_groups` — named, ordered collections of rules.
pub mod rule_groups {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "rule_groups")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub name: String,
        pub phase: String,
        pub priority: i32,
        pub enabled: bool,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `rules` — individual WAF rules written in the PingWAF rules language.
pub mod rules {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "rules")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub group_id: Option<Uuid>,
        pub site_id: Uuid,
        pub name: String,
        pub description: Option<String>,
        pub expression: String,
        pub action: String,
        pub severity: i32,
        pub tags: Vec<String>,
        pub enabled: bool,
        pub mode: String,
        pub priority: i32,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `rate_limit_rules` — request counting and mitigation.
pub mod rate_limit_rules {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "rate_limit_rules")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub name: String,
        pub expression: String,
        /// Counter keys to group requests by, e.g. `ip`, `path`, or the
        /// parameterized `header:<name>` / `cookie:<name>` / `query:<name>`.
        pub characteristics: Vec<String>,
        pub period_seconds: i32,
        pub threshold: i32,
        pub action: String,
        pub mitigation_timeout_seconds: i32,
        pub enabled: bool,
        pub priority: i32,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `cache_rules` — edge caching policy per site.
pub mod cache_rules {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "cache_rules")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Uuid,
        pub name: String,
        pub match_expression: String,
        pub edge_ttl_seconds: i32,
        pub browser_ttl_seconds: i32,
        /// Kept for compatibility; the disk budget moved to cache-settings
        /// (a rule must not own a site-wide resource).
        #[serde(skip_serializing)]
        pub disk_quota_mb: i32,
        pub cache_eligible: bool,
        pub respect_origin: bool,
        pub enabled: bool,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Counter keys accepted in `rate_limit_rules.characteristics`.
///
/// Bare `header` / `cookie` / `query` are not accepted any more — they carry no
/// key to count on. Use the parameterized forms `header:<name>`,
/// `cookie:<name>` and `query:<name>` instead.
pub mod characteristic {
    pub const IP: &str = "ip";
    pub const IP_NAT: &str = "ip_nat";
    pub const HOST: &str = "host";
    pub const PATH: &str = "path";
    pub const HEADER: &str = "header";
    pub const COOKIE: &str = "cookie";
    pub const QUERY: &str = "query";
    pub const ASN: &str = "asn";
    pub const COUNTRY: &str = "country";
    pub const JA3: &str = "ja3";

    /// Splits `header:<name>` / `cookie:<name>` / `query:<name>` into its kind
    /// and parameter name. The parameter must be non-empty, whitespace-free
    /// and at most 128 characters.
    fn split_parameterized(value: &str) -> Option<(&'static str, &str)> {
        let (kind, param) = value.split_once(':')?;
        let kind = match kind {
            HEADER => HEADER,
            COOKIE => COOKIE,
            QUERY => QUERY,
            _ => return None,
        };
        if param.is_empty()
            || param.len() > 128
            || param.chars().any(char::is_whitespace)
        {
            return None;
        }
        Some((kind, param))
    }

    pub fn is_valid(value: &str) -> bool {
        if matches!(value, IP | IP_NAT | HOST | PATH | ASN | COUNTRY | JA3) {
            return true;
        }
        split_parameterized(value).is_some()
    }

    /// `pingwaf::RateLimitCharacteristics` values from control_plane.proto.
    ///
    /// The proto enum uses `RATE_LIMIT_CHAR_*` names, which prost may or may not
    /// shorten when generating Rust variants, so the numbers are spelled out
    /// here instead of referencing the generated constants.
    pub fn to_proto(value: &str) -> i32 {
        match value {
            IP => 0,
            IP_NAT => 1,
            HOST => 2,
            PATH => 3,
            // Bare parameterized kinds come from rows stored before the
            // parameter was required; the edge drops rules that carry them.
            HEADER => 4,
            COOKIE => 5,
            QUERY => 6,
            ASN => 7,
            COUNTRY => 8,
            JA3 => 9,
            _ => split_parameterized(value).map_or(0, |(kind, _)| match kind {
                HEADER => 4,
                COOKIE => 5,
                QUERY => 6,
                _ => 0,
            }),
        }
    }

    /// Parameter name for a parameterized characteristic (empty otherwise);
    /// shipped alongside `to_proto` in `RateLimitRule.characteristic_params`.
    pub fn to_param(value: &str) -> String {
        split_parameterized(value)
            .map(|(_, param)| param.to_string())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_geo_policy_accepts_neither_log_nor_allow() {
        for valid in action::GEO_ALL {
            assert!(action::is_valid_geo(valid));
        }
        // The data plane has no geo outcome for either of these: `log` would
        // behave as a block and `allow` would contradict the match.
        assert!(!action::is_valid_geo(action::LOG));
        assert!(!action::is_valid_geo(action::ALLOW));
    }

    #[test]
    fn basic_auth_is_a_gate_action_not_a_rule_action() {
        assert!(action::is_valid_geo(action::BASIC_AUTH));
        assert!(!action::is_valid(action::BASIC_AUTH));
        assert_eq!(5, action::to_proto(action::BASIC_AUTH));
    }
}
