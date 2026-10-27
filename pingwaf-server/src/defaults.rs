//! Built-in policy seeded for every site.
//!
//! PingWAF is meant to be useful the moment a site is added: a fresh site gets
//! an OWASP-flavoured WAF rule set that is already *enabled* and **blocking**,
//! so "WAF is on" means SQLi/XSS payloads are actually stopped instead of only
//! being recorded while the origin still answers 200. Restoring the defaults on
//! an existing site is the one exception: missing rules come back in monitor
//! mode, so a repair action never starts blocking traffic that site has been
//! serving unfiltered. Caching works the same way, except the seeded cache
//! rules start disabled: switching caching on for a site is a single toggle,
//! and the common cases (static assets, HTML, API responses) are covered.
//!
//! Seeding is idempotent and matched on the rule *name*, so restoring the
//! defaults after an edit only re-adds what is missing and never duplicates.

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use uuid::Uuid;

use crate::models::{cache_rules, ip_groups, mode, rule, rule_groups};

/// Name of the group that holds the built-in WAF rules.
pub const WAF_DEFAULT_GROUP_NAME: &str = "PingWAF 内置防护";
/// Description shown next to the group in the dashboard.
pub const WAF_DEFAULT_GROUP_DESCRIPTION: &str =
    "开箱即用的基础防护规则，按需调整";

/// Official Cloudflare IP list — the default subscription every install gets.
pub const CLOUDFLARE_IPS_URL: &str = "https://api.cloudflare.com/client/v4/ips";
/// Name of the seeded Cloudflare subscription group.
pub const CLOUDFLARE_GROUP_NAME: &str = "Cloudflare";

/// Seeds the built-in Cloudflare subscription group.
///
/// The group exists from the first boot with a daily refresh interval so the
/// operator only has to flip `enabled` (and the action) to use it. It starts
/// *disabled*: its ranges block legitimate visitors when a site is proxied
/// through Cloudflare, so enforcing it is always an operator decision. The
/// background scheduler populates the ranges on its first tick.
pub async fn seed_ip_group_defaults(
    db: &DatabaseConnection,
) -> Result<(), sea_orm::DbErr> {
    let existing = ip_groups::Entity::find()
        .filter(ip_groups::Column::SourceUrl.eq(CLOUDFLARE_IPS_URL))
        .one(db)
        .await?;
    if existing.is_some() {
        return Ok(());
    }

    let timestamp = Utc::now();
    ip_groups::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(CLOUDFLARE_GROUP_NAME.to_string()),
        description: Set(Some(
            "Official Cloudflare IP ranges, refreshed daily from \
             api.cloudflare.com. Disabled by default: enable it once you \
             know how it fits your traffic."
                .to_string(),
        )),
        ip_ranges: Set(Vec::new()),
        action: Set("block".to_string()),
        is_global: Set(true),
        subscription_kind: Set(Some("url".to_string())),
        subscription_enabled: Set(true),
        source_url: Set(Some(CLOUDFLARE_IPS_URL.to_string())),
        sync_interval_minutes: Set(Some(1440)),
        last_synced_at: Set(None),
        last_sync_error: Set(None),
        enabled: Set(false),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(db)
    .await?;

    tracing::info!(
        url = CLOUDFLARE_IPS_URL,
        "seeded the built-in Cloudflare IP subscription group"
    );
    Ok(())
}

/// Disk budget, in MiB, every new site starts with.
pub const DEFAULT_CACHE_QUOTA_MB: i32 = 1024;

/// Default/limits for the per-site downstream read/write timeout.
pub const DEFAULT_SITE_DOWNSTREAM_TIMEOUT_SECS: i32 = 60;
pub const MIN_SITE_DOWNSTREAM_TIMEOUT_SECS: i32 = 1;
pub const MAX_SITE_DOWNSTREAM_TIMEOUT_SECS: i32 = 3600;

/// Normalizes a stored value for display/downstream. 0 is the legacy
/// "unset" sentinel and resolves to the default; out-of-range values are
/// bounded instead of being echoed to the data plane.
pub fn normalize_site_downstream_timeout_secs(value: i32) -> u32 {
    if value <= 0 {
        DEFAULT_SITE_DOWNSTREAM_TIMEOUT_SECS as u32
    } else {
        (value as u32).min(MAX_SITE_DOWNSTREAM_TIMEOUT_SECS as u32)
    }
}

/// A built-in WAF rule, expressed the same way a user-defined rule is.
pub struct DefaultWafRule {
    /// Stable identifier, used as the rule name so seeding stays idempotent.
    pub name: &'static str,
    pub description: &'static str,
    pub expression: &'static str,
    pub action: &'static str,
    /// 1 (info) … 5 (critical).
    pub severity: i32,
    /// Tags drive the detection switches in `grpc::config`; keep the English
    /// keywords (`sqli`, `xss`, `rce`, `lfi`, `ssrf`, `bot`) intact.
    pub tags: &'static [&'static str],
}

/// A built-in cache rule. Disabled until caching is switched on for the site.
pub struct DefaultCacheRule {
    pub name: &'static str,
    pub match_expression: &'static str,
    pub edge_ttl_seconds: i32,
    pub browser_ttl_seconds: i32,
    pub cache_eligible: bool,
    pub respect_origin: bool,
}

/// The built-in WAF rule set: one blocking rule per detection family plus the
/// reconnaissance patterns that generate noise on any public site.
///
/// The *mode* these rules are seeded with is decided by the seeding path (see
/// [`NEW_SITE_WAF_RULE_MODE`] / [`RESTORE_WAF_RULE_MODE`]); every rule keeps its
/// explicit `block` action so switching the mode is all it takes to enforce.
pub fn waf_rules() -> Vec<DefaultWafRule> {
    vec![
        DefaultWafRule {
            name: "SQL 注入检测",
            description: "命中 SQL 注入特征或异常评分时告警",
            expression: "cf.waf.score.sqli ge 40",
            action: "block",
            severity: 5,
            tags: &["sqli", "anomaly"],
        },
        DefaultWafRule {
            name: "XSS 跨站脚本检测",
            description: "命中跨站脚本特征或异常评分时告警",
            expression: "cf.waf.score.xss ge 40",
            action: "block",
            severity: 5,
            tags: &["xss", "anomaly"],
        },
        DefaultWafRule {
            name: "命令注入检测",
            description: "URI 或请求头中出现 shell 命令执行特征",
            expression: r#"http.request.uri.full matches "(?i)(?:;|%3b|\||%7c|\$\(|`)\s*(?:cat|curl|wget|bash|sh|nc|ncat|python|perl|chmod|id)\b""#,
            action: "block",
            severity: 5,
            tags: &["rce", "command-injection"],
        },
        DefaultWafRule {
            name: "Log4Shell 检测",
            description: "请求头中出现 JNDI 注入特征",
            expression: r#"http.request.headers["user-agent"] contains "${jndi:""#,
            action: "block",
            severity: 5,
            tags: &["rce", "log4shell"],
        },
        DefaultWafRule {
            name: "路径穿越 / 文件包含检测",
            description: "URI 中出现目录穿越或敏感文件读取特征",
            expression: r#"http.request.uri.full matches "(?i)(?:\.\./|%2e%2e%2f|%252e%252e|/etc/(?:passwd|shadow|hosts)|/proc/self|win\.ini)""#,
            action: "block",
            severity: 5,
            tags: &["lfi", "file-inclusion"],
        },
        DefaultWafRule {
            name: "SSRF 检测",
            description: "参数中引用了回环 / 内网 / 云元数据地址",
            expression: r#"http.request.uri.full matches "(?i)(?:gopher|dict|ftp|file)://|(?:https?://)?(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1\]|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)""#,
            action: "block",
            severity: 4,
            tags: &["ssrf"],
        },
        DefaultWafRule {
            name: "恶意扫描器识别",
            description: "User-Agent 命中常见扫描 / 爆破工具",
            expression: r#"user_agent matches "(?i)(?:nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|zgrab|hydra|xray|goby)""#,
            action: "block",
            severity: 4,
            tags: &["bot", "scanner", "user-agent"],
        },
        DefaultWafRule {
            name: "敏感文件探测",
            description: "探测 .git/.env 等版本控制与配置残留",
            expression: r#"http.request.uri.path matches "(?i)/\.(?:git|env|svn|hg|aws|kube|ssh|docker|ds_store)""#,
            action: "block",
            severity: 4,
            tags: &["recon", "dotfile"],
        },
        DefaultWafRule {
            name: "备份文件探测",
            description: "探测 .bak/.sql/.zip 等备份文件",
            expression: r#"http.request.uri.path matches "(?i)\.(?:bak|backup|old|orig|swp|sql|tar|tgz|zip|gz|rar|7z)$""#,
            action: "block",
            severity: 3,
            tags: &["recon", "backup"],
        },
        DefaultWafRule {
            name: "危险 HTTP 方法",
            description: "拦截 TRACE / TRACK 请求",
            expression: r#"http.request.method in {"TRACE" "TRACK"}"#,
            action: "block",
            severity: 3,
            tags: &["method"],
        },
        DefaultWafRule {
            name: "超长 URI",
            description: "URI 超过 4096 字节，通常是扫描或缓冲区探测",
            expression: r#"http.request.uri.full matches "^.{4096,}$""#,
            action: "block",
            severity: 3,
            tags: &["size"],
        },
    ]
}

/// The built-in cache rule set: static assets, HTML pages, then an explicit
/// skip for API traffic. All of them are seeded **disabled**.
pub fn cache_rules_defaults() -> Vec<DefaultCacheRule> {
    vec![
        DefaultCacheRule {
            name: "静态资源缓存",
            match_expression: r#"http.request.uri.path matches "(?i)\.(?:css|js|mjs|map|woff2?|ttf|otf|eot|ico|png|jpe?g|gif|svg|webp|avif|mp4|webm)$""#,
            edge_ttl_seconds: 7 * 24 * 3600,
            browser_ttl_seconds: 3600,
            cache_eligible: true,
            respect_origin: false,
        },
        DefaultCacheRule {
            name: "页面缓存",
            match_expression: r#"http.request.uri.path matches "(?i)(?:/|\.html?|\.txt)$""#,
            edge_ttl_seconds: 600,
            browser_ttl_seconds: 60,
            cache_eligible: true,
            respect_origin: true,
        },
        DefaultCacheRule {
            name: "API 不缓存",
            match_expression: r#"http.request.uri.path starts_with "/api/""#,
            edge_ttl_seconds: 0,
            browser_ttl_seconds: 0,
            cache_eligible: false,
            respect_origin: true,
        },
    ]
}

/// Rule mode seeded for the built-in rules of a **new site**.
///
/// "WAF enabled" has to mean the shipped rules actually enforce: seeding them
/// as `monitor` left a fresh site recording SQLi/XSS detections while the same
/// payloads reached the origin and answered 200, which reads as a broken WAF.
/// `block` is therefore the only honest default for a site whose only policy is
/// the built-in one; an operator who wants to start in observe-only can flip
/// the site mode to `monitor` in one place.
pub const NEW_SITE_WAF_RULE_MODE: &str = mode::BLOCK;

/// Rule mode used when the *restore defaults* endpoint re-adds a missing
/// built-in rule to an **existing site**.
///
/// Deliberately `monitor`: a repair action must never start blocking traffic a
/// site has been serving unfiltered, and an existing site's posture is an
/// operator decision. New sites go through [`NEW_SITE_WAF_RULE_MODE`] instead.
pub const RESTORE_WAF_RULE_MODE: &str = mode::MONITOR;

/// Creates the built-in WAF group and any missing WAF rules for `site_id`,
/// seeded in [`RESTORE_WAF_RULE_MODE`].
///
/// Returns the number of rules inserted. Existing rows are left untouched, so
/// an operator edit to a built-in rule survives a later restore.
pub async fn seed_waf_defaults(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<usize, sea_orm::DbErr> {
    seed_waf_defaults_with_mode(db, site_id, RESTORE_WAF_RULE_MODE).await
}

/// Creates the built-in WAF group and any missing WAF rules for `site_id` in
/// `rule_mode`; the single implementation behind both seeding paths.
async fn seed_waf_defaults_with_mode(
    db: &DatabaseConnection,
    site_id: Uuid,
    rule_mode: &str,
) -> Result<usize, sea_orm::DbErr> {
    debug_assert!(mode::is_valid(rule_mode), "invalid seed mode {rule_mode}");
    let timestamp = Utc::now();
    let group = ensure_waf_group(db, site_id, timestamp).await?;

    let existing: Vec<String> = rule::Entity::find()
        .filter(rule::Column::SiteId.eq(site_id))
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.name)
        .collect();

    let mut inserted = 0;
    for (index, spec) in waf_rules().into_iter().enumerate() {
        if existing.iter().any(|name| name == spec.name) {
            continue;
        }
        rule::ActiveModel {
            id: Set(Uuid::new_v4()),
            group_id: Set(Some(group)),
            site_id: Set(site_id),
            name: Set(spec.name.to_string()),
            description: Set(Some(spec.description.to_string())),
            expression: Set(spec.expression.to_string()),
            action: Set(spec.action.to_string()),
            severity: Set(spec.severity),
            tags: Set(spec.tags.iter().map(|tag| tag.to_string()).collect()),
            enabled: Set(true),
            // The seeded mode is what gates enforcement: `block` on the new-site
            // path (the rule's own `action` stays `block`), `monitor` on the
            // restore path so an existing site is never silently promoted.
            mode: Set(rule_mode.to_string()),
            priority: Set(index as i32),
            created_at: Set(timestamp),
            updated_at: Set(timestamp),
        }
        .insert(db)
        .await?;
        inserted += 1;
    }
    Ok(inserted)
}

/// Creates any missing built-in cache rules for `site_id`, disabled.
pub async fn seed_cache_defaults(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<usize, sea_orm::DbErr> {
    let timestamp = Utc::now();
    let existing: Vec<String> = cache_rules::Entity::find()
        .filter(cache_rules::Column::SiteId.eq(site_id))
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.name)
        .collect();

    let mut inserted = 0;
    for spec in cache_rules_defaults() {
        if existing.iter().any(|name| name == spec.name) {
            continue;
        }
        cache_rules::ActiveModel {
            id: Set(Uuid::new_v4()),
            site_id: Set(site_id),
            name: Set(spec.name.to_string()),
            match_expression: Set(spec.match_expression.to_string()),
            edge_ttl_seconds: Set(spec.edge_ttl_seconds),
            browser_ttl_seconds: Set(spec.browser_ttl_seconds),
            // The quota is a site-wide setting; the column stays for schema
            // compatibility and is no longer surfaced per rule.
            disk_quota_mb: Set(0),
            cache_eligible: Set(spec.cache_eligible),
            respect_origin: Set(spec.respect_origin),
            enabled: Set(false),
            created_at: Set(timestamp),
        }
        .insert(db)
        .await?;
        inserted += 1;
    }
    Ok(inserted)
}

/// Seeds both the WAF and cache defaults, used when a site is created.
///
/// The WAF rules land in [`NEW_SITE_WAF_RULE_MODE`] (`block`): this is the only
/// path that seeds a site's *initial* policy, and a brand-new site has no
/// traffic history that a blocking rule could surprise. Existing sites never
/// reach this function.
pub async fn seed_site_defaults(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<(), sea_orm::DbErr> {
    seed_waf_defaults_with_mode(db, site_id, NEW_SITE_WAF_RULE_MODE).await?;
    seed_cache_defaults(db, site_id).await?;
    Ok(())
}

/// Finds the built-in group, creating it when the site does not have one yet.
async fn ensure_waf_group(
    db: &DatabaseConnection,
    site_id: Uuid,
    timestamp: chrono::DateTime<Utc>,
) -> Result<Uuid, sea_orm::DbErr> {
    let existing = rule_groups::Entity::find()
        .filter(rule_groups::Column::SiteId.eq(site_id))
        .filter(rule_groups::Column::Name.eq(WAF_DEFAULT_GROUP_NAME))
        .one(db)
        .await?;
    if let Some(row) = existing {
        return Ok(row.id);
    }

    let id = Uuid::new_v4();
    rule_groups::ActiveModel {
        id: Set(id),
        site_id: Set(site_id),
        name: Set(WAF_DEFAULT_GROUP_NAME.to_string()),
        phase: Set("request".to_string()),
        priority: Set(0),
        enabled: Set(true),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(db)
    .await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingwaf_waf::rules::{CompiledRule, RuleAction};

    fn action_of(value: &str) -> RuleAction {
        match value {
            "block" => RuleAction::Block,
            "log" => RuleAction::Log,
            "challenge" => RuleAction::Challenge,
            "js_challenge" => RuleAction::JsChallenge,
            "allow" => RuleAction::Allow,
            other => panic!("unknown action {other}"),
        }
    }

    #[test]
    fn built_in_waf_rules_compile() {
        let rules = waf_rules();
        assert!(rules.len() >= 8, "expected a meaningful default rule set");
        for spec in rules {
            CompiledRule::compile(
                spec.name,
                spec.name,
                spec.expression,
                action_of(spec.action),
                spec.severity as u8,
                spec.tags.iter().map(|tag| tag.to_string()).collect(),
            )
            .unwrap_or_else(|err| {
                panic!(
                    "built-in rule '{}' has a bad expression: {err}",
                    spec.name
                )
            });
            assert!((1..=5).contains(&spec.severity));
        }
    }

    #[test]
    fn built_in_rules_cover_every_detection_switch() {
        let tags: Vec<&str> = waf_rules()
            .iter()
            .flat_map(|spec| spec.tags.iter().copied())
            .collect();
        // These are the tags `grpc::config::waf_config_to_proto` looks for.
        for required in ["sqli", "xss", "rce", "lfi", "ssrf", "bot"] {
            assert!(tags.contains(&required), "missing tag {required}");
        }
    }

    #[test]
    fn built_in_cache_rules_compile() {
        for spec in cache_rules_defaults() {
            pingwaf_waf::rules::parse_expression(spec.match_expression)
                .unwrap_or_else(|err| {
                    panic!(
                        "cache rule '{}' has a bad expression: {err}",
                        spec.name
                    )
                });
            assert!(spec.edge_ttl_seconds >= 0);
        }
    }

    #[test]
    fn new_sites_seed_blocking_rules_and_restore_stays_monitor() {
        use crate::models::action;

        // D13: "WAF enabled" on a fresh site has to mean enforcement.
        assert_eq!(NEW_SITE_WAF_RULE_MODE, mode::BLOCK);
        assert_eq!(RESTORE_WAF_RULE_MODE, mode::MONITOR);
        assert!(mode::is_valid(NEW_SITE_WAF_RULE_MODE));
        assert!(mode::is_valid(RESTORE_WAF_RULE_MODE));

        // Every built-in rule keeps its explicit `block` action: the seeded
        // mode is the only switch between observe and enforce, so a rule whose
        // action was `log` would stay harmless even after the flip.
        for spec in waf_rules() {
            assert_eq!(spec.action, action::BLOCK, "{}", spec.name);
        }
    }

    #[test]
    fn rule_names_are_unique() {
        let mut names: Vec<&str> =
            waf_rules().iter().map(|spec| spec.name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate built-in WAF rule name");
    }
}
