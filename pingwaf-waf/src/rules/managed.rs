//! Managed rule sets shipped with the engine.
//!
//! These are OWASP-flavoured defaults expressed in the same expression
//! language as user-supplied rules. They are *not* exhaustive — production
//! deployments are expected to receive their bundle from the control plane —
//! but they give a fresh agent meaningful coverage out of the box.
//!
//! The set is parameterized by [`WafLevel`]: the Normal level keeps sub-score
//! gates at their low-false-positive defaults, the Strict level tightens them
//! and adds rules that are too aggressive for general traffic (e.g. blocking
//! on the RCE sub-score alone).

use crate::rules::signatures::AttackCategory;
use crate::rules::{CompiledRule, RuleAction};
use crate::{StackSet, WafLevel};

/// One managed rule template.
struct ManagedSpec {
    id: &'static str,
    name: &'static str,
    expression: String,
    action: RuleAction,
    severity: u8,
    paranoia_level: u8,
    stacks: StackSet,
    /// Only included when the engine runs at [`WafLevel::Strict`].
    strict_only: bool,
    tags: &'static [&'static str],
}

/// Expression of the php2shell (CVE-2026-109618 / CVE-2026-109619) probe rule.
///
/// The vulnerability is a use-after-free in PHP's own multipart parser, so
/// there is no payload signature to match. What is matchable is the request
/// shape `session.upload_progress` requires: a progress field on a multipart
/// body, a well-formed session id, and — for the session-file-write variant —
/// a NUL byte right after the part headers.
///
/// Both condition groups share the same prefix, so it is built once here
/// rather than copied. The media type is matched case-insensitively (`(?i)`):
/// RFC 2045 makes type/subtype case-insensitive on the wire, while the
/// `contains` operator is a byte-exact substring test, so `MULTIPART/FORM-DATA`
/// would otherwise walk straight past the rule. The progress field name stays
/// case-sensitive on purpose — PHP compares it byte-exactly against
/// `session.upload_progress.name`, so folding case would only add false
/// positives.
fn php_upload_progress_expression() -> String {
    let prefix = concat!(
        r#"http.request.body contains "PHP_SESSION_UPLOAD_PROGRESS" and "#,
        r#"http.request.headers["content-type"] matches "(?i)multipart/form-data""#,
    );
    // Plain concatenation, not `format!`: the regex bodies are full of `{n,m}`
    // quantifiers that `format!` would read as placeholders.
    [
        "(",
        prefix,
        " and (",
        r#"http.request.cookies["PHPSESSID"] matches "^[0-9A-Za-z,-]{16,256}$""#,
        r#" or http.request.body matches 'name="PHPSESSID"[^\x0d\x0a]*"#,
        r#"\x0d\x0a([^\x0d\x0a]+\x0d\x0a)*\x0d\x0a[0-9A-Za-z,-]{16,256}'"#,
        r#" or http.request.uri.query matches 'PHPSESSID=[0-9A-Za-z,-]{16,256}'))"#,
        " or (",
        prefix,
        " and ",
        r#"http.request.body matches 'Content-Disposition:\s*form-data;\s*name="[^"]+"#,
        r#"\x0d\x0a([^\x0d\x0a]+\x0d\x0a)*\x0d\x0a[\s\S]{0,32}\x00')"#,
    ]
    .concat()
}

/// Returns the built-in managed rule set for the requested level. Rules that
/// fail to parse are silently skipped (logged at warn level) so a typo in one
/// default never breaks engine startup.
pub fn default_managed_rules(level: WafLevel) -> Vec<CompiledRule> {
    let strict = level.is_strict();
    // Sub-score gates: one critical (sev-5) hit contributes 60 to a family
    // sub-score, so 60 blocks on a single critical detection at Normal. The
    // Strict level lowers the bar to 50 (one critical plus any lesser hit,
    // or two strong hits) and tightens the aggregate gate.
    let family_gate = if strict { 50 } else { 60 };
    let aggregate_gate = if strict { 70 } else { 80 };

    let specs = [
        ManagedSpec {
            id: "PINGWAF-1001",
            name: "Block admin paths from non-trusted networks",
            expression: r#"http.request.uri.path starts_with "/admin" and not ip.src in {10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8}"#.to_string(),
            action: RuleAction::Challenge,
            severity: 3,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["admin", "ip-restriction"],
        },
        ManagedSpec {
            id: "PINGWAF-1002",
            name: "Block known SQL injection anomaly scores",
            expression: format!("cf.waf.score.sqli ge {family_gate}"),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["sqli", "anomaly"],
        },
        ManagedSpec {
            id: "PINGWAF-1003",
            name: "Block known XSS anomaly scores",
            expression: format!("cf.waf.score.xss ge {family_gate}"),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["xss", "anomaly"],
        },
        ManagedSpec {
            id: "PINGWAF-1004",
            name: "Block requests with high aggregate WAF score",
            expression: format!("cf.waf.score ge {aggregate_gate}"),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["anomaly"],
        },
        ManagedSpec {
            id: "PINGWAF-1010",
            name: "Block common scanner user agents",
            expression: r#"user_agent matches "(?i)(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|zgrab)""#.to_string(),
            action: RuleAction::Block,
            severity: 4,
            paranoia_level: 2,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["scanner", "user-agent"],
        },
        ManagedSpec {
            id: "PINGWAF-1011",
            name: "Block empty user agents on non-HEAD requests",
            expression: r#"user_agent eq "" and http.request.method ne "HEAD""#.to_string(),
            action: RuleAction::Challenge,
            severity: 2,
            paranoia_level: 3,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["user-agent"],
        },
        ManagedSpec {
            id: "PINGWAF-1020",
            name: "Block sensitive dotfile probes",
            expression: r#"http.request.uri.path matches "(?i)/\\.(?:git|env|svn|aws|kube|ssh|docker)""#.to_string(),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["dotfile", "recon"],
        },
        ManagedSpec {
            id: "PINGWAF-1021",
            // Archive extensions are ordinary downloadable assets — a bare
            // `.zip`/`.tar.gz` request is a download, not a probe. Only
            // editor/DB leftovers expose source or data.
            name: "Block common backup-file probes",
            expression: r#"http.request.uri.path matches "(?i)\\.(?:bak|backup|old|swp|sql)$""#.to_string(),
            action: RuleAction::Block,
            severity: 4,
            paranoia_level: 2,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["backup", "recon"],
        },
        ManagedSpec {
            id: "PINGWAF-1030",
            name: "Block requests with HTTP method TRACE / TRACK",
            expression: r#"http.request.method in {"TRACE" "TRACK"}"#.to_string(),
            action: RuleAction::Block,
            severity: 3,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["method"],
        },
        ManagedSpec {
            id: "PINGWAF-1031",
            name: "Log unusual HTTP methods",
            expression: r#"not http.request.method in {"GET" "POST" "PUT" "PATCH" "DELETE" "HEAD" "OPTIONS"}"#.to_string(),
            action: RuleAction::Log,
            severity: 1,
            paranoia_level: 2,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["method"],
        },
        ManagedSpec {
            id: "PINGWAF-1040",
            name: "Block phpMyAdmin / wp-admin probes on non-PHP apps",
            expression: r#"http.request.uri.path matches "(?i)/(?:phpmyadmin|pma|wp-admin|wp-login\\.php|xmlrpc\\.php|administrator)""#.to_string(),
            action: RuleAction::Challenge,
            severity: 3,
            paranoia_level: 2,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["recon", "cms"],
        },
        ManagedSpec {
            id: "PINGWAF-1050",
            name: "Block Log4Shell JNDI lookups in any header",
            expression: r#"http.request.headers["user-agent"] contains "${jndi:""#.to_string(),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::JAVA,
            strict_only: false,
            tags: &["log4shell", "rce"],
        },
        ManagedSpec {
            id: "PINGWAF-1051",
            name: "Block requests with very long URIs (likely buffer / scan attempts)",
            expression: r#"http.request.uri.full matches "^.{4096,}$""#.to_string(),
            // Log, not Block: a long URI alone is weak evidence — legit deep
            // paths and encoded query strings trip the 4096 boundary, and at
            // strict this rule was the sole blocker behind 20 false positives.
            // Any real payload in the URI still scores through the signature
            // engine; this only keeps the telemetry.
            action: RuleAction::Log,
            severity: 3,
            paranoia_level: 3,
            stacks: StackSet::GENERIC,
            strict_only: false,
            tags: &["size"],
        },
        ManagedSpec {
            id: "PINGWAF-1061",
            name: "Block requests with a high RCE sub-score",
            expression: "cf.waf.score.rce ge 40".to_string(),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 1,
            stacks: StackSet::GENERIC,
            strict_only: true,
            tags: &["rce", "anomaly"],
        },
        ManagedSpec {
            id: "PINGWAF-1070",
            // php2shell (CVE-2026-109618 / CVE-2026-109619): see
            // [`php_upload_progress_expression`] for what the rule matches and
            // why the media type is folded but the field name is not.
            //
            // Strict-only, and deliberately so. Two independent switches feed
            // `http.request.body`: the site-level `advanced_mode` (which also
            // selects Strict — the control-plane path) and the plugin-level
            // `inspect_body` key (standalone TOML deployments, which may stay
            // Normal). Being Strict-only keeps the rule out of every Normal
            // engine, so a standalone deployment that turns on `inspect_body`
            // alone does not get it — an accepted coverage gap, traded for
            // keeping the false-positive surface to sites that already inspect
            // bodies.
            name: "Block PHP session upload-progress exploit probes (CVE-2026-109618/109619)",
            expression: php_upload_progress_expression(),
            action: RuleAction::Block,
            severity: 5,
            paranoia_level: 2,
            stacks: StackSet::GENERIC.union(StackSet::PHP),
            strict_only: true,
            tags: &["php", "upload-progress", "cve-2026-109618", "rce"],
        },
    ];

    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        if spec.strict_only && !strict {
            continue;
        }
        match CompiledRule::compile(
            spec.id,
            spec.name,
            &spec.expression,
            spec.action,
            spec.severity,
            spec.tags.iter().map(|s| s.to_string()).collect(),
        ) {
            Ok(mut rule) => {
                rule.paranoia_level = spec.paranoia_level;
                rule.stacks = spec.stacks;
                out.push(rule);
            },
            Err(err) => {
                tracing::warn!(rule_id = spec.id, error = %err, "skipping malformed managed rule");
            },
        }
    }
    out
}

/// Rule ids of the built-in managed set, in spec-table order. Serves as the
/// write-side whitelist for per-site "monitor this managed rule" settings.
pub const MANAGED_RULE_IDS: [&str; 15] = [
    "PINGWAF-1001",
    "PINGWAF-1002",
    "PINGWAF-1003",
    "PINGWAF-1004",
    "PINGWAF-1010",
    "PINGWAF-1011",
    "PINGWAF-1020",
    "PINGWAF-1021",
    "PINGWAF-1030",
    "PINGWAF-1031",
    "PINGWAF-1040",
    "PINGWAF-1050",
    "PINGWAF-1051",
    "PINGWAF-1061",
    "PINGWAF-1070",
];

/// Dashboard-facing metadata for one managed rule.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ManagedRuleInfo {
    pub id: String,
    pub name: String,
    pub action: String,
    pub severity: u8,
    pub tags: Vec<String>,
    pub stacks: Vec<String>,
    /// Attack family declared by the rule's tags (`sqli`/`xss`/`rce`), or
    /// `None` for policy rules that no category downgrade applies to.
    pub category: Option<String>,
    /// `true` when the rule only exists at the Strict level.
    pub strict_only: bool,
}

fn stack_names(stacks: StackSet) -> Vec<String> {
    const NAMES: [(u8, &str); 5] = [
        (StackSet::GENERIC.bits(), "generic"),
        (StackSet::JAVA.bits(), "java"),
        (StackSet::PHP.bits(), "php"),
        (StackSet::PYTHON.bits(), "python"),
        (StackSet::NODE.bits(), "node"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| stacks.bits() & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

/// Flatten the built-in rule set into dashboard-facing metadata. `level`
/// decides which rules exist (Strict adds the strict-only gates); the
/// `strict_only` flag is derived from the Normal-level set difference.
pub fn managed_rule_catalogue(level: WafLevel) -> Vec<ManagedRuleInfo> {
    let normal_rules = default_managed_rules(WafLevel::Normal);
    let normal_ids: std::collections::HashSet<&str> =
        normal_rules.iter().map(|r| r.id.as_str()).collect();
    default_managed_rules(level)
        .into_iter()
        .map(|r| {
            let category =
                managed_rule_category(&r).map(|c| c.as_str().to_string());
            ManagedRuleInfo {
                strict_only: !normal_ids.contains(r.id.as_str()),
                id: r.id,
                name: r.name,
                action: r.action.as_str().to_string(),
                severity: r.severity,
                tags: r.tags,
                stacks: stack_names(r.stacks),
                category,
            }
        })
        .collect()
}

/// Map a managed rule onto the attack category its tags declare, so
/// per-site monitor downgrades can apply to literal-expression rules.
/// Score-gate rules (family / aggregate thresholds) don't need this — their
/// expression input already excludes downgraded hits — but the mapping is
/// harmless for them and future literal rules with family tags pick the
/// semantics up automatically. Rules without a family tag (recon, method
/// policy, …) return `None` and are never downgraded.
pub(crate) fn managed_rule_category(
    rule: &CompiledRule,
) -> Option<AttackCategory> {
    const FAMILY_TAGS: [(&str, AttackCategory); 3] = [
        ("sqli", AttackCategory::SqlInjection),
        ("xss", AttackCategory::Xss),
        ("rce", AttackCategory::CommandInjection),
    ];
    FAMILY_TAGS
        .iter()
        .find(|(tag, _)| rule.tags.iter().any(|t| t == tag))
        .map(|(_, category)| *category)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::expression::{evaluate, EvalContext};

    /// An evaluation context that only carries scores; expressions under
    /// test read nothing else.
    fn score_ctx(
        sqli: u8,
        xss: u8,
        rce: u8,
        total: u32,
    ) -> EvalContext<'static> {
        EvalContext {
            method: "GET",
            path: "/",
            full_uri: "/",
            host: "",
            user_agent: "test",
            body: None,
            headers: &[],
            cookies: &[],
            client_ip: "",
            parsed_ip: None,
            country_code: None,
            ssl: false,
            waf_score: total,
            waf_score_sqli: sqli,
            waf_score_xss: xss,
            waf_score_rce: rce,
        }
    }

    fn find<'r>(rules: &'r [CompiledRule], id: &str) -> &'r CompiledRule {
        rules
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} missing"))
    }

    /// Evaluation context for body/header/cookie-oriented rules.
    fn request_ctx<'a>(
        body: Option<&'a str>,
        headers: &'a [(String, String)],
        cookies: &'a [(String, String)],
    ) -> EvalContext<'a> {
        EvalContext {
            body,
            headers,
            cookies,
            ..score_ctx(0, 0, 0, 0)
        }
    }

    fn content_type_header() -> Vec<(String, String)> {
        vec![(
            "content-type".to_string(),
            "multipart/form-data; boundary=----Boundary".to_string(),
        )]
    }

    fn session_cookie() -> Vec<(String, String)> {
        vec![(
            "PHPSESSID".to_string(),
            "abcdefghijklmnopqrstuvwxyz".to_string(),
        )]
    }

    #[test]
    fn all_managed_rules_compile() {
        let rules = default_managed_rules(WafLevel::Normal);
        assert!(rules.len() >= 10, "expected at least 10 managed rules");
        for r in &rules {
            assert!(!r.id.is_empty());
            assert!((1..=5).contains(&r.severity));
            assert!((1..=4).contains(&r.paranoia_level));
        }
    }

    #[test]
    fn strict_level_tightens_gates() {
        let normal = default_managed_rules(WafLevel::Normal);
        let strict = default_managed_rules(WafLevel::Strict);

        // A 55-point family sub-score sits between the Strict gate (50) and
        // the Normal gate (60).
        let ctx = score_ctx(55, 0, 0, 55);
        assert!(!evaluate(&find(&normal, "PINGWAF-1002").expression, &ctx));
        assert!(evaluate(&find(&strict, "PINGWAF-1002").expression, &ctx));

        // An aggregate of 75 sits between the Strict gate (70) and the
        // Normal gate (80).
        let ctx = score_ctx(0, 0, 0, 75);
        assert!(!evaluate(&find(&normal, "PINGWAF-1004").expression, &ctx));
        assert!(evaluate(&find(&strict, "PINGWAF-1004").expression, &ctx));

        // The RCE sub-score gate exists only at Strict.
        assert!(normal.iter().all(|r| r.id != "PINGWAF-1061"));
        assert!(evaluate(
            &find(&strict, "PINGWAF-1061").expression,
            &score_ctx(0, 0, 48, 48)
        ));
    }

    #[test]
    fn log4shell_rule_is_java_scoped() {
        let rules = default_managed_rules(WafLevel::Normal);
        let r = find(&rules, "PINGWAF-1050");
        assert_eq!(r.stacks, StackSet::JAVA);
    }

    #[test]
    fn catalogue_covers_every_managed_rule_id() {
        // The strict-level catalogue is exhaustive; the Normal-level one
        // omits exactly the strict-only rules.
        let strict = managed_rule_catalogue(WafLevel::Strict);
        let normal = managed_rule_catalogue(WafLevel::Normal);
        assert_eq!(strict.len(), MANAGED_RULE_IDS.len());
        for (entry, id) in strict.iter().zip(MANAGED_RULE_IDS.iter()) {
            assert_eq!(entry.id, *id);
            assert!(!entry.name.is_empty());
            assert!((1..=5).contains(&entry.severity));
        }
        assert_eq!(normal.len(), MANAGED_RULE_IDS.len() - 2);

        // `strict_only` is exactly the Normal-level set difference.
        let normal_ids: std::collections::HashSet<&str> =
            normal.iter().map(|e| e.id.as_str()).collect();
        for entry in &strict {
            assert_eq!(
                entry.strict_only,
                !normal_ids.contains(entry.id.as_str()),
                "{}",
                entry.id
            );
        }
        assert!(strict.iter().any(|e| e.strict_only));
        assert!(strict.iter().all(|e| {
            e.strict_only
                == matches!(e.id.as_str(), "PINGWAF-1061" | "PINGWAF-1070")
        }));
    }

    #[test]
    fn catalogue_categories_match_family_tags() {
        // Exactly the family-tagged rules carry a category; the expected
        // values are spelled out so a future tag edit surfaces here.
        let strict = managed_rule_catalogue(WafLevel::Strict);
        let by_id = |id: &str| {
            strict
                .iter()
                .find(|e| e.id == id)
                .unwrap_or_else(|| panic!("{id} missing from catalogue"))
        };
        for (id, category) in [
            ("PINGWAF-1002", "sqli"),
            ("PINGWAF-1003", "xss"),
            ("PINGWAF-1050", "rce"),
            ("PINGWAF-1061", "rce"),
            ("PINGWAF-1070", "rce"),
        ] {
            assert_eq!(by_id(id).category.as_deref(), Some(category), "{id}");
        }

        let family_ids = [
            "PINGWAF-1002",
            "PINGWAF-1003",
            "PINGWAF-1050",
            "PINGWAF-1061",
            "PINGWAF-1070",
        ];
        for entry in &strict {
            assert_eq!(
                entry.category.is_some(),
                family_ids.contains(&entry.id.as_str()),
                "{}",
                entry.id
            );
        }
    }

    #[test]
    fn php_upload_progress_rule_blocks_session_probe() {
        let strict = default_managed_rules(WafLevel::Strict);
        let rule = find(&strict, "PINGWAF-1070");
        assert_eq!(rule.action, RuleAction::Block);
        assert_eq!(rule.severity, 5);
        assert_eq!(rule.paranoia_level, 2);
        assert_eq!(
            rule.stacks,
            StackSet::GENERIC.union(StackSet::PHP),
            "PHP-scoped, generic payloads kept"
        );
        // Strict-only: the rule is absent from every Normal engine (see the
        // spec comment for why that is a deliberate trade-off).
        assert!(
            default_managed_rules(WafLevel::Normal)
                .iter()
                .all(|r| r.id != "PINGWAF-1070")
        );

        let ct = content_type_header();
        let cookie = session_cookie();
        let progress = concat!(
            "------Boundary\r\n",
            "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"",
            "\r\n\r\nx\r\n------Boundary\r\n",
            "Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"",
            "\r\n\r\nAAAA\r\n------Boundary--\r\n",
        );

        // 1. progress field + a well-formed session id in the cookie.
        assert!(evaluate(
            &rule.expression,
            &request_ctx(Some(progress), &ct, &cookie)
        ));

        // 2. the same session id carried as a multipart field instead.
        let as_field = concat!(
            "------Boundary\r\n",
            "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"",
            "\r\n\r\nx\r\n------Boundary\r\n",
            "Content-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n",
            "abcdefghijklmnopqrstuvwxyz\r\n------Boundary--\r\n",
        );
        assert!(evaluate(
            &rule.expression,
            &request_ctx(Some(as_field), &ct, &[])
        ));

        // 3. session-file write shape: NUL within 32 bytes of the part headers.
        let nul = concat!(
            "------Boundary\r\n",
            "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"",
            "\r\n\r\n<?php echo 1;?>\u{0}\r\n------Boundary--\r\n",
        );
        assert!(evaluate(
            &rule.expression,
            &request_ctx(Some(nul), &ct, &cookie)
        ));

        // 4. header stage: no body yet, so the operand is Missing.
        assert!(!evaluate(
            &rule.expression,
            &request_ctx(None, &ct, &cookie)
        ));

        // 5. progress field with neither a session id nor the NUL shape.
        assert!(!evaluate(
            &rule.expression,
            &request_ctx(Some(progress), &ct, &[])
        ));

        // 6. an upload that carries no progress field never reaches the
        // second conjunct.
        let benign = concat!(
            "------Boundary\r\n",
            "Content-Disposition: form-data; name=\"file\"; filename=\"p.jpg\"\r\n",
            "Content-Type: image/jpeg\r\n\r\nJFIF\r\n------Boundary--\r\n",
        );
        assert!(!evaluate(
            &rule.expression,
            &request_ctx(Some(benign), &ct, &cookie)
        ));

        // 7. the media type is matched case-insensitively: `contains` would
        // let `MULTIPART/FORM-DATA` (legal on the wire) walk past.
        let uppercase_ct = vec![(
            "content-type".to_string(),
            "MULTIPART/FORM-DATA; boundary=----Boundary".to_string(),
        )];
        assert!(evaluate(
            &rule.expression,
            &request_ctx(Some(progress), &uppercase_ct, &cookie)
        ));

        // 8. a non-multipart body is never the upload-progress shape.
        let urlencoded_ct = vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )];
        assert!(!evaluate(
            &rule.expression,
            &request_ctx(Some(progress), &urlencoded_ct, &cookie)
        ));

        // 9. a session id shorter than PHP's minimum is not the shape either.
        let short_cookie = vec![("PHPSESSID".to_string(), "abc".to_string())];
        assert!(!evaluate(
            &rule.expression,
            &request_ctx(Some(progress), &ct, &short_cookie)
        ));

        // 10. accepted false positive: an application that genuinely drives
        // PHP's upload-progress feature looks identical to the probe — the
        // rule cannot tell them apart, which is why per-rule monitor exists.
        assert!(evaluate(
            &rule.expression,
            &request_ctx(Some(progress), &ct, &cookie)
        ));
    }
}
