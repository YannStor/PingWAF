//! PingWAF detection engine.
//!
//! Multi-stage request inspection:
//! 1. Normalize / decode input (URL, HTML entities, path traversal collapsing).
//! 2. Stage 1 — fast path: Aho-Corasick signature scan plus libinjection-style
//!    SQLi / XSS detectors. Target ≤ 100µs.
//! 3. Stage 2 — rule engine: expression-based custom and managed rules with
//!    anomaly scoring. Target ≤ 300µs.
//! 4. Emit a [`WafVerdict`] describing the action, score and matched rules.

pub mod engine;
pub mod normalize;
pub mod rules;
pub mod score;

pub use engine::{RequestData, WafEngine, WafEngineConfig, WafMode};
pub use rules::managed::{
    managed_rule_catalogue, ManagedRuleInfo, MANAGED_RULE_IDS,
};
pub use rules::{AttackCategory, CompiledRule, RuleAction};
pub use score::{AnomalyScorer, ScoreBreakdown, ScoreClass};

use serde::{Deserialize, Serialize};

/// Detection level of the engine. Users trade coverage against false
/// positives / per-request cost: `Normal` keeps detection cheap and quiet,
/// `Strict` adds extra decoding passes, structural detectors, tighter
/// sub-score gates and activates the paranoia-level-3 rules.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum WafLevel {
    #[default]
    Normal,
    Strict,
}

impl WafLevel {
    pub fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Strict => "strict",
        }
    }

    /// Parse a config string ("normal" / "strict", case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "normal" => Some(Self::Normal),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }
}

/// Backend-technology dimension of the detection profile.
///
/// Payload families are tagged with the stack whose runtime actually parses
/// them (`aced0005` only matters to a JVM, `unserialize(` to PHP, …), so an
/// engine built for a known stack set can drop irrelevant needles and rules
/// from the hot path entirely. [`StackSet::GENERIC`] patterns apply to every
/// backend and can never be switched off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackSet(u8);

impl StackSet {
    /// Language-agnostic payloads (SQLi, XSS, traversal, …). Always active.
    pub const GENERIC: Self = Self(1 << 0);
    pub const JAVA: Self = Self(1 << 1);
    pub const PHP: Self = Self(1 << 2);
    pub const PYTHON: Self = Self(1 << 3);
    /// Node.js / JavaScript runtimes.
    pub const NODE: Self = Self(1 << 4);
    pub const ALL: Self = Self(0b0001_1111);
    pub const EMPTY: Self = Self(0);

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `true` when every stack in `other` is enabled here.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Parse a single stack name. Accepts common aliases so control-plane
    /// configs written by humans or LLMs still resolve.
    pub fn parse_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "generic" => Some(Self::GENERIC),
            "java" | "jvm" => Some(Self::JAVA),
            "php" => Some(Self::PHP),
            "python" => Some(Self::PYTHON),
            "node" | "nodejs" | "javascript" | "js" => Some(Self::NODE),
            _ => None,
        }
    }

    /// Union of every recognized name. [`StackSet::GENERIC`] is always
    /// included: language-agnostic detection is not optional.
    pub fn from_names<'a, I>(names: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut set = Self::GENERIC;
        for name in names {
            if let Some(s) = Self::parse_name(name) {
                set = set.union(s);
            }
        }
        set
    }

    /// Union of every recognized name WITHOUT forcing [`StackSet::GENERIC`].
    ///
    /// Used for monitor-only downgrade sets, where an empty set means
    /// "enforce everything" — pre-seeding GENERIC would make that impossible.
    pub fn from_names_exact<'a, I>(names: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut set = Self::EMPTY;
        for name in names {
            if let Some(s) = Self::parse_name(name) {
                set = set.union(s);
            }
        }
        set
    }

    /// `true` when any stack is shared with `other`.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Drops the [`StackSet::GENERIC`] bit: language-agnostic patterns can
    /// never be attributed to a single backend stack, so stack-scoped
    /// monitor sets must not match them.
    pub const fn except_generic(self) -> Self {
        Self(self.0 & !Self::GENERIC.0)
    }
}

impl Default for StackSet {
    /// Unconfigured deployments get the full pattern table — narrowing to a
    /// known stack set is an explicit opt-in, never a default.
    fn default() -> Self {
        Self::ALL
    }
}

/// Attack-category dimension of per-site monitor downgrades.
///
/// Categories listed here still get detected and scored (visibility is
/// preserved) but their hits can never block: the engine keeps a separate
/// "blocking" score that excludes these contributions. Mirrors the
/// [`StackSet`] style; the default is empty = enforce everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CategorySet(u16);

impl CategorySet {
    pub const SQLI: Self = Self(1 << 0);
    pub const XSS: Self = Self(1 << 1);
    pub const RCE: Self = Self(1 << 2);
    pub const LFI: Self = Self(1 << 3);
    pub const SSRF: Self = Self(1 << 4);
    pub const DESER: Self = Self(1 << 5);
    pub const CRLF: Self = Self(1 << 6);
    pub const XXE: Self = Self(1 << 7);
    pub const SSTI: Self = Self(1 << 8);
    pub const ALL: Self = Self(0b01_1111_1111);
    pub const EMPTY: Self = Self(0);

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `true` when `category` is in this monitor set.
    pub const fn contains_category(self, category: AttackCategory) -> bool {
        let bit = match category {
            AttackCategory::SqlInjection => Self::SQLI.0,
            AttackCategory::Xss => Self::XSS.0,
            AttackCategory::CommandInjection => Self::RCE.0,
            AttackCategory::PathTraversal => Self::LFI.0,
            AttackCategory::Ssrf => Self::SSRF.0,
            AttackCategory::Deserialization => Self::DESER.0,
            AttackCategory::CrlfInjection => Self::CRLF.0,
            AttackCategory::Xxe => Self::XXE.0,
            AttackCategory::TemplateInjection => Self::SSTI.0,
        };
        self.0 & bit != 0
    }

    /// Parse a single category name (serde form, case-insensitive).
    /// Unknown names return `None` so callers can warn on forward-compat
    /// drift; the set itself is built by [`CategorySet::from_names`].
    pub fn parse_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "sqli" | "sql_injection" => Some(Self::SQLI),
            "xss" => Some(Self::XSS),
            "rce" | "command_injection" => Some(Self::RCE),
            "lfi" | "path_traversal" => Some(Self::LFI),
            "ssrf" => Some(Self::SSRF),
            "deser" | "deserialization" => Some(Self::DESER),
            "crlf" | "crlf_injection" => Some(Self::CRLF),
            "xxe" => Some(Self::XXE),
            "ssti" | "template_injection" => Some(Self::SSTI),
            _ => None,
        }
    }

    /// Union of every recognized name; unrecognized names are ignored
    /// (mirrors [`StackSet::from_names`] tolerance). An empty iterator
    /// yields the empty set = enforce everything.
    pub fn from_names<'a, I>(names: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut set = Self::EMPTY;
        for name in names {
            if let Some(c) = Self::parse_name(name) {
                set = set.union(c);
            }
        }
        set
    }
}

/// Final verdict produced by [`WafEngine::inspect`].
#[derive(Debug, Clone)]
pub struct WafVerdict {
    /// Action the caller should take.
    pub action: WafAction,
    /// Aggregated anomaly score, saturating at `u8::MAX`.
    pub score: u8,
    /// Identifiers of every rule / signature that fired.
    pub matched_rules: Vec<String>,
    /// Identifier of the rule that actually produced the enforced action
    /// (block/challenge), when one exists. Detection signatures and the
    /// enforcing custom/managed rule are frequently different rules; the
    /// event pipeline records this separately so dashboards can attribute
    /// the block to the operator's rule (L3-006). `None` when the verdict
    /// came from the anomaly-score gate or the Stage-1 critical fast path.
    pub enforced_rule_id: Option<String>,
    /// Human-readable explanation suitable for logs.
    pub details: String,
    /// Structured score breakdown by attack family.
    pub breakdown: ScoreBreakdown,
}

impl WafVerdict {
    /// Build a clean "pass" verdict with no hits.
    pub fn pass() -> Self {
        Self {
            action: WafAction::Pass,
            score: 0,
            matched_rules: Vec::new(),
            enforced_rule_id: None,
            details: String::new(),
            breakdown: ScoreBreakdown::clean(),
        }
    }

    /// `true` when the request should be blocked or challenged.
    pub fn is_blocked(&self) -> bool {
        matches!(self.action, WafAction::Block | WafAction::Challenge)
    }
}

/// Action the upstream proxy should perform for the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafAction {
    /// No threat detected, allow through.
    Pass,
    /// Threat detected but engine is in monitor mode — log only.
    Monitor,
    /// Hard block.
    Block,
    /// Issue a JS / managed challenge instead of blocking outright.
    Challenge,
}
