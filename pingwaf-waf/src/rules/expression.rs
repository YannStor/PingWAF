//! Cloudflare-style expression parser and evaluator.
//!
//! Grammar (recursive descent):
//!
//! ```text
//! expr     := or_expr
//! or_expr  := and_expr ("or" and_expr)*
//! and_expr := unary ("and" unary)*
//! unary    := "not" unary | primary
//! primary  := "(" expr ")" | comparison
//! comparison := field op value
//! field    := IDENT ( "[" STRING "]" )?
//! op       := "eq" | "ne" | "contains" | "not contains" | "matches" | "not matches"
//!           | "in" | "not in" | "starts_with" | "ends_with"
//!           | "lt" | "gt" | "le" | "ge"
//! value    := STRING | NUMBER | BOOL | "{" (STRING|NUMBER)+ "}"
//! ```

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Result};
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use tracing::warn;

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Expression {
    Field {
        field: Field,
        operator: Operator,
        value: Value,
    },
    And(Box<Expression>, Box<Expression>),
    Or(Box<Expression>, Box<Expression>),
    Not(Box<Expression>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub kind: FieldKind,
    /// Header / cookie name when `kind` is `RequestHeader` (or similar).
    pub index: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    RequestPath,
    RequestUriFull,
    RequestQuery,
    RequestMethod,
    RequestHeader,
    RequestCookie,
    RequestBody,
    Host,
    IpSrc,
    IpSrcCountry,
    WafScore,
    WafScoreSqli,
    WafScoreXss,
    WafScoreRce,
    Ssl,
    UserAgent,
    Unknown(String),
}

impl FieldKind {
    fn from_path(path: &str) -> Self {
        // Case-insensitive lookup against the canonical field names.
        let lower = path.to_ascii_lowercase();
        match lower.as_str() {
            "http.request.uri.path" | "request.path" | "uri.path" => {
                FieldKind::RequestPath
            },
            "http.request.uri.full" | "http.request.uri" | "request.uri" => {
                FieldKind::RequestUriFull
            },
            "http.request.uri.query"
            | "request.query"
            | "http.request.uri.args" => FieldKind::RequestQuery,
            "http.request.method" | "request.method" => {
                FieldKind::RequestMethod
            },
            "http.request.headers" | "http.request.header" => {
                FieldKind::RequestHeader
            },
            "http.request.cookies" | "http.request.cookie" => {
                FieldKind::RequestCookie
            },
            "http.request.body" | "request.body" => FieldKind::RequestBody,
            "http.host" | "host" => FieldKind::Host,
            "ip.src" | "client.ip" => FieldKind::IpSrc,
            "ip.src.country" | "geo.country" => FieldKind::IpSrcCountry,
            "cf.waf.score" | "waf.score" => FieldKind::WafScore,
            "cf.waf.score.sqli" | "waf.score.sqli" => FieldKind::WafScoreSqli,
            "cf.waf.score.xss" | "waf.score.xss" => FieldKind::WafScoreXss,
            "cf.waf.score.rce" | "waf.score.rce" => FieldKind::WafScoreRce,
            "ssl" | "https" => FieldKind::Ssl,
            "user_agent" | "http.user_agent" | "http.useragent" => {
                FieldKind::UserAgent
            },
            other => FieldKind::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Eq,
    Ne,
    Contains,
    NotContains,
    Matches,
    NotMatches,
    In,
    NotIn,
    StartsWith,
    EndsWith,
    Lt,
    Gt,
    Le,
    Ge,
}

impl Operator {
    fn is_negated(self) -> bool {
        matches!(
            self,
            Operator::Ne
                | Operator::NotContains
                | Operator::NotMatches
                | Operator::NotIn
        )
    }
}

#[derive(Clone)]
pub enum Value {
    Str(String),
    Num(i64),
    Bool(bool),
    Set(Vec<String>),
    /// Set of CIDRs, produced when an `in {...}` value is bound to an IP field.
    CidrSet(Vec<IpNet>),
    /// Compiled regex plus the original pattern (kept for Debug / logging).
    Regex(Box<Regex>, String),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(s) => write!(f, "Str({:?})", s),
            Value::Num(n) => write!(f, "Num({})", n),
            Value::Bool(b) => write!(f, "Bool({})", b),
            Value::Set(v) => f.debug_tuple("Set").field(v).finish(),
            Value::CidrSet(v) => f.debug_tuple("CidrSet").field(v).finish(),
            Value::Regex(_, p) => write!(f, "Regex({:?})", p),
        }
    }
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Str(String),
    Num(i64),
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Eof,
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(16);
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'(' => {
                out.push(Token::LParen);
                i += 1;
            },
            b')' => {
                out.push(Token::RParen);
                i += 1;
            },
            b'[' => {
                out.push(Token::LBracket);
                i += 1;
            },
            b']' => {
                out.push(Token::RBracket);
                i += 1;
            },
            b'{' => {
                out.push(Token::LBrace);
                i += 1;
            },
            b'}' => {
                out.push(Token::RBrace);
                i += 1;
            },
            b'"' | b'\'' => {
                let quote = c;
                let mut j = i + 1;
                let mut buf = String::new();
                let mut closed = false;
                while j < bytes.len() {
                    let b = bytes[j];
                    if b == b'\\' && j + 1 < bytes.len() {
                        let esc = bytes[j + 1];
                        match esc {
                            b'n' => buf.push('\n'),
                            b't' => buf.push('\t'),
                            b'r' => buf.push('\r'),
                            b'\\' => buf.push('\\'),
                            b'"' => buf.push('"'),
                            b'\'' => buf.push('\''),
                            // Unknown escape: preserve verbatim so users can
                            // write regex like `\.` without doubling.
                            _ => {
                                buf.push('\\');
                                let w = utf8_width(esc);
                                buf.push_str(&input[j + 1..j + 1 + w]);
                                j += 1 + w;
                                continue;
                            },
                        }
                        j += 2;
                        continue;
                    }
                    if b == quote {
                        closed = true;
                        j += 1;
                        break;
                    }
                    // Bytes may be part of a multi-byte UTF-8 char; copy via str slice.
                    let width = utf8_width(b);
                    buf.push_str(&input[j..j + width]);
                    j += width;
                }
                if !closed {
                    bail!("unterminated string literal in expression");
                }
                out.push(Token::Str(buf));
                i = j;
            },
            b'-' if i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() => {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let s = &input[start..i];
                let n = i64::from_str(s)
                    .map_err(|e| anyhow!("invalid number {:?}: {}", s, e))?;
                out.push(Token::Num(n));
            },
            // Word: alphanumeric plus the punctuation that can appear inside
            // dotted field paths (`http.request.uri.path`), CIDR literals
            // (`10.0.0.0/8`) and IPv6 addresses (`2001:db8::/32`). We try to
            // parse the result as an integer first so plain numbers stay
            // `Token::Num`.
            b if b.is_ascii_alphanumeric() || b == b'_' => {
                let start = i;
                while i < bytes.len() {
                    let c2 = bytes[i];
                    if c2.is_ascii_alphanumeric()
                        || c2 == b'_'
                        || c2 == b'.'
                        || c2 == b'/'
                        || c2 == b':'
                    {
                        i += 1;
                    } else {
                        break;
                    }
                }
                let word = &input[start..i];
                if let Ok(n) = i64::from_str(word) {
                    out.push(Token::Num(n));
                } else {
                    out.push(Token::Ident(word.to_string()));
                }
            },
            other => {
                bail!("unexpected character {:?} in expression", other as char)
            },
        }
    }
    out.push(Token::Eof);
    Ok(out)
}

fn utf8_width(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser {
    toks: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> &Token {
        self.toks.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn next(&mut self) -> Token {
        let t = self.toks.get(self.pos).cloned().unwrap_or(Token::Eof);
        if self.pos < self.toks.len() {
            self.pos += 1;
        }
        t
    }

    fn expect_ident(&mut self) -> Result<String> {
        match self.next() {
            Token::Ident(s) => Ok(s),
            other => bail!("expected identifier, got {:?}", other),
        }
    }

    fn parse_or(&mut self) -> Result<Expression> {
        let mut lhs = self.parse_and()?;
        while let Token::Ident(s) = self.peek().clone() {
            if s.eq_ignore_ascii_case("or") {
                self.next();
                let rhs = self.parse_and()?;
                lhs = Expression::Or(Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expression> {
        let mut lhs = self.parse_unary()?;
        while let Token::Ident(s) = self.peek().clone() {
            if s.eq_ignore_ascii_case("and") {
                self.next();
                let rhs = self.parse_unary()?;
                lhs = Expression::And(Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expression> {
        if let Token::Ident(s) = self.peek().clone() {
            if s.eq_ignore_ascii_case("not") {
                // Disambiguate `not <expr>` from `field not contains "x"`:
                // if `not` is followed by another operator keyword we leave it
                // for the comparison parser. Here we are at the start of a
                // clause, so it must be unary.
                self.next();
                let inner = self.parse_unary()?;
                return Ok(Expression::Not(Box::new(inner)));
            }
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expression> {
        match self.peek().clone() {
            Token::LParen => {
                self.next();
                let e = self.parse_or()?;
                if self.next() != Token::RParen {
                    bail!("expected ')' in expression");
                }
                Ok(e)
            },
            Token::Ident(_) => self.parse_comparison(),
            other => bail!("unexpected token {:?} in expression", other),
        }
    }

    fn parse_comparison(&mut self) -> Result<Expression> {
        let path = self.expect_ident()?;
        let mut kind = FieldKind::from_path(&path);
        let mut index = None;
        // Console field aliases that denote a specific request header.
        if let FieldKind::Unknown(name) = &kind {
            match name.as_str() {
                "http.referer" => {
                    kind = FieldKind::RequestHeader;
                    index = Some("referer".to_string());
                },
                "http.cookie" => {
                    kind = FieldKind::RequestHeader;
                    index = Some("cookie".to_string());
                },
                _ => {},
            }
        }
        if self.peek() == &Token::LBracket {
            self.next();
            match self.next() {
                Token::Str(s) => index = Some(s),
                other => bail!("expected string after '[', got {:?}", other),
            }
            if self.next() != Token::RBracket {
                bail!("expected ']' after header name");
            }
        }
        let field = Field {
            kind: kind.clone(),
            index: index.clone(),
        };

        let operator = self.parse_operator()?;
        let value = self.parse_value(&field.kind, operator)?;
        Ok(Expression::Field {
            field,
            operator,
            value,
        })
    }

    fn parse_operator(&mut self) -> Result<Operator> {
        let tok = self.next();
        let word = match tok {
            Token::Ident(s) => s,
            other => bail!("expected operator, got {:?}", other),
        };
        let lower = word.to_ascii_lowercase();
        let op = match lower.as_str() {
            "eq" | "=" | "==" => Operator::Eq,
            "ne" | "neq" | "!=" => Operator::Ne,
            "contains" => Operator::Contains,
            "not_contains" => Operator::NotContains,
            "matches" => Operator::Matches,
            "in" => Operator::In,
            "starts_with" | "startswith" => Operator::StartsWith,
            "ends_with" | "endswith" => Operator::EndsWith,
            "lt" | "<" => Operator::Lt,
            "gt" | ">" => Operator::Gt,
            "le" | "<=" => Operator::Le,
            "ge" | ">=" => Operator::Ge,
            "not" => {
                // Two-word operator: `not contains`, `not in`, `not matches`.
                let next = match self.next() {
                    Token::Ident(s) => s.to_ascii_lowercase(),
                    other => {
                        bail!("expected operator after 'not', got {:?}", other)
                    },
                };
                match next.as_str() {
                    "contains" => Operator::NotContains,
                    "in" => Operator::NotIn,
                    "matches" => Operator::NotMatches,
                    other => {
                        bail!("unsupported negated operator 'not {}'", other)
                    },
                }
            },
            other => bail!("unknown operator '{}'", other),
        };
        Ok(op)
    }

    fn parse_value(&mut self, kind: &FieldKind, op: Operator) -> Result<Value> {
        match self.next() {
            Token::Str(s) => finish_scalar(kind, op, Value::Str(s)),
            Token::Num(n) => finish_scalar(kind, op, Value::Num(n)),
            Token::Ident(s) => {
                // Allow bare booleans (`ssl eq true`).
                let lower = s.to_ascii_lowercase();
                let v = match lower.as_str() {
                    "true" => Value::Bool(true),
                    "false" => Value::Bool(false),
                    _ => Value::Str(s),
                };
                finish_scalar(kind, op, v)
            },
            Token::LBrace => {
                let mut items: Vec<Value> = Vec::new();
                loop {
                    match self.peek().clone() {
                        Token::RBrace => {
                            self.next();
                            break;
                        },
                        Token::Eof => bail!(
                            "unterminated set literal (missing closing brace)"
                        ),
                        _ => {},
                    }
                    match self.next() {
                        Token::Str(s) => items.push(Value::Str(s)),
                        Token::Num(n) => items.push(Value::Num(n)),
                        Token::Ident(s) => items.push(Value::Str(s)),
                        other => {
                            bail!("unexpected token {:?} inside set", other)
                        },
                    }
                }
                let value = if matches!(kind, FieldKind::IpSrc)
                    && matches!(
                        op,
                        Operator::In
                            | Operator::NotIn
                            | Operator::Eq
                            | Operator::Ne
                    ) {
                    let mut cidrs = Vec::with_capacity(items.len());
                    for it in &items {
                        if let Value::Str(s) = it {
                            cidrs.push(parse_cidr(s)?);
                        }
                    }
                    Value::CidrSet(cidrs)
                } else {
                    let strs = items
                        .into_iter()
                        .map(|v| match v {
                            Value::Str(s) => s,
                            Value::Num(n) => n.to_string(),
                            Value::Bool(b) => b.to_string(),
                            _ => String::new(),
                        })
                        .collect();
                    Value::Set(strs)
                };
                Ok(value)
            },
            other => bail!("expected value, got {:?}", other),
        }
    }
}

fn finish_scalar(kind: &FieldKind, op: Operator, v: Value) -> Result<Value> {
    if matches!(op, Operator::Matches | Operator::NotMatches) {
        let pattern = match &v {
            Value::Str(s) => s.clone(),
            other => {
                bail!("'matches' requires a string pattern, got {:?}", other)
            },
        };
        // `regex`'s default size limit is far above what a WAF rule needs.
        // Cap the compiled automaton so one pathological operator/pattern
        // cannot pin tens of MB per profile. A pattern that genuinely needs
        // more falls back to the old constructor; this keeps existing rule
        // semantics instead of silently dropping the rule.
        const MAX_REGEX_SIZE: usize = 4 * 1024 * 1024;
        let re = match RegexBuilder::new(&pattern)
            .size_limit(MAX_REGEX_SIZE)
            .dfa_size_limit(MAX_REGEX_SIZE)
            .build()
        {
            Ok(re) => re,
            Err(err) => {
                warn!(
                    pattern = %pattern,
                    error = %err,
                    "regex exceeded the WAF size limit; using the default builder"
                );
                Regex::new(&pattern)?
            },
        };
        return Ok(Value::Regex(Box::new(re), pattern));
    }
    if matches!(kind, FieldKind::IpSrc)
        && matches!(
            op,
            Operator::Eq | Operator::Ne | Operator::In | Operator::NotIn
        )
    {
        if let Value::Str(s) = &v {
            return Ok(Value::CidrSet(vec![parse_cidr(s)?]));
        }
    }
    Ok(v)
}

fn parse_cidr(s: &str) -> Result<IpNet> {
    if let Ok(net) = IpNet::from_str(s) {
        return Ok(net);
    }
    if let Ok(addr) = IpAddr::from_str(s) {
        return Ok(IpNet::from(addr));
    }
    bail!("invalid IP or CIDR: {:?}", s)
}

/// Compiling an expression also builds its regex automata. Control-plane
/// pushes often carry the same custom rule to many sites, so cache the
/// immutable AST by expression text (never by rule id/name) to avoid
/// re-parsing and rebuilding regexes per site. The cache is cleared when it
/// reaches the cap rather than growing with config churn.
const MAX_CACHED_EXPRESSIONS: usize = 512;

fn expression_cache() -> &'static Mutex<HashMap<String, Expression>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Expression>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Parse a Cloudflare-style expression string.
pub fn parse_expression(input: &str) -> Result<Expression> {
    let cache = expression_cache();
    {
        let cache = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(expression) = cache.get(input) {
            return Ok(expression.clone());
        }
    }

    let toks = tokenize(input)?;
    let mut p = Parser { toks, pos: 0 };
    let e = p.parse_or()?;
    if p.peek() != &Token::Eof {
        bail!("trailing tokens after expression at position {}", p.pos);
    }

    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if cache.len() >= MAX_CACHED_EXPRESSIONS {
        cache.clear();
    }
    cache.insert(input.to_string(), e.clone());
    Ok(e)
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Per-request context for [`evaluate`]. Built once by the engine after
/// normalization and Stage 1 scoring.
///
/// Every string borrows the normalized request, so building the context
/// allocates nothing on the hot path.
#[derive(Debug, Clone, Copy)]
pub struct EvalContext<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub full_uri: &'a str,
    pub host: &'a str,
    pub user_agent: &'a str,
    pub body: Option<&'a str>,
    /// Lower-cased header names paired with original-cased values.
    pub headers: &'a [(String, String)],
    pub cookies: &'a [(String, String)],
    pub client_ip: &'a str,
    pub parsed_ip: Option<IpAddr>,
    pub country_code: Option<&'a str>,
    pub ssl: bool,
    pub waf_score: u32,
    pub waf_score_sqli: u8,
    pub waf_score_xss: u8,
    pub waf_score_rce: u8,
}

impl EvalContext<'_> {
    pub fn header(&self, name: &str) -> Option<&str> {
        let needle = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == needle)
            .map(|(_, v)| v.as_str())
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Resolved value of a field at evaluation time.
#[derive(Debug, Clone, Copy)]
enum FieldValue<'a> {
    Str(&'a str),
    Num(i64),
    Bool(bool),
    Ip(Option<IpAddr>),
    Missing,
}

fn resolve_field<'a>(field: &Field, ctx: &'a EvalContext) -> FieldValue<'a> {
    match &field.kind {
        FieldKind::RequestPath => FieldValue::Str(ctx.path),
        FieldKind::RequestUriFull => FieldValue::Str(ctx.full_uri),
        FieldKind::RequestQuery => match ctx.full_uri.split_once('?') {
            Some((_, q)) => FieldValue::Str(q),
            None => FieldValue::Missing,
        },
        FieldKind::RequestMethod => FieldValue::Str(ctx.method),
        FieldKind::RequestBody => match ctx.body {
            Some(b) => FieldValue::Str(b),
            None => FieldValue::Missing,
        },
        FieldKind::Host => FieldValue::Str(ctx.host),
        FieldKind::UserAgent => FieldValue::Str(ctx.user_agent),
        FieldKind::IpSrc => FieldValue::Ip(ctx.parsed_ip),
        FieldKind::IpSrcCountry => match ctx.country_code {
            Some(c) => FieldValue::Str(c),
            None => FieldValue::Missing,
        },
        FieldKind::Ssl => FieldValue::Bool(ctx.ssl),
        FieldKind::WafScore => FieldValue::Num(ctx.waf_score as i64),
        FieldKind::WafScoreSqli => FieldValue::Num(ctx.waf_score_sqli as i64),
        FieldKind::WafScoreXss => FieldValue::Num(ctx.waf_score_xss as i64),
        FieldKind::WafScoreRce => FieldValue::Num(ctx.waf_score_rce as i64),
        FieldKind::RequestHeader => {
            match field.index.as_deref().and_then(|n| ctx.header(n)) {
                Some(v) => FieldValue::Str(v),
                None => FieldValue::Missing,
            }
        },
        FieldKind::RequestCookie => {
            match field.index.as_deref().and_then(|n| ctx.cookie(n)) {
                Some(v) => FieldValue::Str(v),
                None => FieldValue::Missing,
            }
        },
        FieldKind::Unknown(_) => FieldValue::Missing,
    }
}

/// Evaluate `expr` against `ctx`. Unknown fields evaluate to `false` for
/// positive operators and `true` for negated ones, mirroring Cloudflare's
/// "missing field never matches" semantics.
pub fn evaluate(expr: &Expression, ctx: &EvalContext) -> bool {
    match expr {
        Expression::And(a, b) => evaluate(a, ctx) && evaluate(b, ctx),
        Expression::Or(a, b) => evaluate(a, ctx) || evaluate(b, ctx),
        Expression::Not(inner) => !evaluate(inner, ctx),
        Expression::Field {
            field,
            operator,
            value,
        } => {
            let fv = resolve_field(field, ctx);
            apply_operator(fv, *operator, value)
        },
    }
}

fn apply_operator(fv: FieldValue<'_>, op: Operator, value: &Value) -> bool {
    // Missing fields satisfy only negated operators (Cloudflare semantics).
    if matches!(fv, FieldValue::Missing) {
        return op.is_negated();
    }

    // IP fields against CidrSet or single IP literal.
    if let FieldValue::Ip(Some(ip)) = fv {
        let positive = match value {
            Value::CidrSet(nets) => nets.iter().any(|n| n.contains(&ip)),
            Value::Str(s) => match IpAddr::from_str(s) {
                Ok(a) => a == ip,
                Err(_) => {
                    IpNet::from_str(s).map(|n| n.contains(&ip)).unwrap_or(false)
                },
            },
            Value::Set(items) => items.iter().any(|i| {
                IpAddr::from_str(i)
                    .map(|a| a == ip)
                    .or_else(|_| IpNet::from_str(i).map(|n| n.contains(&ip)))
                    .unwrap_or(false)
            }),
            _ => false,
        };
        return negate_if(op, positive);
    }
    if matches!(fv, FieldValue::Ip(None)) {
        return op.is_negated();
    }

    // Boolean fields.
    if let FieldValue::Bool(b) = fv {
        let expected = match value {
            Value::Bool(e) => *e,
            Value::Str(s) => s.eq_ignore_ascii_case("true"),
            Value::Num(n) => *n != 0,
            _ => false,
        };
        return negate_if(op, b == expected);
    }

    // Numeric fields.
    if let FieldValue::Num(n) = fv {
        match value {
            Value::Num(m) => {
                let m = *m;
                let positive = match op {
                    Operator::Eq | Operator::Ne => n == m,
                    Operator::Lt => n < m,
                    Operator::Le => n <= m,
                    Operator::Gt => n > m,
                    Operator::Ge => n >= m,
                    Operator::In | Operator::NotIn => n == m,
                    _ => false,
                };
                return negate_if(op, positive);
            },
            Value::Str(s) => {
                if let Ok(m) = i64::from_str(s) {
                    return apply_operator(
                        FieldValue::Num(n),
                        op,
                        &Value::Num(m),
                    );
                }
                return op.is_negated();
            },
            Value::Set(items) => {
                let ns = n.to_string();
                let positive = items.contains(&ns);
                return negate_if(op, positive);
            },
            _ => return op.is_negated(),
        }
    }

    // String fields.
    let raw = match fv {
        FieldValue::Str(s) => s,
        _ => return op.is_negated(),
    };

    match (op, value) {
        (Operator::Eq, Value::Str(v)) => raw == v,
        (Operator::Ne, Value::Str(v)) => raw != v,
        (Operator::Contains, Value::Str(v)) => raw.contains(v.as_str()),
        (Operator::NotContains, Value::Str(v)) => !raw.contains(v.as_str()),
        (Operator::StartsWith, Value::Str(v)) => raw.starts_with(v.as_str()),
        (Operator::EndsWith, Value::Str(v)) => raw.ends_with(v.as_str()),
        (Operator::Matches, Value::Regex(re, _)) => re.is_match(raw),
        (Operator::NotMatches, Value::Regex(re, _)) => !re.is_match(raw),
        (Operator::In, Value::Set(items)) => items.iter().any(|i| i == raw),
        (Operator::NotIn, Value::Set(items)) => !items.iter().any(|i| i == raw),
        (Operator::In, Value::Str(v)) => raw == v,
        (Operator::NotIn, Value::Str(v)) => raw != v,
        (Operator::Lt, Value::Str(v)) => raw < v.as_str(),
        (Operator::Le, Value::Str(v)) => raw <= v.as_str(),
        (Operator::Gt, Value::Str(v)) => raw > v.as_str(),
        (Operator::Ge, Value::Str(v)) => raw >= v.as_str(),
        (Operator::Eq, Value::Num(n)) => {
            raw.parse::<i64>().map(|m| m == *n).unwrap_or(false)
        },
        (Operator::Ne, Value::Num(n)) => {
            raw.parse::<i64>().map(|m| m != *n).unwrap_or(true)
        },
        (Operator::Lt, Value::Num(n)) => {
            raw.parse::<i64>().map(|m| m < *n).unwrap_or(false)
        },
        (Operator::Le, Value::Num(n)) => {
            raw.parse::<i64>().map(|m| m <= *n).unwrap_or(false)
        },
        (Operator::Gt, Value::Num(n)) => {
            raw.parse::<i64>().map(|m| m > *n).unwrap_or(false)
        },
        (Operator::Ge, Value::Num(n)) => {
            raw.parse::<i64>().map(|m| m >= *n).unwrap_or(false)
        },
        (Operator::Eq, Value::Bool(b)) => {
            raw.parse::<bool>().map(|x| x == *b).unwrap_or(false)
        },
        _ => false,
    }
}

fn negate_if(op: Operator, positive: bool) -> bool {
    match op {
        Operator::Eq
        | Operator::In
        | Operator::Contains
        | Operator::Matches
        | Operator::StartsWith
        | Operator::EndsWith
        | Operator::Lt
        | Operator::Le
        | Operator::Gt
        | Operator::Ge => positive,
        Operator::Ne
        | Operator::NotIn
        | Operator::NotContains
        | Operator::NotMatches => !positive,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Owns the data the borrowed [`EvalContext`] refers to.
    struct TestCtx {
        headers: Vec<(String, String)>,
        cookies: Vec<(String, String)>,
    }

    impl TestCtx {
        fn new() -> Self {
            Self {
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    ("x-custom".into(), "hello".into()),
                ],
                cookies: vec![("session".into(), "abc123".into())],
            }
        }

        fn ctx(&self) -> EvalContext<'_> {
            EvalContext {
                method: "POST",
                path: "/admin/users",
                full_uri: "/admin/users?id=1",
                host: "example.com",
                user_agent: "curl/8.0",
                body: Some("name=test"),
                headers: &self.headers,
                cookies: &self.cookies,
                client_ip: "10.0.0.5",
                parsed_ip: IpAddr::from_str("10.0.0.5").ok(),
                country_code: Some("US"),
                ssl: true,
                waf_score: 25,
                waf_score_sqli: 30,
                waf_score_xss: 10,
                waf_score_rce: 0,
            }
        }
    }

    fn assert_eval(input: &str, expected: bool) {
        let e = parse_expression(input).unwrap();
        let c = TestCtx::new();
        assert_eq!(evaluate(&e, &c.ctx()), expected, "expression: {input}");
    }

    #[test]
    fn parses_simple_comparison() {
        assert_eval(r#"http.request.method eq "POST""#, true);
    }

    #[test]
    fn parses_and_or_not() {
        assert_eval(
            r#"(http.request.uri.path contains "/admin" or http.request.uri.path contains "/api") and not ip.src.country in {"CN" "RU"}"#,
            true,
        );
    }

    #[test]
    fn parses_cidr_set() {
        assert_eval("ip.src in {192.168.0.0/16 10.0.0.0/8}", true);
    }

    #[test]
    fn parses_header_lookup() {
        assert_eval(r#"http.request.headers["x-custom"] eq "hello""#, true);
    }

    #[test]
    fn parses_numeric_threshold() {
        assert_eval("cf.waf.score.sqli lt 20", false);
        assert_eval("cf.waf.score.sqli gt 20", true);
    }

    #[test]
    fn parses_regex_match() {
        assert_eval(r#"http.request.uri.path matches "^/admin/.*$""#, true);
    }

    #[test]
    fn parses_not_contains() {
        assert_eval(r#"http.request.uri.path not contains "/secret""#, true);
    }

    #[test]
    fn parses_ssl_bool() {
        assert_eval("ssl eq true", true);
    }

    #[test]
    fn rejects_unknown_operator() {
        assert!(parse_expression(r#"http.host bogus "x""#).is_err());
    }

    #[test]
    fn rejects_unbalanced_parens() {
        assert!(parse_expression("(http.host eq \"x\"").is_err());
    }
}
