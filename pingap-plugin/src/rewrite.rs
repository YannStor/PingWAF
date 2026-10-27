// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Rewrite plugin — a unified, rule-based request/response rewriter.
//!
//! Where [`super::response_headers`] only touches response headers and
//! [`super::sub_filter`] only rewrites response bodies, this plugin evaluates a
//! prioritised list of [`RewriteRule`]s, each with an optional condition and a
//! list of [`RewriteOperation`]s that span both directions:
//!
//! * **Request phase** — add/set/remove request headers, rewrite the path
//!   (literal or regex), and add/remove query parameters.
//! * **Response phase** — add/set/remove response headers and override the
//!   status code.
//! * **Response body phase** — literal search/replace or full body replacement.
//!
//! Rules come from two sources, resolved per request:
//! * a [`PingWafAgent`] control-plane instance, when one is running and has
//!   rules for the request's domain (cached per host, rebuilt when the agent's
//!   config hash changes);
//! * otherwise the locally configured `rules` from the plugin's TOML config.
//!
//! Conditions use a small Cloudflare-flavoured expression language (see
//! [`parse_condition`]) supporting `and`/`or`/`not`, parentheses, header
//! lookups, `exists`, and `http.response.status`.

use super::{Error, get_hash_key, get_step_conf_in};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bstr::ByteSlice;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use http::HeaderMap;
use http::header::HeaderName;
use http::{HeaderValue, StatusCode};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HTTP_HEADER_TRANSFER_CHUNKED, ModifyResponseBody, Plugin, PluginStep,
    RequestPluginResult, ResponseBodyPluginResult, ResponsePluginResult,
    ensure_client_ip, get_host,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingwaf_agent::PingWafAgent;
use pingwaf_agent::cache::{
    RewriteDirection as CacheRewriteDirection,
    RewriteOperation as CacheRewriteOperation, RewriteRule as CacheRewriteRule,
};
use regex::Regex;
use serde::Deserialize;
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tracing::{debug, warn};

use crate::host_cache::{HostCacheSweep, touch};

/// Key under which the response-body modifier is stashed in [`Ctx`].
const PLUGIN_ID: &str = "_rewrite_";
/// Plugin category name used in error messages and factory registration.
const CATEGORY: &str = "rewrite";

type Result<T, E = Error> = std::result::Result<T, E>;

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid {
        category: CATEGORY.to_string(),
        message: message.into(),
    }
}

// ─────────────────────────────────────────────────────────────
// Public data model
// ─────────────────────────────────────────────────────────────

/// Which phase of the request lifecycle a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteDirection {
    Request,
    Response,
}

impl RewriteDirection {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "request" => Some(Self::Request),
            "response" => Some(Self::Response),
            _ => None,
        }
    }
}

/// A declarative description of a single rewrite operation.
#[derive(Debug, Clone)]
pub enum RewriteOperation {
    SetHeader {
        name: String,
        value: String,
    },
    AddHeader {
        name: String,
        value: String,
    },
    RemoveHeader {
        name: String,
    },
    SetPath {
        value: String,
    },
    RegexReplacePath {
        pattern: String,
        replacement: String,
    },
    SetQueryParam {
        name: String,
        value: String,
    },
    RemoveQueryParam {
        name: String,
    },
    ReplaceBody {
        search: String,
        replacement: String,
    },
    SetBody {
        content: String,
    },
    SetStatusCode {
        code: u16,
    },
}

/// A single rewrite rule: an optional condition plus ordered operations.
#[derive(Debug, Clone)]
pub struct RewriteRule {
    pub id: String,
    pub name: String,
    pub condition: Option<String>,
    pub direction: RewriteDirection,
    pub operations: Vec<RewriteOperation>,
    pub priority: u32,
    pub enabled: bool,
}

// ─────────────────────────────────────────────────────────────
// Compiled (hot-path) representation
// ─────────────────────────────────────────────────────────────

/// An operation with header names and regexes pre-parsed/pre-compiled.
#[derive(Debug, Clone)]
enum CompiledOperation {
    SetHeader { name: HeaderName, value: String },
    AddHeader { name: HeaderName, value: String },
    RemoveHeader { name: HeaderName },
    SetPath { value: String },
    RegexReplacePath { regex: Regex, replacement: String },
    SetQueryParam { name: String, value: String },
    RemoveQueryParam { name: String },
    SetStatusCode { code: StatusCode },
}

/// A body-only operation, applied during the response-body phase.
#[derive(Debug, Clone)]
enum BodyOperation {
    Replace { search: String, replacement: String },
    Set { content: String },
}

/// A rule with its condition parsed and operations compiled.
#[derive(Debug, Clone)]
struct CompiledRewriteRule {
    id: String,
    name: String,
    condition: Option<CondExpr>,
    direction: RewriteDirection,
    operations: Vec<CompiledOperation>,
    body_operations: Vec<BodyOperation>,
    priority: u32,
}

// ─────────────────────────────────────────────────────────────
// Condition expression language
// ─────────────────────────────────────────────────────────────

/// A field referenced by a condition.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CondField {
    Path,
    FullUri,
    Query,
    Method,
    Host,
    ClientIp,
    Country,
    Status,
    Header(String),
}

/// Comparison operators supported by the condition language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CondOp {
    Eq,
    Ne,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    Matches,
    NotMatches,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    NotIn,
    Exists,
    NotExists,
}

impl CondOp {
    fn is_negated(self) -> bool {
        matches!(
            self,
            CondOp::Ne
                | CondOp::NotContains
                | CondOp::NotMatches
                | CondOp::NotIn
                | CondOp::NotExists
        )
    }
}

/// A literal value on the right-hand side of a comparison.
#[derive(Debug, Clone)]
enum CondValue {
    Str(String),
    Num(i64),
    Regex(Box<Regex>),
    Set(Vec<String>),
}

/// Parsed condition AST.
#[derive(Debug, Clone)]
enum CondExpr {
    Field {
        field: CondField,
        op: CondOp,
        value: Option<CondValue>,
    },
    And(Box<CondExpr>, Box<CondExpr>),
    Or(Box<CondExpr>, Box<CondExpr>),
    Not(Box<CondExpr>),
}

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

fn tokenize(input: &str) -> std::result::Result<Vec<Token>, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
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
                            _ => {
                                buf.push('\\');
                                buf.push(esc as char);
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
                    buf.push(b as char);
                    j += 1;
                }
                if !closed {
                    return Err("unterminated string literal".to_string());
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
                let n = i64::from_str(&input[start..i])
                    .map_err(|e| format!("invalid number: {e}"))?;
                out.push(Token::Num(n));
            },
            b if b.is_ascii_alphanumeric() || b == b'_' => {
                let start = i;
                while i < bytes.len() {
                    let c2 = bytes[i];
                    if c2.is_ascii_alphanumeric()
                        || c2 == b'_'
                        || c2 == b'.'
                        || c2 == b'/'
                        || c2 == b':'
                        || c2 == b'-'
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
                return Err(format!(
                    "unexpected character {:?}",
                    other as char
                ));
            },
        }
    }
    out.push(Token::Eof);
    Ok(out)
}

fn parse_field(path: &str) -> CondField {
    match path.to_ascii_lowercase().as_str() {
        "http.request.uri.path" | "request.path" | "uri.path" => {
            CondField::Path
        },
        "http.request.uri.full" | "http.request.uri" | "request.uri" => {
            CondField::FullUri
        },
        "http.request.uri.query"
        | "request.query"
        | "http.request.uri.args" => CondField::Query,
        "http.request.method" | "request.method" => CondField::Method,
        "http.host" | "host" => CondField::Host,
        "ip.src" | "client.ip" => CondField::ClientIp,
        "ip.src.country" | "geo.country" => CondField::Country,
        "http.response.status" | "response.status" | "status" => {
            CondField::Status
        },
        // The console's expression builder exposes these friendly names; they
        // denote the corresponding request header.
        "http.user_agent" | "user_agent" | "http.useragent" => {
            CondField::Header("user-agent".to_string())
        },
        "http.referer" => CondField::Header("referer".to_string()),
        "http.cookie" => CondField::Header("cookie".to_string()),
        _ => CondField::Header(path.to_string()),
    }
}

struct CondParser {
    toks: Vec<Token>,
    pos: usize,
}

impl CondParser {
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
    fn expect_ident(&mut self) -> std::result::Result<String, String> {
        match self.next() {
            Token::Ident(s) => Ok(s),
            other => Err(format!("expected identifier, got {other:?}")),
        }
    }

    fn parse_or(&mut self) -> std::result::Result<CondExpr, String> {
        let mut lhs = self.parse_and()?;
        while let Token::Ident(s) = self.peek().clone() {
            if s.eq_ignore_ascii_case("or") {
                self.next();
                let rhs = self.parse_and()?;
                lhs = CondExpr::Or(Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> std::result::Result<CondExpr, String> {
        let mut lhs = self.parse_unary()?;
        while let Token::Ident(s) = self.peek().clone() {
            if s.eq_ignore_ascii_case("and") {
                self.next();
                let rhs = self.parse_unary()?;
                lhs = CondExpr::And(Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> std::result::Result<CondExpr, String> {
        if let Token::Ident(s) = self.peek().clone()
            && s.eq_ignore_ascii_case("not")
        {
            self.next();
            let inner = self.parse_unary()?;
            return Ok(CondExpr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> std::result::Result<CondExpr, String> {
        match self.peek().clone() {
            Token::LParen => {
                self.next();
                let e = self.parse_or()?;
                if self.next() != Token::RParen {
                    return Err("expected ')'".to_string());
                }
                Ok(e)
            },
            Token::Ident(_) => self.parse_comparison(),
            other => Err(format!("unexpected token {other:?}")),
        }
    }

    fn parse_comparison(&mut self) -> std::result::Result<CondExpr, String> {
        let path = self.expect_ident()?;
        let mut field = parse_field(&path);
        if self.peek() == &Token::LBracket {
            self.next();
            match self.next() {
                Token::Str(s) => field = CondField::Header(s),
                other => {
                    return Err(format!(
                        "expected string after '[', got {other:?}"
                    ));
                },
            }
            if self.next() != Token::RBracket {
                return Err("expected ']'".to_string());
            }
        }
        let op_word = match self.next() {
            Token::Ident(s) => s.to_ascii_lowercase(),
            other => return Err(format!("expected operator, got {other:?}")),
        };
        // `exists` / `not exists` carry no right-hand value.
        if op_word == "exists" {
            return Ok(CondExpr::Field {
                field,
                op: CondOp::Exists,
                value: None,
            });
        }
        if op_word == "not" {
            let second = match self.next() {
                Token::Ident(s) => s.to_ascii_lowercase(),
                other => {
                    return Err(format!(
                        "expected operator after 'not', got {other:?}"
                    ));
                },
            };
            let op = match second.as_str() {
                "exists" => {
                    return Ok(CondExpr::Field {
                        field,
                        op: CondOp::NotExists,
                        value: None,
                    });
                },
                "contains" => CondOp::NotContains,
                "matches" => CondOp::NotMatches,
                "in" => CondOp::NotIn,
                other => {
                    return Err(format!(
                        "unsupported negated operator 'not {other}'"
                    ));
                },
            };
            let value = self.parse_value(op)?;
            return Ok(CondExpr::Field {
                field,
                op,
                value: Some(value),
            });
        }
        let op = match op_word.as_str() {
            "eq" | "=" | "==" => CondOp::Eq,
            "ne" | "neq" | "!=" => CondOp::Ne,
            "contains" => CondOp::Contains,
            "not_contains" => CondOp::NotContains,
            "starts_with" | "startswith" => CondOp::StartsWith,
            "ends_with" | "endswith" => CondOp::EndsWith,
            "matches" => CondOp::Matches,
            "in" => CondOp::In,
            "lt" | "<" => CondOp::Lt,
            "le" | "<=" => CondOp::Le,
            "gt" | ">" => CondOp::Gt,
            "ge" | ">=" => CondOp::Ge,
            other => return Err(format!("unknown operator '{other}'")),
        };
        let value = self.parse_value(op)?;
        Ok(CondExpr::Field {
            field,
            op,
            value: Some(value),
        })
    }

    fn parse_value(
        &mut self,
        op: CondOp,
    ) -> std::result::Result<CondValue, String> {
        match self.next() {
            Token::Str(s) => finish_scalar(op, CondValue::Str(s)),
            Token::Num(n) => Ok(CondValue::Num(n)),
            Token::Ident(s) => {
                let lower = s.to_ascii_lowercase();
                let v = match lower.as_str() {
                    "true" => CondValue::Str("true".to_string()),
                    "false" => CondValue::Str("false".to_string()),
                    _ => CondValue::Str(s),
                };
                finish_scalar(op, v)
            },
            Token::LBrace => {
                let mut items = Vec::new();
                loop {
                    match self.peek().clone() {
                        Token::RBrace => {
                            self.next();
                            break;
                        },
                        Token::Eof => {
                            return Err("unterminated set literal".to_string());
                        },
                        _ => {},
                    }
                    match self.next() {
                        Token::Str(s) => items.push(s),
                        Token::Num(n) => items.push(n.to_string()),
                        Token::Ident(s) => items.push(s),
                        other => {
                            return Err(format!(
                                "unexpected token in set: {other:?}"
                            ));
                        },
                    }
                }
                Ok(CondValue::Set(items))
            },
            other => Err(format!("expected value, got {other:?}")),
        }
    }
}

fn finish_scalar(
    op: CondOp,
    v: CondValue,
) -> std::result::Result<CondValue, String> {
    if matches!(op, CondOp::Matches | CondOp::NotMatches) {
        let pattern = match &v {
            CondValue::Str(s) => s.clone(),
            _ => return Err("'matches' requires a string pattern".to_string()),
        };
        let re = Regex::new(&pattern)
            .map_err(|e| format!("invalid regex '{pattern}': {e}"))?;
        return Ok(CondValue::Regex(Box::new(re)));
    }
    Ok(v)
}

/// Parse a condition expression string into a [`CondExpr`].
fn parse_condition(input: &str) -> std::result::Result<CondExpr, String> {
    let toks = tokenize(input)?;
    let mut p = CondParser { toks, pos: 0 };
    let e = p.parse_or()?;
    if p.peek() != &Token::Eof {
        return Err("trailing tokens after expression".to_string());
    }
    Ok(e)
}

/// Resolved value of a field at evaluation time.
#[derive(Debug, Clone, Copy)]
enum FieldVal<'a> {
    Str(&'a str),
    Num(i64),
    Missing,
}

/// Per-request facts a condition is evaluated against.
struct CondCtx<'a> {
    method: &'a str,
    path: &'a str,
    full_uri: &'a str,
    query: &'a str,
    host: &'a str,
    client_ip: &'a str,
    /// GeoIP country code of `client_ip`; empty when not resolved.
    country: &'a str,
    status: u16,
    headers: &'a HeaderMap,
}

impl<'a> CondCtx<'a> {
    fn header(&self, name: &str) -> Option<&'a str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

fn resolve_field<'a>(field: &CondField, ctx: &'a CondCtx<'a>) -> FieldVal<'a> {
    match field {
        CondField::Path => FieldVal::Str(ctx.path),
        CondField::FullUri => FieldVal::Str(ctx.full_uri),
        CondField::Query => FieldVal::Str(ctx.query),
        CondField::Method => FieldVal::Str(ctx.method),
        CondField::Host => FieldVal::Str(ctx.host),
        CondField::ClientIp => FieldVal::Str(ctx.client_ip),
        CondField::Country => {
            if ctx.country.is_empty() {
                FieldVal::Missing
            } else {
                FieldVal::Str(ctx.country)
            }
        },
        CondField::Status => FieldVal::Num(ctx.status as i64),
        CondField::Header(name) => match ctx.header(name) {
            Some(v) => FieldVal::Str(v),
            None => FieldVal::Missing,
        },
    }
}

/// Whether any rule condition reads `ip.src.country`, so the GeoIP lookup is
/// only paid for when a rule actually needs it.
fn conditions_use_country(rules: &[CompiledRewriteRule]) -> bool {
    fn walk(expr: &CondExpr) -> bool {
        match expr {
            CondExpr::Field { field, .. } => {
                matches!(field, CondField::Country)
            },
            CondExpr::And(a, b) | CondExpr::Or(a, b) => walk(a) || walk(b),
            CondExpr::Not(inner) => walk(inner),
        }
    }
    rules
        .iter()
        .any(|r| r.condition.as_ref().map(walk).unwrap_or(false))
}

fn evaluate(expr: &CondExpr, ctx: &CondCtx<'_>) -> bool {
    match expr {
        CondExpr::And(a, b) => evaluate(a, ctx) && evaluate(b, ctx),
        CondExpr::Or(a, b) => evaluate(a, ctx) || evaluate(b, ctx),
        CondExpr::Not(inner) => !evaluate(inner, ctx),
        CondExpr::Field { field, op, value } => {
            let fv = resolve_field(field, ctx);
            apply_operator(fv, *op, value.as_ref())
        },
    }
}

fn apply_operator(
    fv: FieldVal<'_>,
    op: CondOp,
    value: Option<&CondValue>,
) -> bool {
    if matches!(fv, FieldVal::Missing) {
        return op.is_negated();
    }
    if matches!(op, CondOp::Exists) {
        return true;
    }
    if matches!(op, CondOp::NotExists) {
        return false;
    }
    let Some(value) = value else {
        return op.is_negated();
    };

    if let FieldVal::Num(n) = fv {
        let m = match value {
            CondValue::Num(m) => *m,
            CondValue::Str(s) => match i64::from_str(s) {
                Ok(v) => v,
                Err(_) => return op.is_negated(),
            },
            CondValue::Set(items) => {
                let ns = n.to_string();
                return negate_if(op, items.contains(&ns));
            },
            _ => return op.is_negated(),
        };
        let positive = match op {
            CondOp::Eq | CondOp::Ne => n == m,
            CondOp::Lt => n < m,
            CondOp::Le => n <= m,
            CondOp::Gt => n > m,
            CondOp::Ge => n >= m,
            CondOp::In | CondOp::NotIn => n == m,
            _ => false,
        };
        return negate_if(op, positive);
    }

    let raw = match fv {
        FieldVal::Str(s) => s,
        _ => return op.is_negated(),
    };
    match (op, value) {
        (CondOp::Eq, CondValue::Str(v)) => raw == v,
        (CondOp::Ne, CondValue::Str(v)) => raw != v,
        (CondOp::Contains, CondValue::Str(v)) => raw.contains(v.as_str()),
        (CondOp::NotContains, CondValue::Str(v)) => !raw.contains(v.as_str()),
        (CondOp::StartsWith, CondValue::Str(v)) => raw.starts_with(v.as_str()),
        (CondOp::EndsWith, CondValue::Str(v)) => raw.ends_with(v.as_str()),
        (CondOp::Matches, CondValue::Regex(re)) => re.is_match(raw),
        (CondOp::NotMatches, CondValue::Regex(re)) => !re.is_match(raw),
        (CondOp::In, CondValue::Set(items)) => items.iter().any(|i| i == raw),
        (CondOp::NotIn, CondValue::Set(items)) => {
            !items.iter().any(|i| i == raw)
        },
        (CondOp::In, CondValue::Str(v)) => raw == v,
        (CondOp::NotIn, CondValue::Str(v)) => raw != v,
        (CondOp::Lt, CondValue::Str(v)) => raw < v.as_str(),
        (CondOp::Le, CondValue::Str(v)) => raw <= v.as_str(),
        (CondOp::Gt, CondValue::Str(v)) => raw > v.as_str(),
        (CondOp::Ge, CondValue::Str(v)) => raw >= v.as_str(),
        _ => false,
    }
}

fn negate_if(op: CondOp, positive: bool) -> bool {
    match op {
        CondOp::Ne
        | CondOp::NotIn
        | CondOp::NotContains
        | CondOp::NotMatches => !positive,
        _ => positive,
    }
}

// ─────────────────────────────────────────────────────────────
// Variable interpolation
// ─────────────────────────────────────────────────────────────

/// Values substituted into `${...}` placeholders in header/body values.
#[derive(Debug, Clone, Default)]
struct InterpVars {
    request_id: String,
    client_ip: String,
    host: String,
    path: String,
    method: String,
}

/// Replace `${request_id}`, `${client_ip}`, `${host}`, `${path}` and
/// `${method}` in `value`. Returns the input unchanged when no placeholder is
/// present, avoiding an allocation on the hot path.
fn interpolate<'a>(value: &'a str, vars: &InterpVars) -> Cow<'a, str> {
    if !value.contains("${") {
        return Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(idx) = rest.find("${") {
        out.push_str(&rest[..idx]);
        let after = &rest[idx + 2..];
        match after.find('}') {
            Some(end) => {
                let key = &after[..end];
                match key {
                    "request_id" => out.push_str(&vars.request_id),
                    "client_ip" => out.push_str(&vars.client_ip),
                    "host" => out.push_str(&vars.host),
                    "path" => out.push_str(&vars.path),
                    "method" => out.push_str(&vars.method),
                    // Unknown placeholder: preserve it verbatim.
                    _ => {
                        out.push_str("${");
                        out.push_str(key);
                        out.push('}');
                    },
                }
                rest = &after[end + 1..];
            },
            None => {
                out.push_str(&rest[idx..]);
                return Cow::Owned(out);
            },
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

// ─────────────────────────────────────────────────────────────
// Response body modifier
// ─────────────────────────────────────────────────────────────

/// Buffers the whole response body and applies literal replacements at the end
/// of the stream, mirroring [`super::sub_filter`]'s behaviour.
#[derive(Debug, Clone)]
struct RewriteBodyReplacer {
    ops: Vec<BodyOperation>,
    buffer: BytesMut,
}

impl ModifyResponseBody for RewriteBodyReplacer {
    fn handle(
        &mut self,
        _session: &Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        if let Some(data) = body {
            self.buffer.extend(&data[..]);
            data.clear();
        }
        if !end_of_stream {
            return Ok(());
        }
        let mut data = self.buffer.to_vec();
        for op in &self.ops {
            match op {
                BodyOperation::Replace {
                    search,
                    replacement,
                } => {
                    if !search.is_empty() {
                        data = data
                            .replace(search.as_bytes(), replacement.as_bytes());
                    }
                },
                BodyOperation::Set { content } => {
                    data = content.clone().into_bytes();
                },
            }
        }
        *body = Some(Bytes::from(data));
        Ok(())
    }

    fn name(&self) -> &str {
        "rewrite"
    }
}

// ─────────────────────────────────────────────────────────────
// Config parsing
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RuleSpec {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default = "default_direction")]
    direction: String,
    #[serde(default)]
    operations: Vec<OpSpec>,
    #[serde(default)]
    priority: u32,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_direction() -> String {
    "request".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OpSpec {
    SetHeader {
        name: String,
        value: String,
    },
    AddHeader {
        name: String,
        value: String,
    },
    RemoveHeader {
        name: String,
    },
    SetPath {
        value: String,
    },
    RegexReplacePath {
        pattern: String,
        replacement: String,
    },
    SetQueryParam {
        name: String,
        value: String,
    },
    RemoveQueryParam {
        name: String,
    },
    ReplaceBody {
        search: String,
        replacement: String,
    },
    SetBody {
        content: String,
    },
    SetStatusCode {
        code: u16,
    },
}

impl RuleSpec {
    fn into_rule(self) -> Result<RewriteRule> {
        let direction =
            RewriteDirection::parse(&self.direction).ok_or_else(|| {
                invalid(format!(
                    "invalid direction '{}', expect request or response",
                    self.direction
                ))
            })?;
        let operations = self
            .operations
            .into_iter()
            .map(|op| match op {
                OpSpec::SetHeader { name, value } => {
                    RewriteOperation::SetHeader { name, value }
                },
                OpSpec::AddHeader { name, value } => {
                    RewriteOperation::AddHeader { name, value }
                },
                OpSpec::RemoveHeader { name } => {
                    RewriteOperation::RemoveHeader { name }
                },
                OpSpec::SetPath { value } => {
                    RewriteOperation::SetPath { value }
                },
                OpSpec::RegexReplacePath {
                    pattern,
                    replacement,
                } => RewriteOperation::RegexReplacePath {
                    pattern,
                    replacement,
                },
                OpSpec::SetQueryParam { name, value } => {
                    RewriteOperation::SetQueryParam { name, value }
                },
                OpSpec::RemoveQueryParam { name } => {
                    RewriteOperation::RemoveQueryParam { name }
                },
                OpSpec::ReplaceBody {
                    search,
                    replacement,
                } => RewriteOperation::ReplaceBody {
                    search,
                    replacement,
                },
                OpSpec::SetBody { content } => {
                    RewriteOperation::SetBody { content }
                },
                OpSpec::SetStatusCode { code } => {
                    RewriteOperation::SetStatusCode { code }
                },
            })
            .collect();
        Ok(RewriteRule {
            id: self.id,
            name: self.name,
            condition: self.condition,
            direction,
            operations,
            priority: self.priority,
            enabled: self.enabled,
        })
    }
}

/// Compile a [`RewriteRule`] into its hot-path representation.
fn compile_rule(rule: &RewriteRule) -> Result<CompiledRewriteRule> {
    let condition = match &rule.condition {
        Some(expr) if !expr.trim().is_empty() => {
            Some(parse_condition(expr).map_err(invalid)?)
        },
        _ => None,
    };
    let mut operations = Vec::new();
    let mut body_operations = Vec::new();
    for op in &rule.operations {
        match op {
            RewriteOperation::SetHeader { name, value } => {
                operations.push(CompiledOperation::SetHeader {
                    name: parse_header_name(name)?,
                    value: value.clone(),
                })
            },
            RewriteOperation::AddHeader { name, value } => {
                operations.push(CompiledOperation::AddHeader {
                    name: parse_header_name(name)?,
                    value: value.clone(),
                })
            },
            RewriteOperation::RemoveHeader { name } => {
                operations.push(CompiledOperation::RemoveHeader {
                    name: parse_header_name(name)?,
                })
            },
            RewriteOperation::SetPath { value } => {
                operations.push(CompiledOperation::SetPath {
                    value: value.clone(),
                });
            },
            RewriteOperation::RegexReplacePath {
                pattern,
                replacement,
            } => {
                let regex = Regex::new(pattern).map_err(|e| {
                    invalid(format!("invalid path regex '{pattern}': {e}"))
                })?;
                operations.push(CompiledOperation::RegexReplacePath {
                    regex,
                    replacement: replacement.clone(),
                });
            },
            RewriteOperation::SetQueryParam { name, value } => {
                operations.push(CompiledOperation::SetQueryParam {
                    name: name.clone(),
                    value: value.clone(),
                })
            },
            RewriteOperation::RemoveQueryParam { name } => {
                operations.push(CompiledOperation::RemoveQueryParam {
                    name: name.clone(),
                })
            },
            RewriteOperation::SetStatusCode { code } => {
                let status = StatusCode::from_u16(*code).map_err(|e| {
                    invalid(format!("invalid status code {code}: {e}"))
                })?;
                operations
                    .push(CompiledOperation::SetStatusCode { code: status });
            },
            RewriteOperation::ReplaceBody {
                search,
                replacement,
            } => {
                body_operations.push(BodyOperation::Replace {
                    search: search.clone(),
                    replacement: replacement.clone(),
                });
            },
            RewriteOperation::SetBody { content } => {
                body_operations.push(BodyOperation::Set {
                    content: content.clone(),
                });
            },
        }
    }
    Ok(CompiledRewriteRule {
        id: rule.id.clone(),
        name: rule.name.clone(),
        condition,
        direction: rule.direction,
        operations,
        body_operations,
        priority: rule.priority,
    })
}

fn parse_header_name(name: &str) -> Result<HeaderName> {
    HeaderName::from_str(name)
        .map_err(|e| invalid(format!("invalid header name '{name}': {e}")))
}

/// Compile a list of rules and sort them by ascending priority (stable).
fn compile_rules(rules: Vec<RewriteRule>) -> Result<Vec<CompiledRewriteRule>> {
    let mut compiled: Vec<CompiledRewriteRule> = rules
        .iter()
        .filter(|r| r.enabled)
        .map(compile_rule)
        .collect::<Result<Vec<_>>>()?;
    compiled.sort_by_key(|r| r.priority);
    Ok(compiled)
}

/// Convert agent-supplied rewrite rules into the plugin's data model.
fn convert_agent_rules(rules: &[CacheRewriteRule]) -> Vec<RewriteRule> {
    rules
        .iter()
        .map(|r| {
            let direction = match r.direction {
                CacheRewriteDirection::Request => RewriteDirection::Request,
                CacheRewriteDirection::Response => RewriteDirection::Response,
            };
            let operations =
                r.operations.iter().filter_map(convert_operation).collect();
            RewriteRule {
                id: r.id.clone(),
                name: r.name.clone(),
                condition: if r.match_expression.is_empty() {
                    None
                } else {
                    Some(r.match_expression.clone())
                },
                direction,
                operations,
                priority: r.priority,
                enabled: r.enabled,
            }
        })
        .collect()
}

/// Maps one agent operation (the console's `{type, name, value}` shape) to the
/// plugin's data model. Returns `None` for unknown types so a future console
/// version cannot break rule compilation for the whole site.
fn convert_operation(op: &CacheRewriteOperation) -> Option<RewriteOperation> {
    let converted = match op.op_type.as_str() {
        "set_header" => RewriteOperation::SetHeader {
            name: op.name.clone(),
            value: op.value.clone(),
        },
        "add_header" => RewriteOperation::AddHeader {
            name: op.name.clone(),
            value: op.value.clone(),
        },
        "remove_header" => RewriteOperation::RemoveHeader {
            name: op.name.clone(),
        },
        "set_path" => RewriteOperation::SetPath {
            value: op.value.clone(),
        },
        "regex_replace_path" => RewriteOperation::RegexReplacePath {
            pattern: op.name.clone(),
            replacement: op.value.clone(),
        },
        "set_query_param" => RewriteOperation::SetQueryParam {
            name: op.name.clone(),
            value: op.value.clone(),
        },
        "remove_query_param" => RewriteOperation::RemoveQueryParam {
            name: op.name.clone(),
        },
        "replace_body" => RewriteOperation::ReplaceBody {
            search: op.name.clone(),
            replacement: op.value.clone(),
        },
        other => {
            debug!(op_type = other, "unsupported rewrite operation type");
            return None;
        },
    };
    Some(converted)
}

// ─────────────────────────────────────────────────────────────
// Plugin
// ─────────────────────────────────────────────────────────────

/// Per-host cache of agent-supplied compiled rules plus the fingerprint they
/// were built from.
struct CachedSiteRules {
    fingerprint: Arc<str>,
    rules: Arc<Vec<CompiledRewriteRule>>,
    /// Unix seconds of the last cache hit; feeds the host-cache TTL sweep
    /// (`host_cache`) — wildcard-matched scanner hosts would otherwise cache
    /// a compiled rule set forever.
    last_used: AtomicU64,
}

/// Request/response rewrite plugin.
pub struct RewritePlugin {
    plugin_step: PluginStep,
    /// Locally configured rules, hot-swappable.
    rules: Arc<ArcSwap<Vec<CompiledRewriteRule>>>,
    /// Agent-supplied rules keyed by host.
    site_rules: DashMap<String, CachedSiteRules>,
    /// Sweep gate for the `site_rules` host cache (TTL + hard cap).
    rules_sweep: HostCacheSweep,
    hash_value: String,
}

impl RewritePlugin {
    /// Create a new plugin from configuration.
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new rewrite plugin");
        Self::try_from(params)
    }

    /// Resolve the active rule set for `host`: agent rules when available,
    /// otherwise the locally configured rules.
    fn active_rules(&self, host: &str) -> Arc<Vec<CompiledRewriteRule>> {
        if !host.is_empty()
            && let Some(agent) = PingWafAgent::instance()
            && let Some(site) = agent.get_rules_for_domain(host)
            && !site.rewrite_rules.is_empty()
        {
            let now = crate::host_cache::unix_now();
            self.rules_sweep.prune(&self.site_rules, now, |cached| {
                cached.last_used.load(std::sync::atomic::Ordering::Relaxed)
            });
            let fingerprint = agent.config_hash();
            if let Some(cached) = self.site_rules.get(host)
                && cached.fingerprint == fingerprint
            {
                touch(&cached.last_used, now);
                return cached.rules.clone();
            }
            let converted = convert_agent_rules(&site.rewrite_rules);
            // Compile per rule: one invalid rule must not disable the
            // whole site's rewrite set, so bad rules are dropped with a
            // warning instead of failing everything.
            let mut compiled: Vec<CompiledRewriteRule> = Vec::new();
            for rule in converted {
                match compile_rule(&rule) {
                    Ok(c) => compiled.push(c),
                    Err(e) => {
                        warn!(
                            rule = %rule.id,
                            name = %rule.name,
                            error = e.to_string(),
                            "drop invalid rewrite rule"
                        );
                    },
                }
            }
            compiled.sort_by_key(|r| r.priority);
            let rules = Arc::new(compiled);
            self.site_rules.insert(
                host.to_string(),
                CachedSiteRules {
                    fingerprint,
                    rules: Arc::clone(&rules),
                    last_used: AtomicU64::new(now),
                },
            );
            return rules;
        }
        self.rules.load_full()
    }
}

impl TryFrom<&PluginConf> for RewritePlugin {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let plugin_step = get_step_conf_in(
            value,
            CATEGORY,
            PluginStep::Request,
            &[PluginStep::EarlyRequest, PluginStep::Request],
        )?;

        // `rules` may be a JSON string or a TOML/JSON array.
        let raw_rules = value.get("rules");
        let specs: Vec<RuleSpec> = match raw_rules {
            Some(toml::Value::String(s)) => {
                if s.trim().is_empty() {
                    Vec::new()
                } else {
                    serde_json::from_str(s).map_err(|e| {
                        invalid(format!("invalid rules json: {e}"))
                    })?
                }
            },
            Some(other) => {
                let json = serde_json::to_value(other).map_err(|e| {
                    invalid(format!("invalid rules value: {e}"))
                })?;
                serde_json::from_value(json)
                    .map_err(|e| invalid(format!("invalid rules: {e}")))?
            },
            None => Vec::new(),
        };

        let rules: Vec<RewriteRule> = specs
            .into_iter()
            .map(RuleSpec::into_rule)
            .collect::<Result<Vec<_>>>()?;
        let compiled = compile_rules(rules)?;

        Ok(Self {
            plugin_step,
            rules: Arc::new(ArcSwap::from_pointee(compiled)),
            site_rules: DashMap::new(),
            rules_sweep: HostCacheSweep::default(),
            hash_value,
        })
    }
}

impl RewritePlugin {
    /// Build the interpolation variables for the current request.
    fn interp_vars(session: &Session, ctx: &Ctx) -> InterpVars {
        let req = session.req_header();
        InterpVars {
            request_id: ctx.state.request_id.clone().unwrap_or_default(),
            client_ip: ctx.conn.client_ip.clone().unwrap_or_default(),
            host: get_host(req).unwrap_or_default().to_string(),
            path: req.uri.path().to_string(),
            method: req.method.as_str().to_string(),
        }
    }

    /// Apply request-direction operations, returning whether anything changed.
    fn apply_request_ops(
        rule: &CompiledRewriteRule,
        session: &mut Session,
        vars: &InterpVars,
    ) -> bool {
        let mut changed = false;
        let mut new_path: Option<String> = None;
        let mut query_ops: Vec<&CompiledOperation> = Vec::new();

        for op in &rule.operations {
            match op {
                CompiledOperation::SetHeader { name, value } => {
                    let v = interpolate(value, vars);
                    if let Ok(hv) = HeaderValue::from_str(&v) {
                        let _ =
                            session.req_header_mut().insert_header(name, hv);
                        changed = true;
                    }
                },
                CompiledOperation::AddHeader { name, value } => {
                    let v = interpolate(value, vars);
                    if let Ok(hv) = HeaderValue::from_str(&v) {
                        let _ =
                            session.req_header_mut().append_header(name, hv);
                        changed = true;
                    }
                },
                CompiledOperation::RemoveHeader { name } => {
                    if session.req_header_mut().remove_header(name).is_some() {
                        changed = true;
                    }
                },
                CompiledOperation::SetPath { value } => {
                    new_path = Some(interpolate(value, vars).to_string());
                    changed = true;
                },
                CompiledOperation::RegexReplacePath { regex, replacement } => {
                    let current = new_path.clone().unwrap_or_else(|| {
                        session.req_header().uri.path().to_string()
                    });
                    let replaced = regex
                        .replace(&current, replacement.as_str())
                        .to_string();
                    if replaced != current {
                        new_path = Some(replaced);
                        changed = true;
                    }
                },
                CompiledOperation::SetQueryParam { .. }
                | CompiledOperation::RemoveQueryParam { .. } => {
                    query_ops.push(op);
                },
                // Status code is a response-only operation.
                CompiledOperation::SetStatusCode { .. } => {},
            }
        }

        // Rebuild the URI when the path and/or query changed.
        if changed && (new_path.is_some() || !query_ops.is_empty()) {
            let req = session.req_header();
            let path = new_path
                .clone()
                .unwrap_or_else(|| req.uri.path().to_string());
            let mut query = req.uri.query().unwrap_or_default().to_string();
            for op in query_ops {
                match op {
                    CompiledOperation::SetQueryParam { name, value } => {
                        query = set_query_param(&query, name, value);
                    },
                    CompiledOperation::RemoveQueryParam { name } => {
                        query = remove_query_param(&query, name);
                    },
                    _ => {},
                }
            }
            let uri_str = if query.is_empty() {
                path.clone()
            } else {
                format!("{path}?{query}")
            };
            if let Ok(uri) = http::Uri::from_str(&uri_str) {
                session.req_header_mut().set_uri(uri);
            }
        }
        changed
    }
}

/// Set (or replace) a single query parameter, preserving the others.
fn set_query_param(query: &str, name: &str, value: &str) -> String {
    let mut found = false;
    let mut parts: Vec<String> = Vec::new();
    for item in query.split('&').filter(|s| !s.is_empty()) {
        let key = item.split('=').next().unwrap_or(item);
        if key == name {
            found = true;
            parts.push(format!("{name}={value}"));
        } else {
            parts.push(item.to_string());
        }
    }
    if !found {
        parts.push(format!("{name}={value}"));
    }
    parts.join("&")
}

/// Remove every occurrence of a query parameter.
fn remove_query_param(query: &str, name: &str) -> String {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter(|item| item.split('=').next().unwrap_or(item) != name)
        .collect::<Vec<_>>()
        .join("&")
}

#[async_trait]
impl Plugin for RewritePlugin {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        // Method attribution (see pingwaf-profiler): the timer books the
        // `plugin` module row as well.
        let _profile = pingwaf_profiler::timed_method(
            pingwaf_profiler::Method::PluginRewrite,
        );
        let host = get_host(session.req_header())
            .unwrap_or_default()
            .to_string();
        let rules = self.active_rules(&host);
        if rules
            .iter()
            .all(|r| r.direction != RewriteDirection::Request)
        {
            return Ok(RequestPluginResult::Skipped);
        }

        let client_ip = ensure_client_ip(session, ctx).to_string();
        let country = if conditions_use_country(&rules) {
            crate::waf::lookup_country(&client_ip).unwrap_or_default()
        } else {
            String::new()
        };
        let vars = Self::interp_vars(session, ctx);
        let mut modified = false;

        for rule in rules.iter() {
            if rule.direction != RewriteDirection::Request {
                continue;
            }
            let matched = match &rule.condition {
                None => true,
                Some(cond) => {
                    let req = session.req_header();
                    let cctx = CondCtx {
                        method: req.method.as_str(),
                        path: req.uri.path(),
                        full_uri: req
                            .uri
                            .path_and_query()
                            .map(|s| s.as_str())
                            .unwrap_or_default(),
                        query: req.uri.query().unwrap_or_default(),
                        host: &host,
                        client_ip: &client_ip,
                        country: &country,
                        status: 0,
                        headers: &req.headers,
                    };
                    evaluate(cond, &cctx)
                },
            };
            if matched {
                debug!(rule = %rule.id, name = %rule.name, "rewrite request rule matched");
                if Self::apply_request_ops(rule, session, &vars) {
                    modified = true;
                }
            }
        }

        Ok(if modified {
            RequestPluginResult::Continue
        } else {
            RequestPluginResult::Skipped
        })
    }

    async fn handle_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        let host = get_host(session.req_header())
            .unwrap_or_default()
            .to_string();
        let rules = self.active_rules(&host);
        if rules
            .iter()
            .all(|r| r.direction != RewriteDirection::Response)
        {
            return Ok(ResponsePluginResult::Unchanged);
        }

        let client_ip = ensure_client_ip(session, ctx).to_string();
        let country = if conditions_use_country(&rules) {
            crate::waf::lookup_country(&client_ip).unwrap_or_default()
        } else {
            String::new()
        };
        let vars = Self::interp_vars(session, ctx);
        let status = upstream_response.status.as_u16();
        let mut modified = false;
        let mut body_ops: Vec<BodyOperation> = Vec::new();

        for rule in rules.iter() {
            if rule.direction != RewriteDirection::Response {
                continue;
            }
            let matched = match &rule.condition {
                None => true,
                Some(cond) => {
                    let req = session.req_header();
                    let cctx = CondCtx {
                        method: req.method.as_str(),
                        path: req.uri.path(),
                        full_uri: req
                            .uri
                            .path_and_query()
                            .map(|s| s.as_str())
                            .unwrap_or_default(),
                        query: req.uri.query().unwrap_or_default(),
                        host: &host,
                        client_ip: &client_ip,
                        country: &country,
                        status,
                        headers: &req.headers,
                    };
                    evaluate(cond, &cctx)
                },
            };
            if !matched {
                continue;
            }
            for op in &rule.operations {
                match op {
                    CompiledOperation::SetHeader { name, value } => {
                        let v = interpolate(value, &vars);
                        if let Ok(hv) = HeaderValue::from_str(&v) {
                            let _ = upstream_response.insert_header(name, hv);
                            modified = true;
                        }
                    },
                    CompiledOperation::AddHeader { name, value } => {
                        let v = interpolate(value, &vars);
                        if let Ok(hv) = HeaderValue::from_str(&v) {
                            let _ = upstream_response.append_header(name, hv);
                            modified = true;
                        }
                    },
                    CompiledOperation::RemoveHeader { name } => {
                        if upstream_response.remove_header(name).is_some() {
                            modified = true;
                        }
                    },
                    CompiledOperation::SetStatusCode { code }
                        if upstream_response.set_status(*code).is_ok() =>
                    {
                        modified = true;
                    },
                    // Request-only operations are ignored on the response.
                    _ => {},
                }
            }
            body_ops.extend(rule.body_operations.iter().cloned());
        }

        if !body_ops.is_empty() {
            upstream_response.remove_header(&http::header::CONTENT_LENGTH);
            let _ = upstream_response.insert_header(
                http::header::TRANSFER_ENCODING,
                HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
            );
            ctx.add_modify_body_handler(
                PLUGIN_ID,
                Box::new(RewriteBodyReplacer {
                    ops: body_ops,
                    buffer: BytesMut::new(),
                }),
            );
            modified = true;
        }

        Ok(if modified {
            ResponsePluginResult::Modified
        } else {
            ResponsePluginResult::Unchanged
        })
    }

    fn handle_response_body(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        if let Some(modifier) = ctx.get_modify_body_handler(PLUGIN_ID) {
            modifier.handle(session, body, end_of_stream)?;
            Ok(if end_of_stream {
                ResponseBodyPluginResult::FullyReplaced
            } else {
                ResponseBodyPluginResult::PartialReplaced
            })
        } else {
            Ok(ResponseBodyPluginResult::Unchanged)
        }
    }
}

register_plugin!("rewrite", RewritePlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::h1_session as session;
    use pingap_config::PluginConf;
    use pingap_core::Ctx;
    use pingora::http::ResponseHeader;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_condition() {
        let cond = parse_condition(
            r#"http.request.uri.path starts_with "/api/" and http.request.method eq "GET""#,
        )
        .unwrap();
        let headers = HeaderMap::new();
        let cctx = CondCtx {
            method: "GET",
            path: "/api/users",
            full_uri: "/api/users",
            query: "",
            host: "example.com",
            client_ip: "1.1.1.1",
            country: "",
            status: 0,
            headers: &headers,
        };
        assert!(evaluate(&cond, &cctx));

        let cond = parse_condition("http.response.status eq 404").unwrap();
        let cctx = CondCtx {
            method: "GET",
            path: "/",
            full_uri: "/",
            query: "",
            host: "",
            client_ip: "",
            country: "",
            status: 404,
            headers: &headers,
        };
        assert!(evaluate(&cond, &cctx));

        let cond =
            parse_condition(r#"http.request.headers["x-custom"] exists"#)
                .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", HeaderValue::from_static("v"));
        let cctx = CondCtx {
            method: "GET",
            path: "/",
            full_uri: "/",
            query: "",
            host: "",
            client_ip: "",
            country: "",
            status: 0,
            headers: &headers,
        };
        assert!(evaluate(&cond, &cctx));
    }

    #[test]
    fn test_query_helpers() {
        assert_eq!("a=1&b=2", set_query_param("a=1", "b", "2"));
        assert_eq!("a=9&b=2", set_query_param("a=1&b=2", "a", "9"));
        assert_eq!("b=2", remove_query_param("a=1&b=2", "a"));
    }

    #[test]
    fn test_interpolate() {
        let vars = InterpVars {
            request_id: "rid".into(),
            client_ip: "10.0.0.1".into(),
            host: "example.com".into(),
            path: "/p".into(),
            method: "GET".into(),
        };
        assert_eq!("rid", interpolate("${request_id}", &vars));
        assert_eq!(
            "ip=10.0.0.1 host=example.com",
            interpolate("ip=${client_ip} host=${host}", &vars)
        );
        assert_eq!(Cow::Borrowed("plain"), interpolate("plain", &vars));
    }

    #[test]
    fn test_config_parse() {
        let plugin = RewritePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
category = "rewrite"
step = "request"
rules = '[{"id":"strip","name":"Strip /api","direction":"request","priority":1,"operations":[{"type":"regex_replace_path","pattern":"^/api/(.*)","replacement":"/$1"}]},{"id":"cors","name":"CORS","direction":"response","operations":[{"type":"set_header","name":"Access-Control-Allow-Origin","value":"*"}]}]'
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let rules = plugin.rules.load_full();
        assert_eq!(2, rules.len());
        assert_eq!(PluginStep::Request, plugin.plugin_step);
    }

    #[tokio::test]
    async fn test_request_path_rewrite() {
        let plugin = RewritePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
category = "rewrite"
rules = '[{"id":"strip","direction":"request","condition":"http.request.uri.path starts_with \"/api/\"","operations":[{"type":"regex_replace_path","pattern":"^/api/(.*)","replacement":"/$1"}]}]'
"###,
            )
            .unwrap(),
        )
        .unwrap();

        // A host the agent-mode tests never register: active_rules() defers
        // to the process-global agent when it has rules for the host, so
        // "example.com" here races with agent tests running in parallel.
        let mut s = session("GET", "/api/users", "rewrite.test").await;
        let result = plugin
            .handle_request(PluginStep::Request, &mut s, &mut Ctx::default())
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
        assert_eq!("/users", s.req_header().uri.path());
    }

    #[tokio::test]
    async fn test_response_headers() {
        let plugin = RewritePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
category = "rewrite"
rules = '[{"id":"h","direction":"response","operations":[{"type":"set_header","name":"X-Test","value":"1"},{"type":"remove_header","name":"Server"},{"type":"set_status_code","code":201}]}]'
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let mut s = session("GET", "/", "rewrite.test").await;
        let mut resp = ResponseHeader::build_no_case(200, None).unwrap();
        resp.insert_header("Server", "pingap").unwrap();
        let result = plugin
            .handle_response(&mut s, &mut Ctx::default(), &mut resp)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Modified, result);
        assert_eq!("1", resp.headers.get("x-test").unwrap().to_str().unwrap());
        assert!(resp.headers.get("server").is_none());
        assert_eq!(201, resp.status.as_u16());
    }

    mod agent_mode {
        use super::*;
        use crate::waf::tests::install_test_agent;
        use pingwaf_proto::control_plane as proto;
        use pretty_assertions::assert_eq;

        fn site_config(
            rewrite_rules: Vec<proto::RewriteRule>,
        ) -> proto::SiteConfig {
            proto::SiteConfig {
                sites: vec![proto::Site {
                    id: "site-1".to_string(),
                    name: "example".to_string(),
                    domain: "example.com".to_string(),
                    alternate_domains: Vec::new(),
                    status: 0,
                    rules: Some(proto::RuleBundle {
                        site_id: "site-1".to_string(),
                        config_hash: "hash-1".to_string(),
                        rewrite_rules,
                        ..Default::default()
                    }),
                    trust_proxy_headers: false,
                    trusted_header: String::new(),
                    trust_last_hop: false,
                    trusted_proxy_ranges: Vec::new(),
                    downstream_timeout_secs: 60,
                }],
                config_hash: "hash-1".to_string(),
                updated_at: None,
            }
        }

        fn rule(
            operations: Vec<proto::RewriteOperation>,
        ) -> proto::RewriteRule {
            proto::RewriteRule {
                id: "strip".to_string(),
                name: "strip api prefix".to_string(),
                match_expression: String::new(),
                direction: 0,
                operations,
                enabled: true,
                priority: 1,
            }
        }

        /// Agent-supplied rules drive the rewrite even though the plugin's
        /// local config has none; other hosts stay untouched.
        #[tokio::test]
        async fn agent_rules_rewrite_request_path() {
            let (_guard, agent, _dir) = install_test_agent().await;
            agent
                .rule_cache
                .update_from_site_config(&site_config(vec![rule(vec![
                    proto::RewriteOperation {
                        r#type: "regex_replace_path".to_string(),
                        name: "^/api/(.*)".to_string(),
                        value: "/$1".to_string(),
                    },
                ])]))
                .unwrap();

            let plugin = RewritePlugin::new(
                &toml::from_str::<PluginConf>(r###"category = "rewrite""###)
                    .unwrap(),
            )
            .unwrap();

            let mut s = session("GET", "/api/users", "other.example.com").await;
            plugin
                .handle_request(
                    PluginStep::Request,
                    &mut s,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            assert_eq!("/api/users", s.req_header().uri.path());

            let mut s = session("GET", "/api/users", "example.com").await;
            let result = plugin
                .handle_request(
                    PluginStep::Request,
                    &mut s,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            assert_eq!(true, result == RequestPluginResult::Continue);
            assert_eq!("/users", s.req_header().uri.path());
        }

        /// The console dialect (`not_contains`, `http.user_agent`) compiles and
        /// evaluates; a rule whose condition parses keeps working.
        #[tokio::test]
        async fn agent_rules_understand_console_dialect() {
            let (_guard, agent, _dir) = install_test_agent().await;
            let mut config =
                site_config(vec![rule(vec![proto::RewriteOperation {
                    r#type: "set_header".to_string(),
                    name: "x-rewritten".to_string(),
                    value: "1".to_string(),
                }])]);
            config.sites[0].rules.as_mut().unwrap().rewrite_rules[0]
                .match_expression =
                r#"http.user_agent contains "curl" and http.host not_contains "nope""#
                    .to_string();
            agent.rule_cache.update_from_site_config(&config).unwrap();

            let plugin = RewritePlugin::new(
                &toml::from_str::<PluginConf>(r###"category = "rewrite""###)
                    .unwrap(),
            )
            .unwrap();

            let mut s = session("GET", "/", "example.com").await;
            s.req_header_mut()
                .insert_header("User-Agent", "curl/8.4.0")
                .unwrap();
            let result = plugin
                .handle_request(
                    PluginStep::Request,
                    &mut s,
                    &mut Ctx::default(),
                )
                .await
                .unwrap();
            assert_eq!(RequestPluginResult::Continue, result);
            // The condition matched, so the request header op ran.
            assert_eq!(
                "1",
                s.req_header()
                    .headers
                    .get("x-rewritten")
                    .unwrap()
                    .to_str()
                    .unwrap()
            );
        }
    }
}
