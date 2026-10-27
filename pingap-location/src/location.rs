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

use super::regex::RegexCapture;
use ahash::AHashMap;
use arc_swap::ArcSwapOption;
use http::HeaderName;
use http::HeaderValue;
use ipnet::IpNet;
use pingap_config::Hashable;
use pingap_config::LocationConf;
use pingap_config::validate_rewrite_path;
use pingap_core::new_internal_error;
use pingap_core::{HttpHeader, convert_headers, resolve_static_header_value};
use pingap_core::{LocationInstance, NamedPlugin, PluginProvider};
use pingora::http::RequestHeader;
use regex::Regex;
use snafu::{ResultExt, Snafu};
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, error, warn};

const LOG_TARGET: &str = "pingap::location";

pub type Locations = AHashMap<String, Arc<Location>>;

// Error enum for various location-related errors
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid error {message}"))]
    Invalid { message: String },
    #[snafu(display("Regex value: {value}, {source}"))]
    Regex { value: String, source: regex::Error },
    #[snafu(display("Too Many Requests, max:{max}"))]
    TooManyRequest { max: i32 },
    #[snafu(display("Request Entity Too Large, max:{max}"))]
    BodyTooLarge { max: usize },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub struct LocationStats {
    pub processing: i32,
    pub accepted: u64,
}

// PathSelector enum represents different ways to match request paths:
// - Regex: Uses regex pattern matching
// - Prefix: Matches if path starts with prefix
// - Equal: Matches exact path
// - Any: Matches all paths
#[derive(Debug)]
enum PathSelector {
    Regex(RegexCapture),
    Prefix(String),
    Equal(String),
    Any,
}
impl PathSelector {
    /// Creates a new path selector based on the input path string.
    ///
    /// # Arguments
    /// * `path` - The path pattern string to parse
    ///
    /// # Returns
    /// * `Result<PathSelector>` - The parsed path selector or error
    ///
    /// # Path Format
    /// - Empty string: Matches all paths
    /// - Starting with "~": Regex pattern matching
    /// - Starting with "=": Exact path matching  
    /// - Otherwise: Prefix path matching
    fn new(path: &str) -> Result<Self> {
        let path = path.trim();
        if path.is_empty() {
            return Ok(PathSelector::Any);
        }

        if let Some(re_path) = path.strip_prefix('~') {
            let re = RegexCapture::new(re_path.trim()).context(RegexSnafu {
                value: re_path.trim(),
            })?;
            Ok(PathSelector::Regex(re))
        } else if let Some(eq_path) = path.strip_prefix('=') {
            Ok(PathSelector::Equal(eq_path.trim().to_string()))
        } else {
            Ok(PathSelector::Prefix(path.to_string()))
        }
    }
    #[inline]
    fn is_match(&self, path: &str) -> (bool, Option<AHashMap<String, String>>) {
        match self {
            // For exact path matching, compare path strings directly
            PathSelector::Equal(value) => (value == path, None),
            // For regex path matching, use regex is_match
            PathSelector::Regex(value) => value.captures(path),
            // For prefix path matching, check if path starts with prefix
            PathSelector::Prefix(value) => (path.starts_with(value), None),
            // Empty path selector matches everything
            PathSelector::Any => (true, None),
        }
    }
}

// HostSelector enum represents ways to match request hosts:
// - Regex: Uses regex pattern matching with capture groups
// - Equal: Matches exact hostname
// - Suffix: Matches one-or-more subdomains of a domain (`*.example.com`)
#[derive(Debug)]
enum HostSelector {
    Regex(RegexCapture),
    Equal(String),
    /// Domain without the leading `*.` — e.g. `"example.com"` for `*.example.com`.
    /// Matches `a.example.com` but not the apex `example.com` (same as common
    /// TLS wildcard rules).
    Suffix(String),
}
impl HostSelector {
    /// Creates a new host selector based on the input host string.
    ///
    /// # Arguments
    /// * `host` - The host pattern string to parse
    ///
    /// # Returns
    /// * `Result<HostSelector>` - The parsed host selector or error
    ///
    /// # Host Format
    /// - Empty string: Matches empty host
    /// - Starting with "~": Regex pattern matching with capture groups
    /// - Starting with `*.`: Suffix / subdomain wildcard (`*.example.com`)
    /// - Otherwise: Exact hostname matching
    fn new(host: &str) -> Result<Self> {
        let host = host.trim();
        if let Some(re_host) = host.strip_prefix('~') {
            let re = RegexCapture::new(re_host.trim()).context(RegexSnafu {
                value: re_host.trim(),
            })?;
            Ok(HostSelector::Regex(re))
        } else if let Some(domain) = host.strip_prefix("*.") {
            let domain = domain.trim();
            if domain.is_empty() || domain.contains('*') {
                return Err(Error::Invalid {
                    message: format!("invalid host wildcard pattern: {host}"),
                });
            }
            Ok(HostSelector::Suffix(domain.to_ascii_lowercase()))
        } else {
            Ok(HostSelector::Equal(host.to_ascii_lowercase()))
        }
    }
    /// Host matching is case-insensitive (the Host header may vary in
    /// case) and compares in place: the patterns are stored lowercased, so
    /// no lowercased copy of the request host is made per selector.
    #[inline]
    fn is_match(&self, host: &str) -> (bool, Option<AHashMap<String, String>>) {
        match self {
            HostSelector::Equal(value) => {
                (value.eq_ignore_ascii_case(host), None)
            },
            HostSelector::Suffix(domain) => {
                (host_matches_suffix(host, domain), None)
            },
            HostSelector::Regex(value) => value.captures(host),
        }
    }
}

/// `*.example.com` style: `host` is a subdomain of `domain` (lowercase),
/// not the apex itself. Case-insensitive, byte-wise, so a host that is not
/// ASCII cannot be split inside a character.
#[inline]
pub(crate) fn host_matches_suffix(host: &str, domain: &str) -> bool {
    let host = host.as_bytes();
    let Some(dot) = host.len().checked_sub(domain.len() + 1) else {
        return false;
    };
    dot > 0
        && host[dot] == b'.'
        && host[dot + 1..].eq_ignore_ascii_case(domain.as_bytes())
}

/// The path an upstream should receive for `path`, or `None` when it is
/// forwarded unchanged.
///
/// `rewrite` wins: it replaces the whole path, whatever `prefix` says. Without
/// it, `prefix` (from the location's `PathSelector::Prefix`) is stripped from
/// the front — `/api/users` with `prefix` `/api` becomes `/users`. The result is
/// always an absolute path: an exact hit on the prefix (`/api`) and a prefix
/// that consumed everything (`/` on `/`) collapse to `/`, and a prefix without
/// a trailing slash that leaves no separator (`/api/` on `/api/users`, `/` on
/// `/users`) gets one back.
///
/// The query string is not part of `path`; the caller keeps it. Matching is
/// byte-exact, the same comparison [`PathSelector::is_match`] uses, so a path
/// that did not match the prefix cannot be rewritten here either.
pub(crate) fn stripped_path(
    path: &str,
    prefix: Option<&str>,
    rewrite: Option<&str>,
) -> Option<String> {
    let new_path = match rewrite {
        Some(rewrite) => rewrite.to_string(),
        None => {
            let rest = path.strip_prefix(prefix?)?;
            if rest.is_empty() {
                "/".to_string()
            } else if rest.starts_with('/') {
                rest.to_string()
            } else {
                format!("/{rest}")
            }
        },
    };
    (new_path != path).then_some(new_path)
}

/// Points `header` at `new_path`, keeping the query string it already carries.
/// Returns whether the target was replaced; a target the URI parser rejects
/// leaves the original in place, because forwarding the unstripped path is
/// better than failing the request.
fn set_request_path(header: &mut RequestHeader, new_path: &str) -> bool {
    let query = header.uri.query();
    let mut target = String::with_capacity(
        new_path.len() + query.map_or(0, |q| q.len() + 1),
    );
    target.push_str(new_path);
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }
    match target.parse::<http::Uri>() {
        Ok(uri) => {
            header.set_uri(uri);
            true
        },
        Err(e) => {
            warn!(
                target: LOG_TARGET,
                error = %e,
                path = new_path,
                "upstream path rewrite is not a valid uri, keeping the original path"
            );
            false
        },
    }
}

/// Classification of a single host pattern for the routing index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostIndexEntry {
    /// Exact host string (already lowercased).
    Exact(String),
    /// Suffix domain without `*.` (already lowercased).
    Suffix(String),
    /// Regex host — cannot be hashed, scanned linearly.
    Regex,
    /// No host restriction — matches every request host.
    Any,
}

// proxy_set_header X-Real-IP $remote_addr;
// proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
// proxy_set_header X-Forwarded-Proto $scheme;
// proxy_set_header X-Forwarded-Host $host;
// proxy_set_header X-Forwarded-Port $server_port;
static DEFAULT_PROXY_SET_HEADERS: LazyLock<Vec<HttpHeader>> =
    LazyLock::new(|| {
        convert_headers(&[
            "x-real-ip:$remote_addr".to_string(),
            "x-forwarded-for:$proxy_add_x_forwarded_for".to_string(),
            "x-forwarded-proto:$scheme".to_string(),
            "x-forwarded-host:$host".to_string(),
            "x-forwarded-port:$server_port".to_string(),
        ])
        .expect("Failed to convert default proxy set headers")
    });

/// A compiled URL rewrite rule with values precomputed at construction so the
/// per-request path (see [`Location::rewrite`]) avoids re-deriving them.
#[derive(Debug)]
struct RegexRewrite {
    /// Regex matched against the request path.
    re: Regex,
    /// Replacement string (may contain `$name` capture references).
    value: String,
    /// Pattern is `.*`: the whole path is replaced, no matching needed.
    match_all: bool,
    /// Regex declares named capture groups worth extracting into `variables`.
    has_named_captures: bool,
    /// The replacement holds a `$`, so request variables may apply to it.
    has_variables: bool,
}

impl RegexRewrite {
    /// Parses `"<regex> <replacement>"`. A lone replacement holding `$`
    /// (`"/$1"`) rewrites the whole path; a lone pattern rewrites its
    /// match to nothing. The pattern must compile: a rewrite that did not
    /// used to be silently dropped, leaving the location proxying the
    /// original path.
    fn new(value: &str) -> Result<Self> {
        let mut parts = value.split_whitespace();
        let (pattern, replacement) = match (parts.next(), parts.next()) {
            (Some(only), None) if only.contains('$') => (".*", only),
            (Some(pattern), replacement) => {
                (pattern, replacement.unwrap_or(""))
            },
            (None, _) => (".*", ""),
        };
        if parts.next().is_some() {
            return Err(Error::Invalid {
                message: format!(
                    "rewrite {value:?} is invalid, expected \"<regex> <replacement>\""
                ),
            });
        }
        let re = Regex::new(pattern).context(RegexSnafu { value: pattern })?;
        Ok(Self {
            match_all: re.as_str() == ".*",
            has_named_captures: re.capture_names().flatten().next().is_some(),
            has_variables: replacement.contains('$'),
            re,
            value: replacement.to_string(),
        })
    }
}

/// Substitutes `$name` in `template` with the value of request variable
/// `name`. A `$` naming no variable (`$1`, a regex group) is left for the
/// regex replacement. Borrowed when nothing applied.
fn interpolate_variables<'a>(
    template: &'a str,
    variables: &AHashMap<String, String>,
) -> Cow<'a, str> {
    let bytes = template.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let end = start
            + bytes[start..]
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
                .count();
        if end > start
            && let Some(value) = variables.get(&template[start..end])
        {
            let out = out.get_or_insert_with(|| {
                String::with_capacity(template.len() + 16)
            });
            out.push_str(&template[copied..i]);
            out.push_str(value);
            copied = end;
        }
        i = end.max(start);
    }
    match out {
        Some(mut out) => {
            out.push_str(&template[copied..]);
            Cow::Owned(out)
        },
        None => Cow::Borrowed(template),
    }
}

/// Parses `["name:value", "name", ...]` match conditions into `(name, value)`
/// pairs, where a missing value means a presence-only check.
fn parse_match_conditions(
    list: &Option<Vec<String>>,
) -> Vec<(String, Option<String>)> {
    list.as_ref()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let item = item.trim();
                    if item.is_empty() {
                        return None;
                    }
                    let cond = match item.split_once(':') {
                        Some((n, v)) => {
                            (n.trim().to_string(), Some(v.trim().to_string()))
                        },
                        None => (item.to_string(), None),
                    };
                    Some(cond)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Compiles `match_ip_ranges` into networks. A bare address is read as a
/// host route; an entry that is neither an address nor a CIDR network is a
/// configuration error, so a typo cannot quietly turn a gated location into
/// one that matches nobody (or everybody).
fn parse_ip_conditions(list: &Option<Vec<String>>) -> Result<Vec<IpNet>> {
    let Some(items) = list else {
        return Ok(vec![]);
    };
    items
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| {
            item.parse::<IpNet>()
                .or_else(|_| item.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| Error::Invalid {
                    message: format!("ip or cidr: {item}"),
                })
        })
        .collect()
}

/// Rewrites an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, what a dual-stack
/// listener reports for IPv4 peers) to its IPv4 form so v4 ranges match it.
#[inline]
fn normalize_client_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        },
        v4 => v4,
    }
}

/// Returns true if `actual` satisfies `expected`: present with the exact value,
/// or merely present when no value is required.
#[inline]
fn condition_met(actual: Option<&str>, expected: &Option<String>) -> bool {
    match actual {
        Some(a) => expected.as_deref().is_none_or(|v| v == a),
        None => false,
    }
}

/// The plugin instances a location's names resolved to, stamped with the
/// provider version they came from.
struct ResolvedPlugins {
    version: u64,
    plugins: Arc<[NamedPlugin]>,
}

impl std::fmt::Debug for ResolvedPlugins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> =
            self.plugins.iter().map(|(name, _)| name.as_ref()).collect();
        f.debug_struct("ResolvedPlugins")
            .field("version", &self.version)
            .field("plugins", &names)
            .finish()
    }
}

/// Location represents a routing configuration for handling HTTP requests.
/// It defines rules for matching requests based on paths and hosts, and specifies
/// how these requests should be processed and proxied.
#[derive(Debug)]
pub struct Location {
    /// Unique identifier for this location configuration
    pub name: Arc<str>,

    /// Hash key used for configuration versioning and change detection
    pub key: String,

    /// Target upstream server where requests will be proxied to
    upstream: String,

    /// Compiled path matching rules (regex, prefix, exact or any)
    path_selector: PathSelector,

    /// List of host patterns to match against request Host header
    /// Empty list means match all hosts
    hosts: Vec<HostSelector>,

    /// Optional request-header match conditions. A location matches only when
    /// every condition holds: a `(name, Some(value))` requires that exact
    /// header value, a `(name, None)` requires the header to be present. Empty
    /// (the common case) always matches, so non-conditional locations pay
    /// nothing. Covers headers, query params and cookies.
    header_conditions: Vec<(String, Option<String>)>,
    query_conditions: Vec<(String, Option<String>)>,
    cookie_conditions: Vec<(String, Option<String>)>,

    /// Optional client-IP condition: the peer address must fall inside one of
    /// these networks for the location to serve. Empty (the common case)
    /// always matches.
    ip_conditions: Vec<IpNet>,

    /// Optional URL rewriting rule consisting of:
    /// - regex pattern to match against request path
    /// - replacement string with optional capture group references
    reg_rewrite: Option<RegexRewrite>,

    /// Strip the matched prefix from the path sent upstream (`strip_prefix`).
    /// Only a `PathSelector::Prefix` gives `path_prefix()` a value, so this is
    /// inert for exact/regex locations. Never applied to the session's own
    /// request header — see [`Location::rewrite_upstream_path`].
    strip_prefix: bool,

    /// Fixed path replacing the whole upstream path (`rewrite_path`); wins
    /// over `strip_prefix`.
    rewrite_path: Option<String>,

    /// Headers to set or append on proxied requests
    pub headers: Option<Vec<(HeaderName, HeaderValue, bool)>>,
    /// Host header sent to the upstream; `None` keeps the client's Host.
    upstream_host: Option<HeaderValue>,

    /// Additional headers to append to proxied requests
    /// These are added without removing existing headers
    // pub proxy_add_headers: Option<Vec<HttpHeader>>,

    /// Headers to set on proxied requests
    /// These override any existing headers with the same name
    // pub proxy_set_headers: Option<Vec<HttpHeader>>,

    /// Ordered list of plugin names to execute during request/response processing
    pub plugins: Option<Vec<Arc<str>>>,

    /// `plugins` resolved to instances, kept until the plugin provider
    /// reports a new version. Requests share the list instead of looking
    /// every name up again.
    resolved_plugins: ArcSwapOption<ResolvedPlugins>,

    /// Total number of requests accepted by this location
    /// Used for metrics and monitoring
    accepted: AtomicU64,

    /// Number of requests currently being processed
    /// Used for concurrency control
    processing: AtomicI32,

    /// Maximum number of concurrent requests allowed
    /// Zero means unlimited
    max_processing: i32,

    /// Whether to enable gRPC-Web protocol support
    /// When true, handles gRPC-Web requests and converts them to regular gRPC
    grpc_web: bool,

    /// Maximum allowed size of client request body in bytes
    /// Zero means unlimited. Requests exceeding this limit receive 413 error
    client_max_body_size: usize,

    /// Whether to automatically add standard reverse proxy headers like:
    /// X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, etc.
    // pub enable_reverse_proxy_headers: bool,

    /// Per-site downstream read/write timeout; `None` keeps the listener
    /// default. Stored as a Duration so the request path never parses strings.
    downstream_timeout: Option<Duration>,

    /// Maximum window for retries
    pub max_retries: Option<u8>,

    /// Maximum window for retries
    pub max_retry_window: Option<Duration>,
}

/// Formats a vector of header strings into internal HttpHeader representation.
///
/// # Arguments
/// * `values` - Optional vector of header strings in "Name: Value" format
///
/// # Returns
/// * `Result<Option<Vec<HttpHeader>>>` - Parsed headers or None if input was None
fn format_headers(
    values: &Option<Vec<String>>,
) -> Result<Option<Vec<HttpHeader>>> {
    if let Some(header_values) = values {
        let arr =
            convert_headers(header_values).map_err(|err| Error::Invalid {
                message: err.to_string(),
            })?;
        Ok(Some(arr))
    } else {
        Ok(None)
    }
}

/// Get the content length from http request header.
fn get_content_length(header: &RequestHeader) -> Option<usize> {
    if let Some(content_length) =
        header.headers.get(http::header::CONTENT_LENGTH)
        && let Ok(size) =
            content_length.to_str().unwrap_or_default().parse::<usize>()
    {
        return Some(size);
    }
    None
}

impl Location {
    /// Per-site downstream read/write timeout, if configured. The caller
    /// applies it to the session after this location matches.
    pub fn downstream_timeout(&self) -> Option<Duration> {
        self.downstream_timeout
    }

    /// Creates a new Location from configuration
    /// Validates and compiles path/host patterns and other settings
    pub fn new(name: &str, conf: &LocationConf) -> Result<Location> {
        if name.is_empty() {
            return Err(Error::Invalid {
                message: "Name is required".to_string(),
            });
        }
        let key = conf.hash_key();
        let upstream = conf.upstream.clone().unwrap_or_default();
        // rewrite: "^/users/(.*)$ /api/users/$1"
        let reg_rewrite = conf
            .rewrite
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(RegexRewrite::new)
            .transpose()?;

        let hosts = conf
            .host
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(HostSelector::new)
            .collect::<Result<Vec<_>>>()?;

        // Parse optional match conditions ("name:value" for an exact value, or
        // "name" for a presence check) on headers, query params and cookies.
        let header_conditions = parse_match_conditions(&conf.match_headers);
        let query_conditions = parse_match_conditions(&conf.match_query);
        let cookie_conditions = parse_match_conditions(&conf.match_cookies);
        let ip_conditions = parse_ip_conditions(&conf.match_ip_ranges)?;

        let mut headers: Vec<(HeaderName, HeaderValue, bool)> = vec![];
        if conf.enable_reverse_proxy_headers.unwrap_or_default() {
            for (name, value) in DEFAULT_PROXY_SET_HEADERS.iter() {
                headers.push((name.clone(), value.clone(), false));
            }
        }
        // `$hostname` and `$ENV_VAR` values are fixed for the life of the
        // process: resolve them here so the request path only sees the
        // variables that really change per request.
        if let Some(proxy_set_headers) =
            format_headers(&conf.proxy_set_headers)?
        {
            for (name, value) in proxy_set_headers {
                headers.push((name, resolve_static_header_value(value), false));
            }
        }
        if let Some(proxy_add_headers) =
            format_headers(&conf.proxy_add_headers)?
        {
            for (name, value) in proxy_add_headers {
                headers.push((name, resolve_static_header_value(value), true));
            }
        }

        // A `rewrite_path` the data plane cannot apply is dropped, not fatal:
        // the value arrives through the agent's rule cache, so one bad field
        // must not take the whole site's config down with it. The rule itself
        // is the config file's (`pingap_config::validate_rewrite_path`), and
        // the control plane's route API enforces the same one before storing —
        // this is only the last line of defence.
        let rewrite_path = conf
            .rewrite_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| match validate_rewrite_path(value) {
                Ok(()) => Some(value.to_string()),
                Err(err) => {
                    warn!(
                        target: LOG_TARGET,
                        location = name,
                        rewrite_path = value,
                        error = %err,
                        "ignoring an invalid rewrite_path"
                    );
                    None
                },
            });

        let location = Location {
            name: name.into(),
            key,
            path_selector: PathSelector::new(
                conf.path.as_deref().unwrap_or_default(),
            )?,
            hosts,
            header_conditions,
            query_conditions,
            cookie_conditions,
            ip_conditions,
            upstream,
            reg_rewrite,
            // An empty `rewrite_path` means "unset": the control plane sends
            // every field as a string, so blank is the absent value on the
            // wire even though the config file rejects it.
            strip_prefix: conf.strip_prefix.unwrap_or_default(),
            rewrite_path,
            plugins: conf.plugins.as_ref().map(|list| {
                list.iter().map(|name| Arc::from(name.as_str())).collect()
            }),
            resolved_plugins: ArcSwapOption::const_empty(),
            accepted: AtomicU64::new(0),
            processing: AtomicI32::new(0),
            max_processing: conf.max_processing.unwrap_or_default(),
            grpc_web: conf.grpc_web.unwrap_or_default(),
            headers: if headers.is_empty() {
                None
            } else {
                Some(headers)
            },
            upstream_host: match conf.upstream_host.as_deref() {
                Some(value) if !value.trim().is_empty() => {
                    Some(HeaderValue::from_str(value.trim()).map_err(|e| {
                        Error::Invalid {
                            message: format!(
                                "invalid upstream_host '{value}': {e}"
                            ),
                        }
                    })?)
                },
                _ => None,
            },
            // proxy_add_headers: format_headers(&conf.proxy_add_headers)?,
            // proxy_set_headers: format_headers(&conf.proxy_set_headers)?,
            client_max_body_size: conf
                .client_max_body_size
                .unwrap_or_default()
                .as_u64() as usize,
            // enable_reverse_proxy_headers: conf
            //     .enable_reverse_proxy_headers
            //     .unwrap_or_default(),
            downstream_timeout: conf.downstream_timeout_secs.map(|secs| {
                Duration::from_secs(u64::from(secs.clamp(1, 3600)))
            }),
            max_retries: conf.max_retries,
            max_retry_window: conf.max_retry_window,
        };
        debug!(
            target: LOG_TARGET,
            location = format!("{location:?}"),
            "create a new location"
        );

        Ok(location)
    }

    /// Returns whether gRPC-Web protocol support is enabled for this location
    /// The location's plugins, resolved through `provider`. The list is
    /// built on the first request after the location or the plugins were
    /// loaded and shared by every request after that, so the per-request
    /// cost is one atomic load and one reference count. `None` when the
    /// location names no plugins or none of them exist.
    #[inline]
    pub fn plugins_for(
        &self,
        provider: &dyn PluginProvider,
    ) -> Option<Arc<[NamedPlugin]>> {
        let names = self.plugins.as_ref()?;
        let version = provider.version();
        if let Some(resolved) = self.resolved_plugins.load().as_ref()
            && resolved.version == version
        {
            return (!resolved.plugins.is_empty())
                .then(|| resolved.plugins.clone());
        }
        let plugins: Arc<[NamedPlugin]> = names
            .iter()
            .filter_map(|name| {
                provider.get(name).map(|plugin| (name.clone(), plugin))
            })
            .collect();
        self.resolved_plugins.store(Some(Arc::new(ResolvedPlugins {
            version,
            plugins: plugins.clone(),
        })));
        (!plugins.is_empty()).then_some(plugins)
    }

    /// When enabled, the proxy will handle gRPC-Web requests and convert them to regular gRPC
    #[inline]
    pub fn support_grpc_web(&self) -> bool {
        self.grpc_web
    }

    /// Whether the location strips its matched prefix from the upstream path.
    #[inline]
    pub fn strip_prefix(&self) -> bool {
        self.strip_prefix
    }

    /// The fixed path replacing the upstream path, when one is configured.
    #[inline]
    pub fn rewrite_path(&self) -> Option<&str> {
        self.rewrite_path.as_deref()
    }

    /// The prefix this location matches requests on: `Some` only for a prefix
    /// location, `None` for `=exact`, `~regex` and match-everything, which have
    /// no prefix to strip.
    #[inline]
    pub fn path_prefix(&self) -> Option<&str> {
        match &self.path_selector {
            PathSelector::Prefix(value) => Some(value.as_str()),
            _ => None,
        }
    }

    /// Rewrites `header`'s request target to the path the upstream should see:
    /// `rewrite_path` when configured, otherwise the path with the matched
    /// prefix stripped. The query string survives untouched.
    ///
    /// The proxy calls this on the copy of the request header it sends upstream
    /// (see `pingap-proxy`'s `upstream_request_filter`), so plugins — the WAF
    /// among them — the access log and the cache key all see the client's own
    /// path. Without `strip_prefix` and `rewrite_path` this is one flattened
    /// check and returns without allocating.
    pub fn rewrite_upstream_path(&self, header: &mut RequestHeader) {
        if self.rewrite_path.is_none() && !self.strip_prefix {
            return;
        }
        let path = header.uri.path();
        // Only origin-form targets carry a path to rewrite. `CONNECT` uses
        // authority-form and `OPTIONS *` asterisk-form; turning either into a
        // path would change what the request means.
        if !path.starts_with('/') {
            return;
        }
        let Some(new_path) = stripped_path(
            path,
            self.path_prefix(),
            self.rewrite_path.as_deref(),
        ) else {
            return;
        };
        debug!(
            target: LOG_TARGET,
            location = self.name.as_ref(),
            new_path,
            "rewrite upstream path"
        );
        set_request_path(header, &new_path);
    }

    /// Validates that the request's Content-Length header does not exceed the configured maximum
    ///
    /// # Arguments
    /// * `header` - The HTTP request header to validate
    ///
    /// # Returns
    /// * `Result<()>` - Ok if validation passes, Error::BodyTooLarge if content length exceeds limit
    ///
    /// # Notes
    /// - Returns Ok if client_max_body_size is 0 (unlimited)
    /// - Uses get_content_length() helper to parse the Content-Length header
    #[inline]
    pub fn validate_content_length(
        &self,
        header: &RequestHeader,
    ) -> Result<()> {
        if self.client_max_body_size == 0 {
            return Ok(());
        }
        if get_content_length(header).unwrap_or_default()
            > self.client_max_body_size
        {
            return Err(Error::BodyTooLarge {
                max: self.client_max_body_size,
            });
        }

        Ok(())
    }

    /// Host patterns of this location classified for [`crate::LocationHostIndex`].
    ///
    /// A multi-host location contributes one entry per pattern so it appears in
    /// every relevant bucket. Empty host list → a single [`HostIndexEntry::Any`].
    pub fn host_index_entries(&self) -> Vec<HostIndexEntry> {
        if self.hosts.is_empty() {
            return vec![HostIndexEntry::Any];
        }
        self.hosts
            .iter()
            .map(|selector| match selector {
                HostSelector::Equal(value) => {
                    HostIndexEntry::Exact(value.clone())
                },
                HostSelector::Suffix(domain) => {
                    HostIndexEntry::Suffix(domain.clone())
                },
                HostSelector::Regex(_) => HostIndexEntry::Regex,
            })
            .collect()
    }

    /// Checks if a request matches this location's path and host rules
    /// Returns a tuple containing:
    /// - bool: Whether the request matched both path and host rules
    /// - Option<Vec<(String, String)>>: Any captured variables from regex host matching
    #[inline]
    pub fn match_host_path(
        &self,
        host: &str,
        path: &str,
    ) -> (bool, Option<AHashMap<String, String>>) {
        // Path first: it is the cheaper check and the usual reason not to
        // match.
        let (matched, mut capture_values) = self.path_selector.is_match(path);
        if !matched {
            return (false, None);
        }

        // If no host patterns configured, path match is sufficient
        if self.hosts.is_empty() {
            return (true, capture_values);
        }

        let matched = self.hosts.iter().any(|host_selector| {
            let (matched, captures) = host_selector.is_match(host);
            if let Some(captures) = captures {
                if let Some(values) = capture_values.as_mut() {
                    values.extend(captures);
                } else {
                    capture_values = Some(captures);
                }
            }
            matched
        });

        (matched, capture_values)
    }

    /// Returns true when the request satisfies this location's optional
    /// header / query / cookie / client-IP match conditions. With none
    /// configured this is a cheap `true`, so non-conditional locations pay
    /// nothing.
    #[inline]
    pub fn match_conditions(
        &self,
        req_header: &RequestHeader,
        client_ip: Option<IpAddr>,
    ) -> bool {
        if !self.ip_conditions.is_empty() {
            let Some(client_ip) = client_ip.map(normalize_client_ip) else {
                return false;
            };
            if !self
                .ip_conditions
                .iter()
                .any(|network| network.contains(&client_ip))
            {
                return false;
            }
        }
        self.header_conditions.iter().all(|(name, expected)| {
            condition_met(
                pingap_core::get_req_header_value(req_header, name),
                expected,
            )
        }) && self.query_conditions.iter().all(|(name, expected)| {
            condition_met(
                pingap_core::get_query_value(req_header, name),
                expected,
            )
        }) && self.cookie_conditions.iter().all(|(name, expected)| {
            condition_met(
                pingap_core::get_cookie_value(req_header, name),
                expected,
            )
        })
    }

    pub fn stats(&self) -> LocationStats {
        LocationStats {
            processing: self.processing.load(Ordering::Relaxed),
            accepted: self.accepted.load(Ordering::Relaxed),
        }
    }
}

impl LocationInstance for Location {
    fn upstream_host(&self) -> Option<&HeaderValue> {
        self.upstream_host.as_ref()
    }

    fn name(&self) -> &str {
        self.name.as_ref()
    }
    fn headers(&self) -> Option<&Vec<(HeaderName, HeaderValue, bool)>> {
        self.headers.as_ref()
    }
    fn client_body_size_limit(&self) -> usize {
        self.client_max_body_size
    }
    fn upstream(&self) -> &str {
        self.upstream.as_ref()
    }
    fn rewrite_upstream_path(&self, header: &mut RequestHeader) {
        Location::rewrite_upstream_path(self, header);
    }
    fn on_response(&self) {
        self.processing.fetch_sub(1, Ordering::Relaxed);
    }
    /// Increments the processing and accepted request counters for this location.
    ///
    /// This method is called when a new request starts being processed by this location.
    /// It performs two atomic operations:
    /// 1. Increments the total accepted requests counter
    /// 2. Increments the currently processing requests counter
    ///
    /// # Returns
    /// * `Result<(u64, i32)>` - A tuple containing:
    ///   - The new total number of accepted requests (u64)
    ///   - The new number of currently processing requests (i32)
    ///
    /// # Errors
    /// Returns `Error::TooManyRequest` if the number of currently processing requests
    /// would exceed the configured `max_processing` limit (when non-zero).
    fn on_request(&self) -> pingora::Result<(u64, i32)> {
        let accepted = self.accepted.fetch_add(1, Ordering::Relaxed) + 1;
        let processing = self.processing.fetch_add(1, Ordering::Relaxed) + 1;
        if self.max_processing != 0 && processing > self.max_processing {
            let err = Error::TooManyRequest {
                max: self.max_processing,
            };
            return Err(new_internal_error(429, err));
        }
        Ok((accepted, processing))
    }
    /// Applies URL rewriting rules if configured for this location.
    ///
    /// This method performs path rewriting based on regex patterns and replacement rules.
    /// It supports variable interpolation from captured values in the host matching.
    ///
    /// # Arguments
    /// * `header` - Mutable reference to the request header containing the URI to rewrite
    /// * `variables` - Optional map of variables captured from host matching that can be interpolated
    ///   into the replacement value
    ///
    /// # Returns
    /// * `bool` - Returns true if the path was rewritten, false if no rewriting was performed
    ///
    /// # Examples
    /// ```
    /// // Configuration example:
    /// // rewrite: "^/users/(.*)$ /api/users/$1"
    /// // This would rewrite "/users/123" to "/api/users/123"
    /// ```
    ///
    /// # Notes
    /// - Preserves query parameters when rewriting the path
    /// - Logs debug information about path rewrites
    /// - Logs errors if the new path cannot be parsed as a valid URI
    #[inline]
    fn rewrite(
        &self,
        header: &mut RequestHeader,
        variables: &mut Option<AHashMap<String, String>>,
    ) -> bool {
        let Some(rewrite) = &self.reg_rewrite else {
            return false;
        };
        let re = &rewrite.re;
        let path = header.uri.path();

        // `$name` in the replacement is a request variable (a host capture,
        // a plugin's) before it is a regex group: those are filled in first,
        // and only when the replacement can hold one at all.
        let replacement = match variables.as_ref() {
            Some(vars) if rewrite.has_variables && !vars.is_empty() => {
                interpolate_variables(&rewrite.value, vars)
            },
            _ => Cow::Borrowed(rewrite.value.as_str()),
        };

        // One pass over the path: the leftmost match both builds the new
        // path (what `Regex::replace` does) and keeps its groups, so the
        // named captures below cost no second run of the regex.
        let mut captures = None;
        let mut new_path = if rewrite.match_all {
            replacement.into_owned()
        } else {
            let Some(found) = re.captures(path) else {
                // no match: nothing to rewrite, and nothing was allocated
                return false;
            };
            let Some(whole) = found.get(0) else {
                return false;
            };
            let mut new_path =
                String::with_capacity(path.len() + replacement.len());
            new_path.push_str(&path[..whole.start()]);
            found.expand(replacement.as_ref(), &mut new_path);
            new_path.push_str(&path[whole.end()..]);
            captures = Some(found);
            new_path
        };
        if new_path == path {
            return false;
        }

        if rewrite.has_named_captures
            && let Some(captures) = &captures
        {
            for name in re.capture_names().flatten() {
                if let Some(match_value) = captures.name(name) {
                    let values = variables.get_or_insert_with(AHashMap::new);
                    values.insert(
                        name.to_string(),
                        match_value.as_str().to_string(),
                    );
                }
            }
        }

        // preserve query parameters, appended in place
        if let Some(query) = header.uri.query() {
            new_path.reserve(query.len() + 1);
            new_path.push('?');
            new_path.push_str(query);
        }
        debug!(target: LOG_TARGET, new_path, "rewrite path");

        // set new uri
        if let Err(e) =
            new_path.parse::<http::Uri>().map(|uri| header.set_uri(uri))
        {
            error!(target: LOG_TARGET, error = %e, location = self.name.as_ref(), "new path parse fail");
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytesize::ByteSize;
    use pingap_config::LocationConf;
    use pingora::http::RequestHeader;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_format_headers() {
        let headers = format_headers(&Some(vec![
            "Content-Type: application/json".to_string(),
        ]))
        .unwrap();
        assert_eq!(
            r###"Some([("content-type", "application/json")])"###,
            format!("{headers:?}")
        );
    }
    #[test]
    fn test_new_path_selector() {
        let selector = PathSelector::new("").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::Any));

        let selector = PathSelector::new("~/api").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::Regex(_)));

        let selector = PathSelector::new("=/api").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::Equal(_)));

        let selector = PathSelector::new("/api").unwrap();
        assert_eq!(true, matches!(selector, PathSelector::Prefix(_)));
    }
    #[test]
    fn test_path_host_select_location() {
        let upstream_name = "charts";

        // no path, no host
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("pingap", "/api").0);
        assert_eq!(true, lo.match_host_path("", "").0);

        // host
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                host: Some("test.com,pingap".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("pingap", "/api").0);
        assert_eq!(true, lo.match_host_path("Pingap", "/api").0); // case-insensitive
        assert_eq!(true, lo.match_host_path("pingap", "").0);
        assert_eq!(false, lo.match_host_path("", "/api").0);

        // wildcard suffix host
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                host: Some("*.example.com".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("a.example.com", "/").0);
        assert_eq!(true, lo.match_host_path("api.example.com", "/").0);
        assert_eq!(true, lo.match_host_path("API.Example.COM", "/").0);
        assert_eq!(false, lo.match_host_path("example.com", "/").0);
        assert_eq!(false, lo.match_host_path("evil-example.com", "/").0);
        assert_eq!(false, lo.match_host_path(".example.com", "/").0);
        assert_eq!(false, lo.match_host_path("com", "/").0);
        // a non-ASCII host is compared byte-wise, never split in a char
        assert_eq!(false, lo.match_host_path("ü.example.co", "/").0);
        assert_eq!(true, lo.match_host_path("ü.example.com", "/").0);

        // regex
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("~/users".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("", "/api/users").0);
        assert_eq!(true, lo.match_host_path("", "/users").0);
        assert_eq!(false, lo.match_host_path("", "/api").0);

        // regex ^/api
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("~^/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("", "/api/users").0);
        assert_eq!(false, lo.match_host_path("", "/users").0);
        assert_eq!(true, lo.match_host_path("", "/api").0);

        // prefix
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, lo.match_host_path("", "/api/users").0);
        assert_eq!(false, lo.match_host_path("", "/users").0);
        assert_eq!(true, lo.match_host_path("", "/api").0);

        // equal
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                path: Some("=/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(false, lo.match_host_path("", "/api/users").0);
        assert_eq!(false, lo.match_host_path("", "/users").0);
        assert_eq!(true, lo.match_host_path("", "/api").0);
    }

    #[test]
    fn test_match_host_path_variables() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                host: Some("~(?<name>.+).npmtrend.com".to_string()),
                path: Some("~/(?<route>.+)/(.*)".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let (matched, variables) =
            lo.match_host_path("charts.npmtrend.com", "/users/123");
        assert_eq!(true, matched);
        let variables = variables.unwrap();
        assert_eq!("users", variables.get("route").unwrap());
        assert_eq!("charts", variables.get("name").unwrap());
    }

    #[test]
    fn test_rewrite_path() {
        let upstream_name = "charts";

        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some(upstream_name.to_string()),
                rewrite: Some("^/users/(?<upstream>.*?)/(.*)$ /$2".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/users/rest/me?abc=1", None).unwrap();
        let mut variables = None;
        let matched = lo.rewrite(&mut req_header, &mut variables);
        assert_eq!(true, matched);
        assert_eq!(r#"Some({"upstream": "rest"})"#, format!("{:?}", variables));
        assert_eq!("/me?abc=1", req_header.uri.to_string());

        let mut req_header =
            RequestHeader::build("GET", b"/api/me?abc=1", None).unwrap();
        let mut variables = None;
        let matched = lo.rewrite(&mut req_header, &mut variables);
        assert_eq!(false, matched);
        assert_eq!(None, variables);
        assert_eq!("/api/me?abc=1", req_header.uri.to_string());
    }

    /// The resolved plugin list is shared until the provider reports a new
    /// version, then rebuilt.
    #[test]
    fn test_plugins_for_follows_provider_version() {
        use pingap_core::Plugin;
        use std::sync::atomic::AtomicBool;

        struct NoopPlugin;
        impl Plugin for NoopPlugin {}

        struct Provider {
            version: AtomicU64,
            present: AtomicBool,
        }
        impl PluginProvider for Provider {
            fn get(&self, _name: &str) -> Option<Arc<dyn Plugin>> {
                self.present
                    .load(Ordering::Relaxed)
                    .then(|| Arc::new(NoopPlugin) as Arc<dyn Plugin>)
            }
            fn version(&self) -> u64 {
                self.version.load(Ordering::Relaxed)
            }
        }

        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("up".to_string()),
                plugins: Some(vec!["a".to_string(), "b".to_string()]),
                ..Default::default()
            },
        )
        .unwrap();
        let provider = Provider {
            version: AtomicU64::new(1),
            present: AtomicBool::new(true),
        };
        let first = lo.plugins_for(&provider).expect("resolved");
        assert_eq!(2, first.len());
        assert_eq!("a", first[0].0.as_ref());

        // Same version: the very same list is handed out again.
        let again = lo.plugins_for(&provider).expect("cached");
        assert_eq!(true, Arc::ptr_eq(&first, &again));

        // The provider changed without saying so: the cache is trusted.
        provider.present.store(false, Ordering::Relaxed);
        assert_eq!(true, lo.plugins_for(&provider).is_some());

        // A new version rebuilds the list, and nothing resolves now.
        provider.version.store(2, Ordering::Relaxed);
        assert_eq!(true, lo.plugins_for(&provider).is_none());

        // No plugin names at all: nothing to resolve, nothing cached.
        let bare = Location::new(
            "bare",
            &LocationConf {
                upstream: Some("up".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(true, bare.plugins_for(&provider).is_none());
    }

    /// `$name` in the replacement takes the request variable of that name
    /// (a host capture, a plugin's); `$1` and regex groups are untouched.
    #[test]
    fn test_rewrite_with_variables() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                host: Some("~(?<tenant>.+)\\.example\\.com".to_string()),
                rewrite: Some("^/users/(.*)$ /$tenant/$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let (matched, mut variables) =
            lo.match_host_path("acme.example.com", "/users/me");
        assert_eq!(true, matched);
        let mut req_header =
            RequestHeader::build("GET", b"/users/me?x=1", None).unwrap();
        assert_eq!(true, lo.rewrite(&mut req_header, &mut variables));
        assert_eq!("/acme/me?x=1", req_header.uri.to_string());

        // Without variables the `$tenant` is left to the regex, which knows
        // no such group and expands it to nothing.
        let mut req_header =
            RequestHeader::build("GET", b"/users/me", None).unwrap();
        assert_eq!(true, lo.rewrite(&mut req_header, &mut None));
        assert_eq!("//me", req_header.uri.to_string());

        // A request that does not match the pattern is left alone.
        let mut req_header =
            RequestHeader::build("GET", b"/other?x=1", None).unwrap();
        let mut variables =
            Some(AHashMap::from([("tenant".to_string(), "acme".to_string())]));
        assert_eq!(false, lo.rewrite(&mut req_header, &mut variables));
        assert_eq!("/other?x=1", req_header.uri.to_string());
    }

    #[test]
    fn test_interpolate_variables() {
        let vars = AHashMap::from([
            ("tenant".to_string(), "acme".to_string()),
            ("v".to_string(), "2".to_string()),
        ]);
        let interpolate = |template: &str| {
            interpolate_variables(template, &vars).into_owned()
        };
        assert_eq!("/acme/$1", interpolate("/$tenant/$1"));
        assert_eq!("/api/v2/2", interpolate("/api/v$v/$v"));
        // a name that is only a prefix of a longer identifier is not it
        assert_eq!("/$tenants", interpolate("/$tenants"));
        assert_eq!("/$1/$$", interpolate("/$1/$$"));
        assert_eq!("acme", interpolate("$tenant"));
        assert_eq!("$", interpolate("$"));
        assert_eq!(
            true,
            matches!(interpolate_variables("/plain", &vars), Cow::Borrowed(_))
        );
    }

    /// A rewrite that does not parse is an error, not a silently ignored
    /// rule.
    #[test]
    fn test_invalid_rewrite_is_rejected() {
        let build = |rewrite: &str| {
            Location::new(
                "lo",
                &LocationConf {
                    upstream: Some("charts".to_string()),
                    rewrite: Some(rewrite.to_string()),
                    ..Default::default()
                },
            )
            .err()
            .map(|e| e.to_string())
        };
        assert_eq!(
            Some("Regex value: ^/users/(, regex parse error:\n    ^/users/(\n            ^\nerror: unclosed group".to_string()),
            build("^/users/( /")
        );
        assert_eq!(
            Some("Invalid error rewrite \"^/a /b /c\" is invalid, expected \"<regex> <replacement>\"".to_string()),
            build("^/a /b /c")
        );
        // whitespace runs and a blank rule are fine
        assert_eq!(None, build("^/a   /b"));
        assert_eq!(None, build("  "));
    }

    /// The strip/replace arithmetic, isolated from any location: the origin
    /// gets an absolute path, an exact hit on the prefix collapses to `/`, and
    /// a path that does not carry the prefix is left alone.
    #[test]
    fn stripped_path_rewrites_the_prefix_only() {
        let strip =
            |path: &str, prefix: &str| stripped_path(path, Some(prefix), None);
        assert_eq!(strip("/api/users", "/api"), Some("/users".to_string()));
        // exact hit on the prefix: the origin root
        assert_eq!(strip("/api", "/api"), Some("/".to_string()));
        // prefix with a trailing slash still yields an absolute path
        assert_eq!(strip("/api/users", "/api/"), Some("/users".to_string()));
        // a `/` prefix consumes the separator and puts it back: no change
        assert_eq!(strip("/users", "/"), None);
        assert_eq!(strip("/", "/"), None);
        // not the configured prefix
        assert_eq!(strip("/other", "/api"), None);
        // no prefix (exact/regex location)
        assert_eq!(stripped_path("/api", None, None), None);

        // `rewrite_path` wins over the prefix and ignores it entirely
        assert_eq!(
            stripped_path("/api/users", Some("/api"), Some("/v2")),
            Some("/v2".to_string())
        );
        assert_eq!(
            stripped_path("/api/users", None, Some("/v2")),
            Some("/v2".to_string())
        );
        // the root itself is a valid replacement
        assert_eq!(
            stripped_path("/api/users", None, Some("/")),
            Some("/".to_string())
        );
        // a replacement equal to the current path is no rewrite
        assert_eq!(stripped_path("/v2", None, Some("/v2")), None);
    }

    /// A prefix route strips what it matched, keeps the query string, and
    /// rewrites only the header it is handed — the session's own header is what
    /// plugins and the access log read.
    #[test]
    fn rewrite_upstream_path_strips_the_prefix_and_keeps_the_query() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("api".to_string()),
                path: Some("/api".to_string()),
                strip_prefix: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(lo.strip_prefix());
        assert_eq!(lo.rewrite_path(), None);
        assert_eq!(lo.path_prefix(), Some("/api"));

        let mut header =
            RequestHeader::build("GET", b"/api/users?x=1&y=2", None).unwrap();
        lo.rewrite_upstream_path(&mut header);
        assert_eq!(header.uri.path(), "/users");
        assert_eq!(header.uri.query(), Some("x=1&y=2"));

        // an exact hit reaches the origin root
        let mut header = RequestHeader::build("GET", b"/api", None).unwrap();
        lo.rewrite_upstream_path(&mut header);
        assert_eq!(header.uri.path(), "/");

        // another location's path is untouched
        let mut header =
            RequestHeader::build("GET", b"/other/users", None).unwrap();
        lo.rewrite_upstream_path(&mut header);
        assert_eq!(header.uri.path(), "/other/users");
    }

    /// `rewrite_path` replaces the whole path whatever the match type is, and
    /// keeps the query.
    #[test]
    fn rewrite_upstream_path_replaces_the_whole_path() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("api".to_string()),
                path: Some("=/api".to_string()),
                rewrite_path: Some("/v2".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(lo.rewrite_path(), Some("/v2"));
        // an exact location has no prefix to report
        assert_eq!(lo.path_prefix(), None);

        let mut header =
            RequestHeader::build("GET", b"/api/users?x=1", None).unwrap();
        lo.rewrite_upstream_path(&mut header);
        assert_eq!(header.uri.to_string(), "/v2?x=1");

        // The root is a valid replacement and keeps the query too.
        let lo = Location::new(
            "lo",
            &LocationConf {
                path: Some("/api".to_string()),
                rewrite_path: Some("/".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut header =
            RequestHeader::build("GET", b"/api/users?x=1", None).unwrap();
        lo.rewrite_upstream_path(&mut header);
        assert_eq!(header.uri.to_string(), "/?x=1");
    }

    /// The `rewrite_path` rule the data plane shares with the config file: one
    /// implementation, re-exported by this crate, so the loader and
    /// [`Location::new`] cannot disagree about what they accept.
    #[test]
    fn validate_rewrite_path_is_shared_with_the_config_layer() {
        let check = crate::validate_rewrite_path;

        // Valid: an absolute path, and the root itself (the whole path
        // collapses to the origin root).
        for good in ["/", "/v2", "/a/b", "/a%20b"] {
            assert_eq!(Ok(()), check(good), "{good:?} is a valid rewrite path");
        }

        // An empty string is "unset"; non-empty whitespace is an error,
        // because it looks configured while doing nothing.
        assert_eq!(Ok(()), check(""), "an empty value means unset");
        for blank in [" ", "   ", "\t", "\n"] {
            let err = check(blank).expect_err("blank must be rejected");
            assert!(
                err.contains("must not be blank"),
                "{blank:?} must fail as blank, got: {err}"
            );
        }

        // Absolute only, and nothing is trimmed into acceptance.
        assert!(
            check("v2")
                .expect_err("relative path")
                .contains("must start with '/'")
        );
        assert!(
            check(" /v2")
                .expect_err("padded")
                .contains("must not contain")
        );

        // `?` and `#` are rejected because the client's query string is
        // appended to the replacement verbatim; whitespace and control
        // characters would not survive the URI parser either.
        for bad in ["/v2?x=1", "/v2#frag", "/a b", "/v2\n", "/v2\t", "/v2\u{7}"]
        {
            assert!(check(bad).is_err(), "{bad:?} must be rejected");
        }

        // The ceiling is 2048 **bytes**, not characters.
        let at_limit =
            format!("/{}", "a".repeat(crate::MAX_REWRITE_PATH_LEN - 1));
        assert_eq!(Ok(()), check(&at_limit));
        let over = format!("/{}", "a".repeat(crate::MAX_REWRITE_PATH_LEN));
        assert!(
            check(&over)
                .expect_err("over the ceiling")
                .contains("at most 2048 bytes")
        );
        // 1025 characters, 2049 bytes: a character-count check would pass this.
        let multibyte = format!("/{}", "é".repeat(1024));
        assert_eq!(multibyte.len(), crate::MAX_REWRITE_PATH_LEN + 1);
        assert!(check(&multibyte).is_err(), "the ceiling counts bytes");
    }

    /// A `rewrite_path` the data plane cannot apply is logged and dropped: the
    /// location still loads and forwards the original path, because one bad
    /// field from the rule cache must not take the site's config down.
    #[test]
    fn location_ignores_an_invalid_rewrite_path() {
        let build = |rewrite_path: String| {
            Location::new(
                "lo",
                &LocationConf {
                    upstream: Some("api".to_string()),
                    path: Some("/api".to_string()),
                    rewrite_path: Some(rewrite_path),
                    ..Default::default()
                },
            )
            .expect("an invalid rewrite_path must not fail the location")
        };

        for bad in [
            "v2".to_string(),
            "/v2?x=1".to_string(),
            "/v2#frag".to_string(),
            "/v 2".to_string(),
            format!("/{}", "a".repeat(crate::MAX_REWRITE_PATH_LEN)),
        ] {
            let location = build(bad.clone());
            assert_eq!(
                None,
                location.rewrite_path(),
                "{bad:?} must be dropped, not applied"
            );
            // Nothing is stripped or replaced: the client's path is forwarded.
            let mut header =
                RequestHeader::build("GET", b"/api/users?x=1", None).unwrap();
            location.rewrite_upstream_path(&mut header);
            assert_eq!("/api/users?x=1", header.uri.to_string());
        }

        // Blank is the wire's "unset" (the control plane sends every field as
        // a string) and is dropped without a complaint; padding is trimmed the
        // same way, and a valid value applies.
        assert_eq!(None, build("   ".to_string()).rewrite_path());
        assert_eq!(Some("/v2"), build("  /v2  ".to_string()).rewrite_path());
    }

    /// A target the URI parser rejects leaves the request header alone:
    /// forwarding the unstripped path beats failing the request. The paths this
    /// runs on are normally a `strip_prefix` result or a validated
    /// `rewrite_path`, so this is the guard for everything else — a regex
    /// rewrite's output, a value that lost its leading slash.
    #[test]
    fn set_request_path_keeps_the_original_when_the_uri_is_invalid() {
        let mut header =
            RequestHeader::build("GET", b"/api/users?x=1", None).unwrap();

        // A space is not a uri character; without the leading slash the target
        // is not origin-form.
        for bad in ["/a b", "v2"] {
            assert_eq!(
                false,
                set_request_path(&mut header, bad),
                "{bad:?} is not a valid uri"
            );
            assert_eq!("/api/users?x=1", header.uri.to_string());
        }

        // The same call with a usable target rewrites the path and keeps the
        // query string.
        assert_eq!(true, set_request_path(&mut header, "/v2"));
        assert_eq!("/v2?x=1", header.uri.to_string());
    }

    /// Nothing configured is the common case: the header must come back
    /// untouched, and an exact/regex location ignores `strip_prefix` because it
    /// has no prefix to strip.
    #[test]
    fn rewrite_upstream_path_is_inert_without_a_usable_rule() {
        let plain = Location::new(
            "lo",
            &LocationConf {
                path: Some("/api".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut header =
            RequestHeader::build("GET", b"/api/users?x=1", None).unwrap();
        plain.rewrite_upstream_path(&mut header);
        assert_eq!(header.uri.to_string(), "/api/users?x=1");

        let exact = Location::new(
            "lo",
            &LocationConf {
                path: Some("=/api".to_string()),
                strip_prefix: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
        let mut header =
            RequestHeader::build("GET", b"/api/users?x=1", None).unwrap();
        exact.rewrite_upstream_path(&mut header);
        assert_eq!(header.uri.to_string(), "/api/users?x=1");
    }

    /// A rule whose output equals the input is no rewrite: nothing is set
    /// and no captures are harvested, as before the single-pass version.
    #[test]
    fn test_rewrite_unchanged_path() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                rewrite: Some(
                    "^/(?<first>[a-z]+)/(.*)$ /$first/$2".to_string(),
                ),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/users/me?x=1", None).unwrap();
        let mut variables = None;
        assert_eq!(false, lo.rewrite(&mut req_header, &mut variables));
        assert_eq!(None, variables);
        assert_eq!("/users/me?x=1", req_header.uri.to_string());

        // `$$` is a literal dollar, `$0` the whole match.
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                rewrite: Some("^/old(/.*)$ /new$$$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/old/a", None).unwrap();
        assert_eq!(true, lo.rewrite(&mut req_header, &mut None));
        assert_eq!("/new$/a", req_header.uri.to_string());
    }

    #[test]
    fn test_rewrite_path_without_named_captures() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                rewrite: Some("^/old/(.*)$ /new/$1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/old/thing?x=1", None).unwrap();
        let mut variables = None;
        let matched = lo.rewrite(&mut req_header, &mut variables);
        assert_eq!(true, matched);
        // No named groups -> the second regex pass is skipped, no variables.
        assert_eq!(None, variables);
        assert_eq!("/new/thing?x=1", req_header.uri.to_string());
    }

    #[test]
    fn test_match_conditions() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                match_headers: Some(vec![
                    "x-version:2".to_string(),
                    "x-canary".to_string(),
                ]),
                ..Default::default()
            },
        )
        .unwrap();

        // No matching headers -> no match.
        let req = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(false, lo.match_conditions(&req, None));

        // Only one condition satisfied -> no match.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-version", "2").unwrap();
        assert_eq!(false, lo.match_conditions(&req, None));

        // Exact value + presence both satisfied -> match.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-version", "2").unwrap();
        req.insert_header("x-canary", "anything").unwrap();
        assert_eq!(true, lo.match_conditions(&req, None));

        // Wrong value -> no match.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-version", "3").unwrap();
        req.insert_header("x-canary", "y").unwrap();
        assert_eq!(false, lo.match_conditions(&req, None));

        // A location without conditions matches any request (zero overhead).
        let lo2 = Location::new(
            "lo2",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let req = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(true, lo2.match_conditions(&req, None));

        // Query-param (exact) and cookie (presence) conditions.
        let lo3 = Location::new(
            "lo3",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                match_query: Some(vec!["ver:2".to_string()]),
                match_cookies: Some(vec!["session".to_string()]),
                ..Default::default()
            },
        )
        .unwrap();
        // Query value matches and the session cookie is present -> match.
        let mut req = RequestHeader::build("GET", b"/?ver=2", None).unwrap();
        req.insert_header("Cookie", "session=abc").unwrap();
        assert_eq!(true, lo3.match_conditions(&req, None));
        // Cookie missing -> no match.
        let req = RequestHeader::build("GET", b"/?ver=2", None).unwrap();
        assert_eq!(false, lo3.match_conditions(&req, None));
        // Wrong query value -> no match.
        let mut req = RequestHeader::build("GET", b"/?ver=3", None).unwrap();
        req.insert_header("Cookie", "session=abc").unwrap();
        assert_eq!(false, lo3.match_conditions(&req, None));
    }

    fn ip_location(ranges: Vec<&str>) -> Location {
        Location::new(
            "ip",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                match_ip_ranges: Some(
                    ranges.into_iter().map(str::to_string).collect(),
                ),
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn test_match_conditions_ip_ranges() {
        let lo = ip_location(vec!["192.168.0.0/16", "10.0.0.1"]);
        let req = RequestHeader::build("GET", b"/", None).unwrap();

        // Inside a CIDR / an exact address -> match.
        assert_eq!(
            true,
            lo.match_conditions(&req, Some("192.168.1.7".parse().unwrap()))
        );
        assert_eq!(
            true,
            lo.match_conditions(&req, Some("10.0.0.1".parse().unwrap()))
        );
        // Outside every range -> no match.
        assert_eq!(
            false,
            lo.match_conditions(&req, Some("192.169.0.1".parse().unwrap()))
        );
        assert_eq!(
            false,
            lo.match_conditions(&req, Some("10.0.0.2".parse().unwrap()))
        );
        // A v4 range never matches a v6 client (only mapped addresses do).
        assert_eq!(
            false,
            lo.match_conditions(&req, Some("2001:db8::1".parse().unwrap()))
        );
        // No client address known -> no match.
        assert_eq!(false, lo.match_conditions(&req, None));

        // A dual-stack listener reports v4 peers as `::ffff:a.b.c.d`.
        assert_eq!(
            true,
            lo.match_conditions(
                &req,
                Some("::ffff:192.168.1.7".parse().unwrap())
            )
        );

        // IPv6 ranges work on their own.
        let lo6 = ip_location(vec!["2001:db8::/32"]);
        assert_eq!(
            true,
            lo6.match_conditions(&req, Some("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            false,
            lo6.match_conditions(&req, Some("2001:db9::1".parse().unwrap()))
        );

        // An empty list behaves like no IP condition at all.
        let lo_empty = ip_location(vec![]);
        assert_eq!(true, lo_empty.match_conditions(&req, None));
        assert_eq!(
            true,
            lo_empty.match_conditions(&req, Some("8.8.8.8".parse().unwrap()))
        );

        // Invalid entries are a configuration error, not a silent match-all.
        let err = Location::new(
            "bad",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                match_ip_ranges: Some(vec!["not-an-ip".to_string()]),
                ..Default::default()
            },
        );
        assert!(matches!(err, Err(Error::Invalid { .. })));

        // IP conditions AND with the header conditions.
        let lo_and = Location::new(
            "and",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                match_headers: Some(vec!["x-version:2".to_string()]),
                match_ip_ranges: Some(vec!["192.168.0.0/16".to_string()]),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-version", "2").unwrap();
        assert_eq!(
            true,
            lo_and.match_conditions(&req, Some("192.168.1.1".parse().unwrap()))
        );
        // Header matches but the IP is outside the range -> no match.
        assert_eq!(
            false,
            lo_and.match_conditions(&req, Some("8.8.8.8".parse().unwrap()))
        );
        // IP matches but the header is missing -> no match.
        let req = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(
            false,
            lo_and.match_conditions(&req, Some("192.168.1.1".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn test_get_content_length() {
        let headers = ["Content-Length: 123"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        assert_eq!(get_content_length(session.req_header()), Some(123));
    }

    #[test]
    fn test_validate_content_length() {
        let lo = Location::new(
            "lo",
            &LocationConf {
                client_max_body_size: Some(ByteSize(10)),
                ..Default::default()
            },
        )
        .unwrap();
        let mut req_header =
            RequestHeader::build("GET", b"/users/me?abc=1", None).unwrap();
        assert_eq!(true, lo.validate_content_length(&req_header).is_ok());

        req_header
            .append_header(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str("20").unwrap(),
            )
            .unwrap();
        assert_eq!(
            "Request Entity Too Large, max:10",
            lo.validate_content_length(&req_header)
                .err()
                .unwrap()
                .to_string()
        );
    }

    #[test]
    fn downstream_timeout_changes_the_location_hash() {
        use std::hash::{DefaultHasher, Hash, Hasher};
        let hash = |secs| {
            let mut hasher = DefaultHasher::new();
            LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                downstream_timeout_secs: secs,
                ..Default::default()
            }
            .hash(&mut hasher);
            hasher.finish()
        };
        assert_ne!(hash(Some(60)), hash(Some(120)));
    }

    #[test]
    fn downstream_timeout_is_compiled_to_a_duration() {
        let lo = Location::new(
            "timeout",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                downstream_timeout_secs: Some(120),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(lo.downstream_timeout(), Some(Duration::from_secs(120)));

        let none = Location::new(
            "timeout-default",
            &LocationConf {
                upstream: Some("charts".to_string()),
                path: Some("/".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(none.downstream_timeout(), None);
    }
}
