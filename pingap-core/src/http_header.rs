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

// Import necessary modules and types from supervisors and external crates.
use super::{Ctx, get_hostname};
use ahash::AHashSet;
use arc_swap::ArcSwapOption;
use bytes::BytesMut;
use http::header;
use http::{HeaderName, HeaderValue};
use ipnet::IpNet;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use snafu::{ResultExt, Snafu};
use std::borrow::Cow;
use std::fmt::Write;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// Define string constants for commonly used HTTP header names.
const HTTP_HEADER_X_FORWARDED_FOR: &str = "x-forwarded-for";
const HTTP_HEADER_X_REAL_IP: &str = "x-real-ip";
/// The scheme the outermost proxy saw; read only from a trusted peer.
const HTTP_HEADER_X_FORWARDED_PROTO: &str = "x-forwarded-proto";

// The scheme as a `&'static str`, for callers that build a URL rather than a
// header value (the `SCHEME_*` statics above are `HeaderValue`s).
const SCHEME_HTTPS_STR: &str = "https";
const SCHEME_HTTP_STR: &str = "http";

// Define byte slice constants for special variable tags used in header value processing.
// These are matched against the raw bytes of a header value.
pub const HOST_NAME_TAG: &[u8] = b"$hostname";
const HOST_TAG: &[u8] = b"$host";
const SCHEME_TAG: &[u8] = b"$scheme";
const REMOTE_ADDR_TAG: &[u8] = b"$remote_addr";
const REMOTE_PORT_TAG: &[u8] = b"$remote_port";
const SERVER_ADDR_TAG: &[u8] = b"$server_addr";
const SERVER_PORT_TAG: &[u8] = b"$server_port";
const PROXY_ADD_FORWARDED_TAG: &[u8] = b"$proxy_add_x_forwarded_for";
const UPSTREAM_ADDR_TAG: &[u8] = b"$upstream_addr";

// Define static HeaderValues for HTTP and HTTPS schemes to avoid re-creation.
static SCHEME_HTTPS: HeaderValue = HeaderValue::from_static("https");
static SCHEME_HTTP: HeaderValue = HeaderValue::from_static("http");

/// Defines the custom error types for this module using the snafu crate.
#[derive(Debug, Snafu)]
pub enum Error {
    /// Error for when a string cannot be parsed into a valid HeaderValue.
    #[snafu(display("invalid header value: {value} - {source}"))]
    InvalidHeaderValue {
        value: String,
        source: header::InvalidHeaderValue,
    },
    /// Error for when a string cannot be parsed into a valid HeaderName.
    #[snafu(display("invalid header name: {value} - {source}"))]
    InvalidHeaderName {
        value: String,
        source: header::InvalidHeaderName,
    },
}
/// A convenient type alias for `Result` with the module's `Error` type.
type Result<T, E = Error> = std::result::Result<T, E>;

/// A type alias for a tuple representing an HTTP header.
pub type HttpHeader = (HeaderName, HeaderValue);

/// Normalises a host so every consumer — site rule indexes, failover
/// registries, caches — keys on one canonical form: lowercased, the trailing
/// root dot dropped (`EXAMPLE.com.` → `example.com`), port untouched (callers
/// strip it beforehand via `strip_port`). This mirrors nginx's `$host`
/// semantics and must be applied on **both** sides of a host-keyed lookup.
pub fn normalize_host(host: &str) -> String {
    // ASCII fast path: hosts are IDN A-labels in practice, never UTF-8.
    host.to_ascii_lowercase()
}

/// Gets the request host by checking the URI first, then falling back to the "Host" header.
///
/// This function follows the common practice of prioritizing the host from the absolute URI
/// (e.g., in `GET http://example.com/path HTTP/1.1`) over the `Host` header field.
///
/// The returned host is normalised (lowercase, no trailing root dot); see
/// `normalize_host`.
pub fn get_host(header: &RequestHeader) -> Option<String> {
    // First, try to get the host directly from the parsed URI.
    // http2 will always have a host in the uri
    let raw = if let Some(host) = header.uri.host() {
        host
    } else {
        // If not in the URI, fall back to the "Host" header.
        header
            .headers
            .get(http::header::HOST)
            // Convert the header value to a string slice.
            .and_then(|value| value.to_str().ok())?
    };
    let host = strip_port(raw);
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    Some(normalize_host(host))
}

/// Drops the `:port` suffix of a `Host` value. An IPv6 literal keeps its
/// brackets, and the colons inside them are not a port separator:
/// `[::1]:8080` is `[::1]`, the same form `Uri::host` reports.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        };
    }
    host.split(':').next().unwrap_or(host)
}

/// Converts a single string in "name: value" format into an `HttpHeader` tuple.
///
/// This is a utility function for parsing header configurations. It trims whitespace
/// from both the name and the value.
pub fn convert_header(value: &str) -> Result<Option<HttpHeader>> {
    // `split_once` is an efficient way to split the string into two parts at the first colon.
    value
        .split_once(':')
        // If a colon exists, map the key and value parts.
        .map(|(k, v)| {
            // Parse the trimmed key into a HeaderName, wrapping errors.
            let name = HeaderName::from_str(k.trim())
                .context(InvalidHeaderNameSnafu { value: k })?;
            // Parse the trimmed value into a HeaderValue, wrapping errors.
            let value = HeaderValue::from_str(v.trim())
                .context(InvalidHeaderValueSnafu { value: v })?;
            // If both parsing steps succeed, return the header tuple.
            Ok(Some((name, value)))
        })
        // If `split_once` returns None (no colon), default to `Ok(None)`.
        .unwrap_or(Ok(None))
}

/// Converts a slice of strings into a `Vec` of `HttpHeader`s.
///
/// This function iterates over a list of header strings and uses `convert_header`
/// on each, collecting the valid results into a vector.
pub fn convert_headers(header_values: &[String]) -> Result<Vec<HttpHeader>> {
    header_values
        .iter()
        // `filter_map` is used to iterate, convert, and filter out `None` results elegantly.
        // `transpose` flips `Option<Result<T>>` to `Result<Option<T>>`, which is what `filter_map` expects.
        .filter_map(|item| convert_header(item).transpose())
        // `collect` gathers the `Result<HttpHeader>` items. If any item is an `Err`, `collect` will return that `Err`.
        .collect()
}

// Define common, pre-built HTTP headers as static constants for reuse and performance.
pub static HTTP_HEADER_NO_STORE: HttpHeader = (
    header::CACHE_CONTROL,
    HeaderValue::from_static("private, no-store"),
);
pub static HTTP_HEADER_NO_CACHE: HttpHeader = (
    header::CACHE_CONTROL,
    HeaderValue::from_static("private, no-cache"),
);
pub static HTTP_HEADER_CONTENT_JSON: HttpHeader = (
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/json; charset=utf-8"),
);
pub static HTTP_HEADER_CONTENT_HTML: HttpHeader = (
    header::CONTENT_TYPE,
    HeaderValue::from_static("text/html; charset=utf-8"),
);
pub static HTTP_HEADER_CONTENT_TEXT: HttpHeader = (
    header::CONTENT_TYPE,
    HeaderValue::from_static("text/plain; charset=utf-8"),
);
pub static HTTP_HEADER_TRANSFER_CHUNKED: HttpHeader = (
    header::TRANSFER_ENCODING,
    HeaderValue::from_static("chunked"),
);
pub static HTTP_HEADER_NAME_X_REQUEST_ID: HeaderName =
    HeaderName::from_static("x-request-id");

/// Resolves a header value that cannot change for the life of the process -
/// `$hostname` and `$<ENV_VAR>` - so it can be stored as a plain value when
/// the configuration is loaded instead of being looked up on every request
/// (`std::env::var` takes a process-wide lock and allocates each time).
/// Values that depend on the request (`$host`, `$http_*`, `:key`, ...) and
/// plain values come back unchanged, as does a `$NAME` whose variable is not
/// set, so the request path treats it exactly as before.
pub fn resolve_static_header_value(value: HeaderValue) -> HeaderValue {
    let buf = value.as_bytes();
    if buf.first() != Some(&b'$') {
        return value;
    }
    if buf == HOST_NAME_TAG {
        return HeaderValue::from_str(get_hostname()).unwrap_or(value);
    }
    let request_tags: [&[u8]; 8] = [
        HOST_TAG,
        SCHEME_TAG,
        REMOTE_ADDR_TAG,
        REMOTE_PORT_TAG,
        SERVER_ADDR_TAG,
        SERVER_PORT_TAG,
        PROXY_ADD_FORWARDED_TAG,
        UPSTREAM_ADDR_TAG,
    ];
    if request_tags.contains(&buf) || buf.starts_with(b"$http_") {
        return value;
    }
    let Ok(name) = std::str::from_utf8(&buf[1..]) else {
        return value;
    };
    match std::env::var(name) {
        Ok(env_value) => HeaderValue::from_str(&env_value).unwrap_or(value),
        Err(_) => value,
    }
}

/// Processes a `HeaderValue` that may contain a special dynamic variable (e.g., `$host`).
/// It replaces the variable with its corresponding runtime value.
#[inline]
pub fn convert_header_value(
    value: &HeaderValue,
    session: &Session,
    ctx: &Ctx,
) -> Option<HeaderValue> {
    // Work with the raw byte representation of the header value for efficient matching.
    let buf = value.as_bytes();

    // Perform a quick check for the special variable prefix ('$' or ':') to exit early
    // for normal header values, which is the most common case.
    if buf.is_empty() || !(buf[0] == b'$' || buf[0] == b':') {
        return None;
    }

    // A helper closure to reduce boilerplate when converting a string slice to a HeaderValue.
    let to_header_value = |s: &str| HeaderValue::from_str(s).ok();

    // Match the entire byte slice against the predefined variable tags.
    match buf {
        HOST_TAG => get_host(session.req_header())
            .and_then(|host| to_header_value(&host)),
        SCHEME_TAG => Some(if ctx.conn.tls_version.is_some() {
            SCHEME_HTTPS.clone()
        } else {
            SCHEME_HTTP.clone()
        }),
        HOST_NAME_TAG => to_header_value(get_hostname()),
        REMOTE_ADDR_TAG => {
            ctx.conn.remote_addr.as_deref().and_then(to_header_value)
        },
        REMOTE_PORT_TAG => ctx.conn.remote_port.and_then(|p| {
            // Use `itoa` to format the integer directly into a valid header value
            // without creating an intermediate `String`.
            HeaderValue::from_str(itoa::Buffer::new().format(p)).ok()
        }),
        SERVER_ADDR_TAG => {
            ctx.conn.server_addr.as_deref().and_then(to_header_value)
        },
        SERVER_PORT_TAG => ctx.conn.server_port.and_then(|p| {
            HeaderValue::from_str(itoa::Buffer::new().format(p)).ok()
        }),
        UPSTREAM_ADDR_TAG => {
            if !ctx.upstream.address.is_empty() {
                to_header_value(&ctx.upstream.address)
            } else {
                None
            }
        },
        PROXY_ADD_FORWARDED_TAG => {
            ctx.conn.remote_addr.as_deref().and_then(|remote_addr| {
                // Build the new `x-forwarded-for` value efficiently using `BytesMut` to avoid `format!`.
                let existing = session.get_header(HTTP_HEADER_X_FORWARDED_FOR);
                let capacity =
                    existing.map(|v| v.as_bytes().len() + 2).unwrap_or(0)
                        + remote_addr.len();
                let mut value_buf = BytesMut::with_capacity(capacity);
                if let Some(existing) = existing {
                    value_buf.extend_from_slice(existing.as_bytes());
                    value_buf.extend_from_slice(b", ");
                }
                value_buf.extend_from_slice(remote_addr.as_bytes());
                HeaderValue::from_bytes(&value_buf).ok()
            })
        },
        // If no predefined tag matches, it might be a different type of variable (e.g., `$http_...`).
        _ => handle_special_headers(buf, session, ctx),
    }
}

/// A helper function to handle more complex or less common special header variables.
/// This function is called as a fallback from `convert_header_value`.
#[inline]
fn handle_special_headers(
    buf: &[u8],
    session: &Session,
    ctx: &Ctx,
) -> Option<HeaderValue> {
    // Handle variables that reference other request headers, like `$http_user_agent`.
    if let Some(name) = buf.strip_prefix(b"$http_") {
        let key = std::str::from_utf8(name).ok()?;
        // nginx spelling: `$http_user_agent` names `User-Agent`. Header names
        // never contain underscores, so mapping them is unambiguous.
        if key.contains('_') {
            return session.get_header(key.replace('_', "-")).cloned();
        }
        return session.get_header(key).cloned();
    }
    // Handle variables that reference environment variables, like `$PATH`.
    if buf.starts_with(b"$") {
        let var_name = std::str::from_utf8(&buf[1..]).ok()?;
        // Look up the environment variable and convert its value to a HeaderValue.
        return std::env::var(var_name)
            .ok()
            .and_then(|v| HeaderValue::from_str(&v).ok());
    }
    // Handle variables that reference fields in the `Ctx` struct, like `:connection_id`.
    if buf.starts_with(b":") {
        let key = std::str::from_utf8(&buf[1..]).ok()?;
        // Use `append_log_value` to get the string representation of the context field.
        let mut value = BytesMut::with_capacity(20);
        ctx.append_log_value(&mut value, key);
        if !value.is_empty() {
            // Convert the resulting bytes to a HeaderValue.
            return HeaderValue::from_bytes(&value).ok();
        }
    }
    // If no pattern matches, return None.
    None
}

/// Gets the remote address (IP and port) from the session.
pub fn get_remote_addr(session: &Session) -> Option<(String, u16)> {
    session
        .client_addr()
        // Ensure the address is an IP address (v4 or v6).
        .and_then(|addr| addr.as_inet())
        // Map it to a tuple of (String, u16).
        .map(|addr| (addr.ip().to_string(), addr.port()))
}

/// Parsed trusted downstream proxy addresses: individual IPs plus CIDR
/// networks. Kept small and local since it is only used by `get_client_ip`.
struct TrustedProxies {
    nets: Vec<IpNet>,
    ips: AHashSet<IpAddr>,
}

impl TrustedProxies {
    /// Parses a list of IPs / CIDR ranges. Invalid entries are ignored (a
    /// mistyped proxy simply fails closed: its forwarded headers are dropped).
    fn parse(values: &[String]) -> Self {
        let mut nets = Vec::new();
        let mut ips = AHashSet::new();
        for item in values {
            if let Ok(net) = IpNet::from_str(item) {
                nets.push(net);
            } else if let Ok(ip) = IpAddr::from_str(item) {
                ips.insert(ip);
            }
        }
        Self { nets, ips }
    }

    /// Returns true if `peer` is one of the trusted proxies.
    fn contains(&self, peer: IpAddr) -> bool {
        self.ips.contains(&peer)
            || self.nets.iter().any(|net| net.contains(&peer))
    }
}

// Trusted downstream proxies. When configured, the forwarded client-IP headers
// (`X-Forwarded-For` / `X-Real-IP`) are only honoured for connections whose
// direct TCP peer is one of these addresses; a client connecting directly must
// not be able to spoof its IP for IP-based access control, rate limiting, etc.
// A cheap atomic flag keeps the common "not configured" path to one load;
// the configured path reads the list through an `ArcSwap`, so a reload never
// makes a request wait on a lock.
static TRUSTED_PROXIES_ENABLED: AtomicBool = AtomicBool::new(false);
static TRUSTED_PROXIES: ArcSwapOption<TrustedProxies> =
    ArcSwapOption::const_empty();

/// Sets the trusted downstream proxy addresses (individual IPs or CIDR ranges).
///
/// When a non-empty list is configured, forwarded headers are only trusted for
/// connections coming directly from one of these addresses. Passing `None` or
/// an empty list restores the default: forwarded headers are honoured only
/// from loopback/private-range direct peers, and a public peer always resolves
/// to its own address. Safe to call repeatedly on reload.
pub fn set_trusted_proxies(proxies: &Option<Vec<String>>) {
    let parsed = match proxies {
        Some(list) if !list.is_empty() => Some(TrustedProxies::parse(list)),
        _ => None,
    };
    let enabled = parsed.is_some();
    TRUSTED_PROXIES.store(parsed.map(Arc::new));
    // Set last: a request that sees the flag also sees the list.
    TRUSTED_PROXIES_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Returns true if the direct peer address is a configured trusted proxy.
fn is_trusted_proxy(peer: IpAddr) -> bool {
    TRUSTED_PROXIES
        .load()
        .as_ref()
        .is_some_and(|trusted| trusted.contains(peer))
}

/// Heuristic for the unconfigured default: addresses a same-host or
/// private-network load balancer plausibly connects from. A direct client
/// from a public address must not influence client-IP resolution.
fn is_plausible_internal_proxy(peer: IpAddr) -> bool {
    match peer {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local()
                // IPv4-mapped peers (::ffff:a.b.c.d) follow v4 semantics.
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_private())
        },
    }
}

/// Ensures `ctx.conn.client_ip` is populated and returns a borrowed reference.
///
/// Prefer this on the request path over calling [`get_client_ip`] repeatedly —
/// the first call allocates once and subsequent callers reuse the cached value.
#[inline]
pub fn ensure_client_ip<'a>(session: &Session, ctx: &'a mut Ctx) -> &'a str {
    if ctx.conn.client_ip.is_none() {
        ctx.conn.client_ip = Some(get_client_ip(session));
    }
    // Just inserted or already present — never None after the block above.
    ctx.conn.client_ip.as_deref().unwrap_or_default()
}

/// Gets the client's IP address.
///
/// When trusted proxies are configured, `X-Forwarded-For` / `X-Real-IP` are
/// only honoured if the direct TCP peer is a trusted proxy; otherwise the
/// peer's own address is returned. When no trusted proxies are configured the
/// forwarded headers are honoured only for connections whose direct peer is a
/// loopback or private-range address — the usual shape for a same-host or
/// private-network load balancer. A client arriving directly from a public
/// address controls its own forwarded headers, so honouring them would let
/// anyone forge the identity every IP rule keys on; such connections always
/// resolve to their TCP peer. Deployments behind a proxy with public addresses
/// (e.g. some cloud load balancers) must configure `basic.trusted_proxies`.
/// The lookup order within the honoured path is:
/// 1. `X-Forwarded-For` (taking the first IP in the list)
/// 2. `X-Real-IP`
/// 3. The remote address of the direct TCP connection
pub fn get_client_ip(session: &Session) -> String {
    // When no peer address is available (unit-test mock sessions, exotic
    // setups) trust cannot be judged either way; keep the legacy
    // header-first behaviour rather than resolving to nothing.
    let peer = session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| addr.ip());
    let peer = match peer {
        Some(ip) => ip,
        None => return forwarded_client_ip(session),
    };
    if TRUSTED_PROXIES_ENABLED.load(Ordering::Relaxed) {
        // Compare the address itself; formatting it only to parse it back
        // would cost an allocation per request.
        if !is_trusted_proxy(peer) {
            return peer.to_string();
        }
    } else {
        // Unconfigured: the fail-open default is a public peer's own
        // address — its forwarded headers are attacker-controlled.
        if !is_plausible_internal_proxy(peer) {
            return peer.to_string();
        }
    }
    forwarded_client_ip(session)
}

/// The legacy lookup order: `X-Forwarded-For` (first entry), then
/// `X-Real-IP`, then the connection's remote address.
fn forwarded_client_ip(session: &Session) -> String {
    // 1. Check `X-Forwarded-For`.
    if let Some(value) = session.get_header(HTTP_HEADER_X_FORWARDED_FOR) {
        // Efficiently take the first IP without creating an intermediate Vec.
        if let Ok(s) = value.to_str()
            && let Some(ip) = s.split(',').next()
        {
            let trimmed_ip = ip.trim();
            if !trimmed_ip.is_empty() {
                return trimmed_ip.to_string();
            }
        }
    }
    // 2. Check `X-Real-IP`.
    if let Some(value) = session.get_header(HTTP_HEADER_X_REAL_IP) {
        return value.to_str().unwrap_or_default().to_string();
    }
    // 3. Fall back to the direct connection's remote address.
    if let Some((addr, _)) = get_remote_addr(session) {
        return addr;
    }
    // If all checks fail, return an empty string.
    "".to_string()
}

/// Per-site proxy trust settings, mirrored from the control plane.
///
/// Sites behind a CDN or reverse proxy ask the plugin to derive the client IP
/// from a forwarded header instead of the direct TCP peer, so that IP access
/// rules, rate limiting and logs all key on the real client address. Trust is
/// scoped: only a connection whose direct peer falls inside one of the
/// configured CIDR ranges may influence the resolution at all, so a client
/// that connects directly — skipping the proxy — cannot spoof its IP through
/// forwarded headers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyTrust {
    /// Whether per-site proxy trust is enabled.
    pub enabled: bool,
    /// The forwarded header to trust, lower-case (e.g. `x-forwarded-for`).
    pub header: String,
    /// Trust only the most recent hop: take the last entry of
    /// `X-Forwarded-For` (appended by the closest proxy, so a client cannot
    /// spoof it) instead of the first.
    pub last_hop_only: bool,
    /// CIDR ranges of trusted proxies. An empty list trusts nothing.
    pub trusted_ranges: Vec<IpNet>,
}

impl ProxyTrust {
    /// Builds trust settings from configuration; a bare IP is treated as a
    /// /32 (or /128) host range, and unparsable entries are dropped rather
    /// than failing the whole site.
    pub fn new(
        enabled: bool,
        header: &str,
        last_hop_only: bool,
        trusted_ranges: &[String],
    ) -> Self {
        Self {
            enabled,
            header: header.trim().to_ascii_lowercase(),
            last_hop_only,
            trusted_ranges: trusted_ranges
                .iter()
                .filter_map(|range| {
                    let raw = range.trim();
                    raw.parse::<IpNet>()
                        .map(|net| net.trunc())
                        .or_else(|_| raw.parse::<IpAddr>().map(IpNet::from))
                        .ok()
                })
                .collect(),
        }
    }

    /// Whether the direct peer is allowed to influence the client-IP
    /// resolution. An empty range list trusts nothing.
    pub fn peer_is_trusted(&self, peer: IpAddr) -> bool {
        self.trusted_ranges.iter().any(|net| net.contains(&peer))
    }
}

/// Resolves the client IP from the site-trusted forwarded header.
///
/// Trust is strict: the direct TCP peer must fall inside one of the
/// configured proxy ranges for the forwarded header to be read at all.
/// Anything else — a client connecting directly, or an unparsable header
/// from an otherwise trusted proxy — resolves to the TCP peer itself, never
/// to a client-supplied header value. Returns `None` when proxy trust is
/// disabled or no peer address is available; callers then keep the default
/// [`get_client_ip`] resolution.
pub fn resolve_client_ip_with_trust(
    session: &Session,
    trust: &ProxyTrust,
) -> Option<String> {
    if !trust.enabled || trust.header.is_empty() {
        return None;
    }
    let peer = session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| addr.ip())?;
    if !trust.peer_is_trusted(peer) {
        return Some(peer.to_string());
    }
    let value = session.get_header(trust.header.as_str())?;
    let value = value.to_str().ok()?;
    let raw = if trust.header == HTTP_HEADER_X_FORWARDED_FOR {
        // `X-Forwarded-For` is a comma separated list. The last entry is
        // appended by the closest proxy and cannot be spoofed by the client.
        if trust.last_hop_only {
            value.rsplit(',').next().unwrap_or_default()
        } else {
            value.split(',').next().unwrap_or_default()
        }
    } else {
        value
    };
    match raw.trim().parse::<IpAddr>() {
        Ok(ip) => Some(ip.to_string()),
        // A trusted proxy sent something unusable: fall back to its own
        // address rather than to a spoofable header.
        Err(_) => Some(peer.to_string()),
    }
}

/// The scheme a request actually arrived over, honouring a trusted proxy's
/// `X-Forwarded-Proto`.
///
/// The data plane only sees the last hop. When a CDN or a TLS-terminating
/// load balancer sits in front, that hop is plain HTTP and
/// `ctx.conn.tls_version` is `None` even though the browser used HTTPS — so a
/// caller that derives a redirect URL (OIDC's `redirect_uri`, the session
/// cookie's `Secure` flag) from the connection alone would produce an
/// `http://` URL for a site that is only reachable over `https://`, and the
/// browser would refuse or the cookie would not stick.
///
/// `X-Forwarded-Proto` is client-controlled unless the direct peer is a
/// proxy the operator named, so trust is the same as for the client IP: the
/// peer must fall inside `trust.trusted_ranges`. An untrusted peer, a
/// disabled trust setting, or a value that is not `http`/`https` all fall
/// back to the connection's own TLS state — never to a header a client
/// could set to talk the site into a weaker scheme.
///
/// Only the first entry of a comma-separated list is read, which is what the
/// outermost proxy (the one the browser talked to) appends.
pub fn resolve_scheme_with_trust(
    session: &Session,
    ctx: &Ctx,
    trust: &ProxyTrust,
) -> &'static str {
    let from_connection = || {
        if ctx.conn.tls_version.is_some() {
            SCHEME_HTTPS_STR
        } else {
            SCHEME_HTTP_STR
        }
    };
    if !trust.enabled {
        return from_connection();
    }
    let Some(peer) = session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| addr.ip())
    else {
        // No peer address (a unit-test mock, an exotic transport): trust
        // cannot be judged, so nothing forwarded is believed.
        return from_connection();
    };
    if !trust.peer_is_trusted(peer) {
        return from_connection();
    }
    let Some(value) = get_req_header_value(
        session.req_header(),
        HTTP_HEADER_X_FORWARDED_PROTO,
    ) else {
        return from_connection();
    };
    match value.split(',').next().unwrap_or_default().trim() {
        "https" => SCHEME_HTTPS_STR,
        "http" => SCHEME_HTTP_STR,
        // A trusted proxy sent something unusable. Falling back to the
        // connection is right: it may well be the https we were told about
        // only badly, and it is never worse than what we already knew.
        _ => from_connection(),
    }
}

/// A convenient helper to get a header value as a `&str` from a `RequestHeader`.
pub fn get_req_header_value<'a>(
    req_header: &'a RequestHeader,
    key: &str,
) -> Option<&'a str> {
    // Get the header by its key.
    if let Some(value) = req_header.headers.get(key) {
        // Try to convert it to a string slice. Fails if the value is not valid UTF-8.
        if let Ok(value) = value.to_str() {
            return Some(value);
        }
    }
    None
}

/// Parses the "Cookie" header to find the value of a specific cookie.
pub fn get_cookie_value<'a>(
    req_header: &'a RequestHeader,
    cookie_name: &str,
) -> Option<&'a str> {
    // First, get the entire "Cookie" header string. The '?' operator will short-circuit if it's not present.
    get_req_header_value(req_header, "cookie")?
        // Split the string into individual cookies.
        .split(';')
        // `find_map` is an efficient way to find the first cookie that matches our criteria.
        .find_map(|item| {
            // This chained logic attempts to quickly find a match.
            // It's more complex to handle cases like "key=value" vs "key=" correctly.
            item.trim()
                .strip_prefix(cookie_name)?
                .strip_prefix('=')
                .or_else(|| {
                    // Fallback logic to ensure the cookie name is an exact match.
                    let (k, v) = item.split_once('=')?;
                    if k.trim() == cookie_name {
                        Some(v.trim())
                    } else {
                        None
                    }
                })
        })
}

/// Gets the value of a specific query parameter from the request URI.
pub fn get_query_value<'a>(
    req_header: &'a RequestHeader,
    name: &str,
) -> Option<&'a str> {
    // Get the query string from the URI, exiting if it doesn't exist.
    req_header
        .uri
        .query()?
        // Split the query string into key-value pairs.
        .split('&')
        // `find_map` efficiently searches for the first pair where the key matches.
        .find_map(|item| {
            // Split the pair into key and value.
            let (k, v) = item.split_once('=')?;
            // If the key matches, return the value.
            if k == name { Some(v) } else { None }
        })
}

/// Removes a specific query parameter from the request header's URI.
///
/// This function modifies the `req_header` in place.
pub fn remove_query_from_header(
    req_header: &mut RequestHeader,
    name: &str,
) -> Result<(), http::uri::InvalidUri> {
    // If there is no query string, there is nothing to do.
    let Some(query_str) = req_header.uri.query() else {
        return Ok(());
    };

    // Pre-allocate a String with enough capacity to hold the new query string,
    // which is a performance optimization to avoid reallocations.
    let mut new_query = String::with_capacity(query_str.len());

    // Iterate over each key-value pair in the original query string.
    for item in query_str.split('&') {
        // Get the key part of the pair.
        let key = item.split('=').next().unwrap_or(item);

        // If the key is not the one we want to remove, keep the item.
        if key != name {
            // If the new query string is not empty, add a separator first.
            if !new_query.is_empty() {
                new_query.push('&');
            }
            // Append the original "key=value" slice, which is allocation-free.
            new_query.push_str(item);
        }
    }

    // Reconstruct the URI from its path and the new query string.
    let path = req_header.uri.path();
    // Use `Cow` (Clone-on-Write) to avoid allocating a new String for the path if the query is empty.
    let new_uri_str = if new_query.is_empty() {
        // If the new query is empty, the new URI is just the path. Borrow it.
        Cow::Borrowed(path)
    } else {
        // If the new query is not empty, build a new String. Own it.
        let mut s = String::with_capacity(path.len() + 1 + new_query.len());
        // `write!` is an efficient way to format into an existing String buffer.
        let _ = write!(&mut s, "{path}?{new_query}");
        Cow::Owned(s)
    };

    // Parse the newly constructed string into a `http::Uri`.
    let new_uri = http::Uri::from_str(&new_uri_str)?;
    // Update the request header with the new URI.
    req_header.set_uri(new_uri);

    Ok(())
}

/// Takes `names` out of what the `Connection` header of a request
/// nominates, for the headers the proxy itself has put on the request.
///
/// A header named in `Connection` is one its sender calls hop-by-hop, and it
/// is removed from the request that goes to the upstream. For a header of the
/// client's own that is as it should be. For one a plugin set - the address of
/// the client, what the auth service said of it - it let the client decide that
/// the upstream does not get it: `Connection: X-User-Id` was enough. Only
/// `Host` and the `X-Forwarded-*` headers were safe from that.
///
/// The rest of the header stays as it is: `keep-alive`, `upgrade` and what
/// else the client nominated.
pub fn protect_from_connection_header(
    req: &mut RequestHeader,
    names: &[HeaderName],
) {
    if names.is_empty() || !req.headers.contains_key(header::CONNECTION) {
        return;
    }
    let nominated = |token: &str| {
        names
            .iter()
            .any(|name| name.as_str().eq_ignore_ascii_case(token))
    };
    let mut kept = vec![];
    let mut removed = false;
    for value in req.headers.get_all(header::CONNECTION).iter() {
        // A value that is not text has no name in it to take out.
        // A value that is not text has no name in it to take out, but the other
        // values still do: skipping this one rather than giving up keeps a
        // client from switching the protection off by sending one header line
        // with an invalid byte in it.
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value.split(',').map(str::trim) {
            if token.is_empty() {
                continue;
            }
            if nominated(token) {
                removed = true;
            } else {
                kept.push(token);
            }
        }
    }
    if !removed {
        return;
    }
    let kept = kept.join(", ");
    req.remove_header(&header::CONNECTION);
    if !kept.is_empty() {
        let _ = req.insert_header(header::CONNECTION, kept);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectionInfo, UpstreamInfo, new_test_session};
    use pingora::protocols::SocketDigest;
    use pingora::protocols::l4::socket::SocketAddr;
    use pretty_assertions::assert_eq;

    /// Builds a mock session whose direct TCP peer is `peer`.
    ///
    /// `new_test_session` has no socket, so the digest is synthesized to
    /// let the strict proxy-trust resolution see a peer address.
    async fn new_test_session_with_peer(
        headers: &[&str],
        url: &str,
        peer: IpAddr,
    ) -> pingora::proxy::Session {
        let mut session = new_test_session(headers, url).await;
        let socket_digest = SocketDigest::from_raw_fd(-1);
        socket_digest
            .peer_addr
            .set(Some(SocketAddr::Inet(std::net::SocketAddr::new(peer, 0))))
            .expect("peer addr is unset on a fresh digest");
        session
            .as_downstream_mut()
            .digest_mut()
            .expect("the h1 session always carries a digest")
            .socket_digest = Some(Arc::new(socket_digest));
        session
    }

    /// The scheme a request arrived over, honouring a trusted proxy.
    ///
    /// A CDN or a TLS-terminating load balancer makes the last hop plain HTTP,
    /// so a site that is only reachable over `https://` would otherwise have
    /// its redirect URL and its cookie flags derived from `http://`.
    #[tokio::test]
    async fn test_resolve_scheme_with_trust() {
        let ranges = &["10.0.0.0/8".to_string()];
        let trust = ProxyTrust::new(true, "x-forwarded-for", true, ranges);
        let ctx = Ctx::default();

        // A trusted proxy saying https is believed even though this hop is
        // plain HTTP — the case the whole function exists for.
        let session = new_test_session_with_peer(
            &["Host: app.test", "X-Forwarded-Proto: https"],
            "/",
            "10.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!("https", resolve_scheme_with_trust(&session, &ctx, &trust));

        // A direct client from a public address controls its own headers, so
        // its claim of https is refused and the connection decides.
        let session = new_test_session_with_peer(
            &["Host: app.test", "X-Forwarded-Proto: https"],
            "/",
            "203.0.113.9".parse().unwrap(),
        )
        .await;
        assert_eq!("http", resolve_scheme_with_trust(&session, &ctx, &trust));

        // A trusted proxy that sent something unusable falls back to the
        // connection rather than to a guess.
        let session = new_test_session_with_peer(
            &["Host: app.test", "X-Forwarded-Proto: ftp"],
            "/",
            "10.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!("http", resolve_scheme_with_trust(&session, &ctx, &trust));

        // The first entry is the outermost proxy's, which is what the browser
        // talked to.
        let session = new_test_session_with_peer(
            &["Host: app.test", "X-Forwarded-Proto: https, http"],
            "/",
            "10.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!("https", resolve_scheme_with_trust(&session, &ctx, &trust));

        // Trust disabled: the header is ignored entirely.
        let untrusted = ProxyTrust::default();
        let session = new_test_session_with_peer(
            &["Host: app.test", "X-Forwarded-Proto: https"],
            "/",
            "10.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(
            "http",
            resolve_scheme_with_trust(&session, &ctx, &untrusted)
        );

        // No header at all: the connection's own state, which is https here.
        let mut tls_ctx = Ctx::default();
        tls_ctx.conn.tls_version = Some("tls1.3".into());
        let session = new_test_session_with_peer(
            &["Host: app.test"],
            "/",
            "10.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(
            "https",
            resolve_scheme_with_trust(&session, &tls_ctx, &trust)
        );
    }

    #[tokio::test]
    async fn test_resolve_client_ip_with_trust() {
        // The mock peer sits inside the trusted ranges, so forwarded
        // headers are honored.
        let ranges = &["10.0.0.0/8".to_string()];
        let trust = ProxyTrust::new(true, "x-forwarded-for", true, ranges);
        let session = new_test_session_with_peer(
            &["Host: github.com", "X-Forwarded-For: 1.2.3.4, 10.0.0.1"],
            "/",
            "10.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(
            Some("10.0.0.1".to_string()),
            resolve_client_ip_with_trust(&session, &trust)
        );

        let trust = ProxyTrust::new(true, "x-forwarded-for", false, ranges);
        assert_eq!(
            Some("1.2.3.4".to_string()),
            resolve_client_ip_with_trust(&session, &trust)
        );

        let trust = ProxyTrust::new(true, "cf-connecting-ip", true, ranges);
        let session = new_test_session_with_peer(
            &["Host: github.com", "CF-Connecting-IP: 203.0.113.7"],
            "/",
            "10.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(
            Some("203.0.113.7".to_string()),
            resolve_client_ip_with_trust(&session, &trust)
        );

        let trust = ProxyTrust::new(true, "x-real-ip", true, ranges);
        let session = new_test_session_with_peer(
            &["Host: github.com", "X-Real-IP: 198.51.100.9"],
            "/",
            "10.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(
            Some("198.51.100.9".to_string()),
            resolve_client_ip_with_trust(&session, &trust)
        );
    }

    #[tokio::test]
    async fn test_resolve_client_ip_with_trust_fallbacks() {
        // Disabled trust never resolves through the trusted header.
        let trust = ProxyTrust::new(true, "x-forwarded-for", true, &[]);
        let session = new_test_session(
            &["Host: github.com", "X-Forwarded-For: 1.2.3.4"],
            "/",
        )
        .await;
        assert_eq!(None, resolve_client_ip_with_trust(&session, &trust));

        let trust = ProxyTrust::new(true, "x-forwarded-for", true, &[]);
        // A trusted proxy that sends no header falls back to the default
        // resolution.
        let session = new_test_session(&["Host: github.com"], "/").await;
        assert_eq!(None, resolve_client_ip_with_trust(&session, &trust));
    }

    #[tokio::test]
    async fn test_resolve_client_ip_strict_peer_scope() {
        // Spoofed header: the direct peer is NOT a trusted proxy, so the
        // forwarded header must be ignored in favor of the peer address.
        let ranges = &["10.0.0.0/8".to_string()];
        let trust = ProxyTrust::new(true, "x-forwarded-for", false, ranges);
        let session = new_test_session_with_peer(
            &["Host: github.com", "X-Forwarded-For: 1.2.3.4"],
            "/",
            "203.0.113.50".parse().unwrap(),
        )
        .await;
        assert_eq!(
            Some("203.0.113.50".to_string()),
            resolve_client_ip_with_trust(&session, &trust)
        );

        // Empty ranges trust nothing: same spoofing attempt resolves to
        // the peer even though trust is nominally enabled.
        let trust = ProxyTrust::new(true, "x-forwarded-for", false, &[]);
        let session = new_test_session_with_peer(
            &["Host: github.com", "X-Forwarded-For: 1.2.3.4"],
            "/",
            "203.0.113.50".parse().unwrap(),
        )
        .await;
        assert_eq!(
            Some("203.0.113.50".to_string()),
            resolve_client_ip_with_trust(&session, &trust)
        );

        // A trusted proxy that sends an unparsable header must not
        // surface the injection attempt; the peer address wins.
        let ranges = &["10.0.0.0/8".to_string()];
        let trust = ProxyTrust::new(true, "x-forwarded-for", false, ranges);
        let session = new_test_session_with_peer(
            &["Host: github.com", "X-Forwarded-For: evil.example.com"],
            "/",
            "10.0.0.1".parse().unwrap(),
        )
        .await;
        assert_eq!(
            Some("10.0.0.1".to_string()),
            resolve_client_ip_with_trust(&session, &trust)
        );
    }

    #[test]
    fn test_proxy_trust_range_parsing() {
        let trust = ProxyTrust::new(
            true,
            " X-Forwarded-For ",
            true,
            &[
                "10.0.0.0/8".to_string(),
                " 2001:db8::/32 ".to_string(),
                "not-a-range".to_string(),
            ],
        );
        assert_eq!("x-forwarded-for", trust.header);
        assert_eq!(2, trust.trusted_ranges.len());
        assert!(trust.peer_is_trusted("10.1.2.3".parse().unwrap()));
        assert!(trust.peer_is_trusted("2001:db8::1".parse().unwrap()));
        assert!(!trust.peer_is_trusted("192.168.1.1".parse().unwrap()));
        // A bare IP is normalized to a /32 (or /128) host range.
        let trust = ProxyTrust::new(
            true,
            "x-real-ip",
            false,
            &["203.0.113.7".to_string()],
        );
        assert!(trust.peer_is_trusted("203.0.113.7".parse().unwrap()));
        assert!(!trust.peer_is_trusted("203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn test_convert_headers() {
        let headers = convert_headers(&[
            "Content-Type: application/octet-stream".to_string(),
            "X-Server: $hostname".to_string(),
            "X-User: $USER".to_string(),
        ])
        .unwrap();
        assert_eq!(3, headers.len());
        assert_eq!("content-type", headers[0].0.to_string());
        assert_eq!("application/octet-stream", headers[0].1.to_str().unwrap());
        assert_eq!("x-server", headers[1].0.to_string());
        assert_eq!(false, headers[1].1.to_str().unwrap().is_empty());
        assert_eq!("x-user", headers[2].0.to_string());
        assert_eq!(false, headers[2].1.to_str().unwrap().is_empty());
    }

    #[test]
    fn test_static_value() {
        assert_eq!(
            "cache-control: private, no-store",
            format!(
                "{}: {}",
                HTTP_HEADER_NO_STORE.0.to_string(),
                HTTP_HEADER_NO_STORE.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "cache-control: private, no-cache",
            format!(
                "{}: {}",
                HTTP_HEADER_NO_CACHE.0.to_string(),
                HTTP_HEADER_NO_CACHE.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "content-type: application/json; charset=utf-8",
            format!(
                "{}: {}",
                HTTP_HEADER_CONTENT_JSON.0.to_string(),
                HTTP_HEADER_CONTENT_JSON.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "content-type: text/html; charset=utf-8",
            format!(
                "{}: {}",
                HTTP_HEADER_CONTENT_HTML.0.to_string(),
                HTTP_HEADER_CONTENT_HTML.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!(
            "transfer-encoding: chunked",
            format!(
                "{}: {}",
                HTTP_HEADER_TRANSFER_CHUNKED.0.to_string(),
                HTTP_HEADER_TRANSFER_CHUNKED.1.to_str().unwrap_or_default()
            )
        );

        assert_eq!("x-request-id", HTTP_HEADER_NAME_X_REQUEST_ID.to_string());

        assert_eq!(
            "content-type: text/plain; charset=utf-8",
            format!(
                "{}: {}",
                HTTP_HEADER_CONTENT_TEXT.0.to_string(),
                HTTP_HEADER_CONTENT_TEXT.1.to_str().unwrap_or_default()
            )
        );
    }

    #[tokio::test]
    async fn test_convert_header_value() {
        let session =
            new_test_session(&["Host: pingap.io"], "/vicanso/pingap?size=1")
                .await;
        let default_state = Ctx {
            upstream: UpstreamInfo {
                address: "10.1.1.3:4123".to_string(),
                ..Default::default()
            },
            conn: ConnectionInfo {
                id: 102,
                remote_addr: Some("10.1.1.1".to_string()),
                remote_port: Some(6000),
                server_addr: Some("10.1.1.2".to_string()),
                server_port: Some(6001),
                tls_version: Some("tls1.3".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let value = convert_header_value(
            &HeaderValue::from_str("$host").unwrap(),
            &session,
            &Ctx {
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("pingap.io", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$scheme").unwrap(),
            &session,
            &Ctx {
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("http", value.unwrap().to_str().unwrap());
        let value = convert_header_value(
            &HeaderValue::from_str("$scheme").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("https", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$remote_addr").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.1", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$remote_port").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("6000", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$server_addr").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.2", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$server_port").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("6001", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str("$upstream_addr").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.3:4123", value.unwrap().to_str().unwrap());

        let value = convert_header_value(
            &HeaderValue::from_str(":connection_id").unwrap(),
            &session,
            &default_state,
        );
        assert_eq!(true, value.is_some());
        assert_eq!("102", value.unwrap().to_str().unwrap());

        let session = new_test_session(
            &["X-Forwarded-For: 1.1.1.1, 2.2.2.2"],
            "/vicanso/pingap?size=1",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("$proxy_add_x_forwarded_for").unwrap(),
            &session,
            &Ctx {
                conn: ConnectionInfo {
                    remote_addr: Some("10.1.1.1".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!(
            "1.1.1.1, 2.2.2.2, 10.1.1.1",
            value.unwrap().to_str().unwrap()
        );

        let session = new_test_session(&[""], "/vicanso/pingap?size=1").await;
        let value = convert_header_value(
            &HeaderValue::from_str("$proxy_add_x_forwarded_for").unwrap(),
            &session,
            &Ctx {
                conn: ConnectionInfo {
                    remote_addr: Some("10.1.1.1".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.1", value.unwrap().to_str().unwrap());

        let session = new_test_session(&[""], "/vicanso/pingap?size=1").await;
        let value = convert_header_value(
            &HeaderValue::from_str("$upstream_addr").unwrap(),
            &session,
            &Ctx {
                upstream: UpstreamInfo {
                    address: "10.1.1.1:8001".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert_eq!(true, value.is_some());
        assert_eq!("10.1.1.1:8001", value.unwrap().to_str().unwrap());

        let session = new_test_session(
            &["Origin: https://github.com"],
            "/vicanso/pingap?size=1",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("$http_origin").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(true, value.is_some());
        assert_eq!("https://github.com", value.unwrap().to_str().unwrap());

        let session = new_test_session(
            &["Origin: https://github.com"],
            "/vicanso/pingap?size=1",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("$hostname").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(true, value.is_some());

        let session = new_test_session(
            &["Origin: https://github.com"],
            "/vicanso/pingap?size=1",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("$HOME").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(true, value.is_some());

        let session = new_test_session(
            &["Origin: https://github.com"],
            "/vicanso/pingap?size=1",
        )
        .await;
        let value = convert_header_value(
            &HeaderValue::from_str("UUID").unwrap(),
            &session,
            &Ctx::default(),
        );
        assert_eq!(false, value.is_some());
    }

    #[tokio::test]
    async fn test_get_host() {
        let session =
            new_test_session(&["Host: pingap.io"], "/vicanso/pingap?size=1")
                .await;
        assert_eq!(
            get_host(session.req_header()),
            Some("pingap.io".to_string())
        );
    }

    #[test]
    fn test_remove_query_from_header() {
        let mut req =
            RequestHeader::build("GET", b"/?apikey=123", None).unwrap();
        remove_query_from_header(&mut req, "apikey").unwrap();
        assert_eq!("/", req.uri.to_string());

        let mut req =
            RequestHeader::build("GET", b"/?apikey=123&name=pingap", None)
                .unwrap();
        remove_query_from_header(&mut req, "apikey").unwrap();
        assert_eq!("/?name=pingap", req.uri.to_string());
    }

    #[tokio::test]
    async fn test_get_client_ip() {
        // Default mode: a private-range direct peer (internal LB shape)
        // honours forwarded headers.
        let session = new_test_session_with_peer(
            &["X-Forwarded-For:192.168.1.1"],
            "/vicanso/pingap?size=1",
            "10.0.0.9".parse().unwrap(),
        )
        .await;
        assert_eq!(get_client_ip(&session), "192.168.1.1");

        let session = new_test_session_with_peer(
            &["X-Real-Ip:192.168.1.2"],
            "/vicanso/pingap?size=1",
            "10.0.0.9".parse().unwrap(),
        )
        .await;
        assert_eq!(get_client_ip(&session), "192.168.1.2");

        // A public direct peer controls its own forwarded headers, so they
        // must be ignored: the peer itself is the client IP.
        let session = new_test_session_with_peer(
            &["X-Forwarded-For:192.168.1.1"],
            "/vicanso/pingap?size=1",
            "93.184.216.34".parse().unwrap(),
        )
        .await;
        assert_eq!(get_client_ip(&session), "93.184.216.34");

        // With trusted proxies configured, the strict list wins: a trusted
        // peer's header is honoured, a private-but-unlisted peer's is not.
        set_trusted_proxies(&Some(vec!["10.0.0.0/8".to_string()]));
        let session = new_test_session_with_peer(
            &["X-Forwarded-For:192.168.1.1"],
            "/vicanso/pingap?size=1",
            "10.0.0.9".parse().unwrap(),
        )
        .await;
        assert_eq!(get_client_ip(&session), "192.168.1.1");

        let session = new_test_session_with_peer(
            &["X-Forwarded-For:192.168.1.1"],
            "/vicanso/pingap?size=1",
            "192.168.5.5".parse().unwrap(),
        )
        .await;
        assert_eq!(get_client_ip(&session), "192.168.5.5");

        // Restoring the default honours forwarded headers from private
        // peers again.
        set_trusted_proxies(&None);
        let session = new_test_session_with_peer(
            &["X-Forwarded-For:192.168.1.1"],
            "/vicanso/pingap?size=1",
            "10.0.0.9".parse().unwrap(),
        )
        .await;
        assert_eq!(get_client_ip(&session), "192.168.1.1");
    }

    #[tokio::test]
    async fn test_get_header_value() {
        let session =
            new_test_session(&["Host: pingap.io"], "/vicanso/pingap?size=1")
                .await;
        assert_eq!(
            get_req_header_value(session.req_header(), "Host"),
            Some("pingap.io")
        );
    }

    #[tokio::test]
    async fn test_get_cookie_value() {
        let session = new_test_session(
            &["Cookie: name=pingap"],
            "/vicanso/pingap?size=1",
        )
        .await;
        assert_eq!(
            get_cookie_value(session.req_header(), "name"),
            Some("pingap")
        );
    }

    #[tokio::test]
    async fn test_get_query_value() {
        let session = new_test_session(
            &["X-Forwarded-For:192.168.1.1"],
            "/vicanso/pingap?size=1",
        )
        .await;
        assert_eq!(get_query_value(session.req_header(), "size"), Some("1"));
    }

    /// Tests `convert_header` with edge cases like empty strings,
    /// strings without colons, and invalid header names/values.
    #[test]
    fn test_convert_header_edge_cases() {
        // Empty string should result in Ok(None).
        assert!(convert_header("").unwrap().is_none());
        // String without a colon should result in Ok(None).
        assert!(convert_header("no-colon").unwrap().is_none());
        // Invalid header name should result in an error.
        assert!(convert_header("Invalid Name: value").is_err());
        // Invalid header value (with newline) should result in an error.
        assert!(convert_header("Valid-Name: invalid\r\nvalue").is_err());
    }

    /// Tests `get_host` logic with different request formats.
    #[test]
    fn test_get_host_variants() {
        // Case 1: Host is in the URI authority.
        let uri_string = "http://user:pass@authority.com/path";

        // 使用 .parse() 或 from_str 来创建 Uri
        let uri = http::Uri::from_str(uri_string).unwrap();
        let mut req_with_authority =
            RequestHeader::build("GET", b"/path", None).unwrap();
        req_with_authority.set_uri(uri);
        assert_eq!(
            get_host(&req_with_authority),
            Some("authority.com".to_string())
        );

        // Case 2: Host is in the "Host" header.
        let mut req_with_host_header =
            RequestHeader::build("GET", b"/path", None).unwrap();
        req_with_host_header
            .insert_header("Host", "header-host.com:8080")
            .unwrap();
        assert_eq!(
            get_host(&req_with_host_header),
            Some("header-host.com".to_string())
        );

        // Case 3: No host information available.
        let req_no_host = RequestHeader::build("GET", b"/path", None).unwrap();
        assert_eq!(get_host(&req_no_host), None);

        // Case 4: IPv6 literals keep their brackets and lose only the port.
        // Cases 5-7: hosts are normalised — lowercased and the trailing
        // root dot dropped — so `EXAMPLE.com.` and `example.com` hit the
        // same site-rule or failover-registry key.
        for (host, expected) in [
            ("[::1]:8080", "[::1]"),
            ("[::1]", "[::1]"),
            ("[2001:db8::1]:443", "[2001:db8::1]"),
            ("example.com", "example.com"),
            ("example.com:8080", "example.com"),
            ("EXAMPLE.com:8080", "example.com"),
            ("Example.COM.", "example.com"),
            ("MiXeD.CaSe.Example.ORG.", "mixed.case.example.org"),
        ] {
            let mut req = RequestHeader::build("GET", b"/path", None).unwrap();
            req.insert_header("Host", host).unwrap();
            assert_eq!(get_host(&req), Some(expected.to_string()), "{host}");
        }
    }

    #[test]
    fn test_resolve_static_header_value() {
        let resolve = |value: &str| {
            resolve_static_header_value(HeaderValue::from_str(value).unwrap())
        };
        assert_eq!(get_hostname(), resolve("$hostname").to_str().unwrap());
        let home = std::env::var("HOME").unwrap();
        assert_eq!(home, resolve("$HOME").to_str().unwrap());
        // Request-time variables, plain values and unset variables are left
        // for the request path.
        for value in [
            "$host",
            "$remote_addr",
            "$proxy_add_x_forwarded_for",
            "$http_origin",
            ":connection_id",
            "plain",
            "$PINGAP_TEST_UNSET_VARIABLE",
        ] {
            assert_eq!(value, resolve(value).to_str().unwrap());
        }
    }

    /// `$http_<name>` accepts the nginx spelling with underscores.
    #[tokio::test]
    async fn test_http_variable_with_underscores() {
        let session = new_test_session(
            &["User-Agent: pingap/1", "X-Env-Name: prod"],
            "/",
        )
        .await;
        for (variable, expected) in [
            ("$http_user_agent", Some("pingap/1")),
            ("$http_user-agent", Some("pingap/1")),
            ("$http_x_env_name", Some("prod")),
            ("$http_missing_header", None),
        ] {
            let value = convert_header_value(
                &HeaderValue::from_str(variable).unwrap(),
                &session,
                &Ctx::default(),
            );
            assert_eq!(
                expected,
                value.as_ref().and_then(|v| v.to_str().ok()),
                "{variable}"
            );
        }
    }

    /// Tests `get_cookie_value` with multiple cookies and edge cases.
    #[test]
    fn test_get_cookie_value_advanced() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Cookie", "id=123; session=abc; theme=dark")
            .unwrap();

        assert_eq!(get_cookie_value(&req, "session"), Some("abc"));
        assert_eq!(get_cookie_value(&req, "id"), Some("123"));
        assert_eq!(get_cookie_value(&req, "theme"), Some("dark"));
        // Test for a non-existent cookie.
        assert_eq!(get_cookie_value(&req, "lang"), None);
        // Test for a cookie name that is a prefix of another.
        assert_eq!(get_cookie_value(&req, "the"), None);
    }

    #[test]
    fn test_remove_query_from_header_variants() {
        // Case 1: Remove the only query param.
        let mut req =
            RequestHeader::build("GET", b"/path?key=val", None).unwrap();
        remove_query_from_header(&mut req, "key").unwrap();
        assert_eq!(req.uri.to_string(), "/path");

        // Case 2: Remove the first of multiple params.
        let mut req =
            RequestHeader::build("GET", b"/path?key1=val1&key2=val2", None)
                .unwrap();
        remove_query_from_header(&mut req, "key1").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key2=val2");

        // Case 3: Remove the last of multiple params.
        let mut req =
            RequestHeader::build("GET", b"/path?key1=val1&key2=val2", None)
                .unwrap();
        remove_query_from_header(&mut req, "key2").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key1=val1");

        // Case 4: Remove a middle param.
        let mut req =
            RequestHeader::build("GET", b"/path?key1=v1&key2=v2&key3=v3", None)
                .unwrap();
        remove_query_from_header(&mut req, "key2").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key1=v1&key3=v3");

        // Case 5: Param to remove is not present.
        let mut req =
            RequestHeader::build("GET", b"/path?key=val", None).unwrap();
        remove_query_from_header(&mut req, "nonexistent").unwrap();
        assert_eq!(req.uri.to_string(), "/path?key=val");

        // Case 6: No query string to begin with.
        let mut req = RequestHeader::build("GET", b"/path", None).unwrap();
        remove_query_from_header(&mut req, "key").unwrap();
        assert_eq!(req.uri.to_string(), "/path");
    }
}
