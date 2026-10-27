//! Input normalization: URL decoding, HTML entity decoding, escape-sequence
//! decoding, path collapsing, query string and cookie parsing.
//!
//! Everything the detection stages look at flows through here first so that
//! signature matching and libinjection always see attacker-decoded payloads
//! rather than their obfuscated wire form.
//!
//! The normalized view *borrows* the request's headers and body instead of
//! copying them — the wire-format data already lives in [`RequestData`]
//! upstream, and duplicating it per request was the engine's largest
//! avoidable allocation cost.

pub mod body;
pub mod html;
pub mod path;
pub mod url;

use std::borrow::Cow;

use once_cell::sync::Lazy;

use crate::normalize::body::decode_body;
use crate::normalize::html::decode_entities;
use crate::normalize::path::normalize as normalize_path;
use crate::normalize::url::multi_decode;

/// Where a particular decoded value came from. Used for logging and for
/// per-source weight tuning in the rule engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueSource {
    QueryParam,
    Header,
    Cookie,
    Body,
    Path,
}

impl ValueSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ValueSource::QueryParam => "query",
            ValueSource::Header => "header",
            ValueSource::Cookie => "cookie",
            ValueSource::Body => "body",
            ValueSource::Path => "path",
        }
    }
}

/// A single normalized field of the request, paired with its decoded form.
#[derive(Debug, Clone)]
pub struct DecodedValue {
    pub source: ValueSource,
    /// Parameter / header / cookie name (empty for the path itself).
    pub name: String,
    /// Value after URL-decoding, entity decoding and (optionally) escape
    /// decoding.
    pub decoded: String,
    /// `true` when the value is a discrete input field (query param, cookie,
    /// header, form member, JSON member) rather than an opaque body blob.
    /// Typed fields are the classic injection surface and carry full
    /// severity; bulk blobs (analytics JSON dumps, pasted HTML) often
    /// contain the same strings benignly, so the engine weights blob hits
    /// as weak signals.
    pub field: bool,
}

/// Fully normalized view of an inbound HTTP request. Borrows the request's
/// headers and body; only decoded/parsed material is owned.
#[derive(Debug, Clone)]
pub struct NormalizedRequest<'a> {
    /// Uppercased method — borrowed when the wire form was already uppercase
    /// (the common case), owned otherwise.
    pub method: Cow<'a, str>,
    pub path: String,
    /// Path plus `?query`, with the path portion normalized.
    pub full_uri: String,
    pub query_params: Vec<(String, String)>,
    /// The request's own header list, borrowed verbatim. Header lookups are
    /// ASCII case-insensitive.
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
    /// The body as text for the detectors: `Content-Encoding` undone and
    /// non-UTF-8 bytes mapped through Latin-1 instead of dropping the whole
    /// body. Borrows the wire bytes when they were already plain UTF-8.
    pub body_text: Option<Cow<'a, str>>,
    pub cookies: Vec<(String, String)>,
    /// Flat list of every decoded value the detectors should scan.
    pub decoded_values: Vec<DecodedValue>,
}

impl NormalizedRequest<'_> {
    /// Body as text for rule evaluation. `None` only when the request had no
    /// body; a body that is binary or compressed still yields text (see
    /// [`body_text`](Self::body_text)).
    pub fn body_str(&self) -> Option<&str> {
        self.body_text.as_deref()
    }

    /// Case-insensitive header lookup; returns the first match.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Host header (falls back to `:authority` for HTTP/2 captures).
    pub fn host(&self) -> &str {
        self.header("host")
            .or_else(|| self.header(":authority"))
            .unwrap_or("")
    }

    /// User-Agent header (empty when absent).
    pub fn user_agent(&self) -> &str {
        self.header("user-agent").unwrap_or("")
    }
}

/// Headers whose value should never be inspected as user-controlled data.
/// Skipping these keeps the signature engine from firing on, e.g., the
/// `Cookie` header itself when we already inspect its parsed components.
const SKIP_HEADERS: &[&str] = &[
    "cookie",
    "authorization",
    "proxy-authorization",
    "content-length",
    "transfer-encoding",
];

/// Decode and normalize an entire request.
///
/// `max_decode_layers` caps how many URL-decoding passes are applied to defend
/// against double / triple-encoded payloads without opening a CPU DoS.
/// `decode_escapes` additionally resolves `\xHH` / `\uHHHH` sequences — a
/// Strict-level extra pass, off by default to keep the Normal hot path lean.
#[allow(clippy::too_many_arguments)]
pub fn normalize_request<'a>(
    method: &'a str,
    raw_path: &str,
    raw_query: &str,
    headers: &'a [(String, String)],
    body: Option<&'a [u8]>,
    max_decode_layers: usize,
    decode_escapes: bool,
) -> NormalizedRequest<'a> {
    let decoded_path_raw = multi_decode(raw_path, max_decode_layers);
    let normalized_path = normalize_path(&decoded_path_raw);

    let mut decoded_values = Vec::with_capacity(8);
    decoded_values.push(DecodedValue {
        source: ValueSource::Path,
        name: String::new(),
        // `normalize_path` has already borrowed the decoded form; hand the
        // owned String to the scan list instead of cloning it once more.
        decoded: decoded_path_raw,
        field: true,
    });

    // NOTE: the raw query is split on `&` *before* decoding so that an
    // encoded `%26` inside a value is not mistaken for a separator. Each
    // key/value is then multi-decoded individually inside `parse_query`.
    let query_params = parse_query(
        raw_query,
        max_decode_layers,
        decode_escapes,
        &mut decoded_values,
    );
    // Build the decoded URI in one allocation. The old shape allocated one
    // String per parameter, a Vec of them, and the final joined String; a
    // 100-parameter request paid 202 allocations for a value the detectors
    // usually only read once.
    let mut full_uri =
        String::with_capacity(normalized_path.len() + raw_query.len() + 1);
    full_uri.push_str(&normalized_path);
    if !query_params.is_empty() {
        full_uri.push('?');
        for (index, (key, value)) in query_params.iter().enumerate() {
            if index > 0 {
                full_uri.push('&');
            }
            full_uri.push_str(key);
            // Preserve the old `format!("{key}={value}")` shape, including
            // `flag=` for a bare flag; rules may match on the `=`.
            full_uri.push('=');
            full_uri.push_str(value);
        }
    }

    // The method only needs re-allocating when the wire form was not already
    // uppercase; proxy stacks hand us uppercase methods ~always.
    let method = if method.bytes().any(|b| b.is_ascii_lowercase()) {
        Cow::Owned(method.to_ascii_uppercase())
    } else {
        Cow::Borrowed(method)
    };

    let mut cookies = Vec::new();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("cookie") {
            parse_cookies(
                v,
                max_decode_layers,
                decode_escapes,
                &mut cookies,
                &mut decoded_values,
            );
            continue;
        }
        if SKIP_HEADERS.iter().any(|s| k.eq_ignore_ascii_case(s)) {
            continue;
        }
        let decoded = decode_value(v, max_decode_layers, decode_escapes);
        decoded_values.push(DecodedValue {
            source: ValueSource::Header,
            name: k.clone(),
            decoded,
            field: true,
        });
    }

    // Decoded once and reused: the same text feeds both the per-value scan
    // list built below and the rule engine's `body` operand. `Content-Encoding`
    // is undone first, and a body that is not valid UTF-8 is mapped rather
    // than skipped — see `normalize::body` for why the old early exit was an
    // evasion.
    let body_text = body.and_then(|bytes| decode_body(headers, bytes));

    if let Some(text) = body_text.as_deref() {
        // Form-encoded bodies are split into parameters so each value is
        // inspected separately; anything else is scanned as a single blob.
        let ctype = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_ascii_lowercase())
            .unwrap_or_default();
        if ctype.contains("application/x-www-form-urlencoded") {
            parse_form_body(
                text,
                max_decode_layers,
                decode_escapes,
                &mut decoded_values,
            );
        } else if ctype.contains("json") || looks_like_json(text) {
            // Structured bodies: keep the raw blob (bulk content can be
            // benign), then add every string member as a *field* so the
            // detectors see typed inputs — with JSON escape handling
            // (`\u003c`) resolved by the parser itself.
            let decoded = decode_value(text, max_decode_layers, decode_escapes);
            decoded_values.push(DecodedValue {
                source: ValueSource::Body,
                name: String::new(),
                decoded,
                field: false,
            });
            unpack_json(
                text,
                max_decode_layers,
                decode_escapes,
                &mut decoded_values,
            );
        } else {
            let decoded = decode_value(text, max_decode_layers, decode_escapes);
            decoded_values.push(DecodedValue {
                source: ValueSource::Body,
                name: String::new(),
                decoded,
                field: false,
            });
        }
    }

    expand_base64(&mut decoded_values, max_decode_layers, decode_escapes);
    expand_b64_substrings(&mut decoded_values, decode_escapes);

    NormalizedRequest {
        method,
        path: normalized_path,
        full_uri,
        query_params,
        headers,
        body,
        body_text,
        cookies,
        decoded_values,
    }
}

/// Run URL multi-decoding plus HTML entity decoding, returning a stable form
/// safe for signature matching. With `decode_escapes`, `\xHH` / `\uHHHH`
/// sequences are resolved as well.
pub fn decode_value(
    input: &str,
    max_decode_layers: usize,
    decode_escapes: bool,
) -> String {
    let url_decoded = multi_decode(input, max_decode_layers);
    let out = if url_decoded.contains('&') {
        decode_entities(&url_decoded)
    } else {
        url_decoded
    };
    let out = if decode_escapes {
        decode_escapes_owned(&out)
    } else {
        out
    };
    // Escape resolution can expose a fresh percent layer (`\u0025\u0032\u0035`
    // → `%25`) that the pre-escape multi_decode never saw; re-run the bounded
    // percent pass so the innermost form is readable to the detectors.
    if out.contains('%') {
        multi_decode(&out, max_decode_layers)
    } else {
        out
    }
}

/// `decode_value` with form-encoding semantics: a bare `+` means space, the
/// way every mainstream runtime (nginx, PHP, Tomcat, …) parses query strings
/// and `application/x-www-form-urlencoded` bodies. Without it a payload like
/// `' OR 1=1--` sent as `%27+OR+1%3D1--` keeps its `+` separators and every
/// whitespace-sensitive detector (fingerprinting, regexes) sees one token and
/// walks past. Literal `+` stays reachable via `%2B`, and header / cookie /
/// path values use plain [`decode_value`] because there `+` is a literal.
fn decode_value_form(
    input: &str,
    max_decode_layers: usize,
    decode_escapes: bool,
) -> String {
    if input.contains('+') {
        return decode_value(
            &input.replace('+', " "),
            max_decode_layers,
            decode_escapes,
        );
    }
    decode_value(input, max_decode_layers, decode_escapes)
}

/// Resolve `\xHH` and `\uHHHH` escape sequences. Returns the input untouched
/// (borrowed) when it contains no escape marker, so the Normal-level path
/// never allocates for this.
pub fn decode_escapes(input: &str) -> Cow<'_, str> {
    let has_marker = input.contains("\\x")
        || input.contains("\\X")
        || input.contains("\\u")
        || input.contains("\\U");
    if !has_marker {
        return Cow::Borrowed(input);
    }
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 1 < bytes.len()
            && matches!(bytes[i + 1], b'x' | b'X' | b'u' | b'U')
        {
            let width = if matches!(bytes[i + 1], b'x' | b'X') {
                2
            } else {
                4
            };
            let hex_end = (i + 2 + width).min(bytes.len());
            if hex_end == i + 2 + width
                && bytes[i + 2..hex_end].iter().all(|b| b.is_ascii_hexdigit())
            {
                let n = u32::from_str_radix(&input[i + 2..hex_end], 16)
                    .unwrap_or(0);
                if let Some(c) = char::from_u32(n) {
                    out.push(c);
                    i = hex_end;
                    continue;
                }
            }
        }
        // Copy one full UTF-8 scalar (not one byte) so multi-byte sequences
        // pass through verbatim.
        let ch_len = input[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&input[i..i + ch_len]);
        i += ch_len;
    }
    Cow::Owned(out)
}

fn decode_escapes_owned(input: &str) -> String {
    match decode_escapes(input) {
        Cow::Borrowed(s) => s.to_string(),
        Cow::Owned(s) => s,
    }
}

/// Split a query string on `&` and decode each key/value pair, pushing
/// every value into `decoded_values` for downstream scanning.
fn parse_query(
    query: &str,
    max_decode_layers: usize,
    decode_escapes: bool,
    decoded_values: &mut Vec<DecodedValue>,
) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(4);
    // Split on `&` only. `;` is *not* treated as a separator: doing so would
    // cut classic command-injection payloads (`cmd=;cat /etc/passwd`) into an
    // empty value plus a name-only fragment, hiding the attack from the
    // detectors.
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        // The key runs the full value chain (percent + entity + escape
        // resolution): `\u0025\u0032\u0035…` keys and `redirect:%24%7B…` keys
        // are the same onion as values, just glued into the name position.
        let key_decoded =
            decode_value_form(k, max_decode_layers, decode_escapes);
        let val_decoded =
            decode_value_form(v, max_decode_layers, decode_escapes);
        // A query value that is itself serialized JSON (`?id={"id":"…"}`) is
        // unpacked in place, same as form fields — the container shape hides
        // the member payloads from every detector otherwise.
        if !val_decoded.is_empty()
            && unpack_string_json(
                &val_decoded,
                0,
                &key_decoded,
                max_decode_layers,
                decode_escapes,
                decoded_values,
            )
        {
            // Nothing below uses the key on this branch (the JSON unpack
            // already recorded its members), so move it into `out`.
            out.push((key_decoded, val_decoded));
            continue;
        }
        out.push((key_decoded.clone(), val_decoded.clone()));
        // The key itself is request input too: `?redirect:%24%7B%23a%3D%23…`
        // carries the whole OGNL payload in an *encoded* key with an empty
        // value, invisible to the detectors unless the key joins the scan
        // surface. Bounded so a pathological word-list key cannot mirror a
        // value-sized blob; 1KB still covers the transport-wrapped SQLi keys
        // observed in the wild (a 564B key once slipped past the 512 gate).
        if !key_decoded.is_empty() && key_decoded.len() <= 1024 {
            decoded_values.push(DecodedValue {
                source: ValueSource::QueryParam,
                name: String::new(),
                decoded: key_decoded.clone(),
                field: true,
            });
        }
        decoded_values.push(DecodedValue {
            source: ValueSource::QueryParam,
            name: key_decoded,
            decoded: val_decoded,
            field: true,
        });
    }
    out
}

/// Parse a `application/x-www-form-urlencoded` body. Same shape as
/// [`parse_query`] but tags every value with [`ValueSource::Body`] so the
/// engine can weight body hits differently from query-string hits.
fn parse_form_body(
    body: &str,
    max_decode_layers: usize,
    decode_escapes: bool,
    decoded_values: &mut Vec<DecodedValue>,
) {
    if body.is_empty() {
        return;
    }
    // See `parse_query` — `;` must stay part of the value.
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        // Same full-chain key decode as `parse_query`: percent + entity +
        // escape resolution, so `\u00…`/`%25…` onions glued into the name
        // position are readable.
        let key_decoded =
            decode_value_form(k, max_decode_layers, decode_escapes);
        let val_decoded =
            decode_value_form(v, max_decode_layers, decode_escapes);
        // A form field whose value is itself serialized JSON (APIs that
        // embed `param={"add":5,"delete":0}`) is unpacked in place — the
        // `"key":value` container shape trips libinjection's quote-keyword
        // fingerprint on completely benign payloads.
        if !val_decoded.is_empty()
            && unpack_string_json(
                &val_decoded,
                0,
                &key_decoded,
                max_decode_layers,
                decode_escapes,
                decoded_values,
            )
        {
            continue;
        }
        // Mirror the query-side key scan surface (1KB bound) — form keys are
        // request input too (`ip[0 or updatexml(…)%23]=x`).
        if !key_decoded.is_empty() && key_decoded.len() <= 1024 {
            decoded_values.push(DecodedValue {
                source: ValueSource::Body,
                name: String::new(),
                decoded: key_decoded.clone(),
                field: true,
            });
        }
        decoded_values.push(DecodedValue {
            source: ValueSource::Body,
            name: key_decoded,
            decoded: val_decoded,
            field: true,
        });
    }
}

/// Upper bounds that keep JSON unpacking a bounded operation regardless of
/// what the client sends: recursion depth, per-value byte length and the
/// total number of extracted members. The depth budget covers a nested
/// serialized-JSON string (telemetry beacons embed JSON-in-JSON three to
/// four levels deep), so the walk may descend into a string member's own
/// object tree as well.
const JSON_MAX_DEPTH: usize = 6;
const JSON_MAX_VALUE_LEN: usize = 4096;
const JSON_MAX_VALUES: usize = 64;

/// A JSON-looking body: JSON content type or an object/array opening brace
/// after leading whitespace. The sniff only *enables* the parse — a parse
/// failure falls back to blob-only scanning.
fn looks_like_json(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with('{') || trimmed.starts_with('[')
}

/// Recursively extract string members of a JSON body as typed fields. The
/// parser resolves JSON escape sequences (`\u003c`, `\/`) for us, closing
/// the escape-obfuscation gap without turning on the Strict escape pass.
/// Bounded by [`JSON_MAX_DEPTH`], [`JSON_MAX_VALUE_LEN`] and
/// [`JSON_MAX_VALUES`]; a parse failure simply yields nothing.
fn unpack_json(
    body: &str,
    max_decode_layers: usize,
    decode_escapes: bool,
    decoded_values: &mut Vec<DecodedValue>,
) {
    if body.len() > JSON_MAX_VALUE_LEN * 64 {
        return;
    }
    let Ok(root) = serde_json::from_str::<serde_json::Value>(body) else {
        return;
    };
    let mut count = 0usize;
    walk_json(
        &root,
        0,
        String::new(),
        max_decode_layers,
        decode_escapes,
        decoded_values,
        &mut count,
    );
}

/// Parse a string value that is itself serialized JSON and unpack its
/// members into `decoded_values` under `path`. Returns `true` when the value
/// was replaced by its unpacked members — the caller must then *not* push
/// the container string itself (the `"key":value` shape trips libinjection's
/// quote-keyword fingerprint on benign structured payloads). Depth shares
/// the [`JSON_MAX_DEPTH`] budget of the surrounding walk.
fn unpack_string_json(
    s: &str,
    depth: usize,
    path: &str,
    max_decode_layers: usize,
    decode_escapes: bool,
    decoded_values: &mut Vec<DecodedValue>,
) -> bool {
    if depth >= JSON_MAX_DEPTH || s.is_empty() || s.len() > JSON_MAX_VALUE_LEN {
        return false;
    }
    // A quoting wrapper around the payload (`id='{"id":"…"}'` in a query —
    // a SQL/string-concatenation artifact the backend still strips before
    // parsing) must not hide the members. One shell layer, matching quotes.
    let stripped = s.trim();
    let stripped = {
        let bytes = stripped.as_bytes();
        if bytes.len() >= 2
            && (bytes[0] == b'\'' || bytes[0] == b'"')
            && bytes[bytes.len() - 1] == bytes[0]
        {
            &stripped[1..stripped.len() - 1]
        } else {
            stripped
        }
    };
    if !looks_like_json(stripped) {
        return false;
    }
    let Ok(nested) = serde_json::from_str::<serde_json::Value>(stripped) else {
        return false;
    };
    let before = decoded_values.len();
    let mut count = 0usize;
    walk_json(
        &nested,
        depth + 1,
        path.to_string(),
        max_decode_layers,
        decode_escapes,
        decoded_values,
        &mut count,
    );
    // Replace the container only when members were actually extracted —
    // a value the depth budget rejected stays put rather than vanishing.
    decoded_values.len() > before
}

/// Upper bounds for the base64 value-unwrapping pass: nesting depth (a value
/// that is base64 of base64 of a payload) and the byte size above which a
/// value is bulk content, not a transport-wrapped parameter. 16KB covers the
/// transport-wrapped XML/JSON attack bodies observed in the wild (a 5KB wire
/// value carrying an OGNL `#context.get` payload in `\u`-escaped JSON used to
/// fall between this gate and every detector); the charset + printability
/// gates inside `b64_decode_value` remain the real quality filter.
const B64_MAX_DEPTH: usize = 2;
const B64_MAX_VALUE_LEN: usize = 16384;

/// Expand values whose entire content is base64 (`eyJpZCI6IjEgYW5kIDE9MiJ9`
/// is `{"id":"1 and 1=2"}`): whole payloads get wrapped in a transport
/// encoding the backend is known to unwrap, and no detector can see through
/// it from the wire form. For every discrete field that decodes as base64
/// into printable text an additional decoded value (`<name>.b64`) is pushed
/// and scanned like any other field — including a JSON unpack when the
/// decoded text is structured, and one URL-decode when it carries `%`
/// escapes. Values that decode to non-text (hashes, binary tokens) stay
/// untouched. Bounded by [`B64_MAX_DEPTH`] and [`B64_MAX_VALUE_LEN`].
fn expand_base64(
    decoded_values: &mut Vec<DecodedValue>,
    max_decode_layers: usize,
    decode_escapes: bool,
) {
    let mut layer_start = 0usize;
    let mut layer_end = decoded_values.len();
    let mut depth = 0usize;
    while layer_start < layer_end && depth < B64_MAX_DEPTH {
        // Snapshot the layer: expanding pushes into the same vector.
        let layer: Vec<(ValueSource, String, String)> = decoded_values
            [layer_start..layer_end]
            .iter()
            // Do not clone every field just to discover that it is not
            // base64. The cheap alphabet/length prefilter keeps the common
            // request (no encoded payloads) allocation-free here.
            .filter(|v| {
                v.field
                    && v.decoded.len() >= 10
                    && v.decoded.len() <= B64_MAX_VALUE_LEN
                    && v.decoded.bytes().all(|b| {
                        b.is_ascii_alphanumeric()
                            || b == b'+'
                            || b == b'/'
                            || b == b'='
                    })
            })
            .map(|v| (v.source, v.name.clone(), v.decoded.clone()))
            .collect();
        for (source, name, value) in layer {
            // 10B floor: `MSBhbmQgMT0y` (`1 and 1=2`, 12B) rides inside JSON
            // members and falls between the old 16B gate and the 12B core
            // gate inside `b64_decode_value`. The charset + printability
            // gates there remain the real quality filter; this length check
            // only bounds work.
            if value.len() < 10 || value.len() > B64_MAX_VALUE_LEN {
                continue;
            }
            let Some(mut decoded) = b64_decode_value(&value) else {
                continue;
            };
            // Transport-wrapped payloads often carry a second obfuscation
            // layer inside (`\u0074…` JavaScript/Java escapes); the decoded
            // value is already a deliberately encoded surface, so the escape
            // pass runs regardless of level.
            if decoded.contains("\\u") || decoded.contains("\\x") {
                decoded = decode_escapes_owned(&decoded);
            }
            if decoded.contains('%') || decoded.contains("&#") {
                decoded =
                    decode_value(&decoded, max_decode_layers, decode_escapes);
            }
            if decoded.is_empty() || decoded.len() > B64_MAX_VALUE_LEN {
                continue;
            }
            // Transport padding smuggles bare control characters past the
            // 90% printability gate (stray NUL between `OR` and the block
            // comment, lone CR): every SQL keyword lexer downstream loses
            // the token (`or\0` is not `\bor\b`). Replace them with spaces —
            // same trade as the JSON control-char retry below, spaces keep
            // token boundaries a delete would glue away.
            if decoded.chars().any(|c| {
                c.is_ascii_control() && c != '\t' && c != '\n' && c != '\r'
            }) {
                decoded = decoded
                    .chars()
                    .map(|c| {
                        if c.is_ascii_control()
                            && c != '\t'
                            && c != '\n'
                            && c != '\r'
                        {
                            ' '
                        } else {
                            c
                        }
                    })
                    .collect();
            }
            let name = if name.is_empty() {
                "b64".to_string()
            } else {
                format!("{name}.b64")
            };
            if looks_like_json(&decoded)
                && unpack_string_json(
                    &decoded,
                    0,
                    &name,
                    max_decode_layers,
                    decode_escapes,
                    decoded_values,
                )
            {
                continue;
            }
            // Obfuscated transports sometimes carry bare control characters
            // in JSON structure positions (stray CR between key and colon,
            // NUL before the closing brace) — a strict parse refuses those,
            // so replace them with spaces and retry once. Space keeps the
            // token boundaries a plain delete would glue away (`droP\n1`
            // must not become `droP1`).
            if looks_like_json(&decoded) {
                let had_control = decoded.chars().any(|c| c.is_ascii_control());
                if had_control {
                    let stripped: String = decoded
                        .chars()
                        .map(|c| if c.is_ascii_control() { ' ' } else { c })
                        .collect();
                    if unpack_string_json(
                        &stripped,
                        0,
                        &name,
                        max_decode_layers,
                        decode_escapes,
                        decoded_values,
                    ) {
                        continue;
                    }
                }
            }
            decoded_values.push(DecodedValue {
                source,
                name,
                decoded,
                field: true,
            });
        }
        layer_start = layer_end;
        layer_end = decoded_values.len();
        depth += 1;
    }
}

/// Quoted-run b64 extraction. Some transports hide the payload inside a
/// larger text surface (a JSON array of `\uXXXX`-escaped strings, a quoted
/// member in a form field): the whole value is not base64 so
/// [`expand_base64`] skips it, but the classic b64 run sits inside string
/// quotes after the escape pass. Require the run to open and close inside
/// matching string quotes — UA tokens and header blobs never do — and let
/// the charset + printability gates inside [`b64_decode_value`] reject hex
/// hashes and camelCase words. Strict-only: the escape pass that exposes
/// these runs does not run below Strict.
fn expand_b64_substrings(decoded_values: &mut Vec<DecodedValue>, strict: bool) {
    if !strict {
        return;
    }
    let layer: Vec<(ValueSource, String, String)> = decoded_values
        .iter()
        .filter(|v| {
            v.field
                && !v.name.contains(".b64")
                && v.decoded.len() >= 16
                && (v.decoded.contains('"') || v.decoded.contains('\''))
        })
        .map(|v| (v.source, v.name.clone(), v.decoded.clone()))
        .collect();
    for (source, name, value) in layer {
        let bytes = value.as_bytes();
        let mut pushed = 0usize;
        let mut i = 0usize;
        while i + 1 < bytes.len() && pushed < 4 {
            // Run must open right behind a string quote. Single quotes count
            // too: SQL/Python string literals carry payloads the same way
            // (`{'id': 'MCcgfHwg…='}` unwraps to a UNION/tautology chain),
            // and the white corpus's only single-quoted runs are camelCase
            // API names that the printability gate inside
            // [`b64_decode_value`] rejects after decoding.
            if bytes[i] != b'"' && bytes[i] != b'\'' {
                i += 1;
                continue;
            }
            let quote = bytes[i];
            let start = i + 1;
            let mut end = start;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric()
                    || bytes[end] == b'+'
                    || bytes[end] == b'/'
                    || bytes[end] == b'=')
            {
                end += 1;
            }
            let run_len = end - start;
            // Close straight into the matching quote; padding may precede it.
            if run_len >= 16 && end < bytes.len() && bytes[end] == quote {
                if let Some(decoded) = b64_decode_value(&value[start..end]) {
                    decoded_values.push(DecodedValue {
                        source,
                        name: if name.is_empty() {
                            "b64q".to_string()
                        } else {
                            format!("{name}.b64q")
                        },
                        decoded,
                        field: true,
                    });
                    pushed += 1;
                }
                i = end + 1;
            } else {
                i = end.max(start + 1);
            }
        }
    }
}

/// Decode a value that is *entirely* base64 into text. `None` when the value
/// carries anything outside the base64 alphabet (data URIs, signed tokens,
/// hex hashes decode to binary and fail the printability gate anyway).
/// Lenient decode engine: the stock STANDARD engine rejects non-canonical
/// trailing bits, but mainstream server decoders (python `binascii`, Java
/// `util.Base64` without strict flags) accept them — a payload wrapped by
/// such an encoder (`…S0` ending in a symbol whose low bits are nonzero)
/// decodes on the backend while the WAF's `b64_decode_value` returned None,
/// hiding the whole transport layer. The charset and printability gates
/// around the decode are the quality filter; trailing-bit leniency only
/// widens what reaches them.
static B64_ENGINE: Lazy<base64::engine::general_purpose::GeneralPurpose> =
    Lazy::new(|| {
        use base64::engine::GeneralPurposeConfig as Cfg;
        base64::engine::general_purpose::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            Cfg::new().with_decode_allow_trailing_bits(true),
        )
    });

fn b64_decode_value(s: &str) -> Option<String> {
    use base64::Engine as _;
    if !s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
    }) {
        return None;
    }
    let core = s.trim_end_matches('=');
    if core.len() < 12 {
        return None;
    }
    let pad = (4 - core.len() % 4) % 4;
    if pad == 3 {
        return None;
    }
    let mut buf = String::with_capacity(core.len() + pad);
    buf.push_str(core);
    for _ in 0..pad {
        buf.push('=');
    }
    let raw = B64_ENGINE.decode(buf.as_bytes()).ok()?;
    let text = String::from_utf8(raw).ok()?;
    let printable = text
        .bytes()
        .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    if printable * 10 < text.len() * 9 {
        return None;
    }
    Some(text)
}

#[allow(clippy::too_many_arguments)]
fn walk_json(
    value: &serde_json::Value,
    depth: usize,
    path: String,
    max_decode_layers: usize,
    decode_escapes: bool,
    decoded_values: &mut Vec<DecodedValue>,
    count: &mut usize,
) {
    if *count >= JSON_MAX_VALUES {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            if s.is_empty() || s.len() > JSON_MAX_VALUE_LEN {
                return;
            }
            // A string member that is itself serialized JSON (nested
            // telemetry payloads, icons, embedded config blobs) is unpacked
            // in place instead of being scanned as a container — see
            // [`unpack_string_json`].
            if unpack_string_json(
                s,
                depth,
                &path,
                max_decode_layers,
                decode_escapes,
                decoded_values,
            ) {
                *count += 1;
                return;
            }
            let decoded = decode_value(s, max_decode_layers, decode_escapes);
            decoded_values.push(DecodedValue {
                source: ValueSource::Body,
                name: path,
                decoded,
                field: true,
            });
            *count += 1;
        },
        serde_json::Value::Array(items) => {
            if depth >= JSON_MAX_DEPTH {
                return;
            }
            for (i, item) in items.iter().enumerate() {
                walk_json(
                    item,
                    depth + 1,
                    format!("{path}[{i}]"),
                    max_decode_layers,
                    decode_escapes,
                    decoded_values,
                    count,
                );
            }
        },
        serde_json::Value::Object(map) => {
            if depth >= JSON_MAX_DEPTH {
                return;
            }
            for (k, v) in map {
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                walk_json(
                    v,
                    depth + 1,
                    child,
                    max_decode_layers,
                    decode_escapes,
                    decoded_values,
                    count,
                );
            }
        },
        // Scalars become scannable strings so a nested container made only
        // of numbers/booleans still yields members (keeping the
        // container-replacement rule honest). Scalar values carry no
        // injection payload on their own.
        serde_json::Value::Number(n) => {
            if *count >= JSON_MAX_VALUES {
                return;
            }
            decoded_values.push(DecodedValue {
                source: ValueSource::Body,
                name: path,
                decoded: n.to_string(),
                field: true,
            });
            *count += 1;
        },
        serde_json::Value::Bool(b) => {
            if *count >= JSON_MAX_VALUES {
                return;
            }
            decoded_values.push(DecodedValue {
                source: ValueSource::Body,
                name: path,
                decoded: b.to_string(),
                field: true,
            });
            *count += 1;
        },
        _ => {},
    }
}

/// Parse a `Cookie:` header value (`a=b; c=d`) and decode each pair.
fn parse_cookies(
    header: &str,
    max_decode_layers: usize,
    decode_escapes: bool,
    cookies: &mut Vec<(String, String)>,
    decoded_values: &mut Vec<DecodedValue>,
) {
    for pair in header.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (pair, ""),
        };
        let key_decoded = multi_decode(k, max_decode_layers);
        let val_decoded = decode_value(v, max_decode_layers, decode_escapes);
        cookies.push((key_decoded.clone(), val_decoded.clone()));
        decoded_values.push(DecodedValue {
            source: ValueSource::Cookie,
            name: key_decoded,
            decoded: val_decoded,
            field: true,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_only_b64_and_escape_onions_join_scan_surface() {
        // `?JTI1MjhzZWxlY3Q…` — the whole SQLi payload rides in a 564B
        // key-only parameter: base64 → `%2528select…` → `(select
        // extractvalue(…`. It must clear the 512-era gate (1KB now) and the
        // b64 unwrap must run for keys.
        let key = "JTI1MjhzZWxlY3QlMjUyMGV4dHJhY3R2YWx1ZSUyNTI4eG1sdHlwZSUyNTI4JTI1MjclMjUzQyUyNTNGeG1sJTI1MjB2ZXJzaW9uJTI1M0QlMjUyMjEuMCUyNTIyJTI1MjBlbmNvZGluZyUyNTNEJTI1MjJVVEYtOCUyNTIyJTI1M0YlMjUzRSUyNTNDJTI1MjFET0NUWVBFJTI1MjByb290JTI1MjAlMjU1QiUyNTIwJTI1M0MlMjUyMUVOVElUWSUyNTIwJTI1MjUlMjUyMHZhcG90JTI1MjBTWVNURU0lMjUyMCUyNTIyJTI1MjclMjU3QyUyNTdDJTI1MjhzZWxlY3QlMjUyMHZlcnNpb24lMjUyMGZyb20lMjUyMHYlMjUyNGluc3RhbmNlJTI1MjklMjU3QyUyNTdDJTI1MjdCdXJwJTI1MkYlMjUyMiUyNTNFJTI1MjV2YXBvdCUyNTNCJTI1NUQlMjUzRSUyNTI3JTI1MjklMjUyQyUyNTI3JTI1MkZsJTI1MjclMjUyOSUyNTIwZnJvbSUyNTIwZHVhbCUyNTI5";
        let req = normalize_request("GET", "/", key, &[], None, 3, true);
        let unwrapped = req
            .decoded_values
            .iter()
            .find(|v| v.name == "b64" || v.name.ends_with(".b64"))
            .expect("b64-unwrapped key");
        assert!(
            unwrapped.decoded.contains("(select extractvalue"),
            "decoded head: {:?}",
            &unwrapped.decoded[..unwrapped.decoded.len().min(80)]
        );

        // `\u0025\u0032\u0035\u0032\u0038select…` as a percent-encoded
        // key-only parameter: the escape pass resolves to `%2528select`, and
        // the freshly exposed percent layer must be decoded again instead of
        // stopping at one visible form.
        let escaped_key = "%5Cu0025%5Cu0032%5Cu0035%5Cu0032%5Cu0038s%5Cu0065%5Cu006C%5Cu0065%5Cu0063%5Cu0074%5Cu0020%5Cu0074";
        let req =
            normalize_request("GET", "/", escaped_key, &[], None, 3, true);
        assert!(
            req.decoded_values
                .iter()
                .any(|v| v.decoded.contains("(select t")),
            "no value carries the twice-decoded form; got {:?}",
            req.decoded_values
                .iter()
                .map(|v| v.decoded.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn parses_query_and_cookies() {
        let headers = vec![
            ("User-Agent".to_string(), "curl/8.0".to_string()),
            ("Cookie".to_string(), "a=1; b=hello%20world".to_string()),
        ];
        let req = normalize_request(
            "get",
            "/foo/./bar",
            "x=1&y=hello%20world",
            &headers,
            None,
            3,
            false,
        );
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/foo/bar");
        assert_eq!(req.query_params.len(), 2);
        assert_eq!(
            req.cookies,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "hello world".to_string()),
            ]
        );
        // path + 2 query keys + 2 query values + UA + 2 cookies
        assert_eq!(req.decoded_values.len(), 8);
    }

    #[test]
    fn double_encoded_payloads_are_decoded() {
        let req = normalize_request(
            "GET",
            "/x",
            "p=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            &[],
            None,
            3,
            false,
        );
        let v = req
            .decoded_values
            .iter()
            .find(|v| v.name == "p")
            .expect("param p");
        assert_eq!(v.decoded, "../../etc/passwd");
    }

    #[test]
    fn skips_authorization_header() {
        let headers =
            vec![("Authorization".to_string(), "Bearer xyz".to_string())];
        let req = normalize_request("GET", "/", "", &headers, None, 3, false);
        assert!(!req
            .decoded_values
            .iter()
            .any(|v| v.source == ValueSource::Header
                && v.name == "authorization"));
    }

    #[test]
    fn overlong_utf8_is_restored() {
        // `%C0%BC` is the overlong encoding of `<`; the byte-wise decoder
        // must restore it and keep scanning the payload behind it.
        let req = normalize_request(
            "GET",
            "/",
            "q=%C0%BCscript%3Ealert(1)%3C/script%3E",
            &[],
            None,
            3,
            false,
        );
        let v = req
            .decoded_values
            .iter()
            .find(|v| v.name == "q")
            .expect("param q");
        assert_eq!(v.decoded, "<script>alert(1)</script>");
    }

    #[test]
    fn base64_wrapped_json_payload_is_expanded() {
        // `eyJpZCI6IjEgYW5kIDE9MiJ9` = `{"id":"1 and 1=2"}`: the b64 pass
        // must surface the decoded container's members as scannable fields.
        let req = normalize_request(
            "GET",
            "/",
            "name=eyJpZCI6IjEgYW5kIDE9MiJ9",
            &[],
            None,
            3,
            false,
        );
        let b64 = req
            .decoded_values
            .iter()
            .find(|v| v.name == "name.b64.id")
            .expect("expanded b64 JSON member");
        assert_eq!(b64.decoded, "1 and 1=2");
        assert!(b64.field);
        // The container itself is replaced by its members (the `"k":v`
        // shape trips quote-keyword), so only the member is present.
        assert!(!req.decoded_values.iter().any(|v| v.name == "name.b64"));
    }

    #[test]
    fn base64_double_wrap_is_expanded() {
        // b64(b64("1 union select password from users"))
        let inner = "1 union select password from users";
        use base64::Engine as _;
        let once =
            base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let twice =
            base64::engine::general_purpose::STANDARD.encode(once.as_bytes());
        let query = format!("q={twice}");
        let req = normalize_request("GET", "/", &query, &[], None, 3, false);
        let expanded = req
            .decoded_values
            .iter()
            .find(|v| v.name == "q.b64.b64")
            .expect("second-layer expansion");
        assert_eq!(expanded.decoded, inner);
    }

    #[test]
    fn base64_binary_and_hex_stay_untouched() {
        // An md5 hex string is base64-alphabet-compatible but decodes to
        // binary — it must not surface as an expanded value.
        let req = normalize_request(
            "GET",
            "/",
            "h=d41d8cd98f00b204e9800998ecf8427e",
            &[],
            None,
            3,
            false,
        );
        assert!(!req
            .decoded_values
            .iter()
            .any(|v| v.name.starts_with("h.b64")));
        // Data-URI prefixes carry ':'/';' and never match the alphabet.
        let req = normalize_request(
            "GET",
            "/",
            "d=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUg",
            &[],
            None,
            3,
            false,
        );
        assert!(!req
            .decoded_values
            .iter()
            .any(|v| v.name.starts_with("d.b64")));
    }

    #[test]
    fn headers_are_borrowed_not_copied() {
        let headers = vec![("X-Custom".to_string(), "probe".to_string())];
        let body = b"payload".to_vec();
        let req =
            normalize_request("GET", "/", "", &headers, Some(&body), 3, false);
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.body, Some(body.as_slice()));
        assert_eq!(req.body_str(), Some("payload"));
    }

    #[test]
    fn method_borrowed_when_uppercase() {
        let req = normalize_request("GET", "/", "", &[], None, 3, false);
        assert!(matches!(req.method, Cow::Borrowed("GET")));
        let req = normalize_request("get", "/", "", &[], None, 3, false);
        assert!(matches!(req.method, Cow::Owned(_)));
        assert_eq!(req.method, "GET");
    }

    #[test]
    fn escapes_decoded_only_when_enabled() {
        let headers = vec![];
        let req = normalize_request(
            "GET",
            "/x",
            r"p=%5Cx3cscript%3E",
            &headers,
            None,
            3,
            false,
        );
        let v = req
            .decoded_values
            .iter()
            .find(|v| v.name == "p")
            .expect("param p");
        assert_eq!(v.decoded, r"\x3cscript>");
        assert!(!v.decoded.contains("<script"));

        let req = normalize_request(
            "GET",
            "/x",
            r"p=%5Cx3cscript%3E",
            &headers,
            None,
            3,
            true,
        );
        let v = req
            .decoded_values
            .iter()
            .find(|v| v.name == "p")
            .expect("param p");
        assert_eq!(v.decoded, "<script>");
    }

    #[test]
    fn unicode_escape_decoded() {
        assert_eq!(decode_escapes(r"a\u003cb"), "a<b");
        assert_eq!(decode_escapes("no escapes"), "no escapes");
        // Incomplete / invalid escapes stay verbatim.
        assert_eq!(decode_escapes(r"\xzz"), r"\xzz");
        assert_eq!(decode_escapes(r"\uD83D"), r"\uD83D");
    }

    #[test]
    fn plus_is_space_in_query_and_form_body() {
        let req = normalize_request(
            "GET",
            "/",
            "id=%27+OR+1%3D1--",
            &[],
            None,
            3,
            false,
        );
        let v = req
            .decoded_values
            .iter()
            .find(|v| v.name == "id")
            .expect("param id");
        assert_eq!(v.decoded, "' OR 1=1--");

        let headers = vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )];
        let req = normalize_request(
            "POST",
            "/",
            "",
            &headers,
            Some(b"q=waitfor+delay+%270:0:10%27".as_slice()),
            3,
            false,
        );
        let v = req
            .decoded_values
            .iter()
            .find(|v| v.name == "q")
            .expect("body param q");
        assert_eq!(v.decoded, "waitfor delay '0:0:10'");
    }

    #[test]
    fn plus_stays_literal_in_headers_and_encoded_plus() {
        let headers =
            vec![("User-Agent".to_string(), "C++_runtime".to_string())];
        let req =
            normalize_request("GET", "/a+b", "k=%2B", &headers, None, 3, false);
        let ua = req
            .decoded_values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case("user-agent"))
            .expect("ua value");
        assert_eq!(ua.decoded, "C++_runtime");
        let v = req
            .decoded_values
            .iter()
            .find(|v| v.name == "k")
            .expect("param k");
        assert_eq!(v.decoded, "+");
    }

    #[test]
    fn json_valued_query_param_is_unpacked() {
        // `?j={"id":"1 and 1=2"}` — the container shape hides the member
        // from the detectors unless the query parser unpacks it like form
        // fields do. URL-encoded form: %7B%22id%22%3A%221%20and%201%3D2%22%7D
        let req = normalize_request(
            "GET",
            "/",
            "j=%7B%22id%22%3A%221%20and%201%3D2%22%7D",
            &[],
            None,
            3,
            false,
        );
        let member = req
            .decoded_values
            .iter()
            .find(|v| v.name == "j.id")
            .expect("unpacked JSON member");
        assert_eq!(member.decoded, "1 and 1=2");
        assert!(member.field);
        // The container itself is replaced by its members (its `"k":v`
        // shape trips quote-keyword on benign payloads).
        assert!(!req.decoded_values.iter().any(|v| v.name == "j"));
    }

    #[test]
    fn base64_json_with_unicode_escapes_is_expanded() {
        // b64 of `{"id":"1 un\u0069on select password from users"}` — the
        // transport-decoded text carries literal `\u` escapes that would
        // leave the union keyword invisible behind the escape sequence.
        use base64::Engine as _;
        let inner = r#"{"id":"1 un\u0069on select password from users"}"#;
        let wrapped =
            base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let req = normalize_request(
            "GET",
            "/",
            &format!("q={wrapped}"),
            &[],
            None,
            3,
            false,
        );
        let member = req
            .decoded_values
            .iter()
            .find(|v| v.name == "q.b64.id")
            .expect("expanded b64 JSON member");
        assert_eq!(member.decoded, "1 union select password from users");
    }

    #[test]
    fn base64_json_with_bare_control_chars_is_unpacked() {
        // b64 of a JSON container with bare control bytes in structure
        // positions (stray CR after a key, NUL before the closing brace):
        // the strict parse refuses them, so the unpack must strip and
        // retry — and the member value here is itself base64 (layer 2),
        // `` ; echo `/bin/cat /etc/hosts` ``.
        use base64::Engine as _;
        let inner = "{\r\t\"trajectory\"\r:false,\"policy\":\t\"OyBlY2hvIGAvYmluL2NhdCAvZXRjL2hvc3RzYA==\"\x00} ";
        let wrapped =
            base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let req = normalize_request(
            "GET",
            "/",
            &format!("q={wrapped}"),
            &[],
            None,
            3,
            false,
        );
        let layer2 = req
            .decoded_values
            .iter()
            .find(|v| v.name == "q.b64.policy.b64")
            .expect("layer-2 expansion");
        assert_eq!(layer2.decoded, "; echo `/bin/cat /etc/hosts`");
    }

    #[test]
    fn full_uri_is_built_without_changing_query_shape() {
        let req = normalize_request(
            "GET",
            "/a%2Fb",
            "x=1&flag&y=%2F",
            &[],
            None,
            3,
            false,
        );
        assert_eq!(req.full_uri, "/a/b?x=1&flag=&y=/");
        assert_eq!(req.query_params.len(), 3);
    }
}
