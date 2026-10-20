// Copyright 2025 Tree xie.
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

use super::{Error, get_hash_key, get_str_conf, get_str_slice_conf};
use async_trait::async_trait;
use bstr::ByteSlice;
use bytes::{Bytes, BytesMut};
use flate2::Compression;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HTTP_HEADER_TRANSFER_CHUNKED, ModifyResponseBody, Plugin,
    ResponseBodyPluginResult, ResponsePluginResult,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use regex::Regex;
use regex::bytes::RegexBuilder;
use std::borrow::Cow;
use std::io::{Read, Write};
use std::sync::LazyLock;
use tracing::{debug, warn};

const PLUGIN_ID: &str = "_sub_filter_";

type Result<T, E = Error> = std::result::Result<T, E>;

/// SubFilter plugin for modifying response content using pattern matching and replacement.
/// This plugin supports two types of content replacement:
/// 1. Regex-based replacement (subs_filter)
/// 2. Literal string replacement (sub_filter)
pub struct SubFilter {
    /// Regex pattern that matches against request paths
    /// Only requests with matching paths will be processed by this filter
    path: Option<Regex>,

    /// The content replacement engine that handles both regex and literal replacements
    /// Contains a collection of filter rules that will be applied in sequence
    replacer: SubFilterReplacer,

    /// Unique identifier for this plugin instance
    /// Used for tracking and managing multiple instances of the plugin
    hash_value: String,

    /// Status codes to apply the filter to
    /// If None, the filter will be applied to all status codes
    /// If Some, the filter will be applied to the specified status codes
    /// The status codes are in the format of "200,201,202,..."
    status_codes: Option<Vec<u16>>,
}

// Regular expression for parsing filter rules in the format:
// subs_filter|sub_filter 'pattern' 'replacement' [flags]
static SUBS_FILTER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(subs_filter|sub_filter)\s+'([^']+)'\s+'([^']+)'(?:\s+([ig]+))?",
    )
    .expect("Failed to compile subs filter regex")
});

/// Parameters for configuring a single substitution filter rule
#[derive(Debug, Default, Clone)]
struct SubFilterParams {
    /// Compiled regex pattern for `subs_filter` type replacements
    /// - None for literal string replacements (sub_filter)
    /// - Some(regex) for pattern-based replacements (subs_filter)
    regex_pattern: Option<regex::bytes::Regex>,

    /// Raw bytes pattern for `sub_filter` type replacements
    /// Only used when regex_pattern is None
    /// Stores the literal string to search for as UTF-8 bytes
    pattern: Vec<u8>,

    /// The content to substitute in place of matches
    /// Stored as UTF-8 bytes to support both text and binary replacements
    replacement: Vec<u8>,

    /// Special flags that modify the replacement behavior:
    /// - 'i': case-insensitive matching
    /// - 'g': global replacement (replace all occurrences)
    ///   If 'g' is not present, only the first match is replaced
    flags: Vec<char>,
}

/// Parses a substitution filter rule string into structured parameters.
///
/// # Arguments
/// * `rule` - A string in the format: "subs_filter|sub_filter 'pattern' 'replacement' [flags]"
///
/// # Returns
/// * `Option<SubFilterParams>` - Parsed parameters or None if parsing fails
fn parse_subs_filter(rule: &str) -> Option<SubFilterParams> {
    let captures = SUBS_FILTER_REGEX.captures(rule)?;

    let mut params = SubFilterParams {
        flags: captures
            .get(4)
            .map(|m| m.as_str().chars().collect())
            .unwrap_or_default(),
        replacement: captures.get(3)?.as_str().as_bytes().to_vec(),
        ..Default::default()
    };

    let pattern = captures.get(2)?.as_str();

    match captures.get(1)?.as_str() {
        "subs_filter" => {
            let regex_pattern = RegexBuilder::new(pattern)
                .case_insensitive(params.flags.contains(&'i'))
                .build()
                .ok()?;
            params.regex_pattern = Some(regex_pattern);
        },
        _ => {
            params.pattern = pattern.as_bytes().to_vec();
        },
    };

    Some(params)
}

/// Handles the actual content replacement logic for both regex and literal string replacements
/// Responses up to this size are buffered for replacement; larger ones are
/// passed through untouched. The replacer holds the whole body in memory and
/// makes one full copy per rule, so an unbounded body is a direct memory
/// lever (2026-10-18 audit).
const MAX_SUB_FILTER_BYTES: usize = 8 * 1024 * 1024;

/// The content encodings the replacer can transparently decompress, replace
/// and recompress. Anything else (`br`, `zstd`, multi-value encodings, ...)
/// makes the whole response pass through untouched.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum ContentEncoding {
    /// No meaningful encoding: run the replacement on the raw bytes.
    #[default]
    Plain,
    /// `gzip` / `x-gzip`.
    Gzip,
    /// `deflate` (zlib wrapper; raw deflate is attempted as a fallback).
    Deflate,
}

/// Classifies the `Content-Encoding` of a response.
///
/// Returns `None` when the encoding exists but cannot be handled: the caller
/// must leave the response completely untouched (headers included) rather
/// than corrupt it.
fn classify_content_encoding(
    headers: &http::HeaderMap,
) -> Option<ContentEncoding> {
    // No header at all is the overwhelmingly common case and means the body
    // is plain: `?` here would classify every uncompressed response as
    // "unsupported" and skip the filter (2026-10-21 regression).
    let Some(raw) = headers.get(http::header::CONTENT_ENCODING) else {
        return Some(ContentEncoding::Plain);
    };
    let value = raw.to_str().ok()?.trim();
    match value.to_ascii_lowercase().as_str() {
        "" | "identity" => Some(ContentEncoding::Plain),
        "gzip" | "x-gzip" => Some(ContentEncoding::Gzip),
        "deflate" => Some(ContentEncoding::Deflate),
        // `br`, `zstd`, multi-value (`gzip, br`) or anything unknown.
        _ => None,
    }
}

/// Makes the response headers consistent with a body that will be rewritten:
/// the length can no longer be known up front, validators describing the old
/// body must be weakened or dropped, and caches have to know the body varies
/// with `Accept-Encoding` (the recompressed body differs from the origin's).
/// `Content-Encoding` itself is kept: the body is recompressed with the same
/// algorithm it arrived with.
fn make_headers_consistent(header: &mut ResponseHeader) {
    // The body length changes after the rewrite, and is unknowable before
    // the compression finishes anyway.
    header.remove_header(&http::header::CONTENT_LENGTH);
    // An entity tag describing the origin body is wrong once the body is
    // rewritten: weaken it (`W/`) instead of dropping it so conditional
    // requests keep functioning.
    if let Some(etag) = header
        .headers
        .get(http::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        && !etag.starts_with("W/")
        && let Ok(value) = http::HeaderValue::from_str(&format!("W/{etag}"))
    {
        let _ = header.insert_header(http::header::ETAG, value);
    }
    // Integrity digests of the old body can no longer be correct.
    header.remove_header("Content-MD5");
    header.remove_header("Digest");
    // The recompressed body differs from what the origin sent for other
    // `Accept-Encoding` values, so every cache must key on it.
    match header
        .headers
        .get(http::header::VARY)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    {
        None => {
            let _ = header.insert_header(
                http::header::VARY,
                http::HeaderValue::from_static("Accept-Encoding"),
            );
        },
        Some(vary) => {
            let has = vary.split(',').any(|part| {
                part.trim().eq_ignore_ascii_case("accept-encoding")
            });
            if !has
                && let Ok(value) = http::HeaderValue::from_str(&format!(
                    "{vary}, Accept-Encoding"
                ))
            {
                let _ = header.insert_header(http::header::VARY, value);
            }
        },
    }
}

#[derive(Debug, Default, Clone)]
struct SubFilterReplacer {
    filters: Vec<SubFilterParams>,
    buffer: BytesMut,
    /// Set once the body crosses [`MAX_SUB_FILTER_BYTES`] while streaming.
    ///
    /// [`SubFilter::handle_response`] can only read the cap off
    /// `Content-Length`, and a chunked response does not carry one, so the
    /// bound has to be enforced here as the chunks arrive. Once it trips the
    /// replacer stops buffering and writes every remaining chunk through
    /// unreplaced: the response is already in flight, so the only alternative
    /// would be truncating it.
    passthrough: bool,
    /// The upstream encoding of the buffered bytes, decided by
    /// [`SubFilter::handle_response`] before the body arrives.
    encoding: ContentEncoding,
}

impl ModifyResponseBody for SubFilterReplacer {
    /// Processes the response body data by applying all configured filters
    ///
    /// # Arguments
    /// * `data` - The response body bytes to be modified
    ///
    /// # Returns
    /// * `Bytes` - The modified response body
    fn handle(
        &mut self,
        _session: &Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        // Over the cap already: this chunk (and every later one) is forwarded
        // untouched. `body` is left exactly as the caller handed it over.
        if self.passthrough {
            return Ok(());
        }
        if let Some(data) = body {
            self.buffer.extend(&data[..]);
            data.clear();
        }
        // A chunked response carries no `Content-Length`, so the header-side
        // check cannot bound it and the buffer would grow with the body. Hand
        // back what is already buffered and stop: dropping it would truncate
        // the response, and keeping it would make the plugin itself the
        // unbounded-memory lever the cap exists to prevent.
        if self.buffer.len() > MAX_SUB_FILTER_BYTES {
            let size = self.buffer.len();
            warn!(
                target: PLUGIN_ID,
                size,
                "response body exceeded the sub-filter cap while streaming; \
                 passing the rest through unreplaced"
            );
            self.passthrough = true;
            *body = Some(self.buffer.split().freeze());
            return Ok(());
        }
        if !end_of_stream {
            return Ok(());
        }
        let raw = std::mem::take(&mut self.buffer);
        match self.encoding {
            ContentEncoding::Plain => {
                let mut data = raw.to_vec();
                self.apply_filters(&mut data);
                *body = Some(Bytes::from(data));
                Ok(())
            },
            ContentEncoding::Gzip | ContentEncoding::Deflate => {
                // Decompress, replace, recompress. Every failure path falls
                // back to the original compressed bytes with their
                // `Content-Encoding` intact: the client can always decode
                // the response, just without the replacement.
                let Some(plaintext) = self.decompress(&raw) else {
                    warn!(
                        target: PLUGIN_ID,
                        encoding = ?self.encoding,
                        size = raw.len(),
                        "failed to decompress the response body; \
                         passing the compressed bytes through"
                    );
                    *body = Some(raw.freeze());
                    return Ok(());
                };
                // The decompressed cap guards against compression bombs: a
                // few MiB of gzip can expand to gigabytes, so the plaintext
                // is bounded by the same cap as the raw buffer.
                if plaintext.len() > MAX_SUB_FILTER_BYTES {
                    warn!(
                        target: PLUGIN_ID,
                        size = plaintext.len(),
                        "decompressed body exceeded the sub-filter cap; \
                         passing the compressed bytes through"
                    );
                    *body = Some(raw.freeze());
                    return Ok(());
                }
                let mut data = plaintext.clone();
                self.apply_filters(&mut data);
                if data == plaintext {
                    // No rule matched: emit the origin bytes verbatim so the
                    // response is byte-identical (ETag, digests, signatures).
                    *body = Some(raw.freeze());
                    return Ok(());
                }
                *body = Some(self.recompress(&data).unwrap_or_else(|_| {
                    warn!(
                        target: PLUGIN_ID,
                        encoding = ?self.encoding,
                        "failed to recompress the replaced body; \
                         passing the compressed bytes through"
                    );
                    raw.clone().freeze()
                }));
                Ok(())
            },
        }
    }
    fn name(&self) -> &str {
        "sub_filter"
    }
}

impl SubFilterReplacer {
    /// Runs every configured filter over `data` in order.
    fn apply_filters(&self, data: &mut Vec<u8>) {
        for item in self.filters.iter() {
            if let Some(regex_pattern) = &item.regex_pattern {
                // Handle regex-based replacement (subs_filter)
                if item.flags.contains(&'g') {
                    // Global replacement - replace all occurrences
                    *data = regex_pattern
                        .replace_all(&data[..], &item.replacement)
                        .to_vec();
                } else {
                    // Replace first occurrence only
                    *data = regex_pattern
                        .replace(&data[..], &item.replacement)
                        .to_vec();
                }
            } else {
                // Handle literal string replacement (sub_filter)
                if item.flags.contains(&'g') {
                    // Global replacement
                    *data = data.replace(&item.pattern, &item.replacement);
                } else {
                    // Replace first occurrence only
                    *data = data.replacen(&item.pattern, &item.replacement, 1);
                }
            }
        }
    }
    /// Decompresses the buffered bytes into plaintext, or `None` when the
    /// stream cannot be decoded. `deflate` is ambiguous in the wild, so the
    /// zlib-wrapped form is tried first and raw deflate second.
    fn decompress(&self, raw: &[u8]) -> Option<Vec<u8>> {
        let decode = |decoder: &mut dyn Read| -> Option<Vec<u8>> {
            let mut plaintext = Vec::new();
            decoder.read_to_end(&mut plaintext).ok().map(|_| plaintext)
        };
        match self.encoding {
            ContentEncoding::Plain => Some(raw.to_vec()),
            ContentEncoding::Gzip => decode(&mut GzDecoder::new(raw)),
            ContentEncoding::Deflate => decode(&mut ZlibDecoder::new(raw))
                .or_else(|| decode(&mut DeflateDecoder::new(raw))),
        }
    }
    /// Recompresses the replaced plaintext with the same algorithm the body
    /// arrived with.
    fn recompress(&self, plaintext: &[u8]) -> std::io::Result<Bytes> {
        let bytes = match self.encoding {
            ContentEncoding::Plain => plaintext.to_vec(),
            ContentEncoding::Gzip => {
                let mut encoder =
                    GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(plaintext)?;
                encoder.finish()?
            },
            ContentEncoding::Deflate => {
                // flate2's `Zlib*` types are the zlib-wrapped `deflate`
                // encoding; the raw form was handled by the decoder above.
                let mut encoder =
                    ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(plaintext)?;
                encoder.finish()?
            },
        };
        Ok(Bytes::from(bytes))
    }
}

impl TryFrom<&PluginConf> for SubFilter {
    type Error = Error;

    /// Creates a SubFilter instance from plugin configuration
    ///
    /// # Arguments
    /// * `value` - Plugin configuration containing path, filters, and other settings
    ///
    /// # Returns
    /// * `Result<Self>` - Configured SubFilter instance or error if configuration is invalid
    fn try_from(value: &PluginConf) -> Result<Self> {
        let path_value = get_str_conf(value, "path");
        let path = if path_value.is_empty() {
            None
        } else {
            let regex = Regex::new(get_str_conf(value, "path").as_str())
                .map_err(|e| Error::Invalid {
                    category: PluginCategory::SubFilter.to_string(),
                    message: e.to_string(),
                })?;
            Some(regex)
        };
        let filters = get_str_slice_conf(value, "filters")
            .iter()
            .map(|s| {
                parse_subs_filter(s).ok_or(Error::Invalid {
                    category: PluginCategory::SubFilter.to_string(),
                    message: format!("invalid subs filter: {s}"),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let status_codes = get_str_conf(value, "status_codes");
        let status_codes = if !status_codes.is_empty() {
            Some(
                status_codes
                    .split(",")
                    .flat_map(|s| s.trim().parse::<u16>().ok())
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };
        let hash_value = get_hash_key(value);

        Ok(Self {
            path,
            replacer: SubFilterReplacer {
                filters,
                buffer: BytesMut::new(),
                // Each response gets a fresh clone of this replacer
                // (`ctx.add_modify_body_handler(.., self.replacer.clone())`),
                // so the passthrough latch never leaks across requests.
                passthrough: false,
                // Decided per-response in `handle_response`; the clone the
                // handler registry takes inherits it.
                encoding: ContentEncoding::Plain,
            },
            hash_value,
            status_codes,
        })
    }
}

impl SubFilter {
    /// Creates a new SubFilter instance from plugin configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<Self>` - Configured SubFilter instance or error if configuration is invalid
    pub fn new(params: &PluginConf) -> Result<Self> {
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for SubFilter {
    /// Returns a unique identifier for this plugin instance
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles the response phase of the HTTP request/response lifecycle
    ///
    /// # Arguments
    /// * `session` - HTTP session information
    /// * `ctx` - Plugin state context
    /// * `upstream_response` - Response headers from upstream server
    ///
    /// # Returns
    /// * `pingora::Result<()>` - Success or error status
    async fn handle_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        if let Some(status_codes) = &self.status_codes
            && !status_codes.contains(&upstream_response.status.as_u16())
        {
            return Ok(ResponsePluginResult::Unchanged);
        }
        // default is matched
        let mut is_matched = true;
        // If request path matches, modify the response
        if let Some(regex) = &self.path {
            is_matched = regex.is_match(session.req_header().uri.path());
        }

        if is_matched {
            // Encodings the plugin cannot round-trip (`br`, `zstd`,
            // multi-value) must pass through untouched: rewriting the
            // headers would leave a response the client can still decode
            // but whose bytes were never substituted anyway.
            let Some(encoding) =
                classify_content_encoding(&upstream_response.headers)
            else {
                debug!(
                    target: PLUGIN_ID,
                    "unsupported content encoding, passing through"
                );
                return Ok(ResponsePluginResult::Unchanged);
            };
            // Oversized responses are passed through: the replacer buffers
            // the whole body and copies it once per rule.
            if let Some(value) =
                upstream_response.headers.get(http::header::CONTENT_LENGTH)
                && let Ok(size) =
                    value.to_str().unwrap_or_default().parse::<usize>()
                && size > MAX_SUB_FILTER_BYTES
            {
                debug!(
                    target: PLUGIN_ID,
                    size, "response exceeds the sub-filter cap; passing through"
                );
                return Ok(ResponsePluginResult::Unchanged);
            }
            make_headers_consistent(upstream_response);
            // Switch to chunked transfer encoding: the final length is only
            // known once the (re)compression finishes.
            let _ = upstream_response.insert_header(
                http::header::TRANSFER_ENCODING,
                HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
            );
            // Set up the response body modifier
            ctx.add_modify_body_handler(
                PLUGIN_ID,
                Box::new(SubFilterReplacer {
                    encoding,
                    ..self.replacer.clone()
                }),
            );
            return Ok(ResponsePluginResult::Modified);
        }
        Ok(ResponsePluginResult::Unchanged)
    }
    fn handle_response_body(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        if let Some(modifier) = ctx.get_modify_body_handler(PLUGIN_ID) {
            modifier.handle(session, body, end_of_stream)?;
            let result = if end_of_stream {
                ResponseBodyPluginResult::FullyReplaced
            } else {
                ResponseBodyPluginResult::PartialReplaced
            };
            Ok(result)
        } else {
            Ok(ResponseBodyPluginResult::Unchanged)
        }
    }
}

register_plugin!("sub_filter", SubFilter);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// A response without `Content-Encoding` is plain, not "unsupported":
    /// treating the missing header as `None` skipped the filter for every
    /// uncompressed response (2026-10-21 regression found in E2E).
    #[test]
    fn missing_content_encoding_is_plain() {
        assert_eq!(
            Some(ContentEncoding::Plain),
            classify_content_encoding(&http::HeaderMap::new())
        );
    }

    #[test]
    fn test_parse_subs_filter() {
        let rule = "subs_filter 'http://pingap.io' 'https://pingap.io/api' ig";
        let params = parse_subs_filter(rule).unwrap();
        // assert_eq!(params.directive, "subs_filter");
        assert_eq!(params.regex_pattern.unwrap().as_str(), "http://pingap.io");
        assert_eq!(params.pattern, b"");
        assert_eq!(params.replacement, b"https://pingap.io/api");
        assert_eq!(params.flags, vec!['i', 'g']);

        let rule = "sub_filter 'http://pingap.io' 'https://pingap.io/api' ig";
        let params = parse_subs_filter(rule).unwrap();
        assert_eq!(params.regex_pattern.is_none(), true);
        assert_eq!(params.pattern, b"http://pingap.io");
        assert_eq!(params.replacement, b"https://pingap.io/api");
        assert_eq!(params.flags, vec!['i', 'g']);
    }

    /// Builds a replacer from one rule string.
    fn new_replacer(rule: &str) -> SubFilterReplacer {
        SubFilterReplacer {
            filters: vec![parse_subs_filter(rule).expect("the rule parses")],
            buffer: BytesMut::new(),
            passthrough: false,
            encoding: ContentEncoding::Plain,
        }
    }

    /// `handle` takes a `Session` only because the `ModifyResponseBody` trait
    /// does; the replacer never reads it, so an empty mock connection is enough.
    fn test_session() -> Session {
        Session::new_h1(Box::new(tokio_test::io::Builder::new().build()))
    }

    /// The replacer emits only at end of stream: intermediate chunks are
    /// buffered and the substituted body replaces the (now empty) chunk.
    #[test]
    fn test_sub_filter_replacer() {
        let session = test_session();

        // Literal, global.
        let mut replacer = new_replacer("sub_filter 'Pingap' 'PingWAF' g");
        let mut body = Some(Bytes::from_static(b"Pingap and Pingap"));
        replacer.handle(&session, &mut body, false).unwrap();
        assert_eq!(
            body,
            Some(Bytes::new()),
            "chunks are buffered, not emitted"
        );
        replacer.handle(&session, &mut body, true).unwrap();
        assert_eq!(body, Some(Bytes::from_static(b"PingWAF and PingWAF")));

        // Literal, first occurrence only.
        let mut replacer = new_replacer("sub_filter 'Pingap' 'PingWAF'");
        let mut body = Some(Bytes::from_static(b"Pingap and Pingap"));
        replacer.handle(&session, &mut body, true).unwrap();
        assert_eq!(body, Some(Bytes::from_static(b"PingWAF and Pingap")));

        // Regex, case-insensitive, global.
        let mut replacer = new_replacer("subs_filter 'pingap' 'PingWAF' ig");
        let mut body = Some(Bytes::from_static(b"Pingap pingap Pingap"));
        replacer.handle(&session, &mut body, true).unwrap();
        assert_eq!(body, Some(Bytes::from_static(b"PingWAF PingWAF PingWAF")));
    }

    /// M4: a chunked response carries no `Content-Length`, so the header-side
    /// check in `handle_response` never sees a size. The bound has to be
    /// enforced while the chunks arrive: once the buffer crosses
    /// `MAX_SUB_FILTER_BYTES` the already-buffered bytes are handed back and
    /// every later chunk is forwarded untouched — the buffer never keeps
    /// growing and no byte is dropped.
    #[test]
    fn test_replacer_passes_through_a_body_over_the_cap() {
        let session = test_session();
        let mut replacer = new_replacer("sub_filter 'Pingap' 'PingWAF' g");
        let chunk = Bytes::from(vec![b'a'; 1024 * 1024]);

        // Exactly the cap still buffers: the check is `>`, and one byte less
        // must not silently disable the replacement.
        for index in 0..8 {
            let mut body = Some(chunk.clone());
            replacer.handle(&session, &mut body, false).unwrap();
            assert_eq!(body, Some(Bytes::new()), "chunk {index} is buffered");
        }
        assert!(!replacer.passthrough, "8 MiB is not over the cap");
        assert_eq!(replacer.buffer.len(), MAX_SUB_FILTER_BYTES);

        // The ninth megabyte crosses it: the buffered 9 MiB go out at once and
        // the replacer switches to passthrough.
        let mut body = Some(chunk.clone());
        replacer.handle(&session, &mut body, false).unwrap();
        assert!(replacer.passthrough, "the cap must trip while streaming");
        assert!(replacer.buffer.is_empty(), "the buffer is handed back");
        let forwarded = body.expect("the buffered bytes are written out");
        assert_eq!(forwarded.len(), 9 * 1024 * 1024);

        // Everything after that is forwarded byte-for-byte, end of stream
        // included: no replacement is attempted any more.
        let mut body = Some(Bytes::from_static(b"Pingap"));
        replacer.handle(&session, &mut body, false).unwrap();
        assert_eq!(body, Some(Bytes::from_static(b"Pingap")));
        let mut body = Some(Bytes::from_static(b"Pingap"));
        replacer.handle(&session, &mut body, true).unwrap();
        assert_eq!(
            body,
            Some(Bytes::from_static(b"Pingap")),
            "the tail is forwarded, never rewritten"
        );
    }

    /// Compresses `data` with gzip (or zlib-wrapped deflate) for tests.
    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut decoder = GzDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).unwrap();
        out
    }

    fn zlib_decode(data: &[u8]) -> Vec<u8> {
        let mut decoder = ZlibDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).unwrap();
        out
    }

    /// Feeds the whole `raw` body through the replacer at end of stream.
    fn run(replacer: &mut SubFilterReplacer, raw: &[u8]) -> Bytes {
        let session = test_session();
        let mut body = Some(Bytes::copy_from_slice(raw));
        replacer
            .handle(&session, &mut body, true)
            .expect("the body is handled");
        body.expect("the body is emitted")
    }

    /// gzip body: decompressed, replaced, recompressed as gzip.
    #[test]
    fn gzip_bodies_are_decompressed_replaced_and_recompressed() {
        let mut replacer = new_replacer("sub_filter 'Google' 'PingWAF' g");
        replacer.encoding = ContentEncoding::Gzip;
        let raw = gzip(b"Hello Google");
        let out = run(&mut replacer, &raw);
        assert_ne!(out, raw, "the body is rewritten, not passed through");
        assert_eq!(gunzip(&out), b"Hello PingWAF");
    }

    /// No rule hit: the origin compressed bytes go out byte-identical, so
    /// ETags and digests of the origin body stay valid.
    #[test]
    fn gzip_bodies_without_matches_pass_through_byte_identical() {
        let mut replacer = new_replacer("sub_filter 'Nomatch' 'PingWAF' g");
        replacer.encoding = ContentEncoding::Gzip;
        let raw = gzip(b"Hello Google");
        assert_eq!(run(&mut replacer, &raw), raw);
    }

    /// A body that claims gzip but is not decodable must reach the client
    /// exactly as it arrived, `Content-Encoding` still claiming gzip.
    #[test]
    fn corrupt_gzip_is_passed_through_with_its_encoding() {
        let mut replacer = new_replacer("sub_filter 'Google' 'PingWAF' g");
        replacer.encoding = ContentEncoding::Gzip;
        let raw = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
        assert_eq!(run(&mut replacer, &raw), raw);
    }

    /// `deflate` (zlib wrapper) bodies round-trip the same way as gzip.
    #[test]
    fn deflate_bodies_are_replaced() {
        let mut replacer = new_replacer("sub_filter 'Google' 'PingWAF' g");
        replacer.encoding = ContentEncoding::Deflate;
        let raw = deflate(b"Hello Google");
        let out = run(&mut replacer, &raw);
        assert_eq!(zlib_decode(&out), b"Hello PingWAF");
    }

    /// Raw deflate (no zlib header) is tried as the fallback for `deflate`.
    #[test]
    fn raw_deflate_bodies_are_replaced() {
        let mut encoder = flate2::read::DeflateEncoder::new(
            &b"Hello Google"[..],
            Compression::default(),
        );
        let mut raw = Vec::new();
        encoder.read_to_end(&mut raw).unwrap();
        let mut replacer = new_replacer("sub_filter 'Google' 'PingWAF' g");
        replacer.encoding = ContentEncoding::Deflate;
        assert_eq!(zlib_decode(&run(&mut replacer, &raw)), b"Hello PingWAF");
    }

    /// A response header with the given `Content-Encoding`.
    fn header_with_encoding(encoding: &str) -> ResponseHeader {
        let mut header =
            ResponseHeader::build(200, None).expect("the header builds");
        header
            .insert_header("Content-Encoding", encoding)
            .expect("the header is valid");
        header
    }

    /// Runs `handle_response` synchronously on a stub response.
    fn run_handle_response(
        plugin: &SubFilter,
        header: &mut ResponseHeader,
    ) -> ResponsePluginResult {
        let mut session = test_session();
        let mut ctx = Ctx::new();
        tokio::runtime::Runtime::new()
            .expect("the test runtime starts")
            .block_on(plugin.handle_response(&mut session, &mut ctx, header))
            .expect("the response is handled")
    }

    /// Encodings the plugin cannot round-trip must leave the response —
    /// headers included — completely alone.
    #[test]
    fn brotli_bodies_are_not_touched() {
        let plugin =
            SubFilter::new(&PluginConf::default()).expect("the conf parses");
        let mut header = header_with_encoding("br");
        let result = run_handle_response(&plugin, &mut header);
        assert_eq!(result, ResponsePluginResult::Unchanged);
        assert_eq!(
            header
                .headers
                .get(http::header::CONTENT_LENGTH)
                .map(|v| v.to_str().unwrap()),
            None,
            "no header must be rewritten for an unsupported encoding"
        );
    }

    /// A multi-value encoding (`gzip, br`) is equally unsupported.
    #[test]
    fn multi_value_encoding_is_not_touched() {
        let plugin =
            SubFilter::new(&PluginConf::default()).expect("the conf parses");
        let mut header = header_with_encoding("gzip, br");
        let result = run_handle_response(&plugin, &mut header);
        assert_eq!(result, ResponsePluginResult::Unchanged);
    }

    /// A compressed body whose plaintext would blow the cap falls back to
    /// the original compressed bytes: never a truncated response.
    #[test]
    fn decompressed_size_cap_falls_back_to_the_compressed_bytes() {
        let plaintext = vec![0u8; 9 * 1024 * 1024];
        let raw = gzip(&plaintext);
        assert!(
            raw.len() <= MAX_SUB_FILTER_BYTES,
            "the compressed bytes must fit the cap for the test to isolate \
             the decompressed check"
        );
        let mut replacer = new_replacer("sub_filter 'Nomatch' 'PingWAF' g");
        replacer.encoding = ContentEncoding::Gzip;
        assert_eq!(run(&mut replacer, &raw), raw);
    }

    /// After a rewrite the header set must be consistent: weakened ETag,
    /// no stale digests, a `Vary: Accept-Encoding`, the encoding preserved
    /// and the (now stale) length removed.
    #[test]
    fn headers_are_made_consistent_after_a_rewrite() {
        let mut header = header_with_encoding("gzip");
        header
            .insert_header("Content-Length", "123")
            .expect("the header is valid");
        header
            .insert_header("ETag", "\"abc123\"")
            .expect("the header is valid");
        header
            .insert_header("Content-MD5", "ZGVhZGJlZg==")
            .expect("the header is valid");
        make_headers_consistent(&mut header);
        assert!(
            header.headers.get(http::header::CONTENT_LENGTH).is_none(),
            "the stale length is removed"
        );
        assert_eq!(
            header
                .headers
                .get(http::header::ETAG)
                .and_then(|v| v.to_str().ok()),
            Some("W/\"abc123\""),
            "the entity tag is weakened"
        );
        assert!(header.headers.get("Content-MD5").is_none());
        assert!(
            header
                .headers
                .get(http::header::VARY)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.split(',').any(|part| part
                    .trim()
                    .eq_ignore_ascii_case("accept-encoding"))),
            "Vary gains Accept-Encoding"
        );
        assert_eq!(
            header
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip"),
            "the encoding is preserved: the body is recompressed"
        );
    }

    /// An already-weak ETag is not double-weakened.
    #[test]
    fn weak_etags_are_left_alone() {
        let mut header =
            ResponseHeader::build(200, None).expect("the header builds");
        header
            .insert_header("ETag", "W/\"abc\"")
            .expect("the header is valid");
        header
            .insert_header("Vary", "Accept-Encoding, User-Agent")
            .expect("the header is valid");
        make_headers_consistent(&mut header);
        assert_eq!(
            header
                .headers
                .get(http::header::ETAG)
                .and_then(|v| v.to_str().ok()),
            Some("W/\"abc\"")
        );
        assert_eq!(
            header
                .headers
                .get(http::header::VARY)
                .and_then(|v| v.to_str().ok()),
            Some("Accept-Encoding, User-Agent"),
            "an existing Accept-Encoding in Vary is not duplicated"
        );
    }
}
