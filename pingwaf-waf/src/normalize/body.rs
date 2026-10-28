//! Request-body decoding for the detectors.
//!
//! Two evasions are closed here:
//!
//! * **Non-UTF-8 bodies.** The body used to be skipped entirely unless it
//!   was valid UTF-8 — `if let Ok(text) = str::from_utf8(body) { … }` with
//!   no `else`. Appending a single `0xFF` byte to an otherwise blatant
//!   payload therefore removed it from the scan surface: no form parsing,
//!   no JSON unpacking, no decoded value at all. Binary bodies are exactly
//!   what a file upload or a protobuf endpoint looks like, so the fix is to
//!   always produce scannable text rather than to always reject.
//! * **Compressed bodies.** `Content-Encoding: gzip` (or `deflate`) was
//!   never undone on the request path — the response compression plugin has
//!   `flate2`, the inspection side did not — so the detectors saw the
//!   deflate stream, which is binary and took the same early exit. `gzip` is
//!   the encoding real clients use on request bodies.
//!
//! Decompression is bounded. A request body is attacker-controlled and
//! `gzip` expands at roughly 1000:1, so the decoder reads through a
//! `Read::take` cap: a decompression bomb stops at [`MAX_DECOMPRESSED_BODY`]
//! instead of expanding, and nothing here allocates at a size the attacker
//! chose. The truncation is lossless for detection purposes — a payload
//! that only appears past 1 MiB of decompressed body has already been
//! staged out by the caller's own `max_body_size` cap.

use std::borrow::Cow;
use std::io::Read;

use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};

use crate::normalize::url::bytes_to_scannable;

/// Ceiling on the decompressed body handed to the detectors.
///
/// The proxy stages at most a few tens of KiB before the engine is reached
/// (`max_body_size`, 64 KiB by default) and truncates at that cap itself, so
/// a generous 1 MiB never lets a normal request grow while still leaving
/// room for a caller that raises the cap. What matters is that the size is
/// *ours* and not the attacker's.
pub const MAX_DECOMPRESSED_BODY: usize = 1024 * 1024;

/// What fraction of the request body actually reached the detectors.
///
/// A body that was not inspected must never look like a clean pass: the
/// engine copies this into the verdict details, and the data plane turns it
/// into a security event. Keeping it as a first-class value is what stops a
/// new budget from silently becoming another blind spot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyInspection {
    /// Every byte was handed to the engine.
    Inspected,
    /// Only a prefix was inspected; `reason` names the budget that ran out.
    Prefix {
        checked: usize,
        reason: PrefixReason,
    },
    /// Nothing meaningful was inspected (unsupported/corrupt encoding).
    Uninspected { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixReason {
    /// [`MAX_DECOMPRESSED_BODY`] was reached while undoing
    /// `Content-Encoding`.
    DecompressedCap,
}

impl BodyInspection {
    /// A stable, log-friendly marker, or `None` when the body was fully
    /// inspected.
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::Inspected => None,
            Self::Prefix { checked, reason } => Some(format!(
                "body=prefix(checked={checked}, reason={reason:?})"
            )),
            Self::Uninspected { reason } => {
                Some(format!("body=uninspected({reason})"))
            },
        }
    }
}

/// The body text plus how much of the body it represents.
pub struct DecodedBody<'a> {
    pub text: Cow<'a, str>,
    pub inspection: BodyInspection,
}

/// Undo `Content-Encoding`, apply the declared charset, then decode the bytes
/// as text for scanning.
///
/// `headers` is the request's own header list, used for `Content-Encoding`
/// and the `charset` parameter of `Content-Type`. The result is always
/// scannable text when the caller passed a body: a body that is not valid
/// UTF-8 still comes back as bytes mapped through Latin-1, so the detectors
/// see the payload instead of a hole. `inspection` records whether that text
/// covers the whole body or only a prefix. Only the absence of a body yields
/// `None`.
pub fn decode_body<'a>(
    headers: &[(String, String)],
    body: &'a [u8],
) -> Option<DecodedBody<'a>> {
    let content_type = header_value(headers, "content-type");
    // An encoding we cannot undo is a hole, not a body to scan: say so
    // instead of handing the compressed bytes to the detectors. This also
    // covers `br, gzip`, where the old `?` discarded a gzip layer that had
    // already decoded.
    if let Some(unsupported) = unsupported_encoding(headers) {
        return Some(DecodedBody {
            text: text_from_bytes(body),
            inspection: BodyInspection::Uninspected {
                reason: format!("unsupported-content-encoding:{unsupported}"),
            },
        });
    }
    if let Some(decoded) = decompress(headers, body) {
        let truncated = decoded.len() >= MAX_DECOMPRESSED_BODY;
        // Charset applies to the decoded octets, not the wire bytes, so the
        // `Content-Encoding` layer is undone first (RFC 9110).
        let decoded =
            transcode_to_utf8(content_type, &decoded).unwrap_or(decoded);
        // `String::from_utf8` consumes the Vec without copying when the bytes
        // are valid UTF-8, which is the normal JSON/form case.
        let text = match String::from_utf8(decoded) {
            Ok(text) => text,
            Err(err) => bytes_to_scannable(err.as_bytes()),
        };
        let inspection = if truncated {
            BodyInspection::Prefix {
                checked: MAX_DECOMPRESSED_BODY,
                reason: PrefixReason::DecompressedCap,
            }
        } else {
            BodyInspection::Inspected
        };
        return Some(DecodedBody {
            text: Cow::Owned(text),
            inspection,
        });
    }
    if let Some(transcoded) = transcode_to_utf8(content_type, body) {
        let text = match String::from_utf8(transcoded) {
            Ok(text) => text,
            Err(err) => bytes_to_scannable(err.as_bytes()),
        };
        return Some(DecodedBody {
            text: Cow::Owned(text),
            inspection: BodyInspection::Inspected,
        });
    }
    // No `Content-Encoding` and no UTF-16 charset: borrow the wire bytes when
    // they already are UTF-8, which is the overwhelmingly common case and
    // keeps this path allocation-free.
    Some(DecodedBody {
        text: text_from_bytes(body),
        inspection: BodyInspection::Inspected,
    })
}

fn text_from_bytes<'a>(body: &'a [u8]) -> Cow<'a, str> {
    match std::str::from_utf8(body) {
        Ok(text) => Cow::Borrowed(text),
        Err(_) => Cow::Owned(bytes_to_scannable(body)),
    }
}

/// The first `Content-Encoding` layer this build cannot undo, if any.
fn unsupported_encoding(headers: &[(String, String)]) -> Option<&str> {
    let raw = header_value(headers, "content-encoding")?;
    raw.split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .find(|token| {
            !matches!(
                token.to_ascii_lowercase().as_str(),
                "identity" | "gzip" | "x-gzip" | "deflate"
            )
        })
}

/// First value of `name` in `headers`, case-insensitively.
fn header_value<'a>(
    headers: &'a [(String, String)],
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The `charset` parameter of a `Content-Type` value, lower-cased.
fn charset_of(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("charset") {
            return None;
        }
        Some(value.trim().trim_matches('"').to_ascii_lowercase())
    })
}

/// Rewrites a UTF-16 body as UTF-8.
///
/// A UTF-16LE JSON payload is *valid UTF-8* as far as `from_utf8` is
/// concerned (NUL is a legal scalar), so without this the detectors scan
/// `<NUL>s<NUL>c<NUL>…` and every signature misses while the origin still
/// parses the payload. The BOM wins over the header; `utf-16` without a BOM
/// defaults to little-endian, as browsers do. `None` when no conversion is
/// needed.
fn transcode_to_utf8(
    content_type: Option<&str>,
    body: &[u8],
) -> Option<Vec<u8>> {
    let (big_endian, skip) = if body.starts_with(&[0xFE, 0xFF]) {
        (true, 2)
    } else if body.starts_with(&[0xFF, 0xFE]) {
        (false, 2)
    } else {
        let charset = content_type.and_then(charset_of);
        match charset.as_deref() {
            Some("utf-16le") => (false, 0),
            Some("utf-16be") => (true, 0),
            Some("utf-16") => (false, 0),
            _ => return None,
        }
    };

    let payload = &body[skip..];
    let units: Vec<u16> = payload
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            if big_endian {
                u16::from_be_bytes(*pair)
            } else {
                u16::from_le_bytes(*pair)
            }
        })
        .collect();
    Some(String::from_utf16_lossy(&units).into_bytes())
}

/// The encodings whose place in a request body we can undo.
///
/// `identity` needs no work and is dropped from the list rather than
/// rejected: a client that sends `Content-Encoding: identity` is asking for
/// exactly the bytes it sent. `br` / `zstd` request bodies are not something
/// browsers produce, and a decoder for them is not pulled in for that.
fn decode_one(encoding: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    match encoding {
        "gzip" | "x-gzip" => read_bounded(GzDecoder::new(bytes), bytes.len()),
        // `deflate` means zlib-wrapped per RFC 9110, but a long tail of
        // clients (and older proxies) emit a bare deflate stream. Try the
        // spec form first, then the raw form.
        "deflate" => read_bounded(ZlibDecoder::new(bytes), bytes.len())
            .or_else(|| read_bounded(DeflateDecoder::new(bytes), bytes.len())),
        _ => None,
    }
}

/// Read a decoder to the end, stopping at [`MAX_DECOMPRESSED_BODY`].
///
/// The initial capacity is derived from the compressed input, but capped:
/// a 64 KiB gzip body usually expands to far less than a megabyte, and
/// preallocating the full scan ceiling for every request would raise the
/// concurrent RSS more than it saves in reallocation.
///
/// `None` when the stream produced no output and failed. A truncated stream
/// that already yielded bytes is returned as a prefix: the upstream staging
/// cap can cut a gzip body mid-stream, and discarding the decoded prefix
/// would send the compressed bytes to the detectors instead of the payload.
fn read_bounded<R: Read>(reader: R, input_len: usize) -> Option<Vec<u8>> {
    let initial = input_len
        .saturating_mul(4)
        .clamp(4 * 1024, 64 * 1024)
        .min(MAX_DECOMPRESSED_BODY);
    let mut out = Vec::with_capacity(initial);
    match reader
        .take(MAX_DECOMPRESSED_BODY as u64)
        .read_to_end(&mut out)
    {
        Ok(_) => Some(out),
        Err(_) if !out.is_empty() => Some(out),
        Err(_) => None,
    }
}

/// Returns the decompressed body, or `None` when there is nothing to undo.
///
/// Encodings are applied in the order they were applied on the wire, so they
/// are undone in reverse: `Content-Encoding: gzip, deflate` on the wire means
/// gzip-then-deflate was applied, and the body is deflate-decoded first.
/// An unknown encoding anywhere in the chain leaves the whole body alone
/// rather than guessing at the layer order — the caller then scans the
/// encoded bytes, which keeps a body we cannot read from silently becoming a
/// body nobody looks at.
fn decompress(headers: &[(String, String)], body: &[u8]) -> Option<Vec<u8>> {
    let raw = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, value)| value.as_str())?;

    let mut layers: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect();
    // Applied last on the wire, undone first.
    layers.reverse();

    let mut current: Option<Vec<u8>> = None;
    for layer in layers {
        if layer.eq_ignore_ascii_case("identity") {
            continue;
        }
        let input = current.as_deref().unwrap_or(body);
        current = Some(decode_one(&layer.to_ascii_lowercase(), input)?);
    }
    current
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::write::GzEncoder;
    use flate2::Compression;

    use super::*;

    fn header(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.to_string(), value.to_string())]
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    #[test]
    fn plain_utf8_body_is_borrowed() {
        let decoded = decode_body(&[], b"name=value").expect("body is present");
        assert!(matches!(decoded.text, Cow::Borrowed("name=value")));
    }

    #[test]
    fn non_utf8_body_still_yields_scannable_text() {
        let mut body = b"q=1' OR 1=1--".to_vec();
        body.push(0xFF);
        let decoded = decode_body(&[], &body).expect("body is present");
        // The payload survives byte-for-byte; only the trailing byte is
        // remapped. Before the fix this whole body was skipped.
        assert!(decoded.text.starts_with("q=1' OR 1=1--"));
        assert!(decoded.text.chars().any(|c| c == '\u{ff}'));
    }

    #[test]
    fn utf16le_json_is_transcoded_before_scanning() {
        let payload = r#"{"a":"<script>alert(1)</script>"}"#;
        let mut body = Vec::new();
        for unit in payload.encode_utf16() {
            body.extend_from_slice(&unit.to_le_bytes());
        }
        let headers =
            header("content-type", "application/json; charset=utf-16le");
        let decoded = decode_body(&headers, &body).expect("body is present");
        assert!(
            decoded.text.contains("<script>"),
            "detectors must see the payload, got {:?}",
            decoded.text
        );
    }

    #[test]
    fn utf16_bom_is_honoured_without_a_charset() {
        let payload = "q=1' OR 1=1--";
        let mut body = vec![0xFF, 0xFE];
        for unit in payload.encode_utf16() {
            body.extend_from_slice(&unit.to_le_bytes());
        }
        let decoded = decode_body(&[], &body).expect("body is present");
        assert_eq!(decoded.text.as_ref(), payload);
    }

    #[test]
    fn gzip_body_is_decompressed() {
        let body = gzip(b"q=1' OR 1=1--");
        let decoded = decode_body(&header("content-encoding", "gzip"), &body)
            .expect("body is present");
        assert_eq!(decoded.text.as_ref(), "q=1' OR 1=1--");
    }

    #[test]
    fn content_encoding_name_is_case_insensitive() {
        let body = gzip(b"payload");
        let decoded = decode_body(&header("Content-Encoding", "GZIP"), &body)
            .expect("body is present");
        assert_eq!(decoded.text.as_ref(), "payload");
    }

    #[test]
    fn identity_encoding_scans_the_wire_bytes() {
        let decoded =
            decode_body(&header("content-encoding", "identity"), b"raw")
                .expect("body is present");
        assert_eq!(decoded.text.as_ref(), "raw");
    }

    #[test]
    fn unsupported_encoding_is_marked_uninspected() {
        // `br` is not decoded: the body must not vanish, but it must also
        // not be reported as inspected. The wire bytes stay scannable while
        // the inspection status tells the truth.
        let decoded = decode_body(&header("content-encoding", "br"), b"abc")
            .expect("body is present");
        assert_eq!(decoded.text.as_ref(), "abc");
        assert!(matches!(
            decoded.inspection,
            BodyInspection::Uninspected { .. }
        ));
    }

    #[test]
    fn corrupt_gzip_falls_back_to_the_encoded_bytes() {
        let decoded =
            decode_body(&header("content-encoding", "gzip"), b"\x1f\x8b\x00")
                .expect("body is present");
        assert!(!decoded.text.is_empty());
    }

    #[test]
    fn truncated_gzip_keeps_the_decoded_prefix() {
        let body = gzip(b"payload=1' OR 1=1--");
        // Drop the CRC/trailer: flate2 yields the complete plaintext and then
        // reports UnexpectedEof. The prefix must still reach the detectors.
        let truncated = &body[..body.len() - 4];
        let decoded =
            decode_body(&header("content-encoding", "gzip"), truncated)
                .expect("body is present");
        assert_eq!(decoded.text.as_ref(), "payload=1' OR 1=1--");
    }

    #[test]
    fn decompression_stops_at_the_cap() {
        // 2 MiB of zeros compresses to a few KiB; the reader must stop at
        // the cap instead of expanding a bomb.
        let bomb = gzip(&vec![b'A'; 2 * MAX_DECOMPRESSED_BODY]);
        assert!(bomb.len() < 64 * 1024);
        let decoded = decode_body(&header("content-encoding", "gzip"), &bomb)
            .expect("body is present");
        assert_eq!(decoded.text.len(), MAX_DECOMPRESSED_BODY);
        assert!(matches!(
            decoded.inspection,
            BodyInspection::Prefix {
                reason: PrefixReason::DecompressedCap,
                ..
            }
        ));
    }

    #[test]
    fn layered_encodings_are_undone_in_reverse_order() {
        // Applied gzip-then-zlib on the wire, so the header lists them in
        // that order and decoding starts from the last one.
        let inner = gzip(b"SELECT 1");
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&inner).expect("zlib write");
        let outer = encoder.finish().expect("zlib finish");

        let decoded =
            decode_body(&header("content-encoding", "gzip, deflate"), &outer)
                .expect("body is present");
        assert_eq!(decoded.text.as_ref(), "SELECT 1");
    }

    #[test]
    fn unknown_layer_leaves_the_body_alone() {
        let body = gzip(b"payload");
        let decoded =
            decode_body(&header("content-encoding", "gzip, br"), &body)
                .expect("body is present");
        // Not decompressed — the raw gzip bytes are what gets scanned, and
        // the inspection status says so instead of pretending it was clean.
        assert!(!decoded.text.contains("payload"));
        assert!(matches!(
            decoded.inspection,
            BodyInspection::Uninspected { .. }
        ));
    }
}
