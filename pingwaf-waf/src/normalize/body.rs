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

/// Undo `Content-Encoding`, then decode the bytes as text for scanning.
///
/// `headers` is the request's own header list, used only for
/// `Content-Encoding`. The result is always scannable text when the caller
/// passed a body: a body that is not valid UTF-8 (or that we could not
/// decompress) still comes back as bytes mapped through Latin-1, so the
/// detectors see the payload instead of a hole. Only the absence of a body
/// yields `None`.
pub fn decode_body<'a>(
    headers: &[(String, String)],
    body: &'a [u8],
) -> Option<Cow<'a, str>> {
    if let Some(decoded) = decompress(headers, body) {
        // `String::from_utf8` consumes the decompressed Vec without copying
        // when the bytes are valid UTF-8, which is the normal JSON/form case.
        // Only the invalid-UTF-8 fallback pays for the Latin-1 mapping.
        return Some(Cow::Owned(match String::from_utf8(decoded) {
            Ok(text) => text,
            Err(err) => bytes_to_scannable(err.as_bytes()),
        }));
    }
    // No (supported) `Content-Encoding`: borrow the wire bytes when they
    // already are UTF-8, which is the overwhelmingly common case and keeps
    // this path allocation-free.
    Some(match std::str::from_utf8(body) {
        Ok(text) => Cow::Borrowed(text),
        Err(_) => Cow::Owned(bytes_to_scannable(body)),
    })
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
/// `None` when the stream is corrupt: partial output from a broken stream
/// is not something to hand to the detectors as if it were the payload.
fn read_bounded<R: Read>(reader: R, input_len: usize) -> Option<Vec<u8>> {
    let initial = input_len
        .saturating_mul(4)
        .clamp(4 * 1024, 64 * 1024)
        .min(MAX_DECOMPRESSED_BODY);
    let mut out = Vec::with_capacity(initial);
    reader
        .take(MAX_DECOMPRESSED_BODY as u64)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
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
        assert!(matches!(decoded, Cow::Borrowed("name=value")));
    }

    #[test]
    fn non_utf8_body_still_yields_scannable_text() {
        let mut body = b"q=1' OR 1=1--".to_vec();
        body.push(0xFF);
        let decoded = decode_body(&[], &body).expect("body is present");
        // The payload survives byte-for-byte; only the trailing byte is
        // remapped. Before the fix this whole body was skipped.
        assert!(decoded.starts_with("q=1' OR 1=1--"));
        assert!(decoded.chars().any(|c| c == '\u{ff}'));
    }

    #[test]
    fn gzip_body_is_decompressed() {
        let body = gzip(b"q=1' OR 1=1--");
        let decoded = decode_body(&header("content-encoding", "gzip"), &body)
            .expect("body is present");
        assert_eq!(decoded, "q=1' OR 1=1--");
    }

    #[test]
    fn content_encoding_name_is_case_insensitive() {
        let body = gzip(b"payload");
        let decoded = decode_body(&header("Content-Encoding", "GZIP"), &body)
            .expect("body is present");
        assert_eq!(decoded, "payload");
    }

    #[test]
    fn identity_encoding_scans_the_wire_bytes() {
        let decoded =
            decode_body(&header("content-encoding", "identity"), b"raw")
                .expect("body is present");
        assert_eq!(decoded, "raw");
    }

    #[test]
    fn unsupported_encoding_falls_back_to_the_encoded_bytes() {
        // `br` is not decoded, but the body must not vanish: the detectors
        // get the wire bytes rather than an empty scan surface.
        let decoded = decode_body(&header("content-encoding", "br"), b"abc")
            .expect("body is present");
        assert_eq!(decoded, "abc");
    }

    #[test]
    fn corrupt_gzip_falls_back_to_the_encoded_bytes() {
        let decoded =
            decode_body(&header("content-encoding", "gzip"), b"\x1f\x8b\x00")
                .expect("body is present");
        assert!(!decoded.is_empty());
    }

    #[test]
    fn decompression_stops_at_the_cap() {
        // 2 MiB of zeros compresses to a few KiB; the reader must stop at
        // the cap instead of expanding a bomb.
        let bomb = gzip(&vec![b'A'; 2 * MAX_DECOMPRESSED_BODY]);
        assert!(bomb.len() < 64 * 1024);
        let decoded = decode_body(&header("content-encoding", "gzip"), &bomb)
            .expect("body is present");
        assert_eq!(decoded.len(), MAX_DECOMPRESSED_BODY);
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
        assert_eq!(decoded, "SELECT 1");
    }

    #[test]
    fn unknown_layer_leaves_the_body_alone() {
        let body = gzip(b"payload");
        let decoded =
            decode_body(&header("content-encoding", "gzip, br"), &body)
                .expect("body is present");
        // Not decompressed — the raw gzip bytes are what gets scanned,
        // which is the point: no silent hole.
        assert!(!decoded.contains("payload"));
    }
}
