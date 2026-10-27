//! URL decoding helpers.
//!
//! `urlencoding::decode` handles a single pass; WAF input is frequently
//! double- or triple-encoded to slip past naive filters, so we keep decoding
//! until the value stops changing (bounded by `max_layers`).

use std::borrow::Cow;

/// Percent-decode into raw bytes (`None` when there is nothing to decode).
fn percent_to_bytes(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut any = false;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
        {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'%'));
            i += 3;
            any = true;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    any.then_some(out)
}

/// Bytes to text, restoring overlong UTF-8 sequences first: `C0 AF` is an
/// overlong encoding of `/`, `C0 BC` of `<` — a classic filter-evasion
/// encoding that exploits decoders which reject or mangle invalid UTF-8.
/// Surviving invalid bytes map through Latin-1 so the payload *after* the
/// bad byte (…`script>` behind `%C0%BC`) still becomes scannable text.
///
/// Visible to the whole `normalize` module: the request-body path reuses it
/// so a body that is merely not valid UTF-8 is inspected rather than
/// skipped (see `normalize::decode_body`).
pub(super) fn bytes_to_scannable(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    // Map directly into the output String. The old shape built a Vec<u8> of
    // every byte and then a second String (up to 3× the input peak) for a
    // path that is only reached by invalid/overlong UTF-8 bodies.
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if (0xC0..=0xC1).contains(&b)
            && i + 1 < bytes.len()
            && (bytes[i + 1] & 0xC0) == 0x80
        {
            out.push(char::from(((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F)));
            i += 2;
        } else {
            out.push(char::from(b));
            i += 1;
        }
    }
    out
}

/// Apply percent-decoding repeatedly until the string is stable or the layer
/// budget is exhausted. Returns the input unchanged when there is nothing to
/// decode.
///
/// Unlike `urlencoding::decode`, decoding is byte-wise: an invalid UTF-8
/// sequence (overlong-UTF-8 obfuscation such as `%C0%BCscript%3E`) does not
/// abort the pass — it is restored through [`bytes_to_scannable`] so the
/// payload behind it stays visible to the detectors.
pub fn multi_decode<'a>(input: &'a str, max_layers: usize) -> Cow<'a, str> {
    if max_layers == 0 || !input.contains('%') {
        return Cow::Borrowed(input);
    }
    let mut current = Cow::Borrowed(input);
    for _ in 0..max_layers {
        let Some(bytes) = percent_to_bytes(&current) else {
            break;
        };
        let decoded = bytes_to_scannable(&bytes);
        if decoded == current {
            break;
        }
        current = Cow::Owned(decoded);
        if !current.contains('%') {
            break;
        }
    }
    current
}

/// Lower-case every percent-encoded triplet in `input` so that `%2E` and `%2e`
/// compare equal in subsequent signature matching. Does NOT decode anything.
pub fn normalize_percent_case(input: &str) -> String {
    if !input.contains('%') {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'%' && i + 2 < bytes.len() {
            let hi = bytes[i + 1];
            let lo = bytes[i + 2];
            if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() {
                out.push('%');
                out.push((hi as char).to_ascii_lowercase());
                out.push((lo as char).to_ascii_lowercase());
                i += 3;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_decode() {
        assert_eq!(multi_decode("hello%20world", 3), "hello world");
    }

    #[test]
    fn double_decode() {
        assert_eq!(multi_decode("%252e%252e%252f", 3), "../");
    }

    #[test]
    fn triple_decode() {
        assert_eq!(multi_decode("%25252e%25252e%25252f", 4), "../");
    }

    #[test]
    fn stops_at_layer_budget() {
        // Two passes needed; with budget 1 we should still see one decoded form.
        assert_eq!(multi_decode("%252e", 1), "%2e");
    }

    #[test]
    fn no_percent_is_noop() {
        assert_eq!(multi_decode("plain text", 3), "plain text");
    }

    #[test]
    fn lowercases_percent_triplets() {
        assert_eq!(normalize_percent_case("%2E%2e%2F"), "%2e%2e%2f");
    }
}
