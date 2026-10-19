//! Write-path validators shared by every create/update handler.
//!
//! The data plane is deliberately forgiving: a rule whose expression fails to
//! parse is dropped, a certificate whose PEM does not load takes the site's
//! HTTPS down, and an mTLS trust anchor that is not a PEM chain leaves every
//! client unauthenticated. Forgiving there means silent, so the API has to be
//! strict here — and strict exactly once. Keeping these checks in one place is
//! what stops an update path from drifting away from its create counterpart
//! (2026-10-18/19 audit: `update_rule`, `rate_limiting` create+update,
//! `update_certificate` and the TLS posture all accepted what create rejected).

use crate::api::error::ApiError;

/// Upper bound on a rule expression (bytes).
///
/// Expressions are compiled per site on the data plane and the parser is
/// recursive descent, so an unbounded input is both a parse-time cost and a
/// memory lever. 8 KiB is far above anything a hand-written rule needs.
pub(crate) const MAX_EXPRESSION_LEN: usize = 8 * 1024;

/// Upper bound on a PEM bundle handed to the API (bytes, 1 MiB).
///
/// A certificate chain plus key is a few KiB; the cap keeps a pathological
/// upload from turning the X.509 parser into a DoS vector.
pub(crate) const MAX_PEM_LEN: usize = 1024 * 1024;

/// Validates a rule expression with the same parser the data plane uses.
///
/// Rejects an empty expression, anything over [`MAX_EXPRESSION_LEN`] and any
/// expression that does not parse. The data plane drops a rule whose
/// expression fails to parse, so without this check a rule looks enabled in
/// the console while enforcing nothing.
pub(crate) fn validate_expression(expression: &str) -> Result<(), ApiError> {
    if expression.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "expression must not be empty".to_string(),
        ));
    }
    if expression.len() > MAX_EXPRESSION_LEN {
        return Err(ApiError::BadRequest(format!(
            "expression must be at most {MAX_EXPRESSION_LEN} bytes"
        )));
    }
    pingwaf_waf::rules::expression::parse_expression(expression).map_err(
        |err| ApiError::BadRequest(format!("expression is not valid: {err}")),
    )?;
    Ok(())
}

/// Validates a rate-limit expression, where an empty value is meaningful.
///
/// Unlike a WAF rule, a rate limit without a condition applies to every
/// request for the site (the data plane's `pingap-plugin` maps a blank
/// expression to "no filter"), so blank stays legal; anything present must
/// still parse and respect the same length ceiling.
pub(crate) fn validate_optional_expression(
    expression: &str,
) -> Result<(), ApiError> {
    if expression.trim().is_empty() {
        return Ok(());
    }
    validate_expression(expression)
}

/// Validates one PEM bundle (a leaf/chain or a CA anchor).
///
/// Every certificate in the bundle is parsed, not just the leaf: an agent
/// verifies against the whole anchor, so a broken second block fails every
/// handshake while the first one still looks fine here.
pub(crate) fn validate_pem_bundle(
    cert_pem: &str,
    what: &str,
) -> Result<(), ApiError> {
    if cert_pem.trim().is_empty() {
        return Err(ApiError::BadRequest(format!("{what} must not be empty")));
    }
    if cert_pem.len() > MAX_PEM_LEN {
        return Err(ApiError::BadRequest(format!(
            "{what} must be at most {MAX_PEM_LEN} bytes"
        )));
    }
    // The blocks are counted and parsed by hand rather than through
    // `parse_chain`: that helper stops at the first block it cannot read, so a
    // bundle holding a valid leaf followed by garbage reads as "one
    // certificate, fine". An anchor the agent cannot fully load would then be
    // stored and fail every handshake.
    let blocks = pem_blocks(cert_pem)?;
    if blocks.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{what} contains no certificate"
        )));
    }
    // `parse_chain` is still run so the acceptance criterion is the reader the
    // edge actually uses, and its result must account for every block.
    let chain = crate::pki::tls::parse_chain(cert_pem).map_err(|err| {
        ApiError::BadRequest(format!("{what} is not valid: {err}"))
    })?;
    if chain.len() != blocks.len() {
        return Err(ApiError::BadRequest(format!(
            "{what} contains {} PEM block(s) but only {} certificate(s) could be parsed",
            blocks.len(),
            chain.len()
        )));
    }
    describe_bundle(&blocks, what)?;
    Ok(())
}

/// Runs [`crate::pki::tls::describe`] over every PEM block in a bundle.
///
/// The edge re-verifies client certificates against the whole anchor, so each
/// block has to be a well-formed X.509 certificate on its own.
fn describe_bundle(blocks: &[String], what: &str) -> Result<(), ApiError> {
    for block in blocks {
        crate::pki::tls::describe(block).map_err(|err| {
            ApiError::BadRequest(format!("{what} is not valid: {err}"))
        })?;
    }
    Ok(())
}

/// Splits a concatenated PEM bundle into its individual certificate blocks.
///
/// Deliberately strict: unterminated blocks are an error rather than being
/// skipped, because both readers below happily ignore trailing junk and would
/// otherwise turn a truncated upload into a silently weaker anchor.
fn pem_blocks(cert_pem: &str) -> Result<Vec<String>, ApiError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut blocks = Vec::new();
    let mut current = String::new();
    let mut inside = false;
    for line in cert_pem.lines() {
        let line = line.trim();
        if line == BEGIN {
            current.clear();
            inside = true;
            current.push_str(BEGIN);
            current.push('\n');
            continue;
        }
        if line == END {
            if !inside {
                return Err(ApiError::BadRequest(
                    "the PEM bundle has a certificate footer without a header"
                        .to_string(),
                ));
            }
            current.push_str(END);
            current.push('\n');
            blocks.push(std::mem::take(&mut current));
            inside = false;
            continue;
        }
        if inside {
            current.push_str(line);
            current.push('\n');
        }
    }
    if inside {
        return Err(ApiError::BadRequest(
            "the PEM bundle ends inside a certificate block".to_string(),
        ));
    }
    Ok(blocks)
}

/// Validates that `cert_pem` is a usable certificate and, when a key is
/// supplied, that the two belong together.
///
/// `certify` gates the key check: an update that replaces only one half of the
/// stored pair validates against the other half, so a mismatched pair can
/// never be assembled one request at a time.
pub(crate) fn validate_pem_pair(
    cert_pem: &str,
    key_pem: Option<&str>,
) -> Result<(), ApiError> {
    validate_pem_bundle(cert_pem, "cert_pem")?;
    let Some(key_pem) = key_pem.filter(|pem| !pem.trim().is_empty()) else {
        return Ok(());
    };
    if key_pem.len() > MAX_PEM_LEN {
        return Err(ApiError::BadRequest(format!(
            "key_pem must be at most {MAX_PEM_LEN} bytes"
        )));
    }
    crate::pki::tls::certified_key(cert_pem, key_pem).map_err(|err| {
        ApiError::BadRequest(format!(
            "cert_pem and key_pem cannot be used together: {err}"
        ))
    })?;
    Ok(())
}

/// Validates an uploaded certificate/key pair, both halves required.
pub(crate) fn validate_certificate_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(), ApiError> {
    validate_pem_bundle(cert_pem, "cert_pem")?;
    if key_pem.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "key_pem must not be empty".to_string(),
        ));
    }
    if key_pem.len() > MAX_PEM_LEN {
        return Err(ApiError::BadRequest(format!(
            "key_pem must be at most {MAX_PEM_LEN} bytes"
        )));
    }
    crate::pki::tls::certified_key(cert_pem, key_pem).map_err(|err| {
        ApiError::BadRequest(format!(
            "cert_pem and key_pem cannot be used together: {err}"
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(cn: &str) -> crate::pki::mtls::KeyMaterial {
        crate::pki::tls::generate_self_signed(
            cn,
            &["localhost".to_string()],
            30,
        )
        .expect("the test certificate must generate")
    }

    #[test]
    fn expressions_must_parse() {
        assert!(validate_expression(r#"http.request.method eq "POST""#).is_ok());
        // `==` is not part of the grammar; the data plane would drop the rule.
        assert!(validate_expression("ip.src == 1.2.3.4").is_err());
        assert!(validate_expression("").is_err());
        assert!(validate_expression("   ").is_err());
        assert!(validate_expression("(http.host eq \"x\"").is_err());
    }

    #[test]
    fn expressions_are_capped_at_eight_kibibytes() {
        let base = r#"http.host eq "a""#;
        let mut padded = String::with_capacity(MAX_EXPRESSION_LEN);
        padded.push_str(base);
        while padded.len() <= MAX_EXPRESSION_LEN {
            padded.push(' ');
        }
        assert!(validate_expression(&padded)
            .unwrap_err()
            .to_string()
            .contains("at most 8192 bytes"));
        // The cap is on bytes, so a multi-byte expression is measured in
        // bytes, not chars.
        let wide = "http.host eq \"".to_string()
            + &"é".repeat(MAX_EXPRESSION_LEN)
            + "\"";
        assert!(validate_expression(&wide).is_err());
        assert!(validate_expression(base).is_ok());
    }

    #[test]
    fn optional_expressions_allow_blank_but_not_garbage() {
        assert!(validate_optional_expression("").is_ok());
        assert!(validate_optional_expression("   ").is_ok());
        assert!(validate_optional_expression(r#"http.host eq "a""#).is_ok());
        assert!(validate_optional_expression("http.host ==").is_err());
        assert!(validate_optional_expression(
            &"x".repeat(MAX_EXPRESSION_LEN + 1)
        )
        .is_err());
    }

    #[test]
    fn pem_pairs_must_be_usable_together() {
        let first = self_signed("one");
        let second = self_signed("two");
        let first_key = first.key_pem.as_deref().unwrap();
        let second_key = second.key_pem.as_deref().unwrap();

        validate_certificate_and_key(&first.cert_pem, first_key)
            .expect("a matching pair must validate");
        assert!(
            validate_certificate_and_key(&first.cert_pem, second_key).is_err(),
            "a certificate and a key from another pair must be rejected"
        );
        assert!(validate_certificate_and_key("not a pem", first_key).is_err());
        assert!(validate_certificate_and_key(&first.cert_pem, "").is_err());
        // A private key is not a certificate.
        assert!(validate_certificate_and_key(first_key, first_key).is_err());
    }

    #[test]
    fn pem_pair_checks_the_certificate_even_without_a_key() {
        let material = self_signed("one");
        validate_pem_pair(&material.cert_pem, None)
            .expect("a lone certificate is valid on its own");
        assert!(validate_pem_pair("garbage", None).is_err());
        assert!(validate_pem_pair("", None).is_err());
        assert!(
            validate_pem_pair(&material.cert_pem, Some("not a key")).is_err()
        );
    }

    #[test]
    fn pem_bundles_are_checked_block_by_block() {
        let first = self_signed("one");
        let second = self_signed("two");
        let bundle = format!("{}\n{}", first.cert_pem, second.cert_pem);
        validate_pem_bundle(&bundle, "mtls_client_ca")
            .expect("a two-certificate bundle must validate");
        // A valid leaf followed by a truncated block is the case rustls reads
        // as "one certificate, fine"; the block count catches it.
        let truncated = format!(
            "{}\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            first.cert_pem
        );
        let err = validate_pem_bundle(&truncated, "mtls_client_ca")
            .expect_err("a truncated second block must be rejected");
        assert!(
            err.to_string().contains("PEM block")
                || err.to_string().contains("not valid"),
            "a truncated block must be rejected with a PEM error: {err}"
        );
        assert_eq!(
            pem_blocks(&bundle).expect("the bundle must split").len(),
            2
        );
        // Trailing text outside a block is ignored by the edge and by us: it
        // cannot weaken the anchor, so rejecting it would only refuse uploads
        // with a stray line in them.
        let with_note =
            format!("{}\n# exported from the CA console", first.cert_pem);
        validate_pem_bundle(&with_note, "mtls_client_ca")
            .expect("trailing non-PEM text must not invalidate the anchor");
        assert!(validate_pem_bundle("", "mtls_client_ca").is_err());
        assert!(validate_pem_bundle(
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
            "mtls_client_ca"
        )
        .is_err());
    }
}
