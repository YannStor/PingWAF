//! Certificate generation and inspection for the managed mTLS material.
//!
//! Everything here is pure: PEM in, PEM plus metadata out. Storage, policy and
//! HTTP concerns live in [`crate::api::mtls`].

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// Longest CA lifetime accepted, in days (ten years).
pub const MAX_CA_DAYS: i64 = 3650;
/// Longest client-certificate lifetime accepted, in days (two years).
pub const MAX_CLIENT_CERT_DAYS: i64 = 730;

#[derive(Debug)]
pub enum MtlsError {
    /// The request cannot be satisfied as described.
    Invalid(String),
    /// PEM material could not be parsed or generated.
    Certificate(String),
}

impl std::fmt::Display for MtlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Certificate(message) => {
                write!(f, "{message}")
            },
        }
    }
}

impl std::error::Error for MtlsError {}

/// A freshly signed certificate and its matching private key.
#[derive(Debug)]
pub struct KeyMaterial {
    pub cert_pem: String,
    /// `None` for imported CA certificates (the key stays with the operator).
    pub key_pem: Option<String>,
    pub meta: CertMeta,
}

/// The subset of a certificate the control plane stores and compares on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertMeta {
    pub subject_dn: String,
    pub common_name: Option<String>,
    pub organization: Option<String>,
    /// Lowercase hex, no separators.
    pub serial: String,
    /// Lowercase hex SHA-256 of the DER body, no separators.
    pub fingerprint_sha256: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    pub is_ca: bool,
}

/// Generates a self-signed certificate authority.
pub fn generate_ca(
    common_name: &str,
    organization: Option<&str>,
    validity_days: i64,
) -> Result<KeyMaterial, MtlsError> {
    let days = clamp_days(validity_days, MAX_CA_DAYS, "ca validity")?;
    let mut params = CertificateParams::new(Vec::new())
        .map_err(|err| MtlsError::Invalid(err.to_string()))?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    if let Some(org) = organization {
        dn.push(DnType::OrganizationName, org);
    }
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages =
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // A serial of `None` makes rcgen derive one from the certificate's public
    // key, which is unique per generated key pair.
    let (not_before, not_after) = validity_window(days);
    params.not_before = not_before;
    params.not_after = not_after;

    let key = KeyPair::generate()
        .map_err(|err| MtlsError::Certificate(err.to_string()))?;
    let cert = params
        .self_signed(&key)
        .map_err(|err| MtlsError::Certificate(err.to_string()))?;
    let cert_pem = cert.pem();
    let meta = parse_cert_meta(&cert_pem)?;
    Ok(KeyMaterial {
        cert_pem,
        key_pem: Some(key.serialize_pem()),
        meta,
    })
}

/// Signs a client certificate with the given CA.
///
/// The certificate carries `EKU=clientAuth` and the DN
/// `CN=<common_name>,O=<organization>`; its validity never outlives the CA's.
pub fn issue_client_cert(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    common_name: &str,
    organization: Option<&str>,
    validity_days: i64,
) -> Result<KeyMaterial, MtlsError> {
    let days =
        clamp_days(validity_days, MAX_CLIENT_CERT_DAYS, "cert validity")?;
    let ca_meta = parse_cert_meta(ca_cert_pem)?;
    if !ca_meta.is_ca {
        return Err(MtlsError::Invalid(
            "the selected CA certificate is not a certificate authority"
                .to_string(),
        ));
    }
    let ca_key = KeyPair::from_pem(ca_key_pem).map_err(|err| {
        MtlsError::Invalid(format!("cannot read the CA private key: {err}"))
    })?;
    // rcgen does not check that the issuer key belongs to the issuer
    // certificate, and a mismatch would produce leaflets nothing can verify.
    if Sha256::digest(ca_key.subject_public_key_info())
        != Sha256::digest(ca_public_key_der(ca_cert_pem)?)
    {
        return Err(MtlsError::Invalid(
            "the CA private key does not match the CA certificate".to_string(),
        ));
    }
    let issuer = rcgen::Issuer::from_ca_cert_pem(ca_cert_pem, ca_key)
        .map_err(|err| MtlsError::Certificate(err.to_string()))?;

    let mut params = CertificateParams::new(Vec::new())
        .map_err(|err| MtlsError::Invalid(err.to_string()))?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    if let Some(org) = organization {
        dn.push(DnType::OrganizationName, org);
    }
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let (mut not_before, mut not_after) = validity_window(days);
    if not_after > ca_meta.not_after {
        not_after = ca_meta.not_after;
    }
    // The CA may already be inside its own validity window; a leaf must not
    // outlive it either way.
    if not_before >= not_after {
        not_before = not_after - Duration::hours(1);
    }
    params.not_before = not_before;
    params.not_after = not_after;

    let key = KeyPair::generate()
        .map_err(|err| MtlsError::Certificate(err.to_string()))?;
    let cert = params
        .signed_by(&key, &issuer)
        .map_err(|err| MtlsError::Certificate(err.to_string()))?;
    let cert_pem = cert.pem();
    let meta = parse_cert_meta(&cert_pem)?;
    Ok(KeyMaterial {
        cert_pem,
        key_pem: Some(key.serialize_pem()),
        meta,
    })
}

/// Reads the metadata of a PEM certificate (single certificate, no chain).
pub fn parse_cert_meta(cert_pem: &str) -> Result<CertMeta, MtlsError> {
    let block = parse_pem_block(cert_pem)?;
    let cert = parse_x509(&block)?;
    let common_name = first_attr(cert.subject().iter_common_name());
    let organization = first_attr(cert.subject().iter_organization());
    let subject_dn = cert.subject().to_string();
    let serial = hex::encode(cert.raw_serial());
    // SHA-256 over the whole DER certificate, the fingerprint OpenSSL prints
    // and the one pingora reports as the peer's `cert_digest`; hashing only
    // `tbs_certificate` would never match a client certificate at the edge.
    let fingerprint_sha256 = hex::encode(Sha256::digest(&block.contents));
    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|ext| ext.value.ca);

    Ok(CertMeta {
        subject_dn,
        common_name,
        organization,
        serial,
        fingerprint_sha256,
        not_before: OffsetDateTime::from_unix_timestamp(
            cert.validity().not_before.timestamp(),
        )
        .map_err(|err| MtlsError::Certificate(err.to_string()))?,
        not_after: OffsetDateTime::from_unix_timestamp(
            cert.validity().not_after.timestamp(),
        )
        .map_err(|err| MtlsError::Certificate(err.to_string()))?,
        is_ca,
    })
}

/// Composes the CA bundle agents verify client certificates against.
///
/// Blank entries are dropped so a half-written row cannot weaken the store.
pub fn bundle_pem(certs: &[String]) -> String {
    let mut bundle = String::new();
    for cert in certs {
        let cert = cert.trim();
        if cert.is_empty() {
            continue;
        }
        bundle.push_str(cert);
        bundle.push('\n');
    }
    bundle
}

fn first_attr<'a>(
    mut iter: impl Iterator<Item = &'a x509_parser::x509::AttributeTypeAndValue<'a>>,
) -> Option<String> {
    iter.next()
        .and_then(|attr| attr.as_str().ok())
        .map(str::to_string)
}

pub(crate) fn parse_x509<'a>(
    block: &'a x509_parser::pem::Pem,
) -> Result<x509_parser::certificate::X509Certificate<'a>, MtlsError> {
    block.parse_x509().map_err(|err| {
        MtlsError::Certificate(format!("cannot parse the certificate: {err}"))
    })
}

pub(crate) fn parse_pem_block(
    cert_pem: &str,
) -> Result<x509_parser::pem::Pem, MtlsError> {
    let (_, block) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|err| {
            MtlsError::Certificate(format!(
                "cannot parse the PEM bundle: {err}"
            ))
        })?;
    Ok(block)
}

/// The DER-encoded `SubjectPublicKeyInfo` of a certificate's public key.
fn ca_public_key_der(cert_pem: &str) -> Result<Vec<u8>, MtlsError> {
    let block = parse_pem_block(cert_pem)?;
    Ok(parse_x509(&block)?.public_key().raw.to_vec())
}

pub(crate) fn clamp_days(
    days: i64,
    max: i64,
    field: &str,
) -> Result<i64, MtlsError> {
    if !(1..=max).contains(&days) {
        return Err(MtlsError::Invalid(format!(
            "{field} must be between 1 and {max} days"
        )));
    }
    Ok(days)
}

/// `now - 5 min` to `now + days`, so a client whose clock lags slightly still
/// accepts a fresh certificate.
pub(crate) fn validity_window(days: i64) -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    (now - Duration::minutes(5), now + Duration::days(days))
}

/// Normalises a fingerprint for storage and comparison: lowercase hex with the
/// separators an operator may have copied out of `openssl x509 -fingerprint`.
pub fn normalise_fingerprint(raw: &str) -> String {
    raw.chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ca_is_a_ca_and_roundtrips_through_parse() {
        let ca = generate_ca("PingWAF mTLS CA", Some("Acme"), 365).unwrap();
        assert!(ca.meta.is_ca);
        assert_eq!(ca.meta.common_name.as_deref(), Some("PingWAF mTLS CA"));
        assert_eq!(ca.meta.organization.as_deref(), Some("Acme"));
        assert!(
            ca.meta.subject_dn.contains("Acme"),
            "{}",
            ca.meta.subject_dn
        );
        assert_eq!(ca.meta.fingerprint_sha256.len(), 64);
        // A 20-byte serial, hex-encoded. The length is not fixed: DER drops
        // leading zero bytes from an INTEGER, so a serial that starts with one
        // renders as 38 characters rather than 40 — about one in 256, which is
        // how often this test used to fail. What matters is that it is there
        // and plausibly sized, not that it is exactly 40.
        assert!(
            (38..=40).contains(&ca.meta.serial.len()),
            "serial should be a 20-byte integer: {} ({} chars)",
            ca.meta.serial,
            ca.meta.serial.len()
        );
        assert!(
            ca.meta.serial.chars().all(|c| c.is_ascii_hexdigit()),
            "serial should be hex: {}",
            ca.meta.serial
        );
        // Two certificates must not share a serial, which is the property the
        // random generation is there for.
        let other = generate_ca("PingWAF mTLS CA", Some("Acme"), 365).unwrap();
        assert_ne!(
            ca.meta.serial, other.meta.serial,
            "serials must be unique across generated certificates"
        );
        assert!(ca.key_pem.is_some());

        let reparsed = parse_cert_meta(&ca.cert_pem).unwrap();
        assert_eq!(reparsed, ca.meta);
        assert_eq!(
            normalise_fingerprint(&ca.meta.fingerprint_sha256),
            ca.meta.fingerprint_sha256
        );
    }

    #[test]
    fn issued_client_cert_carries_the_organization_and_is_not_a_ca() {
        let ca = generate_ca("PingWAF mTLS CA", Some("Acme"), 365).unwrap();
        let leaf = issue_client_cert(
            &ca.cert_pem,
            ca.key_pem.as_deref().unwrap(),
            "laptop-1",
            Some("Acme"),
            90,
        )
        .unwrap();

        assert!(!leaf.meta.is_ca);
        assert_eq!(leaf.meta.common_name.as_deref(), Some("laptop-1"));
        assert_eq!(leaf.meta.organization.as_deref(), Some("Acme"));
        assert_ne!(leaf.meta.fingerprint_sha256, ca.meta.fingerprint_sha256);
        assert!(leaf.key_pem.is_some());
    }

    #[test]
    fn fingerprint_covers_the_whole_certificate() {
        let ca = generate_ca("CA", None, 30).unwrap();
        let block = parse_pem_block(&ca.cert_pem).unwrap();
        assert_eq!(
            ca.meta.fingerprint_sha256,
            hex::encode(Sha256::digest(&block.contents))
        );
        // Hashing the TBSCertificate instead would produce a different digest,
        // which is what the edge reports as the peer's certificate digest.
        let tbs = hex::encode(Sha256::digest(
            parse_x509(&block).unwrap().tbs_certificate.as_ref(),
        ));
        assert_ne!(ca.meta.fingerprint_sha256, tbs);
    }

    #[test]
    fn client_cert_never_outlives_its_ca() {
        let ca = generate_ca("CA", None, 30).unwrap();
        let leaf = issue_client_cert(
            &ca.cert_pem,
            ca.key_pem.as_deref().unwrap(),
            "laptop",
            None,
            MAX_CLIENT_CERT_DAYS,
        )
        .unwrap();
        assert!(leaf.meta.not_after <= ca.meta.not_after);
    }

    #[test]
    fn validity_bounds_are_enforced() {
        assert!(matches!(
            generate_ca("CA", None, 0),
            Err(MtlsError::Invalid(_))
        ));
        assert!(matches!(
            generate_ca("CA", None, MAX_CA_DAYS + 1),
            Err(MtlsError::Invalid(_))
        ));

        let ca = generate_ca("CA", None, 365).unwrap();
        let err = issue_client_cert(
            &ca.cert_pem,
            ca.key_pem.as_deref().unwrap(),
            "laptop",
            None,
            0,
        );
        assert!(matches!(err, Err(MtlsError::Invalid(_))));
    }

    #[test]
    fn issuing_rejects_a_non_ca_and_a_wrong_key() {
        // A leaf certificate cannot act as an issuer.
        let ca = generate_ca("CA", Some("Acme"), 365).unwrap();
        let leaf = issue_client_cert(
            &ca.cert_pem,
            ca.key_pem.as_deref().unwrap(),
            "one",
            Some("Acme"),
            30,
        )
        .unwrap();
        assert!(matches!(
            issue_client_cert(
                &leaf.cert_pem,
                leaf.key_pem.as_deref().unwrap(),
                "two",
                None,
                30
            ),
            Err(MtlsError::Invalid(_))
        ));

        // A key that does not match the CA certificate is rejected.
        let other = generate_ca("Other CA", Some("Other"), 365).unwrap();
        assert!(issue_client_cert(
            &ca.cert_pem,
            other.key_pem.as_deref().unwrap(),
            "two",
            None,
            30
        )
        .is_err());
    }

    #[test]
    fn bundle_pem_skips_blank_entries() {
        let ca = generate_ca("CA", None, 365).unwrap();
        let bundle =
            bundle_pem(&["".to_string(), ca.cert_pem.clone(), "  ".into()]);
        assert_eq!(bundle.trim(), ca.cert_pem.trim());
        assert!(bundle_pem(&[]).is_empty());
    }

    #[test]
    fn fingerprint_normalisation_accepts_openssl_output() {
        assert_eq!(normalise_fingerprint("AB:cd:01"), "abcd01".to_string());
        assert_eq!(normalise_fingerprint("ab cd 01"), "abcd01");
    }
}
