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

use ahash::AHashMap;
use arc_swap::ArcSwap;
use pingap_certificate::{
    CertificateProvider, DEFAULT_SERVER_NAME, DynamicCertificates,
    update_certificates,
};
use pingap_config::CertificateConf;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;

struct Provider {
    certificates: ArcSwap<DynamicCertificates>,
}

impl CertificateProvider for Provider {
    fn store(&self, data: DynamicCertificates) {
        self.certificates.store(Arc::new(data));
    }
    fn get(
        &self,
        sni: &str,
    ) -> Option<Arc<pingap_certificate::TlsCertificate>> {
        let certs = self.certificates.load();
        certs
            .get(sni)
            .or_else(|| {
                // If exact match fails, try wildcard match without new string allocation.
                sni.split_once('.')
                    .and_then(|(_, domain)| certs.get(&format!("*.{}", domain)))
            })
            .or_else(|| {
                // Fallback to the default certificate.
                certs.get(DEFAULT_SERVER_NAME)
            })
            .cloned()
    }
    fn list(&self) -> Arc<DynamicCertificates> {
        self.certificates.load().clone()
    }
}

static CERTIFICATE_PROVIDER: LazyLock<Arc<Provider>> = LazyLock::new(|| {
    Arc::new(Provider {
        certificates: ArcSwap::from_pointee(AHashMap::new()),
    })
});

pub fn new_certificate_provider() -> Arc<dyn CertificateProvider> {
    CERTIFICATE_PROVIDER.clone()
}

/// Updates the global certificate store with new configurations
///
/// # Arguments
/// * `certificate_configs` - HashMap of certificate names to their configurations
///
/// # Returns
/// * `Vec<String>` - List of domain names whose certificates were updated
/// * `String` - Semicolon-separated list of parsing errors
///
/// Updates certificates atomically using ArcSwap, detecting changes by comparing hash_keys.
/// Supports multiple domains per certificate and wildcard certificates.
pub fn try_update_certificates(
    certificate_configs: &HashMap<String, CertificateConf>,
) -> (Vec<String>, String) {
    // Certificates whose configuration did not change are carried over
    // as they are, not parsed and loaded again.
    let previous = CERTIFICATE_PROVIDER.list();
    let (mut new_certs, errors, updated_certificates) =
        update_certificates(certificate_configs, &previous);

    // A configuration entry without a PEM (an ACME certificate still being
    // issued, or one whose PEM a lost race failed to persist) is skipped by
    // the update above - and because the provider is replaced wholesale, it
    // used to take the previously served certificate for its domains out of
    // the SNI table, rejecting every TLS handshake until the next issuance.
    // Carry the old entries over by domain so TLS keeps serving; they are
    // replaced as soon as the PEM for that entry shows up.
    for conf in certificate_configs.values() {
        if conf.tls_cert.is_some() && conf.tls_key.is_some() {
            continue;
        }
        let Some(domains) = &conf.domains else {
            continue;
        };
        for domain in domains
            .split(',')
            .map(str::trim)
            .filter(|domain| !domain.is_empty())
        {
            // A domain also served by an entry that does have a PEM wins -
            // never overwrite a freshly loaded certificate with the old one.
            if !new_certs.contains_key(domain)
                && let Some(cert) = previous.get(domain)
            {
                new_certs.insert(domain.to_string(), Arc::clone(cert));
            }
        }
    }

    let error_messages: Vec<String> = errors
        .into_iter()
        .map(|(name, msg)| format!("{}({})", msg, name))
        .collect();

    CERTIFICATE_PROVIDER.store(new_certs);
    (updated_certificates, error_messages.join(";"))
}

#[cfg(test)]
mod tests {
    use super::try_update_certificates;
    use pingap_certificate::CertificateProvider;
    use pingap_certificate::TlsCertificate;
    use pingap_config::CertificateConf;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn seed_provider(domain: &str, name: &str, hash: &str) {
        let mut map = ahash::AHashMap::new();
        map.insert(
            domain.to_string(),
            Arc::new(TlsCertificate {
                name: Some(name.to_string()),
                hash_key: hash.to_string(),
                ..Default::default()
            }),
        );
        super::CERTIFICATE_PROVIDER.store(map);
    }

    fn conf_with(
        domains: &str,
        tls_cert: Option<&str>,
        tls_key: Option<&str>,
    ) -> CertificateConf {
        CertificateConf {
            domains: Some(domains.to_string()),
            tls_cert: tls_cert.map(str::to_string),
            tls_key: tls_key.map(str::to_string),
            ..Default::default()
        }
    }

    /// A certificate entry whose PEM has not (yet) been persisted - the
    /// reload race window or a freshly created ACME entry - must not take
    /// the previously served certificate for its domains out of the SNI
    /// table: TLS would reject every handshake until the next issuance.
    #[test]
    fn test_entries_without_pem_keep_serving_the_previous_certificate() {
        seed_provider("carry-a.example.com", "old", "old-hash");
        let mut configs = HashMap::new();
        configs.insert(
            "panel".to_string(),
            conf_with("carry-a.example.com", None, None),
        );

        let (_, errors) = try_update_certificates(&configs);
        assert!(errors.is_empty(), "{errors}");

        let certs = super::CERTIFICATE_PROVIDER.list();
        let cert = certs
            .get("carry-a.example.com")
            .expect("domain must still be served");
        assert_eq!("old-hash", cert.hash_key);
    }

    /// The carry-over must never shadow a configuration that does have a
    /// PEM: a fresh upload (or a completed ACME issuance) replaces the old
    /// entry even for the same domains.
    #[test]
    fn test_fresh_certificate_wins_over_the_carried_over_one() {
        let certified_key = rcgen::generate_simple_self_signed(vec![
            "carry-b.example.com".to_string(),
        ])
        .unwrap();
        let tls_cert = certified_key.cert.pem();
        let tls_key = certified_key.signing_key.serialize_pem();

        seed_provider("carry-b.example.com", "old", "old-hash");
        let mut configs = HashMap::new();
        configs.insert(
            "upload".to_string(),
            conf_with("carry-b.example.com", Some(&tls_cert), Some(&tls_key)),
        );

        let (updated, errors) = try_update_certificates(&configs);
        assert!(errors.is_empty(), "{errors}");
        assert_eq!(&["upload".to_string()], updated.as_slice());

        let certs = super::CERTIFICATE_PROVIDER.list();
        let cert = certs
            .get("carry-b.example.com")
            .expect("domain must be served by the new certificate");
        assert!(cert.certificate.is_some(), "the loaded cert must win");
        assert_ne!("old-hash", cert.hash_key);
    }
}
