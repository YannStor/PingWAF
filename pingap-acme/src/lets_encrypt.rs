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

use super::{AcmeDnsTask, Error, LOG_TARGET, Result, get_value_from_env};
use crate::dns_ali::AliDnsTask;
use crate::dns_cf::CfDnsTask;
use crate::dns_huawei::HuaweiDnsTask;
use crate::dns_manual::{MANUAL_DNS_REMARK, ManualDnsTask};
use crate::dns_tencent::TencentDnsTask;
use async_trait::async_trait;
use hickory_resolver::Resolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::system_conf::read_system_conf;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use pingap_certificate::CertificateProvider;
use pingap_certificate::{
    Certificate, parse_leaf_chain_certificates, update_certificates,
};
use pingap_config::{
    Category, CertificateConf, ConfigManager, DNS_PROVIDER_MANUAL,
    PingapConfig, StorageConf, normalize_dns_provider,
};
use pingap_core::BackgroundTask;
use pingap_core::Error as ServiceError;
use pingap_core::HttpResponse;
use pingap_core::{
    Ctx, NotificationData, NotificationLevel, NotificationSender,
};
use pingora::http::StatusCode;
use pingora::proxy::Session;
use scopeguard::defer;
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "openssl")]
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

static WELL_KNOWN_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

/// Hard ceiling for one ACME network round trip. instant-acme's built-in
/// hyper client sets no timeout of its own, so a CA endpoint that accepts
/// the connection and then goes silent would otherwise wedge the renewal
/// task — and, through the background service's `join_all`, every other
/// task sharing it — forever.
const ACME_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Longer ceiling for the polling stages: `RetryPolicy` bounds the total
/// wait, but each individual poll shares the same unbounded HTTP client, so
/// an outer timeout covers a poll that never returns at all.
const ACME_POLL_TIMEOUT: Duration = Duration::from_secs(90);

/// Awaits one instant-acme call with a hard timeout, folding both failure
/// modes into this crate's error type with the stage as the category so the
/// logs name where an order stalled.
async fn acme_call<T>(
    category: &'static str,
    timeout: Duration,
    fut: impl std::future::Future<
        Output = std::result::Result<T, instant_acme::Error>,
    >,
) -> Result<T> {
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(source)) => Err(Error::Instant {
            category: category.to_string(),
            source,
        }),
        Err(_) => Err(Error::Fail {
            category: category.to_string(),
            message: format!(
                "no response from the ACME server within {}s; check outbound connectivity to the CA",
                timeout.as_secs()
            ),
        }),
    }
}

/// ACME talks rustls even when the proxy TLS backend is OpenSSL, so the
/// process still needs a CryptoProvider. Prefer the shared installer when
/// the rustls backend owns it; otherwise install aws-lc-rs here once.
fn ensure_crypto_provider() {
    #[cfg(feature = "tls-rustls")]
    {
        pingap_certificate::install_default_crypto_provider();
    }
    #[cfg(feature = "openssl")]
    {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ =
                rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }
}

/// Updates the certificate for the given name and domains using Let's Encrypt.
/// This function will:
/// 1. Verify the certificate configuration can be addressed for saving
/// 2. Generate a new certificate from Let's Encrypt
/// 3. Update the configuration with the new certificate
async fn update_certificate_lets_encrypt(
    config_manager: Arc<ConfigManager>,
    params: UpdateCertificateParams,
) -> Result<()> {
    // Resolve the certificate conf BEFORE talking to the CA, and treat a miss
    // as an error. `get` addresses the conf by its canonical file
    // (`certificates.toml` / `certificates/<name>.toml`), while the loader
    // accepts any layout it can glob - so a certificate defined in a combined
    // file starts up fine but cannot be found here. This used to be a silent
    // `if let Some`, which dropped the freshly issued certificate on the
    // floor: renewal logged success, no error anywhere, every handshake
    // failed with "no match certificate", and the next cycle re-issued from
    // scratch until Let's Encrypt's duplicate-certificate rate limit cut it
    // off. Checking first also means a config that cannot take the
    // certificate never burns an issuance against that rate limit.
    let cert: Option<CertificateConf> = config_manager
        .get(Category::Certificate, &params.name)
        .await
        .map_err(|e| Error::Fail {
            category: "load_config".to_string(),
            message: e.to_string(),
        })?;
    let Some(mut cert) = cert else {
        return Err(Error::Fail {
            category: "save_config".to_string(),
            message: format!(
                "certificate({}) is not stored where this config layout saves it, so the issued certificate could not be persisted. Pingap normalizes the layout at startup; restart to migrate, or move the [certificates.{}] section into its canonical file.",
                params.name, params.name
            ),
        });
    };

    // get new certificate from lets encrypt
    let production = acme_production_from_env();
    let (pem, key) =
        new_lets_encrypt(config_manager.clone(), production, params.clone())
            .await?;

    cert.tls_cert = Some(pem);
    cert.tls_key = Some(key);
    config_manager
        .update(Category::Certificate, &params.name, &cert)
        .await
        .map_err(|e| Error::Fail {
            category: "save_config".to_string(),
            message: e.to_string(),
        })?;
    Ok(())
}

/// File cache parameters
#[derive(Debug, Clone)]
struct UpdateCertificateParams {
    name: String,
    domains: Vec<String>,
    buffer_days: u16,
    dns_challenge: bool,
    dns_provider: String,
    dns_service_url: String,
}

/// Marker the control plane recognises as a terminal issuance failure. The
/// raw ACME capture layer ships message text only, so this prefix is what
/// turns a log line into a certificate state update.
const ACME_FAILURE_MARKER: &str = "acme_failed";

/// The event line for a failed renewal:
/// `acme_failed domain=<d1,d2> reason=<error>`.
///
/// Newlines are folded into spaces: the capture layer stores one message per
/// event and the control plane parses the line.
/// Keeps an error diagnostic without echoing URL query strings. DNS provider
/// errors can include the request URL, and those URLs carry credentials as
/// query parameters; the text is persisted, shown in the console and sent to
/// notification channels, so query strings must never travel with it.
fn redact_url_queries(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for part in text.split_inclusive(char::is_whitespace) {
        if !part.contains("://") {
            out.push_str(part);
            continue;
        }
        match part.split_once('?') {
            Some((prefix, _)) => {
                out.push_str(prefix);
                out.push_str("?[redacted]");
                if let Some(space) =
                    part.chars().last().filter(|c| c.is_whitespace())
                {
                    out.push(space);
                }
            },
            None => out.push_str(part),
        }
    }
    out
}

fn acme_failure_event_message(domains: &[String], error: &Error) -> String {
    let reason =
        redact_url_queries(&error.to_string().replace(['\n', '\r'], " "));
    format!(
        "{} domain={} reason={reason}",
        ACME_FAILURE_MARKER,
        domains.join(",")
    )
}

/// Failure state for one certificate/domain set.
struct RetryState {
    failures: u32,
    next_attempt: Instant,
}

/// Backoff after a failed order. The first retry is deliberately soon (a
/// transient DNS/HTTP hiccup should recover quickly), then backs off to six
/// hours so a persistent misconfiguration cannot exhaust CA quotas or the
/// notification channel.
fn retry_delay(failures: u32) -> Duration {
    match failures {
        0 | 1 => Duration::from_secs(5 * 60),
        2 => Duration::from_secs(15 * 60),
        3 => Duration::from_secs(30 * 60),
        4 => Duration::from_secs(60 * 60),
        _ => Duration::from_secs(6 * 60 * 60),
    }
}

/// Periodically checks and updates certificates that need renewal.
/// A certificate needs renewal if:
/// - It is invalid or expired
/// - The configured domains have changed
/// - The certificate cannot be loaded
///
/// The scan runs every tick so a newly created site is attempted within a
/// minute. Failed certificate/domain pairs are skipped until their own
/// exponential-backoff deadline, so retries stay bounded.
async fn do_update_certificates(
    count: u32,
    config_manager: Arc<ConfigManager>,
    params: &[UpdateCertificateParams],
    provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
    retries: &mut HashMap<String, RetryState>,
) -> Result<bool, ServiceError> {
    if params.is_empty() {
        return Ok(false);
    }
    let config = config_manager.get_current_config();
    for item in params.iter() {
        let name = &item.name;
        let domains = &item.domains;
        let retry_key = format!("{name}|{}", domains.join(","));
        if retries
            .get(&retry_key)
            .is_some_and(|state| state.next_attempt > Instant::now())
        {
            debug!(
                target: LOG_TARGET,
                name,
                domains = domains.join(","),
                "certificate retry is backing off"
            );
            continue;
        }
        let is_manual = item.dns_provider == DNS_PROVIDER_MANUAL;
        // manual dns challenge is only run once
        if item.dns_challenge && is_manual && count > 0 {
            continue;
        }

        let should_renew = match get_lets_encrypt_certificate(&config, name) {
            Ok(Some(certificate)) => {
                // check if certificate is valid or domains changed
                let needs_renewal = !certificate.valid(item.buffer_days);
                let domains_changed = {
                    let mut sorted_domains = domains.clone();
                    let mut cert_domains = certificate.domains.clone();
                    sorted_domains.sort();
                    cert_domains.sort();
                    sorted_domains != cert_domains
                };
                needs_renewal || domains_changed
            },
            Ok(None) => true,
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    name,
                    "failed to get certificate"
                );
                true
            },
        };

        if !should_renew {
            retries.remove(&retry_key);
            debug!(
                target: LOG_TARGET,
                domains = domains.join(","),
                name,
                "certificate still valid"
            );
            continue;
        }

        match renew_certificate(
            config_manager.clone(),
            item.clone(),
            provider.clone(),
            sender.clone(),
        )
        .await
        {
            Ok(()) => {
                retries.remove(&retry_key);
            },
            Err(e) => {
                let failures = retries
                    .get(&retry_key)
                    .map_or(1, |state| state.failures.saturating_add(1));
                let delay = retry_delay(failures);
                retries.insert(
                    retry_key,
                    RetryState {
                        failures,
                        next_attempt: Instant::now() + delay,
                    },
                );
                // Terminal failure for this attempt. Besides the operator log,
                // this line is the event the control plane turns into a
                // `failed` certificate row: the raw ACME capture ships only
                // the message text, so the domains travel inside it for site
                // attribution.
                let message = acme_failure_event_message(domains, &e);
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    domains = domains.join(","),
                    name,
                    retry_in_secs = delay.as_secs(),
                    "{}",
                    message
                );
            },
        }
    }
    Ok(true)
}

async fn renew_certificate(
    config_manager: Arc<ConfigManager>,
    params: UpdateCertificateParams,
    provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<()> {
    update_certificate_lets_encrypt(config_manager.clone(), params.clone())
        .await?;
    handle_successful_renewal(
        &params.domains,
        config_manager,
        provider,
        sender,
    )
    .await?;
    Ok(())
}

/// Installs the certificates from `certificate_configs` in `provider`,
/// keeping every certificate whose configuration did not change; after a
/// renewal that is all of them but the renewed one.
fn try_update_certificates(
    provider: Arc<dyn CertificateProvider>,
    certificate_configs: &HashMap<String, CertificateConf>,
) -> (Vec<String>, String) {
    let (new_certs, errors, updated_certificates) =
        update_certificates(certificate_configs, &provider.list());

    let error_messages: Vec<String> = errors
        .into_iter()
        .map(|(name, msg)| format!("{}({})", msg, name))
        .collect();

    provider.store(new_certs);
    (updated_certificates, error_messages.join(";"))
}

async fn handle_successful_renewal(
    domains: &[String],
    config_manager: Arc<ConfigManager>,
    provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
) -> Result<()> {
    info!(
        target: LOG_TARGET,
        domains = domains.join(","),
        "renew certificate success"
    );
    let toml_config =
        config_manager.load_all().await.map_err(|e| Error::Fail {
            category: "load_config".to_string(),
            message: e.to_string(),
        })?;
    let config =
        toml_config
            .to_pingap_config(true)
            .map_err(|e| Error::Fail {
                category: "convert_config".to_string(),
                message: e.to_string(),
            })?;
    if let Some(sender) = &sender {
        sender
            .notify(NotificationData {
                category: "lets_encrypt".to_string(),
                title: "Generate new cert from let's encrypt".to_string(),
                message: format!("Domains: {domains:?}"),
                ..Default::default()
            })
            .await;
    }

    let (_, error) = try_update_certificates(provider, &config.certificates);
    if !error.is_empty() {
        error!(target: LOG_TARGET, error = error, "parse certificate fail");
        if let Some(sender) = &sender {
            sender
                .notify(NotificationData {
                    category: "parse_certificate_fail".to_string(),
                    level: NotificationLevel::Error,
                    message: error,
                    ..Default::default()
                })
                .await;
        }
    } else {
        // update certificate success
        // so set the current config
        config_manager.set_current_config(config);
    }
    Ok(())
}

struct LetsEncryptTask {
    config_manager: Arc<ConfigManager>,
    certificate_provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
    running: AtomicBool,
    retries: Mutex<HashMap<String, RetryState>>,
}

#[async_trait]
impl BackgroundTask for LetsEncryptTask {
    async fn execute(&self, count: u32) -> Result<bool, ServiceError> {
        if self.running.swap(true, Ordering::Relaxed) {
            return Ok(true);
        }
        defer!(self.running.store(false, Ordering::Relaxed););
        let mut params = vec![];
        let config = self.config_manager.get_current_config();

        for (name, certificate) in config.certificates.iter() {
            let acme = certificate.acme.clone().unwrap_or_default();
            let domains = certificate.domains.clone().unwrap_or_default();
            if acme.is_empty() || domains.is_empty() {
                continue;
            }
            let dns_service_url = get_value_from_env(
                &certificate.dns_service_url.clone().unwrap_or_default(),
            );

            params.push(UpdateCertificateParams {
                name: name.to_string(),
                buffer_days: certificate.buffer_days.unwrap_or_default(),
                domains: domains
                    .split(',')
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect(),
                dns_challenge: certificate.dns_challenge.unwrap_or_default(),
                // Normalized once here so the match below only ever sees a
                // canonical name. `validate` rejects anything unrecognised, so
                // the fallback is only reached for `manual` / unset.
                dns_provider: normalize_dns_provider(
                    &certificate.dns_provider.clone().unwrap_or_default(),
                )
                .unwrap_or(DNS_PROVIDER_MANUAL)
                .to_string(),
                dns_service_url,
            });
        }
        let mut retries = self.retries.lock().await;
        do_update_certificates(
            count,
            self.config_manager.clone(),
            &params,
            self.certificate_provider.clone(),
            self.sender.clone(),
            &mut retries,
        )
        .await?;

        // Hourly (the service ticks once a minute), and never on the first
        // cycle: during a rolling upgrade an old instance may still be mid
        // order, and its tokens - written by a version without `created_at` -
        // are exactly the ones the ageless rule below would remove.
        if count > 0 && count.is_multiple_of(TOKEN_CLEAR_INTERVAL) {
            match clear_stale_http_tokens(
                &self.config_manager,
                pingap_core::now_sec(),
            )
            .await
            {
                Ok(0) => {},
                Ok(removed) => {
                    info!(
                        target: LOG_TARGET,
                        removed, "clear stale http-01 challenge tokens"
                    );
                },
                Err(e) => {
                    error!(
                        target: LOG_TARGET,
                        error = %e,
                        "clear stale http-01 challenge tokens fail"
                    );
                },
            }
        }
        Ok(true)
    }
}

/// The remark every http-01 token is stored with; the cleanup below uses it to
/// tell tokens apart from storage entries a person created.
static HTTP_01_TOKEN_REMARK: &str = "let's encrypt http-01 token";
/// The remark the ACME account credentials are stored with.
static ACCOUNT_REMARK: &str = "let's encrypt account credentials";
/// How long a pending ACME order can stay in flight: Let's Encrypt expires an
/// order about a week after it is created, and only until then can a retry
/// still need the token the order wrote.
const ACME_ORDER_LIFETIME_SECS: u64 = 7 * 24 * 3600;
/// How old a token has to be before cleanup may touch it.
///
/// A token is only needed between `set_ready` and the CA finishing validation,
/// normally minutes. But storage carries no order id, so cleanup cannot ask
/// whether the order that wrote a token is still in flight - and an order that
/// keeps backing off can still be serving its token long after the challenge
/// started. The window is therefore the longest an order can live plus a day
/// of margin. The previous 24h window was shorter than an order's lifetime and
/// deleted tokens out from under retrying validations, which the CA saw as
/// `token not found` 404s.
const HTTP_01_TOKEN_MAX_AGE: u64 = ACME_ORDER_LIFETIME_SECS + 24 * 3600;

// The cleanup window must outlive any order the CA can still validate: a
// shorter window is the bug this constant used to encode.
const _: () = assert!(HTTP_01_TOKEN_MAX_AGE > ACME_ORDER_LIFETIME_SECS);
const _: () = assert!(ACME_ORDER_LIFETIME_SECS >= 7 * 24 * 3600);
/// Cleanup cadence in service cycles (one cycle per minute).
const TOKEN_CLEAR_INTERVAL: u32 = 60;

/// Whether a token written at `created_at` may be removed at `now`.
///
/// A storage entry carries the token value, a remark and a creation time - no
/// order id - so this is the one place the cleanup rule can be expressed:
/// anything younger than the longest an order can stay in flight belongs to an
/// order that may still be retrying, and is kept. Pure so the boundary can be
/// tested without a config manager.
fn http_token_is_stale(created_at: Option<u64>, now: u64) -> bool {
    created_at.is_none_or(|created_at| {
        now.saturating_sub(created_at) > HTTP_01_TOKEN_MAX_AGE
    })
}

/// Removes http-01 challenge tokens, and the TXT values the manual DNS task
/// records, that no validation can still be using.
///
/// Tokens used to be stored and never deleted, piling up in the storage
/// category forever (one file per token in the separated layout). Removal is
/// by age rather than on order completion so it stays safe across processes:
/// deleting an old token cannot sabotage an in-flight validation, no matter
/// which instance wrote it. The age is one order lifetime plus a margin
/// ([`HTTP_01_TOKEN_MAX_AGE`]): the entry has no order id, so "is the order
/// that wrote this token still running?" cannot be answered here. A token
/// without `created_at` predates the field and is removed too - the first
/// sweep runs an hour after start, far longer than the minutes between writing
/// a token and the CA finishing validation.
async fn clear_stale_http_tokens(
    config_manager: &Arc<ConfigManager>,
    now: u64,
) -> Result<u32> {
    let config = config_manager.load_all().await.map_err(|e| Error::Fail {
        category: "load_config".to_string(),
        message: e.to_string(),
    })?;
    let mut removed = 0;
    for (name, value) in config.storages.iter().flatten() {
        let Ok(conf) = value.clone().try_into::<StorageConf>() else {
            continue;
        };
        // The remark decides what is a token; entries people created through
        // the admin panel carry their own remarks and are never touched.
        if !matches!(
            conf.remark.as_deref(),
            Some(remark) if remark == HTTP_01_TOKEN_REMARK || remark == MANUAL_DNS_REMARK
        ) {
            continue;
        }
        if !http_token_is_stale(conf.created_at, now) {
            continue;
        }
        match config_manager.delete(Category::Storage, name).await {
            Ok(()) => {
                info!(
                    target: LOG_TARGET,
                    token = name.as_str(),
                    "remove stale http-01 challenge token"
                );
                removed += 1;
            },
            Err(e) => {
                // Keep going: the next hourly run retries whatever failed.
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    token = name.as_str(),
                    "remove stale http-01 challenge token fail"
                );
            },
        }
    }
    Ok(removed)
}

/// Create a Let's Encrypt service to generate the certificate,
/// and regenerate if the certificate is invalid or will be expired.
pub fn new_lets_encrypt_service(
    config_manager: Arc<ConfigManager>,
    certificate_provider: Arc<dyn CertificateProvider>,
    sender: Option<Arc<NotificationSender>>,
) -> Box<dyn BackgroundTask> {
    Box::new(LetsEncryptTask {
        config_manager,
        certificate_provider,
        sender,
        running: AtomicBool::new(false),
        retries: Mutex::new(HashMap::new()),
    })
}

/// Get the cert from file and convert it to certificate struct.
fn get_lets_encrypt_certificate(
    config: &PingapConfig,
    name: &str,
) -> Result<Option<Certificate>> {
    let Some(cert) = config.certificates.get(name) else {
        return Err(Error::NotFound {
            message: "cert not found".to_string(),
        });
    };

    let pem = cert.tls_cert.as_deref().unwrap_or_default();
    let key = cert.tls_key.as_deref().unwrap_or_default();
    if pem.is_empty() || key.is_empty() {
        return Ok(None);
    }

    let (cert, _) =
        parse_leaf_chain_certificates(pem, key).map_err(|e| Error::Fail {
            category: "new_certificate".to_string(),
            message: e.to_string(),
        })?;
    Ok(Some(cert))
}

/// Handles the HTTP-01 challenge verification for Let's Encrypt.
/// This function:
/// 1. Intercepts requests to /.well-known/acme-challenge/
/// 2. Extracts the challenge token from the URL path
/// 3. Loads the pre-stored token response from storage
/// 4. Returns the token response to validate domain ownership
pub async fn handle_lets_encrypt(
    config_manager: Arc<ConfigManager>,
    session: &mut Session,
    _ctx: &mut Ctx,
) -> pingora::Result<bool> {
    let path = session.req_header().uri.path();
    // lets encrypt acme challenge path
    let Some(token) = path.strip_prefix(WELL_KNOWN_PATH_PREFIX) else {
        return Ok(false);
    };
    {
        // The token is attacker-controlled and used directly as a storage
        // lookup key. ACME HTTP-01 tokens are base64url strings, so reject
        // anything else up front: this blocks path traversal (`../certificate/
        // foo` and percent-encoded variants) and returns a clean 404 rather
        // than a storage error.
        if !is_valid_challenge_token(token) {
            HttpResponse {
                status: StatusCode::NOT_FOUND,
                ..Default::default()
            }
            .send(session)
            .await?;
            return Ok(true);
        }

        let value: Option<StorageConf> = config_manager
            .get(Category::Storage, token)
            .await
            .map_err(|e| {
                error!(
                    target: LOG_TARGET,
                    error = %e,
                    token,
                    "load http-01 token fail"
                );
                pingora::Error::because(
                    pingora::ErrorType::HTTPStatus(500),
                    e.to_string(),
                    pingora::Error::new(pingora::ErrorType::InternalError),
                )
            })?;
        // The validation request normally comes from the CA; the address
        // tells scanner probes and misrouted requests apart from real ones.
        let remote_addr = pingap_core::get_remote_addr(session)
            .map(|(addr, port)| format!("{addr}:{port}"))
            .unwrap_or_default();
        let Some(value) = value else {
            // A token this instance never stored (or stored by a previous
            // order). Serving an empty 200 here - the old behaviour - could
            // never pass validation anyway, but it logged "success" and left
            // the CA reporting a key authorization mismatch that nothing on
            // this side accounted for. A 404 with a warning names the failure
            // where it happens.
            warn!(
                target: LOG_TARGET,
                token,
                remote_addr,
                "let's encrypt http-01 token not found"
            );
            HttpResponse {
                status: StatusCode::NOT_FOUND,
                ..Default::default()
            }
            .send(session)
            .await?;
            return Ok(true);
        };
        info!(
            target: LOG_TARGET,
            token,
            remote_addr,
            "let's encrypt http-01 challenge token served"
        );
        HttpResponse {
            status: StatusCode::OK,
            body: value.value.into(),
            ..Default::default()
        }
        .send(session)
        .await?;
        Ok(true)
    }
}

/// Reads the explicit staging opt-in.
///
/// Production is the default: an unset, empty, false, or malformed value must
/// never silently redirect a deployment at the staging CA. Only the documented
/// truthy spellings do.
fn acme_production_from_value(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "staging" | "stage"
    )
}

/// Resolves the ACME directory from `PINGAP_ACME_STAGING`.
fn acme_production_from_env() -> bool {
    let value = std::env::var("PINGAP_ACME_STAGING").ok();
    acme_production_from_value(value.as_deref())
}

/// The storage entry the ACME account credentials live in, one per CA
/// environment.
fn account_storage_name(production: bool) -> &'static str {
    if production {
        "lets_encrypt_account"
    } else {
        "lets_encrypt_staging_account"
    }
}

/// The ACME account: the one stored from an earlier order when it still
/// works, otherwise a new one, stored for the next time. Every order used to
/// register a new account, which Let's Encrypt rate-limits per IP and which
/// left a trail of one-shot accounts behind.
async fn load_or_create_account(
    config_manager: &Arc<ConfigManager>,
    url: &str,
    production: bool,
) -> Result<Account> {
    let name = account_storage_name(production);
    let stored: Option<StorageConf> = config_manager
        .get(Category::Storage, name)
        .await
        .unwrap_or_else(|e| {
            warn!(
                target: LOG_TARGET,
                error = %e,
                "load let's encrypt account fail, create a new one"
            );
            None
        });
    if let Some(stored) = stored {
        let account = match serde_json::from_str::<AccountCredentials>(
            &stored.value,
        ) {
            Ok(credentials) => {
                let builder =
                    Account::builder().map_err(|e| Error::Instant {
                        category: "create_account".to_string(),
                        source: e,
                    })?;
                acme_call(
                    "load_account",
                    ACME_HTTP_TIMEOUT,
                    builder.from_credentials(credentials),
                )
                .await
            },
            Err(e) => {
                warn!(
                    target: LOG_TARGET,
                    error = %e,
                    "stored let's encrypt account is invalid, create a new one"
                );
                return create_account(config_manager, url, name).await;
            },
        };
        match account {
            Ok(account) => return Ok(account),
            Err(e) => warn!(
                target: LOG_TARGET,
                error = %e,
                "stored let's encrypt account is not usable, create a new one"
            ),
        }
    }
    create_account(config_manager, url, name).await
}

async fn create_account(
    config_manager: &Arc<ConfigManager>,
    url: &str,
    name: &str,
) -> Result<Account> {
    let (account, credentials) = acme_call(
        "create_account",
        ACME_HTTP_TIMEOUT,
        Account::builder()
            .map_err(|e| Error::Instant {
                category: "create_account".to_string(),
                source: e,
            })?
            .create(
                &NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                url.to_string(),
                None,
            ),
    )
    .await?;
    info!(target: LOG_TARGET, "create let's encrypt account success");
    // Best effort: an order can proceed with an account that could not be
    // stored; the next one registers again.
    let value = match serde_json::to_string(&credentials) {
        Ok(value) => value,
        Err(e) => {
            warn!(
                target: LOG_TARGET,
                error = %e,
                "serialize let's encrypt account fail"
            );
            return Ok(account);
        },
    };
    let conf = StorageConf {
        category: "config".to_string(),
        value,
        secret: None,
        remark: Some(ACCOUNT_REMARK.to_string()),
        created_at: Some(pingap_core::now_sec()),
    };
    if let Err(e) = config_manager.update(Category::Storage, name, &conf).await
    {
        warn!(
            target: LOG_TARGET,
            error = %e,
            "save let's encrypt account fail"
        );
    }
    Ok(account)
}

/// A resolver on the system's DNS configuration for confirming that a TXT
/// record has propagated. No caching: the first lookup runs before the
/// record exists, and a cached NXDOMAIN (negative TTL is the SOA minimum -
/// often 600s, longer than the whole wait) would be replayed for every
/// remaining attempt, so the check could never see the record appear.
fn new_txt_resolver() -> Result<Resolver<TokioRuntimeProvider>> {
    // The system resolver, like everything else on this host uses; the
    // previous hardcoded default (Google public DNS) is only the fallback
    // when the system configuration is unreadable.
    let (resolver_config, mut resolver_options) = read_system_conf()
        .unwrap_or_else(|e| {
            warn!(
                target: LOG_TARGET,
                error = %e,
                "read system dns conf fail, use default resolver"
            );
            (ResolverConfig::default(), ResolverOpts::default())
        });
    resolver_options.cache_size = 0;
    // Explicit per-lookup ceiling (the default too, but say it): a silent
    // resolver must surface as a lookup error within seconds, not stall the
    // propagation check.
    resolver_options.timeout = Duration::from_secs(5);
    let mut resolver_builder = Resolver::builder_with_config(
        resolver_config,
        TokioRuntimeProvider::default(),
    );
    *resolver_builder.options_mut() = resolver_options;
    resolver_builder.build().map_err(|e| Error::Fail {
        category: "build_resolver".to_string(),
        message: e.to_string(),
    })
}

/// ACME HTTP-01 tokens are base64url strings; anything else is rejected so the
/// token cannot be abused as a storage lookup key for path traversal.
fn is_valid_challenge_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Generates a new certificate from Let's Encrypt for the given domains.
/// A fresh order is `Pending`. Let's Encrypt answers `Ready` directly when
/// every authorization of the order is still valid (< 30 days old): the
/// challenges have already been validated, so the order can proceed to
/// finalize without repeating them. Everything else (Processing, Valid,
/// Invalid) is not actionable for us and must fail loudly instead of
/// spinning in the renewal loop.
fn order_is_actionable(status: &OrderStatus) -> bool {
    matches!(status, OrderStatus::Pending | OrderStatus::Ready)
}

/// The ACME protocol flow:
/// 1. Creates/retrieves an ACME account with Let's Encrypt
/// 2. Creates a new order for the domains to be certified
/// 3. For each domain:
///    - Gets the HTTP-01 challenge details
///    - Stores the challenge token response
///    - Notifies Let's Encrypt that the challenge is ready
/// 4. Waits for Let's Encrypt to verify domain ownership
/// 5. Generates a CSR (Certificate Signing Request)
/// 6. Submits the CSR and retrieves the signed certificate
///
/// Returns a tuple of (certificate_chain_pem, private_key_pem)
async fn new_lets_encrypt(
    config_manager: Arc<ConfigManager>,
    production: bool,
    params: UpdateCertificateParams,
) -> Result<(String, String)> {
    let mut domains: Vec<String> = params.domains.to_vec();
    // sort domain for comparing later
    domains.sort();
    info!(
        target: LOG_TARGET,
        domains = domains.join(","),
        "acme from let's encrypt"
    );
    let url = if production {
        LetsEncrypt::Production.url()
    } else {
        LetsEncrypt::Staging.url()
    };
    info!(
        target: LOG_TARGET,
        ca = if production { "production" } else { "staging" },
        "acme environment selected"
    );
    ensure_crypto_provider();

    let account =
        load_or_create_account(&config_manager, url, production).await?;

    let identifiers = domains
        .iter()
        .map(|item| Identifier::Dns(item.to_owned()))
        .collect::<Vec<Identifier>>();
    let mut order = acme_call(
        "new_order",
        ACME_HTTP_TIMEOUT,
        account.new_order(&NewOrder::new(&identifiers)),
    )
    .await?;

    let state = order.state();
    if !order_is_actionable(&state.status) {
        return Err(Error::Fail {
            message: format!(
                "order is not actionable, status: {:?}",
                state.status
            ),
            category: "order_status".to_string(),
        });
    }
    // Only a `Pending` order needs its authorizations/challenges (re)run;
    // a `Ready` order skips straight to poll_ready + finalize below.
    let need_challenge = state.status == OrderStatus::Pending;

    let mut dns_tasks = vec![];
    // Built on the first DNS-01 challenge and shared by the order's others.
    let mut resolver = None;

    let result = (async {
        let mut authorizations = order.authorizations();
        // `need_challenge` is false for a `Ready` order: its authorizations
        // are still valid, so re-fetching/validating them is pointless. The
        // condition is constant by design - this is an `if` wrapped around a
        // loop, spelled as `while` to keep the break-driven body flat.
        #[allow(clippy::while_immutable_condition)]
        while need_challenge {
            // Each fetch is a network call on the same unbounded client;
            // without the timeout a silent CA wedges the order here.
            let next = match tokio::time::timeout(
                ACME_HTTP_TIMEOUT,
                authorizations.next(),
            )
            .await
            {
                Ok(next) => next,
                Err(_) => {
                    return Err(Error::Fail {
                        category: "authorizations".to_string(),
                        message: format!(
                            "no response from the ACME server within {}s while fetching authorizations",
                            ACME_HTTP_TIMEOUT.as_secs()
                        ),
                    });
                },
            };
            let Some(result) = next else { break };
            let mut authz = result.map_err(|e| Error::Instant {
                category: "authorizations".to_string(),
                source: e,
            })?;
            info!(
                target: LOG_TARGET,
                status = format!("{:?}", authz.status),
                "authorization from let's encrypt"
            );
            match authz.status {
                instant_acme::AuthorizationStatus::Pending => {},
                instant_acme::AuthorizationStatus::Valid => continue,
                // Invalid / Revoked / Deactivated / Expired: surface an error
                // instead of panicking the renewal background task.
                _ => {
                    return Err(Error::Fail {
                        category: "authorization_status".to_string(),
                        message: format!(
                            "unexpected authorization status: {:?}",
                            authz.status
                        ),
                    });
                },
            }

            let mut challenge = if params.dns_challenge {
                let challenge = authz
                    .challenge(ChallengeType::Dns01)
                    .ok_or_else(|| Error::NotFound {
                        message: "Dns01 challenge not found".to_string(),
                    })?;
                let identifier = challenge.identifier().to_string();
                let identifier =
                    identifier.strip_prefix("*.").unwrap_or(&identifier);
                let dns_txt_value = challenge.key_authorization().dns_value();
                let acme_dns_name = format!("_acme-challenge.{identifier}");
                let task: Box<dyn AcmeDnsTask> = match params
                    .dns_provider
                    .as_str()
                {
                    "ali" => {
                        Box::new(AliDnsTask::new(&params.dns_service_url)?)
                    },
                    "cf" => Box::new(CfDnsTask::new(&params.dns_service_url)?),
                    "tencent" => {
                        Box::new(TencentDnsTask::new(&params.dns_service_url)?)
                    },
                    "huawei" => {
                        Box::new(HuaweiDnsTask::new(&params.dns_service_url)?)
                    },
                    _ => Box::new(ManualDnsTask::new(config_manager.clone())),
                };

                info!(
                    target: LOG_TARGET,
                    dns_provider = params.dns_provider,
                    dns_txt_value,
                    "start add dns txt record for {acme_dns_name}"
                );
                task.add_txt_record(&acme_dns_name, &dns_txt_value).await?;
                info!(
                    target: LOG_TARGET,
                    dns_provider = params.dns_provider,
                    dns_txt_value,
                    "add dns txt record success for {acme_dns_name}"
                );
                let resolver = match &resolver {
                    Some(resolver) => resolver,
                    None => resolver.insert(new_txt_resolver()?),
                };
                // dns txt record may take a while to propagate, so we need to retry
                let mut confirmed = false;
                for i in 0..10 {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    info!(
                        target: LOG_TARGET,
                        "lookup dns txt record of {acme_dns_name}, times:{i}"
                    );
                    match resolver.lookup(&acme_dns_name, RecordType::TXT).await
                    {
                        Ok(response) => {
                            let txt_records: Vec<String> = response
                                .answers()
                                .iter()
                                .filter_map(|record| match &record.data {
                                    hickory_resolver::proto::rr::RData::TXT(
                                        txt,
                                    ) => Some(txt.to_string()),
                                    _ => None,
                                })
                                .collect();
                            let matched =
                                txt_records.contains(&dns_txt_value);
                            // The name accumulates stale values when earlier
                            // runs were killed before their cleanup, so a
                            // `matched: false` is only interpretable next to
                            // the value this run is actually waiting for.
                            info!(
                                target: LOG_TARGET,
                                expected = dns_txt_value,
                                "get dns txt records: {:?}, matched: {matched}",
                                txt_records
                            );
                            if matched {
                                confirmed = true;
                                break;
                            }
                        },
                        // Expected on the early attempts - NXDOMAIN until the
                        // record propagates - but it has to be visible: these
                        // errors were silently swallowed before, which made a
                        // check that never succeeded look like one that never
                        // ran.
                        Err(e) => {
                            warn!(
                                target: LOG_TARGET,
                                error = %e,
                                "lookup dns txt record of {acme_dns_name} fail"
                            );
                        },
                    }
                }
                if !confirmed {
                    // Not fatal by design: this check watches propagation from
                    // this host's viewpoint, while the CA resolves against the
                    // authoritative servers itself - so proceed and let it
                    // decide. Say so, though, or a validation failure right
                    // after looks inexplicable.
                    warn!(
                        target: LOG_TARGET,
                        expected = dns_txt_value,
                        "dns txt record of {acme_dns_name} was not confirmed, proceeding to let the CA validate"
                    );
                }
                dns_tasks.push(task);
                challenge
            } else {
                let challenge = authz
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| Error::NotFound {
                        message: "Http01 challenge not found".to_string(),
                    })?;

                let identifier = challenge.identifier().to_string();
                let key_auth = challenge.key_authorization();
                config_manager
                    .update(
                        Category::Storage,
                        &challenge.token,
                        &StorageConf {
                            value: key_auth.as_str().to_string(),
                            category: "config".to_string(),
                            secret: None,
                            remark: Some(HTTP_01_TOKEN_REMARK.to_string()),
                            // Tokens are never deleted on completion (another
                            // process may still be serving them); the age
                            // based cleanup keys off this instead.
                            created_at: Some(pingap_core::now_sec()),
                        },
                    )
                    .await
                    .map_err(|e| Error::Fail {
                        category: "save_token".to_string(),
                        message: e.to_string(),
                    })?;
                // The identifier ties the token to its authorization: an
                // order for apex + wildcard runs several of these, and a
                // later validation failure names the domain, not the token.
                info!(
                    target: LOG_TARGET,
                    token = challenge.token,
                    identifier,
                    "save let's encrypt http-01 challenge token",
                );
                challenge
            };
            acme_call(
                "set_challenge_ready",
                ACME_HTTP_TIMEOUT,
                challenge.set_ready(),
            )
            .await?;
        }

        let status = acme_call(
            "poll_ready",
            ACME_POLL_TIMEOUT,
            order.poll_ready(
                &RetryPolicy::default().timeout(Duration::from_secs(60)),
            ),
        )
        .await?;

        if status != OrderStatus::Ready {
            return Err(Error::Fail {
                category: "poll_ready".to_string(),
                message: format!("unexpected order status: {status:?}"),
            });
        }
        Ok(())
    })
    .await;

    for task in dns_tasks.iter() {
        // ignore done error
        if let Err(err) = task.done().await {
            error!(
                target: LOG_TARGET,
                error = err.to_string(),
                "remove acme dns text record fail"
            );
        }
    }
    result?;

    let private_key_pem =
        acme_call("finalize", ACME_HTTP_TIMEOUT, order.finalize()).await?;
    let cert_chain_pem = acme_call(
        "poll_certificate",
        ACME_POLL_TIMEOUT,
        order.poll_certificate(
            &RetryPolicy::default().timeout(Duration::from_secs(60)),
        ),
    )
    .await?;

    Ok((cert_chain_pem, private_key_pem))
}

#[cfg(test)]
mod tests {
    use super::is_valid_challenge_token;
    use super::{UpdateCertificateParams, update_certificate_lets_encrypt};
    use pingap_config::new_file_config_manager;
    use std::sync::Arc;

    /// Issue #213: a certificate defined in a combined file loads and serves,
    /// but cannot be addressed by the canonical key the save path uses. That
    /// used to be a silent no-op AFTER issuance - success logged, certificate
    /// dropped, re-issued every cycle until the CA's rate limit. It must be a
    /// loud error, and it must fire BEFORE an issuance is burned (which is
    /// also what makes this testable offline: reaching the CA would be a
    /// network call).
    #[tokio::test]
    async fn test_renewal_fails_loudly_when_conf_is_not_addressable() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("combined.toml"),
            "[certificates.panel]\ndomains = \"example.com\"\nacme = \"lets_encrypt\"\n",
        )
        .unwrap();
        let manager = Arc::new(
            new_file_config_manager(dir.path().to_string_lossy().as_ref())
                .unwrap(),
        );

        let err = update_certificate_lets_encrypt(
            manager,
            UpdateCertificateParams {
                name: "panel".to_string(),
                domains: vec!["example.com".to_string()],
                buffer_days: 30,
                dns_challenge: false,
                dns_provider: "".to_string(),
                dns_service_url: "".to_string(),
            },
        )
        .await
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("panel"), "{message}");
        assert!(message.contains("could not be persisted"), "{message}");
    }

    #[tokio::test]
    async fn test_clear_stale_http_tokens() {
        use super::{HTTP_01_TOKEN_REMARK, clear_stale_http_tokens};
        use pingap_config::{Category, StorageConf};

        let dir = tempfile::TempDir::new().unwrap();
        let manager = Arc::new(
            new_file_config_manager(&format!(
                "{}?separation=true",
                dir.path().to_string_lossy()
            ))
            .unwrap(),
        );
        let now = 1_800_000_000_u64;
        let token = |created_at: Option<u64>, remark: &str| StorageConf {
            category: "config".to_string(),
            value: "key-auth".to_string(),
            secret: None,
            remark: Some(remark.to_string()),
            created_at,
        };
        // Older than an order can live: removable.
        manager
            .update(
                Category::Storage,
                "stale",
                &token(Some(now - 9 * 24 * 3600), HTTP_01_TOKEN_REMARK),
            )
            .await
            .unwrap();
        // Fresh: an in-flight validation on any instance may still need it.
        manager
            .update(
                Category::Storage,
                "fresh",
                &token(Some(now - 60), HTTP_01_TOKEN_REMARK),
            )
            .await
            .unwrap();
        // No created_at: written before the field existed - removable.
        manager
            .update(
                Category::Storage,
                "legacy",
                &token(None, HTTP_01_TOKEN_REMARK),
            )
            .await
            .unwrap();
        // A person's storage entry: wrong remark, never touched however old.
        manager
            .update(
                Category::Storage,
                "user-data",
                &token(Some(now - 999 * 3600), "my secret"),
            )
            .await
            .unwrap();
        // The manual DNS task's TXT value: swept by age like a token.
        manager
            .update(
                Category::Storage,
                "manual-txt",
                &token(
                    Some(now - 9 * 24 * 3600),
                    crate::dns_manual::MANUAL_DNS_REMARK,
                ),
            )
            .await
            .unwrap();

        let removed = clear_stale_http_tokens(&manager, now).await.unwrap();
        assert_eq!(3, removed);

        let left = manager.load_all().await.unwrap();
        let left = left.storages.unwrap();
        assert!(left.contains_key("fresh"));
        assert!(left.contains_key("user-data"));
        assert!(!left.contains_key("stale"));
        assert!(!left.contains_key("legacy"));
        assert!(!left.contains_key("manual-txt"));

        // Nothing left to do on the next run.
        assert_eq!(0, clear_stale_http_tokens(&manager, now).await.unwrap());
    }

    /// D24: the previous 24h window deleted tokens that orders still backing
    /// off needed, which the CA saw as a 404 (`token not found`). Given a
    /// token's creation time and the state its order can still be in, only
    /// tokens older than a whole order lifetime may go.
    #[test]
    fn test_http_token_cleanup_keeps_in_flight_orders() {
        use super::{
            ACME_ORDER_LIFETIME_SECS, HTTP_01_TOKEN_MAX_AGE,
            http_token_is_stale,
        };
        let now = 1_800_000_000_u64;
        let age = |secs: u64| Some(now - secs);

        // Order just started: in flight, the token must stay.
        assert!(!http_token_is_stale(age(0), now));
        // Order still retrying after a day: the old rule deleted this token.
        assert!(!http_token_is_stale(age(24 * 3600 + 1), now));
        // Order at the end of its lifetime: still possibly in flight.
        assert!(!http_token_is_stale(age(ACME_ORDER_LIFETIME_SECS), now));
        // Lifetime plus the margin: no order can still be waiting on it.
        assert!(http_token_is_stale(age(HTTP_01_TOKEN_MAX_AGE + 1), now));
        // Written before `created_at` existed: removable.
        assert!(http_token_is_stale(None, now));
    }

    /// D03: the failure line the control plane relies on must name the domains
    /// (for site attribution) and the real error (for the row's reason).
    #[test]
    fn test_acme_failure_event_is_attributable() {
        use super::{ACME_FAILURE_MARKER, Error, acme_failure_event_message};

        let error = Error::Fail {
            category: "poll_ready".to_string(),
            message: "API error: Invalid response from http://mirror.liveflowhub.com/.well-known/acme-challenge/abc: 404 (urn:ietf:params:acme:error:unauthorized)".to_string(),
        };
        let message = acme_failure_event_message(
            &[
                "mirror.liveflowhub.com".to_string(),
                "www.mirror.liveflowhub.com".to_string(),
            ],
            &error,
        );
        assert!(message.starts_with(&format!("{ACME_FAILURE_MARKER} ")));
        assert!(message.contains(
            "domain=mirror.liveflowhub.com,www.mirror.liveflowhub.com"
        ));
        assert!(message.contains("404"));
        assert!(!message.contains('\n'));

        // A multiline error must stay a single event line.
        let multiline = Error::Fail {
            category: "poll_ready".to_string(),
            message: "line one\nline two".to_string(),
        };
        let message = acme_failure_event_message(
            &["a.example.com".to_string()],
            &multiline,
        );
        assert!(!message.contains('\n'));
        assert!(message.contains("line one line two"));
    }

    #[test]
    fn test_account_storage_name() {
        use super::account_storage_name;
        assert_eq!("lets_encrypt_account", account_storage_name(true));
        assert_eq!("lets_encrypt_staging_account", account_storage_name(false));
    }

    #[test]
    fn failure_text_redacts_url_queries() {
        use super::redact_url_queries;
        let text = "provider https://dns.example/update?access_key_secret=topsecret failed";
        let redacted = redact_url_queries(text);
        assert!(!redacted.contains("topsecret"));
        assert!(redacted.contains("?[redacted]"));
        assert!(redacted.ends_with("failed"));
    }

    #[test]
    fn failed_certificate_retries_back_off() {
        use super::retry_delay;
        use std::time::Duration;
        assert_eq!(retry_delay(1), Duration::from_secs(5 * 60));
        assert_eq!(retry_delay(2), Duration::from_secs(15 * 60));
        assert_eq!(retry_delay(3), Duration::from_secs(30 * 60));
        assert_eq!(retry_delay(4), Duration::from_secs(60 * 60));
        assert_eq!(retry_delay(5), Duration::from_secs(6 * 60 * 60));
        assert_eq!(retry_delay(100), Duration::from_secs(6 * 60 * 60));
    }

    #[test]
    fn staging_is_opt_in_only() {
        use super::acme_production_from_value;

        // Default and every non-truthy spelling keep production.
        assert!(acme_production_from_value(None));
        assert!(acme_production_from_value(Some("")));
        assert!(acme_production_from_value(Some("false")));
        assert!(acme_production_from_value(Some("0")));
        assert!(acme_production_from_value(Some("  nope  ")));
        // Only the documented opt-ins select staging.
        assert!(!acme_production_from_value(Some("1")));
        assert!(!acme_production_from_value(Some("true")));
        assert!(!acme_production_from_value(Some(" YES ")));
        assert!(!acme_production_from_value(Some("On")));
        assert!(!acme_production_from_value(Some("staging")));
        assert!(!acme_production_from_value(Some(" STAGE ")));
        assert!(acme_production_from_value(Some("production")));
    }

    #[test]
    fn test_is_valid_challenge_token() {
        // Well-formed base64url tokens are accepted.
        assert!(is_valid_challenge_token("abcXYZ0123_-"));

        // Empty, traversal and percent-encoded tokens are rejected.
        assert!(!is_valid_challenge_token(""));
        assert!(!is_valid_challenge_token("../certificate/foo"));
        assert!(!is_valid_challenge_token("..%2Fcertificate"));
        assert!(!is_valid_challenge_token("a.b"));
        assert!(!is_valid_challenge_token("a/b"));
    }

    #[test]
    fn test_order_is_actionable() {
        use super::order_is_actionable;
        use instant_acme::OrderStatus;

        // Fresh order: challenges must be run.
        assert!(order_is_actionable(&OrderStatus::Pending));
        // Let's Encrypt returns Ready directly when every authorization is
        // still valid (< 30 days old) - this exact case used to be rejected
        // with "order is not pending" and wedged issuance in a loop.
        assert!(order_is_actionable(&OrderStatus::Ready));

        // Nothing we can do about these: fail loudly instead of looping.
        assert!(!order_is_actionable(&OrderStatus::Processing));
        assert!(!order_is_actionable(&OrderStatus::Valid));
        assert!(!order_is_actionable(&OrderStatus::Invalid));
    }
}
