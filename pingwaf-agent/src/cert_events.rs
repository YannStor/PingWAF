//! Capture of raw ACME certificate-issuance logs on the agent side.
//!
//! Pingap's ACME machinery emits tracing events under the `pingap::acme`
//! target. An [`AcmeCaptureLayer`] installed on the global tracing subscriber
//! siphons those events into a bounded in-memory buffer, which the
//! control-plane client periodically ships through the `ShipCertEvents` RPC.
//! This is what surfaces the original issuance logs on the management panel,
//! letting administrators diagnose certificate problems.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use prost_types::Timestamp;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use pingwaf_proto::control_plane as proto;

/// Maximum number of buffered events. Oldest entries are dropped once full so
/// a stalled shipper can never block the tracing hot path or grow memory.
const CAPACITY: usize = 1024;

/// Target prefix identifying ACME events emitted by pingap.
const ACME_TARGET_PREFIX: &str = "pingap::acme";

static CERT_EVENT_BUFFER: OnceLock<CertEventBuffer> = OnceLock::new();

/// Global capture buffer, created on first use.
pub fn cert_event_buffer() -> &'static CertEventBuffer {
    CERT_EVENT_BUFFER.get_or_init(CertEventBuffer::new)
}

/// Bounded FIFO of raw certificate events captured from tracing.
pub struct CertEventBuffer {
    entries: Mutex<VecDeque<proto::CertEventEntry>>,
}

impl CertEventBuffer {
    fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(CAPACITY)),
        }
    }

    fn push(&self, entry: proto::CertEventEntry) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entries.len() >= CAPACITY {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Take all buffered events, prefixing each with the agent id.
    pub fn drain(&self, agent_id: &str) -> Vec<proto::CertEventEntry> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries
            .drain(..)
            .map(|mut entry| {
                entry.agent_id = agent_id.to_string();
                entry
            })
            .collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

/// `tracing_subscriber::Layer` that copies every event whose target starts
/// with `pingap::acme` into the global [`CertEventBuffer`].
///
/// [`Layer::enabled`] is deliberately not overridden: per-layer `enabled`
/// results are combined across the whole subscriber stack, so returning
/// `false` here would disable non-ACME callsites for the other layers too.
pub struct AcmeCaptureLayer;

impl<S: Subscriber> Layer<S> for AcmeCaptureLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if !event.metadata().target().starts_with(ACME_TARGET_PREFIX) {
            return;
        }
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let Some(message) = visitor.message else {
            return;
        };
        if message.is_empty() {
            return;
        }
        cert_event_buffer().push(proto::CertEventEntry {
            agent_id: String::new(),
            site_id: String::new(),
            certificate_id: String::new(),
            event_type: "acme_raw".to_string(),
            level: event.metadata().level().as_str().to_string(),
            target: event.metadata().target().to_string(),
            message,
            timestamp: Some(Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
        });
    }
}

/// One site's worth of attribution data: every hostname its certificate
/// covers (apex, wildcard and alternates, lowercased) plus the ids events
/// should be stamped with.
#[derive(Debug, Clone)]
pub struct CertAttribution {
    pub domains: Vec<String>,
    pub site_id: String,
    pub certificate_id: String,
}

/// True when `message` contains `domain` as a whole token. The leading
/// boundary rejects alphanumerics, `-` and `*` but accepts `.` — ACME logs
/// routinely name subdomains of the zone (`_acme-challenge.example.com`,
/// `www.example.com`), and those belong to the same site; the trailing
/// boundary additionally rejects `.` so `example.com` matches neither
/// `example.com.cn` nor `example.com.evil.com`.
fn contains_domain(message: &str, domain: &str) -> bool {
    let bytes = message.as_bytes();
    let mut start = 0;
    while let Some(offset) = message[start..].find(domain) {
        let at = start + offset;
        let before_ok = at == 0 || {
            let b = bytes[at - 1];
            !(b.is_ascii_alphanumeric() || b == b'-' || b == b'*')
        };
        let after = at + domain.len();
        let after_ok = after >= bytes.len() || {
            let b = bytes[after];
            !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'*')
        };
        if before_ok && after_ok {
            return true;
        }
        start = at + 1;
    }
    false
}

/// Stamps buffered ACME events with the site and certificate they belong
/// to. The capture layer cannot know the topology, so events arrive with
/// empty ids and are attributed here — at ship time, against the agent's
/// current site rules — by matching the domains each message names. The
/// longest matching domain wins, so `example.com` never shadows
/// `www.example.com`; a wildcard also matches its apex form because the
/// ACME flow logs identifiers with the `*.` prefix stripped. Events already
/// carrying a site id are left alone.
pub fn attribute_events(
    entries: &mut [proto::CertEventEntry],
    attributions: &[CertAttribution],
) {
    if entries.is_empty() || attributions.is_empty() {
        return;
    }
    // (match text, attribution) pairs, longest first.
    let mut matchers: Vec<(&str, &CertAttribution)> = Vec::new();
    for attribution in attributions {
        for domain in &attribution.domains {
            matchers.push((domain.as_str(), attribution));
            if let Some(apex) = domain.strip_prefix("*.") {
                matchers.push((apex, attribution));
            }
        }
    }
    matchers.sort_by_key(|(domain, _)| std::cmp::Reverse(domain.len()));

    for entry in entries.iter_mut() {
        if !entry.site_id.is_empty() {
            continue;
        }
        for (domain, attribution) in &matchers {
            if contains_domain(&entry.message, domain) {
                entry.site_id = attribution.site_id.clone();
                entry.certificate_id = attribution.certificate_id.clone();
                break;
            }
        }
    }
}

/// Visitor that extracts the `message` field of a tracing event.
#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}
impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }

    fn record_error(
        &mut self,
        field: &Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex as StdMutex, OnceLock};

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn push_drops_oldest_when_full() {
        let _guard = test_lock();
        let buffer = CertEventBuffer::new();
        for i in 0..CAPACITY + 100 {
            buffer.push(proto::CertEventEntry {
                agent_id: String::new(),
                site_id: String::new(),
                certificate_id: String::new(),
                event_type: "acme_raw".to_string(),
                level: "INFO".to_string(),
                target: ACME_TARGET_PREFIX.to_string(),
                message: format!("event {i}"),
                timestamp: None,
            });
        }
        let drained = buffer.drain("agent-1");
        assert_eq!(drained.len(), CAPACITY);
        assert_eq!(drained[0].message, "event 100");
        assert_eq!(
            drained.last().unwrap().message,
            format!("event {}", CAPACITY + 99)
        );
        assert!(drained.iter().all(|entry| entry.agent_id == "agent-1"));
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn layer_captures_acme_events_only() {
        let _guard = test_lock();
        cert_event_buffer().drain("");

        use tracing_subscriber::prelude::*;
        let subscriber = tracing_subscriber::registry().with(AcmeCaptureLayer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "pingap::acme", "order created for example.com");
            tracing::warn!(target: "pingap::acme", "challenge failed: dns timeout");
            tracing::info!(target: "pingap::other", "unrelated event");
        });

        let drained = cert_event_buffer().drain("agent-1");
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].message, "order created for example.com");
        assert_eq!(drained[0].level, "INFO");
        assert_eq!(drained[0].event_type, "acme_raw");
        assert_eq!(drained[0].target, "pingap::acme");
        assert_eq!(drained[1].level, "WARN");
        assert_eq!(drained[1].message, "challenge failed: dns timeout");
    }

    fn entry(message: &str) -> proto::CertEventEntry {
        proto::CertEventEntry {
            agent_id: String::new(),
            site_id: String::new(),
            certificate_id: String::new(),
            event_type: "acme_raw".to_string(),
            level: "INFO".to_string(),
            target: ACME_TARGET_PREFIX.to_string(),
            message: message.to_string(),
            timestamp: None,
        }
    }

    #[test]
    fn attribution_matches_the_longest_domain() {
        let attributions = vec![
            CertAttribution {
                domains: vec!["example.com".to_string()],
                site_id: "site-apex".to_string(),
                certificate_id: "cert-apex".to_string(),
            },
            CertAttribution {
                domains: vec!["www.example.com".to_string()],
                site_id: "site-www".to_string(),
                certificate_id: "cert-www".to_string(),
            },
        ];
        let mut entries = vec![
            entry("save let's encrypt http-01 challenge token www.example.com"),
            entry("acme from let's encrypt example.com"),
            entry("order created for unattributed.org"),
        ];
        attribute_events(&mut entries, &attributions);
        assert_eq!(entries[0].site_id, "site-www");
        assert_eq!(entries[0].certificate_id, "cert-www");
        assert_eq!(entries[1].site_id, "site-apex");
        assert_eq!(entries[2].site_id, "");
    }

    #[test]
    fn attribution_matches_wildcards_and_respects_token_boundaries() {
        let attributions = vec![CertAttribution {
            domains: vec!["*.example.com".to_string()],
            site_id: "site-wild".to_string(),
            certificate_id: "cert-wild".to_string(),
        }];
        let mut entries = vec![
            // The ACME flow strips the `*.` prefix from identifiers.
            entry("start add dns txt record for _acme-challenge.example.com"),
            // Lookalike names must not match.
            entry("order created for notexample.com"),
            entry("order created for example.com.cn"),
        ];
        attribute_events(&mut entries, &attributions);
        assert_eq!(entries[0].site_id, "site-wild");
        assert_eq!(entries[1].site_id, "");
        assert_eq!(entries[2].site_id, "");
    }

    #[test]
    fn attribution_leaves_stamped_events_alone() {
        let attributions = vec![CertAttribution {
            domains: vec!["example.com".to_string()],
            site_id: "site-new".to_string(),
            certificate_id: "cert-new".to_string(),
        }];
        let mut stamped = entry("order created for example.com");
        stamped.site_id = "site-original".to_string();
        let mut entries = vec![stamped];
        attribute_events(&mut entries, &attributions);
        assert_eq!(entries[0].site_id, "site-original");
        assert_eq!(entries[0].certificate_id, "");
    }
}
