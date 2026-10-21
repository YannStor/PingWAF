//! SSL/TLS certificate management: upload, ACME issuance, renewal and settings.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{
    ensure_acme_wildcard_supported, load_site_read, load_site_write, non_empty,
    parse_uuid, scope_site, Page, Pagination,
};
use crate::api::error::ApiError;
use crate::api::sites::{
    load_tls_posture, save_tls_posture, touch_site, TlsPosture,
    TlsPostureRequest,
};
use crate::api::state::AppState;
use crate::api::validation::{validate_certificate_and_key, validate_pem_pair};
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{
    acme_challenge, certificate_events, site, site_certificates,
};

/// Certificate status values.
pub(crate) mod cert_status {
    pub const ACTIVE: &str = "active";
    pub const PENDING: &str = "pending";
    pub const EXPIRED: &str = "expired";
    pub const FAILED: &str = "failed";

    pub fn is_valid(status: &str) -> bool {
        matches!(status, ACTIVE | PENDING | EXPIRED | FAILED)
    }
}

/// Public certificate representation (never exposes the private key).
#[derive(Debug, Serialize)]
pub struct CertificateResponse {
    pub id: Uuid,
    pub site_id: Uuid,
    pub domain: String,
    pub issuer: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub auto_renew: bool,
    pub acme_email: Option<String>,
    pub acme_challenge_type: String,
    pub acme_dns_provider: Option<String>,
    pub acme_dns_config: Option<serde_json::Value>,
    pub status: String,
    /// Why the last ACME issuance attempt was given up on; null while an
    /// order is healthy or after it succeeded.
    pub failure_reason: Option<String>,
    pub has_certificate: bool,
    pub has_private_key: bool,
    /// Advisory only: certificate hostnames this site does not serve. Filled
    /// in on every endpoint that returns a certificate — create/update, and
    /// the list/show reads too, so the dashboard badge renders on a page
    /// refresh rather than only right after a save (H3) — but never turned
    /// into a rejection: uploading the certificate before adding its hostname
    /// (or for another site) is a legitimate workflow.
    ///
    /// Empty (not null) when nothing is wrong; `None` only survives on a
    /// response built from a model without a site lookup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<site_certificates::Model> for CertificateResponse {
    fn from(m: site_certificates::Model) -> Self {
        Self {
            id: m.id,
            site_id: m.site_id,
            domain: m.domain,
            issuer: m.issuer,
            not_before: m.not_before,
            expires_at: m.expires_at,
            auto_renew: m.auto_renew,
            acme_email: m.acme_email,
            acme_challenge_type: m.acme_challenge_type,
            acme_dns_provider: m.acme_dns_provider,
            acme_dns_config: m.acme_dns_config,
            status: m.status,
            failure_reason: m.failure_reason,
            has_certificate: m.cert_pem.is_some(),
            has_private_key: m.key_pem.is_some(),
            warnings: None,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// SSL settings response (from site_ssl or derived).
#[derive(Debug, Serialize)]
pub struct SslSettingsResponse {
    pub https_enabled: bool,
    pub min_tls_version: String,
    pub max_tls_version: Option<String>,
    pub self_signed: bool,
    pub certificate_id: Option<Uuid>,
    pub mtls_enabled: bool,
    pub has_mtls_client_ca: bool,
    pub mtls_organization: Option<String>,
    pub mtls_require_client_cert: bool,
    pub hsts_enabled: bool,
    pub hsts_max_age: i32,
    pub always_use_https: bool,
    pub http1_enabled: bool,
    pub http2_enabled: bool,
}

impl From<TlsPosture> for SslSettingsResponse {
    fn from(posture: TlsPosture) -> Self {
        Self {
            https_enabled: posture.https_enabled,
            min_tls_version: posture.min_tls_version,
            max_tls_version: posture.max_tls_version,
            self_signed: posture.self_signed,
            certificate_id: posture.certificate_id,
            mtls_enabled: posture.mtls_enabled,
            has_mtls_client_ca: posture.mtls_client_ca.is_some(),
            mtls_organization: posture.mtls_organization,
            mtls_require_client_cert: posture.mtls_require_client_cert,
            hsts_enabled: posture.hsts_enabled,
            hsts_max_age: posture.hsts_max_age,
            always_use_https: posture.always_use_https,
            http1_enabled: posture.http1_enabled,
            http2_enabled: posture.http2_enabled,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct CreateCertificateRequest {
    pub domain: String,
    #[serde(default)]
    pub cert_pem: Option<String>,
    #[serde(default)]
    pub key_pem: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default = "default_true")]
    pub auto_renew: bool,
    #[serde(default)]
    pub acme_email: Option<String>,
    #[serde(default = "default_challenge_type")]
    pub acme_challenge_type: String,
    #[serde(default)]
    pub acme_dns_provider: Option<String>,
    #[serde(default)]
    pub acme_dns_config: Option<serde_json::Value>,
    /// Site the certificate is uploaded for, when it is not created through the
    /// site's own certificate list.
    #[serde(default)]
    pub site_id: Option<Uuid>,
    /// Attach the certificate to its site (and turn HTTPS on) right away.
    #[serde(default)]
    pub activate: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateCertificateRequest {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub cert_pem: Option<String>,
    #[serde(default)]
    pub key_pem: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub auto_renew: Option<bool>,
    #[serde(default)]
    pub acme_email: Option<String>,
    #[serde(default)]
    pub acme_challenge_type: Option<String>,
    #[serde(default)]
    pub acme_dns_provider: Option<String>,
    #[serde(default)]
    pub acme_dns_config: Option<serde_json::Value>,
    #[serde(default)]
    pub status: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_challenge_type() -> String {
    "http-01".to_string()
}

/// Splits the comma-separated hostname list a certificate row stores.
fn split_domains(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

/// True when the wildcard `cert` (`*.example.com`) matches the concrete
/// hostname `host` under the usual single-label rule: a certificate wildcard
/// covers exactly one label, never `a.b.example.com`. Both inputs are already
/// lower-cased.
fn wildcard_covers(cert: &str, host: &str) -> bool {
    let Some(parent) = cert.strip_prefix("*.") else {
        return false;
    };
    // The wildcard label itself never matches its own parent
    // (`*.example.com` does not cover `example.com`).
    let Some(label) = host.strip_suffix(parent).and_then(|head| {
        head.strip_suffix('.').filter(|label| !label.is_empty())
    }) else {
        return false;
    };
    // Exactly one label, and not a wildcard: `a.b.example.com` and
    // `*.example.com` are both outside a `*.example.com` certificate.
    !label.is_empty() && !label.contains('.') && !label.contains('*')
}

/// Multi-label wildcard suffix check, mirroring the data-plane
/// `lookup_with_wildcard` (pingwaf-agent cache): a site wildcard
/// `*.example.com` covers any depth of subdomain (`a.example.com`,
/// `a.b.example.com`) but not the parent `example.com` itself.
fn site_wildcard_covers(site: &str, cert: &str) -> bool {
    let Some(parent) = site.strip_prefix("*.") else {
        return false;
    };
    // The wildcard never covers its own parent (`*.example.com` does not
    // serve `example.com`), and only concrete hostnames match — not
    // another wildcard.
    let Some(head) =
        cert.strip_suffix(parent).and_then(|h| h.strip_suffix('.'))
    else {
        return false;
    };
    !head.is_empty() && !head.contains('*')
}

/// Whether `served` (a hostname the site answers for) is covered by the
/// certificate hostname `cert`. The two directions are not symmetric: a
/// wildcard on the certificate side covers any single label under it
/// (the TLS standard), while a wildcard on the site side uses multi-label
/// suffix matching, mirroring the agent's data-plane rule lookup — the
/// site serves `*.example.com`, so both `api.example.com` and
/// `a.b.example.com` are served (`example.com` itself is not).
fn cert_name_covers_site_name(cert: &str, served: &str) -> bool {
    cert == served
        || wildcard_covers(cert, served)
        || site_wildcard_covers(served, cert)
}

/// Certificate hostnames the site does not serve.
///
/// The control plane attaches a certificate to whatever hostnames it names,
/// but the site only answers for `site.domain` plus its `alternate_domains`.
/// A certificate carrying a hostname outside that set is almost always a
/// mistake — the wrong site, or a copy-pasted SAN — and used to be saved
/// silently. It is reported as a warning rather than rejected: naming a host
/// the operator is about to add, or one served through a separate site, is a
/// legitimate workflow, and taking HTTPS down over it would be worse.
///
/// Returns the uncovered certificate hostnames in certificate order with
/// duplicates removed (both sides are de-duplicated and lower-cased before
/// the comparison).
fn uncovered_certificate_domains(
    cert_domain: &str,
    site_domain: &str,
    alternate: &[String],
) -> Vec<String> {
    let served: Vec<String> = std::iter::once(site_domain.to_ascii_lowercase())
        .chain(alternate.iter().map(|domain| domain.to_ascii_lowercase()))
        .filter(|domain| !domain.is_empty())
        .collect();

    let mut uncovered: Vec<String> = Vec::new();
    for name in split_domains(cert_domain) {
        let name = name.to_ascii_lowercase();
        if served
            .iter()
            .any(|host| cert_name_covers_site_name(&name, host))
        {
            continue;
        }
        if !uncovered.iter().any(|existing| existing == &name) {
            uncovered.push(name);
        }
    }
    uncovered
}

/// Builds the advisory warnings for a saved certificate, logging each one.
/// Never fails and never blocks the save.
fn certificate_warnings(
    site_id: Uuid,
    site: &site::Model,
    cert_domain: &str,
) -> Vec<String> {
    let warnings = uncovered_certificate_domains(
        cert_domain,
        &site.domain,
        &site.alternate_domains,
    );
    for domain in &warnings {
        tracing::warn!(
            site_id = %site_id,
            domain = %domain,
            "certificate covers hosts the site does not serve"
        );
    }
    warnings
        .iter()
        .map(|domain| {
            format!("certificate domain {domain} is not served by this site")
        })
        .collect()
}

/// The hostnames each site answers for, keyed by site id.
///
/// `(domain, alternate_domains)` is the whole of what
/// [`certificate_warnings_for`] needs, so a list endpoint can fetch it once
/// for the whole page instead of joining per row (H3 N+1). Sites that are
/// gone from the table simply have no entry, which reads as "serves nothing".
type SiteHostnames = HashMap<Uuid, (String, Vec<String>)>;

/// Loads [`SiteHostnames`] for the given site ids in **one** query.
///
/// A database error degrades to an empty map (i.e. "no warnings") rather than
/// propagating: these warnings are advisory, and failing a certificate listing
/// because the advisory decoration could not be computed would be worse than
/// showing the certificates without it.
async fn site_hostname_index(
    state: &AppState,
    site_ids: impl IntoIterator<Item = Uuid>,
) -> SiteHostnames {
    let ids: Vec<Uuid> = {
        let mut ids: Vec<Uuid> = site_ids.into_iter().collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    };
    if ids.is_empty() {
        return HashMap::new();
    }
    match site::Entity::find()
        .filter(site::Column::Id.is_in(ids))
        .all(&state.db)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|model| (model.id, (model.domain, model.alternate_domains)))
            .collect(),
        Err(err) => {
            tracing::warn!(
                error = %err,
                "could not load site hostnames for certificate warnings"
            );
            HashMap::new()
        },
    }
}

/// Computes the advisory warnings for a certificate read back from the
/// database, using hostnames already loaded by [`site_hostname_index`].
///
/// Same wording as [`certificate_warnings`] minus the per-row `tracing::warn!`:
/// a *listing* of N already-saved certificates would otherwise log N WARN
/// lines on every dashboard refresh, drowning the one line that mattered when
/// the certificate was saved.
fn certificate_warnings_for(
    served: &SiteHostnames,
    site_id: Uuid,
    cert_domain: &str,
) -> Vec<String> {
    let Some((domain, alternate)) = served.get(&site_id) else {
        return Vec::new();
    };
    uncovered_certificate_domains(cert_domain, domain, alternate)
        .iter()
        .map(|domain| {
            format!("certificate domain {domain} is not served by this site")
        })
        .collect()
}

/// Longest single hostname a certificate row may name. A DNS name is at most
/// 253 characters (RFC 1035), and one wildcard label still fits inside it.
const MAX_SINGLE_HOSTNAME_LEN: usize = 253;

/// Anti-abuse bound on the whole comma-separated list. The `domain` column is
/// TEXT — a certificate legitimately covering five hostnames already exceeds
/// the old 255-character limit (see
/// `m20240101_000021_site_alternate_domains`) — so the cap here only exists to
/// stop a caller parking an unbounded blob in the row.
const MAX_CERT_DOMAIN_LIST_LEN: usize = 4096;

/// Normalises and vets one hostname from a certificate's hostname list.
///
/// Returns the trimmed, lower-cased form; a single leading `*.` wildcard label
/// is allowed, anything else about the name must look like DNS labels.
fn validate_cert_hostname(raw: &str) -> Result<String, ApiError> {
    let domain = raw.trim().to_ascii_lowercase();
    let invalid = |reason: &str| {
        ApiError::BadRequest(format!("invalid domain: {reason}"))
    };

    if domain.is_empty() {
        return Err(invalid("must be 1-253 characters"));
    }
    if domain.len() > MAX_SINGLE_HOSTNAME_LEN {
        return Err(invalid("must be 1-253 characters"));
    }
    // Control characters and the separators that would make the value
    // ambiguous to whoever parses it as a host: `a/b` reads as a path and
    // `a:443` as host plus port. `,` is the list separator and is handled by
    // the caller, never inside one hostname.
    if domain.chars().any(|ch| {
        ch.is_ascii_control()
            || ch.is_whitespace()
            || matches!(ch, '/' | ':' | '\\' | '@' | '?' | '#' | ',')
    }) {
        return Err(invalid("contains a forbidden character"));
    }

    // One wildcard label, and only as the leftmost label.
    let rest = match domain.strip_prefix("*.") {
        Some(rest) => rest,
        None => domain.as_str(),
    };
    if rest.contains('*') {
        return Err(invalid("wildcard is only allowed as a leading '*.'"));
    }
    if rest.is_empty() {
        return Err(invalid("wildcard needs a parent domain"));
    }
    // Empty labels (`..`, a leading or trailing `.`) and over-long labels.
    for label in rest.split('.') {
        if label.is_empty() {
            return Err(invalid("empty label"));
        }
        if label.len() > 63 {
            return Err(invalid("label exceeds 63 characters"));
        }
    }

    Ok(domain)
}

/// Normalises and vets the `domain` a certificate row is stored under.
///
/// The column holds the comma-separated list of hostnames the certificate is
/// issued for — `a.com,b.com` is an existing, supported input, and five names
/// legitimately exceed 255 characters. Each segment is therefore validated as
/// one hostname and the whole list only carries an anti-abuse bound.
///
/// The value is not merely cosmetic: it names the hostnames the certificate is
/// issued for (the ACME order is built from it) and it is what the control
/// plane matches against a site's hostnames. A string carrying `/`, `:` or
/// control characters used to be stored verbatim, so a caller could park a
/// path, a port or a smuggled header inside a field the edge later parses as a
/// hostname.
///
/// Returns the normalised list: `,`-joined, lower-cased, no surrounding
/// spaces, input order preserved, duplicates dropped. An empty segment
/// (`a.com,,b.com`, a trailing `,`) is a bad request rather than something to
/// silently skip.
pub(crate) fn validate_cert_domain_list(raw: &str) -> Result<String, ApiError> {
    let invalid = |reason: &str| {
        ApiError::BadRequest(format!("invalid domain: {reason}"))
    };

    // Bound the input before splitting so a huge blob is refused cheaply.
    if raw.len() > MAX_CERT_DOMAIN_LIST_LEN {
        return Err(invalid("domain list exceeds 4096 bytes"));
    }
    if raw.trim().is_empty() {
        return Err(invalid("must name at least one hostname"));
    }

    let mut hostnames: Vec<String> = Vec::new();
    for segment in raw.split(',') {
        if segment.trim().is_empty() {
            return Err(invalid(
                "empty entry in the comma-separated domain list",
            ));
        }
        let hostname = validate_cert_hostname(segment)?;
        if !hostnames.iter().any(|existing| existing == &hostname) {
            hostnames.push(hostname);
        }
    }
    if hostnames.is_empty() {
        return Err(invalid("must name at least one hostname"));
    }

    let joined = hostnames.join(",");
    // Deduplication only shortens the list, so this can only fire on input
    // that was already over the bound; kept as a belt-and-braces check.
    if joined.len() > MAX_CERT_DOMAIN_LIST_LEN {
        return Err(invalid("domain list exceeds 4096 bytes"));
    }
    Ok(joined)
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/sites/{site_id}/certificates",
            get(list_certificates).post(create_certificate),
        )
        .route(
            "/sites/{site_id}/certificates/{cert_id}",
            get(show_certificate)
                .put(update_certificate)
                .delete(delete_certificate),
        )
        .route(
            "/sites/{site_id}/certificates/{cert_id}/renew",
            axum::routing::post(renew_certificate),
        )
        .route(
            "/sites/{site_id}/ssl-settings",
            get(get_ssl_settings).put(update_ssl_settings),
        )
        // Global aliases. The dashboard's SSL/TLS page spans sites: it lists
        // every application, uploads or renews a certificate for a chosen site,
        // and summarises what is about to lapse.
        .route(
            "/certificates",
            get(list_all_certificates).post(create_global_certificate),
        )
        .route("/certificates/summary", get(certificate_summary))
        .route(
            "/certificates/{cert_id}",
            get(show_global_certificate)
                .put(update_global_certificate)
                .delete(delete_global_certificate),
        )
        .route(
            "/certificates/{cert_id}/renew",
            axum::routing::post(renew_global_certificate),
        )
        .route(
            "/certificates/{cert_id}/events",
            get(list_certificate_events),
        )
        .route("/ssl-events", get(list_all_events))
}

/// `GET /api/v1/sites/{site_id}/certificates`
async fn list_certificates(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<CertificateResponse>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;
    let pagination = query.pagination.normalise();

    let paginator = site_certificates::Entity::find()
        .filter(site_certificates::Column::SiteId.eq(id))
        .order_by_desc(site_certificates::Column::CreatedAt)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    // H3: the advisory warnings are only useful where the dashboard reads
    // certificates back, so the list fills them in too — one site lookup, then
    // pure string comparisons per row. A failed lookup degrades to "no
    // warnings" rather than failing the read: the list is a listing, and
    // holding it hostage to an advisory field would be the wrong trade.
    let served = site_hostname_index(&state, std::iter::once(id)).await;
    let items: Vec<CertificateResponse> = rows
        .into_iter()
        .map(|row| {
            let mut response = CertificateResponse::from(row);
            response.warnings = Some(certificate_warnings_for(
                &served,
                response.site_id,
                &response.domain,
            ));
            response
        })
        .collect();
    Ok(Json(Page::new(items, total, pagination)))
}

/// `POST /api/v1/sites/{site_id}/certificates`
async fn create_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreateCertificateRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let site = load_site_write(&state.db, id, &current).await?;

    let model = insert_certificate(&state.db, &site, payload).await?;
    announce_certificate_created(&state, &model, Some(&current.email)).await;
    // Advisory only: a certificate naming hosts this site does not serve is
    // saved anyway, with the mismatch reported back to the operator.
    let warnings = certificate_warnings(site.id, &site, &model.domain);
    let mut response = CertificateResponse::from(model);
    response.warnings = Some(warnings);
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Validates and stores one certificate row.
///
/// Takes the connection explicitly so callers can run it inside a transaction:
/// `create_global_certificate` must not leave a certificate behind when the
/// attached TLS posture fails to validate. Side effects that assume the row is
/// committed — the audit event, the site touch and the agent push — belong to
/// [`announce_certificate_created`], run after the surrounding transaction
/// commits.
async fn insert_certificate<C: ConnectionTrait>(
    db: &C,
    site: &site::Model,
    payload: CreateCertificateRequest,
) -> Result<site_certificates::Model, ApiError> {
    let site_id = site.id;
    let domain = validate_cert_domain_list(&payload.domain)?;
    if !acme_challenge::is_valid(&payload.acme_challenge_type) {
        return Err(ApiError::BadRequest(format!(
            "invalid acme_challenge_type '{}'",
            payload.acme_challenge_type
        )));
    }
    // An ACME order without an uploaded PEM is issued against the site's whole
    // hostname set, which a wildcard may not contain under http-01.
    if payload.cert_pem.is_none() && payload.acme_email.is_some() {
        ensure_acme_wildcard_supported(
            site,
            &split_domains(&domain),
            Some(&payload.acme_challenge_type),
        )?;
    }

    // Reject unparsable or mismatched PEM pairs before they reach the data
    // plane: a broken certificate takes the site's HTTPS down, and this path
    // used to store whatever string arrived (2026-10-18 audit). The checks
    // live in `validation`, shared with the update path.
    let has_pem = payload
        .cert_pem
        .as_deref()
        .is_some_and(|pem| !pem.trim().is_empty());
    match (
        payload
            .cert_pem
            .as_deref()
            .filter(|pem| !pem.trim().is_empty()),
        payload
            .key_pem
            .as_deref()
            .filter(|pem| !pem.trim().is_empty()),
    ) {
        (Some(cert_pem), Some(key_pem)) => {
            validate_certificate_and_key(cert_pem, key_pem)?;
        },
        (Some(cert_pem), None) => validate_pem_pair(cert_pem, None)?,
        // A key without its certificate cannot be served; storing it would
        // leave the row looking complete.
        (None, Some(_)) => {
            return Err(ApiError::BadRequest(
                "key_pem requires cert_pem".to_string(),
            ));
        },
        (None, None) => {},
    }

    let status = if has_pem {
        cert_status::ACTIVE
    } else if payload.acme_email.is_some() {
        cert_status::PENDING
    } else {
        // Neither a PEM pair nor an ACME order: nothing to serve, and the
        // old code still marked the row ACTIVE (2026-10-18 audit).
        return Err(ApiError::BadRequest(
            "provide cert_pem/key_pem or an acme_email".to_string(),
        ));
    };

    let timestamp = Utc::now();
    let model = site_certificates::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site_id),
        domain: Set(domain),
        cert_pem: Set(payload.cert_pem),
        key_pem: Set(payload.key_pem),
        issuer: Set(payload.issuer),
        not_before: Set(payload.not_before),
        expires_at: Set(payload.expires_at),
        auto_renew: Set(payload.auto_renew),
        acme_email: Set(payload.acme_email),
        acme_challenge_type: Set(payload.acme_challenge_type),
        acme_dns_provider: Set(payload.acme_dns_provider),
        acme_dns_config: Set(payload.acme_dns_config),
        status: Set(status.to_string()),
        failure_reason: Set(None),
        created_at: Set(timestamp),
        updated_at: Set(timestamp),
    }
    .insert(db)
    .await?;

    tracing::info!(site_id = %site_id, cert_id = %model.id, "certificate created");
    Ok(model)
}

/// Records the audit event for a committed certificate and pushes the change
/// to the site's agents. The event is best-effort (like every certificate
/// event); the touch failure is logged, not propagated — the row already
/// exists, so an error response would misrepresent the outcome.
async fn announce_certificate_created(
    state: &AppState,
    model: &site_certificates::Model,
    actor: Option<&str>,
) {
    write_cert_event(
        &state.db,
        model.id,
        model.site_id,
        "created",
        format!(
            "Certificate for {} created (status: {})",
            model.domain, model.status
        ),
        None,
    )
    .await;
    if let Err(err) = touch_site(state, model.site_id).await {
        tracing::warn!(
            cert_id = %model.id,
            error = %err,
            "could not touch the site after certificate creation"
        );
    }
    notify_config_changed(state, model.site_id, actor).await;
}

/// `GET /api/v1/sites/{site_id}/certificates/{cert_id}`
async fn show_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, cert_id)): Path<(String, String)>,
) -> Result<Json<CertificateResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&cert_id, "certificate id")?;
    load_site_read(&state.db, id, &current).await?;

    let row = find_certificate(&state, id, target).await?;
    let served = site_hostname_index(&state, std::iter::once(id)).await;
    let mut response = CertificateResponse::from(row);
    response.warnings = Some(certificate_warnings_for(
        &served,
        response.site_id,
        &response.domain,
    ));
    Ok(Json(response))
}

/// `PUT /api/v1/sites/{site_id}/certificates/{cert_id}`
async fn update_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, cert_id)): Path<(String, String)>,
    Json(payload): Json<UpdateCertificateRequest>,
) -> Result<Json<CertificateResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&cert_id, "certificate id")?;
    let site = load_site_write(&state.db, id, &current).await?;

    let row = find_certificate(&state, id, target).await?;

    // Replacing either half of the stored pair re-validates the pair as it
    // will be after this request: the update path used to store an unparsable
    // certificate (or a key that does not match it) that create would have
    // refused, which takes the site's HTTPS down on the next push
    // (2026-10-19 audit, D07).
    let stored_cert =
        row.cert_pem.as_deref().filter(|pem| !pem.trim().is_empty());
    let stored_key =
        row.key_pem.as_deref().filter(|pem| !pem.trim().is_empty());
    let next_cert = match payload.cert_pem.as_deref() {
        Some(pem) => Some(pem).filter(|pem| !pem.trim().is_empty()),
        None => stored_cert,
    };
    let next_key = match payload.key_pem.as_deref() {
        Some(pem) => Some(pem).filter(|pem| !pem.trim().is_empty()),
        None => stored_key,
    };
    // A replacement certificate validates against the stored key and a
    // replacement key against the stored certificate, so a mismatched pair
    // cannot be assembled one request at a time.
    if let Some(cert_pem) = next_cert {
        validate_pem_pair(cert_pem, next_key)?;
    } else if next_key.is_some() {
        return Err(ApiError::BadRequest(
            "key_pem requires a certificate: upload cert_pem with it"
                .to_string(),
        ));
    }

    // The domain is vetted first, exactly as on the create path: the ACME
    // wildcard guard below reads the hostname list, so letting it run on the
    // unvalidated `payload.domain` would both check a different string from
    // the one stored and reorder the two failures (audit R-03). A rejected
    // domain must leave the stored certificate exactly as it was.
    let next_domain = match non_empty(&payload.domain) {
        Some(raw) => Some(validate_cert_domain_list(&raw)?),
        None => None,
    };
    // The list the certificate will name once this request commits: the
    // normalised payload domain when one was sent, the stored one otherwise.
    let effective_domain = next_domain.as_deref().unwrap_or(&row.domain);

    // An ACME order without a stored PEM is issued against the site's whole
    // hostname set, which a wildcard may not contain under http-01.
    let cert_missing = match payload.cert_pem.as_deref() {
        Some(pem) => pem.trim().is_empty(),
        None => row
            .cert_pem
            .as_deref()
            .is_none_or(|pem| pem.trim().is_empty()),
    };
    let acme_email = match payload.acme_email.as_ref() {
        Some(email) => non_empty(&Some(email.clone())),
        None => non_empty(&row.acme_email),
    };
    if cert_missing && acme_email.is_some() {
        let challenge = non_empty(&payload.acme_challenge_type)
            .unwrap_or_else(|| row.acme_challenge_type.clone());
        ensure_acme_wildcard_supported(
            &site,
            &split_domains(effective_domain),
            Some(&challenge),
        )?;
    }

    let mut active: site_certificates::ActiveModel = row.into();

    if let Some(domain) = next_domain {
        active.domain = Set(domain);
    }
    if let Some(cert) = payload.cert_pem {
        active.cert_pem = Set(Some(cert));
    }
    if let Some(key) = payload.key_pem {
        active.key_pem = Set(Some(key));
    }
    if let Some(issuer) = payload.issuer {
        active.issuer = Set(non_empty(&Some(issuer)));
    }
    if let Some(nb) = payload.not_before {
        active.not_before = Set(Some(nb));
    }
    if let Some(exp) = payload.expires_at {
        active.expires_at = Set(Some(exp));
    }
    if let Some(ar) = payload.auto_renew {
        active.auto_renew = Set(ar);
    }
    if let Some(email) = payload.acme_email {
        active.acme_email = Set(non_empty(&Some(email)));
    }
    if let Some(ct) = non_empty(&payload.acme_challenge_type) {
        if !acme_challenge::is_valid(&ct) {
            return Err(ApiError::BadRequest(format!(
                "invalid acme_challenge_type '{ct}'"
            )));
        }
        active.acme_challenge_type = Set(ct);
    }
    if let Some(provider) = payload.acme_dns_provider {
        active.acme_dns_provider = Set(non_empty(&Some(provider)));
    }
    if let Some(config) = payload.acme_dns_config {
        active.acme_dns_config = Set(Some(config));
    }
    if let Some(status) = non_empty(&payload.status) {
        if !cert_status::is_valid(&status) {
            return Err(ApiError::BadRequest(format!(
                "invalid certificate status '{status}'"
            )));
        }
        active.status = Set(status.clone());
        // Re-arming an order discards the reason the previous one was given
        // up on, so a stale failure never outlives its retry.
        if status == cert_status::PENDING {
            active.failure_reason = Set(None);
        }
    }
    active.updated_at = Set(Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, cert_id = %target, "certificate updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    // The warning is evaluated against the certificate as it is stored now,
    // not against the payload alone: an update that only replaces the PEM
    // still has to surface a hostname mismatch introduced earlier.
    let warnings = certificate_warnings(site.id, &site, &updated.domain);
    let mut response = CertificateResponse::from(updated);
    response.warnings = Some(warnings);
    Ok(Json(response))
}

/// `DELETE /api/v1/sites/{site_id}/certificates/{cert_id}`
async fn delete_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, cert_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&cert_id, "certificate id")?;
    load_site_write(&state.db, id, &current).await?;
    find_certificate(&state, id, target).await?;

    site_certificates::Entity::delete_by_id(target)
        .exec(&state.db)
        .await?;

    tracing::info!(site_id = %id, cert_id = %target, "certificate deleted");
    // Deleting the certificate cascades to its events, so the deletion's own
    // audit trail must not point at the deleted row — referencing it violates
    // `fk_certificate_events_certificate_id` and the event is silently lost.
    let event = certificate_events::ActiveModel {
        id: Set(Uuid::new_v4()),
        certificate_id: Set(None),
        site_id: Set(Some(id)),
        event_type: Set("deleted".to_string()),
        message: Set(format!("Certificate {target} deleted")),
        details: Set(None),
        created_at: Set(Utc::now()),
    };
    if let Err(err) = event.insert(&state.db).await {
        tracing::warn!(%err, "failed to write certificate event");
    }
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /api/v1/sites/{site_id}/certificates/{cert_id}/renew`
async fn renew_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, cert_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&cert_id, "certificate id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_certificate(&state, id, target).await?;
    if row.acme_email.is_none() {
        return Err(ApiError::BadRequest(
            "certificate is not ACME-managed; cannot auto-renew".to_string(),
        ));
    }

    let domain = row.domain.clone();
    // Mark as pending renewal; the previous failure (if any) is superseded
    // by this retry.
    let mut active: site_certificates::ActiveModel = row.into();
    active.status = Set(cert_status::PENDING.to_string());
    active.failure_reason = Set(None);
    active.updated_at = Set(Utc::now());
    active.update(&state.db).await?;

    tracing::info!(site_id = %id, cert_id = %target, "certificate renewal triggered");
    write_cert_event(
        &state.db,
        target,
        id,
        "renewal_requested",
        format!("Manual renewal requested for {}", domain),
        None,
    )
    .await;

    // Without this the renewal used to be a dud: only the status column
    // changed, the agents were never told to re-pull the site config, and
    // the edge kept serving the old certificate until it lapsed.
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(serde_json::json!({
        "message": "renewal initiated",
        "certificate_id": target,
        "status": cert_status::PENDING,
    })))
}

/// `GET /api/v1/sites/{site_id}/ssl-settings`
async fn get_ssl_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<SslSettingsResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let posture = load_tls_posture(&state, id).await?;
    Ok(Json(posture.into()))
}

/// `PUT /api/v1/sites/{site_id}/ssl-settings`
///
/// Persists the TLS switches on the site's `site_ssl` row, creating the row if
/// the site has none yet — the settings and the certificate share the row, so
/// either endpoint can establish it.
async fn update_ssl_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<TlsPostureRequest>,
) -> Result<Json<SslSettingsResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let site = load_site_write(&state.db, id, &current).await?;

    let posture = save_tls_posture(&state.db, &site, &payload).await?;
    tracing::info!(site_id = %id, "SSL settings updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(posture.into()))
}

/// Loads a certificate scoped to a site.
async fn find_certificate(
    state: &AppState,
    site_id: Uuid,
    cert_id: Uuid,
) -> Result<site_certificates::Model, ApiError> {
    site_certificates::Entity::find_by_id(cert_id)
        .filter(site_certificates::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("certificate {cert_id} not found"))
        })
}

// ─── Global certificate management ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GlobalListQuery {
    /// Restrict the list to one site. Optional for administrators, who would
    /// otherwise have to walk their sites one by one.
    #[serde(default)]
    pub site_id: Option<String>,
    /// Filter on the certificate status (`active`, `pending`, …).
    #[serde(default)]
    pub status: Option<String>,
    #[serde(flatten)]
    pub pagination: Pagination,
}

/// A certificate plus the site it belongs to, for the cross-site list.
#[derive(Debug, Serialize)]
pub struct CertificateWithSite {
    #[serde(flatten)]
    pub certificate: CertificateResponse,
    pub site_domain: String,
    pub site_name: String,
}

/// Counts behind the global SSL/TLS overview.
#[derive(Debug, Serialize)]
pub struct CertificateSummary {
    pub total: usize,
    pub active: usize,
    pub pending: usize,
    pub failed: usize,
    pub expired: usize,
    /// Certificates that lapse within the next 30 days, lapsed ones included.
    pub expiring_soon: usize,
}

/// Sites the caller may see, mapped to `(domain, name)`.
async fn visible_sites(
    state: &AppState,
    current: &AuthUser,
) -> Result<HashMap<Uuid, (String, String)>, ApiError> {
    let mut condition = Condition::all();
    if !current.is_admin() {
        condition = condition.add(site::Column::UserId.eq(current.id));
    }
    let rows = site::Entity::find()
        .filter(condition)
        .all(&state.db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|model| (model.id, (model.domain, model.name)))
        .collect())
}

/// `GET /api/v1/certificates` — certificate applications across every site the
/// caller sees, newest first.
async fn list_all_certificates(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<GlobalListQuery>,
) -> Result<Json<Page<CertificateWithSite>>, ApiError> {
    let requested = match query.site_id.as_deref() {
        Some(raw) => Some(parse_uuid(raw, "site id")?),
        None => None,
    };
    let sites = visible_sites(&state, &current).await?;
    let pagination = query.pagination.normalise();

    let mut condition = Condition::all();
    if let Some(id) = scope_site(requested, &current)? {
        if !sites.contains_key(&id) {
            return Err(ApiError::NotFound(format!("site {id} not found")));
        }
        condition = condition.add(site_certificates::Column::SiteId.eq(id));
    }
    if let Some(status) = non_empty(&query.status) {
        if !cert_status::is_valid(&status) {
            return Err(ApiError::BadRequest(format!(
                "invalid status '{status}' (supported: active, pending, expired, failed)"
            )));
        }
        condition = condition.add(site_certificates::Column::Status.eq(status));
    }

    let paginator = site_certificates::Entity::find()
        .filter(condition)
        .order_by_desc(site_certificates::Column::CreatedAt)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;
    // H3: one batch lookup for the hostnames of every site on this page (plus
    // the site named in the query, if any), then pure string comparisons — no
    // query per row. Sites outside the caller's visible set are skipped here;
    // their certificates are already filtered out above.
    let served = site_hostname_index(
        &state,
        rows.iter().map(|row| row.site_id).chain(requested),
    )
    .await;
    let items: Vec<CertificateWithSite> = rows
        .into_iter()
        .map(|row| {
            let (site_domain, site_name) =
                sites.get(&row.site_id).cloned().unwrap_or_default();
            let warnings = certificate_warnings_for(
                &served,
                row.site_id,
                row.domain.as_str(),
            );
            let mut certificate = CertificateResponse::from(row);
            certificate.warnings = Some(warnings);
            CertificateWithSite {
                certificate,
                site_domain,
                site_name,
            }
        })
        .collect();
    Ok(Json(Page::new(items, total, pagination)))
}

/// `POST /api/v1/certificates` — upload a certificate or apply for one on
/// behalf of a site.
///
/// `activate` attaches it to its site and turns HTTPS on in the same call, so
/// the dashboard does not have to make a second request.
async fn create_global_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<CreateCertificateRequest>,
) -> Result<Response, ApiError> {
    let Some(raw_site) = payload.site_id else {
        return Err(ApiError::BadRequest(
            "site_id is required: a certificate belongs to a site".to_string(),
        ));
    };
    let site_id = parse_uuid(&raw_site.to_string(), "site id")?;
    let site = load_site_write(&state.db, site_id, &current).await?;
    let activate = payload.activate;

    // The row and the activated posture commit together: a posture failure
    // (bad TLS bounds, a certificate id from another site) must not leave a
    // pending certificate behind, which is how the dashboard used to show an
    // errored request with the task already in the list.
    let txn = state.db.begin().await?;
    let model = insert_certificate(&txn, &site, payload).await?;
    if activate {
        let posture = TlsPostureRequest {
            https_enabled: Some(true),
            certificate_id: Some(model.id),
            ..Default::default()
        };
        save_tls_posture(&txn, &site, &posture).await?;
    }
    txn.commit().await?;

    announce_certificate_created(&state, &model, Some(&current.email)).await;
    if activate {
        tracing::info!(site_id = %site_id, cert_id = %model.id, "certificate activated");
    }

    let warnings = certificate_warnings(site_id, &site, &model.domain);
    let mut response = CertificateResponse::from(model);
    response.warnings = Some(warnings);
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// `GET /api/v1/certificates/{cert_id}`
async fn show_global_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path(cert_id): Path<String>,
) -> Result<Json<CertificateResponse>, ApiError> {
    let target = parse_uuid(&cert_id, "certificate id")?;
    let row = find_certificate_by_id(&state, target).await?;
    load_site_read(&state.db, row.site_id, &current).await?;
    let served =
        site_hostname_index(&state, std::iter::once(row.site_id)).await;
    let mut response = CertificateResponse::from(row);
    response.warnings = Some(certificate_warnings_for(
        &served,
        response.site_id,
        &response.domain,
    ));
    Ok(Json(response))
}

/// `PUT /api/v1/certificates/{cert_id}`
async fn update_global_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path(cert_id): Path<String>,
    payload: Json<UpdateCertificateRequest>,
) -> Result<Json<CertificateResponse>, ApiError> {
    let target = parse_uuid(&cert_id, "certificate id")?;
    let row = find_certificate_by_id(&state, target).await?;
    update_certificate(
        State(state),
        current,
        Path((row.site_id.to_string(), cert_id)),
        payload,
    )
    .await
}

/// `DELETE /api/v1/certificates/{cert_id}`
async fn delete_global_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path(cert_id): Path<String>,
) -> Result<Response, ApiError> {
    let target = parse_uuid(&cert_id, "certificate id")?;
    let row = find_certificate_by_id(&state, target).await?;
    delete_certificate(
        State(state),
        current,
        Path((row.site_id.to_string(), cert_id)),
    )
    .await
}

/// `POST /api/v1/certificates/{cert_id}/renew`
async fn renew_global_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path(cert_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let target = parse_uuid(&cert_id, "certificate id")?;
    let row = find_certificate_by_id(&state, target).await?;
    renew_certificate(
        State(state),
        current,
        Path((row.site_id.to_string(), cert_id)),
    )
    .await
}

/// `GET /api/v1/certificates/summary`
async fn certificate_summary(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<CertificateSummary>, ApiError> {
    let sites = visible_sites(&state, &current).await?;
    let mut summary = CertificateSummary {
        total: 0,
        active: 0,
        pending: 0,
        failed: 0,
        expired: 0,
        expiring_soon: 0,
    };
    if !current.is_admin() && sites.is_empty() {
        return Ok(Json(summary));
    }

    let mut condition = Condition::all();
    if !current.is_admin() {
        condition = condition.add(
            site_certificates::Column::SiteId.is_in(sites.keys().copied()),
        );
    }
    let rows = site_certificates::Entity::find()
        .filter(condition)
        .all(&state.db)
        .await?;

    let soon = Utc::now() + chrono::Duration::days(30);
    summary.total = rows.len();
    for row in &rows {
        match row.status.as_str() {
            cert_status::ACTIVE => summary.active += 1,
            cert_status::PENDING => summary.pending += 1,
            cert_status::FAILED => summary.failed += 1,
            cert_status::EXPIRED => summary.expired += 1,
            _ => {},
        }
        if row.expires_at.is_some_and(|expires_at| expires_at <= soon) {
            summary.expiring_soon += 1;
        }
    }
    Ok(Json(summary))
}

/// Looks a certificate up by id alone; the caller authorises through its site.
async fn find_certificate_by_id(
    state: &AppState,
    cert_id: Uuid,
) -> Result<site_certificates::Model, ApiError> {
    site_certificates::Entity::find_by_id(cert_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("certificate {cert_id} not found"))
        })
}

// ─── Certificate event audit trail ──────────────────────────────────────────

/// Certificate event response.
#[derive(Debug, Serialize)]
pub struct CertificateEventResponse {
    pub id: Uuid,
    pub certificate_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub event_type: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub domain: Option<String>,
    pub site_domain: Option<String>,
}

/// Writes one row into `certificate_events`. Best-effort: logs on failure but
/// does not propagate the error, so event recording never breaks the main flow.
async fn write_cert_event(
    db: &sea_orm::DatabaseConnection,
    certificate_id: Uuid,
    site_id: Uuid,
    event_type: &str,
    message: String,
    details: Option<serde_json::Value>,
) {
    let event = certificate_events::ActiveModel {
        id: Set(Uuid::new_v4()),
        certificate_id: Set(Some(certificate_id)),
        site_id: Set(Some(site_id)),
        event_type: Set(event_type.to_string()),
        message: Set(message),
        details: Set(details),
        created_at: Set(Utc::now()),
    };
    if let Err(err) = event.insert(db).await {
        tracing::warn!(%err, "failed to write certificate event");
    }
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub certificate_id: Option<String>,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(flatten)]
    pub pagination: Pagination,
}

/// `GET /api/v1/certificates/{cert_id}/events`
async fn list_certificate_events(
    State(state): State<AppState>,
    current: AuthUser,
    Path(cert_id): Path<String>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<Page<CertificateEventResponse>>, ApiError> {
    let target = parse_uuid(&cert_id, "certificate id")?;
    let row = find_certificate_by_id(&state, target).await?;
    load_site_read(&state.db, row.site_id, &current).await?;

    let pagination = query.pagination.normalise();
    let mut condition = Condition::all()
        .add(certificate_events::Column::CertificateId.eq(target));
    if let Some(ref et) = non_empty(&query.event_type) {
        condition = condition
            .add(certificate_events::Column::EventType.eq(et.as_str()));
    }

    let paginator = certificate_events::Entity::find()
        .filter(condition)
        .order_by_desc(certificate_events::Column::CreatedAt)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;

    let items = rows
        .into_iter()
        .map(|e| CertificateEventResponse {
            id: e.id,
            certificate_id: e.certificate_id,
            site_id: e.site_id,
            event_type: e.event_type,
            message: e.message,
            details: e.details,
            created_at: e.created_at,
            domain: Some(row.domain.clone()),
            site_domain: None,
        })
        .collect();
    Ok(Json(Page::new(items, total, pagination)))
}

/// `GET /api/v1/ssl-events` — cross-certificate event log for the SSL/TLS page.
async fn list_all_events(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<EventsQuery>,
) -> Result<Json<Page<CertificateEventResponse>>, ApiError> {
    let sites = visible_sites(&state, &current).await?;
    let pagination = query.pagination.normalise();

    let mut condition = Condition::all();
    if !current.is_admin() {
        condition = condition.add(
            certificate_events::Column::SiteId.is_in(sites.keys().copied()),
        );
    }
    if let Some(ref cid) = non_empty(&query.certificate_id) {
        let cert_uuid = parse_uuid(cid, "certificate id")?;
        condition = condition
            .add(certificate_events::Column::CertificateId.eq(cert_uuid));
    }
    if let Some(ref et) = non_empty(&query.event_type) {
        condition = condition
            .add(certificate_events::Column::EventType.eq(et.as_str()));
    }

    let paginator = certificate_events::Entity::find()
        .filter(condition)
        .order_by_desc(certificate_events::Column::CreatedAt)
        .paginate(&state.db, pagination.limit());

    let total = paginator.num_items().await?;
    let rows = paginator.fetch_page(pagination.index()).await?;

    let cert_ids: Vec<Uuid> = rows
        .iter()
        .filter_map(|e| e.certificate_id)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let certs = if cert_ids.is_empty() {
        HashMap::new()
    } else {
        site_certificates::Entity::find()
            .filter(site_certificates::Column::Id.is_in(cert_ids))
            .all(&state.db)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|c| (c.id, c))
            .collect()
    };

    let items = rows
        .into_iter()
        .map(|e| {
            let cert = e.certificate_id.and_then(|cid| certs.get(&cid));
            let site_domain = e
                .site_id
                .and_then(|sid| sites.get(&sid))
                .map(|(d, _)| d.clone());
            CertificateEventResponse {
                id: e.id,
                certificate_id: e.certificate_id,
                site_id: e.site_id,
                event_type: e.event_type,
                message: e.message,
                details: e.details,
                created_at: e.created_at,
                domain: cert.map(|c| c.domain.clone()),
                site_domain,
            }
        })
        .collect();
    Ok(Json(Page::new(items, total, pagination)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-03: one hostname longer than a DNS name is refused before it reaches
    /// the database. The bound is per hostname (253), not per row: the row
    /// holds a comma-separated list and the column is TEXT.
    #[test]
    fn an_overlong_certhostname_domain_is_a_bad_request() {
        let long = format!("{}.example.com", "a".repeat(250));
        assert!(long.len() > MAX_SINGLE_HOSTNAME_LEN);
        let err = validate_cert_hostname(&long).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);

        // The same hostname inside a list is refused too.
        let list = format!("a.com,{long}");
        let err = validate_cert_domain_list(&list).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    /// R-03: the empty string and a blank one are not a domain.
    #[test]
    fn a_blank_certificate_domain_is_a_bad_request() {
        for raw in ["", "   ", "\t\n"] {
            let err = validate_cert_domain_list(raw).unwrap_err();
            assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{raw:?}");
            let err = validate_cert_hostname(raw).unwrap_err();
            assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{raw:?}");
        }
    }

    /// R-03: `/` and `:` would let the value read as a path or a host:port to
    /// whoever parses it downstream, so they are refused rather than stored.
    #[test]
    fn a_certificate_domain_with_a_separator_is_a_bad_request() {
        for raw in [
            "example.com/path",
            "example.com:443",
            "https://example.com",
            "exa mple.com",
            "example.com\u{0}",
            "example.com\r\nX-Injected: 1",
            "example.com#frag",
            "user@example.com",
        ] {
            let err = validate_cert_domain_list(raw).unwrap_err();
            assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{raw:?}");
        }
    }

    /// R-03: empty labels are refused; a leading `*.` is not one.
    #[test]
    fn empty_labels_are_refused_but_a_leading_wildcard_is_not() {
        for raw in [
            "..",
            ".example.com",
            "example.com.",
            "a..b",
            "*",
            "*.",
            "*.*.example.com",
            "a.*.com",
        ] {
            let err = validate_cert_domain_list(raw).unwrap_err();
            assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{raw:?}");
        }
        assert_eq!(
            validate_cert_domain_list("*.example.com").unwrap(),
            "*.example.com"
        );
    }

    /// R-03: the stored form is trimmed and lower-cased, and a legitimate
    /// hostname still passes untouched.
    #[test]
    fn a_valid_certificate_domain_is_normalised() {
        assert_eq!(
            validate_cert_domain_list("  Example.COM  ").unwrap(),
            "example.com"
        );
        assert_eq!(
            validate_cert_domain_list("*.Example.COM").unwrap(),
            "*.example.com"
        );
        assert_eq!(
            validate_cert_domain_list("a-b.c1.example.com").unwrap(),
            "a-b.c1.example.com"
        );
        assert_eq!(
            validate_cert_hostname("  Example.COM  ").unwrap(),
            "example.com"
        );
    }

    /// R-03 (High): the column holds the whole hostname list — `a.com,b.com`
    /// is an existing, accepted input (`split_domains`,
    /// `ensure_acme_wildcard_supported`) — so the validator must split on `,`
    /// instead of treating the row as one hostname.
    #[test]
    fn a_certhostname_list_domain_is_accepted() {
        assert_eq!(
            validate_cert_domain_list("a.com,b.com").unwrap(),
            "a.com,b.com"
        );
        // Whitespace around a segment is cosmetic and must not reject the
        // list, nor survive into the stored value.
        assert_eq!(
            validate_cert_domain_list("a.com, b.com").unwrap(),
            "a.com,b.com"
        );
        assert_eq!(
            validate_cert_domain_list(" A.COM ,\tb.com\n").unwrap(),
            "a.com,b.com"
        );
        // A wildcard and an exact name in one certificate.
        assert_eq!(
            validate_cert_domain_list("*.example.com,api.example.com").unwrap(),
            "*.example.com,api.example.com"
        );
        // Input order is preserved, duplicates drop out.
        assert_eq!(
            validate_cert_domain_list("b.com,a.com,b.com").unwrap(),
            "b.com,a.com"
        );
        // An IDN in its A-label form is an ordinary hostname.
        assert_eq!(
            validate_cert_domain_list("xn--fiq228c.com").unwrap(),
            "xn--fiq228c.com"
        );
    }

    /// R-03 (High): a realistic certificate for five hostnames exceeds the old
    /// 255-character limit and must still be accepted — the bound lives on the
    /// column (TEXT, widened by m20240101_000021_site_alternate_domains), not
    /// on the validator.
    #[test]
    fn a_certhostname_list_domain_over_255_chars_is_accepted() {
        let hosts: Vec<String> = (1..=5)
            .map(|i| {
                format!("{i}.{}.production.example.com", "segment".repeat(5))
            })
            .collect();
        let list = hosts.join(",");
        assert!(list.len() > 255, "{list} is {} chars", list.len());
        assert_eq!(validate_cert_domain_list(&list).unwrap(), list);

        // Five long (but legal) hostnames: still well under the 4096 guard.
        let hosts: Vec<String> = (1..=5)
            .map(|i| format!("{i}{}.example.com", "a".repeat(50)))
            .collect();
        let joined = hosts.join(",");
        assert!(joined.len() > 255);
        assert_eq!(validate_cert_domain_list(&joined).unwrap(), joined);
    }

    /// R-03 (High): an empty segment is a mistake in the client's list, not
    /// something to silently skip — `a.com,,b.com` would otherwise store a
    /// shorter list than the caller asked for.
    #[test]
    fn an_empty_certhostname_list_segment_is_a_bad_request() {
        for raw in [
            "a.com,,b.com",
            "a.com,",
            ",a.com",
            ",,",
            "a.com, ,b.com",
            " , ",
        ] {
            let err = validate_cert_domain_list(raw).unwrap_err();
            assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{raw:?}");
        }
    }

    /// R-03 (High): the anti-abuse bound on the whole list is 4096 bytes, so a
    /// caller cannot park an unbounded blob in a TEXT column.
    #[test]
    fn an_oversized_certhostname_list_is_a_bad_request() {
        let hosts: Vec<String> = (0..205)
            .map(|i| format!("host{i:03}.example.com"))
            .collect();
        let joined = hosts.join(",");
        // Just over the bound: the guard, not the hostnames, is what rejects.
        assert!(joined.len() > 4096, "{}", joined.len());
        assert!(joined.len() < 4096 + 32, "{}", joined.len());
        let err = validate_cert_domain_list(&joined).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);

        // Just under the guard still passes, so the bound is the only limit.
        let hosts: Vec<String> = (0..200)
            .map(|i| format!("host{i:03}.example.com"))
            .collect();
        let joined = hosts.join(",");
        assert!(joined.len() < 4096 && joined.len() > 2048);
        assert_eq!(validate_cert_domain_list(&joined).unwrap(), joined);
    }

    /// R-03 (High): a malicious segment inside an otherwise legal list is
    /// refused, so the list form cannot be used to smuggle a path or a port
    /// past the single-hostname checks.
    #[test]
    fn a_bad_segment_inside_a_certhostname_list_is_a_bad_request() {
        for raw in [
            "a.com,evil.com/path",
            "a.com,evil.com:443",
            "a.com,exa mple.com",
            "a.com,evil.com\u{0}",
            "a.com,..",
            "a.com,*.*.evil.com",
            "a.com,evil.com,",
        ] {
            let err = validate_cert_domain_list(raw).unwrap_err();
            assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{raw:?}");
        }
    }

    /* ── Certificate / site hostname mismatch warnings ─────────────── */

    fn warnings_for(cert: &str, site: &str, alternate: &[&str]) -> Vec<String> {
        let alternate: Vec<String> =
            alternate.iter().map(|d| (*d).to_string()).collect();
        uncovered_certificate_domains(cert, site, &alternate)
    }

    /// A certificate whose hostnames are a subset of the site's must not warn:
    /// this is the overwhelmingly common case and a false positive here would
    /// train operators to ignore the field.
    #[test]
    fn a_certificate_inside_the_site_hostnames_warns_about_nothing() {
        assert!(
            warnings_for("api.example.com", "api.example.com", &[]).is_empty()
        );
        assert!(warnings_for(
            "api.example.com,www.example.com",
            "api.example.com",
            &["www.example.com"]
        )
        .is_empty());
        // Same name on both sides, in any order.
        assert!(warnings_for(
            "www.example.com,api.example.com",
            "api.example.com",
            &["www.example.com"]
        )
        .is_empty());
    }

    /// A certificate covering a hostname the site does not serve is reported
    /// but never rejected — the caller saves it and decides.
    #[test]
    fn a_superset_certificate_warns_about_each_extra_hostname() {
        assert_eq!(
            warnings_for(
                "api.example.com,api.other.com",
                "api.example.com",
                &[]
            ),
            vec!["api.other.com".to_string()]
        );
        // Certificate order is preserved, duplicates collapse.
        assert_eq!(
            warnings_for(
                "b.other.com,a.other.com,b.other.com",
                "api.example.com",
                &[]
            ),
            vec!["b.other.com".to_string(), "a.other.com".to_string()]
        );
    }

    /// Certificate wildcards cover exactly one label (TLS standard);
    /// site wildcards cover any number of labels, matching the agent's
    /// data-plane rule lookup.
    #[test]
    fn a_wildcard_covers_exactly_one_label_in_both_directions() {
        // Certificate wildcard, concrete site hostname: covered.
        assert!(warnings_for("*.example.com", "a.example.com", &[]).is_empty());
        // ... but not the parent itself, and not a deeper name (single label).
        assert_eq!(
            warnings_for("*.example.com", "example.com", &[]),
            vec!["*.example.com".to_string()]
        );
        assert_eq!(
            warnings_for("*.example.com", "a.b.example.com", &[]),
            vec!["*.example.com".to_string()]
        );
        // Site wildcard, concrete certificate hostname: covered at any
        // label depth, mirroring lookup_with_wildcard on the data plane.
        assert!(warnings_for("a.example.com", "*.example.com", &[]).is_empty());
        assert!(
            warnings_for("a.b.example.com", "*.example.com", &[]).is_empty()
        );
        assert!(warnings_for("*.example.com", "*.example.com", &[]).is_empty());
        // ... but the site wildcard does not serve its own parent.
        assert_eq!(
            warnings_for("example.com", "*.example.com", &[]),
            vec!["example.com".to_string()]
        );
        // A different parent is never covered.
        assert_eq!(
            warnings_for("*.example.com", "a.other.com", &[]),
            vec!["*.example.com".to_string()]
        );
        // Alternate hostnames widen the site side just like the primary one.
        assert!(warnings_for(
            "api.example.com",
            "other.com",
            &["*.example.com"]
        )
        .is_empty());
    }

    /// Hostnames are compared case-insensitively: a certificate stored in
    /// mixed case must not produce a warning against a lower-case site.
    #[test]
    fn hostname_comparison_is_case_insensitive() {
        assert!(
            warnings_for("API.Example.COM", "api.example.com", &[]).is_empty()
        );
        assert!(
            warnings_for("api.example.com", "API.EXAMPLE.COM", &[]).is_empty()
        );
        assert!(warnings_for("*.Example.com", "a.example.com", &[]).is_empty());
        // A real mismatch still reports the normalised (lower-case) name.
        assert_eq!(
            warnings_for("API.Other.COM", "api.example.com", &[]),
            vec!["api.other.com".to_string()]
        );
    }

    /* ── H3: warnings on the read path ─────────────────────────────── */

    /// Builds the batch index the list endpoints pass in, without a database.
    fn served_index(entries: &[(Uuid, &str, &[&str])]) -> SiteHostnames {
        entries
            .iter()
            .map(|(id, domain, alternate)| {
                (
                    *id,
                    (
                        (*domain).to_string(),
                        alternate.iter().map(|d| (*d).to_string()).collect(),
                    ),
                )
            })
            .collect()
    }

    /// H3: the list/show read path used to leave `warnings` at `None`, so the
    /// dashboard badge never rendered on a page load — only right after a save.
    /// A superset certificate must now come back with the warning populated.
    #[test]
    fn read_path_warnings_are_populated_for_a_superset_certificate() {
        let site_id = Uuid::new_v4();
        let served = served_index(&[(site_id, "api.example.com", &[])]);
        assert_eq!(
            certificate_warnings_for(
                &served,
                site_id,
                "api.example.com,api.other.com"
            ),
            vec![
                "certificate domain api.other.com is not served by this site"
                    .to_string()
            ]
        );
    }

    /// ... and stays empty (not null) for the common case, so a client can
    /// tell "checked, nothing wrong" from "not checked".
    #[test]
    fn read_path_warnings_are_empty_for_a_subset_certificate() {
        let site_id = Uuid::new_v4();
        let served =
            served_index(&[(site_id, "api.example.com", &["www.example.com"])]);
        assert!(certificate_warnings_for(
            &served,
            site_id,
            "api.example.com,www.example.com"
        )
        .is_empty());
    }

    /// A multi-site page is served by one index: every certificate is checked
    /// against **its own** site's hostnames, never a neighbour's.
    #[test]
    fn read_path_warnings_use_the_certificate_own_site() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let served = served_index(&[
            (a, "a.example.com", &[]),
            (b, "b.example.com", &["alt.example.com"]),
        ]);
        // Correct on site A, wrong on site B — the same hostname flips.
        assert!(
            certificate_warnings_for(&served, a, "a.example.com").is_empty()
        );
        assert_eq!(
            certificate_warnings_for(&served, b, "a.example.com"),
            vec![
                "certificate domain a.example.com is not served by this site"
                    .to_string()
            ]
        );
        assert!(
            certificate_warnings_for(&served, b, "alt.example.com").is_empty()
        );
    }

    /// A certificate whose site is missing from the index (deleted between the
    /// paging query and the lookup) must not panic and must not invent a
    /// warning out of an empty hostname set.
    #[test]
    fn read_path_warnings_do_not_panic_for_an_unknown_site() {
        let site_id = Uuid::new_v4();
        let served = served_index(&[]);
        assert!(
            certificate_warnings_for(&served, site_id, "api.example.com")
                .is_empty()
        );
        // ... nor for a multi-site list where only some sites resolved.
        let known = Uuid::new_v4();
        let served = served_index(&[(known, "a.example.com", &[])]);
        assert!(certificate_warnings_for(&served, known, "a.example.com")
            .is_empty());
        assert!(certificate_warnings_for(&served, site_id, "a.example.com")
            .is_empty());
    }

    /// `split_domains` (not a single-hostname parse) feeds the comparison, so
    /// a comma-separated certificate list is checked hostname by hostname.
    #[test]
    fn a_certificate_list_is_checked_hostname_by_hostname() {
        assert_eq!(
            warnings_for(
                "api.example.com, api.other.com ,www.other.com",
                "api.example.com",
                &[]
            ),
            vec!["api.other.com".to_string(), "www.other.com".to_string()]
        );
    }
}
