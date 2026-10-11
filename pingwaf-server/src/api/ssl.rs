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
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Set,
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
    let items: Vec<CertificateResponse> =
        rows.into_iter().map(Into::into).collect();
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

    let model =
        insert_certificate(&state, &site, payload, Some(&current.email))
            .await?;
    Ok(
        (StatusCode::CREATED, Json(CertificateResponse::from(model)))
            .into_response(),
    )
}

/// Validates and stores one certificate row, then tells the site's agents.
async fn insert_certificate(
    state: &AppState,
    site: &site::Model,
    payload: CreateCertificateRequest,
    actor: Option<&str>,
) -> Result<site_certificates::Model, ApiError> {
    let site_id = site.id;
    let domain = payload.domain.trim().to_lowercase();
    if domain.is_empty() || domain.len() > 255 {
        return Err(ApiError::BadRequest(
            "domain must be 1-255 characters".to_string(),
        ));
    }
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

    let status = if payload.cert_pem.is_some() {
        cert_status::ACTIVE
    } else if payload.acme_email.is_some() {
        cert_status::PENDING
    } else {
        cert_status::ACTIVE
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
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %site_id, cert_id = %model.id, "certificate created");
    write_cert_event(
        &state.db,
        model.id,
        site_id,
        "created",
        format!(
            "Certificate for {} created (status: {})",
            model.domain, model.status
        ),
        None,
    )
    .await;
    touch_site(state, site_id).await?;
    notify_config_changed(state, site_id, actor).await;

    Ok(model)
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
    Ok(Json(CertificateResponse::from(row)))
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
        let cert_domain = non_empty(&payload.domain)
            .map(|value| value.to_lowercase())
            .unwrap_or_else(|| row.domain.clone());
        ensure_acme_wildcard_supported(
            &site,
            &split_domains(&cert_domain),
            Some(&challenge),
        )?;
    }

    let mut active: site_certificates::ActiveModel = row.into();

    if let Some(domain) = non_empty(&payload.domain) {
        active.domain = Set(domain.to_lowercase());
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

    Ok(Json(CertificateResponse::from(updated)))
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
    write_cert_event(
        &state.db,
        target,
        id,
        "deleted",
        "Certificate deleted".to_string(),
        None,
    )
    .await;
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

    let posture = save_tls_posture(&state, &site, &payload).await?;
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
    let items: Vec<CertificateWithSite> = rows
        .into_iter()
        .map(|row| {
            let (site_domain, site_name) =
                sites.get(&row.site_id).cloned().unwrap_or_default();
            CertificateWithSite {
                certificate: CertificateResponse::from(row),
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

    let model =
        insert_certificate(&state, &site, payload, Some(&current.email))
            .await?;

    if activate {
        let posture = TlsPostureRequest {
            https_enabled: Some(true),
            certificate_id: Some(model.id),
            ..Default::default()
        };
        save_tls_posture(&state, &site, &posture).await?;
        tracing::info!(site_id = %site_id, cert_id = %model.id, "certificate activated");
        touch_site(&state, site_id).await?;
        notify_config_changed(&state, site_id, Some(&current.email)).await;
    }

    Ok(
        (StatusCode::CREATED, Json(CertificateResponse::from(model)))
            .into_response(),
    )
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
    Ok(Json(CertificateResponse::from(row)))
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
