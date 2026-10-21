//! Managed mTLS material: the certificate authorities a site trusts, the
//! client certificates issued from them, and the write-back that pushes the
//! trust anchor to `site_ssl` (and from there to the edge).

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_write, non_empty, parse_uuid};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{
    ca_source, client_cert_status, mtls_ca, mtls_client_certificate, site_ssl,
};
use crate::pki::mtls::{
    bundle_pem, generate_ca, issue_client_cert, parse_cert_meta, MtlsError,
};

/// A CA as shown in the dashboard — never includes the private key.
#[derive(Debug, Serialize)]
pub struct CaResponse {
    pub id: Uuid,
    pub site_id: Uuid,
    pub name: String,
    pub source: String,
    pub cert_pem: String,
    pub has_private_key: bool,
    pub subject_dn: String,
    pub serial: String,
    pub fingerprint_sha256: String,
    pub expected_organization: Option<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    /// Client certificates issued from this CA (all statuses).
    pub certificate_count: u64,
}

impl CaResponse {
    fn from_model(model: mtls_ca::Model, certificate_count: u64) -> Self {
        Self {
            id: model.id,
            site_id: model.site_id,
            name: model.name,
            source: model.source,
            cert_pem: model.cert_pem,
            has_private_key: model.key_pem.is_some(),
            subject_dn: model.subject_dn,
            serial: model.serial,
            fingerprint_sha256: model.fingerprint_sha256,
            expected_organization: model.expected_organization,
            not_before: model.not_before,
            not_after: model.not_after,
            is_active: model.is_active,
            created_at: model.created_at,
            certificate_count,
        }
    }
}

/// A CA creation response; `key_pem` is returned exactly once.
#[derive(Debug, Serialize)]
pub struct CaCreatedResponse {
    #[serde(flatten)]
    pub ca: CaResponse,
    pub key_pem: Option<String>,
}

/// A client certificate as shown in the dashboard — never includes the key.
#[derive(Debug, Serialize)]
pub struct ClientCertResponse {
    pub id: Uuid,
    pub site_id: Uuid,
    pub ca_id: Uuid,
    pub ca_name: Option<String>,
    pub name: String,
    pub common_name: String,
    pub organization: Option<String>,
    pub serial: String,
    pub fingerprint_sha256: String,
    pub cert_pem: String,
    pub has_private_key: bool,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub status: String,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl ClientCertResponse {
    fn from_model(
        model: mtls_client_certificate::Model,
        ca_name: Option<String>,
    ) -> Self {
        Self {
            id: model.id,
            site_id: model.site_id,
            ca_id: model.ca_id,
            ca_name,
            name: model.name,
            common_name: model.common_name,
            organization: model.organization,
            serial: model.serial,
            fingerprint_sha256: model.fingerprint_sha256,
            cert_pem: model.cert_pem,
            has_private_key: model.key_pem.is_some(),
            not_before: model.not_before,
            not_after: model.not_after,
            status: model.status,
            revoked_at: model.revoked_at,
            revocation_reason: model.revocation_reason,
            created_at: model.created_at,
        }
    }
}

/// An issue response; `key_pem` is returned exactly once.
#[derive(Debug, Serialize)]
pub struct ClientCertIssuedResponse {
    #[serde(flatten)]
    pub certificate: ClientCertResponse,
    pub key_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCaRequest {
    pub name: String,
    /// Import an existing CA certificate instead of generating one. The
    /// private key is never uploaded: imported CAs only act as trust anchors.
    #[serde(default)]
    pub cert_pem: Option<String>,
    /// Organization every certificate from this CA must carry.
    #[serde(default)]
    pub organization: Option<String>,
    /// Validity of a generated CA, in days.
    #[serde(default = "default_ca_days")]
    pub validity_days: i64,
}

#[derive(Debug, Deserialize)]
pub struct IssueCertificateRequest {
    pub ca_id: Uuid,
    /// Label shown in the dashboard; defaults to the common name.
    #[serde(default)]
    pub name: Option<String>,
    /// Subject common name; defaults to the label.
    #[serde(default)]
    pub common_name: Option<String>,
    /// Subject organization; defaults to the CA's expected organization.
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default = "default_client_cert_days")]
    pub validity_days: i64,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/mtls/cas", get(list_cas).post(create_ca))
        .route(
            "/sites/{site_id}/mtls/cas/{ca_id}",
            axum::routing::delete(delete_ca),
        )
        .route(
            "/sites/{site_id}/mtls/certificates",
            get(list_certificates).post(issue_certificate),
        )
        .route(
            "/sites/{site_id}/mtls/certificates/{cert_id}",
            axum::routing::delete(delete_certificate),
        )
        .route(
            "/sites/{site_id}/mtls/certificates/{cert_id}/revoke",
            post(revoke_certificate),
        )
        .route(
            "/sites/{site_id}/mtls/certificates/{cert_id}/download",
            get(download_certificate),
        )
}

fn default_ca_days() -> i64 {
    3650
}

fn default_client_cert_days() -> i64 {
    365
}

fn mtls_error(err: MtlsError) -> ApiError {
    match err {
        MtlsError::Invalid(message) => ApiError::BadRequest(message),
        MtlsError::Certificate(message) => {
            ApiError::BadRequest(format!("invalid certificate: {message}"))
        },
    }
}

/// `time` (used by rcgen) to `chrono` (used by the database models).
pub(crate) fn to_utc(value: time::OffsetDateTime) -> DateTime<Utc> {
    DateTime::from_timestamp(value.unix_timestamp(), 0).unwrap_or_else(Utc::now)
}

/// Rejects empty/oversized labels and values that would break DN rendering.
fn validate_label(
    value: &str,
    what: &str,
    max: usize,
) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max {
        return Err(ApiError::BadRequest(format!(
            "{what} must be 1-{max} characters"
        )));
    }
    if trimmed.chars().any(|ch| ch.is_control() || ch == '/') {
        return Err(ApiError::BadRequest(format!(
            "{what} must not contain control characters or '/'"
        )));
    }
    Ok(trimmed.to_string())
}

/// Loads the site's SSL row, creating it when the site has never had one.
async fn site_ssl_row(
    state: &AppState,
    site_id: Uuid,
    domain: &str,
) -> Result<site_ssl::Model, ApiError> {
    if let Some(row) = site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
    {
        return Ok(row);
    }
    let active = site_ssl::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site_id),
        cert_pem: Set(None),
        key_pem: Set(None),
        issuer: Set(None),
        domain: Set(domain.to_string()),
        expires_at: Set(None),
        auto_renew: Set(true),
        acme_email: Set(None),
        acme_challenge_type: Set(None),
        acme_dns_provider: Set(None),
        acme_dns_config: Set(None),
        https_enabled: Set(false),
        min_tls_version: Set(crate::models::tls_version::TLS_12.to_string()),
        max_tls_version: Set(None),
        self_signed: Set(false),
        certificate_id: Set(None),
        mtls_enabled: Set(false),
        mtls_client_ca: Set(None),
        mtls_organization: Set(None),
        mtls_require_client_cert: Set(false),
        hsts_enabled: Set(false),
        hsts_max_age: Set(0),
        always_use_https: Set(false),
        http1_enabled: Set(true),
        http2_enabled: Set(true),
        created_at: Set(Utc::now()),
    };
    Ok(active.insert(&state.db).await?)
}

/// Recomputes the trust anchor stored on `site_ssl` from the active CAs and
/// pushes the site to its agents.
///
/// A site with no active CA gets `mtls_client_ca = NULL`; when every active CA
/// demands the same organization, an empty `mtls_organization` adopts it (an
/// operator-set value is never overwritten).
async fn sync_trust_anchor(
    state: &AppState,
    site: &crate::models::site::Model,
    actor: Option<&str>,
) -> Result<(), ApiError> {
    let cas = mtls_ca::Entity::find()
        .filter(mtls_ca::Column::SiteId.eq(site.id))
        .filter(mtls_ca::Column::IsActive.eq(true))
        .order_by_asc(mtls_ca::Column::CreatedAt)
        .all(&state.db)
        .await?;

    let bundle = bundle_pem(
        &cas.iter().map(|ca| ca.cert_pem.clone()).collect::<Vec<_>>(),
    );
    let mut organizations = cas
        .iter()
        .filter_map(|ca| ca.expected_organization.clone())
        .collect::<Vec<_>>();
    organizations.sort();
    organizations.dedup();
    let shared_organization =
        (organizations.len() == 1).then(|| organizations[0].clone());

    let row = site_ssl_row(state, site.id, &site.domain).await?;
    let mut active: site_ssl::ActiveModel = row.clone().into();
    let bundle = non_empty(&Some(bundle));
    if row.mtls_enabled && bundle.is_none() {
        // Removing the last CA would leave mTLS enabled with nothing to verify
        // against, which the API refuses everywhere else.
        active.mtls_enabled = Set(false);
        active.mtls_require_client_cert = Set(false);
        active.mtls_organization = Set(None);
    }
    active.mtls_client_ca = Set(bundle);
    if row.mtls_organization.is_none() {
        active.mtls_organization = Set(shared_organization);
    }
    active.update(&state.db).await?;

    touch_site(state, site.id).await?;
    notify_config_changed(state, site.id, actor).await;
    Ok(())
}

/// `GET /api/v1/sites/{site_id}/mtls/cas`
async fn list_cas(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<CaResponse>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let rows = mtls_ca::Entity::find()
        .filter(mtls_ca::Column::SiteId.eq(id))
        .order_by_asc(mtls_ca::Column::CreatedAt)
        .all(&state.db)
        .await?;
    let certificates = mtls_client_certificate::Entity::find()
        .filter(mtls_client_certificate::Column::SiteId.eq(id))
        .all(&state.db)
        .await?;
    let mut counts: std::collections::HashMap<Uuid, u64> =
        std::collections::HashMap::new();
    for cert in certificates {
        *counts.entry(cert.ca_id).or_insert(0) += 1;
    }

    Ok(Json(
        rows.into_iter()
            .map(|ca| {
                let count = counts.get(&ca.id).copied().unwrap_or(0);
                CaResponse::from_model(ca, count)
            })
            .collect(),
    ))
}

/// `POST /api/v1/sites/{site_id}/mtls/cas`
async fn create_ca(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<CreateCaRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let site = load_site_write(&state.db, id, &current).await?;
    let name = validate_label(&payload.name, "name", 200)?;
    let organization = match non_empty(&payload.organization) {
        Some(org) => Some(validate_label(&org, "organization", 255)?),
        None => None,
    };

    let (source, material) = match non_empty(&payload.cert_pem) {
        Some(pem) => {
            let meta = parse_cert_meta(&pem).map_err(mtls_error)?;
            if !meta.is_ca {
                return Err(ApiError::BadRequest(
                    "the uploaded certificate is not a certificate authority"
                        .to_string(),
                ));
            }
            (
                ca_source::IMPORTED.to_string(),
                crate::pki::mtls::KeyMaterial {
                    cert_pem: pem,
                    key_pem: None,
                    meta,
                },
            )
        },
        None => (
            ca_source::GENERATED.to_string(),
            generate_ca(&name, organization.as_deref(), payload.validity_days)
                .map_err(mtls_error)?,
        ),
    };

    let row = mtls_ca::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        name: Set(name),
        source: Set(source),
        cert_pem: Set(material.cert_pem),
        key_pem: Set(material.key_pem.clone()),
        subject_dn: Set(material.meta.subject_dn.clone()),
        serial: Set(material.meta.serial.clone()),
        fingerprint_sha256: Set(material.meta.fingerprint_sha256.clone()),
        expected_organization: Set(organization),
        not_before: Set(to_utc(material.meta.not_before)),
        not_after: Set(to_utc(material.meta.not_after)),
        is_active: Set(true),
        created_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, ca = %row.id, "mTLS CA added");
    sync_trust_anchor(&state, &site, Some(&current.email)).await?;

    let response = CaCreatedResponse {
        ca: CaResponse::from_model(row, 0),
        key_pem: material.key_pem,
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// `DELETE /api/v1/sites/{site_id}/mtls/cas/{ca_id}`
async fn delete_ca(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, ca_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&ca_id, "ca id")?;
    let site = load_site_write(&state.db, id, &current).await?;

    let row = mtls_ca::Entity::find_by_id(target)
        .filter(mtls_ca::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("CA {target} not found")))?;

    let issued = mtls_client_certificate::Entity::find()
        .filter(mtls_client_certificate::Column::CaId.eq(target))
        .all(&state.db)
        .await?;
    if !issued.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "CA still signs {} client certificate(s); revoke and delete them first",
            issued.len()
        )));
    }

    mtls_ca::Entity::delete_by_id(row.id)
        .exec(&state.db)
        .await?;
    tracing::info!(site_id = %id, ca = %target, "mTLS CA removed");
    sync_trust_anchor(&state, &site, Some(&current.email)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/sites/{site_id}/mtls/certificates`
async fn list_certificates(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<ClientCertResponse>>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let rows = mtls_client_certificate::Entity::find()
        .filter(mtls_client_certificate::Column::SiteId.eq(id))
        .order_by_asc(mtls_client_certificate::Column::CreatedAt)
        .all(&state.db)
        .await?;
    let names = ca_names(&state, id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| {
                let ca_name = names.get(&row.ca_id).cloned();
                ClientCertResponse::from_model(row, ca_name)
            })
            .collect(),
    ))
}

async fn ca_names(
    state: &AppState,
    site_id: Uuid,
) -> Result<std::collections::HashMap<Uuid, String>, ApiError> {
    let rows = mtls_ca::Entity::find()
        .filter(mtls_ca::Column::SiteId.eq(site_id))
        .all(&state.db)
        .await?;
    Ok(rows.into_iter().map(|ca| (ca.id, ca.name)).collect())
}

/// `POST /api/v1/sites/{site_id}/mtls/certificates`
async fn issue_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<IssueCertificateRequest>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let ca = mtls_ca::Entity::find_by_id(payload.ca_id)
        .filter(mtls_ca::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("CA {} not found", payload.ca_id))
        })?;
    if !ca.is_active {
        return Err(ApiError::BadRequest(
            "this CA is no longer active; it cannot sign new certificates"
                .to_string(),
        ));
    }
    let Some(ca_key) = ca.key_pem.as_deref().filter(|k| !k.trim().is_empty())
    else {
        return Err(ApiError::BadRequest(
            "this CA was imported without a private key, so PingWAF cannot sign certificates with it"
                .to_string(),
        ));
    };

    let common_name = match non_empty(&payload.common_name) {
        Some(value) => validate_label(&value, "common_name", 255)?,
        None => validate_label(
            &payload.name.clone().unwrap_or_default(),
            "name",
            200,
        )
        .map_err(|_| {
            ApiError::BadRequest(
                "provide a name or a common_name for the certificate"
                    .to_string(),
            )
        })?,
    };
    let name = match non_empty(&payload.name) {
        Some(value) => validate_label(&value, "name", 200)?,
        None => common_name.clone(),
    };
    let organization = match non_empty(&payload.organization) {
        Some(org) => Some(validate_label(&org, "organization", 255)?),
        None => ca.expected_organization.clone(),
    };

    let material = issue_client_cert(
        &ca.cert_pem,
        ca_key,
        &common_name,
        organization.as_deref(),
        payload.validity_days,
    )
    .map_err(mtls_error)?;

    let row = mtls_client_certificate::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(id),
        ca_id: Set(ca.id),
        name: Set(name),
        common_name: Set(common_name),
        organization: Set(organization),
        serial: Set(material.meta.serial.clone()),
        fingerprint_sha256: Set(material.meta.fingerprint_sha256.clone()),
        cert_pem: Set(material.cert_pem.clone()),
        key_pem: Set(material.key_pem.clone()),
        not_before: Set(to_utc(material.meta.not_before)),
        not_after: Set(to_utc(material.meta.not_after)),
        status: Set(client_cert_status::ACTIVE.to_string()),
        revoked_at: Set(None),
        revocation_reason: Set(None),
        created_at: Set(Utc::now()),
    }
    .insert(&state.db)
    .await?;

    tracing::info!(site_id = %id, certificate = %row.id, "mTLS client certificate issued");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    let response = ClientCertIssuedResponse {
        certificate: ClientCertResponse::from_model(row, Some(ca.name)),
        key_pem: material.key_pem,
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// `POST /api/v1/sites/{site_id}/mtls/certificates/{cert_id}/revoke`
async fn revoke_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, cert_id)): Path<(String, String)>,
    payload: Option<Json<RevokeRequest>>,
) -> Result<Json<ClientCertResponse>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&cert_id, "certificate id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = mtls_client_certificate::Entity::find_by_id(target)
        .filter(mtls_client_certificate::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("certificate {target} not found"))
        })?;
    if row.status == client_cert_status::REVOKED {
        return Err(ApiError::BadRequest(
            "this certificate is already revoked".to_string(),
        ));
    }

    let reason = payload
        .as_ref()
        .and_then(|Json(payload)| non_empty(&payload.reason))
        .map(|reason| validate_label(&reason, "reason", 255))
        .transpose()?;

    let mut active: mtls_client_certificate::ActiveModel = row.into();
    active.status = Set(client_cert_status::REVOKED.to_string());
    active.revoked_at = Set(Some(Utc::now()));
    active.revocation_reason = Set(reason);
    let updated = active.update(&state.db).await?;

    tracing::info!(site_id = %id, certificate = %target, "mTLS client certificate revoked");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    let names = ca_names(&state, id).await?;
    let ca_name = names.get(&updated.ca_id).cloned();
    Ok(Json(ClientCertResponse::from_model(updated, ca_name)))
}

/// `DELETE /api/v1/sites/{site_id}/mtls/certificates/{cert_id}`
async fn delete_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, cert_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&cert_id, "certificate id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = mtls_client_certificate::Entity::find_by_id(target)
        .filter(mtls_client_certificate::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("certificate {target} not found"))
        })?;
    // An active certificate has to be revoked first: deleting it outright
    // would silently re-admit a client that is still holding the key.
    if row.status == client_cert_status::ACTIVE {
        return Err(ApiError::BadRequest(
            "revoke the certificate before deleting it".to_string(),
        ));
    }

    mtls_client_certificate::Entity::delete_by_id(row.id)
        .exec(&state.db)
        .await?;
    tracing::info!(site_id = %id, certificate = %target, "mTLS client certificate removed");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/sites/{site_id}/mtls/certificates/{cert_id}/download`
///
/// Serves the certificate (and the key, while it is still stored) as one PEM
/// bundle, so the operator installs a single file on the client.
async fn download_certificate(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, cert_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    let target = parse_uuid(&cert_id, "certificate id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = mtls_client_certificate::Entity::find_by_id(target)
        .filter(mtls_client_certificate::Column::SiteId.eq(id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("certificate {target} not found"))
        })?;

    let mut bundle = row.cert_pem.trim().to_string();
    bundle.push('\n');
    if let Some(key) = row.key_pem.as_deref().filter(|k| !k.trim().is_empty()) {
        bundle.push_str(key.trim());
        bundle.push('\n');
    }
    let filename = download_filename(&row.name);

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pem-file".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        bundle,
    )
        .into_response())
}

/// Keeps the download name to characters that are safe in a header, and never
/// lets it start with a dot so it cannot be mistaken for a hidden/relative path.
fn download_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches(|ch| matches!(ch, '.' | '_'));
    if cleaned.is_empty() {
        "client-certificate.pem".to_string()
    } else {
        format!("{cleaned}.pem")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::mtls::{
        normalise_fingerprint, CertMeta, MAX_CA_DAYS, MAX_CLIENT_CERT_DAYS,
    };

    #[test]
    fn labels_are_normalised_and_guarded() {
        assert_eq!(
            validate_label("  laptop  ", "name", 200).unwrap(),
            "laptop"
        );
        assert!(validate_label("", "name", 200).is_err());
        assert!(validate_label("   ", "name", 200).is_err());
        assert!(validate_label(&"a".repeat(201), "name", 200).is_err());
        assert!(validate_label("line\nbreak", "name", 200).is_err());
        assert!(validate_label("a/b", "name", 200).is_err());
        assert_eq!(
            validate_label(&"a".repeat(200), "name", 200).unwrap().len(),
            200
        );
    }

    #[test]
    fn download_names_stay_safe() {
        assert_eq!(download_filename("laptop 1"), "laptop_1.pem");
        assert_eq!(download_filename("../etc/passwd"), "etc_passwd.pem");
        assert_eq!(download_filename("***"), "client-certificate.pem");
    }

    #[test]
    fn a_generated_ca_round_trips_through_the_store() {
        let material = generate_ca("Site CA", Some("Acme"), 30).unwrap();
        let meta: CertMeta = parse_cert_meta(&material.cert_pem).unwrap();
        assert!(meta.is_ca);
        assert_eq!(meta.fingerprint_sha256, material.meta.fingerprint_sha256);
        assert_eq!(
            normalise_fingerprint(&meta.fingerprint_sha256),
            meta.fingerprint_sha256
        );
    }

    #[test]
    fn validity_defaults_match_the_documented_limits() {
        assert_eq!(default_ca_days(), 3650);
        assert!(default_ca_days() <= MAX_CA_DAYS);
        assert_eq!(default_client_cert_days(), 365);
        assert!(default_client_cert_days() <= MAX_CLIENT_CERT_DAYS);
    }
}
