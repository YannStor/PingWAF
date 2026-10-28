//! Login security: anomaly-detection settings, GeoIP database upload and
//! the login audit history.
//!
//! The detection itself lives in [`crate::notify::login_anomaly`]; this
//! module is the operator surface — settings, the mmdb upload and the
//! read-back of `login_history`. Everything is administrator-only.

use axum::extract::{DefaultBodyLimit, Multipart, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::login_history;
use crate::notify::login_anomaly::{check_geo_url_host, LoginSecuritySettings};

/// GeoLite2-Country is ~60-70 MB; anything far beyond that is not a geo
/// database worth accepting.
const MAX_MMDB_BYTES: usize = 128 * 1024 * 1024;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login-security", get(show).put(update))
        .route(
            "/login-security/geoip",
            post(upload_geoip).layer(DefaultBodyLimit::max(MAX_MMDB_BYTES)),
        )
        .route("/login-history", get(list_history))
}

/// `GET /api/v1/login-security` — administrators only.
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<LoginSecuritySettings>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(LoginSecuritySettings::load(&state.db).await))
}

#[derive(Debug, Deserialize)]
pub struct UpdateLoginSecurityRequest {
    pub anomaly_enabled: Option<bool>,
    pub baseline_count: Option<u32>,
    pub trusted_header: Option<String>,
    pub trust_last_hop: Option<bool>,
    pub online_geo_url: Option<String>,
    pub geoip_local_enabled: Option<bool>,
}

/// `PUT /api/v1/login-security` — administrators only. Partial update over
/// the stored settings.
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<UpdateLoginSecurityRequest>,
) -> Result<Json<LoginSecuritySettings>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let mut settings = LoginSecuritySettings::load(&state.db).await;
    if let Some(value) = payload.anomaly_enabled {
        settings.anomaly_enabled = value;
    }
    if let Some(value) = payload.baseline_count {
        settings.baseline_count = value;
    }
    if let Some(value) = payload.trusted_header {
        settings.trusted_header = Some(value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty());
    }
    if let Some(value) = payload.trust_last_hop {
        settings.trust_last_hop = value;
    }
    if let Some(value) = payload.online_geo_url {
        settings.online_geo_url = value.trim().to_string();
        // Rejected here (400) before `validate()`, so the reason names the
        // offending host instead of the generic validation message below —
        // and so an SSRF attempt never reaches a persisted row.
        check_geo_url_host(&settings.online_geo_url)
            .map_err(ApiError::BadRequest)?;
    }
    if let Some(value) = payload.geoip_local_enabled {
        settings.geoip_local_enabled = value;
    }
    settings.validate().map_err(ApiError::BadRequest)?;
    settings.store(&state.db).await?;
    tracing::info!(
        actor = %current.email,
        anomaly_enabled = settings.anomaly_enabled,
        "login security settings updated"
    );
    Ok(Json(settings))
}

/// `POST /api/v1/login-security/geoip` — administrators only. Accepts a
/// multipart field named `file` holding a MaxMind-format mmdb; the file is
/// validated by opening it before it replaces the previous database.
async fn upload_geoip(
    State(_state): State<AppState>,
    current: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<Value>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let mut bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| ApiError::BadRequest(err.to_string()))?
    {
        if field.name() == Some("file") {
            bytes = Some(
                field
                    .bytes()
                    .await
                    .map_err(|err| ApiError::BadRequest(err.to_string()))?
                    .to_vec(),
            );
            break;
        }
    }
    let Some(bytes) = bytes else {
        return Err(ApiError::BadRequest(
            "multipart field 'file' is required".to_string(),
        ));
    };
    if bytes.is_empty() {
        return Err(ApiError::BadRequest("uploaded file is empty".to_string()));
    }

    let path = crate::notify::login_anomaly::geoip_mmdb_path();
    let tmp = path.with_extension("mmdb.tmp");
    std::fs::write(&tmp, &bytes)
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    // Validate before replacing: a corrupt upload must keep the old file.
    if let Err(err) = maxminddb::Reader::open_readfile(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ApiError::BadRequest(format!(
            "not a valid mmdb database: {err}"
        )));
    }
    if let Err(err) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ApiError::Internal(err.to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o600),
        );
    }

    tracing::info!(
        actor = %current.email,
        bytes = bytes.len(),
        "GeoIP database uploaded"
    );
    Ok(Json(json!({
        "uploaded": true,
        "bytes": bytes.len(),
    })))
}

/// Upper bound on `offset` for the login audit trail (deep pagination is a
/// full scan per page).
const MAX_LOGIN_HISTORY_OFFSET: u64 = 100_000;

#[derive(Debug, Deserialize)]
pub struct ListHistoryQuery {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub email: Option<String>,
}

/// `GET /api/v1/login-history` — administrators only. The login audit
/// trail, newest first.
async fn list_history(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListHistoryQuery>,
) -> Result<Json<Vec<login_history::Model>>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    // Deep offsets cost a full scan; the audit trail is newest-first, so a
    // caller paging past this window should narrow the filter instead of
    // asking the database to skip a million rows (2026-10-19 review, D22).
    let offset = query.offset.unwrap_or(0).min(MAX_LOGIN_HISTORY_OFFSET);
    let mut db_query = login_history::Entity::find()
        .order_by_desc(login_history::Column::CreatedAt)
        .limit(limit)
        .offset(offset);
    if let Some(email) = query
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
    {
        db_query = db_query.filter(login_history::Column::Email.eq(email));
    }
    Ok(Json(db_query.all(&state.db).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::login_anomaly::{check_geo_url_host, url_host};

    fn settings_with(url: &str) -> LoginSecuritySettings {
        LoginSecuritySettings {
            online_geo_url: url.to_string(),
            ..LoginSecuritySettings::default()
        }
    }

    /// D16: the geo URL is fetched from the control plane, so every private /
    /// loopback / link-local / metadata target is refused before it is stored.
    #[test]
    fn private_and_metadata_geo_urls_are_rejected() {
        for url in [
            // Loopback, unspecified, private ranges.
            "http://127.0.0.1/{ip}",
            "http://127.9.9.9:8080/{ip}",
            "http://0.0.0.0/{ip}",
            "http://10.0.0.5/{ip}",
            "http://172.16.0.1/{ip}",
            "http://172.31.255.255/{ip}",
            "http://192.168.1.1/{ip}",
            // Link-local, including the cloud metadata endpoint.
            "http://169.254.169.254/latest/meta-data/{ip}",
            "http://169.254.0.1/{ip}",
            // CGNAT and broadcast.
            "http://100.64.0.1/{ip}",
            "http://255.255.255.255/{ip}",
            // IPv6 loopback / unspecified / unique-local / link-local.
            "http://[::1]/{ip}",
            "http://[::]/{ip}",
            "http://[fc00::1]/{ip}",
            "http://[fd00:ec2::254]/{ip}",
            "http://[fe80::1]/{ip}",
            // IPv4-mapped IPv6 form of a private address.
            "http://[::ffff:10.0.0.5]/{ip}",
            // Internal names, refused literally without a DNS lookup.
            "http://localhost/{ip}",
            "http://LOCALHOST:8080/{ip}",
            "http://geo.local/{ip}",
            "http://metadata.google.internal/{ip}",
            "http://db.home.arpa/{ip}",
            "http://geo/{ip}",
            // Userinfo confusion: the effective host is the private one.
            "http://evil.example@127.0.0.1/{ip}",
        ] {
            assert!(
                check_geo_url_host(url).is_err(),
                "{url} should be rejected"
            );
            assert!(
                settings_with(url).validate().is_err(),
                "{url} should fail settings validation"
            );
        }
    }

    /// D16: an admin update carrying a private geo URL is a client error, not
    /// a stored setting. The handler returns 400 through `ApiError`.
    #[test]
    fn update_payload_with_a_private_geo_url_maps_to_bad_request() {
        let body = serde_json::json!({
            "online_geo_url": "http://169.254.169.254/latest/meta-data/{ip}",
        });
        let payload: UpdateLoginSecurityRequest =
            serde_json::from_value(body).expect("payload parses");
        let mut settings = LoginSecuritySettings::default();
        if let Some(value) = payload.online_geo_url {
            settings.online_geo_url = value.trim().to_string();
        }
        let rejected = check_geo_url_host(&settings.online_geo_url)
            .map_err(ApiError::BadRequest);
        assert!(matches!(rejected, Err(ApiError::BadRequest(_))));
    }

    /// D16: public providers keep working, including a bare IP literal, a
    /// host:port and a bracketed IPv6 literal.
    #[test]
    fn public_geo_urls_are_accepted() {
        for url in [
            "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city",
            "https://geo.example.com/lookup/{ip}",
            "https://geo.example.com:8443/lookup?ip={ip}",
            "https://[2606:4700:4700::1111]/lookup/{ip}",
            "http://8.8.8.8/{ip}",
            "https://user:pass@geo.example.com/{ip}",
        ] {
            assert!(check_geo_url_host(url).is_ok(), "{url} should pass");
            assert!(
                settings_with(url).validate().is_ok(),
                "{url} should validate"
            );
        }
    }

    /// D16: malformed shapes are rejected rather than waved through — a URL
    /// whose host cannot be determined must never reach the fetcher.
    #[test]
    fn unparsable_geo_urls_are_rejected() {
        for url in [
            "http:///{ip}",
            "http://:8080/{ip}",
            "http://user@{ip}",
            "http://geo.example.com:not-a-port/{ip}",
            "ftp://geo.example.com/{ip}",
        ] {
            assert!(
                check_geo_url_host(url).is_err(),
                "{url} should be rejected"
            );
        }
    }

    /// D16: the host is what the client would actually connect to, not the
    /// userinfo or the port.
    #[test]
    fn url_host_resolves_the_effective_authority() {
        assert_eq!(
            url_host("https://geo.example.com:8443/x").as_deref(),
            Some("geo.example.com")
        );
        assert_eq!(
            url_host("http://user:pass@127.0.0.1/{ip}").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(url_host("http://[::1]:8080/{ip}").as_deref(), Some("::1"));
        assert_eq!(
            url_host("https://Geo.Example.COM./{ip}").as_deref(),
            Some("geo.example.com")
        );
    }
}
