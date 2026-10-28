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

use super::{get_hash_key, get_int_conf, get_str_conf, get_str_slice_conf};
use crate::certificates::new_certificate_provider;
use crate::config_manager::get_config_manager;
use crate::process::{get_start_time, restart_now};
use crate::upstreams::new_upstream_provider;
use async_trait::async_trait;
use bytes::Bytes;
use bytes::{BufMut, BytesMut};
use ctor::ctor;
use flate2::Compression;
use flate2::write::GzEncoder;
use hex::ToHex;
use hex::encode;
use http::Method;
use http::{HeaderValue, StatusCode, header};
use humantime::parse_duration;
use pingap_config::hcl::convert_toml_to_hcl;
use pingap_config::kdl::convert_toml_to_kdl;
use pingap_config::{
    CATEGORY_CERTIFICATE, CATEGORY_STORAGE, Category, CertificateConf,
    ConfigManager, LocationConf, PluginCategory, PluginConf, ServerConf,
    StorageConf, UpstreamConf, Validate, format_category,
};
use pingap_config::{
    CATEGORY_LOCATION, CATEGORY_PLUGIN, CATEGORY_SERVER, CATEGORY_UPSTREAM,
    PingapConfig,
};
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, TtlLruLimit,
};
use pingap_performance::get_process_system_info;
use pingap_performance::get_processing_accepted;
use pingap_plugin::{Error, get_plugin_factory};
use pingap_upstream::UpstreamHealthyStatus;
use pingap_util::base64_decode;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use rust_embed::EmbeddedFile;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use substring::Substring;
use tracing::{debug, error};
use urlencoding::decode;

type Result<T> = std::result::Result<T, Error>;

static LOG_TARGET: &str = "main::admin";

#[derive(RustEmbed)]
#[folder = "dist/"]
struct AdminAsset;

/// A file of the embedded admin bundle, with the `max-age` to advertise.
pub struct EmbeddedStaticFile(pub Option<EmbeddedFile>, pub Duration);

/// Below this size the gzip frame costs more than it saves.
const GZIP_MIN_BYTES: usize = 1024;

/// `true` when the request's `Accept-Encoding` lets the caller decode gzip.
///
/// Not an optimisation knob: `Content-Encoding: gzip` on a body the client
/// never asked for is undecodable, so the header decides whether the asset may
/// be compressed at all. The token rules (comma/`;` boundaries, `x-gzip` is a
/// different coding, an explicit `q=0` refuses) are the ones
/// `pingap_plugin::accepts_encoding` applies for the `compression` and
/// `accept_encoding` plugins; that helper is crate-private, so the rule is
/// restated here rather than exposing a pingap-plugin internal for one caller.
fn accepts_gzip(accept_encoding: Option<&str>) -> bool {
    let Some(value) = accept_encoding else {
        return false;
    };
    value.split(',').any(|part| {
        let mut segments = part.split(';');
        let name = segments.next().unwrap_or_default().trim();
        if !name.eq_ignore_ascii_case("gzip") {
            return false;
        }
        // Acceptable unless the token is explicitly weighted q=0.
        !segments.any(|seg| {
            let seg = seg.trim();
            seg.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("q="))
                && seg[2..].trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
        })
    })
}

/// gzip-encodes `data`, or `None` when it cannot — a half-written body is
/// worse than an uncompressed one.
fn gzip_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).ok()?;
    encoder.finish().ok()
}

/// Renders one asset of the bundle for a caller that may or may not accept
/// gzip.
///
/// `Vary: Accept-Encoding` is set whenever the body depends on that header, so
/// a shared cache keeps the compressed and the plain variant apart.
fn static_asset_response(
    data: &[u8],
    mime_type: &str,
    sha256_hash: [u8; 32],
    max_age: Duration,
    gzip: bool,
) -> HttpResponse {
    // generate content hash
    let hash = &encode(sha256_hash)[0..8];
    // cut hash and file length as etag
    let entity_tag = format!(r#""{:x}-{hash}""#, data.len());
    // html set no-cache
    let max_age = if mime_type.contains("text/html") {
        0
    } else {
        max_age.as_secs()
    };

    let mut headers = vec![];
    if let Ok(value) = HeaderValue::from_str(mime_type) {
        headers.push((header::CONTENT_TYPE, value));
    }
    if let Ok(value) = HeaderValue::from_str(&entity_tag) {
        headers.push((header::ETAG, value));
    }

    let mut body = Bytes::copy_from_slice(data);
    if data.len() > GZIP_MIN_BYTES {
        // Only the size-gated branch varies by `Accept-Encoding`.
        headers
            .push((header::VARY, HeaderValue::from_static("Accept-Encoding")));
        if gzip && let Some(compressed) = gzip_bytes(data) {
            headers.push((
                header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            ));
            body = Bytes::from(compressed);
        }
    }

    HttpResponse {
        status: StatusCode::OK,
        body,
        max_age: Some(max_age as u32),
        headers: Some(headers),
        ..Default::default()
    }
}

impl EmbeddedStaticFile {
    /// Renders the asset, compressing only when the caller advertised gzip.
    fn into_response(self, gzip: bool) -> HttpResponse {
        let Some(file) = self.0 else {
            return HttpResponse::not_found("Not Found");
        };
        static_asset_response(
            &file.data,
            file.metadata.mimetype(),
            file.metadata.sha256_hash(),
            self.1,
            gzip,
        )
    }
}

pub struct AdminServe {
    pub path: String,
    pub authorizations: Vec<(String, String)>,
    pub plugin_step: PluginStep,
    manager: Arc<ConfigManager>,
    max_age: Duration,
    hash_value: String,
    ip_fail_limit: TtlLruLimit,
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    message: String,
}

/// Fixed text for a failed admin request. The detail names storage backends,
/// configuration files and I-O paths, so it stays in the log.
const INTERNAL_ERROR_MESSAGE: &str = "internal error";

/// Why an admin handler failed, split by who can fix it.
///
/// The split decides what the client is told: a [`AdminError::BadRequest`]
/// reason is about the request the operator just sent, and is the whole point
/// of the error; anything else collapses to [`INTERNAL_ERROR_MESSAGE`].
#[derive(Debug)]
enum AdminError {
    /// Malformed url, request body or configuration value.
    BadRequest(String),
    /// Storage, config loading or I-O failed. Only ever logged.
    Internal(String),
    /// The client connection broke mid-request; there is nobody to answer.
    Downstream(pingora::BError),
}

/// Every admin handler answers with one of these.
type AdminResult<T> = std::result::Result<T, AdminError>;

impl AdminError {
    fn bad_request(message: impl std::fmt::Display) -> Self {
        AdminError::BadRequest(message.to_string())
    }

    fn internal(err: impl std::fmt::Display) -> Self {
        AdminError::Internal(err.to_string())
    }

    /// Renders the failure as the `{"message": …}` body the admin UI shows.
    fn into_response(self) -> HttpResponse {
        let (status, message) = match self {
            AdminError::BadRequest(message) => {
                (StatusCode::BAD_REQUEST, message)
            },
            AdminError::Internal(detail) => {
                error!(target: LOG_TARGET, error = detail, "admin request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    INTERNAL_ERROR_MESSAGE.to_string(),
                )
            },
            AdminError::Downstream(detail) => {
                // The caller hands a broken connection back to `fail_to_proxy`
                // instead of answering it; this arm keeps the match exhaustive
                // and still leaks nothing if a future caller forgets to.
                error!(target: LOG_TARGET, error = %detail, "admin request aborted");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    INTERNAL_ERROR_MESSAGE.to_string(),
                )
            },
        };
        HttpResponse::try_from_json_status(&ErrorResponse { message }, status)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    }
}

impl From<pingora::BError> for AdminError {
    fn from(err: pingora::BError) -> Self {
        // A read/write failure on the session is the connection, not our
        // processing: hand it back so `fail_to_proxy` can classify it (a client
        // that went away is `499`, and nothing is written).
        if matches!(err.esource(), pingora::ErrorSource::Downstream) {
            return AdminError::Downstream(err);
        }
        AdminError::internal(err)
    }
}

#[derive(Serialize, Deserialize)]
struct BasicInfo {
    start_time: u64,
    version: String,
    rustc_version: String,
    kernel: String,
    config_hash: String,
    pid: String,
    user: String,
    group: String,
    threads: i64,
    processing: i32,
    accepted: u64,
    memory_mb: usize,
    memory: String,
    arch: String,
    cpus: usize,
    physical_cpus: usize,
    total_memory: String,
    used_memory: String,
    features: Vec<String>,
    fd_count: usize,
    tcp_count: usize,
    tcp6_count: usize,
    supported_plugins: Vec<String>,
    upstream_healthy_status: HashMap<String, UpstreamHealthyStatus>,
    support_history: bool,
    git_hash: String,
    now: u64,
}

#[derive(Serialize, Deserialize)]
struct FullConfigJson {
    pub hcl: String,
    pub kdl: String,
    pub full: String,
    pub original: String,
}

impl TryFrom<&PluginConf> for AdminServe {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let mut authorizations = vec![];
        for item in get_str_slice_conf(value, "authorizations").iter() {
            if item.is_empty() {
                continue;
            }
            let data =
                base64_decode(item).map_err(|e| Error::Base64Decode {
                    category: PluginCategory::BasicAuth.to_string(),
                    source: e,
                })?;
            if let Some((user, pass)) =
                std::string::String::from_utf8_lossy(&data).split_once(':')
            {
                authorizations.push((user.to_string(), pass.to_string()));
            }
        }
        let mut ip_fail_limit = get_int_conf(value, "ip_fail_limit");
        if ip_fail_limit <= 0 {
            ip_fail_limit = 10;
        }
        let max_age_value = &get_str_conf(value, "max_age");
        let mut max_age = Duration::from_secs(2 * 24 * 3600);
        if !max_age_value.is_empty() {
            max_age = parse_duration(max_age_value).map_err(|e| {
                Error::ParseDuration {
                    category: "admin".to_string(),
                    source: e,
                }
            })?;
        }
        let mut path = get_str_conf(value, "path");
        if path.len() > 1 && path.ends_with("/") {
            path = path.substring(0, path.len() - 1).to_string();
        }

        let params = AdminServe {
            hash_value,
            max_age,
            plugin_step: PluginStep::Request,
            path,
            ip_fail_limit: TtlLruLimit::new_compact(
                512,
                Duration::from_secs(5 * 60),
                ip_fail_limit as usize,
            ),
            manager: get_config_manager().map_err(|e| Error::Invalid {
                category: "config_manager".to_string(),
                message: e.to_string(),
            })?,
            authorizations,
        };

        Ok(params)
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct AesParams {
    category: String,
    key: String,
    data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AesResp {
    value: String,
}

/// Admin routes buffer the whole body (AES payloads, config imports). A
/// public admin location without `client_max_body_size` used to let a single
/// request accumulate without bound (2026-10-18 audit); cap the buffer and
/// let the caller's parse fail (400) instead.
const MAX_ADMIN_BODY_BYTES: usize = 8 * 1024 * 1024;

async fn get_request_body(session: &mut Session) -> pingora::Result<BytesMut> {
    let mut buf = BytesMut::with_capacity(4096);
    while let Some(value) = session.read_request_body().await? {
        if buf.len() >= MAX_ADMIN_BODY_BYTES {
            break;
        }
        let room = MAX_ADMIN_BODY_BYTES - buf.len();
        let take = room.min(value.len());
        buf.put(&value[..take]);
    }
    Ok(buf)
}

impl AdminServe {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(target: LOG_TARGET, params = params.to_string(), "new admin server plugin");
        let serve = AdminServe::try_from(params)?;

        Ok(serve)
    }
    fn auth_validate(&self, req_header: &RequestHeader) -> bool {
        if self.authorizations.is_empty() {
            return true;
        }
        let path = req_header.uri.path();
        // The login UI's own static assets (js/css/png) and the index page must
        // load before the user authenticates. But API routes must ALWAYS require
        // auth: otherwise auth is bypassed by suffixing an API URL with a
        // static-looking extension, e.g. `GET /api/configs/x.js`. The auth skip
        // and the `/api` router use different criteria, so they must be kept
        // mutually exclusive here.
        let is_api = path.starts_with("/api") || path.starts_with("api/");
        if !is_api
            && (path.len() <= 1
                || path.ends_with(".js")
                || path.ends_with(".css")
                || path.ends_with(".png"))
        {
            return true;
        }
        let value =
            pingap_core::get_req_header_value(req_header, "Authorization")
                .unwrap_or_default();
        if value.is_empty() {
            error!(target: LOG_TARGET, path, "auth validate fail: missing authorization header");
            return false;
        }
        let Some((token, ts)) = value.split_once(':') else {
            error!(target: LOG_TARGET, path, "auth validate fail: malformed authorization, expect token:ts");
            return false;
        };
        let now = pingap_core::now_sec() as i64;
        let parsed_ts = ts.parse::<i64>().unwrap_or_default();
        let offset = now - parsed_ts;
        let max_age = self.max_age.as_secs() as i64;
        if offset.abs() > max_age {
            error!(
                target: LOG_TARGET,
                path,
                ts,
                parsed_ts,
                now,
                offset,
                max_age,
                "auth validate fail: timestamp out of max_age window"
            );
            return false;
        }

        for (user, pass) in self.authorizations.iter() {
            let mut hasher = Sha256::new();
            hasher.update(format!("{user}:{pass}:{ts}").as_bytes());
            let hash256 = hasher.finalize();
            if pingap_core::constant_time_eq(
                hash256.encode_hex::<String>().as_bytes(),
                token.as_bytes(),
            ) {
                return true;
            }
        }
        error!(
            target: LOG_TARGET,
            path,
            ts,
            authorizations = self.authorizations.len(),
            "auth validate fail: token hash mismatch"
        );
        false
    }
    async fn load_config(
        &self,
        replace_include: bool,
    ) -> AdminResult<PingapConfig> {
        let config =
            self.manager.load_all().await.map_err(|e| {
                AdminError::internal(format!("load config: {e}"))
            })?;
        let config = config.to_pingap_config(replace_include).map_err(|e| {
            AdminError::internal(format!("convert config: {e}"))
        })?;
        Ok(config)
    }
    async fn get_config(&self, category: &str) -> AdminResult<HttpResponse> {
        let conf = self.load_config(false).await?;
        if category == "full" {
            let full_conf = self.load_config(true).await?;
            let mut full_toml = toml::to_string_pretty(&full_conf)
                .map_err(AdminError::internal)?;
            if let Ok(value) = pingap_util::toml_omit_empty_value(&full_toml) {
                full_toml = value;
            };
            let hcl = convert_toml_to_hcl(&full_toml)
                .map_err(AdminError::internal)?;
            let kdl = convert_toml_to_kdl(&full_toml)
                .map_err(AdminError::internal)?;
            let mut original_toml =
                toml::to_string_pretty(&conf).map_err(AdminError::internal)?;
            if let Ok(value) =
                pingap_util::toml_omit_empty_value(&original_toml)
            {
                original_toml = value;
            };
            return HttpResponse::try_from_json(&FullConfigJson {
                hcl,
                kdl,
                full: full_toml,
                original: original_toml,
            })
            .map_err(AdminError::from);
        }
        let resp = match category {
            CATEGORY_UPSTREAM => HttpResponse::try_from_json(&conf.upstreams)?,
            CATEGORY_LOCATION => HttpResponse::try_from_json(&conf.locations)?,
            CATEGORY_SERVER => HttpResponse::try_from_json(&conf.servers)?,
            CATEGORY_PLUGIN => HttpResponse::try_from_json(&conf.plugins)?,
            CATEGORY_CERTIFICATE => {
                HttpResponse::try_from_json(&conf.certificates)?
            },
            _ => HttpResponse::try_from_json(&conf)?,
        };
        Ok(resp)
    }

    async fn remove_config(
        &self,
        category: &str,
        name: &str,
    ) -> AdminResult<HttpResponse> {
        let category =
            Category::from_str(category).map_err(AdminError::bad_request)?;
        self.manager
            .delete(category, name)
            .await
            .map_err(|e| AdminError::internal(format!("delete config: {e}")))?;
        Ok(HttpResponse::no_content())
    }
    async fn handle_update_config<T>(
        &self,
        name: &str,
        buf: &[u8],
        category: Category,
    ) -> AdminResult<()>
    where
        T: DeserializeOwned + Serialize + Send + Sync + Validate,
    {
        // The payload is the operator's own JSON, so the parser's complaint is
        // exactly what they need to fix it.
        let conf: T = serde_json::from_slice(buf).map_err(|e| {
            AdminError::bad_request(format!("parse {category} config: {e}"))
        })?;
        conf.validate().map_err(|e| {
            AdminError::bad_request(format!("validate config: {e}"))
        })?;

        self.manager
            .update(category, name, &conf)
            .await
            .map_err(|e| AdminError::internal(format!("update config: {e}")))?;

        Ok(())
    }

    async fn update_config(
        &self,
        session: &mut Session,
        category: &str,
        name: &str,
    ) -> AdminResult<HttpResponse> {
        if name.is_empty() {
            return Err(AdminError::bad_request("name is empty"));
        }
        let buf = get_request_body(session).await?;

        match category {
            CATEGORY_UPSTREAM => {
                self.handle_update_config::<UpstreamConf>(
                    name,
                    &buf,
                    Category::Upstream,
                )
                .await?;
            },
            CATEGORY_LOCATION => {
                self.handle_update_config::<LocationConf>(
                    name,
                    &buf,
                    Category::Location,
                )
                .await?;
            },
            CATEGORY_SERVER => {
                self.handle_update_config::<ServerConf>(
                    name,
                    &buf,
                    Category::Server,
                )
                .await?;
            },
            CATEGORY_PLUGIN => {
                self.handle_update_config::<PluginConf>(
                    name,
                    &buf,
                    Category::Plugin,
                )
                .await?;
            },
            CATEGORY_CERTIFICATE => {
                self.handle_update_config::<CertificateConf>(
                    name,
                    &buf,
                    Category::Certificate,
                )
                .await?;
            },
            CATEGORY_STORAGE => {
                self.handle_update_config::<StorageConf>(
                    name,
                    &buf,
                    Category::Storage,
                )
                .await?;
            },
            other => {
                // Treating an unknown category as `basic` silently
                // overwrote `basic.toml` with the payload meant for
                // something else.
                return Err(AdminError::bad_request(format!(
                    "unknown config category: {other}"
                )));
            },
        };

        Ok(HttpResponse::no_content())
    }
    async fn import_config(
        &self,
        session: &mut Session,
    ) -> AdminResult<HttpResponse> {
        let buf = get_request_body(session).await?;
        let config = toml::from_slice(&buf).map_err(|e| {
            AdminError::bad_request(format!("import config: {e}"))
        })?;
        // Writing the file can fail on permissions or a full disk; that is not
        // the operator's mistake, and the message names the path.
        self.manager
            .save_all(&config)
            .await
            .map_err(|e| AdminError::internal(format!("import config: {e}")))?;

        Ok(HttpResponse::no_content())
    }
}

fn get_method_path(session: &Session) -> (Method, String) {
    let req_header = session.req_header();
    let method = req_header.method.clone();
    let path = req_header.uri.path();
    (method, path.to_string())
}

async fn handle_request_admin(
    plugin: &AdminServe,
    session: &mut Session,
    ctx: &mut Ctx,
) -> pingora::Result<Option<HttpResponse>> {
    let ip = pingap_core::ensure_client_ip(session, ctx);
    if !plugin.ip_fail_limit.validate(ip) {
        return Ok(Some(HttpResponse {
            status: StatusCode::FORBIDDEN,
            body: Bytes::from_static(b"Forbidden, too many failures"),
            ..Default::default()
        }));
    }

    let header = session.req_header_mut();
    let path = header.uri.path();
    let mut new_path =
        path.substring(plugin.path.len(), path.len()).to_string();
    if plugin.path.len() > 1 && new_path.is_empty() {
        new_path = format!("{path}/");
        if let Some(query) = header.uri.query() {
            new_path = format!("{new_path}?{query}");
        }
        let resp = HttpResponse::redirect(&new_path)?;
        return Ok(Some(resp));
    }
    if let Some(query) = header.uri.query() {
        new_path = format!("{new_path}?{query}");
    }
    // ignore parse error
    if let Ok(uri) = new_path.parse::<http::Uri>() {
        header.set_uri(uri);
    }
    if !plugin.auth_validate(header) {
        plugin.ip_fail_limit.inc(ip);
        return Ok(Some(HttpResponse {
            status: StatusCode::UNAUTHORIZED,
            ..Default::default()
        }));
    }
    match route_admin_request(plugin, session).await {
        Ok(resp) => Ok(Some(resp)),
        // The client connection broke mid-request: there is nobody left to
        // answer, so hand the error back and let `fail_to_proxy` classify it
        // (`499` for a client that went away, nothing written).
        Err(AdminError::Downstream(err)) => Err(err),
        Err(err) => Ok(Some(err.into_response())),
    }
}

/// Routes one admin request — the `/api` surface and the static bundle alike.
///
/// Every handler failure comes back as an [`AdminError`], never as a ready-made
/// response: only the caller knows which part of a message is safe to show.
async fn route_admin_request(
    plugin: &AdminServe,
    session: &mut Session,
) -> AdminResult<HttpResponse> {
    let (method, mut path) = get_method_path(session);
    let api_prefix = "/api";
    if path.starts_with(api_prefix) {
        path = path.substring(api_prefix.len(), path.len()).to_string();
    }
    let params: Vec<String> = path
        .split('/')
        .map(|item| decode(item).unwrap_or_default().to_string())
        .collect();
    let mut category = "";
    if params.len() >= 3 {
        category = &params[2];
    }
    let resp = if path.starts_with("/configs") {
        match method {
            Method::POST => {
                if category == "import" {
                    plugin.import_config(session).await?
                } else if params.len() < 4 {
                    return Err(AdminError::bad_request(
                        "Url is invalid(no name)",
                    ));
                } else {
                    plugin.update_config(session, category, &params[3]).await?
                }
            },
            Method::DELETE => {
                if params.len() < 4 {
                    return Err(AdminError::bad_request(
                        "Url is invalid(no name)",
                    ));
                }
                plugin.remove_config(category, &params[3]).await?
            },
            _ => plugin.get_config(category).await?,
        }
    } else if path.starts_with("/config-history") {
        let category =
            Category::from_str(category).map_err(AdminError::bad_request)?;
        // The name segment is optional in the url but not in the code below,
        // so reject a short url instead of indexing past the end of `params`.
        let Some(name) = params.get(3).cloned() else {
            return Err(AdminError::bad_request("Url is invalid(no name)"));
        };
        let arr = plugin
            .manager
            .history(category.clone(), &name)
            .await
            .map_err(|e| {
                AdminError::internal(format!("get config history: {e}"))
            })?
            .unwrap_or_default();

        let mut history = vec![];
        for item in arr {
            // Stored data, not the caller's payload — a parse failure here is
            // corruption, not a mistake to report back.
            let data: toml::Table =
                toml::from_str(&item.data).map_err(|e| {
                    AdminError::internal(format!("parse config history: {e}"))
                })?;
            let key = format_category(&category);
            let Some(data) = data.get(key).cloned() else {
                continue;
            };
            let data = if name.is_empty() {
                data
            } else {
                let Some(data) = data.get(&name).cloned() else {
                    continue;
                };
                data
            };
            history.push(json!({
                "created_at": item.created_at,
                "data": data,
            }));
        }
        HttpResponse::try_from_json(&json!({
            "history": history,
        }))
        .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/basic" {
        let current_config = plugin.load_config(true).await?;
        let info = get_process_system_info();

        let (processing, accepted) = get_processing_accepted();

        let mut basic_info = BasicInfo {
            start_time: get_start_time(),
            version: pingap_util::get_pkg_version().to_string(),
            rustc_version: pingap_util::get_rustc_version().to_string(),
            config_hash: plugin
                .manager
                .get_current_config()
                .hash()
                .unwrap_or_default(),
            user: current_config.basic.user.clone().unwrap_or_default(),
            group: current_config.basic.group.clone().unwrap_or_default(),
            pid: info.pid.to_string(),
            threads: info.threads,
            accepted,
            processing,
            kernel: info.kernel,
            memory_mb: info.memory_mb,
            memory: info.memory,
            arch: info.arch,
            cpus: info.cpus,
            physical_cpus: info.physical_cpus,
            total_memory: info.total_memory,
            used_memory: info.used_memory,
            features: vec![],
            fd_count: info.fd_count,
            tcp_count: info.tcp_count,
            tcp6_count: info.tcp6_count,
            supported_plugins: get_plugin_factory().supported_plugins(),
            upstream_healthy_status: new_upstream_provider().healthy_status(),
            support_history: plugin.manager.support_history(),
            git_hash: crate::git_hash().to_string(),
            now: pingap_core::now_sec(),
        };
        basic_info.features.push("default".to_string());
        // TLS backend name (`openssl` or `rustls`) so the admin UI can disable
        // settings the active binary cannot honour and show it on the home page.
        basic_info
            .features
            .push(pingap_certificate::TLS_BACKEND.to_string());

        cfg_if::cfg_if! {
            if #[cfg(feature = "tracing")] {
                basic_info.features.push("tracing".to_string());
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "full")] {
                basic_info.features.push("full".to_string());
            }
        }
        cfg_if::cfg_if! {
            if #[cfg(feature = "pyro")] {
                basic_info.features.push("pyroscope".to_string());
            }
        }

        HttpResponse::try_from_json(&basic_info)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/restart" && method == Method::POST {
        if let Err(e) = restart_now().await {
            // Spawning the replacement failed; the reason names paths and pids.
            return Err(AdminError::internal(format!("restart: {e}")));
        }
        HttpResponse::no_content()
    } else if path == "/aes" {
        let buf = get_request_body(session).await?;
        let params: AesParams = serde_json::from_slice(buf.as_ref())
            .map_err(AdminError::bad_request)?;
        // A bad key or a payload that is not valid ciphertext is the caller's
        // to fix, and the crypto error says which.
        let value = if params.category == "encrypt" {
            pingap_util::aes_encrypt(&params.key, &params.data)
        } else {
            pingap_util::aes_decrypt(&params.key, &params.data)
        }
        .map_err(AdminError::bad_request)?;
        HttpResponse::try_from_json(&AesResp { value })
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else if path == "/certificates" {
        let mut infos = HashMap::new();
        for (name, cert) in new_certificate_provider().list().iter() {
            if let Some(info) = &cert.info {
                let key = if let Some(value) = &cert.name {
                    value.clone()
                } else {
                    name.clone()
                };
                infos.insert(key, info.clone());
            }
        }
        HttpResponse::try_from_json(&infos)
            .unwrap_or(HttpResponse::unknown_error("Json serde fail"))
    } else {
        let mut file = path.substring(1, path.len());
        if file.is_empty() {
            file = "index.html";
        }
        // The bundle is compressed only for a client that said it can decode
        // it; anybody else gets the plain bytes.
        let gzip = accepts_gzip(pingap_core::get_req_header_value(
            session.req_header(),
            "Accept-Encoding",
        ));
        EmbeddedStaticFile(
            AdminAsset::get(file),
            Duration::from_secs(365 * 24 * 3600),
        )
        .into_response(gzip)
    };
    Ok(resp)
}

#[async_trait]
impl Plugin for AdminServe {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if self.plugin_step != step {
            return Ok(RequestPluginResult::Skipped);
        }
        if !session.req_header().uri.path().starts_with(&self.path) {
            return Ok(RequestPluginResult::Skipped);
        }
        let resp = handle_request_admin(self, session, _ctx).await?;
        if let Some(resp) = resp {
            return Ok(RequestPluginResult::Respond(resp));
        }
        Ok(RequestPluginResult::Continue)
    }
}

#[ctor(unsafe)]
fn init() {
    get_plugin_factory()
        .register("admin", |params| Ok(Arc::new(AdminServe::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::{
        AdminAsset, AdminServe, EmbeddedStaticFile, GZIP_MIN_BYTES,
        accepts_gzip, handle_request_admin, static_asset_response,
    };
    use crate::config_manager::try_init_config_manager;
    use flate2::read::GzDecoder;
    use http::header;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, HttpResponse};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use std::io::Read;
    use std::time::Duration;
    use tokio_test::io::Builder;

    #[test]
    fn test_admin_params() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        // spellchecker:off
        let params = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = [
        "YWRtaW46MTIzMTIz",
        "cGluZ2FwOjEyMzEyMw=="
    ]
    "#,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on
        assert_eq!(
            "admin:123123,pingap:123123",
            params
                .authorizations
                .iter()
                .map(|item| format!("{}:{}", item.0, item.1))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!("request", params.plugin_step.to_string());
        assert_eq!("/", params.path);

        let result = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = [
        "123",
    ]
    "#,
            )
            .unwrap(),
        );

        assert_eq!(
            "Plugin basic_auth, base64 decode error Invalid padding",
            result.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_embedded_static_file() {
        // `dist/` is a build artifact populated by `make build-web`; a clean
        // checkout (e.g. CI) only contains the tracked `dist/README.md`, so skip
        // gracefully instead of panicking when the bundle isn't present.
        let Some(file) = AdminAsset::get("index.html") else {
            eprintln!(
                "skipping test_embedded_static_file: dist/index.html not built (run `make build-web`)"
            );
            return;
        };
        let resp: HttpResponse =
            EmbeddedStaticFile(Some(file), Duration::from_secs(60))
                .into_response(false);
        assert_eq!(true, !resp.body.is_empty());
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(0, resp.max_age.unwrap_or_default());
        assert_eq!(
            r#"("content-type", "text/html")"#,
            format!("{:?}", resp.headers.unwrap_or_default()[0])
        );

        let resp: HttpResponse =
            EmbeddedStaticFile(None, Duration::from_secs(60))
                .into_response(false);
        assert_eq!(404, resp.status.as_u16())
    }

    /// The decision has to come from the request header, so every shape a
    /// client can send is pinned here.
    #[test]
    fn test_accepts_gzip_header() {
        assert_eq!(false, accepts_gzip(None));
        assert_eq!(false, accepts_gzip(Some("")));
        assert_eq!(true, accepts_gzip(Some("gzip")));
        assert_eq!(true, accepts_gzip(Some("GZIP")));
        assert_eq!(true, accepts_gzip(Some("deflate, gzip;q=0.5")));
        assert_eq!(true, accepts_gzip(Some("br;q=1.0,gzip;q=0.8")));
        // `x-gzip` / `gzipx` are different codings.
        assert_eq!(false, accepts_gzip(Some("x-gzip")));
        assert_eq!(false, accepts_gzip(Some("gzipx")));
        assert_eq!(false, accepts_gzip(Some("br, zstd")));
        // An explicit q=0 refuses it.
        assert_eq!(false, accepts_gzip(Some("gzip;q=0")));
        assert_eq!(false, accepts_gzip(Some("gzip;q=0, br")));
    }

    /// A 4 KiB asset over both branches of the `Accept-Encoding` decision.
    fn asset_payload() -> Vec<u8> {
        b"<html><body><h1>pingap admin</h1></body></html>".repeat(96)
    }

    /// Value of one response header, or `""` when it was not set.
    fn header_value(
        resp: &HttpResponse,
        name: &http::header::HeaderName,
    ) -> String {
        resp.headers
            .as_ref()
            .and_then(|headers| {
                headers
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| {
                        value.to_str().unwrap_or_default().to_string()
                    })
            })
            .unwrap_or_default()
    }

    /// D23: a client that never advertised gzip used to be handed gzip bytes
    /// under `Content-Encoding: gzip`. Without the header, nothing is encoded.
    #[test]
    fn test_static_asset_is_not_compressed_without_accept_encoding() {
        let payload = asset_payload();
        assert_eq!(true, payload.len() > GZIP_MIN_BYTES);
        let resp = static_asset_response(
            &payload,
            "text/html",
            [7u8; 32],
            Duration::from_secs(60),
            accepts_gzip(None),
        );
        assert_eq!("", header_value(&resp, &header::CONTENT_ENCODING));
        assert_eq!(payload.len(), resp.body.len());
        assert_eq!(&payload[..], &resp.body[..]);
        // The representation depends on the header even when it is absent, so
        // a shared cache must key on it.
        assert_eq!("Accept-Encoding", header_value(&resp, &header::VARY));
    }

    /// … and with the header, the same asset arrives gzip-encoded and still
    /// decodes back to the original bytes.
    #[test]
    fn test_static_asset_is_compressed_when_gzip_is_accepted() {
        let payload = asset_payload();
        let resp = static_asset_response(
            &payload,
            "text/html",
            [7u8; 32],
            Duration::from_secs(60),
            accepts_gzip(Some("deflate, gzip")),
        );
        assert_eq!("gzip", header_value(&resp, &header::CONTENT_ENCODING));
        assert_eq!("Accept-Encoding", header_value(&resp, &header::VARY));
        assert_eq!(true, resp.body.len() < payload.len());

        let mut decoded = vec![];
        let mut decoder = GzDecoder::new(&resp.body[..]);
        // flate2 reports a short read on a truncated frame, so this also proves
        // the body was written completely.
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(&payload[..], &decoded[..]);
    }

    #[test]
    fn test_auth_validate_skips_only_static_assets() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        // spellchecker:off
        let admin = AdminServe::try_from(
            &toml::from_str::<PluginConf>(
                r#"
    category = "admin"
    path = "/"
    authorizations = ["YWRtaW46MTIzMTIz"]
    "#,
            )
            .unwrap(),
        )
        .unwrap();
        // spellchecker:on

        // `auth_validate` runs on the path AFTER the admin prefix is stripped.
        let auth_skipped = |path: &str| {
            let req = pingora::http::RequestHeader::build(
                http::Method::GET,
                path.as_bytes(),
                None,
            )
            .unwrap();
            admin.auth_validate(&req)
        };

        // Genuine static assets of the login UI load without auth.
        assert_eq!(true, auth_skipped("/"));
        assert_eq!(true, auth_skipped("/assets/index.js"));
        assert_eq!(true, auth_skipped("/assets/index.css"));
        assert_eq!(true, auth_skipped("/pingap.png"));

        // Regression: API routes must never be auth-skipped, even when suffixed
        // with a static-looking extension.
        assert_eq!(false, auth_skipped("/api/configs/anything.js"));
        assert_eq!(false, auth_skipped("/api/configs/upstream/evil.css"));
        assert_eq!(false, auth_skipped("/api/certificates.png"));
        assert_eq!(false, auth_skipped("/api/basic"));
    }

    /// Regression: `/config-history/{category}` without the trailing name used
    /// to index past the end of the split url and panic the request task.
    ///
    /// A url the operator typed wrong is answered as `400` with the reason —
    /// the handler no longer lets its error escape to `fail_to_proxy`.
    #[tokio::test]
    async fn test_config_history_without_name() {
        let file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        try_init_config_manager(&file.path().to_string_lossy()).unwrap();
        let admin = AdminServe::try_from(
            &toml::from_str::<PluginConf>(r#"category = "admin""#).unwrap(),
        )
        .unwrap();

        let mock_io = Builder::new()
            .read(b"GET /api/config-history/upstream HTTP/1.1\r\n\r\n")
            .build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let resp =
            handle_request_admin(&admin, &mut session, &mut Ctx::default())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(400, resp.status.as_u16());
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(
            body.contains("Url is invalid(no name)"),
            "unexpected body: {body}"
        );
    }
}
