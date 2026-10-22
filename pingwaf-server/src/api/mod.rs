//! REST API composition.
//!
//! Every route module contributes a `Router<AppState>` with paths relative to
//! `/api/v1`; this module merges them, attaches the shared middleware stack and
//! finally bakes the [`AppState`] in.

pub mod agents;
pub mod ai;
pub mod ai_crawl;
pub mod ai_rate_limit;
pub mod analytics;
pub mod api_protection;
pub mod auth;
pub mod blocked_ips;
pub mod bot;
pub mod cache;
pub mod cache_settings;
pub mod challenge;
pub mod common;
pub mod config_versions;
pub mod defense;
pub mod error;
pub mod error_pages;
pub mod geo;
pub mod ip_groups;
pub mod ip_rules;
pub mod keys;
pub mod log_retention;
pub mod login_security;
pub mod logs;
pub mod mcp;
pub mod mtls;
pub mod notifications;
pub mod origin_settings;
pub mod passkeys;
pub mod rate_limit;
pub mod rate_limiting;
pub mod rewrite;
pub mod rules;
pub mod self_protection;
pub mod settings;
pub mod site_basic_auth;
pub mod site_failover;
pub mod site_oidc;
pub mod sites;
pub mod ssl;
pub mod state;
pub mod system;
pub mod system_tls;
pub mod users;
pub(crate) mod validation;
pub mod waf_settings;

use crate::frontend::serve_frontend;
use crate::tls::ConnInfo;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::DefaultBodyLimit;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde_json::json;
use std::future::Future;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

pub use error::{error_response, ApiError};
pub use state::AppState;

/// Builds a contract-envelope error response with an endpoint-specific code
/// (C1) for the cases [`ApiError`]'s fixed code set cannot express — e.g.
/// `invalid_range` (analytics) or `unknown_file` (AI crawl preview).
pub(crate) fn contract_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
        .into_response()
}

/// Prefix every REST route lives under.
pub const API_PREFIX: &str = "/api/v1";

/// Global request-body ceiling for the whole control plane (API + MCP +
/// frontend fallback). Route-level limits override it where a route needs
/// more (the GeoIP MMDB upload raises it to 128 MiB; MCP keeps its tighter
/// 256 KiB cap), so this is the backstop that applies when WAF
/// self-protection is disabled and a route never set its own bound: without
/// it, any endpoint would happily buffer an unbounded body into memory.
///
/// 10 MiB covers the legitimate maximum payloads (config-snapshot import
/// ~2 MiB, certificate PEM bundles) with room to spare.
pub const DEFAULT_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;

/// Attributes one control-plane request to the `control` module. The timer
/// is a relaxed atomic add on drop, so the middleware costs nanoseconds.
async fn record_control_module(request: Request, next: Next) -> Response {
    // Method attribution (see pingwaf-profiler): the timer books the
    // `control` module row as well.
    let _profile =
        pingwaf_profiler::timed_method(pingwaf_profiler::Method::ControlHttp);
    next.run(request).await
}

/// Builds the complete HTTP router, including CORS, compression and tracing.
pub fn build_router(state: AppState) -> Router {
    let config = state.config.clone();
    // The D20 middleware needs the state before the router is built; the
    // handler layers take the original `state` through `with_state` at the end.
    let api_state = state.clone();

    let api = Router::new()
        .merge(auth::routes())
        .merge(sites::routes())
        .merge(ai_crawl::routes())
        .merge(site_basic_auth::routes())
        .merge(site_oidc::routes())
        .merge(keys::routes())
        .merge(users::routes())
        .merge(agents::routes())
        .merge(rules::routes())
        .merge(rate_limiting::routes())
        .merge(cache::routes())
        .merge(logs::routes())
        .merge(analytics::routes())
        .merge(settings::routes())
        .merge(log_retention::routes())
        .merge(ssl::routes())
        .merge(mtls::routes())
        .merge(passkeys::routes())
        .merge(ip_rules::routes())
        .merge(ip_groups::routes())
        .merge(blocked_ips::routes())
        .merge(geo::routes())
        .merge(bot::routes())
        .merge(challenge::routes())
        .merge(waf_settings::routes())
        .merge(site_failover::routes())
        .merge(rewrite::routes())
        .merge(error_pages::routes())
        .merge(system::routes())
        .merge(system_tls::routes())
        .merge(defense::routes())
        .merge(cache_settings::routes())
        .merge(origin_settings::routes())
        .merge(api_protection::routes())
        .merge(ai::routes())
        .merge(mcp::routes())
        .merge(config_versions::routes())
        .merge(notifications::routes())
        .merge(login_security::routes())
        .route("/health", get(health))
        .route("/version", get(version))
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed)
        // An account still holding the shipped initial password may only use
        // the endpoints that let it finish the forced change (D20). Applied to
        // the whole `/api/v1` group, so a route added later is covered by
        // default rather than opt-in.
        .layer(middleware::from_fn_with_state(
            api_state.clone(),
            crate::auth::middleware::require_password_change,
        ))
        // The limiter covers the whole API surface but only ever matches the
        // credential endpoints (see `bucket_for`), which is also what keeps
        // passkey logins — registered by a different module — covered.
        .layer(middleware::from_fn(rate_limit::auth_rate_limit))
        // Attribution for the REST surface only: mounted on the `/api/v1`
        // group so MCP, `/healthz` and the SPA fallback do not inflate the
        // `control` row. Outermost here, so it also covers the two
        // middlewares above (both cheap) but not CORS/compression/security
        // headers, which wrap the root router.
        .layer(middleware::from_fn(unified_error_envelope))
        .layer(middleware::from_fn(record_control_module));

    let mut root = Router::new()
        .nest(API_PREFIX, api)
        // The hosted MCP endpoint lives outside `/api/v1` (clients append
        // `/mcp` to the base URL), and hanging off the root router is what
        // makes the self-protection stack below (access log, IP allowlist,
        // WAF) cover it automatically.
        .merge(crate::mcp::routes())
        // Load balancers and container probes usually hit the root path.
        .route("/healthz", get(health));
    // Serve the embedded React frontend for all non-API routes (SPA)
    if config.serve_frontend {
        root = root.fallback(serve_frontend);
    }

    let redirect = RedirectState {
        tls_enabled: state.control_tls.is_enabled(),
        public_host: config.public_host.clone(),
    };
    root.layer(middleware::from_fn_with_state(
        redirect,
        redirect_cleartext_to_https,
    ))
    // Global body-size backstop (S1): applies to everything below — the
    // nested `/api/v1` router, the MCP routes and the frontend fallback —
    // while route-level `DefaultBodyLimit`s (MCP, GeoIP upload) still take
    // precedence as the inner, more specific bounds. Not part of the
    // `control` attribution: `record_control_module` lives on `/api/v1`.
    .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT_BYTES))
    .layer(build_cors(&config.cors_origins))
    // Global security headers. Applied as `if_not_present` so a handler
    // that legitimately needs a different value (e.g. an `<iframe>`-able
    // preview) can still override them.
    //
    // The CSP mirrors the only static assets the dashboard actually
    // loads: `/favicon.svg` and the Vite bundle (both same-origin),
    // inline `style={...}` props on React components, and a
    // `data:` fallback for any future embedded images / webfonts.
    // `connect-src 'self'` keeps XHR/fetch on the API origin only; if a
    // split-origin deployment is ever configured, that will need to
    // widen. The dashboard.svg `?refresh=` SVG embeds an inline script
    // when the user opts in; the SVG response sets its own
    // `Content-Security-Policy: script-src 'unsafe-inline'` for that
    // one path.
    .layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; \
             img-src 'self' data:; \
             font-src 'self' data:; \
             style-src 'self' 'unsafe-inline'; \
             script-src 'self'; \
             connect-src 'self'; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'self'",
        ),
    ))
    .layer(CompressionLayer::new())
    .layer(TraceLayer::new_for_http().make_span_with(
        |request: &axum::http::Request<_>| {
            tracing::info_span!(
                "http_request",
                method = %request.method(),
                path = %request.uri().path(),
            )
        },
    ))
    // Self-protection wraps everything above: the access log sees the final
    // status code, and a request the allowlist or the WAF refuses never
    // reaches the tracing/compression stack. Later `.layer` calls are the
    // outer ones, so `access_log` ends up first.
    .layer(middleware::from_fn_with_state(
        state.clone(),
        self_protection::waf_guard,
    ))
    .layer(middleware::from_fn_with_state(
        state.clone(),
        self_protection::ip_allowlist,
    ))
    .layer(middleware::from_fn_with_state(
        state.clone(),
        self_protection::access_log,
    ))
    .with_state(state)
}

/// By default the dashboard is served from the same origin as the API
/// (the production layout), so no `Access-Control-Allow-Origin` header is
/// needed — and on a credential-bearing API, an unguarded `*` is a
/// footgun. Operators with a split-origin deployment (control plane and
/// API on different hosts) must opt in via the `cors_origins` config,
/// which is honored as an explicit whitelist.
fn build_cors(origins: &[String]) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
        ])
        .max_age(std::time::Duration::from_secs(3600));

    let parsed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| match origin.parse::<HeaderValue>() {
            Ok(value) => Some(value),
            Err(err) => {
                tracing::warn!(%origin, error = %err, "ignoring invalid CORS origin");
                None
            }
        })
        .collect();

    if parsed.is_empty() {
        // Same-origin: leave `allow_origin` unset so the layer emits no
        // CORS headers at all. Cross-origin callers will then be
        // rejected by the browser, which is what we want.
        tracing::info!("no CORS origins configured; same-origin only");
        layer
    } else {
        tracing::info!(origins = ?parsed, "CORS restricted to the configured origins");
        layer.allow_origin(AllowOrigin::list(parsed))
    }
}

/// State of the redirect middleware: whether this process terminates TLS.
///
/// Deliberately smaller than [`AppState`] — the middleware needs no database,
/// which is what lets its connection handling be tested over real sockets.
#[derive(Clone, Debug)]
pub struct RedirectState {
    pub tls_enabled: bool,
    /// Pinned redirect target (`PINGWAF_PUBLIC_HOST`); `None` reuses the
    /// request's `Host` header.
    pub public_host: Option<String>,
}

/// Sends cleartext requests to the HTTPS listener.
///
/// Only meaningful when this process terminates TLS: the mixed listener keeps
/// accepting plaintext so probes and an operator typing `http://` get a real
/// HTTP answer instead of a reset, and this middleware is what turns that
/// answer into a redirect. Health endpoints are exempt so container and load
/// balancer probes keep working without trusting a certificate. The decision
/// is made from the connection, not from `X-Forwarded-Proto`: a caller talking
/// plaintext to this port must not be able to talk its way past the redirect.
async fn redirect_cleartext_to_https(
    State(state): State<RedirectState>,
    request: Request,
    next: Next,
) -> Response {
    // The extension is `ConnectInfo<ConnInfo>`, not `ConnInfo`: axum inserts
    // the newtype its connect-info service builds. Reading the inner type
    // directly always misses, which silently redirects every TLS request to
    // itself — a loop the browser reports as too many redirects.
    let secured = request
        .extensions()
        .get::<ConnectInfo<ConnInfo>>()
        .is_some_and(|info| info.0.tls);
    if !state.tls_enabled || secured || is_health_probe(request.uri().path()) {
        return next.run(request).await;
    }

    match https_location(&state, &request) {
        // `308` keeps the method and body, which a `301` would not.
        Some(location) => (
            StatusCode::PERMANENT_REDIRECT,
            [(axum::http::header::LOCATION, location)],
        )
            .into_response(),
        // Without a Host header there is no absolute URL to build; let the
        // request through so the failure is the usual 400 rather than a
        // redirect loop.
        None => next.run(request).await,
    }
}

/// The `https://` URL of the request, when the Host header allows building one.
///
/// A configured `PINGWAF_PUBLIC_HOST` pins the target instead: behind a
/// reverse proxy the client's `Host` header is whatever the caller sent, and
/// an attacker controlling it would otherwise steer the redirect — and every
/// client that follows it — anywhere they like.
fn https_location(
    state: &RedirectState,
    request: &Request,
) -> Option<HeaderValue> {
    let host = match &state.public_host {
        Some(host) => host.clone(),
        None => request
            .headers()
            .get(axum::http::header::HOST)?
            .to_str()
            .ok()?
            .to_string(),
    };
    let target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    HeaderValue::from_str(&format!("https://{host}{target}")).ok()
}

/// Paths that answer on both schemes, so probes need no certificate.
pub(crate) fn is_health_probe(path: &str) -> bool {
    matches!(path, "/healthz" | "/api/v1/health")
}

/// `GET /healthz` and `GET /api/v1/health` — verifies the database is reachable.
///
/// Answers are reused for a few seconds: container and load-balancer probes
/// hit these paths on a short schedule, and without a cache a database that
/// has slowed down turns every probe into one more query piling onto it.
async fn health(State(state): State<AppState>) -> Response {
    let healthy = health_probe(
        &HEALTH_CACHE,
        HEALTH_CACHE_TTL,
        std::time::Instant::now(),
        || state.db.ping(),
    )
    .await;
    if healthy {
        (
            StatusCode::OK,
            Json(json!({ "status": "ok", "database": "up" })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "degraded", "database": "down" })),
        )
            .into_response()
    }
}

/// How long a health answer is reused before the database is probed again.
const HEALTH_CACHE_TTL: Duration = Duration::from_secs(5);

/// Outcome of the last health probe: when it was taken and what it found.
static HEALTH_CACHE: LazyLock<Mutex<Option<(std::time::Instant, bool)>>> =
    LazyLock::new(|| Mutex::new(None));

/// Answers from `cache` while it is fresh, otherwise awaits `probe` and
/// records its outcome. `now` is injected so tests can age the cache.
async fn health_probe<F, Fut, E>(
    cache: &Mutex<Option<(std::time::Instant, bool)>>,
    ttl: Duration,
    now: std::time::Instant,
    probe: F,
) -> bool
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let cached = cache
        .lock()
        .expect("health cache poisoned")
        .filter(|(at, _)| now.duration_since(*at) < ttl);
    if let Some((_, healthy)) = cached {
        return healthy;
    }

    let result = probe().await;
    let healthy = result.is_ok();
    if let Err(err) = result {
        tracing::error!(error = %err, "database health check failed");
    }
    *cache.lock().expect("health cache poisoned") = Some((now, healthy));
    healthy
}

/// `GET /api/v1/version` — build metadata the frontend shows in the footer.
async fn version(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "api": API_PREFIX,
        "registration_open": state.config.allow_registration,
        // False = the gRPC control plane serves plaintext (degraded mode);
        // the dashboard shows a banner so the operator notices.
        "grpc_tls": state.config.grpc_tls_enabled(),
    }))
}

/// JSON 404 for unmatched API routes, so the frontend never has to
/// parse an HTML error page for API calls.
///
/// This fallback is mounted on the router nested under [`API_PREFIX`], and
/// axum strips that prefix before matching — so the path the client sent has
/// to be re-prepended here: the message must echo the full path (C1/L4-005),
/// not the remainder after `/api/v1`.
async fn api_not_found(uri: axum::http::Uri) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": {
                "code": "not_found",
                "message": format!(
                    "no route matches {API_PREFIX}{}",
                    uri.path()
                ),
            }
        })),
    )
        .into_response()
}

/// JSON 405 for a path that exists but not with this method.
async fn api_method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(json!({
            "error": {
                "code": "method_not_allowed",
                "message": "the method is not allowed for this route",
            }
        })),
    )
        .into_response()
}

/// The `code` for a status code the envelope middleware rewrites, refining
/// 400/422 by the rejection text axum produced (C1). axum's `Query`/`Json`
/// rejections are text/plain with stable message prefixes, which is what lets
/// a middleware — rather than a rewrite of every handler — tell a bad query
/// string from a bad body.
fn error_code_for(status: StatusCode, message: &str) -> &'static str {
    match status.as_u16() {
        400 | 422
            if message.starts_with("Failed to deserialize query string") =>
        {
            "invalid_query"
        },
        400 | 422
            if message.starts_with("Failed to deserialize the JSON")
                || message.starts_with("Failed to parse the request body") =>
        {
            "invalid_body"
        },
        400 => "bad_request",
        401 => "unauthorized",
        403 => "forbidden",
        404 => "not_found",
        405 => "method_not_allowed",
        409 => "conflict",
        429 => "rate_limited",
        500..=599 => "internal_error",
        _ => "request_failed",
    }
}

/// A canonical message for a status when the original body carried none.
fn error_message_for(status: StatusCode) -> &'static str {
    status.canonical_reason().unwrap_or("request failed")
}

/// Rewrites every 4xx/5xx response leaving the API into the unified
/// `{"error":{"code","message"}}` envelope (C1/L4-005), keeping the status
/// code. Responses that are already JSON are left untouched — the handlers'
/// `ApiError` already speaks the envelope — so this only catches axum's
/// extractor rejections (text/plain) and the empty 405 fallback body.
async fn unified_error_envelope(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if !(response.status().is_client_error()
        || response.status().is_server_error())
    {
        return response;
    }
    let is_json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .any(|part| part.trim() == "application/json")
        });
    if is_json {
        return response;
    }

    let status = response.status();
    // Preserve the original headers (Retry-After, WWW-Authenticate, CORS, …):
    // rebuilding the response from a JSON tuple would silently drop them, and
    // an auth challenge without its `WWW-Authenticate` is a different response.
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 8 * 1024)
        .await
        .unwrap_or_default();
    let raw = String::from_utf8_lossy(&body);
    let message = raw.trim();
    let code = error_code_for(status, message);
    let message = if message.is_empty() {
        error_message_for(status).to_string()
    } else {
        message.to_string()
    };
    let mut rebuilt = (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response();
    for (name, value) in headers.iter() {
        if name == axum::http::header::CONTENT_TYPE
            || name == axum::http::header::CONTENT_LENGTH
        {
            continue;
        }
        rebuilt.headers_mut().insert(name.clone(), value.clone());
    }
    rebuilt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str, host: Option<&str>) -> Request {
        let mut builder = Request::builder().uri(uri);
        if let Some(host) = host {
            builder = builder.header(axum::http::header::HOST, host);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn cors_accepts_explicit_origins() {
        let _ = build_cors(&["http://localhost:5173".to_string()]);
        let _ = build_cors(&[]);
        // An unparsable origin is dropped rather than panicking.
        let _ = build_cors(&["not a header value".to_string()]);
    }

    fn redirect_state(public_host: Option<&str>) -> RedirectState {
        RedirectState {
            tls_enabled: true,
            public_host: public_host.map(str::to_string),
        }
    }

    #[test]
    fn the_redirect_target_keeps_the_path_query_and_port() {
        let location = https_location(
            &redirect_state(None),
            &request("/api/v1/sites?page=2", Some("waf.example.com:9080")),
        )
        .unwrap();
        assert_eq!(
            location,
            "https://waf.example.com:9080/api/v1/sites?page=2"
        );

        // An empty path still points at the root.
        assert_eq!(
            https_location(
                &redirect_state(None),
                &request("/", Some("localhost:9080"))
            )
            .unwrap(),
            "https://localhost:9080/"
        );
        // Without a Host header there is nothing to redirect to.
        assert!(https_location(&redirect_state(None), &request("/", None))
            .is_none());
    }

    #[test]
    fn the_public_host_pins_the_redirect_target() {
        // The caller-supplied Host is ignored when one is configured — the
        // redirect cannot be steered by the request.
        let location = https_location(
            &redirect_state(Some("waf.example.com")),
            &request("/api/v1/sites", Some("attacker.example.net")),
        )
        .unwrap();
        assert_eq!(location, "https://waf.example.com/api/v1/sites");

        // It also covers requests that carry no Host header at all, which the
        // Host-based fallback would have to let through unredirected.
        assert_eq!(
            https_location(
                &redirect_state(Some("waf.example.com")),
                &request("/", None)
            )
            .unwrap(),
            "https://waf.example.com/"
        );
    }

    #[tokio::test]
    async fn the_health_answer_is_cached_for_the_ttl() {
        let cache: std::sync::Mutex<Option<(std::time::Instant, bool)>> =
            std::sync::Mutex::new(None);
        let calls = std::cell::Cell::new(0u32);
        let start = std::time::Instant::now();
        let probe = || {
            calls.set(calls.get() + 1);
            async { Err::<(), _>("db down") }
        };

        // Unhealthy answers are cached like any other outcome.
        assert!(
            !health_probe(&cache, Duration::from_secs(5), start, probe).await
        );
        assert!(
            !health_probe(
                &cache,
                Duration::from_secs(5),
                start + Duration::from_secs(4),
                probe
            )
            .await
        );
        assert_eq!(calls.get(), 1);

        // Once the ttl has passed a fresh probe runs.
        assert!(
            !health_probe(
                &cache,
                Duration::from_secs(5),
                start + Duration::from_secs(5),
                probe
            )
            .await
        );
        assert_eq!(calls.get(), 2);
    }

    #[tokio::test]
    async fn a_fresh_healthy_answer_short_circuits_the_probe() {
        let cache: std::sync::Mutex<Option<(std::time::Instant, bool)>> =
            std::sync::Mutex::new(None);
        let calls = std::cell::Cell::new(0u32);
        let start = std::time::Instant::now();
        let probe = || {
            calls.set(calls.get() + 1);
            async { Ok::<(), std::convert::Infallible>(()) }
        };

        assert!(
            health_probe(&cache, Duration::from_secs(5), start, probe).await
        );
        // While the cache is fresh the database is not asked again — that is
        // the point: probes must not pile onto a struggling database.
        assert!(
            health_probe(
                &cache,
                Duration::from_secs(5),
                start + Duration::from_secs(1),
                || async { Err::<(), _>("no connection") }
            )
            .await
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn only_health_endpoints_answer_on_both_schemes() {
        assert!(is_health_probe("/healthz"));
        assert!(is_health_probe("/api/v1/health"));
        assert!(!is_health_probe("/api/v1/sites"));
        assert!(!is_health_probe("/healthz/extra"));
    }

    /// C1/L4-005: axum's rejection texts map onto the contract's codes.
    #[test]
    fn rejection_texts_map_to_contract_codes() {
        assert_eq!(
            "invalid_query",
            error_code_for(
                StatusCode::BAD_REQUEST,
                "Failed to deserialize query string: invalid digit"
            )
        );
        assert_eq!(
            "invalid_body",
            error_code_for(
                StatusCode::BAD_REQUEST,
                "Failed to deserialize the JSON body into the target type"
            )
        );
        assert_eq!(
            "invalid_body",
            error_code_for(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Failed to parse the request body as JSON: trailing comma"
            )
        );
        assert_eq!(
            "method_not_allowed",
            error_code_for(StatusCode::METHOD_NOT_ALLOWED, "")
        );
        assert_eq!("not_found", error_code_for(StatusCode::NOT_FOUND, ""));
        // An unrecognised 400 stays a 400 with a generic code, not 500.
        assert_eq!(
            "bad_request",
            error_code_for(StatusCode::BAD_REQUEST, "anything")
        );
    }

    async fn body_of(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body reads");
        serde_json::from_slice(&bytes).expect("envelope body is json")
    }

    /// `api_not_found` runs on the router nested under `/api/v1`, whose
    /// fallback only sees the path *after* the prefix — the message must
    /// still echo the full path (C1).
    #[tokio::test]
    async fn not_found_message_carries_the_api_prefix() {
        let uri: axum::http::Uri = "/ghosts".parse().expect("uri");
        let response = api_not_found(uri).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());
        let body = body_of(response).await;
        assert_eq!("not_found", body["error"]["code"]);
        assert_eq!("no route matches /api/v1/ghosts", body["error"]["message"]);
    }

    #[tokio::test]
    async fn the_envelope_rewrites_non_json_client_errors_in_place() {
        use tower::ServiceExt;

        // Fields exist only to make the extractors fail on bad input.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct PageQuery {
            page: u32,
        }

        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct CreateBody {
            name: String,
        }

        let app: Router = Router::new()
            .route(
                "/things",
                get(|_query: axum::extract::Query<PageQuery>| async { "ok" })
                    .post(|_body: Json<CreateBody>| async { "ok" }),
            )
            .layer(middleware::from_fn(unified_error_envelope));

        // A bad query string is rejected text/plain by axum; the envelope
        // keeps the 400 and labels it invalid_query, as JSON.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/things?page=abc")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        assert!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("application/json")),
            "the rejection must leave as application/json"
        );
        let body = body_of(response).await;
        assert_eq!("invalid_query", body["error"]["code"]);

        // An invalid JSON body becomes invalid_body, status preserved.
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/things")
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/json",
                    )
                    .body(axum::body::Body::from("{not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        let body = body_of(response).await;
        assert_eq!("invalid_body", body["error"]["code"]);
    }

    #[tokio::test]
    async fn the_method_not_allowed_fallback_speaks_the_envelope() {
        use tower::ServiceExt;

        let app: Router = Router::new()
            .route("/x", get(|| async { "ok" }))
            .method_not_allowed_fallback(api_method_not_allowed)
            .layer(middleware::from_fn(unified_error_envelope));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/x")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(StatusCode::METHOD_NOT_ALLOWED, response.status());
        let body = body_of(response).await;
        assert_eq!("method_not_allowed", body["error"]["code"]);
    }

    /// Drives the middleware over real sockets, with the same listener wiring
    /// `serve_http` uses: what matters here is that a TLS connection is seen as
    /// secured, since reading the wrong connect-info type redirects it to
    /// itself and makes the dashboard unreachable over HTTPS.
    #[tokio::test]
    async fn the_redirect_only_fires_on_cleartext_connections() {
        use crate::pki::tls::{
            crypto_provider, generate_self_signed, parse_chain,
        };
        use crate::tls::{ControlPlaneTls, MixedListener};
        use rustls::pki_types::ServerName;
        use rustls::RootCertStore;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::TlsConnector;

        let material =
            generate_self_signed("PingWAF", &["localhost".to_string()], 30)
                .unwrap();
        let tls = ControlPlaneTls::new(true);
        tls.activate(&material.cert_pem, material.key_pem.as_deref().unwrap())
            .unwrap();

        let router = Router::new()
            .route("/dashboard", get(|| async { "ok" }))
            .route("/healthz", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                RedirectState {
                    tls_enabled: true,
                    public_host: None,
                },
                redirect_cleartext_to_https,
            ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = MixedListener::new(listener, tls.acceptor());
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<ConnInfo>(),
            )
            .await;
        });

        const REQUEST: &str =
            "GET /dashboard HTTP/1.1\r\nHost: waf.example.com\r\nConnection: close\r\n\r\n";

        // Cleartext: a real HTTP answer, pointing at the TLS address.
        let mut plain = TcpStream::connect(addr).await.unwrap();
        plain.write_all(REQUEST.as_bytes()).await.unwrap();
        let mut reply = String::new();
        plain.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 308"), "{reply}");
        assert!(
            reply.contains("location: https://waf.example.com/dashboard"),
            "{reply}"
        );

        // Cleartext probe: answered without a certificate.
        let mut probe = TcpStream::connect(addr).await.unwrap();
        probe
            .write_all(
                b"GET /healthz HTTP/1.1\r\nHost: waf.example.com\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut reply = String::new();
        probe.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");

        // TLS: served as-is.
        let mut roots = RootCertStore::empty();
        roots
            .add(parse_chain(&material.cert_pem).unwrap().remove(0))
            .unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(
            crypto_provider().clone(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = TlsConnector::from(std::sync::Arc::new(client_config));
        let name = ServerName::try_from("localhost").unwrap();
        let mut secure = connector
            .connect(name, TcpStream::connect(addr).await.unwrap())
            .await
            .unwrap();
        secure.write_all(REQUEST.as_bytes()).await.unwrap();
        let mut reply = String::new();
        secure.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    }
}
