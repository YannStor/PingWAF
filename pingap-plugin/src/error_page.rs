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

//! Custom error page plugin — replaces error responses with branded,
//! template-rendered pages.
//!
//! Runs at the response phase. When an upstream (or proxy generated) response
//! carries a status code that has a custom error page configured, the response
//! body is fully replaced by the rendered template and the appropriate
//! `Content-Type` / `Cache-Control` headers are set.
//!
//! Templates use [Tera](https://keats.github.io/tera/) (Jinja2-like) syntax and
//! are compiled **once** at plugin initialisation — never per request — so the
//! hot path only pays for a render.
//!
//! Page definitions come from two sources, resolved per request:
//! * a [`PingWafAgent`] control-plane instance, when one is running and has
//!   error pages for the request's domain (cached per host, rebuilt when the
//!   agent's config hash changes); these take priority;
//! * otherwise the locally configured `pages` from the plugin's TOML config,
//!   optionally merged with the built-in PingWAF defaults.

use super::{Error, get_hash_key};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use http::header;
use http::{HeaderValue, StatusCode};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HTTP_HEADER_CONTENT_HTML, HTTP_HEADER_NO_STORE,
    HTTP_HEADER_TRANSFER_CHUNKED, ModifyResponseBody, Plugin,
    ResponseBodyPluginResult, ResponsePluginResult, ensure_client_ip, get_host,
    get_req_header_value,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingwaf_agent::PingWafAgent;
use pingwaf_agent::cache::CustomErrorPage;
use pingwaf_challenge::generate_request_id;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tera::{Context, Tera};
use tracing::{debug, warn};

use crate::host_cache::{HostCacheSweep, touch};

/// Key under which the response-body replacer is stashed in [`Ctx`].
const PLUGIN_ID: &str = "_error_page_";
/// Plugin category name used in error messages and factory registration.
const CATEGORY: &str = "error_page";
/// Name of the shared style partial registered into every [`Tera`] instance so
/// pages can `{% include "_pw_style" %}` it.
const STYLE_PARTIAL: &str = "_pw_style";

type Result<T, E = Error> = std::result::Result<T, E>;

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid {
        category: CATEGORY.to_string(),
        message: message.into(),
    }
}

// ─────────────────────────────────────────────────────────────
// Built-in PingWAF error pages
// ─────────────────────────────────────────────────────────────

/// Shared CSS for the built-in pages. Registered as a partial so the individual
/// pages stay small and consistent. Supports light/dark via
/// `prefers-color-scheme` and uses the PingWAF orange accent.
///
/// `pub(crate)` so the challenge plugin's short-circuit pages (WAF block,
/// rate limit, …) render in the same visual family — those responses bypass
/// the response-phase plugin pipeline entirely.
pub(crate) const PW_STYLE: &str = r##"<style>
:root{
  --bg:#f6f7f9;--card:#ffffff;--fg:#141417;--muted:#6b6b73;--border:#e7e7ea;
  --accent:#f6821f;--code-bg:#fafafb;--shadow:0 24px 60px rgba(20,20,25,.10);
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0d0d10;--card:#16161a;--fg:#f3f3f5;--muted:#9a9aa4;--border:#26262d;
    --accent:#ff9440;--code-bg:#101014;--shadow:0 24px 60px rgba(0,0,0,.5);
  }
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:24px;color:var(--fg);background-color:var(--bg);
  background-image:
    radial-gradient(60rem 40rem at 12% 15%,rgba(246,130,31,.10),transparent 60%),
    radial-gradient(50rem 40rem at 88% 85%,rgba(246,130,31,.08),transparent 60%);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
}
.card{
  width:100%;max-width:560px;background:var(--card);border:1px solid var(--border);
  border-radius:18px;padding:44px 36px;box-shadow:var(--shadow);text-align:center;
  animation:rise .5s cubic-bezier(.2,.8,.2,1) both;
}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.icon{
  width:68px;height:68px;margin:0 auto 18px;border-radius:18px;display:flex;
  align-items:center;justify-content:center;background:rgba(246,130,31,.12);
}
.icon svg{width:36px;height:36px;stroke:var(--accent);fill:none;stroke-width:1.7;
  stroke-linecap:round;stroke-linejoin:round}
.code{
  font-size:15px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;
  color:var(--accent);margin-bottom:6px;
}
h1{font-size:24px;margin:0 0 10px;letter-spacing:-.015em;font-weight:650}
.msg{color:var(--muted);margin:0 0 26px;line-height:1.65;font-size:14.5px}
.details{
  background:var(--code-bg);border:1px solid var(--border);border-radius:12px;
  padding:14px 16px;text-align:left;font-size:13px;
}
.row{display:flex;justify-content:space-between;gap:16px;padding:6px 0}
.row+.row{border-top:1px solid var(--border)}
.k{color:var(--muted);white-space:nowrap}
.v{
  color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  word-break:break-all;text-align:right;
}
.brand{margin-top:26px;font-size:12px;color:var(--muted);letter-spacing:.02em}
.brand b{color:var(--accent);font-weight:700}
</style>"##;

// NOTE: there are deliberately no built-in 403/429 pages. An origin-returned
// 403 used to be replaced with a WAF-style "Access Denied" page, which made
// every visitor (and every site owner) believe the WAF had blocked them.
// Following Cloudflare's model, origin responses are passed through untouched;
// only gateway-class failures — which the edge itself produces when the
// upstream is unreachable — get a branded page. Administrators can still
// configure custom pages for any status via the control plane.

/// 5xx — origin/gateway failure page (shared by 502/503/504). The copy must
/// make clear that the *website's server* failed, so nobody mistakes it for a
/// security block.
const PAGE_5XX: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Service Unavailable · PingWAF</title>
{% include "_pw_style" %}
</head>
<body>
<div class="card">
  <div class="icon"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg></div>
  <div class="code">Error {{ error_code }}</div>
  <h1>{{ error_code }} — Origin Server Error</h1>
  <p class="msg">The website's origin server failed to complete this request. <b>This is not a security block</b> — the request reached the website, and the website (or its gateway) answered with an error. Please try again in a few moments.</p>
  <div class="details">
    <div class="row"><span class="k">Request ID</span><span class="v">{{ request_id }}</span></div>
    <div class="row"><span class="k">Time</span><span class="v">{{ timestamp }}</span></div>
    <div class="row"><span class="k">Host</span><span class="v">{{ host }}</span></div>
    <div class="row"><span class="k">Path</span><span class="v">{{ method }} {{ path }}</span></div>
    {% if upstream_addr %}
    <div class="row"><span class="k">Upstream</span><span class="v">{{ upstream_name }} → {{ upstream_addr }}</span></div>
    {% endif %}
  </div>
  <p class="brand">Routed via <b>PingWAF</b></p>
</div>
</body>
</html>"##;

// ─────────────────────────────────────────────────────────────
// Data model
// ─────────────────────────────────────────────────────────────

/// A configured error page (before compilation).
#[derive(Debug, Clone)]
struct ErrorPageConfig {
    /// HTTP status code this page handles (403, 429, 502, ...).
    status_code: u16,
    /// Content type: `text/html`, `application/json`, `text/plain`, ...
    content_type: String,
    /// Template body (Tera / Jinja2 syntax).
    template: String,
    /// Human-readable name.
    name: String,
    /// Whether this error page is enabled.
    enabled: bool,
}

/// A compiled error page: the template lives in a [`Tera`] instance under
/// `template_name`, so rendering is a cheap lookup + render.
#[derive(Debug, Clone)]
struct CompiledErrorPage {
    status_code: u16,
    content_type: String,
    /// Name the template is registered under in the owning [`Tera`].
    template_name: String,
    name: String,
}

/// Compiled pages indexed by the status code they render for.
type CompiledErrorPageMap = Arc<HashMap<u16, CompiledErrorPage>>;
/// A [`Tera`] instance plus the pages whose templates live inside it.
type CompiledSitePages = (Arc<Tera>, CompiledErrorPageMap);

/// Per-host cache of agent-supplied compiled pages plus the fingerprint they
/// were built from.
struct CachedSitePages {
    fingerprint: Arc<str>,
    tera: Arc<Tera>,
    pages: CompiledErrorPageMap,
    /// Unix seconds of the last cache hit; feeds the host-cache TTL sweep
    /// (`host_cache`) — wildcard-matched scanner hosts would otherwise cache
    /// a compiled Tera instance forever.
    last_used: AtomicU64,
}

/// Fully replaces the response body with a pre-rendered error page.
struct ErrorPageReplacer {
    body: Bytes,
}

impl ModifyResponseBody for ErrorPageReplacer {
    fn handle(
        &mut self,
        _session: &Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<()> {
        // Discard whatever the upstream produced.
        if let Some(data) = body {
            data.clear();
        }
        if end_of_stream {
            *body = Some(self.body.clone());
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "error_page"
    }
}

/// Custom error page plugin.
pub struct ErrorPagePlugin {
    /// Compiled templates indexed by status code (locally configured).
    templates: Arc<ArcSwap<HashMap<u16, CompiledErrorPage>>>,
    /// Tera engine holding the locally configured templates.
    tera: Arc<Tera>,
    /// Whether the built-in PingWAF pages are used.
    use_defaults: bool,
    /// Agent-supplied pages keyed by host.
    site_pages: DashMap<String, CachedSitePages>,
    /// Sweep gate for the `site_pages` host cache (TTL + hard cap).
    pages_sweep: HostCacheSweep,
    hash_value: String,
}

impl ErrorPagePlugin {
    /// Create a new plugin from configuration.
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new error_page plugin");
        Self::try_from(params)
    }

    /// Build the [`Content-Type`] header value, appending a charset for textual
    /// types when the configuration omitted one.
    fn content_type_value(content_type: &str) -> HeaderValue {
        let mut value = content_type.trim().to_string();
        if value.is_empty() {
            value = "text/html".to_string();
        }
        let lower = value.to_ascii_lowercase();
        if (lower.starts_with("text/") || lower.contains("json"))
            && !lower.contains("charset")
        {
            value.push_str("; charset=utf-8");
        }
        HeaderValue::from_str(&value)
            .unwrap_or_else(|_| HTTP_HEADER_CONTENT_HTML.1.clone())
    }

    /// Resolve the active page set for `host`: agent pages when available,
    /// otherwise the locally configured pages.
    fn resolve(&self, host: &str) -> CompiledSitePages {
        if !host.is_empty()
            && let Some(agent) = PingWafAgent::instance()
            && let Some(site) = agent.get_rules_for_domain(host)
            && !site.error_pages.is_empty()
        {
            let now = crate::host_cache::unix_now();
            self.pages_sweep.prune(&self.site_pages, now, |cached| {
                cached.last_used.load(std::sync::atomic::Ordering::Relaxed)
            });
            let fingerprint = agent.config_hash();
            if let Some(cached) = self.site_pages.get(host)
                && cached.fingerprint == fingerprint
            {
                touch(&cached.last_used, now);
                return (cached.tera.clone(), cached.pages.clone());
            }
            match build_site_pages(&site.error_pages) {
                Ok((tera, pages)) => {
                    self.site_pages.insert(
                        host.to_string(),
                        CachedSitePages {
                            fingerprint,
                            tera: tera.clone(),
                            pages: pages.clone(),
                            last_used: AtomicU64::new(now),
                        },
                    );
                    return (tera, pages);
                },
                Err(e) => {
                    debug!(
                        error = e.to_string(),
                        "compile agent error pages failed"
                    );
                },
            }
        }
        (self.tera.clone(), self.templates.load_full())
    }

    /// Build the Tera render context for the current request.
    fn build_context(
        session: &Session,
        ctx: &Ctx,
        status: u16,
        request_id: &str,
        client_ip: &str,
        host: &str,
    ) -> Context {
        let req = session.req_header();
        let error_message = StatusCode::from_u16(status)
            .ok()
            .and_then(|s| s.canonical_reason())
            .unwrap_or("Error");
        let mut c = Context::new();
        c.insert("request_id", request_id);
        c.insert("error_code", &status);
        c.insert("error_message", error_message);
        c.insert("site_name", host);
        c.insert("client_ip", client_ip);
        c.insert("timestamp", &Utc::now().to_rfc3339());
        c.insert("method", req.method.as_str());
        c.insert("path", req.uri.path());
        c.insert("host", host);
        // Upstream context for gateway-class failures (502/503/504): the
        // upstream group and the backend that was tried. Both are empty on
        // non-upstream errors, so `{% if upstream_addr %}` guards work.
        c.insert("upstream_name", ctx.upstream.name.as_ref());
        c.insert("upstream_addr", &ctx.upstream.address);
        // Aliases the console documents for template authors.
        c.insert("request_path", req.uri.path());
        c.insert("request_host", host);
        c.insert(
            "user_agent",
            get_req_header_value(req, "user-agent").unwrap_or_default(),
        );
        // No WAF verdict is threaded through `Ctx` today; expose empty values so
        // `{% if waf_rule %}` guards behave and templates never fail.
        c.insert("waf_rule", "");
        c.insert("waf_details", "");
        // Optional retry hint honoured by the 429 page when present.
        c.insert("retry_after", "");
        c
    }

    /// Shared response-phase logic. Idempotent: if a body replacer is already
    /// registered for this request it does nothing, so implementing both the
    /// upstream-response and response hooks cannot double-render.
    fn apply(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        if ctx.get_modify_body_handler(PLUGIN_ID).is_some() {
            return Ok(ResponsePluginResult::Unchanged);
        }

        let status = upstream_response.status.as_u16();
        let host = get_host(session.req_header())
            .unwrap_or_default()
            .to_string();
        let (tera, pages) = self.resolve(&host);
        let Some(page) = pages.get(&status) else {
            return Ok(ResponsePluginResult::Unchanged);
        };

        let request_id = ctx
            .state
            .request_id
            .clone()
            .unwrap_or_else(generate_request_id);
        let client_ip = ensure_client_ip(session, ctx).to_string();
        let context = Self::build_context(
            session,
            ctx,
            status,
            &request_id,
            &client_ip,
            &host,
        );

        // Render, falling back to a plain-text body if the template errors.
        let (body, content_type) = match tera
            .render(&page.template_name, &context)
        {
            Ok(rendered) => (rendered, page.content_type.clone()),
            Err(e) => {
                warn!(
                    status,
                    template = %page.template_name,
                    error = %e,
                    "error_page render failed, falling back to plain text"
                );
                let error_message = StatusCode::from_u16(status)
                    .ok()
                    .and_then(|s| s.canonical_reason())
                    .unwrap_or("Error");
                (
                    format!(
                        "{status} {error_message}\nRequest ID: {request_id}\n"
                    ),
                    "text/plain".to_string(),
                )
            },
        };

        // Rewrite the response headers for the new body.
        upstream_response.remove_header(&header::CONTENT_LENGTH);
        let _ = upstream_response.insert_header(
            header::TRANSFER_ENCODING,
            HTTP_HEADER_TRANSFER_CHUNKED.1.clone(),
        );
        let _ = upstream_response.insert_header(
            header::CONTENT_TYPE,
            Self::content_type_value(&content_type),
        );
        let _ = upstream_response.insert_header(
            HTTP_HEADER_NO_STORE.0.clone(),
            HTTP_HEADER_NO_STORE.1.clone(),
        );

        ctx.add_modify_body_handler(
            PLUGIN_ID,
            Box::new(ErrorPageReplacer {
                body: Bytes::from(body),
            }),
        );

        debug!(
            status,
            page = %page.name,
            page_status = page.status_code,
            use_defaults = self.use_defaults,
            "error_page replaced response"
        );
        Ok(ResponsePluginResult::Modified)
    }
}

/// Compile agent-supplied error pages into a fresh [`Tera`] + page map.
fn build_site_pages(pages: &[CustomErrorPage]) -> Result<CompiledSitePages> {
    let mut tera = Tera::default();
    tera.add_raw_template(STYLE_PARTIAL, PW_STYLE)
        .map_err(|e| {
            invalid(format!("failed to register style partial: {e}"))
        })?;
    let mut map: HashMap<u16, CompiledErrorPage> = HashMap::new();
    for (i, page) in pages.iter().enumerate() {
        if !page.enabled {
            continue;
        }
        let Ok(status_code) = u16::try_from(page.status_code) else {
            continue;
        };
        let template_name = format!("pw_agent_{status_code}_{i}");
        tera.add_raw_template(&template_name, &page.body_template)
            .map_err(|e| {
                invalid(format!(
                    "invalid template for status {status_code} ({}): {e}",
                    page.name
                ))
            })?;
        map.insert(
            status_code,
            CompiledErrorPage {
                status_code,
                content_type: page.content_type.clone(),
                template_name,
                name: page.name.clone(),
            },
        );
    }
    Ok((Arc::new(tera), Arc::new(map)))
}

/// Parse the `pages` array from a plugin config into [`ErrorPageConfig`]s.
fn parse_pages(value: &PluginConf) -> Vec<ErrorPageConfig> {
    let Some(items) = value.get("pages").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let status_code =
                item.get("status_code").and_then(|v| v.as_integer())? as u16;
            let template = item
                .get("template")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            Some(ErrorPageConfig {
                status_code,
                content_type: item
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("text/html")
                    .to_string(),
                template,
                name: item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                enabled: item
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
            })
        })
        .collect()
}

impl TryFrom<&PluginConf> for ErrorPagePlugin {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let use_defaults = value
            .get("use_defaults")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let mut tera = Tera::default();
        tera.add_raw_template(STYLE_PARTIAL, PW_STYLE)
            .map_err(|e| {
                invalid(format!("failed to register style partial: {e}"))
            })?;
        let mut map: HashMap<u16, CompiledErrorPage> = HashMap::new();

        // Built-in PingWAF pages: gateway-class failures only. Origin 4xx
        // responses pass through untouched (see the note above PAGE_5XX).
        if use_defaults {
            let defaults: [(u16, &str, &str, &str); 3] = [
                (502, "pw_default_5xx", PAGE_5XX, "PingWAF Bad Gateway"),
                (503, "pw_default_5xx", PAGE_5XX, "PingWAF Unavailable"),
                (504, "pw_default_5xx", PAGE_5XX, "PingWAF Gateway Timeout"),
            ];
            let mut registered: HashMap<&str, &str> = HashMap::new();
            for (status, name, body, label) in defaults {
                if !registered.contains_key(name) {
                    tera.add_raw_template(name, body).map_err(|e| {
                        invalid(format!(
                            "failed to compile default {name}: {e}"
                        ))
                    })?;
                    registered.insert(name, body);
                }
                map.insert(
                    status,
                    CompiledErrorPage {
                        status_code: status,
                        content_type: "text/html; charset=utf-8".to_string(),
                        template_name: name.to_string(),
                        name: label.to_string(),
                    },
                );
            }
        }

        // Locally configured custom pages override the defaults.
        for (i, page) in parse_pages(value).into_iter().enumerate() {
            if !page.enabled {
                continue;
            }
            let template_name = format!("pw_custom_{}_{i}", page.status_code);
            tera.add_raw_template(&template_name, &page.template)
                .map_err(|e| {
                    invalid(format!(
                        "invalid template for status {} ({}): {e}",
                        page.status_code, page.name
                    ))
                })?;
            map.insert(
                page.status_code,
                CompiledErrorPage {
                    status_code: page.status_code,
                    content_type: page.content_type,
                    template_name,
                    name: page.name,
                },
            );
        }

        Ok(Self {
            templates: Arc::new(ArcSwap::from_pointee(map)),
            tera: Arc::new(tera),
            use_defaults,
            site_pages: DashMap::new(),
            pages_sweep: HostCacheSweep::default(),
            hash_value,
        })
    }
}

#[async_trait]
impl Plugin for ErrorPagePlugin {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        self.apply(session, ctx, upstream_response)
    }

    fn handle_upstream_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        self.apply(session, ctx, upstream_response)
    }

    fn handle_response_body(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> pingora::Result<ResponseBodyPluginResult> {
        if let Some(modifier) = ctx.get_modify_body_handler(PLUGIN_ID) {
            modifier.handle(session, body, end_of_stream)?;
            Ok(if end_of_stream {
                ResponseBodyPluginResult::FullyReplaced
            } else {
                ResponseBodyPluginResult::PartialReplaced
            })
        } else {
            Ok(ResponseBodyPluginResult::Unchanged)
        }
    }
}

register_plugin!("error_page", ErrorPagePlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::h1_session as session;
    use pingora::http::ResponseHeader;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_defaults_registered() {
        let plugin = ErrorPagePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
category = "error_page"
use_defaults = true
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(plugin.use_defaults);
        let map = plugin.templates.load_full();
        for status in [502u16, 503, 504] {
            assert!(map.contains_key(&status), "missing default {status}");
        }
        // Origin-returned 4xx responses must pass through untouched: the
        // built-in WAF-style 403/429 pages were the reason every origin 403
        // looked like a security block.
        assert!(!map.contains_key(&403), "403 must not be a default page");
        assert!(!map.contains_key(&429), "429 must not be a default page");
    }

    #[test]
    fn test_render_default_5xx_names_the_origin() {
        let plugin = ErrorPagePlugin::new(
            &toml::from_str::<PluginConf>(r###"category = "error_page""###)
                .unwrap(),
        )
        .unwrap();
        let mut ctx = Context::new();
        ctx.insert("request_id", "req-123");
        ctx.insert("error_code", &502u16);
        ctx.insert("timestamp", "2025-01-01T00:00:00Z");
        ctx.insert("client_ip", "10.0.0.1");
        ctx.insert("method", "GET");
        ctx.insert("path", "/");
        ctx.insert("host", "example.com");
        let out = plugin.tera.render("pw_default_5xx", &ctx).unwrap();
        assert_eq!(true, out.contains("Origin Server Error"));
        // The copy must rule out a security block: that ambiguity is exactly
        // what made origin failures indistinguishable from WAF blocks.
        assert_eq!(true, out.contains("not a security block"));
        assert_eq!(true, out.contains("req-123"));
        assert_eq!(true, out.contains("PingWAF"));
        // Without upstream context the details block omits the upstream
        // row entirely — no empty "Upstream →" line.
        assert_eq!(false, out.contains("Upstream"));
    }

    #[test]
    fn test_render_default_5xx_shows_upstream_when_present() {
        let plugin = ErrorPagePlugin::new(
            &toml::from_str::<PluginConf>(r###"category = "error_page""###)
                .unwrap(),
        )
        .unwrap();
        let mut ctx = Context::new();
        ctx.insert("request_id", "req-123");
        ctx.insert("error_code", &503u16);
        ctx.insert("timestamp", "2025-01-01T00:00:00Z");
        ctx.insert("client_ip", "10.0.0.1");
        ctx.insert("method", "GET");
        ctx.insert("path", "/");
        ctx.insert("host", "example.com");
        ctx.insert("upstream_name", "origin-pool");
        ctx.insert("upstream_addr", "10.0.0.9:8080");
        let out = plugin.tera.render("pw_default_5xx", &ctx).unwrap();
        // A gateway-class failure names the upstream group and the
        // backend that was tried — that is what operators need when the
        // 503 is an upstream outage rather than a bad request.
        assert_eq!(true, out.contains("origin-pool"));
        assert_eq!(true, out.contains("10.0.0.9:8080"));
    }

    #[test]
    fn test_custom_pages_override_defaults() {
        let plugin = ErrorPagePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
category = "error_page"
use_defaults = true

[[pages]]
status_code = 403
content_type = "text/html"
name = "Custom WAF Block"
template = "<html><body><h1>403 - Blocked</h1><p>{{ request_id }}</p></body></html>"

[[pages]]
status_code = 429
content_type = "application/json"
name = "Rate Limit JSON"
template = '{"error":"rate_limit_exceeded","request_id":"{{ request_id }}"}'
"###,
            )
            .unwrap(),
        )
        .unwrap();
        let map = plugin.templates.load_full();
        let page = map.get(&403).unwrap();
        assert_eq!("Custom WAF Block", page.name);

        let mut ctx = Context::new();
        ctx.insert("request_id", "abc");
        let html = plugin.tera.render(&page.template_name, &ctx).unwrap();
        assert_eq!(true, html.contains("403 - Blocked"));
        assert_eq!(true, html.contains("abc"));
        let page429 = map.get(&429).unwrap();
        let json = plugin.tera.render(&page429.template_name, &ctx).unwrap();
        assert_eq!(true, json.contains("rate_limit_exceeded"));
        assert_eq!(true, json.contains("abc"));
    }

    #[tokio::test]
    async fn test_replaces_matching_status() {
        let plugin = ErrorPagePlugin::new(
            &toml::from_str::<PluginConf>(r###"category = "error_page""###)
                .unwrap(),
        )
        .unwrap();

        // Not a host agent-mode tests register: resolve() defers to the
        // process-global agent when it has pages for the host, so
        // "errorpage.test" here races with agent tests running in parallel.
        let mut s = session("GET", "/", "errorpage.test").await;
        let mut resp = ResponseHeader::build_no_case(502, None).unwrap();
        let result = plugin
            .handle_response(&mut s, &mut Ctx::default(), &mut resp)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Modified, result);
        assert_eq!(
            "text/html; charset=utf-8",
            resp.headers.get("content-type").unwrap().to_str().unwrap()
        );
        assert_eq!(
            "private, no-store",
            resp.headers.get("cache-control").unwrap().to_str().unwrap()
        );
    }

    #[tokio::test]
    async fn test_origin_403_passes_through() {
        let plugin = ErrorPagePlugin::new(
            &toml::from_str::<PluginConf>(r###"category = "error_page""###)
                .unwrap(),
        )
        .unwrap();

        // The whole point of dropping the default 403 page: an origin's own
        // 403 must reach the visitor as the origin produced it.
        let mut s = session("GET", "/", "errorpage.test").await;
        let mut resp = ResponseHeader::build_no_case(403, None).unwrap();
        let result = plugin
            .handle_response(&mut s, &mut Ctx::default(), &mut resp)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Unchanged, result);
    }

    #[tokio::test]
    async fn test_passes_through_unconfigured_status() {
        let plugin = ErrorPagePlugin::new(
            &toml::from_str::<PluginConf>(r###"category = "error_page""###)
                .unwrap(),
        )
        .unwrap();

        let mut s = session("GET", "/ok", "errorpage.test").await;
        let mut resp = ResponseHeader::build_no_case(200, None).unwrap();
        let result = plugin
            .handle_response(&mut s, &mut Ctx::default(), &mut resp)
            .await
            .unwrap();
        assert_eq!(ResponsePluginResult::Unchanged, result);
    }

    mod agent_mode {
        use super::*;
        use crate::waf::tests::install_test_agent;
        use pingwaf_proto::control_plane as proto;
        use pretty_assertions::assert_eq;

        /// Agent-supplied pages replace responses for their host, take
        /// precedence over the built-in defaults and expose the variables the
        /// console documents (including the `request_path`/`request_host`
        /// aliases).
        #[tokio::test]
        async fn agent_pages_replace_response() {
            let (_guard, agent, _dir) = install_test_agent().await;
            agent
                .rule_cache
                .update_from_site_config(&proto::SiteConfig {
                    sites: vec![proto::Site {
                        id: "site-1".to_string(),
                        name: "example".to_string(),
                        domain: "example.com".to_string(),
                        alternate_domains: Vec::new(),
                        status: 0,
                        rules: Some(proto::RuleBundle {
                            site_id: "site-1".to_string(),
                            config_hash: "hash-1".to_string(),
                            error_pages: vec![proto::CustomErrorPage {
                                id: "ep-1".to_string(),
                                status_code: 503,
                                content_type: "text/html".to_string(),
                                body_template: concat!(
                                    "<html><body>{{ error_code }} on",
                                    " {{ request_path }} at {{ request_host }}",
                                    " for {{ request_id }}</body></html>"
                                )
                                .to_string(),
                                name: "custom 503".to_string(),
                                enabled: true,
                            }],
                            ..Default::default()
                        }),
                        trust_proxy_headers: false,
                        trusted_header: String::new(),
                        trust_last_hop: false,
                        trusted_proxy_ranges: Vec::new(),
                        downstream_timeout_secs: 60,
                    }],
                    config_hash: "hash-1".to_string(),
                    updated_at: None,
                })
                .unwrap();

            let plugin = ErrorPagePlugin::new(
                &toml::from_str::<PluginConf>(r###"category = "error_page""###)
                    .unwrap(),
            )
            .unwrap();

            let mut s = session("GET", "/maintenance", "example.com").await;
            let mut resp = ResponseHeader::build_no_case(503, None).unwrap();
            let result = plugin
                .handle_response(&mut s, &mut Ctx::default(), &mut resp)
                .await
                .unwrap();
            assert_eq!(ResponsePluginResult::Modified, result);
            // The compiled agent page renders with the documented variables
            // filled in.
            let (tera, pages) = plugin.resolve("example.com");
            let page = pages.get(&503).expect("agent page compiled");
            let mut c = Context::new();
            c.insert("error_code", &503u16);
            c.insert("request_id", "req-1");
            c.insert("request_path", "/maintenance");
            c.insert("request_host", "example.com");
            let rendered = tera.render(&page.template_name, &c).unwrap();
            assert!(rendered.contains("503 on /maintenance"));
            assert!(rendered.contains("at example.com"));
            assert!(rendered.contains("req-1"));
        }

        /// A status without an agent page is passed through untouched — agent
        /// pages replace the built-in defaults for that host.
        #[tokio::test]
        async fn agent_pages_shadow_defaults_per_host() {
            let (_guard, agent, _dir) = install_test_agent().await;
            agent
                .rule_cache
                .update_from_site_config(&proto::SiteConfig {
                    sites: vec![proto::Site {
                        id: "site-1".to_string(),
                        name: "example".to_string(),
                        domain: "example.com".to_string(),
                        alternate_domains: Vec::new(),
                        status: 0,
                        rules: Some(proto::RuleBundle {
                            site_id: "site-1".to_string(),
                            config_hash: "hash-1".to_string(),
                            error_pages: vec![proto::CustomErrorPage {
                                id: "ep-1".to_string(),
                                status_code: 403,
                                content_type: "text/html".to_string(),
                                body_template: "custom".to_string(),
                                name: "custom 403".to_string(),
                                enabled: true,
                            }],
                            ..Default::default()
                        }),
                        trust_proxy_headers: false,
                        trusted_header: String::new(),
                        trust_last_hop: false,
                        trusted_proxy_ranges: Vec::new(),
                        downstream_timeout_secs: 60,
                    }],
                    config_hash: "hash-1".to_string(),
                    updated_at: None,
                })
                .unwrap();

            let plugin = ErrorPagePlugin::new(
                &toml::from_str::<PluginConf>(r###"category = "error_page""###)
                    .unwrap(),
            )
            .unwrap();

            // 404 has no agent page: untouched despite the built-in default.
            let mut s = session("GET", "/x", "example.com").await;
            let mut resp = ResponseHeader::build_no_case(404, None).unwrap();
            let result = plugin
                .handle_response(&mut s, &mut Ctx::default(), &mut resp)
                .await
                .unwrap();
            assert_eq!(ResponsePluginResult::Unchanged, result);

            // Another host (no agent pages) still gets the built-in defaults
            // — but only for gateway-class statuses; an origin 403 passes
            // through untouched.
            let mut s = session("GET", "/x", "other.example.com").await;
            let mut resp = ResponseHeader::build_no_case(502, None).unwrap();
            let result = plugin
                .handle_response(&mut s, &mut Ctx::default(), &mut resp)
                .await
                .unwrap();
            assert_eq!(ResponsePluginResult::Modified, result);
            let mut s = session("GET", "/x", "other.example.com").await;
            let mut resp = ResponseHeader::build_no_case(403, None).unwrap();
            let result = plugin
                .handle_response(&mut s, &mut Ctx::default(), &mut resp)
                .await
                .unwrap();
            assert_eq!(ResponsePluginResult::Unchanged, result);
        }
    }
}
