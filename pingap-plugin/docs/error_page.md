# error_page

Replaces error responses with branded, template-rendered pages. When a response
carries a status code that has a custom error page configured, the body is fully
replaced by the rendered template and the correct `Content-Type` /
`Cache-Control` headers are set.

Templates use [Tera](https://keats.github.io/tera/) (Jinja2-like) syntax and are
compiled **once** at plugin initialisation — never per request — so the hot path
only pays for a render.

- **Step:** `response` (intercepts error responses from upstream and the proxy)
- **Registered as:** `error_page`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `error_page`. |
| `use_defaults` | bool | `true` | Serve the built-in PingWAF pages for `403`, `429`, `502`, `503`, `504`. Custom `[[pages]]` entries override the defaults for the same status code. |
| `pages` | array | `[]` | List of custom error pages (see below). |

Each `[[pages]]` entry:

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `status_code` | int | — | HTTP status this page handles (`403`, `429`, `502`, ...). |
| `content_type` | string | `text/html` | Response `Content-Type`. A `charset=utf-8` suffix is added automatically for textual/JSON types when omitted. |
| `name` | string | `""` | Human-readable label (used in logs). |
| `enabled` | bool | `true` | Disabled pages are ignored. |
| `template` | string | `""` | Tera/Jinja2 template body. |

## Template context variables

Every template — built-in or custom — receives the following variables:

| Variable | Description |
| --- | --- |
| `request_id` | Unique request/event ID. |
| `error_code` | HTTP status code (`403`, `429`, ...). |
| `error_message` | Human-readable reason phrase (`Forbidden`, ...). |
| `site_name` | Site/domain name. |
| `client_ip` | Client IP address. |
| `timestamp` | ISO 8601 (RFC 3339) timestamp. |
| `method` | HTTP method. |
| `path` | Request path. |
| `host` | Request host. |
| `user_agent` | Client user agent. |
| `waf_rule` | WAF rule that triggered (empty when not applicable). |
| `waf_details` | WAF event details (empty when not applicable). |

The built-in pages also `{% include "_pw_style" %}`, a shared CSS partial
registered into the template engine. Custom templates may include it too.

## Response flow

1. The response status code is read.
2. The active page set is resolved for the request host — control-plane pages
   take priority over local config (see below).
3. If no page matches the status, the response passes through unchanged.
4. Otherwise the template is rendered with the context variables above, the body
   is fully replaced, and `Content-Type`, `Transfer-Encoding: chunked` and
   `Cache-Control: private, no-store` headers are set.
5. If rendering fails, the plugin falls back to a short `text/plain` body so the
   client still receives a valid response.

## Built-in pages

| Status | Page |
| --- | --- |
| `403` | **Access Denied** — WAF block page with event ID, time, client IP, path and (when present) the triggering rule. |
| `429` | **Rate Limit Exceeded** — with an optional `retry_after` hint. |
| `502` / `503` / `504` | **Service Temporarily Unavailable** — asks the visitor to try again later. |

All built-in pages are responsive, PingWAF-branded (orange accent) and support
light/dark mode via the `prefers-color-scheme` media query.

## Examples

Use the built-in pages only:

```toml
[plugins.error_page]
category = "error_page"
step = "response"
use_defaults = true
```

Override the block page and return JSON for rate limits:

```toml
[plugins.error_page]
category = "error_page"
step = "response"
use_defaults = true

[[plugins.error_page.pages]]
status_code = 403
content_type = "text/html"
name = "Custom WAF Block"
template = """
<html><body>
<h1>403 - Blocked</h1>
<p>Request ID: {{ request_id }}</p>
<p>If you believe this is an error, contact support.</p>
</body></html>
"""

[[plugins.error_page.pages]]
status_code = 429
content_type = "application/json"
name = "Rate Limit JSON"
template = '{"error":"rate_limit_exceeded","retry_after":60,"request_id":"{{ request_id }}"}'

[locations.site]
upstream = "backend"
path = "/"
plugins = ["error_page"]
```

## Control-plane integration

Like the other PingWAF plugins, when a `PingWafAgent` control-plane instance is
running and has error pages for the request's domain, those pages take priority
over the local configuration. Agent-supplied pages are compiled per host and
cached, then rebuilt automatically when the agent's config hash changes.
Entries idle for more than 600 seconds are evicted, least-recently-used
entries are dropped beyond 1024 hosts (the bound converges within one sweep
interval), and a background sweep runs at most once a minute.

## Usage notes

- Templates are compiled at plugin init; a template that fails to compile is a
  configuration error and surfaces at `pingap -t`.
- Responses are sent with `Cache-Control: private, no-store` so proxies never
  cache error pages.
- The body is replaced via chunked transfer encoding, so any upstream
  `Content-Length` is removed.
- `waf_rule` / `waf_details` are currently exposed as empty strings; guard their
  use with `{% if waf_rule %}` in custom templates.
