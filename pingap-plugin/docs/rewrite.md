# rewrite

Rule-based request and response rewriting. Each rule carries an optional
condition expression, a direction (request or response) and a list of
operations. Request rules run during the request phase and can rewrite the
path, query string and request headers; response rules run during the response
phase and can rewrite response headers, the status code and the response body.

Unlike [`response_headers`](response_headers.md) (headers only) and
[`sub_filter`](sub_filter.md) (body only), `rewrite` provides a single unified,
conditional engine that spans all three phases.

- **Step:** `request` (default) or `early_request` — configurable
- **Registered as:** `rewrite`

Rewrites never block traffic: the request phase always returns `Continue`, and
the response phases mutate the response in place.

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `rewrite`. |
| `step` | string | `request` | `early_request` or `request`. Any other value is a configuration error. |
| `rules` | JSON string \| array | `[]` | The rewrite rules. Accepts either a JSON array encoded as a string, or a native TOML/JSON array. |

## Rule format

Each element of `rules` is an object:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `id` | string | `""` | Stable identifier. Used for logging and control-plane correlation. |
| `name` | string | `""` | Human-readable label. |
| `condition` | string | none | Condition expression. When omitted the rule always matches. See [Conditions](#conditions). |
| `direction` | string | `request` | `request` or `response`. Selects the phase the rule applies to. |
| `operations` | object[] | `[]` | Ordered list of operations to apply when the rule matches. See [Operations](#operations). |
| `priority` | int | `0` | Rules are applied in ascending `priority` order (lower first). |
| `enabled` | bool | `true` | Disabled rules are compiled out and never evaluated. |

## Operations

Operations are internally tagged by a `type` field (snake_case). Request
direction honours header/path/query operations; response direction honours
header/status/body operations.

| `type` | Fields | Direction | Effect |
| --- | --- | --- | --- |
| `set_header` | `name`, `value` | both | Set a header, replacing any existing values. |
| `add_header` | `name`, `value` | both | Append a header value, keeping existing ones. |
| `remove_header` | `name` | both | Remove a header entirely. |
| `set_path` | `value` | request | Replace the request path with a literal value. |
| `regex_replace_path` | `pattern`, `replacement` | request | Rewrite the path via a regex; `$1`/`${1}` capture groups are substituted in `replacement`. |
| `set_query_param` | `name`, `value` | request | Set (or add) a query-string parameter. |
| `remove_query_param` | `name` | request | Remove a query-string parameter. |
| `replace_body` | `search`, `replacement` | response | Literal search/replace across the buffered response body. |
| `set_body` | `content` | response | Replace the entire response body with `content`. |
| `set_status_code` | `code` | response | Override the response status code (e.g. `404` → `200`). |

Regex patterns are compiled once at configuration load, not per request. Header
names and status codes are likewise pre-parsed and validated up front, so an
invalid operation is a configuration error rather than a runtime failure.

## Conditions

Conditions use a Cloudflare-style expression language evaluated against the
request (or response, for `http.response.status`).

### Fields

| Field (aliases in parentheses) | Meaning |
| --- | --- |
| `http.request.uri.path` (`request.path`, `uri.path`) | Request path. |
| `http.request.uri.full` (`http.request.uri`, `request.uri`) | Full path + query string. |
| `http.request.uri.query` (`request.query`) | Query string. |
| `http.request.method` (`request.method`) | HTTP method. |
| `http.host` (`host`) | Request `Host` header. |
| `ip.src` (`client.ip`) | Client IP address. |
| `http.response.status` (`response.status`, `status`) | Response status code. Only meaningful in the response direction (evaluates to `0` during the request phase). |
| `http.request.headers["X-Custom"]` | Any other dotted path is treated as a **request** header lookup. Header conditions always read the request headers, in both the request and response phases. |

### Operators

| Operator | Aliases | Description |
| --- | --- | --- |
| `eq` | `=`, `==` | Equal. |
| `ne` | `neq`, `!=` | Not equal. |
| `contains` | — | Substring match. |
| `starts_with` | `startswith` | Prefix match. |
| `ends_with` | `endswith` | Suffix match. |
| `matches` | — | Regex match (string pattern). |
| `in` | — | Membership in a `{ ... }` set. |
| `lt` `le` `gt` `ge` | `<`, `<=`, `>`, `>=` | Numeric comparison (e.g. status codes). |
| `exists` | — | Field/header is present. No right-hand value. |
| `not exists` | — | Field/header is absent. |
| `not contains` / `not matches` / `not in` | — | Negated forms of the above. |

### Logical composition

- `and`, `or` (case-insensitive), and `not` are supported.
- Group with parentheses: `(a or b) and not c`.

Examples:

```
http.request.uri.path starts_with "/api/"
http.request.method eq "POST" and http.request.uri.path contains "/admin"
http.request.headers["X-Custom"] exists
http.host eq "example.com"
http.response.status eq 404
not (http.request.uri.path in {"/health" "/metrics"})
```

## Variable interpolation

Header values (and body/content strings) support `${...}` placeholders resolved
per request:

| Placeholder | Value |
| --- | --- |
| `${request_id}` | The current request id. |
| `${client_ip}` | Client IP address. |
| `${host}` | Request `Host`. |
| `${path}` | Request path. |
| `${method}` | Request method. |

Unknown placeholders are preserved verbatim. Interpolation is skipped entirely
when the string contains no `${`, so static values incur no allocation.

## Control plane vs standalone

Rules are resolved per request:

- When a **PingWafAgent** control-plane instance is running, the server-pushed
  rewrite rules for the request's `Host` are used. Per-domain rules are cached
  and rebuilt automatically when the agent's config hash changes.
- Otherwise (**standalone pingap**) the locally configured `rules` above are
  used.

Local rules are held in an `ArcSwap` and hot-swapped on reload; agent rules are
converted to the same compiled representation and cached per host in a
`DashMap`, so the hot path never re-parses configuration. Entries idle for more
than 600 seconds are evicted, least-recently-used entries are dropped beyond
1024 hosts (the bound converges within one sweep interval), and a background
sweep runs at most once a minute.

## Examples

Add CORS headers to every response and strip identifying headers:

```toml
[plugins.rewrite]
category = "rewrite"
step = "request"
rules = '''[
  {
    "id": "add-cors",
    "name": "Add CORS headers",
    "direction": "response",
    "operations": [
      {"type": "set_header", "name": "Access-Control-Allow-Origin", "value": "*"},
      {"type": "set_header", "name": "Access-Control-Allow-Methods", "value": "GET, POST, PUT, DELETE"}
    ]
  },
  {
    "id": "remove-server-header",
    "name": "Remove Server header",
    "direction": "response",
    "operations": [
      {"type": "remove_header", "name": "Server"},
      {"type": "remove_header", "name": "X-Powered-By"}
    ]
  }
]'''
```

Strip an `/api` prefix for a specific host, and tag every request with the
request id:

```toml
[plugins.rewrite_paths]
category = "rewrite"
step = "request"
rules = '''[
  {
    "id": "strip-prefix",
    "name": "Strip /api prefix",
    "direction": "request",
    "condition": "http.host eq \"example.com\" and http.request.uri.path starts_with \"/api/\"",
    "operations": [
      {"type": "regex_replace_path", "pattern": "^/api/(.*)", "replacement": "/$1"}
    ]
  },
  {
    "id": "trace-header",
    "name": "Add trace header",
    "direction": "request",
    "operations": [
      {"type": "set_header", "name": "X-Request-Id", "value": "${request_id}"}
    ]
  }
]'''
```

Rewrite a response body and normalise a soft-404 status:

```toml
[plugins.rewrite_body]
category = "rewrite"
step = "request"
rules = '''[
  {
    "id": "branding",
    "direction": "response",
    "condition": "http.request.uri.path starts_with \"/docs/\"",
    "operations": [
      {"type": "replace_body", "search": "Acme Corp", "replacement": "PingWAF"}
    ]
  },
  {
    "id": "soft-404",
    "direction": "response",
    "condition": "http.response.status eq 404",
    "operations": [
      {"type": "set_status_code", "code": 200},
      {"type": "set_body", "content": "<html><body>Not found</body></html>"}
    ]
  }
]'''
```

## Usage notes

- Rules are applied in ascending `priority`; within a rule, operations run in
  the order listed.
- Body operations (`replace_body`, `set_body`) require buffering the full
  response body, which disables streaming for matched responses. Scope them
  with a `condition` (e.g. on `Content-Type`) to avoid buffering large or
  streaming payloads.
- `set_path` / `regex_replace_path` change the upstream path only; they do not
  alter routing decisions made before the plugin runs.
- An operation that references an invalid header name, regex or status code is
  rejected at configuration load with a descriptive error.
- Rewriting is intentionally non-blocking; use the [`waf`](waf.md),
  [`ip_restriction`](ip_restriction.md) or [`redirect`](redirect.md) plugins to
  deny or redirect traffic.
