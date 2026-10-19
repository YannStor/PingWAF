# The HTTP request lifecycle

PingWAF's data plane is a [Pingora](https://github.com/cloudflare/pingora)-based
reverse proxy (`pingap`). Every request walks the same fixed pipeline of
phases, and every PingWAF feature hooks into exactly one of them:

- the **WAF plugin** (`pingwaf:waf`) runs before the cache, before routing to
  the upstream and on the way back — so a cached response can never bypass it;
- the **challenge plugin** (`pingwaf:challenge`) serves the challenge verify
  endpoint at the same early phase;
- the **rewrite plugin** (`pingwaf:rewrite`) and the **cache plugin**
  (`pingwaf:cache`) run once the location is known;
- the **error page plugin** (`pingwaf:error_page`) only acts on responses;
- the per-site **HSTS** and **force-HTTPS** plugins act on response headers and
  on plaintext requests respectively.

Knowing this order is how you predict what a rule will do and debug why a
request was allowed, blocked or challenged. The same stages are shown in the
dashboard under **Request lifecycle** (`/lifecycle`).

## Pipeline at a glance

```
Client
  │  TLS handshake — SNI certificate selection, mTLS client-cert verify
  ▼
┌─ early_request ──────────────────────────────────────────────────────────┐
│  location match (host + path) · request-id · OpenTelemetry                │
│  ▶ pingwaf:waf      站点策略、IP/地域、Basic Auth、Bot、限流、WAF 引擎    │
│  ▶ pingwaf:challenge  质询校验端点 /_pingwaf/challenge/verify             │
└──────────────────────────────────────────────────────────────────────────┘
  ▼
┌─ request ────────────────────────────────────────────────────────────────┐
│  ACME HTTP-01 / metrics answered (after passing the WAF above)            │
│  location path rewrite · no match → 404                                   │
│  ▶ pingwaf:rewrite   request header/path/body rewrite                     │
│  ▶ pingwaf:cache     per-session cache setup, PURGE handling              │
└──────────────────────────────────────────────────────────────────────────┘
  ▼
┌─ cache lookup (pingora built-in) ────────────────────────────────────────┐
│  HIT → 直接返回缓存响应（WAF 已在上面检查过）                              │
│  MISS → 继续                                                            │
└──────────────────────────────────────────────────────────────────────────┘
  ▼
┌─ upstream ───────────────────────────────────────────────────────────────┐
│  proxy_upstream 插件 · 负载均衡选后端 · 连接（可重试）                     │
│  upstream_request_filter 追加 X-Forwarded-* · 请求体大小限制（413）      │
└──────────────────────────────────────────────────────────────────────────┘
  ▼
┌─ upstream response ──────────────────────────────────────────────────────┐
│  上游响应头到达 · 缓存写入决策                                            │
│  ▶ pingwaf:error_page  用站点自定义错误页替换上游错误响应                  │
└──────────────────────────────────────────────────────────────────────────┘
  ▼
┌─ response ───────────────────────────────────────────────────────────────┐
│  ▶ pingwaf:error_page  · pingwaf:waf 记录状态供访问日志                   │
│  ▶ 每站点的 HSTS 响应头插件 · 缓存头（Age 等）                             │
└──────────────────────────────────────────────────────────────────────────┘
  ▼
┌─ response body ──────────────────────────────────────────────────────────┐
│  ▶ pingwaf:waf  流结束时发出访问日志（含响应体采样）                      │
│  响应体重写插件（升级为 WebSocket 的 101 之后跳过）                        │
└──────────────────────────────────────────────────────────────────────────┘
  ▼
┌─ fail_to_proxy（仅出错时） ───────────────────────────────────────────────┐
│  错误分类：502 上游错误 / 499 客户端断开 / 408 读取超时 / 400 非法头       │
│  内置错误模板渲染（不运行插件，自定义错误页不生效）                        │
└──────────────────────────────────────────────────────────────────────────┘
  ▼
┌─ logging ────────────────────────────────────────────────────────────────┐
│  pingap 访问日志（PingWAF 的日志在更早的阶段已经发出）                     │
└──────────────────────────────────────────────────────────────────────────┘
```

## Stages in detail

| # | Stage | Pingora hook | What happens there |
| --- | --- | --- | --- |
| 0 | TLS / connection | *(before HTTP)* | SNI picks the certificate; when any site enables mTLS, the listener verifies client certificates against the union of trusted CAs. Per-site enforcement happens inside the WAF plugin. |
| 1 | Early request | `early_request_filter` | The location (host + path) is matched, the request id and tracing context are created, and **all `early_request` plugins run**: the WAF plugin's full check chain and the challenge verify endpoint. A plugin answering here short-circuits everything below. |
| 2 | Request | `request_filter` | The ACME HTTP-01 challenge, the metrics endpoint and the admin API answer here — **after** the `early_request` plugins, so those requests are still inspected by the WAF when they match a location. Then location-level path rewrite and the **`request` step plugins**: the rewrite plugin and the cache plugin (which configures pingora's HTTP cache for this session and answers `PURGE`). A request matching no location is answered with `404` without running any plugin. |
| 3 | Cache lookup | `proxy_cache` | Pingora's built-in HTTP cache. A **hit finishes the request** without touching the upstream — but only *after* the WAF already inspected it. A miss continues. |
| 4 | Upstream | `proxy_upstream_filter`, `upstream_peer`, `connected_to_upstream`, `upstream_request_filter`, `request_body_filter` | Plugins registered for the `proxy_upstream` step run; the load balancer picks a peer (with retries on connect failure); `X-Forwarded-*` style headers are appended; the request body is streamed upstream and oversized bodies are rejected with `413`. |
| 5 | Upstream response | `upstream_response_filter`, `upstream_response_body_filter` | The upstream response headers arrive: pingora decides whether the response may be stored in the cache, `X-Request-Id` is set, and the error page plugin may replace upstream error responses with the site's configured pages (400 and above, including 502/504). |
| 6 | Response | `response_filter`, `response_body_filter` | Response-step plugins run: the error page plugin gets a second chance on responses, the WAF plugin records the status/size for the access log, the per-site HSTS plugin adds `Strict-Transport-Security`, and cache headers (`Age`, …) are added. Body filters rewrite the response body — except after a `101 Switching Protocols` upgrade, where the bytes are WebSocket traffic, not an HTTP body. At end of stream the WAF plugin emits the access log entry (with response body sampled per the site's logging settings). |
| 7 | Failure | `fail_to_proxy` | Only on errors: classified as `502` (upstream error), `499` (client gone), `408` (read timeout) or `400` (invalid header) and rendered with pingap's built-in error template. No plugins run here, so **custom error pages cannot replace this page** either. |
| 8 | Logging | `logging` | pingap writes its own access log last. PingWAF's log entries were already emitted at the stage where the decision was made (see [Debugging](#debugging-with-the-lifecycle)). |

Plugin **step** names map to the configuration key `step` of each plugin
(`early_request`, `request`, `proxy_upstream`, `upstream_response`,
`response`). PingWAF injects its plugins with fixed steps: the WAF and
challenge plugins at `early_request`, the rewrite and cache plugins at
`request`, the error page plugin on the response path.

## Inside the WAF plugin

The WAF plugin is where most of PingWAF's policy is enforced. Its checks run
in this order and **the first one that answers ends the request**:

| # | Check | Configured under | Behaviour |
| --- | --- | --- | --- |
| 1 | Paused site | Sites list | A paused site answers with the pause page immediately — nothing else runs. |
| 2 | mTLS client certificate | Site → SSL/TLS | Missing or invalid client certificate → blocked (site-level enforcement; the TLS listener only checks the union CA). |
| 3 | IP & geo access rules | Site → Security → Access control | First match wins. Actions: `block`, `allow`, `challenge`, `js_challenge`, or `basic_auth` (deferred to step 4). |
| 4 | Basic Auth | Site → Security → Access control | Site-wide or triggered by an IP/geo rule. Repeats get a small delay; failures get the `401` page. `hide_credentials` strips the `Authorization` header before proxying. |
| 5 | Bot protection | Site → Security → Bot | User-agent classification: pass, deny (block page) or log-only. |
| 6 | Rate limiting | Site → Security → Rate limiting | Fixed-window counters per rule (IP, host, path, header, cookie…). Over the threshold: the rule's action, `challenge` issuing a clearance cookie when configured. |
| 7 | WAF engine | Site → Security → WAF | Rule inspection (signatures + expressions + anomaly score). Verdicts: pass, monitor (log only), block, challenge. |

The WAF engine (step 7) verdict is governed by a **mode**; sites and rules share
the same three API values:

| Mode (API value) | Behaviour |
| --- | --- |
| Off (`off`) | The engine returns immediately: no detection, no event. |
| Observe (`monitor`) | Detects and records events, but never blocks or challenges. |
| Enforce (`block`) | Applies the action configured on the rule. |

The enforcing API value is `block`, **not** `enforce`/`prevention` — anything
else is rejected with a `400` that lists `off|monitor|block`. The site mode is a
ceiling on top of the rules: with the site in `monitor`, a `block` rule is
**downgraded** rather than ignored — the event's `action` is `monitor` and its
`waf_details` ends with
`downgraded=true would_enforce=block cause=site-mode-monitor`, while the rule
keeps its own `rule_action=block`. That marker is what separates "suppressed by
the site mode" from "configured to observe".

A new site seeds the built-in rules as `block`, so "WAF enabled" takes effect
immediately; restoring defaults on an existing site keeps seeding `monitor`, so
a repair never starts blocking traffic that site was serving unfiltered.

Two cross-cutting behaviours are worth remembering:

- **Observation mode** (Site → Security → WAF) downgrades every block/challenge
  from steps 3, 5, 6 and 7 to a recorded "would have blocked" event. What it
  does **not** downgrade: paused sites, mTLS and Basic Auth — these are
  enforced configuration, not detections.
- Failures at steps 1–6 are answered directly with generated pages; they never
  reach the error page plugin (see [stage 6](#stages-in-detail)), so the
  custom error pages do not replace WAF block/challenge pages.

## The challenge subsystem

`pingwaf:challenge` and the WAF plugin share one pending-challenge store:

- a block/challenge verdict returns the JS challenge page (`503`) or a hard
  block (`403`);
- the page posts its proof-of-work solution to `/_pingwaf/challenge/verify`,
  which the challenge plugin serves at the `early_request` phase;
- on success the visitor receives a signed clearance cookie, so later requests
  skip the challenge until it expires;
- difficulty, clearance lifetime and challenge level are per-site settings
  (Site → Security → CC protection).

## Caching and the WAF

The order of stages 1–3 is deliberate: **the WAF sees every request, including
ones that will be served from cache**. Cache configuration comes from the
site's cache rules (Site → Caching); a hit is decided in stage 3, after the
WAF and rewrite plugins already ran, so cache hits cannot bypass security
checks, and a WAF block always wins over a cached response.

## Response modifications and the cache

When a response is both cached and modified, *where* the modification happens
decides what the cache stores:

- **Upstream phase, before the cache write** — changes made by
  `upstream_response_filter` / `upstream_response_body_filter` are part of the
  stored copy. In stock pingap this covers the compression plugin (the
  compressed body is cached) and `response_headers` configured with
  `mode = "upstream"`.
- **Response phase, after the cache write** — changes made by
  `response_filter` / `response_body_filter` are applied **on every serve**,
  cache hits included: a cached response still runs the response filters (only
  the upstream filters are skipped), so the client always gets the modified
  response while the stored copy keeps the upstream's original bytes.
  PingWAF's rewrite response rules and the per-site HSTS header work this way,
  so they are never baked into the cache.
- **Error page replacements are never stored** — while replacing a response
  the plugin sends `Cache-Control: private, no-store`, so the generated page
  is served but not written to the cache.

A practical consequence: modifying a response in the response phase (a PingWAF
rewrite rule) does not change what is cached — the modification runs again on
every request, including cache hits. To store a modified response, make the
change in the upstream phase.

## Debugging with the lifecycle

Start with the **Logs** page, then walk the pipeline:

- **A request has no WAF entry** — it matched no location (`404` at stage 2,
  where no plugin runs). A cache hit is *not* a cause: the WAF inspected the
  request at stage 1 and the access entry is still emitted — only the response
  body comes from the cache instead of the upstream.
- **Certificate issuance fails** — ACME HTTP-01 requests are answered at
  stage 2, but only after the `early_request` plugins: an IP or rate rule
  that blocks `/.well-known/acme-challenge/*` also blocks renewal.
- **A request was blocked or challenged** — the security event names the rule
  and the check that fired (steps 3–7 above). The access entry for a generated
  response (blocks, challenges, pause pages) is emitted at request time with
  its real status.
- **"It should have been blocked but wasn't"** — check observation mode, the
  rule's priority and first-match semantics for IP/geo rules, and whether an
  `allow` rule ran earlier.
- **"The custom error page isn't used"** — pages configured under Settings →
  Error pages replace *upstream* error responses (stage 5). WAF block/challenge
  pages are generated before the upstream is contacted, and proxy failures at
  `fail_to_proxy` (stage 7) are rendered without running any plugin — neither
  is replaced by custom pages, and both keep their built-in design.
- **"Origin never saw the request"** — find the last stage in the logs: cache
  hit (stage 3), WAF answer (stage 1), or a `413` from the body size limit
  (stage 4).

See also: [user-guide.md](./user-guide.md) for the dashboard walkthrough and
[api.md](./api.md) for the log/event schema.
