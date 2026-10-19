# Changelog

This file is the change log of **PingWAF** — the distributed, centrally managed
Web Application Firewall built on top of [pingap](https://github.com/vicanso/pingap)
and Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

PingWAF entries are listed first. The `pingap` history below the divider is
inherited from the upstream proxy that provides PingWAF's data plane; it is kept
verbatim for reference and attribution, and is not maintained here.

## [Unreleased]

### Changed

- **New sites now enforce the built-in WAF rules.** `seed_site_defaults`
  creates the 11 built-in rules with `mode: "block"` instead of `"monitor"`, so
  "WAF enabled" means SQLi/XSS/reconnaissance payloads are actually stopped
  rather than recorded while the origin still answers `200`. Restored defaults
  (`POST /sites/{site_id}/waf/defaults`) intentionally keep seeding `monitor`:
  repairing an existing site must never start blocking traffic that site was
  serving unfiltered. Existing rows are untouched — seeding is name-matched and
  never edits a rule that already exists.
- **A site without a `waf_settings` row now falls back to `monitor`, not
  `off`.** The gRPC config builder used to derive `off` from "no enabled rule
  with an explicit mode", which made an unconfigured site weaker than monitor:
  the engine returned `Pass` before evaluating anything, so not even the
  always-loaded managed ruleset produced an event. `off` is now only what an
  explicit row (or `waf_enabled: false`) says. The REST read model follows the
  same floor (`derive_site_mode`, `GET /sites/{id}/waf/posture`), so opening the
  settings page can no longer weaken a site.
- **Monitor-mode downgrades are visible in security events.** When a rule with
  `action: "block"` runs under a site in `monitor`, the event keeps
  `action: "monitor"` — the semantics are unchanged — but `waf_details` now ends
  with `downgraded=true would_enforce=block cause=site-mode-monitor`, and each
  matched rule records its configured `rule_action=block`. Previously the
  downgraded block and a rule configured to log looked identical.
- **`mode` validation names the legal enum.** Rule and site-settings endpoints
  now answer `400 unknown mode …; allowed: off|monitor|block` instead of a bare
  `unknown mode '…'`, and explicitly point `enforce`/`prevention` at `block`.
  The API value for the enforcing mode is `block`; `enforce` was never accepted.
  Docs (`docs/api.md`, `docs/user-guide.md`, `docs/zh/http-lifecycle.md`) now
  spell the three values out.

## [PingWAF 0.27.9] — 2026-10-19

### Fixed

- **Quick actions are icon-only everywhere.** `IpQuickActions` (the shared
  component behind the dashboard's top-threat-IP table and the site traffic
  page) still rendered an icon plus a visible label; the earlier icon-only
  change had only touched the log drawer, so the two tables looked
  unchanged. Both buttons now use `size="icon"` with an `aria-label` and the
  shared tooltip, matching the drawer; a source-contract test pins the shape.
- Actions column is a fixed 96 px on both tables (the two icon buttons no
  longer shrink-wrap, which had widened the column and forced horizontal
  scrolling on mobile).
- A missing hashed asset now answers 404 instead of the SPA shell:
  returning `200 text/html` for a stale `assets/*` URL hid cache problems
  behind a "successful" HTML response.
- pingora's listener no longer floods ERROR with failed downstream TLS
  handshakes from internet scanners (`pingora_core::services::listening`
  defaults to WARN; an explicit `RUST_LOG` directive still wins).

### Changed

- New shared `Tooltip` component (hover/focus, Esc/blur to close, works on
  disabled buttons) replaces the native `title` on the icon-only quick
  actions: native titles never show on keyboard focus or touch and cannot be
  styled. `aria-label` stays on the buttons; the bubble is linked through
  `aria-describedby` so screen readers read it as a description.

## [PingWAF 0.27.8] — 2026-10-19

### Breaking

- **pprof removed entirely.** Gone: the control-plane endpoints
  (`/api/v1/debug/pprof/{profile,flamegraph,memory,heap}`,
  `.../cpu/{metrics,dashboard.svg,summary}`, `POST .../cpu/summary/import`),
  the data-plane admin routes (`{admin-path}/api/pprof/*`), the MCP tools
  `profile_cpu` / `profile_memory`, the `PINGWAF_DEBUG_LISTEN_ADDR` loopback
  listener (`ServerConfig.debug_listen_addr`), the `mem-prof` cargo feature
  with `Dockerfile.memprof` and its image workflow, and the
  `[basic] pprof_enabled` configuration key / `PINGWAF_PPROF_ENABLED`
  environment variable. Deployments that set any of these must drop the
  setting on upgrade; the observation half is replaced by the read-only
  `GET /api/v1/system/metrics` and `GET /api/v1/system/profile` (see
  [Profiling](./docs/profiling.md#what-changed-vs-pprof)).
- **Cache rules: `disk_quota_mb` removed.** The field is ignored in requests
  and no longer returned in responses (the DB column is kept but no longer
  participates in any calculation; rows created from now on store `0`).
  Disk budgets live only in the site-level `cache-settings.quota_mb` and the
  global `/settings/cache.max_space_mb` —
  see the boundary table in
  [docs/zh/crates/cache.md](./docs/zh/crates/cache.md#缓存策略与规则的边界).
- **Upstream node name removed from the API and UI.** `site_upstreams.name`
  is no longer accepted in requests nor returned in responses (the DB column
  remains, reserved for the upcoming node-group feature; the write path
  mirrors the address).

### Added

- `[basic] client_max_body_size`: a global request-body cap that locations
  inherit when they do not set their own (size string, e.g. `"16MB"`).
  Absent keeps the historic "unlimited" behaviour, so existing configs are
  unchanged.
- `GET /api/v1/system/metrics` (admin): read-only process/host CPU and
  memory snapshot — `cpu` (process and host percent, cores) and `memory`
  (process RSS / virtual, host totals, and cgroup container accounting when
  a memory limit applies).
- `GET /api/v1/system/profile` (admin): module and method CPU/memory
  attribution — 7 module rows (`proxy`, `waf`, `cache`, `plugin`, `db`,
  `control`, `other`) plus up to 40 hottest method rows, computed from
  in-process accounting counters.
- `upstream_host` on locations: optional bare host name that overrides the
  `Host` header the proxy sends to the origin. Unset keeps the client's
  `Host`; an explicit value wins over a `Host` entry in
  `proxy_set_headers`.
- `downstream_connection_timeout` (per-listener, `[servers.*]` tables): connection-phase (TCP accept +
  TLS handshake + request-head read) timeout, applied by taking the shorter
  of it and `downstream_read_timeout` — pingora 0.9 has no separate
  handshake knob.
- `keepalive_request_limit` (per-listener, `[servers.*]` tables): maximum requests served on one
  downstream keep-alive connection before pingora closes it — the supported
  way to bound HTTP/1.1 keep-alive lifetime on pingora 0.9 (it has no h1
  idle timeout).

### Changed

- **CPU/memory attribution is now in-process instrumentation instead of
  sampling.** The profiler records module-level atomic counters
  (`cpu_ns` / `mem_bytes` / `calls`) and times named hot paths with
  `timed_method`: no sampling, no stack unwinding, no allocator hooks, no
  external tool or image; it works on every platform and in every build, at
  the cost of one relaxed atomic add per recording point. See
  [Profiling](./docs/profiling.md).

### Fixed

- **Agent registry: stale heartbeat streams.** Each connection carries a
  generation; the stream teardown only removes the entry when it still owns
  the current generation, so a stream finishing after a reconnect no longer
  marks the live agent offline. The offline-agent sweep also drops queued
  commands for the agent rows it prunes (`pending` no longer outlives them).

### Verified (no change needed)

- **Cache size accounting**: the file backend's per-directory budget and
  the cross-domain quota ledger serve different purposes, and both already
  subtract the previous object's size when overwriting a key; the residual
  difference is the documented estimate rather than a leak.
- **`Box::leak` for cache backends / key locks**: bounded by the number of
  distinct configuration values (typically one per deployment), and
  removing it requires a provider-lifetime redesign — recorded, not changed.

## [PingWAF 0.27.7] — 2026-10-18

### Changed

- **Allocator retention is now derived from the memory ceiling** instead of
  the fixed 1000 ms purge delay baked into the images (mimalloc's own
  default is 10 ms — the pin made every host, including 1 GB ones, retain
  freed pages for a second). Buckets: <1 GB → 0 ms, 1-4 GB → 250 ms,
  4-16 GB → 500 ms, >16 GB → 1000 ms. Applied at startup through
  mimalloc's runtime API (`mi_option_set`), so containers and bare-metal
  systemd units behave identically. Override with
  `PINGWAF_MALLOC_PURGE_DELAY_MS` (fallback: `MIMALLOC_PURGE_DELAY`); the
  effective value is logged at startup.

### Added

- Memory caps from the 2026-10-17 risk audit: `PENDING_ACCESS` 65536 →
  2048 entries (fail-open on enrichment), `DEFERRED_BODY` capped at 1024
  staged bodies (fail-open, body streams through), agent log channel
  16384 → 2048, AI rate-limit table capped at 10 000 with a retain sweep,
  certificate-alert dedup set capped at 4096.
- CPU snapshot reuse: readings younger than 1 s are shared, so
  `/cpu/metrics`, the capture load guard and the console card no longer
  queue behind each other on the sampler lock.

### Fixed

- **etcd watch busy-loop (high):** when the watch stream ended (etcd
  restart / connection drop) the observer returned `Ok(false)` and the
  caller `continue`d immediately, re-polling a dead stream and burning a
  whole runtime worker. The stream is now dropped so the next poll takes
  the sleeping path (periodic diff still covers config changes).
- Challenge/rate tables swept every 64th insert instead of on every
  request once over threshold (removes a request-level O( N ) CPU
  amplifier under challenge floods).
- Memory watchdog polls every 500 ms instead of 250 ms.

### Added

- Startup warning for listeners that leave `downstream_read_timeout` /
  `downstream_write_timeout` unset: a slow client can hold a connection
  open indefinitely, and silence made that look configured.

### Changed

- Documented the two cache size units side by side (`cache_max` counts
  4 KB pages; `directory`'s `?max_size=` is bytes) so a config cannot
  silently mix them.

### Verified (no change needed)

- HTTP/2 limits: the listener already starts from `default_h2_options()`
  (64 KiB header list, 100 concurrent streams) whenever nothing is
  configured, and only overrides what is set — the earlier audit note
  about inheriting an unbounded h2 builder did not hold for this code.
- Closing the downstream connection on internally generated errors is
  intentional (those paths do not reuse connections; advertising
  keep-alive would mislead the client). The TODO is now a decision note.

## [PingWAF 0.27.6] — 2026-10-17

### Changed

- **CPU profiling now defaults to OFF** (behavior change). The built-in
  sampler runs a SIGPROF handler that allocates in signal context, and the
  encode phase after the window spikes RSS — on a 2GB box every capture
  OOM-killed the container (2026-10-17, 4/4 reproductions). Enable
  explicitly for diagnostics: `[basic] pprof_enabled = true` or env
  `PINGWAF_PPROF_ENABLED=1`. Unconfigured deployments answer `503` on the
  capture endpoints; the read-only `memory`/`cpu/metrics`/`cpu/summary`
  views stay available.

### Added

- **Memory admission guard for captures.** Before any capture starts (all
  entry points: control plane, MCP, data-plane admin route), available
  memory is checked (cgroup v2 `memory.max`-`memory.current`, then v1,
  then host `MemAvailable`); below `MIN_AVAILABLE_BYTES` (400 MB) the
  capture is refused with `503 memory_pressure` and audited. Not
  detectable → allowed.
- **Mid-window memory watchdog.** While a capture samples, available
  memory is polled every 250 ms; two consecutive readings below the floor
  abort the sampler early and the pending `finish_*` answers
  `503 memory_pressure` (audit outcome `memory_pressure`).
- **Heap dump guardrails (mem-prof builds).** `GET /debug/pprof/heap`
  applies the same memory admission before dumping, refuses dumps over
  256 MB, and reads the file with a bounded read instead of pulling it
  into memory unbounded.

### Fixed

- **Audit follow-ups, second batch (2026-10-18).** Low: image optimisation
  and `sub_filter` pass oversized bodies through instead of buffering them
  (16 MiB / 8 MiB caps, checked against the declared length before any
  bytes are withheld); unmatched-SNI handshakes log at debug instead of
  error (scanner log flood); the restart counter is a `u32` (the `u8`
  wrapped on the 256th restart); the challenge verify body is truncated
  before copying (the old order copied a whole chunk past the limit); the
  config-observer ticker uses `MissedTickBehavior::Delay` (no burst of
  compensating ticks after a slow round). Medium: the cache ledger keeps
  the entry's creation time when a restored file has no usable atime
  (noatime mounts inverted the LRU order after a restart); least-connections
  selection takes one counter snapshot instead of one locked lookup and one
  String allocation per candidate; `SiteContext` compilation is
  single-flight per host (concurrent cold requests no longer compile and
  overwrite each other); transparent upstreams cache hostname lookups for
  30 s (bounded at 4096 entries, failures not cached) instead of resolving
  per request.
- **Audit follow-ups (2026-10-18 performance/stability review).**
  High: rule `expression` is now parsed at the API boundary (a rule whose
  expression the data plane cannot compile used to be stored as "enabled"
  and silently dropped, enforcing nothing); MCP read tools are scoped to
  the caller's own sites (viewer and read-only API keys could read every
  site's logs/WAF events); bcrypt runs on the blocking pool (concurrent
  logins/API-key checks could starve every control-plane worker);
  health-check task panics are logged instead of silently disabling an
  upstream's checks forever.
  Medium: WAF-only log streams flush on `event_batch` size (a stream that
  never produced access rows grew it without bound); challenge state has a
  hard 4096-entry ceiling; rate-limit counters are swept when a site has no
  rules left; pruned agents now drop their `LAST_PERSISTED_BUCKET` /
  `RESOURCE_STRIKES` entries; hot-reload partial failures return an error so
  the config hash is not recorded (failed reloads used to never retry);
  log archives are deleted after `max(30 days, 4x compression delay)`;
  a missing `-c` config file fails fast instead of starting an empty
  server; the all-in-one/agent entry point registers `storage_clear` so
  expired cache files are reclaimed; certificate uploads parse the chain
  and verify the key pair (and reject a row with neither PEM nor ACME);
  the data-plane admin body buffer is capped at 8 MiB.
- **CPU snapshot rate-limit race.** Concurrent callers of
  `cpu/metrics`/the load guard could both sleep to the same refresh
  deadline, the second refresh observing a ~zero delta and reporting a
  false idle. The stretch-then-refresh sequence is now serialized under
  the sampler lock, so every caller gets one meaningful delta.

## [PingWAF 0.27.5] — 2026-10-17

### Added

- **Profiling: `GET /debug/pprof/cpu/summary` — the bounded server-side
  aggregate becomes the first-class readout.** The endpoint returns
  `{ live, last_capture }`: a live CPU snapshot plus the server-cached
  summary of the most recent capture — a TopN hottest-frames table
  (`name` / `samples` / inclusive `share`, capped at 10 rows),
  `status` (`normal` | `high_load` | `idle` | `platform_limited`), window
  / frequency / capture time — as KB-scale JSON with zero sampling
  overhead. The cache holds only the latest summary and is refreshed by
  every finished capture (`profile`, `flamegraph`, `cpu/dashboard.svg` and
  this endpoint's own capture). With `?capture=true` it runs a fresh
  capture first (same 5-second ceiling, 40% load guard and idle-summary
  behaviour as the other capture endpoints; whether the `pprof_enabled`
  switch is enforced on this path). Consumed by
  the console's Performance diagnostics card and the MCP `profile_cpu`
  tool (`cached=true` returns the last summary without sampling).

- **Profiling: loopback diagnostics listener (`PINGWAF_DEBUG_LISTEN_ADDR`).**
  When the control-plane environment variable is set (e.g.
  `127.0.0.1:9091`), the whole pprof endpoint set is additionally served on
  that address without Bearer auth, so `go tool pprof` / `jeprof` connect
  with zero token exchange. Non-loopback bind addresses are rejected at
  startup (the loopback interface is the trust boundary); default is off.

- **Profiling: `POST /debug/pprof/cpu/summary/import` for legacy profiling
  files.** A previously downloaded pprof protobuf (the `profile` wire
  format) is decoded into the same bounded summary, so historical files
  stay analysable in the console and via MCP without external tools.
  Weight semantics: pprof CPU profiles carry per-sample values in CPU
  nanoseconds, so per-frame weights are CPU nanoseconds (proportional
  `share` unaffected) and `frequency` is reported as `0` (unrecoverable).
  Stateless — starts no capture and does not change the last-capture
  cache.

### Changed

- **Profiling: the diagnostics card leads with the aggregated summary
  instead of file downloads.** The console's Performance diagnostics card
  now renders the live snapshot and the last capture's TopN frames
  directly (KB-scale JSON via `/debug/pprof/cpu/summary`), which removes
  the "giant SVG fails to open" failure mode from the product's artifact
  shape; the full artifacts (CPU profile, SVG flamegraph, memory snapshot)
  remain available as an explicit export path. Aggregated output is
  bounded (TopN capped at 10 frames, one cached summary at a time).

## [PingWAF 0.27.4] — 2026-10-16

### Added

- **Profiling: capture statistics exposed via `GET /debug/pprof/cpu/metrics`.**
  The metrics snapshot now carries a `profiling` object — the cumulative
  count of capture sessions started in this process lifetime
  (`total_started`) and the most recent session record (`finished_at_ms`,
  `duration_secs`, `outcome`: `ok` | `idle` | `no_samples` |
  `report_error` | `abandoned` | `unsupported`) — so "who profiled, when,
  and what came of it" is answerable from the live endpoint alone.

- **Profiling: post-capture audit log.** Every capture emits one structured
  INFO line when it ends (success, rejection or abandonment) with
  `endpoint`, `outcome` and the process RSS right after the capture, so
  memory spikes can be correlated with capture activity.

- **Profiling: deployment switch `PINGWAF_PPROF_ENABLED`.** Setting it to
  `0` (or `false`/`off`/`no`, case-insensitive) disables the three
  control-plane CPU capture endpoints (`/debug/pprof/profile`,
  `/flamegraph`, `/cpu/dashboard.svg` — they answer `503 Service
  Unavailable`) and the MCP `profile_cpu` tool. The read-only snapshots
  (`/debug/pprof/memory`, `/debug/pprof/cpu/metrics`) stay available.
  Defaults to enabled. Within this release the switch has moved to the
  `[basic] pprof_enabled` configuration key; the environment variable
  remains as a fallback honoured only when the key is unset (see below).

- **Profiling: load guard against captures under load.** Before any CPU
  capture starts (the HTTP capture endpoints and the MCP `profile_cpu`
  tool alike), the process CPU usage is checked; above 40% of one core
  (`GUARD_MAX_CPU_PERCENT`) the capture is refused — the HTTP endpoints
  answer `503 Service Unavailable` with the measured value and the limit,
  and the audit log records `outcome=load_guard`. The read-only `memory`
  and `cpu/metrics` snapshots are not subject to the guard. Motivation:
  the pprof-rs sampler allocates inside its `SIGPROF` handler, so
  profiling a busy process can inflate RSS to 1 GB+ within 30-90 seconds
  and end in an OOM kill (observed twice on 2026-10-16); idle captures
  are harmless (measured VmHWM 79 MB).

- **Profiling: `[basic] pprof_enabled` configuration switch.** The
  debug-capture switch moves from env-only into the configuration file
  (boolean, default `true` = captures on). The legacy
  `PINGWAF_PPROF_ENABLED` environment variable is demoted to a fallback,
  honoured only when the key is not set explicitly — the configuration
  file wins; changes require a restart. When off, every CPU capture entry
  point answers `503 Service Unavailable`: the three control-plane
  endpoints, the same capture endpoints on the data-plane admin plugin,
  the MCP `profile_cpu` tool and the new heap endpoint. The read-only
  `memory` and `cpu/metrics` snapshots stay available.

- **Profiling: heap attribution via `--features mem-prof` and
  `GET /debug/pprof/heap`.** The diagnostic `mem-prof` feature swaps the
  global allocator from mimalloc to tikv-jemallocator (heap-profiling
  enabled) and adds the control-plane heap endpoint: it triggers a
  jemalloc `prof.dump` and returns the jeprof-format dump as an
  attachment — every live allocation path with its retained byte count.
  This is the answer to "which function allocates / retains memory",
  where a CPU flame graph answers "where does CPU time go". Requires the
  process to run with `MALLOC_CONF=prof:true`; render with
  `jeprof --svg <binary> <dump>`. Non-`mem-prof` builds answer `501`; the
  endpoint is gated by the debug-capture switch (`503` when off).

- **Profiling: `?selfload=true` for captures on an idle process.** The
  CPU sampler is time-based and records nothing on a quiet process — the
  root cause of `409 no samples`. The new query parameter (accepted by
  the three control-plane capture endpoints, shipped enabled on the
  console's Performance diagnostics card) generates bounded in-process
  load for exactly the capture window — two tokio tasks doing short
  spin-and-yield bursts — so a profile is produced without real traffic.
  Honest limitation: the profile shows the async runtime and the
  synthetic workload, not site business functions; it starts only after
  the load guard has passed.

### Changed

- **Profiling: capture parameters tightened.** `MAX_SECONDS` 120 → 5,
  `MAX_FREQUENCY` 1000 → 250, `DEFAULT_SECONDS` 30 → 5 (the frontend
  constants follow: `PPROF_MAX_SECONDS = 5`,
  `PPROF_DEFAULT_SECONDS = 5`; the MCP `profile_cpu` tool caps follow:
  seconds 30 → 5, default 10 → 5). The window equals the ceiling, so it
  cannot be enlarged via query parameters — every extra second under load
  widens the worst-case memory window (see the load guard above), while
  five seconds at 99 Hz yields ~500 samples, ample for a flame graph. The
  frequency limits (250 Hz REST / 199 Hz MCP) are unchanged.

## [PingWAF 0.27.2] — 2026-10-16

### Changed

- **Worker threads adapt to the available CPUs.** When `basic.threads` is
  unset (or `0`), each server now runs one worker thread per CPU actually
  available to the process — `available_parallelism()`, which honours cgroup
  CPU quotas in containers — instead of the historical single worker, which
  serialized every request behind the accept queue on multi-core hosts
  (measured 4s tail latency at 30 concurrent requests on a 2-vCPU instance).
  Explicit configuration and `--threads` still win.

### Fixed

- **API: code-level findings from the demo E2E pass.**
  - The block page no longer leaks the internal rule UUID: the
    visitor-facing reason names the rule; the id stays in the event record.
  - `GET /logs/access` returns metadata-only summary rows (~4.7KB per row
    down to ~0.9KB; a full page was 919KB). Headers and bodies move to
    `GET /logs/access/{id}`, and lists accept `?full=true` for evidence
    exports and the security-event raw replay. The dashboard fetches the
    full record when the detail drawer opens.
  - The login rate-limit body now carries the wait ("retry in Ns"),
    matching the `Retry-After` header.
  - Malformed JSON bodies answer with the standard error envelope instead
    of axum's plain-text rejection (public auth endpoints).

## [PingWAF 0.27.1] — 2026-10-16

### Fixed

- **Memory: freed pages now reach the OS on glibc too.** mimalloc was
  previously only wired in for musl builds; glibc builds (including the
  production Debian images) used the system allocator, whose multi-arena
  behaviour could pin large arena segments and turn a startup peak into
  permanent RSS (620 MB+ observed on the demo host, twice an OOM kill).
  mimalloc is now the unconditional global allocator on every platform
  (`mimalloc` moved to the regular `[dependencies]` of the root `Cargo.toml`).
- **The container images ship a `MIMALLOC_PURGE_DELAY` default.** The runtime
  stage of `Dockerfile`, `Dockerfile.perf` and `Dockerfile.runtime` sets
  `MIMALLOC_PURGE_DELAY=1000` milliseconds (mimalloc v3's own default).
  Deployments can override it; lower values return freed memory to the OS
  sooner at a small CPU cost.
- **Per-host compile caches no longer grow without bound.** The per-host caches
  of the waf, challenge, error_page, rewrite and cache plugins now expire
  entries idle for more than 600 seconds, evict the least-recently-used
  entries beyond 1024 hosts (the bound converges within one 60-second sweep
  interval rather than being enforced at insert time), and run a background
  sweep at most once every 60 seconds
  (new `host_cache` module in `pingap-plugin`). Previously a wildcard site
  exposed to random scanner `Host` headers accumulated compiled artifacts for
  every host seen.
- **Rate-limit counters expire below the GC threshold too.** `rate_counters`
  now also prunes idle entries when the map is under the 65,536-entry GC
  threshold, once every 600 seconds. Keys that stop receiving traffic
  (one-off scanner IP/path combinations) no longer stay resident forever.
- **Dependency advisories cleared.** `cargo update` moves `rustls` to
  0.23.46 (RUSTSEC-2026-0346/0347/0348/0349) and `yoke-derive` to 0.8.4;
  the `security-audit` workflow is green again. Lockfile-only bump, no
  API changes.
- **The CPU dashboard no longer reports "at 1 Hz" when a capture is
  empty.** The summary finisher took `report.timing.frequency` whenever it
  was positive, but the pprof crate falls back to `1` for empty captures
  — so a profiled-but-idle process rendered as "30s at 1 Hz" even though
  the request was for 99 Hz. The reported frequency is now only trusted
  when the capture has at least one sample; otherwise the default the
  request asked for is used.
- **WAF block / challenge pages no longer emit nested `<style><style>`
  tags.** The shared `PW_STYLE` partial already starts with `<style>`,
  and `brand_page` wrapped it in another — producing
  `<style><style>...</style></style>` in every 401 / 403 / 429 / 503 /
  fail-closed response. Browsers tolerated it; strict HTML validators
  did not. The wrapper is removed.
- **`/debug/pprof/cpu/dashboard.svg` opens in seconds, not 30.** The
  default capture window is now 5 s (still wide enough to catch a busy
  slice on a typical process), so the first response returns in roughly
  the time a "now" tab in any monitoring tool would. Operators who want
  a deeper profile can pass `?seconds=N` (clamped to `1..=120`).
- **The control-plane API is no longer `Access-Control-Allow-Origin: *`
  by default.** Same-origin deployments (the production layout) do not
  need CORS at all — and an unguarded `*` on a credential-bearing API
  is a footgun. With no `cors_origins` configured, the server now emits
  no CORS headers, so cross-origin browsers will block the request
  (same-origin still works unchanged). Split-origin deployments opt in
  via the `cors_origins` list as before.
- **The console HTML now ships with the standard hardening response
  headers.** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: strict-origin-when-cross-origin`, and a CSP
  (`default-src 'self'`, with explicit allowances for React's inline
  `style={…}` props and a `data:` fallback for images / fonts;
  `frame-ancestors 'none'`; `connect-src 'self'`; no `unsafe-eval`) are
  now applied at the router level. The `dashboard.svg` endpoint opts
  back into `script-src 'unsafe-inline'` for the opt-in self-refresh
  path so the live readout keeps working when the file is opened
  directly; the HTML console itself stays strict.

## [PingWAF 0.27.0] — 2026-10-15

### Fixed

- **Memory numbers now match `docker stats`.** The memory snapshot read
  `/proc/meminfo` through sysinfo, which inside a container reports the
  *host's* RAM — so the dashboard and the About page disagreed with
  `docker stats`. The snapshot now carries the cgroup figures
  (`container_memory_used_bytes` / `container_memory_limit_bytes`, scope
  `cgroup_v1` / `cgroup_v2`) whenever the process runs inside a
  memory-limited container, and the dashboard resource card shows a single
  headline figure (process RSS, plus the container line in a container)
  with the full breakdown — virtual memory, host totals, scope
  explanations — folded into a hover panel.
- **Rule-sync no longer doubles agent memory on a large bundle swap.** The
  agent's copy-on-write snapshot cloned every domain string and the whole
  failover registry on each rule push. The registry and the global cache
  settings are now shared behind `Arc` (a bundle swap replaces a pointer,
  not a map), and the domain index stores `Arc<str>` keys and values —
  the clone stays O(map headers) regardless of how many domains and
  policies are registered. The on-disk cache format is unchanged.
- **Log listings no longer scan the whole window to count matches.** The
  `q`/`path`/`host` filters compile to leading-wildcard LIKEs, which a
  btree cannot serve, and the pagination still ran an exact `COUNT(*)`
  over the (up to 90-day) window. Two changes: pg_trgm GIN indexes now
  serve those predicates (migration `…056`), and the count is bounded —
  it stops after 10 001 id hits inside the database and reports
  `total_truncated` so the console renders `10000+` instead of draining
  every match. The wire format of uncapped listings is byte-identical.
- **The admin site overview is capped.** `GET /analytics/sites` loaded
  every site row with no limit and no ordering for the global view. It
  now lists the newest 500 sites and reports `truncated` when the list
  was cut; the site list itself is still fully browsable via pagination.
- **A rate-limit table flood now fails closed.** Login-bucket entries were
  reclaimable only after the *widest* window (one hour), and once the
  10 000-entry table filled anyway, new peers were silently admitted
  without tracking — disabling the limit on exactly the endpoints whose
  bcrypt cost a flood targets. Entries now expire with their own
  bucket's window (a 60-second login slot frees after 60 seconds), and
  a still-full table rejects new peers with `429` plus a retry hint
  instead of admitting them untracked.

### Added

- **Site upstream offline/degraded alerts.** Agents now report per-upstream
  backend health in every heartbeat; the control plane confirms a
  transition after two consecutive heartbeats (a single blip never pages)
  and raises `site.upstream_offline` (critical, all backends down) or
  `site.upstream_abnormal` (warning, partial loss), with recovery reported
  as `site.upstream_offline` at info severity. A `notify_site_upstream`
  settings switch gates both events; webhooks/e-mail/WeCom/DingTalk all
  pick them up like any other event.
- **Upstream context on gateway error pages.** 502/503/504 error-page
  templates (built-in and console defaults) can now show which upstream
  group and backend address were tried (`upstream_name`, `upstream_addr`),
  so an origin outage page is distinguishable from a WAF block at a glance.
- **One-click block / JS challenge from IP tables.** The dashboard's top
  threat IPs and the site traffic page's top client IPs each gained
  block and JS-challenge buttons (confirm dialog, toast feedback, query
  invalidation). The cross-site dashboard targets the IP's most recently
  active site; the site page applies to its own site.
- **CPU profiling without Go tooling: `profile_cpu` MCP tool and SVG
  dashboard.** The new MCP tool captures a CPU profile of the control
  plane (`seconds` 1–30, `frequency` 1–199 — tighter than the REST
  endpoints) and returns a summary, reading notes and a self-contained
  SVG dashboard (usage panel, task distribution, key metrics, status
  badge: `NORMAL` / `HIGH LOAD` / `IDLE` / `PLATFORM-LIMITED`); repeated
  calls within 60 seconds replay the cached capture instead of stacking
  sampler sessions. On non-Linux platforms it degrades to a live
  point-in-time readout instead of failing. The same dashboard is
  available over REST at `GET /debug/pprof/cpu/dashboard.svg`, with an
  optional `?refresh=1-60` embedding a script that polls the new
  `cpu/metrics` endpoint while the file is open in a browser (the
  caller's Bearer token is inlined only when `refresh` is requested, the
  response is `no-store`, and the dashboard prints a do-not-share
  warning on itself).

## [PingWAF 0.26.2] — 2026-10-14

### Fixed

- **Automatic blocks no longer fsync the request hot path** (D2). Each block
  used to serialize the whole blocked-IP map and fsync on the spot — N rapid
  blocks cost N×O(N) disk work exactly during an attack. Mutations now mark
  the map dirty and a background task flushes it every few seconds; shutdown
  still persists synchronously.
- **Blocked-IP map is bounded** (D3). `blocked_ips` (single addresses and
  CIDR ranges) had no capacity ceiling, so an attacker rotating unique source
  IPs could grow it — and the heartbeat snapshot that clones it — without
  limit. At 100 000 entries, expired blocks are swept first, then the oldest
  entries are evicted down to 90 000.
- **Rate-counter GC no longer runs on every request past the threshold**
  (D5). Once an attacker pushed the counter map past 65 536 keys, every
  request paid a full O(N) sweep. Sweeps are now throttled to one per 30 s
  (one per second past 262 144 entries).
- **The control plane now enforces a global request-body limit** (S1). Only
  the MCP endpoint and the GeoIP upload had one; with WAF self-protection
  off, any endpoint would buffer an unbounded body. A 10 MiB default now
  covers everything, with route-level limits (MCP 256 KiB, GeoIP 128 MiB)
  still taking precedence.

### Added

- **MCP tool `profile_memory`** — a read-only memory snapshot of the
  control-plane process (process RSS + host totals) with scope notes, cached
  for a few seconds. Any authenticated MCP session may call it.
- **On-demand profiling image pipeline.** `Dockerfile.perf` (mirror of the
  release Dockerfile built with `--profile release-perf`, symbols kept) plus
  the `Release (perf image)` workflow (`workflow_dispatch`) publishing
  `ghcr.io/shuaizend/pingwaf:perf` (amd64 only, never in the version
  manifests). Profiles taken from it symbolicate to real function names.

## [PingWAF 0.26.1] — 2026-10-14

### Fixed

- **Empty pprof artifacts are gone.** `finish_pprof`/`finish_flamegraph`
  return a `NoSamples` error on zero-sample captures instead of writing a
  0-byte file; the debug API maps it to `409` with guidance
  ("CPU-time based, retry under load or use the memory snapshot").
- **Idle-process profiling is rejected up front.** A capture session
  records `/proc/self/stat` CPU ticks; if the CPU delta stays below 0.1%
  of wall time the session ends with `409 Idle` instead of a useless
  report.
- **Disabling metric shipping no longer disconnects the agent.** With
  `metrics_ship_interval_secs == 0` the metric future parks on
  `std::future::pending()` so the gRPC session is no longer torn down and
  reconnected in a loop; shutdown still completes normally.

### Added

- **Memory accounting is unambiguous.** `MemorySnapshot` now carries
  `process_memory_scope: "process"` and `used_memory_scope: "system"`
  annotations; `rss_bytes` is process RSS while `used/total_memory_bytes`
  are host-level (`/proc/meminfo`) values.
- **Dashboard "process resources" card** (admin-only, 30s polling):
  process RSS as the primary figure, with process virtual memory and
  host memory usage/total clearly labeled; the settings page splits the
  memory snapshot into process vs host rows, and the agent drawer labels
  memory as host memory capacity.

## [PingWAF 0.26.0] — 2026-10-14

### ⚠️ Breaking changes

- **`GET /agents/{agent_id}/metrics` was removed.** The endpoint returned
  aggregated edge-metric history (request/block counters, active
  connections, site cache usage); the agent no longer ships these samples
  and the API route is gone. Use the agent's host probes
  (`GET /agents/{agent_id}/samples`) instead. The corresponding section was
  removed from `docs/api.md`.
- **`cookie_secret` is no longer part of the challenge API.** `GET/PUT
  /sites/{site_id}/challenge` neither return nor accept the field; the
  database column is dropped by migration `000054`. Challenge cookie
  signing is handled internally by the server.
- **IP group write endpoints now require write access (`admin`).** `POST/PUT/
  DELETE /ip-groups`, `PUT /ip-groups/{group_id}/sites` and
  `POST /ip-groups/{group_id}/sync` return `403` for viewer and auditor
  accounts (reads are unchanged).
- **Site domain conflicts are enforced with a `400`.** `POST /sites` and
  `PUT /sites/{site_id}` return `400 "domain already in use by another site"`
  on a conflicting `domain` (a database unique constraint backs the check).
  Migration `000055` makes startup fail and list the conflicting domains when
  the existing data already contains duplicates — resolve them manually
  before upgrading.
- **IP-group subscription sources must be public.** Subscription fetches do
  not follow HTTP redirects (`redirect::Policy::none()`), and the initial
  `source_url` host is DNS-resolved with every returned address checked
  against a non-public IP blacklist (loopback, RFC 1918, link-local including
  the cloud metadata service `169.254.169.254`, fe80::/10, fc00::/7,
  0.0.0.0/8, multicast, 240.0.0.0/4, CGNAT 100.64.0.0/10, 192.0.0.0/24,
  198.18.0.0/15, NAT64 64:ff9b::/96, IPv4-mapped IPv6). A rejected source
  fails with an error naming `private, loopback or otherwise non-public
  network` instead of reaching internal space. Known residual: because
  reqwest resolves DNS again for the actual connection, a DNS-rebinding
  TOCTOU is theoretically possible; the source is configured by an
  authenticated admin, so the risk is accepted and documented rather than
  mitigated.
- **`PUT /sites/{site_id}/challenge` rejects unknown fields** with `422
  Unprocessable Entity` (axum 0.8 maps serde `deny_unknown_fields` rejections
  to 422; the body is plain text, not the JSON error envelope), instead of
  silently ignoring them.
- **Profiling downloads are forced.** `GET /debug/pprof/flamegraph` (and the
  CPU profile endpoint) answer with `Content-Disposition: attachment`, so
  browsers download the SVG / protobuf instead of trying to render it.

### ✨ Features

- **Manual IP blocks now accept CIDR ranges.** `POST /blocked-ips/block`
  and `/sites/{site_id}/blocked-ips/unblock` take a single address or a
  CIDR (host bits are truncated, e.g. `203.0.113.99/24` is stored as
  `203.0.113.0/24`; re-blocking the same target is idempotent). Agents
  match blocked clients with an exact-key fast path plus a CIDR prefix
  scan (IPv4 and IPv6). The mask is capped — at most `/16` for IPv4 and
  `/32` for IPv6 — so an accidental network-wide ban is rejected with
  `400 "CIDR prefix too broad"`. Unblocking a CIDR only removes the
  exactly identical entry; single addresses inside the range stay
  blocked. Both list endpoints return a new `"kind": "single" | "cidr"`
  field per row.

### 🔒 Security & hardening

- **`PUT /sites/{site_id}/challenge` validates `exempt_paths`.** Every entry
  must start with `/`, contain no whitespace or control characters, be at
  most 512 characters, and the list accepts at most 100 entries; invalid
  input is rejected with `400`. Entries are trimmed and blanks dropped.

### 📋 Logging

- Stored `response_headers` (Postgres and Elasticsearch) no longer include
  `content-security-policy-report-only`; `cookie` and `set-cookie` headers
  are still kept for site-origin forensics.

### 🖥 Console

- New admin-only **Performance diagnostics** card under **Settings → About**
  downloads CPU profiles, SVG flamegraphs and memory snapshots from the
  existing `/debug/pprof/*` endpoints. The **Lifecycle** and **Config
  versions** pages now redirect non-admin roles to the dashboard, and
  viewer accounts no longer see the administrator cards on the Settings
  page.

## [PingWAF 0.25.13] — 2026-10-14

### ✨ Features

- **Origin certificate verification is now a site-level setting, and its
  entry points are consistent.** A new `sites.origin_verify_cert` column
  forms a three-level cascade — pool pin > site default > deployment
  default — resolved server-side when the rule bundle is built, so agents
  need no change and pools that leave `verify_cert` unset follow their
  site instead of jumping straight to the global switch. The site tier is
  managed from a new "Origin certificate check" card on the site's SSL
  page; the Basic page's origin-pools section shows the site default and
  each pool's effective value at a glance, and the pool dialog keeps the
  tri-state selector visible (disabled while the origin is HTTP) instead
  of hiding it behind the HTTPS-origin switch. Existing pools are
  unaffected: `NULL` still means "follow the parent level", and the
  migration only adds a nullable column.

## [PingWAF 0.25.12] — 2026-10-14

The hardening release: crash-safe agent rule-cache persistence, a CI gate
that finally does what the docs claimed, the upstream maintenance boundary
written down, and the repository named after the product it ships.

### 🛠 CI & maintenance

- **The daily security audit now honours accepted findings.** The workflow
  switched from `rustsec/audit-check` (which reads no configuration and
  re-opened the same issue every day) to `cargo audit`, which enforces the
  justification-carrying ignore list in `.cargo/audit.toml`.
  RUSTSEC-2024-0449 (`unsafe-libyaml` unmaintained) was accepted there: it
  reaches the tree only as a non-optional dependency of pingora-core 0.9 via
  the deprecated `serde_yaml` — which upstream pingora still requires — and
  never parses network input. RUSTSEC-2026-0344 (`ruzstd` decompression
  bomb) was accepted under the same policy: the fixed 0.9.1 line needs
  object 0.40, but pyroscope — the only path to `object` — pins ^0.39, and
  ruzstd only ever decodes the local binary's own debug sections.

- **CI now does what the docs always claimed.** The `rust` job runs the
  test suite on a real toolchain matrix — 1.96.0 (MSRV), 1.97.0 and stable —
  instead of only stable, and the rustls TLS backend moved from a bare
  `cargo check` to its own job running the clippy gate plus the full test
  suite (`make lint-rustls` / `make test-rustls` equivalents). README badges
  were relabelled and CONTRIBUTING's CI description now matches the
  workflow step for step (including demoting `cargo-machete` and
  `cargo msrv` to local checks). Workflow permissions were narrowed to
  `contents: read`, with `packages: write` scoped to the docker job.
- **Maintenance boundary documented** in the new [UPSTREAM.md](./UPSTREAM.md):
  the workspace is a hard fork of upstream `pingap`; the doc lists which
  crates are inherited versus PingWAF-owned, the manual sync procedure
  (fetch upstream → cherry-pick per fix → full gates → CHANGELOG), and test
  ownership.
- **Repository naming unified on `pingwaf`.** The root Cargo package was
  renamed from `pingap` to `pingwaf` (metadata and deb-packaging included),
  `default-run` now resolves to the shipped binary, the leftover
  `pingap.service` was removed, and the `bloat` / `release-all` make targets
  follow the shipped binary. The `pingap` bin itself stays as the
  upstream-compatibility mode entry point and is not shipped by the release
  pipeline.

### 🔒 Security

- **Cache could replay authenticated responses across users.** Two
  independent holes in `response_cache_filter`. (a) `authorization_present`
  was hard-coded to `false` when calling pingora's `resp_cacheable()`, so a
  request carrying `Authorization` was treated as anonymous — and if the
  origin also answered with a cacheable directive the entry was stored and
  served to the next client. The real request header is now consulted, and
  the RFC 9111 §3.5 opt-in (`public` / `s-maxage` / `must-revalidate`) is
  evaluated against the origin's own `Cache-Control` *before* the proxy
  synthesises `s-maxage` from `max_ttl` — otherwise the proxy's own floor
  masqueraded as origin consent. (b) A response carrying `Set-Cookie` was
  stored and replayed to every later visitor whenever the origin did not
  explicitly opt in to shared caching; such responses are now uncacheable
  unless `Cache-Control` says `public` or `s-maxage`. Together these are
  the classic CDN session-fixation / cross-user disclosure pair.
- **Route-level IP allow-lists read the TCP peer, not the client.** A
  location's `ip_ranges` was matched against `session.client_addr()` — the
  direct TCP peer. Behind a load balancer that is the balancer, so an
  allow-list like `["10.0.0.0/8"]` matched *every* request and the access
  control was silently bypassed; the mirror case (a public entry point)
  rejected every legitimate client. Route matching now goes through
  `ensure_client_ip`, the same `trusted_proxies`-aware resolver the
  `ip_restriction` plugin already used, so a route condition and the plugin
  finally mean the same thing.
- **clearance cookies were not bound to the site that issued them.** The
  challenge short-circuit accepted any validly-signed clearance cookie, and
  the cookie secret is shared across sites in one process — solve a
  challenge on site A and the same cookie satisfied site B. The cookie
  payload's `site_id` is now compared with the request host before the
  short-circuit, matching what the WAF's own clearance check already did.
- **Rate-limit keys silently failed open.** `Limiter::incr` returned early
  when the configured cookie/header/query field was absent, so omitting
  `?session=…` (or the header, or the cookie) disabled the limit entirely.
  A missing key now falls back to the client IP.

### 🐛 Fixes

- **A crash could corrupt the agent's rule cache, and the agent kept that
  quiet.** `sites.json` / `metadata.json` / `blocked_ips.json` were written
  with plain `fs::write`, so power loss mid-write left a torn snapshot; a
  startup load failure was logged at `debug` and the edge ran on empty rules
  silently. Every cache file is now written atomically (same-directory temp
  + fsync + rename, serialized behind a persist lock), the previous snapshot
  is rolled to `sites.json.bak` — only while it still validates — and the
  load path checks the metadata format version plus a CRC32/length stamp
  over the payload, falling back primary → backup → empty-with-warning.
  The load outcome and any degraded reason ride the heartbeat
  (`cache_persist_healthy` / `cache_status_reason`) so the control plane
  sees a fail-open edge instead of guessing.

- **Request bodies were invisible to the WAF when not valid UTF-8 or
  compressed.** Body inspection bailed out on `from_utf8` failure, so a
  single trailing `0xFF` byte — or any `Content-Encoding: gzip` body —
  skipped every signature and libinjection rule. Bodies are now
  decompressed per `Content-Encoding` (`gzip` / `x-gzip` / `deflate`,
  layers peeled in reverse, capped at 1 MiB decompressed to bound a
  zip-bomb) and then decoded tolerantly, so the bytes always reach the
  scanner.
- **HTTP/2 and HTTP/3 bodies skipped inspection.** `has_body` required
  either `Transfer-Encoding` or a positive `Content-Length`; h2/h3 forbid
  the former and may legally omit the latter, so modern clients bypassed
  body scanning. Every non-GET/HEAD request is now registered for the
  deferred body stage.
- **Retries leaked `processing` and least-connections inflight counts.**
  `first_attempt` was derived from `ctx.upstream.retries`, which only
  `fail_to_connect` increments — pingora retries a reused connection on its
  own and re-enters `upstream_peer` without touching that counter, so the
  second attempt was counted again while only one release ever ran.
  `processing` drifted upward forever and `least_connections` skewed
  permanently toward the retried backend. The guard is now the
  `processing_counted` flag, whose whole meaning is "already counted".
- **Sub-second `check_frequency` panicked the health checker.** The
  frequency comparison used whole seconds, so `check_frequency=500ms`
  truncated to 0 and `check_count.is_multiple_of(0)` panicked inside a
  detached task — every tick, so active health checking for that upstream
  never ran and dead backends kept receiving traffic. Frequencies are now
  carried in milliseconds end to end, with an explicit zero guard instead of
  a divide.
- **A `Vary` allow-list narrowed the cache key.** `vary_headers` was
  applied as a filter, so an origin sending `Vary: Cookie` on a
  personalised page had that dimension dropped and all users shared one
  entry. The allow-list no longer prunes the origin's `Vary`; a response
  naming a header outside the list is served uncached.
- **Padded SQLi tautologies scored zero.** `1' OR '1'='1` prefixed with 29
  filler bytes exceeded the 32-byte "search phrase" cut-off and was skipped
  without scoring — filler was the only cost of evading the rule. The
  decoy is now also required to look like prose (≥3 distinct words of 4+
  letters, not glued to an identifier), so real payloads score and padding
  no longer buys a bypass. `id=1 OR 1=1` repeated five times to reach the
  same length is caught too.
- **`browser_ttl` rewrote origin prohibitions into `public`.** Any response
  went out as `Cache-Control: public, max-age=N`, including ones the origin
  marked `private`, `no-store` or `no-cache`. The rewrite now only applies
  when the origin has not restricted reuse.
- **`s-maxage=0` was not treated as "do not reuse".** Only `max-age` was
  checked, so `Cache-Control: s-maxage=0, max-age=600` was stored and
  served stale for 1 second per `META_DEFAULTS`. Rejection now keys off
  `fresh_duration() == ZERO`, which covers both directives.

### ✨ Features

- **HTTPS origin certificate verification switch.** `basic.origin_verify_cert`
  controls whether connections to HTTPS origins validate the upstream
  certificate. Unset keeps the previous behaviour (no verification, so
  self-signed and internal-CA origins keep working) — the switch exists to
  make the choice explicit, and verifying is the recommended setting for
  origins with publicly trusted certificates. It is editable from the
  console's system settings and reaches the data plane through the agent
  bundle without a restart. Per-pool `verify_cert` still overrides it:
  `true` forces verification, `false` forces acceptance, unset defers to
  the global switch. The global default is folded into each upstream's hash
  key *before* the key is computed, and the config diff compares the field
  explicitly, so toggling it actually rebuilds the affected upstreams.
- **Config version page.** The list / detail / rollback API for
  configuration snapshots had no UI at all — it was reachable only by
  calling the API by hand. A new "Config Versions" page lists snapshots
  with scope and date filters and client-side paging, shows a version's
  detail as a per-table diff against its predecessor, and rolls back behind
  a confirmation dialog.

### 📝 Notes

- New `origin_settings` table (migration 52) holding the global
  `origin_verify_cert`, alongside `defense_settings` / `cache_settings`.
  The migration also clears `site_upstream_pools.verify_cert` values that
  were stored as `false` — under the three-state semantics `false` now
  means "force acceptance" rather than "unspecified", so leaving them would
  have pinned those pools to the old default and made the new global switch
  ineffective for them.
- `verify_cert` is now tri-state: `true` verify, `false` accept anything,
  unset defer to `basic.origin_verify_cert`.

## [PingWAF 0.25.11] — 2026-10-13

The root cause behind "every response reports `x-cache-status: expired`",
plus a Cloudflare-style per-file-type cache policy.

### 🐛 Fixes

- **No static fallback when a site's cache rules don't match.** The cache
  plugin is attached to every site once any site has rules, and the
  request handler fell back to the plugin's static config — unconditional
  caching — whenever no rule matched. Traffic the administrator never
  opted in (console API polling, dynamic pages) was cached under
  pingora's 1-second default freshness, so every repeat request reported
  `expired` and the origin was hammered anyway. A known site whose rules
  don't match is now skipped from caching entirely; unknown hosts keep
  the static behaviour for standalone deployments. This is the root
  cause of the fleet-wide `expired` reports.
- **Freshness floor for origin-silent responses.** Origins that send no
  usable freshness — nginx static files with no `Cache-Control` at all,
  or bare `public` / `must-revalidate` directives — silently collapsed
  to pingora's 1-second default even when a rule (or the new policy)
  configured a much longer TTL. The configured TTL now floors those
  responses instead. Explicit origin directives still win: `no-store`,
  `private`, `no-cache` and `max-age=0` reject the entry, and a
  longer-than-configured `max-age` is capped at the configured TTL.
  `Expires`-only origins keep their header-based freshness.
- **Localized cache-type labels.** The size-limits table rendered raw
  i18n keys (`pages.caching.type.html`) instead of the family names.

### ✨ Features

- **Per-site cache type policy.** Five fixed content families —
  web assets (css/js/ico/fonts…), images, media, other, html — each
  with its own toggle, edge TTL, browser TTL and editable extension
  list. The families compile into cache rules behind the site's custom
  rules (custom rules win by first match, so an `/api/` exclusion beats
  the policy's own `.json` entry). Origin silence caches at the
  configured TTL per the freshness floor above; origin prohibitions
  always apply. Served through the agent bundle with full backwards
  compatibility (sites without a policy ship nothing new).
- New `sites.cache_type_policy` column (migration 51).

### 📝 Notes

- After upgrading, sites that rely on the old catch-all static caching
  must enable it explicitly (a catch-all cache rule or a type policy) —
  the silent fallback is gone by design.
- Upgrade hint: `x-cache-status: expired` on console/API paths
  disappears with the first fix; those paths are no longer cached at
  all.

## [PingWAF 0.25.10] — 2026-10-13

Fixes for the cache analytics shipped in 0.25.9: saved bytes always read
zero, and the hit rate was diluted toward zero by traffic that never
consulted the cache.

### 🐛 Fixes

- **Real response byte counts in access logs.** The access entry was
  completed at the response-header phase whenever the body was not worth
  capturing, recording the `content-length` announced by the origin —
  which chunked responses don't send. Every such response logged a size
  of zero, so the "bytes saved by cache" card stayed at zero even on
  hits. Entries are now held until the body phase has counted the bytes
  actually streamed; the announced length only fills in when nothing
  streams (HEAD, 204/304, entries swept mid-exchange). Body *content*
  is still only stored when the header phase deemed it capturable —
  counting is unconditional, storage is not.
- **Cache hit rate over cache-participating requests.** The hit rate was
  `hits / all requests`, so scanner noise and traffic from sites without
  cache rules pushed it toward zero. It is now `hits / requests that
  consulted the cache` (miss/hit/expired/stale/revalidated), the
  Cloudflare-style measure of how well the cache actually serves. The
  hit-count and bytes-saved metrics are unchanged.

### 📝 Notes

- Upgrade hint: hit-rate and bytes-saved cards reflect traffic logged
  after this version is deployed; the 0.25.9 window had zero-byte
  response sizes by construction.

## [PingWAF 0.25.9] — 2026-10-13

The cache management batch — global cache settings, cache analytics, and
per-site / per-content-type size limits.

### ✨ Features

- **Global cache settings.** The settings page gains a "Cache" card with a
  master switch, a per-file size cap (default 16 MB, hard limit 1 GB), a
  global cache space budget (default 10 GB, hard limit 1 TB), and a default
  edge TTL used as the fallback for cache rules without an explicit TTL.
  All values are pushed to the data plane through the agent RuleBundle and
  take effect without restarts; turning the master switch off detaches the
  cache plugin entirely.
- **Cache hit-rate and bytes-saved analytics.** The site traffic page shows
  two new cards: cache hit rate and traffic saved by the cache. Access logs
  now record the real cache phase per request — previously `cache_status`
  was written as an empty string, so hit-based analytics could never be
  non-zero. Historical logs carry no cache status; the cards fill up as new
  traffic flows through.
- **Per-site and per-content-type file size limits.** The site caching page
  gains a per-site max cacheable file size plus per-type caps for HTML,
  CSS, JS, images, fonts, media, and other content. The effective limit is
  `min(global, site, type)`, enforced by the edge before a response body is
  written to disk; oversized responses are simply not cached. Site and type
  values are validated against the global cap on both the server and the
  frontend, with explicit error messages.

### 🔧 Internal

- New `cache_settings` singleton table and two nullable columns on `sites`
  (`cache_max_file_size_mb`, `cache_type_limits_mb`); RuleBundle carries the
  new optional cache fields (26/27), byte-compatible with older agents.

## [PingWAF 0.25.8] — 2026-10-12

The logs page usability batch — search autocomplete, one-click actions on
client IPs, and a unified, denser log list.

### ✨ Features

- **Search autocomplete.** Typing a field name in the logs search box pops
  an inline suggestion panel (filtered by the active tab), with `↑`/`↓`
  navigation, `Tab`/`Enter` to accept, `Esc` to dismiss. The suggestions,
  the clickable field chips under the box, and the parser all read the same
  field metadata (`logQuery.ts`), so they can never drift apart.
- **Clickable field hints + syntax docs.** The static hint line is replaced
  by per-field chips — clicking one appends `field:` to the draft and
  focuses the box. A new syntax line documents the grammar: space = AND,
  comma = OR on one field, `*` wildcard, quoted values; `and` / `or` /
  `not` keywords are not supported.
- **Security event dialog actions.** The method/URL subtitle under the
  dialog title is gone. The client IP is now a link that fills the search
  box and re-runs the query, and two quick actions follow the detail grid:
  **拉黑 IP** (manual block via `POST /blocked-ips/block`, permanent or
  1 h/24 h; disabled for unassigned traffic, which has no site context)
  and **加入 IP 组** (a picker dialog that appends the IP to the chosen
  group's ranges and PUTs the update).
- **Unified log list styling.** All three tabs share one look now:
  timestamps drop the year (`MM-DD HH:mm`), the country marker on client
  IPs is a flag emoji instead of a second text line, the path column is
  fixed-width with truncation plus a full-value tooltip, and IP/path cells
  have a right-click menu — "search this value" and "copy".

## [PingWAF 0.25.7] — 2026-10-12

The console polish batch — cache coverage for large static bundles, the
world map, and a round of semantics fixes surfaced by the pursearea.cn
deployment.

### 🐛 Fixes

- **Large static assets are cached now.** The edge cache plugin's
  `max_file_size` stayed at pingora's 1 MB default, and pingora rejects a
  response at the header stage when its Content-Length exceeds the ceiling —
  a ~10 MB Magento merged `.min.js` bundle therefore never filled the cache
  (no `x-cache-status`, permanent MISS) while smaller `.png` files hit. The
  generated cache plugin config now sets `max_file_size = "16mb"`; disk
  usage remains bounded by the per-site quota and LRU eviction.
- **Breadcrumb 404s on site detail.** `security` and `rules` are path
  prefixes, not pages — the breadcrumb rendered them as links that fell
  through to the 404 route. Both prefixes now redirect to their first
  child page (`security/protection`, `rules/rewrite`), and the breadcrumb
  shows them as plain text instead of a link.
- **Nodes no longer show "未分配".** Since auto-binding was removed, an
  unbound agent serves *every* site of its owner — the nodes list and
  detail pages now say "全部站点" with a hint instead of the stale
  "unassigned" label, and tenant accounts can see their unbound agents
  again (visibility now mirrors the config-push rules, which it
  contradicted before).

### ✨ Features

- **World map of traffic.** The traffic page and the per-site traffic tab
  gain a "地域分布" choropleth: an equirectangular SVG world map
  (d3-geo + bundled 110m topology) with a brand-coloured heat ladder,
  hover tooltips and a top-8 country list. Backed by a new
  `GET /api/v1/geo/global-stats` aggregate (admins: all sites, tenants:
  owned sites) next to the existing per-site `geo/stats`.

### 📝 Docs

- **"后端栈降级" explained.** The card title and hint now state what the
  engine actually does: selected language stacks keep detecting and
  logging, but never block (monitor-only); language-agnostic checks are
  untouched. The old hint ("按后端语言栈降级") read as either "only
  check these" or "skip these".

### 🎨 UI

- **Visit-site shortcut.** The site detail header shows a one-click link
  to `https://<domain>` next to the domain title.

## [PingWAF 0.25.6] — 2026-10-12

The diagnosis and presentation batch — fixes the four defects that stalled
live certificate issuance (the pursearea.cn incident), and makes every
response exit path self-identifying so a blocked page can never be mistaken
for an origin failure again (Cloudflare's model).

### 🐛 Bug Fixes

- *(site API)* **A missing `max_tls_version` no longer means "max = lowest".**
  `TlsPosture::merged()` treated an absent ceiling as `lowest_tls_version`
  itself, so any site saved without an explicit maximum rejected its own
  HTTPS handshake with `unsupported TLS version`. Absence now means
  unbounded — the full 1.0–1.3 range is accepted.
- *(site API)* **Global certificate creation is atomic.** Certificate insert,
  TLS posture save and the site's `ssl_enabled` flip now run in one
  transaction; the ACME announcement, certificate event and config-push
  side effects fire only after the commit succeeds. A mid-flight failure
  previously stranded a half-created certificate with no event trail.
- *(control plane)* **Agent registration no longer auto-binds the owner's
  only site.** With exactly one site in the account, a registering agent
  was silently pinned to it; any later site/SSL save then pushed a payload
  scoped to that one site, so the unbound remainder of the fleet silently
  dropped the site — the root cause of the certificate task that sat in
  Pending forever. Agents now register unbound and receive the
  full-owner-bundle payload until explicitly bound.
- *(control plane)* **Config pushes reach every agent whose visibility
  includes the site.** Push delivery is derived from actual agent
  visibility (bound agents get site-scoped payloads, unbound ones the
  owner-wide bundle) instead of assuming a single-site owner, and a
  skipped push is logged as a warning instead of debug noise.
- *(site API)* **Deleting a certificate no longer trips an FK violation.**
  The deletion event is written with `certificate_id = None` — the event
  row referenced the certificate being cascade-deleted.

### ✨ Features

- **Every response identifies the edge.** Responses from both exit paths —
  origin passthrough and edge-generated errors — carry `server: pingwaf`.
- **Origin 4xx answers pass through untouched.** The default error-page
  plugin no longer intercepts 403/429 (a misattributed "Access Denied"
  page that masked origin problems); defaults now cover only 502/503/504
  and clearly say "Origin Server Error — this is not a security block".
- **Cloudflare-parity mitigation signalling.** WAF block pages add
  `x-pingwaf-mitigated: block`, challenge and rate-limit pages add
  `challenge` — the `cf-mitigated` equivalent, machine-readable by
  monitoring and integrations.
- **Branded block, challenge and status pages.** All WAF-terminated pages
  (block, challenge, basic-auth, paused site, fail-closed, rate-limit) share
  the branded card layout, stamp the request id / reason / time, and
  HTML-escape rule-provided reasons.
- **Branded edge error template.** The gateway's own failure page (upstream
  unreachable, timeouts) is rewritten in the same visual family and now
  shows the request id, error type and detail — with the same explicit
  "this is not a security block" wording.

## [PingWAF 0.25.5] — 2026-10-12

The identity split: global configuration stays in the sidebar's account
page, personal settings move to a dedicated page reached from the
top-right user menu.

### ✨ Features

- **/profile — personal account settings.** Profile, login-name and
  password changes plus passkey binding/renaming/removal live on a new
  page reached from the top-right "account settings" menu item; it is
  deliberately absent from the sidebar. The sidebar /account page now
  hosts only global configuration: API keys and user administration.
- **API key creator attribution.** The key list shows the owning
  account's email; keys the system mints on its own (all-in-one
  bootstrap, agent enrollment) show a "system" badge instead. Deleting a
  system key requires typing the key's full name in a second, red-titled
  confirmation — a mistaken revocation strands agent (re-)registration.
- **Passkey master switch.** Settings keeps a single deployment-wide
  toggle (persisted in `instance_settings`, admin-only, no restart
  needed): with it off, the login form hides the passkey option and new
  registrations are refused; existing credentials are kept.
- **Last login in user administration.** The admin user list shows each
  account's most recent successful sign-in (time + IP), resolved from
  the existing login history — no schema change, and historical data
  appears immediately.

## [PingWAF 0.25.4] — 2026-10-12

### 🐛 Bug Fixes

- *(proxy)* **Snapshot-restored pools get the lenient verification default
  too.** A rule cache restored from the persisted snapshot (`sites.json`)
  carries `verify_cert=null` and never passes through the agent's gRPC
  conversion where the lenient default is applied — the null reached the
  pingora peer builder untouched and meant strict verification there, so
  pools with an SNI but no explicit flag kept failing against self-signed
  origins with `InvalidCert` 502s even after 0.25.3's opt-in change. The
  cache-to-config conversion now normalizes as well: `null`/`None` becomes
  lenient, an explicit opt-in keeps strict validation.

## [PingWAF 0.25.3] — 2026-10-12

The certificate issuance unblocking batch — fixes the two defects that left
live domains stuck on "issuing" with `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` —
plus default-lenient origin certificate verification and three issuance
workflow improvements.

### 🐛 Bug Fixes

- *(acme)* **Ready orders are accepted.** Let's Encrypt answers `Ready`
  directly for a new order when every authorization is still valid
  (< 30 days old). The issuance loop only accepted `Pending`, so renewal
  wedged forever with `order is not pending, status: Ready`. Ready orders
  now skip the challenge loop and go straight to `poll_ready` →
  `finalize`; `Processing` / `Valid` / `Invalid` still fail loudly.
- *(reload)* **An issuance completing mid-reload is no longer clobbered.**
  The hot-reload path fetched the config snapshot without the write lock,
  so a PEM written between the fetch and the reload's save vanished from
  storage (and then from the SNI table on the next provider rebuild),
  rejecting all TLS handshakes. Reload now fetches, merges and persists
  atomically under the new `ConfigManager::update_raw`.
- *(certificates)* **Entries without a PEM keep serving the previous
  certificate.** The certificate provider is replaced wholesale on every
  update, so a configuration entry whose PEM had not (yet) been persisted
  used to take its domains out of the SNI table. Such entries now carry
  the previously served certificates over by domain; a fresh upload or a
  completed issuance still wins.

### ✨ Features

- **Origin certificate verification is opt-in.** New origin pools start
  with `verify_cert=false`: self-signed origins are the common case, and
  an unset flag stays lenient end to end (pool API → agent config
  conversion → pingora options). The dashboard switch is relabeled
  "require trusted origin certificate" for operators who want strict
  validation. This also removes the `InvalidCert` 502s against origins
  behind self-signed certificates.
- **New sites start with SSL enabled.** Every site is created with an SSL
  row (`https_enabled=true`): without it the data plane's `ssl.enabled`
  gate stayed closed and a later ACME request sat pending forever.
- **The SSL issuance dialog autofills domains.** Selecting a site fills
  the domain field with the site's primary and alternate domains (the
  backend already accepts the comma-separated list) instead of making the
  operator retype them.

## [PingWAF 0.25.2] — 2026-10-12

The SSL issuance observability batch — an ACME order can no longer hang
silently or sit in "pending" forever — plus a global IP blacklist page,
full request-body inspection without the 64 KB ceiling, and two
routing/rules resolution fixes.

### ✨ Features

- *(plugin)* **Request-body inspection is streaming and unbounded by the
  old 64 KB retry buffer.** Body bytes are no longer read in the request
  phase (which forced pingora's retry buffer, a hard 64 KB cap whose
  overflow discarded the whole buffered prefix). They now stream through
  a new `handle_request_body` plugin hook on the proxy's request-body
  filter: chunks worth inspecting are withheld from the upstream (empty
  chunk — never `None`, which would truncate the upstream request),
  inspected once the client is done, then either flushed intact or
  answered with a block page before a single body byte reaches the
  source. Bodies beyond `max_body_size` switch to prefix inspection and
  zero-copy passthrough — the tail is forwarded complete instead of
  being lost. `max_body_size` regains its real meaning as the
  configuration cap (previously silently clamped to 64 KB). Behavior
  notes: an attack that only the body reveals is now answered after the
  upstream request headers were sent (no body bytes, connection aborted);
  requests the plugin answers in the request phase (paused sites,
  IP/mTLS/access denials) log without a body prefix; requests served
  from cache skip body inspection.
- *(server)* **443 listens from the first boot.** A fresh deployment
  with no certificate yet still binds the TLS listener (handshakes fail
  until one is issued or uploaded) — the first certificate takes effect
  immediately instead of requiring a process restart.

### 🐛 Bug Fixes

- *(server, web)* **Global IP blacklist page** (`/blocked-ips`): every
  dynamic block in force across all visible sites — WAF/rate-limit
  auto-blocks and manual blocks — folded per (site, IP) with attack
  counts, block time and expiry. One-click unblock fans out to every
  enforcing agent; a manual-block dialog issues a `BlockIp` command to
  every registered agent (queued for offline ones) with a configurable
  duration.
- *(agent)* **Wildcard sites keep their protections.** `*.example.com`
  sites resolve rule lookups for their subdomains through a level-by-
  level wildcard fallback (exact site first, most specific wildcard
  wins, apex never matches `*.` — the routing layer's own semantics).
  Before, a wildcard site lost its WAF rules, cache policy, challenge,
  error pages and rewrites entirely, and its disconnected failover
  policy never applied.
- *(server)* **Routes with priority ≤ 127 are no longer dead.** A
  site's fallback location carried the auto weight 128, so any route
  with an explicit priority below it never matched; the fallback now
  sits at the lowest weight (0) and every explicit priority beats it.
- *(web)* The sidebar entry "IP 黑白名单" is renamed "IP 组" (zh locale),
  and the AI assistant entry is removed from the menu (the page itself
  stays reachable at `/assistant`).

- *(acme)* **Certificate issuance can no longer hang forever.** Every
  ACME network round trip (account load/create, order placement,
  authorization fetch, challenge-ready, finalize, and both polling
  stages) now runs under a hard timeout, and the four DNS provider
  clients (Ali, Cloudflare, Huawei, Tencent) are built with connect and
  total timeouts. instant-acme's bundled hyper client has no timeout of
  its own, so a CA endpoint that accepted the connection and went silent
  used to wedge the renewal task — and, through the background service's
  `join_all`, every other background task with it.
- *(server)* A certificate whose ACME order stays `pending` for more
  than 30 minutes is now marked `failed` with a `failure_reason`, and an
  `issuance_failed` event is recorded (previously nothing ever wrote
  `failed`, so a wedged order spun in the dashboard forever). The reason
  clears on retry or when the edge reports the certificate live.
- *(server)* Manual renewal (`POST …/certificates/{id}/renew`) actually
  reaches the edge now: it touches the site and notifies the agents.
  Before, only the status column changed — the renewal request never
  left the control plane.
- *(agent)* Raw ACME log events are attributed to their site and
  certificate by matching the domains they name against the agent's site
  rules (longest domain wins; wildcards also match their apex form, and
  ACME challenge subdomains resolve to the zone's site), so the panel's
  certificate log no longer shows them unattributed.
- *(core, agent)* A background cycle that overruns its interval with the
  ACME task still working now mirrors the warning onto the
  `pingap::acme` feed, so a stalled issuance surfaces in the panel's
  certificate log.
- *(web)* The global SSL page polls every 10 s while any certificate is
  pending, shows how long an order has been waiting (highlighted past 10
  minutes), and renders the failure reason on failed rows.

## [PingWAF 0.25.1] — 2026-10-11

A data-plane correctness batch from the October deep review, plus posture
dashboard alignment.

### 🐛 Bug Fixes

- *(plugin)* **Request bodies were silently truncated when the WAF captured
  them.** Pingora only replays body bytes through the retry buffer when it is
  enabled before the bytes are read; the proxy enables it deep inside the
  forwarding path, so the WAF's capture pass in the request phase lost every
  byte it read — H2 streams and the first request on an H1 connection lost
  the whole captured prefix (the entire body for payloads ≤ 8 KiB). The WAF
  now enables retry buffering before its read loop and stops capturing at
  the 64 KiB buffer boundary, so bodies up to the cap reach the upstream
  intact.
- *(plugin)* Rate-limit mitigation bans no longer reset when the counter
  window rolls over: `blocked_until` survives until it expires, so a ban
  longer than the window cannot be waited out.
- *(core)* `get_client_ip` no longer honors `X-Forwarded-For` /
  `X-Real-IP` from public direct peers when no `trusted_proxies` are
  configured — those headers were attacker-controlled and poisoned every
  IP rule (allowlists, rate limiting, auto-block, geo). Private/loopback
  peers keep working out of the box; explicit `trusted_proxies` remains the
  strict path.
- *(proxy)* `upstream_peer` failures no longer drive `Upstream.processing`
  permanently negative (each "no available upstream" 503 leaked a −1).
- *(proxy)* least-connections + retry no longer leak inflight counts: the
  release targets the address acquired on the first attempt instead of the
  final peer address after retries.
- *(web)* The custom-rules posture banner and the posture overview now
  reflect the enforced site mode (`settings.mode`) instead of re-deriving
  it from the rule list; the site mode badge is shown first.
- *(web)* Hidden health-check fields no longer block pool saving when
  stored values are out of range; path length is validated in UTF-8 bytes
  to match the server.

## [PingWAF 0.25.0] — 2026-10-09

A security-update batch (control-plane hardening, stricter proxy trust,
stronger bot verification) plus a round of dashboard UX consolidation.

### ⚠️ Breaking Changes

- *(plugin)* Proxy-trust resolution is now **strict**: a site with
  `trust_proxy_headers: true` only believes the forwarded client-IP header
  when the direct TCP peer falls inside `trusted_proxy_ranges` (CIDR list);
  otherwise the connection's own address is used. An empty range list means
  no proxy is trusted — sites that relied on forwarded headers without
  declaring their proxy's ranges must add them (or reference an IP group via
  the new `trusted_proxy_group_ids`) after upgrading. The server logs a
  warning at startup for affected sites.

### ⛰️ Features

- *(server)* The MCP endpoint's authentication now runs the same account
  checks as the REST API: disabled accounts, tokens superseded by a newer
  sign-in and accounts that must change their password are all refused (MCP
  offers no password-change flow). API keys are checked for revocation and
  enabled state. JSON-RPC batches are capped at 16 calls and the request
  body at 256 KiB.
- *(server)* The gRPC control plane serves **TLS by default**. With no
  certificate configured, the first boot generates a self-signed CA + server
  certificate (persisted in `instance_settings` and written to the data
  directory for agents to pin), so distributed deployments are encrypted out
  of the box; explicit `grpc_tls_cert`/`grpc_tls_key` take priority and
  `grpc_tls_mode = "off"` reverts to plaintext with a startup warning and a
  `grpc_tls: false` flag on `GET /version`, surfaced as a console banner.
  The all-in-one mode wires its embedded agent to the generated CA
  automatically.
- *(sites)* Reverse-proxy trust gains `trusted_proxy_ranges` (CIDR list) and
  `trusted_proxy_group_ids` (reference an IP group — its ranges merge with
  the hand-entered list). See the breaking change above for the enforcement
  change.
- *(plugin)* Bot protection verifies claimed bots beyond the spoofable user
  agent: `ip_verification_enabled` with `verified_ip_group_id` treats client
  IPs inside a referenced IP group as verified bots, and
  `dns_verification_enabled` adds reverse-DNS confirmation against the
  vendor domains (`*.googlebot.com`, `yandex.com`, `duckduckgo.com`, …) with
  a cached result and a graceful fallback to the UA verdict. Signals compose
  in the order IP match > confirmed DNS > UA whitelist > browser fingerprint.
- *(server)* IP groups support subscriptions: four built-in snapshot groups
  (Google, Yandex, DuckDuckGo and Cloudflare ranges) are seeded on first
  start, `url` groups pull plain-text/CIDR lists over HTTP, and a daily job
  refreshes both (`last_synced_at` / `last_sync_error` report the outcome).
  Range changes immediately re-push configuration to the sites using the
  group for access rules, route gating, bot verification or proxy trust.
- *(server)* Per-site `waf_enabled` is an explicit engine switch — with it
  off the data plane skips WAF evaluation for the site entirely, instead of
  inferring "no rules configured". `GET /api/v1/sites/{id}/waf/posture`
  aggregates the effective posture (engine, detection surfaces and per-
  category enforcement) for the dashboard and automation.

### 🎨 Miscellaneous

- *(web)* The protection page opens with a "current effective posture" card
  built from the new posture endpoint, and groups the settings into the
  engine / detection / enforcement layers; the protection-mode selector
  moved out of the custom-rules panel.
- *(web)* The site's Basic page is split into focused sections (trust,
  origin pools, routes) with the proxy-trust card gaining the new trust-
  range and IP-group editors; the sidebar now lists global pages only, with
  site-level navigation consolidated into the site tabs.
- *(web)* The agents table replaces the pending-commands column with last
  sync times — agents report when they last applied the site config and the
  rule bundle (`last_config_sync_at` / `last_policy_sync_at` on the agent
  response).

### 🐛 Bug Fixes

- *(web)* Relative times between one minute and one hour rendered as "just
  now", and hour gaps as "N minutes ago" — the unit ladder divided by the
  wrong interval. Heartbeat and sync columns show correct relative times.

### 📚 Documentation

- API reference: MCP authentication and limits, gRPC TLS defaults, WAF
  settings/posture, agent sync fields, IP-group subscriptions, bot
  verification fields and the strict proxy-trust semantics. Quick start and
  deployment guides updated for the TLS-by-default control plane; the
  security checklist gained gRPC-TLS and proxy-trust items.

## [PingWAF 0.24.1] — 2026-10-08

A patch release with three fixes for regressions and gaps reported right
after 0.24.0.

### ⛰️ Features

- *(server)* The account login name — the e-mail you sign in with — can now
  be changed, from Settings → Account (confirming with the current password)
  or by an administrator from the user management table. Changing it revokes
  every outstanding session, since tokens carry the login name as a claim,
  so holders must sign in again with the new name. This also removes the
  brute-force exposure of the fixed `admin@pingwaf.local` default on docker
  installs.

### 🐛 Bug Fixes

- *(web)* Clicking a site row navigated to `/sites/{id}/origin` — a route
  that no longer exists after the 0.23.0 tab reorganisation — so every site
  detail view answered "Page not found". Rows now open the basic tab.
- *(server)* The pingwaf-* crates declared their own `version = "0.1.0"`
  instead of inheriting the workspace version, so `GET /version`, the
  dashboard "About" card and the agent heartbeat version all reported
  `0.1.0`. The crates now use `version.workspace = true`.

### 📚 Documentation

- Version samples that had drifted (install examples, `/version` and agent
  responses in the API reference, the SECURITY.md support table) are synced
  to the current release line.

## [PingWAF 0.24.0] — 2026-10-08

A security-hardening batch: fixes for the risks surfaced by a full control
plane / agent / deployment audit.

### ⚠️ Breaking Changes

- *(compose)* The PostgreSQL port is now published on loopback only
  (`127.0.0.1:5432` by default). Deployments that reach the database from
  another host must set `POSTGRES_BIND=0.0.0.0` explicitly — together with a
  strong password.
- *(agent)* The log, certificate-event and metric shipping streams now
  authenticate with the agent's API key (gRPC metadata). **Upgrade agents
  before the control plane**: a new agent against an old server is ignored
  harmlessly, while an old agent against the new server is refused.
- *(agent)* `fail_open = false` now means what it always claimed: while the
  agent is disconnected from the control plane, hosts without synced rules
  answer `503` instead of silently falling back to the built-in rules in
  block mode. Deployments that set `false` while it was inert will see real
  fail-closed behaviour after upgrading — including a `503` window between
  agent start and the first successful sync.
- *(ci)* Main-branch docker builds publish a `:main` amd64 snapshot instead
  of overwriting the multi-arch `:latest` manifest on every commit;
  `:latest` now tracks releases only.

### ⛰️ Features

- *(server)* Optional TLS on the gRPC control plane: `grpc_tls_cert` +
  `grpc_tls_key` switch the listener to TLS, agents connect with `https://`
  URLs and can pin a private CA via `server_ca_cert`, and the all-in-one
  mode wires both sides up automatically.
- *(server)* The authentication endpoints are rate limited per source
  address — 10 logins/min, 5 registrations/hour, 30 refreshes/min, 10
  password changes/min (passkey logins share the login bucket) — answering
  `429` with `Retry-After` when exceeded.
- *(server)* Startup warns while the default administrator password
  (`pingwaf123`) is still active, next to the forced first-login password
  change.
- *(server)* `PINGWAF_PUBLIC_HOST` (or `--public-host`, or the `public_host`
  file key) pins the cleartext-to-HTTPS redirect target instead of building
  it from the client's `Host` header.

### 🐛 Bug Fixes

- *(server)* Placeholder JWT secrets — the built-in default, the CLI default
  and the compose value — are now all detected as unconfigured and replaced
  by a generated secret persisted on first boot, instead of being used
  verbatim by the single-value check.
- *(server)* Dashboard tokens carry a token version: changing a password,
  disabling an account or changing its role bumps the version and
  immediately invalidates that account's access and refresh tokens. Tokens
  issued before this mechanism existed stay valid until expiry.
- *(server)* The first-admin registration race is closed: sign-up runs in a
  transaction guarded by a Postgres advisory lock, so concurrent requests
  can no longer create a second administrator.
- *(server)* `/healthz` and `/api/v1/health` reuse their database answer for
  5 seconds, so a database that has slowed down stops collecting one extra
  query per container or load-balancer probe.
- *(agent)* `Set-Cookie` pairs shipped in access logs are joined with a
  newline instead of a comma — cookie values routinely contain commas of
  their own inside `Expires` attributes, which made shipped pairs
  indistinguishable.
- *(agent)* The reconnect backoff is jittered (each step lands between 50%
  and 100% of the doubled, capped delay) so a fleet that lost the control
  plane together never retries in lockstep.

### 🔧 Internal

- An outbound-TLS audit confirmed the control plane's HTTP client needs no
  change: reqwest 0.13's `default-tls` already maps to rustls and no
  OpenSSL build slips into the tree (pingora's openssl feature is the data
  plane's outbound backend, unrelated to the API client).

## [PingWAF 0.23.0] — 2026-10-08

### ⛰️ Features

- *(server)* Sites can now declare reverse-proxy trust: whether the origin
  sits behind a CDN/proxy, which header carries the real client IP
  (`x-forwarded-for` default, `cf-connecting-ip`, `x-real-ip`,
  `true-client-ip` and `forwarded` accepted) and whether only the last hop is
  trusted. When enabled, IP block lists, CC/rate limiting and logged client
  IPs are resolved from that header instead of the TCP peer. Ships as a
  migration, REST fields, proto fields, agent cache state and plugin TOML
  keys.
- *(web)* The site "Origin" tab is renamed to **Basic** and gains a
  reverse-proxy trust card driving the new site fields, alongside the origin
  pools and route tables.
- *(web)* On the Web Protection page the **under-attack mode** and **deep
  inspection** switches now sit side by side on one row, and deep inspection
  explicitly extends request-body evaluation to custom rules so body-carrying
  bypass attempts are caught by user-defined expressions too. The API
  protection settings no longer explain the port number, keeping the copy
  lean.
- *(server)* A full account system: `disabled` and `must_change_password`
  flags on users, an `auditor` role (read-only across every resource),
  admin-only user management endpoints with self-lockout protection, forced
  password change on first sign-in, self-service API keys for every account,
  and a random per-install JWT secret generated and persisted on first boot
  whenever the operator has not configured one.
- *(web)* **Account** is a top-level menu outside Settings: profile, password
  and personal API keys for everyone, plus user management (create, disable,
  role assignment with a live last-admin guard) for administrators. A
  first-sign-in gate blocks the whole console behind the change-password
  dialog until the password is replaced.

## [PingWAF 0.22.0] — 2026-10-07

### ⛰️ Features

- *(web)* The Web Protection page is reorganized into three tabs aligned with
  the rule surfaces, replacing the old split where a "grading" tab and a "WAF
  rules" tab overlapped invisibly. **Managed rules** holds the attack
  categories, the built-in rule switches, deep inspection and the backend
  stacks; **Custom rules** holds the posture banner and user-defined rules;
  **Rate limiting & challenge** links to the rate-limiting page and keeps the
  challenge settings. Legacy deep links (`?tab=settings`/`?tab=rules`) are
  normalized to the new tabs while preserving other query parameters, and log
  drill-downs land on the matching tab.
- *(web)* Attack categories are now two-state — **block** or **log only** —
  with the two mechanisms finally visible on one surface. The managed rule
  catalogue carries a `category` field (derived from the engine's family-tag
  mapping, exposed via `GET /api/v1/managed-rules`), and downgrading a
  category (SQLi, XSS, RCE) now also flips its family managed rules to
  log-only in the same request; switching the category back removes those
  downgrades, resetting individual overrides made in between. Per-rule
  switches stay independent, and batch buttons switch every built-in rule at
  once. "Advanced mode" is renamed to "deep inspection" and the old
  "monitoring" wording is replaced by "log only" throughout.
- *(build)* The web dashboard gains a unit-test setup (vitest) wired into CI,
  currently covering the category-linkage logic.

## [PingWAF 0.21.0] — 2026-10-07

### ⛰️ Features

- *(security)* Managed rules are now visible and tunable per site. The 14
  built-in `PINGWAF-*` rules ship in a catalogue (id, name, action, severity,
  tags, backend stacks, strict-only) exposed at `GET /api/v1/managed-rules`
  and rendered in the Web Protection rules panel, where each rule has a
  monitor switch. A monitored managed rule keeps detecting and logging
  normally but never blocks — including the score-gate rules
  (`PINGWAF-1002`/`1003`/`1004`/`1061`) — so a single rule that clashes with a
  site's business traffic can be demoted without touching the rest of the
  posture. The setting flows through the `WafConfig` gRPC message, the
  `waf_settings` table and a new `monitor_managed_rules` static TOML key, and
  sites without it behave bit for bit as before.
- *(security)* Security events are typed. A new `event_type` field classifies
  every event as `managed`, `waf`, `ip_geo`, `bot`, `rate_limit` or
  `challenge`, stamped by the data plane at detection time and carried through
  ingestion to the REST API. The detail link in the logs page now routes by
  type — a rate-limit event opens the exact rate-limiting rule in its editor,
  geo and bot events deep-link into their pages — instead of always landing on
  the WAF rules page, and events are searchable by `type:`. Legacy rows with
  no type keep the old behavior.
- *(security)* Traffic that arrives without a `Host` header (bare-IP access:
  HTTP/1.0 clients, health probes, scanners) is no longer invisible. Such
  requests keep full managed-rule protection, are recorded with a null site in
  both security events and access logs, and show as an unassigned badge in the
  global log views; the site filter gains an unassigned traffic option and
  `site:none` search syntax lists only these requests.
- *(build)* Release binaries shrink by roughly 40%: the release profile now
  optimizes for size (`opt-level = "z"`) and the default release build no
  longer enables the image-optimization feature (pass `--features imageoptim`
  to opt back in). Verified against the full four-configuration replay bench
  with byte-identical verdicts and conserved latency percentiles.

### 🐛 Bug Fixes

- *(dashboard)* Log detail cards no longer show the node (agent) field, the
  country renders as a flag icon prefixing the client IP instead of its own
  row, and the block and error pages label their request identifier as
  "Request ID" — matching what the dashboard searches by — instead of
  "Event ID".

## [PingWAF 0.20.0] — 2026-10-06

### ⛰️ Features

- *(security)* Rule grading: the site's WAF posture is now tunable per attack
  family instead of all-or-nothing. Nine attack categories (SQLi, XSS, RCE,
  LFI, SSRF, deserialization, CRLF, XXE, SSTI) and four backend stacks (Java,
  PHP, Python, Node) can be downgraded to monitor-only — detection and logging
  stay fully active while matches are recorded instead of blocked. Advanced
  mode switches the strict managed rule set plus deep request-body inspection
  on with one toggle, trading performance for the engine's maximum
  interception rate. Settings live in a new `waf_settings` table, flow through
  the `WafConfig` gRPC message to agent caches (old on-disk caches keep the
  default blocking posture), and sites without grading settings behave bit
  for bit as before.
- *(security)* Under Attack Mode: a site-wide emergency switch that challenges
  every visitor with a JavaScript check and turns CC protection on
  automatically. Enable it while the site is under an active flood and
  disable it once the attack subsides.
- *(dashboard)* The WAF and CC pages merge into one Web Protection page with
  three panels — rule grading, WAF rules and CC protection — fronted by a
  prominent under-attack banner. The pseudo detection toggles that only
  filtered the rules table are replaced by the real engine-level category
  switches. Old `/security/waf` and `/security/cc` links redirect with their
  query strings intact.

### 🐛 Bug Fixes

- *(agent)* Honor the heartbeat interval the control plane hands down at
  registration. The agent built its heartbeat timer from the local
  `heartbeat_interval_secs` and only logged the server's value, so an agent
  configured at 30 s kept that cadence even though the control plane told it
  to beat every 15 s — while the server's offline-detection threshold was
  derived from the 15 s it expected. Agents now follow the server-sent
  interval (falling back to the local setting only when the server sends
  none), keeping liveness detection and actual heartbeat frequency aligned.

## [PingWAF 0.19.0] — 2026-10-04

### ⛰️ Features

- *(security)* The edge auto-blocks what it refuses: a WAF block verdict
  blocks the client for ten minutes and a tripped rate limit for its retry
  window, so repeat requests are rejected before the engine even runs. Agents
  report the blocks they enforce on every heartbeat, the control plane mirrors
  them in a new `agent_blocked_ips` table, and the access-restriction page
  gains an auto-blocked IP card — attack counts folded from security events,
  last attack time, expected unblock time and one-click unblock fanned out to
  every enforcing agent.
- *(dashboard)* Traffic pages gain egress bandwidth visualization: a
  rate chart bucketed in 5-second windows (readable as Kbps/Mbps/Gbps) and a
  total-egress card that counts response bytes only — origin-pull traffic is
  never included. Backed by the new `GET /analytics/traffic` endpoint.
- *(dashboard)* The lifecycle reference page moves its numbered stage
  introduction into a left-side quick navigation that tracks the section in
  view, matching the Settings page layout.
- *(dashboard)* Settings gains an About card with the project URL and the
  running version.
- *(cli)* The `pingwaf` binary gains break-glass maintenance commands that talk
  straight to PostgreSQL, so they keep working when the control plane is down,
  not yet seeded, or its own IP allowlist has locked the operator out:
  `user list`, `user add-admin` and `user reset-password` (password generated
  and printed once when omitted), `mode observe` / `mode enforce` /
  `mode status` for observation mode, and `security status` /
  `security allowlist on|off` for the 9080 protection switches.
- *(security)* Observation mode: one global switch makes every protection
  detect but not enforce — a WAF verdict, IP/Geo rule or bot rule that would
  have been blocked, and a rate limit that would have tripped, are recorded as
  monitor security events while the request proceeds. Access control is never
  downgraded: mTLS, basic auth and a paused site still deny. The flag rides
  inside every rule bundle, so agents pick it up on the next configuration
  push; the CLI writes the row and the control plane pushes within seconds.
- *(security)* The control plane protects its own listener (9080). It records
  one access-log row per request — client, user, action, status, latency,
  reason — kept in PostgreSQL with its own retention window (default 30 days),
  searchable in the console and through `GET /logs/control-plane`. An IP
  allowlist (inline addresses and CIDRs plus an optional reference to an
  `ip_groups` row) and the embedded WAF (block or monitor mode, 128 KiB body
  inspection limit) gate every API request; health probes are exempt. A write
  that would enable the allowlist without covering the caller is refused with
  `422` unless `force` is set, so the console cannot lock out its own
  operator. All of it is editable from Settings and via
  `GET/PUT /settings/api-protection`.
- *(dashboard)* Two new Settings cards (administrators only): observation mode
  — with a banner while it is on — and API protection (access log, allowlist
  with inline ranges and IP-group reference, WAF mode). The Logs page gains a
  third "Control plane" tab with the same search grammar and a request detail
  view, and the log purge result reports the control plane rows removed.
  English, Chinese and Japanese translations included.
- *(ai)* An AI assistant is embedded in the console (administrators only). It
  talks to any OpenAI-compatible endpoint — base URL, model, API key,
  temperature, round limit and system prompt live in Settings, with a test
  button before saving — streams answers over SSE, and grounds them by calling
  the built-in MCP tools: sites, agents, certificates, access logs, WAF
  events, traffic and defense status. Read-only tools are on by default; the
  two write tools (observation mode, site enable/disable) stay off until
  explicitly allowed. Conversations are stored server-side, so history
  survives reloads, and the API lives under `/settings/ai` and
  `/ai/conversations`.
- *(mcp)* The control plane speaks MCP over Streamable HTTP at `/mcp`, so
  external agents — Claude, IDE copilots, scripts — can inspect a deployment
  with the same eleven tools as the built-in assistant. Authentication reuses
  API keys (`pwk_…`, requiring the matching read/write permission) or JWT
  users with role-based access, and the endpoint sits behind the same 9080
  protection stack (access log, IP allowlist, embedded WAF) as the rest of
  the API. The transport is stateless, with resources and prompts for common
  deployment data, and GET/DELETE answered with `405`.
- *(dashboard)* Settings gains a quick navigation column (wide screens) that
  tracks the card in view and smooth-scrolls to any section.
- *(dashboard)* The AI assistant's system prompt field is prefilled with the
  built-in default — `GET /settings/ai` returns the prompt in effect — and an
  untouched field round-trips as "no override", so future improvements to the
  default still reach deployments that never customised it.
- *(dashboard)* Log detail dialogs were rebuilt around raw HTTP: request and
  response render as complete raw messages with syntax highlighting (JSON
  bodies are reindented for display while numbers keep their exact text), and
  the separate user-agent/header/body blocks were removed. Everything renders
  as escaped text nodes — never `innerHTML` — so hostile bytes in a captured
  response or header stay inert.
- *(install)* The Add node dialog now hands out a single command: the
  installer starts the agent service itself (`systemctl enable --now` in agent
  mode), the redundant binary-only command is gone, and the raw token is no
  longer displayed — it already rides inside the command.
- *(dashboard)* Settings gains an **MCP server** card: the live endpoint URL
  with a copy button, the transport and authentication facts, the full tool
  inventory with write tags, and copy-paste client snippets (a generic JSON
  config and the `claude mcp add` one-liner) plus a jump to the API-keys card
  for the credential. It is backed by a new `GET /settings/mcp` endpoint that
  any authenticated user may read — viewers can connect read-only.

### 🐛 Bug Fixes

- *(api)* Fix saves of the AI settings and API protection being silent no-ops.
  Both handlers rebuilt the row through `ActiveModel::from(model)`, where every
  column arrives as `Unchanged`; SeaORM treats an all-unchanged model as a
  no-op, skips the `UPDATE` and returns the stale row with `200 OK`. The
  console therefore reported a successful save while the AI provider config —
  and, after the API-protection write only touched `updated_at`, the whole
  settings page — kept showing "unsaved changes" and "disabled". Both writers
  now explicitly `Set` every column, with exhaustive tests that walk the
  entity's column list and fail when a future column is left `Unchanged`.
- *(dashboard)* Log detail dialogs trim the rows the raw capture already
  shows: node, query string, path and method are removed, and the status code
  is a badge next to the "Access log detail" title. In the security-event
  dialog the rule id is now a link that opens that rule's editor on the site's
  WAF page, so a detection can be inspected without searching for the rule.

### ⚡ Performance

- The access log gains `(client_ip, timestamp DESC)` and partial
  `(host, timestamp DESC)` indexes, so "what did this IP request" and
  host-filtered log searches stop scanning the whole table.
- `GET /analytics/sites` replaces its per-site pair of correlated subqueries
  with two grouped queries merged in memory — one round trip per source
  instead of two per site.
- Agent metric series are aggregated by SQL `GROUP BY` on read instead of
  loading every raw row and folding in memory.
- Host samples persist one row per minute per agent instead of one per probe,
  cutting the table to a fraction of its raw volume while the probe panel
  (which diffs counters) stays correct.
- The request path trims allocations: the client IP is parsed once and shared
  by geo lookups, IP access rules, rate limiting and expressions; the logged
  protocol comes from a static table instead of `Debug` formatting; the
  clearance-cookie manager is cached instead of rebuilding its HMAC key per
  validated request; config fingerprints are `Arc<str>` instead of `String`
  copies; and bot classification matches case-insensitively without
  lowercasing the user agent.

### 🔧 Internal

- The API reference (`docs/api.md`) documents the new endpoints
  (`/settings/api-protection`, `/settings/defense`, `/logs/control-plane`,
  the control plane log purge count) and backfills three previously
  undocumented ones (`POST /agents/enroll`, `GET /certificates/summary`,
  `POST /sites/{site_id}/cache/defaults`); the `422` error code now reads
  `unprocessable_entity`, matching the implementation. The AI assistant and
  MCP server are documented as well: the AI settings and conversation
  endpoints (including the SSE event stream), the `/mcp` JSON-RPC surface
  with its authentication rules and tool inventory, and `GET /settings/mcp`.
  `GET /analytics/traffic` and the blocked-IP endpoints
  (`GET /sites/{site_id}/blocked-ips`,
  `POST /sites/{site_id}/blocked-ips/unblock`) are documented too. The user
  guide gains an "AI Assistant & MCP" chapter covering provider setup,
  day-to-day use of the assistant page and connecting external MCP clients.

## [PingWAF 0.18.0] — 2026-09-30

### ⛰️ Features

- *(sites)* A site now serves several hostnames. The primary domain keeps its
  role (display, validation anchor), and `alternate_domains` adds as many more
  as needed — each one routed to the same site, its certificates extended to
  cover them, and settable from the dashboard's domain editor. Wildcards
  (`*.example.com`) are supported and never cover their bare domain. The API
  refuses a name another site already claims, including a hostname covered by
  a different site's wildcard, where the data plane's host matching would be
  ambiguous; wildcard certificates additionally require the `dns-01` ACME
  challenge, enforced both when saving the certificate and on the data plane.
- *(logs)* Log retention is configurable in Settings. Administrators pick how
  long access logs and security events are kept — 180 days each by default,
  1 to 3650 — and a background sweep on the control plane deletes older rows
  in batches every six hours. The Elasticsearch ILM policy keeps its own,
  independent 360-day window for shipped logs; the manually triggered purge
  endpoint is unchanged.
- *(dashboard)* Custom error pages are global now. They moved from each site's
  tab to a single Settings card, one page per status code for the whole
  deployment, pushed to every site as before (and falling back to the built-in
  page when a code has no override).
- *(security)* Basic auth joins access control, in two shapes. A site-wide gate
  (Access Control → Basic Auth: realm, credentials, optional failure delay and
  credential stripping) protects every request of a site, and a `basic_auth`
  action on IP and Geo rules protects just the clients a rule matches.
  Unauthenticated requests answer `401` with a `WWW-Authenticate` challenge;
  after the credentials pass, a rule-gated request continues through the
  remaining checks (bot protection, rate limits, WAF rule sets), while an
  `allow` rule exempts a client from the site-wide gate. The check lives in
  the WAF plugin ahead of the cache, so a cached response can never bypass it.
  Credentials are stored with the site configuration and masked in API
  responses.

### ⚠️ Breaking Changes

- The `jaeger` parameter of an OTLP exporter endpoint no longer enables the
  deprecated Jaeger propagation format: the upgrade to OpenTelemetry 0.33
  removed its propagator crate, and W3C TraceContext (still enabled by
  default) covers the same ground. The parameter is accepted and logged as
  ignored, so existing `otlp_exporter` values keep parsing.

### 🔧 Internal

- Refreshed the delivery toolchain: OpenTelemetry 0.33, ESLint 10 with
  `eslint-plugin-react-hooks` 7, Vite 8 and `@vitejs/plugin-react` 6. The
  dashboard's forms now seed their inputs during render instead of inside
  effects, as the new hooks plugin requires.

## [PingWAF 0.17.1] — 2026-09-30

### 🐛 Bug Fixes

- *(logs)* Record the response of a request the WAF answered itself. A block,
  challenge, rate limit or paused-site response never reaches the proxy's
  response hook, so its access row carried no response headers, no body and a
  zero size — the one response an operator most wants to replay was the one the
  log could not show. The plugin now logs the page it is about to send, headers
  and truncated body included, exactly as it does for proxied traffic.
- *(cli)* `pingwaf --version` works in every mode. With `PINGWAF_MODE` set (the
  value `docker-compose.yml` ships), the mode is injected as a subcommand and
  the version flag was rejected as an unknown argument, leaving no way to ask a
  running deployment which build it runs. The flag is now answered before the
  subcommand is spliced in, `-V` keeps printing the bare number and
  `--version` the full banner.
- *(cli)* The `pingwaf` binary no longer introduces itself as `pingap`. The
  version banner and help were taken from the Cargo package name, which the
  fork keeps for upstream compatibility; they are now taken from the binary
  name, so `pingwaf --version` says `pingwaf 0.17.1 (…, tls=openssl)` while the
  legacy `pingap` binary still says `pingap`.

## [PingWAF 0.17.0] — 2026-09-30

### ⛰️ Features

- *(config)* Load settings from a TOML file with `--config <path>` (or
  `PINGWAF_CONFIG`). The `[server]` and `[agent]` tables take the same names as
  the long flags, with dashes written as underscores (`--admin-addr` →
  `admin_addr`) and lists as TOML arrays; `all-in-one` reads both tables, while
  `server` and `agent` read only their own. Precedence is file, then
  environment, then command line, unknown keys are reported and skipped instead
  of silently ignored, and the effective count is logged at startup. The
  shipped [`pingwaf.toml`](./pingwaf.toml) and `pingwaf.service` are now real,
  loadable configuration, and `install.sh` points the unit at
  `/etc/pingwaf/pingwaf.toml`.
- *(config)* Boolean flags can be turned off again. `--serve-frontend` and
  `--fail-open` were declared as value-less flags, so neither the command line
  nor the environment could set them to `false`; they now take an optional
  value (`--fail-open=false`, `PINGWAF_FAIL_OPEN=false`), and the same fix
  makes the documented `--tls-enabled false` work.
- *(logging)* `RUST_LOG` now defaults to `info,sqlx=warn`. Every SQL statement
  was logged at `info`, burying the control plane's own messages under the
  query log; naming `sqlx` in `RUST_LOG` still gets exactly what was asked for.

### 🐛 Bug Fixes

- *(api)* Fix the HTTPS redirect loop that made the dashboard unreachable over
  TLS. The redirect middleware read the connection info as `ConnInfo`, but axum
  stores it as `ConnectInfo<ConnInfo>`, so the lookup always missed: a request
  that had arrived over TLS looked like cleartext and was redirected to the URL
  it was already on — a `308` loop the browser reports as too many redirects.
  The middleware now reads the newtype, and a socket-level regression test
  covers cleartext, TLS and health-probe requests.
- *(deploy)* Drop the `ExecReload=/bin/kill -HUP` line from the shipped unit
  and the one `install.sh` writes. There is no reload signal, so
  `systemctl reload pingwaf` silently did nothing; the units and the docs now
  say to edit the configuration and restart.

### ⚠️ Breaking Changes

- The configuration file is no longer inert. A deployment that kept unrelated
  content in `/etc/pingwaf/pingwaf.toml` will now see its `[server]` /
  `[agent]` tables applied (unrecognised keys are only warned about), and a
  path named by `--config`/`PINGWAF_CONFIG` that cannot be read stops startup
  instead of being ignored.

## [PingWAF 0.16.0] — 2026-09-30

### ⛰️ Features

- *(api)* Serve the control plane over HTTPS by default. The REST API and
  dashboard port (9080) now speaks TLS, which is what browsers require before
  they will offer a passkey: a self-signed P-256 certificate is generated on
  first boot and covers the configured `tls_sans`, the machine hostname,
  `localhost` and `127.0.0.1`. A single listener dispatches on the first byte,
  so cleartext requests are answered with a `308 Permanent Redirect` to the
  `https://` URL on the same host instead of a connection reset, and the two
  health endpoints (`/healthz`, `/api/v1/health`) stay reachable over both
  schemes so container and load-balancer probes keep working without a
  certificate. `tls_enabled = false` (`PINGWAF_TLS_ENABLED=false`,
  `--tls-enabled false`) restores plain HTTP for deployments behind a
  TLS-terminating proxy.
- *(api)* Manage that certificate from the dashboard. New administrator-only
  endpoints under `/system/tls` report what is being served, download the
  certificate in use, accept an upload (chain + key validated before anything
  is written), and regenerate the self-signed pair; the console gets a
  **Control plane HTTPS** card in Settings that shows the subject, SANs,
  fingerprint and expiry, warns when the hostname you opened the console on is
  not covered, and offers the same actions. A replaced certificate takes effect
  immediately — the listener swaps the pair through a reloadable resolver, no
  restart — and the private key never leaves the server.

### 🐛 Bug Fixes

- *(auth)* Passkeys now work on a deployment that terminates TLS itself. The
  relying-party origin was reported as `http://<host>` unless the operator set
  `passkey_trust_forwarded_proto` **and** a proxy supplied `X-Forwarded-Proto`,
  so a browser on the HTTPS console rejected its own credential with an origin
  mismatch. The scheme now follows the listener — a request that reached a
  handler on a TLS-terminating port arrived over HTTPS — while the forwarded
  header is still only believed when the flag is explicitly set.

### ⚠️ Breaking Changes

- Clients that talked to `http://<host>:9080` now receive a `308` redirect;
  use the `https://` URL (with `curl -k` until the certificate is trusted) or
  set `tls_enabled = false`. The self-signed certificate is not trusted by any
  browser until it is installed or replaced.

## [PingWAF 0.15.0] — 2026-09-29

### ⛰️ Features

- *(sites)* Pause a site and have the edge honour it. The lifecycle flag only
  lived in the control-plane database, so a paused site kept serving traffic;
  it now reaches agents and every request is answered with a 503 maintenance
  page (`Retry-After: 3600`) while TLS, WAF logging and traffic counters keep
  running. Pause/Resume sits behind a confirmation in the site header and the
  sites list, whose status column is now read-only.
- *(ssl)* Enforce HSTS and HTTPS redirection at the edge. `hsts_enabled` and
  `always_use_https` were stored but never applied; responses now carry
  `Strict-Transport-Security: max-age=<n>` and plain-HTTP requests are
  redirected with 301. The console defaults the max-age field to 15552000
  (180 days) when HSTS is switched on.
- *(ssl)* Manage mTLS end to end. Sites can generate or import a client CA,
  issue client certificates (P-256, ClientAuth EKU, validity capped by the CA)
  and revoke them; the private key is returned once at creation time. The
  hosting process requires a client certificate for mTLS sites — there is no
  `FAIL_IF_NO_PEER_CERT`, so a shared :443 still handshakes for non-mTLS sites —
  and the WAF rejects missing certificates, revoked fingerprints and
  certificates issued under a different organization with 403.
- *(routes)* Route by client IP group. A route can be gated to an IP group;
  the group's CIDRs are expanded into the agent's route config and matched
  against the connection address in the data plane, ANDed with the path and
  header conditions. Other clients fall through to the next route.
- *(logs)* Capture the full request *and* response. Response headers, a
  truncated body, its real size and a truncation flag are stored alongside the
  request side, `scheme`/`protocol` are persisted, and the response body cap is
  configurable via `max_body_log_size` (up to 64 KiB). Cookies and the
  authorization header are no longer redacted — the log detail is meant for
  replaying an attack, so treat the log store as sensitive.
- *(logs)* Kibana-style search in the console. One box parses
  `field:value` tokens (`status:4xx`, `client_ip:203.0.113.*`, `rule:942100`,
  free text over path/host) into the existing API filters, the URL stays in
  sync so a query can be shared, and the traffic panels drill into the matching
  log rows. Log detail dialogs gain a response section, a raw-request panel and
  a "copy as curl" button.
- *(auth)* Passkey (WebAuthn) registration and passwordless sign-in, on top of
  `passkey-server`. Challenges are persisted in the control plane so a ceremony
  survives a restart or a second replica, and the login endpoint is rate
  limited.

### 🐛 Bug Fixes

- *(auth)* Answer a wrong current password with 400 instead of 401. The 401 made
  the console treat the session as dead and log the user out mid-form; the
  message is now shown inline and localized.
- *(web)* Validate and document the origin address format. A scheme in the
  address field was silently stripped — the placeholder now shows a full URL
  and the API rejects a path, query or fragment.
- *(web)* Rename the "Custom Error Pages" tab to "Error Pages" so the label no
  longer wraps out of the tab bar.

### ⚠️ Breaking Changes

- Agent caches and control-plane payloads grow new fields (`status`,
  `mtls_*`, `ip_ranges` on routes, access-log response columns); older agents
  ignore them silently, so upgrade agents alongside the control plane.
- Crate-level API changes for embedders: `LocationConf.match_ip_ranges`,
  the wider `match_conditions` signature, and the new `DigestDetail` /
  `Ctx.conn` TLS-peer fields.

## [PingWAF 0.14.8] — 2026-09-29

### ⛰️ Features

- *(waf)* Enforce the remaining protection features in the data plane. Caching,
  bot protection, CC challenge, rate limiting, rewrites and custom error pages
  were configurable in the control plane but never evaluated at the edge; they
  now reach agents through the config stream and the WAF plugin applies them
  per request. Bot protection classifies requests by user agent in v1 (verified
  browsers, suspicious clients, blocked patterns) — TLS fingerprinting and
  behavioral analysis are announced as upcoming. Rate limits count per key with
  expiry, answer over-threshold requests from the edge, and emit security
  events; CC protection challenges suspect bursts before they reach the origin.
- *(logger)* Persist the full request behind every access log: request headers
  plus up to 1 KiB of the body (truncated beyond that) are stored in a new
  request-detail column, and the logs page can search by exact request ID and
  inspect the stored detail.
- *(dashboard)* Rebuild the dashboard around traffic. A new
  `/analytics/sites-over-time` endpoint feeds a per-site multi-line traffic
  chart, alongside new top-paths and status-code-distribution cards; the agent
  fleet and top-sites cards were removed.
- *(ip-groups)* Make IP group subscriptions real. Groups can pull ranges from
  a source URL — Cloudflare's official IP list JSON, generic JSON feeds or
  plain-text lists — a scheduler refreshes them at a chosen interval, and a
  failed fetch records the error without wiping the previously known ranges. A
  global "Cloudflare" subscription group is seeded on first boot, disabled by
  default so enabling it is a deliberate act.
- *(web)* Surface sync state in the IP groups page: a refresh-interval selector
  (manual to weekly) for subscribed groups and the last sync error inline.

## [PingWAF 0.14.7] — 2026-09-28

### ⛰️ Features

- *(waf)* Enforce IP access rules and geo restrictions in the data plane. Both
  policies are evaluated inside the WAF plugin from the cached rule bundle, so
  control-plane edits take effect without a proxy reload: IP rules run
  first-match-wins in priority order — an explicit allow short-circuits
  catch-all blocks, making "whitelist group + block everyone else" work — and
  they apply even when the WAF engine is disabled. Geo rules deny listed
  countries/ASNs, non-whitelisted traffic, or unresolvable countries, and every
  denial is logged with the resolved country code.
- *(ssl)* Report per-site certificate state through agent heartbeats. ACME
  issuance happens entirely on the edge, so the control plane kept showing
  issued certificates as "pending" with no expiry; the hosting process now
  exposes a snapshot (valid / expiring soon / expired, with `not_after`) that
  heartbeats carry back and the server writes onto the site's certificate row.
- *(web)* Merge IP rules and geo restrictions into one "Access control" tab,
  ready to host credential-based restrictions later. The geo panel gains an
  enable switch, per-continent select-all in the country picker, and ASN
  entries stored as strings to match the API; legacy `/security/ip-rules` and
  `/security/geo` links redirect with their query (and `?block=` deep link)
  intact.

### 🐛 Bug Fixes

- *(analytics)* Plumb rule display names and country codes through `LogEntry`
  so security events, access logs and the traffic page stop showing blank rule
  columns, and IP flags can render the client's country.
- *(server)* Serve `GET /sites/{id}/geo/stats` so the geo page's country chart
  has a backing endpoint.
- *(web)* The `?block=` deep link opened an empty dialog: a competing
  form-reset effect wiped the prefilled values. The query parameter is now
  consumed when the dialog closes instead of on open.

## [PingWAF 0.14.6] — 2026-09-28

### 🐛 Bug Fixes

- *(agent)* Open the heartbeat stream before the sender task so neither side
  deadlocks. The control plane holds response headers until it reads the first
  message, which the agent only sent after awaiting those headers — heartbeats
  never flowed, every agent drifted offline and server commands (rule updates,
  IP bans, cache purge) never reached the data plane. Also run the runtime
  images with a writable working directory (`/var/lib/pingwaf`) so agent cache
  persistence and ACME state survive restarts.
- *(agent)* Adopt the server-issued agent id on every gRPC stream. The client
  presented a locally generated UUID, so the control plane rejected each
  heartbeat with "agent_id does not match the presented token".
- *(compose)* Pin the container hostname so a recreated all-in-one agent
  re-registers under the same identity instead of minting a new agent row on
  every deploy.
- *(agent)* Split plaintext and TLS listeners: `global_certificates` enables
  TLS per server, so the combined "0.0.0.0:80, 0.0.0.0:443" listener wrapped
  plaintext HTTP in TLS handshakes — browsers to port 80 died with
  `tls_validate_record_header` errors and ACME HTTP-01 challenges never
  arrived. Port 80 now serves plaintext HTTP while 443 keeps TLS.
- *(server)* Persist the bootstrap API key to `/var/lib/pingwaf/bootstrap_api_key`
  (0600) and verify it against the database hash on startup, so the all-in-one
  agent keeps its key — and its agent row — across control plane restarts
  instead of minting a ghost row on every boot.

## [PingWAF 0.14.5] — 2026-09-28

### ⛰️ Features

- *(agent)* Run the WAF plugin on the data plane. The generated proxy config
  now injects the `pingwaf:waf` plugin and references it from every location,
  so detections execute and request/response logging reaches the control
  plane — dashboard and site analytics show real traffic.
- *(agent)* Hot-reload the data plane config when the rule cache hash changes
  (upstreams, locations, certificates and plugins refresh without restarting
  Pingora).
- *(server)* ACME issuance works in PingWAF mode: HTTP-01 and DNS-01 with
  per-provider default endpoints (aliyun, Cloudflare, DNSPod; Huawei needs a
  region). Raw `pingap::acme` application events ship to the control plane
  and appear in the SSL page's application log for debugging failed
  applications.
- *(server)* Site IP rules can reference global IP groups. Group ranges
  expand live in the rule bundle, so updating a group takes effect on every
  referencing site without touching its rules.

### 🐛 Bug Fixes

- *(web)* Fix the IP rules form dropping the CIDR list on manual-mode writes,
  which made the backend reject the request.
- *(server)* Reuse an agent's row when it reconnects from a new IP instead of
  registering a duplicate that stays offline forever, use the server clock
  for `last_heartbeat`/metrics so clock skew cannot mark healthy agents
  offline, and reset the reconnect backoff as soon as registration succeeds.
- *(server)* `certificate_events.certificate_id` is now nullable (raw ACME
  events can arrive before the certificate row) and `ip_access_rules` gained
  a nullable `group_id` (migration 000012).

## [PingWAF 0.14.4] — 2026-09-27

### 🐛 Bug Fixes

- *(server)* Mount the auth routes under `/api/v1/auth` (`login`, `register`,
  `refresh`, `status`, `me`, `password`). They were registered at the service root,
  so the dashboard login failed with `404 no route matches /auth/login`.
- *(server)* Accept `page` / `page_size` as strings in query structs that flatten
  `Pagination`. Query-string extraction buffers flattened values as strings, which
  made every paginated list endpoint reject `?page_size=200` with
  `invalid type: string "200", expected u64` and broke the dashboard list views.

## [PingWAF 0.14.3] — 2026-09-26 (initial version)

The first PingWAF release line. Version numbering continues from `pingap`
(0.14.x) because PingWAF ships the same proxy data plane inside its binary.

### ⛰️ Features

- *(binary)* Add the `pingwaf` binary with three run modes selected by CLI
  subcommand or `PINGWAF_MODE`: `all-in-one`, `server` (control plane) and
  `agent` (data plane).
- *(server)* Control-plane crate `pingwaf-server`: Axum REST API under
  `http://<host>:9080/api/v1` covering auth (JWT access + refresh tokens),
  sites, upstreams, rules, rate limiting, challenges, bot protection, Geo and IP
  rules, rewrites, error pages, SSL certificates, cache, logs, analytics, agents,
  API keys and settings; `GET /healthz` returns
  `{"status":"ok","database":"up"}`.
- *(server)* PostgreSQL persistence with SeaORM entities and automatic
  migrations on startup (PostgreSQL 14+, 16 recommended), plus an optional
  Elasticsearch log shipper configured through `PINGWAF_ES_*`.
- *(server)* Embedded dashboard served from the binary via `rust-embed`
  (`--serve-frontend`, default `true`) on `0.0.0.0:9080`.
- *(proto)* gRPC control-plane contract `pingwaf-proto/proto/control_plane.proto`
  with `RegisterAgent`, bidirectional `Heartbeat`, `SyncRules`, `ShipLogs`,
  `ShipMetrics` and `GetSiteConfig`; code generated by `protoc` at build time.
- *(agent)* Data-plane crate `pingwaf-agent`: gRPC client with exponential
  reconnect backoff, local rule cache (`--cache-dir`, default `./data/cache`),
  heartbeats (`--heartbeat-interval-secs`, default 30), batched log shipping
  (`--log-batch-size` 100, `--log-flush-interval-secs` 5,
  `--max-body-log-size` 8192) and `--fail-open` (default `true`) so traffic keeps
  flowing while disconnected.
- *(waf)* Detection engine `pingwaf-waf`: input normalisation, an Aho-Corasick
  plus libinjection-style SQLi/XSS fast path, and an expression rule engine with
  anomaly scoring producing a `WafVerdict` (`allow`, `block`, `challenge`,
  `rate_limit`, `log`, `redirect`).
- *(challenge)* `pingwaf-challenge`: JS challenge, clearance cookies with levels
  and expiry, and browser fingerprint verification.
- *(web)* Dashboard `web/`: React 19 + TypeScript + Vite 7 + Tailwind CSS v4,
  Zustand state, TanStack Query, recharts analytics; i18n in English, 中文 and
  日本語.
- *(deploy)* Docker assets: multi-stage `Dockerfile` (Node 22 frontend build →
  Rust 1.98.0 builder with `protoc`, `cmake`, `libclang`, `nasm` → minimal
  runtime) and `docker-compose.yml` with `pingwaf` (all-in-one) plus
  `postgres:16-alpine`, health checks and a commented distributed `pingwaf-agent`
  service.
- *(deploy)* `pingwaf.service` systemd unit with security hardening
  (`NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths`) and
  `install.sh` provisioning script.

### 📚 Documentation

- *(docs)* Add `docs/quick-start.md`: prerequisites, Docker Compose and
  source-build paths, systemd notes, first login and first protected site, run
  mode selection, configuration cheat sheet and troubleshooting.
- *(docs)* Add `docs/api.md`, `docs/user-guide.md` and `docs/deployment.md`
  covering the REST API, dashboard usage and production deployment.
- *(community)* Add `CONTRIBUTING.md` (development setup, code style, testing,
  commit and PR workflow, CLA), `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1)
  and `SECURITY.md` (private vulnerability disclosure, supported versions,
  hardening checklist).
- *(license)* Fill in the Apache-2.0 appendix copyright line:
  `Copyright 2024-2026 The PingWAF Authors`.
- *(changelog)* Introduce this PingWAF section above the inherited `pingap`
  history.

### Build

- *(proto)* `pingwaf-proto/build.rs` now resolves the protobuf well-known type
  include paths (Homebrew on Apple Silicon and Intel, `/usr/include`, and the
  `include` directory next to the `protoc` binary) and honours `$PROTOC`. When
  `protoc` is absent it emits a `cargo:warning` and writes a placeholder instead
  of the generated gRPC code — install `protoc` and run
  `cargo clean -p pingwaf-proto` to recover.

### ⚠️ Known Limitations

- Prebuilt release binaries are **not published yet**, so `install.sh` /
  `https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh` cannot download an artifact. Use Docker Compose or
  `cargo build --release --bin pingwaf --features full`.
- The `pingwaf` binary is configured through CLI flags and `PINGWAF_*`
  environment variables only; `pingwaf.toml` (upstream pingap proxy
  configuration) is not loaded by the control plane.
- Proxy ports `80`/`443` start listening only after at least one site exists.

---

<!-- ─── Inherited pingap history below (upstream proxy data plane) ─── -->

## [0.14.2](https://github.com/vicanso/pingap/compare/v0.14.1..v0.14.2) - 2026-09-12

### ⛰️  Features

- *(webhook)* Hot-reload webhook settings under autoreload/autorestart - ([bb5b222](https://github.com/vicanso/pingap/commit/bb5b222c90fc5a23dc0ca0f9dc6da59b1b744b6e))

### 🐛 Bug Fixes

- *(tls)* Harden openssl/rustls backend split and surface it in admin - ([6d601b9](https://github.com/vicanso/pingap/commit/6d601b93d97455ba053ada4257e9d1c4d6085156))
- *(web)* Keep admin form saves from dropping or rewriting config - ([f9e5a02](https://github.com/vicanso/pingap/commit/f9e5a022d6047de8889bdced1a8bf6ece0597c4d))

### 🚜 Refactor

- *(web)* Densify admin forms and hide empty certificate noise - ([8d8e7e5](https://github.com/vicanso/pingap/commit/8d8e7e52d0cd7ee373957745d0189d3cd243517d))

### 📚 Documentation

- *(tls)* Sync proxy/certificate/admin docs with rustls validation - ([679f081](https://github.com/vicanso/pingap/commit/679f08150b8fe8a435d8505e9b44014ffe2aecf6))

### ⚙️ Miscellaneous Tasks

- *(docker)* Publish a rustls-full image variant - ([69f4a8a](https://github.com/vicanso/pingap/commit/69f4a8ad7a2a8551d55087ae3a797b064512b540))

### Build

- *(deps)* Move pingora from the main git pin to crates.io 0.9.0 - ([2d5be1d](https://github.com/vicanso/pingap/commit/2d5be1debdf76a7346563bd2c33cf01c120a5f59))
- *(deps)* Bump docker/login-action from 3 to 4 - ([a693c36](https://github.com/vicanso/pingap/commit/a693c367355b862c37df1f0e2f900e98904c354b))
- *(deps)* Bump actions/checkout from 4 to 7 - ([b150d47](https://github.com/vicanso/pingap/commit/b150d4723a5cfe2d7cfc43828eb8efbf01a5db0d))
- *(deps)* Bump actions/setup-node from 4 to 7 - ([fa8a0b9](https://github.com/vicanso/pingap/commit/fa8a0b96aaa8518a72f1718d6d1682bfdb3ce8bc))
- *(deps)* Bump actions/deploy-pages from 4 to 5 - ([19a016a](https://github.com/vicanso/pingap/commit/19a016a92883b37e174e2db5ee9eb686d8d222fd))

## [0.14.0](https://github.com/vicanso/pingap/compare/v0.13.10..v0.14.0) - 2026-09-06

### ⛰️  Features

- *(cache)* Honour the origin's Vary header through cache_vary_filter - ([9a7a5dc](https://github.com/vicanso/pingap/commit/9a7a5dc0a93442d88ade12d8eef13f60ef4423b1))
- *(health)* Add ws:// and wss:// WebSocket health checks - ([e07b813](https://github.com/vicanso/pingap/commit/e07b813b5c8603d7497019277e3e152de4733034))
- *(metrics)* Export backend refresh timings and keep-alive pool evictions - ([bd1915e](https://github.com/vicanso/pingap/commit/bd1915e292d238409bf773d6fac0a2a4487270fa))
- *(restart)* Hand over on readiness reported by the new process - ([b8dfc5c](https://github.com/vicanso/pingap/commit/b8dfc5c7b95eb219a02fd780e3a11c90ebad1d15))
- *(server)* Expose pingora's TLS and connect offload thread pools - ([8dfa6d1](https://github.com/vicanso/pingap/commit/8dfa6d1e2e9361caf5987844be0b9190588f1302))
- *(server)* Expose downstream HTTP/2 SETTINGS per listener - ([5df838d](https://github.com/vicanso/pingap/commit/5df838d5ff2d8b715723701279f6aed5cda6c2e0))
- *(timing)* Take handshake durations and keepalive reuse from pingora - ([90a41cc](https://github.com/vicanso/pingap/commit/90a41cc9fc43d810a5f2dc7fa0b3ba4b43fdecbc))
- *(tls)* Make the TLS backend selectable, openssl by default - ([3e4efff](https://github.com/vicanso/pingap/commit/3e4efff0d338478df77d27bb6fbe867662435381))
- *(upstream)* Per-upstream CA bundle and HTTP/2 flow-control windows - ([aaff14f](https://github.com/vicanso/pingap/commit/aaff14f9e6509e0c019ac75b9b566cf95cc93f6d))
- *(upstream)* Expose pingora's request-header policy per upstream - ([d1a98cc](https://github.com/vicanso/pingap/commit/d1a98cc72d0525bfc1e1e7d731606cb029bf30c0))
- Expose blocking thread limit, cache lock retries and h1 pipelining - ([eff206f](https://github.com/vicanso/pingap/commit/eff206f7398b38eb2bc58a9a95f3db8b218d9b3b))

### 🐛 Bug Fixes

- *(deps)* Bump h2 past the empty-DATA-frame advisory - ([1e33b39](https://github.com/vicanso/pingap/commit/1e33b39c3efd2d74de27832bc60c95cec05bc969))
- *(proxy)* Answer 404 when no location matches - ([8d3774e](https://github.com/vicanso/pingap/commit/8d3774e3e217bc0a9145066a01431b43ee05abe6))
- *(web)* Make two unreadable states in the console readable - ([4720b1c](https://github.com/vicanso/pingap/commit/4720b1c9494ac75f8f51fd3fe1a0e0fd1e56cc9e))

### 🚜 Refactor

- *(web)* Polish admin console empty states, search, and routing - ([8355f94](https://github.com/vicanso/pingap/commit/8355f94ec7328d1cf89ba7386bc74545664c4c39))

### ⚙️ Miscellaneous Tasks

- *(release)* Publish rustls-full Linux builds for x86_64 and aarch64 - ([e10519d](https://github.com/vicanso/pingap/commit/e10519d1dd5322fbf99ad2450ced4c49764b93a8))
- Run the test gate on pull requests - ([d90c55f](https://github.com/vicanso/pingap/commit/d90c55f944f033422af480eecce96d8d6328e716))

### Build

- *(deps)* Bump docker/build-push-action from 6 to 7 - ([ccb8b24](https://github.com/vicanso/pingap/commit/ccb8b24bebfbe5225a17216b9b21466ffb970638))
- *(deps)* Bump actions/upload-pages-artifact from 3 to 5 - ([1aa7c34](https://github.com/vicanso/pingap/commit/1aa7c34c9675b1320744443d731c87e8a3b4de78))
- *(deps)* Bump actions/stale from 9 to 11 - ([3e93986](https://github.com/vicanso/pingap/commit/3e939860cbc2cc831d655c38c113d8ff25500c25))
- *(deps)* Bump docker/setup-buildx-action from 3 to 4 - ([f9123d9](https://github.com/vicanso/pingap/commit/f9123d9ab97a8f12ce610020276fc8b993d2b055))
- *(deps)* Bump actions/configure-pages from 5 to 6 - ([cf91c00](https://github.com/vicanso/pingap/commit/cf91c0060bf762f246462b3c3e1edcdda72a9785))
- Move to pingora main, raise MSRV to 1.96, refresh deps and release toolchain - ([19b1276](https://github.com/vicanso/pingap/commit/19b12768343e99d97a869b104d44bb4afb680164))

## [0.13.10](https://github.com/vicanso/pingap/compare/v0.13.9..v0.13.10) - 2026-08-29

### 🐛 Bug Fixes

- Fix cargo fmt - ([b322296](https://github.com/vicanso/pingap/commit/b32229657f7a331443a215f3869109649e6ff8f2))
- Unbreak the deb build and let it fail without sinking the release - ([f1d48c1](https://github.com/vicanso/pingap/commit/f1d48c125b502235bd9375b1445f51b19072726f))

### 🚜 Refactor

- *(web)* Rebuild the admin console around the request path - ([3f24018](https://github.com/vicanso/pingap/commit/3f24018c1e362ff905c9997f65aa6462bc07feb5))
- *(web)* Modernize admin console UX and fix basic auth polling - ([a112a8a](https://github.com/vicanso/pingap/commit/a112a8afa9c60309f39bc6517c6262fd5b89ae19))
- Enhance admin web - ([510c132](https://github.com/vicanso/pingap/commit/510c132466d0030cb4777794fbafbb69d7f9f70b))

### ⚡ Performance

- *(core)* Cut request-path allocations in headers, TLS digest, and limits - ([51a6afc](https://github.com/vicanso/pingap/commit/51a6afca28a3395ab5f85645cd3da2037988efe8))

## [0.13.9](https://github.com/vicanso/pingap/compare/v0.13.8..v0.13.9) - 2026-08-08

### ⛰️  Features

- Publish deb packages for linux releases ([#12](https://github.com/orhun/git-cliff/issues/12)) - ([ab4c377](https://github.com/vicanso/pingap/commit/ab4c3775e40429af08432ad36fe4d3c6a327ab57))
- Live dashboard, unsaved-changes guard and a route error boundary - ([0cc7bc7](https://github.com/vicanso/pingap/commit/0cc7bc74afddd9816d318bb661f98880ce8a22c4))
- Browse config entities as a list, then edit one - ([a030730](https://github.com/vicanso/pingap/commit/a030730673c589b3c60361eb782e99a46199fd08))
- Redesign the web admin UI - ([db1ab2e](https://github.com/vicanso/pingap/commit/db1ab2ead3e81a3b72ac121b973c983c2bd7651d))

### 🐛 Bug Fixes

- Run location plugins on upgrade requests ([#215](https://github.com/orhun/git-cliff/issues/215)) - ([29373ca](https://github.com/vicanso/pingap/commit/29373caaed1252e0162af8ed41b5dae58bc1c1ba))

### ⚙️ Miscellaneous Tasks

- Clear the security audit - ([12812d4](https://github.com/vicanso/pingap/commit/12812d4308f02ecf30510957c0b040d5d015f134))

## [0.13.8](https://github.com/vicanso/pingap/compare/v0.13.7..v0.13.8) - 2026-08-01

### ⛰️  Features

- Purge a whole cache namespace with `PURGE /*` - ([e9f574f](https://github.com/vicanso/pingap/commit/e9f574f8531406372466c37f5dc089946d7fb691))
- Host-indexed routing, disk-budgeted cache, and honest upstream metrics - ([b4c8d88](https://github.com/vicanso/pingap/commit/b4c8d88fb5ffb680541f1f95aea560fe4ec55cc5))

### 🐛 Bug Fixes

- Clear the security audit, removing tldextract for psl - ([7480575](https://github.com/vicanso/pingap/commit/74805756a71eda64252568a9d66cd1157259fea3))
- Stop losing issued ACME certificates, and make every failure say why ([#213](https://github.com/orhun/git-cliff/issues/213)) - ([79a7bda](https://github.com/vicanso/pingap/commit/79a7bdab65ae29260b2d20b2704f7c1ded4fce64))
- Three defects found auditing the request path - ([0561611](https://github.com/vicanso/pingap/commit/056161144ef0fcceb034ca0e5a1973abd48d2d10))

### 🚜 Refactor

- Drop coarsetime, read the clock directly - ([099c0ce](https://github.com/vicanso/pingap/commit/099c0ce0339f04f5f9b1c6fa7dee1670a083ca92))

### 📚 Documentation

- Migrate GitHub Pages site from docsify to VitePress - ([80a13e4](https://github.com/vicanso/pingap/commit/80a13e4f766510e8ed4877197553dc3bc811b1af))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([9ad29ed](https://github.com/vicanso/pingap/commit/9ad29ed4cdb6302481a6266f00e6a2e731f3b6a2))

## [0.13.7](https://github.com/vicanso/pingap/compare/v0.13.4..v0.13.7) - 2026-07-27

### ⛰️  Features

- Start a proxy from the command line without a config file - ([800713b](https://github.com/vicanso/pingap/commit/800713b2ffee8ce86003f7a85360d034528c3ba8))
- Expose max_h2_streams for HTTP/2 upstreams - ([3c2d6a5](https://github.com/vicanso/pingap/commit/3c2d6a5281b13bd67b571cbb0995291bd64ec38c))
- Remote JWKS verification for the jwt plugin - ([c0554b2](https://github.com/vicanso/pingap/commit/c0554b2c82f5d90502a388b494bdc6d7ede55865))
- Header/query/cookie-based location routing - ([9c9cefe](https://github.com/vicanso/pingap/commit/9c9cefe6a92c12c7653b04e20318e2d41de34d74))
- JWT asymmetric verification with static public key - ([00272be](https://github.com/vicanso/pingap/commit/00272be03cfca48002bdcfd362c7d5d9d3dc80bb))
- Add forward_auth plugin (external/forward authentication) - ([2547af5](https://github.com/vicanso/pingap/commit/2547af58cf729e658299bd02d47b7da864e01083))
- Gate X-Forwarded-For with trusted_proxies - ([5d7123f](https://github.com/vicanso/pingap/commit/5d7123f2351da493326df49b28e779bc0300d9b7))

### 🐛 Bug Fixes

- Forward --threads to the process an auto restart spawns - ([6966238](https://github.com/vicanso/pingap/commit/6966238861e637b73015fdf9e321800a4597192e))
- Decide once whether a config path is a file or a directory ([#207](https://github.com/orhun/git-cliff/issues/207)) - ([6c36415](https://github.com/vicanso/pingap/commit/6c3641502a6a9dc19651886952b9a09ea1130267))
- Make a hot restart actually hand over, and stop hiding why it did not - ([8ea8cbd](https://github.com/vicanso/pingap/commit/8ea8cbd5c1bf8116061b58d35d005f1841727573))
- Turn six quietly-ignored plugin misconfigurations into errors - ([2f77bc9](https://github.com/vicanso/pingap/commit/2f77bc94537496479b6b86d5908964b986275266))
- Five smaller defects across redirect, cache, acme, jwt and compression - ([1a3899e](https://github.com/vicanso/pingap/commit/1a3899ed97c47a872f9f78d2e01f65916b4ca8bb))
- Repair the geo feature, an admin panic and jwt signing of error responses - ([e64ecb7](https://github.com/vicanso/pingap/commit/e64ecb78c82ebac3d47c97efed99a6c1a54ea8f5))
- Fix clippy - ([ebc4415](https://github.com/vicanso/pingap/commit/ebc4415bbe3d80bd534e7ead0c0d7db7a49ec356))
- Spawn new process before signaling old on auto restart - ([a5465a4](https://github.com/vicanso/pingap/commit/a5465a48eaae4eb00615f28fc5ae3cec526ad9ed))
- Make pingap-proxy/performance tracing features self-contained - ([8b193de](https://github.com/vicanso/pingap/commit/8b193deeb0aa4dd9465b5ccb57af6a300be18217))
- Serialize ConfigManager writes to prevent lost updates - ([6829191](https://github.com/vicanso/pingap/commit/6829191e217031e89ecd752cdc6cbb096646f9b5))
- Validate ACME http-01 challenge token before storage lookup - ([df397bd](https://github.com/vicanso/pingap/commit/df397bdf2dcc8ce485d4f9f7c2be817223c5799c))
- Reject path separators in config item names (traversal) - ([fa5f1e4](https://github.com/vicanso/pingap/commit/fa5f1e4e6848326eb0a99c6adda327dd7d3cbed4))
- Fix pingap core test - ([ebced87](https://github.com/vicanso/pingap/commit/ebced870f7d603ccea29bd9e8ee11545abd25d3a))
- Fix label of prometheus - ([25f21f4](https://github.com/vicanso/pingap/commit/25f21f42061946e7999fd34f9b903d12741bc4cf))

### 🚜 Refactor

- Constant-time compares, jwt alg allowlist, csrf underflow - ([04a6173](https://github.com/vicanso/pingap/commit/04a6173cda5835bee17f66eb22dad7a602b9a5a4))
- Share HCL/KDL→TOML assembly via config_convert module - ([45d5961](https://github.com/vicanso/pingap/commit/45d5961077a588399e9975349c7bdbe7bfe570d1))
- Replace per-plugin ctor boilerplate with register_plugin! macro - ([3d8a416](https://github.com/vicanso/pingap/commit/3d8a4164ce3f4e8860ac4baeccab2883b0e0a701))
- Clean up deps and remove plugin-path allocations - ([0f0ef2a](https://github.com/vicanso/pingap/commit/0f0ef2ab8d219f14bc8192934463cfd7720dcf74))
- Fmt code - ([f0a211d](https://github.com/vicanso/pingap/commit/f0a211d6febdd98aba532a97e98a2ca64715a421))

### 📚 Documentation

- Point at the real site url and record how to link to it - ([f8e3d2d](https://github.com/vicanso/pingap/commit/f8e3d2d5f86f39d3ce15671b5a34cc379b9a0753))
- Default GitHub Pages home to English docs - ([8644ccb](https://github.com/vicanso/pingap/commit/8644ccb029013c16402845e7d9768ad21ab25258))
- Add bilingual GitHub Pages site (/en, /zh) from repo docs - ([bf58f01](https://github.com/vicanso/pingap/commit/bf58f0123a3b2a9302e159e38d04233e6c94e4d0))
- Document every crate and plugin - ([af533f6](https://github.com/vicanso/pingap/commit/af533f624b5d21615d93bcd2bc817ca799007429))

### ⚡ Performance

- Avoid per-request alloc in circuit-breaker backend check - ([8513c62](https://github.com/vicanso/pingap/commit/8513c62b48d00378ea351c06c79703605ccaa3bc))

### 🎨 Styling

- Apply cargo fmt - ([888dd8a](https://github.com/vicanso/pingap/commit/888dd8a18102ee8e122367e08e6545f4b73396c0))

### ⚙️ Miscellaneous Tasks

- Version 0.13.7 - ([a380dc5](https://github.com/vicanso/pingap/commit/a380dc53112b0568f10c7a3036b9d5cd14520590))
- Update github workflow - ([a28d0fc](https://github.com/vicanso/pingap/commit/a28d0fcae02caac09f3f2606768b32aed34448f2))
- Version 0.13.5 - ([11f95aa](https://github.com/vicanso/pingap/commit/11f95aa9933be3f33cfd3f6253213d7c75ccdfe1))
- Put every crate on one workspace version - ([b25c9dc](https://github.com/vicanso/pingap/commit/b25c9dc6dbddeee23dc6b6ba75d37e06ed20efda))
- Downgrade kdl and sysinfo - ([295217d](https://github.com/vicanso/pingap/commit/295217dc637385e7d6826f212c031ccac1e2f7fa))
- Update dependencies - ([784435c](https://github.com/vicanso/pingap/commit/784435c13ed8c02e29e37d1aa7397b2c47170637))

## [0.13.5](https://github.com/vicanso/pingap/compare/v0.13.4..v0.13.5) - 2026-07-26

### ⛰️  Features

- Start a proxy from the command line without a config file - ([800713b](https://github.com/vicanso/pingap/commit/800713b2ffee8ce86003f7a85360d034528c3ba8))
- Expose max_h2_streams for HTTP/2 upstreams - ([3c2d6a5](https://github.com/vicanso/pingap/commit/3c2d6a5281b13bd67b571cbb0995291bd64ec38c))
- Remote JWKS verification for the jwt plugin - ([c0554b2](https://github.com/vicanso/pingap/commit/c0554b2c82f5d90502a388b494bdc6d7ede55865))
- Header/query/cookie-based location routing - ([9c9cefe](https://github.com/vicanso/pingap/commit/9c9cefe6a92c12c7653b04e20318e2d41de34d74))
- JWT asymmetric verification with static public key - ([00272be](https://github.com/vicanso/pingap/commit/00272be03cfca48002bdcfd362c7d5d9d3dc80bb))
- Add forward_auth plugin (external/forward authentication) - ([2547af5](https://github.com/vicanso/pingap/commit/2547af58cf729e658299bd02d47b7da864e01083))
- Gate X-Forwarded-For with trusted_proxies - ([5d7123f](https://github.com/vicanso/pingap/commit/5d7123f2351da493326df49b28e779bc0300d9b7))

### 🐛 Bug Fixes

- Turn six quietly-ignored plugin misconfigurations into errors - ([2f77bc9](https://github.com/vicanso/pingap/commit/2f77bc94537496479b6b86d5908964b986275266))
- Five smaller defects across redirect, cache, acme, jwt and compression - ([1a3899e](https://github.com/vicanso/pingap/commit/1a3899ed97c47a872f9f78d2e01f65916b4ca8bb))
- Repair the geo feature, an admin panic and jwt signing of error responses - ([e64ecb7](https://github.com/vicanso/pingap/commit/e64ecb78c82ebac3d47c97efed99a6c1a54ea8f5))
- Fix clippy - ([ebc4415](https://github.com/vicanso/pingap/commit/ebc4415bbe3d80bd534e7ead0c0d7db7a49ec356))
- Spawn new process before signaling old on auto restart - ([a5465a4](https://github.com/vicanso/pingap/commit/a5465a48eaae4eb00615f28fc5ae3cec526ad9ed))
- Make pingap-proxy/performance tracing features self-contained - ([8b193de](https://github.com/vicanso/pingap/commit/8b193deeb0aa4dd9465b5ccb57af6a300be18217))
- Serialize ConfigManager writes to prevent lost updates - ([6829191](https://github.com/vicanso/pingap/commit/6829191e217031e89ecd752cdc6cbb096646f9b5))
- Validate ACME http-01 challenge token before storage lookup - ([df397bd](https://github.com/vicanso/pingap/commit/df397bdf2dcc8ce485d4f9f7c2be817223c5799c))
- Reject path separators in config item names (traversal) - ([fa5f1e4](https://github.com/vicanso/pingap/commit/fa5f1e4e6848326eb0a99c6adda327dd7d3cbed4))
- Fix pingap core test - ([ebced87](https://github.com/vicanso/pingap/commit/ebced870f7d603ccea29bd9e8ee11545abd25d3a))
- Fix label of prometheus - ([25f21f4](https://github.com/vicanso/pingap/commit/25f21f42061946e7999fd34f9b903d12741bc4cf))

### 🚜 Refactor

- Constant-time compares, jwt alg allowlist, csrf underflow - ([04a6173](https://github.com/vicanso/pingap/commit/04a6173cda5835bee17f66eb22dad7a602b9a5a4))
- Share HCL/KDL→TOML assembly via config_convert module - ([45d5961](https://github.com/vicanso/pingap/commit/45d5961077a588399e9975349c7bdbe7bfe570d1))
- Replace per-plugin ctor boilerplate with register_plugin! macro - ([3d8a416](https://github.com/vicanso/pingap/commit/3d8a4164ce3f4e8860ac4baeccab2883b0e0a701))
- Clean up deps and remove plugin-path allocations - ([0f0ef2a](https://github.com/vicanso/pingap/commit/0f0ef2ab8d219f14bc8192934463cfd7720dcf74))
- Fmt code - ([f0a211d](https://github.com/vicanso/pingap/commit/f0a211d6febdd98aba532a97e98a2ca64715a421))

### 📚 Documentation

- Point at the real site url and record how to link to it - ([f8e3d2d](https://github.com/vicanso/pingap/commit/f8e3d2d5f86f39d3ce15671b5a34cc379b9a0753))
- Default GitHub Pages home to English docs - ([8644ccb](https://github.com/vicanso/pingap/commit/8644ccb029013c16402845e7d9768ad21ab25258))
- Add bilingual GitHub Pages site (/en, /zh) from repo docs - ([bf58f01](https://github.com/vicanso/pingap/commit/bf58f0123a3b2a9302e159e38d04233e6c94e4d0))
- Document every crate and plugin - ([af533f6](https://github.com/vicanso/pingap/commit/af533f624b5d21615d93bcd2bc817ca799007429))

### ⚡ Performance

- Avoid per-request alloc in circuit-breaker backend check - ([8513c62](https://github.com/vicanso/pingap/commit/8513c62b48d00378ea351c06c79703605ccaa3bc))

### 🎨 Styling

- Apply cargo fmt - ([888dd8a](https://github.com/vicanso/pingap/commit/888dd8a18102ee8e122367e08e6545f4b73396c0))

### ⚙️ Miscellaneous Tasks

- Put every crate on one workspace version - ([b25c9dc](https://github.com/vicanso/pingap/commit/b25c9dc6dbddeee23dc6b6ba75d37e06ed20efda))
- Downgrade kdl and sysinfo - ([295217d](https://github.com/vicanso/pingap/commit/295217dc637385e7d6826f212c031ccac1e2f7fa))
- Update dependencies - ([784435c](https://github.com/vicanso/pingap/commit/784435c13ed8c02e29e37d1aa7397b2c47170637))

## [0.13.3](https://github.com/vicanso/pingap/compare/v0.13.2..v0.13.3) - 2026-05-12

### 🐛 Bug Fixes

- Update hickory-proto version ([#202](https://github.com/orhun/git-cliff/issues/202)) - ([df1598d](https://github.com/vicanso/pingap/commit/df1598d660c749542096f0f53b731b0c4b694019))
- Fix clippy - ([e6cde08](https://github.com/vicanso/pingap/commit/e6cde0803d3ff0d2e51bad5ce0a029af56871980))
- Fix clippy - ([6941496](https://github.com/vicanso/pingap/commit/6941496cd05e981692eb4f8e1a11e0d60e794c94))
- Correct validation of name constraints for URI names ([#190](https://github.com/orhun/git-cliff/issues/190)) - ([21bad9f](https://github.com/vicanso/pingap/commit/21bad9ffb62e17d63c4b5f0eafea2a3d4b547055))

### 🚜 Refactor

- Adjust hickory resolver - ([a678ec6](https://github.com/vicanso/pingap/commit/a678ec6ab3d30b6b3882a4d2aa6129c6af98d996))
- Add install script - ([7be5b87](https://github.com/vicanso/pingap/commit/7be5b8745198c9c86258d030957cbc8169b9aad1))

## [0.13.2](https://github.com/vicanso/pingap/compare/v0.13.1..v0.13.2) - 2026-04-12

### ⛰️  Features

- Add kdl configuration provider and parser ([#184](https://github.com/orhun/git-cliff/issues/184)) - ([79ea335](https://github.com/vicanso/pingap/commit/79ea335eec6ea781bffef0dfdae4621c8d5f5b26))

### 🐛 Bug Fixes

- Update aws-lc ([#180](https://github.com/orhun/git-cliff/issues/180)) - ([47297de](https://github.com/vicanso/pingap/commit/47297de42f5e80bf5a77e49acde2fd4f38c39755))
- Update rustls-webpki ([#181](https://github.com/orhun/git-cliff/issues/181)) - ([ebd09b2](https://github.com/vicanso/pingap/commit/ebd09b2135e7717226b9614880e134e3721ff496))
- Fix cargo machete - ([b0229ec](https://github.com/vicanso/pingap/commit/b0229ec296dabe9986630c35dee0271d10012cc6))
- Correct config loading path and enhance toml validation ([#163](https://github.com/orhun/git-cliff/issues/163)) - ([be0d2bd](https://github.com/vicanso/pingap/commit/be0d2bd4610612ba59a91a1f4230a843d0220bd3))

### ⚙️ Miscellaneous Tasks

- Update pyroscope - ([ab6e97b](https://github.com/vicanso/pingap/commit/ab6e97bf8e8e8a33668bbddb8c0e0b003fcaa983))
- Update image lib - ([1f1d060](https://github.com/vicanso/pingap/commit/1f1d060b24ad7fd93e8b9e3b24110aea974cbae1))

## [0.13.1](https://github.com/vicanso/pingap/compare/v0.13.0..v0.13.1) - 2026-03-19

### ⛰️  Features

- Add support for toml to hcl conversion - ([94dcc7d](https://github.com/vicanso/pingap/commit/94dcc7d8448df74b8e66efd4f24b3d14639518a1))
- Support custom status code in redirect plugin - ([d871b78](https://github.com/vicanso/pingap/commit/d871b7810135d66bb28f4c216ca6cdc0360dc659))
- Support hcl configuration files ([#15](https://github.com/orhun/git-cliff/issues/15)) - ([30b5bdc](https://github.com/vicanso/pingap/commit/30b5bdc50204e782a3b989a4d04589c9c5606909))

### 🐛 Bug Fixes

- Include file path in error message when log file generation fails ([#163](https://github.com/orhun/git-cliff/issues/163)) - ([59ce01e](https://github.com/vicanso/pingap/commit/59ce01e532a9740974d49995abdda721480edd07))
- Cargo machete ignore hcl-rs - ([66a3a8d](https://github.com/vicanso/pingap/commit/66a3a8d23bbc34aad6ee09deb217d1477d2a3634))
- Cargo machete ignore hcl-rs - ([f3a7da9](https://github.com/vicanso/pingap/commit/f3a7da9a4a1b038faaf2dc36e317041982955ee3))
- Fix covert bool from query string - ([6fd2501](https://github.com/vicanso/pingap/commit/6fd2501088f7cb082bebc57866c245271c89b670))
- Fix fmt - ([21216a7](https://github.com/vicanso/pingap/commit/21216a7ba1b591402db1304c41ee1b9b5c928273))

### 🚜 Refactor

- Use Docker events for service discovery instead of polling ([#175](https://github.com/orhun/git-cliff/issues/175)) - ([9800578](https://github.com/vicanso/pingap/commit/98005782d6c5e69442b94818f4141a6d1dd1ca89))
- Restrict upstream configuration to disallow broadcast addresses ([#169](https://github.com/orhun/git-cliff/issues/169)) - ([dce4f80](https://github.com/vicanso/pingap/commit/dce4f80b8e8efa34a4e8574c4512ee968aa2f7cb))
- Improve error message for missing read permissions ([#168](https://github.com/orhun/git-cliff/issues/168)) - ([ca902c0](https://github.com/vicanso/pingap/commit/ca902c058b71f2517430944da47dbaae3e993c4c))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([90920a0](https://github.com/vicanso/pingap/commit/90920a0344ec96b2a0a83f2bebe24e33d7aab7fd))

## [0.13.0](https://github.com/vicanso/pingap/compare/v0.12.8..v0.13.0) - 2026-02-22

### ⛰️  Features

- Add support for HTTP range requests and partial content responses ([#161](https://github.com/orhun/git-cliff/issues/161)) - ([aec8506](https://github.com/vicanso/pingap/commit/aec8506c2fe0f84f9c9dcb460634d39e9e33cfd0))

### 🐛 Bug Fixes

- Fix test for rust 1.85 - ([23818f0](https://github.com/vicanso/pingap/commit/23818f08553c5471929eeb18889e34eaf4810cdc))
- Fix test - ([a7240bf](https://github.com/vicanso/pingap/commit/a7240bf548b5ae387e7c4ef8d1fd613dd8b4395f))
- Fix typos - ([99052d9](https://github.com/vicanso/pingap/commit/99052d943210f38d1f6b85eab42e4bf1b060cccc))

### ⚙️ Miscellaneous Tasks

- Update pingora 0.7.0 - ([b0dc0a5](https://github.com/vicanso/pingap/commit/b0dc0a55401ab8f97db0b65dcefcc2b22e24beff))
- Update pingora - ([0f96c5b](https://github.com/vicanso/pingap/commit/0f96c5b216992e35bf20e8ae48d6cafd91edd375))
- Adjust cargo clippy - ([2558e7a](https://github.com/vicanso/pingap/commit/2558e7ae0a0b7b6ad5ef11063810272c2760d517))
- Cargo fmt - ([9af7cc4](https://github.com/vicanso/pingap/commit/9af7cc4e86971b08bbe8b367faf421d746885f51))
- Update msrv to 1.85 - ([08368dc](https://github.com/vicanso/pingap/commit/08368dc8c2823e195e04942f1af73a41a8de5df0))
- Add `query` feature of reqwest - ([c371ce2](https://github.com/vicanso/pingap/commit/c371ce2d3b7a8f4131a544ff8c1c1f51094449f6))
- Update pingora and reqwest - ([7103835](https://github.com/vicanso/pingap/commit/7103835cc2716b05eb21479961b9806113319d7b))

## [0.12.0](https://github.com/vicanso/pingap/compare/v0.11.2..v0.12.0) - 2025-08-30

### ⛰️  Features

- Support setting coarse clock interval from env - ([a264a12](https://github.com/vicanso/pingap/commit/a264a1213edfb00dfe511e7328d05e41177a52e2))
- Supports acme dns-01 challenge using the huawei cloud dns api - ([2df3a6f](https://github.com/vicanso/pingap/commit/2df3a6f32a2014dd5ec40df303552642f0d638af))
- Supports acme dns-01 challenge using the cloudflare dns api - ([46ded17](https://github.com/vicanso/pingap/commit/46ded171c56b757d9fcfd3b605c1eec53af008a5))
- Supports acme dns-01 challenge using the alibaba cloud dns api - ([7f92f6f](https://github.com/vicanso/pingap/commit/7f92f6f9235d091130c175606bbdcda7d24bba20))

### 🐛 Bug Fixes

- Fix get location plugins handle - ([ea1aa3e](https://github.com/vicanso/pingap/commit/ea1aa3edb104305929e6af75543e1c1bca4a3972))
- Fix format - ([b2ed3fa](https://github.com/vicanso/pingap/commit/b2ed3faaffba286b477afe4d82f8df6ac8488198))
- Fix now time - ([287bbf1](https://github.com/vicanso/pingap/commit/287bbf19822c282c856b42b690dd581e948819b0))
- Fix coarsetime update - ([9e73259](https://github.com/vicanso/pingap/commit/9e7325924b3adde5c95567784ea01ccb40f71f83))
- Fix ttl lru limit - ([941b2c4](https://github.com/vicanso/pingap/commit/941b2c41bcdc977ca8f03d09236dd0815d0a3c6e))
- Fix location path rewrite, #135 - ([07fd221](https://github.com/vicanso/pingap/commit/07fd2218ed4bc017d600843d756509b819f70c84))
- Fix lint - ([6a8004c](https://github.com/vicanso/pingap/commit/6a8004c15c0a4c766e6ae1c3d14ec355ba304c75))
- Fix test error - ([811f255](https://github.com/vicanso/pingap/commit/811f255a7c04943a46ac0f95c94cef5b1329f5a3))

### 🚜 Refactor

- Use include-flat = "=0.3.0" - ([b4e35b9](https://github.com/vicanso/pingap/commit/b4e35b9789a0d9fb88e9e8f4c3fb7bc42a1719c4))
- Adjust timing fields - ([fe802b5](https://github.com/vicanso/pingap/commit/fe802b5aef2eb8e15021f5067ba2588af5618e79))
- Use ahashmap to save modify body handle function - ([04efbc7](https://github.com/vicanso/pingap/commit/04efbc79ac3657608125b0d6c2776f022e630ceb))
- Adjust body response handle plugin - ([d6a19b0](https://github.com/vicanso/pingap/commit/d6a19b07f38e4c4f376ab114d823d4a8bff583e8))
- Add plugin id for upstream body handler - ([50872e8](https://github.com/vicanso/pingap/commit/50872e8bc73fa993606d78b5f16681dd8d4c0d4f))
- Adjust upstream body handler - ([91920a1](https://github.com/vicanso/pingap/commit/91920a1447db4a622b1f23df88c6a989a67f0871))
- Adjust plugin trait - ([24fdbbd](https://github.com/vicanso/pingap/commit/24fdbbdb54dec176c40070e8d54916a7c9983c9e))
- Fill access empty field with "-" - ([2f44c12](https://github.com/vicanso/pingap/commit/2f44c12e4a03bea03ff77a871f6399f093daec34))
- Adjust plugin trait - ([3b337a3](https://github.com/vicanso/pingap/commit/3b337a354c07c6e5198168b146c99f7d0b3cc334))
- Adjust new session for test - ([3b7e6e0](https://github.com/vicanso/pingap/commit/3b7e6e0aa8a7bb75ec8f62328ba28e2347a6ca77))
- Adjust image optimize plugin - ([6db923b](https://github.com/vicanso/pingap/commit/6db923ba921807e29ceab8f526cea3691734ed58))
- Adjust pingap imageoptim - ([54a7aa3](https://github.com/vicanso/pingap/commit/54a7aa329a290d2417bc5ad90066aa1694d7320b))
- Adjust plugin trait of pingap core - ([91e9cc0](https://github.com/vicanso/pingap/commit/91e9cc0e56ea7e978bf59f1ad1745cd9057b9cd4))
- Adjust pingap performance - ([8a1efc8](https://github.com/vicanso/pingap/commit/8a1efc8d59286e9f497e5e3f96991a9137d00b6d))
- Adjust pingap certificate - ([ead8605](https://github.com/vicanso/pingap/commit/ead8605dfe46bbbadfa49185cfab86d99dbeeb81))
- Adjust pingap upstream - ([dc68545](https://github.com/vicanso/pingap/commit/dc68545aede210996c5827655796109b43613eb3))
- Remove unused module - ([18858e5](https://github.com/vicanso/pingap/commit/18858e53fd4d7cc778463b50901982d78115f9ae))
- Adjust pingap location - ([185aa73](https://github.com/vicanso/pingap/commit/185aa732999af57a67803355fb038b5075a444ee))
- Adjust pingap logger - ([542f4a6](https://github.com/vicanso/pingap/commit/542f4a6fe66f761ac5617dabed171199205af5cf))
- Adjust pingap discovery - ([3a389f5](https://github.com/vicanso/pingap/commit/3a389f5e07854be1f8894da787f1cf8780f21f4f))
- Adjust pingap util - ([53278d9](https://github.com/vicanso/pingap/commit/53278d9470605b40d582b9207eaabb6396ffc3a3))
- Use ctor for coarsetime updater - ([8320184](https://github.com/vicanso/pingap/commit/832018407793d2eb0f157c6c75fb7373647018e2))
- Use coarsetime instant for better performance - ([2926d9e](https://github.com/vicanso/pingap/commit/2926d9e3fdff97c14e0205cf7e77f6ea336746e1))
- Use real now ms for accurate calculation - ([ff6eae2](https://github.com/vicanso/pingap/commit/ff6eae24f57dbeddd878358f21c8358a1d47d550))
- Set max value for coarse clock interval - ([b9fe71f](https://github.com/vicanso/pingap/commit/b9fe71f026987cd538dcdf033f471b366401c3c4))
- Adjust background service task - ([39cc5f0](https://github.com/vicanso/pingap/commit/39cc5f01dd43f6d55eae85a2a9a0a665343aa1e3))
- Adjust plugin trait - ([4321ddb](https://github.com/vicanso/pingap/commit/4321ddbad74a5b31fae6572ec567356e1755af11))
- Adjust http header function - ([7ec012c](https://github.com/vicanso/pingap/commit/7ec012c1b3a2c67ef54c2fcc5f4971384d17cb15))
- Adjust the ctx struct into a clean, composed structure - ([2f2ec91](https://github.com/vicanso/pingap/commit/2f2ec91d87a7e41aee5d8e86ca20048a22e2f907))
- Adjust dns 01 challenge handle function - ([491f02e](https://github.com/vicanso/pingap/commit/491f02e2cfa19b236c022c1b372ece0bb54407c0))

### 📚 Documentation

- Update readme of pingap location - ([14d4166](https://github.com/vicanso/pingap/commit/14d41663611fd9126722fd215fdfe9f5a3fd64c2))
- Update readme of pingap util - ([4e5bd18](https://github.com/vicanso/pingap/commit/4e5bd181770e26fa1decc7f66c5ac2b818010f07))
- Update document of core - ([4c567e0](https://github.com/vicanso/pingap/commit/4c567e02b1789356e90107b6d4cae1c51cf255a8))

### 🧪 Testing

- Bench for tinyufo - ([d4f698e](https://github.com/vicanso/pingap/commit/d4f698e8f4bda4bd8c1413e9b8ba1416647b6352))
- Add more test for file cache - ([1e55a02](https://github.com/vicanso/pingap/commit/1e55a024fbbeb34539ac2ca957e4b8521bf040dd))
- Fix test of service time - ([f4aa080](https://github.com/vicanso/pingap/commit/f4aa080c03978a43109e4f1fdbed930f4101a052))
- Adjust ttl lru limit test - ([426e42c](https://github.com/vicanso/pingap/commit/426e42c19d27bfa338a40d9f9cdd2a213d5ed0ed))
- Add more unit test - ([c643b4a](https://github.com/vicanso/pingap/commit/c643b4a5c2ca40c7fd923396edbc590cb5aab738))
- Fix test of request plugin result - ([082ea56](https://github.com/vicanso/pingap/commit/082ea56852915fabb4f6aa6e908c6d08d43e3fdc))

### ⚙️ Miscellaneous Tasks

- Add version tag for docker images - ([50bff53](https://github.com/vicanso/pingap/commit/50bff53f27080ef6300fe33b47ee16cee042aaf4))
- Update pingora - ([aae13de](https://github.com/vicanso/pingap/commit/aae13def9f7397a583f07dd077af09686e1e7341))
- Ignore machete - ([23d0047](https://github.com/vicanso/pingap/commit/23d004715b51ca739b78b49c95065d00ada55ec9))
- Update open telemetry - ([96d6746](https://github.com/vicanso/pingap/commit/96d6746023dcf813d5b3cf74245c6cce57057dd8))
- Adjust github workflow - ([e212c1b](https://github.com/vicanso/pingap/commit/e212c1b6301154596e54076c4cda253c9d413e91))
- Remove unused modules - ([9a8301d](https://github.com/vicanso/pingap/commit/9a8301d91b441f8788e7e522f6654512d5a8cb7a))
- Update github workflow - ([9ad8e05](https://github.com/vicanso/pingap/commit/9ad8e051995e7eb88942e102d0b2e9622236bd6a))
- Update github workflow - ([3bcb6ad](https://github.com/vicanso/pingap/commit/3bcb6ad3ee7e540681511560221f5cfe2a17a48d))

### Eat

- Supports acme dns-01 challenge using the tencent cloud dns api - ([f734cfb](https://github.com/vicanso/pingap/commit/f734cfba14c230aeffad5b1992a071976213bf09))

## [0.12.0](https://github.com/vicanso/pingap/compare/v0.11.2..v0.12.0) - 2025-08-16

### ⛰️  Features

- Support DNS-01 challenge - ([1ea6cf6](https://github.com/vicanso/pingap/commit/1ea6cf6ae8e177b3d3ca74a8c286704994f33869))

### 🐛 Bug Fixes

- Fix lint - ([d53020d](https://github.com/vicanso/pingap/commit/d53020db52ff88003752bc496911dd0d14e4cf29))

### 🚜 Refactor

- Adjust acme log - ([ea75b0a](https://github.com/vicanso/pingap/commit/ea75b0af32e77f8209f13458e8c42dc6dff6707c))
- Adjust enable http challenge - ([a50b22b](https://github.com/vicanso/pingap/commit/a50b22b431bb1e6c1e93b9bcda0f804f65937af6))

### ⚙️ Miscellaneous Tasks

- Version 0.12.0 - ([8e7b1e4](https://github.com/vicanso/pingap/commit/8e7b1e4514ad36741a411eafa6088ac210dc7dc0))
- Use rust 1.88.0 - ([9dc502d](https://github.com/vicanso/pingap/commit/9dc502d292dce1854f504e0b6558d604cbb71601))
- Update github workflow - ([cd42c7d](https://github.com/vicanso/pingap/commit/cd42c7d6928b1a7a5435c168479181579af0cf9b))
- Update pingora to 0.6.0 - ([9368b37](https://github.com/vicanso/pingap/commit/9368b3713acbef3bdc50721b5ba77dccaf32047b))
- Update pingora - ([cd17afd](https://github.com/vicanso/pingap/commit/cd17afd6815b548255ae0786ce535ebe952b2dcd))

## [0.11.2](https://github.com/vicanso/pingap/compare/v0.11.1..v0.11.2) - 2025-08-10

### ⛰️  Features

- Support domain and search for dns discovery - ([19c37cb](https://github.com/vicanso/pingap/commit/19c37cb65bc92cceb914997390f155451c0fc563))
- Add config option for so_reuseport - ([15d746e](https://github.com/vicanso/pingap/commit/15d746e2a4cff3164ef3069c31fd38ba53f52551))
- Support setting read and write timeout for downstream - ([c348739](https://github.com/vicanso/pingap/commit/c3487399636e4b153c6e2536954e113f240ab723))
- Support full body compress mode - ([27f8912](https://github.com/vicanso/pingap/commit/27f8912930b17ec5ab98b74c4c5c26c9ebc9e13d))
- Support setting path levels for dish cache - ([cd742d2](https://github.com/vicanso/pingap/commit/cd742d2f52daa2aa70ea6d7e842f5f9f98b6e919))
- Support setting inactive for dish cache - ([9592c45](https://github.com/vicanso/pingap/commit/9592c45299140455c3fa8739b210d50615dadfab))
- Support setting dns server for dns discovery - ([e164861](https://github.com/vicanso/pingap/commit/e16486174284b8191d5d6dc3dbd8e1de2178a686))
- Support multiple certificates in PEM format, including the certificate chain - ([eee476b](https://github.com/vicanso/pingap/commit/eee476b8d18275a0dd37ae3349e58693ca631197))

### 🐛 Bug Fixes

- Fix acme error - ([52c33d5](https://github.com/vicanso/pingap/commit/52c33d5b853fceb68c99065508584f3bcdd9095c))
- Fix reuse port error of windows - ([bf6e97e](https://github.com/vicanso/pingap/commit/bf6e97ec64aae8017c845dda987a18f2aad8c5c5))
- Fix test error - ([beadb31](https://github.com/vicanso/pingap/commit/beadb3118a94edf1ff3a2a8a70d63688dfee7fd0))
- Fix clippy - ([ce9af97](https://github.com/vicanso/pingap/commit/ce9af97fc67d2fbb4bb9c900621e0575723983cf))
- Fix test for cache key - ([28f5aef](https://github.com/vicanso/pingap/commit/28f5aefe18ee9b4b6c06c0b00e54215abd98448d))
- Fix parse pem certificate - ([f5ded46](https://github.com/vicanso/pingap/commit/f5ded46c6d14983682282ea6cd9d2d63cd9a3304))

### 🚜 Refactor

- Add key field of writing cache log - ([1572e8d](https://github.com/vicanso/pingap/commit/1572e8d1cfdcced629e1b9e9784af9bd50f07c3b))
- Support writing cache log - ([0fcb360](https://github.com/vicanso/pingap/commit/0fcb360ebeaed17afcfbdee61bc6bb46d027aa3b))
- Add modified body time to trace span - ([0965569](https://github.com/vicanso/pingap/commit/09655694b99505848cf2ed30622eb1c947fcf853))
- Remove unused dependency - ([cf2e985](https://github.com/vicanso/pingap/commit/cf2e985da100f217819be38bdf358d1756c7a66c))
- Adjust acme handle function for new instant acme - ([760b829](https://github.com/vicanso/pingap/commit/760b829744f37c4dd6cafaff4867857c033390fa))
- Update dependencies - ([2324ac9](https://github.com/vicanso/pingap/commit/2324ac9fbc378c86f504a25dcf66cb4b619d5dae))
- Skip compress when response header encoding exists - ([17471a1](https://github.com/vicanso/pingap/commit/17471a1b3acf3a141cff2903d71d56a7ef255277))
- Adjust compression level - ([c3e50d7](https://github.com/vicanso/pingap/commit/c3e50d7e6122a27205f3b62d83d2f007e00ecc81))
- Adjust algorithm level handle of compression plugin - ([27fbeed](https://github.com/vicanso/pingap/commit/27fbeeddb63a33d628673ec3aa7334f7c3048ca0))
- Adjust default inactive time for file cache - ([e85c80f](https://github.com/vicanso/pingap/commit/e85c80f46215091317cc81f395f0e5b1b9a2a983))
- Remove empty string and array of config - ([249e9cb](https://github.com/vicanso/pingap/commit/249e9cb46aaa8d55fa3f66852048f882a6dff0b4))
- Set sub menu active background color - ([954046b](https://github.com/vicanso/pingap/commit/954046b00f79869876a8e9e2d4ae6984a1f59230))
- Update pingora and adjust cache storage - ([8ae85d4](https://github.com/vicanso/pingap/commit/8ae85d4cc2199e76d786dc4866b1d9c7ed32d5c8))
- Update hickory resolver and bollard for discovery - ([493bb43](https://github.com/vicanso/pingap/commit/493bb4357e92a49c33c4dda4fde02567839bef42))

### 🧪 Testing

- Remove test of let's encrypt - ([0dd916f](https://github.com/vicanso/pingap/commit/0dd916f87bd511cd70b6019e9c89f7b253773905))

### ⚙️ Miscellaneous Tasks

- Update github action - ([0892573](https://github.com/vicanso/pingap/commit/0892573f823699c99e4db040dc201e6a909dc735))
- Update github action - ([387a294](https://github.com/vicanso/pingap/commit/387a29465fda4ec0cf5698ba180f3a024862a85a))
- Update github action - ([5aab5dd](https://github.com/vicanso/pingap/commit/5aab5dd703deadd47268ada2769e27f78713cf65))
- Remove unused module - ([446cd29](https://github.com/vicanso/pingap/commit/446cd29f6c0104203882a9238b3c1e28ca39a16c))
- Sort dependencies of cargo - ([e8014fe](https://github.com/vicanso/pingap/commit/e8014fefe66fee6d96eabfcd68b3f41160f3c377))
- Update pingora - ([9a84fb9](https://github.com/vicanso/pingap/commit/9a84fb9256f0418a86480a5140eefb12af257b03))

## [0.11.1](https://github.com/vicanso/pingap/compare/v0.11.0..v0.11.1) - 2025-07-05

### ⛰️  Features

- Add upstream healthy status and location stats - ([16c7341](https://github.com/vicanso/pingap/commit/16c73419fe3b7e2fb24fbb7b79dfcb9cbeec77f8))
- Support restart pingap from web admin - ([c805488](https://github.com/vicanso/pingap/commit/c805488ae6c879cf15990a80a159a715c1aabee2))

### 🐛 Bug Fixes

- Fix duration to strimg - ([33ab4a7](https://github.com/vicanso/pingap/commit/33ab4a7650875d2b56173b6305f850cc7f564f70))
- Fix tls cipher suites placeholder of zh, #129 - ([aae734c](https://github.com/vicanso/pingap/commit/aae734c45143b994b43fac864982e2f6c76f1570))
- Fix clippy error - ([5f37185](https://github.com/vicanso/pingap/commit/5f3718525231fb76d1bb43cf248000533ed26a5d))
- Fix clippy - ([764c1e4](https://github.com/vicanso/pingap/commit/764c1e438d3fcad2ee59ada7410ccae9b3a2da41))
- Fix cargo clippy - ([e852e57](https://github.com/vicanso/pingap/commit/e852e57d95947563901bda845d8e06251746bd96))
- Fix clippy error - ([251580d](https://github.com/vicanso/pingap/commit/251580d9168689e435718c9e1ca0b860a1754510))
- Fix generate version change log, #116 - ([6d9431f](https://github.com/vicanso/pingap/commit/6d9431fc2b8c11b3000b343719eac182fa495e6e))

### 🚜 Refactor

- Trim and filter empty domain - ([5cd3860](https://github.com/vicanso/pingap/commit/5cd3860348d23fa47d096046681bed8bdbbb5061))
- Adjust cache meta duration - ([e49e93c](https://github.com/vicanso/pingap/commit/e49e93ccdce45045f4e2c4998d5809bc4030e59b))
- Support tcp user timeout for upstream and server - ([2daee50](https://github.com/vicanso/pingap/commit/2daee50703669cf8bac84472482a3e68c03312d3))
- Update pingora - ([cbc2704](https://github.com/vicanso/pingap/commit/cbc2704efef4a32544a83f46eb3e5d45127d64da))
- Adjust remove config notification content - ([85d9ed8](https://github.com/vicanso/pingap/commit/85d9ed85bcbcc3e5a6ed98fa469aad0c52b346f3))
- Adjust key generate function for image cache - ([e8d86af](https://github.com/vicanso/pingap/commit/e8d86afb57484f0794ce982c2c8e1ce954f0baf4))
- Adjust plugin for handle upstream response - ([4af69d0](https://github.com/vicanso/pingap/commit/4af69d0518a743bb48f8a99e0f4bc4fe7d3b0432))
- Adjust vite build config - ([7ba3c40](https://github.com/vicanso/pingap/commit/7ba3c40f4ef4aed1da2449b382ccf4b793cdfa10))
- Adjust webhook notification - ([dc53b94](https://github.com/vicanso/pingap/commit/dc53b9469df300a24bc4b0ac5c2e1debcc5d967b))

### 📚 Documentation

- Add description for pingap member - ([fe61f48](https://github.com/vicanso/pingap/commit/fe61f48e5993c285509d653f6cee026d6a274f30))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([5ef8966](https://github.com/vicanso/pingap/commit/5ef8966049f8c326871dc673aa620f25b02efda4))
- Update dependencies - ([01761af](https://github.com/vicanso/pingap/commit/01761af2817d758c40cbd578526803a0cd4d7bf1))
- Update rust version of docker build - ([da79886](https://github.com/vicanso/pingap/commit/da798866da32657c00c68fd5ca377bfa58e65c7d))
- Remove unused avif decode - ([0af7796](https://github.com/vicanso/pingap/commit/0af7796cd14d5cd321a516d89958b579fa5e5a8c))
- Setup nasm for image optim plugin - ([cbad23b](https://github.com/vicanso/pingap/commit/cbad23bd5f5b6f00bb26295575d24f8b51de327b))
- Adjust cargo msrv version - ([3a22c24](https://github.com/vicanso/pingap/commit/3a22c243f99faaa625a6daa6838f6aeca38d2f03))
- Update publish script - ([5155801](https://github.com/vicanso/pingap/commit/5155801fa5e09858fef96ca72aa1e46659091142))

## [0.11.0](https://github.com/vicanso/pingap/compare/v0.10.7..0.11.0) - 2025-05-10

### 🐛 Bug Fixes

- Skip plugin for websocket, #114 - ([be345dd](https://github.com/vicanso/pingap/commit/be345dd073bb11c8d326d8b1262fe30d9258f94b))
- Fix test - ([0cbba40](https://github.com/vicanso/pingap/commit/0cbba4005068823d1945c56b22e67f31ac34afa9))
- Fix lint - ([8aa03d0](https://github.com/vicanso/pingap/commit/8aa03d0355f7de1dfa0673e577b0098b69b53113))
- Fix lint - ([eb1faa7](https://github.com/vicanso/pingap/commit/eb1faa757d2f5cc1c50c13c0f3fb78df8e0ff0bd))
- Fix byte size validate function, #112 - ([de9f9b5](https://github.com/vicanso/pingap/commit/de9f9b5e031368049eb26588a7ee427dd8f55e61))

### 🚜 Refactor

- Update pingora to 0.5.0 - ([ed443eb](https://github.com/vicanso/pingap/commit/ed443eb8f3eb6ae24e70fcd5b38eeb2a497fa09a))
- Update pingora version - ([9e93c99](https://github.com/vicanso/pingap/commit/9e93c99182ff36eca5dfbec7700fddd00ae3b246))

### ⚙️ Miscellaneous Tasks

- Set rust min version to 1.82.0 - ([30abd2e](https://github.com/vicanso/pingap/commit/30abd2e0c4706a2f9fdee943866f5aa2668736a4))

## [0.10.7](https://github.com/vicanso/pingap/compare/v0.10.6..0.10.7) - 2025-04-27

### 🚜 Refactor

- Update pingora - ([59f9822](https://github.com/vicanso/pingap/commit/59f9822ddf07f09a1ac13644890dd5ddcfad6f5f))
- Adjust app sidebar - ([01d7b6e](https://github.com/vicanso/pingap/commit/01d7b6ee72ff8a3e1f54b3ff6387f9fee6fdc9a8))
- Update dependencies - ([03c0b1e](https://github.com/vicanso/pingap/commit/03c0b1ec9535e15b3c5228b70de4f04e3f21eb22))
- Update mimalloc version ([#110](https://github.com/orhun/git-cliff/issues/110)) - ([d91592c](https://github.com/vicanso/pingap/commit/d91592c38339bec7bd54352e24547cc56e75ed5b))

### ⚙️ Miscellaneous Tasks

- Update github workflow - ([ddffa4a](https://github.com/vicanso/pingap/commit/ddffa4abd13f42d4b940bd862d00b4a753cc3d81))

## [0.10.6](https://github.com/vicanso/pingap/compare/v0.10.5..0.10.6) - 2025-04-13

### ⛰️  Features

- Add upstream status notification - ([fdd4354](https://github.com/vicanso/pingap/commit/fdd43546b363433d4a3c875188c0e0f61312914b))

### 🐛 Bug Fixes

- Fix crossbeam channel, #109 - ([45d4758](https://github.com/vicanso/pingap/commit/45d4758b83d7d0cf65205d9fe1cc88aa28929795))
- Remove unused module - ([8ba1d2a](https://github.com/vicanso/pingap/commit/8ba1d2a9cdf2852955acef693bc891454424f443))
- Fix lint - ([8c8e772](https://github.com/vicanso/pingap/commit/8c8e772472f0cd34c85d67726d99b4b9c78696d2))
- Temporarily fix sfv - ([c345985](https://github.com/vicanso/pingap/commit/c345985110b8bf53c27217b22ef72d647fe2713a))
- Fix lint of rust 1.86.0 - ([d8bb02b](https://github.com/vicanso/pingap/commit/d8bb02b6f1935744426a9b75fd4f257e5ba6f833))
- Remove syslog of windows target - ([6a58fcc](https://github.com/vicanso/pingap/commit/6a58fcc19e6433778697f4701b33a20faafdacc3))
- Fix async send notification for rust 1.81.0 - ([49e210e](https://github.com/vicanso/pingap/commit/49e210ec4a21506f6c6d356bf5ff0a58c6dad686))

### 🚜 Refactor

- Enhance dns service discovery handling when resolved fail - ([10c449b](https://github.com/vicanso/pingap/commit/10c449b0eea0713fd2f934b618a4c4ca914d09c2))
- Adjust get upstream healthy status - ([51697ba](https://github.com/vicanso/pingap/commit/51697baf69a081a9504202165345c6fe648d7024))
- Add text color for upstream status - ([614fa44](https://github.com/vicanso/pingap/commit/614fa44ff48b7f9ef921fc9ac570ac4ab2b9d872))
- Update tailwind and shadcn - ([20d8b7a](https://github.com/vicanso/pingap/commit/20d8b7a12f002833f6cafd4643cfe790f8778014))
- Adjust webhook notification sender - ([260c861](https://github.com/vicanso/pingap/commit/260c86126e99bfa3bba1b590b9e1b58702ba6dc1))
- Adjust webhook sender - ([7b634e6](https://github.com/vicanso/pingap/commit/7b634e6dd8785a50fd54ef3cdf4ee3dc44fad47f))

### ⚙️ Miscellaneous Tasks

- Update shadcn ui - ([f13f5b2](https://github.com/vicanso/pingap/commit/f13f5b284068018293b474926cd4d87acfe588c7))
- Update modules, #106 - ([6aac395](https://github.com/vicanso/pingap/commit/6aac39590dfff78e88151e555548b33bab1cb405))
- Remove unused components - ([4b02929](https://github.com/vicanso/pingap/commit/4b02929ad2578ce4d97948061662bf1df795fb57))
- Update github workflow - ([6581459](https://github.com/vicanso/pingap/commit/6581459966e6ed7c3b2b8e5ee7eefd1e0ee7b974))
- Add windows build script - ([58117fa](https://github.com/vicanso/pingap/commit/58117fa64d0358cedd7ea93549fe2f2067d5c372))
- Use baco instead of cargo watch - ([8614e25](https://github.com/vicanso/pingap/commit/8614e25b9fb9f83e13032a8e7a38fd8bc40170be))

## [0.10.5](https://github.com/vicanso/pingap/compare/v0.10.4..0.10.5) - 2025-03-23

### ⛰️  Features

- Path rewrite and upstream support variables, #104 - ([3786735](https://github.com/vicanso/pingap/commit/37867358b7569037055ec71ddc582414d2b63937))
- Add syslog writer for logger - ([113d758](https://github.com/vicanso/pingap/commit/113d758889640182e5d1d325f079d10f1fabd8d6))
- Add base64 encode and decode function - ([3d27056](https://github.com/vicanso/pingap/commit/3d27056573e1067c4aecaef614a7c58720651aa7))
- Add cache span attributes of open telemetry - ([103d6c8](https://github.com/vicanso/pingap/commit/103d6c8dcfc57c2d50a84412715d3858224f4bc0))
- Open telemetry support compression - ([36ea569](https://github.com/vicanso/pingap/commit/36ea56943e036c3c7bc5ebc31997193fbd57b0a8))
- Custom buffer days for acme renew or certificate validate - ([dde9738](https://github.com/vicanso/pingap/commit/dde9738bc8083b8e3f50097d72a6e8351f80aec0))

### 🐛 Bug Fixes

- Fix default value of upstream input - ([88fefe1](https://github.com/vicanso/pingap/commit/88fefe17b707a053564941fe337de6f24a081baa))

### 🚜 Refactor

- Adjust location weight calculation method - ([6eb396c](https://github.com/vicanso/pingap/commit/6eb396c5c0eaa1cde950fc7834c7c42af43b0209))
- Adjust sidebar navigation - ([08cc8d0](https://github.com/vicanso/pingap/commit/08cc8d045e35c28609bcaa4e3f188d2985fb986b))
- Adjust sentry core version - ([61182c4](https://github.com/vicanso/pingap/commit/61182c4cd0a437c25141aa7c2f9f6bab06edfde4))
- Remove default parameters for docker run cmd, #103 - ([654ee51](https://github.com/vicanso/pingap/commit/654ee5106c5824658a805ccae05a241ccf0a2fea))
- Update pingora version - ([b3dc30f](https://github.com/vicanso/pingap/commit/b3dc30f742d7ae409cccf1d18a1f134623c9908a))
- Use mimalloc for better performance of musl - ([45cd230](https://github.com/vicanso/pingap/commit/45cd2308a77456cfd8ca1fcb75de93235271ae42))
- Add sub title of location - ([9936ee6](https://github.com/vicanso/pingap/commit/9936ee6606c5da74bba341a265a86bbaefa5f009))
- Adjust access log format - ([85f96f9](https://github.com/vicanso/pingap/commit/85f96f99ae4d87728f180ad931d8bc20fd833895))

### 📚 Documentation

- Add web socket example - ([8a8fd7d](https://github.com/vicanso/pingap/commit/8a8fd7d59ad6197b210c9ef114b942d4c3511e61))

### 🧪 Testing

- Fix test of location weight - ([5c30952](https://github.com/vicanso/pingap/commit/5c309525cda71e73f981f24511a27f4285ee0878))

## [0.10.4](https://github.com/vicanso/pingap/compare/v0.10.3..0.10.4) - 2025-03-02

### ⛰️  Features

- Record the plugin's processing time in context and server timing header - ([17234d7](https://github.com/vicanso/pingap/commit/17234d791d343a6422db9b378ba09ed9eb49c4b8))
- Add weight for rate limit slot - ([177ad52](https://github.com/vicanso/pingap/commit/177ad523ec85663424227171c74ff2a3872f79e1))
- Support http server timing - ([be5fd74](https://github.com/vicanso/pingap/commit/be5fd7426a281b179f7b38e5a970a6f656e10d23))
- Generate server timing from context - ([163482e](https://github.com/vicanso/pingap/commit/163482eec9f6ec25aabdc9e39386b77adcb82ba9))
- Get upstream healthy status - ([3ffe796](https://github.com/vicanso/pingap/commit/3ffe7968ca539ac327f4003121a7b3abe6d72a87))

### 🐛 Bug Fixes

- Fix clippy error - ([4cb7c08](https://github.com/vicanso/pingap/commit/4cb7c0875255abe579b1bb5933071ab97c2f7e94))
- Fix test for server timing - ([b695018](https://github.com/vicanso/pingap/commit/b69501811ff814399659a5adf99c09c0867b93f2))
- Fix spelling check - ([30c0158](https://github.com/vicanso/pingap/commit/30c0158389868095a452cea209344fa187abe57d))
- Fix lint - ([c8ea679](https://github.com/vicanso/pingap/commit/c8ea679452bf8eac246338d7bdf38bfba8da8859))
- Fix sub filter loop modify response body if the data from cache - ([ce7e0ce](https://github.com/vicanso/pingap/commit/ce7e0ce852c0f0855ef0ee9d288779b9285f2b07))
- Fix regex capture - ([8c77612](https://github.com/vicanso/pingap/commit/8c77612f617571493bb600c234ace514c2998c03))
- Fix scheduled clearing of expired data - ([9acebe6](https://github.com/vicanso/pingap/commit/9acebe639d70b972c4af4793713e321277d76c9f))

### 🚜 Refactor

- Sort summary description by name - ([eac4d50](https://github.com/vicanso/pingap/commit/eac4d50580091ab52d60151508e09272da073505))
- Adjust plugin trait to add an "executed" flag that indicates whether the plugin was executed or not - ([1c1264b](https://github.com/vicanso/pingap/commit/1c1264b18635753b7f6a92d7b9eebaf1b2109046))
- Add inline to some plugin functions - ([b75e797](https://github.com/vicanso/pingap/commit/b75e797ebb4686b7b0ea04eac878c3ccce3b9565))
- Lazy formatting for timestamp - ([06386ef](https://github.com/vicanso/pingap/commit/06386ef59346020f4c025b1af00f1fddb9ad9fea))
- Improve the performance of access log format - ([295a20b](https://github.com/vicanso/pingap/commit/295a20bceef4f151cb36cbb7955b00e94f3da6c8))
- Remove not include value of server timing - ([c66c618](https://github.com/vicanso/pingap/commit/c66c618ff6263fc73c890ea8e4d0da5b24eed7c1))
- Support more path options for pid file to facilitate non-root user execution - ([6d70d48](https://github.com/vicanso/pingap/commit/6d70d4804d8a1e6a0168f33fa3425681f6829a8f))
- Adjust open telemetry service name - ([032f544](https://github.com/vicanso/pingap/commit/032f54436435c0d3fbed0566409241d3056c8999))
- Adjust dependencies of open telemetry - ([d807e11](https://github.com/vicanso/pingap/commit/d807e11ae5cc2199c39c0faf46bd5923897717ff))

### 🧪 Testing

- Fix test of generate server timing - ([b205ac0](https://github.com/vicanso/pingap/commit/b205ac0f30c735c729196d374a9cd1c5d01710a9))
- Fix test of server config - ([c1534d3](https://github.com/vicanso/pingap/commit/c1534d3705571555a30e5c5aab51d4f4f9aa17a5))

### ⚙️ Miscellaneous Tasks

- Update rust version to 1.84.0 - ([f8d789c](https://github.com/vicanso/pingap/commit/f8d789c53e2578c4599615a24df48965ac401f83))
- Update machete version for github workflow - ([9cc0495](https://github.com/vicanso/pingap/commit/9cc04957bf00d304b7b7a24fadd890feabe2f262))
- Use edition 2024 - ([609878f](https://github.com/vicanso/pingap/commit/609878ffd1a10aaff9db7bc6c5df44650af958b6))
- Update github workflow - ([862814b](https://github.com/vicanso/pingap/commit/862814b01e639e336833fcd7cc367f9c77a36abc))
- Update msrv - ([5df07a6](https://github.com/vicanso/pingap/commit/5df07a6fb6a23db40d3d11aadf47457514fa422e))
- Update github workflow for rust 1.74.0 - ([c1b9d7a](https://github.com/vicanso/pingap/commit/c1b9d7a96983f2736761517373b64a526c6e176d))
- Support aarch64 full feature release - ([89a358f](https://github.com/vicanso/pingap/commit/89a358f7d135364b759e3daa1afddf28ba580ec0))

## [0.10.1](https://github.com/vicanso/pingap/compare/v0.10.1..0.10.1) - 2025-02-22

### 🚜 Refactor

- Update pingora version - ([4e210a0](https://github.com/vicanso/pingap/commit/4e210a016255181c916d0899402604f547772507))
- Adjust log level selector - ([274f579](https://github.com/vicanso/pingap/commit/274f57905eb448a538ec5ec142d2c2128dbc4c24))
- Set x-trace-id and x-span-id response header - ([3549dd0](https://github.com/vicanso/pingap/commit/3549dd0a3f0ec54b2a8ee79c250e005dc896f27a))
- Update dependencies - ([2c0b8e7](https://github.com/vicanso/pingap/commit/2c0b8e732876e52bb25c5d0e789b87a55ea1132d))
- Use ceil for rate limit plugin - ([bc816c0](https://github.com/vicanso/pingap/commit/bc816c0e2daadaab97014ed70a924cae1fb7d872))
- Downgrade tailwindcss  to v3 - ([a2f70dc](https://github.com/vicanso/pingap/commit/a2f70dcf1e3e9c2b2f3bb9e429a1f6a48d98e98d))
- Adjust log of pingap cache - ([4f5d2cb](https://github.com/vicanso/pingap/commit/4f5d2cba0cc123758e32ec6311334166e77f673f))
- Add log of admin plugin config - ([04526b2](https://github.com/vicanso/pingap/commit/04526b264738b7379c6583bde4f981d6b2dbeb32))
- Adjust background service name - ([22d1bc9](https://github.com/vicanso/pingap/commit/22d1bc9cfe68b54ac599e4f04707fbad470c355f))

### 📚 Documentation

- Update readme - ([c362e54](https://github.com/vicanso/pingap/commit/c362e54ba0e1e73d8b0cf4ca76b1a152b400f425))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([cd129f3](https://github.com/vicanso/pingap/commit/cd129f3ee89c0667ff1946254ab5315aaf0bfa92))

## [0.10.0](https://github.com/vicanso/pingap/compare/v0.9.11..0.10.0) - 2025-02-15

### ⛰️  Features

- Support set `listener_tasks_per_fd` for server configuration - ([5a24214](https://github.com/vicanso/pingap/commit/5a24214849feb6b08c0dd320eda7a4159ae562ce))
- Support plugin factory - ([2c3c2ff](https://github.com/vicanso/pingap/commit/2c3c2ffae27ffbd672fc61b4f00f5a73cab759b4))
- Support upstream connection time for state - ([e88981d](https://github.com/vicanso/pingap/commit/e88981d1fc6405822f8a1154e2cbb42631202257))

### 🐛 Bug Fixes

- Fix hickory dns failure to verify self-signed, #91 - ([99fb7bc](https://github.com/vicanso/pingap/commit/99fb7bc21d5ae52bf1442ad034dbaad874b6f52a))
- Fix test - ([f5331b1](https://github.com/vicanso/pingap/commit/f5331b16bfc76528d8f125eb7fa6f20c256bca3f))
- Fix format - ([56d0149](https://github.com/vicanso/pingap/commit/56d0149356821aa473c0eea5309bf5df5454350f))
- Fix openssl `ssl::select_next_proto use after free`, #89 - ([938b731](https://github.com/vicanso/pingap/commit/938b731d73b12d692653b4e901ddbdc44feffa13))

### 🚜 Refactor

- Adjust cache, config, discovery, health, location and upsgream - ([c5cce43](https://github.com/vicanso/pingap/commit/c5cce43ce8288b8f22fce550b9de0b3777366a0c))
- Adjust pingap cache - ([a5fa802](https://github.com/vicanso/pingap/commit/a5fa802a35e2de6ff3535d10fc25c7499c63dd78))
- Adjust pingap certificate - ([09770e3](https://github.com/vicanso/pingap/commit/09770e3d1e59f3cc3e9009416a83eb1cf75e3398))
- Merge limit and service module into core module - ([60a7f34](https://github.com/vicanso/pingap/commit/60a7f3428bc5c736fb21b77c945996fa5c7ef6db))
- Optimize cache backend initialization - ([9b9a80f](https://github.com/vicanso/pingap/commit/9b9a80f89dd8de7b56228630dc67817cba2f8553))
- Merge the state module with the core module - ([459ba7d](https://github.com/vicanso/pingap/commit/459ba7db0e6a8ea6bbe297fa9ab9c67f25e09c39))
- Adjust pingap core - ([ce2c262](https://github.com/vicanso/pingap/commit/ce2c262baf216b4a761bd035357f0cdfc5b42488))
- Remove state's dependency on util - ([a788778](https://github.com/vicanso/pingap/commit/a788778d7e6004c612916f56659d887683464f41))
- Adjust location and upstream of ctx - ([fdaf7b0](https://github.com/vicanso/pingap/commit/fdaf7b00aeaa46e5bf37c37b1b99302e8be78bae))
- Adjust pingap workspace member - ([ebe820f](https://github.com/vicanso/pingap/commit/ebe820f70d5d2b498cce1863c9a7f9f9d8362731))
- Adjust pingap workspace member - ([beecaeb](https://github.com/vicanso/pingap/commit/beecaeb075654b323e0c7832a7bf3857332f420c))
- Adjust pingap workspace member - ([d372af3](https://github.com/vicanso/pingap/commit/d372af35e08aee01a990b48cd33341e26d66d0dc))
- Adjust pingap workspace member - ([d31293b](https://github.com/vicanso/pingap/commit/d31293bf6bb93661e61a5c7d573e8411203f3135))
- Adjust pingap workspace member - ([b7e1a56](https://github.com/vicanso/pingap/commit/b7e1a5611ad39e85a94d9a1f15d0f6b31a5ec791))
- Adjust pingap workspace member - ([cf41202](https://github.com/vicanso/pingap/commit/cf412029729e5eef35b34cd88a6b10661ffaef20))
- Adjust pingap workspace member - ([72f24ca](https://github.com/vicanso/pingap/commit/72f24ca47642ead8cbb6ba3a3d1867cb91c54e7c))
- Adjust pingap workspace member - ([6f6fb10](https://github.com/vicanso/pingap/commit/6f6fb10ccb93ee30751652d94cfcbafc0c9510a4))
- Adjust pingap workspace member - ([254432a](https://github.com/vicanso/pingap/commit/254432a55566a4a7cfa670e6834325499bc4523f))
- Adjust pingap workspace member - ([95ba42d](https://github.com/vicanso/pingap/commit/95ba42d6ccb20c331ebe872390eff106bf1400c4))
- Adjust pingap workspace member - ([670c9e1](https://github.com/vicanso/pingap/commit/670c9e1622a85ffa15738fa66945251fda2d3917))
- Adjust pingap-util as pingap workspace member - ([2553717](https://github.com/vicanso/pingap/commit/2553717f8fd1239501cf733bf7c46c7d202a9cb2))
- Adjust proxy handle function - ([226d322](https://github.com/vicanso/pingap/commit/226d32258d1b18e669242fdb9b8986e77339330c))
- Add delay for observer watch fail - ([be88a90](https://github.com/vicanso/pingap/commit/be88a906b245d212534575bc245320d28833d367))

### 📚 Documentation

- Update modules - ([f7894ea](https://github.com/vicanso/pingap/commit/f7894eae68fe71972ba9d0e374f00ad354c74125))
- Update module dependency graph - ([d6631e7](https://github.com/vicanso/pingap/commit/d6631e72a2bbe6fbeb585ecc45e7983898c97973))

### 🧪 Testing

- Remove unuse dependencies - ([7ec491a](https://github.com/vicanso/pingap/commit/7ec491aa3df56281ed3b6d10259e23218fe46a06))
- Add more test for core - ([7eba578](https://github.com/vicanso/pingap/commit/7eba5788b272dfa2b0fb9fcab7996bbd0af5a3dd))
- Add test for pingap util - ([71c316f](https://github.com/vicanso/pingap/commit/71c316fcc1dbea18dfe041af0f748f019fdeb0a4))

### ⚙️ Miscellaneous Tasks

- Set build args to github output - ([eb628f2](https://github.com/vicanso/pingap/commit/eb628f2509105586ece5eb910a2d1ae36319cc47))
- Adjust docker image tag - ([caa392d](https://github.com/vicanso/pingap/commit/caa392d2022259eb6f3429e686429bd0d5bf9a68))
- Update github action for building images with different feature - ([e9826a6](https://github.com/vicanso/pingap/commit/e9826a6867327c404c475370f61ff8a7976d7b82))
- Update dependencies - ([13a8665](https://github.com/vicanso/pingap/commit/13a8665e35b1627a0e793826999fc1e4ef2206ea))
- Support build args for dockerfile - ([22add72](https://github.com/vicanso/pingap/commit/22add72d9df1bf160ac4373d0c341a1955263653))
- Support build args for dockerfile - ([6b8b363](https://github.com/vicanso/pingap/commit/6b8b36357581c1f5303a7535d3e5b444f4ebbfb9))
- Update cargo - ([0611610](https://github.com/vicanso/pingap/commit/0611610bf37ce6e6c2e33b4b262be833b8ebfcd2))

## [0.9.10](https://github.com/vicanso/pingap/compare/v0.9.9..0.9.10) - 2025-02-02

### 🐛 Bug Fixes

- Fix loop renew certificate, #88 - ([3cbdd38](https://github.com/vicanso/pingap/commit/3cbdd38191e8f9a7c2f57c3426d1e991dbba8d54))
- Fix disable acme for pingap - ([bc5b506](https://github.com/vicanso/pingap/commit/bc5b5065ab1f1d8b04af0ce0ab4267b19730d010))
- Fix validate empty tls cert and key - ([95ef582](https://github.com/vicanso/pingap/commit/95ef58295885ab89f9acc0ecafe2a8e2abe2481d))
- Fix no native root CA certificates, #85 - ([fbef48b](https://github.com/vicanso/pingap/commit/fbef48bc5f25ce2dbc0e6b78ae9b0d84237b9e93))
- Fix empty certificate parse error - ([5ed9eca](https://github.com/vicanso/pingap/commit/5ed9eca44014e8cb7b2ebc6264342adc52797679))

### 🚜 Refactor

- Add log category for logger - ([64f5cec](https://github.com/vicanso/pingap/commit/64f5cec60a2af411724ff1436bd354fc112506ff))
- Use default port for transparent http/https, #84 - ([2543cd8](https://github.com/vicanso/pingap/commit/2543cd80258980071c4c6b452f9667f9e533f755))
- Add log category for proxy - ([ef53962](https://github.com/vicanso/pingap/commit/ef539622e75235c9ea2578d6358fc9b629026de7))
- Adjust static discovery and add test - ([140f8d2](https://github.com/vicanso/pingap/commit/140f8d20362d368e22056e9f46ccd09d56b26afd))
- Log level allow null - ([28f2cb4](https://github.com/vicanso/pingap/commit/28f2cb4598aceafcefecc920e146027d48d522fd))
- Support setting null as empty string - ([7d82026](https://github.com/vicanso/pingap/commit/7d82026e1b1a1ede2d780eeb336bc670ec63a503))
- Adjust let's encrypt service - ([759a4dc](https://github.com/vicanso/pingap/commit/759a4dc3d33325ba60bae6922c5815965643015d))
- Add log category for cache - ([51048d3](https://github.com/vicanso/pingap/commit/51048d32c11461633b40d30f56baf742c54dd13c))
- Adjust tiny ufo estimated size - ([0c153e9](https://github.com/vicanso/pingap/commit/0c153e9b0ed255146489a9ca3e3eea689bf3b070))
- Adjust let's encrypt - ([f59b204](https://github.com/vicanso/pingap/commit/f59b204a467e8521d71f24d3b89c3744c44c46ee))
- Use ubuntu 20.04 for docker - ([f785e08](https://github.com/vicanso/pingap/commit/f785e08534b119e362b88762c1cd2bc3dab8c51f))
- Some plugin use fixed step - ([64cb9e6](https://github.com/vicanso/pingap/commit/64cb9e6271b17a9aaea68d689590108da30a9855))
- Adjust certificate - ([2092c0c](https://github.com/vicanso/pingap/commit/2092c0c1635e6a21ded685f9d92c84df6967f1d5))

### 📚 Documentation

- Add comments - ([ee93523](https://github.com/vicanso/pingap/commit/ee935231e483070f1a76407529d8583c0793e515))
- Update copyright - ([df8bb50](https://github.com/vicanso/pingap/commit/df8bb50c1f1eaca8b8c2e8c07f8735a6003c2452))
- Update documents - ([82d2b07](https://github.com/vicanso/pingap/commit/82d2b077e96dab0e3fbffdffa745d98c9f48529f))
- Update toml config - ([aab3965](https://github.com/vicanso/pingap/commit/aab3965de6ad134aec788282a2fe28e92fbee2d9))
- Update documents - ([45733d4](https://github.com/vicanso/pingap/commit/45733d4480c4e5292dd8195c6a347bf4f41b2c56))
- Update proxy upstream config, #83 - ([df4f6d1](https://github.com/vicanso/pingap/commit/df4f6d1ed519df7163519a14793b5bc94535819e))

### 🎨 Styling

- Add comments for webhook - ([ac22399](https://github.com/vicanso/pingap/commit/ac22399a84eadf36a7e1406675eb52e22ec18b6a))
- Add comments for state - ([b024e55](https://github.com/vicanso/pingap/commit/b024e556acfc9b18d277078661acf04ac15f3c79))
- Add comments for service - ([53ee207](https://github.com/vicanso/pingap/commit/53ee207e98fd8fb9b60ca53b5a88393680b940fe))
- Add comments for otel - ([4e2e41a](https://github.com/vicanso/pingap/commit/4e2e41af1a3f6555fa47fa8278c37fb9ee21bb6e))

### 🧪 Testing

- Add test for crypto - ([1d614c4](https://github.com/vicanso/pingap/commit/1d614c42478350d4d329062b9a042bfdaabdc42c))
- Add test for certificate - ([8aa1d2b](https://github.com/vicanso/pingap/commit/8aa1d2b8241ffb60c487e64c3782b68e4af15edd))

### ⚙️ Miscellaneous Tasks

- Use sentry core instead of sentry - ([fa1620a](https://github.com/vicanso/pingap/commit/fa1620ad922060e6c13f03292405a83108dd3622))
- Use rust 1.83.0 - ([1e10601](https://github.com/vicanso/pingap/commit/1e10601b5ea76fa5b92d274c22ceb0405435b195))
- Update dependencies - ([e64bb71](https://github.com/vicanso/pingap/commit/e64bb71f2c32009d500df986ceed2b4fe87f8b02))
- Remove modify swap step - ([736123a](https://github.com/vicanso/pingap/commit/736123acfdd88c9ddafcd3a7d65eb854c36e5458))
- Use self hosted runner - ([8a0e602](https://github.com/vicanso/pingap/commit/8a0e60200b81c12af3298d839ad12a6a9a49de56))
- Use ubuntu latest for docker build - ([e606384](https://github.com/vicanso/pingap/commit/e60638447567c4d4cbc73b2e2cea625690e55a54))
- Set docker only build for arm64 - ([d6ed2b5](https://github.com/vicanso/pingap/commit/d6ed2b55ec8280e170f9346c6f007c16bf91c570))
- Update pingora - ([cc10122](https://github.com/vicanso/pingap/commit/cc10122f6f79c55dec3a57c05c8ecf75d53a263f))
- Remove arm64 platform - ([76596eb](https://github.com/vicanso/pingap/commit/76596ebe0bcabf54155f609abe2166725ac75d65))
- Adjust swap size - ([c6da4dd](https://github.com/vicanso/pingap/commit/c6da4dda46081a3ca50e9695f8c6d8499eaa8ca6))
- Add free disk spacke step - ([f15f3ce](https://github.com/vicanso/pingap/commit/f15f3ce05f6f803b17c6b376d4467b2422bcfb94))
- Adjust swap size - ([11e6483](https://github.com/vicanso/pingap/commit/11e6483305d7932bc08bbe26d24fb10aa6862e89))
- Update github workflow - ([14a0dea](https://github.com/vicanso/pingap/commit/14a0deab0371d3b6a95f291000da1c003d27bdbd))
- Update github action - ([309ca20](https://github.com/vicanso/pingap/commit/309ca20a2f83a5f2dcf859b2abfe813333393e4f))
- Update github action for large runner - ([2457c68](https://github.com/vicanso/pingap/commit/2457c68459de47e266079dcdec0d72b21b2508da))

### Fest

- Add test for proxy - ([d02b4d9](https://github.com/vicanso/pingap/commit/d02b4d9f85fade655f776b978274abf10a47ae65))

## [0.9.9](https://github.com/vicanso/pingap/compare/v0.9.8..0.9.9) - 2025-01-18

### ⛰️  Features

- Support getting certificate from file - ([aed1d48](https://github.com/vicanso/pingap/commit/aed1d48be8170373f2f94ee3617478e1d7d7f63a))
- Support set response header if not exists - ([2ca1366](https://github.com/vicanso/pingap/commit/2ca1366f8ef416823e04aae9385f1be4319da905))
- Add sub filter plugin, #80 - ([5ae2a9c](https://github.com/vicanso/pingap/commit/5ae2a9c54bd2e3e38fe2ae7c4eb689c30ce6321d))
- Support cache file max weight for tinyufo of file cache - ([2da5b77](https://github.com/vicanso/pingap/commit/2da5b7766601e7e3d637a05391ccfe264af51b32))

### 🐛 Bug Fixes

- Fix test - ([b137266](https://github.com/vicanso/pingap/commit/b1372664578823bb9ec2548a6d657a39f21acaf6))
- Fix empty access log format - ([ed77687](https://github.com/vicanso/pingap/commit/ed77687f891507ac2d66dbadc0b236d906fd6fe6))

### 🚜 Refactor

- Log chain certificate parse error - ([500dd41](https://github.com/vicanso/pingap/commit/500dd410d7b3b807370500df87e3b3f50404aed6))
- Update shadcn ui - ([30ffc48](https://github.com/vicanso/pingap/commit/30ffc485936735752d020ec44f39f582d4a291ff))
- Set default step for each plugin - ([47326bf](https://github.com/vicanso/pingap/commit/47326bfd0fafd04d4834554ed2018fcc61c0a82c))
- Adjust http header - ([c54db8f](https://github.com/vicanso/pingap/commit/c54db8f1ffded64feb86ccfd690133dda9c3e8ed))
- Adjust performance metrics - ([5be5359](https://github.com/vicanso/pingap/commit/5be5359914aaa61f624867ac4f791112ecb26b7e))
- Remove dhat feature - ([8bcfe7d](https://github.com/vicanso/pingap/commit/8bcfe7d572c2d70c289726e9ea63e89cc6f8e7ff))
- Adjust performance metrics - ([6c8a7e5](https://github.com/vicanso/pingap/commit/6c8a7e5ba8a52a1a4d568dbb712b3607094c6df0))
- Adjust cache storage trait - ([b08a5c0](https://github.com/vicanso/pingap/commit/b08a5c00c713d800d1aadaa9f012f1fe5824a6f3))
- Adjust performance metrics - ([bbd1faf](https://github.com/vicanso/pingap/commit/bbd1faf645e0ced36486e147f06f08b14efff2b4))
- Adjust trait of http cache storage - ([83632a5](https://github.com/vicanso/pingap/commit/83632a5ab6e410309b297e936e1af088f3d77255))
- Adjust tinyufo cache for file cache - ([5b98684](https://github.com/vicanso/pingap/commit/5b98684aa41ed978afda363f2aca976893e3821e))

### 📚 Documentation

- Update comments - ([f31b591](https://github.com/vicanso/pingap/commit/f31b59113d0d438351bf4edb84240cf2cd41e1f3))
- Update documents - ([759159e](https://github.com/vicanso/pingap/commit/759159e2b351af2d0ab8e1427fe488cabaf36a79))
- Add comments - ([b6e4219](https://github.com/vicanso/pingap/commit/b6e42191160480fcf3fb73880fd61c5a70e94b7c))
- Add comments - ([616e75f](https://github.com/vicanso/pingap/commit/616e75f4c2605ecb6419654c597a79e8acb221df))
- Add comments to service - ([2c2440d](https://github.com/vicanso/pingap/commit/2c2440de49138a48cbd4961139e3708bbf3aa5d6))
- Add comments to plugin - ([15bb6be](https://github.com/vicanso/pingap/commit/15bb6be5429093dcf56f26ae14e146703ff86229))
- Update proxy upstream example - ([ab07a99](https://github.com/vicanso/pingap/commit/ab07a99bacf378cc7ff40003cf2f8f78ff351b43))

## [0.9.8](https://github.com/vicanso/pingap/compare/v0.9.7..0.9.8) - 2025-01-04

### ⛰️  Features

- Support set default reverse proxy header, #77 - ([2a4d198](https://github.com/vicanso/pingap/commit/2a4d1984c08aedd764845d27083505cd15f4795d))

### 🐛 Bug Fixes

- Fix test - ([0489480](https://github.com/vicanso/pingap/commit/0489480027f8c4dfc04080cb757a3c58299fb508))
- Fix format - ([cf9ddb8](https://github.com/vicanso/pingap/commit/cf9ddb8cd5f06c3260f2de89c25beb7a431341c8))

### 🚜 Refactor

- Update dependencies - ([248c32f](https://github.com/vicanso/pingap/commit/248c32fda5ae8fa0073a0e6ccaaf3d5789178930))
- Update upstream health check - ([7fa172c](https://github.com/vicanso/pingap/commit/7fa172c28ab97365c0a193a4be20aa5760410daa))
- Adjust upstream discovery - ([fc3414e](https://github.com/vicanso/pingap/commit/fc3414ea2286e5c1ebfcdc84029230faa5cdf9d0))
- Add comments - ([b6454cb](https://github.com/vicanso/pingap/commit/b6454cb15d42717278d83ac99d0af4445046e582))
- Adjust label name of config - ([c724a87](https://github.com/vicanso/pingap/commit/c724a8705c107908705f4ec176bcc920cf4c6448))
- Add more comments - ([7fe8e20](https://github.com/vicanso/pingap/commit/7fe8e20049a0c588e3be9957caef66e909e5ad9a))
- Adjust the code of service - ([788e86e](https://github.com/vicanso/pingap/commit/788e86e7fcd0373eb87b552a66a90e8baaeaa813))
- Adjust acme handle function - ([fba764b](https://github.com/vicanso/pingap/commit/fba764ba540fccabc789b1e7985cb613f1b1e431))
- Use crc32 hash for secret description - ([a5ef9c1](https://github.com/vicanso/pingap/commit/a5ef9c1c0e0293d98b430887eaa56241d7f990f2))

### 📚 Documentation

- Update documents - ([776c293](https://github.com/vicanso/pingap/commit/776c29321d52288b7dfe3caf32000d155e3e66d1))
- Update reademd - ([492405b](https://github.com/vicanso/pingap/commit/492405b9ce5adeb5302a766f83db9da56746e782))

## [0.9.7](https://github.com/vicanso/pingap/compare/v0.9.5..0.9.7) - 2024-12-28

### ⛰️  Features

- Add performance metrics log task - ([7dbe176](https://github.com/vicanso/pingap/commit/7dbe176d4a1c0e1580ddd093cdc8c6f768e0856e))

### 🐛 Bug Fixes

- Fix format - ([8493bfc](https://github.com/vicanso/pingap/commit/8493bfc3881b001083d347319efd670d6bd7b4a6))
- Fix validate certificate of let's encrypt - ([bfc88af](https://github.com/vicanso/pingap/commit/bfc88af74151254409f61e1b5aefa62fc55002e6))
- Fix test of prometheus - ([4e39e26](https://github.com/vicanso/pingap/commit/4e39e2602c3cc7b56866ad8c4d6b175bfa36fd97))

### 🚜 Refactor

- Adjust ua restriction plugin exec step - ([34c47f9](https://github.com/vicanso/pingap/commit/34c47f9540bf69f911ce01f472c2895efe229f1a))
- Adjust ip and referer restriction plugin exec step - ([733de57](https://github.com/vicanso/pingap/commit/733de57aeacb56ad0931a5660b26147f287017fa))
- Adjust comibined auth plugin exec step - ([9db1bd3](https://github.com/vicanso/pingap/commit/9db1bd3865df6dedbde6995399c5ede88aa59d5d))
- Adjust jwt auth plugin exec step - ([c53a1eb](https://github.com/vicanso/pingap/commit/c53a1eb4330664b938e8be5af08f7f38ed3f76d1))
- Adjust grpc health check - ([1757aa7](https://github.com/vicanso/pingap/commit/1757aa7e337c7b4e0a725bb73c04d3678a82789e))
- Adjust redirect for admin prefix path - ([761f043](https://github.com/vicanso/pingap/commit/761f043c63f121604d9e9786c397020788c8c2f8))
- Adjust background service log - ([b908d07](https://github.com/vicanso/pingap/commit/b908d07a6f2324a78216881a4c28902a61634f85))
- Adjust log of background service task - ([918afd3](https://github.com/vicanso/pingap/commit/918afd3f3d242fe337d01aac73fa0a0fe106f787))
- Adjust async webhook notification - ([252c7c3](https://github.com/vicanso/pingap/commit/252c7c3173558ff0c518a5f2c45aea72ca3483b7))
- Adjust prometheus metrics - ([fefb2f3](https://github.com/vicanso/pingap/commit/fefb2f3d446d1a7d71d921b3bd12e5f93c9dc125))
- Merge prometheus push service to simple background service - ([3c27551](https://github.com/vicanso/pingap/commit/3c275510d67d9207ed4c554be8bb1e19cfc4306f))
- Merge let's encrypt and log compress to simple background service - ([6100d36](https://github.com/vicanso/pingap/commit/6100d364252e8466ee98954d7d38fef0050dae0d))

### 📚 Documentation

- Update documents - ([34028d0](https://github.com/vicanso/pingap/commit/34028d065b5952b61ff5c849b6ad30f760b17d2b))

### ⚙️ Miscellaneous Tasks

- Version 0.9.6 - ([3027d71](https://github.com/vicanso/pingap/commit/3027d71e7f5af6ddb5358645c79860d2e355fd69))
- Add ignore for mechete - ([de22dd0](https://github.com/vicanso/pingap/commit/de22dd06b610ca182d125b3f1686747f708c65f2))
- Add cargo machete - ([6a42f39](https://github.com/vicanso/pingap/commit/6a42f39f42ca4f8b5e37d9391584998e8f8215e8))

## [0.9.6](https://github.com/vicanso/pingap/compare/v0.9.5..0.9.6) - 2024-12-28

### ⛰️  Features

- Add performance metrics log task - ([7dbe176](https://github.com/vicanso/pingap/commit/7dbe176d4a1c0e1580ddd093cdc8c6f768e0856e))

### 🐛 Bug Fixes

- Fix test of prometheus - ([4e39e26](https://github.com/vicanso/pingap/commit/4e39e2602c3cc7b56866ad8c4d6b175bfa36fd97))

### 🚜 Refactor

- Adjust ua restriction plugin exec step - ([34c47f9](https://github.com/vicanso/pingap/commit/34c47f9540bf69f911ce01f472c2895efe229f1a))
- Adjust ip and referer restriction plugin exec step - ([733de57](https://github.com/vicanso/pingap/commit/733de57aeacb56ad0931a5660b26147f287017fa))
- Adjust comibined auth plugin exec step - ([9db1bd3](https://github.com/vicanso/pingap/commit/9db1bd3865df6dedbde6995399c5ede88aa59d5d))
- Adjust jwt auth plugin exec step - ([c53a1eb](https://github.com/vicanso/pingap/commit/c53a1eb4330664b938e8be5af08f7f38ed3f76d1))
- Adjust grpc health check - ([1757aa7](https://github.com/vicanso/pingap/commit/1757aa7e337c7b4e0a725bb73c04d3678a82789e))
- Adjust redirect for admin prefix path - ([761f043](https://github.com/vicanso/pingap/commit/761f043c63f121604d9e9786c397020788c8c2f8))
- Adjust background service log - ([b908d07](https://github.com/vicanso/pingap/commit/b908d07a6f2324a78216881a4c28902a61634f85))
- Adjust log of background service task - ([918afd3](https://github.com/vicanso/pingap/commit/918afd3f3d242fe337d01aac73fa0a0fe106f787))
- Adjust async webhook notification - ([252c7c3](https://github.com/vicanso/pingap/commit/252c7c3173558ff0c518a5f2c45aea72ca3483b7))
- Adjust prometheus metrics - ([fefb2f3](https://github.com/vicanso/pingap/commit/fefb2f3d446d1a7d71d921b3bd12e5f93c9dc125))
- Merge prometheus push service to simple background service - ([3c27551](https://github.com/vicanso/pingap/commit/3c275510d67d9207ed4c554be8bb1e19cfc4306f))
- Merge let's encrypt and log compress to simple background service - ([6100d36](https://github.com/vicanso/pingap/commit/6100d364252e8466ee98954d7d38fef0050dae0d))

### 📚 Documentation

- Update documents - ([34028d0](https://github.com/vicanso/pingap/commit/34028d065b5952b61ff5c849b6ad30f760b17d2b))

### ⚙️ Miscellaneous Tasks

- Add ignore for mechete - ([de22dd0](https://github.com/vicanso/pingap/commit/de22dd06b610ca182d125b3f1686747f708c65f2))
- Add cargo machete - ([6a42f39](https://github.com/vicanso/pingap/commit/6a42f39f42ca4f8b5e37d9391584998e8f8215e8))

## [0.9.5](https://github.com/vicanso/pingap/compare/v0.9.4..0.9.5) - 2024-12-21

### ⛰️  Features

- Admin panel support set upstream keepalive pool size - ([d6ed036](https://github.com/vicanso/pingap/commit/d6ed036c36c91a79fb5f01a32835618ca7ab1593))
- Support generate certificate from self sigined ca, #66 - ([f1b2f6f](https://github.com/vicanso/pingap/commit/f1b2f6f8c5cd0626ab41ee6958f1bafcbcf1068e))
- Support print default config template - ([c3ea1d6](https://github.com/vicanso/pingap/commit/c3ea1d6df91e5cf773c5f013c0ba5b9489f1e5c2))

### 🐛 Bug Fixes

- Fix spelling - ([a97f232](https://github.com/vicanso/pingap/commit/a97f232bd4ae8909b54537432db4f54d35ac2740))

### 🚜 Refactor

- Use namespace of cache plugin as sub directory - ([e2ef50c](https://github.com/vicanso/pingap/commit/e2ef50c7cd87f38e816b919c6b7a42393db82edd))
- Adjust certificate of acme and self signed - ([69e7f37](https://github.com/vicanso/pingap/commit/69e7f379fa2ed5a61574e4d0aa31828f9bbd7b78))
- Adjust chain and self signed certificate - ([32efe09](https://github.com/vicanso/pingap/commit/32efe09c50c96bcc57898711bd81048949aa87ee))
- Make background service more simplified - ([be8652d](https://github.com/vicanso/pingap/commit/be8652dbe834858bf946480cd64695420ee55d34))
- Remove stale self signed certificate interval - ([a75af2a](https://github.com/vicanso/pingap/commit/a75af2ae8069dbcbe106a1d196fc67e064468d78))
- Adjust validate error of config - ([9ddccb1](https://github.com/vicanso/pingap/commit/9ddccb166c950dad9ec9b5f6053c49953824a700))
- Adjust log for discovery - ([5ffd70a](https://github.com/vicanso/pingap/commit/5ffd70a3f56b7a20ebc050e8dff817caacdd8427))
- Enhance file and tinyufo cache - ([c602154](https://github.com/vicanso/pingap/commit/c6021540201f033208d281c95546fecc3c5474a0))
- Add error log for self signed certificate fail - ([eb97a4d](https://github.com/vicanso/pingap/commit/eb97a4d6491a38186bbfd4cdf5cbd5f2cd46e1ee))

### ⚙️ Miscellaneous Tasks

- Sync pingora latest commit - ([818ee7a](https://github.com/vicanso/pingap/commit/818ee7aafb140aecab4089519371b6ce231807be))

## [0.9.4](https://github.com/vicanso/pingap/compare/v0.9.3..0.9.4) - 2024-12-14

### ⛰️  Features

- File cache support limit tinyufo cache size - ([9aa1219](https://github.com/vicanso/pingap/commit/9aa12195562ec970cb0b0923bb34a93e67125435))

### 🐛 Bug Fixes

- Fix open telemetry init - ([a6784a0](https://github.com/vicanso/pingap/commit/a6784a0f7a6ea42d93db0bee4f8a94c595b4e7c5))
- Fix 80 port for admin plugin, #58 - ([1d41c05](https://github.com/vicanso/pingap/commit/1d41c057f6df561b9549b9c08a4bb015fef6d7e1))

### 🚜 Refactor

- Update package - ([e744805](https://github.com/vicanso/pingap/commit/e74480551eb0eacd258bcc16890114accb385278))
- Adjust acme token directory - ([55413ad](https://github.com/vicanso/pingap/commit/55413ad78b691465a7814ea3c6b05fb17fbd2ef3))
- Save acme token as file - ([00cb15b](https://github.com/vicanso/pingap/commit/00cb15baa01548990925619b8f0ed0da860d996c))
- Save let's encrypt cert and key to config storage - ([6e7b5b7](https://github.com/vicanso/pingap/commit/6e7b5b7991f4dc8afc618117de8cbc8d7e340823))
- Adjust certificate of tls - ([757a75c](https://github.com/vicanso/pingap/commit/757a75cd272cd6cffd9fdb7ccc49a159ff55ba01))

### 📚 Documentation

- Update benchmark - ([3406310](https://github.com/vicanso/pingap/commit/3406310c9d2901b79d18a559c170559287e672e9))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([571d199](https://github.com/vicanso/pingap/commit/571d19973c9016fc34048c549b6b24dc9fc95134))
- Use rust 1.82.0 - ([f314e83](https://github.com/vicanso/pingap/commit/f314e83ae2bbbbdbb408614c156de542f6378a4e))

## [0.9.3](https://github.com/vicanso/pingap/compare/v0.9.2..0.9.3) - 2024-12-08

### ⛰️  Features

- Support importing config to storage, #58 - ([767df00](https://github.com/vicanso/pingap/commit/767df009fc2c895ac2c59d4640565e1a86b9e8e3))
- Support transparent proxy gateway, #66 - ([14cc735](https://github.com/vicanso/pingap/commit/14cc735964e7a52e4b4aa1c2a53d0e5c55a4002b))

### 🐛 Bug Fixes

- Remove validate from admin get config function, #67 - ([762e1a1](https://github.com/vicanso/pingap/commit/762e1a1030bdac57a070f1ae2004012b0711c7ad))

### 🚜 Refactor

- Adjust location of server - ([43fb471](https://github.com/vicanso/pingap/commit/43fb4714f5e876146b330c11bb13bffd20f281d2))
- Adjust derive debug for location and upstream - ([073c6c2](https://github.com/vicanso/pingap/commit/073c6c2a7086a4c745606998eb06bedc37a207db))
- Add original and compress size - ([8b82709](https://github.com/vicanso/pingap/commit/8b82709d379a0489db7a4fdd534c494ee1fa2a0e))
- Support reading and writing max count for file cache storage - ([aacfb31](https://github.com/vicanso/pingap/commit/aacfb31d8b244c453fed5d38ba87524f44691fc3))
- Adjust let's encrypt renew - ([f596461](https://github.com/vicanso/pingap/commit/f5964611ed435bcd405b4b949fa54956dae06a0e))
- Guess discovery for name addrs, #67 - ([227dd3a](https://github.com/vicanso/pingap/commit/227dd3a2c4d2f10b452eb6c68fdba090e178e7c4))
- Validity checker ignore acme certificate - ([5cf182f](https://github.com/vicanso/pingap/commit/5cf182f56fbd777a213bc56975fefc255ecd0799))

### 📚 Documentation

- Add transparent proxy demo - ([27503f2](https://github.com/vicanso/pingap/commit/27503f2062fb32077f86eef069fdbdc05a408b3c))

### 🧪 Testing

- Fix request entity too large error - ([bb56bc0](https://github.com/vicanso/pingap/commit/bb56bc0bab9d5a7540a5fcb50144fb846366d222))

### ⚙️ Miscellaneous Tasks

- Update pingap service - ([3809608](https://github.com/vicanso/pingap/commit/38096087c417849871a5a20e60a6e79dfcac71b2))

## [0.9.2](https://github.com/vicanso/pingap/compare/v0.9.1..0.9.2) - 2024-11-30

### ⛰️  Features

- Cache plugin support skip handle - ([111ccb6](https://github.com/vicanso/pingap/commit/111ccb623d82e4527195f1cee047f32db08b0c5e))
- Support add admin plugin to server, #58 - ([d9cd254](https://github.com/vicanso/pingap/commit/d9cd254bf4a231605c94f02ec9d05cef44802133))
- Response header plugin support rename header, #61 ([#62](https://github.com/orhun/git-cliff/issues/62)) - ([66b4824](https://github.com/vicanso/pingap/commit/66b48241fad52624c93ec9ae3e5a8ed3a671d40f))

### 🐛 Bug Fixes

- Fix base64 encode of admin auth, #63 - ([a435cbf](https://github.com/vicanso/pingap/commit/a435cbf0606648dae34d2c16bdb0dd1f5c71d264))

### 🚜 Refactor

- Adjust admin login page - ([6e458f2](https://github.com/vicanso/pingap/commit/6e458f22a2714758757b6d8e88af40663fc87481))
- Adjust admin login page - ([9f3825c](https://github.com/vicanso/pingap/commit/9f3825cccb30f5d28061e76de0c76af95352afd1))
- Update open telemetry module ([#59](https://github.com/orhun/git-cliff/issues/59)) - ([2feb080](https://github.com/vicanso/pingap/commit/2feb0805ebd201e3265d095307eecee68c5693b9))
- Adjust get query from etcd connection uri - ([5103c26](https://github.com/vicanso/pingap/commit/5103c26d0cf01d3e5596c49bb10d5c0275ec6e76))

### 🧪 Testing

- Fix clippy result large err - ([fbe27fe](https://github.com/vicanso/pingap/commit/fbe27fe0d2ba95f73479ca5b6243f4502718311d))

### ⚙️ Miscellaneous Tasks

- Update deppendencies - ([626b829](https://github.com/vicanso/pingap/commit/626b829b8d7b5dfe5910b6ede4d0b1ad0853fdde))
- Update modules - ([b4bb67e](https://github.com/vicanso/pingap/commit/b4bb67eae34d243a966b0a484c8572a594243c38))
- Add pingap service config - ([e008557](https://github.com/vicanso/pingap/commit/e00855760d22c465c7b4f510f6087b0c594813c6))

## [0.9.1](https://github.com/vicanso/pingap/compare/v0.9.0..0.9.1) - 2024-11-23

### ⛰️  Features

- Split and save the config as single toml in separation mode - ([562085b](https://github.com/vicanso/pingap/commit/562085b0d2cda2724739b83cbc93cabe7363cbb5))
- Supports days_ago and time_point_hour parameters for log compression - ([ee76bd7](https://github.com/vicanso/pingap/commit/ee76bd7313d2d6deee1b426f24c55e4398bd0759))
- Admin argument supports path - ([d676aeb](https://github.com/vicanso/pingap/commit/d676aeb06438ef4e1d5433dce6a542f0a2eb481b))
- Supports log compression ([#57](https://github.com/orhun/git-cliff/issues/57)) - ([b6be388](https://github.com/vicanso/pingap/commit/b6be388f7e1910d04a7a4002fdbb5fab678366dc))
- Health check supports grpc protocol ([#56](https://github.com/orhun/git-cliff/issues/56)) - ([165fa8a](https://github.com/vicanso/pingap/commit/165fa8aca23011517c21929c13d01c7421232a57))
- Support pingap accept encoding adjustment plugin - ([22ab2fc](https://github.com/vicanso/pingap/commit/22ab2fc68500530cfb06423ece504fe146dee62e))
- Show validity date of certificate - ([9d40a98](https://github.com/vicanso/pingap/commit/9d40a98acba45dc5fc82675b1e6064ad5f0fc30f))
- Path rewrite support variable substitution - ([4c62dc2](https://github.com/vicanso/pingap/commit/4c62dc25a2b160f1d4588b4389cab2c928450338))
- Server and location support grpc web module - ([e353aa6](https://github.com/vicanso/pingap/commit/e353aa67090a231c9dac2aa91bc6934c8911c646))
- Location host match supports regex - ([8498168](https://github.com/vicanso/pingap/commit/84981687261eddcd3e9006ffae6d1ef5163634ef))
- Tinyufo cache supports remove function - ([23833bf](https://github.com/vicanso/pingap/commit/23833bf13e17d011bf55bf35c6adf470ff225000))

### 🐛 Bug Fixes

- Fix non-latin name of config, #55 - ([b7b5129](https://github.com/vicanso/pingap/commit/b7b5129f0ac36d5c6c2f14d7a8158169f7addf15))
- Fix lint error - ([7cea336](https://github.com/vicanso/pingap/commit/7cea33643c7a4a208f8e45a1a80d773021751e2c))

### 🚜 Refactor

- Create toml config if if not exists - ([46b17e7](https://github.com/vicanso/pingap/commit/46b17e7b0aef054fb1a42ab5e7f34a0effa3b358))
- Add debug for proxy http trait - ([025031e](https://github.com/vicanso/pingap/commit/025031e626e585d9b59e2b616c6c5b579b9dadab))
- Add static serve example - ([2384ffe](https://github.com/vicanso/pingap/commit/2384ffe5c9b886733b4050a678cb3a3a049c8cf9))
- Adjust certificate editor - ([20acd3e](https://github.com/vicanso/pingap/commit/20acd3edf96bdee0f4ab6259da8a5f3a69b18b1b))
- Ctx supports add variable function - ([cd66f0d](https://github.com/vicanso/pingap/commit/cd66f0db80d9b75741a3f0776b494e1e0f0dfa21))
- Adjust regex capture for variables - ([9ade424](https://github.com/vicanso/pingap/commit/9ade4247fd953715bf460a6a2a49a6d734a6f4e4))
- Update logo of pingap - ([01ffb87](https://github.com/vicanso/pingap/commit/01ffb876b8fd71ccb4d2b38d3d42c5fb1ac8f478))
- Update opentelemetry - ([9a04df1](https://github.com/vicanso/pingap/commit/9a04df1857059711a161eaf85b60e1097f505f94))

### 📚 Documentation

- Add grpc web example - ([10001c3](https://github.com/vicanso/pingap/commit/10001c3fdbf230f406d744dc5aae372c99b76d53))
- Add proxy upstream example - ([e7fbacd](https://github.com/vicanso/pingap/commit/e7fbacd4ad721cac79f5f85810f02d7eb56e8493))

### 🧪 Testing

- Add purge test for cache plugin - ([1411704](https://github.com/vicanso/pingap/commit/1411704819802016e157946ec66443efc9b20962))
- Add test for basic auth plugin - ([04d1ec0](https://github.com/vicanso/pingap/commit/04d1ec0aee48ba1324b6bf22d297f4355be897ab))
- Add test for config - ([9c13cbb](https://github.com/vicanso/pingap/commit/9c13cbb8569c8aff47a746b6173eb72e4e696a6f))

### ⚙️ Miscellaneous Tasks

- Update pingora version - ([5bc53d3](https://github.com/vicanso/pingap/commit/5bc53d35ae158689d72ee388ea63ab7ade56a9eb))
- Using ubuntu 18.04 as the build system - ([8a592e4](https://github.com/vicanso/pingap/commit/8a592e4638cf34d33c3a6782e8cf68be1ab21db0))
- Benchmark test - ([0e519eb](https://github.com/vicanso/pingap/commit/0e519eb0f4156919477770db478130390b44bd05))
- Use latest commit pingora - ([7199e3c](https://github.com/vicanso/pingap/commit/7199e3ce72887001f584b02e87f435b4d6211053))

## [0.9.0](https://github.com/vicanso/pingap/compare/v0.8.12..0.9.0) - 2024-11-02

### ⛰️  Features

- Support user agent restriction plugin - ([c97adcd](https://github.com/vicanso/pingap/commit/c97adcd5ff8eb317ac1161e77139b8ddec713005))
- Support get storage value for pingap - ([e51a076](https://github.com/vicanso/pingap/commit/e51a076529c73bf7c07cca145d570f484051fc95))
- Support aes encrypt and decrypt - ([b38843f](https://github.com/vicanso/pingap/commit/b38843f83eca7221467648c3eaca1565e179fbf8))

### 🚜 Refactor

- Adjust aes encrypt and decrypt - ([f700ff7](https://github.com/vicanso/pingap/commit/f700ff789329ff5e2ac8eefd2c72ce8dc0a7447f))
- Adjust prometheus - ([2c86d21](https://github.com/vicanso/pingap/commit/2c86d217108a0b093239c3b76e2c29d24d5442d3))
- Adjust omit includes value - ([d2b2306](https://github.com/vicanso/pingap/commit/d2b23063157e5ac154bb005d67ab63ddcea09201))

### ⚙️ Miscellaneous Tasks

- Update pingora version - ([b9533d6](https://github.com/vicanso/pingap/commit/b9533d67c437d1dbb5b8dd11b48e91ac59934ed0))

## [0.8.12](https://github.com/vicanso/pingap/compare/v0.8.11..0.8.12) - 2024-10-27

### ⛰️  Features

- Support file storage clear background service - ([4e4afcd](https://github.com/vicanso/pingap/commit/4e4afcdda32670589b4bf58f933b04c46d72e70d))
- Support server addr and port for response header - ([7ae4ed1](https://github.com/vicanso/pingap/commit/7ae4ed1575ec8457dd86f263011a8a109a84a6dc))
- Support check cache control for cache plugin - ([ba48ed5](https://github.com/vicanso/pingap/commit/ba48ed5a4016b66fcff709ec85751619be07ef8f))
- Support pingap config preview - ([42b3ff8](https://github.com/vicanso/pingap/commit/42b3ff858775dd7325bebc214ecb50d99aa77576))
- Support get connection id from context - ([139c04c](https://github.com/vicanso/pingap/commit/139c04c071c7bda8f0afd43e7cc26c1450b359b7))

### 🐛 Bug Fixes

- Fix fd and connection count - ([9def503](https://github.com/vicanso/pingap/commit/9def50380444dd33524dfabf79a7e3c481e7487e))
- Fix process id - ([ae4f946](https://github.com/vicanso/pingap/commit/ae4f946b1cc5cb5d8a725edd7407e2454e90579a))
- Fix default threads of service - ([e2a2a68](https://github.com/vicanso/pingap/commit/e2a2a68b48a1cc5212a6437b22b99904a9c140d8))
- Fix prefix of redirect plugin - ([97fc5e0](https://github.com/vicanso/pingap/commit/97fc5e06815d8403baa5a92954024a83cdce2212))
- Fix connection id for windows - ([1d21562](https://github.com/vicanso/pingap/commit/1d21562e03080d3b7b50740c4cdce2c468154cb9))

### 🚜 Refactor

- Add fd and tcp default for home page - ([9b824f8](https://github.com/vicanso/pingap/commit/9b824f8395f6995fb3c1e598be2bcee806e66b62))
- Adjust stats of pingap - ([99f0183](https://github.com/vicanso/pingap/commit/99f0183357c573c15349a819942f16263a80f602))
- Adjust common service task - ([718ab0e](https://github.com/vicanso/pingap/commit/718ab0e687931e39b5f43f5a4fe73c52c8cd87b5))
- Set default certificate for none server name - ([d5fb595](https://github.com/vicanso/pingap/commit/d5fb59540fcdc9566957450d292e0151d428f802))
- Adjust web admin for open telemetry and pyroscope - ([3a79342](https://github.com/vicanso/pingap/commit/3a7934283d78364fb6b7d8c2320fad1341f82c87))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([296fd10](https://github.com/vicanso/pingap/commit/296fd1034fc365016a63eb6aa0149a61ea5eb328))

## [0.8.11](https://github.com/vicanso/pingap/compare/v0.8.10..0.8.11) - 2024-10-19

### ⛰️  Features

- Support daily rolling log - ([34c99e1](https://github.com/vicanso/pingap/commit/34c99e1aa8f8f67340cb6044f46b2ef45c7033bb))

### 🐛 Bug Fixes

- Fix lint error - ([fc40efe](https://github.com/vicanso/pingap/commit/fc40efe8eec386f36add0937f87a87dcf312e8bb))

### 🚜 Refactor

- Support windows ([#47](https://github.com/orhun/git-cliff/issues/47)) - ([ede1024](https://github.com/vicanso/pingap/commit/ede1024e88d75ab7167781c22864bf59b31c748a))
- Adjust tracking feature for prometheus and open telemetry ([#46](https://github.com/orhun/git-cliff/issues/46)) - ([f46edc8](https://github.com/vicanso/pingap/commit/f46edc879290e8dc9050bee949e868295e24b0ae))
- Adjust main header - ([0e38e1f](https://github.com/vicanso/pingap/commit/0e38e1feb8032ad5a43faa05eaeb5fbb29c88ab6))
- Support more header for http - ([24267bd](https://github.com/vicanso/pingap/commit/24267bd2055844e5118a9d0e13abf582986feb74))
- Support more rolling type - ([538ba7a](https://github.com/vicanso/pingap/commit/538ba7a95bb5fb850c613c1495ad0391657f3811))
- Adjust label of pingap config web page - ([2b917cf](https://github.com/vicanso/pingap/commit/2b917cf60dfd6eeba2ba3fc2f1574aeed6b51fbf))
- Add tracking and kernel for basic info - ([d7ed17d](https://github.com/vicanso/pingap/commit/d7ed17dffeeaba065f641cc3e0faa6c2412b18dc))
- Adjust sentry optional - ([d778449](https://github.com/vicanso/pingap/commit/d778449e13008b17d0d53ea05e459e0341b569a1))

### ⚙️ Miscellaneous Tasks

- Update workflow - ([adc53e8](https://github.com/vicanso/pingap/commit/adc53e8fc77f780b6685be17fb3a3bfe8ae6c94a))
- Update workflow - ([681620d](https://github.com/vicanso/pingap/commit/681620d8d3943432b8984e2c2eef91a6567ce248))

## [0.8.10](https://github.com/vicanso/pingap/compare/v0.8.8..0.8.10) - 2024-10-13

### ⛰️  Features

- Support more infomations for stats - ([ec74050](https://github.com/vicanso/pingap/commit/ec74050f5ee59016a3ea2c9fab99598aa5751ce6))

### 🧪 Testing

- Fix test - ([acda41e](https://github.com/vicanso/pingap/commit/acda41e40772859f9acc00eb85f1d7b5578d6ac0))

### ⚙️ Miscellaneous Tasks

- Use ubuntu 20.04 for workflow - ([af70c91](https://github.com/vicanso/pingap/commit/af70c913bbc974a09e8a2a5215b8045b8ffe5fba))
- Version 0.8.9 - ([9241030](https://github.com/vicanso/pingap/commit/9241030ea2ffa29987549a6b9e89fec93d2c9a15))
- Version 0.8.8 - ([bcb5ef4](https://github.com/vicanso/pingap/commit/bcb5ef46f1f1be374b6e5e932451bc0ad11684fe))
- Update components - ([746294e](https://github.com/vicanso/pingap/commit/746294e32be82b149071e51bc4465f4bb3de9daa))

## [0.8.9](https://github.com/vicanso/pingap/compare/v0.8.8..0.8.9) - 2024-10-13

### ⛰️  Features

- Support more infomations for stats - ([ec74050](https://github.com/vicanso/pingap/commit/ec74050f5ee59016a3ea2c9fab99598aa5751ce6))

### 🧪 Testing

- Fix test - ([acda41e](https://github.com/vicanso/pingap/commit/acda41e40772859f9acc00eb85f1d7b5578d6ac0))

### ⚙️ Miscellaneous Tasks

- Version 0.8.8 - ([bcb5ef4](https://github.com/vicanso/pingap/commit/bcb5ef46f1f1be374b6e5e932451bc0ad11684fe))
- Update components - ([746294e](https://github.com/vicanso/pingap/commit/746294e32be82b149071e51bc4465f4bb3de9daa))

## [0.8.8](https://github.com/vicanso/pingap/compare/v0.8.8..0.8.8) - 2024-10-13

### ⛰️  Features

- Support more infomations for stats - ([ec74050](https://github.com/vicanso/pingap/commit/ec74050f5ee59016a3ea2c9fab99598aa5751ce6))

### 🧪 Testing

- Fix test - ([acda41e](https://github.com/vicanso/pingap/commit/acda41e40772859f9acc00eb85f1d7b5578d6ac0))

### ⚙️ Miscellaneous Tasks

- Update components - ([746294e](https://github.com/vicanso/pingap/commit/746294e32be82b149071e51bc4465f4bb3de9daa))

## [0.8.7](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.7) - 2024-09-29

### ⛰️  Features

- Support gzip for admin - ([308d226](https://github.com/vicanso/pingap/commit/308d2266487a8b4a8d6e13eb1c17240df0772ae8))
- Web admin supports combined auth plugin config - ([8ec0960](https://github.com/vicanso/pingap/commit/8ec09600d280aace01390ce89a64ca95f7ea50cb))
- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Fix get location of empty host - ([30b48ea](https://github.com/vicanso/pingap/commit/30b48ea88c0bb2a92c3045a0d3a6c1ac2d66290f))
- Fix certificate summary list - ([c176296](https://github.com/vicanso/pingap/commit/c17629668d8d4de4703cb11a917b93a3d3642847))
- Fix get weight of location - ([1b8d094](https://github.com/vicanso/pingap/commit/1b8d09413030a56501f431e91c1846f2a2b7dc98))
- Fix select category of plugin - ([1ad25aa](https://github.com/vicanso/pingap/commit/1ad25aa15179cb324008346b598d5f97fde6e9de))
- Adjust base path for static serve - ([64cdf29](https://github.com/vicanso/pingap/commit/64cdf29c5f91aa5437ce3cb8247f4ba6837b76f4))
- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### 🚜 Refactor

- Adjust remove popup over - ([cff3354](https://github.com/vicanso/pingap/commit/cff3354d9f90eea6e053bff05734232a07144814))
- Adjust home page - ([53e006b](https://github.com/vicanso/pingap/commit/53e006bb31a111a41d5a5483b345e0a1cb24bf6a))
- Adjust home page - ([e322dc4](https://github.com/vicanso/pingap/commit/e322dc4ed86ee9bdbafe04c580832126ace707e8))
- Adjust config tabs - ([48989db](https://github.com/vicanso/pingap/commit/48989dba1971eca181acf12d97e1eecc9ec55007))
- Adjust config editor - ([cb0ea53](https://github.com/vicanso/pingap/commit/cb0ea53e7e7085e78ca53e68c6df1b658a2e1626))
- Adjust i18n - ([4c4b8b6](https://github.com/vicanso/pingap/commit/4c4b8b6c48a24e88712536397896a18fc451a1a1))

### 📚 Documentation

- Update CHANGELOG - ([b8498b8](https://github.com/vicanso/pingap/commit/b8498b8ca44e9c6b6fc20023f9251148122b26ce))

### ⚙️ Miscellaneous Tasks

- Version 0.8.6 - ([5bf9602](https://github.com/vicanso/pingap/commit/5bf9602b599305ff40aaacf0f7237ed4280a8394))
- Fix spelling - ([0ffb5e1](https://github.com/vicanso/pingap/commit/0ffb5e17c284ed9ae039897764036754718a86bc))
- Version 0.8.5 - ([80c0253](https://github.com/vicanso/pingap/commit/80c0253ba829d64b9cf9b428b80a7128e45e6218))
- Update cargo msrv - ([0f73b82](https://github.com/vicanso/pingap/commit/0f73b824257ca47395fb0f9519be2c1bb6940428))
- Version 0.8.4 - ([a870107](https://github.com/vicanso/pingap/commit/a87010770dd5ad10d5a4de8d6c59a23bf3c3de9d))
- Version 0.8.3 - ([9c139b8](https://github.com/vicanso/pingap/commit/9c139b8d4ff5af5ab4cee3a7408f8a532687407b))
- Version 0.8.2 - ([daf9a19](https://github.com/vicanso/pingap/commit/daf9a19516d63162a6f4bcd415f7a0cdef71f40b))
- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.6](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.6) - 2024-09-29

### ⛰️  Features

- Support gzip for admin - ([308d226](https://github.com/vicanso/pingap/commit/308d2266487a8b4a8d6e13eb1c17240df0772ae8))
- Web admin supports combined auth plugin config - ([8ec0960](https://github.com/vicanso/pingap/commit/8ec09600d280aace01390ce89a64ca95f7ea50cb))
- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Fix certificate summary list - ([c176296](https://github.com/vicanso/pingap/commit/c17629668d8d4de4703cb11a917b93a3d3642847))
- Fix get weight of location - ([1b8d094](https://github.com/vicanso/pingap/commit/1b8d09413030a56501f431e91c1846f2a2b7dc98))
- Fix select category of plugin - ([1ad25aa](https://github.com/vicanso/pingap/commit/1ad25aa15179cb324008346b598d5f97fde6e9de))
- Adjust base path for static serve - ([64cdf29](https://github.com/vicanso/pingap/commit/64cdf29c5f91aa5437ce3cb8247f4ba6837b76f4))
- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### 🚜 Refactor

- Adjust remove popup over - ([cff3354](https://github.com/vicanso/pingap/commit/cff3354d9f90eea6e053bff05734232a07144814))
- Adjust home page - ([53e006b](https://github.com/vicanso/pingap/commit/53e006bb31a111a41d5a5483b345e0a1cb24bf6a))
- Adjust home page - ([e322dc4](https://github.com/vicanso/pingap/commit/e322dc4ed86ee9bdbafe04c580832126ace707e8))
- Adjust config tabs - ([48989db](https://github.com/vicanso/pingap/commit/48989dba1971eca181acf12d97e1eecc9ec55007))
- Adjust config editor - ([cb0ea53](https://github.com/vicanso/pingap/commit/cb0ea53e7e7085e78ca53e68c6df1b658a2e1626))
- Adjust i18n - ([4c4b8b6](https://github.com/vicanso/pingap/commit/4c4b8b6c48a24e88712536397896a18fc451a1a1))

### 📚 Documentation

- Update CHANGELOG - ([b8498b8](https://github.com/vicanso/pingap/commit/b8498b8ca44e9c6b6fc20023f9251148122b26ce))

### ⚙️ Miscellaneous Tasks

- Fix spelling - ([0ffb5e1](https://github.com/vicanso/pingap/commit/0ffb5e17c284ed9ae039897764036754718a86bc))
- Version 0.8.5 - ([80c0253](https://github.com/vicanso/pingap/commit/80c0253ba829d64b9cf9b428b80a7128e45e6218))
- Update cargo msrv - ([0f73b82](https://github.com/vicanso/pingap/commit/0f73b824257ca47395fb0f9519be2c1bb6940428))
- Version 0.8.4 - ([a870107](https://github.com/vicanso/pingap/commit/a87010770dd5ad10d5a4de8d6c59a23bf3c3de9d))
- Version 0.8.3 - ([9c139b8](https://github.com/vicanso/pingap/commit/9c139b8d4ff5af5ab4cee3a7408f8a532687407b))
- Version 0.8.2 - ([daf9a19](https://github.com/vicanso/pingap/commit/daf9a19516d63162a6f4bcd415f7a0cdef71f40b))
- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.5](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.5) - 2024-09-28

### ⛰️  Features

- Support gzip for admin - ([308d226](https://github.com/vicanso/pingap/commit/308d2266487a8b4a8d6e13eb1c17240df0772ae8))
- Web admin supports combined auth plugin config - ([8ec0960](https://github.com/vicanso/pingap/commit/8ec09600d280aace01390ce89a64ca95f7ea50cb))
- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Fix select category of plugin - ([1ad25aa](https://github.com/vicanso/pingap/commit/1ad25aa15179cb324008346b598d5f97fde6e9de))
- Adjust base path for static serve - ([64cdf29](https://github.com/vicanso/pingap/commit/64cdf29c5f91aa5437ce3cb8247f4ba6837b76f4))
- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### 🚜 Refactor

- Adjust remove popup over - ([cff3354](https://github.com/vicanso/pingap/commit/cff3354d9f90eea6e053bff05734232a07144814))
- Adjust home page - ([53e006b](https://github.com/vicanso/pingap/commit/53e006bb31a111a41d5a5483b345e0a1cb24bf6a))
- Adjust home page - ([e322dc4](https://github.com/vicanso/pingap/commit/e322dc4ed86ee9bdbafe04c580832126ace707e8))
- Adjust config tabs - ([48989db](https://github.com/vicanso/pingap/commit/48989dba1971eca181acf12d97e1eecc9ec55007))
- Adjust config editor - ([cb0ea53](https://github.com/vicanso/pingap/commit/cb0ea53e7e7085e78ca53e68c6df1b658a2e1626))
- Adjust i18n - ([4c4b8b6](https://github.com/vicanso/pingap/commit/4c4b8b6c48a24e88712536397896a18fc451a1a1))

### 📚 Documentation

- Update CHANGELOG - ([b8498b8](https://github.com/vicanso/pingap/commit/b8498b8ca44e9c6b6fc20023f9251148122b26ce))

### ⚙️ Miscellaneous Tasks

- Update cargo msrv - ([0f73b82](https://github.com/vicanso/pingap/commit/0f73b824257ca47395fb0f9519be2c1bb6940428))
- Version 0.8.4 - ([a870107](https://github.com/vicanso/pingap/commit/a87010770dd5ad10d5a4de8d6c59a23bf3c3de9d))
- Version 0.8.3 - ([9c139b8](https://github.com/vicanso/pingap/commit/9c139b8d4ff5af5ab4cee3a7408f8a532687407b))
- Version 0.8.2 - ([daf9a19](https://github.com/vicanso/pingap/commit/daf9a19516d63162a6f4bcd415f7a0cdef71f40b))
- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.3](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.3) - 2024-09-25

### ⛰️  Features

- Web admin supports combined auth plugin config - ([8ec0960](https://github.com/vicanso/pingap/commit/8ec09600d280aace01390ce89a64ca95f7ea50cb))
- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Adjust base path for static serve - ([64cdf29](https://github.com/vicanso/pingap/commit/64cdf29c5f91aa5437ce3cb8247f4ba6837b76f4))
- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### 🚜 Refactor

- Adjust home page - ([e322dc4](https://github.com/vicanso/pingap/commit/e322dc4ed86ee9bdbafe04c580832126ace707e8))
- Adjust config tabs - ([48989db](https://github.com/vicanso/pingap/commit/48989dba1971eca181acf12d97e1eecc9ec55007))
- Adjust config editor - ([cb0ea53](https://github.com/vicanso/pingap/commit/cb0ea53e7e7085e78ca53e68c6df1b658a2e1626))
- Adjust i18n - ([4c4b8b6](https://github.com/vicanso/pingap/commit/4c4b8b6c48a24e88712536397896a18fc451a1a1))

### 📚 Documentation

- Update CHANGELOG - ([b8498b8](https://github.com/vicanso/pingap/commit/b8498b8ca44e9c6b6fc20023f9251148122b26ce))

### ⚙️ Miscellaneous Tasks

- Version 0.8.3 - ([9c139b8](https://github.com/vicanso/pingap/commit/9c139b8d4ff5af5ab4cee3a7408f8a532687407b))
- Version 0.8.2 - ([daf9a19](https://github.com/vicanso/pingap/commit/daf9a19516d63162a6f4bcd415f7a0cdef71f40b))
- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.3](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.3) - 2024-09-25

### ⛰️  Features

- Web admin supports combined auth plugin config - ([8ec0960](https://github.com/vicanso/pingap/commit/8ec09600d280aace01390ce89a64ca95f7ea50cb))
- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Adjust base path for static serve - ([64cdf29](https://github.com/vicanso/pingap/commit/64cdf29c5f91aa5437ce3cb8247f4ba6837b76f4))
- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### 🚜 Refactor

- Adjust home page - ([e322dc4](https://github.com/vicanso/pingap/commit/e322dc4ed86ee9bdbafe04c580832126ace707e8))
- Adjust config tabs - ([48989db](https://github.com/vicanso/pingap/commit/48989dba1971eca181acf12d97e1eecc9ec55007))
- Adjust config editor - ([cb0ea53](https://github.com/vicanso/pingap/commit/cb0ea53e7e7085e78ca53e68c6df1b658a2e1626))
- Adjust i18n - ([4c4b8b6](https://github.com/vicanso/pingap/commit/4c4b8b6c48a24e88712536397896a18fc451a1a1))

### ⚙️ Miscellaneous Tasks

- Version 0.8.3 - ([9c139b8](https://github.com/vicanso/pingap/commit/9c139b8d4ff5af5ab4cee3a7408f8a532687407b))
- Version 0.8.2 - ([daf9a19](https://github.com/vicanso/pingap/commit/daf9a19516d63162a6f4bcd415f7a0cdef71f40b))
- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.2](https://github.com/vicanso/pingap/compare/v0.8.1..0.8.2) - 2024-09-21

### ⛰️  Features

- Add combined auth plugin - ([69f931b](https://github.com/vicanso/pingap/commit/69f931b1bfec44f712712187ed4b476b7982d300))
- Support accept encoding adjustment plugin - ([aebc237](https://github.com/vicanso/pingap/commit/aebc237d657910653642d86f0330ed8c9f7da235))
- Support purge http cache - ([0e0ffa7](https://github.com/vicanso/pingap/commit/0e0ffa7fb3fb79e3cf505cb5fde67b8c51aced33))

### 🐛 Bug Fixes

- Fix lint - ([0351267](https://github.com/vicanso/pingap/commit/0351267779ab81804ab11bb132a5e235d577221e))

### ⚙️ Miscellaneous Tasks

- Update dependencies - ([ca80442](https://github.com/vicanso/pingap/commit/ca80442b8d55cfc87328c8d5626cff3fb3c7bc39))

## [0.8.1](https://github.com/vicanso/pingap/compare/v0.8.0..0.8.1) - 2024-09-07

### ⛰️  Features

- Support hot reload certificates - ([202c5d7](https://github.com/vicanso/pingap/commit/202c5d799fa566dd60165a49a39148e8342bde40))
- Support sync config to other storage - ([e66740d](https://github.com/vicanso/pingap/commit/e66740d389ef5a792131a6e0b9d0c1908ab866d2))

### 🚜 Refactor

- Adjust certificate reload - ([e6b5e04](https://github.com/vicanso/pingap/commit/e6b5e0496cab829b1021e74f7ff51965587fcfa7))
- Adjust certificate of config - ([a5e484a](https://github.com/vicanso/pingap/commit/a5e484af9634d8cab8e29436656f6e891ea0c8a3))
- Adjust stats and compression plugin - ([2334f5a](https://github.com/vicanso/pingap/commit/2334f5a395c5cde8e1650b2fc27c3626193a9239))
- Set max limit for tcp probe count - ([8da5d08](https://github.com/vicanso/pingap/commit/8da5d08cc059d5ae58912a1d4a546b2c0b4f8d72))

### ⚙️ Miscellaneous Tasks

- Version 0.8.1 - ([8083922](https://github.com/vicanso/pingap/commit/80839223e8f1aae688cf7314cdf849d07064966e))
- Update dependencies - ([a612d45](https://github.com/vicanso/pingap/commit/a612d45b88ac4ab2f86b4f5a4124681c9d23a4b4))

## [0.8.0](https://github.com/vicanso/pingap/compare/v0.7.0..0.8.0) - 2024-08-31

### ⛰️  Features

- Support observe config update for etcd storage - ([622ef94](https://github.com/vicanso/pingap/commit/622ef94cc2a5648f00f27503435691b571d2cf30))
- Support docker service discovery - ([3bed37b](https://github.com/vicanso/pingap/commit/3bed37b19e24cf5f6cf137c117bd185c84430232))
- Support upstream and location updated notification - ([ee73fac](https://github.com/vicanso/pingap/commit/ee73fac1774612c2da34c5665114e6bf651976ef))

### 🐛 Bug Fixes

- Fix docker discovery find by name - ([8aaec59](https://github.com/vicanso/pingap/commit/8aaec59dfc5accfab6c88de58e418a401d55d230))
- Fix get version of rustc - ([c03b4ac](https://github.com/vicanso/pingap/commit/c03b4ac253d98bf888f58cdca80e66ff15aa56ff))

### 🚜 Refactor

- Adjust http cache plugin - ([0401080](https://github.com/vicanso/pingap/commit/0401080c14d7cc29768e28f2c786f307041e4076))
- Adjust docker service discover for label filter - ([925a105](https://github.com/vicanso/pingap/commit/925a1057ba857b7e9af3a211a17220a02ce4becf))
- Adjust config reload handle - ([fc4d6e7](https://github.com/vicanso/pingap/commit/fc4d6e7a8434ac891ad3d1a522ec804e3f9fc5a0))
- Adjust proxy server - ([15e6143](https://github.com/vicanso/pingap/commit/15e61436320cb906774e189bb4c297954edecd50))
- Adjust discovery and otel - ([7a61860](https://github.com/vicanso/pingap/commit/7a61860a00e55901fea0836edc5ef93f3a514637))
- Adjust cache modules - ([ef7ce98](https://github.com/vicanso/pingap/commit/ef7ce9831875e37aaf08b3ae3134930db6e915aa))
- Adjust acme handler - ([c6ea96c](https://github.com/vicanso/pingap/commit/c6ea96cb344cbacfc1a441f7831e67534877beb1))
- Remove unused features - ([a39b1ce](https://github.com/vicanso/pingap/commit/a39b1ce752b663d2dde3d0db3b8d953061d5f191))
- Adjust dns service discovery - ([ec2f190](https://github.com/vicanso/pingap/commit/ec2f190db3a7d7f48dab7399fabf33ebb9ce9464))
- Adjust tls validity handle - ([87f8a74](https://github.com/vicanso/pingap/commit/87f8a744b5d31f0b19cad4074bc98e04943537aa))
- Add realod fail notification for web hook - ([85be103](https://github.com/vicanso/pingap/commit/85be1035f40dbe2ba9a73a6814395632511d589a))
- Adjust plugin reload function - ([cf5e8f5](https://github.com/vicanso/pingap/commit/cf5e8f5f66fb7621f87c899e797f97e8931c01a4))
- Adjust sentry client options - ([46f85e6](https://github.com/vicanso/pingap/commit/46f85e610a58233dd086cb080ece4c9b8929f5ec))
- Support auto reload plugin handler - ([f8ea609](https://github.com/vicanso/pingap/commit/f8ea6090f785ef33558cbab241d903917db14644))
- Adjust scopeguard for reading writing count - ([44234e0](https://github.com/vicanso/pingap/commit/44234e00e3870070184060a3c4f285b8517ce35f))
- Adjust backend observe notification - ([6065894](https://github.com/vicanso/pingap/commit/6065894448cfb538ee98454574042377d92c306d))
- Adjust base64 encode and decode - ([69a84af](https://github.com/vicanso/pingap/commit/69a84af7fdaefaef15fbcfda0b44eb20a68ff98d))
- Adjust error handler - ([121f428](https://github.com/vicanso/pingap/commit/121f428c71c2e3d1c7c6566cfdc6e4b6a4a5ae8a))

### 📚 Documentation

- Update documents, #21 - ([8d39a6b](https://github.com/vicanso/pingap/commit/8d39a6bd3ded554323041cc0d0c11560e377b449))

### ⚙️ Miscellaneous Tasks

- Version 0.8.0 - ([27cdc8e](https://github.com/vicanso/pingap/commit/27cdc8edefda33e79148be1ab8ee9ce7b4da9a67))
- Update dependencies - ([3d54394](https://github.com/vicanso/pingap/commit/3d543941308c9fe27a476a614b3563c509a9dd54))
- Add security audit - ([fc281c9](https://github.com/vicanso/pingap/commit/fc281c9e76b694860fc70c13fb925778177d9c28))

## [0.7.0](https://github.com/vicanso/pingap/compare/v0.6.2..0.7.0) - 2024-08-10

### ⛰️  Features

- Support get arguments from env - ([33ed2a8](https://github.com/vicanso/pingap/commit/33ed2a88091d4ac3e0ae3faa1d443e9c3c992b58))
- Support opentelemetry ([#20](https://github.com/orhun/git-cliff/issues/20)) - ([d50596c](https://github.com/vicanso/pingap/commit/d50596c5882ad91744dd19eba69232fc142bb438))
- Add docker-compose template config, #19 - ([534c0b5](https://github.com/vicanso/pingap/commit/534c0b53b93e81eaa8aaeff471b633113076df9c))
- Support backend health observe handler - ([5f5892b](https://github.com/vicanso/pingap/commit/5f5892baa862bb02476f9f8d302372ec885871e0))
- Support different backends webhook event - ([bccc695](https://github.com/vicanso/pingap/commit/bccc6958232b7d211a0d17c3aeb7e035622c3bf4))
- Add rustc version to basic info - ([ad21162](https://github.com/vicanso/pingap/commit/ad21162b3825b1ba298bd4cba8aff68e4634ece3))
- Support delay for mock response plugin - ([1f368c3](https://github.com/vicanso/pingap/commit/1f368c3f3f63595013a8bbd3b0451136c5ad2e50))

### 🐛 Bug Fixes

- Fixed dns discovery not update backend health status - ([f6f8b0a](https://github.com/vicanso/pingap/commit/f6f8b0a998ae99e4fedbfd2a665fe0951ee8bf0c))

### 🚜 Refactor

- Update pingora version - ([aa8c96e](https://github.com/vicanso/pingap/commit/aa8c96e322be3f782f556bf300a82ad9e4a0bec7))
- Support more params for opentelemetry - ([66694b0](https://github.com/vicanso/pingap/commit/66694b01374d19b1428bf0d34aa29dce574b769c))
- Adjust auto reload and restart handler - ([b8f8799](https://github.com/vicanso/pingap/commit/b8f87997d96fc0ad4f6a70709e4e054d59302832))
- Adjust conf parameter get from env - ([778d944](https://github.com/vicanso/pingap/commit/778d94487ee939a3a5d66b50e659f3f8ec9989b9))
- Adjust open telemetry for each server service, not global - ([e022cf3](https://github.com/vicanso/pingap/commit/e022cf3c07791d453e3b6fc3882a7545e54b9d30))
- Adjust http status code of error - ([db351fb](https://github.com/vicanso/pingap/commit/db351fb6dfe334f8bbeff2beebe640de854a6e90))
- Adjust file cache stats - ([462f46f](https://github.com/vicanso/pingap/commit/462f46f99b880556c67e15df6a7cacb727f520de))
- Set ip strategy for better performance - ([1e701c2](https://github.com/vicanso/pingap/commit/1e701c2cc00fba07090da36db03c88e9c5386324))
- Adjust dns timeout for lookup ip - ([9b9a6b8](https://github.com/vicanso/pingap/commit/9b9a6b883c765dc978938e1e4df76ca1ad825f2c))
- Adjust configuration diff handler - ([3f283f4](https://github.com/vicanso/pingap/commit/3f283f430dfeae7b9d6d3b44b6a09f70ae7b3285))
- Adjust error message - ([d7a2d3c](https://github.com/vicanso/pingap/commit/d7a2d3cba0f530a3550bef994f40d3c409b927dd))
- Adjust upstream and location update handler - ([1ea5e92](https://github.com/vicanso/pingap/commit/1ea5e92e8755ae5a433f22a80da0c411f1e6a4d2))
- Adjust acme and rcgen - ([8a8b12d](https://github.com/vicanso/pingap/commit/8a8b12da9390ea2e5eefb63ef4f5116cd6090924))
- Adjust update and health check frequency - ([25dbc7b](https://github.com/vicanso/pingap/commit/25dbc7bb98732ee0143f968cda6ac4f42d28a211))
- Adjust http cache storage trait - ([aafde95](https://github.com/vicanso/pingap/commit/aafde955b39f20dbef099fd93f374ee810b7afd0))
- Adjust webhook notification - ([8ec4fcc](https://github.com/vicanso/pingap/commit/8ec4fccbf34b4cba874b99f5a0e07d8f421ab17a))
- Adjust prometheus timing - ([de46260](https://github.com/vicanso/pingap/commit/de46260e1cadfd714005e2e6b8f55228af1133f0))

## [0.6.2](https://github.com/vicanso/pingap/compare/v0.6.1..0.6.2) - 2024-07-26

### ⛰️  Features

- Support delay processing for plugin auth fail - ([a272b1c](https://github.com/vicanso/pingap/commit/a272b1c252d6fdc45db10d7b0251f35856db3fc9))
- Add cache reading and writing for prometheus metrics - ([171d3f2](https://github.com/vicanso/pingap/commit/171d3f2181e7c9236c2e9047f9f693a695368099))
- Support get processing count of file cache - ([e9392a1](https://github.com/vicanso/pingap/commit/e9392a1b759fa2a8c1d41a72dbc08ee477cd6235))
- Set upstream processing count to prometheus metrics - ([38503fb](https://github.com/vicanso/pingap/commit/38503fbcf0c04b924253fb7e9912bb023d1b9a54))
- Set upstream connected count to prometheus metrics - ([8fe5d37](https://github.com/vicanso/pingap/commit/8fe5d376abcdbb9f2c0cb1016e47ec4784914fbd))

### 🐛 Bug Fixes

- Fix wrong chain certificate - ([8448010](https://github.com/vicanso/pingap/commit/8448010a578a88395a63a82639e086922213935b))

### 🚜 Refactor

- Adjust dns resolve timeout - ([7aae593](https://github.com/vicanso/pingap/commit/7aae5934052b8f022d9103cf98cc66bcbd50508b))
- Adjust configuration hot reload - ([2b79357](https://github.com/vicanso/pingap/commit/2b793570dbf78803ae1c923c42e7df040d7337b2))
- Add error type for error template - ([4f18011](https://github.com/vicanso/pingap/commit/4f18011e7a81e723aba17e7e9720cbbb3745e021))
- Add more message for diff config - ([c4ea78b](https://github.com/vicanso/pingap/commit/c4ea78b739573063bc24163be7cc6c79663f8e5a))

### 📚 Documentation

- Update document - ([80a82e3](https://github.com/vicanso/pingap/commit/80a82e3e5e6a5848face114dfc741c9899a172df))
- Update changelog - ([8ebdb8f](https://github.com/vicanso/pingap/commit/8ebdb8f6ea1880b96870515f21fdbfa38001b35f))

### 🧪 Testing

- Add test for prometheus - ([59336d9](https://github.com/vicanso/pingap/commit/59336d959151ce591acc5b2bc6be1569a81861ed))

### ⚙️ Miscellaneous Tasks

- Version 0.6.2 - ([e3d0e20](https://github.com/vicanso/pingap/commit/e3d0e2063293ecbc82ca7db5c566dcb0e0d35073))

## [0.6.1](https://github.com/vicanso/pingap/compare/v0.6.0..0.6.1) - 2024-07-20

### ⛰️  Features

- Support buffer file logger - ([9bb88e8](https://github.com/vicanso/pingap/commit/9bb88e85dcbf8d19c8b5fd0c855a0bf6ffa394e7))
- Support prometheus push - ([774a350](https://github.com/vicanso/pingap/commit/774a350b4b8e3ffcd957f90369252b899d010be5))
- Add `upstream_tls_handshake_time` to prometheus metrics - ([490221a](https://github.com/vicanso/pingap/commit/490221a339abd17357a4c0847efa31e9b2d60fb6))
- Support prometheus metrics - ([2b059ea](https://github.com/vicanso/pingap/commit/2b059ea5c42d8645fe6d15f7dc76a9fac1fa8b1f))

### 🐛 Bug Fixes

- Fix diff result of hot reload - ([0e97a17](https://github.com/vicanso/pingap/commit/0e97a1751e5f05fa1fe06f473f2804bbb795ee28))

### 🚜 Refactor

- Adjust http cache Vec<u8> to Bytes - ([d0f91c2](https://github.com/vicanso/pingap/commit/d0f91c2c429a70d86d2da3c060c2fe542685805e))
- Add log for service task - ([d5266b1](https://github.com/vicanso/pingap/commit/d5266b1d3dc049b6d51001f128a49b98a172ac1e))
- Adjust weight of cache - ([ab38612](https://github.com/vicanso/pingap/commit/ab386124d10ab299a85370bc94f47c297ef6b72d))

### 📚 Documentation

- Adjust documents - ([7f5868a](https://github.com/vicanso/pingap/commit/7f5868aa3f667be36591b80e554f4e7ebb2ccb5d))

### ⚙️ Miscellaneous Tasks

- Version 0.6.1 - ([55287d9](https://github.com/vicanso/pingap/commit/55287d9e5fbe68053fc8100ebaf29c855925b8d1))
- Adjust meta size - ([d0c8e10](https://github.com/vicanso/pingap/commit/d0c8e10fc34da363252de4d01fc7a80aaea4b4d0))

