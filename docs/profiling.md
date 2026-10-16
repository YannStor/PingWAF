# PingWAF Profiling

PingWAF ships built-in pprof-style profiling in every binary — no sidecar, no external collector, no cargo feature for CPU sampling. (The one exception is heap attribution, an opt-in `mem-prof` diagnostic build — see [Heap attribution](#heap-attribution-the-mem-prof-build-and-debugpprofheap).) It works like Go's `net/http/pprof`: hit an endpoint, get a profile.

Both planes are covered:

| Plane | Endpoints | Auth |
| --- | --- | --- |
| Control plane (`pingwaf-server`) | `GET /api/v1/debug/pprof/{profile,flamegraph,memory,heap}`, `GET /api/v1/debug/pprof/cpu/{metrics,dashboard.svg,summary}` and `POST /api/v1/debug/pprof/cpu/summary/import` | Admin JWT bearer token |
| Data plane (pingap admin plugin) | `GET {admin-path}/api/pprof/{profile,flamegraph,memory}` | Admin plugin credentials |

`heap` exists only on the control plane and only in a `mem-prof` diagnostic
build (`501` otherwise) — see [Heap attribution](#heap-attribution-the-mem-prof-build-and-debugpprofheap).

In the console, administrators also find a **Performance diagnostics** card
under **Settings → About**. It leads with the aggregated server-side summary
([`cpu/summary`](#summary-endpoint-bounded-aggregated-readout)) — the live
CPU readout plus the last capture's hottest frames as KB-scale JSON, shown
directly in the card instead of downloading files. The full artifacts (CPU
profile, SVG flamegraph, memory snapshot) remain available as an explicit
export path.

## Endpoints

- `profile` — gzip-compressed pprof protobuf, the exact wire format `go tool pprof` expects. Sampling takes `seconds` (1-5, default 5 — the default is also the hard ceiling, so the window cannot be enlarged via query parameters) at `frequency` Hz (1-250, default 99 — off-round so the sampler does not lock onto periodic work).
- `flamegraph` — SVG flamegraph rendered by inferno; open it directly in a browser.
- `cpu/dashboard.svg` — self-contained SVG **dashboard** for one capture: the process CPU share over the window, the task distribution (top functions by inclusive sample share), the key metrics and a color-coded status badge (`NORMAL` / `HIGH LOAD` / `IDLE` / `PLATFORM-LIMITED`). Unlike the raw capture endpoints this degrades off-Linux: there it renders the live readout with a `PLATFORM-LIMITED` badge instead of answering `501`. With `?refresh=<1-60>` the SVG embeds a script that polls `cpu/metrics` and refreshes the live strip while the file is open in a browser; because the metrics endpoint is Bearer-only, the caller's own token is inlined into that poll (opt-in via the `refresh` parameter, `no-store`, and the dashboard prints a do-not-share warning on itself).
- `cpu/metrics` — cheap point-in-time CPU snapshot (process and host usage, core count) polled by the dashboard's refresh script; costs one sysinfo refresh, no sampling session. It also carries a `profiling` object (see [Capture audit and the enable switch](#capture-audit-and-the-enable-switch)).
- `cpu/summary` — the bounded aggregated readout the console and MCP consume: a live CPU snapshot plus the server-cached summary of the most recent capture, as one KB-scale JSON body with zero sampling overhead. See [Summary endpoint](#summary-endpoint-bounded-aggregated-readout).
- `cpu/summary/import` — `POST` a previously downloaded pprof protobuf (the `profile` wire format) to decode it into the same bounded summary. See [Legacy file import](#legacy-file-import).
- `memory` — JSON snapshot of process RSS and system RAM; returns immediately. `rss_bytes` is this process's footprint; `total_memory_bytes`/`used_memory_bytes` are the **host's** RAM (inside a container that is the host's total, not the container limit), marked by `used_memory_scope: "system"` vs `process_memory_scope: "process"`. Inside a memory-limited container the snapshot additionally carries the cgroup figures — `container_memory_used_bytes`/`container_memory_limit_bytes` with `container_memory_scope: "cgroup_v1" | "cgroup_v2"` — the same numbers `docker stats` reports; prefer them over the host totals when they are present. Show the process card from `rss_bytes`.

Sampling is process-global: a second concurrent capture gets `409 Conflict`. Report symbolisation runs off the async runtime, so a capture costs one sleeping request plus the CPU the sampler itself burns (~1% at 99 Hz).

The sampler fires on **process CPU time** (`SIGPROF` / `ITIMER_PROF`), not wall clock. A capture of an idle process therefore yields no samples: instead of an empty profile the endpoints answer `409 Conflict` with guidance — retry under load, or use the `memory` snapshot. A session whose CPU time grew by less than 1% of its wall-clock window is rejected the same way.

To profile an idle process anyway, append `?selfload=true` (accepted by `profile`, `flamegraph` and `cpu/dashboard.svg`; the console's Performance diagnostics card ships with the switch on). For exactly the capture window the server generates light in-process load — two tokio tasks doing short spin bursts between yields — so the time-based sampler has frames to catch. Keep expectations straight: a selfload profile shows the async runtime and this synthetic workload, **not** the site's business functions. It answers "does the capture pipeline work" and gives a runtime-level baseline; for *memory* attribution the right tool is the [heap endpoint](#heap-attribution-the-mem-prof-build-and-debugpprofheap), and for CPU attribution under real traffic, capture with traffic on.

## Capturing a profile

Control plane:

```bash
go tool pprof -http=: http://localhost:9080/api/v1/debug/pprof/profile?seconds=5
```

Data plane (profiling is served by the binary's own admin plugin, which is only
mounted when you pass `--admin`; replace `<admin-addr>` / `<admin-path>` with your
values — e.g. `127.0.0.1:3018` and `/admin` in `make dev` — and use `-H` or a
browser session for the plugin's auth):

```bash
curl -u admin:password \
  "http://<admin-addr>/<admin-path>/api/pprof/profile?seconds=5" -o pingwaf-cpu.pb.gz
go tool pprof -http=: pingwaf-cpu.pb.gz
```

Flamegraph without Go tooling:

```bash
curl -u admin:password \
  "http://<admin-addr>/<admin-path>/api/pprof/flamegraph?seconds=5" > flamegraph.svg
open flamegraph.svg
```

CPU dashboard on the control plane (self-contained SVG; append `&refresh=5`
to embed the live-refresh script, then open the file in a browser):

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9080/api/v1/debug/pprof/cpu/dashboard.svg?seconds=5&refresh=5" \
  > cpu-dashboard.svg
open cpu-dashboard.svg
```

The MCP `profile_cpu` tool returns the same dashboard inline (as the `svg`
field of its JSON result) together with the summary and reading notes;
repeated calls within 60 seconds replay the cached last capture, and
`cached=true` returns the last summary without starting a capture at all.

## Summary endpoint: bounded aggregated readout

`GET /api/v1/debug/pprof/cpu/summary` is the first-class performance
readout — the console's Performance diagnostics card and the MCP tool
consume it, and so can any admin client:

```json
{
  "live": {
    "process_cpu_percent": 12.5,
    "host_cpu_percent": 8.1,
    "cores": 4,
    "collected_at_ms": 1760000000000,
    "profiling": { "total_started": 2, "last": { "…": "…" } }
  },
  "last_capture": {
    "total_samples": 470,
    "frequency": 99,
    "window_secs": 5,
    "cpu_secs": 0.9,
    "process_cpu_fraction": 0.18,
    "top_frames": [
      { "name": "pingap_proxy::forward", "samples": 152, "share": 0.32 }
    ],
    "status": "normal",
    "collected_at_ms": 1760000000000
  }
}
```

(Values are illustrative; the shape is what the server returns.)

- `live` — the same point-in-time CPU snapshot `cpu/metrics` serves,
  including the `profiling` capture statistics.
- `last_capture` — the server's cached summary of the most recent capture,
  or `null` before the first completed capture since process start. The
  cache holds **only the latest** summary; every finished capture folds its
  result in — `profile`, `flamegraph`, `cpu/dashboard.svg` and
  `cpu/summary?capture=true` alike — including idle captures, which carry
  the `idle` status instead of failing. It is bounded by construction: the
  `top_frames` table is capped at the 10 hottest functions
  (`name` / `samples` / inclusive `share` of the window), `status` is
  `normal` | `high_load` | `idle` | `platform_limited`, and the whole body
  is KB-scale JSON. "What is running hot right now" becomes one cheap read,
  not a multi-megabyte SVG the browser cannot open.

Without query parameters the endpoint costs one `cpu/metrics`-style
snapshot and reads the cache — zero sampling overhead — and answers
normally even on a deployment with captures switched off, exactly like the
other read-only snapshots.

`?capture=true` runs a fresh capture first (accepting the usual
`seconds` / `frequency` / `selfload` parameters, `seconds` defaulting to
the 5-second ceiling) and returns the new summary. That is a real capture,
so it passes through the same [load guard](#load-guard) — a refusal
answers `503` and is audited as `load_guard` — and an idle window yields
an `idle`-status summary rather than the raw capture endpoints' `409`.
Whether this capture also honours the `pprof_enabled` switch: **yes** — when the switch is off, `capture=true` answers `503` with the same deployment-disabled message as the other capture endpoints (and is audited as such); the read-only no-capture path stays available.

## Loopback diagnostics listener

For `go tool pprof` / `jeprof` workflows, the server can expose the whole
pprof endpoint set on a loopback-only listener **without Bearer auth**.
Set the control-plane environment variable `PINGWAF_DEBUG_LISTEN_ADDR`
(for example `127.0.0.1:9091`) and restart. The same endpoints as
`/api/v1/debug/pprof/*` are then served on that address under
`/debug/pprof/...`:

```bash
go tool pprof -http=: http://127.0.0.1:9091/debug/pprof/profile?seconds=5
```

Security boundaries, enforced at startup:

- **Loopback only.** A non-loopback address is rejected — the server
  refuses to start rather than exposing unauthenticated debug endpoints
  (`127.0.0.1` or `::1` are the accepted bind targets; the loopback
  interface is the trust boundary).
- **No Bearer token on this listener.** Everything reachable on it is the
  debug endpoint set (`profile`, `flamegraph`, `heap`, `cpu/metrics`,
  `cpu/dashboard.svg`, `cpu/summary`, `cpu/summary/import`, `memory`);
  bind it only where every local process is trusted, and never route or
  expose it beyond the host. Default is **off**: nothing listens unless
  the variable is set.
- The main API listener keeps requiring the admin token for
  `/api/v1/debug/pprof/*`; this listener is an additional one, not a
  replacement.

## Legacy file import

Previously downloaded profiling files stay analysable inside the product:

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @pingwaf-cpu.pb.gz \
  "https://localhost:9080/api/v1/debug/pprof/cpu/summary/import"
```

`POST /api/v1/debug/pprof/cpu/summary/import` decodes a pprof protobuf
body — the exact wire format `GET /debug/pprof/profile` exports — into
the same bounded summary, without a browser or an external `go tool pprof`.
It is a stateless decode: it neither starts a capture nor changes the
server's last-capture cache. Weight semantics differ from a live capture
because pprof CPU profiles record per-sample values in CPU nanoseconds:

- `total_samples` and the per-frame `samples` weights are **CPU
  nanoseconds**, not sample counts; the proportional `share` values — what
  the console renders — are unaffected.
- `frequency` is reported as `0` (unknown), because it cannot be recovered
  from the file.

Malformed bodies answer with the profiling error envelope and are audited
like a failed capture.

## Symbols: build with `release-perf`

The default `release` profile strips debug symbols, so profiles from a `release` binary show mostly `Unknown` frames. For readable flame graphs:

```bash
make release-perf        # cargo build --profile=release-perf --features=perf
```

`release-perf` inherits `release` but keeps `debug = 1` and disables stripping. It is a diagnostics build — production still runs the stripped `release` binary; take the `release-perf` binary to the same environment when investigating.

### Prebuilt perf image

For Docker deployments there is an on-demand pipeline: run the **Release (perf image)** workflow (Actions → *Release (perf image)* → *Run workflow*) or:

```bash
gh workflow run release-perf.yml
```

It builds `Dockerfile.perf` (the same multi-stage build, `--profile release-perf`) and publishes `ghcr.io/shuaizend/pingwaf:perf` (amd64). Deploy it in place of the regular tag, reproduce the load, capture the profile, then switch back — the image is 2-4× larger and never enters the version manifests.

## Heap attribution: the `mem-prof` build and `/debug/pprof/heap`

A CPU flame graph answers "where does CPU time go". For "which function
allocates / retains memory" the tool is heap profiling, shipped as the
`mem-prof` cargo feature:

```bash
cargo build --profile=release-perf --features=mem-prof
```

`mem-prof` swaps the global allocator from mimalloc to tikv-jemallocator
(jemalloc with heap-profiling support). That changes allocator semantics
relative to the shipped images, so it is a diagnostic build, not a production
one — take the binary to the same environment when investigating, like
`release-perf`. Start the process with `MALLOC_CONF=prof:true` (jemalloc heap
profiling is sampled and off by default), then request the dump:

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:9080/api/v1/debug/pprof/heap" -o pingwaf-heap.prof
```

The endpoint triggers a jemalloc `prof.dump` and returns the jeprof-format
dump as an attachment — every live allocation path with its retained byte
count. Render it as a call graph with `jeprof` (ships with gperftools; any
build of the same source revision works for symbolisation):

```bash
jeprof --svg <binary> pingwaf-heap.prof > heap.svg
```

Behaviour notes:

- The endpoint is read-only like the `memory` snapshot — no sampling session,
  it answers immediately — but it is gated by the
  [debug-capture switch](#capture-audit-and-the-enable-switch): a deployment
  that turned captures off answers `503` for heap dumps too.
- On a build without `mem-prof` the endpoint answers `501 Not Implemented`,
  pointing at the `memory` snapshot for aggregate usage instead.
- The dump reflects the instant it was taken (`no-store`, no caching).
- Control plane only: the data-plane admin plugin serves the three CPU
  capture endpoints, not the heap dump.

## Reading the results

- Widest boxes are where CPU time goes; the box above is the caller.
- For the data plane the interesting frames are `pingwaf_waf` (rule evaluation), `pingap_proxy` (upstream forwarding) and `pingap_cache` (cache lookups).
- Compare a capture under load against one at idle; the delta is your hot path.

For continuous always-on profiling shipped to a server, see the Pyroscope integration (`pingap-pyroscope`, `--features=pyro`). The built-in endpoints are for on-demand investigation.

## Capture audit and the enable switch

Profiling captures are auditable. `GET /debug/pprof/cpu/metrics` includes a
`profiling` object with the capture statistics for this process lifetime:

```json
"profiling": {
  "total_started": 2,
  "last": { "finished_at_ms": 1760000000000, "duration_secs": 30.0, "outcome": "ok" }
}
```

- `total_started` — sampling sessions started since process start, including ones that failed or were abandoned.
- `last` — the most recently finished (or abandoned) session: `finished_at_ms` (Unix epoch ms), `duration_secs` (wall-clock window), and `outcome` — `ok` when a profile was produced, otherwise `idle`, `no_samples`, `report_error`, `abandoned`, `load_guard` (refused by the [load guard](#load-guard)) or `unsupported`.

Every capture also emits one structured INFO audit log line when it ends (success, rejection or abandonment):

```text
profiling capture finished endpoint=… outcome=… rss=…
```

`rss` is the process RSS right after the capture, so memory spikes can be correlated with capture activity.

Captures can be disabled per deployment with the `[basic] pprof_enabled`
configuration key in `conf/basic.toml` — a boolean, default `true`
(debug-capture mode on). The legacy `PINGWAF_PPROF_ENABLED=0` environment
variable (or `false`/`off`/`no`, case-insensitive) still works, but only as a
fallback honoured when the key is **not** set explicitly — the configuration
file wins. Changes require a restart.

When the switch is off, every CPU capture entry point answers `503 Service
Unavailable`: the three control-plane endpoints (`profile`, `flamegraph`,
`cpu/dashboard.svg`), the same capture endpoints on the data-plane admin
plugin, the MCP `profile_cpu` tool, and the
[heap endpoint](#heap-attribution-the-mem-prof-build-and-debugpprofheap). The
read-only snapshots stay available — `memory`, `cpu/metrics` and
`cpu/summary` (without `?capture=true`) answer normally with captures off,
which is exactly the view an operator needs when investigating without
sampling.

**Measured capture overhead:** on a v0.27.2 (mimalloc) container, completing two 30 s captures at 99 Hz left the process VmHWM at only 79 MB — **on an idle process** pprof capture itself does not cause memory spikes. (Those windows predate the current 5-second hard cap; smaller windows only shrink the exposure.) Under load the story is different (see [Load guard](#load-guard)). When investigating an OOM or memory spike, check the `profiling` field of `/debug/pprof/cpu/metrics` and the capture audit logs first to rule captures in or out before looking elsewhere.

## Load guard

Before a CPU capture starts (the `profile`, `flamegraph` and `cpu/dashboard.svg`
endpoints, `cpu/summary?capture=true` and the MCP `profile_cpu` tool alike),
the process CPU usage is checked — the single-core percentage from the same
live snapshot the dashboard polls. Above 40% of one core the capture is
refused:

- The HTTP endpoints answer `503 Service Unavailable` with the measured value
  and the limit: `the process is busy (CPU N% of one core, limit 40%); profiling under load risks an out-of-memory kill — retry when the load drops`.
- The MCP `profile_cpu` tool returns the equivalent error text.
- The audit log records `outcome=load_guard`.
- The read-only snapshots are **not** subject to the guard — `memory` and
  `cpu/metrics` keep answering normally on a busy process.
- The `?selfload=true` workload starts only after the guard has passed and is
  deliberately light (short spin bursts separated by sleeps), so opting in
  cannot mask a busy process from the guard.

The guard exists because the pprof-rs sampler allocates memory inside its
`SIGPROF` signal handler (a known design limitation of the crate). On an idle
process a capture is harmless (measured VmHWM 79 MB), but sampling a busy
process can inflate RSS from tens of MB to over 1 GB within 30-90 seconds
until the OOM killer strikes (observed twice on the demo instance on
2026-10-16).

> **Warning — profiling under load can OOM the process.** For production
> instances, keep the debug-capture switch off (`[basic] pprof_enabled =
> false`; legacy deployments `PINGWAF_PPROF_ENABLED=0`) and turn captures on
> temporarily, at low load, only while investigating. On the host, prefer
> `transparent_hugepage=madvise`; run the container with a memory limit
> (`mem_limit`) so a bad capture cannot take down the host.

## Platform support

CPU sampling runs on **Linux only**: there the sampling handler unwinds with pprof-rs's own signal-safe DWARF walker. On macOS the handler would have to unwind through libunwind, which is not async-signal-safe and can abort the process from inside the handler (tikv/pprof-rs#36), so the capture endpoints refuse to start there and answer `501 Not Implemented` instead of risking the process. The `memory` snapshot, `cpu/metrics` and the `cpu/dashboard.svg` degradation work on every platform.
