# PingWAF Profiling

PingWAF ships built-in pprof-style profiling in every binary — no sidecar, no external collector, no cargo feature. It works like Go's `net/http/pprof`: hit an endpoint, get a profile.

Both planes are covered:

| Plane | Endpoints | Auth |
| --- | --- | --- |
| Control plane (`pingwaf-server`) | `GET /api/v1/debug/pprof/{profile,flamegraph,memory}` and `GET /api/v1/debug/pprof/cpu/{metrics,dashboard.svg}` | Admin JWT bearer token |
| Data plane (pingap admin plugin) | `GET {admin-path}/api/pprof/{profile,flamegraph,memory}` | Admin plugin credentials |

In the console, administrators also find a **Performance diagnostics** card
under **Settings → About** that downloads the same three artifacts (CPU
profile, SVG flamegraph, memory snapshot) from the control-plane endpoints
without constructing the URLs by hand.

## Endpoints

- `profile` — gzip-compressed pprof protobuf, the exact wire format `go tool pprof` expects. Sampling takes `seconds` (1-120, default 30) at `frequency` Hz (1-1000, default 99 — off-round so the sampler does not lock onto periodic work).
- `flamegraph` — SVG flamegraph rendered by inferno; open it directly in a browser.
- `cpu/dashboard.svg` — self-contained SVG **dashboard** for one capture: the process CPU share over the window, the task distribution (top functions by inclusive sample share), the key metrics and a color-coded status badge (`NORMAL` / `HIGH LOAD` / `IDLE` / `PLATFORM-LIMITED`). Unlike the raw capture endpoints this degrades off-Linux: there it renders the live readout with a `PLATFORM-LIMITED` badge instead of answering `501`. With `?refresh=<1-60>` the SVG embeds a script that polls `cpu/metrics` and refreshes the live strip while the file is open in a browser; because the metrics endpoint is Bearer-only, the caller's own token is inlined into that poll (opt-in via the `refresh` parameter, `no-store`, and the dashboard prints a do-not-share warning on itself).
- `cpu/metrics` — cheap point-in-time CPU snapshot (process and host usage, core count) polled by the dashboard's refresh script; costs one sysinfo refresh, no sampling session.
- `memory` — JSON snapshot of process RSS and system RAM; returns immediately. `rss_bytes` is this process's footprint; `total_memory_bytes`/`used_memory_bytes` are the **host's** RAM (inside a container that is the host's total, not the container limit), marked by `used_memory_scope: "system"` vs `process_memory_scope: "process"`. Inside a memory-limited container the snapshot additionally carries the cgroup figures — `container_memory_used_bytes`/`container_memory_limit_bytes` with `container_memory_scope: "cgroup_v1" | "cgroup_v2"` — the same numbers `docker stats` reports; prefer them over the host totals when they are present. Show the process card from `rss_bytes`.

Sampling is process-global: a second concurrent capture gets `409 Conflict`. Report symbolisation runs off the async runtime, so a capture costs one sleeping request plus the CPU the sampler itself burns (~1% at 99 Hz).

The sampler fires on **process CPU time** (`SIGPROF` / `ITIMER_PROF`), not wall clock. A capture of an idle process therefore yields no samples: instead of an empty profile the endpoints answer `409 Conflict` with guidance — retry under load, or use the `memory` snapshot. A session whose CPU time grew by less than 1% of its wall-clock window is rejected the same way.

## Capturing a profile

Control plane:

```bash
go tool pprof -http=: http://localhost:9080/api/v1/debug/pprof/profile?seconds=30
```

Data plane (profiling is served by the binary's own admin plugin, which is only
mounted when you pass `--admin`; replace `<admin-addr>` / `<admin-path>` with your
values — e.g. `127.0.0.1:3018` and `/admin` in `make dev` — and use `-H` or a
browser session for the plugin's auth):

```bash
curl -u admin:password \
  "http://<admin-addr>/<admin-path>/api/pprof/profile?seconds=30" -o pingwaf-cpu.pb.gz
go tool pprof -http=: pingwaf-cpu.pb.gz
```

Flamegraph without Go tooling:

```bash
curl -u admin:password \
  "http://<admin-addr>/<admin-path>/api/pprof/flamegraph?seconds=30" > flamegraph.svg
open flamegraph.svg
```

CPU dashboard on the control plane (self-contained SVG; append `&refresh=5`
to embed the live-refresh script, then open the file in a browser):

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9080/api/v1/debug/pprof/cpu/dashboard.svg?seconds=10&refresh=5" \
  > cpu-dashboard.svg
open cpu-dashboard.svg
```

The MCP `profile_cpu` tool returns the same dashboard inline (as the `svg`
field of its JSON result) together with the summary and reading notes;
repeated calls within 60 seconds replay the cached last capture.

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

## Reading the results

- Widest boxes are where CPU time goes; the box above is the caller.
- For the data plane the interesting frames are `pingwaf_waf` (rule evaluation), `pingap_proxy` (upstream forwarding) and `pingap_cache` (cache lookups).
- Compare a capture under load against one at idle; the delta is your hot path.

For continuous always-on profiling shipped to a server, see the Pyroscope integration (`pingap-pyroscope`, `--features=pyro`). The built-in endpoints are for on-demand investigation.

## Platform support

CPU sampling runs on **Linux only**: there the sampling handler unwinds with pprof-rs's own signal-safe DWARF walker. On macOS the handler would have to unwind through libunwind, which is not async-signal-safe and can abort the process from inside the handler (tikv/pprof-rs#36), so the capture endpoints refuse to start there and answer `501 Not Implemented` instead of risking the process. The `memory` snapshot, `cpu/metrics` and the `cpu/dashboard.svg` degradation work on every platform.
