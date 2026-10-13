# PingWAF Profiling

PingWAF ships built-in pprof-style profiling in every binary — no sidecar, no external collector, no cargo feature. It works like Go's `net/http/pprof`: hit an endpoint, get a profile.

Both planes are covered:

| Plane | Endpoints | Auth |
| --- | --- | --- |
| Control plane (`pingwaf-server`) | `GET /api/v1/debug/pprof/{profile,flamegraph,memory}` | Admin JWT bearer token |
| Data plane (pingap admin plugin) | `GET {admin-path}/api/pprof/{profile,flamegraph,memory}` | Admin plugin credentials |

## Endpoints

- `profile` — gzip-compressed pprof protobuf, the exact wire format `go tool pprof` expects. Sampling takes `seconds` (1-120, default 30) at `frequency` Hz (1-1000, default 99 — off-round so the sampler does not lock onto periodic work).
- `flamegraph` — SVG flamegraph rendered by inferno; open it directly in a browser.
- `memory` — JSON snapshot of process RSS and system RAM; returns immediately.

Sampling is process-global: a second concurrent capture gets `409 Conflict`. Report symbolisation runs off the async runtime, so a capture costs one sleeping request plus the CPU the sampler itself burns (~1% at 99 Hz).

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

## Symbols: build with `release-perf`

The default `release` profile strips debug symbols, so profiles from a `release` binary show mostly `Unknown` frames. For readable flame graphs:

```bash
make release-perf        # cargo build --profile=release-perf --features=perf
```

`release-perf` inherits `release` but keeps `debug = 1` and disables stripping. It is a diagnostics build — production still runs the stripped `release` binary; take the `release-perf` binary to the same environment when investigating.

## Reading the results

- Widest boxes are where CPU time goes; the box above is the caller.
- For the data plane the interesting frames are `pingwaf_waf` (rule evaluation), `pingap_proxy` (upstream forwarding) and `pingap_cache` (cache lookups).
- Compare a capture under load against one at idle; the delta is your hot path.

For continuous always-on profiling shipped to a server, see the Pyroscope integration (`pingap-pyroscope`, `--features=pyro`). The built-in endpoints are for on-demand investigation.

## Platform support

CPU sampling runs on **Linux only**: there the sampling handler unwinds with pprof-rs's own signal-safe DWARF walker. On macOS the handler would have to unwind through libunwind, which is not async-signal-safe and can abort the process from inside the handler (tikv/pprof-rs#36), so the capture endpoints refuse to start there and answer `501 Not Implemented` instead of risking the process. The `memory` snapshot works on every platform.
