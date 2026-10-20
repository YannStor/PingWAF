# PingWAF System Observation & Attribution

PingWAF ships read-only self-observation in every binary: two admin endpoints
that report what the process is doing right now (CPU and memory) and where the
time goes (module and method attribution). There is no sampling, no stack
unwinding, no allocator hook, no sidecar and no diagnostic image to deploy —
everything works on every platform and in every build.

> **Migration from the removed pprof endpoints.** Earlier releases exposed
> pprof-style CPU sampling (`/api/v1/debug/pprof/*` and the data-plane
> `/api/pprof/*` routes), a `mem-prof` heap-dump build, the MCP
> `profile_cpu`/`profile_memory` tools, the `PINGWAF_DEBUG_LISTEN_ADDR`
> loopback listener and the `pprof_enabled` / `PINGWAF_PPROF_ENABLED` switches.
> All of that has been **removed**. The observation half lives on as
> `/api/v1/system/metrics`; the attribution half is replaced by
> `/api/v1/system/profile`, whose accounting approach is deliberately different
> — see [What changed vs. pprof](#what-changed-vs-pprof) for the mapping.

Both endpoints require an admin JWT bearer token (the same `AdminUser`
authentication as the rest of the API).

## `GET /api/v1/system/metrics`

A point-in-time snapshot of process/host CPU and memory. No capture session,
no state: the handler reads counters the OS already keeps (`/proc` or the
platform equivalent, via a blocking task so the async workers are not stalled)
and answers immediately.

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:9080/api/v1/system/metrics"
```

**Response (200):**

```json
{
  "cpu": {
    "process_cpu_percent": 12.5,
    "host_cpu_percent": 8.1,
    "cores": 4,
    "collected_at_ms": 1760000000000
  },
  "memory": {
    "rss_bytes": 120258048,
    "virtual_bytes": 805984256,
    "total_memory_bytes": 17179869184,
    "used_memory_bytes": 9663676416,
    "rss": "121.2 MB",
    "total_memory": "16.0 GB",
    "used_memory": "9.0 GB",
    "collected_at_ms": 1727443200000,
    "used_memory_scope": "system",
    "process_memory_scope": "process",
    "container_memory_used_bytes": 805306368,
    "container_memory_limit_bytes": 1073741824,
    "container_memory_used": "805.3 MB",
    "container_memory_limit": "1.0 GB",
    "container_memory_scope": "cgroup_v2",
    "rss_peak_bytes": 154140467,
    "rss_peak": "154.1 MB",
    "swap_used_bytes": 0,
    "swap_total_bytes": 2147483648,
    "swap_used": "0 B",
    "swap_total": "2.0 GB",
    "mem_available_bytes": 6442450944,
    "mem_available": "6.0 GB",
    "memory_used_percent": 56.3,
    "page_faults_minor": 482113,
    "page_faults_major": 1024,
    "cached_bytes": 3221225472,
    "buffers_bytes": 268435456,
    "cached": "3.0 GB",
    "buffers": "256.0 MB"
  }
}
```

(Values are illustrative; the shape is what the server returns.)

### `cpu` — process and machine CPU

| Field | Meaning |
| --- | --- |
| `process_cpu_percent` | This process's CPU usage in percent of one core (multi-threaded work can exceed 100) |
| `host_cpu_percent` | Average CPU usage across all machine cores, in percent |
| `cores` | Number of CPU cores on the machine |
| `collected_at_ms` | Unix epoch milliseconds at which the snapshot was taken |

### `memory` — process RSS, host RAM and container accounting

| Field | Meaning |
| --- | --- |
| `rss_bytes` / `rss` | This process's resident memory (bytes / human-readable) — use this for the process card |
| `virtual_bytes` | This process's virtual memory, bytes |
| `total_memory_bytes` / `total_memory` | **Host** RAM total (inside a container this is the host's total, not the container limit) |
| `used_memory_bytes` / `used_memory` | **Host** RAM in use |
| `used_memory_scope` / `process_memory_scope` | Scope labels: `"system"` for the host figures, `"process"` for `rss` |
| `container_memory_used_bytes` / `container_memory_limit_bytes` | cgroup usage and limit, present **only** when a container memory limit applies (`null` otherwise) |
| `container_memory_used` / `container_memory_limit` | Human-readable container usage and limit |
| `container_memory_scope` | Which cgroup version produced the container numbers (`"cgroup_v1"` / `"cgroup_v2"`) |
| `rss_peak_bytes` / `rss_peak` | Peak process RSS since process start, `/proc/self/status` `VmHWM` (bytes / human-readable) — `0` when the counter is unavailable (non-Linux) |
| `swap_used_bytes` / `swap_used` | Swap in use: `/proc/meminfo` `SwapTotal` − `SwapFree` — `0` on hosts with swap disabled |
| `swap_total_bytes` / `swap_total` | Configured swap, `/proc/meminfo` `SwapTotal` |
| `mem_available_bytes` / `mem_available` | Memory the kernel estimates as available for new work without swapping, `/proc/meminfo` `MemAvailable` (kernel 3.14+; `0` before that) |
| `memory_used_percent` | `used_memory_bytes / total_memory_bytes * 100`, one decimal place; carries the host (`"system"`) scope |
| `page_faults_minor` | Minor page faults (served without I/O), cumulative for the process — `/proc/self/stat` field 10 |
| `page_faults_major` | Major page faults (required I/O), cumulative for the process — `/proc/self/stat` field 12 |
| `cached_bytes` / `cached` | Page cache excluding swap cache, `/proc/meminfo` `Cached` |
| `buffers_bytes` / `buffers` | Block-device buffers, `/proc/meminfo` `Buffers` |

The fields above are read from `/proc` (or the cgroup equivalent); a counter
the platform does not expose is reported as `0`.

When the container fields are present they match what `docker stats` reports
and should be preferred over the host totals.

The cost is one CPU/memory refresh of the system tables — cheap enough for a
polling dashboard, and there is no enable switch: it is an ordinary admin
endpoint that works in every build.

## `GET /api/v1/system/profile`

Wall-clock time and memory attribution by module and method. This is **not**
a sampled profile — it is pure Rust instrumentation (`pingwaf-profiler`): the
code that knows what it is doing accounts for itself.

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:9080/api/v1/system/profile"
```

**Response (200):**

```json
{
  "collected_at_ms": 1760000000000,
  "total_cpu_ms": 48213.4,
  "total_elapsed_ms": 48213.4,
  "modules": [
    { "module": "proxy",   "cpu_ms": 30102.1, "cpu_share": 0.62, "elapsed_ms": 30102.1, "elapsed_share": 0.62, "mem_bytes": 41943040, "mem_share": 0.55, "disk_bytes": 0,        "disk_share": 0.00, "calls": 102341, "avg_us": 294.1 },
    { "module": "waf",     "cpu_ms": 11101.2, "cpu_share": 0.23, "elapsed_ms": 11101.2, "elapsed_share": 0.23, "mem_bytes": 8388608,  "mem_share": 0.11, "disk_bytes": 0,        "disk_share": 0.00, "calls": 98111,  "avg_us": 113.1 },
    { "module": "cache",   "cpu_ms": 4000.8,  "cpu_share": 0.08, "elapsed_ms": 4000.8,  "elapsed_share": 0.08, "mem_bytes": 15728640, "mem_share": 0.21, "disk_bytes": 734003200, "disk_share": 1.00, "calls": 44120,  "avg_us": 90.7 },
    { "module": "plugin",  "cpu_ms": 1500.1,  "cpu_share": 0.03, "elapsed_ms": 1500.1,  "elapsed_share": 0.03, "mem_bytes": 2097152,  "mem_share": 0.03, "disk_bytes": 0,        "disk_share": 0.00, "calls": 30112,  "avg_us": 49.8 },
    { "module": "db",      "cpu_ms": 1000.6,  "cpu_share": 0.02, "elapsed_ms": 1000.6,  "elapsed_share": 0.02, "mem_bytes": 1048576,  "mem_share": 0.01, "disk_bytes": 0,        "disk_share": 0.00, "calls": 2140,   "avg_us": 467.6 },
    { "module": "control", "cpu_ms": 400.2,   "cpu_share": 0.01, "elapsed_ms": 400.2,   "elapsed_share": 0.01, "mem_bytes": 524288,   "mem_share": 0.01, "disk_bytes": 0,        "disk_share": 0.00, "calls": 980,    "avg_us": 408.4 },
    { "module": "other",   "cpu_ms": 108.4,   "cpu_share": 0.00, "elapsed_ms": 108.4,   "elapsed_share": 0.00, "mem_bytes": 0,        "mem_share": 0.00, "disk_bytes": 0,        "disk_share": 0.00, "calls": 210,    "avg_us": 516.2 }
  ],
  "methods": [
    { "method": "waf::handle_request",   "cpu_ms": 9200.4, "elapsed_ms": 9200.4, "calls": 98111, "avg_us": 93.8 },
    { "method": "proxy::request_filter", "cpu_ms": 7100.9, "elapsed_ms": 7100.9, "calls": 88430, "avg_us": 80.3 }
  ]
}
```

(Values are illustrative.)

### 口径 — what the numbers are, and what they are not

- **Wall time, not CPU time.** Every timer is `Instant`-based, so it
  measures the elapsed time spent inside the timed scope. A scope that
  awaits a database query, a lock or the upstream reports that wait too;
  when the executor deschedules the task the clock keeps running. Treat
  every share as "of the attributed wall time", not "of the CPU the process
  burned" — reading `cpu_ms` as CPU seconds is the mistake that once made
  `control::http` look like 90 % CPU when it was mostly waiting.
- **`cpu_*` is a deprecated alias of `elapsed_*`.** The snapshot publishes
  each figure twice: under the historical `cpu_ms` / `cpu_share` names —
  kept so existing dashboards keep parsing — and under `elapsed_ms` /
  `elapsed_share`, which say what is measured. Both pairs always carry the
  same value (`total_cpu_ms` == `total_elapsed_ms`). New consumers should
  use `elapsed_*`.
- **Instrumentation scope.** The seven module rows are fed by timers on
  instrumented hot paths — the data-plane request pipeline, WAF evaluation,
  cache and rewrite rules, plus two control-plane scopes (the agent
  heartbeat persistence and `/api/v1` requests). The `/api/v1` timer sits
  *inside* the CORS, compression, security-header and body-limit layers, so
  those middleware costs are not part of the `control` row. The same timer
  fills both the `control` module row and the `control::http` method row.
  The module row was never recorded twice: before the refactor the module
  timer and the method timer each wrote their own row, one entry per
  request. If `control` drops noticeably after upgrading, the real causes
  are the narrowed instrumentation scope (root listener → `/api/v1`
  requests only, so MCP, `/healthz` and the SPA fallback are no longer
  attributed) and the removal of a per-request method-map hash — not a
  sudden performance change.
- **Method names are a compile-time static enumeration.** The instrumented
  call sites are fixed at build time (`proxy::request_filter`,
  `waf::handle_request`, `cache::handle_request`, `plugin::rewrite`,
  `db::persist_heartbeat`, `control::http`); recording is array indexing
  plus four relaxed atomic adds per request (two for the method rows, two
  for the module row) — no hash lookup, no allocation.
  A method that never ran gets no row.

### How attribution works

- **Modules** — the process's functional areas are recorded in a fixed array
  of atomics. Every instrumented scope adds its elapsed time to its module
  with one `fetch_add`; the seven modules always appear in the response:
  `proxy`, `waf`, `cache`, `plugin`, `db`, `control`, `other` (anything not
  yet instrumented).
- **Methods** — named call sites are timed with `timed_method`. The set of
  call sites is a compile-time static enumeration (see
  [口径](#口径--what-the-numbers-are-and-what-they-are-not)), so recording
  is four relaxed atomic adds per request (two for the method rows, two
  for the module row) — no hash lookup, no allocation.
- **Memory** — *reported*, not intercepted. Modules that own large structures
  (cache capacity, WAF body buffers, log batches) publish their current byte
  count; nothing hooks the allocator, so this works with any allocator and on
  any platform. `mem_bytes` is "bytes currently held **in memory**", not
  cumulative allocation.
- **Disk** — *reported*, same mechanism, separate figure. `disk_bytes` is the
  module's on-disk footprint and is published only by the cache module; every
  other module reports `0`. See
  [Memory vs. disk in the cache module](#memory-vs-disk-in-the-cache-module).

### Memory vs. disk in the cache module

The `cache` row is the only one that reports both figures, and the two must
not be read as one number:

- **`mem_bytes` — real memory**: the on-disk index structures **plus**
  `in_flight_bytes`, the read buffers of objects currently being served out
  of the cache. A cache that stores everything on disk should not make the
  process look like it holds every cached byte in RAM.
- **`disk_bytes` — disk footprint**: what the cache backend currently
  occupies on its storage directory. Unbounded by the process's memory; the
  quota (if configured) applies to this figure, not to `mem_bytes`.

**Why the split exists.** Earlier releases published the backend's
`current_size` — the **disk** footprint — through the memory gauge, so the
`cache` module row reported disk usage as memory. A file-backed cache of a
few GiB read as a few GiB of RSS and the module table misranked the memory
hotspots. The fix moved the disk figure to its own gauge
(`disk_bytes` / `disk_share`); `mem_bytes` now counts index + in-flight
buffers only.

**Streaming reads and `in_flight_bytes`.** Objects larger than the inline
threshold (256 KiB) are never read fully into memory on a hit: the backend
hands back an open file handle and the body is streamed to the client in
64 KiB chunks (pingora writes each chunk downstream before the next is
read). While the hit is being served, `in_flight_bytes` carries the chunk
budget (plus inline objects being read); when the read finishes — success
or error — an RAII guard releases it, so `in_flight_bytes` returns to zero
and does not leak. Small objects stay inline (single buffer, same RAII
release). A plain miss charges nothing.

### Cache storage directory and its memory impression

The cache plugin's `directory` configuration key decides whether the cache
is file-backed or in-memory:

- **Unset** now defaults to **`/tmp/pingwaf-cache`** (a file-backed cache).
  Earlier releases defaulted to the in-memory backend, so an upgrade changes
  behaviour for every config that never set the key: the cache's bytes move
  from the process's memory (`mem_bytes` / RSS) to the storage directory,
  where the `cache` module row reports them as `disk_bytes`.
- **`directory = ""` or `memory://`** still selects the in-memory backend —
  this is how every config written before the default existed keeps its
  semantics.

> **Containers: `/tmp` is often tmpfs.** Inside a container `/tmp` commonly
> is a tmpfs mount — a file-backed cache under it then consumes **memory**
> (it counts against the container's memory limit) and disappears with the
> container. In production either mount a real volume at the cache directory
> or point `directory` at a persistent path (e.g.
> `directory = "/var/lib/pingwaf/cache"`).

### Response fields

| Field | Meaning |
| --- | --- |
| `collected_at_ms` | Unix epoch milliseconds at which the snapshot was taken |
| `total_cpu_ms` / `total_elapsed_ms` | Total wall-clock time attributed across all modules, in milliseconds (always equal; `total_elapsed_ms` is the name that matches the measurement) |
| `modules` | Exactly 7 rows, one per module, in fixed order (`proxy`, `waf`, `cache`, `plugin`, `db`, `control`, `other`) |
| `modules[].module` | Module key |
| `modules[].cpu_ms` / `elapsed_ms` | Cumulative **wall-clock** time attributed to the module (ms); the two fields always carry the same value |
| `modules[].cpu_share` / `elapsed_share` | Share of the total attributed wall-clock time, 0.0–1.0 |
| `modules[].mem_bytes` / `mem_share` | Bytes the module currently reports as held in memory, and its share of the total |
| `modules[].disk_bytes` / `disk_share` | Bytes the module currently occupies on disk, and its share of the total — reported only by the cache module (`0` elsewhere) |
| `modules[].calls` / `avg_us` | Number of timed operations and average microseconds per operation |
| `methods` | Method rows, hottest first, capped at 40 |
| `methods[].method` | Call-site name (from the compile-time static enumeration) |
| `methods[].cpu_ms` / `elapsed_ms` / `calls` / `avg_us` | Same semantics as the module rows |

Counters are **cumulative since process start** (they reset only when the
process restarts), so read them as "where has the time gone since boot",
not "what is hot this second". For a live question, take two snapshots some
seconds apart and compare the deltas of `elapsed_ms` (`cpu_ms` is the same
number) — the largest positive delta is your current hotspot. Typical
interesting rows: `waf` (rule evaluation), `proxy` (upstream forwarding),
`cache` (cache lookups).

### Overhead

Recording is a few relaxed atomic adds per instrumented scope (four per
request: two for the method rows, two for the module row): no sampling signal, no stack
unwinding, no symbolisation, no allocation and no hash lookup on the hot
path — method slots are fixed array entries. The same accounting works in a
debug build on a
laptop and a stripped release build in a container, which is why the endpoint
has no platform restriction, no feature flag and no diagnostic image. The
endpoint itself is bounded by construction — 7 module rows, at most 40 method
rows, KB-scale JSON — and computed from atomics, so polling it is cheap.

## What changed vs. pprof

| Removed | Replacement |
| --- | --- |
| `GET /api/v1/debug/pprof/{profile,flamegraph,memory,heap}`, `.../cpu/{metrics,dashboard.svg,summary}`, `POST .../cpu/summary/import` | `GET /api/v1/system/metrics` (CPU + memory snapshot) and `GET /api/v1/system/profile` (attribution) |
| Data-plane admin routes `GET {admin-path}/api/pprof/*` | Same two endpoints on the control plane |
| MCP tools `profile_cpu` / `profile_memory` | Read the two endpoints directly from any admin client |
| Loopback diagnostics listener (`PINGWAF_DEBUG_LISTEN_ADDR`) | Removed with the endpoints it served |
| `[basic] pprof_enabled` / `PINGWAF_PPROF_ENABLED` switches | No switch exists — the observation endpoints are ordinary admin endpoints |
| `mem-prof` cargo feature and `Dockerfile.memprof` | No diagnostic image needed; attribution works in the shipped binary. The `release-perf` build and the `Dockerfile.perf` image remain for out-of-band profiling with external tools |

What you lose and where to go instead:

- **Per-function flame graphs / stack samples.** Not available anywhere
  anymore. Use `/system/profile`'s module and method tables: they answer
  "which functional area and which instrumented hot path dominates", which is
  the question the old summary endpoint was reduced to anyway.
- **jemalloc heap dumps (`mem-prof`).** Not available. Use
  `memory.rss_bytes` and the per-module `mem_bytes` gauges to see *how much*
  each subsystem holds; for *which code allocates*, use an external profiler
  attached out of band (e.g. `valgrind`/`heaptrack` on a non-production
  replica).
- **`go tool pprof` files.** The endpoints no longer produce pprof protobufs;
  there is nothing to import (the old `summary/import` endpoint is gone).

For continuous always-on profiling shipped to a server, the Pyroscope
integration (`pingap-pyroscope`, `--features=pyro`) still exists — it is
independent of the removed endpoints.
