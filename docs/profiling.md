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
    "container_memory_scope": "cgroup_v2"
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

When the container fields are present they match what `docker stats` reports
and should be preferred over the host totals.

The cost is one CPU/memory refresh of the system tables — cheap enough for a
polling dashboard, and there is no enable switch: it is an ordinary admin
endpoint that works in every build.

## `GET /api/v1/system/profile`

CPU and memory attribution by module and method. This is **not** a sampled
profile — it is pure Rust instrumentation (`pingwaf-profiler`): the code that
knows what it is doing accounts for itself.

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:9080/api/v1/system/profile"
```

**Response (200):**

```json
{
  "collected_at_ms": 1760000000000,
  "total_cpu_ms": 48213.4,
  "modules": [
    { "module": "proxy",   "cpu_ms": 30102.1, "cpu_share": 0.62, "mem_bytes": 41943040, "mem_share": 0.55, "calls": 102341, "avg_us": 294.1 },
    { "module": "waf",     "cpu_ms": 11101.2, "cpu_share": 0.23, "mem_bytes": 8388608,  "mem_share": 0.11, "calls": 98111,  "avg_us": 113.1 },
    { "module": "cache",   "cpu_ms": 4000.8,  "cpu_share": 0.08, "mem_bytes": 15728640, "mem_share": 0.21, "calls": 44120,  "avg_us": 90.7 },
    { "module": "plugin",  "cpu_ms": 1500.1,  "cpu_share": 0.03, "mem_bytes": 2097152,  "mem_share": 0.03, "calls": 30112,  "avg_us": 49.8 },
    { "module": "db",      "cpu_ms": 1000.6,  "cpu_share": 0.02, "mem_bytes": 1048576,  "mem_share": 0.01, "calls": 2140,   "avg_us": 467.6 },
    { "module": "control", "cpu_ms": 400.2,   "cpu_share": 0.01, "mem_bytes": 524288,   "mem_share": 0.01, "calls": 980,    "avg_us": 408.4 },
    { "module": "other",   "cpu_ms": 108.4,   "cpu_share": 0.00, "mem_bytes": 0,        "mem_share": 0.00, "calls": 210,    "avg_us": 516.2 }
  ],
  "methods": [
    { "method": "waf::evaluate",     "cpu_ms": 9200.4, "calls": 98111, "avg_us": 93.8 },
    { "method": "proxy::forward",    "cpu_ms": 7100.9, "calls": 88430, "avg_us": 80.3 }
  ]
}
```

(Values are illustrative.)

### How attribution works

- **Modules** — the process's functional areas are recorded in a fixed array
  of atomics. Every instrumented scope adds its elapsed time to its module
  with one `fetch_add`; the seven modules always appear in the response:
  `proxy`, `waf`, `cache`, `plugin`, `db`, `control`, `other` (anything not
  yet instrumented).
- **Methods** — named call sites (e.g. `"proxy::forward"`, `"waf::evaluate"`)
  are timed with `timed_method` and kept in a concurrent map. Only the hot
  paths are instrumented, since a map lookup is the expensive part.
- **Memory** — *reported*, not intercepted. Modules that own large structures
  (cache capacity, WAF body buffers, log batches) publish their current byte
  count; nothing hooks the allocator, so this works with any allocator and on
  any platform. `mem_bytes` is "bytes currently held", not cumulative
  allocation.

### Response fields

| Field | Meaning |
| --- | --- |
| `collected_at_ms` | Unix epoch milliseconds at which the snapshot was taken |
| `total_cpu_ms` | Total CPU time attributed across all modules, in milliseconds |
| `modules` | Exactly 7 rows, one per module, in fixed order (`proxy`, `waf`, `cache`, `plugin`, `db`, `control`, `other`) |
| `modules[].module` | Module key |
| `modules[].cpu_ms` | Cumulative CPU time attributed to the module (ms) |
| `modules[].cpu_share` | Share of `total_cpu_ms`, 0.0–1.0 |
| `modules[].mem_bytes` / `mem_share` | Bytes the module currently reports as held, and its share of the total |
| `modules[].calls` / `avg_us` | Number of timed operations and average microseconds per operation |
| `methods` | Method rows, hottest first, capped at 40 |
| `methods[].method` | Call-site name |
| `methods[].cpu_ms` / `calls` / `avg_us` | Same semantics as the module rows |

Counters are **cumulative since process start** (they reset only when the
process restarts), so read them as "where has the time gone since boot",
not "what is hot this second". For a live question, take two snapshots some
seconds apart and compare the deltas of `cpu_ms` — the largest positive delta
is your current hotspot. Typical interesting rows: `waf` (rule evaluation),
`proxy` (upstream forwarding), `cache` (cache lookups).

### Overhead

Recording is a few relaxed atomic adds per instrumented scope: no sampling
signal, no stack unwinding, no symbolisation, no allocation on the hot path
beyond the method map lookup. The same accounting works in a debug build on a
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
