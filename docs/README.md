# PingWAF Documentation

Welcome to the PingWAF documentation index. PingWAF is a distributed,
centrally-controlled Web Application Firewall built on
[`pingap`](https://github.com/vicanso/pingap) and Cloudflare
[`Pingora`](https://github.com/cloudflare/pingora).

> Project home: [`README.md`](../README.md) · [中文](../README_zh.md)

## 🚀 Getting started

| Document | What you'll find |
| --- | --- |
| [quick-start.md](./quick-start.md) | From zero to your first protected site: prerequisites, install, first run |
| [deployment.md](./deployment.md) | Docker Compose, binary + systemd, and distributed (server + agents) topologies |
| [user-guide.md](./user-guide.md) | Dashboard walkthrough — sites, rules, policies, IP access, rate limiting |
| [http-lifecycle.md](./http-lifecycle.md) | Where every feature acts in the request pipeline — the WAF check order, caching, error pages, and how to debug with it |
| [api.md](./api.md) | REST API reference (base URL `https://<host>:9080/api/v1`) |
| [ai-crawl.md](./ai-crawl.md) | AI Crawl Control — crawler families, per-site policy, generated robots.txt / llms.txt |
| [profiling.md](./profiling.md) | System observation and attribution: `/system/metrics` CPU/memory snapshots, `/system/profile` module/method attribution |

## 🧭 Project & community

| Document | What you'll find |
| --- | --- |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute — setup, workflow, code style |
| [SECURITY.md](../SECURITY.md) | Vulnerability disclosure policy |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Community guidelines |
| [LICENSE](../LICENSE) | Apache License 2.0 |

## 🏗️ Architecture at a glance

```
Client ──HTTP/HTTPS──► Data-plane Agent (:80/:443)
                              │  gRPC bidi streams (rules / logs / metrics)
                              ▼
                    Control-plane Server
                    ├─ REST API + Dashboard (:9080, HTTPS)
                    ├─ gRPC ControlPlane    (:9090)
                    ├─ PostgreSQL (state)
                    └─ Elasticsearch (logs, optional)
```

Run everything in one process with `all-in-one`, or split the control plane
(`server`) from one or many edge agents (`agent`).

## 📦 Crate documentation

PingWAF adds six WAF-specific crates on top of the `pingap` proxy foundation.

**WAF crates:**

| Crate | What it does |
| --- | --- |
| [pingwaf-proto](../pingwaf-proto) | Control-plane gRPC protocol definitions (single source: `control_plane.proto`) |
| [pingwaf-server](../pingwaf-server) | Control plane: Axum REST + tonic gRPC + SeaORM/PostgreSQL + ES logs + embedded frontend + agent health monitoring |
| [pingwaf-agent](../pingwaf-agent) | Data-plane agent: connects to the control plane, caches rules with disk persistence, ships logs/metrics, receives commands |
| [pingwaf-waf](../pingwaf-waf) | Detection engine: normalize → signatures → expression → anomaly score |
| [pingwaf-challenge](../pingwaf-challenge) | Dynamic challenges: JS 5-second shield, interactive challenge, PoW, fingerprinting, HMAC clearance cookies |
| `pingwaf-profiler` (no README) | Module/method CPU and memory attribution tables served at `/api/v1/system/profile` |
| `pingwaf-system` (no README) | Process/host CPU snapshots and memory/cgroup accounting served at `/api/v1/system/metrics` |

**Proxy foundation (`pingap-*`) — each crate has its own README** describing what
it owns, how it is configured and where it sits in the dependency graph:

| Crate | What it does |
| --- | --- |
| [pingap-util](../pingap-util/README.md) | Crypto, IP rules, PEM/base64, path and formatting helpers |
| [pingap-core](../pingap-core/README.md) | `Ctx`, `HttpResponse`, the `Plugin` trait, background services, clock helpers |
| [pingap-config](../pingap-config/README.md) | Configuration model, storage backends, TOML/HCL/KDL |
| [pingap-discovery](../pingap-discovery/README.md) | Static / DNS / Docker / transparent backend discovery |
| [pingap-health](../pingap-health/README.md) | TCP, HTTP(S), gRPC, WS and WSS health checks |
| [pingap-upstream](../pingap-upstream/README.md) | Load balancing, circuit breaking, upstream connection options |
| [pingap-location](../pingap-location/README.md) | Host/path matching, rewriting, per-location limits |
| [pingap-certificate](../pingap-certificate/README.md) | SNI-based dynamic TLS certificate store |
| [pingap-acme](../pingap-acme/README.md) | Let's Encrypt HTTP-01 and DNS-01 automation |
| [pingap-cache](../pingap-cache/README.md) | Memory (TinyUFO) and file cache backends |
| [pingap-plugin](../pingap-plugin/README.md) | Built-in plugins — see the [plugin index](../pingap-plugin/README.md#plugin-index) |
| [pingap-imageoptim](../pingap-imageoptim/README.md) | PNG/JPEG → WebP/AVIF conversion |
| [pingap-logger](../pingap-logger/README.md) | Access logs, file/syslog writers, rotation and compression |
| [pingap-performance](../pingap-performance/README.md) | Prometheus metrics and process introspection |
| [pingap-otel](../pingap-otel/README.md) | OpenTelemetry distributed tracing |
| [pingap-sentry](../pingap-sentry/README.md) | Sentry error reporting |
| [pingap-pyroscope](../pingap-pyroscope/README.md) | Continuous CPU profiling |
| [pingap-webhook](../pingap-webhook/README.md) | Operational notifications to WeCom / DingTalk / HTTP |
| [pingap-proxy](../pingap-proxy/README.md) | The proxy engine: lifecycle, routing, server configuration |

## 🔌 Plugin documentation

Every plugin has a page covering its configuration keys, worked examples and the
caveats worth knowing before you deploy it:
[pingap-plugin/docs](../pingap-plugin/README.md#plugin-index).

## 🌐 Reference material

- [acme_chart.md](./acme_chart.md) — ACME / Let's Encrypt issuance flow.
- [modules.md](./modules.md) — module map of the workspace.
- **Chinese translations** — [zh/](./zh/) (home, plugins, crates, guide, [http-lifecycle](./zh/http-lifecycle.md)).
