<div align="center">

# 🛡️ PingWAF

**A distributed, centrally-controlled Web Application Firewall built on [`pingap`](https://github.com/vicanso/pingap) and Cloudflare [`Pingora`](https://github.com/cloudflare/pingora).**

Semantic-grade attack detection · Cloudflare-style rules · CC & Bot defense · Automatic TLS · Embedded i18n dashboard

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/shuaiZend/PingWAF/actions/workflows/ci.yml/badge.svg)](https://github.com/shuaiZend/PingWAF/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/docker-compose%20ready-2496ED?logo=docker&logoColor=white)](./docker-compose.yml)

**[English](./README.md) | [简体中文](./README_zh.md) | [Español](./README_es.md) | [Français](./README_fr.md)**

[Quick Start](#-quick-start) · [Architecture](#-architecture) · [Features](#-features) · [Documentation](#-documentation) · [Contributing](./CONTRIBUTING.md)

</div>

---

## 📖 What is PingWAF?

**PingWAF** is a high-performance, open-source **Web Application Firewall (WAF)** that brings Cloudflare-class edge security to your own infrastructure. It is built on top of [`pingap`](https://github.com/vicanso/pingap) — a production reverse proxy powered by Cloudflare's [`Pingora`](https://github.com/cloudflare/pingora) networking framework — and adds a **distributed, centrally-controlled** security layer over it.

A single **control plane** defines sites, rules and policies; one or many **data-plane agents** enforce them at the edge. Rules, logs and metrics flow between the two over persistent **gRPC bidirectional streams**, so a policy change made in the dashboard propagates to every agent in seconds — no reload, no downtime.

- 🎯 **Semantic detection** — SQLi / XSS / RCE / path traversal / command injection via `libinjection` + Aho-Corasick signature matching, anomaly scoring and Cloudflare-style expression rules.
- 🕸️ **Distributed by design** — run everything in one process (`all-in-one`), or scale the data plane out to many independent edge agents (`server` + `agent`).
- 🧭 **Batteries included, off by default** — every protection feature ships disabled and is enabled per site, so you stay in full control of your traffic.
- ⚡ **Rust all the way down** — memory safety, async I/O and a single self-contained binary with the dashboard embedded.

> PingWAF is an independent project. It is not affiliated with, nor endorsed by, Cloudflare or the `pingap` maintainers. See [Acknowledgements](#-acknowledgements).

---

## 🏗️ Architecture

```mermaid
graph TB
    Client[Client / Browser]

    subgraph ControlPlane["Control Plane (pingwaf server)"]
        Dashboard[Embedded Dashboard + REST API :9080]
        GRPC[gRPC ControlPlane service :9090]
        PG[(PostgreSQL 14+)]
        ES[(Elasticsearch - optional)]
    end

    subgraph DataPlane["Data Plane (pingwaf agents)"]
        AgentA[Edge Agent A :80 / :443]
        AgentB[Edge Agent B :80 / :443]
    end

    Origin[Origin / Upstream servers]

    Client -->|HTTP / HTTPS| AgentA
    Client -->|HTTP / HTTPS| AgentB
    AgentA <-->|gRPC bidi streams| GRPC
    AgentB <-->|gRPC bidi streams| GRPC
    Dashboard --> PG
    GRPC --> PG
    GRPC --> ES
    AgentA -->|safe traffic| Origin
    AgentB -->|safe traffic| Origin
```

The control plane and the data plane talk over the `ControlPlane` gRPC service (defined in [`control_plane.proto`](./pingwaf-proto/proto/control_plane.proto)) with seven RPCs:

| RPC | Kind | Purpose |
| --- | --- | --- |
| `RegisterAgent` | Unary | An agent joins the fleet and receives its ID + heartbeat interval |
| `Heartbeat` | Bidirectional stream | Liveness, stats and per-site certificate status upstream; live commands downstream |
| `SyncRules` | Server stream | Rule bundles pushed to agents whenever policy changes |
| `ShipLogs` | Client stream | Batched request/attack logs streamed to the control plane |
| `ShipCertEvents` | Client stream | ACME issuance events captured on the agent, streamed to the control plane |
| `ShipMetrics` | Client stream | Batched traffic metrics streamed to the control plane |
| `GetSiteConfig` | Unary | An agent pulls the full config for a single site |

**Two deployment shapes, one binary:**

- **All-in-One** — control plane + data plane in a single process. Ideal for a single node, small deployments and local evaluation.
- **Distributed** — one independent `server` (control plane) plus many `agent` processes at the edge. Ideal for fleets, multi-region rollouts and central management.

---

## ✨ Features

### 🛡️ Security Detection
- **Semantic WAF engine** covering SQL injection, XSS, RCE, path traversal and command injection — powered by `libinjection` heuristics plus Aho-Corasick multi-pattern signature matching.
- **Four-phase pipeline**: `normalize` (request normalization) → `signatures` (signature / libinjection) → `expression` (rule expressions) → `anomaly score` (weighted scoring).
- **Cloudflare-style expression rules** — write conditions like `http.request.uri.path contains "/admin" and ip.src in {1.2.3.0/24}`.
- **Anomaly scoring** with four verdicts: `Pass`, `Monitor`, `Block`, `Challenge`.
- **Managed rule sets** — curated signatures you can toggle per site.

### 🤖 CC & Bot Defense
- **CC protection / 5-second shield** — JavaScript challenge, Proof-of-Work and interactive challenges, with HMAC-signed clearance cookies.
- **Bot protection** — verified-bot whitelist, known-browser pass-through and a configurable action for everything else; TLS fingerprinting and behavioral analysis are on the roadmap.

### 🚦 Access Control
- **IP access rules** — `block` / `allow` / `challenge` / `js_challenge`, with CIDR ranges, CSV bulk import and named rules.
- **Global IP groups** — subscription-backed CIDR lists (plain text, JSON or the Cloudflare IP ranges API) synced to every site on a schedule, with sync-error reporting.
- **Geo restriction** — allow or block by country and by autonomous system number (ASN), with an optional "block unknown countries" policy.
- **Multi-dimensional rate limiting** — by IP, host, path, ASN, country, or a request header, cookie or query parameter.

### 🌊 Traffic Management
- **Origin pools & routes** — group upstreams into pools with load balancing (round-robin, least connections, random or consistent hashing by IP/URL/path/header/cookie/query) and route requests by prefix, exact match or regex — optionally restricted to an IP group, so a path can be served differently to office or partner addresses.
- **Edge caching** with per-site disk quotas and LRU eviction, stale-while-revalidate and browser TTL control.
- **Request / response rewriting** — headers, paths, query strings, status codes and body search/replace.
- **Custom error pages** rendered with Tera templates — including edge-generated responses such as WAF blocks and paused sites.
- **Pause a site** from the console: every request gets a `503` maintenance page while the certificate keeps serving and traffic stays logged.

### 🔐 TLS & Certificates
- **Automatic ACME / Let's Encrypt** issuance and renewal on the edge (HTTP-01 and DNS-01).
- **Multiple DNS providers** for DNS-01 (Aliyun, Cloudflare, Tencent Cloud DNSPod, Huawei Cloud, manual).
- **Per-site certificate status** (`valid` / `expiring soon` / `expired`) reported to the control plane over heartbeats, with a searchable ACME event log.
- **HSTS and forced HTTPS** applied at the edge, with a 180-day default `max-age`.
- **Mutual TLS (mTLS)** — generate or import a CA, issue client certificates from the console, and revoke a single certificate with immediate effect at the edge; a certificate is refused when it is revoked or was issued for another site.
- **HTTPS origin certificate verification is an explicit switch** — a deployment-wide default in **Settings → Origin**, overridable per origin pool. The default accepts any origin certificate so self-signed and internal-PKI origins keep working; turn it on where origins present a trusted certificate.

### 📊 Observability
- **Full request logging to Elasticsearch** with body truncation and a WAL buffer for reliability.
- **Raw request and response capture** — headers, body prefixes, real sizes and truncation flags in PostgreSQL, so a log entry can be replayed as a `curl` command from the console. Headers are stored verbatim (cookies included) to make an attack reproducible.
- **Analytics** dashboards for traffic and attack trends.
- Agent health, traffic stats and cache hit/eviction metrics reported to the control plane over heartbeats.

### 🎛️ Management Console
- **JWT + bcrypt authentication** and **multi-tenant** isolation.
- **Passkey sign-in** (WebAuthn) alongside passwords — bind a platform authenticator or security key from Settings and sign in without a password.
- **Embedded i18n dashboard** (English / 简体中文 / 日本語), compiled into the binary via `rust-embed`.
- **Everything is off by default** — enable protections explicitly, per site.
- **Configuration versioning** — the console lists every configuration snapshot with filters, diffs a version against its predecessor table by table, and rolls back behind a confirmation.

---

## 🧱 Tech Stack

| Layer | Technology |
| --- | --- |
| Data plane / proxy | Rust · [`Pingora`](https://github.com/cloudflare/pingora) · [`pingap`](https://github.com/vicanso/pingap) |
| Control plane API | [`Axum`](https://github.com/tokio-rs/axum) (REST) · [`tonic`](https://github.com/hyperium/tonic) (gRPC) |
| Persistence | [`SeaORM`](https://www.sea-ql.org/SeaORM/) · PostgreSQL 14+ (16 recommended) |
| Log storage | Elasticsearch (optional) |
| Dashboard | React 19 · Vite · Tailwind CSS v4 (embedded with `rust-embed`) |
| WAF engine | `libinjection` · Aho-Corasick · expression evaluator |

**Core crates:**

| Crate | Responsibility |
| --- | --- |
| [`pingwaf-proto`](./pingwaf-proto) | Control-plane gRPC protocol definitions (single source: `control_plane.proto`) |
| [`pingwaf-server`](./pingwaf-server) | Control plane: Axum REST + tonic gRPC + SeaORM/PostgreSQL + ES logs + embedded frontend + agent health monitoring |
| [`pingwaf-agent`](./pingwaf-agent) | Data-plane agent: connects to the control plane, caches rules with disk persistence, ships logs/metrics, receives commands |
| [`pingwaf-waf`](./pingwaf-waf) | Detection engine: normalize → signatures → expression → anomaly score |
| [`pingwaf-challenge`](./pingwaf-challenge) | Dynamic challenges: JS 5-second shield, interactive challenge, PoW, fingerprinting, HMAC clearance cookies |
| `pingwaf-profiler` / `pingwaf-system` (no README) | In-process CPU/memory attribution and snapshots served at `/api/v1/system/profile` and `/api/v1/system/metrics` |

---

## 🚀 Quick Start

> **Note:** Prebuilt binaries are currently published for **Linux (amd64 / arm64)** only — see the [releases page](https://github.com/shuaiZend/PingWAF/releases). On macOS, build from source (Option B). The Docker image supports both architectures.

### Option A — Docker Compose (recommended)

The bundled [`docker-compose.yml`](./docker-compose.yml) starts PingWAF in `all-in-one` mode together with PostgreSQL, pulling the pre-built image from GHCR (`ghcr.io/shuaizend/pingwaf:latest`):

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF

# Start the control plane + data plane + PostgreSQL
docker compose up -d
```

Then open the dashboard:

- **URL:** https://localhost:9080
- **Email:** `admin@pingwaf.local`
- **Password:** `pingwaf123`

> ⚠️ **Change the default admin password and `PINGWAF_JWT_SECRET` before any production use.**

The dashboard is served over **HTTPS** with a self-signed certificate generated
on first boot, so the browser warns until you either trust the downloaded
certificate or upload a real one under **Settings → Control plane HTTPS**. Set
`PINGWAF_TLS_SANS` to the hostname you use if it is not `localhost`.

Health check: `GET http://localhost:9080/healthz` (answers on HTTP and HTTPS;
everything else redirects to `https://`). Use a bounded probe, e.g.
`curl --connect-timeout 2 --max-time 3 http://localhost:9080/healthz`; `9080`
is the admin origin and should be bound privately or protected by a firewall,
not published as a public API.

### Option B — Build from source

**Prerequisites**

| Tool | Version | Notes |
| --- | --- | --- |
| Rust | 1.96+ (MSRV) | CI tracks stable; the Docker image and release binaries build with 1.98.1 |
| Node.js | 26.12.1+ | Required to build the dashboard — lower versions fail `npm ci` (`engine-strict` pins the 2026-10 security fixes) |
| `protoc` | any recent | **Required** — gRPC code generation |
| `cmake` | any recent | Required to build the TLS backend (OpenSSL) |
| PostgreSQL | 14+ (16 recommended) | Control-plane datastore |

> ⚠️ **`protoc` is mandatory.** If it is missing, `pingwaf-proto` silently falls back to placeholder files and downstream crates fail to compile. Install it first:
>
> ```bash
> brew install protobuf                 # macOS
> sudo apt install protobuf-compiler cmake   # Debian / Ubuntu
> ```

**Build & run**

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF

# 1. Build the embedded dashboard
cd web && npm ci && npm run build && cd ..

# 2. Build the pingwaf binary
cargo build --release --bin pingwaf --features full

# 3. Run in all-in-one mode
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

### Option C — Install script (Linux)

On a Linux server, the one-line script downloads the prebuilt binary, installs it and (optionally) sets up a systemd service:

```bash
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | sudo bash -s -- --mode all-in-one
```

> Releases ship two archives per architecture: `pingwaf-linux-{amd64,arm64}.tar.xz` (primary, smaller) and `.tar.gz` (compatibility fallback), each with a `.sha256` sidecar. The script prefers `.tar.xz` and falls back to `.tar.gz` when `xz(1)` is missing locally or the download fails.

👉 For a full walkthrough (database setup, first site, distributed agents, systemd), see **[docs/quick-start.md](./docs/quick-start.md)**.

---

## 🧭 Run Modes

PingWAF is a single binary (`pingwaf`) that shares its entry point with `pingap`. It selects a mode from the CLI subcommand **or** the `PINGWAF_MODE` environment variable.

| Mode | Command | Role |
| --- | --- | --- |
| **Control plane** | `pingwaf server` | REST API + gRPC server + dashboard + PostgreSQL. Does not proxy traffic. |
| **Data plane** | `pingwaf agent` | Connects to a remote control plane, enforces rules, proxies traffic on :80/:443. |
| **All-in-One** | `pingwaf all-in-one` | Both of the above in one process (agent talks to the local server over loopback). |

```bash
# Equivalent to `pingwaf all-in-one`
PINGWAF_MODE=all-in-one ./pingwaf
```

---

## ⚙️ Configuration

PingWAF is configured through a **TOML file**, **`PINGWAF_*` environment variables**, and **CLI flags**, in that order of precedence (a later channel overrides an earlier one).

```bash
pingwaf all-in-one --config /etc/pingwaf/pingwaf.toml

PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml pingwaf all-in-one   # equivalent
```

> ℹ️ The [`pingwaf.toml`](./pingwaf.toml) in the repository root is a working
> example — pass it with `--config` and its `[server]` / `[agent]` tables are
> applied (the process logs `pingwaf: loaded N setting(s)`). Keys are the flag
> names with underscores (`admin_addr`, `max_body_log_size`); unknown keys are
> reported and skipped.

### Key environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `PINGWAF_CONFIG` | — | Path to the TOML configuration file |
| `PINGWAF_MODE` | — | `server`, `agent` or `all-in-one` |
| `PINGWAF_DB_URL` | `postgres://pingwaf:pingwaf@localhost:5432/pingwaf` | PostgreSQL DSN |
| `PINGWAF_ADMIN_ADDR` | `0.0.0.0:9080` | REST API + dashboard listen address |
| `PINGWAF_GRPC_ADDR` | `0.0.0.0:9090` | gRPC control-plane listen address |
| `PINGWAF_JWT_SECRET` | `change-me-in-production` | JWT signing secret (**≥ 16 chars**, change in production) |
| `PINGWAF_ADMIN_EMAIL` | `admin@pingwaf.local` | Seeded administrator email |
| `PINGWAF_ADMIN_PASSWORD` | `pingwaf123` | Seeded administrator password (**change in production**) |
| `PINGWAF_ALLOW_REGISTRATION` | `true` | Whether `POST /api/v1/auth/register` accepts signups (`docker-compose.yml` sets this to `false`) |
| `PINGWAF_HEARTBEAT_INTERVAL` | `15` | Heartbeat interval the control plane hands to agents at registration (seconds). The agent-side `--heartbeat-interval-secs` flag reads the same variable but falls back to `30`, and only applies when the control plane hands nothing down |
| `PINGWAF_TLS_ENABLED` | `true` | Serve the REST API + dashboard over HTTPS (self-signed until replaced); `false` behind a TLS-terminating proxy |
| `PINGWAF_TLS_SANS` | hostname, `localhost`, `127.0.0.1` | Comma-separated SANs of the generated self-signed certificate |
| `PINGWAF_SERVER_URL` | `http://localhost:9090` | *(agent)* control-plane gRPC URL |
| `PINGWAF_API_KEY` | *(empty)* | *(agent)* API key; empty = auto-register over loopback |
| `PINGWAF_CACHE_DIR` | `./data/cache` | *(agent)* local rule cache directory |
| `PINGWAF_ES_ENABLED` | `false` | Enable Elasticsearch log shipping |
| `PINGWAF_ES_URLS` | *(empty)* | Comma-separated Elasticsearch URLs |

### Default ports

| Port | Purpose |
| --- | --- |
| `9080` | REST API + embedded dashboard over HTTPS (health: `GET /healthz`, answered on HTTP too); restrict to admin/VPN sources |
| `9090` | gRPC control plane (agents connect here) |
| `80` / `443` | Proxied traffic (bound once the first site exists; `443` opens only after a certificate is issued or uploaded — until then only port `80` serves HTTP) |

👉 Full configuration reference: **[docs/deployment.md](./docs/deployment.md)** and **[docs/api.md](./docs/api.md)**.

---

## 📚 Documentation

| Document | What you'll find |
| --- | --- |
| [docs/quick-start.md](./docs/quick-start.md) | From zero to your first protected site |
| [docs/deployment.md](./docs/deployment.md) | Docker, binary + systemd, distributed topologies |
| [docs/user-guide.md](./docs/user-guide.md) | Dashboard walkthrough, sites, rules, policies |
| [docs/http-lifecycle.md](./docs/http-lifecycle.md) | Where every feature acts in the request pipeline (WAF check order, caching, error pages) and how to debug with it |
| [docs/api.md](./docs/api.md) | REST API reference (`https://<host>:9080/api/v1`) |
| [docs/README.md](./docs/README.md) | Full documentation index |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | How to contribute |
| [SECURITY.md](./SECURITY.md) | Vulnerability disclosure policy |
| [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) | Community guidelines |

---

## 🤝 Contributing

Contributions are welcome! Please read **[CONTRIBUTING.md](./CONTRIBUTING.md)** before opening a pull request, and **[SECURITY.md](./SECURITY.md)** for how to responsibly report a vulnerability.

---

## 🙏 Acknowledgements

PingWAF stands on the shoulders of excellent open-source projects:

- **[pingap](https://github.com/vicanso/pingap)** by Tree Xie — the reverse-proxy foundation (routing, plugins, ACME, caching, hot reload) that PingWAF's data plane is built on.
- **[Pingora](https://github.com/cloudflare/pingora)** by Cloudflare — the async networking framework that powers `pingap`.
- **[libinjection](https://github.com/client9/libinjection)** — SQLi/XSS detection heuristics used by the WAF engine.

PingWAF is a derivative work that adds the WAF control plane, data-plane agents and detection engine. It is distributed under the same **[Apache License 2.0](./LICENSE)** as its upstream dependencies, and the original `pingap`/`Pingora` copyright notices are preserved. PingWAF is **not** affiliated with or endorsed by Cloudflare or the `pingap` project.

---

## 📄 License

PingWAF is released under the **[Apache License 2.0](./LICENSE)**.
