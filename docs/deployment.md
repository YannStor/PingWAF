# PingWAF Deployment Guide

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Linux (amd64/arm64), macOS | Ubuntu 22.04+, Debian 12+ |
| PostgreSQL | 14+ | 16 |
| RAM | 512 MB | 2 GB+ |
| Disk | 1 GB | 10 GB+ (logs, cache) |
| Ports | 80, 443, 9080, 9090 | — |

## Quick Start (Docker Compose)

The fastest way to get PingWAF running:

```bash
# Clone the repository
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF

# Set secrets (recommended)
export JWT_SECRET=$(openssl rand -hex 32)
export ADMIN_PASSWORD=$(openssl rand -hex 16)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)

# Start all services
docker compose up -d

# Verify (the health endpoint answers on HTTP and HTTPS alike)
curl http://localhost:9080/healthz
```

Dashboard: `https://localhost:9080` — served over TLS with a self-signed
certificate generated on first boot, so the browser warns until it is trusted
or replaced (**Settings → Control plane HTTPS**). Set `TLS_SANS` to the hostname
you use if it is not `localhost`.  
Default credentials: `admin@pingwaf.local` / value of `$ADMIN_PASSWORD`

### Environment Variables (docker-compose)

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_PASSWORD` | `pingwaf` | PostgreSQL password |
| `POSTGRES_BIND` | `127.0.0.1` | Host address the PostgreSQL port publishes on (`0.0.0.0` exposes it to the network) |
| `POSTGRES_PORT` | `5432` | Host port for PostgreSQL |
| `JWT_SECRET` | placeholder | JWT signing secret — leaving the placeholder is safe: a random secret is generated on first boot and persisted (≥16 chars when set) |
| `ADMIN_EMAIL` | `admin@pingwaf.local` | Initial admin email |
| `ADMIN_PASSWORD` | `pingwaf123` | Initial admin password (the dashboard forces a change at first login) |
| `ALLOW_REGISTRATION` | `false` | Allow new user signups |
| `HEARTBEAT_INTERVAL` | `15` | Agent heartbeat interval (seconds) |
| `RUST_LOG` | `info,sqlx=warn` | Log level filter |

## Manual Installation (Binary + systemd)

### 1. Install the Binary

```bash
# Automatic (downloads latest release)
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | bash

# Or specify version and mode
./install.sh --version 0.25.0 --mode all-in-one
```

> Prebuilt release assets are published for **Linux** (amd64/arm64) only; on
> macOS, [build from source](./quick-start.md#path-2-build-from-source).
>
> The binaries are linked against the glibc of the runner that builds them
> (Ubuntu 24.04, **glibc 2.39**), so they run on Debian 12+/Ubuntu 24.04+ and
> equivalent. On older distributions (CentOS/RHEL 8, Debian 11, Ubuntu 22.04,
> Alpine, ...) `install.sh` stops with the loader's error — build from source
> there, or run the container image.

### 2. Set Up PostgreSQL

```bash
# Install PostgreSQL
sudo apt install postgresql-16

# Create user and database
sudo -u postgres createuser pingwaf
sudo -u postgres createdb -O pingwaf pingwaf
sudo -u postgres psql -c "ALTER USER pingwaf PASSWORD 'your-secure-password';"
```

### 3. Configure

Settings come from three places, each overriding the one before it: a TOML
file, `PINGWAF_*` environment variables, and command-line flags.

1. **A TOML file** — `--config /etc/pingwaf/pingwaf.toml` (or
   `PINGWAF_CONFIG`). `install.sh` writes one and points the unit at it; its
   `[server]` and `[agent]` tables hold the settings listed in the
   [Configuration Reference](#configuration-reference).
2. **Environment variables** — set as `Environment=` lines in the systemd unit
   (a drop-in override with `sudo systemctl edit pingwaf` survives package
   upgrades).
3. **Command-line flags** — in the unit's `ExecStart`, e.g.
   `pingwaf all-in-one --tls-enabled false`.

```ini
[Service]
Environment=PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml
# Environment variables remain useful for the settings the file cannot
# express, and for secrets you would rather not put in a file:
Environment=PINGWAF_ALLOW_REGISTRATION=false
Environment=PINGWAF_DB_MAX_CONNECTIONS=40
Environment=RUST_LOG=info,sqlx=warn
```

The settings with no file key — `allow_registration`, `db_max_connections`,
`metric_retention_days`, `cors_origins`, the passkey settings and the
`PINGWAF_ES_*` Elasticsearch block — are listed under
[Environment-only settings](#server-configuration-server).

There is no reload signal: edit the file or the drop-in and
`sudo systemctl restart pingwaf`.

### 4. Start the Service

```bash
sudo systemctl enable --now pingwaf
sudo systemctl status pingwaf

# View logs
sudo journalctl -u pingwaf -f
```

## Configuration Reference

The `[server]` and `[agent]` tables of the configuration file
(`--config` / `PINGWAF_CONFIG`) take the long-flag names with dashes written as
underscores (`--admin-addr` → `admin_addr`); list values are TOML arrays. The
`all-in-one` mode reads both tables, `server` and `agent` only their own. A key
that is not recognised is reported and ignored, and a setting given both in the
file and in the environment is taken from the environment.

### Server Configuration (`[server]`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `db_url` | string | `postgres://pingwaf:pingwaf@localhost:5432/pingwaf` | PostgreSQL DSN |
| `admin_addr` | string | `0.0.0.0:9080` | REST API + dashboard address |
| `grpc_addr` | string | `0.0.0.0:9090` | gRPC control plane address |
| `grpc_tls_mode` | string | `tls` | `tls` (default) or `off`. With `tls` and no certificate configured, a self-signed CA + server certificate is generated on first boot and reused after |
| `grpc_tls_cert` | string | — | PEM certificate for the gRPC listener; takes priority over the self-signed pair (requires `grpc_tls_key`) |
| `grpc_tls_key` | string | — | PEM private key for `grpc_tls_cert` |
| `public_host` | string | — | Host the dashboard is reached under from the outside (optionally with port); pinned into the HTTP-to-HTTPS redirect instead of the client's `Host` header |
| `jwt_secret` | string | `change-me-in-production` | JWT signing secret (≥16 chars, required) |
| `admin_email` | string | `admin@pingwaf.local` | Seeded admin email |
| `admin_password` | string | `pingwaf123` | Seeded admin password |
| `serve_frontend` | bool | `true` | Serve the embedded dashboard SPA for non-API routes |
| `tls_enabled` | bool | `true` | Serve the REST API + dashboard over HTTPS; cleartext requests get a `308` redirect, health probes are exempt. Turn off behind a TLS-terminating proxy |
| `tls_sans` | string[] | hostname, `localhost`, `127.0.0.1` | Subject alternative names of the generated self-signed certificate |

The rest of the server settings are **environment-only** — they have no flag
and therefore no file key:

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `PINGWAF_JWT_EXPIRATION_HOURS` | `12` | Access token lifetime |
| `PINGWAF_ALLOW_REGISTRATION` | `true` (code); `docker-compose.yml` sets `false` | Allow new user signups |
| `PINGWAF_HEARTBEAT_INTERVAL` | `15` | Heartbeat interval handed to agents at registration. The agent-side `--heartbeat-interval-secs` flag reads the same variable and falls back to `30` |
| `PINGWAF_DB_MAX_CONNECTIONS` | `20` | Connection pool maximum |
| `PINGWAF_METRIC_RETENTION_DAYS` | `7` | Days of edge-metric samples kept in `agent_metrics` |
| `PINGWAF_CORS_ORIGINS` | `[]` (all) | Allowed CORS origins, comma-separated |
| `PINGWAF_PASSKEY_ENABLED` | `true` | Offer passkey (WebAuthn) registration and login |
| `PINGWAF_PASSKEY_RP_NAME` | `PingWAF` | Relying party name shown by the authenticator |
| `PINGWAF_PASSKEY_RP_ID` | derived from the request | Relying party ID, i.e. the effective domain |
| `PINGWAF_PASSKEY_ORIGIN` | derived from the request | Origin the dashboard is served from |
| `PINGWAF_PASSKEY_TRUST_FORWARDED_PROTO` | `false` | Believe `X-Forwarded-Proto` when deriving the origin |
| `PINGWAF_MALLOC_PURGE_DELAY_MS` | derived from memory ceiling | Allocator purge delay in **milliseconds** (mimalloc `mi_option_purge_delay`). Overrides the automatic bucketing (<1 GB → 0, 1-4 GB → 250, 4-16 GB → 500, >16 GB → 1000); `-1` disables purging. The standard `MIMALLOC_PURGE_DELAY` is honoured as a fallback |

The refresh-token lifetime (30 days), the minimum pool size (`1`) and the
server-side log batch size (`500`) are compiled-in constants with no override.

### Agent Configuration (`[agent]`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server_url` | string | `http://localhost:9090` (`--server-url`); the compiled-in struct default is `https://localhost:9090` and applies when the key is absent from the file | Control plane gRPC URL |
| `server_ca_cert` | string | — | PEM file with the CA that signed the control plane's TLS certificate (required for private CAs; bundled roots are used otherwise) |
| `api_key` | string | `""` | Agent authentication key (empty = auto-register over loopback in all-in-one) |
| `cache_dir` | string | `./data/cache` (`--cache-dir`); the compiled-in struct default is `/var/lib/pingwaf/cache` and applies when the key is absent from the file | Local rule cache directory |
| `fail_open` | bool | `true` | Local fallback while disconnected: `true` keeps serving with the last synced rules; `false` answers 503 for hosts without synced rules. The per-site failover policy (console → site → basic) and the control-plane-wide default (settings → defense) take precedence once synced |
| `heartbeat_interval_secs` | int | `30` | Fallback heartbeat frequency, used only when the control plane hands no interval down at registration |
| `log_batch_size` | int | `100` | Log entries before flush |
| `log_flush_interval_secs` | int | `5` | Max time between flushes |
| `max_body_log_size` | int | `8192` | Max request body bytes to log |
| `metrics_ship_interval_secs` | int | `30` | Edge-metrics ship interval; `0` disables shipping |

Environment variables: `PINGWAF_SERVER_URL`, `PINGWAF_API_KEY`,
`PINGWAF_CACHE_DIR`, `PINGWAF_FAIL_OPEN`, `PINGWAF_HEARTBEAT_INTERVAL`,
`PINGWAF_METRICS_SHIP_INTERVAL`. The three log settings and the reconnect
backoff constants (`1 s` doubling to `60 s`) have no environment variable.

### Environment Variables

Every setting can be given as an environment variable. The ones with a file key
are listed against it below; the dash in a table entry means the setting has no
`--flag` and is environment-only (or compiled in).

| Variable | File key |
|----------|-----------|
| `PINGWAF_CONFIG` | — (names the configuration file itself) |
| `PINGWAF_DB_URL` | `server.db_url` |
| `PINGWAF_ADMIN_ADDR` | `server.admin_addr` |
| `PINGWAF_HTTP_ADDR` | `server.admin_addr` (alias) |
| `DATABASE_URL` | `server.db_url` (used only when `PINGWAF_DB_URL` is unset) |
| `PINGWAF_GRPC_ADDR` | `server.grpc_addr` |
| `PINGWAF_JWT_SECRET` | `server.jwt_secret` |
| `PINGWAF_ADMIN_EMAIL` | `server.admin_email` |
| `PINGWAF_ADMIN_PASSWORD` | `server.admin_password` |
| `PINGWAF_SERVE_FRONTEND` | `server.serve_frontend` |
| `PINGWAF_JWT_EXPIRATION_HOURS` | — |
| `PINGWAF_ALLOW_REGISTRATION` | — |
| `PINGWAF_HEARTBEAT_INTERVAL` | `server.heartbeat_interval_seconds` (agents follow the value the control plane hands them; `agent.heartbeat_interval_secs` is only a fallback) |
| `PINGWAF_DB_MAX_CONNECTIONS` | — |
| `PINGWAF_METRIC_RETENTION_DAYS` | — |
| `PINGWAF_TLS_ENABLED` | `server.tls_enabled` |
| `PINGWAF_TLS_SANS` | `server.tls_sans` (comma-separated) |
| `PINGWAF_CORS_ORIGINS` | — (comma-separated) |
| `PINGWAF_PASSKEY_ENABLED` | — |
| `PINGWAF_PASSKEY_RP_NAME` | — |
| `PINGWAF_PASSKEY_RP_ID` | — |
| `PINGWAF_PASSKEY_ORIGIN` | — |
| `PINGWAF_PASSKEY_TRUST_FORWARDED_PROTO` | — |
| `PINGWAF_MODE` | CLI mode (`all-in-one`, `server`, `agent`) |
| `PINGWAF_SERVER_URL` | `agent.server_url` |
| `PINGWAF_API_KEY` | `agent.api_key` |
| `PINGWAF_CACHE_DIR` | `agent.cache_dir` |
| `PINGWAF_FAIL_OPEN` | `agent.fail_open` |
| `PINGWAF_METRICS_SHIP_INTERVAL` | `agent.metrics_ship_interval_secs` |
| `PINGWAF_ES_ENABLED` | — Elasticsearch shipper toggle |
| `PINGWAF_ES_URLS` | — Elasticsearch URLs (comma-separated) |
| `PINGWAF_ES_INDEX_PREFIX` | — ES index prefix |
| `PINGWAF_ES_USERNAME` | — ES basic auth username |
| `PINGWAF_ES_PASSWORD` | — ES basic auth password |
| `PINGWAF_ES_API_KEY` | — ES API key |
| `PINGWAF_ES_MAX_BODY_SIZE` | — ES body truncation limit |
| `PINGWAF_ES_BUFFER_DIR` | — ES on-disk buffer directory |
| `RUST_LOG` | Tracing log filter (default `info,sqlx=warn`) |

## Deployment Modes

### All-in-One Mode

Runs both control plane and data plane in a single process. Best for single-server setups.

```bash
pingwaf all-in-one --db-url "postgres://..." --admin-addr 0.0.0.0:9080
```

### Distributed Mode

Separate control plane server and multiple edge agents.

**Control Plane (server):**
```bash
pingwaf server --db-url "postgres://..." --admin-addr 0.0.0.0:9080 --grpc-addr 0.0.0.0:9090
```

**Edge Agent:**
```bash
pingwaf agent --server-url "http://control-plane:9090" --api-key "your-agent-key"
```

Generate an agent API key from the dashboard: **Settings → API Keys → Create Key**.

The log, certificate-event and metric shipping streams authenticate with the
agent token sent as `x-agent-token` gRPC metadata. **In distributed
deployments, upgrade the control plane first, then the agents** (see
[Rolling Upgrade](#rolling-upgrade-distributed)): a new server rejects shipping
streams that carry no token, while an old server simply ignores the metadata.

## Downstream Timeouts & Keep-Alive

These are per-listener settings in the `[servers.<name>]` tables of the data
plane's configuration file (the `conf/servers.toml` shipped with the repo
documents every key; `h2_idle_timeout` and the `tcp_*` keys sit in the same
table). They govern the client-facing side of the proxy:

| Key | Default | Meaning |
|-----|---------|---------|
| `downstream_read_timeout` | unset | Max gap between reads from the client. Unset, a slow client can hold a connection open indefinitely — the startup log warns when it is missing |
| `downstream_write_timeout` | unset | Max gap between writes to the client |
| `downstream_connection_timeout` | unset | **Read-timeout cap for the connection phase.** Pingora 0.9 has no first-read-only knob, so the effective read timeout is `min(this, downstream_read_timeout)`. It can only *tighten* the read timeout, never extend it; a value larger than the read timeout is ignored |
| `keepalive_request_limit` | unset (pingora default: no limit) | Maximum requests served on one downstream keep-alive connection before pingora closes it |
| `h2_idle_timeout` | unset (never) | Close an idle HTTP/2 client connection after this long |
| `tcp_idle` / `tcp_interval` / `tcp_probe_count` | unset | TCP keepalive probes on client connections |

`downstream_connection_timeout` and `keepalive_request_limit` exist because
pingora 0.9 has no independent HTTP/1.1 idle timeout: without them, a client
that opens a connection, completes the handshake and then goes quiet holds a
worker connection for as long as the read timeout (or forever, if read timeout
is unset).

Recommendations (starting points, not defaults):

- Set `downstream_read_timeout` (e.g. `60s`) and
  `downstream_write_timeout` (e.g. `60s`) unless a workload genuinely needs
  longer gaps.
- Set `downstream_connection_timeout` **below** the read timeout (it is a
  cap, not an independent budget) — most
  legitimate TLS handshakes finish in well under a second even on mobile
  networks, so `5s`–`10s` comfortably separates stalled handshakes from slow
  clients. Note the effective first-read timeout is the **shorter** of the
  two, so a connection timeout larger than the read timeout has no effect.
- Set `keepalive_request_limit` to a finite value (e.g. `1000`) to bound
  connection age; behind a load balancer that reuses connections
  aggressively, a lower value spreads traffic across workers more evenly.

## Upstream Host Override

By default the proxy forwards the client's `Host` header to the origin
unchanged. A location can override which virtual host the origin sees with
`upstream_host` on the location (`LocationConf.upstream_host`, configurable
through the location form / `PUT /api/v1/sites/{site_id}` locations):

- Value is a **bare host name** — no scheme, no path, no spaces (validation
  rejects `http://…`, `/…` and anything over 253 characters). A port is not
  part of the Host the origin needs for virtual-host selection either; the
  upstream address determines where to connect, `upstream_host` only rewrites
  the header.
- Unset (the default) keeps the client's `Host` — historic behaviour.
- An explicit value **wins over** any `Host` entry in the location's
  `proxy_set_headers`, so "which virtual host the origin sees" has one
  obvious knob instead of competing header rewrites.

Typical use: a pool of origins behind one address that route by
`Host` (virtual hosts, multi-tenant origins) — set `upstream_host` to the
name the origin expects instead of asking every client to send it.

## Small-Memory Instances

On instances with less than 2 GiB of RAM (especially all-in-one deployments
that share the box with PostgreSQL):

- **Cap the container's memory.** Prevent a single process from squeezing out
  the database on the same host:
  `docker run --memory=1g ...` (the same flag works with podman), or in
  Compose:

  ```yaml
  services:
    pingwaf:
      mem_limit: 1g
  ```

- **The allocator returns freed memory to the OS.** PingWAF links
  [mimalloc](https://github.com/microsoft/mimalloc) as its global allocator on
  every platform (previously only musl builds used it; glibc builds went
  through the system allocator, whose per-thread arenas could pin tens of
  megabytes of RSS). Freed pages are purged back to the kernel instead of
  lingering until a restart, and the purge delay now **derives from the memory
  ceiling at startup** (cgroup limit, then host total):

  | Memory ceiling | Purge delay |
  | --- | --- |
  | < 1 GB | 0 ms (return pages immediately) |
  | 1-4 GB | 250 ms |
  | 4-16 GB | 500 ms |
  | > 16 GB | 1000 ms |

  Small hosts return pages aggressively (a little more CPU for a materially
  lower RSS); large hosts keep mimalloc's lazier default. Pin an explicit
  value with `PINGWAF_MALLOC_PURGE_DELAY_MS` (milliseconds, `-1` = never
  purge); the standard `MIMALLOC_PURGE_DELAY` is honoured as a fallback. The
  effective value is logged at startup
  (`pingwaf: allocator retention purge_delay=...`).
- **Set transparent hugepages to `madvise`** on the host kernel
  (`/sys/kernel/mm/transparent_hugepage/enabled`); `always` lets the
  hugepage backing inflate resident memory.
- **Swap is a buffer, not a substitute.** Configuring swap absorbs slow growth,
  but a sudden burst allocates faster than the kernel can swap out, so the OOM
  killer still fires first — keep the memory cap.

To observe actual memory usage, call `GET /api/v1/system/metrics` — the
`memory` object carries the process RSS, the host totals and the cgroup
figures the dashboard reads; see
[System observation](./profiling.md#get-apiv1systemmetrics).

## SSL/TLS Configuration

### Automatic (ACME / Let's Encrypt)

Configure through the dashboard:
1. Add a site with your domain
2. Go to **SSL** tab
3. Select "Let's Encrypt" and choose challenge type:
   - **HTTP-01**: Requires port 80 accessible
   - **DNS-01**: Supports Cloudflare, AliDNS, Huawei DNS, Tencent DNS

Certificates are automatically renewed before expiry.

### Manual Certificates

Upload PEM-encoded certificate and key through the dashboard or API:

```bash
curl -k -X POST https://localhost:9080/api/v1/sites/{site_id}/certificates \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-cert",
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "domains": ["example.com", "*.example.com"]
  }'
```

### Origin Certificate Verification

When a site's origin pool has an SNI hostname, traffic to the origin goes over
HTTPS. Whether that origin's certificate is validated is a separate decision from the
certificate the proxy serves to clients. The effective value resolves through a
three-level cascade — the first level that is set wins:

1. **Per pool** — an origin pool's own `verify_cert` (origin pool dialog).
   `true` forces validation, `false` forces acceptance, and leaving it unset
   falls through to the site default.
2. **Per site** — the site's `origin_verify_cert` (origin certificate check
   card on the site's SSL page, or `origin_verify_cert` on
   `PUT /api/v1/sites/{site_id}`). `true`/`false` pins a default for every
   pool of the site; `null` (no site preference) falls through to the global
   default.
3. **Global default** — **Settings → Origin TLS verification** in the
   dashboard, or `PUT /api/v1/settings/origin`. The console writes
   `verify_cert: false` so that self-signed and internal-PKI origins keep
   working; set it to `true` when every origin presents a publicly trusted
   certificate. The value reaches the agents through the next rule bundle, so
   no restart is needed.

Accepting an unvalidated origin certificate means an attacker who can
intercept the connection to the origin can impersonate it. Prefer issuing the
origin a certificate from a CA the proxy trusts (a private CA works: upload it
as the pool's `ca` file) and enabling verification, rather than disabling it.

### Control-Plane Certificate (dashboard)

The dashboard and REST API are served over HTTPS with a certificate that is
managed from the dashboard itself — no files to edit:

1. **First boot** generates a self-signed pair (EC P-256) covering the
   configured `tls_sans` plus the machine hostname, `localhost` and `127.0.0.1`.
2. **Settings → Control plane HTTPS** shows what is being served (subject,
   SANs, fingerprint, expiry) and lets you download it, upload a real
   certificate + key, or regenerate the self-signed pair.
3. Uploads are validated first — a mismatched key or a broken chain is rejected
   with `400` and the previous certificate keeps serving — and take effect
   immediately, without a restart.

`PINGWAF_TLS_ENABLED=false` (or `tls_enabled = false`) switches the port back
to plain HTTP, which is the right setting behind a reverse proxy that
terminates TLS. Passkeys require a secure origin, so with plain HTTP they are
unavailable unless the proxy publishes an HTTPS origin and
`PINGWAF_PASSKEY_TRUST_FORWARDED_PROTO=true` is set.

### gRPC Control-Plane TLS

The gRPC listener agents connect to (default `0.0.0.0:9090`) serves **TLS by
default**. With no certificate configured, the first boot generates a
self-signed CA plus server certificate (SANs: `localhost`, the hostname and
the listener IPs), persists it in `instance_settings` and writes the PEM files
to the data directory — the agent then only needs that CA to verify the
server. The generated pair survives restarts; deleting it makes the next boot
issue a fresh one (agents must be re-pointed at the new CA).

For a publicly trusted certificate (e.g. issued for the control plane's
hostname), point the server at a PEM certificate and key — explicit
certificates take priority over the self-signed pair:

```bash
pingwaf server \
  --grpc-tls-cert /etc/pingwaf/certs/grpc.pem \
  --grpc-tls-key /etc/pingwaf/certs/grpc-key.pem
```

Or set `grpc_tls_cert` / `grpc_tls_key` in `pingwaf.toml`, or the
`PINGWAF_GRPC_TLS_CERT` / `PINGWAF_GRPC_TLS_KEY` environment variables. Both
paths must be present; a mismatch or unreadable file aborts startup instead of
falling back to plaintext.

`grpc_tls_mode = "off"` (or `PINGWAF_GRPC_TLS_MODE=off`) reverts to plaintext
h2c. The server logs a warning at startup and `GET /version` reports
`grpc_tls: false`, which the console surfaces as a degraded-mode banner —
acceptable for loopback all-in-one deployments, not for agents across
untrusted networks.

Agents switch to `https://` server URLs and either trust the bundled webpki
roots (publicly trusted certificate) or load the signing CA — the generated
self-signed CA when the server auto-generates:

```bash
pingwaf agent \
  --server-url "https://control-plane.example.com:9090" \
  --server-ca-cert /var/lib/pingwaf/data/grpc-ca.pem \
  --api-key "your-agent-key"
```

The certificate must carry a subject alternative name for whatever agents
connect to: a DNS name for domain URLs, an IP SAN for `https://<ip>:9090`, and
`127.0.0.1` for all-in-one mode — which switches its embedded agent to
`https://127.0.0.1` automatically and wires up the generated CA, so a default
all-in-one boots fully encrypted with no extra configuration.

The API for all of this is documented in
[`docs/api.md` → Control-plane certificate](./api.md#control-plane-certificate).

## Firewall & Port Requirements

| Port | Protocol | Purpose | Required |
|------|----------|---------|----------|
| 80 | TCP | HTTP traffic / ACME HTTP-01 | Yes (for proxied sites) |
| 443 | TCP | HTTPS traffic | Yes (for proxied sites) |
| 9080 | TCP | Admin dashboard + REST API (HTTPS) | Yes |
| 9090 | TCP | gRPC control plane (agents) | Distributed mode |
| 5432 | TCP | PostgreSQL | Internal only |

```bash
# UFW example
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 9080/tcp
sudo ufw allow 9090/tcp  # Only if agents connect remotely
```

### Login Rate Limiting

The control plane rate-limits its credential endpoints (`login`, passkey
login, `register`, token `refresh`, password change) per source address:
10 login attempts/min, 5 registrations/hour, 30 refreshes/min, 10 password
changes/min. The limit is keyed by the real TCP peer address — forwarding
headers are never trusted — so a proxy in front of the dashboard must not be
shared by other clients that would otherwise be throttled together. Behind a
large NAT exit (offices, campus networks) all users share one address and can
exhaust the login budget with legitimate traffic; give the dashboard a
dedicated ingress address in that case. Exceeding a limit answers `429` with
a `Retry-After` header. These token buckets are counted **in-process**: the
counters are not shared across control-plane instances, so in a multi-replica
deployment each replica enforces the limits independently and the effective
budget per source address is the configured threshold multiplied by the
number of replicas — scale the thresholds up accordingly.

## Security Checklist

A hardening pass before exposing the control plane beyond localhost:

- **Change the default administrator.** First boot seeds
  `admin@pingwaf.local` / `pingwaf123` — the server logs a warning while that
  password is active, and the dashboard forces a password change on first
  login, but do not leave the seed in place. `pingwaf user add` can create
  administrators before boot instead.
- **Give the control plane a real JWT secret.** A placeholder secret (the
  `change-me-…` default or the compose value) makes the server generate and
  persist a random one on first boot, which is safe but rotates whenever the
  persisted copy is lost; set `PINGWAF_JWT_SECRET` explicitly when tokens
  must survive re-provisioning or be shared across instances.
- **Restrict CORS.** With no `PINGWAF_CORS_ORIGINS` the API answers
  cross-origin requests from any origin — acceptable when the embedded
  dashboard is the only client and served from the same origin, but list
  your dashboard origin(s) explicitly when anything else calls the API.
- **Keep gRPC TLS on for cross-network agents.** It is the default: a
  self-signed CA + server certificate is generated on first boot and agents
  verify against it. Replace it with a publicly trusted certificate where
  possible; only loopback all-in-one deployments may consider
  `grpc_tls_mode = "off"`, which logs a warning and shows a degraded banner.
- **Keep PostgreSQL off public interfaces.** The compose file binds 5432 to
  loopback by default; set `POSTGRES_BIND=0.0.0.0` only when another host
  genuinely needs the database, and then with a strong password and
  firewall rules in front of it.
- **Choose `fail_open` deliberately.** Disconnected behaviour is resolved per
  host: the site's failover policy (console → site → basic settings) wins,
  then the control-plane-wide default (settings → defense), then the agent's
  local `--fail-open` flag. `true` (default at every layer) keeps sites
  serving with the last synced rules while the agent is disconnected;
  `false` refuses traffic (`503`) for hosts without synced rules, trading
  availability for guaranteeing the WAF sees every request. With a closed
  policy, remember the window between agent start and first sync refuses
  traffic for all hosts.
- **Verify origin certificates where you can.** The console defaults
  `Settings → Origin` to off, which accepts any certificate from an HTTPS
  origin and therefore allows an on-path attacker to impersonate it. Turn it
  on once origins present a certificate the proxy can chain — a private CA
  works, uploaded as the pool's `ca` — and keep per-pool overrides for the
  few origins that cannot.
- **Treat cache rules as shared by default.** A response is only cached when
  the origin allows it, but a cache rule toggled on with a long TTL will
  serve one user's response to the next unless the origin marks it
  personalised (`private`, `no-store`, `Cache-Control: no-cache`) or sends
  `Vary` on the request dimensions. Responses carrying `Set-Cookie` and
  requests carrying `Authorization` are excluded unless the origin opts in
  explicitly, so origins that authenticate through a header other than
  `Authorization` rely on you marking those responses correctly.
- **Session revocation semantics.** Accounts carry a token version;
  changing a password, disabling an account, or changing its role bumps the
  version and immediately invalidates that account's access and refresh
  tokens. Password changes by the user do the same for their own sessions.

## Backup & Recovery

### Database Backup

```bash
# Full backup
pg_dump -U pingwaf -d pingwaf -F c -f pingwaf_backup_$(date +%Y%m%d).dump

# Restore
pg_restore -U pingwaf -d pingwaf --clean pingwaf_backup_20240101.dump
```

### Configuration Backup

```bash
tar -czf pingwaf_config_backup.tar.gz /etc/pingwaf/ /var/lib/pingwaf/certs/
```

### Automated Backups (cron)

```cron
# Daily at 2:00 AM
0 2 * * * pg_dump -U pingwaf -d pingwaf -F c -f /backups/pingwaf_$(date +\%Y\%m\%d).dump
# Remove backups older than 30 days
0 3 * * * find /backups -name "pingwaf_*.dump" -mtime +30 -delete
```

## Upgrade Procedure

### Docker

```bash
docker compose pull
docker compose up -d
```

### Binary

```bash
# Download and install new version
./install.sh --version NEW_VERSION --no-systemd

# Restart service
sudo systemctl restart pingwaf
```

Database migrations run automatically on startup.

Upgrading to the release that adds the origin certificate switch (migration
52) resets `verify_cert` on every origin pool that had it stored as `false` to
"unset". Under the old two-state field, `false` meant "not configured"; it now
means "accept any certificate", so leaving those rows would have pinned them
to the lenient behaviour and ignored the new global switch. The pools fall
back to the global default, which that migration seeds as `false` as well —
behaviour is unchanged on upgrade. Review **Settings → Origin** afterwards and
turn verification on where the origins can support it.

### Rolling Upgrade (Distributed)

1. Upgrade the control plane server first
2. Verify agents reconnect successfully
3. Upgrade agents one at a time

## Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u pingwaf --no-pager -n 50

# Common issues:
# - PostgreSQL not running: systemctl status postgresql
# - Port already in use: ss -tlnp | grep -E '9080|9090'
# - Invalid config: pingwaf all-in-one --db-url "..." (run interactively)
```

### Database connection failed

```bash
# Test connection
psql "postgres://pingwaf:password@localhost:5432/pingwaf" -c "SELECT 1"

# Check pg_hba.conf allows connections
# Ensure the user has CREATEDB privilege for migrations
```

### Agent not connecting

1. Verify the control plane gRPC port (9090) is accessible
2. Check the API key is valid
3. Review agent logs: `RUST_LOG=debug pingwaf agent --server-url ...`
4. Ensure clocks are synchronized (NTP)

### High memory usage

- Reduce `db_max_connections`
- Lower `log_batch_size`
- Check if cache disk quota is configured
- Call `GET /api/v1/system/metrics`
  ([System observation](./profiling.md#get-apiv1systemmetrics)) to see whether
  it is process RSS or the host that is under pressure

### Error pages & debugging

When the edge cannot serve a request through the upstream (502/503/504, …),
the built-in error page shows a fixed, category-level message only:

- `Upstream Timeout` — upstream read/write/connect timeout
- `Upstream Unavailable` — connection refused / unreachable / TLS handshake failure
- `Upstream Connection Error` — upstream read/write failure
- `Upstream Protocol Error` — HTTP/2 protocol violation
- `Internal Server Error` — anything else

The page also renders the `request_id`, and the response carries the error
class in the `X-Pingap-EType` header. It **never** shows the internal error
chain, plugin names or upstream addresses — the original error goes to the
server log only. To debug, take the `request_id` from the page and grep the
server log with it:

```bash
grep "<request_id>" /var/log/pingwaf/server.log
```

The log line holds the original error text, the error type and the site, which
is enough to tell a slow origin from a dead one without exposing internals to
visitors.

### Health check endpoint

```bash
curl http://localhost:9080/healthz
# {"status":"ok","database":"up"}
```
