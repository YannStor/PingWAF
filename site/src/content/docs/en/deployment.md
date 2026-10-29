---
title: Deployment
description: Docker Compose and source builds, ports, configuration precedence, systemd units and distributed agent setups.
minutes: 10
---

## Deployment shapes

**All-in-one** runs the control plane and one data plane in a single process. It is the right choice for a single node, for evaluation, and for small deployments where one edge is enough.

**Distributed** runs one `pingwaf server` and any number of `pingwaf agent` processes. The control plane keeps state; agents stay stateless apart from their rule cache, so you can add edges without touching the database.

## Ports

| Port | Used by | Notes |
| --- | --- | --- |
| `9080` | REST API + dashboard | HTTPS with a self-signed certificate until you replace it; keep it private |
| `9090` | gRPC control plane | Agents connect here; TLS by default, `grpc_tls_mode = "off"` downgrades to plaintext |
| `80` | Proxied traffic | Bound once the first site exists |
| `443` | Proxied traffic | Opens only after a certificate is issued or uploaded |

`GET /healthz` answers on both HTTP and HTTPS, which is what the compose health check and most load balancers should probe. Everything else redirects to HTTPS.

## Docker Compose

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
```

The compose file starts `ghcr.io/shuaizend/pingwaf:latest` in all-in-one mode next to `postgres:16-alpine`, publishing `80`, `443`, `9080` and `9090`. The database port is bound to `127.0.0.1` by default.

> Keep `hostname` stable. The control plane matches re-registrations by hostname plus API key, so a changing container ID leaves ghost offline agents behind.

## Source build

| Tool | Version | Why |
| --- | --- | --- |
| Rust | 1.96+ (MSRV) | The binary itself |
| Node.js | 26.12.1+ | Builds the embedded dashboard; `web/.npmrc` sets `engine-strict=true` |
| `protoc` | recent | gRPC code generation — **mandatory** |
| `cmake` | recent | TLS backend build |
| PostgreSQL | 14+ (16 recommended) | Control-plane datastore; the role needs DDL rights |

Without `protoc`, `pingwaf-proto` silently writes placeholder files and the downstream crates fail to compile — install it before you build.

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release --bin pingwaf --features full
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

On Linux, `install.sh` downloads the prebuilt archive, installs to `/usr/local/bin`, writes `/etc/pingwaf/pingwaf.toml` and a systemd unit, and starts the agent automatically (`--mode all-in-one|server|agent`, `--no-systemd` to skip).

## Configuration precedence

Settings are read from the TOML file first, then `PINGWAF_*` environment variables, then CLI flags — later channels win. Unknown TOML keys are reported and skipped.

```bash
pingwaf all-in-one --config /etc/pingwaf/pingwaf.toml
PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml pingwaf all-in-one   # equivalent
```

The `[server]` table covers `db_url`, `admin_addr`, `tls_enabled`, `tls_sans`, `grpc_addr`, `jwt_secret`, `admin_email` and `serve_frontend`. The `[agent]` table covers `server_url`, `server_ca_cert`, `api_key`, `cache_dir`, `heartbeat_interval_secs`, log batching, `fail_open` and metric shipping.

## Distributed agents

An agent needs three things: where the control plane is, how to authenticate, and where to cache rules.

```bash
PINGWAF_SERVER_URL="https://control.example.com:9090" \
PINGWAF_API_KEY="<enrollment key>" \
PINGWAF_CACHE_DIR="/var/lib/pingwaf/cache" \
pingwaf agent
```

Enrollment keys are created from the console (`POST /api/v1/agents/enroll` returns an install command). An empty `PINGWAF_API_KEY` is only valid for loopback auto-registration in all-in-one mode.

## systemd

The shipped `pingwaf.service` runs as the `pingwaf` user with `Restart=always`, `LimitNOFILE=65536`, `ProtectSystem=strict` and write access limited to `/var/lib/pingwaf` and `/etc/pingwaf`. There is no reload signal: configuration changes are applied by the control plane, and a binary or unit change needs `systemctl restart pingwaf`.

## TLS on the control plane

The dashboard is HTTPS from the first boot with a generated self-signed certificate. Set `PINGWAF_TLS_SANS` to the hostname you actually use (comma separated) before generating it, or upload a real certificate under **Settings → Control plane HTTPS**. When the console sits behind a TLS-terminating proxy, set `PINGWAF_TLS_ENABLED=false`.
