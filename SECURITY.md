# Security Policy

PingWAF sits directly in the request path of the applications it protects, so
its own security matters as much as the rules it enforces. We take vulnerability
reports seriously and appreciate the effort of security researchers who disclose
them responsibly.

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue, discussion, or pull request for a
security vulnerability.** Public reports put every PingWAF deployment at risk
before a fix exists.

Instead, report privately:

| Channel | Address |
| --- | --- |
| **Email (preferred)** | `security@pingwaf.local` |

> **Maintainers:** replace `security@pingwaf.local` with a real, monitored
> mailbox owned by at least two people before publishing this repository widely.
> Consider publishing a PGP key for that address, and enabling GitHub's
> *Private vulnerability reporting* (Security → Advisories) as a second channel,
> then document it here.

### What to include

The more detail you provide, the faster we can triage:

1. **Summary** of the vulnerability and its impact.
2. **Affected versions** — release tag, or the exact git commit if you built
   from source (`git rev-parse HEAD`).
3. **Deployment context** — run mode (`all-in-one`, `server`, `agent`), OS and
   architecture, TLS backend (`openssl` or `tls-rustls`), feature flags used,
   whether the instance is internet-facing.
4. **Step-by-step reproduction**, including any request payload, configuration
   or rule set required. A minimal, self-contained PoC is ideal.
5. **Attack prerequisites** — unauthenticated remote attacker, authenticated
   dashboard user, agent API key, network position, etc.
6. **Whether the vulnerability is already public** or known to be exploited.
7. Your **handle for credit** (optional) and any **CVE/CNA preference**.

Please redact secrets (JWT tokens, database passwords, agent API keys) from
anything you send us.

### Response timeline

| Stage | Target |
| --- | --- |
| Acknowledge receipt | Within **3 business days** |
| Initial triage and severity assessment | Within **7 business days** |
| Status updates while a fix is developed | At least **weekly** |
| Fix, advisory and release | As soon as practical; coordinated with you |
| Public disclosure | After the fix ships, or **90 days** from the report — whichever comes first |

We will keep you informed, credit you in the advisory if you wish, and never
pursue legal action for good-faith research conducted under this policy.

## Supported Versions

PingWAF shares its version lineage with [pingap](https://github.com/vicanso/pingap),
from which it inherits the proxy data plane.

| Version | Status | Receives security fixes |
| --- | --- | --- |
| `main` | Active development | Yes — but expect breaking changes |
| `0.25.x` (current release line, 0.25.0) | Supported | **Yes** |
| `0.24.x` | Security fixes only | No |
| `0.23.x` | Security fixes only | No |
| `0.22.x` | Security fixes only | No |
| `0.21.x` | Security fixes only | No |
| `0.20.x` | Security fixes only | No |
| `0.16.x` | Security fixes only | No |
| `0.15.x` | Security fixes only | No |
| `0.14.x` | Security fixes only | No |
| `0.13.x` and older (pingap lineage) | Legacy | Best effort, case by case |

Only the latest release line is guaranteed to receive security patches. If you
run an older version, please upgrade — see
[`docs/deployment.md` → Upgrade Procedure](./docs/deployment.md#upgrade-procedure).

> **Note:** prebuilt Linux (amd64/arm64) binaries are published on
> [GitHub Releases](https://github.com/shuaiZend/PingWAF/releases); on macOS,
> build from source. Either way, pin the exact version or commit you deploy so
> you can tell us what you are running.

## Scope

The following are in scope for this policy:

- **WAF bypass** — payloads that evade normalisation, signature matching or the
  rule engine (`pingwaf-waf`) and reach the origin unblocked.
- **Authentication and authorisation** — JWT issuance/validation, session and
  refresh-token handling, role checks, user registration controls in the
  control-plane REST API (`/api/v1`), and the MCP endpoint's credential
  handling at `/mcp`.
- **Control-plane protocol** — the gRPC channel between agents and the server:
  agent authentication and API keys, rule/config push integrity, command
  execution (block IP, purge cache, restart agent).
- **Injection and traversal** — SQL injection via SeaORM/raw queries in the
  control plane, path traversal in dashboard asset serving or the local rule
  cache, template or log injection.
- **Credential and secret exposure** — leaked database credentials, ACME/DNS
  provider tokens, TLS private keys, API keys, or secrets written to logs,
  metrics, Elasticsearch documents or error responses.
- **TLS handling** — certificate validation, ACME issuance/renewal, protocol
  and cipher downgrade, SNI handling.
- **Memory safety and DoS** — panics, unbounded allocation, quadratic parsing or
  other resource exhaustion reachable from untrusted HTTP input.
- **Proxy request smuggling** — HTTP/1.1, HTTP/2 or gRPC-Web parsing
  inconsistencies between PingWAF and an upstream or downstream hop.

Out of scope (please still tell us if you are unsure):

- Reports that require physical access to the host, or an already-compromised
  server.
- Findings that depend on a deployment running with the documented insecure
  defaults (`pingwaf123`, `change-me-in-production`, open registration) on a
  public network — these are configuration issues, covered under
  [Hardening](#hardening-checklist) below.
- Missing security headers or TLS best-practice settings on *your* origin.
- Vulnerabilities in third-party dependencies without a demonstrated impact on
  PingWAF (please report those upstream, and open an issue for the dependency
  bump).
- Social engineering of maintainers or contributors.

## Disclosure Policy

We follow **coordinated disclosure**:

1. You report privately and give us a reasonable window to fix the issue.
2. We develop the fix on a private branch and prepare a security advisory.
3. We agree on a disclosure date with you, request a CVE where appropriate, and
   publish the advisory together with the patched release.
4. You are credited in the advisory unless you prefer to stay anonymous.
5. We do not disclose report details publicly before the agreed date, and we ask
   you to do the same.

Dependency vulnerabilities found by `cargo audit` are tracked against
[`.cargo/audit.toml`](./.cargo/audit.toml); every accepted exception there must
document why it is not exploitable and when it can be removed.

## Hardening Checklist

PingWAF ships with development-friendly defaults so you can evaluate it quickly.
**Change every one of them before exposing an instance to a network you do not
control.**

### Credentials and secrets

- [ ] Set `PINGWAF_ADMIN_EMAIL` and a strong `PINGWAF_ADMIN_PASSWORD` — never
      leave `admin@pingwaf.local` / `pingwaf123`.
- [ ] Set `PINGWAF_JWT_SECRET` to at least 16 characters of random data
      (32 random bytes recommended): `openssl rand -hex 32`. Rotate it
      immediately if it was ever committed or logged.
- [ ] Set `PINGWAF_ALLOW_REGISTRATION=false` unless you need self-service
      signups.
- [ ] Change the PostgreSQL password away from `pingwaf`, and use a role with
      the minimum privileges PingWAF needs (DDL rights are required at startup
      for migrations).
- [ ] Issue a dedicated agent API key per edge node
      (**Settings → API Keys → Create Key**) and rotate keys on staff or host
      changes.

### Network exposure

- [ ] Bind the dashboard/REST API to `127.0.0.1:9080` or a private interface and
      reach it through a VPN/SSH tunnel or a reverse proxy. Do not publish
      `0.0.0.0:9080` on the public internet: it is the administrative origin and
      is continuously scanned. If remote access is unavoidable, restrict the
      cloud security group/host firewall to known administrator addresses.
      The port serves HTTPS by default with a self-signed certificate — upload a
      real one (**Settings → Control plane HTTPS**) or set
      `PINGWAF_TLS_ENABLED=false` behind a proxy that terminates TLS.
- [ ] Allow port `9090` (gRPC control plane) only from your agent hosts — it is
      not needed by end users.
- [ ] Use bounded health probes (`curl --connect-timeout 2 --max-time 3`) and an
      external watchdog; a container healthcheck process can itself hang when
      the listener is saturated, leaving the status stale.
- [ ] Never expose PostgreSQL (`5432`) publicly; keep it on a private network or
      the Docker Compose internal network.
- [ ] Restrict `80`/`443` to the sites you intend to serve.
- [ ] Use a host firewall (`ufw`, security groups) in addition to binding
      addresses.

### Transport security

- [ ] Enable TLS for every site (ACME/Let's Encrypt or uploaded certificates)
      and force HTTPS with HSTS — see
      [`docs/user-guide.md` → SSL Certificate Management](./docs/user-guide.md#ssl-certificate-management).
- [ ] Set the minimum TLS version to 1.2 or 1.3 per site.
- [ ] Keep gRPC control-plane TLS enabled (the default; a self-signed CA is
      generated on first boot). Do not set `grpc_tls_mode = "off"` for agents
      connecting over any network you do not fully control — the server warns
      at startup and the console shows a degraded banner while it is off.
- [ ] Protect ACME/DNS provider credentials as you would protect TLS private
      keys.

### Reverse-proxy trust

- [ ] When a site sets `trust_proxy_headers: true`, also list the proxy/CDN
      source ranges in `trusted_proxy_ranges` (or reference an IP group such
      as the built-in Cloudflare subscription via `trusted_proxy_group_ids`).
      Trust is strict: with no ranges configured the forwarded client-IP
      header is ignored and the TCP peer is used, so sites upgraded from
      earlier releases must add their proxy ranges to keep CDN-aware rules
      (rate limiting, allowlists, geo) working.

### Availability trade-offs

- [ ] Disconnected behaviour defaults to fail-open at every layer: an agent
      keeps proxying traffic when it cannot reach the control plane, which
      favours availability over enforcement. Per-site failover policies and
      the control-plane-wide default (console → settings) override the
      agent's local `--fail-open` once synced. For high-security deployments
      where unfiltered traffic is unacceptable, set the global default — or
      individual sites — to fail-closed, or start agents with
      `--fail-open=false`, and accept the availability trade-off.
- [ ] Right-size `--log-batch-size`, `--max-body-log-size` and
      `PINGWAF_DB_MAX_CONNECTIONS`; consider shipping logs to Elasticsearch
      instead of retaining everything in PostgreSQL.
- [ ] Run the service as an unprivileged user with the hardened
      [`pingwaf.service`](./pingwaf.service) unit (`NoNewPrivileges`,
      `ProtectSystem=strict`, read-only paths).

### Operations

- [ ] Track the version/commit you run and upgrade promptly when a security
      advisory is published.
- [ ] Back up PostgreSQL regularly (`pg_dump`) — see
      [`docs/deployment.md` → Backup & Recovery](./docs/deployment.md#backup--recovery).
- [ ] Monitor **Logs → Security**, **Agents** (offline/degraded state) and the
      health endpoint `GET /healthz`.
- [ ] Set `RUST_LOG=info,sqlx=warn` in production; use `debug` only while
      investigating, since debug output is far more verbose.
- [ ] Keep the host patched and verify system clocks are NTP-synchronised —
      skewed clocks weaken token validation.

## Further Reading

- [`docs/quick-start.md`](./docs/quick-start.md) — installation and configuration reference
- [`docs/deployment.md`](./docs/deployment.md) — production deployment, TLS, firewall, upgrades
- [`docs/api.md`](./docs/api.md) — REST API and authentication
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — development setup and code style
