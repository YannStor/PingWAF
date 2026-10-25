# PingWAF User Guide

## Getting Started

### First Login

1. Open the dashboard at `https://your-server:9080` (self-signed certificate
   until you upload a real one under Settings → Control plane HTTPS)
2. Log in with the seeded credentials:
   - Email: `admin@pingwaf.local`
   - Password: `pingwaf123`
3. **Change your password when prompted**: the console blocks the whole UI
   behind a change-password dialog on the first sign-in (the server refuses
   every authenticated request except the auth endpoints). Changing the
   password revokes all of that account's sessions, so the console signs you
   out and asks you to sign in again with the new password — the flag is
   stored per account, not per browser

### Dashboard Overview

The dashboard provides:
- **Analytics**: Request trends, per-site traffic over time, top rules triggered, status codes
- **Sites**: Manage protected websites
- **Agents**: Monitor connected data-plane agents
- **Logs**: Security events and access logs
- **Account**: Profile, password, personal API keys and (for
  administrators) user management
- **Settings**: Elasticsearch, global preferences, origin certificate verification, control-plane HTTPS. Administrator-only pages (**Config versions**, **Lifecycle**) redirect other roles to the dashboard. System observation lives on the dedicated **/system** page (admin-only, from the account dropdown) rather than the settings page.
- **Config versions**: every configuration snapshot, with per-table diff and rollback

## Adding a Website

### Step 1: Create a Site

Navigate to **Sites → Add Site**:
- **Name**: Human-readable label (e.g., "Production API")
- **Domain**: The hostname to protect (e.g., `api.example.com`)
- **Plan**: `free`, `pro`, or `enterprise` (affects feature limits)

### Step 2: Configure Upstreams

Each site needs at least one origin server:

```
Sites → [your site] → Origin → Add node
```

The **Origin** tab is a site's default view. Every site starts with a `default` origin pool, and the first node you add goes into it — see [Origin Pools & Routes](#origin-pools--routes) for pools, load balancing and path-based dispatch.

| Field | Description |
|-------|-------------|
| Node name | Label for this origin (e.g., "origin-1") |
| Origin address | Origin `host:port` (e.g., `10.0.0.1:8080`) |
| Weight | 1–10000; round robin splits traffic by weight (default: 1) |
| Pool | Origin pool the node belongs to |

### Step 3: DNS Setup

Point your domain's DNS to the PingWAF server:
- **A record**: `api.example.com → YOUR_PINGWAF_IP`
- **CNAME**: If behind a load balancer

### Step 4: SSL Certificate

See [SSL Certificate Management](#ssl-certificate-management) below.

## Origin Pools & Routes

Open **Sites → [your site] → Basic** to manage origin pools, load balancing,
route dispatch and reverse-proxy trust.

### Reverse-Proxy Trust

When the site sits behind a CDN or a reverse proxy (Cloudflare, nginx, a load
balancer), the TCP peer address is the proxy, not the visitor. Enable
**Reverse-proxy trust** on the Basic page to resolve the client IP from a
trusted header instead:

| Setting | Description |
|---------|-------------|
| Front-end CDN / reverse proxy | Enables header-based client IP resolution |
| Trusted header | Which header carries the client IP; defaults to `X-Forwarded-For` (`CF-Connecting-IP`, `X-Real-IP`, `True-Client-IP` and `Forwarded` are also offered) |
| Trust last hop only | Use only the right-most value of the header and discard everything else |

With trust enabled, IP block lists, rate limiting (CC), access rules and the
client IP recorded in logs are all derived from that header. Only enable it
when every request really passes through the proxy — otherwise visitors could
spoof their IP by sending the header themselves.

### Origin Pools

An origin pool is a set of origin nodes sharing one load-balancing algorithm and origin protocol.

| Field | Description |
|-------|-------------|
| Pool name | Label for the pool (e.g., "primary") |
| Load balancing | `Round robin` or a hash algorithm (see below) |
| SNI hostname | Non-empty enables **HTTPS to origin**; must be a bare hostname covered by the origin certificate (`$host` is not supported) |
| Verify origin certificate | Whether an HTTPS origin's certificate is validated. Unset inherits the site default (SSL page's origin certificate check) and then the global setting from the console's system settings; `true` requires a certificate that validates against the system trust store (or the pool's own CA); `false` accepts any certificate and is not recommended. |

Load-balancing algorithms:

| Algorithm | Spec | Behavior |
|-----------|------|----------|
| Round robin | `round_robin` | Spreads requests by node weight |
| Least connections | `least_connections` | Picks the node with the fewest in-flight requests |
| Random | `random` | Picks a node at random (weight-aware) |
| IP hash | `hash:ip` | Pins the same client IP to one node |
| URL hash | `hash:url` | Pins by request URL |
| Path hash | `hash:path` | Pins by request path |
| Header hash | `hash:header:<name>` | Pins by a request header value |
| Cookie hash | `hash:cookie:<name>` | Pins by a cookie value |
| Query hash | `hash:query:<name>` | Pins by a query-string parameter |

The site's default pool (marked **Default**) cannot be deleted, and a pool can only be deleted once no origin nodes and no routes reference it.

The **Verify origin certificate** field only matters when the pool has an SNI
hostname. Left unset it follows a three-level cascade: the site default on the
site's SSL page (**Origin certificate check**), and when the site has no
preference either, the deployment-wide default under **Settings → Origin TLS
verification**, which is off — accepting any certificate so that self-signed
and internal-PKI origins keep working. Turn the global default on once every
origin presents a certificate the proxy can chain to a trust store (a private
CA counts; upload it to the pool), pin the site default for a whole site, and
leave per-pool overrides unset unless a specific origin cannot comply.

### Routes

Routes dispatch requests to different pools by path; unmatched traffic goes to the default pool.

| Field | Description |
|-------|-------------|
| Rule name | Label for the route (e.g., "api-to-dedicated-pool") |
| Match | `Prefix`, `Exact`, or `Regex` |
| Path | Starts with `/` (e.g., `/api`), or a regular expression (e.g., `^/static/.*`) |
| Priority weight | 1–60000; empty uses the auto weight (exact 1024 / prefix 512 / regex 256) |
| Target pool | Pool that receives matching traffic |
| Upstream host | Optional; overrides the `Host` header the origin sees for this route. Empty = forward the client's `Host` (historic behaviour) |
| Enabled | Toggle a route without deleting it |

A prefix route on `/` is rejected: it would conflict with the default-pool fallback.

**Upstream host.** Fill this in when the route's pool fronts a virtual host
that routes by `Host` — for example a mirror route to `google.com`: without
an override the origin sees your site's domain and answers 404. The value
must be a bare host name (at most 253 bytes, no scheme `://`, no path `/`,
no whitespace or control characters; a port is accepted). Other rewrite
knobs on the same route: **Strip path prefix** removes the matched prefix
(`/api/users` → `/users`), **Rewrite path** replaces the whole forwarded
path — see the [API docs](api.md#post-sitessite_idroutes) for exact
semantics.

## WAF Configuration

The Web Protection page is organized into three tabs — **Managed rules** (attack categories, built-in rules, deep inspection, backend stacks), **Custom rules** (posture and user-defined rules) and **Rate limiting & challenge** (rate-limit entry plus challenge settings).

### Security Modes

Each site operates in one of three modes. The console labels are shown first;
the value in parentheses is what the API expects:

| Mode | API value | Behavior |
|------|-----------|----------|
| **Off** | `off` | Traffic passes through without inspection |
| **Detection** | `monitor` | Rules evaluated, matches logged, but not blocked |
| **Prevention** | `block` | Rules evaluated, matches blocked with configured action |

The enforcing value is `block` — **not** `enforce` or `prevention`. The API
rejects anything else with a `400` that lists `off|monitor|block`. The same enum
applies per rule; see [Rule modes](#rule-modes).

Set via: `Sites → [site] → Web Protection → Custom rules`

### Rule modes

Every rule has its own `mode`: `off` (fully disabled — the rule is not
compiled, not evaluated and produces no security event or log entry),
`monitor` (detect and record, never enforce) or `block` (enforce the rule's
action); `enabled: false` is equivalent to `off` and also takes the rule out
of evaluation. A brand-new site is seeded with the built-in rule set in
`block`, so switching the WAF on protects it immediately; restored defaults on
an existing site come back as `monitor` so a repair never starts blocking
traffic that site was serving unfiltered.

The site mode caps the rules: with the site in **Detection** (`monitor`), a rule
that says `block` is *downgraded*, not ignored. The request passes, and the
security event shows both sides — `action: monitor` with `waf_details` ending in
`downgraded=true would_enforce=block cause=site-mode-monitor`, plus the rule's
own `rule_action=block`. If the event has no `downgraded=true`, the rule itself
was configured to observe.

### Rule Groups

Rules are organized into groups that execute in order:

| Phase | Description |
|-------|-------------|
| `request` | Evaluated on incoming requests |
| `response` | Evaluated on upstream responses |
| `custom` | User-defined rule groups |

### Custom Rules

Each rule defines a condition and an action:

**Conditions** (match any):
- Request URI path (regex or prefix)
- HTTP method
- Request headers
- Query parameters
- Request body content
- IP address / CIDR range
- User-Agent string
- Country (GeoIP)

**Actions**:
- `allow` — Skip remaining rules, permit request
- `block` — Return 403 Forbidden
- `challenge` — Show CAPTCHA/JS challenge
- `rate_limit` — Apply rate limiting
- `log` — Log only, do not block
- `redirect` — Redirect to a URL

### Managed Rules

PingWAF includes built-in protection against SQL injection, XSS, remote code execution, path traversal, command injection and protocol violations. The protection page splits this into two cards:

**Attack categories** (9): `sqli`, `xss`, `rce`, `lfi`, `ssrf`, `deser`, `crlf`, `xxe`, `ssti`. Each category is a two-state switch — **Block** (default) or **Log only**. Log-only keeps the family's detection and logging fully active but stops blocking its matches. There is no per-category "off": detection always runs.

**Built-in rules**: each of the built-in managed rules has its own Block / Log-only switch, independent of the category switches. Batch buttons switch all rules at once. Because a family's rules (SQLi, XSS, RCE score gates) and its category switch control the same signature surface, downgrading a category also flips its family rules to log-only; switching the category back removes those per-rule downgrades, resetting any individual overrides made in between.

**Deep inspection** enables the strict managed rule set plus deep request-body inspection. Higher interception rate at a proportional performance cost. Custom rules receive the same request-body evaluation while deep inspection is on, so body-carrying bypass attempts are caught by user-defined expressions too. On the page the two posture switches — **Under-attack mode** and **Deep inspection** — sit side by side on one row.

**Backend stacks** (`java`, `php`, `python`, `node`) downgrade stack-specific detections the same way; language-agnostic detections are never affected by a stack switch. Stack switches are collapsed by default.

A site without explicit settings inherits the aggregate of its enabled rules: `block` when any rule blocks, otherwise `monitor`. It never silently lands on `off` — an unconfigured site keeps detecting and logging, and only an explicit **Off** (or the engine switch) turns inspection off.

### Under Attack Mode

```
Sites → [site] → Web Protection (top banner)
```

A site-wide emergency switch: every visitor is challenged with a JavaScript check, and CC protection is switched on automatically. Enable it only while the site is under an active flood attack and disable it once the attack subsides.

## Rate Limiting

Configure per-site rate limits:

```
Sites → [site] → Rate Limiting → Add Rule
```

| Field | Description |
|-------|-------------|
| Name | Rule label |
| Threshold | Max requests allowed in the period |
| Period (seconds) | Time window for counting (1–86400) |
| Action | `block`, `log`, `challenge`, `js_challenge`, or `allow` |
| Characteristics | How to group traffic: `ip`, `ip_nat`, `host`, `path`, `asn`, `country`, plus parameterized forms `header:<name>`, `cookie:<name>`, `query:<name>` |
| Filter expression | Optional match condition (empty = all requests) |
| Mitigation timeout | How long the action applies once triggered (0–86400 seconds) |

Example: Limit to 100 requests per 60 seconds per IP on `/api/*`.

Requests missing the header, cookie or query parameter bucket together, so they still count against the limit. Header names match case-insensitively; cookie and query names are case-sensitive. The `ja3` characteristic is reserved for future use and is not yet accepted by the API.

## Challenges (CC Protection)

### Challenge Settings

```
Sites → [site] → Web Protection → Rate limiting & challenge
```

Dimension-based rate limit rules live on the separate Rate Limiting page; this tab links to it and holds the challenge settings below.

| Setting | Options |
|---------|---------|
| Mode | `off`, `passive`, `active` |
| Type | `js_challenge`, `captcha`, `managed` |
| Expiry | How long a passed challenge remains valid |

- **Passive**: Challenge only when suspicious behavior is detected
- **Active**: Challenge all requests matching configured criteria

## Cache Configuration

### Cache Rules

```
Sites → [site] → Cache Rules
```

| Field | Description |
|-------|-------------|
| Name | Rule label |
| Path pattern | URI pattern to cache (e.g., `/static/*`) |
| Edge TTL | How long to cache at the edge (seconds) |
| Browser TTL | `Cache-Control: max-age` sent to clients |
| Status | `enabled` or `disabled` |

### Cache Purging

Purge cached content immediately:

```
Cache → Purge
```

Options:
- Purge all cache for a site
- Purge by URL pattern
- Purge by cache tag

### Disk Quotas

Monitor cache disk usage:

```
Cache → Status
```

Shows per-site cache size and hit rates.

## SSL Certificate Management

### Automatic (ACME / Let's Encrypt)

```
Sites → [site] → Certificates → Add → Let's Encrypt
```

**Challenge Types:**
- **HTTP-01**: Requires port 80 reachable. Best for most setups.
- **DNS-01**: Supports wildcard certificates. Providers (`dns_provider` value in parentheses):
  - Aliyun (Alibaba Cloud) — `ali`
  - Cloudflare — `cf`
  - DNSPod (Tencent Cloud) — `tencent`
  - Huawei Cloud — `huawei`
  - Manual — anything else

Certificates auto-renew 30 days before expiry.

### Manual Upload

```
Sites → [site] → Certificates → Add → Upload
```

Provide:
- Certificate (PEM format, including chain)
- Private key (PEM format)
- Domain names covered

### SSL Settings

```
Sites → [site] → SSL Settings
```

- Minimum TLS version (1.2 or 1.3)
- Force HTTPS redirect
- HSTS configuration
- OCSP stapling

### Certificate Status and Events

Agents report each site's certificate status in every heartbeat, shown on the SSL/TLS page:

- **Valid**
- **Expiring soon** — the certificate lapses within 48 hours
- **Expired**

The SSL/TLS page also keeps an event log per certificate — created, renewal requested, renewed, failed, deleted, plus raw ACME output — so issuance attempts can be followed from the console.

## Request/Response Rewriting

### Rewrite Rules

```
Sites → [site] → Rewrite Rules → Add
```

| Field | Description |
|-------|-------------|
| Type | `request` or `response` |
| Match | URL pattern (regex) |
| Replace | Replacement string |
| Headers | Add/remove/modify headers |

Examples:
- Strip `/api/v1` prefix: match `^/api/v1/(.*)` → replace `/$1`
- Add security headers: `X-Frame-Options: DENY`
- Remove `Server` header from responses

### Response Body Replacement

Beyond headers, a site can rewrite strings inside response bodies. Configure
it from the site's **Rewrite Rules** page (the card sits under the rule list)
or via `PUT /api/v1/sites/{site_id}` with a `response_replace` object — see
the [API docs](api.md#put-sitessite_id) for the full field list:

```json
{
  "path": "^/status",
  "status_codes": [200],
  "rules": [
    { "pattern": "Google", "replacement": "PingWAF", "is_regex": false }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `path` | Regex the request path must match; empty = every path |
| `status_codes` | Status codes to rewrite; empty = all. Each entry 100–599 |
| `rules` | Up to 20 replacements, applied in order |
| `rules[].pattern` | Text (1–512 bytes) matched literally, or as a regex when `is_regex` is set (regex must compile) |
| `rules[].replacement` | Substitution text (1–2048 bytes); with `is_regex`, `$1` / `$name` refer to capture groups |
| `rules[].is_regex` | Compile `pattern` as a regex instead of a literal |

Two hard constraints, enforced with a `400` at save time: a rule's pattern
or replacement may **not contain a single quote**, and neither side may be
empty. Clearing the policy is done with `null` — or an empty `rules` list,
which counts as "no policy".

**Compressed responses.** The replacement understands `gzip` / `x-gzip` and
`deflate` responses: the body is decompressed, rewritten and recompressed with
the same algorithm, so `Content-Encoding` is preserved. Responses with `br`,
`zstd` or multi-value encodings (e.g. `gzip, br`) are passed through untouched.
Note that even when no rule matches, a compressed response the plugin handles
is re-chunked and its strong `ETag` weakened. Bodies **larger than 8 MiB after
decompression** are passed through as the original compressed bytes.

## Custom Error Pages

```
Sites → [site] → Error Pages → Add
```

| Field | Description |
|-------|-------------|
| Status code | HTTP status to customize (e.g., 403, 429, 502) |
| Content type | `html`, `json`, or `text` |
| Body | Custom response content |

## Log Management

### Viewing Logs

**Security Events**: `Logs → Security`
- Filtered by site, rule, action, time range
- Shows matched rule, client IP, request details

**Access Logs**: `Logs → Access`
- All proxied requests with timing information
- Filter by status code, path, client IP
- Request headers and a body preview (first 1 KiB) are stored in PostgreSQL, so requests can be inspected from the dashboard without Elasticsearch

#### Unassigned (no Host header) traffic

Requests that arrive at a bare IP with no `Host` header (HTTP/1.0 clients,
health probes, scanners) are proxied by the default site and their managed-rule
protection stays active, but they cannot be attributed to any site. Both log
views record them with a null site — shown as an **unassigned** badge in the
global log views — so they remain traceable:

- The site filter offers an **unassigned traffic** option (or search
  `site:none`) to list only these requests.
- Search `type:` in Security Events narrows by event type (`managed`, `waf`,
  `ip_geo`, `bot`, `rate_limit`, `challenge`).

### Elasticsearch Integration

For high-volume deployments, ship logs to Elasticsearch:

```
Settings → Elasticsearch
```

| Setting | Description |
|---------|-------------|
| URLs | Comma-separated ES endpoints |
| Index prefix | Prefix for daily indices |
| Username/Password | Basic auth credentials |
| API Key | Alternative to basic auth |
| Max body size | Truncation limit for logged bodies |

Enable the Elasticsearch shipper via environment:
```bash
PINGWAF_ES_ENABLED=true
PINGWAF_ES_URLS=http://elasticsearch:9200
```

### Log Retention

Purge old logs:
```
Logs → Purge (select age threshold)
```

## Account & User Management

**Account** is a top-level menu, separate from Settings. It holds the signed-in
user's profile, password, API keys, and — for administrators — the user list.

### Profile & Password

Update your display name and email, or change your password (current password
required; the new one must be at least 8 characters). Changing the password,
or the email you sign in with, signs you out everywhere — including this
browser — so you are asked to sign in again. Your personal API keys live on the
same page: any account can mint keys for itself, but only an administrator's
key can carry more than `read` (a non-administrator's request is silently
narrowed to `read`).

### User Management (administrators)

Administrators see a **Users** card on the Account page:

- **Create** accounts with an email, initial password and role
- **Disable** accounts — a disabled account cannot sign in, and its existing
  tokens are refused on every request
- **Change role** or profile details

Roles:

| Role | Capabilities |
|------|--------------|
| `admin` | Read and write everything, manage users |
| `auditor` | Read-only across every resource — for review/compliance access |
| `viewer` | Read-only |

Self-lockout is prevented: an administrator can neither downgrade nor disable
their own account, and the last enabled administrator can never lose admin
access.

### Forced First-Sign-In Password Change

Accounts seeded with the shipped default password — the first administrator on
a fresh deployment, and any account created with `pingwaf user add-admin` —
start with a `must change password` flag. On the first sign-in the console
blocks the whole UI behind a change-password dialog, and the server refuses
every authenticated request except the auth endpoints until the password is
replaced. Changing the password clears the flag and revokes every session, so
the console sends you back to the login form.

### JWT Secret Provisioning

On the very first boot, if no JWT secret is configured (via
`PINGWAF_JWT_SECRET`), the control plane generates a random 256-bit secret and
persists it in the database; every later boot reuses it. This removes the
historical default-secret foot-gun in open-source deployments: without an
explicitly configured secret, tokens are still signed by a unique per-install
key. An explicitly configured secret always wins.

## Agent Management

### Adding Agents

1. Generate an API key: **Account → API keys → Create**
2. Install the agent on the edge server:
   ```bash
   pingwaf agent --server-url http://control-plane:9090 --api-key YOUR_KEY
   ```
3. The agent appears automatically in **Agents**

### Monitoring Agents

The Agents page shows:
- Connection status (online/offline/degraded)
- Last heartbeat time
- System info (hostname, OS, CPU, memory)
- Agent version
- Pending commands

### Agent Commands

Push commands to connected agents:
- **Reload Config**: Force immediate config sync
- **Block IP**: Temporarily block an IP address
- **Unblock IP**: Remove a temporary block
- **Purge Cache**: Clear local cache
- **Restart Agent**: Graceful agent restart

## Access Control

Per-site IP rules and geo restrictions live on one page:

```
Sites → [site] → Access control
```

Switch between the **IP rules** and **Geo restrictions** tabs with `?tab=ip` / `?tab=geo`; links to the former separate IP-rules and geo pages redirect here automatically.

### IP Rules

| Field | Description |
|-------|-------------|
| Rule name | Label for the rule (e.g., "Block scraper subnet") |
| Target | A manual **IP / CIDR** list, or an **IP group reference** whose ranges always follow the group's latest contents |
| IP/CIDR | Address or range (e.g., `192.168.1.0/24`) — manual mode only |
| Action | `block`, `allow`, `challenge`, or `js_challenge` |
| Note | Why this rule exists (audit) |
| Priority | Lower values are matched first |

IP rules are evaluated before the WAF. Bulk import accepts one IP or CIDR per line.

### Geo Restrictions

Block or allow traffic by country and ASN:

- **Mode**: `block_list` (block specific countries) or `allow_list` (allow only specific countries)
- **Countries**: ISO 3166-1 alpha-2 codes (e.g., US, CN, DE)
- **Blocked ASNs**: deny entire autonomous systems (e.g., `AS13335`)
- **Block unknown locations**: deny traffic whose location cannot be determined
- **Action**: how matched traffic is handled

A "Requests by country" chart (last 24 hours) sits next to the policy editor.

### Global IP Groups

**IP Groups** (in the sidebar) manages named collections of IP ranges, either **global** (applied to all sites) or **per-site** (assigned to selected sites). Each group has an action: `block` or `allow`.

Groups can subscribe to an external list instead of (or in addition to) manually entered ranges:

| Field | Description |
|-------|-------------|
| Subscription Source URL | URL of the list to fetch (e.g., `https://example.com/ip-list.txt`) |
| Refresh interval | Manual only, hourly, every 6 hours, daily, or weekly |

A background scheduler refreshes enabled subscriptions when their interval elapses; use **Sync now** to refresh immediately. A failed sync keeps the previous ranges and records the error, which is shown on the group's row as the last sync error.

One group, **Cloudflare**, is seeded on first boot: the official Cloudflare IP ranges from `https://api.cloudflare.com/client/v4/ips`, refreshed daily. It starts disabled — enable it once you know how it fits your traffic.

Site IP rules can reference a group instead of enumerating ranges; see [IP Rules](#ip-rules) above.

## Bot Protection

```
Sites → [site] → Bot Protection
```

| Setting | Description |
|---------|-------------|
| Enable bot protection | Turn classification on or off |
| User-Agent analysis | Inspect the User-Agent header to classify traffic |
| Bot action | `block`, `challenge`, or `log` — applied to traffic classified as a bot (non-browser user agents) |
| Known bots | Whitelist of good crawlers that always pass |

How a request is classified:

1. Verified bots whose User-Agent matches a **known bots** entry pass.
2. Real browsers (known browser user agents) pass.
3. Everything else receives the configured **bot action**.

Known-bot entries are case-insensitive substrings matched against the User-Agent header (e.g., `Googlebot`); the console offers quick-add suggestions for common crawlers.

JavaScript detection, TLS fingerprinting and behavioral analysis appear in the console as *Coming soon* — they are roadmap items, not implemented yet.

## AI Assistant

```
Settings → AI assistant · sidebar assistant icon
```

The console embeds an AI assistant that answers questions about your deployment by calling the same MCP tools external clients use (see below). Configure an OpenAI-compatible provider under **Settings → AI assistant**:

| Setting | Description |
|---------|-------------|
| Enable assistant | Master switch; the AI Assistant page prompts for setup while it is off |
| Base URL | OpenAI-compatible endpoint, e.g. `https://api.openai.com/v1` |
| Model | Model name, e.g. `gpt-4o-mini` |
| API key | Provider credential, stored server-side and shown masked afterwards |
| Temperature | 0–2; lower answers change less between runs |
| Max tool rounds | How many tool-call rounds one answer may take (1–10) |
| System prompt | Prefilled with the built-in default; clear and save to reuse it |
| Allow write tools | Off by default; enables the tools that change state (observation mode, site enable/disable) |

**Test draft** verifies the provider without saving. Once enabled, ask a question on the AI Assistant page and watch tool calls appear inline as the answer streams. Conversations are stored server-side, so history survives reloads, and the assistant is administrator-only.

## MCP Server

```
Settings → MCP server
```

Every deployment hosts an MCP (Model Context Protocol) endpoint at `/mcp` on the console origin, so external AI agents — Claude Code, IDE copilots, scripts — can inspect and operate the firewall. The Settings card shows the live endpoint, the tool inventory (write tools tagged), and copy-paste client snippets.

To connect a client you need an API key (**Account → API keys**) with the `read` permission; add `write`, whose owner must be an administrator, for the two tools that change state. Then paste the card's JSON into the client, or for Claude Code run:

```bash
claude mcp add --transport http pingwaf https://waf.example.com:9080/mcp \
  --header "Authorization: Bearer pwk_YOUR_KEY"
```

Read-only credentials see only the read tools; administrators with a `write` key may also call `set_observation_mode` and `set_site_status`. The endpoint sits behind the same API protection as the console (access log, IP allowlist, WAF), so it obeys whatever **Settings → API protection** allows.

## Config Versions

**Config versions** in the sidebar records a version of the configuration on
every change and lets you roll one back. Administrators only: other roles are
redirected away from the page.

- **The list** shows each version's scope (site domain, global settings or full
  deployment), config hash, source, operator and row counts. Filter by scope
  and date, and page through the history. Versions older than 30 days and
  entries beyond the newest 50 per scope are pruned at startup, daily and on
  demand with **Prune old versions**.
- **The detail view** compares a version with the one before it, table by
  table, so you can see exactly which rows a change touched before deciding.
- **Rollback** archives the live state first, restores the selected snapshot
  and pushes it to the agents, behind a confirmation. It is recorded as a new
  version and can be rolled back in turn.

### Encrypted configuration backups

The same page also manages complete encrypted backups:

1. **Add a target** (optional): an S3-compatible endpoint/bucket or a GitHub
   repository. Credentials are sealed with `PINGWAF_SECRET_KEY` and never
   returned by the API. Use **Test connection** before the first upload.
2. **Create encrypted backup now** and enter a backup password of at least 12
   characters. The password is used only for that operation and is not stored
   or logged. Choose a remote target or keep the backup local, then download
   the `.pwb.json` envelope for safekeeping.
3. **Upload backup file** to restore. Enter the same password and review the
   dry-run: before/after rows, additions, removals, changes, owner mappings
   and warnings. No secret values are shown. A deployment restore requires a
   complete schema-2 snapshot; an invalid password, checksum or scope is
   refused.
4. **Confirm full replacement** only after reviewing the impact. PingWAF
   creates a fresh encrypted pre-restore backup and applies the change in one
   serializable transaction. If anything fails, no partial configuration or
   pre-restore record is left. On success the pre-restore backup remains
   available as a way back, and runtime refresh failures are reported as
   warnings rather than hidden.

Backups include the restorable database configuration (sites, rules, shared
resources, OIDC, visitors and grants, notifications, AI, cache and
certificates). They exclude console identities, agent state, logs, temporary
authentication state, environment variables and local GeoIP files. Restoring
sealed AI or notification credentials requires the current instance's
`PINGWAF_SECRET_KEY`. Backup records follow the same 30-day and per-scope
retention policy, and abandoned uploads become retryable after their lease
expires.

## Internationalization (i18n)

The dashboard supports multiple languages:
- English (default)
- 中文 (Chinese)
- 日本語 (Japanese)

Language is auto-detected from the browser. Override via the language selector in the dashboard header.
