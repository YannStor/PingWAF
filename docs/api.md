# PingWAF REST API Reference

Base URL: `https://your-server:9080/api/v1`

The control plane serves HTTPS by default (`tls_enabled = true`) with a
self-signed certificate generated on first boot, so `curl` needs `-k` until the
certificate is trusted or replaced (see
[Control-plane certificate](#control-plane-certificate)). When TLS is disabled
(`tls_enabled = false`, e.g. TLS terminated by a reverse proxy) the same port
serves plain HTTP.

Cleartext requests to a TLS-enabled listener are answered with `308 Permanent
Redirect` to the `https://` URL on the same host, so scripts should either use
`https://` directly or follow redirects. The two health endpoints (`/healthz`
and `/api/v1/health`) are exempt and answer on both schemes, which keeps
container health checks working without a certificate.

## Authentication

All endpoints (except `/auth/login`, `/auth/register`, `/auth/status`, the
passkey sign-in pair `/auth/passkey/login/begin`, `/auth/passkey/login/finish`,
`/health` and `/version`) require a Bearer token:

```
Authorization: Bearer <access_token>
```

### POST /auth/login

Authenticate and receive tokens.

**Request:**
```json
{
  "email": "admin@pingwaf.local",
  "password": "pingwaf123"
}
```

**Response (200):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 43200,
  "user": {
    "id": "uuid",
    "email": "admin@pingwaf.local",
    "name": "Administrator",
    "role": "admin",
    "must_change_password": false,
    "disabled": false,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

The user object (also returned by `GET /auth/me`) carries two extra flags:
`must_change_password` is `true` for freshly seeded accounts — the server
rejects every write until the password is changed — and `disabled` accounts
cannot sign in at all.

### POST /auth/register

Create a new account (when registration is open).

**Request:**
```json
{
  "email": "user@example.com",
  "password": "secure-password",
  "name": "Optional Name"
}
```

**Response (201):** Same as login.

### POST /auth/refresh

Exchange a refresh token for new tokens.

**Request:**
```json
{
  "refresh_token": "eyJ..."
}
```

**Response (200):** Same as login.

### GET /auth/status

Check if setup is needed, and which credential types this deployment offers.

**Response (200):**
```json
{
  "needs_setup": false,
  "registration_open": true,
  "passkey_enabled": true
}
```

### GET /auth/me

Get current user profile. Same shape as the `user` object above, including the
`must_change_password` and `disabled` flags.

### PUT /auth/me

Update current user profile. Optionally change the login name (the `email`)
by supplying `email` together with `current_password` — the server answers
`400` when the password is missing or wrong and `409` when the login name is
already taken. A login-name change revokes every outstanding token, so the
console must sign in again.

**Request:**
```json
{
  "name": "New Name",
  "email": "new-login-name@example.com",
  "current_password": "current-password"
}
```

### PUT /auth/password

Change password. The new password must be at least 8 characters.

**Request:**
```json
{
  "current_password": "old-password",
  "new_password": "new-password"
}
```

**Response (204):** empty.

A wrong `current_password` is a `400` (not a `401`), so clients do not treat a
typo as a dead session. Answers `204` on success. Changing the password also
clears the account's `must_change_password` flag, which is what releases a
first sign-in from the forced password change.

---

## Users

Dashboard user administration. Every route here requires the `admin` role.
Self-lockout is prevented: an administrator can neither change their own role
nor disable themselves, and the last enabled administrator can never be
downgraded or disabled.

Roles: `admin` (read and write everything), `auditor` (read-only across all
resources) and `viewer` (read-only).

### GET /users

List users (paginated).

### POST /users

Create an account. `role` defaults to `viewer`; `password` must be at least 8
characters. The new account starts with `must_change_password: true`.

**Request:**
```json
{
  "email": "auditor@example.com",
  "password": "start-up-password",
  "name": "Compliance",
  "role": "auditor"
}
```

**Response (201):** the created user object (same shape as `GET /auth/me`).

### PUT /users/{user_id}

Update `name`, `role`, `disabled` and/or `email` (the login name). An
administrator cannot change their own `role`/`disabled` (`400`); downgrading
or disabling the last enabled administrator is rejected with `400` as well.
A login-name change revokes the account's outstanding tokens; a duplicate
login name is rejected with `409`.

---

## Passkeys

Passkeys (WebAuthn) are an alternative sign-in for a browser that owns a
platform authenticator or a security key. A passkey is always bound to an
account that is already signed in — the console mints them from Settings →
Passkeys, and the operator then signs in with the fingerprint/face/PIN prompt
instead of a password.

Two conditions must hold for the browser prompt to even appear:

* `GET /auth/status` reports `passkey_enabled: true` (the `passkey_enabled`
  server setting, on by default). When it is `false` every endpoint below
  answers `501`.
* The page is a secure context: HTTPS, or `localhost`. A passkey cannot be
  created for a bare IP address or over plain HTTP on a hostname. The control
  plane therefore serves HTTPS by default with a self-signed certificate that
  can be replaced under [Control-plane certificate](#control-plane-certificate);
  a bare-IP deployment needs that IP in the certificate's SANs.

### GET /auth/passkeys

List the passkeys bound to the signed-in account. Neither the credential id nor
the public key is exposed.

```json
[
  {
    "id": "uuid",
    "name": "Work laptop",
    "created_at": "2024-01-01T00:00:00Z",
    "last_used_at": "2024-02-01T09:12:00Z"
  }
]
```

### PATCH /auth/passkeys/{passkey_id}

Rename a passkey.

**Request:**
```json
{ "name": "Work laptop" }
```

**Response (200):** the updated summary. Names are 1-100 characters.

### DELETE /auth/passkeys/{passkey_id}

Remove a passkey. Answers `204`. The credential can no longer sign in; the
account's password still can.

### POST /auth/passkey/register/begin

Start binding a new passkey to the signed-in account.

**Response (200):** `PublicKeyCredentialCreationOptions` in the WebAuthn JSON
encoding (base64url strings, camelCase fields) to be handed to
`navigator.credentials.create()`.

```json
{
  "rp": { "id": "waf.example.com", "name": "PingWAF" },
  "user": { "id": "…", "name": "ops@example.com", "displayName": "Ops" },
  "challenge": "…",
  "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
  "timeout": 300000,
  "excludeCredentials": [],
  "authenticatorSelection": { "residentKey": "preferred" },
  "attestation": "none"
}
```

### POST /auth/passkey/register/finish

Complete the ceremony with the credential returned by the browser.

**Request:** the standard registration response — `id`, `rawId`, `type`,
`response.{clientDataJSON, attestationObject, transports}` (base64url) plus an
optional `name` label and `clientExtensionResults`.

**Response (201):** the stored passkey summary, shaped like `GET /auth/passkeys`.

### POST /auth/passkey/login/begin

Start a password-less sign-in. Public — no bearer token.

**Response (200):** `PublicKeyCredentialRequestOptions` (base64url `challenge`,
`rpId`, `allowCredentials`) to be handed to `navigator.credentials.get()`.

Because the account is not known yet, the authenticator must be able to
discover the credential (a "discoverable"/resident key). Passkeys minted through
`register/finish` are created as `residentKey: "preferred"`: platform
authenticators make them discoverable by default, but a legacy security key that
refuses to store the credential cannot be used for password-less sign-in.

### POST /auth/passkey/login/finish

Verify the assertion and mint a session. Public — no bearer token.

**Request:** the standard assertion — `id`, `rawId`, `type`,
`response.{clientDataJSON, authenticatorData, signature, userHandle}` (base64url)
and `clientExtensionResults`.

**Response (200):** identical to `POST /auth/login`, so the client stores the
tokens the same way.

**Errors:** every verification failure is a `400` with an `error` message — a
`401` would make the console log the operator out mid-ceremony.

Ceremony state lives in the database with a 5 minute lifetime, so several
control plane replicas can serve one ceremony without sticky sessions.
Unauthenticated challenges share a process-wide budget (120/minute); exceeding
it answers `429`.

**Configuration** (`ServerConfig`, environment overrides):

| Env var | Default | Meaning |
|---------|---------|---------|
| `PINGWAF_PASSKEY_ENABLED` | `true` | Offer passkeys at all |
| `PINGWAF_PASSKEY_RP_NAME` | `PingWAF` | Relying party name shown by the browser |
| `PINGWAF_PASSKEY_RP_ID` | derived from `Host` | Relying party id (registrable domain) |
| `PINGWAF_PASSKEY_ORIGIN` | derived from `Host` | Exact origin the browser must report |
| `PINGWAF_PASSKEY_TRUST_FORWARDED_PROTO` | `false` | Honour `X-Forwarded-Proto` when deriving the origin |

Deriving from `Host` assumes the console is reached directly. Behind a reverse
proxy that terminates TLS, either set `PINGWAF_PASSKEY_ORIGIN` explicitly or turn
on `PINGWAF_PASSKEY_TRUST_FORWARDED_PROTO` — a wrong origin is an opaque
`SecurityError` in the browser, not a helpful message.

---

## Health & Version

### GET /health

Database connectivity check.

**Response (200):**
```json
{"status": "ok", "database": "up"}
```

### GET /version

Build metadata.

**Response (200):**
```json
{
  "name": "pingwaf-server",
  "version": "0.25.0",
  "api": "/api/v1",
  "registration_open": true,
  "grpc_tls": true
}
```

`grpc_tls` reports whether the gRPC control plane serves TLS. `false` means
plaintext traffic (degraded mode) — agents connect unencrypted; the console
surfaces this as a warning on the agents page and the settings "About" card.

---

## Sites

A site is one protected domain plus its origin pools, rules and TLS posture. A
site may serve several hostnames: `domain` is the primary one and
`alternate_domains` lists the rest, all sharing the same routing, WAF and cache
configuration. Wildcards are accepted in the leading label (`*.example.com`)
and only match subdomains — the bare domain needs its own entry. A wildcard
never matches the apex, so `example.com` plus `*.example.com` is a valid pair.

Two sites may not claim overlapping hostnames: identical names, a wildcard
covering another site's hostname, and nested wildcards are all rejected with
`400` because pingap's host matching would make the winner depend on
configuration order. A conflicting `domain` is additionally guarded by a
database unique constraint: create and update requests return `400` with
`"domain already in use by another site"`. When upgrading to the release that
introduced this constraint (migration `000055`), startup fails and lists the
conflicting domains if the existing data already contains duplicates — resolve
them manually (rename or delete one of the sites) before the upgrade can
complete. An ACME certificate for a wildcard hostname requires the
`dns-01` challenge with a configured DNS provider — `http-01` cannot validate
`*`, and the API refuses that combination.

`status` is the site lifecycle:

| Value | Edge behaviour |
|-------|----------------|
| `active` | Traffic is proxied normally |
| `paused` | Every request is answered `503` with `Retry-After: 3600` before any rule runs — the certificate keeps serving and the request is still logged, so pausing is visible in the console rather than a silent outage. The site's custom `503` page is used when one is configured. |
| `pending` | Serves normally; a bookkeeping state for sites that are not finished being set up |

Only `paused` changes how traffic is handled.

### GET /sites

List sites (paginated).

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number (default: 1) |
| `page_size` | int | Items per page (default: 50, max: 200) |
| `search` | string | Filter by name/domain |
| `status` | string | Filter by status: `active`, `paused`, `pending` |

**Response (200):**
```json
{
  "items": [
    {
      "id": "uuid",
      "name": "My Site",
      "domain": "example.com",
      "alternate_domains": ["api.example.com", "*.static.example.com"],
      "status": "active",
      "plan": "free",
      "user_id": "uuid",
      "trust_proxy_headers": false,
      "trusted_header": "",
      "trust_last_hop": false,
      "trusted_proxy_ranges": [],
      "trusted_proxy_group_ids": [],
      "origin_verify_cert": null,
      "created_at": "...",
      "updated_at": "..."
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50
}
```

### POST /sites

Create a new site. `upstream_address` is required: a site without an origin cannot serve traffic. The site is created with a `default` origin pool containing that origin.

**Request:**
```json
{
  "name": "My Site",
  "domain": "example.com",
  "alternate_domains": ["*.example.com"],
  "upstream_address": "10.0.1.50:3000",
  "upstream_name": "origin",
  "upstream_tls": false,
  "status": "active",
  "plan": "free"
}
```

**Response (201):** Site object.

### GET /sites/{site_id}

Get site details including upstreams and SSL config.

### PUT /sites/{site_id}

Update site fields, including the status that pauses and resumes a site:

```json
{ "status": "paused" }
```

Only the fields present in the body are touched. `alternate_domains` replaces
the whole list when present; `[]` clears it. Changing `domain` or
`alternate_domains` re-runs the cross-site hostname checks above.

Reverse-proxy trust fields: set `trust_proxy_headers: true` when the site is
behind a CDN/reverse proxy and `trusted_header` names the header the client IP
is resolved from (`x-forwarded-for` default; `cf-connecting-ip`, `x-real-ip`,
`true-client-ip`, `forwarded` accepted). `trust_last_hop: true` restricts the
lookup to the right-most value. With trust enabled, IP block lists, rate
limiting and logged client IPs derive from that header instead of the TCP
peer.

Trust is **strict**: the direct TCP peer must fall inside `trusted_proxy_ranges`
(a list of CIDRs, e.g. `173.245.48.0/20`) for the trusted header to be
believed; otherwise the connection's own address is used and the header is
ignored. An empty list therefore means "trust no one" — set the ranges of
every proxy that can reach the listener. `trusted_proxy_group_ids` references
IP groups (see [IP Groups](#ip-groups)); the union of the group's ranges and
the hand-entered `trusted_proxy_ranges` forms the effective trust scope. The
console's Cloudflare subscription group covers the official CDN ranges for
exactly this purpose.

`origin_verify_cert` sets the site-level default for origin TLS certificate
verification: omitting the key leaves the current value unchanged, `null`
clears the site's preference, and `true`/`false` pins a site-wide default for
every origin pool under the site. It only applies to pools whose own
`verify_cert` is `null` — see [origin pools](#post-sitessite_idupstream-pools) for the
full precedence order.

### DELETE /sites/{site_id}

Delete a site and all associated resources.

---

## Site Upstreams

### GET /sites/{site_id}/upstreams

List origin servers for a site.

### POST /sites/{site_id}/upstreams

Add an upstream (origin node). Without `pool_id` the node joins the site's default pool.

**Request:**
```json
{
  "name": "app-server-1",
  "address": "10.0.1.50:3000",
  "weight": 1,
  "tls": false,
  "pool_id": "uuid"
}
```

`address` is `host[:port]`. A leading `http://` or `https://` is accepted and
stripped (copy-pasting a URL is normal), a trailing `/` is ignored, and anything
longer — a path, query or fragment — is rejected with `400` rather than silently
dropped, because a dropped path also corrupts the SNI derived from the host. To
speak TLS to the origin set `tls: true` or give the pool an `sni`.

### PUT /sites/{site_id}/upstreams/{upstream_id}

Update an upstream.

### DELETE /sites/{site_id}/upstreams/{upstream_id}

Remove an upstream.

### GET /sites/{site_id}/upstream-pools

List origin pools for a site, default pool first. Each pool:

```json
{
  "id": "uuid",
  "site_id": "uuid",
  "name": "default",
  "lb_algorithm": "round_robin",
  "sni": null,
  "verify_cert": null,
  "is_default": true,
  "created_at": "2024-01-01T00:00:00Z"
}
```

### POST /sites/{site_id}/upstream-pools

Create an origin pool.

**Request:**
```json
{
  "name": "primary",
  "lb_algorithm": "hash:cookie:session",
  "sni": "origin.example.com",
  "verify_cert": true
}
```

`lb_algorithm` accepts `round_robin`, `random`, `least_connections` or `hash:<type>[:<key>]` with type in `ip`, `url`, `path` (no key) or `header`, `cookie`, `query` (key required). A non-empty `sni` enables TLS to the origin.

`verify_cert` is tri-state: `true` requires the origin's certificate to validate against the system trust store or the pool's own CA, `false` accepts any certificate (not recommended), and `null` — the default — defers first to the site-level `origin_verify_cert` default and, when that is also unset, to [the global `/settings/origin` value](#get-settingsorigin). Only meaningful when `sni` is set.

### PUT /sites/{site_id}/upstream-pools/{pool_id}

Update an origin pool (`sni: ""` disables origin TLS).

### DELETE /sites/{site_id}/upstream-pools/{pool_id}

Remove an origin pool. Refused with `400` for the default pool and `409` while routes still reference it or origin nodes remain in it.

### GET /sites/{site_id}/routes

List path-based routes for a site, highest priority first. Each route:

```json
{
  "id": "uuid",
  "site_id": "uuid",
  "name": "api-to-dedicated-pool",
  "match_type": "prefix",
  "path": "/api",
  "priority": 512,
  "enabled": true,
  "pool_id": "uuid",
  "ip_group_id": null,
  "ip_group_name": null,
  "strip_prefix": false,
  "rewrite_path": null,
  "created_at": "2024-01-01T00:00:00Z"
}
```

### POST /sites/{site_id}/routes

Create a route.

**Request:**
```json
{
  "name": "api-to-dedicated-pool",
  "match_type": "prefix",
  "path": "/api",
  "priority": 512,
  "enabled": true,
  "pool_id": "uuid",
  "ip_group_id": "uuid",
  "strip_prefix": false,
  "rewrite_path": null
}
```

`match_type` is `prefix`, `exact` or `regex`; `priority` (1-60000) is optional and defaults to the auto weight. `ip_group_id` is optional and must name an existing, enabled IP group visible to the caller whose membership is not empty; `ip_group_name` is filled in on responses.

#### Path rewriting (`strip_prefix` / `rewrite_path`)

Two optional fields control what path the origin receives; both default to
off, so existing routes keep forwarding the request path unchanged.

- `strip_prefix` (boolean, default `false`) — remove the matched `path`
  prefix from the forwarded path. With a rule on `/api`, `/api/users` is
  forwarded as `/users` and `/api` itself as `/`; the query string is kept.
- `rewrite_path` (string or `null`) — replace the **whole** forwarded path
  with this fixed value; the query string is kept. It wins over
  `strip_prefix` when both are set.

`strip_prefix` takes effect only for `match_type: "prefix"` routes — on an
`exact` or `regex` route there is no prefix to strip, so the combination is
rejected with `400`. `rewrite_path` works with any match type: it replaces
the whole path of every request the route matched. Validation for
`rewrite_path`: must start with `/`, at most 2048 characters, and must not
contain `?`, `#`, whitespace or control characters (the client's query
string is appended verbatim, so those would be ambiguous). Saving fails
with `400` on violation.

On `PUT`, `strip_prefix` is tri-state (`true`/`false` set it, absent leaves
it); `rewrite_path` follows the same pattern — absent leaves the stored
value, `null` or a blank string clears it, a value sets it.

Example: to point a site's `/api` traffic at a pool that serves `/users`
without the prefix, create a `prefix` route on `/api` with
`strip_prefix: true` — `/api/users` reaches the origin as `/users`. To send
everything under `/legacy` to a fixed upstream path instead, set
`rewrite_path: "/v2"`.

A route with an IP group only matches clients whose address is inside one of the
group's CIDR ranges. Both conditions are ANDed, so the route above sends
`203.0.113.7` to the dedicated pool for `/api` but leaves every other client on
the default pool. This is how an internal-only or partner-only path is split off
without touching address-based access rules. The IP ranges are resolved when the
configuration is generated, so changing group membership takes effect after the
next configuration push — the agent does not need to be pointed at the group.
Routes without an IP group match any client.

### PUT /sites/{site_id}/routes/{route_id}

Update a route (`priority: 0` resets it to the auto weight; `ip_group_id: null`
clears the group).

### DELETE /sites/{site_id}/routes/{route_id}

Remove a route; matching traffic falls back to the default pool.

---

## Site SSL

### GET /sites/{site_id}/ssl

Get SSL configuration for a site.

### PUT /sites/{site_id}/ssl

Create or update SSL settings. `domain` is required; TLS switches (https, HSTS, mTLS, TLS versions) are shared with the ssl-settings endpoint.

**Request:**
```json
{
  "domain": "example.com",
  "https_enabled": true,
  "min_tls_version": "1.2",
  "hsts_enabled": true,
  "hsts_max_age": 31536000
}
```

### DELETE /sites/{site_id}/ssl

Remove SSL settings.

### GET /sites/{site_id}/ssl-settings

The effective TLS posture of the site.

**Response (200):**
```json
{
  "https_enabled": true,
  "min_tls_version": "1.2",
  "max_tls_version": null,
  "self_signed": false,
  "certificate_id": "uuid",
  "mtls_enabled": false,
  "has_mtls_client_ca": false,
  "mtls_organization": null,
  "mtls_require_client_cert": false,
  "hsts_enabled": true,
  "hsts_max_age": 15552000,
  "always_use_https": true
}
```

### PUT /sites/{site_id}/ssl-settings

Update one or more fields; omitted fields keep their value. Requires the `write`
role.

**Request:**
```json
{
  "hsts_enabled": true,
  "hsts_max_age": 15552000,
  "always_use_https": true,
  "mtls_enabled": true,
  "mtls_require_client_cert": true,
  "mtls_organization": "Acme Devices"
}
```

| Field | Behaviour at the edge |
|-------|-----------------------|
| `hsts_enabled` / `hsts_max_age` | Adds `Strict-Transport-Security: max-age=<n>` to HTTPS responses. `max-age` is 0-63072000 seconds (two years); `hsts_max_age: 0` is what browsers read as "stop pinning", so the console defaults to `15552000` (180 days) when HSTS is switched on. |
| `always_use_https` | Plain HTTP requests are answered `301` with the `https://` equivalent before any rule runs. The two listeners share one location, so this is safe to enable with traffic on both ports. **Browsers cache HSTS**: when testing, keep `hsts_max_age` low or use a throwaway domain, or a redirect will haunt the browser for months. |
| `mtls_enabled` / `mtls_require_client_cert` / `mtls_organization` | Requires a client certificate; see [mTLS](#mtls). |
| `min_tls_version` / `max_tls_version` | Accepted as `1.0`, `1.1`, `1.2` (default) or `1.3`. |

---

## Certificates

### GET /sites/{site_id}/certificates

List certificates for a site.

### Certificate `warnings`

Every response that returns a certificate — the create and update responses,
and the list/show reads below — may carry a `warnings` array:

```json
"warnings": ["certificate domain api.other.com is not served by this site"]
```

The entries name certificate hostnames (from `domain`, a comma-separated list)
that the certificate's **own** site does not serve, i.e. that match neither the
site's `domain` nor its `alternate_domains` (wildcards cover exactly one label,
in both directions, case-insensitively).

**Advisory only — it never blocks anything.** A certificate naming a hostname
the site does not serve is still saved, and `200`/`201` is still returned:
uploading a certificate before adding its hostname, or for a site that serves
it through another edge, are legitimate workflows, and refusing the save would
take HTTPS down over a warning. An empty array means "checked, nothing wrong".

### POST /sites/{site_id}/certificates

Add a certificate (manual upload or ACME request).

**Request (manual):**
```json
{
  "domain": "example.com",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "key_pem": "-----BEGIN PRIVATE KEY-----\n...",
  "issuer": "Let's Encrypt",
  "expires_at": "2025-12-31T23:59:59Z",
  "auto_renew": false
}
```

**Request (ACME):**
```json
{
  "domain": "example.com",
  "acme_email": "ops@example.com",
  "acme_challenge_type": "dns-01",
  "acme_dns_provider": "cloudflare",
  "acme_dns_config": {"api_token": "..."},
  "auto_renew": true
}
```

`acme_challenge_type` is `http-01` or `dns-01`; `acme_dns_provider` is one of `cloudflare`, `route53`, `digitalocean`, `aliyun`, `dnspod`, `cloudxns`, `manual`.

The response is the saved certificate, `warnings` included (see
[Certificate `warnings`](#certificate-warnings)).

### GET /sites/{site_id}/certificates/{cert_id}

Get certificate details, `warnings` included.

### PUT /sites/{site_id}/certificates/{cert_id}

Update certificate. The response carries `warnings` recomputed against the
post-update hostnames.

### DELETE /sites/{site_id}/certificates/{cert_id}

Remove certificate.

### GET /certificates

Certificate applications across every site the caller may see, newest first
(paginated, optionally scoped with `site_id` and filtered with `status`). Each
item is the certificate flattened together with its `site_id`/`site_domain`/
`site_name`, and — like the per-site list — carries
[`warnings`](#certificate-warnings) computed against the certificate's own
site. Hostnames for the whole page are fetched in one query, so paging does not
cost a lookup per row.

### GET /certificates/{cert_id}

Get certificate details across sites, `warnings` included.

### POST /sites/{site_id}/certificates/{cert_id}/renew

Trigger manual certificate renewal (ACME-managed certificates only).

### GET /certificates/summary

Certificate counts across every site the caller may see (administrators: all
sites; other accounts: their own). Handy for a dashboard badge — one call
instead of paging through every site.

**Response (200):**
```json
{
  "total": 12,
  "active": 10,
  "pending": 1,
  "failed": 0,
  "expired": 0,
  "expiring_soon": 1
}
```

`expiring_soon` counts certificates that lapse within the next 30 days,
already-lapsed ones included.

### GET /certificates/{cert_id}/events

Event log for one certificate, newest first (paginated).

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `event_type` | string | Filter by event type (e.g., `created`, `renewal_requested`, `renewed`, `failed`, `deleted`, `acme_raw`) |
| `page` | int | Page number |
| `page_size` | int | Items per page |

**Response (200):**
```json
{
  "items": [
    {
      "id": "uuid",
      "certificate_id": "uuid",
      "site_id": "uuid",
      "event_type": "renewal_requested",
      "message": "Manual renewal requested for example.com",
      "details": null,
      "created_at": "2024-01-01T00:00:00Z",
      "domain": "example.com",
      "site_domain": null
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50
}
```

### GET /ssl-events

Cross-certificate event log for every site the caller may see (paginated). Supports the same `certificate_id` and `event_type` filters; each event additionally carries the resolved `domain` and `site_domain`.

---

## mTLS

Mutual TLS for one site: the edge asks the client for a certificate, and a
request only reaches the origin when that certificate was issued by a CA the
site trusts, has not been revoked, and was issued for this site.

Two halves work together:

* **Trust and revocation** live here — a CA (generated by the control plane or
  imported) plus the client certificates issued from it.
* **Enforcement** is the site's TLS posture: set `mtls_enabled: true` via
  `PUT /sites/{site_id}/ssl-settings`, and `mtls_require_client_cert: true` to
  refuse requests that present no certificate at all. Setting `mtls_organization`
  pins the organization a client certificate must carry, which is what keeps a
  certificate issued for one site from being replayed against another.

Adding or removing a CA rewrites the site's trust anchor and pushes the
configuration; a site that loses its last CA is left with `mtls_enabled: false`
rather than enabled-but-unverifiable.

Only certificates generated here come with a private key, and the key is
returned **exactly once** — when the CA or the certificate is created. Imported
CAs act as trust anchors only.

> Certificates generated by the control plane are stored unencrypted in the
> database. Treat a database dump as key material.

### GET /sites/{site_id}/mtls/cas

List the site's CAs. Private keys are never included; `has_private_key` and the
SHA-256 fingerprint are.

```json
[
  {
    "id": "uuid",
    "site_id": "uuid",
    "name": "Acme device CA",
    "source": "generated",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n…",
    "has_private_key": true,
    "subject_dn": "CN=Acme device CA",
    "serial": "0a1b…",
    "fingerprint_sha256": "9f2c…",
    "expected_organization": "Acme Devices",
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2025-01-01T00:00:00Z",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00Z",
    "certificate_count": 3
  }
]
```

### POST /sites/{site_id}/mtls/cas

Create a CA. Requires the `write` role.

**Request (generate):**
```json
{
  "name": "Acme device CA",
  "organization": "Acme Devices",
  "validity_days": 3650
}
```

**Request (import):**
```json
{
  "name": "Corporate PKI",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n…",
  "organization": "Acme Devices"
}
```

`cert_pem` switches to import mode: the certificate becomes a trust anchor and
no private key is involved. `validity_days` is capped at 3650 for a CA.

**Response (201):** the CA plus `key_pem`, present only for a generated CA and
only on this response.

### DELETE /sites/{site_id}/mtls/cas/{ca_id}

Delete a CA. Refused with `400` while any client certificate issued from it still
exists — revoked ones included, since they are what keeps the revocation list
intact.

### GET /sites/{site_id}/mtls/certificates

List client certificates, revoked ones included (`status` is `active` or
`revoked`). `ca_name` is filled in for convenience.

```json
[
  {
    "id": "uuid",
    "site_id": "uuid",
    "ca_id": "uuid",
    "ca_name": "Acme device CA",
    "name": "laptop-1",
    "common_name": "laptop-1",
    "organization": "Acme Devices",
    "serial": "1f0c…",
    "fingerprint_sha256": "c4d1…",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n…",
    "has_private_key": true,
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2025-01-01T00:00:00Z",
    "status": "active",
    "revoked_at": null,
    "revocation_reason": null,
    "created_at": "2024-01-01T00:00:00Z"
  }
]
```

### POST /sites/{site_id}/mtls/certificates

Issue a client certificate from one of the site's CAs.

**Request:**
```json
{
  "ca_id": "uuid",
  "name": "laptop-1",
  "common_name": "laptop-1",
  "organization": "Acme Devices",
  "validity_days": 365
}
```

`name`, `common_name` and `organization` default to the CA's values; the
validity is capped at the CA's own `not_after`, because a certificate outliving
its CA verifies against nothing.

**Response (201):** the certificate plus `key_pem`, returned exactly once.

### POST /sites/{site_id}/mtls/certificates/{cert_id}/revoke

Revoke a certificate. The fingerprint joins the site's revocation list and the
configuration is pushed, so the very next request with that certificate is
refused with `403` — no waiting for a CRL or an OCSP check.

**Request:**
```json
{ "reason": "laptop lost" }
```

**Response (200):** the updated certificate.

### DELETE /sites/{site_id}/mtls/certificates/{cert_id}

Delete a certificate row. An `active` certificate must be revoked first (`400`
otherwise) so that removing a record cannot quietly re-admit a client that is
still holding the key. Revoking also removes its fingerprint from the deny list;
the request-detail history keeps naming it.

### GET /sites/{site_id}/mtls/certificates/{cert_id}/download

Download the certificate, and its private key when it has one, as a single PEM
bundle (`application/x-pem-file`) suitable for `curl --cert`.

### How a client presents it

```bash
curl --cert laptop-1.pem --key laptop-1.pem https://example.com/
```

Requests that reach the site from a client without a usable certificate are
answered `403` and recorded as access-log rows only — they are not WAF verdicts
and do not show up as security events.

---

## API Keys

Keys authenticate an agent (or any script) without a user password. The
plaintext is shown once, at creation; the row keeps a bcrypt hash and the first
8 characters for display. Agents send the key as `Authorization: Bearer pwk_…`.

### GET /keys

List API keys (paginated). Administrators see every key, other callers see their
own. The plaintext is never returned here.

### POST /keys

Create a new API key. Requires the `write` role.

**Request:**
```json
{
  "name": "Agent Key",
  "permissions": ["agent", "read"],
  "expires_at": "2025-01-01T00:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Label, 1-100 characters (required) |
| `permissions` | string[] | Any of `agent`, `read`, `write`; defaults to `["agent", "read"]` |
| `expires_at` | string | RFC 3339 instant in the future; omitted = never expires |

**Response (201):**
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "name": "Agent Key",
  "key_prefix": "pwk_9f2c",
  "key": "pwk_9f2c8d1e…",
  "permissions": ["agent", "read"],
  "expires_at": "2025-01-01T00:00:00Z",
  "last_used_at": null,
  "created_at": "2024-01-01T00:00:00Z"
}
```

> The full key is returned **only** by this call. `last_used_at` is filled in as
> agents authenticate.

### DELETE /keys/{key_id}

Revoke an API key. Answers `204`; the key stops authenticating immediately.
Administrators may revoke any key, other callers only their own.

---

## Agents

> **Note on `agent_metrics`:** the underlying edge-metric data is still
> collected from agents over gRPC (`ShipMetrics`), stored in the database and
> pruned by the retention policy — only the REST query endpoints were removed
> (October 2026 change). There is no built-in consumer UI for it today.

### GET /agents

List registered agents.

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number |
| `page_size` | int | Items per page |
| `site_id` | string | Filter by site |
| `status` | string | Filter: `online`, `offline`, `degraded` |

**Response (200):**
```json
{
  "items": [
    {
      "id": "uuid",
      "site_id": "uuid",
      "site_domain": "example.com",
      "hostname": "edge-01",
      "ip_address": "10.0.1.5",
      "version": "0.25.0",
      "os_info": "Linux 6.1.0",
      "cpu_cores": 4,
      "memory_bytes": 8589934592,
      "status": "online",
      "last_heartbeat": "2024-01-01T12:00:00Z",
      "registered_at": "2024-01-01T00:00:00Z",
      "last_config_sync_at": "2024-01-01T11:58:00Z",
      "last_policy_sync_at": "2024-01-01T11:58:00Z",
      "connected": true,
      "pending_commands": 0
    }
  ],
  "total": 1
}
```

### POST /agents/enroll

Mint an agent API key and get back the command line that brings a node
online. Any account with write access (non-viewer). The agent registers
itself over gRPC on first connect, so running the returned command is all
that is needed for the node to appear in `GET /agents`.

**Request:**
```json
{
  "name": "edge-01"
}
```

`name` is optional — it labels the minted key in `GET /keys` and defaults to
`agent-enrollment-<timestamp>`. Max `100` characters.

**Response (201):**
```json
{
  "key_id": "uuid",
  "token": "pwk_…",
  "server_url": "waf.example.com:9090",
  "install_command": "curl -fsSL …/install.sh | sudo bash -s -- --mode agent --server-url waf.example.com:9090 --api-key pwk_…"
}
```

`token` is returned exactly once — only its hash is stored. It is already part
of `install_command`; API callers may build their own command from it.
`server_url` is the caller's host plus the configured gRPC port (the bind
address is not routable from another server). The key carries the `agent` and
`read` permissions. Running `install_command` on a fresh host installs the
binary, writes the node configuration and starts the service, so the node
registers itself without further steps.

### GET /agents/{agent_id}

Get agent details.

### GET /agents/{agent_id}/samples

Host probe history (CPU, memory, network, disk), newest first. Cumulative counters (network and disk totals) are returned raw; difference consecutive rows to obtain rates.

**Query params:** `from`, `to` (RFC 3339), `page`, `page_size`.

### DELETE /agents/{agent_id}

Deregister an agent.

### POST /agents/{agent_id}/commands

Send a command to an agent.

**Request:**
```json
{
  "command": "block_ip",
  "payload": {
    "ip": "1.2.3.4",
    "duration_secs": 3600
  }
}
```

**Available commands:**
| Command | Payload |
|---------|---------|
| `rule_update` | `{}` |
| `config_reload` | `{}` |
| `block_ip` | `{"ip": "single address or CIDR", "duration_secs": 3600}` |
| `unblock_ip` | `{"ip": "single address or CIDR"}` |
| `purge_cache` | `{"pattern": "..."}` |
| `update_site` | `{"site_id": "..."}` |
| `restart_agent` | `{}` |

---

## WAF Settings

Per-site switches for the WAF engine and its judgement layers.

### GET /sites/{site_id}/waf/settings

Reads the site's WAF settings, creating the default row on first access.

### PUT /sites/{site_id}/waf/settings

Patch semantics: omitted fields keep their current value.

**Request:**
```json
{
  "waf_enabled": true,
  "advanced_mode": false,
  "monitor_categories": ["sqli"],
  "monitor_stacks": ["java"],
  "monitor_managed_rules": ["930120"],
  "body_stage_timeout_secs": 10
}
```

`waf_enabled` is the explicit engine switch (`true` default). With it off the
data plane skips WAF evaluation for the site entirely — custom rules, managed
rules, CC and bot checks included. `advanced_mode` raises the managed ruleset
to the Strict level with body deep inspection. The three `monitor_*` lists
downgrade matching managed rules to observe-only, described in
[Monitoring downgrades](#waf-rules).

`mode` is the site-level enforcement mode. It accepts exactly three values —
the same enum every rule carries (see [Rule modes](#rule-modes)):

| `mode` | Behaviour at the edge |
|--------|-----------------------|
| `off` | The engine returns immediately: nothing is detected, no events are written.; site-level signature detectors still score |
| `monitor` | Everything is detected and recorded, nothing is blocked. A rule that asks to block is downgraded and the event says so (`downgraded=true`). |
| `block` | Rules enforce their configured action. |

The value that enforces is `block`; `enforce` and `prevention` are **not**
accepted, and a request that sends one is rejected with
`400 unknown mode value 'enforce'; allowed: off|monitor|block` (plus a hint
that `block` is the enforcing value). A site without a settings row falls back
to the aggregate mode of its enabled rules and, when it has none, to `monitor`
— never to `off`, which is only ever an explicit choice.

#### `body_stage_timeout_secs`

Upper bound, in seconds, on how long the data plane may **withhold** a request
body while body inspection runs. With `advanced_mode` on, the edge buffers the
body before handing it to the WAF; this is the wall-clock budget for that wait
— a slow client trickling bytes, or a large upload completing.

| Value | Behaviour |
|-------|-----------|
| `1`–`30` | The window, in seconds. `30` is the default. |
| `0` | **Reset to the default (30).** Accepted on write; the response reports `30`, and `30` is what is stored. |

Anything outside `0..=30` is a `400 body_stage_timeout_secs must be between 0
and 30 (0 resets to the default)` — out-of-range values are rejected rather
than silently clamped, so a caller that sent `50` finds out instead of quietly
running with 30.

`0` meaning "unset / default" is the same rule the data plane applies: a row
that has never been written reads as 30. There is no way to store a *different*
default per site; set `1`–`29` for a shorter window.

The window is a **fail-open** bound, not a block. Expiring it does not reject
the request: the body is released to the upstream with whatever inspection
completed, and the truncated inspection is the price of not letting a trickling
client hold a connection. Keeping it small is therefore the security-relevant
direction — 30s is the ceiling because holding a body longer than that turns
every slowloris-style client into a connection-exhaustion vector.

**Response (200)** — the same fields on `GET` and `PUT`:

```json
{
  "waf_enabled": true,
  "mode": "monitor",
  "paranoia_level": 2,
  "advanced_mode": false,
  "monitor_categories": ["sqli"],
  "monitor_stacks": ["java"],
  "monitor_managed_rules": ["930120"],
  "body_stage_timeout_secs": 30,
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-01T00:00:00Z"
}
```

`body_stage_timeout_secs` in a response is always inside `1..=30`: a row
edited behind the API's back (`0`, `-5`, `31`, ...) is reported as the default
30 rather than as a value the data plane would never run with.

### GET /sites/{site_id}/waf/posture

The site's effective WAF posture — what the data plane enforces right now,
aggregated from the engine switch, rules, rate limits, bot protection and the
global observation mode. The dashboard renders this on the protection page;
automation can poll it to detect configuration drift.

**Response (200):**
```json
{
  "engine": "on",
  "detection": {
    "managed": true,
    "custom": true,
    "deep_inspection": false,
    "under_attack": false
  },
  "enforcement": {
    "managed": { "sqli": "monitor", "xss": "block" },
    "custom_rules": "block",
    "cc": "block",
    "bot": "challenge",
    "observation_mode": false
  }
}
```

`engine` mirrors `waf_enabled`; when off, the rest still reports what *would*
apply. `detection.managed` is always true (the managed ruleset ships with the
binary); `custom` reflects enabled custom rules; `deep_inspection` mirrors
`advanced_mode`; `under_attack` mirrors the challenge settings. In
`enforcement`, `managed` maps each attack category to `block` or `monitor`,
`custom_rules` aggregates custom-rule modes (block > monitor > off), `cc` is
the strongest action among enabled rate-limit rules, and `bot` the bot
protection action — both `"off"` when none apply. `observation_mode: true`
means the global switch turns every protective action into logging.

## WAF Rules

### Security event detail suffixes

`waf_details` may end with optional, machine-readable suffixes (added 2026-10-19):

- `; surface=<query|header|body|path>` — the first surface that matched;
- `; surfaces=<a,b>` — every surface that matched in this pass;
- `; downgraded=true would_enforce=<block|challenge> cause=site-mode-monitor` —
  a would-be enforcement suppressed by the site-wide monitor mode.

They never contain rule ids, rule names or request content.

### Rule modes

Every rule — custom or built-in — carries a `mode` field with the same three
values as the site mode:

| `mode` | Behaviour |
|--------|-----------|
| `off` | Fully disabled: the rule is **not compiled, not evaluated, and produces no security event or log entry**. `enabled: false` is equivalent — the rule is skipped when the compiled rule set is built. To observe a rule without enforcing it, use `monitor` instead. |
| `monitor` | The rule still evaluates and its match is recorded, but it never blocks or challenges. |
| `block` | The rule enforces the action in its `action` field. |

The API field name is `block`, **not** `enforce`: `"mode": "enforce"` is
rejected with a `400` that lists `off|monitor|block`. UI copy may call the
blocking mode "Prevention"/"Enforce"; the wire value is always `block`.

The site mode is a ceiling on top of the rule mode. With the site in `monitor`,
a rule whose action is `block` is downgraded rather than dropped: the request
goes through, and the security event records the suppression. `waf_details`
ends with `downgraded=true would_enforce=block cause=site-mode-monitor`, while
each matched rule keeps its configured `rule_action=block`. `action: "monitor"`
plus that marker is the "observed, not enforced" signal; a plain `monitor` with
no marker means the rule itself was configured to observe.

A **new site** is seeded with the built-in rule set in `mode: "block"`, so
"WAF enabled" means the shipped SQLi/XSS/reconnaissance rules actually enforce;
before this change they were seeded as `monitor` and a fresh site answered 200
to SQLi/XSS payloads while only logging them. The restore endpoint
(`POST /sites/{site_id}/waf/defaults`) is the deliberate exception: rules it
re-adds come back in `monitor`, so repairing an existing site never starts
blocking traffic that site was serving unfiltered. Seeding is matched on the
rule name and never edits an existing row.

### GET /sites/{site_id}/rule-groups

List rule groups.

### POST /sites/{site_id}/rule-groups

Create a rule group.

**Request:**
```json
{
  "name": "Custom Rules",
  "phase": "request",
  "priority": 100,
  "enabled": true
}
```

### PUT /sites/{site_id}/rule-groups/{group_id}

Update a rule group.

### DELETE /sites/{site_id}/rule-groups/{group_id}

Delete a rule group and its rules.

### GET /sites/{site_id}/rules

List rules.

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number |
| `page_size` | int | Items per page |
| `group_id` | string | Filter by group |
| `enabled` | bool | Filter enabled/disabled |
| `search` | string | Search by name/description |

### POST /sites/{site_id}/rules

Create a rule.

**Request:**
```json
{
  "group_id": "uuid",
  "name": "Block SQL Injection",
  "description": "Detects common SQLi patterns",
  "enabled": true,
  "priority": 10,
  "mode": "block",
  "conditions": [
    {
      "field": "uri",
      "operator": "regex",
      "value": "(?i)(union\\s+select|drop\\s+table)"
    }
  ],
  "action": "block",
  "tags": ["sqli", "owasp-a03"]
}
```

### GET /sites/{site_id}/rules/{rule_id}

Get rule details.

### PUT /sites/{site_id}/rules/{rule_id}

Update a rule.

### DELETE /sites/{site_id}/rules/{rule_id}

Delete a rule.

---

## Rate Limiting

### GET /sites/{site_id}/rate-limit-rules

List rate limit rules.

### POST /sites/{site_id}/rate-limit-rules

Create a rate limit rule.

**Request:**
```json
{
  "name": "API Rate Limit",
  "expression": "",
  "enabled": true,
  "threshold": 100,
  "period_seconds": 60,
  "action": "block",
  "mitigation_timeout_seconds": 60,
  "characteristics": ["ip"],
  "priority": 100
}
```

`characteristics` accepts `ip`, `ip_nat`, `host`, `path`, `asn`, `country`, and the parameterized forms `header:<name>`, `cookie:<name>`, `query:<name>` (requests missing the value bucket together). Header names match case-insensitively; cookie and query names are case-sensitive. `ja3` is reserved for future use. `expression` is an optional filter — empty means all requests.

### PUT /sites/{site_id}/rate-limit-rules/{rule_id}

Update a rate limit rule.

### DELETE /sites/{site_id}/rate-limit-rules/{rule_id}

Delete a rate limit rule.

---

## Cache

### GET /sites/{site_id}/cache-rules

List cache rules for a site.

### POST /sites/{site_id}/cache-rules

Create a cache rule.

**Request:**
```json
{
  "name": "Static Assets",
  "path_pattern": "/static/*",
  "edge_ttl": 86400,
  "browser_ttl": 3600,
  "status": "enabled"
}
```

### PUT /sites/{site_id}/cache-rules/{rule_id}

Update a cache rule.

### DELETE /sites/{site_id}/cache-rules/{rule_id}

Delete a cache rule.

### POST /sites/{site_id}/cache/defaults

Re-add the built-in cache rules that are missing, **disabled**, so caching can
be turned on with a single switch instead of writing rules from scratch. Rules
that already exist (matched by name) are left untouched, and the site's
configuration is pushed to its agents when anything was inserted.

**Response (200):**
```json
{
  "inserted": 2,
  "total": 5
}
```

`total` is the number of built-in rules; `inserted` how many were missing.

### GET /cache/status

Get cache usage across all sites.

### GET /cache/status/{site_id}

Get cache usage for a specific site.

### POST /cache/purge

Purge cached content.

**Request:**
```json
{
  "site_id": "uuid",
  "pattern": "/images/*"
}
```

**Delivery scope (D09).** `site_id` is required. The command reaches the
agents **bound to that site plus the global (unbound) agents** (the latter
serve the site through their key's owner). An agent bound to *another* site
is never included, so one tenant's purge cannot spill onto another tenant's
edges.

There is no request form that purges "everything on every edge": the
`purge_target_agents(None)` branch inside the control plane is reserved for a
future global endpoint and has no HTTP caller today.

### GET /cache/rules

List all cache rules (cross-site, query by `site_id`).

### POST /cache/rules

Create cache rule with `site_id` in body.

### PUT /cache/rules/{rule_id}

Update by rule ID.

### DELETE /cache/rules/{rule_id}

Delete by rule ID.

---

## Logs

Every proxied request writes one `access_logs` row; a request the WAF acted on
also writes a `security_events` row that shares its `request_id` with the access
row, so a security event can be joined back to the full request and response.

The control plane keeps a third, separate log about *itself*:
`control_plane_access_logs` records the requests served by the dashboard and
REST API on port 9080. It is never mixed into the site logs, carries no site
id, and is readable by administrators only — see
[GET /logs/control-plane](#get-logscontrol-plane).

> **Headers and bodies are stored verbatim.** `Cookie`, `Authorization` and
> `Set-Cookie` values are deliberately *not* redacted — the console is meant to
> reproduce what a client actually sent — so `access_logs` is sensitive data.
> Keep the retention window short (`DELETE /logs/purge`) and restrict access.
> One exception on the response side: `content-security-policy-report-only`
> is dropped from the stored `response_headers` (Postgres and Elasticsearch
> alike) — it is noise from report-only CSP deployments, while `cookie` and
> `set-cookie` are kept for site-origin forensics.

Request and response bodies are prefixes: the agent stores at most
`max_body_log_size` bytes per direction (8 KiB by default, 64 KiB ceiling,
`capture_response_body` can switch response capture off). Both directions report
the real size and a `*_truncated` flag, so a short body is never mistaken for a
complete one.

Repeated header names are folded into the single value the stored map accepts:
most headers join with `, ` (the way HTTP prescribes), while `Set-Cookie`
values join with a newline (`\n`) — cookie values routinely carry commas of
their own inside `Expires` attributes, so a comma join would make the pairs
indistinguishable.

**Console search syntax.** The log pages accept one Kibana-style query string and
translate it into the parameters below, so the same filters are reachable from
the API:

```
client_ip:203.0.113.44      exact;  client_ip:203.0.113.*   prefix
client_ip:10.0.0.1,10.0.0.8 any of several values
path:/api/v1/users          substring;  status:404  status:4xx
method:POST,PUT   action:block   rule:xss-001
country:CN   cache_status:hit   latency:>500   site:<uuid>
from:2026-09-01  to:2026-09-02
api/v1/users                free text: matches path or host
```

Values containing spaces go in double quotes (`path:"/my files"`), `ip:` and
`rule:` alias `client_ip:` and `rule_id:`, and `method`, `action`, `rule` and
`cache_status` are only understood on the tab they belong to. A term the grammar
cannot place is reported to the operator rather than ignored.

### GET /logs/security

List security events, newest first.

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number (default: 1) |
| `page_size` | int | Items per page (default: 50, max: 200) |
| `site_id` | string | Filter by site; omitted = every site the caller may see |
| `from` | string | RFC 3339 start (default: 24 hours ago) |
| `to` | string | RFC 3339 end (default: now) |
| `client_ip` | string | Exact IP; `a,b` for a list; `10.0.0.*` for a prefix |
| `action` | string | `block`, `challenge`, `log`, `allow` (`a,b` for a list) |
| `rule_id` | string | Rule id (`a,b` for a list) |
| `host` | string | Request host (`*` wildcards allowed) |
| `path` | string | Substring match on the request path |
| `country_code` | string | ISO country code, upper-cased server side |
| `request_id` | string | Exact request id, e.g. from an `X-Request-ID` header |
| `q` | string | Free text; matches the path or the host |

`from` must be earlier than `to` and the window may not exceed 90 days.

`action` is the verdict that was actually taken: `monitor` covers both "the rule
was configured to observe" and "a block was suppressed by the site mode". Those
two are told apart by `waf_details`: a downgraded block ends with
`downgraded=true would_enforce=block cause=site-mode-monitor` and keeps the
rule's own `rule_action=block`, so a monitor-mode site never looks like a site
whose block rules silently stopped working.

**Response (200):** paginated `security_events` rows.

```json
{
  "items": [
    {
      "id": 1,
      "site_id": "uuid",
      "agent_id": "uuid",
      "request_id": "6f1c…",
      "timestamp": "2024-01-01T00:00:00Z",
      "client_ip": "203.0.113.7",
      "method": "GET",
      "host": "example.com",
      "path": "/search",
      "rule_id": "942100",
      "rule_name": "SQL Injection Attack Detected",
      "action": "block",
      "score": 5,
      "waf_details": "{\"matched\":\"1' or '1'='1\"}",
      "country_code": "US",
      "user_agent": "curl/8.4.0",
      "created_at": "2024-01-01T00:00:01Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50
}
```

### GET /logs/access

List access logs, newest first.

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number (default: 1) |
| `page_size` | int | Items per page (default: 50, max: 200) |
| `site_id` | string | Filter by site; omitted = every site the caller may see |
| `from` | string | RFC 3339 start (default: 24 hours ago) |
| `to` | string | RFC 3339 end (default: now) |
| `client_ip` | string | Exact IP; `a,b` for a list; `10.0.0.*` for a prefix |
| `method` | string | HTTP method, upper-cased server side (`a,b` for a list) |
| `status_code` | int | Exact status, 100-599 |
| `status_class` | int | Status class: `1`, `2`, `3`, `4` or `5` |
| `host` | string | Request host (`*` wildcards allowed) |
| `path` | string | Substring match on the request path |
| `cache_status` | string | `hit`, `miss`, … (lower-cased, `a,b` for a list) |
| `country_code` | string | ISO country code, upper-cased server side |
| `min_latency_ms` | int | Only rows at or above this total latency |
| `request_id` | string | Exact request id |
| `q` | string | Free text; matches the path or the host |

**Response (200):** paginated `access_logs` rows.

```json
{
  "items": [
    {
      "id": 1,
      "site_id": "uuid",
      "agent_id": "uuid",
      "request_id": "6f1c…",
      "timestamp": "2024-01-01T00:00:00Z",
      "client_ip": "203.0.113.7",
      "method": "GET",
      "host": "example.com",
      "path": "/search",
      "query_string": "q=hello",
      "status_code": 200,
      "response_size": 5120,
      "upstream_addr": "10.0.1.50:3000",
      "upstream_latency_ms": 12,
      "total_latency_ms": 15,
      "cache_status": null,
      "user_agent": "curl/8.4.0",
      "referer": null,
      "country_code": "US",
      "tls_version": "TLSv1.3",
      "scheme": "https",
      "protocol": "HTTP/1.1",
      "request_headers": {"accept": "*/*", "cookie": "session=…"},
      "request_body": "q=hello",
      "request_body_size": 7,
      "request_body_truncated": false,
      "response_headers": {"content-type": "text/html", "set-cookie": "a=1; Path=/\nb=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT"},
      "response_body": "<!doctype html>…",
      "response_body_size": 5120,
      "response_body_truncated": true
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50
}
```

Rows are only as complete as the agent that produced them: `scheme`, `protocol`
and the response fields come from agents on 0.15.0 or newer. Against an older
agent those columns stay `null` and the console shows the request side only.

### GET /logs/control-plane

List the control plane's own access log (port 9080), newest first.
Administrators only: the table is cross-tenant and has no site column.
Recording is controlled by the `access_log_enabled` switch and
`access_log_retention_days` of
[PUT /settings/api-protection](#put-settingsapi-protection). Health probes
(`/healthz`, `/api/v1/health`) are exempt and write no rows.

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number (default: 1) |
| `page_size` | int | Items per page (default: 50, max: 200) |
| `from` | string | RFC 3339 start (default: 24 hours ago) |
| `to` | string | RFC 3339 end (default: now) |
| `client_ip` | string | Exact IP; `a,b` for a list; `10.0.0.*` for a prefix |
| `method` | string | HTTP method, upper-cased server side (`a,b` for a list) |
| `action` | string | `allowed`, `blocked_allowlist`, `blocked_waf`, `observed_waf` (`a,b` for a list) |
| `status_code` | int | Exact status, 100-599 |
| `path` | string | Substring match on the request path |
| `host` | string | Request host (`*` wildcards allowed) |
| `request_id` | string | Exact request id |
| `q` | string | Free text; matches the path or the host |

`from` must be earlier than `to` and the window may not exceed 90 days.

**Response (200):** paginated `control_plane_access_logs` rows.

```json
{
  "items": [
    {
      "id": 1,
      "request_id": "6f1c…",
      "timestamp": "2024-01-01T00:00:00Z",
      "client_ip": "203.0.113.7",
      "method": "GET",
      "host": "waf.example.com:9080",
      "path": "/api/v1/sites",
      "query_string": "page=1",
      "scheme": "https",
      "protocol": "HTTP/1.1",
      "status_code": 200,
      "latency_ms": 12,
      "user_agent": "curl/8.4.0",
      "referer": null,
      "user_id": "uuid",
      "user_email": "admin@pingwaf.local",
      "action": "allowed",
      "reason": null
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50
}
```

`action` records what the listener's self-protection did with the request:

| Value | Meaning |
|-------|---------|
| `allowed` | The request passed every check (the default). |
| `blocked_allowlist` | Refused with `403 ip_not_allowed` by the IP allowlist. |
| `blocked_waf` | Refused with `403 blocked_by_waf`, or `413 request_body_too_large` when the body exceeded the inspection limit. |
| `observed_waf` | A WAF match that was recorded but not enforced, either because `waf_mode` is `monitor` or because the engine itself rated the verdict monitor-only. |

`reason` carries the detail behind a non-`allowed` action and is `null`
otherwise. `user_id` and `user_email` are decoded from a Bearer token that
happens to be on the request, purely for the log — the handler still
authenticates for real, so an invalid token logs `null` for both. `client_ip`
is always the TCP peer, never a forwarding header: behind a reverse proxy the
proxy's address is what is logged (and must be allowlisted).

Rows are written asynchronously and in batches, so the newest seconds of
traffic may not be visible yet; a queue overflow drops records with a server
warning rather than stalling requests.

### DELETE /logs/purge

Delete log rows older than a cutoff. Administrators only.

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `older_than_days` | int | Retention window in days, 1-3650 (default: 30) |
| `site_id` | string | Limit the purge to one site; omitted = every site |

```
DELETE /api/v1/logs/purge?older_than_days=30
```

**Response (200):**
```json
{
  "deleted_security_events": 120,
  "deleted_access_logs": 8421,
  "deleted_control_plane_logs": 42,
  "cutoff": "2024-01-01T00:00:00Z"
}
```

`deleted_control_plane_logs` counts rows removed from
`control_plane_access_logs`; it is always `0` when `site_id` is given, since
control plane rows carry no site. The scheduled sweep keeps that table to its
own window (`access_log_retention_days` of the API protection settings).

---

## Analytics

### GET /analytics/summary

Aggregate statistics for a time range.

**Query Parameters:** `site_id`, `from`, `to` (ISO 8601; default window is the last 24 hours, capped at 31 days)

**Response (200):**
```json
{
  "from": "2024-01-01T00:00:00Z",
  "to": "2024-01-02T00:00:00Z",
  "site_id": null,
  "requests": 125000,
  "unique_ips": 8900,
  "cache_hits": 98000,
  "cache_hit_rate": 0.784,
  "avg_latency_ms": 42,
  "max_latency_ms": 5120,
  "client_errors": 2100,
  "server_errors": 130,
  "security_events": 3650,
  "blocked_requests": 3200,
  "distinct_attackers": 412,
  "rules_triggered": 1880
}
```

### GET /analytics/requests-over-time

Time-series request data.

**Query Parameters:** `site_id`, `from`, `to`, `interval` (`minute`, `hour` (default), `day` or `week`), `limit`

### GET /analytics/traffic

Egress bandwidth per fixed-width bucket — response bytes streamed to clients only; origin-pull traffic is never counted. Without `site_id` the call covers every site the caller may see.

**Query Parameters:** `site_id`, `from`, `to`, `step` (bucket width in seconds; one of `5`, `10`, `30`, `60`, `300`, `900`, `3600`, `86400` — default `5`)

**Response (200):**
```json
{
  "from": "2024-01-01T00:00:00Z",
  "to": "2024-01-01T00:10:00Z",
  "site_id": null,
  "step_seconds": 5,
  "total_bytes": 536870912,
  "buckets": [
    {
      "bucket": "2024-01-01T00:00:00Z",
      "bytes": 1048576
    }
  ]
}
```

### GET /analytics/sites-over-time

Request volume over time for the busiest sites — one series per site, for the dashboard's multi-line chart. Without `site_id` the top 8 sites by in-window traffic are returned; non-administrators are scoped to their own sites.

**Query Parameters:** `site_id`, `from`, `to`, `interval` (`minute`, `hour` (default), `day` or `week`)

**Response (200):**
```json
[
  {
    "bucket": "2024-01-01T12:00:00Z",
    "site_id": "uuid",
    "site_domain": "example.com",
    "site_name": "My Site",
    "requests": 1520
  }
]
```

### GET /analytics/top-rules

Most triggered rules.

### GET /analytics/top-ips

Top client IPs by request count.

### GET /analytics/top-paths

Most requested paths.

### GET /analytics/status-codes

Distribution of HTTP response codes.

### GET /analytics/sites

Overview of all sites with request counts.

---

## IP Access Rules

### GET /sites/{site_id}/ip-rules

List IP access rules.

### POST /sites/{site_id}/ip-rules

Create an IP rule. Set either `ip_ranges` (manual mode) or `group_id` (reference a global/per-site IP group) — not both.

**Request:**
```json
{
  "name": "Known bad actor",
  "ip_ranges": ["192.168.1.0/24"],
  "action": "block",
  "note": "Blocked subnet",
  "enabled": true,
  "priority": 100
}
```

`action` is `block`, `allow`, `challenge`, `js_challenge` or `basic_auth`. Sending `group_id` instead of `ip_ranges` makes the rule track the group's latest ranges. A `basic_auth` rule challenges the matched clients and continues to the remaining checks once they authenticate; configure the credentials under [Basic Auth](#basic-auth) first.

### PUT /sites/{site_id}/ip-rules/{rule_id}

Update an IP rule (sending `ip_ranges` or `group_id` switches between manual and group mode).

### DELETE /sites/{site_id}/ip-rules/{rule_id}

Remove an IP rule.

### POST /sites/{site_id}/ip-rules/bulk

Bulk import IP rules (one IP or CIDR per entry).

**Request:**
```json
{
  "ip_ranges": ["1.2.3.4", "5.6.7.0/24"],
  "action": "block",
  "note": "Imported blocklist",
  "enabled": true
}
```

### GET /sites/{site_id}/blocked-ips

Dynamic blocks the edge currently enforces for the site — WAF/rate-limit auto-blocks, server-issued block commands and manual CIDR blocks. Every agent reports the blocks it enforces on each heartbeat; rows are folded per IP (or CIDR), with the attack history folded in from the security-event log.

**Response (200):**
```json
[
  {
    "ip": "203.0.113.7",
    "kind": "single",
    "reason": "waf: SQL injection in query string",
    "blocked_at": "2024-01-01T12:00:00Z",
    "expires_at": "2024-01-01T12:10:00Z",
    "agent_count": 2,
    "attack_count": 1842,
    "last_attack_at": "2024-01-01T11:59:58Z"
  },
  {
    "ip": "198.51.100.0/24",
    "kind": "cidr",
    "reason": "manual block from dashboard",
    "blocked_at": "2024-01-01T12:05:00Z",
    "expires_at": null,
    "agent_count": 2,
    "attack_count": 0,
    "last_attack_at": null
  }
]
```

`expires_at` is `null` for permanent blocks; `reason` may be `null` for blocks reported by older agents. `kind` is `"single"` for one address and `"cidr"` for a range; the same field appears on every row of the global list (`GET /blocked-ips`).

### POST /blocked-ips/block

Issue a manual dynamic block for a site: a `BlockIp` command goes to every registered agent (queued for offline ones) and mirror rows are written so the dashboard reflects the block immediately; the next heartbeat reconciles any drift. `duration_seconds` of `0` (or omitted) blocks permanently until unblocked. Requires write permission on the site.

The `ip` field accepts a single address **or a CIDR range** (e.g. `198.51.100.0/24`, `2001:db8:abcd::/48`). CIDRs are normalised — host bits are truncated (`203.0.113.99/24` is stored as `203.0.113.0/24`) — and re-blocking the same target is idempotent. To keep a fat-fingered network-wide ban from taking the edge down, the mask is capped: **at most /16 for IPv4 and /32 for IPv6**; broader prefixes are rejected with `400` and a message containing `CIDR prefix too broad`.

**Request:**
```json
{
  "site_id": "…",
  "ip": "198.51.100.0/24",
  "duration_seconds": 3600,
  "reason": "manual block from dashboard"
}
```

**Response (202):**
```json
{
  "ip": "198.51.100.0/24",
  "kind": "cidr",
  "site_id": "…",
  "duration_seconds": 3600,
  "agents": 2,
  "delivered": 2
}
```

### POST /sites/{site_id}/blocked-ips/unblock

Lift a dynamic block: an `UnblockIp` command goes to every agent still enforcing it (queued when disconnected) and the mirrored rows are removed. Requires write permission.

`ip` accepts a single address or a CIDR, matching the block input. Unblocking a CIDR only removes the **exactly identical** CIDR entry — it does not lift blocks for individual addresses that happen to fall inside the range (and vice versa).

**Request:**
```json
{
  "ip": "198.51.100.0/24"
}
```

**Response (202):**
```json
{
  "ip": "203.0.113.7",
  "agents": 2,
  "delivered": 2
}
```

---

## IP Groups

Named collections of IP ranges, global (`is_global`, applied to all sites) or per-site. Each group carries an `action` of `block` or `allow`, and can subscribe to an external list via `source_url` with a `sync_interval_minutes` refresh interval (`null` = manual sync only).

Groups can also be **subscription-backed** (`subscription_kind`): `builtin`
groups ship with the control plane — Google, Yandex, DuckDuckGo and Cloudflare
verifier/CDN ranges as static snapshots, seeded on first start — and `url`
groups pull a plain-text or CIDR list over HTTP. Both are refreshed
automatically by a daily background job (`subscription_enabled: false` opts
out); `last_synced_at` and `last_sync_error` report the last run. Range
changes propagate: sites that use the group for access rules, route gating,
bot verification or proxy trust get their configuration re-pushed
immediately.

Subscription fetches refuse to contact non-public networks. Three layers apply
(`pingwaf-server/src/subscription.rs`):

* **No redirects.** The fetch client sets `redirect::Policy::none()`, so a
  public source cannot answer with a `302 -> http://169.254.169.254/` and slip
  past the IP checks.
* **Full IP blacklist on the initial host.** The `source_url` host — an IP
  literal directly, otherwise resolved via DNS with *every* returned address
  checked — is validated against a blacklist: loopback, RFC 1918 private,
  link-local (including the cloud metadata service `169.254.169.254`),
  fe80::/10, fc00::/7 unique-local, 0.0.0.0/8, multicast, 240.0.0.0/4, CGNAT
  100.64.0.0/10, IETF protocol assignments 192.0.0.0/24, benchmarking
  198.18.0.0/15, the NAT64 prefix 64:ff9b::/96, and IPv4-mapped IPv6 (judged
  by the IPv4 blacklist). A rejected URL fails with an error mentioning
  `private, loopback or otherwise non-public network` — at validation time and
  again before each sync sends a byte.
* **Known residual risk.** DNS resolution and the actual connection are
  performed independently by reqwest, so a DNS rebinding TOCTOU window
  theoretically remains. The precondition is an already-authenticated admin
  configuring the subscription source; the risk is accepted at the level of
  this documentation note rather than mitigated in code.

**Permissions:** reads are available to every role; the mutating endpoints
(`POST/PUT/DELETE /ip-groups`, `PUT /ip-groups/{group_id}/sites` and
`POST /ip-groups/{group_id}/sync`) require write access (`admin`) — viewer and
auditor accounts receive `403`.

### GET /ip-groups

List IP groups (paginated), each with a `site_count`.

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number |
| `page_size` | int | Items per page |
| `action` | string | Filter: `block` or `allow` |
| `is_global` | bool | Filter global/per-site groups |
| `enabled` | bool | Filter enabled/disabled |

**Response (200):**
```json
{
  "items": [
    {
      "id": "uuid",
      "name": "Cloudflare",
      "description": "Official Cloudflare IP ranges, refreshed daily from api.cloudflare.com.",
      "ip_ranges": ["173.245.48.0/20"],
      "action": "block",
      "is_global": true,
      "source_url": "https://api.cloudflare.com/client/v4/ips",
      "sync_interval_minutes": 1440,
      "last_synced_at": "2024-01-01T12:00:00Z",
      "last_sync_error": null,
      "subscription_kind": "builtin",
      "subscription_enabled": true,
      "enabled": false,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z",
      "site_count": 0
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50
}
```

### POST /ip-groups

Create an IP group (up to 10000 ranges). Requires write access (`admin`).

**Request:**
```json
{
  "name": "Office allowlist",
  "description": "Corporate egress IPs",
  "ip_ranges": ["203.0.113.7", "198.51.100.0/24"],
  "action": "allow",
  "is_global": false,
  "source_url": "https://example.com/ip-list.txt",
  "sync_interval_minutes": 1440,
  "enabled": true
}
```

### GET /ip-groups/{group_id}

Get an IP group with its `site_count`.

### PUT /ip-groups/{group_id}

Update an IP group (all fields optional). Requires write access (`admin`).

### DELETE /ip-groups/{group_id}

Delete an IP group. Requires write access (`admin`).

### GET /ip-groups/{group_id}/sites

List the sites associated with a per-site group.

### PUT /ip-groups/{group_id}/sites

Replace the site associations of a per-site group. Refused with `400` for global groups. Requires write access (`admin`).

**Request:**
```json
{
  "site_ids": ["uuid"]
}
```

### POST /ip-groups/{group_id}/sync

Trigger an immediate subscription sync from `source_url`. Requires write access (`admin`). On success the fetched ranges replace the stored ones; on failure the previous ranges are kept, the error is recorded in `last_sync_error`, and the API returns `502`.

**Response (200):**
```json
{
  "id": "uuid",
  "synced_at": "2024-01-01T12:00:00Z",
  "ip_count": 15
}
```

---

## Geo Restrictions

### GET /sites/{site_id}/geo

Get geo restriction settings.

### PUT /sites/{site_id}/geo

Update geo restrictions.

**Request:**
```json
{
  "enabled": true,
  "mode": "block_list",
  "countries": ["CN", "RU", "IR"],
  "blocked_asns": ["AS13335"],
  "block_unknown": false,
  "action": "block"
}
```

`mode` is `block_list` or `allow_list`; `blocked_asns` entries are ASN numbers, optionally prefixed with `AS`. `action` is `block`, `challenge`, `js_challenge` or `basic_auth`.

### GET /sites/{site_id}/geo/stats

Requests per country over the last 24 hours (up to 20 countries), for the bar chart next to the policy editor. Traffic whose country could not be resolved is skipped.

**Response (200):**
```json
[
  {"country_code": "CN", "requests": 5210},
  {"country_code": "US", "requests": 1240}
]
```

---

## Basic Auth

HTTP basic authentication for one site. The check runs inside the WAF plugin,
ahead of the cache, so a stored response can never answer an unauthenticated
request. It applies site-wide when `enabled` is true, and to the clients an IP
or geo rule with the `basic_auth` action matches — an explicit `allow` rule
exempts a client from the site-wide gate.

Passwords are masked with `***` in responses; sending the mask back keeps the
stored password instead of overwriting it. Site write permission is required.

### GET /sites/{site_id}/basic-auth

Get the site's basic auth configuration, creating a disabled default when the
site never saved one.

**Response (200):**
```json
{
  "id": "0d1b0f2e-…",
  "site_id": "6f1c…",
  "enabled": false,
  "realm": "Restricted",
  "credentials": [{"username": "alice", "password": "***"}],
  "delay_seconds": 1,
  "hide_credentials": false,
  "created_at": "2026-09-30T09:00:00Z",
  "updated_at": "2026-09-30T09:00:00Z"
}
```

### PUT /sites/{site_id}/basic-auth

Update basic auth. `credentials` replaces the whole list when present; `realm`
must be 1–200 characters, `delay_seconds` between 0 and 10, and usernames must
be non-empty and unique. Enabling the gate with no credential is rejected.

**Request:**
```json
{
  "enabled": true,
  "realm": "Staging",
  "credentials": [
    {"username": "alice", "password": "hunter2"},
    {"username": "bob", "password": "***"}
  ],
  "delay_seconds": 1,
  "hide_credentials": true
}
```

---

## Bot Protection

### GET /sites/{site_id}/bot-protection

Get bot protection settings.

### PUT /sites/{site_id}/bot-protection

Update bot protection.

**Request:**
```json
{
  "enabled": true,
  "ua_analysis": true,
  "action": "challenge",
  "known_bots_whitelist": ["Googlebot", "bingbot"],
  "ip_verification_enabled": true,
  "dns_verification_enabled": true,
  "verified_ip_group_id": "uuid"
}
```

`action` is `block`, `challenge`, `js_challenge`, `log` or `allow` and is applied to traffic classified as a bot (non-browser user agents). `known_bots_whitelist` is a JSON array of case-insensitive User-Agent substrings that always pass.

Beyond the user agent — trivially spoofed — two stronger signals exist.
`ip_verification_enabled` plus `verified_ip_group_id` treats client IPs inside
the referenced group's ranges as verified bots (pick the built-in Google or
Cloudflare subscription group). `dns_verification_enabled` adds reverse DNS:
for a suspicious user agent the client's PTR record is resolved and forward-
confirmed against the vendor's domain (`*.googlebot.com`, `yandex.com`,
`duckduckgo.com`, …). Verification runs only when the UA already looks like a
bot, results are cached, and a failed lookup falls back to the UA verdict
rather than blocking the request. Signals compose in the order: IP match >
confirmed DNS > UA whitelist > browser fingerprint heuristic > the configured
action.

---

## Challenge Settings

### GET /sites/{site_id}/challenge

Get challenge configuration, creating a disabled default when the site never
saved one.

**Response (200):**
```json
{
  "id": "0d1b0f2e-…",
  "site_id": "6f1c…",
  "enabled": false,
  "under_attack_mode": false,
  "default_level": "non_interactive",
  "clearance_duration_secs": 1800,
  "rate_threshold": 100,
  "exempt_paths": [],
  "browser_integrity_check": true,
  "tls_fingerprint_check": false,
  "updated_at": "2026-09-30T09:00:00Z"
}
```

### PUT /sites/{site_id}/challenge

Update challenge settings. All fields are optional; omitted fields keep their
value. Site write permission is required. Unknown fields are rejected with
`422 Unprocessable Entity` (`deny_unknown_fields`) — note that axum 0.8 maps
serde deserialization rejections to 422, and the response body is plain text,
not the unified JSON error envelope.

**Request:**
```json
{
  "enabled": true,
  "under_attack_mode": true,
  "default_level": "managed",
  "clearance_duration_secs": 1800,
  "rate_threshold": 100,
  "exempt_paths": ["/health", "/static/"],
  "browser_integrity_check": true,
  "tls_fingerprint_check": false
}
```

| Field | Description |
|-------|-------------|
| `enabled` | Master switch for the challenge gate |
| `under_attack_mode` | Show the under-attack banner; setting it to `true` also forces `enabled` to `true` |
| `default_level` | `none`, `non_interactive`, `managed` or `interactive`; other values are rejected with `400` |
| `clearance_duration_secs` | Clearance cookie lifetime, 60–86400 seconds |
| `rate_threshold` | Requests per window before a challenge is issued, 1–10000000 |
| `exempt_paths` | Bypass list; see validation rules below |
| `browser_integrity_check` | Browser fingerprint heuristic |
| `tls_fingerprint_check` | TLS fingerprint check |

`exempt_paths` is an optional bypass list of path prefixes served without a
challenge. Each entry must start with `/`, contain no whitespace or control
characters, be at most 512 characters, and the list accepts at most 100
entries — anything else is rejected with `400`. Entries are trimmed and blank
entries are dropped. The challenge cookie signing secret is internal to the
server and is not part of this API (the former `cookie_secret` field was
removed; the database column is dropped by migration `000054`).

---

## Rewrite Rules

### GET /sites/{site_id}/rewrite-rules

List rewrite rules.

### POST /sites/{site_id}/rewrite-rules

Create a rewrite rule.

**Request:**
```json
{
  "name": "Strip API prefix",
  "type": "request",
  "match_pattern": "^/api/v1/(.*)",
  "replace_with": "/$1",
  "headers_add": {"X-Forwarded-By": "PingWAF"},
  "headers_remove": ["Server"],
  "priority": 10,
  "enabled": true
}
```

### PUT /sites/{site_id}/rewrite-rules/{rule_id}

Update a rewrite rule.

### DELETE /sites/{site_id}/rewrite-rules/{rule_id}

Delete a rewrite rule.

---

## Error Pages

A custom error page replaces the body of any response with a matching status
code — including responses the edge itself produces (a WAF block, a rate limit,
a paused site), not only ones that came from the origin. At most one page per
status code, and the pages are global: every site is served the same templates.
Administrators only, and edited from Settings in the dashboard.

A write pushes the new templates to every registered agent's next configuration
update, so no per-site publish is involved.

### GET /error-pages

List custom error pages (paginated), ordered by status code.

### POST /error-pages

Create a custom error page.

**Request:**
```json
{
  "status_code": 403,
  "name": "Access denied",
  "content_type": "text/html",
  "body_template": "<html><body><h1>Access Denied</h1><p>{{ request_id }}</p></body></html>",
  "enabled": true
}
```

| Field | Description |
|-------|-------------|
| `status_code` | 400-599, unique |
| `name` | 1-200 characters |
| `content_type` | Defaults to `text/html` |
| `body_template` | Tera template, must not be empty |
| `enabled` | Defaults to `true`; a disabled page is skipped |

`body_template` renders with `request_id`, `error_code`, `error_message`,
`site_name`, `client_ip`, `timestamp`, `method`, `path` (aliased as
`request_path`), `host` (aliased as `request_host`) and `user_agent`. A template
that fails to render falls back to a plain-text body, so a typo cannot turn a
`403` into a `500`.

### PUT /error-pages/{page_id}

Update an error page; omitted fields keep their value.

### DELETE /error-pages/{page_id}

Delete an error page.

---

## Settings

> **Control-plane-local settings.** The endpoints below take effect only in
> the control-plane process itself; they are **not** pushed to agents and do
> not appear in the rule bundle: `PUT /settings/elasticsearch` (a saved change
> needs a control-plane restart to apply — the response's `requires_restart`
> flag reports this), `GET/PUT /settings/api-protection` (the 9080
> self-protection policy is rebuilt in-process), `GET/PUT /settings/ai`,
> `GET/PUT /login-security` and the `/notifications/*` endpoints. In a
> multi-instance deployment each instance must be configured separately.

### GET /settings/elasticsearch

Get Elasticsearch configuration.

### PUT /settings/elasticsearch

Update Elasticsearch settings.

**Request:**
```json
{
  "enabled": true,
  "urls": ["http://elasticsearch:9200"],
  "index_prefix": "pingwaf",
  "username": "elastic",
  "password": "secret",
  "max_body_size": 8192
}
```

### POST /settings/elasticsearch/test

Test Elasticsearch connectivity.

**Response (200):**
```json
{
  "success": true,
  "message": "Connected to Elasticsearch 8.12.0"
}
```

### GET /settings/log-retention

How long the PostgreSQL log tables are kept, in days. Administrators only. The
row is created with the default `180` days on first read.

**Response (200):**
```json
{
  "id": 1,
  "access_log_retention_days": 180,
  "security_event_retention_days": 180,
  "updated_at": "2026-09-30T00:00:00Z"
}
```

### PUT /settings/log-retention

Update one or both retention windows. Administrators only. Each value must be
between `1` and `3650` days.

**Request:**
```json
{
  "access_log_retention_days": 90,
  "security_event_retention_days": 365
}
```

A background sweep runs shortly after startup and then every six hours, so a
saved change takes effect without a restart. The optional `site_id` on
`DELETE /logs/purge` still narrows a manual purge; these settings configure the
automatic sweeps only. Elasticsearch archives are governed separately: the ILM
policy deletes indices after a fixed 360 days.

### GET /settings/defense

Global defense switches, stored as a single row. Administrators only.
Today that is observation mode: with it **on**, the data plane keeps every
detection running (WAF, IP and geo rules, bot protection, rate limiting) but
only records what it would have blocked — nothing is blocked, challenged or
rate-limited. Access control is never downgraded: mTLS, basic auth and a
paused site still take effect.

**Response (200):**
```json
{
  "id": 1,
  "observation_mode": false,
  "updated_at": "2026-10-03T00:00:00Z"
}
```

The row is created with `observation_mode: false` on first read.

### PUT /settings/defense

Set observation mode. Administrators only. The flag rides inside every rule
bundle, so a change marks all site configurations as changed and pushes fresh
bundles to the agents right away — no restart, no manual sync.

**Request:**
```json
{
  "observation_mode": true
}
```

`observation_mode` is required; a body without it is rejected with `400`.
A change made directly in the database — e.g. by the
`pingwaf mode observe` CLI on the server — is picked up and pushed by a
background watcher within about 15 seconds.

**Response (200):** the updated row, same shape as `GET`.

### GET /settings/origin

The deployment-wide default for validating an HTTPS origin's certificate,
stored as a single row. Administrators only. It applies to every origin pool
that does not state a `verify_cert` of its own, so one self-signed origin can
opt out without weakening the rest of the deployment.

With `verify_cert` **off** (the value the console writes by default) the data
plane accepts any origin certificate — including one it cannot chain to a
trust store. That is what self-signed and internal-PKI origins need, and it
keeps an existing deployment serving across an upgrade; it is not recommended
for origins that present a publicly trusted certificate. Set it to `true` to
require a chain that validates against the system trust store or the pool's
own `ca`.

**Response (200):**
```json
{
  "id": 1,
  "verify_cert": false,
  "updated_at": "2026-10-13T00:00:00Z"
}
```

The row is created with `verify_cert: false` on first read. A failed read
degrades to that same lenient value rather than failing, because the check is
a per-request data-plane decision and failing it closed would turn a
transient database problem into a `502` for every HTTPS origin.

### PUT /settings/origin

Set the global origin certificate check. Administrators only. The value rides
inside every rule bundle, so a change marks all site configurations as changed
and pushes fresh bundles to the agents right away — no restart, no per-pool
edit.

**Request:**
```json
{
  "verify_cert": true
}
```

`verify_cert` is required; a body without it is rejected with `400`.

**Response (200):** the updated row, same shape as `GET`.

### GET /settings/api-protection

The 9080 listener's self-protection: its own access log, IP allowlist and
WAF. Administrators only. The row is created on first read with the defaults
shown below.

**Response (200):**
```json
{
  "id": 1,
  "access_log_enabled": true,
  "access_log_retention_days": 30,
  "ip_allowlist_enabled": false,
  "ip_allowlist_ranges": [],
  "ip_allowlist_group_id": null,
  "waf_enabled": false,
  "waf_mode": "block",
  "updated_at": "2026-10-03T00:00:00Z",
  "effective_allowlist_entries": 0
}
```

`effective_allowlist_entries` is what the allowlist resolves to right now:
the inline ranges plus the ranges of the referenced group (a disabled group
contributes nothing); `0` while the allowlist is switched off.

While a guard is on, a request it refuses never reaches the API: the
allowlist answers `403` with error code `ip_not_allowed`, the WAF answers
`403 blocked_by_waf` (or `413 request_body_too_large` for a body above the
inspection limit), and either refusal is recorded in
`GET /logs/control-plane`.

### PUT /settings/api-protection

Update any subset of the settings. Administrators only. Every field is
optional — omitted fields keep their current value, so a JSON body may hold
just the one switch being changed. A successful write rebuilds the
in-process policy before responding, so the change applies to the next 9080
request.

**Request:**
```json
{
  "access_log_enabled": true,
  "access_log_retention_days": 30,
  "ip_allowlist_enabled": true,
  "ip_allowlist_ranges": ["203.0.113.4", "10.0.0.0/8"],
  "ip_allowlist_group_id": "uuid",
  "waf_enabled": true,
  "waf_mode": "monitor",
  "force": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `access_log_enabled` | bool | Record one row per 9080 request (see `GET /logs/control-plane`). |
| `access_log_retention_days` | int | Retention window for that log, 1-3650 days. |
| `ip_allowlist_enabled` | bool | Restrict the API to the allowlist below. |
| `ip_allowlist_ranges` | string[] | Addresses and CIDRs; blanks are dropped, each entry must parse. |
| `ip_allowlist_group_id` | string | Reference an `ip_groups` row; `""` clears the reference; omit or `null` to keep it. |
| `waf_enabled` | bool | Inspect API requests with the embedded WAF engine. |
| `waf_mode` | string | `block` or `monitor`; monitor only records matches (they show up as `observed_waf`). |
| `force` | bool | Apply a change the lockout guard below would refuse. |

Validation failures return `400`: an unparsable allowlist entry, a retention
outside 1-3650 days, an unknown `ip_groups` reference, or a `waf_mode` other
than `block` / `monitor`.

**Lockout guard.** A write that leaves the allowlist enabled without covering
the connection sending it is refused with `422`, because it would lock the
operator out of the console they are using:

```json
{
  "error": {
    "code": "unprocessable_entity",
    "message": "the new allowlist does not include your address (203.0.113.7); add it first, or send force=true to apply anyway"
  }
}
```

Add the address (or retry with `force: true`) to apply it anyway. The
`pingwaf security allowlist off` CLI on the server is the escape hatch when
HTTP access is already gone.

**Response (200):** the same view as `GET`.

---

## Configuration versions

Every configuration push records a version of the rows it changed — per site,
or deployment-wide for the global settings. The console's **Config versions**
page is built on the three endpoints below; all of them are administrators
only.

### GET /config-versions

List versions, newest first, without their snapshot payloads.

| Query | Meaning |
| --- | --- |
| `site_id` | A site UUID, or `global` for deployment-wide versions. Omit for both. Anything else is a `400`. |
| `limit` | Rows to return, default `50`, clamped to `1..=200`. |
| `offset` | Rows to skip, default `0`. |

**Response (200):**
```json
[
  {
    "id": 412,
    "site_id": "3f5c…",
    "site_domain": "example.com",
    "config_hash": "…",
    "source": "console",
    "actor": "admin@example.com",
    "summary": { "sites": 1, "site_rules": 12 },
    "created_at": "2026-10-13T09:31:02Z"
  }
]
```

`site_id` is `null` for a global version, and `site_domain` is resolved for
display. `summary` holds the per-table row counts captured with the version,
which is what the console diffs against the previous version.

### GET /config-versions/{version_id}

The full snapshot, including the row payloads. Returns `404` when the version
does not exist.

### POST /config-versions/{version_id}/rollback

Restore a snapshot. The rows are rewritten inside a transaction, then the
restored configuration is pushed to the agents like any other change — a site
version through its own bundle, a global version through all of them. The
rollback is itself recorded as a new version attributed to the operator, so
rolling back a rollback works and the history stays linear.

**Response (200):**
```json
{
  "restored_version": 412,
  "new_version": 418,
  "scope": "3f5c…"
}
```

`scope` is `"global"` for a deployment-wide rollback, otherwise the site UUID.

---

## Control-plane certificate

The certificate the dashboard and REST API are served with. Administrators
only: the private key never leaves the server and no endpoint returns it.

A self-signed pair (EC P-256, `CN=PingWAF Control Plane`) is generated on first
boot when TLS is enabled and nothing has been stored yet. Replacing it takes
effect immediately — the listener swaps the pair in place, so no restart is
needed. Passkeys require a secure origin, which is the reason this exists.

### GET /system/tls

Current status, including the active certificate's metadata.

**Response (200):**
```json
{
  "enabled": true,
  "has_certificate": true,
  "certificate": {
    "id": "uuid",
    "source": "self_signed",
    "subject_dn": "CN=PingWAF Control Plane",
    "common_name": "PingWAF Control Plane",
    "sans": ["localhost", "127.0.0.1", "waf.example.com"],
    "serial": "1f0c…",
    "fingerprint_sha256": "3b1a…",
    "not_before": "2026-09-30T00:00:00Z",
    "not_after": "2028-12-30T00:00:00Z",
    "created_at": "2026-09-30T00:00:00Z",
    "expires_in_days": 821
  },
  "default_sans": ["localhost", "127.0.0.1", "waf.example.com"],
  "max_validity_days": 3650
}
```

`enabled` mirrors `tls_enabled`; `has_certificate` reports whether the running
listener holds a usable pair. `certificate` is omitted when nothing is stored.

### GET /system/tls/certificate

Download the certificate in use (PEM, chain included) as
`application/x-pem-file`. Handy for pinning or for installing the self-signed
pair into a trust store.

### PUT /system/tls/certificate

Upload a certificate and its private key. The pair is validated before anything
is written: a mismatched key or an unparsable chain returns `400` and the
running listener keeps serving the previous certificate.

**Request:**
```json
{
  "cert_pem": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n",
  "key_pem": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----\n"
}
```

`cert_pem` carries the leaf first, then intermediates when the issuer is not a
root. `key_pem` accepts PKCS#8, PKCS#1 or SEC1 (`RSA`, `EC` and `PKCS8`
begin-lines are all understood).

**Response (200):** the same shape as `GET /system/tls`.

### POST /system/tls/certificate/self-signed

Generate and install a fresh self-signed certificate.

**Request** (every field optional):
```json
{
  "common_name": "PingWAF Control Plane",
  "sans": ["waf.example.com", "10.0.0.5"],
  "validity_days": 825
}
```

Defaults: the configured console common name, the deployment's alternative
names (configured `tls_sans` plus the host name, the passkey relying party,
`localhost` and `127.0.0.1`, and the host the request arrived on), and 825 days
(capped at `max_validity_days`, 3650).

**Response (200):** the same shape as `GET /system/tls`.

---

## AI assistant

The built-in assistant behind the console's **AI Assistant** page. A turn runs
an OpenAI-compatible chat-completions loop (streaming when the provider
supports it) and hands the model the same tool registry that backs the
[MCP server](#mcp-server), so it can inspect sites, agents, certificates,
traffic and logs — and, when allowed, change sites.

Every endpoint in this section is administrators only: one provider key is
shared across the fleet and the tools reach every site.

### GET /settings/ai

The assistant's configuration, stored as a single row. The row is created with
the defaults shown below on first read.

**Response (200):**
```json
{
  "enabled": false,
  "base_url": "https://api.openai.com/v1",
  "api_key": "",
  "model": "gpt-4o-mini",
  "system_prompt": "You are the built-in assistant of PingWAF, a reverse-proxy and web application firewall console. …",
  "temperature": 0.2,
  "max_tool_rounds": 5,
  "allow_write_tools": false,
  "updated_at": "2026-10-03T00:00:00Z"
}
```

`api_key` is `***` when a key is stored and empty when none is; the stored key
is never returned. `system_prompt` is the prompt in effect: the saved override,
or the full built-in default (shown abbreviated above) when no override is
stored.

### PUT /settings/ai

Update any subset of the settings; omitted fields keep their stored value.
`api_key` follows the secret round-trip: omitted or `null` keeps the stored
key, `***` keeps it too (what the dashboard sends when the field was left
untouched), and `""` clears it. Enabling the assistant requires a `base_url`
(http or https), a `model` and a key; an incomplete configuration is refused
with `400`.

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Master switch. While off, chat turns are refused with `409`. |
| `base_url` | string | OpenAI-compatible API root, at most 500 characters. |
| `api_key` | string | Provider key; see the round-trip rules above. |
| `model` | string | Model name, at most 200 characters. |
| `system_prompt` | string | Overrides the built-in prompt; `""` clears the override so the default applies again. |
| `temperature` | number | 0–2. |
| `max_tool_rounds` | int | Tool-calling rounds per answer, 1–10. |
| `allow_write_tools` | bool | Let the assistant call the site-mutating tools. |

**Response (200):** the same view as `GET`.

### POST /settings/ai/test

Probe a provider. The JSON body may hold any subset of the fields above;
absent fields fall back to the stored row, and the probe runs with `enabled`
forced on, so a draft can be tested before it is saved. The model is asked for
a one-word reply.

**Response (200):**
```json
{
  "ok": true,
  "model": "gpt-4o-mini",
  "reply": "ok",
  "error": null
}
```

A reachable provider that answers with an error still returns `200` with
`ok: false` and the provider's message in `error`; only an unusable
configuration (missing URL or model) is a `400`.

### GET /ai/conversations

List conversations, newest first. Supports the standard pagination query
(`page`, `page_size`).

**Response (200):**
```json
{
  "items": [
    {
      "id": "uuid",
      "title": "Why is example.com returning 502s?",
      "created_at": "2026-10-03T00:00:00Z",
      "updated_at": "2026-10-03T00:05:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

The `title` is derived from the first message (first line, 60 characters,
ellipsised) and stays empty until the first message is sent.

### POST /ai/conversations

Create an empty conversation. `title` is optional (at most 200 characters) and
usually left out — the first message names the conversation.

**Response (201):** the conversation summary.

### GET /ai/conversations/{conversation_id}

One conversation with its messages, oldest first, capped at the most recent
500. `404` for an unknown id.

**Response (200):**
```json
{
  "id": "uuid",
  "title": "Why is example.com returning 502s?",
  "created_at": "2026-10-03T00:00:00Z",
  "updated_at": "2026-10-03T00:05:00Z",
  "messages": [
    { "id": "uuid", "role": "user", "content": "…", "created_at": "…" },
    {
      "id": "uuid",
      "role": "assistant",
      "content": "",
      "tool_calls": [
        {
          "id": "call_1",
          "type": "function",
          "function": {
            "name": "query_access_logs",
            "arguments": "{\"status_class\":5}"
          }
        }
      ],
      "created_at": "…"
    },
    {
      "id": "uuid",
      "role": "tool",
      "content": "{\"rows\":[…]}",
      "tool_call_id": "call_1",
      "tool_name": "query_access_logs",
      "created_at": "…"
    }
  ]
}
```

`tool_calls` appears on assistant messages only, and `tool_call_id` /
`tool_name` on tool messages only.

### DELETE /ai/conversations/{conversation_id}

Delete a conversation and its messages (cascade). **Response:** `204`.

### POST /ai/conversations/{conversation_id}/messages

Run one turn: the message is stored, then the model may call tools (at most
`max_tool_rounds` rounds) before it answers.

**Request:**
```json
{ "content": "Which sites returned 5xx in the last hour?" }
```

With `Accept: text/event-stream` the response is an SSE stream of JSON events,
one `data:` line per event:

| Event | Payload | Meaning |
|-------|---------|---------|
| `conversation` | `{"id","title"}` | Sent first when the first message names the conversation. |
| `delta` | `{"text"}` | Incremental assistant text. |
| `tool_call` | `{"id","name","arguments"}` | The model requested a tool call. |
| `tool_result` | `{"id","name","result","is_error"}` | The tool answered; `result` is its raw JSON. |
| `done` | `{"content"}` | The turn finished; `content` is the final answer. |
| `error` | `{"message"}` | The turn failed; the message is safe to display. |

Without that header the same events are folded into one buffered JSON
response once the turn completes:

```json
{
  "conversation_id": "uuid",
  "content": "The final answer…",
  "tool_calls": [
    { "id": "call_1", "name": "query_access_logs", "arguments": {}, "result": {}, "is_error": false }
  ]
}
```

Errors: `400` for an empty or oversized message (8 000 characters), `404` for
an unknown conversation, `409` when the assistant is disabled or its provider
configuration is incomplete. A failure during the turn arrives as an `error`
event in SSE mode and as `502 Bad Gateway` in buffered mode.

## MCP server

The control plane hosts an MCP (Model Context Protocol) endpoint at `/mcp` —
note the path hangs off the root of the TLS listener, not under `/api/v1`. It
speaks MCP over **Streamable HTTP**: clients `POST` JSON-RPC 2.0 messages and
receive JSON responses; `GET` and `DELETE` answer `405` so probing clients
fall back to POST. The endpoint is stateless — no `Mcp-Session-Id` is issued.

Authentication reuses the console credentials: `Authorization: Bearer` with
either a `pwk_…` API key or a user JWT. A key needs the `read` permission (and
its owner must be an administrator) to be accepted at all; the write tools
additionally require the `write` permission on the key. Revoked or disabled
keys are rejected. JWT sessions run through the same account checks as the
REST API — disabled accounts and stale tokens (superseded by a newer sign-in)
are refused, and an account that must change its password at next sign-in is
rejected outright since MCP offers no way to complete that flow.

The endpoint is rate limited alongside the REST API and capped for abuse
resistance: a JSON-RPC batch may contain at most 16 calls (larger batches are
rejected with `-32600`), and the request body is limited to 256 KiB.

Supported methods: `initialize`, `ping`, `tools/list`, `tools/call`,
`resources/list`, `resources/read`, `resources/templates/list`,
`prompts/list`, `prompts/get`, `logging/setLevel` (accepted, no-op), and
JSON-RPC batches thereof. Notifications receive `202 Accepted`.

Because the route hangs off the root router, the 9080 self-protection stack —
access log, IP allowlist, WAF ([see API protection](#get-settingsapi-protection))
— applies to `/mcp` exactly as it does to the REST API.

### GET /settings/mcp

Introspection for the MCP endpoint, used by the Settings card: where the
endpoint lives and what this build exposes. Any authenticated console user
(viewers included — they may connect read-only).

**Response (200):**
```json
{
  "path": "/mcp",
  "transport": "streamable_http",
  "tools": [
    { "name": "list_sites", "write": false },
    { "name": "set_site_status", "write": true }
  ],
  "prompts": 3,
  "resources": 5
}
```

`tools` lists the full catalogue in order, `write` marking the tools that
require a write credential. `prompts` and `resources` count what
`prompts/list` and `resources/list` will serve.

### Connecting a client

Point the client at `<console origin>/mcp` and authenticate with a `pwk_…`
API key (create one under **Settings → API keys** with the `read` permission,
plus `write` for the write tools). A generic Streamable HTTP client:

```json
{
  "mcpServers": {
    "pingwaf": {
      "url": "https://waf.example.com:9080/mcp",
      "headers": { "Authorization": "Bearer pwk_YOUR_KEY" }
    }
  }
}
```

Claude Code takes the same settings in one command:

```bash
claude mcp add --transport http pingwaf https://waf.example.com:9080/mcp \
  --header "Authorization: Bearer pwk_YOUR_KEY"
```

### Tools

The registry is shared with the AI assistant; `tools/list` returns only the
tools the calling credential may use (write tools are hidden from read-only
credentials).

| Tool | Write | Description |
|------|-------|-------------|
| `list_sites` | | Sites with status and online agent count. |
| `list_agents` | | Agents with status, version and heartbeat. |
| `certificate_summary` | | TLS certificate counts, including expiring-in-30-days. |
| `query_access_logs` | | Recent proxied requests; the primary diagnosis tool. |
| `query_waf_events` | | WAF detections with rule, request and action. |
| `get_traffic_summary` | | Aggregated traffic for a window. |
| `get_defense_status` | | Observation mode and the control plane's own guards. |
| `list_ip_groups` | | Shared IP groups with size and sync state. |
| `query_control_plane_logs` | | The 9080 access log, including allowlist/WAF verdicts. |
| `set_observation_mode` | ✓ | Turn global observation mode on or off. |
| `set_site_status` | ✓ | Activate or pause one site. |

Errors follow the JSON-RPC convention: `-32601` for an unknown method,
`-32602` for invalid parameters, and a tool's own failure is returned as a
result with `isError: true` and the message in the content text.

### Resources and prompts

`resources/list` exposes the fleet's readable state as MCP resources, each
with a `pingwaf://` URI (defense status, sites, agents, certificates, traffic
and the control-plane log). `prompts/list` offers ready-made troubleshooting
prompts — incident triage, traffic report, security review and certificate
audit — that clients can surface as one-click actions.

---

## System Observation

Read-only self-observation of the process (successor of the removed pprof
endpoints — see [Profiling](profiling.md#what-changed-vs-pprof) for the
migration table). Both endpoints require an admin token, work on every
platform and in every build, and have no enable switch.

### GET /system/metrics

Point-in-time snapshot of process/host CPU and memory. No sampling and no
state: the handler reads counters the OS already keeps (off the async runtime)
and answers immediately.

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

`cpu.process_cpu_percent` is percent of one core (multi-threaded work can
exceed 100); `memory.total_memory_bytes` / `used_memory_bytes` are **host**
figures, marked by `used_memory_scope: "system"` vs
`process_memory_scope: "process"` for `rss`. The `container_memory_*` fields
are present only when a container memory limit applies and match what
`docker stats` reports — prefer them over the host totals in that case.
The remaining `memory.*` fields come from `/proc` (or the cgroup equivalent):
`rss_peak_bytes` is the high-water mark (`VmHWM`), `swap_*` the configured
and in-use swap, `mem_available_bytes` the kernel's estimate of memory
available for new work, `memory_used_percent` the host used/total ratio,
`page_faults_*` the process's cumulative minor/major fault counts, and
`cached_bytes` / `buffers_bytes` the kernel page cache and block-device
buffers. A counter the platform does not expose (e.g. non-Linux, or a kernel
without `MemAvailable`) is reported as `0`.

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:9080/api/v1/system/metrics"
```

### GET /system/profile

Wall-clock time and memory attribution by module and method — pure Rust
instrumentation (`pingwaf-profiler`), not a sampled profile: module-level
atomic counters plus compile-time-registered method timers on instrumented
hot paths. No sampling, no stack unwinding, no allocator hook, no external
tool or image. Counters are cumulative since process start; take two
snapshots and compare deltas for a live view.

> **These numbers are wall-clock time, not CPU time.** Every timer is
> `Instant`-based: a scope that awaits a database query, a lock or the
> upstream reports that wait too. Shares are "of the attributed wall time",
> not "of the CPU the process burned" — reading `cpu_ms` as CPU seconds is
> the mistake that once made `control::http` look like 90 % CPU when it was
> mostly waiting. Each figure is therefore published twice: under the
> historical `cpu_ms` / `cpu_share` names (kept so existing dashboards keep
> parsing) and under `elapsed_ms` / `elapsed_share`, which say what is
> measured. Both pairs always carry the same value; prefer `elapsed_*` in
> new consumers.

**Response (200):**

```json
{
  "collected_at_ms": 1760000000000,
  "total_cpu_ms": 48213.4,
  "total_elapsed_ms": 48213.4,
  "modules": [
    { "module": "proxy",  "cpu_ms": 30102.1, "cpu_share": 0.62, "elapsed_ms": 30102.1, "elapsed_share": 0.62, "mem_bytes": 41943040, "mem_share": 0.55, "calls": 102341, "avg_us": 294.1 },
    { "module": "waf",    "cpu_ms": 11101.2, "cpu_share": 0.23, "elapsed_ms": 11101.2, "elapsed_share": 0.23, "mem_bytes": 8388608,  "mem_share": 0.11, "calls": 98111,  "avg_us": 113.1 }
  ],
  "methods": [
    { "method": "waf::handle_request",  "cpu_ms": 9200.4, "elapsed_ms": 9200.4, "calls": 98111, "avg_us": 93.8 },
    { "method": "proxy::request_filter", "cpu_ms": 7100.9, "elapsed_ms": 7100.9, "calls": 88430, "avg_us": 80.3 }
  ]
}
```

- `modules` — always exactly 7 rows in fixed order: `proxy`, `waf`, `cache`,
  `plugin`, `db`, `control`, `other` (anything not yet instrumented).
  `cpu_share` / `elapsed_share` are the share of the total attributed
  wall-clock time (`total_cpu_ms` / `total_elapsed_ms`, always equal);
  `mem_bytes` is bytes the module currently reports as held (reported, not
  intercepted — no allocator hook), with `mem_share` its share of the total;
  `calls` / `avg_us` are the timed operation count and average microseconds
  per operation.
- `methods` — named call sites, hottest first, capped at 40 rows. Method
  names come from a compile-time static enumeration (the instrumented call
  sites: `proxy::request_filter`, `waf::handle_request`,
  `cache::handle_request`, `plugin::rewrite`, `db::persist_heartbeat`,
  `control::http`), so recording costs two relaxed atomic adds per request —
  no hash lookup. Otherwise the same semantics as the module rows.
- `collected_at_ms` — Unix epoch milliseconds of the snapshot.

**What the `control` row covers.** The control-plane timer books every
`/api/v1` request once — the same timer fills both the `control` module row
and the `control::http` method row (a previous release recorded the module
twice, which inflated its share; that is an accounting fix, not a sudden
performance change). The timer sits *inside* the CORS, compression,
security-header and body-limit layers, so those middleware costs are not
part of `control`.

The response is bounded by construction (7 module rows, at most 40 method
rows, KB-scale JSON) and computed from atomics, so polling it is cheap. See
[Profiling](profiling.md#get-apiv1systemprofile) for field tables and the
reading recipe.

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:9080/api/v1/system/profile"
```

---

## Error Responses

All errors follow a consistent format:

```json
{
  "error": {
    "code": "not_found",
    "message": "Site not found"
  }
}
```

| HTTP Status | Code | Description |
|-------------|------|-------------|
| 400 | `bad_request` | Invalid input |
| 401 | `unauthorized` | Missing or invalid token |
| 403 | `forbidden` | Insufficient permissions |
| 404 | `not_found` | Resource does not exist |
| 409 | `conflict` | Duplicate resource |
| 422 | `unprocessable_entity` | Validation failed by a business rule |
| 429 | `too_many_requests` | Rate limited (passkey challenges) |
| 500 | `internal_error` | Server error |
| 501 | `not_implemented` | Feature disabled on this deployment (passkeys) |

---

## Pagination

List endpoints support pagination:

**Query:** `?page=1&page_size=50`

| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number, 1-based (default: 1) |
| `page_size` | int | Items per page (default: 50, maximum: 200) |

**Response:**
```json
{
  "items": [...],
  "total": 100,
  "page": 1,
  "page_size": 50
}
```

`total` is the number of rows matching the filters, not the size of `items`.

## Log retention

Log rows are swept automatically: the control plane deletes rows older than the
configured windows (see `GET/PUT /settings/log-retention`, default `180` days
for both tables) every six hours. `DELETE /logs/purge` remains available for an
ad-hoc cleanup and deletes rows older than `older_than_days` (default 30) for
one site or, for an administrator, for every site.

The control plane's own access log has its own window,
`access_log_retention_days` on `GET/PUT /settings/api-protection` (default
`30` days). The scheduled sweep enforces it; an ad-hoc `DELETE /logs/purge`
without `site_id` trims it with the same `older_than_days` as the site logs.
