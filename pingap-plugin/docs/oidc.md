# oidc

OpenID Connect login for browser traffic: an unauthenticated browser is sent
to the configured identity provider (authorization code flow with PKCE) and
comes back with a verified ID token, which becomes an encrypted session
cookie — nothing is stored on this side.

- **Step:** `request` only (a configuration with another `step` is rejected
  at startup)
- **Registered as:** `oidc`

## Login flow

1. A browser asks for a page without a valid session. If the request is a
   navigation (a `GET` a browser would follow), it is redirected (302) to the
   provider's authorization endpoint with PKCE (`S256`), `state` and `nonce`.
2. The provider sends the browser back to `redirect_path` with a code. The
   code is traded at the token endpoint for an ID token, whose signature is
   verified against the provider's JWKS, together with `iss`, `aud`, `exp`
   and `nonce`.
3. The kept claims (`sub` plus everything `claims_to_headers` names) are
   sealed into an encrypted cookie: the key is
   `SHA-256(cookie_secret || 0x00 || issuer || 0x00 || client_id)` and the
   cipher is AES-256-GCM-SIV with a fresh nonce per value. Every instance
   sharing the secret reads the cookie, so the sessions survive a restart and
   need no shared store.
4. Later requests with a valid session get the configured claims in their
   configured request headers and pass through; the browser is redirected to
   the provider again when the session has expired.

A request that is not a navigation (a script's `fetch`, a form `POST`, or any
non-`GET`) cannot follow the redirect: without a session it is told so with
`401 Login required` instead.

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `oidc`. |
| `issuer` | string | — | Required. http(s) URL of the provider; trailing slashes are stripped. The discovery document must name exactly this issuer. |
| `client_id` | string | — | Required. Client id registered at the provider. |
| `client_secret` | string | — | Client secret. May be empty for a public client. |
| `cookie_secret` | string | — | Required, at least 16 characters. Seeds the session-cookie key together with `issuer` and `client_id`. |
| `redirect_path` | string | `/oauth2/callback` | Path the provider returns to. Must be a bare path starting with `/`, without a query or fragment. |
| `logout_path` | string | none | Path that ends the session. Must differ from `redirect_path`; unset means there is no logout endpoint. |
| `redirect_url` | string | none | The callback as the provider is to see it, when that is not derivable from the request (behind another proxy or a CDN). Must be an http(s) URL whose path equals `redirect_path`. |
| `scopes` | string[] | `[openid]` | Scopes to ask for. `openid` is always present and always first. |
| `cookie_name` | string | `pingap_oidc` | Session cookie name. Only letters, digits, `.`, `_` and `-`; must not start with `__Host-` (the login cookie is scoped to `redirect_path`, not `/`). |
| `session_ttl` | duration | `12h` | How long a session lasts. At least `1m`. |
| `claims_to_headers` | string[] | — | ID-token claims copied into request headers, as `claim:X-Header` (e.g. `email:X-Auth-Email`). The header name must not be `Content-Length`, `Transfer-Encoding`, `Host` or `Connection`. |

## Examples

### Keycloak

```toml
[plugins.oidcAuth]
category = "oidc"
issuer = "https://keycloak.example.com/realms/main"
client_id = "pingap"
client_secret = "change-me"
cookie_secret = "0123456789abcdef0123456789abcdef"
redirect_path = "/oauth2/callback"
logout_path = "/oauth2/logout"
scopes = ["openid", "profile", "email"]
claims_to_headers = ["email:X-Auth-Email", "preferred_username:X-Auth-User"]

[locations.app]
upstream = "app"
path = "/"
plugins = ["oidcAuth"]
```

Register `https://app.example.com/oauth2/callback` as the client's redirect
URI at Keycloak — the scheme and host come from the request (`redirect_url`
is unset), the path from `redirect_path`.

### Generic provider behind a CDN

```toml
[plugins.oidcAuth]
category = "oidc"
issuer = "https://accounts.example.com"
client_id = "web"
cookie_secret = "0123456789abcdef0123456789abcdef"
redirect_url = "https://app.example.com/oauth2/callback"
session_ttl = "30m"
```

`redirect_url` pins the callback the provider is told about: the request's
`Host` behind a CDN or an inner proxy is not the address the client was
registered with. Its path must equal `redirect_path`.

## Responses

| Situation | Status | Body |
| --- | --- | --- |
| No session, navigation request | 302 | redirect to the provider |
| No session, not a navigation request | 401 | `Login required` |
| Provider unreachable while starting a login | 502 | `Login is not available` |
| Callback without a code, or a login that was not started here / already finished / expired | 400 | the reason |
| The provider refused the login | 403 | `Login refused: <error name>` |
| Token exchange or ID-token verification failed | 502 | `Login failed` |

## Observability

Two kinds of login failure are reported as security events and turned into
alerts by the control plane:

| Event | Severity | When |
| --- | --- | --- |
| `site.oidc_login_failed` | warning | A login could not complete: the client secret was wrong, the code was replayed, the `state` did not match, the ID token was invalid. |
| `site.oidc_idp_unavailable` | critical | The provider could not be reached (discovery, JWKS or token endpoint), so nobody can complete a login. |

An unauthenticated browser being redirected to the provider is normal traffic
and is not reported. Alert delivery is gated by the `notify_site_oidc_auth`
notification switch (on by default), which covers both events.

Note that `site.oidc_login_failed` can be raised by any anonymous visitor —
posting a bogus `code` and `state` to the callback path is enough. Alerts are
deduplicated per site and per channel over the notification dedup window, so a
burst collapses into one message rather than flooding the channels; a real
problem still surfaces because the alert keeps recurring.

## Usage notes

- **PKCE (`S256`), `state` and `nonce` are all verified** on the way back;
  the ID token's signature is checked against the provider's JWKS keys, and
  `iss`, `aud` (the client id), `exp` (and `nbf`) and the `nonce` of this very
  login are validated, with a clock leeway of 60 seconds.
- **The discovery document must name the configured `issuer` exactly** — a
  provider that calls itself something else is refused, so tokens are never
  sent to an impostor's endpoints.
- The provider's description of itself (discovery) is cached for one hour,
  refetched single-flight with a 10 second cooldown when it failed, and every
  HTTP request to it has a 10 second timeout. A login in flight expires after
  10 minutes.
- The claim headers are the plugin's own: whatever a client sent under those
  names is stripped before authentication (including the same name written
  with `_` for `-`), so a client cannot forge an identity, and
  `protect_from_connection_header` keeps a `Connection: X-Auth-Email` from
  taking a claim header away from the upstream.
- `client_secret` and `cookie_secret` are never logged; the constructor
  records only `issuer` and `client_id`, and failure details name a reason
  from a closed set.
- An ID token that names no `kid` is tried against every key the provider
  publishes (a single-key provider may omit it). `alg` is still pinned to the
  asymmetric algorithms, and `iss`/`aud`/`exp`/`nonce` are checked the same way.
- `claims_to_headers` refuses the headers that change what a request means:
  `Content-Length`, `Transfer-Encoding`, `Host`, `Connection`, plus
  `Authorization`, `Cookie`, `Set-Cookie`, `X-Forwarded-For`,
  `X-Forwarded-Proto` and `X-Real-IP`.
- With no `redirect_url` configured the callback address is derived from the
  request's `Host`, and `Secure` on the session cookie from whether the
  connection arrived over TLS. Behind a TLS-terminating proxy or load balancer
  the plugin sees plain HTTP, so **set `redirect_url` explicitly there** — an
  `http://` callback is usually rejected by the provider, and the cookie would
  lose `Secure`.
- Session cookies are `HttpOnly; SameSite=Lax` with `Max-Age`, and `Secure`
  when the site is reached over TLS. The session cookie is scoped to `/`; the
  short-lived cookie that carries a login in progress is scoped to
  `redirect_path`, and finished (or abandoned) ones are cleared.
- Requests to `logout_path` clear the session cookie, clear leftover login
  cookies, and redirect to the provider's `end_session_endpoint` (with the
  client id) when discovery advertises one — otherwise they answer
  `200 Logged out`.
- The callback is matched against the path the browser asked for, not the
  rewritten one: a location rewrite (e.g. `strip_prefix`) cannot move the
  callback out from under the plugin (`Ctx::features::original_uri`).
- A session has to fit in one cookie (about 4 KB); claims that do not fit
  fail the login rather than truncate.
- Two plugins that share `cookie_secret` but differ in `issuer` or
  `client_id` derive different keys and cannot read each other's cookies.
