# challenge

CC protection / "5-second shield". Intercepts requests that look automated or
excessive, serves a JavaScript challenge page, and grants a signed clearance
cookie to visitors that solve it.

- **Step:** `early_request` (default) or `request` — configurable
- **Registered as:** `challenge`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `challenge`. |
| `enabled` | bool | `true` | Master switch. An added challenge plugin is active unless explicitly disabled. |
| `under_attack_mode` | bool | `false` | When `true`, challenge **every** request regardless of rate. |
| `clearance_duration_secs` | int | `1800` | Lifetime of the clearance cookie (seconds). |
| `rate_threshold` | int | `100` | Requests per 60-second window above which a visitor is challenged. |
| `pow_difficulty` | int | `20` | Proof-of-work difficulty (leading zero bits). Higher = harder for bots, slower for users. |
| `cookie_secret` | string | *(generated)* | HMAC key used to sign clearance cookies. Leave it unset (or set to the legacy `change-me`) and the process generates a random key instead — set it explicitly only if the secret must survive restarts. |
| `cookie_name` | string | `__pingwaf_clearance` | Name of the clearance cookie. |
| `exempt_paths` | string[] | `[]` | Paths that bypass the challenge (health checks, APIs). |
| `exempt_user_agents` | string[] | `[]` | User-agent substrings that bypass the challenge. |
| `browser_integrity_check` | bool | `true` | Validate browser fingerprint consistency during verification. |
| `submission_max_age_secs` | int | `300` | Maximum age of a valid challenge submission (seconds). |
| `step` | string | `early_request` | `early_request` or `request`. Any other value is a configuration error. |

## Request flow

1. **Verify endpoint** — if the path is `/_pingwaf/challenge/verify` and method
   is `POST`, the plugin parses the proof-of-work submission, validates it, and
   either sets the clearance cookie and returns a redirect to the original URL,
   or returns a `403` block page.
2. **Clearance cookie** — if the request carries a valid, unexpired clearance
   cookie issued for the same site and at a sufficient challenge level, the
   request passes immediately without further checks. A cookie issued by
   another site is ignored even when the signature verifies: the cookie
   secret is per process, so without the site check one solved challenge
   would clear every site served by that process.
3. **Rate tracking** — the per-IP request count in the current 60-second window
   is recorded and fed to the challenge engine.
4. **Engine decision:**

| Decision | Result |
| --- | --- |
| `Pass` | `Continue` — request proceeds. |
| `JsChallenge` | `503` JavaScript challenge page (auto-solve). |
| `ManagedChallenge` | `503` managed challenge page (combined JS + fingerprint). |
| `InteractiveChallenge` | `503` interactive challenge page (user action). |
| `Block` | `403` hard block page. |

## Examples

Standard CC protection:

```toml
[plugins.ccShield]
category = "challenge"
rate_threshold = 60
clearance_duration_secs = 3600
cookie_secret = "my-production-secret-key"
exempt_paths = ["/health", "/api/internal"]
```

Under-attack mode (challenge everyone):

```toml
[plugins.underAttack]
category = "challenge"
under_attack_mode = true
pow_difficulty = 22
cookie_secret = "my-production-secret-key"

[locations.site]
upstream = "backend"
path = "/"
plugins = ["underAttack"]
```

## Interaction with the WAF plugin

The [`waf`](waf.md) plugin may issue a `Challenge` verdict. When it does, the
challenge page is rendered by shared code in this module and the pending nonce is
stored in a process-wide map. The `challenge` plugin's verify endpoint resolves
that nonce and completes the proof-of-work flow.

Both plugins share the same verify endpoint and pending store, so they work
together transparently. Keep `pow_difficulty` and `cookie_secret` **consistent**
across the two plugins to ensure challenges issued by the WAF can be verified by
the challenge plugin.

## Usage notes

- Set `cookie_secret` to a long random value if the clearance cookies must stay
  valid across restarts. When it is unset (or left at the legacy `change-me`),
  the process generates a random secret at startup and logs a warning, so
  cookies are invalidated by a restart but are never signed with a public key.
- `exempt_paths` is a prefix match: `/api` exempts `/api`, `/api/v1`, etc.
- Per-IP rate counters are per-process. Behind a load balancer with N instances
  the effective threshold is N × `rate_threshold`.
- Challenge pages include a `Cache-Control: no-store` header so proxies never
  cache them.
- The verify endpoint body limit is 64 KiB; larger submissions are rejected.
