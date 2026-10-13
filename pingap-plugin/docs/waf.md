# waf

Web Application Firewall request inspection. Every request is scored against the
PingWAF detection engine (managed signature rules plus optional per-site custom
rules), and the resulting verdict is mapped onto the proxy pipeline.

- **Step:** `early_request` (default) or `request` — configurable
- **Registered as:** `waf`

## Configuration

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | Must be `waf`. |
| `mode` | string | `block` | `off`, `monitor` or `block`. `off` skips inspection entirely; `monitor` logs events but never blocks; `block` enforces verdicts. Case-insensitive; unknown values fall back to `block`. |
| `advanced_mode` | bool | `false` | One-step Strict grading: implies `level = "strict"` and `inspect_body = true`, taking precedence over an explicit `level` key. |
| `level` | string | `normal` | Rule grading level, `normal` or `strict`. `strict` additionally assembles Strict-only managed rules (e.g. `PINGWAF-1061`). Ignored when `advanced_mode` is on. |
| `stacks` | string[] | all | Backend stacks to detect for: `generic`, `java`, `php`, `python`, `node`. Empty means all stacks. Stack filters apply to signatures and managed rules alike. |
| `monitor_categories` | string[] | `[]` | Attack categories to downgrade to monitor-only: `sqli`, `xss`, `rce`, `lfi`, `ssrf`, `deser`, `crlf`, `xxe`, `ssti`. Matched requests are still detected and logged but never blocked. Unknown names are ignored with a warning. |
| `monitor_stacks` | string[] | `[]` | Backend stacks to downgrade to monitor-only (same names as `stacks`). Language-agnostic (generic) detection is never downgradable. |
| `monitor_managed_rules` | string[] | `[]` | Managed rule ids to downgrade to monitor-only, e.g. `["PINGWAF-1010"]`. Applies to every managed rule including score-gate rules (`PINGWAF-1002`/`1003`/`1004`/`1061`). Unknown ids are ignored with a warning. |
| `paranoia_level` | int | `2` | Detection sensitivity, clamped to `1`–`4`. Higher catches more but increases false positives. |
| `anomaly_threshold` | int | `40` | Accumulated anomaly score at which a request is blocked/challenged. |
| `detections` | string[] | `[]` | Enabled detection families, e.g. `["sqli", "xss", "rce", "lfi", "ssrf"]`. |
| `ml_enabled` | bool | `false` | Reserved: enable the ML scoring pass. **Not wired up yet** — the engine ignores it at runtime. |
| `ml_threshold` | float | `0.5` | Reserved: ML confidence threshold (`0.0`–`1.0`). **Not wired up yet** — ignored at runtime. |
| `inspect_body` | bool | `false` | Read and inspect the request body. Off by default — reading the body on every request is expensive and interferes with streaming uploads. |
| `max_body_size` | int | `65536` | Upper bound (bytes) of the body read when `inspect_body` is on. |
| `pow_difficulty` | int | `20` | Proof-of-work difficulty used when a `Challenge` verdict delegates to the challenge subsystem. |
| `step` | string | `early_request` | `early_request` or `request`. Any other value is a configuration error. |

## Verdicts

| Verdict | Result |
| --- | --- |
| `Pass` | `Continue` — request proceeds untouched. |
| `Monitor` | Event logged, `Continue`. |
| `Block` | `403 Forbidden` HTML block page with the request id. |
| `Challenge` | `503` JS challenge page (delegated to the [challenge](challenge.md) subsystem). |

The block page body is:

```html
<html><body><h1>403 Forbidden</h1><p>Request blocked by PingWAF.</p>
<p>Reason: {reason}</p><p>Request ID: {request_id}</p></body></html>
```

## Control plane vs standalone

Rules are resolved per request:

- When a **PingWafAgent** control-plane instance is running, the site rules for
  the request's `Host` are used. Per-domain engines are cached and rebuilt
  automatically when the agent's config hash changes. If the control plane marks
  WAF disabled for a site, inspection is skipped for that host.
- Otherwise (**standalone pingap**) the locally configured engine above is used.

When either a `Block` or `Challenge` fires and an agent is present, a
`SecurityEvent` is shipped to the control plane and the site's request counters
are updated.

## Examples

Blocking mode with a raised paranoia level and body inspection:

```toml
[plugins.waf]
category = "waf"
mode = "block"
paranoia_level = 3
anomaly_threshold = 30
detections = ["sqli", "xss", "rce", "lfi", "ssrf"]
inspect_body = true
max_body_size = 131072

[locations.api]
upstream = "backend"
path = "/api"
plugins = ["waf"]
```

Monitor (shadow) mode — log what would be blocked without enforcing:

```toml
[plugins.wafShadow]
category = "waf"
mode = "monitor"
paranoia_level = 2
```

Strict grading with body inspection, keeping a known-noisy managed rule in
monitor-only mode and ignoring SQLi hits for a PHP backend:

```toml
[plugins.waf]
category = "waf"
advanced_mode = true
monitor_managed_rules = ["PINGWAF-1010"]
monitor_categories = ["sqli"]
stacks = ["php"]
```

## Usage notes

- `waf` runs at `early_request` by default, ahead of most other plugins, so
  malicious traffic is rejected before authentication, caching or upstream work.
- Pair with [`challenge`](challenge.md): a `Challenge` verdict renders the
  challenge page, and the challenge plugin's verify endpoint completes the flow.
  Keep `pow_difficulty` and `cookie_secret` consistent between the two.
- The engine runs on **every** request. Leave `inspect_body` off unless you need
  body-level detection, and keep `max_body_size` bounded.
- **Body inspection is prefix-only**: with `inspect_body` on, only the first
  `max_body_size` bytes (default 64 KiB) are decoded and scanned; a payload
  placed entirely after that boundary is not seen by the engine. Raise
  `max_body_size` to cover larger expected payloads — at the cost of memory
  and latency on big uploads — and treat the setting as a tuned trade-off,
  not a hard security boundary. Access logs record
  `request_body_truncated` whenever the limit cut a body short.
- **Encoded and non-text bodies are decoded before scanning.** With
  `inspect_body` on, a `Content-Encoding: gzip` / `x-gzip` / `deflate` body is
  decompressed first (layers peeled in reverse, decompressed size capped at
  1 MiB so a decompression bomb cannot exhaust memory), and a body that is not
  valid UTF-8 is decoded leniently rather than skipped. An encoding the engine
  does not recognise is scanned as-is. The scan therefore covers the bytes a
  payload actually carries, not just the ones that happened to be readable.
- The engine is held behind `Arc<RwLock<..>>` and per-domain engines are cached,
  so control-plane rule updates hot-reload without restarting pingap.
