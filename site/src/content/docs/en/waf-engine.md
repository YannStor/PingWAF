---
title: WAF engine
description: The four-phase detection pipeline, expression rules, anomaly scoring, verdicts and the challenge flow.
minutes: 9
---

## The pipeline

Every request that has WAF enabled runs through four phases:

```
normalize → signatures → expression rules → anomaly score → verdict
```

1. **Normalize** — repeated URL decoding (three layers by default, `max_decode_layers`), HTML entity decoding, path folding, query and cookie splitting. Strict mode also decodes escape sequences.
2. **Signatures** — Aho-Corasick multi-pattern matching plus libinjection heuristics for SQLi and XSS, evaluated against every decoded value. Reflected hits in `Referer` and `User-Agent` are downgraded to weak signals.
3. **Expression rules** — compiled conditions, evaluated after allow rules have had a chance to short-circuit.
4. **Anomaly score** — matches aggregate into a score that is compared against the threshold to produce exactly one verdict.

## Scoring and verdicts

Severity maps to points on an OWASP-style scale: critical 5, high 4, medium 3, low 2, informational 1. The default aggregate threshold is **40** with paranoia **2** (range 1–4).

| Verdict | When it is produced |
| --- | --- |
| `Pass` | Nothing matched, or the score stayed at zero |
| `Monitor` | The score is non-zero but below the blocking threshold |
| `Block` | The score reached the threshold, or a critical signature hit the fast path |
| `Challenge` | A rule forced a challenge; the client must clear it before continuing |

Rule-forced actions win over scoring, and `Block` outranks `Challenge`. With `fast_path_block_on_critical` enabled (default), a critical stage-1 signature blocks immediately and stage 2 is skipped. Monitor mode (`WafMode::Monitor`) downgrades Block and Challenge to Monitor and records `would_enforce` in the details so you can tune before enforcing.

## Expressions

The grammar is a small recursive-descent parser: `field operator value`, combined with `and`, `or` and `not`, with values that can be strings, numbers, booleans or sets.

```
http.request.uri.path starts_with "/admin"
  and not ip.src in {10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8}

cf.waf.score.sqli ge 60

user_agent matches "(?i)(nikto|sqlmap|nmap|masscan|acunetix)"

http.request.method in {"TRACE" "TRACK"}

http.request.headers["user-agent"] contains "${jndi:"
```

Available fields include `http.request.uri.path`, `http.request.uri.full`, `http.request.uri.query`, `http.request.method`, `http.request.headers[...]`, `http.request.cookies[...]`, `http.request.body`, `http.host`, `ip.src`, `ip.src.country`, `cf.waf.score`, `cf.waf.score.sqli`, `cf.waf.score.xss`, `cf.waf.score.rce`, `ssl` and `user_agent`.

Operators: `eq`/`=`/`==`, `ne`/`!=`, `contains`, `not_contains`, `matches`, `in`, `starts_with`, `ends_with`, `lt`, `gt`, `le`, `ge`, plus the `not <op>` forms.

## Managed rules

Fifteen `PINGWAF-xxxx` rules ship in the binary and are loaded according to the configured level. They cover injection families, admin path exposure, scanner user agents, forbidden methods, JNDI payloads and oversized URIs. A managed rule that fails to parse is skipped with a warning rather than failing the whole bundle.

## Challenges and CC protection

| Setting | Default |
| --- | --- |
| `enabled` | `true` |
| `under_attack_mode` | `false` |
| `default_level` | `NonInteractive` (JavaScript 5-second shield) |
| `clearance_duration_secs` | `1800` |
| `rate_threshold` | 100 requests/minute/IP |
| `exempt_paths` | `/health`, `/ping` |
| `browser_integrity_check` | `true` |
| `pow_difficulty` | `20` |
| `submission_max_age_secs` | `300` |

Challenge levels are `None`, `NonInteractive`, `Managed` (picks per request risk) and `Interactive`. Proof of work uses SHA-256 with a leading-zero target. A pass is stored in `__pingwaf_clearance`, a cookie whose value is `base64(payload).base64(HMAC-SHA256)` and which is bound to the issuing site, so it cannot be replayed against another hostname.

## Bot policy

Bot protection is configured per site with `ua_analysis`, `js_detection`, `tls_fingerprint`, `behavioral_analysis`, an action (`block`, `challenge`, `js_challenge`, `log`, `allow`), a known-bot allow list, IP and DNS verification, and an optional verified-IP group. Rate limiting uses the same dimension vocabulary — `ip`, `ip_nat`, `host`, `path`, `asn`, `country`, `header:<name>`, `cookie:<name>`, `query:<name>` — with actions `block`, `log`, `challenge`, `js_challenge` and `allow`.

## Where to change thresholds

Site-level WAF settings are written through `PUT /api/v1/sites/{site_id}/waf/settings`: `waf_enabled`, `mode`, `paranoia_level`, `advanced_mode`, monitor flags and `body_stage_timeout_secs`. The same values flow to agents in `WafConfig` with `anomaly_threshold` and `paranoia_level`.
