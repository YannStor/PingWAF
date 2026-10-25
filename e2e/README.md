# Browser E2E

Playwright tests for the real console and edge. Application setup and
assertions go through the browser; the shell is only used for containers,
logs, TLS inspection and database diagnostics. No test calls the PingWAF REST
API directly.

## Coverage

| File | Covers |
| --- | --- |
| `specs/proxy-routing.spec.ts` | site creation, primary/alias hosts, prefix/exact/regex routes, rewrite, strip, upstream Host, unknown-host 404 |
| `specs/proxy-upstream.spec.ts` | multi-origin and health/failover checks |
| `specs/proxy-protocol.spec.ts` | WebSocket, 1 MiB+ response, request headers, HTTPS origin |
| `specs/proxy-cache-compression.spec.ts` | edge HIT/MISS via an origin sequence, upstream gzip; brotli is checked with `curl --compressed` because Chromium 156 reports `ERR_CONTENT_DECODING_FAILED` for the fixture |
| `specs/proxy-errors.spec.ts` | unknown host, path traversal, 1 MiB upload |
| `specs/acme-staging.spec.ts` | unreachable upstream + HTTP-01 + staging issuer + HTTPS/HTTP2 |

## Demo origin

The tests use hostnames under `E2E_ZONE` (`e2e.test` by default). Chromium
maps them to the edge IP with `--host-resolver-rules`; no DNS records are
needed. Only the ACME test uses the real `E2E_ACME_DOMAIN`, whose A record must
point at the edge.

On the demo host, place `origin/server.mjs` under `/root/waf/e2e-origin` and run
two nodes on the `waf_pingwaf-net` network:

```bash
podman build -t localhost/pingwaf-e2e-origin /root/waf/e2e-origin
for n in a b; do
  podman run -d --name e2e-origin-$n --network waf_pingwaf-net \
    -e ORIGIN_NAME=$n -e TLS_PORT=8443 \
    -e TLS_CERT=/certs/cert.pem -e TLS_KEY=/certs/key.pem \
    -v /root/waf/e2e-origin/certs:/certs:ro \
    localhost/pingwaf-e2e-origin
done
```

The origin exposes `/`, `/a`, `/b`, `/headers`, `/echo`, `/cache`, `/big`,
`/gzip`, `/br`, `/slow`, `/status`, `/count` and `/ws`.

## Run

```bash
cd e2e
npm ci
E2E_ADMIN_PASSWORD='...' E2E_ACME_DOMAIN=mirror.liveflowhub.com npm test
```

`E2E_ADMIN_PASSWORD` is required and is never written to a config file. The
dashboard certificate is self-signed, so the browser context enables
`ignoreHTTPSErrors`; staging certificates are likewise untrusted and their
issuer is checked separately with `openssl`.

The suite serialises workers because all tests share one demo control plane.
Each test creates unique `*-<run>.e2e.test` sites and removes them in a
`finally` block. The ACME test deletes and recreates the configured domain; it
must only run against the dedicated demo with a pre-test database snapshot.

## Diagnostics

On failure Playwright writes a screenshot and trace under `test-results/`, plus
the HTML/JSON report under `artifacts/`. Collect the data plane log and the
certificate rows/events before deleting the site:

```bash
docker compose logs --since 30m pingwaf
docker compose exec -T postgres psql -U pingwaf -d pingwaf \
  -c "SELECT id,site_id,domain,status,failure_reason,updated_at FROM site_certificates ORDER BY created_at DESC LIMIT 10;" \
  -c "SELECT event_type,message,created_at FROM certificate_events ORDER BY created_at DESC LIMIT 20;"
```

Never commit traces, screenshots, ACME tokens, private keys or the admin
password.
