import { test, expect } from '../fixtures/app'
import { requiredEnv } from '../support/env'

const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const origin = requiredEnv('E2E_ORIGIN_URL')
const tlsOrigin = process.env.E2E_ORIGIN_TLS_URL

test.describe('reverse proxy protocol and transport', () => {
  test('WebSocket, headers and large responses survive the edge', async ({ app }) => {
    const domain = `protocol-${run}.e2e.test`
    await app.createSite({
      name: `E2E protocol ${run}`,
      domain,
      upstream: origin,
    })
    try {
      await app.waitForSite(domain)
      await app.page.goto(`http://${domain}/`)
      const echoed = await app.page.evaluate(
        () =>
          new Promise<string>((resolve, reject) => {
            const ws = new WebSocket(`ws://${location.host}/ws`)
            const timer = setTimeout(() => reject(new Error('websocket timeout')), 10_000)
            ws.onopen = () => ws.send('hello')
            ws.onmessage = (event) => {
              clearTimeout(timer)
              ws.close()
              resolve(String(event.data))
            }
            ws.onerror = () => {
              clearTimeout(timer)
              reject(new Error('websocket error'))
            }
          }),
      )
      expect(echoed).toBe('echo:hello')

      const headers = await app.page.evaluate(async () => {
        const response = await fetch('/headers', { headers: { 'x-e2e': 'present' } })
        return (await response.json()) as { headers: Record<string, string> }
      })
      expect(headers.headers['x-e2e']).toBe('present')
      expect(headers.headers.host).toBe(domain)

      const big = await app.page.evaluate(async () => {
        const response = await fetch('/big')
        return {
          status: response.status,
          bytes: (await response.arrayBuffer()).byteLength,
        }
      })
      expect(big.status).toBe(200)
      expect(big.bytes).toBeGreaterThan(2 * 1024 * 1024 - 1024)
    } finally {
      await app.deleteSite(domain)
    }
  })

  test('HTTPS origin is supported with certificate verification disabled', async ({ app }) => {
    test.skip(!tlsOrigin, 'E2E_ORIGIN_TLS_URL is not configured')
    const domain = `tls-origin-${run}.e2e.test`
    await app.createSite({
      name: `E2E TLS origin ${run}`,
      domain,
      upstream: tlsOrigin as string,
      upstreamTls: true,
    })
    try {
      await app.waitForSite(domain)
      const response = await app.page.goto(`http://${domain}/a`)
      expect(response?.status()).toBe(200)
      expect(await app.page.locator('body').innerText()).toContain('"route":"a"')
    } finally {
      await app.deleteSite(domain)
    }
  })
})
