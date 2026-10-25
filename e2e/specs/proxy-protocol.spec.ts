import { test, expect } from '../fixtures/app'

const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const origin = process.env.E2E_ORIGIN_URL ?? 'http://e2e-origin-a:8080'

test.describe('reverse proxy protocol and transport', () => {
  test('WebSocket, headers and large responses survive the edge', async ({ app }) => {
    const domain = `protocol-${run}.e2e.test`
    await app.createSite({
      name: `E2E protocol ${run}`,
      domain,
      upstream: origin,
    })
    try {
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

      const response = await app.page.goto(`http://${domain}/big`)
      expect(response?.status()).toBe(200)
      expect((await response?.body())?.length).toBeGreaterThan(2 * 1024 * 1024 - 1024)
    } finally {
      await app.deleteSite(domain)
    }
  })

  test('HTTPS origin is supported with certificate verification disabled', async ({ app }) => {
    const domain = `tls-origin-${run}.e2e.test`
    await app.createSite({
      name: `E2E TLS origin ${run}`,
      domain,
      upstream: 'https://e2e-origin-a:8443',
      upstreamTls: true,
    })
    try {
      const response = await app.page.goto(`http://${domain}/a`)
      expect(response?.status()).toBe(200)
      expect(await app.page.locator('body').innerText()).toContain('"route":"a"')
    } finally {
      await app.deleteSite(domain)
    }
  })
})
