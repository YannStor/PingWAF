import { test, expect } from '../fixtures/app'
import { requiredEnv } from '../support/env'

const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const origin = requiredEnv('E2E_ORIGIN_URL')

test.describe('proxy error and boundary handling', () => {
  test('rejects unknown hosts, blocks path traversal and streams a 1 MiB body', async ({ app }) => {
    const domain = `errors-${run}.e2e.test`
    await app.createSite({
      name: `E2E errors ${run}`,
      domain,
      upstream: origin,
    })
    try {
      await app.waitForSite(domain)
      const echo = await app.page.evaluate(async () => {
        const body = new Uint8Array(1024 * 1024)
        const response = await fetch('/echo', { method: 'POST', body })
        return {
          status: response.status,
          json: (await response.json()) as { bytes: number; sha256: string },
        }
      })
      expect(echo.status).toBe(200)
      expect(echo.json.bytes).toBe(1024 * 1024)
      expect(echo.json.sha256).toHaveLength(64)

      const traversal = await app.page.goto(`http://${domain}/%2e%2e/%2e%2e/etc/passwd`)
      expect(traversal?.status() ?? 0).toBeGreaterThanOrEqual(400)
      expect(await app.page.locator('body').innerText()).not.toContain('root:x:')

      const unknown = await app.page.goto(`http://unknown-${run}.e2e.test/`)
      expect(unknown?.status()).toBe(404)
    } finally {
      await app.deleteSite(domain)
    }
  })
})
