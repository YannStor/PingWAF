import { test, expect } from '../fixtures/app'

const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const origin = process.env.E2E_ORIGIN_URL ?? 'http://e2e-origin-a:8080'

test.describe('cache and compression', () => {
  test('caches an eligible response and preserves encoded bodies', async ({ app }) => {
    const domain = `cache-${run}.e2e.test`
    const siteId = await app.createSite({
      name: `E2E cache ${run}`,
      domain,
      upstream: origin,
    })
    try {
      await app.page.goto(`https://47.242.20.155:9080/sites/${siteId}/caching`)
      await app.page.getByRole('button', { name: 'Add rule' }).click()
      const dialog = app.page.getByRole('dialog', { name: 'Add rule' })
      await dialog.getByRole('textbox', { name: /Name/ }).fill('E2E cache')
      await dialog.getByRole('textbox', { name: 'Match expression' }).fill('http.request.uri.path starts_with "/cache"')
      await dialog.getByRole('spinbutton', { name: 'Edge TTL' }).fill('60')
      await dialog.getByRole('spinbutton', { name: 'Browser TTL' }).fill('0')
      await dialog.getByRole('switch', { name: /Respect origin/ }).uncheck()
      await dialog.getByRole('button', { name: 'Create', exact: true }).click()
      await expect(dialog).toHaveCount(0)

      const first = await app.page.goto(`http://${domain}/cache`)
      expect(first?.status()).toBe(200)
      const second = await app.page.goto(`http://${domain}/cache`)
      expect(second?.status()).toBe(200)
      const counts = await app.page.evaluate(async () => {
        const response = await fetch('/count')
        return (await response.json()) as { counts: Record<string, number> }
      })
      expect(counts.counts['/cache']).toBe(1)

      const gzip = await app.page.goto(`http://${domain}/gzip`)
      expect(gzip?.status()).toBe(200)
      expect(gzip?.headers()['content-encoding']).toContain('gzip')
      expect((await gzip?.body())?.length).toBeGreaterThan(10_000)

      const brotli = await app.page.goto(`http://${domain}/br`)
      expect(brotli?.status()).toBe(200)
      expect(brotli?.headers()['content-encoding']).toContain('br')
    } finally {
      await app.deleteSite(domain)
    }
  })
})
