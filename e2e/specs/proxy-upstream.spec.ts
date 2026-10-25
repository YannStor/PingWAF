import { test, expect } from '../fixtures/app'

const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const originA = process.env.E2E_ORIGIN_URL ?? 'http://e2e-origin-a:8080'
const originB = process.env.E2E_ORIGIN_B_URL ?? 'http://e2e-origin-b:8080'

test.describe('multi-upstream and health handling', () => {
  test('a second origin can be added and the site keeps serving', async ({ app }) => {
    const domain = `upstream-${run}.e2e.test`
    const siteId = await app.createSite({
      name: `E2E upstream ${run}`,
      domain,
      upstream: originA,
    })
    try {
      await app.page.goto(`https://47.242.20.155:9080/sites/${siteId}/basic`)
      await app.addNode(originB)

      const seen = new Set<string>()
      for (let i = 0; i < 8; i++) {
        const response = await app.page.goto(`http://${domain}/?probe=${i}`)
        expect(response?.status()).toBe(200)
        seen.add(await app.page.locator('body').innerText())
      }
      expect([...seen].some((body) => body.includes('"origin":"a"'))).toBe(true)
    } finally {
      await app.deleteSite(domain)
    }
  })
})
