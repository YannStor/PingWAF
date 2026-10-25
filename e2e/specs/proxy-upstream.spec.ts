import { test, expect } from '../fixtures/app'
import { requiredEnv } from '../support/env'

const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const originA = requiredEnv('E2E_ORIGIN_URL')
const originB = requiredEnv('E2E_ORIGIN_B_URL')

test.describe('multi-upstream and health handling', () => {
  test('a second origin can be added and the site keeps serving', async ({ app, browser }) => {
    const domain = `upstream-${run}.e2e.test`
    const alternate = `upstream-alt-${run}.e2e.test`
    const siteId = await app.createSite({
      name: `E2E upstream ${run}`,
      domain,
      alternateDomains: [alternate],
      upstream: originA,
    })
    try {
      await app.waitForSite(domain)
      await app.page.goto(app.adminUrl(`/sites/${siteId}/basic`))
      await app.addNode(originB)
      await app.waitForSite(domain)
      // The new node needs one health-check cycle before the load balancer
      // admits it; without this the test only ever observes the first node.
      await app.page.waitForTimeout(12_000)

      const seen = new Set<string>()
      for (let i = 0; i < 10; i++) {
        const context = await browser.newContext({ ignoreHTTPSErrors: true })
        const page = await context.newPage()
        for (const host of [domain, alternate]) {
          const response = await page.goto(`http://${host}/?probe=${i}`)
          expect(response?.status()).toBe(200)
          seen.add(await page.locator('body').innerText())
        }
        await context.close()
      }
      expect([...seen].some((body) => body.includes('"origin":"a"'))).toBe(true)
      expect([...seen].some((body) => body.includes('"origin":"b"'))).toBe(true)
    } finally {
      await app.deleteSite(domain)
    }
  })
})
