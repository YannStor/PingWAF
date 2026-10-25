import { test, expect } from '../fixtures/app'

const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const domain = `routing-${run}.e2e.test`
const alternate = `alt-${run}.e2e.test`
const origin = process.env.E2E_ORIGIN_URL ?? 'http://e2e-origin-a:8080'

async function get(page: import('@playwright/test').Page, url: string) {
  const response = await page.goto(url, { waitUntil: 'domcontentloaded' })
  return { status: response?.status() ?? 0, body: await page.locator('body').innerText() }
}

test.describe('basic reverse proxy routing', () => {
  test('routes hosts, matches paths, rewrites and strips prefixes', async ({ app }) => {
    await app.createSite({
      name: `E2E routing ${run}`,
      domain,
      alternateDomains: [alternate],
      upstream: origin,
    })
    try {
      const root = await get(app.page, `http://${domain}/`)
      expect(root.status).toBe(200)
      expect(root.body).toContain('"origin":"a"')

      const alt = await get(app.page, `http://${alternate}/`)
      expect(alt.status).toBe(200)
      expect(alt.body).toContain('"origin":"a"')

      await app.addRoute({ name: 'exact', path: '/exact', match: 'exact', rewritePath: '/a' })
      await app.addRoute({ name: 'prefix', path: '/api', match: 'prefix', stripPrefix: true })
      await app.addRoute({ name: 'regex', path: '^/re/[0-9]+$', match: 'regex', rewritePath: '/b' })
      await app.addRoute({
        name: 'host',
        path: '/host',
        match: 'exact',
        rewritePath: '/headers',
        upstreamHost: 'upstream.example',
      })

      await expect
        .poll(async () => (await get(app.page, `http://${domain}/exact`)).body)
        .toContain('"route":"a"')
      await expect
        .poll(async () => (await get(app.page, `http://${domain}/api/foo`)).body)
        .toContain('"path":"/foo"')
      await expect
        .poll(async () => (await get(app.page, `http://${domain}/re/123`)).body)
        .toContain('"route":"b"')
      await expect
        .poll(async () => (await get(app.page, `http://${domain}/host`)).body)
        .toContain('"host":"upstream.example"')

      const unknown = await get(app.page, `http://unknown-${run}.e2e.test/`)
      expect(unknown.status).toBe(404)
    } finally {
      await app.deleteSite(domain)
    }
  })
})
