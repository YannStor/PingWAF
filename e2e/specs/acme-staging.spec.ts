import { execFileSync } from 'node:child_process'
import { test, expect } from '../fixtures/app'

const domain = process.env.E2E_ACME_DOMAIN ?? 'mirror.liveflowhub.com'
const timeout = Number(process.env.E2E_ACME_TIMEOUT ?? 900_000)

test.describe('ACME staging with an unreachable origin', () => {
  test('issues HTTP-01 even when the site has no usable upstream', async ({ app }) => {
    test.setTimeout(timeout + 120_000)
    await app.deleteSiteIfPresent(domain)
    await app.createSite({
      name: `E2E ACME ${Date.now().toString(36)}`,
      domain,
      upstream: 'http://127.0.0.1:9',
    })
    try {
      await app.requestCertificate({
        domain,
        email: `e2e+acme@${domain}`,
        challenge: 'http-01',
      })
      await app.waitForCertificate(domain, 'active', timeout)

      const response = await app.page.goto(`https://${domain}/`, {
        waitUntil: 'domcontentloaded',
      })
      expect(response?.status()).toBeGreaterThanOrEqual(500)
      const protocol = await app.page.evaluate(() => {
        const entry = performance.getEntriesByType('navigation')[0] as
          | PerformanceNavigationTiming
          | undefined
        return entry?.nextHopProtocol ?? ''
      })
      expect(protocol.toLowerCase()).toContain('h2')

      const certificate = execFileSync(
        'openssl',
        ['s_client', '-connect', `${new URL(app.page.url()).hostname}:443`, '-servername', domain, '-showcerts'],
        { input: '', encoding: 'utf8', timeout: 20_000 },
      )
      expect(certificate).toContain('BEGIN CERTIFICATE')
      expect(certificate.toUpperCase()).toContain('STAGING')
    } finally {
      await app.deleteSiteIfPresent(domain)
    }
  })
})
