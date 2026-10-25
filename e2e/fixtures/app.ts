import { test as base, expect, type Page } from '@playwright/test'
import { requiredEnv } from '../support/env'

export type App = {
  page: Page
  adminUrl(path: string): string
  createSite(input: {
    name: string
    domain: string
    upstream: string
    alternateDomains?: string[]
    upstreamTls?: boolean
  }): Promise<string>
  waitForSite(domain: string, timeout?: number): Promise<void>
  deleteSite(domain: string): Promise<void>
  deleteSiteIfPresent(domain: string): Promise<void>
  deleteCertificatesFor(domain: string): Promise<void>
  addRoute(input: {
    name: string
    path: string
    match?: 'prefix' | 'exact' | 'regex'
    rewritePath?: string
    stripPrefix?: boolean
    upstreamHost?: string
  }): Promise<void>
  addNode(address: string): Promise<void>
  requestCertificate(input: {
    domain: string
    email: string
    challenge?: 'http-01' | 'dns-01'
  }): Promise<void>
  waitForCertificate(domain: string, status: string, timeout?: number): Promise<void>
}

function adminPath(path: string) {
  return new URL(path, requiredEnv('E2E_BASE_URL')).toString()
}

async function login(page: Page) {
  const email = process.env.E2E_ADMIN_EMAIL ?? 'admin@pingwaf.local'
  const password = process.env.E2E_ADMIN_PASSWORD
  if (!password) throw new Error('E2E_ADMIN_PASSWORD is required')
  await page.goto('/login')
  await page.getByRole('textbox', { name: /Email/ }).fill(email)
  await page.getByRole('textbox', { name: /Password/ }).fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 })
}

async function createSite(
  page: Page,
  input: {
    name: string
    domain: string
    upstream: string
    alternateDomains?: string[]
    upstreamTls?: boolean
  },
) {
  await page.goto(adminPath('/sites'))
  await page.getByRole('button', { name: 'Add site' }).click()
  const dialog = page.getByRole('dialog', { name: 'Add site' })
  await dialog.getByRole('textbox', { name: /Name/ }).fill(input.name)
  await dialog.getByRole('textbox', { name: /Domain/ }).fill(input.domain)
  for (const domain of input.alternateDomains ?? []) {
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await dialog
      .getByRole('textbox', { name: 'Additional domains' })
      .last()
      .fill(domain)
  }
  await dialog
    .getByRole('textbox', { name: /Origin address/ })
    .fill(input.upstream)
  if (input.upstreamTls) {
    await dialog.getByRole('switch', { name: /HTTPS to origin/ }).check()
  }
  await dialog.getByRole('button', { name: 'Create', exact: true }).click()
  await expect(page).toHaveURL(/\/sites\/([0-9a-f-]{36})\/basic/, { timeout: 90_000 })
  const match = page.url().match(/\/sites\/([0-9a-f-]{36})\/basic/)
  if (!match) throw new Error(`site id missing from ${page.url()}`)
  return match[1]
}

async function waitForSite(page: Page, domain: string, timeout = 30_000) {
  await expect
    .poll(
      async () => {
        const response = await page.goto(`http://${domain}/?e2e-ready=1`, {
          waitUntil: 'domcontentloaded',
        })
        return response?.status() ?? 0
      },
      { timeout, intervals: [1_000, 2_000, 5_000] },
    )
    .toBe(200)
}

async function deleteSite(page: Page, domain: string) {
  await page.goto(adminPath('/sites'))
  const search = page.getByRole('textbox', { name: 'Search' })
  if (await search.count()) await search.fill(domain)
  const row = page.getByRole('row').filter({ hasText: domain })
  await row.getByRole('button', { name: 'Delete' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('button', { name: /Delete/ }).last().click()
  await expect(row).toHaveCount(0, { timeout: 30_000 })
}

async function deleteSiteIfPresent(page: Page, domain: string) {
  await page.goto(adminPath('/sites'))
  const search = page.getByRole('textbox', { name: 'Search' })
  if (await search.count()) await search.fill(domain)
  const row = page.getByRole('row').filter({ hasText: domain })
  if ((await row.count()) === 0) return
  await row.getByRole('button', { name: 'Delete' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('button', { name: /Delete/ }).last().click()
  await expect(row).toHaveCount(0, { timeout: 30_000 })
}

async function deleteCertificatesFor(page: Page, domain: string) {
  await page.goto(adminPath('/ssl'))
  for (;;) {
    const row = page.getByRole('row').filter({ hasText: domain })
    if ((await row.count()) === 0) return
    await row.first().getByRole('button', { name: 'Delete' }).click()
    const dialog = page.getByRole('dialog')
    await dialog.getByRole('button', { name: /Delete/ }).last().click()
    await expect(row).toHaveCount(0, { timeout: 30_000 })
  }
}

async function addRoute(
  page: Page,
  input: {
    name: string
    path: string
    match?: 'prefix' | 'exact' | 'regex'
    rewritePath?: string
    stripPrefix?: boolean
    upstreamHost?: string
  },
) {
  await page.getByRole('button', { name: 'Add route' }).first().click()
  const dialog = page.getByRole('dialog', { name: 'Add route' })
  await dialog.getByRole('textbox', { name: /Rule name/ }).fill(input.name)
  if (input.match) {
    await dialog.getByRole('combobox', { name: 'Match' }).selectOption(input.match)
  }
  await dialog.getByRole('textbox', { name: /Path/ }).fill(input.path)
  if (input.rewritePath) {
    if ((input.match ?? 'prefix') !== 'prefix') {
      throw new Error('rewritePath is only available for prefix routes')
    }
    await dialog.getByRole('textbox', { name: 'Rewrite path' }).fill(input.rewritePath)
  }
  if (input.stripPrefix) {
    await dialog.getByRole('switch', { name: /Strip prefix/ }).check()
  }
  if (input.upstreamHost) {
    await dialog.getByRole('textbox', { name: 'Upstream Host override' }).fill(input.upstreamHost)
  }
  await dialog.getByRole('button', { name: 'Create', exact: true }).click()
  await expect(dialog).toHaveCount(0, { timeout: 30_000 })
}

async function addNode(page: Page, address: string) {
  await page.getByRole('button', { name: 'Add node' }).first().click()
  const dialog = page.getByRole('dialog', { name: 'Add node' })
  await dialog.getByRole('textbox', { name: /address/i }).fill(address)
  await dialog.getByRole('button', { name: 'Create', exact: true }).click()
  await expect(dialog).toHaveCount(0, { timeout: 30_000 })
}

async function requestCertificate(
  page: Page,
  input: { domain: string; email: string; challenge?: 'http-01' | 'dns-01' },
) {
  await page.goto(adminPath('/ssl'))
  await page.getByRole('button', { name: 'Apply or upload' }).click()
  const dialog = page.getByRole('dialog', {
    name: 'Apply for or upload a certificate',
  })
  const site = dialog.getByRole('combobox', { name: 'Site' })
  const value = await site
    .locator('option')
    .filter({ hasText: input.domain })
    .first()
    .getAttribute('value')
  if (!value) throw new Error(`site option not found for ${input.domain}`)
  await site.selectOption(value)
  await dialog.getByRole('textbox', { name: 'ACME email' }).fill(input.email)
  if (input.challenge && input.challenge !== 'http-01') {
    await dialog
      .getByRole('combobox', { name: 'Challenge type' })
      .selectOption(input.challenge)
  }
  await dialog.getByRole('button', { name: 'Submit application' }).click()
  await expect(dialog).toHaveCount(0, { timeout: 30_000 })
}

async function waitForCertificate(page: Page, domain: string, status: string, timeout = 900_000) {
  await page.goto(adminPath('/ssl'))
  const row = page
    .getByRole('row')
    .filter({ hasText: domain })
    .filter({ hasText: new RegExp(status, 'i') })
  await expect(row.first()).toBeVisible({ timeout })
}

export const test = base.extend<{ app: App }>({
  app: async ({ page }, use) => {
    await page.addInitScript(() => localStorage.setItem('i18nextLng', 'en'))
    await login(page)
    await use({
      page,
      adminUrl: (path) => new URL(path, requiredEnv('E2E_BASE_URL')).toString(),
      createSite: (input) => createSite(page, input),
      waitForSite: (domain, timeout) => waitForSite(page, domain, timeout),
      deleteSite: (domain) => deleteSite(page, domain),
      deleteSiteIfPresent: (domain) => deleteSiteIfPresent(page, domain),
      deleteCertificatesFor: (domain) => deleteCertificatesFor(page, domain),
      addRoute: (input) => addRoute(page, input),
      addNode: (address) => addNode(page, address),
      requestCertificate: (input) => requestCertificate(page, input),
      waitForCertificate: (domain, status, timeout) => waitForCertificate(page, domain, status, timeout),
    })
  },
})

export { expect }
