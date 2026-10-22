import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it, vi } from 'vitest'

vi.hoisted(() => {
  const ls = globalThis.localStorage as unknown
  if (typeof ls !== 'object' || ls === null || typeof (ls as { getItem?: unknown }).getItem !== 'function') {
    ;(globalThis as Record<string, unknown>).localStorage = {
      getItem: () => null,
      setItem: () => undefined,
      removeItem: () => undefined,
    }
  }
})
import {
  OIDC_DEFAULT_COOKIE_NAME,
  OIDC_DEFAULT_REDIRECT_PATH,
  OIDC_DEFAULT_SESSION_TTL_SECONDS,
  OIDC_MAX_SESSION_TTL_SECONDS,
  OIDC_MIN_COOKIE_SECRET_LENGTH,
  OIDC_MIN_SESSION_TTL_SECONDS,
  OIDC_SECRET_MASK,
} from '@/api/types'
import { defaultSiteOidc, siteOidcApi, siteOidcKeys } from '@/api/siteOidc'

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

/** 站点级 OIDC：REST 路径与掩码语义契约。 */
describe('site OIDC API contract', () => {
  it('siteOidcApi hits /sites/{siteId}/oidc for GET and PUT', () => {
    const src = read('src/api/siteOidc.ts')
    expect(src).toContain('apiClient.get<SiteOidc>(`/sites/${siteId}/oidc`)')
    expect(src).toContain('apiClient.put<SiteOidc>(`/sites/${siteId}/oidc`, data)')
  })

  it('exposes the query keys and the frozen secret mask', () => {
    expect(siteOidcKeys.all).toEqual(['site-oidc'])
    expect(siteOidcKeys.detail('s1')).toEqual(['site-oidc', 's1'])
    expect(siteOidcApi.get).toBeTypeOf('function')
    expect(siteOidcApi.update).toBeTypeOf('function')
    expect(OIDC_SECRET_MASK).toBe('***')
  })

  it('defaultSiteOidc matches the server default row', () => {
    const { created_at, updated_at, ...rest } = defaultSiteOidc('site-1')
    expect(rest).toEqual({
      id: '',
      site_id: 'site-1',
      enabled: false,
      issuer: '',
      client_id: '',
      client_secret: '',
      cookie_secret: '',
      redirect_path: OIDC_DEFAULT_REDIRECT_PATH,
      logout_path: '',
      redirect_url: '',
      scopes: ['openid'],
      cookie_name: OIDC_DEFAULT_COOKIE_NAME,
      session_ttl_seconds: OIDC_DEFAULT_SESSION_TTL_SECONDS,
      claims_to_headers: [],
    })
    expect(created_at).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(updated_at).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  it('carries the frozen defaults and bounds', () => {
    expect(OIDC_DEFAULT_REDIRECT_PATH).toBe('/oauth2/callback')
    expect(OIDC_DEFAULT_COOKIE_NAME).toBe('pingap_oidc')
    expect(OIDC_DEFAULT_SESSION_TTL_SECONDS).toBe(43200)
    expect(OIDC_MIN_SESSION_TTL_SECONDS).toBe(60)
    expect(OIDC_MAX_SESSION_TTL_SECONDS).toBe(31536000)
    expect(OIDC_MIN_COOKIE_SECRET_LENGTH).toBe(16)
  })
})

/** 面板交互契约：保存调用、镜像守卫、未保存提醒。 */
describe('OidcPanel contract', () => {
  const src = read('src/pages/sites/OidcPanel.tsx')

  it('saves through siteOidcApi.update and invalidates the oidc queries', () => {
    expect(src).toContain('siteOidcApi.update(siteId')
    expect(src).toContain('siteOidcKeys.detail(siteId)')
    expect(src).toContain('queryKey: siteOidcKeys.all')
  })

  it('guards with blockedReason and useUnsavedGuard', () => {
    expect(src).toContain('blockedReason')
    expect(src).toContain('useUnsavedGuard(dirty)')
  })

  it('respects the mask semantics: stored secrets send the mask, new values update', () => {
    expect(src).toContain('OIDC_SECRET_MASK')
  })

  it('can drop a stored secret: an emptied field sends "" instead of the mask', () => {
    // Without this a confidential client could never become a public one,
    // and a cookie_secret could never be replaced by leaving the field blank.
    expect(src).toContain('cleared')
    expect(src).toContain('state.cleared')
    // Clearing the cookie secret must block the save, since the API rejects
    // an enabled row without one.
    expect(src).toContain('cookieSecret.cleared')
  })
})

/** i18n 契约：三语 locale 必须带齐全部 pages.oidc.* 与 tabOidc key。 */
describe('site OIDC locale contract', () => {
  const KEYS = [
    'saved', 'provider', 'providerHint', 'issuer', 'issuerHint', 'clientId',
    'clientSecret', 'clientSecretHint', 'cookieSecret', 'cookieSecretHint',
    'cookieSecretRequired', 'storedSecret', 'endpoints', 'endpointsHint',
    'redirectPath', 'logoutPath', 'logoutPathHint', 'redirectUrl',
    'redirectUrlHint', 'scopes', 'scopesHint', 'addScope', 'cookieName',
    'cookieNameHint', 'sessionTtl', 'sessionTtlHint', 'claims', 'claimsHint',
    'addClaim', 'claim', 'header', 'removeClaim', 'enabled', 'enabledHint',
    'clientIdRequired', 'issuerRequired', 'secretRequired',
    'cookieSecretTooShort', 'notes', 'noteOrder', 'notePkce', 'noteExempt',
  ]

  it('every language carries all pages.oidc keys and the tab label', () => {
    for (const lang of ['en', 'zh', 'ja']) {
      const parsed = JSON.parse(read(`src/i18n/locales/${lang}/common.json`)) as {
        pages: { accessControl: Record<string, string>; oidc: Record<string, string> }
      }
      expect(parsed.pages.accessControl.tabOidc, `${lang}.tabOidc`).toBeTruthy()
      for (const key of KEYS) {
        expect(parsed.pages.oidc[key], `${lang}.pages.oidc.${key}`).toBeTruthy()
      }
    }
  })
})
