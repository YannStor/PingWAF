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
  OIDC_ACCESS_MODES,
  OIDC_ACCESS_OPERATORS,
  OIDC_ALWAYS_SCOPE,
  OIDC_DEFAULT_COOKIE_NAME,
  OIDC_DEFAULT_REDIRECT_PATH,
  OIDC_DEFAULT_SESSION_TTL_SECONDS,
  OIDC_MAX_SESSION_TTL_SECONDS,
  OIDC_MIN_COOKIE_SECRET_LENGTH,
  OIDC_MIN_SESSION_TTL_SECONDS,
  OIDC_SECRET_MASK,
} from '@/api/types'
import {
  defaultSiteOidc,
  oidcProviderApi,
  oidcProviderKeys,
  siteOidcApi,
  siteOidcKeys,
} from '@/api/siteOidc'

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

/** 身份源（部署级）：REST 路径与掩码语义契约。 */
describe('OIDC provider API contract', () => {
  const src = read('src/api/siteOidc.ts')

  it('hits /oidc/providers for list/create and /oidc/providers/{id} for the rest', () => {
    expect(src).toContain("apiClient.get<OidcProvider[]>('/oidc/providers')")
    expect(src).toContain("apiClient.post<OidcProvider>('/oidc/providers', data)")
    expect(src).toContain('apiClient.get<OidcProvider>(`/oidc/providers/${providerId}`)')
    expect(src).toContain(
      'apiClient.put<OidcProvider>(`/oidc/providers/${providerId}`, data)',
    )
    expect(src).toContain(
      'apiClient.delete<{ deleted: boolean }>(`/oidc/providers/${providerId}`)',
    )
  })

  it('exposes the query keys the account page and the site picker share', () => {
    expect(oidcProviderKeys.all).toEqual(['oidc-providers'])
    expect(oidcProviderKeys.detail('p1')).toEqual(['oidc-providers', 'p1'])
    expect(oidcProviderApi.list).toBeTypeOf('function')
    expect(oidcProviderApi.remove).toBeTypeOf('function')
  })

  /**
   * Provider credentials belong to the deployment, so the site's own type must
   * not carry them: a site references one by id and holds only what differs
   * per site. A regression here would put a client secret back on every site.
   */
  it('a site references a provider instead of holding its credentials', () => {
    const types = read('src/api/types.ts')
    const site = types.slice(
      types.indexOf('export interface SiteOidc'),
      types.indexOf('export type UpdateOidcRequest'),
    )
    for (const gone of ['issuer', 'client_id', 'client_secret', 'scopes']) {
      expect(site, `SiteOidc must not carry ${gone}`).not.toMatch(
        new RegExp(`^\\s*${gone}[?:]`, 'm'),
      )
    }
    expect(site).toContain('provider_id: string | null')
    expect(site).toContain('access_mode: OidcAccessMode')
    expect(site).toContain('access_rules: OidcAccessRule[]')
  })

  /**
   * Omitting `provider_id` keeps the stored provider; `null` clears it. The
   * two are different requests and the API reads them apart.
   */
  it('the update payload can clear the provider but not by omission', () => {
    const types = read('src/api/types.ts')
    expect(types).toContain('provider_id?: string | null')
  })
})

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
      provider_id: null,
      provider_name: null,
      cookie_secret: '',
      redirect_path: OIDC_DEFAULT_REDIRECT_PATH,
      logout_path: '',
      redirect_url: '',
      cookie_name: OIDC_DEFAULT_COOKIE_NAME,
      session_ttl_seconds: OIDC_DEFAULT_SESSION_TTL_SECONDS,
      claims_to_headers: [],
      // The default admits every signed-in user, which is what the gate did
      // before access rules existed.
      access_mode: 'allow_all',
      access_rules: [],
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

  /** The two enums the API validates against; a drift here is a 400. */
  it('mirrors the control plane access enums', () => {
    expect(OIDC_ACCESS_MODES).toEqual(['allow_all', 'require_any', 'require_all'])
    expect(OIDC_ACCESS_OPERATORS).toEqual(['eq', 'ne', 'contains', 'in', 'exists'])
    expect(OIDC_ALWAYS_SCOPE).toBe('openid')
  })
})

/** 面板交互契约：保存调用、镜像守卫、未保存提醒、访问规则清理。 */
describe('OidcPanel contract', () => {
  const src = read('src/pages/sites/OidcPanel.tsx')

  it('saves through siteOidcApi.update and invalidates the oidc queries', () => {
    expect(src).toContain('siteOidcApi.update(siteId')
    expect(src).toContain('siteOidcKeys.detail(siteId)')
    expect(src).toContain('queryKey: siteOidcKeys.all')
  })

  it('reads the providers from the account page rather than duplicating them', () => {
    expect(src).toContain('oidcProviderApi.list')
    expect(src).toContain('queryKey: oidcProviderKeys.all')
    // The picker offers no credentials: those are not the site's to set.
    expect(src).not.toContain('pages.oidc.issuer')
    expect(src).not.toContain('pages.oidc.clientSecret')
  })

  it('guards with blockedReason and useUnsavedGuard', () => {
    expect(src).toContain('blockedReason')
    expect(src).toContain('useUnsavedGuard(dirty)')
  })

  it('requires a provider while the gate is on', () => {
    expect(src).toContain('provider_id === null')
    expect(src).toContain('pages.oidc.providerRequired')
  })

  it('respects the mask semantics: stored secrets send the mask, new values update', () => {
    expect(src).toContain('OIDC_SECRET_MASK')
  })

  it('can drop a stored secret: an emptied field sends "" instead of the mask', () => {
    // Without this a cookie_secret could never be replaced by leaving the
    // field blank.
    expect(src).toContain('cleared')
    expect(src).toContain('state.cleared')
    expect(src).toContain('cookieSecret.cleared')
  })

  /**
   * An enforcing mode with no usable rule denies everyone, the operator
   * included; the panel must block the save rather than let the API answer
   * with a 400 the user cannot act on.
   */
  it('blocks an enforcing mode with no usable rule', () => {
    expect(src).toContain('accessRulesRequired')
    expect(src).toContain("access_mode !== 'allow_all'")
  })

  /** Half-filled rows are dropped rather than sent, since the API rejects them. */
  it('drops half-filled access rules instead of sending them', () => {
    expect(src).toContain('cleanedRules')
    expect(src).toContain("rule.operator === 'exists'")
  })
})

/** i18n 契约：三语 locale 必须带齐面板与账户页的全部 key。 */
describe('site OIDC locale contract', () => {
  const OIDC_KEYS = [
    'saved', 'provider', 'providerPickerHint', 'providerNone',
    'providerRequired', 'cookieSecret', 'cookieSecretHint',
    'cookieSecretRequired', 'storedSecret', 'endpoints', 'endpointsHint',
    'redirectPath', 'logoutPath', 'logoutPathHint', 'redirectUrl',
    'redirectUrlHint', 'cookieName', 'cookieNameHint', 'sessionTtl',
    'sessionTtlHint', 'claims', 'claimsHint', 'addClaim', 'claim', 'header',
    'removeClaim', 'enabled', 'enabledHint', 'secretRequired',
    'cookieSecretTooShort', 'notes', 'noteOrder', 'notePkce', 'noteExempt',
    'access', 'accessHint', 'accessMode', 'addRule', 'ruleClaim',
    'ruleOperator', 'ruleValue', 'accessRulesRequired',
  ]

  const ACCOUNT_KEYS = [
    'oidcProviders', 'oidcProvidersHint', 'oidcProviderAdd',
    'oidcProviderEdit', 'oidcProviderName', 'oidcProviderNameHint',
    'oidcProviderIssuer', 'oidcProviderIssuerHint', 'oidcProviderClientId',
    'oidcProviderClientSecret', 'oidcProviderSecretHint',
    'oidcProviderSecretStored', 'oidcProviderScopes',
    'oidcProviderScopesHint', 'oidcProviderEnabled',
    'oidcProviderEnabledHint', 'oidcProviderDisabled',
    'oidcProviderSiteCount', 'oidcProvidersEmpty', 'oidcProvidersEmptyHint',
    'oidcProviderCreated', 'oidcProviderSaved', 'oidcProviderDeleted',
    'oidcProviderDeleteTitle', 'oidcProviderDeleteMessage',
    'oidcProviderNameRequired', 'oidcProviderIssuerRequired',
    'oidcProviderClientIdRequired',
  ]

  it('every language carries all pages.oidc keys and the tab label', () => {
    for (const lang of ['en', 'zh', 'ja']) {
      const parsed = JSON.parse(read(`src/i18n/locales/${lang}/common.json`)) as {
        pages: {
          accessControl: Record<string, string>
          oidc: Record<string, string>
          account: Record<string, string>
        }
      }
      expect(parsed.pages.accessControl.tabOidc, `${lang}.tabOidc`).toBeTruthy()
      for (const key of OIDC_KEYS) {
        expect(parsed.pages.oidc[key], `${lang}.pages.oidc.${key}`).toBeTruthy()
      }
      for (const key of ACCOUNT_KEYS) {
        expect(parsed.pages.account[key], `${lang}.pages.account.${key}`).toBeTruthy()
      }
      // Every mode and operator the picker offers has a label, or the select
      // renders a raw key.
      for (const mode of OIDC_ACCESS_MODES) {
        expect(parsed.pages.oidc[`accessMode_${mode}`], `${lang}.accessMode_${mode}`).toBeTruthy()
        expect(
          parsed.pages.oidc[`accessModeHint_${mode}`],
          `${lang}.accessModeHint_${mode}`,
        ).toBeTruthy()
      }
      for (const operator of OIDC_ACCESS_OPERATORS) {
        expect(parsed.pages.oidc[`operator_${operator}`], `${lang}.operator_${operator}`).toBeTruthy()
      }
    }
  })

  /**
   * Every key the panel and the account card ask for must exist, or the UI
   * renders the key itself. This is the check that caught `providerHint`
   * being removed as an "orphan" while a card still read it.
   */
  it('every key the two components ask for is defined in all three locales', () => {
    const sources = [
      read('src/pages/sites/OidcPanel.tsx'),
      read('src/components/account/OidcProvidersCard.tsx'),
    ].join('\n')
    const asked = new Set<string>()
    for (const match of sources.matchAll(/t\('(pages\.(?:oidc|account)\.[A-Za-z_]+)'\)/g)) {
      asked.add(match[1]!)
    }
    // The dynamic keys: built from the enums rather than written literally.
    for (const mode of OIDC_ACCESS_MODES) {
      asked.add(`pages.oidc.accessMode_${mode}`)
      asked.add(`pages.oidc.accessModeHint_${mode}`)
    }
    for (const operator of OIDC_ACCESS_OPERATORS) {
      asked.add(`pages.oidc.operator_${operator}`)
    }
    expect(asked.size).toBeGreaterThan(40)

    for (const lang of ['en', 'zh', 'ja']) {
      const parsed = JSON.parse(read(`src/i18n/locales/${lang}/common.json`)) as {
        pages: { oidc: Record<string, string>; account: Record<string, string> }
      }
      for (const key of asked) {
        const [, section, name] = key.split('.') as [string, 'oidc' | 'account', string]
        expect(parsed.pages[section][name], `${lang}:${key}`).toBeTruthy()
      }
    }
  })

  /** The provider's fields left the site panel; their keys must not linger. */
  it('the site panel keeps no keys for credentials it no longer sets', () => {
    for (const lang of ['en', 'zh', 'ja']) {
      const parsed = JSON.parse(read(`src/i18n/locales/${lang}/common.json`)) as {
        pages: { oidc: Record<string, unknown> }
      }
      for (const gone of ['issuer', 'clientId', 'clientSecret', 'scopes', 'addScope']) {
        expect(parsed.pages.oidc[gone], `${lang}.pages.oidc.${gone}`).toBeUndefined()
      }
    }
  })
})