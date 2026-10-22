import { apiClient } from './client'
import type { SiteOidc, UpdateOidcRequest } from './types'
import {
  OIDC_DEFAULT_COOKIE_NAME,
  OIDC_DEFAULT_REDIRECT_PATH,
  OIDC_DEFAULT_SESSION_TTL_SECONDS,
} from './types'

/**
 * Per-site OpenID Connect sign-in — `/api/v1/sites/{siteId}/oidc`.
 *
 * Secrets are masked with `***` in responses: send the mask back to keep a
 * stored secret unchanged, an empty string to clear it.
 */
export const siteOidcApi = {
  get: (siteId: string) => apiClient.get<SiteOidc>(`/sites/${siteId}/oidc`),

  update: (siteId: string, data: UpdateOidcRequest) =>
    apiClient.put<SiteOidc>(`/sites/${siteId}/oidc`, data),
}

export const siteOidcKeys = {
  all: ['site-oidc'] as const,
  detail: (siteId: string) => [...siteOidcKeys.all, siteId] as const,
}

/** The shape the server creates for a site that never saved OIDC settings. */
export function defaultSiteOidc(siteId: string): SiteOidc {
  const now = new Date().toISOString()
  return {
    id: '',
    site_id: siteId,
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
    created_at: now,
    updated_at: now,
  }
}

export default siteOidcApi
