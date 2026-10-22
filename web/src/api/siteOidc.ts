import { apiClient } from './client'
import type {
  CreateOidcProviderRequest,
  OidcProvider,
  SiteOidc,
  UpdateOidcProviderRequest,
  UpdateOidcRequest,
} from './types'
import {
  OIDC_DEFAULT_COOKIE_NAME,
  OIDC_DEFAULT_REDIRECT_PATH,
  OIDC_DEFAULT_SESSION_TTL_SECONDS,
} from './types'

/**
 * Identity providers — `/api/v1/oidc/providers`.
 *
 * Provider credentials belong to the deployment rather than to a site, so they
 * are managed once here (the Account page) and referenced from each site's
 * gate. `client_secret` is masked with `***` in responses: send the mask back
 * to keep the stored secret, an empty string to clear it.
 */
export const oidcProviderApi = {
  list: () => apiClient.get<OidcProvider[]>('/oidc/providers'),

  get: (providerId: string) =>
    apiClient.get<OidcProvider>(`/oidc/providers/${providerId}`),

  create: (data: CreateOidcProviderRequest) =>
    apiClient.post<OidcProvider>('/oidc/providers', data),

  update: (providerId: string, data: UpdateOidcProviderRequest) =>
    apiClient.put<OidcProvider>(`/oidc/providers/${providerId}`, data),

  /**
   * Refused with a `409` while sites still point at the provider, so the
   * caller can say which ones rather than leaving them silently unconfigured.
   */
  remove: (providerId: string) =>
    apiClient.delete<{ deleted: boolean }>(`/oidc/providers/${providerId}`),
}

export const oidcProviderKeys = {
  all: ['oidc-providers'] as const,
  detail: (providerId: string) =>
    [...oidcProviderKeys.all, providerId] as const,
}

/**
 * Per-site OpenID Connect sign-in — `/api/v1/sites/{siteId}/oidc`.
 *
 * The site holds a provider reference plus its own callback paths, session
 * settings and access rules; the provider's credentials are not here.
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

/** The shape the server describes for a site that never saved OIDC settings. */
export function defaultSiteOidc(siteId: string): SiteOidc {
  const now = new Date().toISOString()
  return {
    id: '',
    site_id: siteId,
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
    access_mode: 'allow_all',
    access_rules: [],
    created_at: now,
    updated_at: now,
  }
}

export default siteOidcApi