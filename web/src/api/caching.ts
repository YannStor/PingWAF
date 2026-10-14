import { apiClient } from './client'
import type {
  CacheRule,
  CacheSettings,
  CacheStatus,
  CreateCacheRuleRequest,
  Page,
  PaginationQuery,
  PurgeCacheRequest,
  PurgeCacheResult,
  UpdateCacheRuleRequest,
  UpdateCacheSettingsRequest,
} from './types'

/** `POST /sites/{site_id}/cache/defaults` ack. */
export interface SeedCacheDefaultsResult {
  inserted: number
  total: number
}

/**
 * Caching — site rules, the site-wide disk budget, usage and purging.
 *
 * Rules decide *what* the edge stores; the disk budget is a property of the
 * **site**, not of any single rule, so it lives on the site (`/cache-settings`)
 * and every hostname of the site shares it.
 */
export const cachingApi = {
  listRules: (siteId: string, query: PaginationQuery = {}) =>
    apiClient.get<Page<CacheRule>>(`/sites/${siteId}/cache-rules`, {
      query: { page_size: 200, ...query },
    }),

  createRule: (siteId: string, data: CreateCacheRuleRequest) =>
    apiClient.post<CacheRule>(`/sites/${siteId}/cache-rules`, data),

  updateRule: (siteId: string, id: string, data: UpdateCacheRuleRequest) =>
    apiClient.put<CacheRule>(`/sites/${siteId}/cache-rules/${id}`, data),

  deleteRule: (siteId: string, id: string) =>
    apiClient.delete<void>(`/sites/${siteId}/cache-rules/${id}`),

  toggleEnabled: (siteId: string, id: string, enabled: boolean) =>
    apiClient.put<CacheRule>(`/sites/${siteId}/cache-rules/${id}`, { enabled }),

  /** Re-adds missing built-in rules; edited ones are left untouched. */
  restoreDefaults: (siteId: string) =>
    apiClient.post<SeedCacheDefaultsResult>(`/sites/${siteId}/cache/defaults`),

  /* ── Disk budget (site-wide) ─────────────────────────────────────── */
  getSettings: (siteId: string) =>
    apiClient.get<CacheSettings>(`/sites/${siteId}/cache-settings`),

  updateSettings: (siteId: string, data: UpdateCacheSettingsRequest) =>
    apiClient.put<CacheSettings>(`/sites/${siteId}/cache-settings`, data),

  /* ── Usage ───────────────────────────────────────────────────────── */
  status: (siteId: string) => apiClient.get<CacheStatus>(`/cache/status/${siteId}`),

  purge: (data: PurgeCacheRequest) =>
    apiClient.post<PurgeCacheResult>('/cache/purge', data),
}

export const cacheKeys = {
  all: ['cache'] as const,
  site: (siteId: string) => [...cacheKeys.all, 'site', siteId] as const,
  rules: (siteId: string, query?: PaginationQuery) =>
    [...cacheKeys.site(siteId), 'rules', query ?? {}] as const,
  settings: (siteId: string) => [...cacheKeys.site(siteId), 'settings'] as const,
  status: (siteId: string) => [...cacheKeys.site(siteId), 'status'] as const,
}

export default cachingApi
