import { apiClient } from './client'

/** One recorded configuration version (snapshot excluded). */
export interface ConfigVersionSummary {
  id: number
  scope: 'site' | 'global' | 'deployment'
  site_id: string | null
  site_domain: string | null
  config_hash: string
  source: 'api' | 'cli' | 'rollback' | 'restore' | 'pre-rollback' | string
  actor: string | null
  /** Per-table row counts captured with the version. */
  summary: Record<string, number> | null
  created_at: string
}

/** A full version, including the restorable snapshot document. */
export interface ConfigVersionDetail extends ConfigVersionSummary {
  snapshot: {
    schema: number
    scope?: 'site' | 'global' | 'deployment'
    site_id?: string | null
    site?: Record<string, unknown> | null
    tables: Record<
      string,
      Record<string, unknown>[] | Record<string, unknown> | null
    >
  }
}

export interface PruneResult {
  deleted: number
  cutoff: string
}

/** What a rollback produced. */
export interface RollbackResult {
  restored_version: number
  new_version: number | null
  scope: string
}

export const configVersionKeys = {
  all: ['config-versions'] as const,
  list: (siteId?: string) =>
    [...configVersionKeys.all, 'list', siteId ?? 'all'] as const,
  detail: (id: number) => [...configVersionKeys.all, 'detail', id] as const,
}

export const configVersionsApi = {
  list: (siteId?: string, limit = 100, offset = 0) => {
    const params = new URLSearchParams()
    params.set('limit', String(limit))
    params.set('offset', String(offset))
    if (siteId) params.set('site_id', siteId)
    return apiClient.get<ConfigVersionSummary[]>(
      `/config-versions?${params.toString()}`,
    )
  },

  get: (id: number) =>
    apiClient.get<ConfigVersionDetail>(`/config-versions/${id}`),

  rollback: (id: number) =>
    apiClient.post<RollbackResult>(`/config-versions/${id}/rollback`, {}),

  prune: () => apiClient.post<PruneResult>('/config-versions/prune', {}),
}

export default configVersionsApi
