import { apiClient } from './client'
import type {
  CreatePoolRequest,
  CreateRouteRequest,
  CreateSiteRequest,
  CloneSiteRequest,
  CreateUpstreamRequest,
  Page,
  Route,
  Site,
  SiteDetail,
  SiteListQuery,
  SslConfig,
  UpdatePoolRequest,
  UpdateRouteRequest,
  UpdateSiteRequest,
  UpdateUpstreamRequest,
  Upstream,
  UpstreamPool,
  UpsertSslRequest,
} from './types'

/**
 * Sites CRUD — `/api/v1/sites`.
 *
 * `GET /sites` is paginated (`Page<Site>`); administrators see every site while
 * other roles only see their own. A site the caller may not see answers `404`
 * rather than `403` so existence is never leaked.
 */
export const sitesApi = {
  list: (query: SiteListQuery = {}) =>
    apiClient.get<Page<Site>>('/sites', { query: { page_size: 200, ...query } }),

  get: (id: string) => apiClient.get<SiteDetail>(`/sites/${id}`),

  create: (data: CreateSiteRequest) => apiClient.post<Site>('/sites', data),

  update: (id: string, data: UpdateSiteRequest) =>
    apiClient.put<Site>(`/sites/${id}`, data),

  delete: (id: string) => apiClient.delete<void>(`/sites/${id}`),

  /**
   * Clone a site's configuration (rules, pools, routes, cache, WAF) under a
   * new primary domain. Answers `201` with the created site (same shape as
   * `POST /sites`).
   */
  cloneSite: (id: string, data: CloneSiteRequest) =>
    apiClient.post<Site>(`/sites/${id}/clone`, data),

  /* ── Origin nodes ────────────────────────────────────────────────── */
  listUpstreams: (siteId: string) =>
    apiClient.get<Upstream[]>(`/sites/${siteId}/upstreams`),

  createUpstream: (siteId: string, data: CreateUpstreamRequest) =>
    apiClient.post<Upstream>(`/sites/${siteId}/upstreams`, data),

  updateUpstream: (siteId: string, upstreamId: string, data: UpdateUpstreamRequest) =>
    apiClient.put<Upstream>(`/sites/${siteId}/upstreams/${upstreamId}`, data),

  deleteUpstream: (siteId: string, upstreamId: string) =>
    apiClient.delete<void>(`/sites/${siteId}/upstreams/${upstreamId}`),

  /* ── Origin pools ────────────────────────────────────────────────── */
  listPools: (siteId: string) =>
    apiClient.get<UpstreamPool[]>(`/sites/${siteId}/upstream-pools`),

  createPool: (siteId: string, data: CreatePoolRequest) =>
    apiClient.post<UpstreamPool>(`/sites/${siteId}/upstream-pools`, data),

  updatePool: (siteId: string, poolId: string, data: UpdatePoolRequest) =>
    apiClient.put<UpstreamPool>(`/sites/${siteId}/upstream-pools/${poolId}`, data),

  deletePool: (siteId: string, poolId: string) =>
    apiClient.delete<void>(`/sites/${siteId}/upstream-pools/${poolId}`),

  /* ── Routes ──────────────────────────────────────────────────────── */
  listRoutes: (siteId: string) => apiClient.get<Route[]>(`/sites/${siteId}/routes`),

  createRoute: (siteId: string, data: CreateRouteRequest) =>
    apiClient.post<Route>(`/sites/${siteId}/routes`, data),

  updateRoute: (siteId: string, routeId: string, data: UpdateRouteRequest) =>
    apiClient.put<Route>(`/sites/${siteId}/routes/${routeId}`, data),

  deleteRoute: (siteId: string, routeId: string) =>
    apiClient.delete<void>(`/sites/${siteId}/routes/${routeId}`),

  /* ── TLS material ────────────────────────────────────────────────── */
  getSsl: (siteId: string) => apiClient.get<SslConfig | null>(`/sites/${siteId}/ssl`),

  upsertSsl: (siteId: string, data: UpsertSslRequest) =>
    apiClient.put<SslConfig>(`/sites/${siteId}/ssl`, data),
}

/** Query keys shared by every site consumer. */
export const siteKeys = {
  all: ['sites'] as const,
  list: (query?: SiteListQuery) => [...siteKeys.all, 'list', query ?? {}] as const,
  detail: (id: string) => [...siteKeys.all, 'detail', id] as const,
  upstreams: (id: string) => [...siteKeys.all, id, 'upstreams'] as const,
  pools: (id: string) => [...siteKeys.all, id, 'pools'] as const,
  routes: (id: string) => [...siteKeys.all, id, 'routes'] as const,
  ssl: (id: string) => [...siteKeys.all, id, 'ssl'] as const,
}

export default sitesApi
