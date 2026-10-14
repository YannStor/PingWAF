import { apiClient } from './client'
import type {
  CreateIpGroupRequest,
  IpGroup,
  IpGroupListQuery,
  IpGroupResponse,
  Page,
  Site,
  UpdateIpGroupRequest,
} from './types'

/**
 * IP groups — `/api/v1/ip-groups`.
 *
 * Named collections of IP/CIDR ranges that can be applied globally or to
 * specific sites as a blacklist or whitelist. Optionally synced from a
 * subscription source URL.
 */
export const ipGroupsApi = {
  list: (query: IpGroupListQuery = {}) =>
    apiClient.get<Page<IpGroupResponse>>('/ip-groups', {
      query: { page_size: 50, ...query },
    }),

  create: (data: CreateIpGroupRequest) =>
    apiClient.post<IpGroup>('/ip-groups', data),

  update: (id: string, data: UpdateIpGroupRequest) =>
    apiClient.put<IpGroup>(`/ip-groups/${id}`, data),

  delete: (id: string) =>
    apiClient.delete<void>(`/ip-groups/${id}`),

  listSites: (id: string) =>
    apiClient.get<Site[]>(`/ip-groups/${id}/sites`),

  setSites: (id: string, siteIds: string[]) =>
    apiClient.put<void>(`/ip-groups/${id}/sites`, { site_ids: siteIds }),

  sync: (id: string) =>
    apiClient.post<{ id: string; synced_at: string | null; ip_count: number }>(
      `/ip-groups/${id}/sync`,
    ),
}

export const ipGroupKeys = {
  all: ['ip-groups'] as const,
  list: (query?: IpGroupListQuery) =>
    ['ip-groups', 'list', query ?? {}] as const,
  detail: (id: string) => ['ip-groups', id] as const,
  sites: (id: string) => ['ip-groups', id, 'sites'] as const,
}

export default ipGroupsApi
