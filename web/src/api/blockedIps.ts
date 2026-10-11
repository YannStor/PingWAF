import { apiClient } from './client'
import type {
  BlockedIp,
  GlobalBlockedIp,
  ManualBlockIpRequest,
  ManualBlockIpResponse,
  UnblockIpResponse,
} from './types'

/**
 * Auto-blocked IPs — `/api/v1/sites/{siteId}/blocked-ips`.
 *
 * Dynamic blocks the edge enforces for a site (WAF/rate-limit auto-blocks
 * plus server-issued block commands). The list is reconciled from every
 * agent heartbeat; the UI polls it because blocks appear and expire without
 * any user action.
 */
export const blockedIpsApi = {
  list: (siteId: string) =>
    apiClient.get<BlockedIp[]>(`/sites/${siteId}/blocked-ips`),

  unblock: (siteId: string, ip: string) =>
    apiClient.post<UnblockIpResponse>(
      `/sites/${siteId}/blocked-ips/unblock`,
      { ip },
    ),

  /**
   * Global cross-site view — `GET /api/v1/blocked-ips`. Admins see every
   * site; other accounts only their own. `site_id` narrows to one site,
   * `ip` is a substring filter.
   */
  globalList: (params: { site_id?: string; ip?: string } = {}) =>
    apiClient.get<GlobalBlockedIp[]>('/blocked-ips', { query: params }),

  /**
   * Manual dynamic block — `POST /api/v1/blocked-ips/block`. A BlockIp
   * command fans out to every registered agent (queued for offline ones).
   */
  block: (payload: ManualBlockIpRequest) =>
    apiClient.post<ManualBlockIpResponse>('/blocked-ips/block', payload),
}

export const blockedIpKeys = {
  all: (siteId: string) => ['sites', siteId, 'blocked-ips'] as const,
  list: (siteId: string) =>
    ['sites', siteId, 'blocked-ips', 'list'] as const,
  global: ['blocked-ips'] as const,
  globalList: (params: { site_id?: string; ip?: string }) =>
    [...blockedIpKeys.global, 'list', params] as const,
}

export default blockedIpsApi
