import { apiClient } from './client'
import type {
  ActiveVisitorsResponse,
  AnalyticsSummary,
  ClientTypesResponse,
  RangeQuery,
  SiteTrafficBucket,
  SitesOverviewResponse,
  StatusCodeCount,
  TimeBucket,
  TopIp,
  TopPath,
  TopRule,
  TrafficRange,
  TrafficSeries,
} from './types'

/**
 * Analytics — `/api/v1/analytics/*`.
 *
 * Every endpoint accepts the same `RangeQuery`. Defaults are a trailing 24h
 * window and `interval=hour`; the server rejects ranges wider than 31 days.
 */
export const analyticsApi = {
  summary: (params: RangeQuery = {}) =>
    apiClient.get<AnalyticsSummary>('/analytics/summary', { query: params }),

  requestsOverTime: (params: RangeQuery = {}) =>
    apiClient.get<TimeBucket[]>('/analytics/requests-over-time', { query: params }),

  /**
   * Egress bytes bucketed at a fixed width (default 5s). `step` must be one of
   * the server whitelist (5/10/30/60/300/900/3600/86400) and small enough that
   * the window yields at most ~8k buckets.
   */
  traffic: (params: RangeQuery & { step?: number } = {}) =>
    apiClient.get<TrafficSeries>('/analytics/traffic', { query: params }),

  sitesOverTime: (params: RangeQuery = {}) =>
    apiClient.get<SiteTrafficBucket[]>('/analytics/sites-over-time', { query: params }),

  topRules: (params: RangeQuery = {}) =>
    apiClient.get<TopRule[]>('/analytics/top-rules', { query: { limit: 10, ...params } }),

  topIps: (params: RangeQuery = {}) =>
    apiClient.get<TopIp[]>('/analytics/top-ips', { query: { limit: 10, ...params } }),

  topPaths: (params: RangeQuery = {}) =>
    apiClient.get<TopPath[]>('/analytics/top-paths', { query: { limit: 10, ...params } }),

  statusCodes: (params: RangeQuery = {}) =>
    apiClient.get<StatusCodeCount[]>('/analytics/status-codes', { query: params }),

  /**
   * Traffic per site for the home page; the global view is server-capped
   * (newest sites first) and `truncated` reports whether the list was cut.
   */
  sitesOverview: (params: RangeQuery = {}) =>
    apiClient.get<SitesOverviewResponse>('/analytics/sites', { query: params }),

  /** Distinct client IPs seen over the trailing `minutes` window (clamped 1..60, default 5). */
  activeVisitors: (params: { siteId?: string; minutes?: number } = {}) =>
    apiClient.get<ActiveVisitorsResponse>('/analytics/active-visitors', {
      query: {
        ...(params.siteId ? { site_id: params.siteId } : {}),
        ...(params.minutes !== undefined ? { minutes: params.minutes } : {}),
      },
    }),

  /**
   * Client-type breakdown (desktop / mobile / other). Preset ranges map to the
   * server whitelist (`24h|7d|30d`); shorter ranges fall back to explicit
   * `from`/`to` built with `rangeFor`.
   */
  clientTypes: (params: { siteId?: string; range?: TrafficRange } = {}) =>
    apiClient.get<ClientTypesResponse>('/analytics/client-types', {
      query: {
        ...(params.siteId ? { site_id: params.siteId } : {}),
        ...(params.range ? clientTypesRangeQuery(params.range) : {}),
      },
    }),
}

/** RFC 3339 helper — the backend parses `from`/`to` with `DateTime::parse_from_rfc3339`. */
export function toRfc3339(date: Date): string {
  return date.toISOString()
}

/** Builds `{from,to}` for one of the preset dashboard windows. */
export function rangeFor(hours: number): { from: string; to: string } {
  const to = new Date()
  const from = new Date(to.getTime() - hours * 3600_000)
  return { from: toRfc3339(from), to: toRfc3339(to) }
}

const CLIENT_TYPES_RANGE_HOURS: Record<TrafficRange, number> = {
  '1h': 1,
  '6h': 6,
  '24h': 24,
  '7d': 24 * 7,
  '30d': 24 * 30,
}

/**
 * Query params for `GET /analytics/client-types` — the endpoint only accepts
 * `range=24h|7d|30d`, so shorter windows are expressed as `from`/`to`.
 */
export function clientTypesRangeQuery(range: TrafficRange): { range: string } | { from: string; to: string } {
  if (range === '24h' || range === '7d' || range === '30d') return { range }
  return rangeFor(CLIENT_TYPES_RANGE_HOURS[range])
}

/**
 * Picks a bucketing interval that keeps the series readable for a window.
 * The server caps `minute` buckets, so short windows only.
 */
export function intervalForHours(hours: number): 'minute' | 'hour' | 'day' | 'week' {
  if (hours <= 2) return 'minute'
  if (hours <= 72) return 'hour'
  if (hours <= 24 * 21) return 'day'
  return 'week'
}

export const analyticsKeys = {
  all: ['analytics'] as const,
  summary: (params: RangeQuery) => [...analyticsKeys.all, 'summary', params] as const,
  traffic: (params: RangeQuery) => [...analyticsKeys.all, 'traffic', params] as const,
  bandwidth: (params: RangeQuery & { step?: number }) =>
    [...analyticsKeys.all, 'bandwidth', params] as const,
  sitesOverTime: (params: RangeQuery) => [...analyticsKeys.all, 'sites-over-time', params] as const,
  topRules: (params: RangeQuery) => [...analyticsKeys.all, 'top-rules', params] as const,
  topIps: (params: RangeQuery) => [...analyticsKeys.all, 'top-ips', params] as const,
  topPaths: (params: RangeQuery) => [...analyticsKeys.all, 'top-paths', params] as const,
  statusCodes: (params: RangeQuery) => [...analyticsKeys.all, 'status-codes', params] as const,
  sites: (params: RangeQuery) => [...analyticsKeys.all, 'sites', params] as const,
  overview: (params: RangeQuery) => [...analyticsKeys.all, 'overview', params] as const,
  activeVisitors: (params: { siteId?: string; minutes?: number } = {}) =>
    [...analyticsKeys.all, 'active-visitors', params] as const,
  clientTypes: (params: { siteId?: string; range?: TrafficRange } = {}) =>
    [...analyticsKeys.all, 'client-types', params] as const,
}

export default analyticsApi
