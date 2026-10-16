import { apiClient } from './client'
import type {
  AccessLog,
  AccessLogSummary,
  LogQueryParams,
  Page,
  PurgeResult,
  SecurityEvent,
} from './types'

/**
 * Logs — `/api/v1/logs/*`.
 *
 * Backed by PostgreSQL for recent events and Elasticsearch for the long tail;
 * the API hides which one answered. `from`/`to` are RFC 3339, defaulting to the
 * trailing 24h with a hard cap of 90 days.
 *
 * Access-log lists return metadata-only rows (`AccessLogSummary`); pass
 * `full: true` — or fetch one record via `accessLogDetail` — when the raw
 * request/response replay is needed.
 */
export const logsApi = {
  securityEvents: (params: LogQueryParams = {}) =>
    apiClient.get<Page<SecurityEvent>>('/logs/security', { query: params }),

  accessLogs: (params: LogQueryParams = {}) =>
    apiClient.get<Page<AccessLogSummary>>('/logs/access', { query: params }),

  accessLogDetail: (id: number) =>
    apiClient.get<AccessLog>(`/logs/access/${id}`),

  purge: (params: { site_id?: string; older_than_days?: number } = {}) =>
    apiClient.delete<PurgeResult>('/logs/purge', { query: params }),
}

/**
 * Triggers a client-side download of the current result set as JSON.
 *
 * There is no server-side export endpoint, so we serialise the page the user is
 * looking at — which is exactly what an operator expects from an "export"
 * button on a filtered table.
 */
export function downloadJson(filename: string, payload: unknown): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: 'application/json',
  })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename.endsWith('.json') ? filename : `${filename}.json`
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  // Give the browser a tick to start the download before revoking.
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** ISO-ish stamp safe for filenames: `2026-09-25T10-30-00`. */
export function fileTimestamp(date = new Date()): string {
  return date.toISOString().replace(/[:.]/g, '-').slice(0, 19)
}

export const logKeys = {
  all: ['logs'] as const,
  security: (params: LogQueryParams) => [...logKeys.all, 'security', params] as const,
  access: (params: LogQueryParams) => [...logKeys.all, 'access', params] as const,
}

export default logsApi
