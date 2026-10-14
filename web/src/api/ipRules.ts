import { apiClient } from './client'
import type {
  BulkImportIpRequest,
  CreateIpRuleRequest,
  IpRule,
  Page,
  PaginationQuery,
  UpdateIpRuleRequest,
} from './types'

/**
 * IP access rules — `/api/v1/sites/{siteId}/ip-rules`.
 *
 * Allow / block / challenge traffic from an explicit IP/CIDR list or by
 * referencing an IP group. Rules are evaluated before the WAF, so an explicit
 * allow short-circuits everything downstream.
 */
export const ipRulesApi = {
  list: (siteId: string, query: PaginationQuery = {}) =>
    apiClient.get<Page<IpRule>>(`/sites/${siteId}/ip-rules`, {
      query: { page_size: 200, ...query },
    }),

  create: (siteId: string, data: CreateIpRuleRequest) =>
    apiClient.post<IpRule>(`/sites/${siteId}/ip-rules`, data),

  update: (siteId: string, id: string, data: UpdateIpRuleRequest) =>
    apiClient.put<IpRule>(`/sites/${siteId}/ip-rules/${id}`, data),

  delete: (siteId: string, id: string) =>
    apiClient.delete<void>(`/sites/${siteId}/ip-rules/${id}`),

  toggleEnabled: (siteId: string, id: string, enabled: boolean) =>
    ipRulesSafePut(siteId, id, { enabled }),

  bulkImport: (siteId: string, data: BulkImportIpRequest) =>
    apiClient.post<{ id: string; imported: number }>(
      `/sites/${siteId}/ip-rules/bulk`,
      data,
    ),
}

/** Kept separate so `toggleEnabled` reads cleanly at the call site. */
function ipRulesSafePut(siteId: string, id: string, data: UpdateIpRuleRequest) {
  return apiClient.put<IpRule>(`/sites/${siteId}/ip-rules/${id}`, data)
}

/* ────────────────────────────────────────────────────────────────
   Validation
   ──────────────────────────────────────────────────────────────── */

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/** True for a dotted-quad with every octet in 0..255. */
export function isValidIpv4(value: string): boolean {
  const m = IPV4_RE.exec(value.trim())
  if (!m) return false
  return [m[1], m[2], m[3], m[4]].every((oct) => {
    const n = Number(oct)
    return Number.isInteger(n) && n >= 0 && n <= 255
  })
}

/**
 * True for a valid IPv6 address, mirroring Rust's `IpAddr::from_str` rules:
 * at most one `::` (which must compress at least one group), 1-4 hex digits
 * per group, exactly 8 groups when no `::` is present, and an IPv4 tail
 * (dotted quad, counts as two groups) only at the very end, e.g.
 * `::ffff:192.168.1.1` or `1:2:3:4:5:6:1.2.3.4`.
 */
export function isValidIpv6(value: string): boolean {
  const v = value.trim()
  if (!v.includes(':') || v.includes(':::')) return false

  // Split around the (single) `::` compression marker.
  const parts = v.split('::')
  if (parts.length > 2) return false
  const compressed = parts.length === 2
  const head = parts[0] ? parts[0].split(':') : []
  const tail = compressed && parts[1] ? parts[1].split(':') : []
  if (head.some((g) => g === '') || tail.some((g) => g === '')) return false

  if (head.length + tail.length === 0) return compressed // bare `::`

  // IPv4 tail is only allowed as the very last group of the address.
  const last =
    compressed && tail.length > 0 ? tail[tail.length - 1] : head[head.length - 1]
  if (compressed && tail.length === 0 && last.includes('.')) return false
  const hasV4Tail = last.includes('.')
  const hexGroups = hasV4Tail ? [...head, ...tail].slice(0, -1) : [...head, ...tail]
  if (!hexGroups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return false
  if (hasV4Tail && !isValidIpv4(last)) return false

  // A dotted quad occupies two groups but already appears as one element
  // in head/tail, so it adds one extra group to the count.
  const total = head.length + tail.length + (hasV4Tail ? 1 : 0)
  if (!compressed) return total === 8
  return total <= 7 // `::` must compress at least one group
}

/**
 * Validates a single address or CIDR range. Returns `null` when valid, or a
 * short reason string the form can surface.
 */
export function validateIpCidr(value: string): string | null {
  const v = value.trim()
  if (!v) return 'empty'
  const [addr, prefix, ...rest] = v.split('/')
  if (rest.length > 0) return 'malformed'
  if (prefix !== undefined) {
    // `10.0.0.0/` — empty prefix is malformed, not prefix 0.
    if (prefix === '') return 'malformed'
    const bits = Number(prefix)
    const isV6 = addr.includes(':')
    const max = isV6 ? 128 : 32
    if (!Number.isInteger(bits) || bits < 0 || bits > max) return 'prefix'
    if (isV6 ? !isValidIpv6(addr) : !isValidIpv4(addr)) return 'address'
    return null
  }
  if (isValidIpv4(addr) || isValidIpv6(addr)) return null
  return 'address'
}

/** Minimum prefix length per family (larger number = narrower range). */
export interface MinPrefix {
  v4: number
  v6: number
}

/**
 * Validates manual-block input: a single address or a CIDR range
 * (`addr/prefix`, prefix within the address family's bit length). When
 * `minPrefix` is given, ranges broader than the floor (e.g. `10.0.0.0/8`
 * against `{ v4: 16, v6: 32 }`) are rejected with `tooBroad` — this mirrors
 * the backend's manual-block width limits without affecting bulk import.
 * Returns `null` when valid, or a short reason string the form can surface.
 */
export function validateIpOrCidr(
  value: string,
  minPrefix?: MinPrefix,
): string | null {
  const reason = validateIpCidr(value)
  if (reason !== null || !minPrefix) return reason
  const [addr, prefix] = value.trim().split('/')
  if (prefix !== undefined) {
    const bits = Number(prefix)
    const floor = addr.includes(':') ? minPrefix.v6 : minPrefix.v4
    if (bits < floor) return 'tooBroad'
  }
  return null
}

/**
 * Validates a single IP address (no CIDR). Returns `null` when valid, or a
 * short reason string the form can surface. Kept for callers that still need
 * address-only input (e.g. IP rule panels).
 */
export function validateSingleIp(value: string): string | null {
  const v = value.trim()
  if (!v) return 'empty'
  if (v.includes('/')) return 'cidr'
  if (isValidIpv4(v) || isValidIpv6(v)) return null
  return 'address'
}

/**
 * Splits a bulk-import textarea into valid IP/CIDR entries.
 *
 * Duplicates (including repeats of invalid lines) are counted separately so
 * callers can surface a compact message instead of listing every row.
 */
export function parseIpList(raw: string): {
  valid: string[]
  invalid: string[]
  /** How many raw lines were dropped as repeats of an earlier entry. */
  duplicateCount: number
} {
  const valid: string[] = []
  const invalid: string[] = []
  const seen = new Set<string>()
  let duplicateCount = 0
  for (const line of raw.split(/[\n,;]/)) {
    const entry = line.trim()
    if (!entry) continue
    if (seen.has(entry)) {
      duplicateCount += 1
      continue
    }
    seen.add(entry)
    if (validateIpCidr(entry) === null) valid.push(entry)
    else invalid.push(entry)
  }
  return { valid, invalid, duplicateCount }
}

/**
 * Compact, i18n-ready description of the invalid lines from
 * {@link parseIpList}, grouped by rejection reason: e.g.
 * `"3 invalid: a, b, c"` / `"2 duplicate entries ignored"`.
 */
export function summarizeInvalid(
  invalid: string[],
  duplicateCount: number,
  t: (key: string, opts?: Record<string, unknown>) => string,
): string | null {
  const parts: string[] = []
  if (invalid.length > 0) {
    parts.push(
      t('pages.ipRules.bulkInvalid', {
        count: invalid.length,
        list: invalid.slice(0, 5).join(', '),
      }),
    )
  }
  if (duplicateCount > 0) {
    parts.push(t('pages.ipRules.bulkDuplicates', { count: duplicateCount }))
  }
  return parts.length > 0 ? parts.join(' ') : null
}

export const ipRuleKeys = {
  all: (siteId: string) => ['sites', siteId, 'ip-rules'] as const,
  list: (siteId: string, query?: PaginationQuery) =>
    ['sites', siteId, 'ip-rules', 'list', query ?? {}] as const,
}

export default ipRulesApi
