import type { UpstreamPool } from '@/api/types'

/* ── Load-balancing algorithm helpers ─────────────────────────────── */

/** Select values that require a hash-key input; keyed by `hash:<type>`. */
export const HASH_KEY_TYPES = ['hash:header', 'hash:cookie', 'hash:query']

export function isHashKeyType(value: string) {
  return HASH_KEY_TYPES.includes(value)
}

/** Parses `round_robin | least_connections | random | hash:ip | hash:header:key` into form fields. */
export function splitLbAlgorithm(algo: string): { lbType: string; hashKey: string } {
  if (!algo || algo === 'round_robin') return { lbType: 'round_robin', hashKey: '' }
  if (algo === 'least_connections' || algo === 'random') {
    return { lbType: algo, hashKey: '' }
  }
  const parts = algo.split(':')
  if (parts[0] !== 'hash' || parts.length < 2) {
    return { lbType: 'round_robin', hashKey: '' }
  }
  return { lbType: `hash:${parts[1]}`, hashKey: parts.slice(2).join(':') }
}

/** Label keys for the LB dropdown; resolved with `t()` at the call site. */
export const LB_OPTION_KEYS = [
  { value: 'round_robin', labelKey: 'pages.basic.lb.roundRobin' },
  { value: 'least_connections', labelKey: 'pages.basic.lb.leastConnections' },
  { value: 'random', labelKey: 'pages.basic.lb.random' },
  { value: 'hash:ip', labelKey: 'pages.basic.lb.hashIp' },
  { value: 'hash:url', labelKey: 'pages.basic.lb.hashUrl' },
  { value: 'hash:path', labelKey: 'pages.basic.lb.hashPath' },
  { value: 'hash:header', labelKey: 'pages.basic.lb.hashHeader' },
  { value: 'hash:cookie', labelKey: 'pages.basic.lb.hashCookie' },
  { value: 'hash:query', labelKey: 'pages.basic.lb.hashQuery' },
]

/* ── Form state ───────────────────────────────────────────────────── */

export interface PoolFormState {
  name: string
  lbType: string
  hashKey: string
  httpsOrigin: boolean
  sni: string
  verifyCert: boolean
  healthCheckEnabled: boolean
  /** Kept as strings: raw input, validated on submit. */
  healthCheckPath: string
  healthCheckInterval: string
  healthCheckTimeout: string
  healthCheckUnhealthy: string
  healthCheckHealthy: string
}

export const emptyPoolForm = (): PoolFormState => ({
  name: '',
  lbType: 'round_robin',
  hashKey: '',
  httpsOrigin: false,
  sni: '',
  verifyCert: false,
  healthCheckEnabled: false,
  healthCheckPath: '/healthz',
  healthCheckInterval: '10',
  healthCheckTimeout: '3000',
  healthCheckUnhealthy: '2',
  healthCheckHealthy: '1',
})

export function poolFormFromPool(pool: UpstreamPool): PoolFormState {
  const { lbType, hashKey } = splitLbAlgorithm(pool.lb_algorithm)
  return {
    name: pool.name,
    lbType,
    hashKey,
    httpsOrigin: Boolean(pool.sni),
    sni: pool.sni ?? '',
    verifyCert: pool.verify_cert ?? false,
    healthCheckEnabled: pool.health_check_enabled,
    healthCheckPath: pool.health_check_path || '/healthz',
    healthCheckInterval: String(pool.health_check_interval_seconds),
    healthCheckTimeout: String(pool.health_check_timeout_ms),
    healthCheckUnhealthy: String(pool.health_check_unhealthy_threshold),
    healthCheckHealthy: String(pool.health_check_healthy_threshold),
  }
}

/**
 * Mirrors the server's `PoolHealthCheck` validation so a bad posture fails
 * inline instead of as a generic 400. Runs unconditionally — the server
 * validates the stored values even while the check is disabled. Returns the
 * `pages.basic.errors.*` i18n key suffix, or null when the fields are valid.
 */
export function validatePoolHealthCheck(form: PoolFormState): string | null {
  const path = form.healthCheckPath.trim()
  // The server counts UTF-8 bytes, not UTF-16 code units — multi-byte
  // characters must not slip past the front end.
  if (
    !path.startsWith('/') ||
    /[ ?#]/.test(path) ||
    new TextEncoder().encode(path).length > 255
  ) {
    return 'healthPathInvalid'
  }
  const int = (raw: string) => (/^\d+$/.test(raw.trim()) ? Number(raw.trim()) : NaN)
  const interval = int(form.healthCheckInterval)
  if (!(interval >= 5 && interval <= 3600)) return 'healthIntervalInvalid'
  const timeout = int(form.healthCheckTimeout)
  if (!(timeout >= 100 && timeout <= 30000)) return 'healthTimeoutInvalid'
  const unhealthy = int(form.healthCheckUnhealthy)
  if (!(unhealthy >= 1 && unhealthy <= 10)) return 'healthThresholdInvalid'
  const healthy = int(form.healthCheckHealthy)
  if (!(healthy >= 1 && healthy <= 10)) return 'healthThresholdInvalid'
  return null
}

/**
 * Health-check fields as submitted to the server. While the probe is
 * disabled the inputs are not rendered, so an out-of-range stored value
 * (API-written data, older server, partial response) must never block the
 * dialog: the server validates stored values unconditionally, so invalid
 * hidden values are silently normalized to the server defaults instead.
 * Valid values — including custom ones — pass through unchanged.
 */
export function poolHealthCheckPayload(form: PoolFormState): {
  health_check_enabled: boolean
  health_check_path: string
  health_check_interval_seconds: number
  health_check_timeout_ms: number
  health_check_unhealthy_threshold: number
  health_check_healthy_threshold: number
} {
  if (form.healthCheckEnabled && validatePoolHealthCheck(form) === null) {
    return {
      health_check_enabled: true,
      health_check_path: form.healthCheckPath.trim(),
      health_check_interval_seconds: Number(form.healthCheckInterval.trim()),
      health_check_timeout_ms: Number(form.healthCheckTimeout.trim()),
      health_check_unhealthy_threshold: Number(form.healthCheckUnhealthy.trim()),
      health_check_healthy_threshold: Number(form.healthCheckHealthy.trim()),
    }
  }
  // Server defaults (PoolHealthCheck::default_values). Used verbatim when
  // the probe is on and every field is valid, and to normalize inert
  // out-of-range values when it is off.
  const defaults = emptyPoolForm()
  const int = (raw: string, min: number, max: number, fallback: number) => {
    const n = /^\d+$/.test(raw.trim()) ? Number(raw.trim()) : NaN
    return n >= min && n <= max ? n : fallback
  }
  const path = form.healthCheckPath.trim()
  const validPath =
    path.startsWith('/') && !/[ ?#]/.test(path) && new TextEncoder().encode(path).length <= 255
  return {
    health_check_enabled: false,
    health_check_path: validPath ? path : defaults.healthCheckPath,
    health_check_interval_seconds: int(
      form.healthCheckInterval, 5, 3600, 10,
    ),
    health_check_timeout_ms: int(form.healthCheckTimeout, 100, 30000, 3000),
    health_check_unhealthy_threshold: int(form.healthCheckUnhealthy, 1, 10, 2),
    health_check_healthy_threshold: int(form.healthCheckHealthy, 1, 10, 1),
  }
}

export interface NodeFormState {
  name: string
  address: string
  weight: string
  poolId: string
}

export const emptyNodeForm = (poolId: string): NodeFormState => ({
  name: '',
  address: '',
  weight: '1',
  poolId,
})

/**
 * Mirrors the server's origin-address normalization (`host[:port]`) so a
 * pasted URL fails inline instead of as a generic 400.
 *
 * Returns the i18n key of the error, or the canonical address.
 */
export function parseOriginAddress(raw: string): { error: string } | { address: string } {
  let address = raw.trim()
  for (const scheme of ['http://', 'https://']) {
    if (address.toLowerCase().startsWith(scheme)) {
      address = address.slice(scheme.length)
      break
    }
  }
  address = address.replace(/\/+$/, '')
  if (!address || address.length > 255) return { error: 'errors.addressRequired' }
  if (/[?#]/.test(address) || address.includes('/')) return { error: 'errors.addressPath' }

  let host = address
  let port = ''
  if (address.startsWith('[')) {
    const end = address.indexOf(']')
    if (end < 2) return { error: 'errors.addressInvalid' }
    host = address.slice(1, end)
    const tail = address.slice(end + 1)
    if (tail && !tail.startsWith(':')) return { error: 'errors.addressInvalid' }
    port = tail.slice(1)
    if (!/^[0-9A-Fa-f:.]+$/.test(host)) return { error: 'errors.addressInvalid' }
  } else {
    const parts = address.split(':')
    // A bare IPv6 literal has to be bracketed, otherwise the port is ambiguous.
    if (parts.length > 2) return { error: 'errors.addressInvalid' }
    if (parts.length === 2) {
      host = parts[0]
      port = parts[1]
    }
    if (!/^[A-Za-z0-9._-]+$/.test(host)) return { error: 'errors.addressInvalid' }
  }
  if (port && (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)) {
    return { error: 'errors.addressPort' }
  }
  return { address }
}

export interface RouteFormState {
  name: string
  matchType: string
  path: string
  priority: string
  poolId: string
  /** Empty string gates the route to no group (every client matches). */
  ipGroupId: string
  enabled: boolean
}

export const emptyRouteForm = (poolId: string): RouteFormState => ({
  name: '',
  matchType: 'prefix',
  path: '',
  priority: '',
  poolId,
  ipGroupId: '',
  enabled: true,
})

/* ── Trusted proxy helpers ────────────────────────────────────────── */

/** Select values for the trusted forwarded header dropdown. */
export const TRUSTED_HEADER_OPTIONS = [
  { value: 'x-forwarded-for', labelKey: 'pages.basic.proxyTrust.headerXff' },
  { value: 'x-real-ip', labelKey: 'pages.basic.proxyTrust.headerRealIp' },
  { value: 'cf-connecting-ip', labelKey: 'pages.basic.proxyTrust.headerCf' },
  { value: 'true-client-ip', labelKey: 'pages.basic.proxyTrust.headerTrueClient' },
]

/** Validates one IPv4/IPv6 literal; mirrors the server's `parse_proxy_range`. */
export function isValidIpLiteral(value: string): boolean {
  if (value.includes(':')) {
    try {
      new URL(`http://[${value}]/`)
      return true
    } catch {
      return false
    }
  }
  const octets = value.split('.')
  if (octets.length !== 4) return false
  return octets.every((o) => /^\d+$/.test(o) && Number(o) <= 255)
}

/**
 * Parses the ranges textarea (one CIDR or bare IP per line). Returns the
 * list, or null when any entry is malformed.
 */
export function parseTrustedRanges(raw: string): string[] | null {
  const ranges: string[] = []
  for (const line of raw.split(/\r?\n|,/)) {
    const value = line.trim()
    if (!value) continue
    const parts = value.split('/')
    if (parts.length > 2 || !isValidIpLiteral(parts[0])) return null
    if (parts.length === 2) {
      if (!/^\d+$/.test(parts[1])) return null
      const max = parts[0].includes(':') ? 128 : 32
      if (Number(parts[1]) > max) return null
    }
    ranges.push(value)
  }
  return ranges
}
