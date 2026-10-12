import type { LogQueryParams } from '@/api/types'

export type LogTab = 'security' | 'access' | 'control'

export interface LogSearch {
  /** Backend params derived from the search text (page/from/to flow in too). */
  params: LogQueryParams
  /** Tokens the grammar does not understand, shown as an inline hint. */
  unknown: string[]
}

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

/**
 * Kibana-style search grammar for the log pages.
 *
 * ```
 * client_ip:203.0.113.44         exact match (`ip:` alias)
 * client_ip:203.0.113.*          `*` wildcard, matched server-side
 * client_ip:10.0.0.1,10.0.0.8    any of several values
 * path:/api/v1/users             substring match
 * status:404                     exact status code
 * status:4xx                     whole status class
 * method:POST,PUT                one of several methods
 * action:block,challenge         WAF decision
 * rule:xss-001                   rule id
 * type:managed,bot               security event protection type
 * country:CN  cache_status:hit
 * latency:>500                   minimum total latency in ms
 * site:9f8f8e5c-…                site id
 * site:none                      traffic with no owning site (no Host header)
 * host:example.com               exact host (`*` for a wildcard)
 * from:2026-09-01  to:2026-09-02 time window (overrides the pickers)
 * free text terms                matched against path and host
 * ```
 *
 * Values with spaces go in double quotes: `path:"/my files"`.
 */
export function parseLogQuery(input: string, tab: LogTab): LogSearch {
  const params: LogQueryParams = {}
  const unknown: string[] = []
  const terms: string[] = []

  for (const token of tokenize(input)) {
    const separator = token.indexOf(':')
    if (separator <= 0) {
      terms.push(token)
      continue
    }
    const field = token.slice(0, separator).toLowerCase().replace(/-/g, '_')
    const value = token.slice(separator + 1).trim()
    if (!value) {
      unknown.push(token)
      continue
    }
    switch (field) {
      case 'ip':
      case 'client_ip':
        params.client_ip = value
        break
      case 'host':
        params.host = value
        break
      case 'path':
        params.path = value
        break
      case 'site':
      case 'site_id':
        if (value === 'none') params.unassigned = true
        else if (UUID_RE.test(value)) params.site_id = value
        else unknown.push(token)
        break
      case 'type':
      case 'event_type':
        if (tab === 'security') params.event_type = value.toLowerCase()
        else unknown.push(token)
        break
      case 'request_id':
        params.request_id = value
        break
      case 'country':
      case 'country_code':
        if (tab === 'control') unknown.push(token)
        else params.country_code = value.toUpperCase()
        break
      case 'status': {
        // `4xx` selects the whole class; a three-digit code matches exactly.
        if (/^[1-5]xx$/.test(value)) {
          if (tab === 'control') unknown.push(token)
          else params.status_class = Number(value[0])
        } else if (/^\d{3}$/.test(value)) {
          params.status_code = Number(value)
        } else {
          unknown.push(token)
        }
        break
      }
      case 'latency':
      case 'min_latency_ms': {
        const number = value.replace(/^>=?/, '')
        if (/^\d+$/.test(number)) params.min_latency_ms = Number(number)
        else unknown.push(token)
        break
      }
      case 'action':
        if (tab === 'security' || tab === 'control') params.action = value
        else unknown.push(token)
        break
      case 'rule':
      case 'rule_id':
        if (tab === 'security') params.rule_id = value
        else unknown.push(token)
        break
      case 'method':
        if (tab === 'access' || tab === 'control') params.method = value.toUpperCase()
        else unknown.push(token)
        break
      case 'cache':
      case 'cache_status':
        if (tab === 'access') params.cache_status = value.toLowerCase()
        else unknown.push(token)
        break
      case 'from':
      case 'to': {
        const date = new Date(value)
        if (Number.isNaN(date.getTime())) {
          unknown.push(token)
        } else if (field === 'from') {
          params.from = date.toISOString()
        } else {
          params.to = date.toISOString()
        }
        break
      }
      default:
        unknown.push(token)
    }
  }

  if (terms.length > 0) params.q = terms.join(' ')
  return { params, unknown }
}

/** Renders params back into search text; the inverse of {@link parseLogQuery}. */
export function formatLogQuery(params: LogQueryParams, tab: LogTab): string {
  const quote = (value: string) => (value.includes(' ') ? `"${value}"` : value)
  const parts: string[] = []
  if (params.client_ip) parts.push(`client_ip:${quote(params.client_ip)}`)
  if (params.host) parts.push(`host:${quote(params.host)}`)
  if (params.path) parts.push(`path:${quote(params.path)}`)
  if (params.status_class) parts.push(`status:${params.status_class}xx`)
  else if (params.status_code) parts.push(`status:${params.status_code}`)
  if (tab === 'access') {
    if (params.method) parts.push(`method:${params.method}`)
    if (params.cache_status) parts.push(`cache_status:${params.cache_status}`)
    if (params.min_latency_ms != null) {
      parts.push(`latency:>${params.min_latency_ms}`)
    }
  } else {
    if (params.action) parts.push(`action:${params.action}`)
    if (params.rule_id) parts.push(`rule:${quote(params.rule_id)}`)
    if (params.event_type) parts.push(`type:${params.event_type}`)
    if (tab === 'control' && params.method) parts.push(`method:${params.method}`)
  }
  if (params.country_code) parts.push(`country:${params.country_code}`)
  if (params.request_id) parts.push(`request_id:${params.request_id}`)
  if (params.unassigned) parts.push('site:none')
  else if (params.site_id) parts.push(`site:${params.site_id}`)
  if (params.q) parts.push(quote(params.q))
  return parts.join(' ')
}

/** Splits on whitespace, honouring double quotes around a whole segment. */
function tokenize(input: string): string[] {
  const tokens: string[] = []
  let current = ''
  let quoted = false
  const flush = () => {
    const token = current.trim()
    if (token) tokens.push(token)
    current = ''
  }
  for (const char of input) {
    if (char === '"') {
      quoted = !quoted
      continue
    }
    if (!quoted && /\s/.test(char)) {
      flush()
      continue
    }
    current += char
  }
  flush()
  return tokens
}

/* ────────────────────────────────────────────────────────────────
   Field metadata — the single source for the search autocomplete
   and the clickable field-hint chips under the input. Kept in sync
   with the parser above by construction (same file).
   ──────────────────────────────────────────────────────────────── */

export interface LogQueryField {
  /** Canonical name inserted by autocomplete / hint chips. */
  name: string
  /** Alternative spellings the parser also accepts. */
  aliases?: string[]
  /** Tabs the field filters on (elsewhere it lands in `unknown`). */
  tabs: LogTab[]
  /** Key under `pages.logs.fieldHints` describing the field. */
  descKey: string
  /** Example value rendered next to the field name. */
  example: string
}

export const LOG_QUERY_FIELDS: LogQueryField[] = [
  {
    name: 'client_ip',
    aliases: ['ip'],
    tabs: ['security', 'access'],
    descKey: 'clientIp',
    example: '203.0.113.44',
  },
  {
    name: 'path',
    tabs: ['security', 'access'],
    descKey: 'path',
    example: '/api/v1/users',
  },
  {
    name: 'host',
    tabs: ['security', 'access'],
    descKey: 'host',
    example: 'example.com',
  },
  {
    name: 'site',
    aliases: ['site_id'],
    tabs: ['security', 'access'],
    descKey: 'site',
    example: '<site-id>|none',
  },
  {
    name: 'rule',
    aliases: ['rule_id'],
    tabs: ['security'],
    descKey: 'rule',
    example: 'xss-001',
  },
  {
    name: 'type',
    aliases: ['event_type'],
    tabs: ['security'],
    descKey: 'type',
    example: 'managed,bot',
  },
  {
    name: 'action',
    tabs: ['security', 'control'],
    descKey: 'action',
    example: 'block,challenge',
  },
  {
    name: 'country',
    aliases: ['country_code'],
    tabs: ['security', 'access'],
    descKey: 'country',
    example: 'CN',
  },
  {
    name: 'status',
    tabs: ['security', 'access', 'control'],
    descKey: 'status',
    example: '404|4xx',
  },
  {
    name: 'method',
    tabs: ['access', 'control'],
    descKey: 'method',
    example: 'POST,PUT',
  },
  {
    name: 'cache',
    aliases: ['cache_status'],
    tabs: ['access'],
    descKey: 'cache',
    example: 'hit',
  },
  {
    name: 'latency',
    aliases: ['min_latency_ms'],
    tabs: ['access'],
    descKey: 'latency',
    example: '>500',
  },
  {
    name: 'request_id',
    tabs: ['security', 'access', 'control'],
    descKey: 'requestId',
    example: 'e7a1…',
  },
]

/** Fields valid for `tab`, sorted for the hint chips. */
export function logQueryFieldsFor(tab: LogTab): LogQueryField[] {
  return LOG_QUERY_FIELDS.filter((f) => f.tabs.includes(tab))
}
