import type { AccessLog } from '@/api/types'

/**
 * Pure builders for the raw-HTTP view in the logs page.
 *
 * Everything here returns text plus Tailwind color classes; the caller renders
 * it as React text nodes, so hostile header or body bytes can never become
 * markup (no `innerHTML`/`dangerouslySetInnerHTML` anywhere on this path).
 */

/** One styled span of a raw message line; `tone` is a text-color class. */
export interface RawToken {
  text: string
  tone?: string
}

/** One line of a raw message, split into colored spans. */
export type RawLine = RawToken[]

/** Text color for a status code, by response class. */
function statusTextTone(code: number | null): string {
  if (code == null) return 'text-fg'
  if (code >= 500) return 'text-fg-danger'
  if (code >= 400) return 'text-warning'
  if (code >= 300) return 'text-link'
  if (code >= 200) return 'text-fg-success'
  return 'text-fg'
}

/** Enough of the registry for the statuses a proxy emits. */
const REASON_PHRASES: Record<number, string> = {
  200: 'OK',
  201: 'Created',
  202: 'Accepted',
  204: 'No Content',
  206: 'Partial Content',
  301: 'Moved Permanently',
  302: 'Found',
  303: 'See Other',
  304: 'Not Modified',
  307: 'Temporary Redirect',
  308: 'Permanent Redirect',
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  406: 'Not Acceptable',
  408: 'Request Timeout',
  409: 'Conflict',
  410: 'Gone',
  413: 'Payload Too Large',
  414: 'URI Too Long',
  415: 'Unsupported Media Type',
  418: "I'm a Teapot",
  422: 'Unprocessable Entity',
  429: 'Too Many Requests',
  499: 'Client Closed Request',
  500: 'Internal Server Error',
  501: 'Not Implemented',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
  505: 'HTTP Version Not Supported',
}

/** `Name: value` with the name highlighted; CR/LF cannot ride along. */
function headerLine(name: string, value: string): RawLine {
  const cleanName = name.replace(/[\r\n]+/g, ' ')
  const cleanValue = value.replace(/[\r\n]+/g, ' ')
  return [
    { text: `${cleanName}: `, tone: 'text-link' },
    { text: cleanValue },
  ]
}

/**
 * Header lines of the captured map, plus the denormalized fields the capture
 * did not repeat (so nothing the row knows is silently missing).
 */
function headerLines(
  raw: Record<string, string> | null | undefined,
  extras: [string, string | null | undefined][],
): RawLine[] {
  const headers = raw ?? {}
  const seen = new Set(Object.keys(headers).map((name) => name.toLowerCase()))
  const lines = Object.entries(headers).map(([name, value]) =>
    headerLine(name, value),
  )
  for (const [name, value] of extras) {
    if (!value || seen.has(name.toLowerCase())) continue
    lines.push(headerLine(name, value))
  }
  return lines
}

/** Matches one JSON token: a string (optionally a key), literal, number or punctuation. */
const JSON_TOKEN_RE =
  /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}[\],])/g

/** Colors the tokens of one pretty-printed JSON line. */
function highlightJsonLine(line: string): RawLine {
  const tokens: RawLine = []
  let last = 0
  for (const match of line.matchAll(JSON_TOKEN_RE)) {
    const at = match.index ?? 0
    if (at > last) tokens.push({ text: line.slice(last, at) })
    const [full, string, colon, literal, number, punctuation] = match
    if (string) {
      tokens.push({
        text: string,
        tone: colon ? 'text-link' : 'text-fg-success',
      })
      if (colon) tokens.push({ text: colon, tone: 'text-fg-subtle' })
    } else if (literal) {
      tokens.push({ text: literal, tone: 'text-warning' })
    } else if (number) {
      tokens.push({ text: number, tone: 'text-brand' })
    } else if (punctuation) {
      tokens.push({ text: punctuation, tone: 'text-fg-subtle' })
    } else {
      tokens.push({ text: full })
    }
    last = at + full.length
  }
  if (last < line.length) tokens.push({ text: line.slice(last) })
  return tokens
}

function isJson(source: string): boolean {
  try {
    JSON.parse(source)
    return true
  } catch {
    return false
  }
}

/** First non-whitespace character from `from`, or `''` at the end. */
function nextNonSpace(source: string, from: number): string {
  for (let i = from; i < source.length; i += 1) {
    const ch = source[i]
    if (ch !== ' ' && ch !== '\n' && ch !== '\t' && ch !== '\r') return ch
  }
  return ''
}

/**
 * Reindents JSON for display without re-serialising it, so numbers keep their
 * exact text — `JSON.parse` + `JSON.stringify` would round large integers.
 */
function prettyJson(source: string): string {
  let out = ''
  let depth = 0
  let inString = false
  let escaped = false
  const containerIsEmpty: boolean[] = []
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i]
    if (inString) {
      out += ch
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === '"') inString = false
      continue
    }
    if (ch === '"') {
      inString = true
      out += ch
      continue
    }
    if (ch === '{' || ch === '[') {
      const closer = ch === '{' ? '}' : ']'
      const empty = nextNonSpace(source, i + 1) === closer
      containerIsEmpty.push(empty)
      depth += 1
      out += empty ? ch : ch + '\n' + '  '.repeat(depth)
      continue
    }
    if (ch === '}' || ch === ']') {
      const empty = containerIsEmpty.pop() ?? false
      depth = Math.max(0, depth - 1)
      out += empty ? ch : '\n' + '  '.repeat(depth) + ch
      continue
    }
    if (ch === ',') {
      out += ',\n' + '  '.repeat(depth)
      continue
    }
    if (ch === ':') {
      out += ': '
      continue
    }
    if (ch === ' ' || ch === '\n' || ch === '\t' || ch === '\r') continue
    out += ch
  }
  return out
}

/** Body lines: JSON is reindented and colored, anything else stays verbatim. */
function bodyLines(body: string | null | undefined, emptyLabel: string): RawLine[] {
  if (!body) return [[{ text: emptyLabel, tone: 'text-fg-subtle' }]]
  if (isJson(body)) {
    return prettyJson(body).split('\n').map(highlightJsonLine)
  }
  return body.split(/\r?\n/).map((line) => [{ text: line }])
}

/** Verbatim request: start line, headers, blank line, body. */
export function requestLines(log: AccessLog, emptyBodyLabel: string): RawLine[] {
  const target = `${log.path ?? '/'}${
    log.query_string ? `?${log.query_string}` : ''
  }`
  const start: RawLine = [
    { text: log.method, tone: 'text-brand font-medium' },
    { text: ' ' },
    { text: target, tone: 'text-fg-strong' },
  ]
  if (log.protocol) {
    start.push({ text: ' ' }, { text: log.protocol, tone: 'text-fg-subtle' })
  }
  return [
    start,
    ...headerLines(log.request_headers, [
      ['Host', log.host],
      ['User-Agent', log.user_agent],
      ['Referer', log.referer],
    ]),
    [],
    ...bodyLines(log.request_body, emptyBodyLabel),
  ]
}

/** Verbatim response: status line, headers, blank line, body. */
export function responseLines(log: AccessLog, emptyBodyLabel: string): RawLine[] {
  const code = log.status_code
  const start: RawLine = []
  if (log.protocol) {
    start.push({ text: log.protocol, tone: 'text-fg-subtle' }, { text: ' ' })
  }
  start.push({
    text: code != null ? String(code) : '—',
    tone: `font-medium ${statusTextTone(code)}`,
  })
  const reason = code != null ? REASON_PHRASES[code] : undefined
  if (reason) {
    start.push({ text: ' ' }, { text: reason, tone: 'text-fg-subtle' })
  }
  return [
    start,
    ...headerLines(log.response_headers, []),
    [],
    ...bodyLines(log.response_body, emptyBodyLabel),
  ]
}
