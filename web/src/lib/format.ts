/**
 * Presentation helpers shared by every page.
 *
 * The API returns RFC 3339 timestamps and raw counters; the console needs
 * locale-aware, compact and *relative* renderings of both. Keeping the rules
 * here means the logs table, the dashboard and the agents page all agree on
 * what "3 minutes ago" looks like.
 */

const numberFormatter = new Intl.NumberFormat('en-US')

/** `1234567` → `1,234,567`. */
export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—'
  return numberFormatter.format(value)
}

/** `1234567` → `1.2M`. */
export function formatCompactNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—'
  return new Intl.NumberFormat('en-US', {
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(value)
}

/** `0.4231` → `42.3%`. */
export function formatPercent(ratio: number | null | undefined, digits = 1): string {
  if (ratio === null || ratio === undefined || !Number.isFinite(ratio)) return '—'
  return `${(ratio * 100).toFixed(digits)}%`
}

/** `820` → `820 µs`; above 1 ms delegates to {@link formatLatency}. */
export function formatMicros(us: number | null | undefined): string {
  if (us === null || us === undefined || !Number.isFinite(us)) return '—'
  // Round first: 999.6 µs is 1000 µs, which must read as 1.0 ms rather than
  // printing "1000 µs" from the µs branch.
  const rounded = Math.round(us)
  if (rounded < 1000) return `${rounded} µs`
  return formatLatency(us / 1000)
}

/**
 * Tiered latency: `0.8 ms` / `850 ms` / `3.2 s` / `5m 12s` / `3h 05m` / `2d 4h`.
 * Negative or NaN inputs render as `—`.
 */
export function formatLatency(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms < 0) return '—'
  // A genuine zero (cache hit, sub-tick timer) is not "0.0 ms"; keep it short
  // and distinct from a missing value.
  if (ms === 0) return '0 ms'
  if (ms < 1) return `${ms.toFixed(1)} ms`
  if (ms < 1000) return `${Math.round(ms)} ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
  if (ms < 86_400_000) {
    const h = Math.floor(ms / 3_600_000)
    return `${h}h ${String(Math.round((ms % 3_600_000) / 60_000)).padStart(2, '0')}m`
  }
  return `${Math.floor(ms / 86_400_000)}d ${Math.round((ms % 86_400_000) / 3_600_000)}h`
}

/**
 * BCP-47 tag the date formatters use.
 *
 * Defaults to the browser locale, but the i18n layer calls
 * {@link setDisplayLocale} so a console switched to 中文 or 日本語 renders its
 * timestamps in that language instead of whatever the machine happens to run.
 */
let displayLocale: string | undefined = undefined

/** Point the date formatters at a language; called by the i18n layer. */
export function setDisplayLocale(locale: string): void {
  displayLocale = locale
}

interface DateFormatters {
  absolute: Intl.DateTimeFormat
  shortTime: Intl.DateTimeFormat
  shortDate: Intl.DateTimeFormat
  relative: Intl.RelativeTimeFormat
}

const formatterCache = new Map<string, DateFormatters>()

function formatters(): DateFormatters {
  const key = displayLocale ?? 'default'
  const cached = formatterCache.get(key)
  if (cached) return cached
  const locale = displayLocale
  const set: DateFormatters = {
    absolute: new Intl.DateTimeFormat(locale, {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }),
    shortTime: new Intl.DateTimeFormat(locale, {
      hour: '2-digit',
      minute: '2-digit',
    }),
    shortDate: new Intl.DateTimeFormat(locale, {
      month: 'short',
      day: '2-digit',
    }),
    relative: new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }),
  }
  formatterCache.set(key, set)
  return set
}

/** Full local timestamp for table cells and detail rows. */
export function formatDateTime(value: string | number | Date | null | undefined): string {
  const date = toDate(value)
  return date ? formatters().absolute.format(date) : '—'
}

/**
 * Compact log-table timestamp — month/day plus hour:minute, no year and no
 * seconds. Log windows span at most 90 days, so the year is noise.
 */
export function formatLogTime(value: string | number | Date | null | undefined): string {
  const date = toDate(value)
  if (!date) return '—'
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

/** Time only — for a chart axis bucketed within one day. */
export function formatTime(value: string | number | Date | null | undefined): string {
  const date = toDate(value)
  return date ? formatters().shortTime.format(date) : '—'
}

/** Date only — for a chart axis spanning several days. */
export function formatDate(value: string | number | Date | null | undefined): string {
  const date = toDate(value)
  return date ? formatters().shortDate.format(date) : '—'
}

/**
 * Bucket labels adapt to the span: hours inside a day, dates across days.
 * `spanMs` is the total window the series covers.
 */
export function formatBucket(
  value: string | number | Date | null | undefined,
  spanMs: number,
): string {
  const date = toDate(value)
  if (!date) return '—'
  const { shortDate, shortTime } = formatters()
  return spanMs > 36 * 3600_000 ? shortDate.format(date) : shortTime.format(date)
}

function toDate(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null
  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

/** `"3m ago"` / `"in 2h"` — the primary way operators read heartbeat columns. */
export function formatRelative(
  value: string | number | Date | null | undefined,
  now = Date.now(),
): string {
  const date = toDate(value)
  if (!date) return '—'
  const diff = date.getTime() - now
  const abs = Math.abs(diff)

  const rtf = formatters().relative
  if (abs < 45_000) return rtf.format(0, 'minute')
  if (abs < 60_000) return rtf.format(Math.round(diff / 1000), 'second')

  // First row whose upper bound exceeds the gap wins; divide by that row's
  // own unit length so the label and the divisor always agree.
  const ladder: [number, Intl.RelativeTimeFormatUnit, number][] = [
    [3_600_000, 'minute', 60_000],
    [86_400_000, 'hour', 3_600_000],
    [604_800_000, 'day', 86_400_000],
    [2_629_800_000, 'week', 604_800_000],
    [31_557_600_000, 'month', 2_629_800_000],
  ]
  for (const [bound, unit, unitMs] of ladder) {
    if (abs < bound) return rtf.format(Math.round(diff / unitMs), unit)
  }
  return rtf.format(Math.round(diff / 31_557_600_000), 'year')
}

/** `2026-09-25T10:30:00Z` → the `YYYY-MM-DDTHH:mm` shape `<input type=datetime-local>` wants. */
export function toLocalInputValue(value: Date | null | undefined): string {
  if (!value) return ''
  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}` +
    `T${pad(value.getHours())}:${pad(value.getMinutes())}`
  )
}

/** Inverse of {@link toLocalInputValue}; returns `undefined` for an empty field. */
export function fromLocalInputValue(value: string): string | undefined {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}

/** `bytes` → `1.4 MB`, with a fixed unit ladder so columns stay comparable. */
export function formatSize(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return '—'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i += 1
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`
}

/** `bit/s` → `1.3 Mbps`; decimal ladder, as customary for bandwidth. */
export function formatBitrate(bps: number | null | undefined): string {
  if (bps === null || bps === undefined || !Number.isFinite(bps)) return '—'
  if (bps < 1000) return `${Math.round(bps)} bps`
  const units = ['Kbps', 'Mbps', 'Gbps']
  let value = bps / 1000
  let i = 0
  while (value >= 1000 && i < units.length - 1) {
    value /= 1000
    i += 1
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`
}

/** Uppercases an HTTP verb for table cells. */
export function formatMethod(method: string | null | undefined): string {
  return method ? method.toUpperCase() : '—'
}

/** Colour class for an HTTP status: 2xx green, 3xx neutral, 4xx amber, 5xx red. */
export function statusTone(code: number | null | undefined): 'success' | 'neutral' | 'warning' | 'danger' {
  if (code === null || code === undefined) return 'neutral'
  if (code >= 500) return 'danger'
  if (code >= 400) return 'warning'
  if (code >= 300) return 'neutral'
  return 'success'
}
