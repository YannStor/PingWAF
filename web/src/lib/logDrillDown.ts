import { toLocalInputValue } from './format'

/**
 * Deep link from a ranking row into the log rows behind it.
 *
 * Both the dashboard's threat tables and the site traffic page's ranking tables
 * hand off to `/logs`, and both used to pass only `preset`. The logs page reads
 * its window from `from`/`to` and falls back to *the moment the page loads* when
 * they are absent, so a 30-day ranking drilled into a 24-hour query: the range
 * picker said 30d while the result set covered one day. The window is therefore
 * written out explicitly here, from the same `hours` the ranking was computed
 * over — one helper so the two pages cannot drift apart again.
 */

export interface LogDrillDown {
  tab: 'access' | 'security'
  /** Search text in the logs page's own grammar (`client_ip:…`, `rule:…`). */
  q: string
  /** Window the ranking covered, in hours. */
  hours: number
  /** Site to scope to; omit for the cross-site view. */
  siteId?: string | null
}

/**
 * Builds `/logs?…` with an explicit `from`/`to` window. `now` is injectable so
 * the output is testable without freezing the clock.
 *
 * `preset` is written too, but only so the range picker echoes the window that
 * was chosen: the logs page derives its actual query from `from`/`to`, and
 * falls back to *its own* 24-hour default when they are absent — which is the
 * bug this helper exists to prevent.
 */
export function buildLogsDrillDownUrl(
  { tab, q, hours, siteId }: LogDrillDown,
  now: Date = new Date(),
): string {
  const params = new URLSearchParams({ tab, q, preset: String(hours) })
  if (siteId) params.set('site_id', siteId)
  // Same local `YYYY-MM-DDTHH:mm` shape the logs page's pickers use, so the
  // window survives the round trip through `fromLocalInputValue`.
  params.set('to', toLocalInputValue(now))
  params.set('from', toLocalInputValue(new Date(now.getTime() - hours * 3600_000)))
  return `/logs?${params.toString()}`
}

/**
 * Badge tone for a WAF decision, shared by every table that shows one.
 *
 * `TopRulesTable` is the reason this exists: the dashboard rendered `log` as
 * info while the traffic page rendered everything that was not `block` as
 * warning, so aligning the two tables on one of them silently recoloured the
 * dashboard's "log" badges. This is `LogsPage.ACTION_TONE` — the surface an
 * operator compares these tables against — plus `monitor`, which a verdict can
 * also record (`action_str(WafAction::Monitor)` in the data plane).
 *
 * Every key here needs a label in all three locales: `actions.*` falls back to
 * the raw English value, so a decision without a translation renders verbatim
 * ("pass", "monitor") in the Chinese and Japanese UI.
 */
export const RULE_ACTION_TONE: Record<
  string,
  'danger' | 'warning' | 'info' | 'success' | 'neutral'
> = {
  block: 'danger',
  blocked: 'danger',
  challenge: 'warning',
  js_challenge: 'warning',
  log: 'info',
  monitor: 'warning',
  allow: 'success',
  allowed: 'success',
  pass: 'success',
}

/** Tone for a decision, defaulting to neutral for values we do not know. */
export function ruleActionTone(action: string): 'danger' | 'warning' | 'info' | 'success' | 'neutral' {
  return RULE_ACTION_TONE[action] ?? 'neutral'
}