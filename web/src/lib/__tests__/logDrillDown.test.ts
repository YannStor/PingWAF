import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { RULE_ACTION_TONE, buildLogsDrillDownUrl, ruleActionTone } from '../logDrillDown'
import { fromLocalInputValue } from '../format'

/**
 * 排行表下钻链接必须带上真实的 from/to 窗口。
 *
 * 历史缺陷：两页都只传 `preset`，而日志页在 URL 缺 from/to 时按「页面加载时刻」
 * 的 24h 兜底 —— 于是 30d 的排行点进去实际只查了 24h，选择器却显示 30d。
 */
describe('buildLogsDrillDownUrl', () => {
  const now = new Date('2026-10-23T12:00:00')
  const params = (url: string) => new URL(url, 'http://localhost').searchParams

  it('writes the window out explicitly, so the logs page cannot fall back to 24h', () => {
    const p = params(buildLogsDrillDownUrl({ tab: 'access', q: 'client_ip:1.2.3.4', hours: 720 }, now))
    expect(p.get('tab')).toBe('access')
    expect(p.get('q')).toBe('client_ip:1.2.3.4')
    expect(p.get('preset')).toBe('720')
    // 30 天前的同一时刻，而不是日志页加载时的 24h。
    expect(p.get('to')).toBe('2026-10-23T12:00')
    expect(p.get('from')).toBe('2026-09-23T12:00')
  })

  it('survives the round trip through the logs page own date parsing', () => {
    const p = params(buildLogsDrillDownUrl({ tab: 'security', q: 'rule:xss-1', hours: 24 }, now))
    const spanMs =
      Date.parse(fromLocalInputValue(p.get('to') as string) as string) -
      Date.parse(fromLocalInputValue(p.get('from') as string) as string)
    expect(spanMs).toBe(24 * 3600_000)
  })

  it('scopes to a site only when one is given', () => {
    const scoped = params(
      buildLogsDrillDownUrl({ tab: 'access', q: 'client_ip:1.2.3.4', hours: 1, siteId: 'site-1' }, now),
    )
    expect(scoped.get('site_id')).toBe('site-1')
    const fleet = params(
      buildLogsDrillDownUrl({ tab: 'access', q: 'client_ip:1.2.3.4', hours: 1, siteId: null }, now),
    )
    // 跨站点视角：不带 site_id，否则会把排行统计的其它站点日志排除掉。
    expect(fleet.has('site_id')).toBe(false)
  })
})

/** 处置徽章配色必须与日志页的 ACTION_TONE 一致（两页曾对 log 各用一色）。 */
describe('ruleActionTone', () => {
  it('matches the logs page for every decision the API can send', () => {
    expect(ruleActionTone('block')).toBe('danger')
    expect(ruleActionTone('log')).toBe('info')
    expect(ruleActionTone('challenge')).toBe('warning')
    expect(ruleActionTone('js_challenge')).toBe('warning')
    expect(ruleActionTone('allow')).toBe('success')
    // 数据面的 `action_str(WafAction::Monitor)` 也会写进安全事件。
    expect(ruleActionTone('monitor')).toBe('warning')
  })

  it('falls back to neutral instead of throwing on an unknown decision', () => {
    expect(ruleActionTone('something-new')).toBe('neutral')
  })

  it('every mapped decision has a label in all three locales', () => {
    // `t(\`actions.${action}\`, action)` 在缺键时回退成原始英文值，所以给一个
    // 没有译文的动作配色，会在中/日界面里直接显示 "pass" / "monitor"。
    const missing: string[] = []
    for (const lang of ['en', 'zh', 'ja']) {
      const parsed = JSON.parse(
        readFileSync(resolve(process.cwd(), `src/i18n/locales/${lang}/common.json`), 'utf8'),
      ) as { actions: Record<string, string> }
      for (const action of Object.keys(RULE_ACTION_TONE)) {
        if (!parsed.actions[action]) missing.push(`${lang}.actions.${action}`)
      }
    }
    expect(missing).toEqual([])
  })
})