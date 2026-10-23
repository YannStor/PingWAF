import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { rankingView } from './rankingView'

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

/**
 * Dashboard 与站点流量页的「威胁 IP 排行 / 触发规则排行」必须只有一处实现。
 *
 * 历史问题：两张表分别手写，国旗、拦截徽章、行内下钻、数量上限逐项漂移
 * （2026-10-23 对齐）。这组断言把"共用同一个组件"固定下来 —— 任何一页重新
 * 长出自己的一套列定义都会失败。
 *
 * 这里只做源码级契约断言（测试跑在 node 环境，没有 DOM）；下钻 URL 与徽章
 * 配色的行为断言在 `src/lib/__tests__/logDrillDown.test.ts`。
 */
describe('top ranking tables are shared between the dashboard and site traffic', () => {
  it('both pages render the shared component and define no columns of their own', () => {
    for (const page of [
      'src/pages/DashboardPage.tsx',
      'src/pages/sites/TrafficPage.tsx',
    ]) {
      const src = read(page)
      expect(src, page).toContain('TopIpsTable')
      expect(src, page).toContain('TopRulesTable')
      // 本页不再自带 IP/规则列定义（pathColumns 属于 Top paths，保留）。
      expect(src, page).not.toMatch(/const\s+ipColumns\b/)
      expect(src, page).not.toMatch(/const\s+ruleColumns\b/)
    }
  })

  it('the shared tables keep the aligned rendering the two pages drifted apart on', () => {
    const src = read('src/components/waf/TopRankingTables.tsx')
    // 国旗 emoji + 等宽 IP（Dashboard 曾只显示国家代码文本）。
    expect(src).toContain('countryFlag(r.country_code')
    expect(src).toContain('pw-mono')
    // 拦截数 >0 用 danger 徽章（Dashboard 曾用红色文本）。
    expect(src).toMatch(/Badge tone="danger" size="sm"/)
    // 规则名单行 + 早期事件只有 rule_id 时显示 ID。
    expect(src).toContain('r.rule_name || r.rule_id')
    // 处置徽章走共享的 tone 映射，而不是各自内联三元表达式。
    expect(src).toContain('ruleActionTone(r.action)')
    expect(src).not.toMatch(/r\.action === 'block' \? 'danger'/)
    // 加载 / 错误 / 空态统一。
    expect(src).toContain('SkeletonRows')
    expect(src).toContain('ErrorState')
    expect(src).toContain('EmptyState')
  })

  it('a failed query renders the error, never an empty state', () => {
    // 错误分支必须在空态之前，否则一次失败的请求会被读成「没有数据」。
    expect(rankingView({ rows: undefined, error: new Error('boom') })).toBe('error')
    expect(rankingView({ rows: [], error: new Error('boom') })).toBe('error')
    // 首载还没有数据时才画骨架屏。
    expect(rankingView({ rows: undefined, loading: true })).toBe('loading')
    // 真的没有数据才是空态。
    expect(rankingView({ rows: [], loading: false })).toBe('empty')
  })

  it('a failed background refetch keeps the rows already on screen', () => {
    // 这两张表是 60s 轮询的：首载成功后任意一次刷新抖动都会让 error 非空而
    // data 仍在，此时整表变红会把已拿到的排行丢掉（全仓惯例 isError && !data）。
    expect(rankingView({ rows: [{ client_ip: '1.2.3.4' }], error: new Error('boom') })).toBe('rows')
  })

  it('both pages drill down into the matching log rows through the shared builder', () => {
    for (const page of [
      'src/pages/DashboardPage.tsx',
      'src/pages/sites/TrafficPage.tsx',
    ]) {
      const src = read(page)
      expect(src, page).toMatch(/drillDown\('access'/)
      expect(src, page).toMatch(/drillDown\('security'/)
      // 窗口由共享的构建器写入（只传 preset 会让日志页回落到 24h）。
      expect(src, page).toContain('buildLogsDrillDownUrl')
      expect(src, page).not.toContain('LOGS_PRESET')
    }
  })
})