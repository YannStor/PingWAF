import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

/**
 * Quick actions 必须是纯图标按钮（`size="icon"` + tooltip），否则 Dashboard 与
 * 站点流量页会渲染成"图标 + 文字"——2026-10-19 E2E 里正是这个形态让图标化
 * 改动看起来"未生效"。这里对源文件做契约断言（前端测试跑在 node 环境，没有 DOM）。
 */
const source = readFileSync(
  new URL('./IpQuickActions.tsx', import.meta.url),
  'utf8',
)

/** 按钮区域：去掉 JSX 注释，并截到 ConfirmDialog 之前。 */
const actions = source
  .replace(/\{\/\*[\s\S]*?\*\/\}/g, '')
  .split('<ConfirmDialog')[0]

describe('IpQuickActions', () => {
  it('renders both actions as icon-only buttons', () => {
    expect(actions.match(/size="icon"/g)).toHaveLength(2)
    // 可见文字子节点会把按钮撑成 icon+label，正是本次修复的回归点。
    expect(source).not.toMatch(
      />\s*\{t\('components\.ipQuickActions\.(blockLabel|challengeLabel)'\)\}\s*</,
    )
  })

  it('keeps tooltip and accessible name on both buttons', () => {
    expect(actions.match(/aria-label=/g)).toHaveLength(2)
    expect(actions.match(/title=\{/g)).toHaveLength(2)
  })
})
