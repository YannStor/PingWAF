import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

/**
 * Tooltip 组件契约（前端测试跑在 node 环境，没有 DOM）：它承担图标按钮的
 * 唯一语义提示，因此必须 role=tooltip、关联 aria-describedby、并支持 Esc 关闭。
 */
const source = readFileSync(new URL('./Tooltip.tsx', import.meta.url), 'utf8')

describe('Tooltip', () => {
  it('renders an accessible tooltip element', () => {
    expect(source).toContain('role="tooltip"')
    expect(source).toContain("'aria-describedby'")
    expect(source).toContain('useId')
  })

  it('closes on Escape and blur', () => {
    expect(source).toMatch(/event\.key === 'Escape'/)
    expect(source).toContain('onBlur')
  })
})
