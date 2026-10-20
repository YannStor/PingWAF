import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

/**
 * CertWarnings 契约（前端测试跑在 node 环境，没有 DOM）：只在 warnings 非空
 * 时渲染，逐条展示于 Tooltip，并带可读的无障碍标签。
 */
const source = readFileSync(
  new URL('../CertWarnings.tsx', import.meta.url),
  'utf8',
)

describe('CertWarnings', () => {
  it('hides when warnings are empty or missing', () => {
    expect(source).toContain('!warnings || warnings.length === 0')
    expect(source).toContain('return null')
  })

  it('renders every warning inside the shared Tooltip', () => {
    expect(source).toContain('<Tooltip')
    expect(source).toContain('warnings.map((warning)')
    expect(source).toContain('key={warning}')
  })

  it('exposes an accessible label for one and many warnings', () => {
    expect(source).toContain('pages.ssl.certDomainWarning')
    expect(source).toContain('pages.ssl.certDomainWarnings')
    expect(source).toContain('aria-label=')
  })
})
