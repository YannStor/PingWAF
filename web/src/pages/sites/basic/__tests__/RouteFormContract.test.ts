import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

describe('route form strip_prefix / rewrite_path contract', () => {
  it('RouteDialog renders both fields with the i18n keys', () => {
    const src = read('src/pages/sites/basic/RouteDialog.tsx')
    expect(src).toContain("t('pages.routes.stripPrefix')")
    expect(src).toContain("t('pages.routes.stripPrefixHint')")
    expect(src).toContain("t('pages.routes.rewritePath')")
    expect(src).toContain("t('pages.routes.rewritePathHint')")
    expect(src).toContain('strip_prefix:')
    expect(src).toContain('rewrite_path:')
  })

  it('disables both controls for non-prefix match types and when rewrite wins', () => {
    const src = read('src/pages/sites/basic/RouteDialog.tsx')
    expect(src).toMatch(/matchType !== 'prefix'/)
    expect(src).toMatch(/rewritePath\.trim\(\) !== ''/)
  })

  it('types expose the new fields on Route and both request shapes', () => {
    const src = read('src/api/types.ts')
    expect(src.match(/strip_prefix\??: boolean/g)?.length).toBe(3)
    expect(src.match(/rewrite_path\??: string \| null/g)?.length).toBe(3)
  })

  it('locales keep the preset keys in every language', () => {
    for (const lang of ['en', 'zh', 'ja']) {
      const src = read(`src/i18n/locales/${lang}/common.json`)
      for (const key of [
        'stripPrefix',
        'stripPrefixHint',
        'rewritePath',
        'rewritePathHint',
      ]) {
        expect(src, `${lang}.${key}`).toContain(`"${key}"`)
      }
    }
  })
})
