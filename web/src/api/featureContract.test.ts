import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it, vi } from 'vitest'

vi.hoisted(() => {
  const ls = globalThis.localStorage as unknown
  if (typeof ls !== 'object' || ls === null || typeof (ls as { getItem?: unknown }).getItem !== 'function') {
    ;(globalThis as Record<string, unknown>).localStorage = {
      getItem: () => null,
      setItem: () => undefined,
      removeItem: () => undefined,
    }
  }
})
import type { SystemNodes } from '@/api/debug'
import { isValidUpstreamHost } from '@/lib/routeRewrite'

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

/** 节点视图契约：null 缺失值 + control 全量数值字段。 */
describe('GET /api/v1/system/nodes contract', () => {
  const PAYLOAD: SystemNodes = {
    control: {
      process_cpu_percent: 3.2,
      host_cpu_percent: 41.7,
      cores: 8,
      rss_bytes: 115343360,
      rss_peak_bytes: 134217728,
      requests: 42,
      avg_elapsed_ms: 1.5,
    },
    agents: [
      {
        id: '00000000-0000-0000-0000-000000000001',
        name: 'edge-1',
        status: 'online',
        cpu_percent: null,
        memory_bytes: null,
        total_memory_bytes: 8589934592,
        used_memory_bytes: 2147483648,
        connections: 12,
        rps: null,
        sites: 3,
        last_seen: null,
      },
    ],
  }

  it('types carry the null-able agent fields; fetchSystemNodes hits /system/nodes', async () => {
    expect(PAYLOAD.agents[0]!.cpu_percent).toBeNull()
    expect(PAYLOAD.agents[0]!.last_seen).toBeNull()
    const src = read('src/api/debug.ts')
    expect(src).toContain("apiClient.get<SystemNodes>('/system/nodes')")
  })

  it('NodeSection renders missing values as — and empty agents as a placeholder', () => {
    const src = read('src/components/system/NodeSection.tsx')
    expect(src).toContain("t('system.nodes.empty')")
    expect(src).toContain('—')
    expect(src).toContain('formatRelative(a.last_seen)')
  })

  it('agent memory column shows used_memory_bytes ?? memory_bytes with a total tooltip', () => {
    const src = read('src/components/system/NodeSection.tsx')
    expect(src).toContain('a.used_memory_bytes ?? a.memory_bytes')
    expect(src).toContain("t('system.nodes.memoryTotal')")
  })

  it('locales carry the new memory and pool-node keys in every language', () => {
    for (const lang of ['en', 'zh', 'ja']) {
      const parsed = JSON.parse(read(`src/i18n/locales/${lang}/common.json`)) as {
        system: { nodes: Record<string, string> }
        pages: { origin: Record<string, string> }
      }
      expect(parsed.system.nodes.memoryTotal).toBeTruthy()
      expect(parsed.system.nodes.memoryUsed).toBeTruthy()
      expect(parsed.pages.origin.poolNodes).toBeTruthy()
      expect(parsed.pages.origin.poolEmpty).toBeTruthy()
    }
  })

  it('CPU bar uses host_cpu_percent only (process_cpu can exceed 100)', () => {
    const src = read('src/components/system/NodeSection.tsx')
    expect(src).not.toContain('processBar')
    expect(src).toContain('cpuBar(control.host_cpu_percent)')
    // rps 是整数，不做小数位
    expect(src).toContain('a.rps.toFixed(0)')
  })
})

/** 模块表磁盘列契约。 */
describe('profile module disk column contract', () => {
  it('SystemProfileModule carries disk_bytes/disk_share and ModuleTable renders them', () => {
    const api = read('src/api/debug.ts')
    expect(api).toContain('disk_bytes: number')
    expect(api).toContain('disk_share: number')
    const table = read('src/components/system/ModuleTable.tsx')
    expect(table).toContain("t('system.disk')")
    expect(table).toContain("t('system.diskHint')")
  })
})

/** response_replace 提交体契约：rules 为空 → null。 */
describe('site response_replace submit contract', () => {
  it('ResponseReplaceCard sends response_replace via sitesApi.update and nulls an empty rule list', () => {
    const src = read('src/pages/sites/basic/ResponseReplaceCard.tsx')
    expect(src).toContain('sitesApi.update(site.id')
    expect(src).toContain("save.mutate({ response_replace })")
    expect(src).toMatch(/rules\.length === 0\s*\?\s*null/)
  })

  it('locales keep responseReplace and routes.upstreamHost keys in every language', () => {
    for (const lang of ['en', 'zh', 'ja']) {
      const src = read(`src/i18n/locales/${lang}/common.json`)
      for (const key of [
        'responseReplace', 'gzipHint', 'addRule', 'removeRule', 'statusCodes',
      ]) {
        expect(src, `${lang}.responseReplace.${key}`).toContain(`"${key}"`)
      }
      expect(src, `${lang}.upstreamHost`).toContain('"upstreamHost"')
    }
  })
})

/** upstream_host 前端校验与后端 validate_upstream_host 一致。 */
describe('upstream host validation', () => {
  it('mirrors the server: no scheme/path/whitespace, ≤253 bytes', () => {
    expect(isValidUpstreamHost('www.example.com')).toBe(true)
    expect(isValidUpstreamHost('http://x.com')).toBe(false)
    expect(isValidUpstreamHost('a/b')).toBe(false)
    expect(isValidUpstreamHost('a b')).toBe(false)
    expect(isValidUpstreamHost('x'.repeat(254))).toBe(false)
    expect(isValidUpstreamHost('x'.repeat(253))).toBe(true)
  })

  it('rejects C1 control chars and JS line separators like the server', () => {
    expect(isValidUpstreamHost('a\u0080b')).toBe(false)
    expect(isValidUpstreamHost('a\u009fb')).toBe(false)
    expect(isValidUpstreamHost('a\u2028b')).toBe(false)
    expect(isValidUpstreamHost('a\u2029b')).toBe(false)
    expect(isValidUpstreamHost('example.com:8443')).toBe(true)
  })
})
