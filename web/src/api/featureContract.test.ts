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
    boots: [
      {
        booted_at: '2026-10-22T12:00:00Z',
        reason: 'unclean',
        version: '0.29.3',
        hostname: 'waf-1',
        previous_uptime_seconds: 12,
      },
      {
        booted_at: '2026-10-22T11:59:00Z',
        reason: 'fresh',
        version: '0.29.3',
        hostname: 'waf-1',
        previous_uptime_seconds: null,
      },
    ],
  }

  it('types carry the null-able agent fields; fetchSystemNodes hits /system/nodes', async () => {
    expect(PAYLOAD.agents[0]!.cpu_percent).toBeNull()
    expect(PAYLOAD.agents[0]!.last_seen).toBeNull()
    const src = read('src/api/debug.ts')
    expect(src).toContain("apiClient.get<SystemNodes>('/system/nodes')")
  })

  it('the boot history is typed with a nullable previous uptime', () => {
    // A first boot has no predecessor: the uptime is null, not 0, so the card
    // cannot read "lived 0 seconds".
    expect(PAYLOAD.boots[1]!.previous_uptime_seconds).toBeNull()
    expect(PAYLOAD.boots[0]!.previous_uptime_seconds).toBe(12)
    const src = read('src/api/debug.ts')
    expect(src).toContain('SystemControlPlaneBoot')
    expect(src).toContain('previous_uptime_seconds: number | null')
  })

  it('NodeSection renders the boot history, not an agent table', () => {
    const src = read('src/components/system/NodeSection.tsx')
    // The agent table is gone: the card is the control-plane restart history.
    expect(src).not.toContain('AgentTable')
    expect(src).not.toContain('last_seen')
    expect(src).toContain("t('system.nodes.boots')")
    expect(src).toContain("t('system.nodes.bootsEmpty')")
    expect(src).toContain('boot.previous_uptime_seconds')
  })

  it('an unclean boot is the only reason that reads as danger', () => {
    const src = read('src/components/system/NodeSection.tsx')
    expect(src).toContain('unclean: ')
    expect(src).toContain("REASON_TONE[boot.reason]")
  })

  it('locales carry the boot-history and pool-node keys in every language', () => {
    for (const lang of ['en', 'zh', 'ja']) {
      const parsed = JSON.parse(read(`src/i18n/locales/${lang}/common.json`)) as {
        system: { nodes: Record<string, string> & { reason: Record<string, string> } }
        pages: { origin: Record<string, string> }
      }
      expect(parsed.system.nodes.boots).toBeTruthy()
      expect(parsed.system.nodes.bootsHint).toBeTruthy()
      expect(parsed.system.nodes.bootsEmpty).toBeTruthy()
      expect(parsed.system.nodes.uptimeHint).toBeTruthy()
      // Every reason the API can send has a label, in every language.
      for (const reason of ['fresh', 'after_stop', 'unclean']) {
        expect(parsed.system.nodes.reason[reason], `${lang}.reason.${reason}`).toBeTruthy()
      }
      expect(parsed.pages.origin.poolNodes).toBeTruthy()
      expect(parsed.pages.origin.poolEmpty).toBeTruthy()
    }
  })

  it('the removed agent table leaves no orphan keys behind', () => {
    for (const lang of ['en', 'zh', 'ja']) {
      const parsed = JSON.parse(read(`src/i18n/locales/${lang}/common.json`)) as {
        system: { nodes: Record<string, unknown> }
      }
      for (const gone of ['agents', 'name', 'status', 'memoryTotal', 'memoryUsed', 'lastSeen', 'empty']) {
        expect(parsed.system.nodes[gone], `${lang}.${gone}`).toBeUndefined()
      }
    }
  })

  it('CPU bar uses host_cpu_percent only (process_cpu can exceed 100)', () => {
    const src = read('src/components/system/NodeSection.tsx')
    expect(src).not.toContain('processBar')
    expect(src).toContain('cpuBar(control.host_cpu_percent)')
  })
})

/** 模块表内存列契约（磁盘列已下线；占比不再画条，内存只展示绝对值）。 */
describe('profile module memory column contract', () => {
  it('SystemProfileModule drops disk fields; tables show absolute memory without share bars', () => {
    const api = read('src/api/debug.ts')
    expect(api).not.toContain('disk_bytes')
    expect(api).not.toContain('disk_share')
    expect(api).toContain('total_elapsed_ms')
    expect(api).toMatch(/mem_bytes: number/)
    const table = read('src/components/system/ModuleTable.tsx')
    expect(table).not.toContain("t('system.disk')")
    // The table may pass a fallback as the second argument, so match the call
    // prefix rather than the exact string.
    expect(table).toMatch(/t\('system\.notReported'/)
    // Memory is a bookkeeping estimate with an incomparable denominator, so the
    // tables show bytes (plus a peak line) and draw no share bar.
    expect(table).toContain('formatSize(m.mem_bytes)')
    expect(table).not.toContain('bg-success')
    expect(table).toMatch(/t\('system\.heldHint'/)
    const methods = read('src/components/system/MethodTable.tsx')
    expect(methods).toContain("t('system.held')")
    // The mem_share column is gone on purpose; only absolute bytes remain.
    expect(methods).not.toContain("t('system.memShare')")
    expect(methods).not.toContain('bg-success')
    // Durations scale past a second instead of printing raw milliseconds.
    expect(methods).toContain('formatLatency')
    expect(methods).toContain('formatMicros')
    expect(methods).toContain("'system.sortByElapsed'")
    expect(methods).toContain("'system.sortByMem'")
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
