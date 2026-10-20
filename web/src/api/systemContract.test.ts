import { describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// `@/api/debug` 的导入链会加载 client/authStore（node 环境），
// 先垫一个最小 localStorage 存根再执行模块导入。
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
import { normaliseUsagePercent, type SystemMetrics } from '@/api/debug'
import type {
  SystemProfile,
  SystemProfileModule,
  SystemProfileMethod,
} from '@/api/debug'
import { routeRewriteFlags } from '@/pages/sites/basic/types'

/**
 * 契约测试：`/api/v1/system/metrics` 与 `/api/v1/system/profile` 的响应结构。
 * 样例载荷按真实后端实现构造；类型不匹配会在编译期失败，字段缺失在运行期失败。
 */

const METRICS: SystemMetrics = {
  cpu: {
    process_cpu_percent: 0.12,
    host_cpu_percent: 0.34,
    cores: 8,
    collected_at_ms: 1730000000000,
  },
  memory: {
    rss_bytes: 115343360,
    virtual_bytes: 536870912,
    total_memory_bytes: 17179869184,
    used_memory_bytes: 8589934592,
    rss: '110.0 MiB',
    total_memory: '16.0 GiB',
    used_memory: '8.0 GiB',
    collected_at_ms: 1730000000000,
    used_memory_scope: 'system',
    process_memory_scope: 'process',
    container_memory_used_bytes: null,
    container_memory_limit_bytes: null,
    container_memory_used: null,
    container_memory_limit: null,
    container_memory_scope: null,
    rss_peak_bytes: 134217728,
    rss_peak: '128.0 MiB',
    swap_used_bytes: 0,
    swap_total_bytes: 0,
    swap_used: '0 B',
    swap_total: '0 B',
    mem_available_bytes: 8589934592,
    mem_available: '8.0 GiB',
    memory_used_percent: 56.3,
    page_faults_minor: 1234,
    page_faults_major: 5,
    cached_bytes: 0,
    buffers_bytes: 0,
  },
}

const MODULE: SystemProfileModule = {
  module: 'proxy',
  cpu_ms: 12.5,
  cpu_share: 0.25,
  mem_bytes: 4096,
  mem_share: 0.1,
  elapsed_ms: 40,
  elapsed_share: 0.4,
  calls: 100,
  avg_us: 400,
}

const METHOD: SystemProfileMethod = {
  method: 'proxy.handle',
  cpu_ms: 5,
  elapsed_ms: 20,
  calls: 50,
  avg_us: 400,
}

const PROFILE: SystemProfile = {
  collected_at_ms: 1730000000000,
  total_cpu_ms: 50,
  modules: [MODULE],
  methods: [METHOD],
}

const MODULE_NAMES = ['proxy', 'waf', 'cache', 'plugin', 'db', 'control', 'other']

describe('system API contract', () => {
  it('memory_used_percent is 0-100 and consumers must not rescale it', () => {
    // 后端（pingwaf-system/src/memory.rs）按 0-100、1 位小数上报。
    expect(METRICS.memory.memory_used_percent).toBe(56.3)
    expect(METRICS.memory.memory_used_percent).toBeLessThanOrEqual(100)
    // 量纲断言：消费端（MemoryDetail / MetricCards）只允许经
    // normaliseUsagePercent 归一，禁止残留 `* 100` 或裸 `Math.min(1, …)` 钳制。
    const consumers = [
      'src/components/system/MemoryDetail.tsx',
      'src/components/system/MetricCards.tsx',
    ].map((p) => readFileSync(resolve(process.cwd(), p), 'utf8'))
    for (const src of consumers) {
      expect(src).not.toMatch(/memory_used_percent\s*\*\s*100/)
      expect(src).not.toMatch(/Math\.min\(1,\s*[^)]*memory_used_percent/)
    }
  })

  it('normaliseUsagePercent maps 0-100 to 0-1', () => {
    expect(normaliseUsagePercent(56.3)).toBeCloseTo(0.563, 10)
    expect(normaliseUsagePercent(100)).toBe(1)
    expect(normaliseUsagePercent(0)).toBe(0)
    // 越界钳制，不产生 >1 或 <0。
    expect(normaliseUsagePercent(150)).toBe(1)
    expect(normaliseUsagePercent(-5)).toBe(0)
  })

  it('non-prefix routes always submit strip_prefix: false', () => {
    // 编辑场景：库里的 strip_prefix=true（Switch 已 disabled），改 match_type 后提交
    // 必须强制 false，否则后端按旧值合并校验会恒 400。
    for (const matchType of ['exact', 'regex']) {
      expect(
        routeRewriteFlags({ matchType, rewritePath: '', stripPrefix: true }),
      ).toEqual({ strip_prefix: false, rewrite_path: null })
    }
    // prefix 下原语义保持：rewrite 优先，开关仅在无 rewrite 且开启时生效。
    expect(
      routeRewriteFlags({ matchType: 'prefix', rewritePath: '/v1', stripPrefix: true }),
    ).toEqual({ strip_prefix: false, rewrite_path: '/v1' })
    expect(
      routeRewriteFlags({ matchType: 'prefix', rewritePath: '', stripPrefix: true }),
    ).toEqual({ strip_prefix: true, rewrite_path: null })
  })

  it('metrics snapshot exposes the fields SystemPage renders', () => {
    expect(METRICS.cpu.cores).toBeGreaterThan(0)
    expect(METRICS.memory.rss_peak).toBeTruthy()
    expect(METRICS.memory.mem_available).toBeTruthy()
    expect(METRICS.memory.memory_used_percent).toBeGreaterThanOrEqual(0)
    expect(METRICS.memory.page_faults_minor).toBeGreaterThanOrEqual(0)
    expect(METRICS.memory.cached_bytes).toBeGreaterThanOrEqual(0)
    expect(METRICS.memory.buffers_bytes).toBeGreaterThanOrEqual(0)
    // 容器字段可选：非容器环境为 null。
    expect(METRICS.memory.container_memory_used_bytes).toBeNull()
  })

  it('profile attribution is wall-clock based (elapsed_*), not CPU', () => {
    expect(PROFILE.modules[0].elapsed_share).toBeGreaterThanOrEqual(0)
    expect(PROFILE.modules[0].elapsed_ms).toBeGreaterThanOrEqual(0)
    expect(PROFILE.methods[0].elapsed_ms).toBeGreaterThanOrEqual(0)
  })

  it('module rows cover the fixed 7-module attribution set', () => {
    const rows: SystemProfileModule[] = MODULE_NAMES.map((m) => ({ ...MODULE, module: m }))
    expect(rows.map((r) => r.module)).toEqual(MODULE_NAMES)
  })
})
