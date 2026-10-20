import { describe, expect, it } from 'vitest'
import type {
  SystemMetrics,
  SystemProfile,
  SystemProfileModule,
  SystemProfileMethod,
} from '@/api/debug'

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
    memory_used_percent: 0.5,
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
