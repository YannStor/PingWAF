import { apiClient } from './client'

/**
 * System observability — `/api/v1/system/metrics` 与 `/api/v1/system/profile`（仅 Admin）。
 *
 * - metrics：进程/主机 CPU、内存占用（含容器 cgroup 数值，非容器环境为 null）。
 * - profile：按模块归因的 CPU/内存分布（固定 7 行）与热点方法（最多 40 行，按 cpu_ms 降序）。
 */

/** 进程/主机 CPU 快照。 */
export interface SystemCpuMetrics {
  /** 本进程 CPU 使用率（百分比，0.0-1.0）。 */
  process_cpu_percent: number
  /** 整机 CPU 使用率（百分比，0.0-1.0）。 */
  host_cpu_percent: number
  /** 逻辑核心数。 */
  cores: number
  /** 采样时间（Unix 毫秒）。 */
  collected_at_ms: number
}

/** 内存快照 — `rss_bytes`/`virtual_bytes` 为进程自身占用，`used_memory_bytes` 为主机内存。 */
export interface SystemMemoryMetrics {
  /** 进程 RSS（字节）。 */
  rss_bytes: number
  /** 进程虚拟内存（字节）。 */
  virtual_bytes: number
  /** 主机物理内存总量（字节）。 */
  total_memory_bytes: number
  /** 主机已用内存（字节）。 */
  used_memory_bytes: number
  /** `rss_bytes` 的人类可读形式，如 "110.0 MiB"。 */
  rss: string
  /** `total_memory_bytes` 的人类可读形式。 */
  total_memory: string
  /** `used_memory_bytes` 的人类可读形式。 */
  used_memory: string
  /** 采样时间（Unix 毫秒）。 */
  collected_at_ms: number
  /** `used_memory_*` 的口径标识，恒为 `"system"`（主机内存）。 */
  used_memory_scope: string
  /** `rss_bytes`/`virtual_bytes` 的口径标识，恒为 `"process"`（进程自身）。 */
  process_memory_scope: string
  /** 容器内存用量（cgroup v2 `memory.current` / v1 `usage_in_bytes`）；非受限容器为 null。 */
  container_memory_used_bytes?: number | null
  /** 容器内存上限；cgroup 未设限时为 null。 */
  container_memory_limit_bytes?: number | null
  /** `container_memory_used_bytes` 的人类可读形式。 */
  container_memory_used?: string | null
  /** `container_memory_limit_bytes` 的人类可读形式。 */
  container_memory_limit?: string | null
  /** `"cgroup_v1" | "cgroup_v2"`；容器外为 null。 */
  container_memory_scope?: string | null
}

/** `GET /api/v1/system/metrics` 响应。 */
export interface SystemMetrics {
  cpu: SystemCpuMetrics
  memory: SystemMemoryMetrics
}

/** 模块归因行 — 固定 7 行：proxy/waf/cache/plugin/db/control/other。 */
export interface SystemProfileModule {
  module: string
  cpu_ms: number
  /** 占总 CPU 的比例（0.0-1.0）。 */
  cpu_share: number
  mem_bytes: number
  /** 占总内存的比例（0.0-1.0）。 */
  mem_share: number
  calls: number
  /** 平均单次调用耗时（微秒）。 */
  avg_us: number
}

/** 热点方法行 — 最多 40 行，按 `cpu_ms` 降序。 */
export interface SystemProfileMethod {
  method: string
  cpu_ms: number
  calls: number
  avg_us: number
}

/** `GET /api/v1/system/profile` 响应。 */
export interface SystemProfile {
  collected_at_ms: number
  total_cpu_ms: number
  modules: SystemProfileModule[]
  methods: SystemProfileMethod[]
}

/** `GET /api/v1/system/metrics`（AdminUser）。 */
export function fetchSystemMetrics(): Promise<SystemMetrics> {
  return apiClient.get<SystemMetrics>('/system/metrics')
}

/** `GET /api/v1/system/profile`（AdminUser）。 */
export function fetchSystemProfile(): Promise<SystemProfile> {
  return apiClient.get<SystemProfile>('/system/profile')
}

export const debugKeys = {
  all: ['system'] as const,
  metrics: () => [...debugKeys.all, 'metrics'] as const,
  profile: () => [...debugKeys.all, 'profile'] as const,
}
