import { apiClient } from './client'

/**
 * System observability — `/api/v1/system/metrics` 与 `/api/v1/system/profile`（仅 Admin）。
 *
 * - metrics：进程/主机 CPU、内存占用（含容器 cgroup 数值，非容器环境为 null）。
 * - profile：按模块归因的 CPU/内存分布与热点方法（最多 40 行，按 cpu_ms 降序）。
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
  /** 进程 RSS 历史峰值（字节）。 */
  rss_peak_bytes: number
  /** `rss_peak_bytes` 的人类可读形式。 */
  rss_peak: string
  /** Swap 已用量（字节）；无 swap 时为 0。 */
  swap_used_bytes: number
  /** Swap 总量（字节）。 */
  swap_total_bytes: number
  /** `swap_used_bytes` 的人类可读形式。 */
  swap_used: string
  /** `swap_total_bytes` 的人类可读形式。 */
  swap_total: string
  /** 主机可用内存（字节）。 */
  mem_available_bytes: number
  /** `mem_available_bytes` 的人类可读形式。 */
  mem_available: string
  /** 主机内存使用率（0-100，1 位小数，如 `56.3`）。 */
  memory_used_percent: number
  /** 次要缺页次数（累计）。 */
  page_faults_minor: number
  /** 主要缺页次数（累计）。 */
  page_faults_major: number
  /** 主机页缓存（字节）；不可用时为 0。 */
  cached_bytes: number
  /** 主机 Buffer（字节）；不可用时为 0。 */
  buffers_bytes: number
}

/** `GET /api/v1/system/metrics` 响应。 */
export interface SystemMetrics {
  cpu: SystemCpuMetrics
  memory: SystemMemoryMetrics
}

/**
 * 模块归因行 — proxy/waf 及其子模块（waf_normalize/waf_signature/waf_expression/
 * waf_body）、cache/plugin/db/control/other、log/agent/http_client。
 */
export interface SystemProfileModule {
  module: string
  cpu_ms: number
  /** 占总 CPU 的比例（0.0-1.0）。 */
  cpu_share: number
  mem_bytes: number
  /** 占总内存的比例（0.0-1.0）。 */
  mem_share: number
  /** 峰值持有字节（自启动或上次 reset 起）。旧后端不返回。 */
  mem_peak_bytes?: number
  /** 占全部模块峰值之和的比例（0.0-1.0）。 */
  mem_peak_share?: number
  /** 墙钟耗时（毫秒）。⚠️ 口径为墙钟，非 CPU。 */
  elapsed_ms: number
  /** 墙钟耗时占比（0.0-1.0）。⚠️ 口径为墙钟，非 CPU。 */
  elapsed_share: number
  calls: number
  /** 平均单次调用耗时（微秒）。 */
  avg_us: number
}

/** 热点方法行 — 最多 40 行，按 `cpu_ms` 降序。 */
export interface SystemProfileMethod {
  method: string
  cpu_ms: number
  /** 占总 CPU 的比例（0.0-1.0）。 */
  cpu_share: number
  /** 墙钟耗时（毫秒）。⚠️ 口径为墙钟，非 CPU。 */
  elapsed_ms: number
  /** 墙钟耗时占比（0.0-1.0）。⚠️ 口径为墙钟，非 CPU。 */
  elapsed_share: number
  /** 该方法当前持有的内存字节。 */
  mem_bytes: number
  /** 占所属模块内存的比例（0.0-1.0）。 */
  mem_share: number
  /** 峰值持有字节（自启动或上次 reset 起）。旧后端不返回。 */
  mem_peak_bytes?: number
  /** 占全部模块峰值之和的比例（0.0-1.0）。 */
  mem_peak_share?: number
  calls: number
  /** 平均单次调用耗时（微秒）。 */
  avg_us: number
}

/** `GET /api/v1/system/profile` 响应。 */
export interface SystemProfile {
  collected_at_ms: number
  total_cpu_ms: number
  /** 采样窗口总墙钟耗时（毫秒）。 */
  total_elapsed_ms: number
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

/** `GET /api/v1/system/nodes` 控制面节点 — 服务请求的本进程。 */
export interface SystemControlNode {
  /** 本进程 CPU 使用率（单核百分比，可超 100）。 */
  process_cpu_percent: number
  /** 整机 CPU 使用率（百分比）。 */
  host_cpu_percent: number
  /** 逻辑核心数。 */
  cores: number
  /** 进程 RSS（字节）。 */
  rss_bytes: number
  /** 进程 RSS 历史峰值（字节；OS 不暴露时为 0）。 */
  rss_peak_bytes: number
  /** profiler 归因到 control 模块的请求数。 */
  requests: number
  /** 归因到 control 的请求平均墙钟耗时（毫秒）。 */
  avg_elapsed_ms: number
}

/** `GET /api/v1/system/nodes` 单个 agent 节点 — 未知值一律为 null，禁止当 0 渲染。 */
export interface SystemAgentNode {
  id: string
  /** 显示名（节点的 hostname）。 */
  name: string
  /** `online` / `offline` / `degraded` 等最近上报状态。 */
  status: string
  /** 节点 CPU（百分比）；null = 无样本。 */
  cpu_percent: number | null
  /** 节点内存占用（字节）；null = 无样本。 */
  memory_bytes: number | null
  /** 节点物理内存总量（字节）；null = 从未上报。 */
  total_memory_bytes: number | null
  /** 节点内存占用（字节，与 `memory_bytes` 同义的新字段）；null = 无样本。 */
  used_memory_bytes: number | null
  /** 边缘进程当前连接数；null = 从未上报。 */
  connections: number | null
  /** 边缘 RPS；null = 从未上报。 */
  rps: number | null
  /** 节点承载的站点数。 */
  sites: number
  /** 末次心跳（RFC3339）；null = 从未心跳。 */
  last_seen: string | null
}

/**
 * `GET /api/v1/system/nodes` 记录的一次控制平面启动。
 *
 * 控制平面无法宣告自己的死亡（OOM kill 不执行任何代码），因此每次启动写一行；
 * 相邻两行的间隔即上一个进程的存活时长。反复短命启动 = 疑似 OOM/崩溃循环。
 */
export interface SystemControlPlaneBoot {
  /** 启动时刻（RFC3339，服务端时间）。 */
  booted_at: string
  /** `fresh`（无上一行）/ `after_stop`（上一进程活得够久）/ `unclean`（不够久）。 */
  reason: string
  /** 当次启动的版本号。 */
  version: string
  /** 当次启动所在机器。 */
  hostname: string
  /** 上一进程存活秒数；null = 首次启动或时钟回退（不可信）。 */
  previous_uptime_seconds: number | null
}

/** `GET /api/v1/system/nodes` 响应。 */
export interface SystemNodes {
  control: SystemControlNode
  agents: SystemAgentNode[]
  /** 最近的控制平面启动记录，倒序（最新在前）。 */
  boots: SystemControlPlaneBoot[]
}

/** `GET /api/v1/system/nodes`（AdminUser）。 */
export function fetchSystemNodes(): Promise<SystemNodes> {
  return apiClient.get<SystemNodes>('/system/nodes')
}

/**
 * `memory_used_percent` 量纲归一：后端按 0-100（1 位小数）上报，
 * 这里换算为 0-1 供进度条/阈值使用。⚠️ 全仓只允许在消费端调用本函数
 * 做一次除法，禁止再对原始值做 `* 100` 或 `Math.min(1, …)` 钳制。
 */
export function normaliseUsagePercent(v: number): number {
  return Math.min(1, Math.max(0, v / 100))
}

export const debugKeys = {
  all: ['system'] as const,
  metrics: () => [...debugKeys.all, 'metrics'] as const,
  profile: () => [...debugKeys.all, 'profile'] as const,
  nodes: () => [...debugKeys.all, 'nodes'] as const,
}
