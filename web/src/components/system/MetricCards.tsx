import type { ReactNode } from 'react'
import { Cpu, Gauge, Memory } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/ui/Card'
import { cn } from '@/lib/utils'
import type { SystemMetrics } from '@/api/debug'

function MetricCard({
  icon,
  label,
  value,
  sub,
}: {
  icon: ReactNode
  label: string
  value: string
  sub?: string
}) {
  return (
    <Card className="p-4">
      <div className="flex items-center gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-brand/10 text-brand">
          {icon}
        </span>
        <div className="min-w-0">
          <p className="truncate text-[11px] text-fg-subtle">{label}</p>
          <p className="text-lg font-semibold text-fg-strong tabular-nums">{value}</p>
          {sub && <p className="truncate text-[11px] text-fg-subtle tabular-nums">{sub}</p>}
        </div>
      </div>
    </Card>
  )
}

/**
 * 概览区：进程 CPU%、主机 CPU%、核心数、容器内存（有则显示，否则以 RSS 补位）。
 */
export function MetricCards({
  metrics,
  loading,
}: {
  metrics: SystemMetrics | undefined
  loading: boolean
}) {
  const { t } = useTranslation()
  const cpu = metrics?.cpu
  const mem = metrics?.memory
  const hasContainer =
    mem?.container_memory_scope != null && mem.container_memory_used_bytes != null

  const dash = '—'
  return (
    <div
      className={cn(
        'grid grid-cols-2 gap-3 lg:grid-cols-4',
        loading && 'opacity-70 transition-opacity',
      )}
    >
      <MetricCard
        icon={<Cpu weight="duotone" className="h-[18px] w-[18px]" />}
        label={t('system.processCpu')}
        value={cpu ? `${cpu.process_cpu_percent.toFixed(1)}%` : dash}
      />
      <MetricCard
        icon={<Gauge weight="duotone" className="h-[18px] w-[18px]" />}
        label={t('system.hostCpu')}
        value={cpu ? `${cpu.host_cpu_percent.toFixed(1)}%` : dash}
      />
      <MetricCard
        icon={<Gauge weight="duotone" className="h-[18px] w-[18px]" />}
        label={t('system.cores')}
        value={cpu ? String(cpu.cores) : dash}
      />
      <MetricCard
        icon={<Memory weight="duotone" className="h-[18px] w-[18px]" />}
        label={hasContainer ? t('system.containerMemory') : t('system.rss')}
        value={
          hasContainer
            ? `${mem?.container_memory_used} / ${mem?.container_memory_limit}`
            : (mem?.rss ?? dash)
        }
        sub={hasContainer ? mem?.container_memory_scope ?? undefined : undefined}
      />
    </div>
  )
}

/** 概览下方的胶囊条：RSS / RSS 峰值 / 可用内存 / 使用率。 */
export function MetricPills({ metrics }: { metrics: SystemMetrics | undefined }) {
  const { t } = useTranslation()
  const mem = metrics?.memory
  if (!mem) return null
  const items = [
    { label: t('system.rss'), value: mem.rss },
    { label: t('system.rssPeak'), value: mem.rss_peak },
    { label: t('system.available'), value: mem.mem_available },
    { label: t('system.usagePercent'), value: `${(mem.memory_used_percent * 100).toFixed(1)}%` },
  ]
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((it) => (
        <span
          key={it.label}
          className="inline-flex items-center gap-1.5 rounded-full border border-line bg-bg-subtle px-3 py-1 text-xs text-fg-subtle"
        >
          {it.label}
          <span className="font-medium text-fg-strong tabular-nums">{it.value}</span>
        </span>
      ))}
    </div>
  )
}
