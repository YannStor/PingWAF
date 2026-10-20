import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { normaliseUsagePercent, type SystemMemoryMetrics } from '@/api/debug'
import { formatSize } from '@/lib/format'

function Row({
  label,
  value,
  children,
}: {
  label: string
  value?: string
  children?: ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-line/60 py-2 last:border-0">
      <span className="text-xs text-fg-subtle">{label}</span>
      {children ?? (
        <span className="text-[13px] font-medium text-fg-strong tabular-nums">{value}</span>
      )}
    </div>
  )
}

/** 内存明细卡：两列键值表，数值右对齐 tabular-nums。 */
export function MemoryDetail({ memory }: { memory: SystemMemoryMetrics | undefined }) {
  const { t } = useTranslation()
  if (!memory) return null
  const mem = memory
  // 后端按 0-100（1 位小数）上报，这里换算为 0-1 供进度条/阈值使用。
  const usagePercent = normaliseUsagePercent(mem.memory_used_percent)
  const tone =
    usagePercent > 0.9 ? 'bg-danger' : usagePercent > 0.75 ? 'bg-warning' : 'bg-brand'

  return (
    <Card>
      <CardHeader title={t('system.memoryDetail')} />
      <CardBody>
        <div className="grid grid-cols-1 gap-x-10 sm:grid-cols-2">
          <div>
            <Row label={t('system.rss')} value={mem.rss} />
            <Row label={t('system.rssPeak')} value={mem.rss_peak} />
            <Row label={t('system.virtual')} value={formatSize(mem.virtual_bytes)} />
            <Row label={t('system.swap')} value={`${mem.swap_used} / ${mem.swap_total}`} />
            <Row label={t('system.available')} value={mem.mem_available} />
          </div>
          <div>
            <Row label={t('system.usagePercent')}>
              <div className="flex items-center gap-2">
                <div
                  className="h-1.5 w-28 overflow-hidden rounded-full bg-recessed"
                  role="progressbar"
                  aria-valuenow={Math.round(usagePercent * 100)}
                  aria-valuemin={0}
                  aria-valuemax={100}
                >
                  <div
                    className={`h-full rounded-full ${tone}`}
                    style={{ width: `${usagePercent * 100}%` }}
                  />
                </div>
                <span className="text-[13px] font-medium text-fg-strong tabular-nums">
                  {mem.memory_used_percent.toFixed(1)}%
                </span>
              </div>
            </Row>
            <Row
              label={t('system.pageFaults')}
              value={`${mem.page_faults_minor.toLocaleString()} / ${mem.page_faults_major.toLocaleString()}`}
            />
            <Row label={t('system.cached')} value={formatSize(mem.cached_bytes)} />
            <Row label={t('system.buffers')} value={formatSize(mem.buffers_bytes)} />
          </div>
        </div>
      </CardBody>
    </Card>
  )
}
