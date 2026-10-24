import { useTranslation } from 'react-i18next'
import { Badge } from '@/components/ui/Badge'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { ErrorState } from '@/components/ErrorState'
import { formatDateTime, formatLatency, formatSize } from '@/lib/format'
import { cpuBar, formatCpuPercent } from './cpuDisplay'
import type { SystemControlNode, SystemControlPlaneBoot } from '@/api/debug'

/**
 * `/system` 控制面区：本进程资源卡 + 最近 5 次启动记录。
 *
 * 数据来自 `GET /api/v1/system/nodes`（Admin），由父级以 15s 轮询。
 *
 * 为什么是"启动"而不是"离线"：控制平面被 OOM kill 或崩溃时不会执行任何代码，
 * 死亡瞬间无法写记录；它唯一能说话的时刻是**启动**。所以每行是一次启动，相邻
 * 两行的间隔就是上一个进程的存活时长 —— 几分钟内出现多次启动，就是重启循环。
 */
export function NodeSection({
  nodes,
  error,
  loading,
  onRetry,
}: {
  nodes:
    | { control: SystemControlNode; boots: SystemControlPlaneBoot[] }
    | undefined
  error: unknown
  loading: boolean
  onRetry: () => void
}) {
  const { t } = useTranslation()

  return (
    <div className="mt-4">
      <p className="mb-2 text-xs font-medium uppercase tracking-wide text-fg-subtle">
        {t('system.nodes.title')}
      </p>
      {error ? (
        <ErrorState
          variant="inline"
          error={error}
          onRetry={onRetry}
          retrying={loading}
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          {nodes?.control && (
            <Card>
              <CardHeader title={t('system.nodes.control')} />
              <CardBody>
                <ControlNodeCard control={nodes.control} />
              </CardBody>
            </Card>
          )}
          <Card className={nodes?.control ? '' : 'xl:col-span-2'}>
            <CardHeader
              title={t('system.nodes.boots')}
              description={t('system.nodes.bootsHint')}
            />
            <CardBody>
              <BootHistory boots={nodes?.boots} loading={loading} />
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  )
}

/** 单值行：label + 右对齐值。 */
function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1">
      <span className="text-[13px] text-fg-subtle">{label}</span>
      <span className="text-[13px] font-medium tabular-nums text-fg-strong">{value}</span>
    </div>
  )
}

export function ControlNodeCard({ control }: { control: SystemControlNode }) {
  const { t } = useTranslation()
  const processBar = cpuBar(control.process_cpu_percent)
  const hostBar = cpuBar(control.host_cpu_percent)
  return (
    <div className="flex flex-col gap-2">
      <div className="grid grid-cols-1 gap-x-8 sm:grid-cols-2">
        <Metric
          label={t('system.nodes.processCpu')}
          value={formatCpuPercent(control.process_cpu_percent)}
        />
        <Metric
          label={t('system.nodes.hostCpu')}
          value={formatCpuPercent(control.host_cpu_percent)}
        />
        <Metric label={t('system.nodes.cores')} value={String(control.cores)} />
        <Metric label={t('system.nodes.rss')} value={formatSize(control.rss_bytes)} />
        <Metric label={t('system.nodes.rssPeak')} value={formatSize(control.rss_peak_bytes)} />
        <Metric label={t('system.nodes.requests')} value={control.requests.toLocaleString()} />
        <Metric
          label={t('system.nodes.avgElapsed')}
          value={formatLatency(control.avg_elapsed_ms)}
        />
      </div>
      {(processBar || hostBar) && (
        <div className="flex flex-col gap-1.5 pt-1">
          {processBar && (
            <div
              className="h-1.5 overflow-hidden rounded-full bg-recessed"
              aria-hidden
              title={t('system.nodes.processCpu')}
            >
              <div className="h-full rounded-full bg-brand/60" style={{ width: processBar }} />
            </div>
          )}
          {hostBar && (
            <div
              className="h-1.5 overflow-hidden rounded-full bg-recessed"
              aria-hidden
              title={t('system.nodes.hostCpu')}
            >
              <div className="h-full rounded-full bg-brand/30" style={{ width: hostBar }} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/** 启动原因 → Badge 色调：`unclean` 是唯一需要警惕的状态。 */
const REASON_TONE: Record<string, 'success' | 'danger' | 'neutral'> = {
  fresh: 'neutral',
  after_stop: 'success',
  unclean: 'danger',
}

/**
 * 存活时长的可读形式。
 *
 * 秒级（重启循环）是这里最要紧的读数，所以短时长保留秒；超过一天才换算成天，
 * 避免 "172800s" 这种读不出量级的数字。
 */
function formatUptime(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds) || seconds < 0) return '—'
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86_400) return `${(seconds / 3600).toFixed(1)}h`
  return `${(seconds / 86_400).toFixed(1)}d`
}

function BootHistory({
  boots,
  loading,
}: {
  boots: SystemControlPlaneBoot[] | undefined
  loading: boolean
}) {
  const { t } = useTranslation()

  if (!boots || boots.length === 0) {
    return (
      <div className="py-10 text-center text-sm text-fg-subtle">
        {loading ? t('system.nodes.loading') : t('system.nodes.bootsEmpty')}
      </div>
    )
  }

  return (
    <ul className="flex flex-col">
      {boots.map((boot, index) => (
        <li
          key={`${boot.booted_at}-${index}`}
          className="flex items-center justify-between gap-3 border-b border-border py-2 last:border-b-0"
        >
          <div className="flex min-w-0 flex-col gap-0.5">
            <span className="pw-mono text-[13px] tabular-nums text-fg-strong">
              {formatDateTime(boot.booted_at)}
            </span>
            <span className="truncate text-xs text-fg-subtle">
              {boot.hostname} · v{boot.version}
            </span>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <span
              className="text-[13px] tabular-nums text-fg-subtle"
              title={t('system.nodes.uptimeHint')}
            >
              {formatUptime(boot.previous_uptime_seconds)}
            </span>
            <Badge tone={REASON_TONE[boot.reason] ?? 'neutral'}>
              {t(`system.nodes.reason.${boot.reason}`, boot.reason)}
            </Badge>
          </div>
        </li>
      ))}
    </ul>
  )
}