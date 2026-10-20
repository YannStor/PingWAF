import { useTranslation } from 'react-i18next'
import { Badge } from '@/components/ui/Badge'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Table, type Column } from '@/components/ui/Table'
import { ErrorState } from '@/components/ErrorState'
import { formatRelative, formatSize } from '@/lib/format'
import { normaliseUsagePercent } from '@/api/debug'
import type { SystemAgentNode, SystemControlNode } from '@/api/debug'

/**
 * `/system` 节点区：控制面单卡 + agent 表格。
 *
 * 数据来自 `GET /api/v1/system/nodes`（Admin），由父级以 15s 轮询。
 * agent 的 `cpu_percent`/`memory_bytes`/`connections`/`rps`/`last_seen`
 * 缺失时后端给 null —— 一律渲染 `—`，禁止当 0 显示（0 会读成"空闲"）。
 */
export function NodeSection({
  nodes,
  error,
  loading,
  onRetry,
}: {
  nodes: { control: SystemControlNode; agents: SystemAgentNode[] } | undefined
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
            <CardHeader title={t('system.nodes.agents')} />
            <CardBody>
              <AgentTable agents={nodes?.agents} loading={loading} />
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  )
}

/** 单值行：label + 右对齐值；null/undefined 渲染 `—`。 */
function Metric({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1">
      <span className="text-[13px] text-fg-subtle">{label}</span>
      <span className="text-[13px] font-medium tabular-nums text-fg-strong">{value}</span>
    </div>
  )
}

/** CPU 百分比 → 0-1 供进度条；>1（多核超载）钳制显示。 */
function cpuBar(percent: number | null): string | null {
  if (percent === null || !Number.isFinite(percent)) return null
  return `${Math.min(100, normaliseUsagePercent(percent) * 100)}%`
}

export function ControlNodeCard({ control }: { control: SystemControlNode }) {
  const { t } = useTranslation()
  const pct = (v: number) => `${(v * 100).toFixed(1)}%`
  const processBar = cpuBar(control.process_cpu_percent)
  const hostBar = cpuBar(control.host_cpu_percent)
  return (
    <div className="flex flex-col gap-2">
      <div className="grid grid-cols-1 gap-x-8 sm:grid-cols-2">
        <Metric label={t('system.nodes.processCpu')} value={pct(control.process_cpu_percent)} />
        <Metric label={t('system.nodes.hostCpu')} value={pct(control.host_cpu_percent)} />
        <Metric label={t('system.nodes.cores')} value={String(control.cores)} />
        <Metric label={t('system.nodes.rss')} value={formatSize(control.rss_bytes)} />
        <Metric label={t('system.nodes.rssPeak')} value={formatSize(control.rss_peak_bytes)} />
        <Metric label={t('system.nodes.requests')} value={control.requests.toLocaleString()} />
        <Metric
          label={t('system.nodes.avgElapsed')}
          value={`${control.avg_elapsed_ms.toFixed(1)} ms`}
        />
      </div>
      {(processBar || hostBar) && (
        <div className="flex flex-col gap-1.5 pt-1">
          {processBar && (
            <div className="h-1.5 overflow-hidden rounded-full bg-recessed" aria-hidden>
              <div className="h-full rounded-full bg-brand" style={{ width: processBar }} />
            </div>
          )}
          {hostBar && (
            <div className="h-1.5 overflow-hidden rounded-full bg-recessed" aria-hidden>
              <div className="h-full rounded-full bg-brand/60" style={{ width: hostBar }} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const STATUS_TONE: Record<string, 'success' | 'danger' | 'warning' | 'neutral'> = {
  online: 'success',
  offline: 'danger',
  degraded: 'warning',
}

const NULL_CELL = <span className="text-fg-subtle">—</span>

function AgentTable({
  agents,
  loading,
}: {
  agents: SystemAgentNode[] | undefined
  loading: boolean
}) {
  const { t } = useTranslation()
  const columns = [
    {
      key: 'name',
      header: t('system.nodes.name'),
      accessor: (a: SystemAgentNode) => a.name,
      sortable: true,
      cell: (a: SystemAgentNode) => (
        <span className="pw-mono text-[13px] text-fg">{a.name}</span>
      ),
    },
    {
      key: 'status',
      header: t('system.nodes.status'),
      accessor: (a: SystemAgentNode) => a.status,
      width: '1%',
      cell: (a: SystemAgentNode) => (
        <Badge tone={STATUS_TONE[a.status] ?? 'neutral'}>{a.status}</Badge>
      ),
    },
    {
      key: 'cpu_percent',
      header: t('system.nodes.cpu'),
      align: 'right',
      accessor: (a: SystemAgentNode) => a.cpu_percent ?? -1,
      sortable: true,
      cell: (a: SystemAgentNode) =>
        a.cpu_percent === null || !Number.isFinite(a.cpu_percent) ? (
          NULL_CELL
        ) : (
          <span className="tabular-nums">{`${a.cpu_percent.toFixed(1)}%`}</span>
        ),
    },
    {
      key: 'memory_bytes',
      header: t('system.nodes.memory'),
      align: 'right',
      accessor: (a: SystemAgentNode) => a.memory_bytes ?? -1,
      cell: (a: SystemAgentNode) =>
        a.memory_bytes === null || !Number.isFinite(a.memory_bytes) ? (
          NULL_CELL
        ) : (
          <span className="tabular-nums">{formatSize(a.memory_bytes)}</span>
        ),
    },
    {
      key: 'connections',
      header: t('system.nodes.connections'),
      align: 'right',
      accessor: (a: SystemAgentNode) => a.connections ?? -1,
      cell: (a: SystemAgentNode) =>
        a.connections === null || !Number.isFinite(a.connections) ? (
          NULL_CELL
        ) : (
          <span className="tabular-nums">{a.connections.toLocaleString()}</span>
        ),
    },
    {
      key: 'rps',
      header: t('system.nodes.rps'),
      align: 'right',
      accessor: (a: SystemAgentNode) => a.rps ?? -1,
      cell: (a: SystemAgentNode) =>
        a.rps === null || !Number.isFinite(a.rps) ? (
          NULL_CELL
        ) : (
          <span className="tabular-nums">{a.rps.toFixed(1)}</span>
        ),
    },
    {
      key: 'sites',
      header: t('system.nodes.sites'),
      align: 'right',
      accessor: (a: SystemAgentNode) => a.sites,
      cell: (a: SystemAgentNode) => (
        <span className="tabular-nums">{a.sites.toLocaleString()}</span>
      ),
    },
    {
      key: 'last_seen',
      header: t('system.nodes.lastSeen'),
      accessor: (a: SystemAgentNode) => a.last_seen ?? '',
      cell: (a: SystemAgentNode) =>
        a.last_seen ? (
          <span className="text-[13px] text-fg-subtle">{formatRelative(a.last_seen)}</span>
        ) : (
          NULL_CELL
        ),
    },
  ] satisfies Column<SystemAgentNode>[]

  return (
    <Table
      columns={columns}
      data={agents ?? []}
      rowKey={(a) => a.id}
      loading={loading}
      dense
      empty={
        <div className="py-10 text-center text-sm text-fg-subtle">
          {t('system.nodes.empty')}
        </div>
      }
    />
  )
}
