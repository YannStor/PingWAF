import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Badge } from '@/components/ui/Badge'
import { Table, type Column } from '@/components/ui/Table'
import { formatSize } from '@/lib/format'
import type { SystemProfileModule } from '@/api/debug'

const MODULE_TONES: Record<string, 'brand' | 'success' | 'warning' | 'danger' | 'neutral'> = {
  proxy: 'brand',
  waf: 'danger',
  cache: 'success',
  plugin: 'warning',
  db: 'neutral',
  control: 'brand',
  other: 'neutral',
}

/**
 * 模块归因表：固定 7 行（proxy/waf/cache/plugin/db/control/other）。
 * 「耗时占比」为墙钟耗时占比（elapsed_share），非 CPU。
 */
export function ModuleTable({
  modules,
  loading,
}: {
  modules: SystemProfileModule[] | undefined
  loading: boolean
}) {
  const { t } = useTranslation()
  const columns = useMemo<Column<SystemProfileModule>[]>(
    () => [
      {
        key: 'module',
        header: t('system.module'),
        accessor: (m) => m.module,
        sortable: true,
        cell: (m) => (
          <Badge tone={MODULE_TONES[m.module] ?? 'neutral'} className="pw-mono">
            {m.module}
          </Badge>
        ),
      },
      {
        key: 'elapsed_share',
        header: t('system.share'),
        accessor: (m) => m.elapsed_share,
        sortable: true,
        cell: (m) => (
          <div className="flex items-center justify-end gap-2">
            <div className="h-1.5 w-24 overflow-hidden rounded-full bg-recessed">
              <div
                className="h-full rounded-full bg-brand"
                style={{ width: `${Math.min(100, m.elapsed_share * 100)}%` }}
              />
            </div>
            <span className="w-14 text-right tabular-nums">
              {(m.elapsed_share * 100).toFixed(1)}%
            </span>
          </div>
        ),
      },
      {
        key: 'mem_bytes',
        header: t('system.held'),
        accessor: (m) => m.mem_bytes,
        align: 'right',
        sortable: true,
        cell: (m) => <span className="tabular-nums">{formatSize(m.mem_bytes)}</span>,
      },
      {
        key: 'disk_bytes',
        header: t('system.disk'),
        accessor: (m) => m.disk_bytes,
        align: 'right',
        sortable: true,
        cell: (m) => (
          <div className="flex items-center justify-end gap-2">
            <div className="h-1.5 w-16 overflow-hidden rounded-full bg-recessed">
              <div
                className="h-full rounded-full bg-success"
                style={{ width: `${Math.min(100, (m.disk_share ?? 0) * 100)}%` }}
              />
            </div>
            <span className="w-20 text-right tabular-nums">
              {formatSize(m.disk_bytes)}
              {m.disk_share > 0 ? (
                <span className="ml-1 text-fg-subtle">{`${(m.disk_share * 100).toFixed(0)}%`}</span>
              ) : null}
            </span>
          </div>
        ),
      },
      {
        key: 'calls',
        header: t('system.calls'),
        accessor: (m) => m.calls,
        align: 'right',
        sortable: true,
        cell: (m) => <span className="tabular-nums">{m.calls.toLocaleString()}</span>,
      },
      {
        key: 'avg_us',
        header: t('system.avgTime'),
        accessor: (m) => m.avg_us,
        align: 'right',
        sortable: true,
        cell: (m) => <span className="tabular-nums">{m.avg_us.toFixed(1)} µs</span>,
      },
    ],
    [t],
  )

  return (
    <div>
      <Table
        columns={columns}
        data={modules ?? []}
        rowKey={(m) => m.module}
        loading={loading}
        dense
        empty={
          <div className="py-10 text-center text-sm text-fg-subtle">{t('system.empty')}</div>
        }
      />
      <p className="mt-2 text-xs text-fg-subtle">{t('system.diskHint')}</p>
    </div>
  )
}
