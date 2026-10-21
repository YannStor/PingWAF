import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Badge } from '@/components/ui/Badge'
import { Table, type Column } from '@/components/ui/Table'
import { formatSize } from '@/lib/format'
import type { SystemProfileModule } from '@/api/debug'

const MODULE_TONES: Record<string, 'brand' | 'success' | 'warning' | 'danger' | 'neutral'> = {
  proxy: 'brand',
  waf: 'danger',
  waf_normalize: 'warning',
  waf_signature: 'danger',
  waf_expression: 'brand',
  waf_body: 'success',
  cache: 'success',
  plugin: 'warning',
  db: 'neutral',
  control: 'brand',
  log: 'neutral',
  agent: 'brand',
  http_client: 'warning',
  other: 'neutral',
}

/** WAF 子模块在视觉上归入 waf 组（缩进 + 小标签），不影响排序逻辑。 */
const WAF_SUBMODULES = new Set(['waf_normalize', 'waf_signature', 'waf_expression', 'waf_body'])

/**
 * 模块归因表：proxy/waf（含子模块）/cache/plugin/db/control/other/log/agent/http_client。
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
        cell: (m) => {
          const isSub = WAF_SUBMODULES.has(m.module)
          return (
            <span
              className={
                isSub
                  ? 'flex items-center gap-1.5 pl-3'
                  : 'flex items-center gap-1.5'
              }
            >
              <Badge tone={MODULE_TONES[m.module] ?? 'neutral'} className="pw-mono">
                {m.module}
              </Badge>
              {isSub ? (
                <span className="rounded bg-recessed px-1.5 py-0.5 text-[10px] font-medium text-fg-subtle">
                  {t('system.wafSub')}
                </span>
              ) : null}
            </span>
          )
        },
      },
      {
        key: 'elapsed_share',
        header: (
          <span title={t('system.shareHint', '模块耗时占全部归因时间的比例，非 CPU 占比')}>
            {t('system.share')}
          </span>
        ),
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
        cell: (m) => {
          const peak = (m as { mem_peak_bytes?: number }).mem_peak_bytes ?? 0
          const peakShare = (m as { mem_peak_share?: number }).mem_peak_share ?? 0
          if (m.mem_bytes === 0) {
            // 未上报（C3）：当前值与峰值都缺省时不渲染 0 宽度进度条
            if (peak <= 0) {
              return (
                <span
                  className="flex justify-end tabular-nums text-fg-subtle"
                  title={t('system.notReported', 'Not reported')}
                >
                  —
                </span>
              )
            }
            // 当前值为 0 但存在峰值保持：显示峰值并标注 peak
            return (
              <div className="flex items-center justify-end gap-2">
                <div className="h-1.5 w-16 overflow-hidden rounded-full bg-recessed">
                  <div
                    className="h-full rounded-full bg-warning"
                    style={{ width: `${Math.min(100, peakShare * 100)}%` }}
                  />
                </div>
                <span className="w-20 text-right tabular-nums">
                  {formatSize(peak)}
                  <span className="ml-1 rounded bg-recessed px-1 text-[10px] font-medium text-fg-subtle">
                    {t('system.peak', 'peak')}
                  </span>
                </span>
              </div>
            )
          }
          return (
            <div className="flex items-center justify-end gap-2">
              <div className="h-1.5 w-16 overflow-hidden rounded-full bg-recessed">
                <div
                  className="h-full rounded-full bg-success"
                  style={{ width: `${Math.min(100, m.mem_share * 100)}%` }}
                />
              </div>
              <span className="w-20 text-right tabular-nums">
                {formatSize(m.mem_bytes)}
                {m.mem_share > 0 ? (
                  <span className="ml-1 text-fg-subtle">{`${(m.mem_share * 100).toFixed(0)}%`}</span>
                ) : null}
              </span>
            </div>
          )
        },
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
    </div>
  )
}
