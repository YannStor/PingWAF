import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Badge } from '@/components/ui/Badge'
import { Table, type Column } from '@/components/ui/Table'
import { formatMicros, formatPercent, formatSize } from '@/lib/format'
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
          <span className="block text-right tabular-nums">
            {formatPercent(m.elapsed_share)}
          </span>
        ),
      },
      {
        key: 'mem_bytes',
        header: (
          <span title={t('system.heldHint', '记账式估算：仅统计已埋点的持有内存，非堆分配归因')}>
            {t('system.held')}
          </span>
        ),
        accessor: (m) => m.mem_bytes,
        align: 'right',
        sortable: true,
        cell: (m) => {
          const peak = (m as { mem_peak_bytes?: number }).mem_peak_bytes ?? 0
          if (m.mem_bytes === 0 && peak <= 0) {
            return (
              <span
                className="flex justify-end tabular-nums text-fg-subtle"
                title={t('system.notReported', 'Not reported')}
              >
                —
              </span>
            )
          }
          return (
            <div className="flex flex-col items-end">
              <span className="tabular-nums">
                {formatSize(m.mem_bytes)}
              </span>
              {peak > m.mem_bytes ? (
                <span className="text-[11px] text-fg-subtle tabular-nums">
                  {t('system.peak', 'peak')} {formatSize(peak)}
                </span>
              ) : null}
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
        cell: (m) => <span className="tabular-nums">{formatMicros(m.avg_us)}</span>,
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
