import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Check, Copy } from '@phosphor-icons/react'
import { Table, type Column } from '@/components/ui/Table'
import { formatLatency, formatMicros, formatSize } from '@/lib/format'
import type { SystemProfileMethod } from '@/api/debug'

type MethodSort = 'elapsed' | 'mem'

/** Top 方法表：最多 40 行，等宽方法名 + 复制按钮；支持按耗时/按内存排序。 */
export function MethodTable({
  methods,
  loading,
}: {
  methods: SystemProfileMethod[] | undefined
  loading: boolean
}) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState<string | null>(null)
  const [sortBy, setSortBy] = useState<MethodSort>('elapsed')

  const copy = (method: string) => {
    void navigator.clipboard?.writeText(method)
    setCopied(method)
    window.setTimeout(() => setCopied((c) => (c === method ? null : c)), 1500)
  }

  const sorted = useMemo(() => {
    const list = [...(methods ?? [])]
    list.sort((a, b) => (sortBy === 'elapsed' ? b.elapsed_ms - a.elapsed_ms : b.mem_bytes - a.mem_bytes))
    return list
  }, [methods, sortBy])

  const columns = useMemo<Column<SystemProfileMethod>[]>(
    () => [
      {
        key: 'method',
        header: t('system.method'),
        accessor: (m) => m.method,
        cell: (m) => (
          <span className="flex items-center gap-1.5">
            <span className="pw-mono max-w-[420px] truncate" title={m.method}>
              {m.method}
            </span>
            <button
              type="button"
              aria-label={t('common.copy')}
              title={t('common.copy')}
              className="shrink-0 rounded p-0.5 text-fg-subtle/50 transition-colors hover:text-fg"
              onClick={(e) => {
                e.stopPropagation()
                copy(m.method)
              }}
            >
              {copied === m.method ? (
                <Check weight="bold" className="h-3.5 w-3.5 text-success" />
              ) : (
                <Copy weight="regular" className="h-3.5 w-3.5" />
              )}
            </button>
          </span>
        ),
      },
      {
        key: 'elapsed_ms',
        header: t('system.elapsed'),
        accessor: (m) => m.elapsed_ms,
        align: 'right',
        sortable: true,
        cell: (m) => <span className="tabular-nums">{formatLatency(m.elapsed_ms)}</span>,
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
    [t, copied],
  )

  return (
    <div>
      <div className="mb-2 flex items-center gap-1.5 text-xs">
        <span className="text-fg-subtle">{t('system.sortBy')}</span>
        {(
          [
            ['elapsed', 'system.sortByElapsed'],
            ['mem', 'system.sortByMem'],
          ] as const
        ).map(([value, key]) => (
          <button
            key={value}
            type="button"
            aria-pressed={sortBy === value}
            className={
              sortBy === value
                ? 'rounded-full bg-brand/10 px-2.5 py-1 font-medium text-brand'
                : 'rounded-full px-2.5 py-1 text-fg-subtle transition-colors hover:text-fg'
            }
            onClick={() => setSortBy(value)}
          >
            {t(key)}
          </button>
        ))}
      </div>
      <Table
        columns={columns}
        data={sorted}
        rowKey={(m) => m.method}
        loading={loading}
        pageSize={40}
        dense
        empty={
          <div className="py-10 text-center text-sm text-fg-subtle">{t('system.empty')}</div>
        }
      />
    </div>
  )
}
