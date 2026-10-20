import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Check, Copy } from '@phosphor-icons/react'
import { Table, type Column } from '@/components/ui/Table'
import type { SystemProfileMethod } from '@/api/debug'

/** Top 方法表：最多 40 行，等宽方法名 + 复制按钮。 */
export function MethodTable({
  methods,
  loading,
}: {
  methods: SystemProfileMethod[] | undefined
  loading: boolean
}) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState<string | null>(null)

  const copy = (method: string) => {
    void navigator.clipboard?.writeText(method)
    setCopied(method)
    window.setTimeout(() => setCopied((c) => (c === method ? null : c)), 1500)
  }

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
        cell: (m) => <span className="tabular-nums">{m.elapsed_ms.toFixed(1)} ms</span>,
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
    [t, copied],
  )

  return (
    <Table
      columns={columns}
      data={methods ?? []}
      rowKey={(m) => m.method}
      loading={loading}
      pageSize={40}
      dense
      empty={
        <div className="py-10 text-center text-sm text-fg-subtle">{t('system.empty')}</div>
      }
    />
  )
}
