import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'
import { ChartDonut } from '@phosphor-icons/react'
import { EmptyState } from '@/components/ui/EmptyState'
import { formatPercent } from '@/lib/format'
import { cn } from '@/lib/utils'

export interface DonutDatum {
  name: string
  value: number
  color: string
}

/**
 * Compact donut chart with a legend listing each slice's name and share of
 * the total. Empty data renders an `EmptyState` placeholder instead of an
 * empty ring.
 */
export function DonutChart({
  data,
  height = 180,
  centerLabel,
  centerValue,
  className,
}: {
  data: DonutDatum[]
  height?: number
  centerLabel?: string
  centerValue?: string
  className?: string
}) {
  const { t } = useTranslation()
  const total = useMemo(() => data.reduce((sum, d) => sum + d.value, 0), [data])

  if (data.length === 0 || total === 0) {
    return (
      <EmptyState
        icon={<ChartDonut weight="duotone" className="h-8 w-8" />}
        title={t('common.noData')}
        className={cn('border-0 py-8', className)}
      />
    )
  }

  return (
    <div className={cn('flex flex-col items-center gap-4 sm:flex-row', className)}>
      <div className="relative shrink-0" style={{ height, width: height }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius="62%"
              outerRadius="92%"
              paddingAngle={2}
              strokeWidth={0}
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        {(centerValue || centerLabel) && (
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            {centerValue && (
              <span className="text-xl font-semibold tabular-nums text-fg-strong">{centerValue}</span>
            )}
            {centerLabel && <span className="mt-0.5 text-[11px] text-fg-subtle">{centerLabel}</span>}
          </div>
        )}
      </div>
      <ul className="min-w-0 flex-1 space-y-1.5">
        {data.map((entry) => (
          <li key={entry.name} className="flex items-center gap-2 text-[13px]">
            <span
              className="h-2.5 w-2.5 shrink-0 rounded-full"
              style={{ backgroundColor: entry.color }}
            />
            <span className="min-w-0 flex-1 truncate text-fg">{entry.name}</span>
            <span className="tabular-nums text-fg-subtle">
              {formatPercent(total > 0 ? entry.value / total : 0)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default DonutChart
