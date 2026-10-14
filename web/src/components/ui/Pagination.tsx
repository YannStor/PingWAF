import { CaretLeft, CaretRight } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { Button } from './Button'
import { cn } from '@/lib/utils'

export interface PaginationProps {
  /** 1-based current page. */
  page: number
  pageSize: number
  total: number
  onChange: (page: number) => void
  className?: string
  /** Page-size picker values; omit to hide the control. */
  pageSizeOptions?: number[]
  onPageSizeChange?: (size: number) => void
  /**
   * True when `total` is a lower bound: the server capped the count, so
   * the true count is larger. Renders "10000+" instead of "10000"; page
   * numbers only cover the capped window.
   */
  totalTruncated?: boolean
}

/** Window of page numbers rendered around the current one. */
function pageWindow(page: number, pageCount: number): (number | 'gap')[] {
  if (pageCount <= 7) return Array.from({ length: pageCount }, (_, i) => i + 1)
  const out: (number | 'gap')[] = [1]
  const from = Math.max(2, page - 1)
  const to = Math.min(pageCount - 1, page + 1)
  if (from > 2) out.push('gap')
  for (let p = from; p <= to; p += 1) out.push(p)
  if (to < pageCount - 1) out.push('gap')
  out.push(pageCount)
  return out
}

/**
 * Server-side pagination control.
 *
 * `Table` only knows how to slice a fully-loaded array; the logs and agents
 * endpoints page on the server (and must — a busy site writes millions of
 * events), so those pages drive this component instead.
 */
export function Pagination({
  page,
  pageSize,
  total,
  onChange,
  className,
  pageSizeOptions,
  onPageSizeChange,
  totalTruncated,
}: PaginationProps) {
  const { t } = useTranslation()
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(total, page * pageSize)

  return (
    <div
      className={cn(
        'flex flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-3',
        className,
      )}
    >
      <div className="flex items-center gap-3 text-[13px] text-fg-subtle">
        <span>
          {t('pagination.showing', {
            from,
            to,
            total: totalTruncated ? `${total}+` : total,
          })}
        </span>
        {pageSizeOptions && onPageSizeChange && (
          <label className="flex items-center gap-1.5">
            <span className="sr-only">{t('pagination.perPage')}</span>
            <select
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              className="h-7 rounded-md border border-line bg-elevated px-1.5 text-[13px] text-fg"
            >
              {pageSizeOptions.map((size) => (
                <option key={size} value={size}>
                  {size} / {t('pagination.page')}
                </option>
              ))}
            </select>
          </label>
        )}
      </div>

      <nav aria-label={t('pagination.label')} className="flex items-center gap-1">
        <Button
          size="icon"
          variant="ghost"
          aria-label={t('pagination.previous')}
          disabled={page <= 1}
          onClick={() => onChange(page - 1)}
          icon={<CaretLeft weight="bold" className="h-4 w-4" />}
        />
        {pageWindow(page, pageCount).map((entry, i) =>
          entry === 'gap' ? (
            <span key={`gap-${i}`} className="px-1.5 text-[13px] text-fg-subtle">
              …
            </span>
          ) : (
            <button
              key={entry}
              type="button"
              aria-current={entry === page ? 'page' : undefined}
              onClick={() => onChange(entry)}
              className={cn(
                'h-8 min-w-8 rounded-md px-2 text-[13px] font-medium transition-colors',
                entry === page
                  ? 'bg-brand text-white'
                  : 'text-fg-subtle hover:bg-recessed hover:text-fg',
              )}
            >
              {entry}
            </button>
          ),
        )}
        <Button
          size="icon"
          variant="ghost"
          aria-label={t('pagination.next')}
          disabled={page >= pageCount}
          onClick={() => onChange(page + 1)}
          icon={<CaretRight weight="bold" className="h-4 w-4" />}
        />
      </nav>
    </div>
  )
}

export default Pagination
