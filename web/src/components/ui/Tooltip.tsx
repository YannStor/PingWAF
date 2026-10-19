import { cloneElement, useId, useState, type ReactElement, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

type Side = 'top' | 'bottom'

export interface TooltipProps {
  /** 提示内容；为空时只渲染子元素。 */
  content: ReactNode
  /** 唯一子元素（通常是一个图标按钮）。 */
  children: ReactElement
  /** 气泡方向，默认上方。 */
  side?: Side
}

interface ChildHandlers {
  onMouseEnter?: () => void
  onMouseLeave?: () => void
  onFocus?: () => void
  onBlur?: () => void
  onKeyDown?: (event: React.KeyboardEvent) => void
}

/**
 * 轻量 tooltip：hover 或 focus 时显示，Esc 与 blur 隐藏。
 *
 * 与原生 `title` 的差异（2026-10-19 E2E 报告 P2）：键盘聚焦同样可见、样式与
 * 主题一致、触屏点击（聚焦）也能拿到提示，并且 `disabled` 的按钮也能显示
 * （事件挂在包裹层而不是按钮本身）。不引入第三方依赖。
 */
export function Tooltip({ content, children, side = 'top' }: TooltipProps) {
  const [open, setOpen] = useState(false)
  const id = useId()
  const handlers = (children.props ?? {}) as ChildHandlers

  const show = () => {
    if (content !== null && content !== undefined && content !== '') {
      setOpen(true)
    }
  }
  const hide = () => setOpen(false)

  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => {
        show()
        handlers.onMouseEnter?.()
      }}
      onMouseLeave={() => {
        hide()
        handlers.onMouseLeave?.()
      }}
      onFocus={() => {
        show()
        handlers.onFocus?.()
      }}
      onBlur={() => {
        hide()
        handlers.onBlur?.()
      }}
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          hide()
        }
        handlers.onKeyDown?.(event)
      }}
    >
      {cloneElement(
        // 泛型放宽到 Record，`aria-describedby` 才是合法属性。
        children as ReactElement<Record<string, unknown>>,
        { 'aria-describedby': open ? id : undefined },
      )}
      {open && (
        <span
          role="tooltip"
          id={id}
          className={cn(
            'pointer-events-none absolute left-1/2 z-50 -translate-x-1/2 whitespace-nowrap rounded-md border border-line bg-elevated px-2 py-1 text-xs text-fg shadow-lg',
            side === 'top' ? 'bottom-full mb-1.5' : 'top-full mt-1.5',
          )}
        >
          {content}
        </span>
      )}
    </span>
  )
}
