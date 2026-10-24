/**
 * `/system` 控制面卡片的 CPU 展示换算。
 *
 * 抽成独立模块的原因有二：组件文件会连带加载 React 组件链（`authStore`
 * 依赖 `localStorage`），纯函数测试不该被拖进去；而这里的换算正是历史缺陷
 * 的落点，值得有自己的测试。
 *
 * 本模块刻意**不 import `@/api/debug`**：那个 barrel 会牵连 `authStore`，
 * 让纯函数测试在无 DOM 环境下失败。归一逻辑与
 * `normaliseUsagePercent`（`@/api/debug`）保持一致 —— 后端按 0-100 上报，
 * 消费端做**一次**除法换算为 0-1。
 */

/** 0-100 的百分比 → 0-1；越界钳制。 */
function toFraction(percent: number): number {
  return Math.min(1, Math.max(0, percent / 100))
}

/**
 * CPU 读数 → 展示文本。
 *
 * 后端上报的已经是 0-100 的百分比（见 `normaliseUsagePercent` 的契约注释：
 * 「全仓只允许在消费端调用本函数做一次除法，禁止再对原始值做 `* 100`」）。
 * 这里**只做格式化，不做换算** —— 再乘一次 100 会把 5% 显示成 500%，这正是
 * `/system` 控制面卡片出现 500% 的原因。
 */
export function formatCpuPercent(percent: number | null): string {
  if (percent === null || !Number.isFinite(percent)) return '—'
  return `${percent.toFixed(1)}%`
}

/**
 * CPU 百分比 → 进度条宽度；越界值钳制到 [0, 100]。
 *
 * 两个 CPU 字段现在都是整机口径，进度条与文本读同一个数；钳制是最后一道
 * 防线，即便上游回退成单核口径（可到 400），条宽也不会溢出容器。
 */
export function cpuBar(percent: number | null): string | null {
  if (percent === null || !Number.isFinite(percent)) return null
  return `${(toFraction(percent) * 100).toFixed(1)}%`
}