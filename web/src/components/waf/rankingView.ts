/** 排行表要渲染哪一种状态。 */
export type RankingView = 'rows' | 'loading' | 'error' | 'empty'

/**
 * 从「有没有数据 / 在加载 / 出错」推出该渲染哪一块。
 *
 * 单独成文件是为了能被直接测到：测试跑在 node 环境，没有 DOM，而
 * `TopRankingTables.tsx` 一旦被导入就会连带整棵 UI 组件树与 i18n 初始化。
 *
 * 判定规则：
 * - 有数据就画表，**即使同时出错** —— 这两张表是 60s 轮询的，首载成功后任意
 *   一次后台刷新抖动都会让 `error` 非空而 `data` 仍在，整张表变红会把已经拿到
 *   的排行丢掉。全仓惯例是 `isError && !data`（见 `AgentsPage` / `LogsPage`）。
 * - 没数据时，错误优先于空态，否则一次失败的请求会被读成「没有数据」。
 * - 首载（还没有任何数据）才画骨架屏；后台刷新时保留旧行。
 */
export function rankingView({
  rows,
  loading,
  error,
}: {
  rows: readonly unknown[] | undefined
  loading?: boolean
  error?: unknown
}): RankingView {
  if ((rows?.length ?? 0) > 0) return 'rows'
  if (error) return 'error'
  if (loading) return 'loading'
  return 'empty'
}