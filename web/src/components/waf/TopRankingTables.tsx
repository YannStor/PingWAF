import { useMemo, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Lightning, ShieldSlash } from '@phosphor-icons/react'
import { countryFlag } from '@/api/geo'
import { IpQuickActions } from '@/components/waf/IpQuickActions'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { Table, type Column } from '@/components/ui/Table'
import { formatNumber } from '@/lib/format'
import { ruleActionTone } from '@/lib/logDrillDown'
import { rankingView } from './rankingView'
import type { TopIp, TopRule } from '@/api/types'

/**
 * 「威胁 IP 排行 / 触发规则排行」的唯一实现。
 *
 * Dashboard 与站点流量页各有一张同样的表，历史上是两份分别手写的 JSX，于是
 * 国旗、拦截徽章、行内下钻、数量上限逐项漂移（2026-10-23 对齐）。现在两张表
 * 只有这一处实现：两页各自保留合理的卡片标题/描述，表格本身完全一致。
 *
 * 加载态、空态、行内错误态也在这里统一 —— 站点流量页此前没有加载态，会先渲染
 * 一张空表再突然填充。
 *
 * 表头文案取自 `pages.traffic.*`：两页共用同一列定义，Dashboard 那一列的措辞
 * 因此由 traffic 命名空间决定（「请求数 / 已拦截 / 命中次数 / 独立 IP」）。
 */

interface RankingState {
  loading?: boolean
  error?: unknown
  onRetry?: () => void
}

/** 统一的加载/错误/空态外壳；有数据时才渲染表格。 */
function RankingBody({
  rows,
  loading,
  error,
  onRetry,
  empty,
  children,
}: RankingState & {
  rows: readonly unknown[] | undefined
  empty: ReactNode
  children: ReactNode
}) {
  switch (rankingView({ rows, loading, error })) {
    case 'rows':
      return <>{children}</>
    case 'error':
      return (
        <div className="p-4">
          <ErrorState variant="inline" error={error} onRetry={onRetry} />
        </div>
      )
    case 'loading':
      return <SkeletonRows rows={5} columns={4} />
    default:
      return <>{empty}</>
  }
}

export interface TopIpsTableProps extends RankingState {
  rows: TopIp[] | undefined
  /**
   * 快捷操作的目标站点：站点流量页用页面站点，Dashboard 用该 IP 最近活跃的
   * 站点（`top_site_id`）。返回空值时按钮禁用并给出提示。
   */
  siteIdFor?: (row: TopIp) => string | null | undefined
  onRowClick?: (row: TopIp) => void
  /** 空态文案按页给（Dashboard 讲威胁，流量页只是没数据）。 */
  emptyTitle?: string
  emptyDescription?: string
}

/** 威胁/热门客户端 IP：国旗 + IP、请求数、拦截徽章、快捷操作。 */
export function TopIpsTable({
  rows,
  loading,
  error,
  onRetry,
  siteIdFor,
  onRowClick,
  emptyTitle,
  emptyDescription,
}: TopIpsTableProps) {
  const { t } = useTranslation()

  const columns = useMemo<Column<TopIp>[]>(
    () => [
      {
        key: 'client_ip',
        header: t('pages.traffic.clientIp'),
        accessor: (r) => r.client_ip,
        cell: (r) => (
          <div className="flex items-center gap-2">
            <span className="text-base leading-none">{countryFlag(r.country_code ?? '')}</span>
            <span className="pw-mono text-[13px] text-fg-strong">{r.client_ip}</span>
          </div>
        ),
      },
      {
        key: 'requests',
        header: t('pages.traffic.requests'),
        accessor: (r) => r.requests,
        align: 'right',
        sortable: true,
        width: '1%',
        cell: (r) => (
          <span className="tabular-nums text-[13px] text-fg">{formatNumber(r.requests)}</span>
        ),
      },
      {
        key: 'blocked',
        header: t('pages.traffic.blocked'),
        accessor: (r) => r.blocked,
        align: 'right',
        sortable: true,
        width: '1%',
        cell: (r) =>
          r.blocked > 0 ? (
            <Badge tone="danger" size="sm">
              {formatNumber(r.blocked)}
            </Badge>
          ) : (
            <span className="text-[13px] text-fg-subtle">0</span>
          ),
      },
      {
        key: 'actions',
        header: t('pages.dashboard.quickActions'),
        align: 'right',
        // 两个图标按钮的固定宽度：'1%' 会让单元格收缩包裹内容，把列撑宽并在移动端
        // 触发横向滚动（2026-10-19 E2E）。
        width: '96px',
        // 行本身可点击（下钻日志）。不拦冒泡的话点「封禁」会同时弹出确认框并
        // 导航到日志页，确认框随页面卸载而消失 —— 操作直接丢失。
        cell: (r) => (
          <div onClick={(e) => e.stopPropagation()}>
            <IpQuickActions ip={r.client_ip} siteId={siteIdFor ? siteIdFor(r) : null} />
          </div>
        ),
      },
    ],
    [t, siteIdFor],
  )

  return (
    <RankingBody
      rows={rows}
      loading={loading}
      error={error}
      onRetry={onRetry}
      empty={
        // `border-0` only: `cn` is plain concatenation (no tailwind-merge), so
        // overriding the background here would depend on utility ordering.
        // This matches every other in-card empty state on the traffic page.
        <EmptyState
          className="border-0 py-10"
          icon={<ShieldSlash weight="duotone" className="h-7 w-7" />}
          title={emptyTitle ?? t('common.noData')}
          description={emptyDescription}
        />
      }
    >
      <Table
        columns={columns}
        data={rows ?? []}
        rowKey={(r) => r.client_ip}
        dense
        onRowClick={onRowClick}
      />
    </RankingBody>
  )
}

export interface TopRulesTableProps extends RankingState {
  rows: TopRule[] | undefined
  onRowClick?: (row: TopRule) => void
  emptyTitle?: string
  emptyDescription?: string
}

/** 触发规则排行：规则名、处置徽章、命中次数、独立 IP 数。 */
export function TopRulesTable({
  rows,
  loading,
  error,
  onRetry,
  onRowClick,
  emptyTitle,
  emptyDescription,
}: TopRulesTableProps) {
  const { t } = useTranslation()

  const columns = useMemo<Column<TopRule>[]>(
    () => [
      {
        key: 'rule_name',
        header: t('pages.traffic.rule'),
        // 早期事件只带规则 ID —— 显示它而不是一个空单元格。
        accessor: (r) => r.rule_name || r.rule_id,
        cell: (r) => (
          <span className="text-[13px] font-medium text-fg-strong">
            {r.rule_name || r.rule_id}
          </span>
        ),
      },
      {
        key: 'action',
        header: t('pages.waf.action'),
        accessor: (r) => r.action,
        width: '1%',
        cell: (r) => (
          <Badge tone={ruleActionTone(r.action)} size="sm">
            {t(`actions.${r.action}`, r.action)}
          </Badge>
        ),
      },
      {
        key: 'hits',
        header: t('pages.traffic.hits'),
        accessor: (r) => r.hits,
        align: 'right',
        sortable: true,
        width: '1%',
        cell: (r) => (
          <span className="tabular-nums text-[13px] text-fg">{formatNumber(r.hits)}</span>
        ),
      },
      {
        key: 'unique_ips',
        header: t('pages.traffic.uniqueIps'),
        accessor: (r) => r.unique_ips,
        align: 'right',
        width: '1%',
        cell: (r) => (
          <span className="tabular-nums text-[13px] text-fg-subtle">
            {formatNumber(r.unique_ips)}
          </span>
        ),
      },
    ],
    [t],
  )

  return (
    <RankingBody
      rows={rows}
      loading={loading}
      error={error}
      onRetry={onRetry}
      empty={
        <EmptyState
          className="border-0 py-10"
          icon={<Lightning weight="duotone" className="h-7 w-7" />}
          title={emptyTitle ?? t('common.noData')}
          description={emptyDescription}
        />
      }
    >
      <Table
        columns={columns}
        data={rows ?? []}
        rowKey={(r) => r.rule_id}
        dense
        onRowClick={onRowClick}
      />
    </RankingBody>
  )
}