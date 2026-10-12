import { useMemo, useState, type ReactNode } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import {
  ChartLine,
  ArrowClockwise,
  Globe,
  Users,
  ShieldSlash,
  Timer,
  UploadSimple,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Table, type Column } from '@/components/ui/Table'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonStat } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ErrorState'
import { trafficApi, trafficKeys, RANGE_HOURS, TRAFFIC_STEP, groupStatusCodes } from '@/api/traffic'
import { countryFlag, geoApi, geoKeys } from '@/api/geo'
import { WorldMapChart } from '@/components/charts/WorldMapChart'
import { cn } from '@/lib/utils'
import {
  formatBitrate,
  formatBucket,
  formatCompactNumber,
  formatLatency,
  formatNumber,
  formatPercent,
  formatSize,
} from '@/lib/format'
import { TRAFFIC_RANGES, type TopIp, type TopRule, type TrafficRange } from '@/api/types'

const PIE_COLORS = ['#18794e', '#0051c3', '#ffb224', '#e54d2a']

/** Traffic range → logs page `preset` (hours). */
const LOGS_PRESET: Record<TrafficRange, string> = {
  '1h': '1',
  '6h': '6',
  '24h': '24',
  '7d': '168',
  '30d': '720',
}

const tooltipStyle = {
  background: 'var(--color-bg-elevated)',
  border: '1px solid var(--color-border-line)',
  borderRadius: 8,
  fontSize: 12,
  color: 'var(--color-text-default)',
}

/**
 * Every traffic widget, for one site or for the whole fleet.
 *
 * Passing `siteId` scopes the query to that site; omitting it asks the control
 * plane for the aggregate across every site the caller may see, which is what
 * the global traffic page renders.
 */
export function TrafficPanels({ siteId }: { siteId?: string }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [range, setRange] = useState<TrafficRange>('24h')

  const scoped = siteId !== undefined

  // Top IPs and top rules double as entry points into the matching log rows.
  const drillDown = (tab: 'access' | 'security', q: string) => {
    const params = new URLSearchParams({ tab, q, preset: LOGS_PRESET[range] })
    if (siteId) params.set('site_id', siteId)
    navigate(`/logs?${params.toString()}`)
  }

  const overviewQuery = useQuery({
    queryKey: trafficKeys.overview(siteId, range),
    queryFn: () => trafficApi.overview(siteId, range),
    enabled: scoped ? Boolean(siteId) : true,
    refetchInterval: 60_000,
  })

  const data = overviewQuery.data
  const spanMs = RANGE_HOURS[range] * 3600_000

  // Per-country requests for the world map. The site-scoped endpoint keeps a
  // fixed 24h window; the aggregate endpoint follows the selected range.
  const geoStatsQuery = useQuery({
    queryKey: scoped
      ? geoKeys.stats(siteId as string)
      : geoKeys.globalStats(RANGE_HOURS[range]),
    queryFn: () =>
      scoped
        ? geoApi.stats(siteId as string)
        : geoApi.globalStats({ hours: RANGE_HOURS[range], limit: 250 }),
    enabled: scoped ? Boolean(siteId) : true,
    refetchInterval: 60_000,
  })
  const geoStats = geoStatsQuery.data ?? []

  const seriesData = useMemo(
    () =>
      (data?.series ?? []).map((b) => ({
        label: formatBucket(b.bucket, spanMs),
        requests: b.requests,
        passed: Math.max(0, b.requests - b.blocked),
        blocked: b.blocked,
        latency: b.avg_latency_ms,
      })),
    [data, spanMs],
  )

  // Egress per bucket, converted to a bit rate so the axis reads as Mbps/Kbps.
  const egress = data?.egress
  const egressData = useMemo(() => {
    const step = egress?.step_seconds ?? TRAFFIC_STEP[range]
    return (egress?.buckets ?? []).map((b) => ({
      label: formatBucket(b.bucket, spanMs),
      bps: (b.bytes * 8) / step,
    }))
  }, [egress, spanMs, range])

  const avgBitrate =
    egress && spanMs > 0 ? (egress.total_bytes * 8) / (spanMs / 1000) : 0

  const pathData = useMemo(
    () => (data?.topPaths ?? []).map((p) => ({ path: p.path, requests: p.requests })),
    [data],
  )

  const statusData = useMemo(
    () => groupStatusCodes(data?.statusCodes ?? []),
    [data],
  )

  const summary = data?.summary
  const blockRate =
    summary && summary.requests > 0 ? summary.blocked_requests / summary.requests : 0

  const ipColumns: Column<TopIp>[] = [
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
  ]

  const ruleColumns: Column<TopRule>[] = [
    {
      key: 'rule_name',
      header: t('pages.traffic.rule'),
      // Older events carry only the rule id — show it rather than a blank cell.
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
        <Badge tone={r.action === 'block' ? 'danger' : 'warning'} size="sm">
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
  ]

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1 rounded-lg bg-recessed p-1">
          {TRAFFIC_RANGES.map((r) => (
            <button
              key={r}
              type="button"
              onClick={() => setRange(r)}
              className={cn(
                'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                range === r
                  ? 'bg-elevated text-fg-strong shadow-sm'
                  : 'text-fg-subtle hover:text-fg',
              )}
            >
              {r}
            </button>
          ))}
        </div>
        <Button
          className="ml-auto"
          variant="secondary"
          loading={overviewQuery.isFetching}
          onClick={() => overviewQuery.refetch()}
          icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
        >
          {t('common.refresh')}
        </Button>
      </div>

      {/* Summary */}
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-5">
        {overviewQuery.isPending && !data ? (
          <>
            <SkeletonStat />
            <SkeletonStat />
            <SkeletonStat />
            <SkeletonStat />
            <SkeletonStat />
          </>
        ) : (
          <>
            <SummaryCard
              icon={<ChartLine weight="duotone" className="h-4 w-4" />}
              label={t('pages.traffic.totalRequests')}
              value={formatCompactNumber(summary?.requests ?? 0)}
            />
            <SummaryCard
              icon={<UploadSimple weight="duotone" className="h-4 w-4" />}
              label={t('pages.traffic.totalEgress')}
              value={formatSize(egress?.total_bytes ?? 0)}
            />
            <SummaryCard
              icon={<Users weight="duotone" className="h-4 w-4" />}
              label={t('pages.traffic.uniqueIps')}
              value={formatCompactNumber(summary?.unique_ips ?? 0)}
            />
            <SummaryCard
              icon={<ShieldSlash weight="duotone" className="h-4 w-4" />}
              label={t('pages.traffic.blockRate')}
              value={formatPercent(blockRate)}
              tone="danger"
            />
            <SummaryCard
              icon={<Timer weight="duotone" className="h-4 w-4" />}
              label={t('pages.traffic.avgLatency')}
              value={formatLatency(summary?.avg_latency_ms ?? 0)}
            />
          </>
        )}
      </div>

      {overviewQuery.isError && !data ? (
        <ErrorState
          error={overviewQuery.error}
          onRetry={() => overviewQuery.refetch()}
          retrying={overviewQuery.isFetching}
        />
      ) : (
        <div className="flex flex-col gap-6">
          {/* Requests over time */}
          <Card>
            <CardHeader
              title={t('pages.traffic.requestsOverTime')}
              description={t('pages.traffic.requestsOverTimeHint')}
            />
            <CardBody>
              {seriesData.length === 0 ? (
                <EmptyState
                  className="border-0 py-10"
                  icon={<ChartLine weight="duotone" className="h-8 w-8" />}
                  title={t('pages.traffic.noTraffic')}
                />
              ) : (
                <div className="h-72 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={seriesData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                      <defs>
                        <linearGradient id="trafficReq" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#f6821f" stopOpacity={0.35} />
                          <stop offset="100%" stopColor="#f6821f" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="trafficBlock" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#e54d2a" stopOpacity={0.3} />
                          <stop offset="100%" stopColor="#e54d2a" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border-line)" vertical={false} />
                      <XAxis
                        dataKey="label"
                        tick={{ fontSize: 11, fill: 'var(--color-text-subtle)' }}
                        tickLine={false}
                        axisLine={{ stroke: 'var(--color-border-line)' }}
                        minTickGap={24}
                      />
                      <YAxis
                        tick={{ fontSize: 11, fill: 'var(--color-text-subtle)' }}
                        tickLine={false}
                        axisLine={false}
                        tickFormatter={(v: number) => formatCompactNumber(v)}
                      />
                      <Tooltip contentStyle={tooltipStyle} formatter={(v) => formatNumber(Number(v ?? 0))} />
                      <Legend wrapperStyle={{ fontSize: 12 }} iconType="circle" />
                      <Area type="monotone" dataKey="passed" name={t('pages.traffic.passed')} stroke="#18794e" strokeWidth={2} fill="transparent" />
                      <Area type="monotone" dataKey="requests" name={t('pages.traffic.requests')} stroke="#f6821f" strokeWidth={2} fill="url(#trafficReq)" />
                      <Area type="monotone" dataKey="blocked" name={t('pages.traffic.blocked')} stroke="#e54d2a" strokeWidth={2} fill="url(#trafficBlock)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardBody>
          </Card>

          {/* Egress bandwidth */}
          <Card>
            <CardHeader
              title={t('pages.traffic.bandwidth')}
              description={t('pages.traffic.egressHint')}
            />
            <CardBody>
              {egressData.length === 0 ? (
                <EmptyState
                  className="border-0 py-10"
                  icon={<UploadSimple weight="duotone" className="h-8 w-8" />}
                  title={t('pages.traffic.noTraffic')}
                />
              ) : (
                <>
                  <div className="mb-4 flex flex-wrap gap-x-10 gap-y-3">
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
                        {t('pages.traffic.totalEgress')}
                      </p>
                      <p className="mt-1 text-xl font-semibold tabular-nums text-fg-strong">
                        {formatSize(egress?.total_bytes ?? 0)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-fg-subtle">
                        {t('pages.traffic.avgBitrate')}
                      </p>
                      <p className="mt-1 text-xl font-semibold tabular-nums text-fg-strong">
                        {formatBitrate(avgBitrate)}
                      </p>
                    </div>
                  </div>
                  <div className="h-56 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={egressData} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
                        <defs>
                          <linearGradient id="trafficEgress" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#2f6fed" stopOpacity={0.35} />
                            <stop offset="100%" stopColor="#2f6fed" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border-line)" vertical={false} />
                        <XAxis
                          dataKey="label"
                          tick={{ fontSize: 11, fill: 'var(--color-text-subtle)' }}
                          tickLine={false}
                          axisLine={{ stroke: 'var(--color-border-line)' }}
                          minTickGap={24}
                        />
                        <YAxis
                          tick={{ fontSize: 11, fill: 'var(--color-text-subtle)' }}
                          tickLine={false}
                          axisLine={false}
                          width={64}
                          tickFormatter={(v: number) => formatBitrate(v)}
                        />
                        <Tooltip
                          contentStyle={tooltipStyle}
                          formatter={(v) => formatBitrate(Number(v ?? 0))}
                        />
                        <Area
                          type="monotone"
                          dataKey="bps"
                          name={t('pages.traffic.bandwidth')}
                          stroke="#2f6fed"
                          strokeWidth={2}
                          fill="url(#trafficEgress)"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </>
              )}
            </CardBody>
          </Card>

          {/* Geographic distribution */}
          <Card>
            <CardHeader
              title={t('pages.traffic.geoMap.title')}
              description={
                scoped
                  ? t('pages.traffic.geoMap.hintSite')
                  : t('pages.traffic.geoMap.hint')
              }
              action={<Globe weight="duotone" className="h-4 w-4 text-fg-subtle" />}
            />
            <CardBody>
              {geoStatsQuery.isPending && !geoStatsQuery.data ? (
                <div className="h-64 animate-pulse rounded-lg bg-recessed" />
              ) : geoStatsQuery.isError ? (
                <ErrorState
                  error={geoStatsQuery.error}
                  onRetry={() => geoStatsQuery.refetch()}
                  retrying={geoStatsQuery.isFetching}
                />
              ) : geoStats.length === 0 ? (
                <EmptyState
                  className="border-0 py-10"
                  icon={<Globe weight="duotone" className="h-8 w-8" />}
                  title={t('common.noData')}
                />
              ) : (
                <WorldMapChart data={geoStats} />
              )}
            </CardBody>
          </Card>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Top paths */}
            <Card>
              <CardHeader title={t('pages.traffic.topPaths')} />
              <CardBody>
                {pathData.length === 0 ? (
                  <EmptyState className="border-0 py-8" title={t('common.noData')} />
                ) : (
                  <div className="h-72 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={pathData} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border-line)" horizontal={false} />
                        <XAxis type="number" tick={{ fontSize: 11, fill: 'var(--color-text-subtle)' }} tickLine={false} axisLine={false} tickFormatter={(v: number) => formatCompactNumber(v)} />
                        <YAxis type="category" dataKey="path" width={120} tick={{ fontSize: 11, fill: 'var(--color-text-subtle)' }} tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={tooltipStyle} formatter={(v) => formatNumber(Number(v ?? 0))} cursor={{ fill: 'var(--color-bg-recessed)' }} />
                        <Bar dataKey="requests" name={t('pages.traffic.requests')} fill="#f6821f" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardBody>
            </Card>

            {/* Status codes */}
            <Card>
              <CardHeader title={t('pages.traffic.statusCodes')} />
              <CardBody>
                {statusData.length === 0 ? (
                  <EmptyState className="border-0 py-8" title={t('common.noData')} />
                ) : (
                  <div className="h-72 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={statusData}
                          dataKey="requests"
                          nameKey="family"
                          cx="50%"
                          cy="50%"
                          innerRadius={55}
                          outerRadius={90}
                          paddingAngle={2}
                        >
                          {statusData.map((entry, i) => (
                            <Cell key={entry.family} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={tooltipStyle} formatter={(v) => formatNumber(Number(v ?? 0))} />
                        <Legend wrapperStyle={{ fontSize: 12 }} iconType="circle" />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardBody>
            </Card>
          </div>

          {/* Latency over time */}
          <Card>
            <CardHeader title={t('pages.traffic.latency')} description={t('pages.traffic.latencyHint')} />
            <CardBody>
              {seriesData.length === 0 ? (
                <EmptyState className="border-0 py-8" title={t('common.noData')} />
              ) : (
                <div className="h-56 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={seriesData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border-line)" vertical={false} />
                      <XAxis dataKey="label" tick={{ fontSize: 11, fill: 'var(--color-text-subtle)' }} tickLine={false} axisLine={{ stroke: 'var(--color-border-line)' }} minTickGap={24} />
                      <YAxis tick={{ fontSize: 11, fill: 'var(--color-text-subtle)' }} tickLine={false} axisLine={false} tickFormatter={(v: number) => `${Math.round(v)}ms`} />
                      <Tooltip contentStyle={tooltipStyle} formatter={(v) => formatLatency(Number(v ?? 0))} />
                      <Line type="monotone" dataKey="latency" name={t('pages.traffic.avgLatency')} stroke="#0051c3" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardBody>
          </Card>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Top IPs */}
            <Card>
              <CardHeader
                title={t('pages.traffic.topIps')}
                action={<Globe weight="duotone" className="h-4 w-4 text-fg-subtle" />}
              />
              <CardBody className="p-0">
                <Table
                  columns={ipColumns}
                  data={data?.topIps ?? []}
                  rowKey={(r) => r.client_ip}
                  dense
                  onRowClick={(r) => drillDown('access', `client_ip:${r.client_ip}`)}
                  empty={<div className="py-8 text-center text-sm text-fg-subtle">{t('common.noData')}</div>}
                />
              </CardBody>
            </Card>

            {/* Top rules */}
            <Card>
              <CardHeader title={t('pages.traffic.topRules')} />
              <CardBody className="p-0">
                <Table
                  columns={ruleColumns}
                  data={data?.topRules ?? []}
                  rowKey={(r) => r.rule_id}
                  dense
                  onRowClick={(r) => drillDown('security', `rule:${r.rule_id}`)}
                  empty={<div className="py-8 text-center text-sm text-fg-subtle">{t('common.noData')}</div>}
                />
              </CardBody>
            </Card>
          </div>
        </div>
      )}
    </>
  )
}

/** One site's traffic — the panels scoped to the `:siteId` route param. */
export function TrafficPage() {
  const { t } = useTranslation()
  const { siteId = '' } = useParams<{ siteId: string }>()

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.traffic.title')}
        description={t('pages.traffic.description')}
      />
      <TrafficPanels siteId={siteId} />
    </div>
  )
}

function SummaryCard({
  icon,
  label,
  value,
  tone = 'brand',
}: {
  icon: ReactNode
  label: string
  value: string
  tone?: 'brand' | 'danger'
}) {
  const toneClass =
    tone === 'danger' ? 'bg-danger/12 text-fg-danger' : 'bg-brand-soft text-brand'
  return (
    <Card padded>
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wide text-fg-subtle">{label}</p>
          <p className="mt-1.5 text-2xl font-semibold tabular-nums text-fg-strong">{value}</p>
        </div>
        <span className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-lg', toneClass)}>
          {icon}
        </span>
      </div>
    </Card>
  )
}

export default TrafficPage
