import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  AreaChart,
  Area,
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
  Globe,
  Desktop,
  ArrowsDownUp,
  ShieldSlash,
  Gauge,
  Database,
  ArrowRight,
  Lightning,
  Clock,
  UploadSimple,
  Cpu,
  Info,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { IpQuickActions } from '@/components/waf/IpQuickActions'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Select } from '@/components/ui/Select'
import { EmptyState } from '@/components/ui/EmptyState'
import { Table, type Column } from '@/components/ui/Table'
import { ErrorState } from '@/components/ErrorState'
import { Skeleton, SkeletonRows } from '@/components/ui/Skeleton'
import { analyticsApi, analyticsKeys } from '@/api/analytics'
import { agentsApi, agentKeys } from '@/api/agents'
import { fetchSystemMetrics, debugKeys } from '@/api/debug'
import { useAuthStore } from '@/stores/authStore'
import { useSitesList } from '@/hooks'
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
import type { RangeQuery, TopIp, TopPath, TopRule } from '@/api/types'

/** Preset windows, in hours. The API caps a single range at 31 days. */
const RANGE_OPTIONS = [
  { value: '1', label: '1h' },
  { value: '6', label: '6h' },
  { value: '24', label: '24h' },
  { value: '72', label: '3d' },
  { value: '168', label: '7d' },
  { value: '720', label: '30d' },
]

/** 30s polling cadence, matching the dashboard's "live" promise. */
const REFRESH_MS = 30_000

/** Stroke palette for the per-site traffic lines (capped at 8 sites server-side). */
const SITE_LINE_COLORS = [
  '#f6821f',
  '#18794e',
  '#2f6fed',
  '#e54d2a',
  '#8b5cf6',
  '#0891b2',
  '#ca8a04',
  '#db2777',
]

/** Badge tone matching the HTTP class of a status code. */
function statusCodeTone(code: number): 'success' | 'info' | 'warning' | 'danger' {
  if (code < 300) return 'success'
  if (code < 400) return 'info'
  if (code < 500) return 'warning'
  return 'danger'
}

function statusCodeBar(code: number): string {
  if (code < 300) return 'bg-success'
  if (code < 400) return 'bg-focus'
  if (code < 500) return 'bg-warning'
  return 'bg-danger'
}

function intervalFor(hours: number): 'minute' | 'hour' | 'day' {
  if (hours <= 2) return 'minute'
  if (hours <= 96) return 'hour'
  return 'day'
}

/** Bucket width for the egress chart: fine 5s steps for short windows only. */
function trafficStepFor(hours: number): number {
  if (hours <= 2) return 5
  if (hours <= 6) return 30
  if (hours <= 24) return 300
  if (hours <= 168) return 900
  return 3600
}

export function DashboardPage() {
  const { t } = useTranslation()
  const [hours, setHours] = useState(24)
  const [siteId, setSiteId] = useState<string>('')
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'

  const { data: sites } = useSitesList()

  // Recomputed only when the window or the site filter changes, so the 30s
  // refetch keeps a stable query key and does not invalidate the cache each tick.
  const range = useMemo<RangeQuery>(() => {
    const to = new Date()
    const from = new Date(to.getTime() - hours * 3600_000)
    return {
      from: from.toISOString(),
      to: to.toISOString(),
      interval: intervalFor(hours),
      ...(siteId ? { site_id: siteId } : {}),
    }
  }, [hours, siteId])

  const summary = useQuery({
    queryKey: analyticsKeys.summary(range),
    queryFn: () => analyticsApi.summary(range),
    refetchInterval: REFRESH_MS,
  })

  const traffic = useQuery({
    queryKey: analyticsKeys.traffic(range),
    queryFn: () => analyticsApi.requestsOverTime(range),
    refetchInterval: REFRESH_MS,
  })

  const bandwidth = useQuery({
    queryKey: analyticsKeys.bandwidth({ ...range, step: trafficStepFor(hours) }),
    queryFn: () => analyticsApi.traffic({ ...range, step: trafficStepFor(hours) }),
    refetchInterval: REFRESH_MS,
  })

  const topIps = useQuery({
    queryKey: analyticsKeys.topIps(range),
    queryFn: () => analyticsApi.topIps({ ...range, limit: 8 }),
    refetchInterval: REFRESH_MS,
  })

  const topRules = useQuery({
    queryKey: analyticsKeys.topRules(range),
    queryFn: () => analyticsApi.topRules({ ...range, limit: 6 }),
    refetchInterval: REFRESH_MS,
  })

  // Per-site series only make sense across sites, so the chart is hidden
  // while a single site is selected.
  const siteTraffic = useQuery({
    queryKey: analyticsKeys.sitesOverTime(range),
    queryFn: () => analyticsApi.sitesOverTime(range),
    refetchInterval: REFRESH_MS,
    enabled: !siteId,
  })

  const topPaths = useQuery({
    queryKey: analyticsKeys.topPaths(range),
    queryFn: () => analyticsApi.topPaths({ ...range, limit: 8 }),
    refetchInterval: REFRESH_MS,
  })

  const statusCodes = useQuery({
    queryKey: analyticsKeys.statusCodes(range),
    queryFn: () => analyticsApi.statusCodes(range),
    refetchInterval: REFRESH_MS,
  })

  const agents = useQuery({
    queryKey: agentKeys.list(),
    queryFn: () => agentsApi.list(),
    select: (page) => page.items,
    refetchInterval: REFRESH_MS,
  })

  const siteOptions = useMemo(
    () => [
      { value: '', label: t('pages.dashboard.allSites') },
      ...(sites ?? []).map((s) => ({ value: s.id, label: s.domain })),
    ],
    [sites, t],
  )

  const spanMs = hours * 3600_000
  const chartData = useMemo(
    () =>
      (traffic.data ?? []).map((b) => ({
        label: formatBucket(b.bucket, spanMs),
        requests: b.requests,
        blocked: b.blocked,
        cache_hits: b.cache_hits,
        errors: b.client_errors + b.server_errors,
      })),
    [traffic.data, spanMs],
  )

  // The API returns one row per (bucket, site); pivot into one object per
  // bucket with a column per site so recharts can draw one line per site.
  const siteTrafficData = useMemo(() => {
    const domains: string[] = []
    const names = new Map<string, string>()
    const buckets = new Map<string, Record<string, string | number>>()
    for (const point of siteTraffic.data ?? []) {
      if (!names.has(point.site_domain)) {
        names.set(point.site_domain, point.site_name || point.site_domain)
        domains.push(point.site_domain)
      }
      let bucket = buckets.get(point.bucket)
      if (!bucket) {
        bucket = { bucket: point.bucket }
        buckets.set(point.bucket, bucket)
      }
      bucket[point.site_domain] = point.requests
    }
    const data = [...buckets.values()]
      .sort((a, b) => String(a.bucket).localeCompare(String(b.bucket)))
      .map((bucket) => ({ ...bucket, label: formatBucket(bucket.bucket, spanMs) }))
    return { data, domains, names }
  }, [siteTraffic.data, spanMs])

  const statusRows = statusCodes.data ?? []
  const statusTotal = statusRows.reduce((sum, row) => sum + row.requests, 0)

  const s = summary.data
  const onlineAgents = (agents.data ?? []).filter((a) => a.status === 'online').length
  const totalAgents = agents.data?.length ?? 0
  const egress = bandwidth.data
  const egressAvg =
    egress && spanMs > 0 ? (egress.total_bytes * 8) / (spanMs / 1000) : undefined

  const stats = [
    {
      key: 'requests',
      label: t('pages.dashboard.requestsWindow'),
      value: s ? formatCompactNumber(s.requests) : undefined,
      sub: s ? t('pages.dashboard.uniqueIps', { count: formatCompactNumber(s.unique_ips) }) : undefined,
      icon: ArrowsDownUp,
      tone: 'text-link bg-focus/10',
    },
    {
      key: 'egress',
      label: t('pages.dashboard.egressWindow'),
      value: egress ? formatSize(egress.total_bytes) : undefined,
      sub:
        egressAvg !== undefined
          ? `${t('pages.traffic.avgBitrate')}: ${formatBitrate(egressAvg)}`
          : undefined,
      icon: UploadSimple,
      tone: 'text-link bg-focus/10',
    },
    {
      key: 'blocked',
      label: t('pages.dashboard.blockedWindow'),
      value: s ? formatCompactNumber(s.blocked_requests) : undefined,
      sub: s
        ? t('pages.dashboard.attackers', { count: formatCompactNumber(s.distinct_attackers) })
        : undefined,
      icon: ShieldSlash,
      tone: 'text-fg-danger bg-danger/12',
    },
    {
      key: 'security',
      label: t('pages.dashboard.securityEvents'),
      value: s ? formatCompactNumber(s.security_events) : undefined,
      sub: s
        ? t('pages.dashboard.rulesTriggered', { count: formatCompactNumber(s.rules_triggered) })
        : undefined,
      icon: Lightning,
      tone: 'text-brand bg-brand-soft',
    },
    {
      key: 'agents',
      label: t('pages.dashboard.activeAgents'),
      value: agents.data ? `${onlineAgents}/${totalAgents}` : undefined,
      sub: agents.data
        ? t('pages.dashboard.agentsOnline', { count: onlineAgents })
        : undefined,
      icon: Desktop,
      tone: 'text-fg-success bg-success/12',
    },
    {
      key: 'cache',
      label: t('pages.dashboard.cacheHitRate'),
      value: s ? formatPercent(s.cache_hit_rate) : undefined,
      sub: s ? `${formatCompactNumber(s.cache_hits)} ${t('nav.caching')}` : undefined,
      icon: Database,
      tone: 'text-fg-success bg-success/12',
    },
    {
      key: 'latency',
      label: t('pages.dashboard.avgLatency'),
      value: s ? formatLatency(s.avg_latency_ms) : undefined,
      sub: s
        ? `${t('pages.dashboard.errors')}: ${formatCompactNumber(s.client_errors + s.server_errors)}`
        : undefined,
      icon: Gauge,
      tone: 'text-fg bg-recessed',
    },
  ]

  const ipColumns: Column<TopIp>[] = [
    {
      key: 'client_ip',
      header: t('pages.logs.clientIp'),
      accessor: (r) => r.client_ip,
      cell: (r) => <span className="pw-mono text-[13px] text-fg">{r.client_ip}</span>,
    },
    {
      key: 'country',
      header: t('pages.dashboard.country'),
      accessor: (r) => r.country_code ?? '',
      cell: (r) =>
        r.country_code ? (
          <span className="text-[13px] text-fg-subtle">{r.country_code.toUpperCase()}</span>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
    },
    {
      key: 'requests',
      header: t('pages.dashboard.hits'),
      accessor: (r) => r.requests,
      align: 'right',
      sortable: true,
      cell: (r) => <span className="tabular-nums">{formatNumber(r.requests)}</span>,
    },
    {
      key: 'blocked',
      header: t('pages.dashboard.blocked'),
      accessor: (r) => r.blocked,
      align: 'right',
      sortable: true,
      cell: (r) => (
        <span className={cn('tabular-nums', r.blocked > 0 && 'font-medium text-fg-danger')}>
          {formatNumber(r.blocked)}
        </span>
      ),
    },
    {
      key: 'actions',
      header: t('pages.dashboard.quickActions'),
      align: 'right',
      // Fixed width for two icon buttons: '1%' let the cells shrink-wrap their
      // content, which widened the column and forced horizontal scrolling on
      // mobile once the labels were removed (2026-10-19 E2E).
      width: '96px',
      cell: (r) => <IpQuickActions ip={r.client_ip} siteId={r.top_site_id ?? null} />,
    },
  ]

  const ruleColumns: Column<TopRule>[] = [
    {
      key: 'rule_name',
      header: t('common.name'),
      accessor: (r) => r.rule_name,
      cell: (r) => (
        <div className="min-w-0">
          <p className="truncate text-[13px] font-medium text-fg">{r.rule_name || r.rule_id}</p>
          <p className="pw-mono truncate text-xs text-fg-subtle">{r.rule_id}</p>
        </div>
      ),
    },
    {
      key: 'action',
      header: t('pages.waf.action'),
      accessor: (r) => r.action,
      cell: (r) => (
        <Badge tone={r.action === 'block' ? 'danger' : r.action === 'log' ? 'info' : 'warning'}>
          {t(`actions.${r.action}`, r.action)}
        </Badge>
      ),
    },
    {
      key: 'hits',
      header: t('pages.dashboard.hits'),
      accessor: (r) => r.hits,
      align: 'right',
      sortable: true,
      cell: (r) => <span className="tabular-nums">{formatNumber(r.hits)}</span>,
    },
    {
      key: 'unique_ips',
      header: t('pages.dashboard.uniqueIpsShort'),
      accessor: (r) => r.unique_ips,
      align: 'right',
      cell: (r) => <span className="tabular-nums">{formatNumber(r.unique_ips)}</span>,
    },
  ]

  const pathColumns: Column<TopPath>[] = [
    {
      key: 'path',
      header: t('pages.dashboard.path'),
      accessor: (r) => r.path,
      cell: (r) => <span className="pw-mono block truncate text-[13px] text-fg">{r.path}</span>,
    },
    {
      key: 'requests',
      header: t('pages.dashboard.hits'),
      accessor: (r) => r.requests,
      align: 'right',
      sortable: true,
      cell: (r) => <span className="tabular-nums">{formatNumber(r.requests)}</span>,
    },
    {
      key: 'cache_hits',
      header: t('pages.dashboard.cacheHits'),
      accessor: (r) => r.cache_hits,
      align: 'right',
      cell: (r) => <span className="tabular-nums text-fg-subtle">{formatNumber(r.cache_hits)}</span>,
    },
    {
      key: 'avg_latency_ms',
      header: t('pages.dashboard.avgLatency'),
      accessor: (r) => r.avg_latency_ms,
      align: 'right',
      cell: (r) => <span className="tabular-nums">{formatLatency(r.avg_latency_ms)}</span>,
    },
  ]

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.dashboard.title')}
        description={t('pages.dashboard.description')}
        actions={
          <div className="flex items-center gap-2">
            <span className="hidden items-center gap-1.5 text-xs text-fg-subtle sm:inline-flex">
              <Clock weight="duotone" className="h-3.5 w-3.5" />
              {t('pages.dashboard.autoRefresh')}
            </span>
            <Select
              aria-label={t('pages.dashboard.siteFilter')}
              className="h-9 w-44"
              value={siteId}
              options={siteOptions}
              onChange={(e) => setSiteId(e.target.value)}
            />
            <Select
              aria-label={t('pages.dashboard.timeRange')}
              className="h-9 w-24"
              value={String(hours)}
              options={RANGE_OPTIONS}
              onChange={(e) => setHours(Number(e.target.value))}
            />
            <Button
              variant="secondary"
              size="md"
              loading={summary.isFetching}
              onClick={() => {
                void summary.refetch()
                void traffic.refetch()
                void topIps.refetch()
                void topRules.refetch()
                void topPaths.refetch()
                void statusCodes.refetch()
                if (!siteId) void siteTraffic.refetch()
              }}
            >
              {t('common.refresh')}
            </Button>
          </div>
        }
      />

      {/* Stat cards */}
      {summary.isError && !summary.data ? (
        <ErrorState error={summary.error} onRetry={() => summary.refetch()} retrying={summary.isFetching} />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
          {stats.map((stat) => {
            const Icon = stat.icon
            return (
              <Card key={stat.key} className="p-4">
                <div className="flex items-start justify-between">
                  <span className={cn('flex h-9 w-9 items-center justify-center rounded-lg', stat.tone)}>
                    <Icon weight="duotone" className="h-[18px] w-[18px]" />
                  </span>
                </div>
                {stat.value === undefined ? (
                  <div className="mt-3">
                    <Skeleton className="h-7 w-20" />
                    <Skeleton className="mt-2 h-3 w-24" />
                  </div>
                ) : (
                  <>
                    <p className="mt-3 text-2xl font-semibold tracking-tight text-fg-strong tabular-nums">
                      {stat.value}
                    </p>
                    <p className="mt-0.5 text-[13px] text-fg-subtle">{stat.label}</p>
                    {stat.sub && (
                      <p className="mt-1 text-xs text-fg-subtle/80 tabular-nums">{stat.sub}</p>
                    )}
                  </>
                )}
              </Card>
            )
          })}
          {isAdmin && <SystemCpuCard />}
        </div>
      )}

      {/* Traffic chart */}
      <Card className="mt-4">
        <CardHeader
          title={t('pages.dashboard.trafficOverview')}
          description={t('pages.dashboard.trafficOverviewDescription', { hours })}
          action={
            summary.data ? (
              <span className="text-xs text-fg-subtle tabular-nums">
                {formatNumber(summary.data.requests)} {t('pages.traffic.requests')}
              </span>
            ) : undefined
          }
        />
        <CardBody>
          {traffic.isPending ? (
            <div className="flex h-72 items-end gap-1.5">
              {Array.from({ length: 24 }).map((_, i) => (
                <Skeleton
                  key={i}
                  className="flex-1"
                  style={{ height: `${28 + ((i * 37) % 60)}%` }}
                />
              ))}
            </div>
          ) : traffic.isError ? (
            <ErrorState
              variant="inline"
              error={traffic.error}
              onRetry={() => traffic.refetch()}
              retrying={traffic.isFetching}
            />
          ) : chartData.length === 0 ? (
            <EmptyState
              icon={<ArrowsDownUp weight="duotone" className="h-8 w-8" />}
              title={t('pages.dashboard.noTraffic')}
              description={t('pages.dashboard.noTrafficDescription')}
              className="py-10"
            />
          ) : (
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                  <defs>
                    <linearGradient id="reqFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#f6821f" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="#f6821f" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="blockFill" x1="0" y1="0" x2="0" y2="1">
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
                  <Tooltip
                    contentStyle={{
                      background: 'var(--color-bg-elevated)',
                      border: '1px solid var(--color-border-line)',
                      borderRadius: 8,
                      fontSize: 12,
                      color: 'var(--color-text-default)',
                    }}
                    formatter={(value) => formatNumber(Number(value ?? 0))}
                  />
                  <Legend wrapperStyle={{ fontSize: 12 }} iconType="circle" />
                  <Area
                    type="monotone"
                    dataKey="requests"
                    name={t('pages.traffic.requests')}
                    stroke="#f6821f"
                    strokeWidth={2}
                    fill="url(#reqFill)"
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    name={t('pages.dashboard.blockedShort')}
                    stroke="#e54d2a"
                    strokeWidth={2}
                    fill="url(#blockFill)"
                  />
                  <Area
                    type="monotone"
                    dataKey="cache_hits"
                    name={t('nav.caching')}
                    stroke="#18794e"
                    strokeWidth={2}
                    fill="transparent"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </CardBody>
      </Card>

      {/* Per-site traffic */}
      {!siteId && (
        <Card className="mt-4">
          <CardHeader
            title={t('pages.dashboard.sitesTraffic')}
            description={t('pages.dashboard.sitesTrafficDescription')}
            action={
              siteTraffic.data ? (
                <span className="text-xs text-fg-subtle tabular-nums">
                  {t('pages.dashboard.sitesTracked', { count: siteTrafficData.domains.length })}
                </span>
              ) : undefined
            }
          />
          <CardBody>
            {siteTraffic.isPending ? (
              <Skeleton className="h-72 w-full" />
            ) : siteTraffic.isError ? (
              <ErrorState
                variant="inline"
                error={siteTraffic.error}
                onRetry={() => siteTraffic.refetch()}
                retrying={siteTraffic.isFetching}
              />
            ) : siteTrafficData.data.length === 0 ? (
              <EmptyState
                icon={<Globe weight="duotone" className="h-8 w-8" />}
                title={t('pages.dashboard.noSiteTraffic')}
                description={t('pages.dashboard.noSiteTrafficDescription')}
                className="py-10"
              />
            ) : (
              <div className="h-72 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={siteTrafficData.data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
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
                    <Tooltip
                      contentStyle={{
                        background: 'var(--color-bg-elevated)',
                        border: '1px solid var(--color-border-line)',
                        borderRadius: 8,
                        fontSize: 12,
                        color: 'var(--color-text-default)',
                      }}
                      formatter={(value) => formatNumber(Number(value ?? 0))}
                    />
                    <Legend wrapperStyle={{ fontSize: 12 }} iconType="circle" />
                    {siteTrafficData.domains.map((domain, index) => (
                      <Line
                        key={domain}
                        type="monotone"
                        dataKey={domain}
                        name={siteTrafficData.names.get(domain)}
                        stroke={SITE_LINE_COLORS[index % SITE_LINE_COLORS.length]}
                        strokeWidth={2}
                        dot={false}
                        activeDot={{ r: 3 }}
                        connectNulls
                      />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardBody>
        </Card>
      )}

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* Top threat IPs */}
        <Card>
          <CardHeader
            title={t('pages.dashboard.topThreatIps')}
            description={t('pages.dashboard.topThreatIpsDescription')}
            action={
              <Link to="/logs">
                <Button variant="ghost" size="sm" icon={<ArrowRight weight="bold" className="h-3.5 w-3.5" />}>
                  {t('common.viewAll')}
                </Button>
              </Link>
            }
          />
          <CardBody className="px-0 py-0">
            {topIps.isPending ? (
              <SkeletonRows rows={5} columns={4} />
            ) : topIps.isError ? (
              <div className="p-4">
                <ErrorState variant="inline" error={topIps.error} onRetry={() => topIps.refetch()} />
              </div>
            ) : (topIps.data ?? []).length === 0 ? (
              <EmptyState
                className="py-10"
                icon={<ShieldSlash weight="duotone" className="h-7 w-7" />}
                title={t('pages.dashboard.noThreats')}
                description={t('pages.dashboard.noThreatsDescription')}
              />
            ) : (
              <Table columns={ipColumns} data={topIps.data ?? []} rowKey={(r) => r.client_ip} dense />
            )}
          </CardBody>
        </Card>

        {/* Top triggered rules */}
        <Card>
          <CardHeader
            title={t('pages.dashboard.topRules')}
            description={t('pages.dashboard.topRulesDescription')}
          />
          <CardBody className="px-0 py-0">
            {topRules.isPending ? (
              <SkeletonRows rows={5} columns={4} />
            ) : topRules.isError ? (
              <div className="p-4">
                <ErrorState variant="inline" error={topRules.error} onRetry={() => topRules.refetch()} />
              </div>
            ) : (topRules.data ?? []).length === 0 ? (
              <EmptyState
                className="py-10"
                icon={<Lightning weight="duotone" className="h-7 w-7" />}
                title={t('pages.dashboard.noRulesTriggered')}
                description={t('pages.dashboard.noRulesTriggeredDescription')}
              />
            ) : (
              <Table columns={ruleColumns} data={topRules.data ?? []} rowKey={(r) => r.rule_id} dense />
            )}
          </CardBody>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* Top paths */}
        <Card>
          <CardHeader
            title={t('pages.dashboard.topPaths')}
            description={t('pages.dashboard.topPathsDescription')}
          />
          <CardBody className="px-0 py-0">
            {topPaths.isPending ? (
              <SkeletonRows rows={5} columns={4} />
            ) : topPaths.isError ? (
              <div className="p-4">
                <ErrorState variant="inline" error={topPaths.error} onRetry={() => topPaths.refetch()} />
              </div>
            ) : (topPaths.data ?? []).length === 0 ? (
              <EmptyState
                className="py-10"
                icon={<ArrowsDownUp weight="duotone" className="h-7 w-7" />}
                title={t('pages.dashboard.noTraffic')}
                description={t('pages.dashboard.noTrafficDescription')}
              />
            ) : (
              <Table columns={pathColumns} data={topPaths.data ?? []} rowKey={(r) => r.path} dense />
            )}
          </CardBody>
        </Card>

        {/* Status codes */}
        <Card>
          <CardHeader
            title={t('pages.dashboard.statusCodes')}
            description={t('pages.dashboard.statusCodesDescription')}
          />
          <CardBody>
            {statusCodes.isPending ? (
              <SkeletonRows rows={5} columns={3} />
            ) : statusCodes.isError ? (
              <ErrorState
                variant="inline"
                error={statusCodes.error}
                onRetry={() => statusCodes.refetch()}
                retrying={statusCodes.isFetching}
              />
            ) : statusRows.length === 0 ? (
              <EmptyState
                className="py-10"
                icon={<Gauge weight="duotone" className="h-7 w-7" />}
                title={t('pages.dashboard.noTraffic')}
                description={t('pages.dashboard.noTrafficDescription')}
              />
            ) : (
              <div className="space-y-3">
                {statusRows.map((row) => (
                  <div key={row.status_code} className="flex items-center gap-3">
                    <Badge size="sm" tone={statusCodeTone(row.status_code)} className="w-14 justify-center">
                      {row.status_code}
                    </Badge>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-recessed">
                      <div
                        className={cn('h-full rounded-full', statusCodeBar(row.status_code))}
                        style={{ width: `${Math.max(2, (row.requests / statusTotal) * 100)}%` }}
                      />
                    </div>
                    <span className="w-20 text-right text-[13px] tabular-nums text-fg">
                      {formatCompactNumber(row.requests)}
                    </span>
                    <span className="w-12 text-right text-xs tabular-nums text-fg-subtle">
                      {statusTotal > 0 ? formatPercent(row.requests / statusTotal) : '—'}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  )
}

/**
 * Admin-only「System 观测」CPU 卡片，数据来自 `/api/v1/system/metrics`（15s 轮询，
 * 静默失败）。大字显示进程 CPU%，辅以主机 CPU%、cores 与 RSS 小字。
 */
function SystemCpuCard() {
  const { t } = useTranslation()
  const metrics = useQuery({
    queryKey: debugKeys.metrics(),
    queryFn: fetchSystemMetrics,
    refetchInterval: 15_000,
    retry: false,
  })

  if (metrics.isError) {
    return <ErrorState variant="inline" error={metrics.error} onRetry={() => metrics.refetch()} retrying={metrics.isFetching} />
  }

  const snap = metrics.data
  return (
    <Card className="group relative overflow-hidden p-4 transition-shadow group-hover:shadow-md">
      <div className="flex items-start justify-between">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg text-success bg-success/10">
          <Cpu weight="duotone" className="h-[18px] w-[18px]" />
        </span>
        <Info
          weight="regular"
          className="h-4 w-4 text-fg-subtle/50 transition-colors group-hover:text-fg-subtle"
          aria-hidden
        />
      </div>
      {snap === undefined ? (
        <div className="mt-3">
          <Skeleton className="h-7 w-20" />
          <Skeleton className="mt-2 h-3 w-24" />
        </div>
      ) : (
        <>
          <p className="mt-3 text-2xl font-semibold tracking-tight text-fg-strong tabular-nums">
            {snap.cpu.process_cpu_percent.toFixed(1)}%
          </p>
          <p className="mt-0.5 text-[13px] text-fg-subtle">{t('pages.dashboard.cpuCard.processCpu')}</p>
          <p className="mt-1 text-xs text-fg-subtle/80 tabular-nums">
            {t('pages.dashboard.cpuCard.hostCpu')}:{' '}
            <span className="font-medium text-fg">{snap.cpu.host_cpu_percent.toFixed(1)}%</span>
            <span className="mx-2 text-fg-subtle/40">·</span>
            {t('pages.dashboard.cpuCard.cores')}: {snap.cpu.cores}
          </p>
          <p className="mt-0.5 text-xs text-fg-subtle/70 tabular-nums">
            {t('pages.dashboard.cpuCard.rss')}: {snap.memory.rss}
          </p>
        </>
      )}
    </Card>
  )
}
