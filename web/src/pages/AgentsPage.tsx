import { useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Desktop,
  MagnifyingGlass,
  Trash,
  ArrowClockwise,
  Lightning,
  Plugs,
  Cpu,
  HardDrives,
  Copy,
  Plus,
  Warning,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { AgentProbePanel } from '@/components/agents/AgentProbePanel'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { AGENT_STATUSES, agentKeys, agentsApi, countByStatus } from '@/api/agents'
import { systemApi } from '@/api/system'
import { analyticsApi } from '@/api/analytics'
import { useCanWrite, useDebouncedValue, useNow, useSitesList } from '@/hooks'
import { cn } from '@/lib/utils'
import { formatDateTime, formatLatency, formatNumber, formatRelative, formatSize } from '@/lib/format'
import type { Agent, AgentCommand, AgentEnrollRequest, AgentEnrollResponse, AgentStatus } from '@/api/types'

const STATUS_TONE: Record<AgentStatus, 'success' | 'warning' | 'neutral'> = {
  online: 'success',
  degraded: 'warning',
  offline: 'neutral',
}

const STATUS_DOT: Record<AgentStatus, string> = {
  online: 'bg-success',
  degraded: 'bg-warning',
  offline: 'bg-fg-subtle/50',
}

/** 30s — matches the heartbeat cadence the agents report on. */
const REFRESH_MS = 30_000

const COMMANDS: AgentCommand[] = ['reload', 'restart', 'purge_cache']

export function AgentsPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const now = useNow(15_000)

  const [search, setSearch] = useState('')
  const debouncedSearch = useDebouncedValue(search.trim(), 350)
  const [statusFilter, setStatusFilter] = useState('')
  const [siteFilter, setSiteFilter] = useState('')
  const [detail, setDetail] = useState<Agent | null>(null)
  const [pendingDelete, setPendingDelete] = useState<Agent | null>(null)
  const [pendingCommand, setPendingCommand] = useState<{ agent: Agent; command: AgentCommand } | null>(null)
  const [enrollOpen, setEnrollOpen] = useState(false)
  const [enrollName, setEnrollName] = useState('')
  const [enrollResult, setEnrollResult] = useState<AgentEnrollResponse | null>(null)

  const { data: sites } = useSitesList()

  const agentsQuery = useQuery({
    queryKey: agentKeys.list({
      search: debouncedSearch || undefined,
      status: statusFilter || undefined,
      site_id: siteFilter || undefined,
    }),
    queryFn: () =>
      agentsApi.list({
        search: debouncedSearch || undefined,
        status: statusFilter || undefined,
        site_id: siteFilter || undefined,
      }),
    refetchInterval: REFRESH_MS,
  })

  const agents = useMemo(() => agentsQuery.data?.items ?? [], [agentsQuery.data])
  const total = agentsQuery.data?.total ?? 0
  const counts = useMemo(() => countByStatus(agents), [agents])

  const versionQuery = useQuery({
    queryKey: ['version'],
    queryFn: () => systemApi.version(),
    staleTime: 60_000,
  })

  // Traffic served by the fleet, for the summary strip.
  const summaryQuery = useQuery({
    queryKey: ['agents', 'summary-traffic'],
    queryFn: () => analyticsApi.summary(),
    staleTime: 60_000,
    refetchInterval: REFRESH_MS,
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: agentKeys.all })
  }

  const enroll = useMutation({
    mutationFn: (data: AgentEnrollRequest) => agentsApi.enroll(data),
    onSuccess: (data) => setEnrollResult(data),
  })

  const submitEnroll = () => {
    enroll.mutate({ name: enrollName.trim() || undefined })
  }

  const openEnroll = () => {
    enroll.reset()
    setEnrollName('')
    setEnrollResult(null)
    setEnrollOpen(true)
  }

  const closeEnroll = () => {
    setEnrollOpen(false)
    enroll.reset()
    setEnrollResult(null)
  }

  const finishEnroll = () => {
    closeEnroll()
    invalidate()
  }

  const copyText = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      toast.success(t('pages.agents.copied'))
    } catch {
      toast.error(t('pages.agents.copyFailed'))
    }
  }

  const remove = useMutation({
    mutationFn: (id: string) => agentsApi.remove(id),
    onSuccess: (_data, id) => {
      const target = agents.find((a) => a.id === id)
      toast.success(t('pages.agents.removed'), target?.hostname)
      setPendingDelete(null)
      setDetail(null)
      invalidate()
    },
  })

  const sendCommand = useMutation({
    mutationFn: ({ agent, command }: { agent: Agent; command: AgentCommand }) =>
      agentsApi.sendCommand(agent.id, { command }),
    onSuccess: (result) => {
      toast.success(
        t(`pages.agents.command_${result.command}`, result.command),
        result.delivered
          ? t('pages.agents.commandDelivered')
          : t('pages.agents.commandQueued'),
      )
      setPendingCommand(null)
      invalidate()
    },
  })

  const siteOptions = useMemo(
    () => [
      { value: '', label: t('pages.agents.allSites') },
      ...(sites ?? []).map((s) => ({ value: s.id, label: s.domain })),
    ],
    [sites, t],
  )

  const columns: Column<Agent>[] = [
    {
      key: 'hostname',
      header: t('pages.agents.hostname'),
      accessor: (a) => a.hostname,
      sortable: true,
      cell: (a) => (
        <div className="flex items-center gap-3">
          <span
            className={cn(
              'flex h-8 w-8 shrink-0 items-center justify-center rounded-md',
              a.status === 'online'
                ? 'bg-success/12 text-fg-success'
                : a.status === 'degraded'
                  ? 'bg-warning/12 text-fg-warning'
                  : 'bg-recessed text-fg-subtle',
            )}
          >
            <Desktop weight="duotone" className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <p className="truncate text-[13px] font-medium text-fg-strong">{a.hostname}</p>
            <p className="pw-mono truncate text-xs text-fg-subtle">{a.ip_address}</p>
          </div>
        </div>
      ),
    },
    {
      key: 'site',
      header: t('pages.agents.site'),
      accessor: (a) => a.site_domain ?? '',
      cell: (a) =>
        a.site_domain ? (
          <span className="pw-mono truncate text-[13px] text-fg">{a.site_domain}</span>
        ) : (
          // Unbound agents serve every site of their owner (config-push
          // visibility) — "all sites", not "unassigned".
          <span
            className="text-[13px] text-fg-subtle"
            title={t('pages.agents.allSitesHint')}
          >
            {t('pages.agents.allSites')}
          </span>
        ),
    },
    {
      key: 'version',
      header: t('pages.agents.version'),
      accessor: (a) => a.version ?? '',
      width: '1%',
      cell: (a) => (
        <span className="pw-mono text-xs text-fg-subtle">{a.version ?? '—'}</span>
      ),
    },
    {
      key: 'status',
      header: t('common.status'),
      accessor: (a) => a.status,
      width: '1%',
      cell: (a) => (
        <span className="inline-flex items-center gap-2">
          <span
            className={cn(
              'h-2 w-2 shrink-0 rounded-full',
              STATUS_DOT[a.status as AgentStatus] ?? 'bg-fg-subtle/50',
              a.status === 'online' && 'animate-pulse',
            )}
          />
          <Badge tone={STATUS_TONE[a.status as AgentStatus] ?? 'neutral'}>
            {t(`status.${a.status}`, a.status)}
          </Badge>
        </span>
      ),
    },
    {
      key: 'heartbeat',
      header: t('pages.agents.lastHeartbeat'),
      accessor: (a) => a.last_heartbeat ?? '',
      sortable: true,
      width: '1%',
      cell: (a) => (
        <span
          className={cn(
            'whitespace-nowrap text-[13px]',
            a.status === 'offline' ? 'text-fg-subtle' : 'text-fg',
          )}
          title={a.last_heartbeat ? formatDateTime(a.last_heartbeat) : undefined}
        >
          {a.last_heartbeat ? formatRelative(a.last_heartbeat, now) : t('pages.agents.neverSeen')}
        </span>
      ),
    },
    {
      key: 'sync',
      header: t('pages.agents.lastSync'),
      accessor: (a) => a.last_config_sync_at ?? '',
      width: '1%',
      cell: (a) => (
        <div className="space-y-0.5">
          <p
            className="whitespace-nowrap text-[13px] text-fg"
            title={
              a.last_config_sync_at
                ? formatDateTime(a.last_config_sync_at)
                : undefined
            }
          >
            <span className="text-fg-subtle">{t('pages.agents.syncConfig')}:</span>{' '}
            {a.last_config_sync_at
              ? formatRelative(a.last_config_sync_at, now)
              : '—'}
          </p>
          <p
            className="whitespace-nowrap text-[13px] text-fg"
            title={
              a.last_policy_sync_at
                ? formatDateTime(a.last_policy_sync_at)
                : undefined
            }
          >
            <span className="text-fg-subtle">{t('pages.agents.syncPolicy')}:</span>{' '}
            {a.last_policy_sync_at
              ? formatRelative(a.last_policy_sync_at, now)
              : '—'}
          </p>
        </div>
      ),
    },
    {
      key: 'row-actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (a) => (
        <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('pages.agents.remove')}
            disabled={!canWrite}
            onClick={() => setPendingDelete(a)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  const stats = [
    {
      key: 'total',
      label: t('pages.agents.totalAgents'),
      value: agentsQuery.data ? formatNumber(total) : undefined,
      icon: Desktop,
      tone: 'text-link bg-focus/10',
    },
    {
      key: 'online',
      label: t('status.online'),
      value: agentsQuery.data ? formatNumber(counts.online ?? 0) : undefined,
      icon: Plugs,
      tone: 'text-fg-success bg-success/12',
    },
    {
      key: 'degraded',
      label: t('status.degraded'),
      value: agentsQuery.data ? formatNumber(counts.degraded ?? 0) : undefined,
      icon: Lightning,
      tone: 'text-fg-warning bg-warning/12',
    },
    {
      key: 'offline',
      label: t('status.offline'),
      value: agentsQuery.data ? formatNumber(counts.offline ?? 0) : undefined,
      icon: Desktop,
      tone: 'text-fg-subtle bg-recessed',
    },
  ]

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.agents.title')}
        description={t('pages.agents.description')}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              loading={agentsQuery.isFetching}
              onClick={() => agentsQuery.refetch()}
              icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
            >
              {t('common.refresh')}
            </Button>
            {canWrite && (
              <Button
                variant="primary"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={openEnroll}
              >
                {t('pages.agents.addNode')}
              </Button>
            )}
          </div>
        }
      />

      {/* Fleet summary */}
      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {stats.map((stat) => {
          const Icon = stat.icon
          return (
            <Card key={stat.key}>
              <CardBody className="flex items-center gap-3 py-3.5">
                <span
                  className={cn(
                    'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg',
                    stat.tone,
                  )}
                >
                  <Icon weight="duotone" className="h-4 w-4" />
                </span>
                <div className="min-w-0">
                  <p className="truncate text-xs text-fg-subtle">{stat.label}</p>
                  {stat.value === undefined ? (
                    <span className="pw-skeleton mt-1 block h-5 w-12 rounded" />
                  ) : (
                    <p className="tabular-nums text-lg font-semibold leading-tight text-fg-strong">
                      {stat.value}
                    </p>
                  )}
                </div>
              </CardBody>
            </Card>
          )
        })}
      </div>

      {summaryQuery.data && (
        <div className="mb-4 flex flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border border-line bg-elevated px-4 py-2.5 text-[13px] text-fg-subtle">
          <span>
            {t('pages.dashboard.requestsWindow')}:{' '}
            <strong className="tabular-nums text-fg-strong">
              {formatNumber(summaryQuery.data.requests)}
            </strong>
          </span>
          <span>
            {t('pages.dashboard.blockedWindow')}:{' '}
            <strong className="tabular-nums text-fg-danger">
              {formatNumber(summaryQuery.data.blocked_requests)}
            </strong>
          </span>
          <span>
            {t('pages.dashboard.avgLatency')}:{' '}
            <strong className="tabular-nums text-fg-strong">
              {formatLatency(summaryQuery.data.avg_latency_ms)}
            </strong>
          </span>
        </div>
      )}

      {versionQuery.data && !versionQuery.data.grpc_tls && (
        <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] leading-relaxed text-fg">
          <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
          {t('pages.agents.grpcPlaintext')}
        </p>
      )}

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="w-full max-w-xs">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('pages.agents.searchPlaceholder')}
            prefixIcon={<MagnifyingGlass weight="duotone" />}
            aria-label={t('common.search')}
          />
        </div>
        <Select
          aria-label={t('common.status')}
          className="h-9 w-40"
          value={statusFilter}
          options={[
            { value: '', label: t('pages.agents.anyStatus') },
            ...AGENT_STATUSES.map((s) => ({ value: s, label: t(`status.${s}`, s) })),
          ]}
          onChange={(e) => setStatusFilter(e.target.value)}
        />
        <Select
          aria-label={t('pages.agents.site')}
          className="h-9 w-48"
          value={siteFilter}
          options={siteOptions}
          onChange={(e) => setSiteFilter(e.target.value)}
        />
      </div>

      {agentsQuery.isError && !agentsQuery.data ? (
        <ErrorState
          error={agentsQuery.error}
          onRetry={() => agentsQuery.refetch()}
          retrying={agentsQuery.isFetching}
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            {agentsQuery.isPending ? (
              <SkeletonRows rows={6} columns={7} />
            ) : agents.length === 0 ? (
              <EmptyState
                className="py-14"
                icon={<Desktop weight="duotone" className="h-8 w-8" />}
                title={
                  search || statusFilter || siteFilter
                    ? t('pages.agents.noResults')
                    : t('pages.agents.empty')
                }
                description={
                  search || statusFilter || siteFilter
                    ? t('pages.agents.noResultsDescription')
                    : t('pages.agents.emptyDescription')
                }
                action={
                  search || statusFilter || siteFilter ? (
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setSearch('')
                        setStatusFilter('')
                        setSiteFilter('')
                      }}
                    >
                      {t('common.reset')}
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <Table
                columns={columns}
                data={agents}
                rowKey={(a) => a.id}
                dense
                onRowClick={(a) => setDetail(a)}
              />
            )}
          </CardBody>
        </Card>
      )}

      {/* Agent detail */}
      <Dialog
        open={detail !== null}
        onClose={() => setDetail(null)}
        size="lg"
        title={detail?.hostname}
        description={detail?.ip_address}
        footer={
          <>
            {canWrite && detail && (
              <div className="mr-auto flex items-center gap-2">
                {COMMANDS.map((command) => (
                  <Button
                    key={command}
                    size="sm"
                    variant="secondary"
                    onClick={() => setPendingCommand({ agent: detail, command })}
                  >
                    {t(`pages.agents.command_${command}`, command)}
                  </Button>
                ))}
              </div>
            )}
            <Button variant="ghost" onClick={() => setDetail(null)}>
              {t('common.close')}
            </Button>
          </>
        }
      >
        {detail && (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-2">
                <span
                  className={cn(
                    'h-2 w-2 rounded-full',
                    STATUS_DOT[detail.status as AgentStatus] ?? 'bg-fg-subtle/50',
                  )}
                />
                <Badge tone={STATUS_TONE[detail.status as AgentStatus] ?? 'neutral'}>
                  {t(`status.${detail.status}`, detail.status)}
                </Badge>
              </span>
              {detail.connected && <Badge tone="success">{t('pages.agents.connected')}</Badge>}
              {detail.pending_commands > 0 && (
                <Badge tone="warning">
                  {t('pages.agents.pendingCommands')}: {detail.pending_commands}
                </Badge>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <MetricTile
                icon={<Cpu weight="duotone" className="h-4 w-4" />}
                label={t('pages.agents.cpuCores')}
                value={detail.cpu_cores != null ? String(detail.cpu_cores) : '—'}
              />
              <MetricTile
                icon={<HardDrives weight="duotone" className="h-4 w-4" />}
                label={t('pages.agents.hostMemory')}
                value={detail.memory_bytes != null ? formatSize(detail.memory_bytes) : '—'}
              />
              <MetricTile
                icon={<Desktop weight="duotone" className="h-4 w-4" />}
                label={t('pages.agents.os')}
                value={detail.os_info ?? '—'}
              />
              <MetricTile
                icon={<Lightning weight="duotone" className="h-4 w-4" />}
                label={t('pages.agents.version')}
                value={detail.version ?? '—'}
              />
            </div>

            <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
              <DetailRow label={t('pages.agents.site')} value={detail.site_domain ?? t('pages.agents.allSites')} />
              <DetailRow label={t('pages.agents.publicIp')} value={detail.public_ip} mono />
              <DetailRow label={t('pages.agents.privateIp')} value={detail.private_ip} mono />
              <DetailRow label={t('pages.agents.ipAddress')} value={detail.ip_address} />
              <DetailRow
                label={t('pages.agents.lastHeartbeat')}
                value={
                  detail.last_heartbeat
                    ? `${formatRelative(detail.last_heartbeat, now)} · ${formatDateTime(detail.last_heartbeat)}`
                    : t('pages.agents.neverSeen')
                }
              />
              <DetailRow
                label={t('pages.agents.lastConfigSync')}
                value={
                  detail.last_config_sync_at
                    ? `${formatRelative(detail.last_config_sync_at, now)} · ${formatDateTime(detail.last_config_sync_at)}`
                    : t('pages.agents.neverSynced')
                }
              />
              <DetailRow
                label={t('pages.agents.lastPolicySync')}
                value={
                  detail.last_policy_sync_at
                    ? `${formatRelative(detail.last_policy_sync_at, now)} · ${formatDateTime(detail.last_policy_sync_at)}`
                    : t('pages.agents.neverSynced')
                }
              />
              <DetailRow label={t('pages.agents.registeredAt')} value={formatDateTime(detail.registered_at)} />
              <DetailRow label={t('pages.agents.agentId')} value={detail.id} mono />
              <DetailRow label={t('pages.agents.configHash')} value={detail.config_hash} mono />
              <DetailRow label={t('pages.agents.apiKeyId')} value={detail.api_key_id} mono />
            </dl>

            <div className="border-t border-line pt-4">
              <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
                <h3 className="text-[13px] font-semibold text-fg-strong">
                  {t('pages.agents.probe.title')}
                </h3>
                <span className="text-[11px] text-fg-subtle">
                  {t('pages.agents.probe.cadence')}
                </span>
              </div>
              <AgentProbePanel agentId={detail.id} />
            </div>
          </div>
        )}
      </Dialog>

      {/* Command confirmation */}
      <ConfirmDialog
        open={pendingCommand !== null}
        onClose={() => setPendingCommand(null)}
        onConfirm={() => pendingCommand && sendCommand.mutate(pendingCommand)}
        tone="primary"
        title={
          pendingCommand
            ? t(`pages.agents.command_${pendingCommand.command}`, pendingCommand.command)
            : ''
        }
        description={t('pages.agents.commandConfirmDescription')}
        confirmLabel={t('common.confirm')}
        loading={sendCommand.isPending}
      >
        {pendingCommand && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingCommand.agent.hostname}</p>
            <p className="pw-mono mt-0.5 text-xs text-fg-subtle">
              {pendingCommand.agent.ip_address}
            </p>
          </div>
        )}
      </ConfirmDialog>

      {/* Remove confirmation */}
      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete.id)}
        title={t('pages.agents.removeTitle')}
        description={t('pages.agents.removeDescription')}
        confirmLabel={t('pages.agents.remove')}
        loading={remove.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDelete.hostname}</p>
            <p className="pw-mono mt-0.5 text-xs text-fg-subtle">{pendingDelete.ip_address}</p>
            <p className="mt-1.5 text-xs text-fg-subtle">
              {pendingDelete.site_domain
                ? t('pages.agents.removeSiteNote', { domain: pendingDelete.site_domain })
                : t('pages.agents.removeUnassignedNote')}
            </p>
          </div>
        )}
      </ConfirmDialog>

      {/* Enrol a new node */}
      <Dialog
        open={enrollOpen}
        onClose={closeEnroll}
        size="md"
        title={t('pages.agents.addNode')}
        description={enrollResult ? undefined : t('pages.agents.addNodeDescription')}
        footer={
          enrollResult ? (
            <Button variant="primary" onClick={finishEnroll}>
              {t('pages.agents.done')}
            </Button>
          ) : (
            <>
              <Button variant="ghost" onClick={closeEnroll}>
                {t('common.cancel')}
              </Button>
              <Button variant="primary" loading={enroll.isPending} onClick={submitEnroll}>
                {t('pages.agents.generateCommand')}
              </Button>
            </>
          )
        }
      >
        <div className="flex flex-col gap-4">
          {enroll.isError && (
            <ErrorState
              variant="inline"
              error={enroll.error}
              onRetry={submitEnroll}
              retrying={enroll.isPending}
            />
          )}

          {enrollResult ? (
            <>
              <p className="text-[13px] leading-relaxed text-fg-subtle">
                {t('pages.agents.enrollIntro')}
              </p>

              <CommandBlock
                caption={t('pages.agents.installDeploy')}
                command={enrollResult.install_command}
                onCopy={copyText}
              />

              <p className="flex items-start gap-2 rounded-md border border-warning/30 bg-warning/10 px-3 py-2 text-xs leading-relaxed text-fg">
                <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
                <span>{t('pages.agents.enrollNeverExpires')}</span>
              </p>
            </>
          ) : (
            <>
              <Input
                label={t('common.name')}
                value={enrollName}
                autoFocus
                disabled={enroll.isPending}
                placeholder={t('pages.agents.nodeNamePlaceholder')}
                hint={t('pages.agents.nodeNameHint')}
                onChange={(e) => setEnrollName(e.target.value)}
              />
            </>
          )}
        </div>
      </Dialog>
    </div>
  )
}

/** One of the ready-to-paste enrolment commands, with its own copy button. */
function CommandBlock({
  caption,
  command,
  onCopy,
}: {
  caption: string
  command: string
  onCopy: (value: string) => void
}) {
  const { t } = useTranslation()
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <span className="text-xs text-fg-subtle">{caption}</span>
        <Button
          size="sm"
          variant="ghost"
          aria-label={`${t('pages.agents.copy')}: ${caption}`}
          icon={<Copy weight="duotone" className="h-3.5 w-3.5" />}
          onClick={() => onCopy(command)}
        >
          {t('pages.agents.copy')}
        </Button>
      </div>
      <pre className="pw-mono break-all whitespace-pre-wrap rounded-md border border-line bg-recessed px-3 py-2 text-xs text-fg">{command}</pre>
    </div>
  )
}

function MetricTile({
  icon,
  label,
  value,
}: {
  icon: ReactNode
  label: string
  value: string
}) {
  return (
    <div className="rounded-lg border border-line bg-recessed px-3 py-2.5">
      <span className="flex items-center gap-1.5 text-[11px] text-fg-subtle">
        {icon}
        {label}
      </span>
      <p className="mt-1 truncate text-sm font-medium text-fg-strong">{value}</p>
    </div>
  )
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string
  value: string | null | undefined
  mono?: boolean
}) {
  const text = value && value.length > 0 ? value : '—'
  return (
    <div className="flex min-w-0 items-baseline justify-between gap-3 border-b border-line/60 pb-1.5">
      <dt className="shrink-0 text-xs text-fg-subtle">{label}</dt>
      <dd className={cn('min-w-0 truncate text-right text-[13px] text-fg', mono && 'pw-mono text-xs')}>
        {text}
      </dd>
    </div>
  )
}

export default AgentsPage
