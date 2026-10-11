import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Prohibit, ShieldWarning } from '@phosphor-icons/react'
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
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { blockedIpsApi, blockedIpKeys } from '@/api/blockedIps'
import { validateIpCidr } from '@/api/ipRules'
import { useCanWrite, useSitesList } from '@/hooks'
import { formatDateTime, formatNumber, formatRelative } from '@/lib/format'
import type { GlobalBlockedIp } from '@/api/types'

/** Block durations offered by the manual-block dialog, in seconds (0 = permanent). */
const DURATION_OPTIONS = [
  { value: '600', labelKey: 'duration10m' },
  { value: '3600', labelKey: 'duration1h' },
  { value: '86400', labelKey: 'duration1d' },
  { value: '604800', labelKey: 'duration7d' },
  { value: '0', labelKey: 'durationPermanent' },
] as const

/**
 * Global blacklist: every dynamic block in force across all sites the caller
 * can see — WAF/rate-limit auto-blocks plus server-issued (manual) blocks —
 * each row folded per (site, IP) with its attack history. Offers one-click
 * unblock and a manual block that fans out to every registered agent. The
 * list polls because blocks appear and expire without user action.
 */
export function BlockedIpsPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const [siteFilter, setSiteFilter] = useState('')
  const [ipFilter, setIpFilter] = useState('')
  const [blockOpen, setBlockOpen] = useState(false)
  const [pendingUnblock, setPendingUnblock] =
    useState<GlobalBlockedIp | null>(null)

  const { data: sites } = useSitesList()

  const filters = useMemo(
    () => ({
      site_id: siteFilter || undefined,
      ip: ipFilter.trim() || undefined,
    }),
    [siteFilter, ipFilter],
  )

  const listQuery = useQuery({
    queryKey: blockedIpKeys.globalList(filters),
    queryFn: () => blockedIpsApi.globalList(filters),
    refetchInterval: 30_000,
  })

  const items = useMemo(() => listQuery.data ?? [], [listQuery.data])

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: blockedIpKeys.global })
  }

  const unblock = useMutation({
    mutationFn: (row: GlobalBlockedIp) =>
      blockedIpsApi.unblock(row.site_id, row.ip),
    onSuccess: () => {
      toast.success(t('pages.blockedIps.unblocked'))
      setPendingUnblock(null)
      invalidate()
    },
    onError: (e) =>
      toast.error(e instanceof Error ? e.message : String(e)),
  })

  const columns: Column<GlobalBlockedIp>[] = useMemo(
    () => [
      {
        key: 'ip',
        header: t('pages.blockedIps.colIp'),
        accessor: (r) => r.ip,
        cell: (r) => (
          <div className="min-w-0">
            <p className="pw-mono truncate text-[13px] font-medium text-fg-strong">
              {r.ip}
            </p>
            {r.reason && (
              <p className="line-clamp-1 text-xs text-fg-subtle">{r.reason}</p>
            )}
          </div>
        ),
      },
      {
        key: 'site',
        header: t('pages.blockedIps.colSite'),
        accessor: (r) => r.site_name,
        cell: (r) => (
          <Link
            to={`/sites/${r.site_id}/security/access`}
            className="text-[13px] text-brand hover:underline"
            onClick={(e) => e.stopPropagation()}
          >
            {r.site_name || r.site_id}
          </Link>
        ),
      },
      {
        key: 'attack_count',
        header: t('pages.blockedIps.colAttacks'),
        accessor: (r) => r.attack_count,
        sortable: true,
        width: '1%',
        cell: (r) =>
          r.attack_count > 0 ? (
            <Badge tone="danger">{formatNumber(r.attack_count)}</Badge>
          ) : (
            <span className="text-[13px] text-fg-subtle">—</span>
          ),
      },
      {
        key: 'last_attack_at',
        header: t('pages.blockedIps.colLastAttack'),
        accessor: (r) => r.last_attack_at ?? '',
        sortable: true,
        width: '1%',
        cell: (r) =>
          r.last_attack_at ? (
            <span
              className="text-[13px] text-fg-subtle"
              title={formatDateTime(r.last_attack_at)}
            >
              {formatRelative(r.last_attack_at)}
            </span>
          ) : (
            <span className="text-[13px] text-fg-subtle">—</span>
          ),
      },
      {
        key: 'blocked_at',
        header: t('pages.blockedIps.colBlockedAt'),
        accessor: (r) => r.blocked_at,
        sortable: true,
        width: '1%',
        cell: (r) => (
          <div className="min-w-0">
            <p
              className="text-[13px] text-fg-strong"
              title={formatDateTime(r.blocked_at)}
            >
              {formatRelative(r.blocked_at)}
            </p>
            <p className="text-xs text-fg-subtle">
              {formatDateTime(r.blocked_at)}
            </p>
          </div>
        ),
      },
      {
        key: 'expires_at',
        header: t('pages.blockedIps.colExpiresAt'),
        accessor: (r) => r.expires_at ?? '',
        width: '1%',
        cell: (r) =>
          r.expires_at ? (
            <div className="min-w-0">
              <p
                className="text-[13px] text-fg-strong"
                title={formatDateTime(r.expires_at)}
              >
                {formatRelative(r.expires_at)}
              </p>
              <p className="text-xs text-fg-subtle">
                {formatDateTime(r.expires_at)}
              </p>
            </div>
          ) : (
            <Badge tone="neutral">{t('pages.blockedIps.permanent')}</Badge>
          ),
      },
      {
        key: 'agent_count',
        header: t('pages.blockedIps.colAgents'),
        accessor: (r) => r.agent_count,
        width: '1%',
        cell: (r) => (
          <Badge tone="info">
            {t('pages.blockedIps.agentsCount', { count: r.agent_count })}
          </Badge>
        ),
      },
      {
        key: 'row-actions',
        header: '',
        align: 'right',
        width: '1%',
        cell: (r) => (
          <Button
            size="sm"
            variant="secondary"
            disabled={!canWrite}
            onClick={(e) => {
              e.stopPropagation()
              setPendingUnblock(r)
            }}
          >
            {t('pages.blockedIps.unblock')}
          </Button>
        ),
      },
    ],
    [t, canWrite],
  )

  return (
    <>
      <PageHeader
        title={t('pages.blockedIps.title')}
        description={t('pages.blockedIps.description')}
        actions={
          canWrite ? (
            <Button variant="primary" onClick={() => setBlockOpen(true)}>
              <Plus className="h-4 w-4" />
              {t('pages.blockedIps.blockManual')}
            </Button>
          ) : undefined
        }
      />

      <Card>
        <CardBody>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <Select
              value={siteFilter}
              onChange={(e) => setSiteFilter(e.target.value)}
              options={[
                { value: '', label: t('pages.blockedIps.filterAllSites') },
                ...(sites ?? []).map((s) => ({
                  value: s.id,
                  label: s.name || s.domain,
                })),
              ]}
            />
            <Input
              value={ipFilter}
              onChange={(e) => setIpFilter(e.target.value)}
              placeholder={t('pages.blockedIps.filterIpPh')}
              className="w-52"
            />
            <span className="ml-auto text-sm text-fg-subtle">
              {t('pages.blockedIps.total', { count: items.length })}
            </span>
          </div>

          {listQuery.isError && !listQuery.data ? (
            <ErrorState
              error={listQuery.error}
              onRetry={() => listQuery.refetch()}
              retrying={listQuery.isFetching}
            />
          ) : listQuery.isPending ? (
            <SkeletonRows columns={8} rows={5} />
          ) : items.length === 0 ? (
            <EmptyState
              icon={<ShieldWarning weight="duotone" className="h-8 w-8" />}
              title={t('pages.blockedIps.empty')}
              description={t('pages.blockedIps.emptyDescription')}
            />
          ) : (
            <Table
              columns={columns}
              data={items}
              rowKey={(r) => `${r.site_id}:${r.ip}`}
              dense
            />
          )}
        </CardBody>
      </Card>

      {blockOpen && (
        <ManualBlockDialog
          onClose={() => setBlockOpen(false)}
          onBlocked={() => {
            setBlockOpen(false)
            invalidate()
          }}
        />
      )}

      <ConfirmDialog
        open={pendingUnblock !== null}
        onClose={() => setPendingUnblock(null)}
        onConfirm={() => pendingUnblock && unblock.mutate(pendingUnblock)}
        title={t('pages.blockedIps.unblockTitle')}
        description={t('pages.blockedIps.unblockDescription')}
        confirmLabel={t('pages.blockedIps.unblock')}
        loading={unblock.isPending}
      >
        {pendingUnblock && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono flex items-center gap-2 text-[13px] font-medium text-fg-strong">
              <Prohibit weight="duotone" className="h-4 w-4 text-fg-danger" />
              {pendingUnblock.ip}
            </p>
            <p className="mt-0.5 text-xs text-fg-subtle">
              {pendingUnblock.site_name}
              {pendingUnblock.reason ? ` · ${pendingUnblock.reason}` : ''}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </>
  )
}

/* ── Manual block dialog ──────────────────────────────────────────── */

interface ManualBlockDialogProps {
  onClose: () => void
  onBlocked: () => void
}

function ManualBlockDialog({ onClose, onBlocked }: ManualBlockDialogProps) {
  const { t } = useTranslation()
  const toast = useToast()
  const { data: sites } = useSitesList()

  const [siteId, setSiteId] = useState('')
  const [ip, setIp] = useState('')
  const [duration, setDuration] = useState('3600')
  const [reason, setReason] = useState('')

  const ipError = useMemo(() => {
    const v = ip.trim()
    if (!v) return null
    // The edge command blocks a single address; CIDR ranges belong in IP
    // rules, so reject them here even though they parse fine.
    if (v.includes('/')) return t('pages.blockedIps.ipNoCidr')
    return validateIpCidr(v) !== null ? t('pages.blockedIps.ipInvalid') : null
  }, [ip, t])

  const canSubmit = Boolean(siteId) && ip.trim().length > 0 && !ipError

  const block = useMutation({
    mutationFn: () =>
      blockedIpsApi.block({
        site_id: siteId,
        ip: ip.trim(),
        duration_seconds: Number(duration),
        reason: reason.trim() || undefined,
      }),
    onSuccess: (result) => {
      toast.success(
        t('pages.blockedIps.blocked', {
          ip: result.ip,
          delivered: result.delivered,
          agents: result.agents,
        }),
      )
      onBlocked()
    },
    onError: (e) =>
      toast.error(
        e instanceof Error ? e.message : t('pages.blockedIps.blockFailed'),
      ),
  })

  return (
    <Dialog
      open
      onClose={onClose}
      title={t('pages.blockedIps.blockTitle')}
      className="max-w-lg"
    >
      <div className="space-y-4">
        <Select
          label={t('pages.blockedIps.fieldSite')}
          value={siteId}
          onChange={(e) => setSiteId(e.target.value)}
          options={[
            { value: '', label: t('pages.blockedIps.fieldSitePh') },
            ...(sites ?? []).map((s) => ({
              value: s.id,
              label: s.name || s.domain,
            })),
          ]}
        />
        <div>
          <Input
            label={t('pages.blockedIps.fieldIp')}
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder={t('pages.blockedIps.fieldIpPh')}
          />
          {ipError && <p className="mt-1 text-xs text-danger">{ipError}</p>}
        </div>
        <Select
          label={t('pages.blockedIps.fieldDuration')}
          value={duration}
          onChange={(e) => setDuration(e.target.value)}
          options={DURATION_OPTIONS.map((option) => ({
            value: option.value,
            label: t(`pages.blockedIps.${option.labelKey}`),
          }))}
        />
        <Input
          label={t('pages.blockedIps.fieldReason')}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={t('pages.blockedIps.fieldReasonPh')}
        />
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            disabled={!canSubmit || block.isPending}
            onClick={() => block.mutate()}
          >
            {t('pages.blockedIps.blockConfirm')}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}

export default BlockedIpsPage
