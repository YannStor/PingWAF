import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Prohibit, ShieldWarning, X } from '@phosphor-icons/react'
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
import { errorMessage } from '@/api/errors'
import { validateIpOrCidr } from '@/api/ipRules'
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
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [batch, setBatch] = useState<{ total: number; done: number; failed: string[] } | null>(null)
  const [pendingBatchUnblock, setPendingBatchUnblock] = useState(false)

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

  /* ── Row selection + batch unblock ────────────────────────────────── */
  const rowKeyOf = (r: GlobalBlockedIp) => `${r.site_id}:${r.ip}`
  const selectedRows = useMemo(() => items.filter((r) => selected.has(rowKeyOf(r))), [items, selected])
  const allSelected = items.length > 0 && selectedRows.length === items.length
  const someSelected = selectedRows.length > 0 && !allSelected

  const toggleRow = (r: GlobalBlockedIp) =>
    setSelected((prev) => {
      const next = new Set(prev)
      const key = rowKeyOf(r)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })

  const toggleAll = () =>
    setSelected(allSelected ? new Set() : new Set(items.map(rowKeyOf)))

  const clearSelection = () => setSelected(new Set())

  /** Sequentially unblocks the selection with progress "3/10" reporting. */
  const runBatchUnblock = async () => {
    const rows = selectedRows
    setPendingBatchUnblock(false)
    if (rows.length === 0) return
    const failed: string[] = []
    for (let done = 0; done < rows.length; done++) {
      setBatch({ total: rows.length, done, failed: [...failed] })
      try {
        await blockedIpsApi.unblock(rows[done].site_id, rows[done].ip)
      } catch {
        failed.push(rows[done].ip)
      }
    }
    setBatch({ total: rows.length, done: rows.length, failed: [...failed] })
    invalidate()
    clearSelection()
    if (failed.length === 0) {
      toast.success(t('common.batch.done', { count: rows.length }))
    } else {
      toast.error(
        t('common.batch.partial', {
          failed: failed.length,
          total: rows.length,
          names: failed.slice(0, 3).join(', '),
        }),
      )
    }
    setBatch(null)
  }

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
        key: 'select',
        header: (
          <input
            type="checkbox"
            aria-label={t('common.batch.selectAll')}
            checked={allSelected}
            ref={(el) => {
              if (el) el.indeterminate = someSelected
            }}
            onChange={toggleAll}
            disabled={batch !== null}
            className="h-4 w-4 cursor-pointer rounded border-border align-middle disabled:cursor-not-allowed disabled:opacity-50"
          />
        ),
        width: '1%',
        cell: (r) => (
          <input
            type="checkbox"
            aria-label={r.ip}
            checked={selected.has(rowKeyOf(r))}
            onChange={() => toggleRow(r)}
            onClick={(e) => e.stopPropagation()}
            disabled={batch !== null}
            className="h-4 w-4 cursor-pointer rounded border-border align-middle disabled:cursor-not-allowed disabled:opacity-50"
          />
        ),
      },
      {
        key: 'ip',
        header: t('pages.blockedIps.colIp'),
        accessor: (r) => r.ip,
        cell: (r) => (
          <div className="min-w-0">
            <p className="pw-mono flex items-center gap-1.5 truncate text-[13px] font-medium text-fg-strong">
              {r.ip}
              {r.kind === 'cidr' && (
                <Badge tone="warning">{t('pages.blockedIps.kindCidr')}</Badge>
              )}
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
    [t, canWrite, allSelected, someSelected, selected],
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

      {/* Batch unblock bar */}
      {batch ? (
        <div className="mb-4 flex flex-wrap items-center gap-3 rounded-md border border-line bg-recessed px-4 py-2.5 text-[13px]">
          <span className="inline-flex items-center gap-2">
            <span className="h-4 w-4 animate-spin-slow rounded-full border-2 border-brand border-t-transparent" />
            {t('common.batch.progress', { done: batch.done, total: batch.total })}
          </span>
          <span className="text-fg-subtle">{t('pages.blockedIps.unblocking')}</span>
        </div>
      ) : selectedRows.length > 0 && canWrite ? (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-md border border-brand/40 bg-brand-soft px-4 py-2.5 text-[13px]">
          <span className="font-medium text-fg-strong">
            {t('common.batch.selected', { count: selectedRows.length })}
          </span>
          <div className="ml-auto flex items-center gap-2">
            <Button size="sm" variant="secondary" icon={<Prohibit weight="duotone" className="h-4 w-4" />} onClick={() => setPendingBatchUnblock(true)}>
              {t('pages.blockedIps.unblock')}
            </Button>
            <Button size="sm" variant="ghost" icon={<X weight="bold" className="h-4 w-4" />} onClick={clearSelection}>
              {t('common.batch.clear')}
            </Button>
          </div>
        </div>
      ) : null}

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
              key={`${siteFilter}|${ipFilter}`}
              columns={columns}
              data={items}
              rowKey={(r) => `${r.site_id}:${r.ip}`}
              pageSize={50}
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
      <ConfirmDialog
        open={pendingBatchUnblock}
        onClose={() => setPendingBatchUnblock(false)}
        onConfirm={() => void runBatchUnblock()}
        title={t('pages.blockedIps.unblockTitle')}
        description={t('common.batch.unblockDescription', { count: selectedRows.length })}
        confirmLabel={t('pages.blockedIps.unblock')}
        tone="primary"
      >
        <div className="max-h-40 overflow-y-auto rounded-md border border-line bg-recessed px-3 py-2">
          {selectedRows.map((r) => (
            <p key={`${r.site_id}:${r.ip}`} className="pw-mono truncate text-[13px] text-fg-strong">
              {r.ip}
            </p>
          ))}
        </div>
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
    // The backend accepts a single address or a CIDR range; prefixes broader
    // than /16 (IPv4) or /32 (IPv6) are rejected server-side with a 400, so
    // the same floor is enforced here with a dedicated inline error.
    const reason = validateIpOrCidr(v, { v4: 16, v6: 32 })
    if (reason === 'prefix') return t('pages.blockedIps.ipPrefixInvalid')
    if (reason === 'tooBroad') return t('pages.blockedIps.ipTooBroad')
    if (reason !== null) return t('pages.blockedIps.ipInvalid')
    return null
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
    onError: (e) => toast.error(errorMessage(e) || t('pages.blockedIps.blockFailed')),
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
            hint={t('pages.blockedIps.fieldIpHint')}
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
