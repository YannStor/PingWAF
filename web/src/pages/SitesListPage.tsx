import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Globe,
  MagnifyingGlass,
  Pause,
  PencilSimple,
  Play,
  Trash,
  X,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody } from '@/components/ui/Card'
import { Badge, type BadgeTone } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Table, type Column } from '@/components/ui/Table'
import { Dialog } from '@/components/ui/Dialog'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { EmptyState } from '@/components/ui/EmptyState'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { sitesApi, siteKeys } from '@/api/sites'
import { analyticsApi, analyticsKeys } from '@/api/analytics'
import { useCanWrite, useDebouncedValue } from '@/hooks'
import { formatCompactNumber, formatDateTime, formatNumber } from '@/lib/format'
import type { CreateSiteRequest, Site, SiteStatus, UpdateSiteRequest } from '@/api/types'

const STATUS_TONE: Record<SiteStatus, BadgeTone> = {
  active: 'success',
  paused: 'warning',
  pending: 'neutral',
}

/** Per-field form errors — one slot per validated field. */
interface SiteFormErrors {
  name?: string
  domain?: string
  alternateDomains?: string
  upstream?: string
}

interface SiteFormState {
  name: string
  domain: string
  alternateDomains: string[]
  upstreamAddress: string
  upstreamName: string
  upstreamTls: boolean
}

const emptyForm: SiteFormState = {
  name: '',
  domain: '',
  alternateDomains: [],
  upstreamAddress: '',
  upstreamName: '',
  upstreamTls: false,
}

/**
 * A hostname, optionally a wildcard: `*.` may only lead, its base needs at
 * least two labels, so `*.com` is not a valid hostname.
 */
const DOMAIN_PATTERN = /^(?=.{1,253}$)(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/

/** Drops a pasted scheme/trailing path and lower-cases the hostname. */
function normaliseDomainInput(value: string): string {
  return value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
}

export function SitesListPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const [query, setQuery] = useState('')
  const debouncedQuery = useDebouncedValue(query.trim(), 350)

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<Site | null>(null)
  const [form, setForm] = useState<SiteFormState>(emptyForm)
  const [formErrors, setFormErrors] = useState<SiteFormErrors>({})
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [batch, setBatch] = useState<{
    kind: 'pause' | 'resume' | 'delete'
    total: number
    done: number
    failed: string[]
  } | null>(null)
  const [pendingBatchDelete, setPendingBatchDelete] = useState(false)
  const [pendingBatchToggle, setPendingBatchToggle] = useState<
    'pause' | 'resume' | null
  >(null)
  const [pendingDelete, setPendingDelete] = useState<Site | null>(null)
  const [pendingToggle, setPendingToggle] = useState<Site | null>(null)

  const sitesQuery = useQuery({
    queryKey: siteKeys.list({ search: debouncedQuery || undefined }),
    queryFn: () => sitesApi.list({ search: debouncedQuery || undefined }),
    select: (page) => page.items,
  })

  // Per-site request/blocked counters live in analytics, not in `/sites`.
  const trafficQuery = useQuery({
    queryKey: analyticsKeys.sites({}),
    queryFn: () => analyticsApi.sitesOverview(),
    staleTime: 60_000,
  })

  const trafficBySite = useMemo(() => {
    const map = new Map<string, { requests: number; blocked: number }>()
    for (const row of trafficQuery.data ?? []) {
      map.set(row.site_id, { requests: row.requests, blocked: row.blocked })
    }
    return map
  }, [trafficQuery.data])

  const sites = sitesQuery.data ?? []

  /* ── Row selection (Z1 batch operations) ─────────────────────────── */
  const selectedIds = useMemo(
    () => sites.filter((s) => selected.has(s.id)).map((s) => s.id),
    [sites, selected],
  )
  const allSelected = sites.length > 0 && selectedIds.length === sites.length
  const someSelected = selectedIds.length > 0 && !allSelected

  const toggleRow = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const toggleAll = () =>
    setSelected(allSelected ? new Set() : new Set(sites.map((s) => s.id)))

  const clearSelection = () => setSelected(new Set())

  /**
   * Runs a mutation over the selection sequentially, tracking progress so the
   * batch bar can show "3/10" while it runs. Failures are collected and
   * summarised at the end; the list is invalidated once, after the loop.
   */
  const runBatch = async (
    kind: 'pause' | 'resume' | 'delete',
    rows: Site[],
    apply: (row: Site) => Promise<unknown>,
  ) => {
    const failed: string[] = []
    for (let done = 0; done < rows.length; done++) {
      setBatch({ kind, total: rows.length, done, failed: [...failed] })
      try {
        await apply(rows[done])
      } catch {
        failed.push(rows[done].domain || rows[done].id)
      }
    }
    setBatch({ kind, total: rows.length, done: rows.length, failed: [...failed] })
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

  const batchPause = () => {
    setPendingBatchToggle(null)
    void runBatch(
      'pause',
      sites.filter((s) => selected.has(s.id) && s.status === 'active'),
      (s) => sitesApi.update(s.id, { status: 'paused' }),
    )
  }

  const batchResume = () => {
    setPendingBatchToggle(null)
    void runBatch(
      'resume',
      sites.filter((s) => selected.has(s.id) && s.status === 'paused'),
      (s) => sitesApi.update(s.id, { status: 'active' }),
    )
  }

  const batchDelete = () => {
    const rows = sites.filter((s) => selected.has(s.id))
    setPendingBatchDelete(false)
    void runBatch('delete', rows, (s) => sitesApi.delete(s.id))
  }


  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: siteKeys.all })
    void queryClient.invalidateQueries({ queryKey: analyticsKeys.all })
  }

  const createSite = useMutation({
    mutationFn: (data: CreateSiteRequest) => sitesApi.create(data),
    onSuccess: (site) => {
      toast.success(t('pages.sites.created'), site.domain)
      closeDialog()
      invalidate()
      navigate(`/sites/${site.id}/basic`)
    },
  })

  const updateSite = useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateSiteRequest }) =>
      sitesApi.update(id, data),
    onSuccess: (site) => {
      toast.success(t('pages.sites.updated'), site.domain)
      closeDialog()
      invalidate()
    },
  })

  /** Pausing takes a site off the air, so it always goes through a confirm. */
  const toggleStatus = useMutation({
    mutationFn: ({ site, status }: { site: Site; status: SiteStatus }) =>
      sitesApi.update(site.id, { status }),
    onSuccess: (site) => {
      toast.success(
        site.status === 'active' ? t('pages.sites.activated') : t('pages.sites.deactivated'),
        site.domain,
      )
      setPendingToggle(null)
      invalidate()
    },
  })

  const deleteSite = useMutation({
    mutationFn: (id: string) => sitesApi.delete(id),
    onSuccess: (_data, id) => {
      const removed = sites.find((s) => s.id === id)
      toast.success(t('pages.sites.deleted'), removed?.domain)
      setPendingDelete(null)
      invalidate()
    },
  })

  const openCreate = () => {
    setEditing(null)
    setForm(emptyForm)
    setFormErrors({})
    setDialogOpen(true)
  }

  const openEdit = (site: Site) => {
    setEditing(site)
    setForm({
      ...emptyForm,
      name: site.name,
      domain: site.domain,
      alternateDomains: site.alternate_domains ?? [],
    })
    setFormErrors({})
    setDialogOpen(true)
  }

  const closeDialog = () => {
    setDialogOpen(false)
    setEditing(null)
    setForm(emptyForm)
    setFormErrors({})
  }

  /** Blur-level format check: cheap, per-field, no cross-field rules. */
  const validateName = () => {
    setFormErrors((e) => ({
      ...e,
      name: form.name.trim() ? undefined : t('pages.sites.nameRequired'),
    }))
  }

  const validateDomainField = () => {
    const domain = normaliseDomainInput(form.domain)
    setFormErrors((e) => ({
      ...e,
      domain: DOMAIN_PATTERN.test(domain) ? undefined : t('pages.sites.domainInvalid'),
    }))
  }

  const validateAlternateDomain = (index: number) => {
    const raw = form.alternateDomains[index]
    if (raw === undefined) return
    const value = normaliseDomainInput(raw)
    setFormErrors((e) => ({
      ...e,
      alternateDomains:
        !value || DOMAIN_PATTERN.test(value)
          ? undefined
          : t('pages.sites.domainInvalid'),
    }))
  }

  const submit = () => {
    const domain = normaliseDomainInput(form.domain)
    const name = form.name.trim()
    const errors: SiteFormErrors = {}

    if (!name) errors.name = t('pages.sites.nameRequired')
    if (!DOMAIN_PATTERN.test(domain)) errors.domain = t('pages.sites.domainInvalid')

    const alternateDomains: string[] = []
    for (const raw of form.alternateDomains) {
      const value = normaliseDomainInput(raw)
      if (!value) continue
      if (!DOMAIN_PATTERN.test(value)) {
        errors.alternateDomains = t('pages.sites.domainInvalid')
        break
      }
      if (value === domain || alternateDomains.includes(value)) {
        errors.alternateDomains = t('pages.sites.domainDuplicate', { domain: value })
        break
      }
      alternateDomains.push(value)
    }

    if (!editing && !form.upstreamAddress.trim()) {
      errors.upstream = t('pages.sites.upstreamRequired')
    }

    setFormErrors(errors)
    if (Object.values(errors).some(Boolean)) return

    if (editing) {
      updateSite.mutate({
        id: editing.id,
        data: { name, domain, alternate_domains: alternateDomains },
      })
      return
    }

    const upstreamAddress = form.upstreamAddress.trim()

    const payload: CreateSiteRequest = {
      name,
      domain,
      alternate_domains: alternateDomains,
      upstream_address: upstreamAddress,
    }
    const upstreamName = form.upstreamName.trim()
    if (upstreamName) payload.upstream_name = upstreamName
    if (form.upstreamTls) payload.upstream_tls = true
    createSite.mutate(payload)
  }

  const pending = createSite.isPending || updateSite.isPending

  const columns: Column<Site>[] = [
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
          aria-label={r.name || r.domain}
          checked={selected.has(r.id)}
          onChange={() => toggleRow(r.id)}
          onClick={(e) => e.stopPropagation()}
          disabled={batch !== null}
          className="h-4 w-4 cursor-pointer rounded border-border align-middle disabled:cursor-not-allowed disabled:opacity-50"
        />
      ),
    },
    {
      key: 'domain',
      header: t('pages.sites.domain'),
      accessor: (r) => r.domain,
      sortable: true,
      cell: (r) => (
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-brand-soft text-brand">
            <Globe weight="duotone" className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <p className="pw-mono truncate font-medium text-fg-strong">
              {r.domain}
              {(r.alternate_domains?.length ?? 0) > 0 && (
                <span className="ml-1.5 text-xs font-normal text-fg-subtle">
                  +{r.alternate_domains.length}
                </span>
              )}
            </p>
            <p className="truncate text-xs text-fg-subtle">{r.name}</p>
          </div>
        </div>
      ),
    },
    {
      key: 'status',
      header: t('common.status'),
      accessor: (r) => (r.status === 'active' ? 1 : 0),
      width: '120px',
      cell: (r) => (
        <Badge tone={STATUS_TONE[r.status as SiteStatus] ?? 'neutral'} dot>
          {t(`status.${r.status}`, r.status)}
        </Badge>
      ),
    },
    {
      key: 'requests',
      header: t('pages.sites.requests'),
      align: 'right',
      sortable: true,
      accessor: (r) => trafficBySite.get(r.id)?.requests ?? 0,
      cell: (r) => (
        <span className="tabular-nums text-[13px]">
          {trafficQuery.isPending
            ? '…'
            : formatCompactNumber(trafficBySite.get(r.id)?.requests ?? 0)}
        </span>
      ),
    },
    {
      key: 'blocked',
      header: t('pages.sites.blocked'),
      align: 'right',
      sortable: true,
      accessor: (r) => trafficBySite.get(r.id)?.blocked ?? 0,
      cell: (r) => (
        <span className="tabular-nums text-[13px] text-fg-danger">
          {trafficQuery.isPending
            ? '…'
            : formatCompactNumber(trafficBySite.get(r.id)?.blocked ?? 0)}
        </span>
      ),
    },
    {
      key: 'created_at',
      header: t('pages.sites.added'),
      accessor: (r) => r.created_at,
      sortable: true,
      cell: (r) => (
        <span className="text-[13px] text-fg-subtle">{formatDateTime(r.created_at)}</span>
      ),
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (r) => (
        <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <Button
            size="icon"
            variant="ghost"
            aria-label={
              r.status === 'active' ? t('pages.sites.deactivate') : t('pages.sites.activate')
            }
            disabled={!canWrite || toggleStatus.isPending}
            loading={toggleStatus.isPending && toggleStatus.variables?.site.id === r.id}
            onClick={() => setPendingToggle(r)}
            icon={
              r.status === 'active' ? (
                <Pause weight="duotone" className="h-4 w-4" />
              ) : (
                <Play weight="duotone" className="h-4 w-4" />
              )
            }
          />
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('common.edit')}
            disabled={!canWrite}
            onClick={() => openEdit(r)}
            icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            className="hover:text-fg-danger"
            onClick={() => setPendingDelete(r)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.sites.title')}
        description={t('pages.sites.description')}
        actions={
          canWrite ? (
            <Button
              variant="primary"
              icon={<Plus weight="bold" className="h-4 w-4" />}
              onClick={openCreate}
            >
              {t('pages.sites.addSite')}
            </Button>
          ) : undefined
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="w-full max-w-sm">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('pages.sites.searchPlaceholder')}
            prefixIcon={<MagnifyingGlass weight="duotone" />}
            aria-label={t('common.search')}
          />
        </div>
        {!sitesQuery.isPending && (
          <span className="text-[13px] text-fg-subtle tabular-nums">
            {t('pages.sites.count', { count: sites.length })}
          </span>
        )}
      </div>

      {/* Batch operations bar */}
      {batch ? (
        <div className="mb-4 flex flex-wrap items-center gap-3 rounded-md border border-line bg-recessed px-4 py-2.5 text-[13px]">
          <span className="inline-flex items-center gap-2">
            <span className="h-4 w-4 animate-spin-slow rounded-full border-2 border-brand border-t-transparent" />
            {t('common.batch.progress', { done: batch.done, total: batch.total })}
          </span>
          <span className="text-fg-subtle">
            {batch.kind === 'delete'
              ? t('common.batch.deleting')
              : batch.kind === 'pause'
                ? t('common.batch.pausing')
                : t('common.batch.resuming')}
          </span>
        </div>
      ) : selectedIds.length > 0 && canWrite ? (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-md border border-brand/40 bg-brand-soft px-4 py-2.5 text-[13px]">
          <span className="font-medium text-fg-strong">
            {t('common.batch.selected', { count: selectedIds.length })}
          </span>
          <div className="ml-auto flex items-center gap-2">
            <Button size="sm" variant="secondary" icon={<Pause weight="duotone" className="h-4 w-4" />} onClick={() => setPendingBatchToggle('pause')}>
              {t('pages.sites.deactivate')}
            </Button>
            <Button size="sm" variant="secondary" icon={<Play weight="duotone" className="h-4 w-4" />} onClick={() => setPendingBatchToggle('resume')}>
              {t('pages.sites.activate')}
            </Button>
            <Button size="sm" variant="secondary" className="hover:text-fg-danger" icon={<Trash weight="duotone" className="h-4 w-4" />} onClick={() => setPendingBatchDelete(true)}>
              {t('common.delete')}
            </Button>
            <Button size="sm" variant="ghost" icon={<X weight="bold" className="h-4 w-4" />} onClick={clearSelection}>
              {t('common.batch.clear')}
            </Button>
          </div>
        </div>
      ) : null}

      {sitesQuery.isError && !sitesQuery.data ? (
        <ErrorState
          error={sitesQuery.error}
          onRetry={() => sitesQuery.refetch()}
          retrying={sitesQuery.isFetching}
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            {sitesQuery.isPending ? (
              <SkeletonRows rows={6} columns={5} />
            ) : sites.length === 0 ? (
              debouncedQuery ? (
                <EmptyState
                  className="py-14"
                  icon={<MagnifyingGlass weight="duotone" className="h-8 w-8" />}
                  title={t('pages.sites.noResults')}
                  description={t('pages.sites.noResultsDescription', { query: debouncedQuery })}
                  action={
                    <Button variant="secondary" onClick={() => setQuery('')}>
                      {t('common.reset')}
                    </Button>
                  }
                />
              ) : (
                <EmptyState
                  className="py-14"
                  icon={<Globe weight="duotone" className="h-8 w-8" />}
                  title={t('pages.sites.emptyTitle')}
                  description={t('pages.sites.emptyDescription')}
                  action={
                    canWrite ? (
                      <Button
                        variant="primary"
                        icon={<Plus weight="bold" className="h-4 w-4" />}
                        onClick={openCreate}
                      >
                        {t('pages.sites.addSite')}
                      </Button>
                    ) : undefined
                  }
                />
              )
            ) : (
              <Table
                columns={columns}
                data={sites}
                rowKey={(r) => r.id}
                pageSize={20}
                onRowClick={(r) => navigate(`/sites/${r.id}/basic`)}
              />
            )}
          </CardBody>
        </Card>
      )}

      {/* Create / edit dialog */}
      <Dialog
        open={dialogOpen}
        onClose={pending ? () => undefined : closeDialog}
        title={editing ? t('pages.sites.editSite') : t('pages.sites.addSite')}
        description={editing ? t('pages.sites.editDescription') : t('pages.sites.createDescription')}
        footer={
          <>
            <Button variant="ghost" onClick={closeDialog} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button variant="primary" onClick={submit} loading={pending}>
              {editing ? t('common.save') : t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Input
            label={t('common.name')}
            value={form.name}
            placeholder={t('pages.sites.namePlaceholder')}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            onBlur={validateName}
            error={formErrors.name}
            autoFocus
            required
          />
          <Input
            label={t('pages.sites.domain')}
            value={form.domain}
            placeholder="example.com"
            hint={t('pages.sites.domainHint')}
            error={formErrors.domain}
            prefixIcon={<Globe weight="duotone" />}
            onChange={(e) => setForm((f) => ({ ...f, domain: e.target.value }))}
            onBlur={validateDomainField}
            required
          />

          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-[13px] font-medium text-fg-subtle">
                {t('pages.sites.alternateDomains')}
              </span>
              <Button
                size="sm"
                variant="ghost"
                icon={<Plus weight="bold" className="h-3.5 w-3.5" />}
                onClick={() =>
                  setForm((f) => ({ ...f, alternateDomains: [...f.alternateDomains, ''] }))
                }
              >
                {t('common.add')}
              </Button>
            </div>
            {form.alternateDomains.map((value, index) => (
              <div key={index} className="flex items-center gap-2">
                <div className="flex-1">
                  <Input
                    value={value}
                    placeholder="*.example.com"
                    aria-label={t('pages.sites.alternateDomains')}
                    prefixIcon={<Globe weight="duotone" />}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        alternateDomains: f.alternateDomains.map((item, i) =>
                          i === index ? e.target.value : item,
                        ),
                      }))
                    }
                    onBlur={() => validateAlternateDomain(index)}
                  />
                </div>
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label={t('common.remove')}
                  className="hover:text-fg-danger"
                  onClick={() =>
                    setForm((f) => ({
                      ...f,
                      alternateDomains: f.alternateDomains.filter((_, i) => i !== index),
                    }))
                  }
                  icon={<X weight="bold" className="h-4 w-4" />}
                />
              </div>
            ))}
            <p className="text-xs text-fg-subtle">{t('pages.sites.alternateDomainsHint')}</p>
          </div>

          {!editing && (
            <>
              <Input
                label={t('pages.sites.upstream')}
                value={form.upstreamAddress}
                placeholder="https://origin.example.com:443"
                hint={t('pages.sites.upstreamHint')}
                error={formErrors.upstream}
                onChange={(e) => setForm((f) => ({ ...f, upstreamAddress: e.target.value }))}
                required
              />
              <div className="grid grid-cols-2 gap-3">
                <Input
                  label={t('pages.sites.upstreamName')}
                  value={form.upstreamName}
                  placeholder="origin-1"
                  onChange={(e) => setForm((f) => ({ ...f, upstreamName: e.target.value }))}
                />
                <div className="flex items-end pb-1">
                  <Switch
                    checked={form.upstreamTls}
                    onCheckedChange={(upstreamTls) => setForm((f) => ({ ...f, upstreamTls }))}
                    label={t('pages.sites.upstreamTls')}
                    description={t('pages.sites.upstreamTlsHint')}
                  />
                </div>
              </div>
            </>
          )}
        </div>
      </Dialog>

      {/* Pause / resume confirmation */}
      <ConfirmDialog
        open={pendingToggle !== null}
        onClose={() => setPendingToggle(null)}
        onConfirm={() =>
          pendingToggle &&
          toggleStatus.mutate({
            site: pendingToggle,
            status: pendingToggle.status === 'active' ? 'paused' : 'active',
          })
        }
        title={
          pendingToggle?.status === 'active'
            ? t('pages.sites.pauseTitle')
            : t('pages.sites.resumeTitle')
        }
        description={
          pendingToggle?.status === 'active'
            ? t('pages.sites.pauseDescription')
            : t('pages.sites.resumeDescription')
        }
        confirmLabel={
          pendingToggle?.status === 'active'
            ? t('pages.sites.deactivate')
            : t('pages.sites.activate')
        }
        tone={pendingToggle?.status === 'active' ? 'danger' : 'primary'}
        loading={toggleStatus.isPending}
      >
        {pendingToggle && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono text-[13px] font-medium text-fg-strong">
              {pendingToggle.domain}
            </p>
          </div>
        )}
      </ConfirmDialog>

      {/* Delete confirmation */}
      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && deleteSite.mutate(pendingDelete.id)}
        title={t('pages.sites.deleteTitle')}
        description={t('pages.sites.deleteDescription')}
        confirmLabel={t('common.delete')}
        loading={deleteSite.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono text-[13px] font-medium text-fg-strong">{pendingDelete.domain}</p>
            <p className="mt-0.5 text-xs text-fg-subtle">
              {t('pages.sites.deleteMeta', {
                requests: formatNumber(trafficBySite.get(pendingDelete.id)?.requests ?? 0),
              })}
            </p>
          </div>
        )}
      </ConfirmDialog>
      {/* Batch pause / resume confirmation */}
      <ConfirmDialog
        open={pendingBatchToggle !== null}
        onClose={() => setPendingBatchToggle(null)}
        onConfirm={pendingBatchToggle === 'resume' ? batchResume : batchPause}
        title={
          pendingBatchToggle === 'resume'
            ? t('common.batch.resumeTitle')
            : t('common.batch.pauseTitle')
        }
        description={
          pendingBatchToggle === 'resume'
            ? t('common.batch.resumeDescription', { count: selectedIds.length })
            : t('common.batch.pauseDescription', { count: selectedIds.length })
        }
        confirmLabel={
          pendingBatchToggle === 'resume'
            ? t('pages.sites.activate')
            : t('pages.sites.deactivate')
        }
        tone={pendingBatchToggle === 'resume' ? 'primary' : 'danger'}
      >
        <div className="max-h-40 overflow-y-auto rounded-md border border-line bg-recessed px-3 py-2">
          {sites
            .filter((s) =>
              pendingBatchToggle === 'resume'
                ? selected.has(s.id) && s.status === 'paused'
                : selected.has(s.id) && s.status === 'active',
            )
            .map((s) => (
              <p key={s.id} className="pw-mono truncate text-[13px] text-fg-strong">
                {s.domain}
              </p>
            ))}
        </div>
      </ConfirmDialog>
      {/* Batch delete confirmation */}
      <ConfirmDialog
        open={pendingBatchDelete}
        onClose={() => setPendingBatchDelete(false)}
        onConfirm={batchDelete}
        title={t('common.batch.deleteTitle')}
        description={t('common.batch.deleteDescription', { count: selectedIds.length })}
        confirmLabel={t('common.delete')}
        tone="danger"
      >
        <div className="max-h-40 overflow-y-auto rounded-md border border-line bg-recessed px-3 py-2">
          {sites
            .filter((s) => selected.has(s.id))
            .map((s) => (
              <p key={s.id} className="pw-mono truncate text-[13px] text-fg-strong">
                {s.domain}
              </p>
            ))}
        </div>
      </ConfirmDialog>
    </div>
  )
}
