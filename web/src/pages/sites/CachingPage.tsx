import { useMemo, useState, type ReactNode } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  ArrowCounterClockwise,
  Broom,
  CheckCircle,
  Lightning,
  PencilSimple,
  Plus,
  Trash,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Dialog } from '@/components/ui/Dialog'
import { Textarea } from '@/components/ui/Textarea'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { Skeleton, SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { cachingApi, cacheKeys } from '@/api/caching'
import { useCanWrite } from '@/hooks'
import { cn } from '@/lib/utils'
import { formatDateTime, formatNumber, formatPercent, formatSize } from '@/lib/format'
import type {
  CacheRule,
  CacheSettings,
  CreateCacheRuleRequest,
  UpdateCacheSettingsRequest,
} from '@/api/types'

/** `MAX_DISK_QUOTA_MB` on the server — reject out-of-range values up front. */
const MAX_QUOTA_MB = 1024 * 1024

/** `CACHE_TYPE_KEYS` on the server — the per-type single-file cap families. */
const CACHE_TYPE_KEYS = [
  'html',
  'css',
  'js',
  'image',
  'font',
  'media',
  'other',
] as const

interface FormState {
  name: string
  match_expression: string
  edge_ttl_seconds: number
  browser_ttl_seconds: number
  cache_eligible: boolean
  respect_origin: boolean
  enabled: boolean
}

const emptyForm = (): FormState => ({
  name: '',
  match_expression: '',
  edge_ttl_seconds: 3600,
  browser_ttl_seconds: 300,
  cache_eligible: true,
  respect_origin: true,
  enabled: true,
})

function formFromRule(rule: CacheRule): FormState {
  return {
    name: rule.name,
    match_expression: rule.match_expression,
    edge_ttl_seconds: rule.edge_ttl_seconds,
    browser_ttl_seconds: rule.browser_ttl_seconds,
    cache_eligible: rule.cache_eligible,
    respect_origin: rule.respect_origin,
    enabled: rule.enabled,
  }
}

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

type Translate = ReturnType<typeof useTranslation>['t']

function formatTtl(seconds: number, t: Translate): string {
  if (seconds <= 0) return t('pages.caching.respectOrigin')
  if (seconds >= 3600 && seconds % 3600 === 0) return t('pages.caching.hours', { n: seconds / 3600 })
  if (seconds >= 60 && seconds % 60 === 0) return t('pages.caching.minutes', { n: seconds / 60 })
  return t('pages.caching.seconds', { n: seconds })
}

export function CachingPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<CacheRule | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm())
  const [error, setError] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<CacheRule | null>(null)
  const [purgeUrls, setPurgeUrls] = useState('')
  const [purgeAllOpen, setPurgeAllOpen] = useState(false)
  /** Set right after a successful activation so the built-in set is called out. */
  const [justActivated, setJustActivated] = useState(false)
  const [quotaInput, setQuotaInput] = useState('0')
  const [quotaError, setQuotaError] = useState<string | null>(null)
  const [fileSizeInput, setFileSizeInput] = useState('')
  const [fileSizeError, setFileSizeError] = useState<string | null>(null)
  const [typeLimitsInput, setTypeLimitsInput] = useState<
    Record<string, string>
  >({})
  const [typeLimitsError, setTypeLimitsError] = useState<string | null>(null)

  /* ── Site-wide cache state (activation + disk budget) ─────────────── */
  const settingsQuery = useQuery({
    queryKey: cacheKeys.settings(siteId),
    queryFn: () => cachingApi.getSettings(siteId),
    enabled: Boolean(siteId),
  })

  const rulesQuery = useQuery({
    queryKey: cacheKeys.rules(siteId),
    queryFn: () => cachingApi.listRules(siteId),
    enabled: Boolean(siteId),
    select: (page) => page.items,
  })

  /** Edge heartbeats — polled, and refreshable by hand. */
  const statusQuery = useQuery({
    queryKey: cacheKeys.status(siteId),
    queryFn: () => cachingApi.status(siteId),
    enabled: Boolean(siteId),
    refetchInterval: 30_000,
  })

  const rules = useMemo(
    () => [...(rulesQuery.data ?? [])].sort((a, b) => a.name.localeCompare(b.name)),
    [rulesQuery.data],
  )

  const settings = settingsQuery.data
  const cacheEnabled = settings?.cache_enabled ?? false
  const enabledRuleCount = settings?.enabled_rule_count ?? 0
  const ruleCount = settings?.rule_count ?? 0
  const appliedQuotaMb = settings?.quota_mb ?? 0
  const quotaDirty = quotaInput.trim() !== String(appliedQuotaMb)

  const status = statusQuery.data
  const reportingEdges = status?.reporting_edges ?? 0
  const quotaBytesTotal = status?.quota_bytes_total ?? 0
  const usagePercent = status?.usage_percent ?? 0
  const configuredQuotaMb = status?.configured_quota_mb ?? appliedQuotaMb
  const quotaValueLabel =
    configuredQuotaMb > 0
      ? `${formatNumber(configuredQuotaMb)} MiB`
      : t('pages.caching.unlimited')
  /** Site setting as stored, i.e. without waiting for an edge heartbeat. */
  const appliedQuotaLabel =
    appliedQuotaMb > 0
      ? `${formatNumber(appliedQuotaMb)} MiB`
      : t('pages.caching.unlimited')

  // Re-seed the dialog form every time it opens (render-phase reset), so the
  // first paint already shows the right rule instead of the previous one.
  const seedKey = dialogOpen ? (editing?.id ?? 'new') : ''
  const [lastSeedKey, setLastSeedKey] = useState<string | null>(null)
  if (seedKey !== lastSeedKey) {
    setLastSeedKey(seedKey)
    if (dialogOpen) {
      setError(null)
      setForm(editing ? formFromRule(editing) : emptyForm())
    }
  }

  /** Keep the input in step with the server value (also picks up clamping). */
  const [lastQuotaMb, setLastQuotaMb] = useState<number | null>(null)
  if (appliedQuotaMb !== lastQuotaMb) {
    setLastQuotaMb(appliedQuotaMb)
    setQuotaInput(String(appliedQuotaMb))
  }

  /* ── Single-file caps (site + per-type) ────────────────────────────── */
  const limitsSeed = settings
    ? `${settings.max_file_size_mb ?? ''}:${JSON.stringify(
        settings.type_limits ?? {},
      )}`
    : ''
  const [lastLimitsSeed, setLastLimitsSeed] = useState<string | null>(null)
  if (settings && limitsSeed !== lastLimitsSeed) {
    setLastLimitsSeed(limitsSeed)
    setFileSizeInput(
      settings.max_file_size_mb === null
        ? ''
        : String(settings.max_file_size_mb),
    )
    setTypeLimitsInput(
      Object.fromEntries(
        Object.entries(settings.type_limits ?? {}).map(([key, value]) => [
          key,
          String(value),
        ]),
      ),
    )
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: cacheKeys.site(siteId) })
  }

  const patchSettings = (patch: Partial<CacheSettings>) => {
    queryClient.setQueryData<CacheSettings>(cacheKeys.settings(siteId), (prev) =>
      prev ? { ...prev, ...patch } : prev,
    )
  }

  /* ── Activation ───────────────────────────────────────────────────── */

  /**
   * Turning caching on must not leave the operator with nothing to cache:
   * built-in rules are restored first (idempotent), then every cache-eligible
   * rule is enabled. `cache_enabled` is derived from "any rule enabled".
   */
  const enable = useMutation({
    mutationFn: async () => {
      const seeded = await cachingApi.restoreDefaults(siteId)
      const page = await cachingApi.listRules(siteId)
      const eligible = page.items.filter((rule) => rule.cache_eligible)
      const off = eligible.filter((rule) => !rule.enabled)
      await Promise.all(off.map((rule) => cachingApi.toggleEnabled(siteId, rule.id, true)))
      return { seeded, enabled: eligible.length }
    },
    onSuccess: ({ seeded, enabled }) => {
      setJustActivated(enabled > 0)
      patchSettings({ cache_enabled: enabled > 0, enabled_rule_count: enabled })
      invalidate()
      if (enabled === 0) {
        toast.warning(
          t('pages.caching.noEligibleRulesTitle'),
          t('pages.caching.noEligibleRulesHint'),
        )
        return
      }
      toast.success(
        t('pages.caching.enableTitle'),
        t('pages.caching.enableDescription', {
          enabled,
          inserted: seeded.inserted,
          total: seeded.total,
        }),
      )
    },
    onError: (e) => toast.error(t('pages.caching.actionFailed'), errorText(e)),
  })

  /** Turning caching off keeps every rule in place, just disabled. */
  const disable = useMutation({
    mutationFn: async () => {
      const page = await cachingApi.listRules(siteId)
      const on = page.items.filter((rule) => rule.enabled)
      await Promise.all(on.map((rule) => cachingApi.toggleEnabled(siteId, rule.id, false)))
      return on.length
    },
    onSuccess: (count) => {
      setJustActivated(false)
      patchSettings({ cache_enabled: false, enabled_rule_count: 0 })
      invalidate()
      toast.success(
        t('pages.caching.disableTitle'),
        t('pages.caching.disableDescription', { count: formatNumber(count) }),
      )
    },
    onError: (e) => toast.error(t('pages.caching.actionFailed'), errorText(e)),
  })

  const restore = useMutation({
    mutationFn: () => cachingApi.restoreDefaults(siteId),
    onSuccess: (result) => {
      toast.success(
        t('pages.caching.restoredTitle'),
        t('pages.caching.restoredDescription', {
          inserted: result.inserted,
          total: result.total,
        }),
      )
      invalidate()
    },
    onError: (e) => toast.error(t('pages.caching.actionFailed'), errorText(e)),
  })

  const activationBusy = enable.isPending || disable.isPending

  const saveQuota = useMutation({
    mutationFn: (quota_mb: number) => cachingApi.updateSettings(siteId, { quota_mb }),
    onSuccess: (next) => {
      queryClient.setQueryData(cacheKeys.settings(siteId), next)
      setQuotaInput(String(next.quota_mb))
      setQuotaError(null)
      toast.success(
        t('pages.caching.quotaSaved'),
        t('pages.caching.quotaSavedDescription', { quota: formatNumber(next.quota_mb) }),
      )
      invalidate()
    },
    onError: (e) => setQuotaError(errorText(e)),
  })

  const saveLimits = useMutation({
    mutationFn: (payload: UpdateCacheSettingsRequest) =>
      cachingApi.updateSettings(siteId, payload),
    onSuccess: (next) => {
      queryClient.setQueryData<CacheSettings>(cacheKeys.settings(siteId), next)
      setFileSizeError(null)
      setTypeLimitsError(null)
      toast.success(t('pages.caching.limitsSaved'))
      invalidate()
    },
    onError: (e) => setTypeLimitsError(errorText(e)),
  })

  /* ── Rules ────────────────────────────────────────────────────────── */

  const save = useMutation({
    mutationFn: (payload: CreateCacheRuleRequest) =>
      editing
        ? cachingApi.updateRule(siteId, editing.id, payload)
        : cachingApi.createRule(siteId, payload),
    onSuccess: (rule) => {
      toast.success(
        editing ? t('pages.caching.ruleUpdated') : t('pages.caching.ruleCreated'),
        rule.name,
      )
      closeDialog()
      invalidate()
    },
    onError: (e) => setError(errorText(e)),
  })

  const toggle = useMutation({
    mutationFn: ({ rule, enabled }: { rule: CacheRule; enabled: boolean }) =>
      cachingApi.toggleEnabled(siteId, rule.id, enabled),
    onSuccess: () => invalidate(),
    onError: (e) => toast.error(t('pages.caching.actionFailed'), errorText(e)),
  })

  const remove = useMutation({
    mutationFn: (id: string) => cachingApi.deleteRule(siteId, id),
    onSuccess: (_d, id) => {
      toast.success(t('pages.caching.ruleDeleted'), rules.find((r) => r.id === id)?.name)
      setPendingDelete(null)
      invalidate()
    },
  })

  const purge = useMutation({
    mutationFn: (payload: { urls?: string[]; purge_all?: boolean }) =>
      cachingApi.purge({ site_id: siteId, ...payload }),
    onSuccess: (result, payload) => {
      toast.success(
        payload.purge_all ? t('pages.caching.purgedAll') : t('pages.caching.purgedUrls'),
        t('pages.caching.purgeResult', {
          delivered: formatNumber(result.delivered),
          queued: formatNumber(result.queued),
        }),
      )
      if (!payload.purge_all) setPurgeUrls('')
      setPurgeAllOpen(false)
      invalidate()
    },
    onError: (e) => toast.error(t('pages.caching.actionFailed'), errorText(e)),
  })

  const closeDialog = () => {
    setDialogOpen(false)
    setEditing(null)
    setForm(emptyForm())
    setError(null)
  }

  const submit = () => {
    setError(null)
    const name = form.name.trim()
    if (!name) {
      setError(t('pages.caching.nameRequired'))
      return
    }
    save.mutate({
      name,
      match_expression: form.match_expression.trim(),
      edge_ttl_seconds: form.edge_ttl_seconds,
      browser_ttl_seconds: form.browser_ttl_seconds,
      cache_eligible: form.cache_eligible,
      respect_origin: form.respect_origin,
      enabled: form.enabled,
    })
  }

  const submitQuota = () => {
    setQuotaError(null)
    const value = Number(quotaInput)
    if (!Number.isInteger(value) || value < 0 || value > MAX_QUOTA_MB) {
      setQuotaError(t('pages.caching.quotaInvalid'))
      return
    }
    saveQuota.mutate(value)
  }

  const globalMaxFileSize = settings?.global_max_file_size_mb ?? 16
  const effectiveMaxFileSize = settings?.effective_max_file_size_mb ?? 16
  const fileSizeDirty =
    fileSizeInput.trim() !==
    (settings?.max_file_size_mb == null
      ? ''
      : String(settings.max_file_size_mb))
  const typeLimitsDirty = CACHE_TYPE_KEYS.some(
    (key) =>
      (typeLimitsInput[key]?.trim() ?? '') !==
      String(settings?.type_limits?.[key] ?? ''),
  )
  const limitsDirty = fileSizeDirty || typeLimitsDirty

  const submitLimits = () => {
    setFileSizeError(null)
    setTypeLimitsError(null)
    let siteCap: number | null = null
    if (fileSizeInput.trim() !== '') {
      const value = Number(fileSizeInput)
      if (
        !Number.isInteger(value) ||
        value < 1 ||
        value > globalMaxFileSize
      ) {
        setFileSizeError(
          t('pages.caching.maxFileSizeInvalid', { max: globalMaxFileSize }),
        )
        return
      }
      siteCap = value
    }
    // Per-type values are measured against the cap this request installs,
    // falling back to the currently effective one.
    const cap = siteCap ?? effectiveMaxFileSize
    const typeLimits: Record<string, number> = {}
    for (const key of CACHE_TYPE_KEYS) {
      const raw = typeLimitsInput[key]?.trim() ?? ''
      if (raw === '') continue
      const value = Number(raw)
      if (!Number.isInteger(value) || value < 1 || value > cap) {
        setTypeLimitsError(
          t('pages.caching.typeLimitInvalid', { type: key, max: cap }),
        )
        return
      }
      typeLimits[key] = value
    }
    const payload: UpdateCacheSettingsRequest = {}
    if (fileSizeDirty) {
      payload.max_file_size_mb = siteCap
    }
    if (typeLimitsDirty) {
      payload.type_limits = typeLimits
    }
    if (Object.keys(payload).length === 0) {
      return
    }
    saveLimits.mutate(payload)
  }

  const submitPurgeUrls = () => {
    const urls = purgeUrls
      .split('\n')
      .map((u) => u.trim())
      .filter(Boolean)
    if (urls.length === 0) {
      toast.warning(t('pages.caching.purgeEmpty'))
      return
    }
    purge.mutate({ urls })
  }

  const refreshAll = () => {
    void settingsQuery.refetch()
    void rulesQuery.refetch()
    void statusQuery.refetch()
  }
  const refreshing =
    settingsQuery.isFetching || rulesQuery.isFetching || statusQuery.isFetching

  const columns: Column<CacheRule>[] = [
    {
      key: 'name',
      header: t('common.name'),
      accessor: (r) => r.name,
      sortable: true,
      cell: (r) => (
        <div className="min-w-0">
          <div className="flex min-w-0 items-center gap-2">
            <p className="truncate text-[13px] font-medium text-fg-strong">{r.name}</p>
            {!r.cache_eligible && (
              <Badge tone="neutral" size="sm">
                {t('pages.caching.notEligible')}
              </Badge>
            )}
          </div>
          <p className="pw-mono truncate text-xs text-fg-subtle">
            {r.match_expression || t('pages.caching.allRequests')}
          </p>
        </div>
      ),
    },
    {
      key: 'edge_ttl',
      header: t('pages.caching.edgeTtl'),
      accessor: (r) => r.edge_ttl_seconds,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span className="tabular-nums text-[13px] text-fg">
          {formatTtl(r.edge_ttl_seconds, t)}
        </span>
      ),
    },
    {
      key: 'browser_ttl',
      header: t('pages.caching.browserTtl'),
      accessor: (r) => r.browser_ttl_seconds,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span className="tabular-nums text-[13px] text-fg-subtle">
          {formatTtl(r.browser_ttl_seconds, t)}
        </span>
      ),
    },
    {
      key: 'enabled',
      header: t('common.enabled'),
      accessor: (r) => (r.enabled ? 1 : 0),
      width: '1%',
      cell: (r) => (
        <Switch
          size="sm"
          checked={r.enabled}
          disabled={!canWrite || toggle.isPending}
          aria-label={`${t('common.enabled')}: ${r.name}`}
          onCheckedChange={(enabled) => toggle.mutate({ rule: r, enabled })}
        />
      ),
    },
    {
      key: 'row-actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (r) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('common.edit')}
            disabled={!canWrite}
            onClick={() => {
              setEditing(r)
              setDialogOpen(true)
            }}
            icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            onClick={() => setPendingDelete(r)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  const settingsFailed = settingsQuery.isError && !settingsQuery.data
  const rulesFailed = rulesQuery.isError && !rulesQuery.data

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.caching.title')}
        description={t('pages.caching.description')}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              loading={refreshing}
              onClick={refreshAll}
              icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
            >
              {t('common.refresh')}
            </Button>
            {canWrite && (
              <Button
                variant="primary"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={() => {
                  setEditing(null)
                  setDialogOpen(true)
                }}
              >
                {t('pages.caching.addRule')}
              </Button>
            )}
          </div>
        }
      />

      {settingsFailed || rulesFailed ? (
        <ErrorState
          error={settingsQuery.error ?? rulesQuery.error}
          onRetry={refreshAll}
          retrying={refreshing}
        />
      ) : (
        <>
          {/* ── Activation ──────────────────────────────────────────── */}
          {settingsQuery.isPending && !settings ? (
            <Skeleton className="mb-4 h-40 w-full rounded-lg" />
          ) : (
            <Card className="mb-4">
              <CardHeader
                title={t('pages.caching.activationTitle')}
                description={t('pages.caching.activationHint')}
                action={
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={!canWrite || activationBusy}
                    loading={restore.isPending}
                    onClick={() => restore.mutate()}
                    icon={<ArrowCounterClockwise weight="duotone" className="h-4 w-4" />}
                  >
                    {t('pages.caching.restoreButton')}
                  </Button>
                }
              />
              <CardBody className="flex flex-col gap-4">
                <div className="flex flex-wrap items-center gap-4">
                  <span
                    className={cn(
                      'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
                      cacheEnabled ? 'bg-brand-soft text-brand' : 'bg-recessed text-fg-subtle',
                    )}
                  >
                    <Lightning weight="duotone" className="h-5 w-5" />
                  </span>
                  <Switch
                    className="min-w-[220px] flex-1"
                    checked={cacheEnabled}
                    disabled={!canWrite || activationBusy || settingsQuery.isPending}
                    onCheckedChange={(next) => {
                      if (!canWrite || activationBusy) return
                      if (next) enable.mutate()
                      else disable.mutate()
                    }}
                    label={t('pages.caching.activationSwitch')}
                    description={t('pages.caching.activationSwitchHint')}
                  />
                  <div className="flex shrink-0 flex-wrap items-center gap-3">
                    <Badge tone={cacheEnabled ? 'success' : 'neutral'} dot>
                      {cacheEnabled
                        ? t('pages.caching.stateActive')
                        : t('pages.caching.stateInactive')}
                    </Badge>
                    <span className="text-xs tabular-nums text-fg-subtle">
                      {t('pages.caching.activationCounts', {
                        enabled: enabledRuleCount,
                        total: ruleCount,
                      })}
                    </span>
                    {activationBusy && (
                      <span className="text-xs text-fg-subtle">
                        {t('pages.caching.activationPending')}
                      </span>
                    )}
                  </div>
                </div>

                {justActivated && cacheEnabled && (
                  <div className="flex items-start gap-2 rounded-md border border-success/30 bg-success/8 px-3 py-2">
                    <CheckCircle
                      weight="duotone"
                      className="mt-px h-4 w-4 shrink-0 text-fg-success"
                    />
                    <p className="text-xs leading-relaxed text-fg-subtle">
                      {t('pages.caching.activatedNotice')}
                    </p>
                  </div>
                )}

                <div className="rounded-md border border-line bg-recessed px-3 py-2">
                  <p className="text-xs leading-relaxed text-fg-subtle">
                    <span className="font-medium text-fg">
                      {t('pages.caching.cacheHeaderTitle')}
                    </span>{' '}
                    <code className="pw-mono text-fg">x-cache-status</code>{' '}
                    {t('pages.caching.cacheHeaderNote')}
                  </p>
                </div>
              </CardBody>
            </Card>
          )}

          {/* ── Usage + site-wide quota ─────────────────────────────── */}
          <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader
                title={t('pages.caching.usageTitle')}
                description={t('pages.caching.usageHint')}
                action={
                  <Button
                    size="sm"
                    variant="ghost"
                    loading={statusQuery.isFetching}
                    onClick={() => statusQuery.refetch()}
                    icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
                  >
                    {t('common.refresh')}
                  </Button>
                }
              />
              <CardBody className="flex flex-col gap-4">
                {statusQuery.isPending && !status ? (
                  <Skeleton className="h-24 w-full" />
                ) : statusQuery.isError && !status ? (
                  <ErrorState
                    variant="inline"
                    error={statusQuery.error}
                    onRetry={() => statusQuery.refetch()}
                    retrying={statusQuery.isFetching}
                  />
                ) : reportingEdges === 0 ? (
                  <>
                    <div className="rounded-md border border-line bg-recessed px-3 py-2">
                      <p className="text-xs leading-relaxed text-fg-subtle">
                        {t('pages.caching.noEdgeReport')}
                      </p>
                    </div>
                    <Metric
                      label={t('pages.caching.quotaConfigured')}
                      value={quotaValueLabel}
                    />
                  </>
                ) : (
                  <>
                    <div className="grid grid-cols-2 gap-x-6 gap-y-4 lg:grid-cols-3">
                      <Metric
                        label={t('pages.caching.quotaConfigured')}
                        value={quotaValueLabel}
                        hint={
                          quotaBytesTotal > 0
                            ? t('pages.caching.quotaPerEdge', {
                                size: formatSize(status?.quota_bytes_per_edge ?? 0),
                              })
                            : t('pages.caching.unlimited')
                        }
                      />
                      <Metric
                        label={t('pages.caching.diskUsage')}
                        value={formatSize(status?.disk_bytes ?? 0)}
                        hint={
                          quotaBytesTotal > 0
                            ? t('pages.caching.diskUsageOf', {
                                total: formatSize(quotaBytesTotal),
                              })
                            : t('pages.caching.unlimited')
                        }
                      />
                      <Metric
                        label={t('pages.caching.quotaUsed')}
                        value={
                          quotaBytesTotal > 0
                            ? formatPercent(usagePercent / 100)
                            : t('pages.caching.unlimited')
                        }
                      />
                      <Metric
                        label={t('pages.caching.cachedItems')}
                        value={formatNumber(status?.items ?? 0)}
                        hint={t('pages.caching.cachedItemsHint')}
                      />
                      <Metric
                        label={t('pages.caching.evictions')}
                        value={formatNumber(status?.evictions_total ?? 0)}
                      />
                      <Metric
                        label={t('pages.caching.lastReported')}
                        value={formatDateTime(status?.last_reported_at)}
                      />
                    </div>
                    {quotaBytesTotal > 0 ? (
                      <div>
                        <div className="h-1.5 w-full overflow-hidden rounded-full bg-recessed">
                          <div
                            className={cn(
                              'h-full rounded-full transition-all',
                              usagePercent > 85 ? 'bg-danger' : 'bg-brand',
                            )}
                            style={{
                              width: `${Math.max(0, Math.min(100, usagePercent))}%`,
                            }}
                          />
                        </div>
                        <p className="mt-2 text-xs text-fg-subtle">
                          {t('pages.caching.reportingEdges', {
                            count: formatNumber(reportingEdges),
                          })}
                        </p>
                      </div>
                    ) : (
                      <p className="text-xs leading-relaxed text-fg-subtle">
                        {t('pages.caching.noQuotaNote')}
                      </p>
                    )}
                  </>
                )}
              </CardBody>
            </Card>

            <Card>
              <CardHeader
                title={t('pages.caching.quotaTitle')}
                description={t('pages.caching.quotaHint')}
              />
              <CardBody className="flex flex-col gap-3">
                {settingsQuery.isPending && !settings ? (
                  <Skeleton className="h-20 w-full" />
                ) : (
                  <>
                    <Input
                      type="number"
                      label={t('pages.caching.quotaLabel')}
                      className="tabular-nums"
                      value={quotaInput}
                      min={0}
                      max={MAX_QUOTA_MB}
                      disabled={!canWrite || saveQuota.isPending}
                      error={quotaError}
                      hint={t('pages.caching.quotaFieldHint')}
                      onChange={(e) => {
                        setQuotaError(null)
                        setQuotaInput(e.target.value)
                      }}
                    />
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <span className="text-xs text-fg-subtle">
                        {t('pages.caching.quotaCurrent', { quota: appliedQuotaLabel })}
                      </span>
                      <Button
                        size="sm"
                        variant="primary"
                        disabled={!canWrite || !quotaDirty || saveQuota.isPending}
                        loading={saveQuota.isPending}
                        onClick={submitQuota}
                      >
                        {t('common.save')}
                      </Button>
                    </div>
                  </>
                )}
              </CardBody>
            </Card>
          </div>

          {/* ── Single-file caps ────────────────────────────────────── */}
          <Card className="mb-4">
            <CardHeader
              title={t('pages.caching.limitsTitle')}
              description={t('pages.caching.limitsHint', {
                global: settings?.global_max_file_size_mb ?? 16,
              })}
            />
            <CardBody className="flex flex-col gap-3">
              {settingsQuery.isPending && !settings ? (
                <Skeleton className="h-20 w-full" />
              ) : (
                <>
                  <Input
                    type="number"
                    min={1}
                    max={globalMaxFileSize}
                    className="tabular-nums"
                    label={t('pages.caching.maxFileSizeLabel')}
                    value={fileSizeInput}
                    placeholder={t('pages.caching.maxFileSizePlaceholder')}
                    hint={t('pages.caching.maxFileSizeHint', {
                      effective: formatNumber(effectiveMaxFileSize),
                      global: formatNumber(globalMaxFileSize),
                    })}
                    error={fileSizeError}
                    disabled={!canWrite || saveLimits.isPending}
                    onChange={(e) => {
                      setFileSizeError(null)
                      setFileSizeInput(e.target.value)
                    }}
                  />
                  <div>
                    <p className="mb-2 text-xs font-medium uppercase tracking-wide text-fg-subtle">
                      {t('pages.caching.typeLimitsLabel')}
                    </p>
                    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
                      {CACHE_TYPE_KEYS.map((key) => (
                        <Input
                          key={key}
                          type="number"
                          min={1}
                          max={globalMaxFileSize}
                          className="tabular-nums"
                          label={t(`pages.caching.type.${key}`)}
                          value={typeLimitsInput[key] ?? ''}
                          placeholder={t('pages.caching.typeFollow')}
                          disabled={!canWrite || saveLimits.isPending}
                          onChange={(e) => {
                            setTypeLimitsError(null)
                            setTypeLimitsInput((prev) => ({
                              ...prev,
                              [key]: e.target.value,
                            }))
                          }}
                        />
                      ))}
                    </div>
                  </div>
                  {typeLimitsError && (
                    <p className="text-xs text-fg-danger">{typeLimitsError}</p>
                  )}
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <span className="text-xs text-fg-subtle">
                      {t('pages.caching.limitsEffectiveHint', {
                        effective: formatNumber(effectiveMaxFileSize),
                      })}
                    </span>
                    <Button
                      size="sm"
                      variant="primary"
                      disabled={
                        !canWrite || !limitsDirty || saveLimits.isPending
                      }
                      loading={saveLimits.isPending}
                      onClick={submitLimits}
                    >
                      {t('common.save')}
                    </Button>
                  </div>
                </>
              )}
            </CardBody>
          </Card>

          {/* ── Rules ───────────────────────────────────────────────── */}
          <Card className="mb-4">
            <CardHeader
              title={t('pages.caching.rulesTitle')}
              description={t('pages.caching.rulesHint')}
            />
            <CardBody className="p-0">
              {rulesQuery.isPending ? (
                <SkeletonRows rows={4} columns={5} />
              ) : rules.length === 0 ? (
                <EmptyState
                  className="border-0 py-12"
                  icon={<Lightning weight="duotone" className="h-8 w-8" />}
                  title={t('pages.caching.empty')}
                  description={t('pages.caching.emptyDescription')}
                  action={
                    canWrite ? (
                      <div className="flex flex-wrap items-center justify-center gap-2">
                        <Button
                          variant="primary"
                          icon={<Plus weight="bold" className="h-4 w-4" />}
                          onClick={() => {
                            setEditing(null)
                            setDialogOpen(true)
                          }}
                        >
                          {t('pages.caching.addRule')}
                        </Button>
                        <Button
                          variant="secondary"
                          loading={restore.isPending}
                          disabled={activationBusy}
                          onClick={() => restore.mutate()}
                          icon={
                            <ArrowCounterClockwise weight="duotone" className="h-4 w-4" />
                          }
                        >
                          {t('pages.caching.restoreButton')}
                        </Button>
                      </div>
                    ) : undefined
                  }
                />
              ) : (
                <Table
                  columns={columns}
                  data={rules}
                  rowKey={(r) => r.id}
                  dense
                  onRowClick={
                    canWrite
                      ? (r) => {
                          setEditing(r)
                          setDialogOpen(true)
                        }
                      : undefined
                  }
                />
              )}
            </CardBody>
          </Card>

          {/* ── Purge ───────────────────────────────────────────────── */}
          <Card>
            <CardHeader
              title={t('pages.caching.purgeTitle')}
              description={t('pages.caching.purgeHint')}
            />
            <CardBody className="flex flex-col gap-4">
              <Textarea
                label={t('pages.caching.purgeUrls')}
                mono
                rows={4}
                disabled={!canWrite}
                value={purgeUrls}
                placeholder={'https://example.com/index.html\nhttps://example.com/assets/app.css'}
                hint={t('pages.caching.purgeUrlsHint')}
                onChange={(e) => setPurgeUrls(e.target.value)}
              />
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="primary"
                  disabled={!canWrite || purge.isPending}
                  loading={purge.isPending}
                  icon={<Broom weight="duotone" className="h-4 w-4" />}
                  onClick={submitPurgeUrls}
                >
                  {t('pages.caching.purgeUrls')}
                </Button>
                <Button
                  variant="danger"
                  disabled={!canWrite || purge.isPending}
                  onClick={() => setPurgeAllOpen(true)}
                >
                  {t('pages.caching.purgeAll')}
                </Button>
              </div>
            </CardBody>
          </Card>
        </>
      )}

      {/* Create / edit */}
      <Dialog
        open={dialogOpen}
        onClose={save.isPending ? () => undefined : closeDialog}
        size="lg"
        title={editing ? t('pages.caching.editRule') : t('pages.caching.addRule')}
        description={t('pages.caching.dialogDescription')}
        footer={
          <>
            <Button variant="ghost" onClick={closeDialog} disabled={save.isPending}>
              {t('common.cancel')}
            </Button>
            <Button variant="primary" onClick={submit} loading={save.isPending}>
              {editing ? t('common.save') : t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Input
            label={t('common.name')}
            value={form.name}
            autoFocus
            placeholder={t('pages.caching.namePlaceholder')}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            required
          />
          <Input
            label={t('pages.caching.matchExpression')}
            value={form.match_expression}
            className="pw-mono text-[13px]"
            placeholder='http.request.uri.path starts_with "/static"'
            hint={t('pages.caching.matchExpressionHint')}
            onChange={(e) => setForm((f) => ({ ...f, match_expression: e.target.value }))}
          />
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Input
              type="number"
              label={t('pages.caching.edgeTtl')}
              value={form.edge_ttl_seconds}
              min={0}
              hint={t('pages.caching.ttlSecondsHint')}
              onChange={(e) =>
                setForm((f) => ({ ...f, edge_ttl_seconds: Number(e.target.value) }))
              }
            />
            <Input
              type="number"
              label={t('pages.caching.browserTtl')}
              value={form.browser_ttl_seconds}
              min={0}
              onChange={(e) =>
                setForm((f) => ({ ...f, browser_ttl_seconds: Number(e.target.value) }))
              }
            />
          </div>
          <Switch
            checked={form.cache_eligible}
            onCheckedChange={(cache_eligible) => setForm((f) => ({ ...f, cache_eligible }))}
            label={t('pages.caching.cacheEligible')}
            description={t('pages.caching.cacheEligibleHint')}
          />
          <Switch
            checked={form.respect_origin}
            onCheckedChange={(respect_origin) => setForm((f) => ({ ...f, respect_origin }))}
            label={t('pages.caching.respectOriginLabel')}
            description={t('pages.caching.respectOriginHint')}
          />
          <Switch
            checked={form.enabled}
            onCheckedChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
            label={t('common.enabled')}
          />
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-xs leading-relaxed text-fg-subtle">
              {t('pages.caching.quotaNotPerRule')}
            </p>
          </div>
          {error && (
            <p
              role="alert"
              className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
            >
              {error}
            </p>
          )}
        </div>
      </Dialog>

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete.id)}
        title={t('pages.caching.deleteTitle')}
        description={t('pages.caching.deleteDescription')}
        confirmLabel={t('common.delete')}
        loading={remove.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDelete.name}</p>
          </div>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={purgeAllOpen}
        onClose={() => setPurgeAllOpen(false)}
        onConfirm={() => purge.mutate({ purge_all: true })}
        title={t('pages.caching.purgeAllTitle')}
        description={t('pages.caching.purgeAllDescription')}
        confirmLabel={t('pages.caching.purgeAll')}
        loading={purge.isPending}
      />
    </div>
  )
}

/** Label + value + optional hint, for the compact metric grid inside a card. */
function Metric({
  label,
  value,
  hint,
}: {
  label: string
  value: ReactNode
  hint?: ReactNode
}) {
  return (
    <div className="min-w-0">
      <p className="text-xs font-medium uppercase tracking-wide text-fg-subtle">{label}</p>
      <p className="mt-1 text-lg font-semibold tabular-nums text-fg-strong">{value}</p>
      {hint && <p className="mt-0.5 truncate text-xs text-fg-subtle">{hint}</p>}
    </div>
  )
}

export default CachingPage
