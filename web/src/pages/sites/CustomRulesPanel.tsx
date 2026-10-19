import { useMemo, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Shield,
  ShieldCheck,
  ShieldWarning,
  Plus,
  PencilSimple,
  Trash,
  MagnifyingGlass,
  ArrowClockwise,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Dialog } from '@/components/ui/Dialog'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows, SkeletonStat } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { RuleDialog } from '@/components/waf/RuleDialog'
import { deriveWafConfig, ruleKeys, rulesApi } from '@/api/rules'
import { wafSettingsApi, wafSettingsKeys } from '@/api/wafSettings'
import { siteKeys } from '@/api/sites'
import { useCanWrite, useDebouncedValue } from '@/hooks'
import { cn } from '@/lib/utils'
import { type Rule, type RuleGroup } from '@/api/types'

const ACTION_TONE: Record<string, 'danger' | 'warning' | 'info' | 'success' | 'neutral'> = {
  block: 'danger',
  challenge: 'warning',
  js_challenge: 'warning',
  log: 'info',
  allow: 'success',
}

const MODE_TONE: Record<string, 'danger' | 'warning' | 'neutral'> = {
  block: 'danger',
  monitor: 'warning',
  off: 'neutral',
}

/** The custom-rules module of the protection page: posture, mode, groups and the user's own rules. */
export function CustomRulesPanel() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()
  const [searchParams, setSearchParams] = useSearchParams()

  const [search, setSearch] = useState('')
  const debouncedSearch = useDebouncedValue(search.trim(), 300)
  const [groupFilter, setGroupFilter] = useState('')
  const [enabledFilter, setEnabledFilter] = useState('')
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<Rule | null>(null)
  const [presetTags, setPresetTags] = useState<string[] | undefined>(undefined)
  const [pendingDelete, setPendingDelete] = useState<Rule | null>(null)
  const [groupDialogOpen, setGroupDialogOpen] = useState(false)
  const [groupName, setGroupName] = useState('')
  const [groupPhase, setGroupPhase] = useState('request')

  const rulesQuery = useQuery({
    queryKey: ruleKeys.list(siteId, { search: debouncedSearch || undefined }),
    queryFn: () => rulesApi.list(siteId, { search: debouncedSearch || undefined }),
    select: (page) => page.items,
    enabled: Boolean(siteId),
  })

  const groupsQuery = useQuery({
    queryKey: ruleKeys.groups(siteId),
    queryFn: () => rulesApi.listGroups(siteId),
    select: (page) => page.items,
    enabled: Boolean(siteId),
  })

  const allRules = useMemo(() => rulesQuery.data ?? [], [rulesQuery.data])
  const groups = useMemo(() => groupsQuery.data ?? [], [groupsQuery.data])

  /** Derived exactly the way the control plane derives it for the agents. */
  const waf = useMemo(
    () => deriveWafConfig(allRules, groups),
    [allRules, groups],
  )

  // The banner must reflect the *enforced* posture, which lives in the
  // settings row (mode + paranoia level), not in a re-derivation from the
  // rule list — a rule kept at mode=block while the site runs monitor would
  // otherwise make this banner contradict the Protection page card.
  const settingsQuery = useQuery({
    queryKey: wafSettingsKeys.settings(siteId),
    queryFn: () => wafSettingsApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const settings = settingsQuery.data
  const effectiveMode = settings?.mode ?? waf.mode
  const effectiveParanoia = settings?.paranoia_level ?? waf.paranoia_level

  const visibleRules = useMemo(() => {
    const filtered = allRules.filter((r) => {
      if (groupFilter === 'none' && r.group_id !== null) return false
      if (groupFilter && groupFilter !== 'none' && r.group_id !== groupFilter) return false
      if (enabledFilter === 'enabled' && !r.enabled) return false
      if (enabledFilter === 'disabled' && r.enabled) return false
      return true
    })
    // Lowest priority number runs first — that is the order the agents use.
    return [...filtered].sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name))
  }, [allRules, groupFilter, enabledFilter])

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ruleKeys.all(siteId) })
    void queryClient.invalidateQueries({ queryKey: ruleKeys.groups(siteId) })
    void queryClient.invalidateQueries({ queryKey: siteKeys.detail(siteId) })
    // Rule changes feed the derived posture and the settings row's
    // lazy-created mode seed — refresh both instead of waiting for the
    // posture poll.
    void queryClient.invalidateQueries({ queryKey: wafSettingsKeys.posture(siteId) })
    void queryClient.invalidateQueries({ queryKey: wafSettingsKeys.settings(siteId) })
  }

  /* ── Mutations ───────────────────────────────────────────────────── */

  const toggleRule = useMutation({
    mutationFn: ({ rule, enabled }: { rule: Rule; enabled: boolean }) =>
      rulesApi.toggleEnabled(siteId, rule.id, enabled),
    onSuccess: (saved) => {
      queryClient.setQueryData<Rule[]>(
        ruleKeys.list(siteId, { search: debouncedSearch || undefined }),
        (prev) => (prev ? prev.map((r) => (r.id === saved.id ? saved : r)) : prev),
      )
      invalidate()
    },
  })

  const deleteRule = useMutation({
    mutationFn: (ruleId: string) => rulesApi.delete(siteId, ruleId),
    onSuccess: (_data, ruleId) => {
      const removed = allRules.find((r) => r.id === ruleId)
      toast.success(t('pages.waf.ruleDeleted'), removed?.name)
      setPendingDelete(null)
      invalidate()
    },
  })

  /** Re-adds the built-in rule pack for a site whose rules were deleted. */
  const restoreBuiltins = useMutation({
    mutationFn: () => rulesApi.restoreDefaults(siteId),
    onSuccess: (result) => {
      if (result.inserted === 0) {
        toast.info(t('pages.waf.restoreNothing'), t('pages.waf.restoreNothingHint'))
      } else {
        toast.success(
          t('pages.waf.restoreDone', { count: result.inserted }),
          t('pages.waf.restoreDoneHint'),
        )
      }
      invalidate()
    },
  })

  const toggleGroup = useMutation({
    mutationFn: ({ group, enabled }: { group: RuleGroup; enabled: boolean }) =>
      rulesApi.updateGroup(siteId, group.id, { enabled }),
    onSuccess: () => invalidate(),
  })

  const deleteGroup = useMutation({
    mutationFn: (groupId: string) => rulesApi.deleteGroup(siteId, groupId),
    onSuccess: () => {
      toast.success(t('pages.waf.groupDeleted'))
      invalidate()
    },
  })

  const createGroup = useMutation({
    mutationFn: () =>
      rulesApi.createGroup(siteId, { name: groupName.trim(), phase: groupPhase }),
    onSuccess: (group) => {
      toast.success(t('pages.waf.groupCreated'), group.name)
      setGroupDialogOpen(false)
      setGroupName('')
      invalidate()
    },
  })

  const openCreate = (tags?: string[]) => {
    setEditing(null)
    setPresetTags(tags)
    setDialogOpen(true)
  }

  const openEdit = (rule: Rule) => {
    setEditing(rule)
    setPresetTags(undefined)
    setDialogOpen(true)
  }

  const closeDialog = () => {
    setDialogOpen(false)
    setEditing(null)
    setPresetTags(undefined)
    if (searchParams.has('rule')) {
      const next = new URLSearchParams(searchParams)
      next.delete('rule')
      setSearchParams(next, { replace: true })
    }
  }

  // Deep link from the log console: /sites/:siteId/security/protection?rule=<id>
  // opens that rule's dialog once the list has loaded. `null` until the first
  // matching pass, so a link present at mount still opens; the param is
  // stripped on close so revisiting the same link opens the dialog again.
  const requestedRuleId = searchParams.get('rule')
  const [lastRequestedRuleId, setLastRequestedRuleId] = useState<string | null>(null)
  if (
    canWrite &&
    requestedRuleId &&
    !rulesQuery.isPending &&
    requestedRuleId !== lastRequestedRuleId
  ) {
    setLastRequestedRuleId(requestedRuleId)
    const rule = allRules.find((r) => r.id === requestedRuleId)
    if (rule) openEdit(rule)
  }

  /* ── Columns ─────────────────────────────────────────────────────── */

  const columns: Column<Rule>[] = [
    {
      key: 'priority',
      header: t('common.priority'),
      accessor: (r) => r.priority,
      sortable: true,
      align: 'right',
      width: '1%',
      cell: (r) => (
        <span className="pw-mono tabular-nums text-xs text-fg-subtle">{r.priority}</span>
      ),
    },
    {
      key: 'name',
      header: t('common.name'),
      accessor: (r) => r.name,
      sortable: true,
      cell: (r) => (
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <p className="truncate text-[13px] font-medium text-fg-strong">{r.name}</p>
            {r.group_id && (
              <span className="shrink-0 rounded border border-line px-1.5 py-px text-[10px] text-fg-subtle">
                {groups.find((g) => g.id === r.group_id)?.name ?? t('pages.waf.noGroup')}
              </span>
            )}
          </div>
          <p className="pw-mono truncate text-xs text-fg-subtle">{r.expression}</p>
        </div>
      ),
    },
    {
      key: 'action',
      header: t('pages.waf.action'),
      accessor: (r) => r.action,
      cell: (r) => (
        <Badge tone={ACTION_TONE[r.action] ?? 'neutral'}>
          {t(`actions.${r.action}`, r.action)}
        </Badge>
      ),
    },
    {
      key: 'mode',
      header: t('pages.waf.mode'),
      accessor: (r) => r.mode,
      cell: (r) => (
        <Badge
          tone={MODE_TONE[r.mode] ?? 'neutral'}
          dot
          title={
            r.mode === 'monitor' && r.action === 'block'
              ? t('pages.waf.modeMonitorHint')
              : undefined
          }
        >
          {t(`pages.waf.mode_${r.mode}`, r.mode)}
        </Badge>
      ),
    },
    {
      key: 'severity',
      header: t('pages.waf.severity'),
      accessor: (r) => r.severity,
      sortable: true,
      align: 'center',
      width: '1%',
      cell: (r) => (
        <div className="flex items-center justify-center gap-0.5" title={`${r.severity}/5`}>
          {[1, 2, 3, 4, 5].map((n) => (
            <span
              key={n}
              className={cn(
                'h-1.5 w-3 rounded-full',
                n <= r.severity
                  ? r.severity >= 4
                    ? 'bg-danger'
                    : 'bg-brand'
                  : 'bg-fill',
              )}
            />
          ))}
        </div>
      ),
    },
    {
      key: 'tags',
      header: t('pages.waf.tags'),
      width: '1%',
      cell: (r) => (
        <div className="flex max-w-[180px] flex-wrap gap-1">
          {(r.tags ?? []).slice(0, 3).map((tag) => (
            <span
              key={tag}
              className="pw-mono rounded border border-line bg-recessed px-1.5 py-px text-[10px] text-fg-subtle"
            >
              {tag}
            </span>
          ))}
          {(r.tags ?? []).length > 3 && (
            <span className="text-[10px] text-fg-subtle">+{r.tags.length - 3}</span>
          )}
        </div>
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
          disabled={!canWrite || toggleRule.isPending}
          aria-label={`${t('common.enabled')}: ${r.name}`}
          onCheckedChange={(enabled) => toggleRule.mutate({ rule: r, enabled })}
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
            onClick={() => openEdit(r)}
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

  const groupOptions = useMemo(
    () => [
      { value: '', label: t('pages.waf.allGroups') },
      ...groups.map((g) => ({ value: g.id, label: g.name })),
      { value: 'none', label: t('pages.waf.ungrouped') },
    ],
    [groups, t],
  )

  const loading =
    rulesQuery.isPending || groupsQuery.isPending || settingsQuery.isPending
  const failed = (rulesQuery.isError && !rulesQuery.data) || (groupsQuery.isError && !groupsQuery.data)

  return (
    <div>
      {failed ? (
        <ErrorState
          error={rulesQuery.error ?? groupsQuery.error}
          onRetry={() => {
            void rulesQuery.refetch()
            void groupsQuery.refetch()
          }}
          retrying={rulesQuery.isFetching}
        />
      ) : (
        <>
          {/* ── Posture banner ─────────────────────────────────────── */}
          {loading ? (
            <SkeletonStat className="mb-4 h-20 w-full" />
          ) : (
            <div
              className={cn(
                'mb-4 flex flex-wrap items-center gap-4 rounded-lg border px-4 py-3',
                effectiveMode !== 'off'
                  ? effectiveMode === 'block'
                    ? 'border-danger/35 bg-danger/8'
                    : 'border-warning/35 bg-warning/8'
                  : 'border-line bg-elevated',
              )}
            >
              <span
                className={cn(
                  'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
                  effectiveMode !== 'off'
                    ? effectiveMode === 'block'
                      ? 'bg-danger/15 text-fg-danger'
                      : 'bg-warning/15 text-fg-warning'
                    : 'bg-recessed text-fg-subtle',
                )}
              >
                {effectiveMode !== 'off' ? (
                  effectiveMode === 'block' ? (
                    <ShieldCheck weight="duotone" className="h-5 w-5" />
                  ) : (
                    <ShieldWarning weight="duotone" className="h-5 w-5" />
                  )
                ) : (
                  <Shield weight="duotone" className="h-5 w-5" />
                )}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-fg-strong">
                  {effectiveMode !== 'off'
                    ? effectiveMode === 'block'
                      ? t('pages.waf.postureBlocking')
                      : t('pages.waf.postureMonitoring')
                    : t('pages.waf.postureOff')}
                </p>
                <p className="text-xs text-fg-subtle">
                  {t('pages.waf.postureHint', {
                    active: waf.active_rules,
                    total: waf.total_rules,
                  })}
                </p>
              </div>
              <div className="flex items-center gap-4">
                <PostureStat
                  label={t('pages.waf.paranoiaLevel')}
                  value={effectiveParanoia}
                />
                <PostureStat
                  label={t('pages.waf.activeRules')}
                  value={`${waf.active_rules}/${waf.total_rules}`}
                />
                <Badge tone={MODE_TONE[effectiveMode] ?? 'neutral'} dot>
                  {t(`pages.waf.mode_${effectiveMode}`)}
                </Badge>
                {canWrite && (
                  <>
                    <Button
                      size="sm"
                      variant="secondary"
                      loading={rulesQuery.isFetching}
                      onClick={() => {
                        void rulesQuery.refetch()
                        void groupsQuery.refetch()
                      }}
                      icon={<ArrowClockwise weight="duotone" className="h-3.5 w-3.5" />}
                    >
                      {t('common.refresh')}
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      loading={restoreBuiltins.isPending}
                      onClick={() => restoreBuiltins.mutate()}
                      icon={<ShieldCheck weight="duotone" className="h-3.5 w-3.5" />}
                    >
                      {t('pages.waf.restoreBuiltins')}
                    </Button>
                  </>
                )}
              </div>
            </div>
          )}

          {/* ── Rule groups ──────────────────────────────────────────── */}
          <Card className="mt-4">
            <CardHeader
              title={t('pages.waf.groups')}
              description={t('pages.waf.groupsHint')}
              action={
                canWrite ? (
                  <Button
                    size="sm"
                    variant="secondary"
                    icon={<Plus weight="bold" className="h-3.5 w-3.5" />}
                    onClick={() => setGroupDialogOpen(true)}
                  >
                    {t('pages.waf.addGroup')}
                  </Button>
                ) : undefined
              }
            />
            <CardBody>
              {loading ? (
                <SkeletonRows rows={2} columns={3} />
              ) : groups.length === 0 ? (
                <p className="py-2 text-sm text-fg-subtle">{t('pages.waf.noGroups')}</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {[...groups]
                    .sort((a, b) => a.priority - b.priority)
                    .map((group) => (
                      <div
                        key={group.id}
                        className={cn(
                          'flex items-center gap-3 rounded-lg border px-3 py-2 transition-colors',
                          group.enabled
                            ? 'border-line bg-elevated'
                            : 'border-line bg-recessed opacity-70',
                        )}
                      >
                        <div className="min-w-0">
                          <p className="truncate text-[13px] font-medium text-fg-strong">
                            {group.name}
                          </p>
                          <p className="text-[11px] text-fg-subtle">
                            {t(`pages.waf.phase_${group.phase}`, group.phase)}
                            <span className="mx-1">·</span>
                            {t('common.priority')} {group.priority}
                          </p>
                        </div>
                        <Switch
                          size="sm"
                          checked={group.enabled}
                          disabled={!canWrite || toggleGroup.isPending}
                          aria-label={group.name}
                          onCheckedChange={(enabled) => toggleGroup.mutate({ group, enabled })}
                        />
                        {canWrite && (
                          <Button
                            size="icon"
                            variant="ghost"
                            className="hover:text-fg-danger"
                            aria-label={t('common.delete')}
                            disabled={deleteGroup.isPending}
                            onClick={() => deleteGroup.mutate(group.id)}
                            icon={<Trash weight="duotone" className="h-3.5 w-3.5" />}
                          />
                        )}
                      </div>
                    ))}
                </div>
              )}
            </CardBody>
          </Card>

          {/* ── Custom rules ─────────────────────────────────────────── */}
          <Card className="mt-4">
            <CardHeader
              title={t('pages.waf.customRules')}
              description={t('pages.waf.customRulesHint')}
              action={
                canWrite ? (
                  <Button
                    size="sm"
                    variant="primary"
                    icon={<Plus weight="bold" className="h-4 w-4" />}
                    onClick={() => openCreate()}
                  >
                    {t('common.add')}
                  </Button>
                ) : undefined
              }
            />
            <CardBody>
              <div className="mb-4 flex flex-wrap items-end gap-3">
                <div className="w-full max-w-xs">
                  <Input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder={t('pages.waf.searchRules')}
                    prefixIcon={<MagnifyingGlass weight="duotone" />}
                    aria-label={t('common.search')}
                  />
                </div>
                <Select
                  aria-label={t('pages.waf.group')}
                  className="h-9 w-44"
                  value={groupFilter}
                  options={groupOptions}
                  onChange={(e) => setGroupFilter(e.target.value)}
                />
                <Select
                  aria-label={t('common.status')}
                  className="h-9 w-40"
                  value={enabledFilter}
                  options={[
                    { value: '', label: t('pages.waf.anyState') },
                    { value: 'enabled', label: t('common.enabled') },
                    { value: 'disabled', label: t('common.disabled') },
                  ]}
                  onChange={(e) => setEnabledFilter(e.target.value)}
                />
                {!loading && (
                  <span className="tabular-nums text-[13px] text-fg-subtle">
                    {t('pages.waf.ruleCount', { count: visibleRules.length })}
                  </span>
                )}
              </div>
            </CardBody>
            <CardBody className="p-0">
              {loading ? (
                <SkeletonRows rows={5} columns={7} />
              ) : visibleRules.length === 0 ? (
                <EmptyState
                  className="py-12"
                  icon={<Shield weight="duotone" className="h-8 w-8" />}
                  title={
                    allRules.length === 0
                      ? t('pages.waf.emptyTitle')
                      : t('pages.waf.noResults')
                  }
                  description={
                    allRules.length === 0
                      ? t('pages.waf.emptyDescription')
                      : t('pages.waf.noResultsDescription')
                  }
                  action={
                    allRules.length === 0 ? (
                      canWrite ? (
                        <div className="flex items-center gap-2">
                          <Button
                            variant="primary"
                            loading={restoreBuiltins.isPending}
                            onClick={() => restoreBuiltins.mutate()}
                            icon={<ShieldCheck weight="duotone" className="h-4 w-4" />}
                          >
                            {t('pages.waf.restoreBuiltins')}
                          </Button>
                          <Button
                            variant="secondary"
                            icon={<Plus weight="bold" className="h-4 w-4" />}
                            onClick={() => openCreate()}
                          >
                            {t('pages.waf.addRule')}
                          </Button>
                        </div>
                      ) : undefined
                    ) : (
                      <Button
                        variant="secondary"
                        onClick={() => {
                          setSearch('')
                          setGroupFilter('')
                          setEnabledFilter('')
                        }}
                      >
                        {t('common.reset')}
                      </Button>
                    )
                  }
                />
              ) : (
                <Table
                  columns={columns}
                  data={visibleRules}
                  rowKey={(r) => r.id}
                  dense
                  onRowClick={canWrite ? (r) => openEdit(r) : undefined}
                />
              )}
            </CardBody>
          </Card>
        </>
      )}

      {/* ── Dialogs ──────────────────────────────────────────────────── */}
      <RuleDialog
        open={dialogOpen}
        onClose={closeDialog}
        siteId={siteId}
        groups={groups}
        rule={editing}
        presetTags={presetTags}
      />

      <Dialog
        open={groupDialogOpen}
        onClose={createGroup.isPending ? () => undefined : () => setGroupDialogOpen(false)}
        size="sm"
        title={t('pages.waf.addGroup')}
        description={t('pages.waf.groupDialogDescription')}
        footer={
          <>
            <Button variant="ghost" onClick={() => setGroupDialogOpen(false)} disabled={createGroup.isPending}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              loading={createGroup.isPending}
              disabled={!groupName.trim()}
              onClick={() => createGroup.mutate()}
            >
              {t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <Input
            label={t('common.name')}
            value={groupName}
            autoFocus
            placeholder={t('pages.waf.groupNamePlaceholder')}
            onChange={(e) => setGroupName(e.target.value)}
          />
          <Select
            label={t('pages.waf.phase')}
            value={groupPhase}
            options={['request', 'response', 'custom'].map((p) => ({
              value: p,
              label: t(`pages.waf.phase_${p}`, p),
            }))}
            onChange={(e) => setGroupPhase(e.target.value)}
          />
        </div>
      </Dialog>

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && deleteRule.mutate(pendingDelete.id)}
        title={t('pages.waf.deleteRuleTitle')}
        description={t('pages.waf.deleteRuleDescription')}
        confirmLabel={t('common.delete')}
        loading={deleteRule.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDelete.name}</p>
            <p className="pw-mono mt-0.5 break-all text-xs text-fg-subtle">
              {pendingDelete.expression}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </div>
  )
}

function PostureStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="text-center">
      <p className="tabular-nums text-base font-semibold leading-tight text-fg-strong">{value}</p>
      <p className="text-[11px] leading-tight text-fg-subtle">{label}</p>
    </div>
  )
}

export default CustomRulesPanel
