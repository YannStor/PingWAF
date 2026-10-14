import { useMemo, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  IdentificationCard,
  Plus,
  PencilSimple,
  Trash,
  ArrowClockwise,
  UploadSimple,
  Users,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Tabs } from '@/components/ui/Tabs'
import { Textarea } from '@/components/ui/Textarea'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import {
  ipRulesApi,
  ipRuleKeys,
  parseIpList,
  summarizeInvalid,
} from '@/api/ipRules'
import { ipGroupsApi, ipGroupKeys } from '@/api/ipGroups'
import { AutoBlockedIpsCard } from '@/pages/sites/AutoBlockedIpsCard'
import { useCanWrite } from '@/hooks'
import { formatDateTime } from '@/lib/format'
import {
  IP_RULE_ACTIONS,
  type BulkImportIpRequest,
  type CreateIpRuleRequest,
  type IpRule,
} from '@/api/types'

const ACTION_TONE: Record<string, 'danger' | 'warning' | 'success' | 'neutral'> = {
  block: 'danger',
  challenge: 'warning',
  js_challenge: 'warning',
  allow: 'success',
}

type RuleMode = 'group' | 'manual'
type DialogTab = 'single' | 'bulk'

interface FormState {
  mode: RuleMode
  name: string
  group_id: string
  ranges: string
  action: string
  note: string
  enabled: boolean
  priority: number
}

const emptyForm = (): FormState => ({
  mode: 'group',
  name: '',
  group_id: '',
  ranges: '',
  action: 'block',
  note: '',
  enabled: true,
  priority: 0,
})

function formFromRule(rule: IpRule): FormState {
  return {
    mode: rule.group_id ? 'group' : 'manual',
    name: rule.name,
    group_id: rule.group_id ?? '',
    ranges: rule.ip_ranges.join('\n'),
    action: rule.action,
    note: rule.note ?? '',
    enabled: rule.enabled,
    priority: rule.priority,
  }
}

/** The IP rule module of the site's access-control tab. */
export function IpRulesPanel() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()
  const [searchParams, setSearchParams] = useSearchParams()

  const [dialogOpen, setDialogOpen] = useState(false)
  const [tab, setTab] = useState<DialogTab>('single')
  const [editing, setEditing] = useState<IpRule | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm())
  const [bulk, setBulk] = useState('')
  const [bulkAction, setBulkAction] = useState('block')
  const [error, setError] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<IpRule | null>(null)

  // Quick-block deep link: /security/access?tab=ip&block=1.2.3.4
  // The param is consumed when the dialog closes — clearing it on open would
  // re-trigger the form-reset effect below and wipe the prefill.
  const prefillBlock = searchParams.get('block')

  // `null` until the first pass: a deep link present at mount must still open
  // the dialog.
  const [lastPrefillBlock, setLastPrefillBlock] = useState<string | null>(null)
  if (prefillBlock !== lastPrefillBlock) {
    setLastPrefillBlock(prefillBlock)
    if (prefillBlock) {
      setTab('single')
      setForm({
        ...emptyForm(),
        mode: 'manual',
        ranges: prefillBlock,
        action: 'block',
      })
      setDialogOpen(true)
    }
  }

  const rulesQuery = useQuery({
    queryKey: ipRuleKeys.list(siteId),
    queryFn: () => ipRulesApi.list(siteId),
    enabled: Boolean(siteId),
    select: (page) => page.items,
  })

  const groupsQuery = useQuery({
    queryKey: ipGroupKeys.list({ enabled: true }),
    queryFn: () => ipGroupsApi.list({ enabled: true }),
    select: (page) => page.items,
  })
  const groups = groupsQuery.data ?? []

  const rules = useMemo(
    () =>
      [...(rulesQuery.data ?? [])].sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      ),
    [rulesQuery.data],
  )

  const openCreate = (mode: RuleMode = 'group') => {
    setEditing(null)
    setTab('single')
    setForm({ ...emptyForm(), mode })
    setDialogOpen(true)
  }

  // Re-seed the dialog form every time it opens (render-phase reset), so the
  // first paint already shows the right rule instead of the previous one.
  const seedKey = dialogOpen ? `${editing?.id ?? 'new'}:${prefillBlock ?? ''}` : ''
  const [lastSeedKey, setLastSeedKey] = useState<string | null>(null)
  if (seedKey !== lastSeedKey) {
    setLastSeedKey(seedKey)
    if (dialogOpen) {
      setError(null)
      if (editing) setForm(formFromRule(editing))
      else if (!prefillBlock) setForm(emptyForm())
    }
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ipRuleKeys.all(siteId) })
  }

  const buildPayload = (): CreateIpRuleRequest => ({
    name: form.name.trim(),
    action: form.action,
    note: form.note.trim() || null,
    enabled: form.enabled,
    priority: form.priority,
    ...(form.mode === 'group'
      ? { group_id: form.group_id }
      : { ip_ranges: parseIpList(form.ranges).valid }),
  })

  const save = useMutation({
    mutationFn: (payload: CreateIpRuleRequest) =>
      editing
        ? ipRulesApi.update(siteId, editing.id, payload)
        : ipRulesApi.create(siteId, payload),
    onSuccess: (rule) => {
      toast.success(
        editing ? t('pages.ipRules.ruleUpdated') : t('pages.ipRules.ruleCreated'),
        rule.name,
      )
      closeDialog()
      invalidate()
    },
    onError: (e) => setError(e instanceof Error ? e.message : String(e)),
  })

  const bulkSave = useMutation({
    mutationFn: (payload: BulkImportIpRequest) =>
      ipRulesApi.bulkImport(siteId, payload),
    onSuccess: (result) => {
      toast.success(t('pages.ipRules.bulkCreated', { count: result.imported }))
      closeDialog()
      invalidate()
    },
    onError: (e) => setError(e instanceof Error ? e.message : String(e)),
  })

  const toggle = useMutation({
    mutationFn: ({ rule, enabled }: { rule: IpRule; enabled: boolean }) =>
      ipRulesApi.toggleEnabled(siteId, rule.id, enabled),
    onSuccess: () => invalidate(),
  })

  const remove = useMutation({
    mutationFn: (id: string) => ipRulesApi.delete(siteId, id),
    onSuccess: (_d, id) => {
      toast.success(t('pages.ipRules.ruleDeleted'), rules.find((r) => r.id === id)?.name)
      setPendingDelete(null)
      invalidate()
    },
  })

  const closeDialog = () => {
    setDialogOpen(false)
    setEditing(null)
    setForm(emptyForm())
    setBulk('')
    setError(null)
    if (prefillBlock) {
      const params = new URLSearchParams(searchParams)
      params.delete('block')
      setSearchParams(params, { replace: true })
    }
  }

  const submitSingle = () => {
    setError(null)
    if (!form.name.trim()) {
      setError(t('pages.ipRules.nameRequired'))
      return
    }
    if (form.mode === 'group') {
      if (!form.group_id) {
        setError(t('pages.ipRules.groupRequired'))
        return
      }
    } else {
      const { valid, invalid, duplicateCount } = parseIpList(form.ranges)
      if (valid.length === 0) {
        setError(t('pages.ipRules.manualNone'))
        return
      }
      const problem = summarizeInvalid(invalid, duplicateCount, t)
      if (problem) {
        setError(problem)
        return
      }
    }
    save.mutate(buildPayload())
  }

  const submitBulk = () => {
    setError(null)
    const { valid, invalid, duplicateCount } = parseIpList(bulk)
    if (valid.length === 0) {
      setError(t('pages.ipRules.bulkNone'))
      return
    }
    const problem = summarizeInvalid(invalid, duplicateCount, t)
    if (problem) {
      setError(problem)
      return
    }
    bulkSave.mutate({ ip_ranges: valid, action: bulkAction, enabled: true })
  }

  const columns: Column<IpRule>[] = [
    {
      key: 'name',
      header: t('pages.ipRules.name'),
      accessor: (r) => r.name,
      sortable: true,
      cell: (r) => (
        <div className="min-w-0">
          <p className="truncate text-[13px] font-medium text-fg-strong">{r.name}</p>
          {r.note && (
            <p className="line-clamp-1 text-xs text-fg-subtle">{r.note}</p>
          )}
        </div>
      ),
    },
    {
      key: 'target',
      header: t('pages.ipRules.target'),
      accessor: (r) => r.group_name ?? r.ip_ranges.join(' '),
      cell: (r) =>
        r.group_name ? (
          <Badge tone="info">
            <Users weight="duotone" className="mr-1 h-3 w-3" />
            {r.group_name}
          </Badge>
        ) : (
          <span className="text-[13px] text-fg-subtle">
            {t('pages.ipRules.rangeCount', { count: r.ip_ranges.length })}
          </span>
        ),
    },
    {
      key: 'action',
      header: t('pages.waf.action'),
      accessor: (r) => r.action,
      width: '1%',
      cell: (r) => (
        <Badge tone={ACTION_TONE[r.action] ?? 'neutral'}>
          {t(`actions.${r.action}`, r.action)}
        </Badge>
      ),
    },
    {
      key: 'priority',
      header: t('pages.ipRules.priority'),
      accessor: (r) => r.priority,
      sortable: true,
      width: '1%',
      cell: (r) => (
        <span className="text-[13px] text-fg-subtle">{r.priority}</span>
      ),
    },
    {
      key: 'created_at',
      header: t('pages.ipRules.created'),
      accessor: (r) => r.created_at,
      sortable: true,
      width: '1%',
      cell: (r) => (
        <span className="text-[13px] text-fg-subtle">{formatDateTime(r.created_at)}</span>
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
              setTab('single')
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

  const blockedCount = rules.filter((r) => r.action === 'block' && r.enabled).length
  const groupedCount = rules.filter((r) => r.group_id).length

  const groupOptions = groups.map((g) => ({
    value: g.id,
    label: `${g.name} (${g.ip_ranges.length})`,
  }))

  const parsedManual = parseIpList(form.ranges)

  return (
    <div>
      <div className="mb-4 flex items-center justify-end gap-2">
        <Button
          variant="secondary"
          loading={rulesQuery.isFetching}
          onClick={() => rulesQuery.refetch()}
          icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
        >
          {t('common.refresh')}
        </Button>
        {canWrite && (
          <Button
            variant="primary"
            icon={<Plus weight="bold" className="h-4 w-4" />}
            onClick={() => openCreate('group')}
          >
            {t('pages.ipRules.addRule')}
          </Button>
        )}
      </div>

      {rules.length > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-4 rounded-lg border border-line bg-elevated px-4 py-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-soft text-brand">
            <IdentificationCard weight="duotone" className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-fg-strong">
              {t('pages.ipRules.summary', { total: rules.length, blocked: blockedCount })}
            </p>
            <p className="text-xs text-fg-subtle">
              {t('pages.ipRules.summaryHint', { grouped: groupedCount })}
            </p>
          </div>
        </div>
      )}

      {rulesQuery.isError && !rulesQuery.data ? (
        <ErrorState
          error={rulesQuery.error}
          onRetry={() => rulesQuery.refetch()}
          retrying={rulesQuery.isFetching}
        />
      ) : (
        <>
          <AutoBlockedIpsCard siteId={siteId} />
          <Card className="mt-4">
            <CardHeader title={t('pages.ipRules.rulesTitle')} />
          <CardBody className="p-0">
            {rulesQuery.isPending ? (
              <SkeletonRows rows={5} columns={7} />
            ) : rules.length === 0 ? (
              <EmptyState
                className="border-0 py-12"
                icon={<IdentificationCard weight="duotone" className="h-8 w-8" />}
                title={t('pages.ipRules.empty')}
                description={t('pages.ipRules.emptyDescription')}
                action={
                  canWrite ? (
                    <Button
                      variant="primary"
                      icon={<Plus weight="bold" className="h-4 w-4" />}
                      onClick={() => openCreate('group')}
                    >
                      {t('pages.ipRules.addRule')}
                    </Button>
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
                        setTab('single')
                        setDialogOpen(true)
                      }
                    : undefined
                }
              />
            )}
          </CardBody>
        </Card>
        </>
      )}

      <Dialog
        open={dialogOpen}
        onClose={save.isPending || bulkSave.isPending ? () => undefined : closeDialog}
        size="lg"
        title={editing ? t('pages.ipRules.editRule') : t('pages.ipRules.addRule')}
        description={t('pages.ipRules.dialogDescription')}
        footer={
          <>
            <Button variant="ghost" onClick={closeDialog} disabled={save.isPending || bulkSave.isPending}>
              {t('common.cancel')}
            </Button>
            {tab === 'single' ? (
              <Button variant="primary" onClick={submitSingle} loading={save.isPending}>
                {editing ? t('common.save') : t('common.create')}
              </Button>
            ) : (
              <Button variant="primary" onClick={submitBulk} loading={bulkSave.isPending}>
                {t('pages.ipRules.importCount', { count: parseIpList(bulk).valid.length })}
              </Button>
            )}
          </>
        }
      >
        {!editing && (
          <Tabs
            variant="pill"
            className="mb-4"
            value={tab}
            onChange={(v) => setTab(v as DialogTab)}
            items={[
              { value: 'single', label: t('pages.ipRules.single') },
              { value: 'bulk', label: t('pages.ipRules.bulk'), icon: <UploadSimple weight="duotone" className="h-4 w-4" /> },
            ]}
          />
        )}

        {tab === 'single' ? (
          <div className="flex flex-col gap-4">
            <Tabs
              variant="pill"
              value={form.mode}
              onChange={(v) => setForm((f) => ({ ...f, mode: v as RuleMode }))}
              items={[
                { value: 'group', label: t('pages.ipRules.modeGroup') },
                { value: 'manual', label: t('pages.ipRules.modeManual') },
              ]}
            />
            <Input
              label={t('pages.ipRules.name')}
              value={form.name}
              autoFocus
              placeholder={t('pages.ipRules.namePlaceholder')}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              required
            />
            {form.mode === 'group' ? (
              <Select
                label={t('pages.ipRules.groupName')}
                value={form.group_id}
                options={[
                  { value: '', label: t('pages.ipRules.selectGroup'), disabled: true },
                  ...groupOptions,
                ]}
                hint={t('pages.ipRules.groupHint')}
                onChange={(e) => setForm((f) => ({ ...f, group_id: e.target.value }))}
                required
              />
            ) : (
              <Textarea
                label={t('pages.ipRules.rangesLabel')}
                mono
                rows={6}
                value={form.ranges}
                placeholder={'203.0.113.44\n10.0.0.0/24'}
                hint={t('pages.ipRules.rangesHint')}
                onChange={(e) => setForm((f) => ({ ...f, ranges: e.target.value }))}
              />
            )}
            {form.mode === 'manual' && form.ranges.trim() && (
              <p className="text-xs text-fg-subtle">
                {t('pages.ipRules.bulkPreview', {
                  valid: parsedManual.valid.length,
                  invalid: parsedManual.invalid.length,
                })}
              </p>
            )}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Select
                label={t('pages.waf.action')}
                value={form.action}
                hint={
                  form.action === 'basic_auth'
                    ? t('pages.basicAuth.ruleActionHint')
                    : undefined
                }
                options={IP_RULE_ACTIONS.map((a) => ({
                  value: a,
                  label: t(`actions.${a}`, a),
                }))}
                onChange={(e) => setForm((f) => ({ ...f, action: e.target.value }))}
              />
              <Input
                label={t('pages.ipRules.note')}
                value={form.note}
                placeholder={t('pages.ipRules.notePlaceholder')}
                onChange={(e) => setForm((f) => ({ ...f, note: e.target.value }))}
              />
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Input
                label={t('pages.ipRules.priority')}
                type="number"
                min={0}
                value={form.priority}
                hint={t('pages.ipRules.priorityHint')}
                onChange={(e) =>
                  setForm((f) => ({ ...f, priority: Number(e.target.value) || 0 }))
                }
              />
              <div className="flex items-end pb-1">
                <Switch
                  checked={form.enabled}
                  onCheckedChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
                  label={t('common.enabled')}
                />
              </div>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            <Textarea
              label={t('pages.ipRules.bulkLabel')}
              mono
              rows={8}
              value={bulk}
              placeholder={'203.0.113.44\n10.0.0.0/24\n198.51.100.7'}
              hint={t('pages.ipRules.bulkHint')}
              onChange={(e) => setBulk(e.target.value)}
            />
            <Select
              label={t('pages.waf.action')}
              value={bulkAction}
              hint={
                bulkAction === 'basic_auth'
                  ? t('pages.basicAuth.ruleActionHint')
                  : undefined
              }
              options={IP_RULE_ACTIONS.map((a) => ({
                value: a,
                label: t(`actions.${a}`, a),
              }))}
              onChange={(e) => setBulkAction(e.target.value)}
            />
            {bulk.trim() && (
              <p className="text-xs text-fg-subtle">
                {t('pages.ipRules.bulkPreview', {
                  valid: parseIpList(bulk).valid.length,
                  invalid: parseIpList(bulk).invalid.length,
                })}
              </p>
            )}
          </div>
        )}

        {error && (
          <p
            role="alert"
            className="mt-4 rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
          >
            {error}
          </p>
        )}
      </Dialog>

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete.id)}
        title={t('pages.ipRules.deleteTitle')}
        description={t('pages.ipRules.deleteDescription')}
        confirmLabel={t('common.delete')}
        loading={remove.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono text-[13px] font-medium text-fg-strong">
              {pendingDelete.name}
            </p>
            {pendingDelete.group_name && (
              <p className="mt-0.5 text-xs text-fg-subtle">
                <Users weight="duotone" className="mr-1 inline h-3 w-3" />
                {pendingDelete.group_name}
              </p>
            )}
          </div>
        )}
      </ConfirmDialog>
    </div>
  )
}

export default IpRulesPanel
