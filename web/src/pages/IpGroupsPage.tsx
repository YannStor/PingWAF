import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Trash,
  Pencil,
  ArrowClockwise,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Switch } from '@/components/ui/Switch'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { ipGroupKeys, ipGroupsApi } from '@/api/ipGroups'
import { validateIpCidr } from '@/api/ipRules'
import { useCanWrite, useSitesList } from '@/hooks'
import { formatDateTime, formatRelative } from '@/lib/format'
import type {
  CreateIpGroupRequest,
  IpGroupResponse,
  Site,
} from '@/api/types'
import { IP_GROUP_ACTIONS } from '@/api/types'

const ACTION_TONE: Record<string, 'danger' | 'success'> = {
  block: 'danger',
  allow: 'success',
}

/** Refresh intervals offered for subscriptions, in minutes (0 = manual). */
const SYNC_INTERVAL_OPTIONS = [
  { value: '0', labelKey: 'syncManual' },
  { value: '60', labelKey: 'syncHourly' },
  { value: '360', labelKey: 'sync6h' },
  { value: '1440', labelKey: 'syncDaily' },
  { value: '10080', labelKey: 'syncWeekly' },
] as const

const SYNC_INTERVAL_DEFAULT = '1440'

export function IpGroupsPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const [actionFilter, setActionFilter] = useState('')
  const [scopeFilter, setScopeFilter] = useState('')
  const [editing, setEditing] = useState<IpGroupResponse | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<IpGroupResponse | null>(null)
  const [expandedErrorId, setExpandedErrorId] = useState<string | null>(null)

  const { data: sites } = useSitesList()

  const listQuery = useQuery({
    queryKey: ipGroupKeys.list({
      action: actionFilter || undefined,
      is_global: scopeFilter === 'global' ? true : scopeFilter === 'site' ? false : undefined,
    }),
    queryFn: () =>
      ipGroupsApi.list({
        action: actionFilter || undefined,
        is_global: scopeFilter === 'global' ? true : scopeFilter === 'site' ? false : undefined,
      }),
  })

  const groups = useMemo(() => listQuery.data?.items ?? [], [listQuery.data])
  const total = listQuery.data?.total ?? 0

  const invalidate = async () => {
    await queryClient.invalidateQueries({ queryKey: ipGroupKeys.all })
  }

  const deleteMutation = useMutation({
    mutationFn: (id: string) => ipGroupsApi.delete(id),
    onSuccess: () => {
      toast.success(t('pages.ipGroups.deleted'))
      invalidate()
    },
    onError: () => toast.error(t('pages.ipGroups.deleteFailed')),
  })

  /**
   * Z4: the sync button stays loading until the group's `last_synced_at`
   * actually changes in the list data — the mutation's own `isPending` ends
   * before the server has refreshed the row. We remember the timestamp from
   * before the call and wait for the list query to reflect the new value.
   */
  const [syncingId, setSyncingId] = useState<string | null>(null)
  const syncedAtBefore = useRef<Map<string, string | null>>(new Map())

  useEffect(() => {
    if (!syncingId) return
    const row = groups.find((g) => g.id === syncingId)
    const before = syncedAtBefore.current.get(syncingId)
    if (!row) {
      setSyncingId(null)
      return
    }
    if ((row.last_synced_at ?? null) !== (before ?? null)) {
      syncedAtBefore.current.delete(syncingId)
      setSyncingId(null)
      toast.success(t('pages.ipGroups.synced'))
    }
  }, [groups, syncingId, t, toast])

  const syncMutation = useMutation({
    mutationFn: async (id: string) => {
      const before = groups.find((g) => g.id === id)?.last_synced_at ?? null
      syncedAtBefore.current.set(id, before)
      setSyncingId(id)
      await ipGroupsApi.sync(id)
      await invalidate()
    },
    onError: (error) => {
      setSyncingId(null)
      toast.error(error.message || t('pages.ipGroups.syncFailed'))
    },
  })

  const subscriptionToggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      ipGroupsApi.update(id, { subscription_enabled: enabled }),
    onSuccess: () => invalidate(),
    onError: () =>
      toast.error(t('pages.ipGroups.subscriptionUpdateFailed')),
  })

  const hasSubscription = (row: IpGroupResponse) =>
    row.subscription_kind !== null || row.source_url !== null

  const columns: Column<IpGroupResponse>[] = useMemo(
    () => [
      {
        key: 'name',
        header: t('pages.ipGroups.colName'),
        accessor: (row) => row.name,
      },
      {
        key: 'action',
        header: t('pages.ipGroups.colAction'),
        accessor: (row) => row.action,
        cell: (row) => (
          <Badge tone={ACTION_TONE[row.action] ?? 'neutral'}>
            {t(`pages.ipGroups.action_${row.action}`)}
          </Badge>
        ),
      },
      {
        key: 'scope',
        header: t('pages.ipGroups.colScope'),
        accessor: (row) => (row.is_global ? 'global' : 'site'),
        cell: (row) =>
          row.is_global ? (
            <Badge tone="info">{t('pages.ipGroups.scopeGlobal')}</Badge>
          ) : (
            <span className="text-fg-subtle">
              {row.site_count} {t('pages.ipGroups.sitesCount')}
            </span>
          ),
      },
      {
        key: 'ipCount',
        header: t('pages.ipGroups.colIpCount'),
        accessor: (row) => row.ip_ranges.length,
      },
      {
        key: 'source',
        header: t('pages.ipGroups.colSource'),
        accessor: (row) => row.subscription_kind ?? row.source_url ?? '',
        cell: (row) => (
          <div className="flex items-center gap-2">
            {row.subscription_kind === 'builtin' ? (
              <Badge tone="info">{t('pages.ipGroups.subBuiltin')}</Badge>
            ) : row.source_url ? (
              <span
                className="max-w-52 truncate text-xs text-fg-subtle"
                title={row.source_url}
              >
                {row.source_url}
              </span>
            ) : (
              <span className="text-fg-subtle">—</span>
            )}
            {canWrite && hasSubscription(row) && (
              <span
                title={
                  row.subscription_enabled
                    ? t('pages.ipGroups.subOn')
                    : t('pages.ipGroups.subOff')
                }
              >
                <Switch
                  size="sm"
                  checked={row.subscription_enabled}
                  onCheckedChange={(value) =>
                    subscriptionToggleMutation.mutate({
                      id: row.id,
                      enabled: value,
                    })
                  }
                />
              </span>
            )}
          </div>
        ),
      },
      {
        key: 'lastSync',
        header: t('pages.ipGroups.colLastSync'),
        accessor: (row) => row.last_synced_at ?? '',
        cell: (row) => (
          <div className="min-w-0">
            {row.last_synced_at ? (
              <span title={formatDateTime(row.last_synced_at)}>
                {formatRelative(row.last_synced_at)}
              </span>
            ) : (
              <span className="text-fg-subtle">—</span>
            )}
            {row.last_sync_error &&
              (expandedErrorId === row.id ? (
                <button
                  type="button"
                  className="max-w-64 cursor-pointer break-all text-left text-xs text-danger hover:underline"
                  title={t('pages.ipGroups.syncErrorExpand')}
                  onClick={() => setExpandedErrorId(null)}
                >
                  {row.last_sync_error}
                </button>
              ) : (
                <button
                  type="button"
                  className="max-w-48 cursor-pointer text-left text-xs text-danger hover:underline"
                  title={t('pages.ipGroups.syncErrorExpand')}
                  onClick={() =>
                    setExpandedErrorId((prev) => (prev === row.id ? null : row.id))
                  }
                >
                  {row.last_sync_error}
                </button>
              ))}
          </div>
        ),
      },
      {
        key: 'actions',
        header: '',
        width: '1%',
        cell: (row) => (
          <div className="flex items-center justify-end gap-1">
            {(row.source_url || row.subscription_kind === 'builtin') && (
              <Button
                size="sm"
                variant="ghost"
                loading={syncingId === row.id}
                disabled={syncingId !== null && syncingId !== row.id}
                onClick={() => syncMutation.mutate(row.id)}
                title={t('pages.ipGroups.syncNow')}
              >
                <ArrowClockwise className="h-4 w-4" />
              </Button>
            )}
            {canWrite && (
              <>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setEditing(row)}
                  title={t('common.edit')}
                >
                  <Pencil className="h-4 w-4" />
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setPendingDelete(row)}
                  title={t('common.delete')}
                >
                  <Trash className="h-4 w-4 text-danger" />
                </Button>
              </>
            )}
          </div>
        ),
      },
    ],
    [t, canWrite, syncMutation, subscriptionToggleMutation],
  )

  return (
    <>
      <PageHeader
        title={t('pages.ipGroups.title')}
        description={t('pages.ipGroups.description')}
        actions={
          canWrite ? (
            <Button variant="primary" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4" />
              {t('pages.ipGroups.create')}
            </Button>
          ) : undefined
        }
      />

      <Card>
        <CardBody>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <Select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              options={[
                { value: '', label: t('pages.ipGroups.filterAllActions') },
                ...IP_GROUP_ACTIONS.map((a) => ({
                  value: a,
                  label: t(`pages.ipGroups.action_${a}`),
                })),
              ]}
            />
            <Select
              value={scopeFilter}
              onChange={(e) => setScopeFilter(e.target.value)}
              options={[
                { value: '', label: t('pages.ipGroups.filterAllScopes') },
                { value: 'global', label: t('pages.ipGroups.scopeGlobal') },
                { value: 'site', label: t('pages.ipGroups.scopeSite') },
              ]}
            />
            <span className="ml-auto text-sm text-fg-subtle">
              {total} {total === 1 ? 'group' : 'groups'}
            </span>
          </div>

          {listQuery.isLoading ? (
            <SkeletonRows columns={7} rows={5} />
          ) : listQuery.isError ? (
            <ErrorState error={listQuery.error} onRetry={invalidate} />
          ) : groups.length === 0 ? (
            <EmptyState
              title={t('pages.ipGroups.empty')}
              description={t('pages.ipGroups.emptyHint')}
              action={
                canWrite ? (
                  <Button variant="primary" onClick={() => setCreateOpen(true)}>
                    <Plus className="h-4 w-4" />
                    {t('pages.ipGroups.create')}
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <Table columns={columns} data={groups} rowKey={(row) => row.id} />
          )}
        </CardBody>
      </Card>

      {createOpen && (
        <GroupDialog
          sites={sites ?? []}
          onClose={() => setCreateOpen(false)}
          onSaved={() => {
            setCreateOpen(false)
            invalidate()
          }}
        />
      )}

      {editing && (
        <GroupDialog
          initial={editing}
          sites={sites ?? []}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            invalidate()
          }}
        />
      )}

      <ConfirmDialog
        open={Boolean(pendingDelete)}
        title={t('pages.ipGroups.confirmDeleteTitle')}
        description={t('pages.ipGroups.confirmDeleteDesc', {
          name: pendingDelete?.name,
        })}
        confirmLabel={t('common.delete')}
        tone="danger"
        onConfirm={() => {
          if (pendingDelete) deleteMutation.mutate(pendingDelete.id)
          setPendingDelete(null)
        }}
        onClose={() => setPendingDelete(null)}
      />
    </>
  )
}

/* ── Create / Edit dialog ─────────────────────────────────────────── */

interface GroupDialogProps {
  initial?: IpGroupResponse
  sites: Site[]
  onClose: () => void
  onSaved: () => void
}

function GroupDialog({ initial, sites, onClose, onSaved }: GroupDialogProps) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const isEdit = Boolean(initial)
  // Built-in snapshot groups: the source URL and interval are owned by the
  // seeder, so the dialog neither edits nor submits them.
  const isBuiltin =
    isEdit && initial?.subscription_kind === 'builtin'

  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [action, setAction] = useState(initial?.action ?? 'block')
  const [isGlobal, setIsGlobal] = useState(initial?.is_global ?? true)
  const [sourceUrl, setSourceUrl] = useState(initial?.source_url ?? '')
  const [syncInterval, setSyncInterval] = useState(
    String(initial?.sync_interval_minutes ?? SYNC_INTERVAL_DEFAULT),
  )
  const [enabled, setEnabled] = useState(initial?.enabled ?? true)
  const [ipText, setIpText] = useState(initial?.ip_ranges.join('\n') ?? '')
  const [selectedSites, setSelectedSites] = useState<Set<string>>(
    () => new Set(),
  )

  // Load associated sites for edit mode
  useQuery({
    queryKey: ipGroupKeys.sites(initial?.id ?? ''),
    queryFn: () => ipGroupsApi.listSites(initial!.id),
    enabled: isEdit && !isGlobal,
    select: (data) => {
      setSelectedSites(new Set(data.map((s) => s.id)))
      return data
    },
  })

  const saveMutation = useMutation({
    mutationFn: async () => {
      const ipRanges = ipText
        .split(/[\n,;]/)
        .map((l) => l.trim())
        .filter(Boolean)

      const payload: CreateIpGroupRequest = {
        name: name.trim(),
        description: description.trim() || null,
        ip_ranges: ipRanges,
        action,
        is_global: isGlobal,
        enabled,
      }
      if (!isBuiltin) {
        payload.source_url = sourceUrl.trim() || null
        // 0 = manual; the server maps it to a null interval.
        payload.sync_interval_minutes = sourceUrl.trim()
          ? Number(syncInterval)
          : 0
      }

      if (isEdit && initial) {
        await ipGroupsApi.update(initial.id, payload)
        if (!isGlobal) {
          await ipGroupsApi.setSites(
            initial.id,
            Array.from(selectedSites),
          )
        }
      } else {
        const created = await ipGroupsApi.create(payload)
        if (!isGlobal) {
          await ipGroupsApi.setSites(created.id, Array.from(selectedSites))
        }
      }
    },
    onSuccess: () => {
      toast.success(
        isEdit
          ? t('pages.ipGroups.updated')
          : t('pages.ipGroups.created'),
      )
      queryClient.invalidateQueries({ queryKey: ipGroupKeys.all })
      onSaved()
    },
    onError: () =>
      toast.error(
        isEdit
          ? t('pages.ipGroups.updateFailed')
          : t('pages.ipGroups.createFailed'),
      ),
  })

  const ipValidation = useMemo(() => {
    const lines = ipText
      .split(/[\n,;]/)
      .map((l) => l.trim())
      .filter(Boolean)
    const invalid = lines.filter((l) => validateIpCidr(l) !== null)
    return { total: lines.length, invalid }
  }, [ipText])

  const canSave =
    name.trim().length > 0 &&
    (ipValidation.total > 0 || sourceUrl.trim().length > 0) &&
    ipValidation.invalid.length === 0

  const toggleSite = (id: string) =>
    setSelectedSites((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  return (
    <Dialog
      open
      onClose={onClose}
      title={
        isEdit
          ? t('pages.ipGroups.editTitle')
          : t('pages.ipGroups.createTitle')
      }
      className="max-w-2xl"
    >
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <Input
            label={t('pages.ipGroups.fieldName')}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t('pages.ipGroups.fieldNamePh')}
          />
          <Select
            label={t('pages.ipGroups.fieldAction')}
            value={action}
            onChange={(e) => setAction(e.target.value)}
            options={IP_GROUP_ACTIONS.map((a) => ({
              value: a,
              label: t(`pages.ipGroups.action_${a}`),
            }))}
          />
        </div>

        <Input
          label={t('pages.ipGroups.fieldDescription')}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />

        <div>
          <label className="mb-1 block text-sm font-medium text-fg">
            {t('pages.ipGroups.fieldIpRanges')}
          </label>
          <textarea
            className="w-full rounded-md border border-border bg-surface px-3 py-2 text-sm font-mono text-fg outline-none focus:border-brand focus:ring-1 focus:ring-brand"
            rows={6}
            value={ipText}
            onChange={(e) => setIpText(e.target.value)}
            placeholder={t('pages.ipGroups.fieldIpRangesPh')}
          />
          <div className="mt-1 flex gap-3 text-xs">
            <span className="text-fg-subtle">
              {t('pages.ipGroups.ipCount', { count: ipValidation.total })}
            </span>
            {ipValidation.invalid.length > 0 && (
              <span className="text-danger">
                {t('pages.ipGroups.ipInvalid', {
                  count: ipValidation.invalid.length,
                })}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={isGlobal}
              onChange={(e) => setIsGlobal(e.target.checked)}
              className="rounded border-border"
            />
            {t('pages.ipGroups.fieldGlobal')}
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="rounded border-border"
            />
            {t('pages.ipGroups.fieldEnabled')}
          </label>
        </div>

        {!isGlobal && sites.length > 0 && (
          <div>
            <label className="mb-1 block text-sm font-medium text-fg">
              {t('pages.ipGroups.fieldSites')}
            </label>
            <div className="max-h-32 space-y-1 overflow-y-auto rounded-md border border-border p-2">
              {sites.map((s) => (
                <label
                  key={s.id}
                  className="flex items-center gap-2 text-sm"
                >
                  <input
                    type="checkbox"
                    checked={selectedSites.has(s.id)}
                    onChange={() => toggleSite(s.id)}
                    className="rounded border-border"
                  />
                  {s.domain}
                </label>
              ))}
            </div>
          </div>
        )}

        {isBuiltin ? (
          <p className="rounded-md border border-border bg-recessed px-3 py-2 text-xs text-fg-subtle">
            {t('pages.ipGroups.builtinNote')}
          </p>
        ) : (
          <>
            <Input
              label={t('pages.ipGroups.fieldSourceUrl')}
              value={sourceUrl}
              onChange={(e) => setSourceUrl(e.target.value)}
              placeholder={t('pages.ipGroups.fieldSourceUrlPh')}
            />

            {sourceUrl.trim() && (
              <Select
                label={t('pages.ipGroups.fieldSyncInterval')}
                value={syncInterval}
                onChange={(e) => setSyncInterval(e.target.value)}
                options={SYNC_INTERVAL_OPTIONS.map((option) => ({
                  value: option.value,
                  label: t(`pages.ipGroups.${option.labelKey}`),
                }))}
              />
            )}
          </>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            disabled={!canSave}
            onClick={() => saveMutation.mutate()}
          >
            {isEdit ? t('common.save') : t('common.create')}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}
