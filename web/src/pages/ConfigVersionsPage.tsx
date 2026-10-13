import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowCounterClockwise,
  ClockCounterClockwise,
  Eye,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { ErrorState } from '@/components/ErrorState'
import { Badge, type BadgeTone } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody } from '@/components/ui/Card'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { Select } from '@/components/ui/Select'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { Table, type Column } from '@/components/ui/Table'
import { useToast } from '@/components/ui/Toast'
import {
  configVersionsApi,
  configVersionKeys,
  type ConfigVersionDetail,
  type ConfigVersionSummary,
} from '@/api/configVersions'
import { errorMessage } from '@/api/errors'
import { useCanWrite, useSitesList } from '@/hooks'
import { formatDateTime } from '@/lib/format'

/**
 * How many versions one request asks for. The console keeps its own
 * pagination client-side (`Table`), so a page here is one round trip.
 */
const PAGE_SIZE = 50

/** Scope filter value standing for the deployment-wide versions. */
const GLOBAL_SCOPE = 'global'

/* ── Snapshot diffing ───────────────────────────────────────────────── */

/** One snapshot row — the serialized model, field names as stored. */
type SnapshotRow = Record<string, unknown>

/** Columns that can identify a row across two snapshots, best first. */
const IDENTITY_KEYS = [
  'id',
  'uuid',
  'status_code',
  'domain',
  'name',
  'key',
  'group_id',
] as const

function rowIdentity(row: SnapshotRow): string | null {
  for (const key of IDENTITY_KEYS) {
    const value = row[key]
    if (typeof value === 'string' || typeof value === 'number') {
      return `${key}=${value}`
    }
  }
  return null
}

/**
 * Canonical form of a row for comparison: top-level keys sorted, so a
 * reordered serialization does not read as a change. Nested values keep the
 * order the server serialized them in, which is stable across snapshots
 * because it follows the model definition.
 */
function canonical(row: SnapshotRow): string {
  const keys = Object.keys(row).sort()
  return JSON.stringify(keys.map((key) => [key, row[key]]))
}

interface TableDiff {
  table: string
  added: SnapshotRow[]
  removed: SnapshotRow[]
  changed: number
}

/**
 * Compares two snapshots table by table.
 *
 * Rows are matched on the first identity column they carry; a row whose
 * identity is absent (or duplicated) is counted as added or removed rather
 * than guessed at. A matched row whose content differs counts as changed.
 */
function diffSnapshots(
  previous: Record<string, SnapshotRow[]>,
  current: Record<string, SnapshotRow[]>,
): TableDiff[] {
  const tables = [...new Set([...Object.keys(previous), ...Object.keys(current)])].sort()
  const diffs: TableDiff[] = []

  for (const table of tables) {
    const before = previous[table] ?? []
    const after = current[table] ?? []

    const known = new Map<string, SnapshotRow>()
    const anonymous: SnapshotRow[] = []
    for (const row of before) {
      const identity = rowIdentity(row)
      if (identity === null || known.has(identity)) {
        anonymous.push(row)
      } else {
        known.set(identity, row)
      }
    }

    const added: SnapshotRow[] = []
    let changed = 0
    for (const row of after) {
      const identity = rowIdentity(row)
      if (identity === null) {
        added.push(row)
        continue
      }
      const match = known.get(identity)
      if (!match) {
        added.push(row)
        continue
      }
      known.delete(identity)
      if (canonical(match) !== canonical(row)) changed += 1
    }

    const removed = [...anonymous, ...known.values()]
    if (added.length > 0 || removed.length > 0 || changed > 0) {
      diffs.push({ table, added, removed, changed })
    }
  }

  return diffs
}

const SOURCE_TONES: Record<string, BadgeTone> = {
  api: 'info',
  cli: 'neutral',
  rollback: 'warning',
}

/* ── Detail dialog ──────────────────────────────────────────────────── */

function VersionDetailDialog({
  versionId,
  previousId,
  onClose,
  onRollback,
}: {
  versionId: number
  /** The next-older version of the same scope, when the list has one. */
  previousId: number | null
  onClose: () => void
  onRollback: (version: ConfigVersionDetail) => void
}) {
  const { t } = useTranslation()

  const detail = useQuery({
    queryKey: configVersionKeys.detail(versionId),
    queryFn: () => configVersionsApi.get(versionId),
  })

  const previous = useQuery({
    queryKey: configVersionKeys.detail(previousId ?? -1),
    queryFn: () => configVersionsApi.get(previousId as number),
    enabled: previousId !== null,
  })

  const data = detail.data
  const diffs = useMemo(() => {
    if (!data) return null
    // Without a predecessor there is nothing to diff against; the whole
    // snapshot is "added", which is noise. The dialog then shows the row
    // counts only.
    if (!previous.data) return null
    return diffSnapshots(
      previous.data.snapshot.tables ?? {},
      data.snapshot.tables ?? {},
    )
  }, [data, previous.data])

  const counts = useMemo(() => {
    if (!data) return []
    return Object.entries(data.snapshot.tables ?? {})
      .filter(([, rows]) => rows.length > 0)
      .sort(([a], [b]) => a.localeCompare(b))
  }, [data])

  return (
    <Dialog
      open
      onClose={onClose}
      size="xl"
      title={t('pages.configVersions.detailTitle', { id: versionId })}
      description={t('pages.configVersions.detailDescription')}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t('common.close')}
          </Button>
          {data && (
            <Button
              variant="danger"
              onClick={() => onRollback(data)}
            >
              <ArrowCounterClockwise className="h-4 w-4" />
              {t('pages.configVersions.rollback')}
            </Button>
          )}
        </>
      }
    >
      {detail.isError && !data ? (
        <ErrorState
          variant="inline"
          error={detail.error}
          onRetry={() => detail.refetch()}
          retrying={detail.isFetching}
        />
      ) : !data ? (
        <SkeletonRows rows={4} columns={2} />
      ) : (
        <div className="flex flex-col gap-5">
          <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
            {[
              {
                label: t('pages.configVersions.recordedAt'),
                value: formatDateTime(data.created_at),
              },
              {
                label: t('pages.configVersions.scope'),
                value: data.site_domain ?? t('pages.configVersions.globalScope'),
              },
              {
                label: t('pages.configVersions.source'),
                value: t(`pages.configVersions.sources.${data.source}`),
              },
              {
                label: t('pages.configVersions.actor'),
                value: data.actor ?? t('pages.configVersions.actorUnknown'),
              },
              { label: t('pages.configVersions.hash'), value: data.config_hash },
              {
                label: t('pages.configVersions.schema'),
                value: String(data.snapshot.schema),
              },
            ].map((item) => (
              <div key={item.label} className="flex flex-col gap-0.5">
                <dt className="text-xs text-fg-subtle">{item.label}</dt>
                <dd className="pw-mono break-all text-sm text-fg">
                  {item.value}
                </dd>
              </div>
            ))}
          </dl>

          <section className="flex flex-col gap-2">
            <h3 className="text-sm font-medium text-fg">
              {t('pages.configVersions.diffTitle')}
            </h3>
            {previousId === null ? (
              <p className="text-xs text-fg-subtle">
                {t('pages.configVersions.diffNoPredecessor')}
              </p>
            ) : previous.isError ? (
              <p className="text-xs text-fg-subtle">
                {t('pages.configVersions.diffUnavailable')}
              </p>
            ) : !previous.data ? (
              <SkeletonRows rows={2} columns={1} />
            ) : !diffs || diffs.length === 0 ? (
              <p className="text-xs text-fg-subtle">
                {t('pages.configVersions.diffEmpty')}
              </p>
            ) : (
              <div className="flex flex-col divide-y divide-border rounded-md border border-border">
                {diffs.map((diff) => (
                  <div
                    key={diff.table}
                    className="flex flex-col gap-1 px-3 py-2"
                  >
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="pw-mono text-xs text-fg">
                        {diff.table}
                      </span>
                      {diff.added.length > 0 && (
                        <Badge tone="success" size="sm">
                          {t('pages.configVersions.diffAdded', {
                            count: diff.added.length,
                          })}
                        </Badge>
                      )}
                      {diff.changed > 0 && (
                        <Badge tone="warning" size="sm">
                          {t('pages.configVersions.diffChanged', {
                            count: diff.changed,
                          })}
                        </Badge>
                      )}
                      {diff.removed.length > 0 && (
                        <Badge tone="danger" size="sm">
                          {t('pages.configVersions.diffRemoved', {
                            count: diff.removed.length,
                          })}
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="flex flex-col gap-2">
            <h3 className="text-sm font-medium text-fg">
              {t('pages.configVersions.tablesTitle')}
            </h3>
            {counts.length === 0 ? (
              <p className="text-xs text-fg-subtle">
                {t('pages.configVersions.tablesEmpty')}
              </p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {counts.map(([table, rows]) => (
                  <Badge key={table} tone="neutral" size="sm">
                    <span className="pw-mono">{table}</span>
                    <span className="ml-1.5 text-fg-subtle">{rows.length}</span>
                  </Badge>
                ))}
              </div>
            )}
          </section>
        </div>
      )}
    </Dialog>
  )
}

/* ── Page ───────────────────────────────────────────────────────────── */

export function ConfigVersionsPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const [scope, setScope] = useState('')
  const [detail, setDetail] = useState<ConfigVersionSummary | null>(null)
  const [pending, setPending] = useState<ConfigVersionSummary | null>(null)

  const sites = useSitesList({ page: 1, page_size: 200 })

  const versions = useQuery({
    queryKey: configVersionKeys.list(scope || undefined),
    queryFn: () =>
      configVersionsApi.list(scope || undefined, PAGE_SIZE, 0),
  })

  const rows = versions.data ?? []

  const rollback = useMutation({
    mutationFn: (id: number) => configVersionsApi.rollback(id),
    onSuccess: (result) => {
      setPending(null)
      setDetail(null)
      toast.success(
        t('pages.configVersions.rollbackDone', {
          id: result.restored_version,
        }),
      )
      // A rollback rewrites live configuration, so everything that reads it
      // is stale — not just the version list.
      void queryClient.invalidateQueries()
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  /**
   * The version recorded immediately before `row` inside the same scope —
   * what the detail dialog diffs against. The API returns the list newest
   * first, so it is the next entry with the same `site_id`.
   */
  const previousOf = (row: ConfigVersionSummary): number | null => {
    const index = rows.findIndex((item) => item.id === row.id)
    for (let cursor = index + 1; cursor < rows.length; cursor += 1) {
      if (rows[cursor].site_id === row.site_id) return rows[cursor].id
    }
    return null
  }

  const columns = useMemo<Column<ConfigVersionSummary>[]>(
    () => [
      {
        key: 'created_at',
        header: t('pages.configVersions.recordedAt'),
        accessor: (row) => row.created_at,
        sortable: true,
        cell: (row) => (
          <span className="text-sm">{formatDateTime(row.created_at)}</span>
        ),
      },
      {
        key: 'scope',
        header: t('pages.configVersions.scope'),
        accessor: (row) => row.site_domain ?? '',
        sortable: true,
        cell: (row) =>
          row.site_domain ? (
            <span className="pw-mono text-sm">{row.site_domain}</span>
          ) : (
            <Badge tone="brand" size="sm">
              {t('pages.configVersions.globalScope')}
            </Badge>
          ),
      },
      {
        key: 'source',
        header: t('pages.configVersions.source'),
        accessor: (row) => row.source,
        sortable: true,
        cell: (row) => (
          <Badge tone={SOURCE_TONES[row.source] ?? 'neutral'} size="sm">
            {t(`pages.configVersions.sources.${row.source}`)}
          </Badge>
        ),
      },
      {
        key: 'actor',
        header: t('pages.configVersions.actor'),
        accessor: (row) => row.actor ?? '',
        cell: (row) => (
          <span className="text-sm text-fg-subtle">
            {row.actor ?? t('pages.configVersions.actorUnknown')}
          </span>
        ),
      },
      {
        key: 'summary',
        header: t('pages.configVersions.content'),
        cell: (row) => {
          const entries = Object.entries(row.summary ?? {})
          if (entries.length === 0) {
            return <span className="text-sm text-fg-subtle">—</span>
          }
          return (
            <span className="text-xs text-fg-subtle">
              {t('pages.configVersions.tableCount', {
                count: entries.length,
              })}
            </span>
          )
        },
      },
      {
        key: 'actions',
        header: '',
        align: 'right',
        width: '1%',
        cell: (row) => (
          <div className="flex justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setDetail(row)}
            >
              <Eye className="h-4 w-4" />
              {t('pages.configVersions.view')}
            </Button>
            {canWrite && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setPending(row)}
              >
                <ArrowCounterClockwise className="h-4 w-4" />
                {t('pages.configVersions.rollback')}
              </Button>
            )}
          </div>
        ),
      },
    ],
    [t, canWrite],
  )

  const scopeOptions = useMemo(
    () => [
      { value: '', label: t('pages.configVersions.allScopes') },
      { value: GLOBAL_SCOPE, label: t('pages.configVersions.globalScope') },
      ...(sites.data ?? []).map((site) => ({
        value: site.id,
        label: site.domain,
      })),
    ],
    [t, sites.data],
  )

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('pages.configVersions.title')}
        description={t('pages.configVersions.description')}
        actions={
          <Button
            variant="ghost"
            onClick={() => void versions.refetch()}
            loading={versions.isFetching}
          >
            <ClockCounterClockwise className="h-4 w-4" />
            {t('common.refresh')}
          </Button>
        }
      />

      <Card>
        <CardBody className="flex flex-col gap-4">
          <div className="max-w-sm">
            <Select
              label={t('pages.configVersions.scopeFilter')}
              value={scope}
              options={scopeOptions}
              onChange={(event) => setScope(event.target.value)}
            />
          </div>

          {versions.isError && !versions.data ? (
            <ErrorState
              variant="inline"
              error={versions.error}
              onRetry={() => versions.refetch()}
              retrying={versions.isFetching}
            />
          ) : !versions.data ? (
            <SkeletonRows rows={5} columns={5} />
          ) : (
            <Table
              columns={columns}
              data={rows}
              rowKey={(row) => String(row.id)}
              pageSize={20}
              empty={
                <EmptyState
                  icon={<ClockCounterClockwise className="h-6 w-6" />}
                  title={t('pages.configVersions.emptyTitle')}
                  description={t('pages.configVersions.emptyDescription')}
                />
              }
            />
          )}

          {rows.length === PAGE_SIZE && (
            <p className="text-xs text-fg-subtle">
              {t('pages.configVersions.windowHint', { count: PAGE_SIZE })}
            </p>
          )}
        </CardBody>
      </Card>

      {detail && (
        <VersionDetailDialog
          versionId={detail.id}
          previousId={previousOf(detail)}
          onClose={() => setDetail(null)}
          onRollback={(version) => {
            setDetail(null)
            setPending({
              ...detail,
              id: version.id,
            })
          }}
        />
      )}

      <ConfirmDialog
        open={pending !== null}
        onClose={() => setPending(null)}
        onConfirm={() => {
          if (pending) rollback.mutate(pending.id)
        }}
        tone="danger"
        loading={rollback.isPending}
        title={t('pages.configVersions.rollbackConfirmTitle', {
          id: pending?.id ?? '',
        })}
        description={t('pages.configVersions.rollbackConfirmDescription', {
          scope:
            pending?.site_domain ?? t('pages.configVersions.globalScope'),
          time: formatDateTime(pending?.created_at),
        })}
        confirmLabel={t('pages.configVersions.rollback')}
        cancelLabel={t('common.cancel')}
      />
    </div>
  )
}

export default ConfigVersionsPage
