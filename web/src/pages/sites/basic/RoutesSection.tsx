import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { Signpost, Plus, PencilSimple, Trash } from '@phosphor-icons/react'
import { Card, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Switch } from '@/components/ui/Switch'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { sitesApi, siteKeys } from '@/api/sites'
import { errorMessage } from '@/api/errors'
import { useCanWrite } from '@/hooks'
import type { IpGroupResponse, Route, UpstreamPool } from '@/api/types'

/**
 * Route dispatch table with the enable switches, row actions and the
 * delete confirmation.
 */
export function RoutesSection({
  siteId,
  routesQuery,
  poolById,
  ipGroupById,
  onEditRoute,
  onCreateRoute,
}: {
  siteId: string
  routesQuery: UseQueryResult<Route[], Error>
  poolById: Map<string, UpstreamPool>
  ipGroupById: Map<string, IpGroupResponse>
  onEditRoute: (route: Route) => void
  onCreateRoute: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const routes = useMemo(
    () =>
      [...(routesQuery.data ?? [])].sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      ),
    [routesQuery.data],
  )

  const [pendingDeleteRoute, setPendingDeleteRoute] = useState<Route | null>(null)

  const toggleRoute = useMutation({
    mutationFn: ({ route, enabled }: { route: Route; enabled: boolean }) =>
      sitesApi.updateRoute(siteId, route.id, { enabled }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: siteKeys.all })
    },
    onError: (e) => toast.error(t('pages.basic.routeToggleFailed'), errorMessage(e)),
  })

  const deleteRoute = useMutation({
    mutationFn: (id: string) => sitesApi.deleteRoute(siteId, id),
    onSuccess: (_d, id) => {
      toast.success(
        t('pages.basic.routeDeleted'),
        (routesQuery.data ?? []).find((r) => r.id === id)?.name,
      )
      setPendingDeleteRoute(null)
      void queryClient.invalidateQueries({ queryKey: siteKeys.all })
    },
    onError: (e) => toast.error(t('pages.basic.routeDeleteFailed'), errorMessage(e)),
  })

  const MATCH_TONE: Record<string, 'neutral' | 'info' | 'warning'> = {
    prefix: 'neutral',
    exact: 'info',
    regex: 'warning',
  }

  const routeColumns: Column<Route>[] = [
    {
      key: 'name',
      header: t('common.name'),
      accessor: (r) => r.name,
      sortable: true,
      cell: (r) => (
        <div className="min-w-0">
          <p className="truncate text-[13px] font-medium text-fg-strong">{r.name}</p>
          <p className="truncate text-xs text-fg-subtle">
            {poolById.get(r.pool_id)?.name ?? t('pages.basic.missingPool')}
          </p>
        </div>
      ),
    },
    {
      key: 'match_type',
      header: t('pages.basic.matchType'),
      accessor: (r) => r.match_type,
      width: '1%',
      cell: (r) => (
        <Badge tone={MATCH_TONE[r.match_type] ?? 'neutral'}>
          {t(`pages.basic.match.${r.match_type}`, r.match_type)}
        </Badge>
      ),
    },
    {
      key: 'path',
      header: t('pages.basic.routePath'),
      accessor: (r) => r.path,
      cell: (r) => (
        <span className="pw-mono text-[13px] text-fg">
          {r.path}
          {r.rewrite_path ? (
            <Badge tone="brand" size="sm" className="ml-1.5">
              → {r.rewrite_path}
            </Badge>
          ) : r.strip_prefix ? (
            <Badge tone="brand" size="sm" className="ml-1.5">
              {t('pages.routes.stripPrefix')}
            </Badge>
          ) : null}
        </span>
      ),
    },
    {
      key: 'priority',
      header: t('pages.basic.priority'),
      align: 'right',
      sortable: true,
      accessor: (r) => r.priority ?? 0,
      cell: (r) => (
        <span className="tabular-nums text-[13px] text-fg-subtle">
          {r.priority ?? t('pages.basic.auto')}
        </span>
      ),
    },
    {
      key: 'ip_group',
      header: t('pages.basic.ipGroup'),
      accessor: (r) => (r.ip_group_id ? ipGroupById.get(r.ip_group_id)?.name ?? '' : ''),
      cell: (r) => {
        if (!r.ip_group_id) {
          return <span className="text-xs text-fg-subtle">—</span>
        }
        const group = ipGroupById.get(r.ip_group_id)
        if (!group) {
          return <Badge tone="warning">{t('pages.basic.ipGroupMissing')}</Badge>
        }
        return <Badge tone="brand">{group.name}</Badge>
      },
    },
    {
      key: 'pool',
      header: t('pages.basic.targetPool'),
      accessor: (r) => poolById.get(r.pool_id)?.name ?? '',
      cell: (r) => {
        const pool = poolById.get(r.pool_id)
        return pool ? (
          <span className="text-[13px]">
            {pool.name}
            {pool.is_default && (
              <Badge tone="brand" size="sm" className="ml-1.5">
                {t('pages.basic.defaultBadge')}
              </Badge>
            )}
          </span>
        ) : (
          <span className="text-[13px] text-fg-danger">{t('pages.basic.missingPool')}</span>
        )
      },
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
          disabled={!canWrite || toggleRoute.isPending}
          aria-label={`${t('common.enabled')}: ${r.name}`}
          onCheckedChange={(enabled) => toggleRoute.mutate({ route: r, enabled })}
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
            onClick={() => onEditRoute(r)}
            icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            onClick={() => setPendingDeleteRoute(r)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  return (
    <>
      {routesQuery.isError && !routesQuery.data ? (
        <ErrorState
          error={routesQuery.error}
          onRetry={() => routesQuery.refetch()}
          retrying={routesQuery.isFetching}
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            {routesQuery.isPending ? (
              <SkeletonRows rows={4} columns={6} />
            ) : routes.length === 0 ? (
              <EmptyState
                className="border-0 py-10"
                icon={<Signpost weight="duotone" className="h-8 w-8" />}
                title={t('pages.basic.routesEmpty')}
                description={t('pages.basic.routesEmptyDescription')}
                action={
                  canWrite ? (
                    <Button
                      variant="primary"
                      icon={<Plus weight="bold" className="h-4 w-4" />}
                      onClick={onCreateRoute}
                    >
                      {t('pages.basic.addRoute')}
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <Table
                columns={routeColumns}
                data={routes}
                rowKey={(r) => r.id}
                dense
                onRowClick={canWrite ? (r) => onEditRoute(r) : undefined}
              />
            )}
          </CardBody>
        </Card>
      )}

      {pendingDeleteRoute && (
        <ConfirmDialog
          open
          onClose={() => setPendingDeleteRoute(null)}
          onConfirm={() => deleteRoute.mutate(pendingDeleteRoute.id)}
          title={t('pages.basic.deleteRouteTitle')}
          description={t('pages.basic.deleteRouteDescription')}
          confirmLabel={t('common.delete')}
          loading={deleteRoute.isPending}
        >
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDeleteRoute.name}</p>
            <p className="pw-mono mt-0.5 text-xs text-fg-subtle">{pendingDeleteRoute.path}</p>
          </div>
        </ConfirmDialog>
      )}
    </>
  )
}
