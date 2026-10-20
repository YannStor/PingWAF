import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import {
  Globe,
  Lock,
  Network,
  Plus,
  PencilSimple,
  Trash,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { sitesApi, siteKeys } from '@/api/sites'
import { errorMessage } from '@/api/errors'
import { useCanWrite } from '@/hooks'
import { formatDateTime } from '@/lib/format'
import type { Upstream, UpstreamPool } from '@/api/types'
import { NodeDialog, type NodeDialogRequest } from './NodeDialog'
import { LB_OPTION_KEYS, splitLbAlgorithm } from './types'

/**
 * Origin pool cards (one per pool, two per row on xl screens) with their
 * node tables, plus the node dialog and pool/node delete confirmations.
 */
export function OriginPoolsSection({
  siteId,
  siteOriginVerifyCert,
  poolsQuery,
  upstreamsQuery,
  onEditPool,
  onCreatePool,
}: {
  siteId: string
  /** The site's own origin certificate check; `null` follows the global default. */
  siteOriginVerifyCert: boolean | null
  poolsQuery: UseQueryResult<UpstreamPool[], Error>
  upstreamsQuery: UseQueryResult<Upstream[], Error>
  onEditPool: (pool: UpstreamPool) => void
  onCreatePool: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const pools = useMemo(
    () =>
      [...(poolsQuery.data ?? [])].sort((a, b) => {
        if (a.is_default !== b.is_default) return a.is_default ? -1 : 1
        return a.created_at.localeCompare(b.created_at)
      }),
    [poolsQuery.data],
  )
  const nodesByPool = useMemo(() => {
    const map = new Map<string, Upstream[]>()
    for (const node of upstreamsQuery.data ?? []) {
      const list = map.get(node.pool_id) ?? []
      list.push(node)
      map.set(node.pool_id, list)
    }
    return map
  }, [upstreamsQuery.data])

  const [nodeRequest, setNodeRequest] = useState<NodeDialogRequest | null>(null)
  const [pendingDeletePool, setPendingDeletePool] = useState<UpstreamPool | null>(null)
  const [pendingDeleteNode, setPendingDeleteNode] = useState<Upstream | null>(null)

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: siteKeys.all })
  }

  const deletePool = useMutation({
    mutationFn: (id: string) => sitesApi.deletePool(siteId, id),
    onSuccess: (_d, id) => {
      const pool = (poolsQuery.data ?? []).find((p) => p.id === id)
      toast.success(t('pages.basic.poolDeleted'), pool?.name)
      setPendingDeletePool(null)
      invalidate()
    },
    onError: (e) => {
      toast.error(t('pages.basic.poolDeleteFailed'), errorMessage(e))
    },
  })

  const deleteNode = useMutation({
    mutationFn: (id: string) => sitesApi.deleteUpstream(siteId, id),
    onSuccess: () => {
      toast.success(t('pages.basic.nodeDeleted'))
      setPendingDeleteNode(null)
      invalidate()
    },
    onError: (e) => toast.error(t('pages.basic.nodeDeleteFailed'), errorMessage(e)),
  })

  const lbLabel = (algo: string) => {
    const { lbType, hashKey } = splitLbAlgorithm(algo)
    const option = LB_OPTION_KEYS.find((o) => o.value === lbType)
    const base = option ? t(option.labelKey) : algo
    return hashKey ? `${base} · ${hashKey}` : base
  }

  /* ── Node table (per pool) ─────────────────────────────────────── */

  const nodeColumns: Column<Upstream>[] = [
    {
      key: 'address',
      header: t('pages.basic.nodeAddress'),
      accessor: (n) => n.address,
      sortable: true,
      cell: (n) => (
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded bg-brand-soft text-brand">
            <Globe weight="duotone" className="h-3.5 w-3.5" />
          </span>
          <span className="pw-mono text-[13px] font-medium text-fg-strong">{n.address}</span>
        </div>
      ),
    },
    {
      key: 'weight',
      header: t('pages.basic.nodeWeight'),
      align: 'right',
      sortable: true,
      accessor: (n) => n.weight,
      cell: (n) => <span className="tabular-nums text-[13px] text-fg-subtle">{n.weight}</span>,
    },
    {
      key: 'created_at',
      header: t('pages.basic.added'),
      accessor: (n) => n.created_at,
      sortable: true,
      cell: (n) => (
        <span className="text-[13px] text-fg-subtle">{formatDateTime(n.created_at)}</span>
      ),
    },
    {
      key: 'row-actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (n) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('common.edit')}
            disabled={!canWrite}
            onClick={() => setNodeRequest({ mode: 'edit', node: n })}
            icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            onClick={() => setPendingDeleteNode(n)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  const loading = poolsQuery.isPending || upstreamsQuery.isPending

  return (
    <>
      {/* Site-wide origin TLS default — the middle tier of the cascade.
          Rendered at the top so the effective policy is visible without
          opening any pool dialog. */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line bg-bg-subtle/60 px-4 py-2.5 text-[13px]">
        <span className="flex items-center gap-1.5 text-fg-subtle">
          <Lock weight="duotone" className="h-3.5 w-3.5" />
          {t('pages.basic.originTlsSummary')}
          <span
            className={
              'font-medium ' +
              (siteOriginVerifyCert === null
                ? 'text-fg'
                : siteOriginVerifyCert
                  ? 'text-success'
                  : 'text-warning')
            }
          >
            {siteOriginVerifyCert === null
              ? t('pages.basic.certFollowGlobal')
              : siteOriginVerifyCert
                ? t('pages.basic.certVerified')
                : t('pages.basic.certNotVerified')}
          </span>
        </span>
        <Link
          to={`/sites/${siteId}/ssl`}
          className="text-fg-subtle transition-colors hover:text-fg"
        >
          {t('pages.basic.originTlsSettingsLink')}
        </Link>
      </div>
      {poolsQuery.isError && !poolsQuery.data ? (
        <ErrorState
          error={poolsQuery.error}
          onRetry={() => poolsQuery.refetch()}
          retrying={poolsQuery.isFetching}
        />
      ) : loading ? (
        <Card>
          <CardBody className="p-0">
            <SkeletonRows rows={5} columns={4} />
          </CardBody>
        </Card>
      ) : pools.length === 0 ? (
        <Card>
          <CardBody className="p-0">
            <EmptyState
              className="border-0 py-12"
              icon={<Network weight="duotone" className="h-8 w-8" />}
              title={t('pages.basic.poolsEmptyTitle')}
              description={t('pages.basic.poolsEmptyDescription')}
              action={
                canWrite ? (
                  <Button
                    variant="primary"
                    icon={<Plus weight="bold" className="h-4 w-4" />}
                    onClick={onCreatePool}
                  >
                    {t('pages.basic.addPool')}
                  </Button>
                ) : undefined
              }
            />
          </CardBody>
        </Card>
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {pools.map((pool) => {
            // Prefer the separately fetched upstreams; fall back to the list
            // endpoint's inlined `pool.upstreams` when that query has no data.
            const nodes = nodesByPool.get(pool.id) ?? pool.upstreams ?? []
            return (
              <Card key={pool.id}>
                <CardHeader
                  title={
                    <span className="flex items-center gap-2">
                      <span className="truncate">{pool.name}</span>
                      {pool.is_default && (
                        <Badge tone="brand" size="sm">
                          {t('pages.basic.defaultBadge')}
                        </Badge>
                      )}
                    </span>
                  }
                  description={
                    <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
                      <span className="flex items-center gap-1">
                        <Network weight="duotone" className="h-3.5 w-3.5" />
                        {lbLabel(pool.lb_algorithm)}
                      </span>
                      <span className="flex items-center gap-1">
                        <Globe weight="duotone" className="h-3.5 w-3.5" />
                        {nodes.length} {t('pages.origin.poolNodes')}
                      </span>
                      {pool.sni ? (
                        <span className="flex items-center gap-1">
                          <Lock weight="duotone" className="h-3.5 w-3.5" />
                          <span className="pw-mono">{pool.sni}</span>
                          <span className="text-fg-subtle/70">
                            {(pool.verify_cert ?? siteOriginVerifyCert) ===
                            null
                              ? t('pages.basic.certFollowGlobal')
                              : (pool.verify_cert ?? siteOriginVerifyCert)
                                ? t('pages.basic.certVerified')
                                : t('pages.basic.certNotVerified')}
                          </span>
                        </span>
                      ) : (
                        <span className="flex items-center gap-1">
                          <Globe weight="duotone" className="h-3.5 w-3.5" />
                          {t('pages.basic.httpOrigin')}
                        </span>
                      )}
                    </span>
                  }
                  action={
                    <div className="flex items-center gap-1">
                      {canWrite && (
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label={t('common.edit')}
                          onClick={() => onEditPool(pool)}
                          icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
                        />
                      )}
                      {canWrite && !pool.is_default && (
                        <Button
                          size="icon"
                          variant="ghost"
                          className="hover:text-fg-danger"
                          aria-label={t('common.delete')}
                          onClick={() => setPendingDeletePool(pool)}
                          icon={<Trash weight="duotone" className="h-4 w-4" />}
                        />
                      )}
                    </div>
                  }
                />
                <CardBody className="p-0">
                  {nodes.length === 0 ? (
                    <EmptyState
                      className="border-0 py-8"
                      icon={<Globe weight="duotone" className="h-6 w-6" />}
                      title={t('pages.origin.poolEmpty')}
                      description={t('pages.basic.nodesEmptyDescription')}
                      action={
                        canWrite ? (
                          <Button
                            size="sm"
                            variant="secondary"
                            icon={<Plus weight="bold" className="h-3.5 w-3.5" />}
                            onClick={() => setNodeRequest({ mode: 'create', poolId: pool.id })}
                          >
                            {t('pages.basic.addNode')}
                          </Button>
                        ) : undefined
                      }
                    />
                  ) : (
                    <>
                      <Table
                        columns={nodeColumns}
                        data={nodes}
                        rowKey={(n) => n.id}
                        dense
                        onRowClick={
                          canWrite
                            ? (n) => setNodeRequest({ mode: 'edit', node: n })
                            : undefined
                        }
                      />
                      {canWrite && (
                        <div className="border-t border-line px-5 py-2">
                          <Button
                            size="sm"
                            variant="ghost"
                            icon={<Plus weight="bold" className="h-3.5 w-3.5" />}
                            onClick={() => setNodeRequest({ mode: 'create', poolId: pool.id })}
                          >
                            {t('pages.basic.addNode')}
                          </Button>
                        </div>
                      )}
                    </>
                  )}
                </CardBody>
              </Card>
            )
          })}
        </div>
      )}

      {nodeRequest && (
        <NodeDialog
          siteId={siteId}
          request={nodeRequest}
          pools={pools}
          onClose={() => setNodeRequest(null)}
        />
      )}

      {pendingDeletePool && (
        <ConfirmDialog
          open
          onClose={() => setPendingDeletePool(null)}
          onConfirm={() => deletePool.mutate(pendingDeletePool.id)}
          title={t('pages.basic.deletePoolTitle')}
          description={t('pages.basic.deletePoolDescription')}
          confirmLabel={t('common.delete')}
          loading={deletePool.isPending}
        >
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDeletePool.name}</p>
            <p className="mt-0.5 text-xs text-fg-subtle">
              {(nodesByPool.get(pendingDeletePool.id) ?? []).length}{' '}
              {t('pages.basic.nodesCount')}
            </p>
          </div>
        </ConfirmDialog>
      )}

      {pendingDeleteNode && (
        <ConfirmDialog
          open
          onClose={() => setPendingDeleteNode(null)}
          onConfirm={() => deleteNode.mutate(pendingDeleteNode.id)}
          title={t('pages.basic.deleteNodeTitle')}
          description={t('pages.basic.deleteNodeDescription')}
          confirmLabel={t('common.delete')}
          loading={deleteNode.isPending}
        >
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono text-[13px] font-medium text-fg-strong">
              {pendingDeleteNode.address}
            </p>
          </div>
        </ConfirmDialog>
      )}
    </>
  )
}
