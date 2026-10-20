import { useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { ArrowClockwise, Plus } from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Button } from '@/components/ui/Button'
import { sitesApi, siteKeys } from '@/api/sites'
import { ipGroupsApi, ipGroupKeys } from '@/api/ipGroups'
import { useCanWrite } from '@/hooks'
import type { IpGroupResponse } from '@/api/types'
import { FailoverPanel } from '../FailoverPanel'
import { ProxyTrustCard } from './ProxyTrustCard'
import { ResponseReplaceCard } from './ResponseReplaceCard'
import { OriginPoolsSection } from './OriginPoolsSection'
import { RoutesSection } from './RoutesSection'
import { PoolDialog, type PoolDialogRequest } from './PoolDialog'
import { RouteDialog, type RouteDialogRequest } from './RouteDialog'

/**
 * Site basics: trusted-proxy ingress, origin pools with their nodes, and
 * route dispatch. Data lives here; the section components own their own
 * mutations and dialogs.
 */
export function BasicPage() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const poolsQuery = useQuery({
    queryKey: siteKeys.pools(siteId),
    queryFn: () => sitesApi.listPools(siteId),
    enabled: Boolean(siteId),
  })
  const upstreamsQuery = useQuery({
    queryKey: siteKeys.upstreams(siteId),
    queryFn: () => sitesApi.listUpstreams(siteId),
    enabled: Boolean(siteId),
  })
  const routesQuery = useQuery({
    queryKey: siteKeys.routes(siteId),
    queryFn: () => sitesApi.listRoutes(siteId),
    enabled: Boolean(siteId),
  })
  const ipGroupsQuery = useQuery({
    queryKey: ipGroupKeys.list({ page_size: 100 }),
    queryFn: () => ipGroupsApi.list({ page_size: 100 }),
  })
  const siteQuery = useQuery({
    queryKey: siteKeys.detail(siteId),
    queryFn: () => sitesApi.get(siteId),
    enabled: Boolean(siteId),
  })

  const pools = useMemo(
    () =>
      [...(poolsQuery.data ?? [])].sort((a, b) => {
        if (a.is_default !== b.is_default) return a.is_default ? -1 : 1
        return a.created_at.localeCompare(b.created_at)
      }),
    [poolsQuery.data],
  )
  const poolById = useMemo(() => new Map(pools.map((p) => [p.id, p])), [pools])
  const defaultPool = pools.find((p) => p.is_default)

  const ipGroups: IpGroupResponse[] = useMemo(
    () => ipGroupsQuery.data?.items ?? [],
    [ipGroupsQuery.data],
  )
  const ipGroupById = useMemo(() => new Map(ipGroups.map((g) => [g.id, g])), [ipGroups])
  const gateableGroups = useMemo(
    () => ipGroups.filter((g) => g.enabled && g.ip_ranges.length > 0),
    [ipGroups],
  )

  const [poolRequest, setPoolRequest] = useState<PoolDialogRequest | null>(null)
  const [routeRequest, setRouteRequest] = useState<RouteDialogRequest | null>(null)

  const refresh = () => {
    void poolsQuery.refetch()
    void upstreamsQuery.refetch()
    void routesQuery.refetch()
  }

  const openCreateRoute = () => {
    setRouteRequest({ mode: 'create', poolId: defaultPool?.id ?? pools[0]?.id ?? '' })
  }

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.basic.title')}
        description={t('pages.basic.description')}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              loading={poolsQuery.isFetching || routesQuery.isFetching}
              onClick={refresh}
              icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
            >
              {t('common.refresh')}
            </Button>
            {canWrite && (
              <Button
                variant="secondary"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={() => setPoolRequest({ mode: 'create' })}
              >
                {t('pages.basic.addPool')}
              </Button>
            )}
            {canWrite && (
              <Button
                variant="primary"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={openCreateRoute}
              >
                {t('pages.basic.addRoute')}
              </Button>
            )}
          </div>
        }
      />

      {siteQuery.data && (
        <section className="mt-6">
          <h2 className="text-sm font-semibold text-fg-strong">
            {t('pages.basic.sections.trust')}
          </h2>
          <div className="mt-3">
            <ProxyTrustCard
              site={siteQuery.data.site}
              ipGroups={gateableGroups}
            />
          </div>
        </section>
      )}

      {/* Disconnected (failover) policy */}
      <FailoverPanel />

      {siteQuery.data && (
        <section className="mt-8">
          <ResponseReplaceCard site={siteQuery.data.site} />
        </section>
      )}

      <section className="mt-8">
        <h2 className="text-sm font-semibold text-fg-strong">
          {t('pages.basic.sections.pools')}
        </h2>
        <div className="mt-3">
          <OriginPoolsSection
            siteId={siteId}
            siteOriginVerifyCert={siteQuery.data?.site.origin_verify_cert ?? null}
            poolsQuery={poolsQuery}
            upstreamsQuery={upstreamsQuery}
            onEditPool={(pool) => setPoolRequest({ mode: 'edit', pool })}
            onCreatePool={() => setPoolRequest({ mode: 'create' })}
          />
        </div>
      </section>

      <section className="mt-8">
        <h2 className="text-sm font-semibold text-fg-strong">
          {t('pages.basic.sections.routes')}
        </h2>
        <p className="mt-0.5 text-[13px] text-fg-subtle">{t('pages.basic.routesDescription')}</p>
        <div className="mt-3">
          <RoutesSection
            siteId={siteId}
            routesQuery={routesQuery}
            poolById={poolById}
            ipGroupById={ipGroupById}
            onEditRoute={(route) => setRouteRequest({ mode: 'edit', route })}
            onCreateRoute={openCreateRoute}
          />
        </div>
      </section>

      {poolRequest && (
        <PoolDialog
          siteId={siteId}
          request={poolRequest}
          onClose={() => setPoolRequest(null)}
        />
      )}
      {routeRequest && (
        <RouteDialog
          siteId={siteId}
          request={routeRequest}
          pools={pools}
          gateableGroups={gateableGroups}
          ipGroupById={ipGroupById}
          onClose={() => setRouteRequest(null)}
        />
      )}
    </div>
  )
}
