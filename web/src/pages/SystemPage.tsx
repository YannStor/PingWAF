import { ArrowClockwise } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { PageHeader } from '@/components/PageHeader'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { MetricCards, MetricPills } from '@/components/system/MetricCards'
import { ModuleTable } from '@/components/system/ModuleTable'
import { MethodTable } from '@/components/system/MethodTable'
import { NodeSection } from '@/components/system/NodeSection'
import { fetchSystemMetrics, fetchSystemNodes, fetchSystemProfile, debugKeys } from '@/api/debug'
import { formatDateTime } from '@/lib/format'

/** metrics 轮询周期（10s），staleTime 取一半。 */
const METRICS_INTERVAL_MS = 10_000
/** profile 轮询周期（60s），staleTime 取一半。 */
const PROFILE_INTERVAL_MS = 60_000
/** nodes 轮询周期（15s），staleTime 取一半。 */
const NODES_INTERVAL_MS = 15_000

/**
 * System 观测页 — `/api/v1/system/metrics` + `/api/v1/system/profile`（仅 Admin）。
 * metrics 10s 轮询、profile 60s 轮询；错误以行内重试呈现，不整页报错。
 */
export function SystemPage() {
  const { t } = useTranslation()

  const metrics = useQuery({
    queryKey: debugKeys.metrics(),
    queryFn: fetchSystemMetrics,
    refetchInterval: METRICS_INTERVAL_MS,
    staleTime: METRICS_INTERVAL_MS / 2,
    retry: false,
  })
  const profile = useQuery({
    queryKey: debugKeys.profile(),
    queryFn: fetchSystemProfile,
    refetchInterval: PROFILE_INTERVAL_MS,
    staleTime: PROFILE_INTERVAL_MS / 2,
    retry: false,
  })

  const nodes = useQuery({
    queryKey: debugKeys.nodes(),
    queryFn: fetchSystemNodes,
    refetchInterval: NODES_INTERVAL_MS,
    staleTime: NODES_INTERVAL_MS / 2,
    retry: false,
  })

  const collectedAt = metrics.data?.cpu.collected_at_ms ?? metrics.data?.memory.collected_at_ms

  return (
    <div>
      <PageHeader
        title={t('system.title')}
        description={t('system.subtitle')}
        actions={
          <>
            {collectedAt != null && (
              <span className="hidden text-xs text-fg-subtle tabular-nums sm:inline">
                {t('system.collectedAt', { time: formatDateTime(collectedAt) })}
              </span>
            )}
            <Button
              variant="secondary"
              size="sm"
              icon={
                <ArrowClockwise
                  weight="duotone"
                  className={`h-4 w-4 ${metrics.isFetching || profile.isFetching || nodes.isFetching ? 'animate-spin-slow' : ''}`}
                />
              }
              onClick={() => {
                void metrics.refetch()
                void profile.refetch()
                void nodes.refetch()
              }}
            >
              {t('system.refresh')}
            </Button>
          </>
        }
      />

      {metrics.isError ? (
        <div className="mb-4">
          <ErrorState
            variant="inline"
            error={metrics.error}
            onRetry={() => void metrics.refetch()}
            retrying={metrics.isFetching}
          />
        </div>
      ) : (
        <>
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-fg-subtle">
            {t('system.overview')}
          </p>
          <MetricCards metrics={metrics.data} loading={metrics.isFetching} />
          <div className="mt-3">
            <MetricPills metrics={metrics.data} />
          </div>
        </>
      )}

      <NodeSection
        nodes={
          nodes.data
            ? { control: nodes.data.control, boots: nodes.data.boots }
            : undefined
        }
        error={nodes.isError ? nodes.error : null}
        loading={nodes.isFetching}
        onRetry={() => void nodes.refetch()}
      />

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader
            title={t('system.modules')}
            description={t(
              'system.samplingHint',
              '内存列为当前持有值（0 表示尚未上报，—/peak 为峰值口径）；各占比为占所属模块/全部归因时间的比例，子阶段份额不应相加。',
            )}
          />
          <CardBody>
            {profile.isError ? (
              <ErrorState
                variant="inline"
                error={profile.error}
                onRetry={() => void profile.refetch()}
                retrying={profile.isFetching}
              />
            ) : (
              <ModuleTable modules={profile.data?.modules} loading={profile.isLoading} />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title={t('system.topMethods')} />
          <CardBody>
            {profile.isError ? (
              <ErrorState
                variant="inline"
                error={profile.error}
                onRetry={() => void profile.refetch()}
                retrying={profile.isFetching}
              />
            ) : (
              <MethodTable methods={profile.data?.methods} loading={profile.isLoading} />
            )}
          </CardBody>
        </Card>
      </div>

      {!metrics.isLoading && !metrics.data && !metrics.isError && (
        <div className="mt-4">
          <EmptyState title={t('system.empty')} description={t('system.loadError')} />
        </div>
      )}
    </div>
  )
}

export default SystemPage
