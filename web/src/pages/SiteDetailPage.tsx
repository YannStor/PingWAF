import { useEffect, useState } from 'react'
import { NavLink, Outlet, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Globe,
  Shield,
  Lightning,
  Lock,
  ChartLine,
  Sliders,
  Gauge,
  CaretLeft,
  Pause,
  Play,
  Robot,
  IdentificationCard,
  Network,
  Warning,
  ArrowSquareOut,
} from '@phosphor-icons/react'
import { Link } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Skeleton } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { AgentStatusBanner } from '@/components/AgentStatusBanner'
import { sitesApi, siteKeys } from '@/api/sites'
import { wafSettingsApi, wafSettingsKeys } from '@/api/wafSettings'
import { useCanWrite, useSiteDetail } from '@/hooks'
import { useSiteStore } from '@/stores/siteStore'
import type { SiteStatus } from '@/api/types'

const STATUS_TONE: Record<SiteStatus, 'success' | 'warning' | 'neutral'> = {
  active: 'success',
  paused: 'warning',
  pending: 'neutral',
}

export function SiteDetailPage() {
  const { t } = useTranslation()
  const { siteId } = useParams<{ siteId: string }>()
  const setCurrentSiteId = useSiteStore((s) => s.setCurrentSiteId)
  const canWrite = useCanWrite()
  const toast = useToast()
  const queryClient = useQueryClient()
  const [confirmToggle, setConfirmToggle] = useState(false)

  useEffect(() => {
    if (siteId) setCurrentSiteId(siteId)
  }, [siteId, setCurrentSiteId])

  const detail = useSiteDetail(siteId)
  const site = detail.data?.site
  // The per-site detail bundles the SSL state: with a certificate the site is
  // safely reachable over HTTPS, otherwise fall back to plain HTTP.
  const hasCertificate = Boolean(detail.data?.ssl?.has_certificate)
  const visitTitle = hasCertificate
    ? t('pages.siteDetail.visitSite')
    : t('pages.siteDetail.visitSiteHttpHint')

  const toggleStatus = useMutation({
    mutationFn: (status: SiteStatus) => sitesApi.update(siteId as string, { status }),
    onSuccess: (updated) => {
      toast.success(
        updated.status === 'active' ? t('pages.sites.activated') : t('pages.sites.deactivated'),
        updated.domain,
      )
      setConfirmToggle(false)
      void queryClient.invalidateQueries({ queryKey: siteKeys.all })
    },
  })

  const paused = site?.status === 'paused'

  // Z6: persistent observation-mode banner — reuse the posture query the
  // protection pages use (same key), so any waf-settings mutation refreshes it.
  const postureQuery = useQuery({
    queryKey: wafSettingsKeys.posture(siteId ?? ''),
    queryFn: () => wafSettingsApi.posture(siteId as string),
    enabled: Boolean(siteId),
    staleTime: 30_000,
  })
  const wafMode = postureQuery.data?.enforcement.mode
  const observationMode = wafMode === 'off' || wafMode === 'monitor'

  const base = `/sites/${siteId}`
  const tabs = [
    { to: `${base}/basic`, label: t('nav.basic'), icon: Network },
    {
      to: `${base}/security/protection`,
      label: t('nav.securityProtection'),
      icon: Shield,
    },
    {
      to: `${base}/security/rate-limiting`,
      label: t('nav.securityRateLimiting'),
      icon: Gauge,
    },
    { to: `${base}/security/bot`, label: t('nav.securityBot'), icon: Robot },
    {
      to: `${base}/security/access`,
      label: t('nav.securityAccess'),
      icon: IdentificationCard,
    },
    { to: `${base}/caching`, label: t('nav.caching'), icon: Lightning },
    { to: `${base}/ssl`, label: t('nav.ssl'), icon: Lock },
    { to: `${base}/traffic`, label: t('nav.traffic'), icon: ChartLine },
    { to: `${base}/rules/rewrite`, label: t('pages.rewrite.title'), icon: Sliders },
  ]

  // The server answers 404 for sites the caller may not see — surface that
  // instead of rendering an empty shell around a broken id.
  if (detail.isError && !detail.data) {
    return (
      <div className="animate-slide-up">
        <ErrorState
          error={detail.error}
          onRetry={() => detail.refetch()}
          retrying={detail.isFetching}
          action={
            <Link to="/sites">
              <span className="inline-flex items-center gap-1.5 text-[13px] font-medium text-link">
                <CaretLeft weight="bold" className="h-3.5 w-3.5" />
                {t('pages.sites.title')}
              </span>
            </Link>
          }
        />
      </div>
    )
  }

  return (
    <div className="animate-slide-up">
      {/* Site header */}
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg bg-brand-soft text-brand">
            <Globe weight="duotone" className="h-6 w-6" />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              {site ? (
                <h1 className="pw-mono truncate text-lg font-semibold tracking-tight text-fg-strong">
                  {site.domain}
                </h1>
              ) : (
                <Skeleton className="h-6 w-56 rounded-md" />
              )}
              {site && (
                <Badge tone={STATUS_TONE[site.status as SiteStatus] ?? 'neutral'} dot>
                  {t(`status.${site.status}`, site.status)}
                </Badge>
              )}
              {site && (
                <a
                  href={`${hasCertificate ? 'https' : 'http'}://${site.domain}`}
                  target="_blank"
                  rel="noreferrer"
                  title={visitTitle}
                  className="inline-flex items-center gap-1 rounded-md border border-line px-1.5 py-0.5 text-[11px] text-fg-subtle transition-colors hover:border-focus hover:text-link"
                >
                  <ArrowSquareOut weight="duotone" className="h-3.5 w-3.5" />
                  {t('pages.siteDetail.visitSite')}
                </a>
              )}
            </div>
            <p className="truncate text-[13px] text-fg-subtle">
              {site ? (
                <>
                  {site.name}
                  <span className="mx-1.5 text-fg-subtle/50">·</span>
                  <span className="capitalize">{t(`plans.${site.plan}`, site.plan)}</span>
                </>
              ) : (
                t('pages.siteDetail.overview')
              )}
            </p>
            {site && (site.alternate_domains?.length ?? 0) > 0 && (
              <p
                className="pw-mono truncate text-xs text-fg-subtle"
                title={site.alternate_domains?.join(', ')}
              >
                + {site.alternate_domains?.join(', ')}
              </p>
            )}
          </div>
        </div>

        {/* Live counters straight from SiteDetail */}
        <div className="flex shrink-0 items-center gap-4">
          {detail.data && (
            <div className="flex items-center gap-4 text-[13px]">
              <Counter
                label={t('nav.securityWaf')}
                value={detail.data.rule_count}
              />
              <Counter
                label={t('nav.securityRateLimiting')}
                value={detail.data.rate_limit_count}
              />
              <Counter label={t('nav.ssl')} value={detail.data.ssl ? 1 : 0} />
              <Counter
                label={t('pages.siteDetail.upstreams')}
                value={detail.data.upstreams.length}
              />
            </div>
          )}
          {site && canWrite && (
            <Button
              variant={paused ? 'primary' : 'secondary'}
              size="sm"
              loading={toggleStatus.isPending}
              icon={
                paused ? (
                  <Play weight="duotone" className="h-4 w-4" />
                ) : (
                  <Pause weight="duotone" className="h-4 w-4" />
                )
              }
              onClick={() => setConfirmToggle(true)}
            >
              {paused ? t('pages.sites.activate') : t('pages.sites.deactivate')}
            </Button>
          )}
        </div>
      </div>

      {/* The edge answers a paused site with a maintenance page, so say so. */}
      {paused && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-[13px] text-fg">
          <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg" />
          <p>{t('pages.siteDetail.pausedNote')}</p>
        </div>
      )}

      {/* Z6: WAF enforcement is off/monitor — attacks are logged, not blocked. */}
      {!paused && observationMode && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-[13px] text-fg">
          <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg" />
          <p>{t('common.siteBanners.observationMode')}</p>
        </div>
      )}

      {/* Z5: offline/degraded agents mean config changes may lag. */}
      <AgentStatusBanner siteId={siteId} />

      {/* Tab nav */}
      <div className="mb-6 flex gap-1 overflow-x-auto border-b border-line">
        {tabs.map((tab) => {
          const Icon = tab.icon
          return (
            <NavLink
              key={tab.to}
              to={tab.to}
              className={({ isActive }) =>
                cn(
                  '-mb-px inline-flex shrink-0 items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2.5 text-sm font-medium transition-colors',
                  isActive
                    ? 'border-brand text-fg-strong'
                    : 'border-transparent text-fg-subtle hover:text-fg',
                )
              }
            >
              <Icon weight="duotone" className="h-4 w-4" />
              {tab.label}
            </NavLink>
          )
        })}
      </div>

      <Outlet />

      <ConfirmDialog
        open={confirmToggle}
        onClose={() => setConfirmToggle(false)}
        onConfirm={() => toggleStatus.mutate(paused ? 'active' : 'paused')}
        title={paused ? t('pages.sites.resumeTitle') : t('pages.sites.pauseTitle')}
        description={
          paused ? t('pages.sites.resumeDescription') : t('pages.sites.pauseDescription')
        }
        confirmLabel={paused ? t('pages.sites.activate') : t('pages.sites.deactivate')}
        tone={paused ? 'primary' : 'danger'}
        loading={toggleStatus.isPending}
      >
        {site && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono text-[13px] font-medium text-fg-strong">{site.domain}</p>
          </div>
        )}
      </ConfirmDialog>
    </div>
  )
}

function Counter({ label, value }: { label: string; value: number }) {
  return (
    <div className="text-center">
      <p className="tabular-nums text-base font-semibold leading-tight text-fg-strong">
        {value}
      </p>
      <p className="text-[11px] leading-tight text-fg-subtle">{label}</p>
    </div>
  )
}
