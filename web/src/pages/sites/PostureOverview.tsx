import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { Pulse } from '@phosphor-icons/react'
import { Card, CardBody } from '@/components/ui/Card'
import { Badge, type BadgeTone } from '@/components/ui/Badge'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { ErrorState } from '@/components/ErrorState'
import { wafSettingsApi, wafSettingsKeys } from '@/api/wafSettings'

/** Where a posture badge can send the user. */
export type PostureTarget = 'managed' | 'custom' | 'cc' | 'bot'

const CATEGORY_TONE: Record<string, BadgeTone> = {
  block: 'danger',
  monitor: 'warning',
  off: 'neutral',
}

function PostureBadge({
  label,
  value,
  tone,
  onClick,
}: {
  label: string
  value: string
  tone: BadgeTone
  onClick?: () => void
}) {
  const badge = (
    <Badge tone={tone} dot className={onClick ? 'cursor-pointer' : undefined}>
      {label}&nbsp;{value}
    </Badge>
  )
  if (!onClick) return badge
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-full outline-none focus-visible:ring-2 focus-visible:ring-brand"
      title={label}
    >
      {badge}
    </button>
  )
}

/**
 * The site's effective WAF posture: what the data plane actually enforces
 * right now, aggregated by the server from rules, settings and global
 * switches. Polled every minute; waf-settings mutations invalidate the query.
 */
export function PostureOverview({
  siteId,
  onNavigate,
}: {
  siteId: string
  onNavigate: (target: PostureTarget) => void
}) {
  const { t } = useTranslation()

  const query = useQuery({
    queryKey: wafSettingsKeys.posture(siteId),
    queryFn: () => wafSettingsApi.posture(siteId),
    enabled: Boolean(siteId),
    refetchInterval: 60_000,
  })

  if (query.isPending) return <SkeletonCard className="h-24" />
  if (query.isError || !query.data) {
    return <ErrorState error={query.error} onRetry={() => void query.refetch()} />
  }

  const { engine, detection, enforcement } = query.data
  const on = t('pages.protection.postureOn')
  const off = t('pages.protection.postureOff')
  const actionLabel = (action: string) =>
    action === 'off' ? off : t(`actions.${action}`, action)

  return (
    <Card>
      <CardBody className="flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <Pulse weight="duotone" className="h-4 w-4 text-fg-subtle" />
          <h2 className="text-sm font-semibold text-fg-strong">
            {t('pages.protection.postureTitle')}
          </h2>
          <span className="text-xs text-fg-subtle">
            {t('pages.protection.postureHint')}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {/* The site-level mode is the outermost gate: per-category badges
              below show what each rule pack would do, but nothing enforces
              unless this is monitor/block. Always render it first. */}
          <PostureBadge
            label={t('pages.protection.postureMode')}
            value={t(`pages.waf.mode_${enforcement.mode}`, enforcement.mode)}
            tone={
              enforcement.mode === 'block'
                ? 'success'
                : enforcement.mode === 'monitor'
                  ? 'warning'
                  : 'neutral'
            }
          />
          <PostureBadge
            label={t('pages.protection.postureWaf')}
            value={engine === 'on' ? on : off}
            tone={engine === 'on' ? 'success' : 'neutral'}
          />
          <PostureBadge
            label={t('pages.protection.deepInspection')}
            value={detection.deep_inspection ? on : off}
            tone={detection.deep_inspection ? 'info' : 'neutral'}
          />
          <PostureBadge
            label={t('pages.protection.underAttackTitle')}
            value={detection.under_attack ? on : off}
            tone={detection.under_attack ? 'danger' : 'neutral'}
          />
          {enforcement.observation_mode && (
            <PostureBadge
              label={t('pages.protection.postureObservation')}
              value={on}
              tone="warning"
            />
          )}
          {/* Observation mode means every category detects but nothing is
              enforced — the "enabled" badges above can mislead without this. */}
          {enforcement.observation_mode && (
            <p className="text-xs text-fg-warning">
              {t('pages.protection.observationModeHint')}
            </p>
          )}
          {Object.entries(enforcement.managed).map(([category, action]) => (
            <PostureBadge
              key={category}
              label={t(`pages.waf.${category}`, category)}
              value={actionLabel(action)}
              tone={CATEGORY_TONE[action] ?? 'neutral'}
              onClick={() => onNavigate('managed')}
            />
          ))}
          <PostureBadge
            label={t('pages.protection.tabCustom')}
            value={actionLabel(enforcement.custom_rules)}
            tone={CATEGORY_TONE[enforcement.custom_rules] ?? 'neutral'}
            onClick={() => onNavigate('custom')}
          />
          <PostureBadge
            label={t('pages.protection.tabCc')}
            value={actionLabel(enforcement.cc)}
            tone={CATEGORY_TONE[enforcement.cc] ?? 'neutral'}
            onClick={() => onNavigate('cc')}
          />
          <PostureBadge
            label={t('pages.protection.postureBot')}
            value={actionLabel(enforcement.bot)}
            tone={
              enforcement.bot === 'off'
                ? 'neutral'
                : CATEGORY_TONE[enforcement.bot] ?? 'warning'
            }
            onClick={() => onNavigate('bot')}
          />
        </div>
      </CardBody>
    </Card>
  )
}