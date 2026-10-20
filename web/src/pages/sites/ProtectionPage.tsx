import { useEffect, useState } from 'react'
import { Navigate, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Cloud, Gauge, Lightning, ShieldCheck, Sliders, Timer, Warning } from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Tabs } from '@/components/ui/Tabs'
import { Switch } from '@/components/ui/Switch'
import { Card, CardBody } from '@/components/ui/Card'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { Input } from '@/components/ui/Input'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { useToast } from '@/components/ui/Toast'
import { challengeApi, challengeKeys } from '@/api/challenge'
import { wafSettingsApi, wafSettingsKeys } from '@/api/wafSettings'
import { RULE_MODES, type RuleMode, type WafSettings } from '@/api/types'
import { useCanWrite, useWafSettingsMutation } from '@/hooks'
import { cn } from '@/lib/utils'
import { PostureOverview, type PostureTarget } from './PostureOverview'
import { ManagedRulesPanel } from './ManagedRulesPanel'
import { CustomRulesPanel } from './CustomRulesPanel'
import { MitigationPanel } from './MitigationPanel'

type ProtectionTab = 'managed' | 'custom' | 'cc'

/** Body-stage inspection budget bounds — must match the server contract. */
const BODY_STAGE_TIMEOUT_MIN = 1
const BODY_STAGE_TIMEOUT_MAX = 30
const BODY_STAGE_TIMEOUT_DEFAULT = 30

function clampBodyStageTimeout(value: number): number {
  return Math.min(
    Math.max(Math.round(value), BODY_STAGE_TIMEOUT_MIN),
    BODY_STAGE_TIMEOUT_MAX,
  )
}

const PROTECTION_TABS: ProtectionTab[] = ['managed', 'custom', 'cc']

/** Pre-0.22 tab values, still accepted in links and normalized on load. */
const LEGACY_TABS: Record<string, ProtectionTab> = {
  settings: 'managed',
  rules: 'custom',
}

function parseTab(value: string | null): ProtectionTab {
  if (value && LEGACY_TABS[value]) return LEGACY_TABS[value]
  return PROTECTION_TABS.includes(value as ProtectionTab)
    ? (value as ProtectionTab)
    : 'managed'
}

function SectionHeading({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="mb-3">
      <h2 className="text-sm font-semibold text-fg-strong">{title}</h2>
      {hint && <p className="mt-0.5 text-[13px] text-fg-subtle">{hint}</p>}
    </div>
  )
}

/**
 * Web protection for one site, laid out around three concepts: the WAF
 * engine switch, detection grading (under attack / deep inspection), and
 * enforcement (managed categories, custom rules, rate limiting) — fronted by
 * a live posture card aggregating what the data plane actually enforces.
 */
export function ProtectionPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const navigate = useNavigate()
  const { siteId = '' } = useParams<{ siteId: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = parseTab(searchParams.get('tab'))

  const setTab = (next: string) => {
    const params = new URLSearchParams(searchParams)
    params.set('tab', next)
    setSearchParams(params, { replace: true })
  }

  const handlePostureNavigate = (target: PostureTarget) => {
    if (target === 'bot') {
      navigate(`/sites/${siteId}/security/bot`)
    } else {
      setTab(target)
    }
  }

  // Rewrite a legacy `?tab=settings|rules` link in place so the address bar
  // always shows the current vocabulary — every other param (`?rule=`) stays.
  useEffect(() => {
    const raw = searchParams.get('tab')
    if (raw !== 'settings' && raw !== 'rules') return
    const params = new URLSearchParams(searchParams)
    params.set('tab', parseTab(raw))
    setSearchParams(params, { replace: true })
  }, [searchParams, setSearchParams])

  const challengeQuery = useQuery({
    queryKey: challengeKeys.config(siteId),
    queryFn: () => challengeApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const settingsQuery = useQuery({
    queryKey: wafSettingsKeys.settings(siteId),
    queryFn: () => wafSettingsApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const settings = settingsQuery.data
  const updateSettings = useWafSettingsMutation(siteId)
  const engineOn = settings?.waf_enabled ?? true

  const underAttack = challengeQuery.data?.under_attack_mode ?? false

  const setUnderAttack = useMutation({
    mutationFn: (enabled: boolean) =>
      challengeApi.update(siteId, {
        // The challenge gate must be on for the banner to mean anything; the
        // server forces the same pairing.
        under_attack_mode: enabled,
        ...(enabled ? { enabled: true } : {}),
      }),
    onSuccess: (saved) => {
      queryClient.setQueryData(challengeKeys.config(siteId), saved)
      toast.success(
        saved.under_attack_mode
          ? t('pages.protection.underAttackOn')
          : t('pages.protection.underAttackOff'),
      )
      void queryClient.invalidateQueries({ queryKey: challengeKeys.all(siteId) })
    },
    onError: (error) => {
      toast.error(
        t('pages.protection.updateFailed'),
        error instanceof Error ? error.message : undefined,
      )
    },
  })

  const [confirmUnderAttack, setConfirmUnderAttack] = useState(false)

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.protection.title')}
        description={t('pages.protection.description')}
      />

      {/* ── Current effective posture ─────────────────────────────────── */}
      <div className="mb-5">
        <PostureOverview siteId={siteId} onNavigate={handlePostureNavigate} />
      </div>

      {/* ── WAF Engine ────────────────────────────────────────────────── */}
      <section className="mb-5">
        <SectionHeading
          title={t('pages.protection.engineTitle')}
          hint={t('pages.protection.engineHint')}
        />
        {settingsQuery.isPending ? (
          <SkeletonCard className="h-16" />
        ) : (
          <div
            className={`flex flex-wrap items-center justify-between gap-4 rounded-lg border px-4 py-3 ${
              engineOn ? 'border-line bg-elevated' : 'border-warning/45 bg-warning/10'
            }`}
          >
            <span className="flex min-w-0 items-center gap-3">
              <span
                className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${
                  engineOn ? 'bg-brand-soft text-brand' : 'bg-warning/15 text-fg-warning'
                }`}
              >
                <ShieldCheck weight="duotone" className="h-5 w-5" />
              </span>
              <span className="min-w-0">
                <span className="block text-sm font-semibold text-fg-strong">
                  {t('pages.protection.engineTitle')}
                </span>
                <span className="mt-0.5 block text-[13px] text-fg-subtle">
                  {t('pages.protection.engineCardHint')}
                </span>
                {!engineOn && (
                  <span className="mt-1.5 block text-xs text-fg-warning">
                    {t('pages.protection.engineOffWarn')}
                  </span>
                )}
              </span>
            </span>
            <Switch
              size="md"
              checked={engineOn}
              disabled={!canWrite || updateSettings.isPending}
              aria-label={t('pages.protection.engineTitle')}
              onCheckedChange={(waf_enabled) => updateSettings.mutate({ waf_enabled })}
            />
          </div>
        )}
      </section>

      {/* ── Detection ─────────────────────────────────────────────────── */}
      <section className="mb-5">
        <SectionHeading
          title={t('pages.protection.detectionTitle')}
          hint={t('pages.protection.detectionHint')}
        />
        <div className="grid gap-4 lg:grid-cols-2">
        {challengeQuery.isPending ? (
          <SkeletonCard className="h-16" />
        ) : (
          <div
            className={`flex flex-wrap items-center justify-between gap-4 rounded-lg border px-4 py-3 ${
              underAttack
                ? 'border-danger/45 bg-danger/10'
                : 'border-line bg-elevated'
            }`}
          >
            <span className="flex min-w-0 items-center gap-3">
              <span
                className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${
                  underAttack
                    ? 'bg-danger/15 text-fg-danger'
                    : 'bg-recessed text-fg-subtle'
                }`}
              >
                {underAttack ? (
                  <Warning weight="fill" className="h-5 w-5" />
                ) : (
                  <ShieldCheck weight="duotone" className="h-5 w-5" />
                )}
              </span>
              <span className="min-w-0">
                <span className="block text-sm font-semibold text-fg-strong">
                  {underAttack
                    ? t('pages.protection.underAttackActive')
                    : t('pages.protection.underAttackTitle')}
                </span>
                <span className="mt-0.5 block text-[13px] text-fg-subtle">
                  {underAttack
                    ? t('pages.protection.underAttackActiveHint')
                    : t('pages.protection.underAttackHint')}
                </span>
              </span>
            </span>
            {canWrite && (
              <Switch
                size="md"
                checked={underAttack}
                disabled={!canWrite || setUnderAttack.isPending}
                aria-label={t('pages.protection.underAttackTitle')}
                onCheckedChange={(enabled) => {
                  if (enabled) {
                    setConfirmUnderAttack(true)
                  } else {
                    setUnderAttack.mutate(false)
                  }
                }}
              />
            )}
          </div>
        )}
        {settingsQuery.isPending ? (
          <SkeletonCard className="h-16" />
        ) : (
          <div
            className={`flex flex-wrap items-center justify-between gap-4 rounded-lg border px-4 py-3 ${
              settings?.advanced_mode
                ? 'border-danger/45 bg-danger/10'
                : 'border-line bg-elevated'
            }`}
          >
            <span className="flex min-w-0 items-center gap-3">
              <span
                className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${
                  settings?.advanced_mode
                    ? 'bg-danger/15 text-fg-danger'
                    : 'bg-recessed text-fg-subtle'
                }`}
              >
                <Lightning weight="duotone" className="h-5 w-5" />
              </span>
              <span className="min-w-0">
                <span className="block text-sm font-semibold text-fg-strong">
                  {t('pages.protection.deepInspection')}
                </span>
                <span className="mt-0.5 block text-[13px] text-fg-subtle">
                  {t('pages.protection.deepInspectionHint')}
                </span>
                <span className="mt-1.5 flex items-center gap-1.5 text-xs text-fg-warning">
                  <Gauge weight="duotone" className="h-3.5 w-3.5 shrink-0" />
                  {t('pages.protection.performanceHint')}
                </span>
              </span>
            </span>
            <Switch
              size="md"
              checked={settings?.advanced_mode ?? false}
              disabled={!canWrite || updateSettings.isPending}
              aria-label={t('pages.protection.deepInspection')}
              onCheckedChange={(advanced_mode) => updateSettings.mutate({ advanced_mode })}
            />
          </div>
        )}
        {settingsQuery.isPending ? (
          <SkeletonCard className="h-16" />
        ) : (
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-line bg-elevated px-4 py-3">
            <span className="flex min-w-0 items-center gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-recessed text-fg-subtle">
                <Gauge weight="duotone" className="h-5 w-5" />
              </span>
              <span className="min-w-0">
                <span className="block text-sm font-semibold text-fg-strong">
                  {t('pages.protection.paranoiaTitle')}
                </span>
                <span className="mt-0.5 block text-[13px] text-fg-subtle">
                  {t('pages.protection.paranoiaCardHint')}
                </span>
                <span className="mt-2 flex items-center gap-1">
                  {[1, 2, 3, 4].map((level) => {
                    const active = (settings?.paranoia_level ?? 2) === level
                    return (
                      <button
                        key={level}
                        type="button"
                        disabled={!canWrite || updateSettings.isPending}
                        aria-label={`${t('pages.protection.paranoiaTitle')} ${level}`}
                        onClick={() => updateSettings.mutate({ paranoia_level: level })}
                        className={cn(
                          'h-7 w-9 rounded-md border text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60',
                          active
                            ? 'border-brand bg-brand-soft text-brand'
                            : 'border-line text-fg-subtle hover:border-fill hover:bg-recessed',
                        )}
                      >
                        {level}
                      </button>
                    )
                  })}
                </span>
              </span>
            </span>
          </div>
        )}
        <BodyStageTimeoutCard
          settings={settings}
          canWrite={canWrite}
          pending={updateSettings.isPending}
          onCommit={(secs) => updateSettings.mutate({ body_stage_timeout_secs: secs })}
        />
        </div>
      </section>

      {/* ── Enforcement ───────────────────────────────────────────────── */}
      <section>
        <SectionHeading
          title={t('pages.protection.enforcementTitle')}
          hint={t('pages.protection.enforcementHint')}
        />
        <EnforcementModeCard />

        <Tabs
          variant="pill"
          className="mb-5"
          value={tab}
          onChange={setTab}
          items={[
            {
              value: 'managed',
              label: t('pages.protection.tabManaged'),
              icon: <Sliders weight="duotone" className="h-4 w-4" />,
            },
            {
              value: 'custom',
              label: t('pages.protection.tabCustom'),
              icon: <ShieldCheck weight="duotone" className="h-4 w-4" />,
            },
            {
              value: 'cc',
              label: t('pages.protection.tabCc'),
              icon: <Cloud weight="duotone" className="h-4 w-4" />,
            },
          ]}
        />

        {tab === 'managed' && <ManagedRulesPanel />}
        {tab === 'custom' && <CustomRulesPanel />}
        {tab === 'cc' && <MitigationPanel />}
      </section>

      <ConfirmDialog
        open={confirmUnderAttack}
        onClose={() => setConfirmUnderAttack(false)}
        onConfirm={() => {
          setConfirmUnderAttack(false)
          setUnderAttack.mutate(true)
        }}
        tone="danger"
        title={t('pages.protection.underAttackConfirmTitle')}
        description={t('pages.protection.underAttackConfirmDescription')}
        confirmLabel={t('pages.protection.underAttackCta')}
        loading={setUnderAttack.isPending}
      />
    </div>
  )
}

/**
 * Site-level enforcement mode — the master switch the WAF engine runs in
 * (block > monitor > off), stored on the site's WAF settings row and shipped
 * to the data plane verbatim. Custom rules keep their per-rule mode; a
 * monitor-mode rule only downgrades its own action while the site is in
 * block. Kept out of the custom-rules panel so the Enforcement section opens
 * with the posture-level control.
 */
function EnforcementModeCard() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const settingsQuery = useQuery({
    queryKey: wafSettingsKeys.settings(siteId),
    queryFn: () => wafSettingsApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const loading = settingsQuery.isPending
  // The stored value is authoritative; legacy rows without it read as off.
  const mode = settingsQuery.data?.mode ?? 'off'

  const applyMode = useMutation({
    mutationFn: async (next: RuleMode) => {
      await wafSettingsApi.update(siteId, { mode: next })
      return next
    },
    onSuccess: (next) => {
      toast.success(t('pages.waf.modeApplied'), t(`pages.waf.mode_${next}`))
      void queryClient.invalidateQueries({
        queryKey: wafSettingsKeys.settings(siteId),
      })
      void queryClient.invalidateQueries({
        queryKey: wafSettingsKeys.posture(siteId),
      })
    },
    onError: (error) => {
      toast.error(
        t('pages.protection.updateFailed'),
        error instanceof Error ? error.message : undefined,
      )
    },
  })

  return (
    <Card className="mb-5 max-w-2xl">
      <div className="flex items-center justify-between gap-3 px-4 pt-4">
        <div>
          <h3 className="text-sm font-semibold text-fg-strong">
            {t('pages.waf.mode')}
          </h3>
          <p className="mt-0.5 text-[13px] text-fg-subtle">
            {t('pages.waf.modeCardHint')}
          </p>
        </div>
        {settingsQuery.isFetching && (
          <span className="text-xs text-fg-subtle">{t('pages.waf.applyingMode')}</span>
        )}
      </div>
      <CardBody className="flex flex-col gap-3">
        <div className="flex flex-col gap-2">
          {RULE_MODES.map((m) => {
            const active = mode === m
            return (
              <button
                key={m}
                type="button"
                disabled={!canWrite || applyMode.isPending || loading}
                onClick={() => applyMode.mutate(m as RuleMode)}
                className={cn(
                  'flex items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-left transition-all disabled:cursor-not-allowed disabled:opacity-60',
                  active
                    ? 'border-brand bg-brand-soft'
                    : 'border-line hover:border-fill hover:bg-recessed',
                )}
              >
                <span className="min-w-0">
                  <span
                    className={cn(
                      'block text-sm font-medium',
                      active ? 'text-brand' : 'text-fg',
                    )}
                  >
                    {t(`pages.waf.mode_${m}`)}
                  </span>
                  <span className="block text-xs text-fg-subtle">
                    {t(`pages.waf.modeHint_${m}`)}
                  </span>
                </span>
                {active && <ShieldCheck weight="fill" className="h-4 w-4 shrink-0 text-brand" />}
              </button>
            )
          })}
        </div>
        <div className="rounded-md border border-line bg-recessed px-3 py-2">
          <p className="text-xs leading-relaxed text-fg-subtle">
            {t('pages.waf.modeExplainer')}
          </p>
        </div>
      </CardBody>
    </Card>
  )
}

/**
 * Body-stage inspection budget — how long the data plane may hold a request
 * while inspecting its body before failing open. Not a downstream timeout.
 */
function BodyStageTimeoutCard({
  settings,
  canWrite,
  pending,
  onCommit,
}: {
  settings?: WafSettings
  canWrite: boolean
  pending: boolean
  onCommit: (secs: number) => void
}) {
  const { t } = useTranslation()
  const serverValue = settings?.body_stage_timeout_secs
  const committed = serverValue && serverValue > 0 ? serverValue : BODY_STAGE_TIMEOUT_DEFAULT
  const [draft, setDraft] = useState<string>(String(committed))

  useEffect(() => {
    setDraft(String(committed))
  }, [committed])

  const commit = () => {
    const parsed = Number(draft)
    if (!Number.isFinite(parsed)) {
      setDraft(String(committed))
      return
    }
    const next = clampBodyStageTimeout(parsed)
    setDraft(String(next))
    if (next !== committed) onCommit(next)
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-line bg-elevated px-4 py-3">
      <span className="flex min-w-0 items-center gap-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-recessed text-fg-subtle">
          <Timer weight="duotone" className="h-5 w-5" />
        </span>
        <span className="min-w-0">
          <span className="block text-sm font-semibold text-fg-strong">
            {t('pages.waf.bodyStageTimeout')}
          </span>
          <span className="mt-0.5 block max-w-md text-[13px] text-fg-subtle">
            {t('pages.waf.bodyStageTimeoutHint')}
          </span>
        </span>
      </span>
      <Input
        type="number"
        className="w-24 text-right"
        min={BODY_STAGE_TIMEOUT_MIN}
        max={BODY_STAGE_TIMEOUT_MAX}
        step={1}
        disabled={!canWrite || pending}
        aria-label={t('pages.waf.bodyStageTimeout')}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.currentTarget.blur()
          }
        }}
      />
    </div>
  )
}

/** Forwards a pre-merge route (`/security/waf`, `/security/cc`) here, query intact. */
export function LegacyProtectionRedirect({ tab }: { tab: ProtectionTab }) {
  const { siteId = '' } = useParams<{ siteId: string }>()
  const location = useLocation()
  const params = new URLSearchParams(location.search)
  params.set('tab', tab)
  return (
    <Navigate to={`/sites/${siteId}/security/protection?${params.toString()}`} replace />
  )
}

export default ProtectionPage
