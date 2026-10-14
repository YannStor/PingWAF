import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  ArrowRight,
  Gauge,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { useUnsavedGuard } from '@/hooks/useUnsavedGuard'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { TagInput } from '@/components/ui/MultiSelect'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { challengeApi, challengeKeys, defaultChallengeConfig } from '@/api/challenge'
import { rateLimitApi, rateLimitKeys } from '@/api/rateLimiting'
import { useCanWrite } from '@/hooks'
import { CHALLENGE_LEVELS, type ChallengeConfig } from '@/api/types'

const MIN_CLEARANCE_SECS = 60
const MAX_CLEARANCE_SECS = 86_400

/** Bounds mirrored from the server's `exempt_paths` validation. */
const EXEMPT_PATHS_MAX_COUNT = 100
const EXEMPT_PATH_MAX_LENGTH = 512

/**
 * Mirrors the server-side `exempt_paths` checks: each entry must start with
 * `/`, contain no whitespace or control characters, be at most 512 characters,
 * and the list at most 100 entries. Returns an i18n key suffix or `null`.
 */
function validateExemptPaths(paths: string[]): string | null {
  if (paths.length > EXEMPT_PATHS_MAX_COUNT) return 'tooMany'
  for (const p of paths) {
    if (p.length > EXEMPT_PATH_MAX_LENGTH) return 'tooLong'
    if (!p.startsWith('/')) return 'invalid'
    if (/[\s\x00-\x1f\x7f]/.test(p)) return 'invalid'
  }
  return null
}

/**
 * The mitigation module of the protection page: an entry card into the
 * dedicated rate-limiting page plus the site's challenge configuration.
 */
export function MitigationPanel() {
  const { siteId = '' } = useParams<{ siteId: string }>()
  return (
    <div className="flex flex-col gap-4">
      <RateLimitingEntryCard siteId={siteId} />
      <ChallengeConfigCard siteId={siteId} />
    </div>
  )
}

/** Shortcut to the rate-limiting page, with a live count of that site's rules. */
function RateLimitingEntryCard({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const navigate = useNavigate()

  const rulesQuery = useQuery({
    queryKey: rateLimitKeys.list(siteId),
    queryFn: () => rateLimitApi.list(siteId),
    enabled: Boolean(siteId),
  })
  const rules = rulesQuery.data?.items ?? []
  const enabled = rules.filter((r) => r.enabled).length

  return (
    <Card>
      <CardBody className="flex flex-wrap items-center gap-4">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-recessed text-fg-subtle">
          <Gauge weight="duotone" className="h-5 w-5" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold text-fg-strong">
            {t('pages.protection.rateLimitingEntry.title')}
          </span>
          <span className="mt-0.5 block text-[13px] text-fg-subtle">
            {t('pages.protection.rateLimitingEntry.description')}
          </span>
          {!rulesQuery.isPending && !rulesQuery.isError && rules.length > 0 && (
            <span className="mt-1 block text-xs text-fg-subtle">
              {t('pages.protection.rateLimitingEntry.ruleCount', {
                enabled,
                total: rules.length,
              })}
            </span>
          )}
        </span>
        <Button
          variant="secondary"
          onClick={() => navigate(`/sites/${siteId}/security/rate-limiting`)}
          icon={<ArrowRight weight="duotone" className="h-4 w-4" />}
        >
          {t('pages.protection.rateLimitingEntry.cta')}
        </Button>
      </CardBody>
    </Card>
  )
}

function ChallengeConfigCard({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const [config, setConfig] = useState<ChallengeConfig | null>(null)
  const [dirty, setDirty] = useState(false)

  const configQuery = useQuery({
    queryKey: challengeKeys.config(siteId),
    queryFn: () => challengeApi.get(siteId),
    enabled: Boolean(siteId),
  })

  // Seed the form from the query (render-phase reset on new data / first
  // failure), so nothing flashes stale values on the first paint.
  const serverConfig = configQuery.data
  const loadFailed = configQuery.isError && Boolean(siteId)
  // `null` until the first seed: cached query data present at mount must still
  // reach the form.
  const [sync, setSync] = useState<{ config: typeof serverConfig; failed: boolean } | null>(null)
  if (!sync || sync.config !== serverConfig || sync.failed !== loadFailed) {
    setSync({ config: serverConfig, failed: loadFailed })
    if (serverConfig) {
      setConfig(serverConfig)
      setDirty(false)
    } else if (loadFailed) {
      setConfig(defaultChallengeConfig())
    }
  }

  const patch = (part: Partial<ChallengeConfig>) => {
    setConfig((c) => (c ? { ...c, ...part } : c))
    setDirty(true)
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: challengeKeys.all(siteId) })
  }

  const save = useMutation({
    mutationFn: (payload: ChallengeConfig) =>
      challengeApi.update(siteId, {
        enabled: payload.enabled,
        default_level: payload.default_level,
        clearance_duration_secs: payload.clearance_duration_secs,
        rate_threshold: payload.rate_threshold,
        exempt_paths: payload.exempt_paths,
        browser_integrity_check: payload.browser_integrity_check,
        tls_fingerprint_check: payload.tls_fingerprint_check,
      }),
    onSuccess: (saved) => {
      setConfig(saved)
      setDirty(false)
      toast.success(t('pages.cc.saved'))
      invalidate()
    },
  })

  const unsavedDialog = useUnsavedGuard(dirty)

  if (configQuery.isPending) {
    return <SkeletonCard className="h-64" />
  }
  if (configQuery.isError && !config) {
    return (
      <ErrorState
        error={configQuery.error}
        onRetry={() => configQuery.refetch()}
        retrying={configQuery.isFetching}
      />
    )
  }

  const exemptPathsIssue = config ? validateExemptPaths(config.exempt_paths) : null

  return (
    <div>
      {unsavedDialog}
      {config ? (
        <div className="flex flex-col gap-4">
          {/* Under-attack mode is managed from the page-level banner; keep it
              out of this form so the two controls cannot fight each other. */}
          <Card>
            <CardHeader
              title={t('pages.cc.general')}
              action={
                <span className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    loading={configQuery.isFetching}
                    onClick={() => configQuery.refetch()}
                    icon={<ArrowClockwise weight="duotone" className="h-3.5 w-3.5" />}
                  >
                    {t('common.refresh')}
                  </Button>
                  {canWrite && (
                    <Button
                      size="sm"
                      variant="primary"
                      disabled={!dirty || save.isPending || exemptPathsIssue !== null}
                      loading={save.isPending}
                      onClick={() => config && save.mutate(config)}
                    >
                      {t('common.save')}
                    </Button>
                  )}
                </span>
              }
            />
            <CardBody className="flex flex-col gap-5">
              <Switch
                checked={config.enabled}
                disabled={!canWrite}
                onCheckedChange={(enabled) => patch({ enabled })}
                label={t('pages.cc.enable')}
                description={t('pages.cc.enableHint')}
              />
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <Select
                  label={t('pages.cc.challengeLevel')}
                  value={config.default_level}
                  disabled={!canWrite || !config.enabled}
                  options={CHALLENGE_LEVELS.map((l) => ({
                    value: l,
                    label: t(`challengeLevels.${l}`, l),
                  }))}
                  onChange={(e) => patch({ default_level: e.target.value })}
                />
                <Input
                  type="number"
                  label={t('pages.cc.clearanceDuration')}
                  value={Math.round(config.clearance_duration_secs / 60)}
                  min={MIN_CLEARANCE_SECS / 60}
                  max={MAX_CLEARANCE_SECS / 60}
                  disabled={!canWrite || !config.enabled}
                  hint={t('pages.cc.minutes')}
                  onChange={(e) =>
                    patch({
                      clearance_duration_secs: Math.min(
                        MAX_CLEARANCE_SECS,
                        Math.max(MIN_CLEARANCE_SECS, Number(e.target.value) * 60),
                      ),
                    })
                  }
                />
                <Input
                  type="number"
                  label={t('pages.cc.rateThreshold')}
                  value={config.rate_threshold}
                  min={1}
                  disabled={!canWrite || !config.enabled}
                  hint={t('pages.cc.rateThresholdHint')}
                  onChange={(e) => patch({ rate_threshold: Number(e.target.value) })}
                />
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={t('pages.cc.checks')}
              description={t('pages.cc.checksHint')}
            />
            <CardBody className="flex flex-col gap-5">
              <Switch
                checked={config.browser_integrity_check}
                disabled={!canWrite || !config.enabled}
                onCheckedChange={(browser_integrity_check) => patch({ browser_integrity_check })}
                label={t('pages.cc.browserIntegrity')}
                description={t('pages.cc.browserIntegrityHint')}
              />
              <Switch
                checked={config.tls_fingerprint_check}
                disabled={!canWrite || !config.enabled}
                onCheckedChange={(tls_fingerprint_check) => patch({ tls_fingerprint_check })}
                label={t('pages.cc.tlsFingerprint')}
                description={t('pages.cc.tlsFingerprintHint')}
              />
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={t('pages.cc.exemptPaths')}
              description={t('pages.cc.exemptPathsHint')}
              action={
                <span className="flex items-center gap-1.5 text-xs text-fg-subtle">
                  {config.exempt_paths.length}
                </span>
              }
            />
            <CardBody>
              <TagInput
                value={config.exempt_paths}
                disabled={!canWrite || !config.enabled}
                placeholder="/health"
                suggestions={['/health', '/status', '/api/heartbeat']}
                onChange={(exempt_paths) => patch({ exempt_paths })}
              />
              {exemptPathsIssue && (
                <p className="mt-2 text-xs text-fg-danger">
                  {t(`pages.cc.exemptPaths_${exemptPathsIssue}`)}
                </p>
              )}
            </CardBody>
          </Card>
        </div>
      ) : null}
    </div>
  )
}

export default MitigationPanel
