import { useRef, useState, type FormEvent, type ReactNode } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  Plus,
  X,
  Bug,
  Fingerprint,
  Brain,
  UserFocus,
  Robot,
  Eye,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { useUnsavedGuard } from '@/hooks/useUnsavedGuard'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { botApi, botKeys, defaultBotConfig, COMMON_KNOWN_BOTS } from '@/api/bot'
import {
  aiCrawlApi,
  aiCrawlKeys,
  aiCrawlBodyTooLong,
  AI_CRAWL_MAX_CACHE_AGE,
} from '@/api/aiCrawl'
import { ipGroupsApi, ipGroupKeys } from '@/api/ipGroups'
import { useCanWrite } from '@/hooks'
import { Dialog } from '@/components/ui/Dialog'
import { BOT_ACTIONS, AI_CRAWL_ACTIONS, AI_CRAWL_POLICY_ACTIONS } from '@/api/types'
import type {
  AiBotCatalogEntry,
  AiBotPolicySetting,
  AiCrawlPolicyAction,
  AiCrawlPreview,
  AiCrawlSettings,
  BotConfig,
  UpdateAiCrawlSettingsRequest,
} from '@/api/types'

export function BotPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const [config, setConfig] = useState<BotConfig | null>(null)
  const [dirty, setDirty] = useState(false)
  const [newBot, setNewBot] = useState('')

  const configQuery = useQuery({
    queryKey: botKeys.config(siteId),
    queryFn: () => botApi.get(siteId),
    enabled: Boolean(siteId),
  })

  // Enabled groups offered as verified-bot networks; the server validates
  // global/linkage on save, the selector is only a convenience.
  const groupsQuery = useQuery({
    queryKey: ipGroupKeys.list({ enabled: true }),
    queryFn: () => ipGroupsApi.list({ enabled: true, page_size: 100 }),
    enabled: Boolean(siteId),
  })
  const ipGroups = groupsQuery.data?.items ?? []

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
      setConfig(defaultBotConfig(siteId))
    }
  }

  const patch = (part: Partial<BotConfig>) => {
    setConfig((c) => (c ? { ...c, ...part } : c))
    setDirty(true)
  }

  const save = useMutation({
    mutationFn: (payload: BotConfig) =>
      botApi.update(siteId, {
        enabled: payload.enabled,
        ua_analysis: payload.ua_analysis,
        action: payload.action,
        known_bots_whitelist: payload.known_bots_whitelist,
        ip_verification_enabled: payload.ip_verification_enabled,
        verified_ip_group_id: payload.verified_ip_group_id,
        dns_verification_enabled: payload.dns_verification_enabled,
      }),
    onSuccess: (saved) => {
      setConfig(saved)
      setDirty(false)
      toast.success(t('pages.bot.saved'))
      void queryClient.invalidateQueries({ queryKey: botKeys.all(siteId) })
    },
  })

  const unsavedDialog = useUnsavedGuard(dirty)

  const addWhitelistEntry = (pattern: string) => {
    const trimmed = pattern.trim()
    if (!config || !trimmed) return
    if (
      config.known_bots_whitelist.some(
        (entry) => entry.toLowerCase() === trimmed.toLowerCase(),
      )
    ) {
      setNewBot('')
      return
    }
    patch({ known_bots_whitelist: [...config.known_bots_whitelist, trimmed] })
    setNewBot('')
  }

  const removeWhitelistEntry = (pattern: string) => {
    if (!config) return
    patch({
      known_bots_whitelist: config.known_bots_whitelist.filter(
        (entry) => entry !== pattern,
      ),
    })
  }

  const submitNewBot = (e: FormEvent) => {
    e.preventDefault()
    addWhitelistEntry(newBot)
  }

  const knownBots = config?.known_bots_whitelist ?? []
  const quickAdd = COMMON_KNOWN_BOTS.filter(
    (bot) =>
      !knownBots.some((entry) => entry.toLowerCase() === bot.toLowerCase()),
  )

  return (
    <div className="animate-slide-up">
      {unsavedDialog}
      <PageHeader
        title={t('pages.bot.title')}
        description={t('pages.bot.description')}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              loading={configQuery.isFetching}
              onClick={() => configQuery.refetch()}
              icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
            >
              {t('common.refresh')}
            </Button>
            {canWrite && (
              <Button
                variant="primary"
                disabled={!dirty || save.isPending}
                loading={save.isPending}
                onClick={() => config && save.mutate(config)}
              >
                {t('common.save')}
              </Button>
            )}
          </div>
        }
      />

      {configQuery.isError && !config ? (
        <ErrorState
          error={configQuery.error}
          onRetry={() => configQuery.refetch()}
          retrying={configQuery.isFetching}
        />
      ) : config ? (
        <div className="flex flex-col gap-6">
          <Card>
            <CardHeader title={t('pages.bot.detection')} description={t('pages.bot.detectionHint')} />
            <CardBody className="flex flex-col gap-5">
              <Switch
                checked={config.enabled}
                disabled={!canWrite}
                onCheckedChange={(enabled) => patch({ enabled })}
                label={t('pages.bot.enable')}
                description={t('pages.bot.enableHint')}
              />
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <MethodToggle
                  icon={<Bug weight="duotone" className="h-4 w-4" />}
                  checked={config.ua_analysis}
                  disabled={!canWrite || !config.enabled}
                  onChange={(ua_analysis) => patch({ ua_analysis })}
                  label={t('pages.bot.userAgentAnalysis')}
                  description={t('pages.bot.userAgentAnalysisHint')}
                />
                <MethodToggle
                  icon={<Fingerprint weight="duotone" className="h-4 w-4" />}
                  checked={config.js_detection}
                  disabled
                  comingSoon
                  label={t('pages.bot.jsDetection')}
                  description={t('pages.bot.jsDetectionHint')}
                />
                <MethodToggle
                  icon={<Brain weight="duotone" className="h-4 w-4" />}
                  checked={config.tls_fingerprint}
                  disabled
                  comingSoon
                  label={t('pages.bot.tlsFingerprinting')}
                  description={t('pages.bot.tlsFingerprintingHint')}
                />
                <MethodToggle
                  icon={<UserFocus weight="duotone" className="h-4 w-4" />}
                  checked={config.behavioral_analysis}
                  disabled
                  comingSoon
                  label={t('pages.bot.behavioralAnalysis')}
                  description={t('pages.bot.behavioralAnalysisHint')}
                />
              </div>
              <Select
                label={t('pages.bot.action')}
                value={config.action}
                disabled={!canWrite || !config.enabled}
                containerClassName="max-w-xs"
                hint={t('pages.bot.actionHint')}
                options={BOT_ACTIONS.map((a) => ({ value: a, label: t(`actions.${a}`, a) }))}
                onChange={(e) => patch({ action: e.target.value })}
              />
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={t('pages.bot.verification.title')}
              description={t('pages.bot.verification.hint')}
            />
            <CardBody className="flex flex-col gap-5">
              <Switch
                checked={config.ip_verification_enabled}
                disabled={!canWrite || !config.enabled}
                onCheckedChange={(ip_verification_enabled) =>
                  patch({ ip_verification_enabled })
                }
                label={t('pages.bot.verification.ip')}
                description={t('pages.bot.verification.ipHint')}
              />
              {config.ip_verification_enabled && (
                <Select
                  label={t('pages.bot.verification.group')}
                  value={config.verified_ip_group_id ?? ''}
                  disabled={!canWrite || !config.enabled}
                  containerClassName="max-w-xs"
                  hint={t('pages.bot.verification.groupHint')}
                  options={[
                    {
                      value: '',
                      label: t('pages.bot.verification.groupNone'),
                    },
                    ...ipGroups.map((group) => ({
                      value: group.id,
                      label: group.is_global
                        ? `${group.name} · ${t('pages.bot.verification.globalGroup')}`
                        : group.name,
                    })),
                  ]}
                  onChange={(e) =>
                    patch({ verified_ip_group_id: e.target.value || null })
                  }
                />
              )}
              <Switch
                checked={config.dns_verification_enabled}
                disabled={!canWrite || !config.enabled}
                onCheckedChange={(dns_verification_enabled) =>
                  patch({ dns_verification_enabled })
                }
                label={t('pages.bot.verification.dns')}
                description={t('pages.bot.verification.dnsHint')}
              />
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={t('pages.bot.knownBots')}
              description={t('pages.bot.knownBotsHint')}
            />
            <CardBody className="flex flex-col gap-4">
              {canWrite && (
                <form onSubmit={submitNewBot} className="flex max-w-md items-start gap-2">
                  <Input
                    value={newBot}
                    className="pw-mono"
                    placeholder="Googlebot"
                    hint={t('pages.bot.uaPatternHint')}
                    disabled={!config.enabled}
                    onChange={(e) => setNewBot(e.target.value)}
                  />
                  <Button
                    type="submit"
                    variant="secondary"
                    disabled={!config.enabled || !newBot.trim()}
                    icon={<Plus weight="bold" className="h-4 w-4" />}
                  >
                    {t('common.add')}
                  </Button>
                </form>
              )}
              {knownBots.length === 0 ? (
                <p className="text-sm text-fg-subtle">{t('pages.bot.noKnownBots')}</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {knownBots.map((pattern) => (
                    <span
                      key={pattern}
                      className="pw-mono inline-flex items-center gap-1.5 rounded-full border border-line bg-recessed px-2.5 py-1 text-xs text-fg-strong"
                    >
                      {pattern}
                      {canWrite && config.enabled && (
                        <button
                          type="button"
                          aria-label={t('common.delete')}
                          className="text-fg-subtle transition-colors hover:text-fg-danger"
                          onClick={() => removeWhitelistEntry(pattern)}
                        >
                          <X weight="bold" className="h-3 w-3" />
                        </button>
                      )}
                    </span>
                  ))}
                </div>
              )}
              {canWrite && config.enabled && quickAdd.length > 0 && (
                <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
                  <span className="text-xs text-fg-subtle">{t('pages.bot.quickAdd')}</span>
                  {quickAdd.slice(0, 6).map((bot) => (
                    <button
                      key={bot}
                      type="button"
                      onClick={() => addWhitelistEntry(bot)}
                      className="rounded-full border border-dashed border-line px-2.5 py-0.5 text-xs text-fg-subtle transition-colors hover:border-brand hover:text-brand"
                    >
                      + {bot}
                    </button>
                  ))}
                </div>
              )}
            </CardBody>
          </Card>

          <AiCrawlCard siteId={siteId} canWrite={canWrite} />
        </div>
      ) : null}
    </div>
  )
}

const CATEGORY_TONES: Record<string, 'brand' | 'info' | 'warning' | 'neutral'> = {
  training: 'warning',
  search: 'brand',
  agent: 'info',
  other: 'neutral',
}

/**
 * AI Crawl Control card — the site-wide switch, per-family overrides, and the
 * robots.txt / llms.txt generators, all saved with one PUT.
 */
function AiCrawlCard({ siteId, canWrite }: { siteId: string; canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [draft, setDraft] = useState<AiCrawlSettings | null>(null)
  // Per-family UI action; `inherit` entries are omitted from the PUT payload.
  const [policyMap, setPolicyMap] = useState<Record<string, AiCrawlPolicyAction>>({})
  const [dirty, setDirty] = useState(false)
  const [preview, setPreview] = useState<{
    file: 'robots' | 'llms'
    data: AiCrawlPreview | null
    error: Error | null
  } | null>(null)
  // Request sequence guard: only the latest preview click may update state,
  // so rapid robots/llms alternation can't leave a stale response on screen.
  const previewSeq = useRef(0)

  // Long-lived static data: the family catalog rarely changes.
  const catalogQuery = useQuery({
    queryKey: aiCrawlKeys.catalog(),
    queryFn: () => aiCrawlApi.catalog(),
    staleTime: 24 * 3600_000,
  })
  const catalog: AiBotCatalogEntry[] = catalogQuery.data ?? []

  const settingsQuery = useQuery({
    queryKey: aiCrawlKeys.settings(siteId),
    queryFn: () => aiCrawlApi.get(siteId),
    enabled: Boolean(siteId),
  })

  // Seed the form from the query (render-phase reset, same pattern as the
  // classic bot config above) so no stale values flash on the first paint.
  const serverSettings = settingsQuery.data
  const [sync, setSync] = useState<typeof serverSettings | null>(null)
  if (sync !== serverSettings) {
    setSync(serverSettings)
    if (serverSettings) {
      setDraft(serverSettings)
      const map: Record<string, AiCrawlPolicyAction> = {}
      for (const p of serverSettings.policies ?? []) {
        map[p.bot_id] = (p.action as AiCrawlPolicyAction) ?? 'inherit'
      }
      setPolicyMap(map)
      setDirty(false)
    }
  }

  const patch = (part: Partial<AiCrawlSettings>) => {
    setDraft((d) => (d ? { ...d, ...part } : d))
    setDirty(true)
  }

  const setPolicy = (botId: string, action: AiCrawlPolicyAction) => {
    setPolicyMap((m) => ({ ...m, [botId]: action }))
    setDirty(true)
  }

  const buildPayload = (): UpdateAiCrawlSettingsRequest | null => {
    if (!draft) return null
    // Front-end validation mirroring the server bounds.
    const age = Number.isFinite(draft.cache_max_age) ? Math.floor(draft.cache_max_age) : -1
    if (age < 0 || age > AI_CRAWL_MAX_CACHE_AGE) return null
    if (aiCrawlBodyTooLong(draft.robots_body) || aiCrawlBodyTooLong(draft.llms_body))
      return null
    // The server replaces the whole policy set when `policies` is present.
    // Without the catalogue the table cannot render its selects, so sending
    // an (empty) set would silently wipe overrides the operator never saw.
    const catalogReady = catalogQuery.isSuccess && catalog.length > 0
    const policies: AiBotPolicySetting[] | undefined = catalogReady
      ? Object.entries(policyMap)
          .filter(([, action]) => action !== 'inherit')
          .map(([bot_id, action]) => ({ bot_id, action }))
      : undefined
    return {
      enabled: draft.enabled,
      default_action: draft.default_action,
      robots_mode: draft.robots_mode,
      robots_body: draft.robots_body,
      llms_mode: draft.llms_mode,
      llms_body: draft.llms_body,
      llms_include_routes: draft.llms_include_routes,
      cache_max_age: age,
      content_signal_search: draft.content_signal_search,
      content_signal_ai_train: draft.content_signal_ai_train,
      content_signal_ai_input: draft.content_signal_ai_input,
      ...(policies ? { policies } : {}),
    }
  }

  const cacheAgeInvalid =
    draft !== null &&
    (!Number.isFinite(draft.cache_max_age) ||
      draft.cache_max_age < 0 ||
      draft.cache_max_age > AI_CRAWL_MAX_CACHE_AGE)
  const bodyTooLong =
    draft !== null &&
    (aiCrawlBodyTooLong(draft.robots_body) || aiCrawlBodyTooLong(draft.llms_body))

  const save = useMutation({
    mutationFn: (payload: UpdateAiCrawlSettingsRequest) =>
      aiCrawlApi.update(siteId, payload),
    onSuccess: (saved) => {
      setDraft(saved)
      const map: Record<string, AiCrawlPolicyAction> = {}
      for (const p of saved.policies ?? []) {
        map[p.bot_id] = (p.action as AiCrawlPolicyAction) ?? 'inherit'
      }
      setPolicyMap(map)
      setDirty(false)
      queryClient.setQueryData(aiCrawlKeys.settings(siteId), saved)
      void queryClient.invalidateQueries({ queryKey: aiCrawlKeys.settings(siteId) })
      toast.success(t('pages.bots.aiCrawl.saved'))
    },
    onError: (err) => {
      toast.error(
        err instanceof Error ? err.message : t('errors.unknown'),
      )
    },
  })

  const openPreview = (file: 'robots' | 'llms') => {
    const seq = ++previewSeq.current
    setPreview({ file, data: null, error: null })
    aiCrawlApi
      .preview(siteId, file)
      .then((data) => {
        if (previewSeq.current === seq) setPreview({ file, data, error: null })
      })
      .catch((err: unknown) => {
        if (previewSeq.current === seq)
          setPreview({ file, data: null, error: err instanceof Error ? err : new Error(String(err)) })
      })
  }

  const actionOptions = AI_CRAWL_POLICY_ACTIONS.map((a) => ({
    value: a,
    label:
      a === 'inherit'
        ? t('pages.bots.aiCrawl.inherit')
        : t(`pages.bots.aiCrawl.action.${a}`),
  }))

  return (
    <Card>
      <CardHeader
        title={t('pages.bots.aiCrawl.title')}
        description={t('pages.bots.aiCrawl.description')}
        action={<Robot weight="duotone" className="h-4 w-4 text-fg-subtle" />}
      />
      <CardBody className="flex flex-col gap-5">
        {settingsQuery.isError && !draft ? (
          <ErrorState
            error={settingsQuery.error}
            onRetry={() => settingsQuery.refetch()}
            retrying={settingsQuery.isFetching}
          />
        ) : !draft ? (
          <div className="h-24 animate-pulse rounded-lg bg-recessed" />
        ) : (
          <>
            {/* Posture */}
            <Switch
              checked={draft.enabled}
              disabled={!canWrite}
              onCheckedChange={(enabled) => patch({ enabled })}
              label={t('pages.bots.aiCrawl.enable')}
              description={t('pages.bots.aiCrawl.enableHint')}
            />
            <p className="-mt-3 text-xs text-fg-subtle">
              {t(
                'pages.bots.aiCrawl.upstreamHint',
                'When the AI crawler is disabled, robots.txt / llms.txt requests pass through to your origin, which decides the response.',
              )}
            </p>
            <Select
              label={t('pages.bots.aiCrawl.defaultAction')}
              value={draft.default_action}
              disabled={!canWrite || !draft.enabled}
              containerClassName="max-w-xs"
              hint={t('pages.bots.aiCrawl.defaultActionHint')}
              options={AI_CRAWL_ACTIONS.map((a) => ({
                value: a,
                label: t(`pages.bots.aiCrawl.action.${a}`),
              }))}
              onChange={(e) => patch({ default_action: e.target.value })}
            />
            <div>
              <p className="mb-2 text-sm font-medium text-fg-strong">
                {t('pages.bots.aiCrawl.contentSignals')}
              </p>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <Switch
                  checked={draft.content_signal_search}
                  disabled={!canWrite}
                  onCheckedChange={(content_signal_search) =>
                    patch({ content_signal_search })
                  }
                  label={t('pages.bots.aiCrawl.signalSearch')}
                  description={t('pages.bots.aiCrawl.signalSearchHint')}
                />
                <Switch
                  checked={draft.content_signal_ai_train}
                  disabled={!canWrite}
                  onCheckedChange={(content_signal_ai_train) =>
                    patch({ content_signal_ai_train })
                  }
                  label={t('pages.bots.aiCrawl.signalTrain')}
                  description={t('pages.bots.aiCrawl.signalTrainHint')}
                />
                <Switch
                  checked={draft.content_signal_ai_input}
                  disabled={!canWrite}
                  onCheckedChange={(content_signal_ai_input) =>
                    patch({ content_signal_ai_input })
                  }
                  label={t('pages.bots.aiCrawl.signalInput')}
                  description={t('pages.bots.aiCrawl.signalInputHint')}
                />
              </div>
            </div>

            {/* Family table */}
            <div>
              <p className="mb-2 text-sm font-medium text-fg-strong">
                {t('pages.bots.aiCrawl.families')}
              </p>
              {catalogQuery.isError ? (
                <ErrorState
                  error={catalogQuery.error}
                  onRetry={() => catalogQuery.refetch()}
                  retrying={catalogQuery.isFetching}
                />
              ) : (
              <div className="overflow-x-auto rounded-lg border border-line">
                <table className="w-full text-left text-[13px]">
                  <thead className="bg-recessed/60 text-xs uppercase tracking-wide text-fg-subtle">
                    <tr>
                      <th className="px-3 py-2 font-medium">
                        {t('pages.bots.aiCrawl.colName')}
                      </th>
                      <th className="px-3 py-2 font-medium">
                        {t('pages.bots.aiCrawl.colOperator')}
                      </th>
                      <th className="px-3 py-2 font-medium">
                        {t('pages.bots.aiCrawl.colCategory')}
                      </th>
                      <th className="w-40 px-3 py-2 text-right font-medium">
                        {t('pages.bots.aiCrawl.colAction')}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {catalog.map((entry) => (
                      <tr key={entry.id} className="border-t border-line">
                        <td className="px-3 py-2 font-medium text-fg-strong">
                          {entry.name}
                        </td>
                        <td className="px-3 py-2 text-fg-subtle">{entry.operator}</td>
                        <td className="px-3 py-2">
                          <Badge size="sm" tone={CATEGORY_TONES[entry.category] ?? 'neutral'}>
                            {t(`pages.bots.aiCrawl.category.${entry.category}`, entry.category)}
                          </Badge>
                        </td>
                        <td className="px-3 py-2">
                          <Select
                            className="h-8 text-xs"
                            value={policyMap[entry.id] ?? 'inherit'}
                            disabled={!canWrite || !draft.enabled}
                            options={actionOptions}
                            onChange={(e) =>
                              setPolicy(entry.id, e.target.value as AiCrawlPolicyAction)
                            }
                          />
                        </td>
                      </tr>
                    ))}
                    {catalog.length === 0 && (
                      <tr>
                        <td colSpan={4} className="px-3 py-6 text-center text-fg-subtle">
                          {t('common.noData')}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              )}
            </div>

            {/* robots.txt / llms.txt */}
            <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
              <FileConfig
                title="robots.txt"
                mode={draft.robots_mode}
                body={draft.robots_body}
                disabled={!canWrite}
                modeLabel={(v) =>
                  t(`pages.bots.aiCrawl.mode.${v === 'generate' ? 'generate' : 'off'}`)
                }
                onMode={(robots_mode) => patch({ robots_mode })}
                onBody={(robots_body) => patch({ robots_body })}
                ariaDescribedBy={bodyTooLong ? 'ai-crawl-body-too-long' : undefined}
                onPreview={() => openPreview('robots')}
              />
              <FileConfig
                title="llms.txt"
                mode={draft.llms_mode}
                body={draft.llms_body}
                disabled={!canWrite}
                modeLabel={(v) =>
                  t(`pages.bots.aiCrawl.mode.${v === 'generate' ? 'generate' : 'off'}`)
                }
                onMode={(llms_mode) => patch({ llms_mode })}
                onBody={(llms_body) => patch({ llms_body })}
                ariaDescribedBy={bodyTooLong ? 'ai-crawl-body-too-long' : undefined}
                onPreview={() => openPreview('llms')}
                extra={
                  <Switch
                    checked={draft.llms_include_routes}
                    disabled={!canWrite}
                    onCheckedChange={(llms_include_routes) =>
                      patch({ llms_include_routes })
                    }
                    label={t('pages.bots.aiCrawl.includeRoutes')}
                    description={t('pages.bots.aiCrawl.includeRoutesHint')}
                  />
                }
              />
            </div>

            <Input
              label={t('pages.bots.aiCrawl.cacheMaxAge')}
              type="number"
              min={0}
              max={AI_CRAWL_MAX_CACHE_AGE}
              value={draft.cache_max_age}
              disabled={!canWrite}
              containerClassName="max-w-xs"
              hint={t('pages.bots.aiCrawl.cacheMaxAgeHint')}
              error={cacheAgeInvalid ? t('pages.bots.aiCrawl.cacheMaxAgeInvalid') : undefined}
              onChange={(e) => patch({ cache_max_age: Number(e.target.value) })}
            />
            {bodyTooLong && (
              <p id="ai-crawl-body-too-long" className="text-sm text-fg-danger">
                {t('pages.bots.aiCrawl.bodyTooLong')}
              </p>
            )}

            {canWrite && (
              <div className="flex items-center justify-end gap-2 border-t border-line pt-4">
                <Button
                  variant="primary"
                  disabled={!dirty || cacheAgeInvalid || bodyTooLong || save.isPending}
                  loading={save.isPending}
                  onClick={() => {
                    const payload = buildPayload()
                    if (payload) save.mutate(payload)
                  }}
                >
                  {t('common.save')}
                </Button>
              </div>
            )}
          </>
        )}
      </CardBody>

      <Dialog
        open={preview !== null}
        onClose={() => setPreview(null)}
        size="lg"
        title={t(
          'pages.bots.aiCrawl.previewTitle',
          preview?.file === 'llms' ? 'llms.txt preview' : 'robots.txt preview',
          { file: preview?.file === 'llms' ? 'llms.txt' : 'robots.txt' },
        )}
        description={preview?.data?.content_type}
        footer={
          <Button variant="secondary" onClick={() => setPreview(null)}>
            {t('common.close')}
          </Button>
        }
      >
        {preview?.error ? (
          <div className="flex flex-col items-center gap-3 py-8">
            <span className="text-sm text-fg-danger">
              {t('pages.bots.aiCrawl.previewFailed', 'Failed to load preview')}
            </span>
            {preview.error.message && (
              <span className="pw-mono text-xs text-fg-subtle">{preview.error.message}</span>
            )}
            <Button
              size="sm"
              variant="secondary"
              onClick={() => openPreview(preview.file)}
            >
              {t('common.retry', 'Retry')}
            </Button>
          </div>
        ) : preview?.data ? (
          <pre className="pw-mono max-h-[60vh] overflow-auto whitespace-pre-wrap rounded-lg bg-recessed p-3 text-xs text-fg">
            {preview.data.body || t('pages.bots.aiCrawl.previewEmpty')}
          </pre>
        ) : (
          <div className="flex h-32 items-center justify-center">
            <span className="flex items-center gap-2 text-sm text-fg-subtle">
              <Eye weight="duotone" className="h-4 w-4 animate-pulse" />
              {t('pages.bots.aiCrawl.previewLoading')}
            </span>
          </div>
        )}
      </Dialog>
    </Card>
  )
}

/** One generated-file block: mode picker, optional body editor, preview. */
function FileConfig({
  title,
  mode,
  body,
  disabled,
  modeLabel,
  onMode,
  onBody,
  onPreview,
  ariaDescribedBy,
  extra,
}: {
  title: string
  mode: string
  body: string
  disabled: boolean
  modeLabel: (mode: string) => string
  onMode: (mode: string) => void
  onBody: (body: string) => void
  onPreview: () => void
  ariaDescribedBy?: string
  extra?: ReactNode
}) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-line bg-recessed/40 p-3">
      <div className="flex items-center justify-between gap-2">
        <p className="pw-mono text-sm font-medium text-fg-strong">{title}</p>
        <Button
          size="sm"
          variant="secondary"
          disabled={disabled}
          onClick={onPreview}
          icon={<Eye weight="duotone" className="h-4 w-4" />}
        >
          {t('pages.bots.aiCrawl.preview')}
        </Button>
      </div>
      <Select
        label={t('pages.bots.aiCrawl.modeLabel')}
        value={mode === 'generate' ? 'generate' : 'off'}
        disabled={disabled}
        options={[
          { value: 'off', label: modeLabel('off') },
          { value: 'generate', label: modeLabel('generate') },
        ]}
        onChange={(e) => onMode(e.target.value)}
      />
      {mode === 'generate' && (
        <>
          <textarea
            className="pw-mono min-h-28 w-full rounded-md border border-line bg-elevated px-3 py-2 text-xs text-fg focus:border-brand focus:outline-none"
            placeholder={t('pages.bots.aiCrawl.bodyPlaceholder')}
            value={body}
            disabled={disabled}
            aria-describedby={ariaDescribedBy}
            onChange={(e) => onBody(e.target.value)}
          />
          <p className="text-xs text-fg-subtle">{t('pages.bots.aiCrawl.bodyHint')}</p>
        </>
      )}
      {extra}
    </div>
  )
}

function MethodToggle({
  icon,
  checked,
  disabled,
  onChange,
  label,
  description,
  comingSoon = false,
}: {
  icon: ReactNode
  checked: boolean
  disabled?: boolean
  onChange?: (v: boolean) => void
  label: string
  description: string
  comingSoon?: boolean
}) {
  const { t } = useTranslation()
  return (
    <div className="flex items-start gap-3 rounded-lg border border-line bg-recessed/40 p-3">
      <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-brand-soft text-brand">
        {icon}
      </span>
      {comingSoon ? (
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <p className="text-sm font-medium text-fg-strong">{label}</p>
            <Badge tone="neutral" size="sm">
              {t('pages.bot.comingSoon')}
            </Badge>
          </div>
          <p className="mt-0.5 text-xs text-fg-subtle">{description}</p>
        </div>
      ) : (
        <Switch
          checked={checked}
          disabled={disabled}
          onCheckedChange={onChange}
          label={label}
          description={description}
        />
      )}
    </div>
  )
}

export default BotPage
