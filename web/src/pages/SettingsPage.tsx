import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Sun,
  MoonStars,
  Monitor,
  Check,
  Database,
  Eye,
  Key,
  Trash,
  Copy,
  PlugsConnected,
  ArrowClockwise,
  ArrowsCounterClockwise,
  BracketsCurly,
  Code,
  FileHtml,
  Warning,
  Certificate,
  DownloadSimple,
  LockKey,
  ShieldCheck,
  Sparkle,
  UploadSimple,
  GithubLogo,
  ArrowSquareOut,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { QuickNav } from '@/components/ui/QuickNav'
import { Switch } from '@/components/ui/Switch'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Textarea } from '@/components/ui/Textarea'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { useAnyUnsaved, useRegisterUnsaved, useUnsavedGuard } from '@/hooks/useUnsavedGuard'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows, SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import {
  SECRET_MASK,
  defaultEsConfig,
  settingsApi,
  settingsKeys,
  stripMaskedSecrets,
  type EsConfigDraft,
} from '@/api/settings'
import { downloadCertificateFile, tlsApi, tlsKeys } from '@/api/tls'
import {
  errorPagesApi,
  errorPageKeys,
  ERROR_PAGE_MESSAGES,
  ERROR_PAGE_VARIABLES,
  defaultErrorPageTemplate,
  renderErrorPageTemplate,
} from '@/api/errorPages'
import { PasskeyToggleCard } from '@/components/account/PasskeyToggleCard'
import { apiProtectionApi, apiProtectionKeys } from '@/api/apiProtection'
import { aiApi, aiKeys } from '@/api/ai'
import { mcpApi, mcpKeys } from '@/api/mcp'
import { ipGroupKeys, ipGroupsApi } from '@/api/ipGroups'
import { systemApi } from '@/api/system'
import { ApiError } from '@/api/client'
import { errorMessage, handleApiError } from '@/api/errors'
import { useAuthStore } from '@/stores/authStore'
import { useCanWrite } from '@/hooks'
import { useThemeStore, type ThemeMode } from '@/stores/themeStore'
import { supportedLanguages } from '@/i18n'
import { cn } from '@/lib/utils'
import { formatDateTime } from '@/lib/format'
import type {
  AiSettings,
  AiTestResult,
  ApiProtectionView,
  ApiProtectionWafMode,
  EsTestResult,
  UpdateAiSettingsRequest,
  UpdateApiProtectionRequest,
} from '@/api/types'
import {
  ERROR_PAGE_CONTENT_TYPE_LABELS,
  ERROR_PAGE_CONTENT_TYPES,
  ERROR_PAGE_STATUS_CODES,
  type ErrorPage,
  type ErrorPageContentType,
} from '@/api/types'

const langLabels: Record<string, string> = { en: 'English', zh: '中文', ja: '日本語' }

/** Public project repository shown in the About card. */
const PROJECT_URL = 'https://github.com/shuaiZend/PingWAF'

/** Upstream proxy engine shown in the About card. */
const UPSTREAM_URL = 'https://github.com/cloudflare/pingora'

/**
 * Quick-navigation anchors in page order; each id must match the `id` of the
 * section that wraps the matching card below.
 */
const SETTINGS_NAV = [
  { id: 'appearance', labelKey: 'pages.settings.appearance' },
  { id: 'passkeys', labelKey: 'pages.settings.passkeys' },
  { id: 'control-plane-tls', labelKey: 'pages.settings.controlPlaneTls' },
  { id: 'observation-mode', labelKey: 'pages.settings.observationMode' },
  { id: 'api-protection', labelKey: 'pages.settings.apiProtection' },
  { id: 'cache', labelKey: 'pages.settings.cache' },
  { id: 'origin-tls', labelKey: 'pages.settings.originTls' },
  { id: 'ai-assistant', labelKey: 'pages.settings.aiAssistant' },
  { id: 'mcp', labelKey: 'pages.settings.mcp' },
  { id: 'elasticsearch', labelKey: 'pages.settings.elasticsearch' },
  { id: 'log-retention', labelKey: 'pages.settings.logRetention' },
  { id: 'error-pages', labelKey: 'pages.settings.errorPages' },
  { id: 'about', labelKey: 'pages.settings.about' },
]

/** Sections hidden entirely for non-admin users (the cards render `null`). */
const ADMIN_ONLY_NAV_IDS = new Set([
  'control-plane-tls',
  'observation-mode',
  'api-protection',
  'cache',
  'origin-tls',
  'ai-assistant',
  'elasticsearch',
  'log-retention',
  'error-pages',
])

export function SettingsPage() {
  const { t, i18n } = useTranslation()
  const { mode, setMode } = useThemeStore()
  const canWrite = useCanWrite()
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'
  // Section cards register their dirty flags; the page guards as a whole.
  const unsavedDialog = useUnsavedGuard(useAnyUnsaved())

  const themeOptions: { value: ThemeMode; label: string; icon: typeof Sun }[] = [
    { value: 'light', label: t('theme.light'), icon: Sun },
    { value: 'dark', label: t('theme.dark'), icon: MoonStars },
    { value: 'system', label: t('theme.system'), icon: Monitor },
  ]

  const navItems = useMemo(
    () =>
      SETTINGS_NAV.filter(({ id }) => isAdmin || !ADMIN_ONLY_NAV_IDS.has(id)).map(
        ({ id, labelKey }) => ({ id, label: t(labelKey) }),
      ),
    [t, isAdmin],
  )

  return (
    <div className="animate-slide-up">
      {unsavedDialog}
      <PageHeader title={t('pages.settings.title')} description={t('pages.settings.description')} />

      <div className="flex max-w-6xl items-start gap-8">
        <QuickNav ariaLabel={t('pages.settings.quickNav')} items={navItems} />
        <div className="flex min-w-0 max-w-4xl flex-1 flex-col gap-4">
          <section id="appearance" className="scroll-mt-6">
            <AppearanceCard themeOptions={themeOptions} mode={mode} setMode={setMode} i18n={i18n} />
          </section>
          <section id="passkeys" className="scroll-mt-6">
            <PasskeyToggleCard />
          </section>
          <section id="control-plane-tls" className="scroll-mt-6">
            {isAdmin && <ControlPlaneTlsCard canWrite={canWrite} />}
          </section>
          <section id="observation-mode" className="scroll-mt-6">
            {isAdmin && <ObservationModeCard canWrite={canWrite} />}
          </section>
          <section id="api-protection" className="scroll-mt-6">
            {isAdmin && <ApiProtectionCard canWrite={canWrite} />}
          </section>
          <section id="cache" className="scroll-mt-6">
            {isAdmin && <CacheSettingsCard canWrite={canWrite} />}
          </section>
          <section id="origin-tls" className="scroll-mt-6">
            {isAdmin && <OriginTlsCard canWrite={canWrite} />}
          </section>
          <section id="ai-assistant" className="scroll-mt-6">
            {isAdmin && <AiAssistantCard canWrite={canWrite} />}
          </section>
          <section id="mcp" className="scroll-mt-6">
            <McpCard />
          </section>
          <section id="elasticsearch" className="scroll-mt-6">
            {isAdmin && <ElasticsearchCard canWrite={canWrite} />}
          </section>
          <section id="log-retention" className="scroll-mt-6">
            {isAdmin && <LogRetentionCard canWrite={canWrite} />}
          </section>
          <section id="error-pages" className="scroll-mt-6">
            {isAdmin && <ErrorPagesCard canWrite={canWrite} />}
          </section>
          <section id="about" className="scroll-mt-6 flex flex-col gap-4">
            <AboutCard />
          </section>
        </div>
      </div>
    </div>
  )
}

/* ── Appearance ─────────────────────────────────────────────────────── */

function AppearanceCard({
  themeOptions,
  mode,
  setMode,
  i18n,
}: {
  themeOptions: { value: ThemeMode; label: string; icon: typeof Sun }[]
  mode: ThemeMode
  setMode: (m: ThemeMode) => void
  i18n: { language?: string; changeLanguage: (lng: string) => Promise<unknown> }
}) {
  const { t } = useTranslation()
  return (
    <Card>
      <CardHeader
        title={t('pages.settings.appearance')}
        description={t('pages.settings.appearanceDescription')}
      />
      <CardBody className="flex flex-col gap-6">
        <div>
          <p className="mb-2 text-[13px] font-medium text-fg-subtle">
            {t('pages.settings.themePreference')}
          </p>
          <div className="grid grid-cols-3 gap-2 sm:max-w-md">
            {themeOptions.map((opt) => {
              const Icon = opt.icon
              const active = mode === opt.value
              return (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setMode(opt.value)}
                  className={cn(
                    'flex flex-col items-center gap-2 rounded-lg border p-4 text-sm transition-all',
                    active
                      ? 'border-brand bg-brand-soft text-brand'
                      : 'border-line text-fg-subtle hover:border-fill hover:text-fg',
                  )}
                >
                  <Icon weight="duotone" className="h-6 w-6" />
                  {opt.label}
                </button>
              )
            })}
          </div>
        </div>

        <div>
          <p className="mb-2 text-[13px] font-medium text-fg-subtle">
            {t('pages.settings.languagePreference')}
          </p>
          <div className="flex flex-wrap gap-2">
            {supportedLanguages.map((lng) => {
              const active = i18n.language?.startsWith(lng)
              return (
                <button
                  key={lng}
                  type="button"
                  onClick={() => void i18n.changeLanguage(lng)}
                  className={cn(
                    'inline-flex items-center gap-2 rounded-md border px-4 py-2 text-sm transition-colors',
                    active
                      ? 'border-brand bg-brand-soft text-brand'
                      : 'border-line text-fg-subtle hover:border-fill hover:text-fg',
                  )}
                >
                  {active && <Check weight="bold" className="h-4 w-4" />}
                  {langLabels[lng]}
                </button>
              )
            })}
          </div>
        </div>
      </CardBody>
    </Card>
  )
}

function ElasticsearchCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [draft, setDraft] = useState<EsConfigDraft>(defaultEsConfig)
  const [urlsText, setUrlsText] = useState('')
  const [dirty, setDirty] = useState(false)
  const [testResult, setTestResult] = useState<EsTestResult | null>(null)
  useRegisterUnsaved(dirty)

  const settings = useQuery({
    queryKey: settingsKeys.elasticsearch(),
    queryFn: () => settingsApi.getElasticsearch(),
  })

  // Load the stored config into the form, turning `***` into blank fields so a
  // save can never write the mask back over the real secret. Render-phase
  // reseed on new query data, so the form is right from the first paint.
  const loadedConfig = settings.data?.config
  const [lastLoadedConfig, setLastLoadedConfig] = useState<typeof loadedConfig | null>(null)
  if (loadedConfig && loadedConfig !== lastLoadedConfig) {
    setLastLoadedConfig(loadedConfig)
    const stripped = stripMaskedSecrets(loadedConfig)
    setDraft(stripped)
    setUrlsText(stripped.urls.join('\n'))
    setDirty(false)
    setTestResult(null)
  }

  const patch = (next: Partial<EsConfigDraft>) => {
    setDraft((d) => ({ ...d, ...next }))
    setDirty(true)
  }

  /** Turns the textarea into the URL list, dropping blanks. */
  const collect = (): EsConfigDraft => ({
    ...draft,
    urls: urlsText
      .split('\n')
      .map((u) => u.trim())
      .filter(Boolean),
  })

  const save = useMutation({
    mutationFn: () => settingsApi.saveElasticsearch(collect()),
    onSuccess: (view) => {
      void queryClient.invalidateQueries({ queryKey: settingsKeys.elasticsearch() })
      setDirty(false)
      if (view.requires_restart) {
        toast.warning(t('pages.settings.esSaved'), t('pages.settings.esRequiresRestart'))
      } else {
        toast.success(t('pages.settings.esSaved'), t('pages.settings.esApplied'))
      }
    },
  })

  const testDraft = useMutation({
    mutationFn: () => settingsApi.testElasticsearch(collect()),
    onSuccess: (result) => setTestResult(result),
  })

  const testLive = useMutation({
    mutationFn: () => settingsApi.testLive(),
    onSuccess: (result) => setTestResult(result),
  })

  const health = settings.data?.health
  const running = settings.data?.running ?? false

  const num = (key: keyof EsConfigDraft, value: string) => {
    const parsed = Number(value)
    patch({ [key]: Number.isFinite(parsed) ? parsed : 0 } as Partial<EsConfigDraft>)
  }

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.elasticsearch')}
        description={t('pages.settings.elasticsearchDescription')}
        action={
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5">
              <span
                className={cn(
                  'h-2 w-2 rounded-full',
                  running ? 'bg-success animate-pulse' : 'bg-fg-subtle/50',
                )}
              />
              <span className="text-xs text-fg-subtle">
                {running ? t('pages.settings.esRunning') : t('pages.settings.esStopped')}
              </span>
            </span>
            {health && (
              <Badge
                tone={
                  health.status === 'green'
                    ? 'success'
                    : health.status === 'yellow'
                      ? 'warning'
                      : 'danger'
                }
              >
                {health.status}
              </Badge>
            )}
          </div>
        }
      />
      <CardBody className="flex flex-col gap-5">
        {settings.isError && !settings.data ? (
          <ErrorState
            variant="inline"
            error={settings.error}
            onRetry={() => settings.refetch()}
            retrying={settings.isFetching}
          />
        ) : settings.isPending ? (
          <SkeletonRows rows={4} columns={2} />
        ) : (
          <>
            {settings.data?.requires_restart && (
              <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] text-fg">
                <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
                {t('pages.settings.esRequiresRestart')}
              </p>
            )}

            <Switch
              checked={draft.enabled}
              onCheckedChange={(enabled) => patch({ enabled })}
              disabled={!canWrite}
              label={t('pages.settings.esEnabled')}
              description={t('pages.settings.esEnabledHint')}
            />

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="sm:col-span-2">
                <label
                  htmlFor="es-urls"
                  className="mb-1.5 block text-[13px] font-medium text-fg"
                >
                  {t('pages.settings.esUrls')}
                </label>
                <textarea
                  id="es-urls"
                  rows={3}
                  disabled={!canWrite}
                  value={urlsText}
                  placeholder={'http://localhost:9200'}
                  onChange={(e) => {
                    setUrlsText(e.target.value)
                    setDirty(true)
                  }}
                  className="pw-mono w-full rounded-md border border-line bg-recessed px-3 py-2 text-[13px] text-fg placeholder:text-fg-subtle/60 focus:border-focus focus:outline-none disabled:opacity-60"
                />
                <p className="mt-1 text-xs text-fg-subtle">{t('pages.settings.esUrlsHint')}</p>
              </div>

              <Input
                label={t('pages.settings.esIndexPrefix')}
                value={draft.index_prefix}
                disabled={!canWrite}
                onChange={(e) => patch({ index_prefix: e.target.value })}
              />
              <Input
                label={t('pages.settings.esUsername')}
                value={draft.username ?? ''}
                autoComplete="off"
                disabled={!canWrite}
                onChange={(e) => patch({ username: e.target.value || null })}
              />
              <Input
                type="password"
                label={t('pages.settings.esPassword')}
                value={draft.password ?? ''}
                autoComplete="new-password"
                placeholder={
                  settings.data?.config.password === SECRET_MASK
                    ? t('pages.settings.secretStored')
                    : ''
                }
                hint={t('pages.settings.secretHint')}
                disabled={!canWrite}
                onChange={(e) => patch({ password: e.target.value || null })}
              />
              <Input
                type="password"
                label={t('pages.settings.esApiKey')}
                value={draft.api_key ?? ''}
                autoComplete="new-password"
                placeholder={
                  settings.data?.config.api_key === SECRET_MASK
                    ? t('pages.settings.secretStored')
                    : ''
                }
                hint={t('pages.settings.apiKeyHint')}
                disabled={!canWrite}
                onChange={(e) => patch({ api_key: e.target.value || null })}
              />
            </div>

            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Input
                type="number"
                label={t('pages.settings.esBulkMaxSize')}
                value={draft.bulk_max_size}
                min={1}
                disabled={!canWrite}
                onChange={(e) => num('bulk_max_size', e.target.value)}
              />
              <Input
                type="number"
                label={t('pages.settings.esBulkFlushMs')}
                value={draft.bulk_flush_interval_ms}
                min={1}
                disabled={!canWrite}
                onChange={(e) => num('bulk_flush_interval_ms', e.target.value)}
              />
              <Input
                type="number"
                label={t('pages.settings.esMaxBodySize')}
                value={draft.max_body_size}
                min={0}
                hint={t('pages.settings.bytes')}
                disabled={!canWrite}
                onChange={(e) => num('max_body_size', e.target.value)}
              />
              <Input
                type="number"
                label={t('pages.settings.esRequestTimeout')}
                value={draft.request_timeout_secs}
                min={1}
                disabled={!canWrite}
                onChange={(e) => num('request_timeout_secs', e.target.value)}
              />
              <Input
                label={t('pages.settings.esBufferDir')}
                value={draft.buffer_dir ?? ''}
                placeholder={t('pages.settings.esBufferDirPlaceholder')}
                className="pw-mono text-[13px]"
                disabled={!canWrite}
                onChange={(e) => patch({ buffer_dir: e.target.value || null })}
              />
              <Input
                type="number"
                label={t('pages.settings.esBufferMaxMb')}
                value={draft.buffer_max_size_mb}
                min={1}
                disabled={!canWrite}
                onChange={(e) => num('buffer_max_size_mb', e.target.value)}
              />
              <Input
                type="number"
                label={t('pages.settings.esChannelCapacity')}
                value={draft.channel_capacity}
                min={1}
                disabled={!canWrite}
                onChange={(e) => num('channel_capacity', e.target.value)}
              />
            </div>

            {testResult && (
              <div
                className={cn(
                  'rounded-md border px-3 py-2 text-[13px]',
                  testResult.ok
                    ? 'border-success/40 bg-success/8 text-fg'
                    : 'border-danger/40 bg-danger/8 text-fg-danger',
                )}
              >
                <p className="font-medium">
                  {testResult.ok
                    ? t('pages.settings.esTestOk')
                    : t('pages.settings.esTestFailed')}
                </p>
                {testResult.error && <p className="pw-mono mt-1 break-all text-xs">{testResult.error}</p>}
                {testResult.health && (
                  <p className="mt-1 text-xs text-fg-subtle">
                    {t('pages.settings.esCluster')}: {testResult.health.cluster_name ?? '—'} ·{' '}
                    {t('pages.settings.esNodes')}: {testResult.health.number_of_nodes ?? '—'} ·{' '}
                    {t('pages.settings.esShards')}: {testResult.health.active_shards ?? '—'}
                  </p>
                )}
                <p className="mt-1 text-xs text-fg-subtle">
                  {testResult.template_installed
                    ? t('pages.settings.esTemplateInstalled')
                    : t('pages.settings.esTemplateMissing')}
                </p>
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2 border-t border-line pt-4">
              <Button
                variant="primary"
                disabled={!canWrite || !dirty}
                loading={save.isPending}
                icon={<Database weight="duotone" className="h-4 w-4" />}
                onClick={() => save.mutate()}
              >
                {t('common.save')}
              </Button>
              <Button
                variant="secondary"
                disabled={!canWrite}
                loading={testDraft.isPending}
                icon={<PlugsConnected weight="duotone" className="h-4 w-4" />}
                onClick={() => testDraft.mutate()}
              >
                {t('pages.settings.testDraft')}
              </Button>
              <Button
                variant="ghost"
                loading={testLive.isPending}
                icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
                onClick={() => testLive.mutate()}
              >
                {t('pages.settings.testLive')}
              </Button>
              {dirty && (
                <span className="text-xs text-fg-warning">{t('pages.settings.unsavedChanges')}</span>
              )}
            </div>
          </>
        )}
      </CardBody>
    </Card>
  )
}

/* ── Log retention ──────────────────────────────────────────────────── */

/** Server-side bounds from `api::log_retention::validate_days`. */
const MIN_RETENTION_DAYS = 1
const MAX_RETENTION_DAYS = 3650

function LogRetentionCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [accessDays, setAccessDays] = useState('')
  const [securityDays, setSecurityDays] = useState('')
  const [dirty, setDirty] = useState(false)
  useRegisterUnsaved(dirty)

  const settings = useQuery({
    queryKey: settingsKeys.logRetention(),
    queryFn: () => settingsApi.getLogRetention(),
  })

  const serverRow = settings.data
  const [lastServerRow, setLastServerRow] = useState<typeof serverRow | null>(null)
  if (serverRow && serverRow !== lastServerRow) {
    setLastServerRow(serverRow)
    setAccessDays(String(serverRow.access_log_retention_days))
    setSecurityDays(String(serverRow.security_event_retention_days))
    setDirty(false)
  }

  const parsed = {
    access: Number(accessDays),
    security: Number(securityDays),
  }
  const inRange = (value: number) =>
    Number.isInteger(value) && value >= MIN_RETENTION_DAYS && value <= MAX_RETENTION_DAYS
  const valid = inRange(parsed.access) && inRange(parsed.security)

  const save = useMutation({
    mutationFn: () =>
      settingsApi.saveLogRetention({
        access_log_retention_days: parsed.access,
        security_event_retention_days: parsed.security,
      }),
    onSuccess: (row) => {
      void queryClient.invalidateQueries({ queryKey: settingsKeys.logRetention() })
      setAccessDays(String(row.access_log_retention_days))
      setSecurityDays(String(row.security_event_retention_days))
      setDirty(false)
      toast.success(t('pages.settings.logRetentionSaved'))
    },
  })

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.logRetention')}
        description={t('pages.settings.logRetentionDescription')}
        action={
          <Button
            variant="primary"
            size="sm"
            disabled={!canWrite || !dirty || !valid}
            loading={save.isPending}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
            onClick={() => save.mutate()}
          >
            {t('common.save')}
          </Button>
        }
      />
      <CardBody>
        <div className="grid gap-4 sm:grid-cols-2">
          <Input
            type="number"
            label={t('pages.settings.logRetentionAccess')}
            value={accessDays}
            min={MIN_RETENTION_DAYS}
            max={MAX_RETENTION_DAYS}
            disabled={!canWrite}
            onChange={(e) => {
              setAccessDays(e.target.value)
              setDirty(true)
            }}
          />
          <Input
            type="number"
            label={t('pages.settings.logRetentionSecurity')}
            value={securityDays}
            min={MIN_RETENTION_DAYS}
            max={MAX_RETENTION_DAYS}
            disabled={!canWrite}
            onChange={(e) => {
              setSecurityDays(e.target.value)
              setDirty(true)
            }}
          />
        </div>

        {!valid && (
          <p className="mt-3 flex items-center gap-2 text-xs text-fg-danger">
            <Warning weight="duotone" className="h-4 w-4 shrink-0" />
            {t('pages.settings.logRetentionRange')}
          </p>
        )}
        <p className="mt-3 text-xs text-fg-subtle">{t('pages.settings.logRetentionHint')}</p>
        <p className="mt-1 text-xs text-fg-subtle">{t('pages.settings.logRetentionEsNote')}</p>
      </CardBody>
    </Card>
  )
}

/* ── Custom error pages ─────────────────────────────────────────────── */

interface ErrorPageEditor {
  status_code: number
  name: string
  content_type: ErrorPageContentType
  body_template: string
  enabled: boolean
  existingId: string | null
}

/**
 * The global error page templates, edited from here because they apply to
 * every site. One card per status code; a card opens the template editor for
 * that code (or creates it), and the dialog previews the rendered output with
 * sample variables.
 */
function ErrorPagesCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [editor, setEditor] = useState<ErrorPageEditor | null>(null)
  const [pendingReset, setPendingReset] = useState<ErrorPageEditor | null>(null)
  const [pendingDelete, setPendingDelete] = useState<ErrorPage | null>(null)

  const pagesQuery = useQuery({
    queryKey: errorPageKeys.list(),
    queryFn: () => errorPagesApi.list(),
    select: (res) => res.items,
  })

  const byStatus = useMemo(() => {
    const map = new Map<number, ErrorPage>()
    for (const p of pagesQuery.data ?? []) map.set(p.status_code, p)
    return map
  }, [pagesQuery.data])

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: errorPageKeys.all })
  }

  const save = useMutation({
    mutationFn: (state: ErrorPageEditor) =>
      state.existingId
        ? errorPagesApi.update(state.existingId, {
            status_code: state.status_code,
            name: state.name,
            content_type: state.content_type,
            body_template: state.body_template,
            enabled: state.enabled,
          })
        : errorPagesApi.upsert({
            status_code: state.status_code,
            name: state.name,
            content_type: state.content_type,
            body_template: state.body_template,
            enabled: state.enabled,
          }),
    onSuccess: () => {
      toast.success(t('pages.errorPages.saved'))
      setEditor(null)
      invalidate()
    },
  })

  const toggle = useMutation({
    mutationFn: ({ page, enabled }: { page: ErrorPage; enabled: boolean }) =>
      errorPagesApi.update(page.id, { enabled }),
    onSuccess: () => invalidate(),
  })

  const remove = useMutation({
    mutationFn: (id: string) => errorPagesApi.delete(id),
    onSuccess: () => {
      toast.success(t('pages.errorPages.deleted'))
      setPendingDelete(null)
      setEditor(null)
      invalidate()
    },
  })

  const openEditor = (statusCode: number) => {
    const existing = byStatus.get(statusCode)
    setEditor({
      status_code: statusCode,
      name: existing?.name ?? ERROR_PAGE_MESSAGES[statusCode] ?? String(statusCode),
      content_type: (existing?.content_type as ErrorPageContentType) ?? 'text/html',
      body_template:
        existing?.body_template ??
        defaultErrorPageTemplate(
          statusCode,
          (existing?.content_type as ErrorPageContentType) ?? 'text/html',
        ),
      enabled: existing?.enabled ?? true,
      existingId: existing?.id ?? null,
    })
  }

  const previewHtml = editor ? renderErrorPageTemplate(editor.body_template) : ''

  return (
    <>
      <Card>
        <CardHeader
          title={t('pages.errorPages.title')}
          description={t('pages.errorPages.description')}
          action={
            <Button
              variant="secondary"
              size="sm"
              loading={pagesQuery.isFetching}
              onClick={() => pagesQuery.refetch()}
              icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
            >
              {t('common.refresh')}
            </Button>
          }
        />
        <CardBody>
          {pagesQuery.isError && !pagesQuery.data ? (
            <ErrorState
              error={pagesQuery.error}
              onRetry={() => pagesQuery.refetch()}
              retrying={pagesQuery.isFetching}
            />
          ) : pagesQuery.isPending ? (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {ERROR_PAGE_STATUS_CODES.map((c) => (
                <SkeletonCard key={c} />
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {ERROR_PAGE_STATUS_CODES.map((code) => {
                const page = byStatus.get(code)
                const customized = Boolean(page)
                return (
                  <Card
                    key={code}
                    interactive
                    padded
                    onClick={() => canWrite && openEditor(code)}
                    className={cn('cursor-pointer', !canWrite && 'cursor-default')}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <span
                          className={cn(
                            'flex h-12 w-12 shrink-0 items-center justify-center rounded-lg text-lg font-bold tabular-nums',
                            page?.enabled
                              ? 'bg-brand-soft text-brand'
                              : 'bg-recessed text-fg-subtle',
                          )}
                        >
                          {code}
                        </span>
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-fg-strong">
                            {page?.name || ERROR_PAGE_MESSAGES[code]}
                          </p>
                          <p className="mt-0.5 text-xs uppercase tracking-wide text-fg-subtle">
                            {page?.content_type ?? 'text/html'}
                          </p>
                        </div>
                      </div>
                      {customized ? (
                        <Badge tone="brand" size="sm">
                          {t('pages.errorPages.customized')}
                        </Badge>
                      ) : (
                        <Badge tone="neutral" size="sm">
                          {t('pages.errorPages.default')}
                        </Badge>
                      )}
                    </div>
                    <div className="mt-4 flex items-center justify-between">
                      <span className="text-xs text-fg-subtle">
                        {customized
                          ? t('pages.errorPages.clickToEdit')
                          : t('pages.errorPages.clickToCreate')}
                      </span>
                      {page && (
                        <span onClick={(e) => e.stopPropagation()}>
                          <Switch
                            size="sm"
                            checked={page.enabled}
                            disabled={!canWrite || toggle.isPending}
                            aria-label={`${t('common.enabled')}: ${code}`}
                            onCheckedChange={(enabled) => toggle.mutate({ page, enabled })}
                          />
                        </span>
                      )}
                    </div>
                  </Card>
                )
              })}
            </div>
          )}
        </CardBody>
      </Card>

      <Dialog
        open={editor !== null}
        onClose={save.isPending ? () => undefined : () => setEditor(null)}
        size="lg"
        title={editor ? `${editor.status_code} · ${t('pages.errorPages.editTitle')}` : ''}
        description={t('pages.errorPages.editDescription')}
        className="max-w-4xl"
        footer={
          editor && (
            <>
              {editor.existingId && canWrite && (
                <Button
                  variant="ghost"
                  className="mr-auto hover:text-fg-danger"
                  onClick={() => {
                    const page = byStatus.get(editor.status_code)
                    if (page) setPendingDelete(page)
                  }}
                  icon={<FileHtml weight="duotone" className="h-4 w-4" />}
                >
                  {t('pages.errorPages.delete')}
                </Button>
              )}
              <Button
                variant="secondary"
                onClick={() => setPendingReset(editor)}
                icon={<ArrowsCounterClockwise weight="duotone" className="h-4 w-4" />}
              >
                {t('pages.errorPages.resetDefault')}
              </Button>
              <Button variant="ghost" onClick={() => setEditor(null)} disabled={save.isPending}>
                {t('common.cancel')}
              </Button>
              <Button
                variant="primary"
                onClick={() => editor && save.mutate(editor)}
                loading={save.isPending}
              >
                {t('common.save')}
              </Button>
            </>
          )
        }
      >
        {editor && (
          <div className="flex flex-col gap-4">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <Input
                label={t('pages.errorPages.pageName')}
                value={editor.name}
                onChange={(e) => setEditor({ ...editor, name: e.target.value })}
              />
              <Select
                label={t('pages.errorPages.contentType')}
                value={editor.content_type}
                options={ERROR_PAGE_CONTENT_TYPES.map((c) => ({
                  value: c,
                  label: ERROR_PAGE_CONTENT_TYPE_LABELS[c] ?? c.toUpperCase(),
                }))}
                onChange={(e) => {
                  const content_type = e.target.value as ErrorPageContentType
                  setEditor({ ...editor, content_type })
                }}
              />
              <div className="flex items-end pb-1">
                <Switch
                  checked={editor.enabled}
                  onCheckedChange={(enabled) => setEditor({ ...editor, enabled })}
                  label={t('common.enabled')}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_1fr_220px]">
              {/* Template */}
              <div className="flex flex-col gap-1.5">
                <span className="flex items-center gap-1.5 text-[13px] font-medium text-fg">
                  <Code weight="duotone" className="h-4 w-4" />
                  {t('pages.errorPages.template')}
                </span>
                <Textarea
                  mono
                  rows={18}
                  value={editor.body_template}
                  onChange={(e) => setEditor({ ...editor, body_template: e.target.value })}
                />
              </div>

              {/* Preview */}
              <div className="flex flex-col gap-1.5">
                <span className="flex items-center gap-1.5 text-[13px] font-medium text-fg">
                  <Eye weight="duotone" className="h-4 w-4" />
                  {t('pages.errorPages.preview')}
                </span>
                <div className="h-[388px] overflow-hidden rounded-md border border-line bg-white">
                  {editor.content_type === 'text/html' ? (
                    <iframe
                      title={t('pages.errorPages.preview')}
                      className="h-full w-full"
                      sandbox=""
                      srcDoc={previewHtml}
                    />
                  ) : (
                    <pre className="pw-mono h-full w-full overflow-auto bg-recessed p-3 text-xs text-fg">
                      {previewHtml}
                    </pre>
                  )}
                </div>
              </div>

              {/* Variables */}
              <div className="flex flex-col gap-1.5">
                <span className="flex items-center gap-1.5 text-[13px] font-medium text-fg">
                  <BracketsCurly weight="duotone" className="h-4 w-4" />
                  {t('pages.errorPages.variables')}
                </span>
                <div className="flex max-h-[388px] flex-col gap-1 overflow-y-auto rounded-md border border-line bg-recessed/40 p-2">
                  {ERROR_PAGE_VARIABLES.map((v) => (
                    <button
                      key={v.name}
                      type="button"
                      title={v.description}
                      onClick={() =>
                        setEditor((e) =>
                          e ? { ...e, body_template: `${e.body_template}{{${v.name}}}` } : e,
                        )
                      }
                      className="group flex flex-col items-start rounded px-1.5 py-1 text-left transition-colors hover:bg-elevated"
                    >
                      <span className="pw-mono text-xs text-brand">{`{{${v.name}}}`}</span>
                      <span className="text-[11px] leading-tight text-fg-subtle">
                        {v.description}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </Dialog>

      <ConfirmDialog
        open={pendingReset !== null}
        onClose={() => setPendingReset(null)}
        tone="primary"
        onConfirm={() => {
          if (!pendingReset) return
          setEditor({
            ...pendingReset,
            content_type: pendingReset.content_type,
            body_template: defaultErrorPageTemplate(
              pendingReset.status_code,
              pendingReset.content_type,
            ),
          })
          setPendingReset(null)
        }}
        title={t('pages.errorPages.resetTitle')}
        description={t('pages.errorPages.resetDescription')}
        confirmLabel={t('pages.errorPages.resetDefault')}
      />

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete.id)}
        title={t('pages.errorPages.deleteTitle')}
        description={t('pages.errorPages.deleteDescription')}
        confirmLabel={t('common.delete')}
        loading={remove.isPending}
      />
    </>
  )
}

/* ── Control-plane HTTPS ────────────────────────────────────────────── */

/**
 * Whether a certificate's SANs cover the host the console is open on.
 *
 * A wildcard covers exactly one label (`*.example.com` matches
 * `waf.example.com` but not `a.b.example.com`), mirroring how browsers match.
 * IP addresses only match a literal SAN, so a bare-IP deployment needs an IP
 * entry — which is why the self-signed generator adds one.
 */
function sanCoversHost(sans: string[], host: string): boolean {
  const target = host.trim().toLowerCase()
  if (!target) return true
  return sans.some((san) => {
    const value = san.trim().toLowerCase()
    if (!value) return false
    if (value === target) return true
    if (!value.startsWith('*.')) return false
    const suffix = value.slice(2)
    const dot = target.indexOf('.')
    return dot > 0 && target.slice(dot + 1) === suffix
  })
}

function TlsDetail({
  label,
  value,
  mono = false,
  className,
}: {
  label: string
  value: string
  mono?: boolean
  className?: string
}) {
  return (
    <div className={className}>
      <dt className="text-xs text-fg-subtle">{label}</dt>
      <dd className={cn('mt-0.5 break-all text-fg', mono && 'pw-mono text-xs')}>{value}</dd>
    </div>
  )
}

/**
 * The certificate the dashboard itself is served with.
 *
 * Passkeys (and the browser clipboard) require a secure origin, so this card is
 * the only place an operator can look at — and replace — the certificate
 * without touching the server's files. An upload takes effect immediately: the
 * running listener swaps the pair through its reloadable resolver.
 */
function ControlPlaneTlsCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [uploadOpen, setUploadOpen] = useState(false)
  const [regenOpen, setRegenOpen] = useState(false)
  const [certPem, setCertPem] = useState('')
  const [keyPem, setKeyPem] = useState('')

  const status = useQuery({
    queryKey: tlsKeys.status(),
    queryFn: () => tlsApi.getStatus(),
  })

  const view = status.data
  const certificate = view?.certificate ?? null

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: tlsKeys.all })
  }

  const upload = useMutation({
    mutationFn: () =>
      tlsApi.uploadCertificate({
        cert_pem: certPem.trim(),
        key_pem: keyPem.trim(),
      }),
    onSuccess: () => {
      invalidate()
      setUploadOpen(false)
      setCertPem('')
      setKeyPem('')
      toast.success(t('pages.settings.tlsUploaded'))
    },
  })

  const regenerate = useMutation({
    mutationFn: () => tlsApi.generateSelfSigned({}),
    onSuccess: () => {
      invalidate()
      setRegenOpen(false)
      toast.success(t('pages.settings.tlsGenerated'))
    },
  })

  const download = useMutation({
    mutationFn: () => tlsApi.downloadCertificate(),
    onSuccess: (pem) => {
      downloadCertificateFile(
        certificate?.source === 'self_signed'
          ? 'pingwaf-control-plane-self-signed.crt'
          : 'pingwaf-control-plane.crt',
        pem,
      )
      toast.success(t('pages.settings.tlsDownloaded'))
    },
  })

  const copyFingerprint = async () => {
    if (!certificate) return
    try {
      await navigator.clipboard.writeText(certificate.fingerprint_sha256)
      toast.success(t('pages.settings.copied'))
    } catch {
      toast.error(t('pages.settings.copyFailed'))
    }
  }

  const closeUpload = () => {
    if (upload.isPending) return
    setUploadOpen(false)
  }

  const selfSigned = certificate?.source === 'self_signed'
  const host = window.location.hostname
  const covered = certificate ? sanCoversHost(certificate.sans, host) : true
  const expiringSoon =
    certificate !== null &&
    certificate.expires_in_days <= 30 &&
    certificate.expires_in_days >= 0

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.controlPlaneTls')}
        description={t('pages.settings.controlPlaneTlsDescription')}
        action={
          view && (
            <Badge tone={view.enabled ? 'success' : 'neutral'} dot>
              {view.enabled
                ? t('pages.settings.tlsEnabled')
                : t('pages.settings.tlsDisabled')}
            </Badge>
          )
        }
      />
      <CardBody className="flex flex-col gap-5">
        {status.isError && !view ? (
          <ErrorState
            variant="inline"
            error={status.error}
            onRetry={() => status.refetch()}
            retrying={status.isFetching}
          />
        ) : !view ? (
          <SkeletonRows rows={3} columns={2} />
        ) : (
          <>
            {!view.enabled && (
              <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] text-fg">
                <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
                {t('pages.settings.tlsDisabledHint')}
              </p>
            )}
            {certificate && !covered && (
              <p className="flex items-start gap-2 rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg">
                <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-danger" />
                {t('pages.settings.tlsHostMismatch', { host })}
              </p>
            )}
            {selfSigned && (
              <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] text-fg">
                <ShieldCheck weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
                {t('pages.settings.tlsSelfSignedHint')}
              </p>
            )}
            {expiringSoon && (
              <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] text-fg">
                <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
                {t('pages.settings.tlsExpiringSoon', {
                  count: certificate?.expires_in_days ?? 0,
                })}
              </p>
            )}

            {certificate ? (
              <div className="rounded-md border border-line bg-recessed px-4 py-3">
                <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
                  <TlsDetail
                    label={t('pages.settings.tlsSource')}
                    value={
                      selfSigned
                        ? t('pages.settings.tlsSourceSelfSigned')
                        : t('pages.settings.tlsSourceUploaded')
                    }
                    className="sm:col-span-2"
                  />
                  <TlsDetail
                    label={t('pages.settings.tlsSubject')}
                    value={certificate.subject_dn}
                    mono
                    className="sm:col-span-2"
                  />
                  <TlsDetail
                    label={t('pages.settings.tlsValidity')}
                    value={`${formatDateTime(certificate.not_before)} → ${formatDateTime(certificate.not_after)}`}
                    className="sm:col-span-2"
                  />
                  <TlsDetail
                    label={t('pages.settings.tlsExpiresIn')}
                    value={t('pages.settings.tlsDays', {
                      count: certificate.expires_in_days,
                    })}
                  />
                  <TlsDetail
                    label={t('pages.settings.tlsSerial')}
                    value={certificate.serial}
                    mono
                  />
                  <TlsDetail
                    label={t('pages.settings.tlsFingerprint')}
                    value={certificate.fingerprint_sha256}
                    mono
                    className="sm:col-span-2"
                  />
                  <div className="sm:col-span-2">
                    <dt className="text-xs text-fg-subtle">
                      {t('pages.settings.tlsSans')}
                    </dt>
                    <dd className="mt-1 flex flex-wrap gap-1.5">
                      {certificate.sans.length === 0 ? (
                        <span className="text-[13px] text-fg-subtle">—</span>
                      ) : (
                        certificate.sans.map((san) => (
                          <Badge key={san} size="sm" tone="neutral" className="pw-mono">
                            {san}
                          </Badge>
                        ))
                      )}
                    </dd>
                  </div>
                </dl>
              </div>
            ) : (
              <EmptyState
                icon={<LockKey weight="duotone" />}
                title={t('pages.settings.tlsNoCertificate')}
                description={t('pages.settings.tlsNoCertificateDescription')}
                className="py-8"
              />
            )}

            <div className="flex flex-wrap gap-2">
              <Button
                variant="secondary"
                disabled={!certificate}
                loading={download.isPending}
                icon={<DownloadSimple weight="duotone" className="h-4 w-4" />}
                onClick={() => download.mutate()}
              >
                {t('pages.settings.tlsDownload')}
              </Button>
              <Button
                variant="ghost"
                disabled={!certificate}
                icon={<Copy weight="duotone" className="h-4 w-4" />}
                onClick={copyFingerprint}
              >
                {t('pages.settings.tlsCopyFingerprint')}
              </Button>
              <Button
                disabled={!canWrite}
                icon={<UploadSimple weight="duotone" className="h-4 w-4" />}
                onClick={() => setUploadOpen(true)}
              >
                {t('pages.settings.tlsUpload')}
              </Button>
              <Button
                variant="secondary"
                disabled={!canWrite}
                icon={<LockKey weight="duotone" className="h-4 w-4" />}
                onClick={() => setRegenOpen(true)}
              >
                {t('pages.settings.tlsGenerate')}
              </Button>
            </div>
            <p className="flex items-start gap-2 text-xs leading-relaxed text-fg-subtle">
              <Certificate weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
              {t('pages.settings.tlsApplyHint')}
            </p>
          </>
        )}
      </CardBody>

      <Dialog
        open={uploadOpen}
        onClose={closeUpload}
        size="md"
        title={t('pages.settings.tlsUploadTitle')}
        description={t('pages.settings.tlsUploadDescription')}
        footer={
          <>
            <Button variant="secondary" onClick={closeUpload} disabled={upload.isPending}>
              {t('common.cancel')}
            </Button>
            <Button
              loading={upload.isPending}
              disabled={!certPem.trim() || !keyPem.trim()}
              onClick={() => upload.mutate()}
            >
              {t('pages.settings.tlsUpload')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Textarea
            label={t('pages.settings.tlsCertPem')}
            hint={t('pages.settings.tlsCertPemHint')}
            mono
            rows={7}
            value={certPem}
            placeholder="-----BEGIN CERTIFICATE-----"
            onChange={(e) => setCertPem(e.target.value)}
          />
          <Textarea
            label={t('pages.settings.tlsKeyPem')}
            hint={t('pages.settings.tlsKeyPemHint')}
            mono
            rows={7}
            value={keyPem}
            placeholder="-----BEGIN PRIVATE KEY-----"
            onChange={(e) => setKeyPem(e.target.value)}
          />
          {upload.isError && (
            <p className="text-[13px] font-medium text-fg-danger">
              {errorMessage(upload.error)}
            </p>
          )}
        </div>
      </Dialog>

      <ConfirmDialog
        open={regenOpen}
        onClose={() => setRegenOpen(false)}
        onConfirm={() => regenerate.mutate()}
        tone="primary"
        title={t('pages.settings.tlsGenerateConfirmTitle')}
        description={t('pages.settings.tlsGenerateConfirm')}
        confirmLabel={t('pages.settings.tlsGenerate')}
        loading={regenerate.isPending}
      >
        {(view?.default_sans.length ?? 0) > 0 && (
          <p className="text-xs text-fg-subtle">
            {t('pages.settings.tlsDefaultSans')}:{' '}
            <span className="pw-mono">{view?.default_sans.join(', ')}</span>
          </p>
        )}
      </ConfirmDialog>
    </Card>
  )
}

/* ── Defense: observation mode ──────────────────────────────────────── */

/**
 * The global data-plane switch (the console twin of `pingwaf mode observe`):
 * every protection keeps detecting but only records. mTLS, basic auth and
 * suspended sites stay enforced, which is why this is a warning-toned toggle
 * rather than a plain setting.
 */
function ObservationModeCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const settings = useQuery({
    queryKey: apiProtectionKeys.defense(),
    queryFn: () => apiProtectionApi.getDefense(),
  })

  const save = useMutation({
    mutationFn: (payload: {
      observation_mode?: boolean
      default_fail_open?: boolean
    }) => apiProtectionApi.updateDefense(payload),
    onSuccess: (row) => {
      queryClient.setQueryData(apiProtectionKeys.defense(), row)
      toast.success(t('pages.settings.observationModeSaved'))
    },
  })

  const enabled = settings.data?.observation_mode ?? false
  const defaultFailOpen = settings.data?.default_fail_open ?? true

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.observationMode')}
        description={t('pages.settings.observationModeDescription')}
        action={
          settings.data && (
            <Badge tone={enabled ? 'warning' : 'success'} dot>
              {enabled
                ? t('pages.settings.observationModeOn')
                : t('pages.settings.observationModeOff')}
            </Badge>
          )
        }
      />
      <CardBody className="flex flex-col gap-4">
        {settings.isError && !settings.data ? (
          <ErrorState
            variant="inline"
            error={settings.error}
            onRetry={() => settings.refetch()}
            retrying={settings.isFetching}
          />
        ) : !settings.data ? (
          <SkeletonRows rows={2} columns={2} />
        ) : (
          <>
            <Switch
              checked={enabled}
              disabled={!canWrite || save.isPending}
              onCheckedChange={(next) => save.mutate({ observation_mode: next })}
              label={t('pages.settings.observationModeToggle')}
              description={t('pages.settings.observationModeToggleHint')}
            />
            <Switch
              checked={defaultFailOpen}
              disabled={!canWrite || save.isPending}
              onCheckedChange={(next) =>
                save.mutate({ default_fail_open: next })
              }
              label={t('pages.settings.defaultFailOpen')}
              description={t('pages.settings.defaultFailOpenHint')}
            />
            {enabled && (
              <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] text-fg">
                <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
                {t('pages.settings.observationModeBanner')}
              </p>
            )}
            <p className="flex items-start gap-2 text-xs leading-relaxed text-fg-subtle">
              <Eye weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
              {t('pages.settings.observationModeHint')}
            </p>
          </>
        )}
      </CardBody>
    </Card>
  )
}

/* ── Global cache ceiling ───────────────────────────────────────────── */

const CACHE_FILE_MAX = 1024
const CACHE_SPACE_MAX = 1024 * 1024
const CACHE_TTL_MAX = 30 * 24 * 3600

function CacheSettingsCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const settings = useQuery({
    queryKey: settingsKeys.cache(),
    queryFn: () => settingsApi.getCache(),
  })

  const [fileSize, setFileSize] = useState('')
  const [space, setSpace] = useState('')
  const [defaultTtl, setDefaultTtl] = useState('')
  const [errors, setErrors] = useState<Record<string, string>>({})

  const save = useMutation({
    mutationFn: (payload: {
      max_file_size_mb?: number
      max_space_mb?: number
      default_edge_ttl_seconds?: number
    }) => settingsApi.saveCache(payload),
    onSuccess: (row) => {
      queryClient.setQueryData(settingsKeys.cache(), row)
      setFileSize('')
      setSpace('')
      setDefaultTtl('')
      setErrors({})
      toast.success(t('pages.settings.cacheSaved'))
    },
    onError: () => toast.error(t('common.saveFailed')),
  })

  const toggleMaster = useMutation({
    mutationFn: (master_enabled: boolean) =>
      settingsApi.saveCache({ master_enabled }),
    onSuccess: (row) => {
      queryClient.setQueryData(settingsKeys.cache(), row)
      toast.success(t('pages.settings.cacheSaved'))
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  const data = settings.data
  const submit = () => {
    const next: Record<string, string> = {}
    const payload: {
      max_file_size_mb?: number
      max_space_mb?: number
      default_edge_ttl_seconds?: number
    } = {}
    if (fileSize !== '') {
      const value = Number(fileSize)
      if (!Number.isInteger(value) || value < 1 || value > CACHE_FILE_MAX) {
        next.fileSize = t('pages.settings.cacheFileSizeInvalid', {
          max: CACHE_FILE_MAX,
        })
      } else {
        payload.max_file_size_mb = value
      }
    }
    if (space !== '') {
      const value = Number(space)
      if (!Number.isInteger(value) || value < 0 || value > CACHE_SPACE_MAX) {
        next.space = t('pages.settings.cacheSpaceInvalid', {
          max: CACHE_SPACE_MAX,
        })
      } else {
        payload.max_space_mb = value
      }
    }
    if (defaultTtl !== '') {
      const value = Number(defaultTtl)
      if (!Number.isInteger(value) || value < 0 || value > CACHE_TTL_MAX) {
        next.defaultTtl = t('pages.settings.cacheTtlInvalid', {
          max: CACHE_TTL_MAX,
        })
      } else {
        payload.default_edge_ttl_seconds = value
      }
    }
    setErrors(next)
    if (Object.keys(next).length === 0 && Object.keys(payload).length > 0) {
      save.mutate(payload)
    }
  }

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.cache')}
        description={t('pages.settings.cacheDescription')}
        action={
          data && (
            <Badge tone={data.master_enabled ? 'success' : 'neutral'} dot>
              {data.master_enabled
                ? t('pages.settings.cacheOn')
                : t('pages.settings.cacheOff')}
            </Badge>
          )
        }
      />
      <CardBody className="flex flex-col gap-4">
        {settings.isError && !data ? (
          <ErrorState
            variant="inline"
            error={settings.error}
            onRetry={() => settings.refetch()}
            retrying={settings.isFetching}
          />
        ) : !data ? (
          <SkeletonRows rows={2} columns={2} />
        ) : (
          <>
            <Switch
              checked={data.master_enabled}
              disabled={!canWrite || toggleMaster.isPending}
              onCheckedChange={(next) => toggleMaster.mutate(next)}
              label={t('pages.settings.cacheMasterToggle')}
              description={t('pages.settings.cacheMasterToggleHint')}
            />
            <div className="grid gap-4 sm:grid-cols-3">
              <Input
                type="number"
                min={1}
                max={CACHE_FILE_MAX}
                label={t('pages.settings.cacheFileSize')}
                hint={t('pages.settings.cacheFileSizeHint', {
                  current: data.max_file_size_mb,
                })}
                value={fileSize === '' ? String(data.max_file_size_mb) : fileSize}
                onChange={(event) => setFileSize(event.target.value)}
                error={errors.fileSize}
                disabled={!canWrite || save.isPending}
              />
              <Input
                type="number"
                min={0}
                max={CACHE_SPACE_MAX}
                label={t('pages.settings.cacheSpace')}
                hint={t('pages.settings.cacheSpaceHint', {
                  current: data.max_space_mb,
                })}
                value={space === '' ? String(data.max_space_mb) : space}
                onChange={(event) => setSpace(event.target.value)}
                error={errors.space}
                disabled={!canWrite || save.isPending}
              />
              <Input
                type="number"
                min={0}
                max={CACHE_TTL_MAX}
                label={t('pages.settings.cacheTtl')}
                hint={t('pages.settings.cacheTtlHint', {
                  current: data.default_edge_ttl_seconds,
                })}
                value={
                  defaultTtl === ''
                    ? String(data.default_edge_ttl_seconds)
                    : defaultTtl
                }
                onChange={(event) => setDefaultTtl(event.target.value)}
                error={errors.defaultTtl}
                disabled={!canWrite || save.isPending}
              />
            </div>
            <div>
              <Button
                variant="primary"
                onClick={submit}
                disabled={
                  !canWrite ||
                  save.isPending ||
                  (fileSize === '' && space === '' && defaultTtl === '')
                }
              >
                {t('common.save')}
              </Button>
            </div>
            <p className="flex items-start gap-2 text-xs leading-relaxed text-fg-subtle">
              <Database weight="duotone" className="mt-0.5 h-4 w-4 shrink-0" />
              {t('pages.settings.cacheScopeHint')}
            </p>
          </>
        )}
      </CardBody>
    </Card>
  )
}

/* ── Origin TLS (how the data plane validates an origin certificate) ── */

function OriginTlsCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const settings = useQuery({
    queryKey: settingsKeys.origin(),
    queryFn: () => settingsApi.getOrigin(),
  })

  const save = useMutation({
    mutationFn: (verify_cert: boolean) => settingsApi.saveOrigin({ verify_cert }),
    onSuccess: (row) => {
      queryClient.setQueryData(settingsKeys.origin(), row)
      toast.success(t('pages.settings.originSaved'))
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  const data = settings.data

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.originTls')}
        description={t('pages.settings.originTlsDescription')}
        action={
          data && (
            <Badge tone={data.verify_cert ? 'success' : 'warning'} dot>
              {data.verify_cert
                ? t('pages.settings.originVerifyOn')
                : t('pages.settings.originVerifyOff')}
            </Badge>
          )
        }
      />
      <CardBody className="flex flex-col gap-4">
        {settings.isError && !data ? (
          <ErrorState
            variant="inline"
            error={settings.error}
            onRetry={() => settings.refetch()}
            retrying={settings.isFetching}
          />
        ) : !data ? (
          <SkeletonRows rows={1} columns={1} />
        ) : (
          <>
            <Switch
              checked={data.verify_cert}
              disabled={!canWrite || save.isPending}
              onCheckedChange={(next) => save.mutate(next)}
              label={t('pages.settings.originVerifyToggle')}
              description={t('pages.settings.originVerifyToggleHint')}
            />
            <p className="flex items-start gap-2 text-xs leading-relaxed text-fg-subtle">
              <ShieldCheck
                weight="duotone"
                className="mt-0.5 h-4 w-4 shrink-0"
              />
              {t('pages.settings.originScopeHint')}
            </p>
          </>
        )}
      </CardBody>
    </Card>
  )
}

/* ── API protection (control plane listener) ────────────────────────── */

interface ApiProtectionDraft {
  accessLogEnabled: boolean
  retentionDays: string
  allowlistEnabled: boolean
  rangesText: string
  groupId: string
  wafEnabled: boolean
  wafMode: string
}

function apiProtectionDraft(view: ApiProtectionView): ApiProtectionDraft {
  return {
    accessLogEnabled: view.access_log_enabled,
    retentionDays: String(view.access_log_retention_days),
    allowlistEnabled: view.ip_allowlist_enabled,
    rangesText: view.ip_allowlist_ranges.join('\n'),
    groupId: view.ip_allowlist_group_id ?? '',
    wafEnabled: view.waf_enabled,
    wafMode: view.waf_mode,
  }
}

/**
 * The control-plane listener's self-protection: access log, IP allowlist and WAF.
 *
 * Enabling the allowlist without covering the current connection is refused
 * by the server (422); we turn that refusal into an explicit "apply anyway"
 * dialog instead of a toast, because the consequence — locking every operator
 * out of the console — deserves a deliberate second click.
 */
function ApiProtectionCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [draft, setDraft] = useState<ApiProtectionDraft | null>(null)
  const [dirty, setDirty] = useState(false)
  const [forceOpen, setForceOpen] = useState(false)
  useRegisterUnsaved(dirty)

  const settings = useQuery({
    queryKey: apiProtectionKeys.settings(),
    queryFn: () => apiProtectionApi.get(),
  })

  const groups = useQuery({
    queryKey: ipGroupKeys.list(),
    queryFn: () => ipGroupsApi.list({ page_size: 200 }),
  })

  // Render-phase reseed on new query data (identity changes only when the
  // payload really differs — TanStack Query keeps structural sharing).
  const loaded = settings.data
  const [lastLoaded, setLastLoaded] = useState<typeof loaded | null>(null)
  if (loaded && loaded !== lastLoaded) {
    setLastLoaded(loaded)
    setDraft(apiProtectionDraft(loaded))
    setDirty(false)
  }

  const patch = (next: Partial<ApiProtectionDraft>) => {
    setDraft((current) => (current ? { ...current, ...next } : current))
    setDirty(true)
  }

  const retentionDays = Number(draft?.retentionDays ?? '')
  const retentionValid =
    Number.isInteger(retentionDays) &&
    retentionDays >= MIN_RETENTION_DAYS &&
    retentionDays <= MAX_RETENTION_DAYS

  const ranges = (draft?.rangesText ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)

  const group = groups.data?.items.find((g) => g.id === draft?.groupId)
  // A disabled group contributes nothing to the effective allowlist.
  const groupEntries = group?.enabled ? group.ip_ranges.length : 0
  const previewEntries = draft?.allowlistEnabled ? ranges.length + groupEntries : 0

  const collect = (): UpdateApiProtectionRequest => ({
    access_log_enabled: draft?.accessLogEnabled,
    access_log_retention_days: retentionDays,
    ip_allowlist_enabled: draft?.allowlistEnabled,
    ip_allowlist_ranges: ranges,
    ip_allowlist_group_id: draft?.groupId ?? '',
    waf_enabled: draft?.wafEnabled,
    waf_mode: draft?.wafMode,
  })

  const save = useMutation({
    // The 422 lockout refusal opens a dialog instead of a toast; other
    // failures go through the standard handler below.
    meta: { silentToast: true },
    mutationFn: (force: boolean) =>
      apiProtectionApi.update({ ...collect(), force }),
    onSuccess: (view) => {
      queryClient.setQueryData(apiProtectionKeys.settings(), view)
      setLastLoaded(view)
      setDraft(apiProtectionDraft(view))
      setDirty(false)
      setForceOpen(false)
      toast.success(t('pages.settings.apiProtectionSaved'))
    },
    onError: (err, force) => {
      if (!force && err instanceof ApiError && err.status === 422) {
        setForceOpen(true)
        return
      }
      handleApiError(err)
    },
  })

  const groupOptions = [
    { value: '', label: t('pages.settings.apiProtectionGroupNone') },
    ...(groups.data?.items ?? []).map((g) => ({
      value: g.id,
      label: g.enabled ? g.name : `${g.name} (${t('common.disabled')})`,
    })),
  ]

  const wafModes: { value: ApiProtectionWafMode; label: string }[] = [
    { value: 'block', label: t('pages.settings.apiProtectionWafModeBlock') },
    { value: 'monitor', label: t('pages.settings.apiProtectionWafModeMonitor') },
  ]

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.apiProtection')}
        description={t('pages.settings.apiProtectionDescription')}
        action={
          loaded && (
            <Badge
              tone={
                !loaded.ip_allowlist_enabled
                  ? 'neutral'
                  : loaded.effective_allowlist_entries === 0
                    ? 'warning'
                    : 'success'
              }
              dot
            >
              {loaded.ip_allowlist_enabled
                ? t('pages.settings.apiProtectionEffective', {
                    count: loaded.effective_allowlist_entries,
                  })
                : t('common.disabled')}
            </Badge>
          )
        }
      />
      <CardBody className="flex flex-col gap-5">
        {settings.isError && !loaded ? (
          <ErrorState
            variant="inline"
            error={settings.error}
            onRetry={() => settings.refetch()}
            retrying={settings.isFetching}
          />
        ) : !draft ? (
          <SkeletonRows rows={4} columns={2} />
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-2">
              <Switch
                checked={draft.accessLogEnabled}
                disabled={!canWrite}
                onCheckedChange={(value) => patch({ accessLogEnabled: value })}
                label={t('pages.settings.apiProtectionAccessLog')}
                description={t('pages.settings.apiProtectionAccessLogHint')}
              />
              <Input
                type="number"
                label={t('pages.settings.apiProtectionRetention')}
                value={draft.retentionDays}
                min={MIN_RETENTION_DAYS}
                max={MAX_RETENTION_DAYS}
                disabled={!canWrite || !draft.accessLogEnabled}
                onChange={(e) => patch({ retentionDays: e.target.value })}
              />
            </div>
            {!retentionValid && (
              <p className="flex items-center gap-2 text-xs text-fg-danger">
                <Warning weight="duotone" className="h-4 w-4 shrink-0" />
                {t('pages.settings.logRetentionRange')}
              </p>
            )}

            <div className="flex flex-col gap-4 border-t border-line pt-4">
              <Switch
                checked={draft.allowlistEnabled}
                disabled={!canWrite}
                onCheckedChange={(value) => patch({ allowlistEnabled: value })}
                label={t('pages.settings.apiProtectionAllowlist')}
                description={t('pages.settings.apiProtectionAllowlistHint')}
              />
              <Textarea
                label={t('pages.settings.apiProtectionRanges')}
                hint={t('pages.settings.apiProtectionRangesHint')}
                mono
                rows={4}
                value={draft.rangesText}
                placeholder={'203.0.113.4\n10.0.0.0/8'}
                disabled={!canWrite || !draft.allowlistEnabled}
                onChange={(e) => patch({ rangesText: e.target.value })}
              />
              <div className="grid gap-4 sm:grid-cols-2">
                <Select
                  label={t('pages.settings.apiProtectionGroup')}
                  value={draft.groupId}
                  options={groupOptions}
                  hint={t('pages.settings.apiProtectionGroupHint')}
                  disabled={!canWrite || !draft.allowlistEnabled}
                  onChange={(e) => patch({ groupId: e.target.value })}
                />
                <div className="flex items-end pb-1">
                  <span className="text-xs text-fg-subtle">
                    {t('pages.settings.apiProtectionEffective', {
                      count: previewEntries,
                    })}
                  </span>
                </div>
              </div>
              {draft.allowlistEnabled && previewEntries === 0 && (
                <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] text-fg">
                  <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
                  {t('pages.settings.apiProtectionEmptyWarning')}
                </p>
              )}
            </div>

            <div className="grid gap-4 border-t border-line pt-4 sm:grid-cols-2">
              <Switch
                checked={draft.wafEnabled}
                disabled={!canWrite}
                onCheckedChange={(value) => patch({ wafEnabled: value })}
                label={t('pages.settings.apiProtectionWaf')}
                description={t('pages.settings.apiProtectionWafHint')}
              />
              <Select
                label={t('pages.settings.apiProtectionWafMode')}
                value={draft.wafMode}
                options={wafModes}
                disabled={!canWrite || !draft.wafEnabled}
                onChange={(e) => patch({ wafMode: e.target.value })}
              />
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-line pt-4">
              <Button
                variant="primary"
                size="sm"
                disabled={!canWrite || !dirty || !retentionValid}
                loading={save.isPending}
                icon={<ShieldCheck weight="duotone" className="h-4 w-4" />}
                onClick={() => save.mutate(false)}
              >
                {t('common.save')}
              </Button>
            </div>
          </>
        )}
      </CardBody>

      <ConfirmDialog
        open={forceOpen}
        onClose={() => setForceOpen(false)}
        onConfirm={() => save.mutate(true)}
        title={t('pages.settings.apiProtectionLockoutTitle')}
        description={t('pages.settings.apiProtectionLockoutDescription')}
        confirmLabel={t('pages.settings.apiProtectionForceApply')}
        loading={save.isPending}
      />
    </Card>
  )
}

/* ── AI assistant ───────────────────────────────────────────────────── */

/** Mirrors the server-side bounds in `api::ai` / `models::ai`. */
const AI_MAX_TEMPERATURE = 2
const AI_MAX_TOOL_ROUNDS = 10

interface AiDraft {
  enabled: boolean
  baseUrl: string
  apiKey: string
  model: string
  temperature: string
  maxToolRounds: string
  allowWriteTools: boolean
  systemPrompt: string
}

function aiDraft(view: AiSettings): AiDraft {
  return {
    enabled: view.enabled,
    baseUrl: view.base_url,
    // Blank means "keep the stored key" — the `api_key: null` round-trip,
    // same treatment as the Elasticsearch secrets.
    apiKey: '',
    model: view.model,
    temperature: String(view.temperature),
    maxToolRounds: String(view.max_tool_rounds),
    allowWriteTools: view.allow_write_tools,
    systemPrompt: view.system_prompt,
  }
}

/**
 * The AI assistant's provider — the console half of the built-in agent.
 *
 * The assistant shares the MCP tool registry and answers on the AI Assistant
 * page. `allow_write_tools` hands it the site-mutating half of that registry,
 * so an enabled switch gets an explicit warning instead of a plain label.
 */
function AiAssistantCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [draft, setDraft] = useState<AiDraft | null>(null)
  const [dirty, setDirty] = useState(false)
  const [testResult, setTestResult] = useState<AiTestResult | null>(null)
  useRegisterUnsaved(dirty)

  const settings = useQuery({
    queryKey: aiKeys.settings(),
    queryFn: () => aiApi.getSettings(),
  })

  // Render-phase reseed on new query data (identity changes only when the
  // payload really differs — TanStack Query keeps structural sharing).
  const loaded = settings.data
  const [lastLoaded, setLastLoaded] = useState<typeof loaded | null>(null)
  if (loaded && loaded !== lastLoaded) {
    setLastLoaded(loaded)
    setDraft(aiDraft(loaded))
    setDirty(false)
    setTestResult(null)
  }

  const patch = (next: Partial<AiDraft>) => {
    setDraft((d) => (d ? { ...d, ...next } : d))
    setDirty(true)
  }

  const temperature = Number(draft?.temperature ?? '')
  const temperatureValid =
    Number.isFinite(temperature) &&
    temperature >= 0 &&
    temperature <= AI_MAX_TEMPERATURE
  const rounds = Number(draft?.maxToolRounds ?? '')
  const roundsValid = Number.isInteger(rounds) && rounds >= 1 && rounds <= AI_MAX_TOOL_ROUNDS
  const baseUrl = (draft?.baseUrl ?? '').trim()
  const baseUrlFilled = /^https?:\/\//.test(baseUrl)
  const modelFilled = (draft?.model ?? '').trim() !== ''
  const keyStored = loaded?.api_key === SECRET_MASK
  const keyFilled = keyStored || (draft?.apiKey ?? '').trim() !== ''
  // An enabled assistant must be fully reachable; the server enforces the
  // same rule, so refuse locally first.
  const valid =
    temperatureValid &&
    roundsValid &&
    (draft?.enabled ? baseUrlFilled : baseUrl === '' || baseUrlFilled) &&
    (draft?.enabled ? modelFilled : true) &&
    (draft?.enabled ? keyFilled : true)
  const testable = temperatureValid && roundsValid && baseUrlFilled && modelFilled && keyFilled

  // The prompt arrives prefilled with whatever is in effect — the stored
  // override, or the built-in default. Omitting it while untouched keeps
  // "no override" stored as no override, instead of freezing today's default
  // text into the row.
  const systemPrompt = (draft?.systemPrompt ?? '').trim()
  const collect = (): UpdateAiSettingsRequest => ({
    enabled: draft?.enabled,
    base_url: baseUrl,
    api_key: draft?.apiKey.trim() ? draft.apiKey : null,
    model: (draft?.model ?? '').trim(),
    temperature,
    max_tool_rounds: rounds,
    allow_write_tools: draft?.allowWriteTools,
    system_prompt:
      systemPrompt === (loaded?.system_prompt ?? '') ? undefined : systemPrompt,
  })

  const save = useMutation({
    mutationFn: () => aiApi.saveSettings(collect()),
    onSuccess: (view) => {
      queryClient.setQueryData(aiKeys.settings(), view)
      setTestResult(null)
      toast.success(t('pages.settings.aiSaved'))
    },
  })

  const testDraft = useMutation({
    mutationFn: () => aiApi.test(collect()),
    onSuccess: (result) => setTestResult(result),
  })

  const invalidHint = !temperatureValid
    ? t('pages.settings.aiTemperatureRange')
    : !roundsValid
      ? t('pages.settings.aiMaxToolRoundsRange')
      : draft?.enabled && !baseUrlFilled
        ? t('pages.settings.aiBaseUrlInvalid')
        : draft?.enabled && !modelFilled
          ? t('pages.settings.aiModelRequired')
          : draft?.enabled && !keyFilled
            ? t('pages.settings.aiApiKeyRequired')
            : null

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.aiAssistant')}
        description={t('pages.settings.aiAssistantDescription')}
        action={
          loaded && (
            <Badge tone={loaded.enabled ? 'success' : 'neutral'} dot>
              {loaded.enabled ? t('common.enabled') : t('common.disabled')}
            </Badge>
          )
        }
      />
      <CardBody className="flex flex-col gap-5">
        {settings.isError && !loaded ? (
          <ErrorState
            variant="inline"
            error={settings.error}
            onRetry={() => settings.refetch()}
            retrying={settings.isFetching}
          />
        ) : !draft ? (
          <SkeletonRows rows={4} columns={2} />
        ) : (
          <>
            <Switch
              checked={draft.enabled}
              disabled={!canWrite}
              onCheckedChange={(value) => patch({ enabled: value })}
              label={t('pages.settings.aiEnabled')}
              description={t('pages.settings.aiEnabledHint')}
            />

            <div className="grid gap-4 sm:grid-cols-2">
              <Input
                label={t('pages.settings.aiBaseUrl')}
                value={draft.baseUrl}
                placeholder="https://api.openai.com/v1"
                hint={t('pages.settings.aiBaseUrlHint')}
                className="pw-mono text-[13px]"
                disabled={!canWrite}
                onChange={(e) => patch({ baseUrl: e.target.value })}
              />
              <Input
                label={t('pages.settings.aiModel')}
                value={draft.model}
                placeholder="gpt-4o-mini"
                className="pw-mono text-[13px]"
                disabled={!canWrite}
                onChange={(e) => patch({ model: e.target.value })}
              />
              <Input
                type="password"
                label={t('pages.settings.aiApiKey')}
                value={draft.apiKey}
                autoComplete="new-password"
                placeholder={keyStored ? t('pages.settings.secretStored') : ''}
                hint={t('pages.settings.aiApiKeyHint')}
                disabled={!canWrite}
                onChange={(e) => patch({ apiKey: e.target.value })}
              />
              <div className="grid grid-cols-2 gap-4">
                <Input
                  type="number"
                  label={t('pages.settings.aiTemperature')}
                  value={draft.temperature}
                  min={0}
                  max={AI_MAX_TEMPERATURE}
                  step={0.1}
                  hint={t('pages.settings.aiTemperatureHint')}
                  disabled={!canWrite}
                  onChange={(e) => patch({ temperature: e.target.value })}
                />
                <Input
                  type="number"
                  label={t('pages.settings.aiMaxToolRounds')}
                  value={draft.maxToolRounds}
                  min={1}
                  max={AI_MAX_TOOL_ROUNDS}
                  hint={t('pages.settings.aiMaxToolRoundsHint')}
                  disabled={!canWrite}
                  onChange={(e) => patch({ maxToolRounds: e.target.value })}
                />
              </div>
            </div>

            {invalidHint && (
              <p className="flex items-center gap-2 text-xs text-fg-danger">
                <Warning weight="duotone" className="h-4 w-4 shrink-0" />
                {invalidHint}
              </p>
            )}

            <Switch
              checked={draft.allowWriteTools}
              disabled={!canWrite}
              onCheckedChange={(value) => patch({ allowWriteTools: value })}
              label={t('pages.settings.aiAllowWriteTools')}
              description={t('pages.settings.aiAllowWriteToolsHint')}
            />
            {draft.allowWriteTools && (
              <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] text-fg">
                <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
                {t('pages.settings.aiAllowWriteToolsWarning')}
              </p>
            )}

            <Textarea
              label={t('pages.settings.aiSystemPrompt')}
              hint={t('pages.settings.aiSystemPromptHint')}
              rows={4}
              value={draft.systemPrompt}
              placeholder={t('pages.settings.aiSystemPromptPlaceholder')}
              disabled={!canWrite}
              onChange={(e) => patch({ systemPrompt: e.target.value })}
            />

            {testResult && (
              <div
                className={cn(
                  'rounded-md border px-3 py-2 text-[13px]',
                  testResult.ok
                    ? 'border-success/40 bg-success/8 text-fg'
                    : 'border-danger/40 bg-danger/8 text-fg-danger',
                )}
              >
                <p className="font-medium">
                  {testResult.ok
                    ? t('pages.settings.aiTestOk')
                    : t('pages.settings.aiTestFailed')}
                </p>
                {testResult.error && (
                  <p className="pw-mono mt-1 break-all text-xs">{testResult.error}</p>
                )}
                {testResult.reply && (
                  <p className="mt-1 text-xs text-fg-subtle">
                    {t('pages.settings.aiTestReply')}: {testResult.reply}
                  </p>
                )}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2 border-t border-line pt-4">
              <Button
                variant="primary"
                disabled={!canWrite || !dirty || !valid}
                loading={save.isPending}
                icon={<Sparkle weight="duotone" className="h-4 w-4" />}
                onClick={() => save.mutate()}
              >
                {t('common.save')}
              </Button>
              <Button
                variant="secondary"
                disabled={!canWrite || !testable}
                loading={testDraft.isPending}
                icon={<PlugsConnected weight="duotone" className="h-4 w-4" />}
                onClick={() => testDraft.mutate()}
              >
                {t('pages.settings.testDraft')}
              </Button>
              {dirty && (
                <span className="text-xs text-fg-warning">{t('pages.settings.unsavedChanges')}</span>
              )}
            </div>
          </>
        )}
      </CardBody>
    </Card>
  )
}

/* ── MCP server ─────────────────────────────────────────────────────── */

/** One copyable snippet with a caption header, shared by the MCP card. */
function SnippetBlock({
  caption,
  code,
  onCopy,
}: {
  caption: string
  code: string
  onCopy: (value: string) => void
}) {
  const { t } = useTranslation()
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-fg-subtle">{caption}</span>
        <Button
          size="sm"
          variant="ghost"
          aria-label={`${t('pages.settings.copy')}: ${caption}`}
          icon={<Copy weight="duotone" className="h-3.5 w-3.5" />}
          onClick={() => onCopy(code)}
        >
          {t('pages.settings.copy')}
        </Button>
      </div>
      <pre className="pw-mono break-all whitespace-pre-wrap rounded-md border border-line bg-recessed px-3 py-2 text-xs text-fg">
        {code}
      </pre>
    </div>
  )
}

/**
 * The built-in MCP endpoint, as clients see it.
 *
 * The catalogue is compiled into the binary, so there is no switch to flip
 * here — the card reports what the endpoint exposes and hands out copyable
 * client snippets whose only variable is an API key. Viewers can connect
 * read-only, so the card is visible to everyone; key management lives in
 * the API keys card below, hence the jump link.
 */
function McpCard() {
  const { t } = useTranslation()
  const toast = useToast()

  const status = useQuery({
    queryKey: mcpKeys.status(),
    queryFn: () => mcpApi.status(),
  })

  const view = status.data
  const endpoint = view ? `${window.location.origin}${view.path}` : ''
  const writeTools = view?.tools.filter((tool) => tool.write).length ?? 0
  const configSnippet = JSON.stringify(
    {
      mcpServers: {
        pingwaf: {
          url: endpoint,
          headers: { Authorization: 'Bearer pwk_YOUR_KEY' },
        },
      },
    },
    null,
    2,
  )
  const cliSnippet = `claude mcp add --transport http pingwaf ${endpoint} \\\n  --header "Authorization: Bearer pwk_YOUR_KEY"`

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      toast.success(t('pages.settings.copied'))
    } catch {
      toast.error(t('pages.settings.copyFailed'))
    }
  }

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.mcp')}
        description={t('pages.settings.mcpDescription')}
        action={
          view && (
            <Badge tone="success" dot>
              {t('pages.settings.mcpRunning')}
            </Badge>
          )
        }
      />
      <CardBody className="flex flex-col gap-5">
        {status.isError && !view ? (
          <ErrorState
            variant="inline"
            error={status.error}
            onRetry={() => status.refetch()}
            retrying={status.isFetching}
          />
        ) : !view ? (
          <SkeletonRows rows={3} columns={2} />
        ) : (
          <>
            <div>
              <p className="mb-1.5 text-xs font-medium text-fg-subtle">
                {t('pages.settings.mcpEndpoint')}
              </p>
              <div className="flex items-center gap-2">
                <code className="pw-mono min-w-0 flex-1 truncate rounded-md border border-line bg-recessed px-3 py-2 text-xs text-fg">
                  {endpoint}
                </code>
                <Button
                  size="icon"
                  variant="secondary"
                  aria-label={`${t('pages.settings.copy')}: ${t('pages.settings.mcpEndpoint')}`}
                  icon={<Copy weight="duotone" className="h-4 w-4" />}
                  onClick={() => copy(endpoint)}
                />
              </div>
            </div>

            <dl className="grid gap-4 text-[13px] sm:grid-cols-2">
              <div>
                <dt className="text-xs font-medium text-fg-subtle">
                  {t('pages.settings.mcpTransport')}
                </dt>
                <dd className="mt-1 text-fg">{t('pages.settings.mcpTransportValue')}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium text-fg-subtle">
                  {t('pages.settings.mcpAuth')}
                </dt>
                <dd className="mt-1 text-fg">{t('pages.settings.mcpAuthValue')}</dd>
              </div>
            </dl>

            <p className="text-[13px] text-fg-subtle">
              {t('pages.settings.mcpCapabilities', {
                tools: view.tools.length,
                write: writeTools,
                prompts: view.prompts,
                resources: view.resources,
              })}
            </p>

            <div>
              <p className="mb-1.5 text-xs font-medium text-fg-subtle">
                {t('pages.settings.mcpTools')}
              </p>
              <div className="flex flex-wrap gap-1.5">
                {view.tools.map((tool) => (
                  <span
                    key={tool.name}
                    className="inline-flex items-center gap-1.5 rounded-md border border-line bg-elevated px-2 py-1"
                  >
                    <code className="pw-mono text-xs text-fg">{tool.name}</code>
                    {tool.write && (
                      <Badge size="sm" tone="warning">
                        {t('pages.settings.mcpWriteTag')}
                      </Badge>
                    )}
                  </span>
                ))}
              </div>
            </div>

            <SnippetBlock
              caption={t('pages.settings.mcpClientConfig')}
              code={configSnippet}
              onCopy={copy}
            />
            <SnippetBlock
              caption={t('pages.settings.mcpCli')}
              code={cliSnippet}
              onCopy={copy}
            />

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4">
              <p className="max-w-xl text-xs leading-relaxed text-fg-subtle">
                {t('pages.settings.mcpNote')}
              </p>
              <Button
                size="sm"
                variant="secondary"
                icon={<Key weight="duotone" className="h-4 w-4" />}
                onClick={() =>
                  document
                    .getElementById('api-keys')
                    ?.scrollIntoView({ behavior: 'smooth', block: 'start' })
                }
              >
                {t('pages.settings.mcpManageKeys')}
              </Button>
            </div>
          </>
        )}
      </CardBody>
    </Card>
  )
}

/* ── About ──────────────────────────────────────────────────────────── */

function AboutCard() {
  const { t } = useTranslation()
  const toast = useToast()

  const version = useQuery({
    queryKey: ['system', 'version'],
    queryFn: () => systemApi.version(),
  })

  const view = version.data

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      toast.success(t('pages.settings.copied'))
    } catch {
      toast.error(t('pages.settings.copyFailed'))
    }
  }

  return (
    <Card>
      <CardHeader title={t('pages.settings.about')} description={t('pages.settings.aboutDescription')} />
      <CardBody className="flex flex-col gap-5">
        {version.isError && !view ? (
          <ErrorState
            variant="inline"
            error={version.error}
            onRetry={() => version.refetch()}
            retrying={version.isFetching}
          />
        ) : !view ? (
          <SkeletonRows rows={3} columns={2} />
        ) : (
          <>
            {!view.grpc_tls && (
              <p className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/8 px-3 py-2 text-[13px] leading-relaxed text-fg">
                <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
                {t('pages.settings.aboutGrpcPlaintext')}
              </p>
            )}
            <dl className="grid gap-4 text-[13px] sm:grid-cols-2">
              <div>
                <dt className="text-xs font-medium text-fg-subtle">{t('pages.settings.aboutProduct')}</dt>
                <dd className="mt-1 flex items-center gap-2 text-fg">
                  <ShieldCheck weight="duotone" className="h-4 w-4 text-brand" />
                  PingWAF
                  <Badge tone="brand">{view.version}</Badge>
                </dd>
              </div>
              <div>
                <dt className="text-xs font-medium text-fg-subtle">{t('pages.settings.aboutUpstream')}</dt>
                <dd className="mt-1 flex items-center gap-2 text-fg">
                  <span>{t('pages.settings.aboutUpstreamValue')}</span>
                  <a
                    href={UPSTREAM_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-brand hover:underline"
                  >
                    Cloudflare Pingora
                    <ArrowSquareOut weight="duotone" className="h-3.5 w-3.5" />
                  </a>
                  <Button
                    size="icon"
                    variant="secondary"
                    aria-label={`${t('pages.settings.copy')}: ${t('pages.settings.aboutUpstream')}`}
                    icon={<Copy weight="duotone" className="h-4 w-4" />}
                    onClick={() => copy(UPSTREAM_URL)}
                  />
                </dd>
              </div>
            </dl>

            <p className="flex items-start gap-2 rounded-md border border-line bg-recessed px-3 py-2 text-[13px] leading-relaxed text-fg-subtle">
              <ShieldCheck weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-brand" />
              {t('pages.settings.aboutAttribution')}
            </p>

            <div>
              <p className="mb-1.5 text-xs font-medium text-fg-subtle">
                {t('pages.settings.aboutProject')}
              </p>
              <div className="flex items-center gap-2">
                <code className="pw-mono min-w-0 flex-1 truncate rounded-md border border-line bg-recessed px-3 py-2 text-xs text-fg">
                  {PROJECT_URL}
                </code>
                <Button
                  size="icon"
                  variant="secondary"
                  aria-label={`${t('pages.settings.copy')}: ${t('pages.settings.aboutProject')}`}
                  icon={<Copy weight="duotone" className="h-4 w-4" />}
                  onClick={() => copy(PROJECT_URL)}
                />
                <Button
                  size="icon"
                  variant="secondary"
                  aria-label={t('pages.settings.aboutOpenProject')}
                  icon={<ArrowSquareOut weight="duotone" className="h-4 w-4" />}
                  onClick={() => window.open(PROJECT_URL, '_blank', 'noopener,noreferrer')}
                />
              </div>
            </div>

            <div className="flex items-center gap-2 border-t border-line pt-4">
              <GithubLogo weight="duotone" className="h-4 w-4 shrink-0 text-fg-subtle" />
              <p className="text-xs leading-relaxed text-fg-subtle">
                {t('pages.settings.aboutNote')}
              </p>
            </div>
          </>
        )}
      </CardBody>
    </Card>
  )
}

export default SettingsPage
