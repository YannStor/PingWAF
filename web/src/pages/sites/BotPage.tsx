import { useState, type FormEvent, type ReactNode } from 'react'
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
import { ipGroupsApi, ipGroupKeys } from '@/api/ipGroups'
import { useCanWrite } from '@/hooks'
import { BOT_ACTIONS, type BotConfig } from '@/api/types'

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
        </div>
      ) : null}
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
