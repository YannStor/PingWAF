import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  Eye,
  EyeSlash,
  Key,
  LockSimple,
  Plus,
  Trash,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { useUnsavedGuard } from '@/hooks/useUnsavedGuard'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import {
  siteBasicAuthApi,
  siteBasicAuthKeys,
  defaultSiteBasicAuth,
} from '@/api/siteBasicAuth'
import { useCanWrite } from '@/hooks'
import {
  BASIC_AUTH_MAX_DELAY_SECONDS,
  BASIC_AUTH_MIN_DELAY_SECONDS,
  BASIC_AUTH_SECRET_MASK,
  type BasicAuthCredential,
  type SiteBasicAuth,
} from '@/api/types'

/** One credential row being edited; `stored` marks a password the API masked. */
interface CredentialRow {
  username: string
  password: string
  stored: boolean
}

function rowsFrom(config: SiteBasicAuth): CredentialRow[] {
  return config.credentials.map((credential) => ({
    username: credential.username,
    password: credential.password,
    stored: credential.password === BASIC_AUTH_SECRET_MASK,
  }))
}

function rowsToCredentials(rows: CredentialRow[]): BasicAuthCredential[] {
  return rows.map((row) => ({
    username: row.username,
    password: row.password,
  }))
}

/** The basic auth module of the site's access-control tab. */
export function BasicAuthPanel() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const [config, setConfig] = useState<SiteBasicAuth | null>(null)
  const [rows, setRows] = useState<CredentialRow[]>([])
  const [dirty, setDirty] = useState(false)
  const [revealed, setRevealed] = useState<Set<number>>(new Set())

  const configQuery = useQuery({
    queryKey: siteBasicAuthKeys.detail(siteId),
    queryFn: () => siteBasicAuthApi.get(siteId),
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
      setRows(rowsFrom(serverConfig))
      setDirty(false)
      setRevealed(new Set())
    } else if (loadFailed) {
      setConfig(defaultSiteBasicAuth(siteId))
      setRows([])
      setDirty(false)
    }
  }

  const patch = (part: Partial<SiteBasicAuth>) => {
    setConfig((c) => (c ? { ...c, ...part } : c))
    setDirty(true)
  }

  const updateRow = (index: number, part: Partial<CredentialRow>) => {
    setRows((current) =>
      current.map((row, i) =>
        i === index ? { ...row, ...part, stored: false } : row,
      ),
    )
    setDirty(true)
  }

  const addRow = () => {
    setRows((current) => [
      ...current,
      { username: '', password: '', stored: false },
    ])
    setDirty(true)
  }

  const removeRow = (index: number) => {
    setRows((current) => current.filter((_, i) => i !== index))
    setRevealed((current) => {
      const next = new Set<number>()
      for (const i of current) {
        if (i < index) next.add(i)
        else if (i > index) next.add(i - 1)
      }
      return next
    })
    setDirty(true)
  }

  const toggleReveal = (index: number) => {
    setRevealed((current) => {
      const next = new Set(current)
      if (next.has(index)) next.delete(index)
      else next.add(index)
      return next
    })
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({
      queryKey: siteBasicAuthKeys.all,
    })
  }

  const save = useMutation({
    mutationFn: (payload: SiteBasicAuth) =>
      siteBasicAuthApi.update(siteId, {
        enabled: payload.enabled,
        realm: payload.realm,
        credentials: rowsToCredentials(rows),
        delay_seconds: payload.delay_seconds,
        hide_credentials: payload.hide_credentials,
      }),
    onSuccess: (saved) => {
      setConfig(saved)
      setRows(rowsFrom(saved))
      setDirty(false)
      setRevealed(new Set())
      toast.success(t('pages.basicAuth.saved'))
      invalidate()
    },
  })

  const unsavedDialog = useUnsavedGuard(dirty)

  // Mirrors the control plane: an enabled gate with no credential would lock
  // everyone out, so the save button stays off until one is configured.
  const usableCredentials = rows.filter(
    (row) => row.username.trim() !== '' && row.password !== '',
  ).length
  const blockedReason =
    config?.enabled && rows.length === 0
      ? t('pages.basicAuth.credentialsRequired')
      : rows.some((row) => row.username.trim() === '')
        ? t('pages.basicAuth.usernameRequired')
        : rows.some((row) => row.password === '')
          ? t('pages.basicAuth.passwordRequired')
          : undefined

  return (
    <div>
      {unsavedDialog}
      <div className="mb-4 flex items-center justify-end gap-2">
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
            disabled={!dirty || save.isPending || Boolean(blockedReason)}
            loading={save.isPending}
            onClick={() => config && save.mutate(config)}
          >
            {t('common.save')}
          </Button>
        )}
      </div>

      {configQuery.isError && !config ? (
        <ErrorState
          error={configQuery.error}
          onRetry={() => configQuery.refetch()}
          retrying={configQuery.isFetching}
        />
      ) : !config ? (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_360px]">
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_360px]">
          <div className="flex flex-col gap-6">
            {/* Credentials */}
            <Card>
              <CardHeader
                title={t('pages.basicAuth.credentials')}
                description={t('pages.basicAuth.credentialsHint')}
                action={
                  <Badge
                    tone={config.enabled ? 'success' : 'neutral'}
                    dot
                    size="sm"
                  >
                    {config.enabled ? t('common.enabled') : t('common.disabled')}
                  </Badge>
                }
              />
              <CardBody className="flex flex-col gap-4">
                {rows.length === 0 ? (
                  <EmptyState
                    icon={<Key weight="duotone" className="h-6 w-6" />}
                    title={t('pages.basicAuth.emptyTitle')}
                    description={t('pages.basicAuth.emptyHint')}
                    action={
                      canWrite && (
                        <Button
                          variant="secondary"
                          onClick={addRow}
                          icon={<Plus weight="duotone" className="h-4 w-4" />}
                        >
                          {t('pages.basicAuth.addCredential')}
                        </Button>
                      )
                    }
                  />
                ) : (
                  <>
                    <div className="flex flex-col gap-3">
                      {rows.map((row, index) => (
                        <div
                          key={index}
                          className="grid grid-cols-1 items-start gap-3 sm:grid-cols-[1fr_1fr_auto]"
                        >
                          <Input
                            label={t('pages.basicAuth.username')}
                            value={row.username}
                            disabled={!canWrite}
                            autoComplete="off"
                            onChange={(e) =>
                              updateRow(index, { username: e.target.value })
                            }
                          />
                          <Input
                            label={t('pages.basicAuth.password')}
                            type={revealed.has(index) ? 'text' : 'password'}
                            value={row.password}
                            disabled={!canWrite}
                            autoComplete="new-password"
                            placeholder={
                              row.stored ? t('pages.basicAuth.storedPassword') : undefined
                            }
                            suffixIcon={
                              <button
                                type="button"
                                onClick={() => toggleReveal(index)}
                                aria-label={
                                  revealed.has(index)
                                    ? t('auth.hidePassword')
                                    : t('auth.showPassword')
                                }
                                className="transition-colors hover:text-fg"
                              >
                                {revealed.has(index) ? (
                                  <EyeSlash weight="duotone" />
                                ) : (
                                  <Eye weight="duotone" />
                                )}
                              </button>
                            }
                            onChange={(e) =>
                              updateRow(index, { password: e.target.value })
                            }
                          />
                          <div className="pt-6">
                            {canWrite && (
                              <Button
                                variant="ghost"
                                aria-label={t('pages.basicAuth.removeCredential')}
                                onClick={() => removeRow(index)}
                                icon={<Trash weight="duotone" className="h-4 w-4" />}
                              />
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                    {canWrite && (
                      <div>
                        <Button
                          variant="secondary"
                          onClick={addRow}
                          icon={<Plus weight="duotone" className="h-4 w-4" />}
                        >
                          {t('pages.basicAuth.addCredential')}
                        </Button>
                      </div>
                    )}
                    <p className="text-xs text-fg-subtle">
                      {t('pages.basicAuth.credentialsCount', {
                        count: usableCredentials,
                      })}
                    </p>
                  </>
                )}
                {blockedReason && (
                  <p className="text-xs text-fg-danger">{blockedReason}</p>
                )}
              </CardBody>
            </Card>
          </div>

          {/* Behaviour */}
          <div className="flex flex-col gap-6">
            <Card>
              <CardHeader
                title={t('pages.basicAuth.behaviour')}
                description={t('pages.basicAuth.behaviourHint')}
              />
              <CardBody className="flex flex-col gap-5">
                <Switch
                  checked={config.enabled}
                  disabled={!canWrite}
                  onCheckedChange={(enabled) => patch({ enabled })}
                  label={t('pages.basicAuth.enabled')}
                  description={t('pages.basicAuth.enabledHint')}
                />
                <Input
                  label={t('pages.basicAuth.realm')}
                  value={config.realm}
                  disabled={!canWrite}
                  hint={t('pages.basicAuth.realmHint')}
                  onChange={(e) => patch({ realm: e.target.value })}
                />
                <Input
                  label={t('pages.basicAuth.delay')}
                  type="number"
                  min={BASIC_AUTH_MIN_DELAY_SECONDS}
                  max={BASIC_AUTH_MAX_DELAY_SECONDS}
                  value={config.delay_seconds}
                  disabled={!canWrite}
                  hint={t('pages.basicAuth.delayHint')}
                  onChange={(e) =>
                    patch({
                      delay_seconds: Math.min(
                        BASIC_AUTH_MAX_DELAY_SECONDS,
                        Math.max(
                          BASIC_AUTH_MIN_DELAY_SECONDS,
                          Number(e.target.value) || 0,
                        ),
                      ),
                    })
                  }
                />
                <Switch
                  checked={config.hide_credentials}
                  disabled={!canWrite}
                  onCheckedChange={(hide_credentials) =>
                    patch({ hide_credentials })
                  }
                  label={t('pages.basicAuth.hideCredentials')}
                  description={t('pages.basicAuth.hideCredentialsHint')}
                />
              </CardBody>
            </Card>

            <Card>
              <CardBody className="flex flex-col gap-2 text-xs text-fg-subtle">
                <p className="flex items-center gap-2 text-[13px] font-medium text-fg">
                  <LockSimple weight="duotone" className="h-4 w-4" />
                  {t('pages.basicAuth.notes')}
                </p>
                <p>{t('pages.basicAuth.noteOrder')}</p>
                <p>{t('pages.basicAuth.noteRules')}</p>
                <p>{t('pages.basicAuth.noteExempt')}</p>
              </CardBody>
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}

export default BasicAuthPanel
