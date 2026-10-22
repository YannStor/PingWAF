import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  Eye,
  EyeSlash,
  LockSimple,
  Plus,
  ShieldCheck,
  Trash,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { useUnsavedGuard } from '@/hooks/useUnsavedGuard'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { SkeletonCard } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import {
  siteOidcApi,
  siteOidcKeys,
  defaultSiteOidc,
} from '@/api/siteOidc'
import { useCanWrite } from '@/hooks'
import {
  OIDC_MAX_SESSION_TTL_SECONDS,
  OIDC_MIN_COOKIE_SECRET_LENGTH,
  OIDC_MIN_SESSION_TTL_SECONDS,
  OIDC_SECRET_MASK,
  type OidcHeaderClaim,
  type SiteOidc,
} from '@/api/types'

/** A secret field being edited; `stored` marks a secret the API masked. */
interface SecretState {
  value: string
  stored: boolean
  /**
   * The user emptied the field, which means "drop the stored secret" — a
   * different thing from never having touched it, where what is stored stays.
   * Without this a confidential client could never become a public one.
   */
  cleared: boolean
}

function secretFrom(masked: string): SecretState {
  return { value: '', stored: masked === OIDC_SECRET_MASK, cleared: false }
}

/** The OIDC module of the site's access-control tab. */
export function OidcPanel() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const [config, setConfig] = useState<SiteOidc | null>(null)
  const [scopes, setScopes] = useState<string[]>([])
  const [claims, setClaims] = useState<OidcHeaderClaim[]>([])
  const [clientSecret, setClientSecret] = useState<SecretState>({
    value: '',
    stored: false,
    cleared: false,
  })
  const [cookieSecret, setCookieSecret] = useState<SecretState>({
    value: '',
    stored: false,
    cleared: false,
  })
  const [dirty, setDirty] = useState(false)
  const [revealed, setRevealed] = useState<{ client: boolean; cookie: boolean }>({
    client: false,
    cookie: false,
  })

  const configQuery = useQuery({
    queryKey: siteOidcKeys.detail(siteId),
    queryFn: () => siteOidcApi.get(siteId),
    enabled: Boolean(siteId),
  })

  // Seed the form from the query (render-phase reset on new data / first
  // failure), so nothing flashes stale values on the first paint.
  const serverConfig = configQuery.data
  const loadFailed = configQuery.isError && Boolean(siteId)
  const [sync, setSync] = useState<{ config: typeof serverConfig; failed: boolean } | null>(null)
  if (!sync || sync.config !== serverConfig || sync.failed !== loadFailed) {
    setSync({ config: serverConfig, failed: loadFailed })
    if (serverConfig) {
      setConfig(serverConfig)
      setScopes(serverConfig.scopes)
      setClaims(serverConfig.claims_to_headers)
      setClientSecret(secretFrom(serverConfig.client_secret))
      setCookieSecret(secretFrom(serverConfig.cookie_secret))
      setDirty(false)
      setRevealed({ client: false, cookie: false })
    } else if (loadFailed) {
      const fallback = defaultSiteOidc(siteId)
      setConfig(fallback)
      setScopes(fallback.scopes)
      setClaims([])
      setClientSecret({ value: '', stored: false, cleared: false })
      setCookieSecret({ value: '', stored: false, cleared: false })
      setDirty(false)
    }
  }

  const patch = (part: Partial<SiteOidc>) => {
    setConfig((c) => (c ? { ...c, ...part } : c))
    setDirty(true)
  }

  const updateScope = (index: number, scope: string) => {
    setScopes((current) => current.map((s, i) => (i === index ? scope : s)))
    setDirty(true)
  }

  const addScope = () => {
    setScopes((current) => [...current, ''])
    setDirty(true)
  }

  const removeScope = (index: number) => {
    setScopes((current) => current.filter((_, i) => i !== index))
    setDirty(true)
  }

  const updateClaim = (index: number, part: Partial<OidcHeaderClaim>) => {
    setClaims((current) =>
      current.map((row, i) => (i === index ? { ...row, ...part } : row)),
    )
    setDirty(true)
  }

  const addClaim = () => {
    setClaims((current) => [...current, { claim: '', header: '' }])
    setDirty(true)
  }

  const removeClaim = (index: number) => {
    setClaims((current) => current.filter((_, i) => i !== index))
    setDirty(true)
  }

  const patchSecret = (
    which: 'client' | 'cookie',
    part: Partial<SecretState>,
  ) => {
    const set = which === 'client' ? setClientSecret : setCookieSecret
    // Typing tracks `cleared` alongside the text: emptying the box drops the
    // stored secret, typing into it (or leaving it alone) keeps or replaces it.
    const next =
      part.value === undefined ? part : { ...part, cleared: part.value === '' }
    set((current) => ({ ...current, ...next }))
    setDirty(true)
  }

  const toggleReveal = (which: 'client' | 'cookie') => {
    setRevealed((current) => ({ ...current, [which]: !current[which] }))
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: siteOidcKeys.all })
  }

  const save = useMutation({
    mutationFn: (payload: SiteOidc) => {
      // Secrets: a typed value updates, an untouched stored field sends the
      // mask to keep the old value, and clearing an unset field is a no-op.
      // Cleared sends "" (the API drops the stored secret); untouched keeps
      // the stored one by echoing the mask; anything typed replaces it.
      const toSecret = (state: SecretState) =>
        state.cleared
          ? ''
          : state.value !== ''
            ? state.value
            : state.stored
              ? OIDC_SECRET_MASK
              : ''
      return siteOidcApi.update(siteId, {
        enabled: payload.enabled,
        issuer: payload.issuer.trim(),
        client_id: payload.client_id.trim(),
        client_secret: toSecret(clientSecret),
        cookie_secret: toSecret(cookieSecret),
        redirect_path: payload.redirect_path,
        logout_path: payload.logout_path,
        redirect_url: payload.redirect_url,
        scopes: scopes.map((s) => s.trim()).filter((s) => s !== ''),
        cookie_name: payload.cookie_name.trim(),
        session_ttl_seconds: payload.session_ttl_seconds,
        claims_to_headers: claims.filter(
          (row) => row.claim.trim() !== '' && row.header.trim() !== '',
        ),
      })
    },
    onSuccess: (saved) => {
      setConfig(saved)
      setScopes(saved.scopes)
      setClaims(saved.claims_to_headers)
      setClientSecret(secretFrom(saved.client_secret))
      setCookieSecret(secretFrom(saved.cookie_secret))
      setDirty(false)
      setRevealed({ client: false, cookie: false })
      toast.success(t('pages.oidc.saved'))
      invalidate()
    },
  })

  const unsavedDialog = useUnsavedGuard(dirty)

  // Mirrors the control plane's enabled guard, in the same order.
  const effectiveCookieSecret = cookieSecret.cleared
    ? ''
    : cookieSecret.value !== ''
      ? cookieSecret.value
      : cookieSecret.stored
        ? 'x'.repeat(OIDC_MIN_COOKIE_SECRET_LENGTH)
        : ''
  const blockedReason = config?.enabled
    ? config.issuer.trim() === ''
      ? t('pages.oidc.issuerRequired')
      : config.client_id.trim() === ''
        ? t('pages.oidc.clientIdRequired')
        : // No client_secret requirement: a public client (PKCE only) has
          // none, and the control plane accepts that.
          cookieSecret.cleared || (cookieSecret.value === '' && !cookieSecret.stored)
          ? t('pages.oidc.secretRequired')
          : effectiveCookieSecret.length < OIDC_MIN_COOKIE_SECRET_LENGTH
            ? t('pages.oidc.cookieSecretTooShort')
            : undefined
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
      {blockedReason && (
        <p className="mb-4 text-xs text-fg-danger">{blockedReason}</p>
      )}

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
            {/* Provider */}
            <Card>
              <CardHeader
                title={t('pages.oidc.provider')}
                description={t('pages.oidc.providerHint')}
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
              <CardBody className="flex flex-col gap-5">
                <Switch
                  checked={config.enabled}
                  disabled={!canWrite}
                  onCheckedChange={(enabled) => patch({ enabled })}
                  label={t('pages.oidc.enabled')}
                  description={t('pages.oidc.enabledHint')}
                />
                <Input
                  label={t('pages.oidc.issuer')}
                  value={config.issuer}
                  disabled={!canWrite}
                  hint={t('pages.oidc.issuerHint')}
                  placeholder="https://accounts.example.com"
                  onChange={(e) => patch({ issuer: e.target.value })}
                />
                <Input
                  label={t('pages.oidc.clientId')}
                  value={config.client_id}
                  disabled={!canWrite}
                  autoComplete="off"
                  onChange={(e) => patch({ client_id: e.target.value })}
                />
                <Input
                  label={t('pages.oidc.clientSecret')}
                  type={revealed.client ? 'text' : 'password'}
                  value={clientSecret.value}
                  disabled={!canWrite}
                  autoComplete="new-password"
                  hint={t('pages.oidc.clientSecretHint')}
                  placeholder={
                    clientSecret.stored ? t('pages.oidc.storedSecret') : undefined
                  }
                  suffixIcon={
                    <button
                      type="button"
                      onClick={() => toggleReveal('client')}
                      aria-label={
                        revealed.client
                          ? t('auth.hidePassword')
                          : t('auth.showPassword')
                      }
                      className="transition-colors hover:text-fg"
                    >
                      {revealed.client ? (
                        <EyeSlash weight="duotone" />
                      ) : (
                        <Eye weight="duotone" />
                      )}
                    </button>
                  }
                  onChange={(e) =>
                    patchSecret('client', { value: e.target.value })
                  }
                />
                <Input
                  label={t('pages.oidc.cookieSecret')}
                  type={revealed.cookie ? 'text' : 'password'}
                  value={cookieSecret.value}
                  disabled={!canWrite}
                  autoComplete="new-password"
                  hint={t('pages.oidc.cookieSecretHint')}
                  placeholder={
                    cookieSecret.stored
                      ? t('pages.oidc.storedSecret')
                      : t('pages.oidc.cookieSecretRequired')
                  }
                  suffixIcon={
                    <button
                      type="button"
                      onClick={() => toggleReveal('cookie')}
                      aria-label={
                        revealed.cookie
                          ? t('auth.hidePassword')
                          : t('auth.showPassword')
                      }
                      className="transition-colors hover:text-fg"
                    >
                      {revealed.cookie ? (
                        <EyeSlash weight="duotone" />
                      ) : (
                        <Eye weight="duotone" />
                      )}
                    </button>
                  }
                  onChange={(e) =>
                    patchSecret('cookie', { value: e.target.value })
                  }
                />
              </CardBody>
            </Card>

            {/* Endpoints */}
            <Card>
              <CardHeader
                title={t('pages.oidc.endpoints')}
                description={t('pages.oidc.endpointsHint')}
              />
              <CardBody className="flex flex-col gap-5">
                <Input
                  label={t('pages.oidc.redirectPath')}
                  value={config.redirect_path}
                  disabled={!canWrite}
                  onChange={(e) => patch({ redirect_path: e.target.value })}
                />
                <Input
                  label={t('pages.oidc.logoutPath')}
                  value={config.logout_path}
                  disabled={!canWrite}
                  hint={t('pages.oidc.logoutPathHint')}
                  onChange={(e) => patch({ logout_path: e.target.value })}
                />
                <Input
                  label={t('pages.oidc.redirectUrl')}
                  value={config.redirect_url}
                  disabled={!canWrite}
                  hint={t('pages.oidc.redirectUrlHint')}
                  onChange={(e) => patch({ redirect_url: e.target.value })}
                />
              </CardBody>
            </Card>

            {/* Scopes */}
            <Card>
              <CardHeader
                title={t('pages.oidc.scopes')}
                description={t('pages.oidc.scopesHint')}
              />
              <CardBody className="flex flex-col gap-3">
                {scopes.map((scope, index) => (
                  <div key={index} className="flex items-start gap-3">
                    <Input
                      value={scope}
                      disabled={!canWrite}
                      autoComplete="off"
                      onChange={(e) => updateScope(index, e.target.value)}
                    />
                    {canWrite && (
                      <Button
                        variant="ghost"
                        aria-label={t('common.remove')}
                        onClick={() => removeScope(index)}
                        icon={<Trash weight="duotone" className="h-4 w-4" />}
                      />
                    )}
                  </div>
                ))}
                {canWrite && (
                  <div>
                    <Button
                      variant="secondary"
                      onClick={addScope}
                      icon={<Plus weight="duotone" className="h-4 w-4" />}
                    >
                      {t('pages.oidc.addScope')}
                    </Button>
                  </div>
                )}
              </CardBody>
            </Card>

            {/* Claims */}
            <Card>
              <CardHeader
                title={t('pages.oidc.claims')}
                description={t('pages.oidc.claimsHint')}
              />
              <CardBody className="flex flex-col gap-3">
                {claims.length === 0 ? (
                  <p className="text-xs text-fg-subtle">{t('pages.oidc.claimsHint')}</p>
                ) : (
                  claims.map((row, index) => (
                    <div
                      key={index}
                      className="grid grid-cols-1 items-start gap-3 sm:grid-cols-[1fr_1fr_auto]"
                    >
                      <Input
                        label={t('pages.oidc.claim')}
                        value={row.claim}
                        disabled={!canWrite}
                        autoComplete="off"
                        onChange={(e) => updateClaim(index, { claim: e.target.value })}
                      />
                      <Input
                        label={t('pages.oidc.header')}
                        value={row.header}
                        disabled={!canWrite}
                        autoComplete="off"
                        onChange={(e) => updateClaim(index, { header: e.target.value })}
                      />
                      <div className="pt-6">
                        {canWrite && (
                          <Button
                            variant="ghost"
                            aria-label={t('pages.oidc.removeClaim')}
                            onClick={() => removeClaim(index)}
                            icon={<Trash weight="duotone" className="h-4 w-4" />}
                          />
                        )}
                      </div>
                    </div>
                  ))
                )}
                {canWrite && (
                  <div>
                    <Button
                      variant="secondary"
                      onClick={addClaim}
                      icon={<Plus weight="duotone" className="h-4 w-4" />}
                    >
                      {t('pages.oidc.addClaim')}
                    </Button>
                  </div>
                )}
              </CardBody>
            </Card>

            {/* Behaviour */}
            <Card>
              <CardBody className="flex flex-col gap-5">
                <Input
                  label={t('pages.oidc.cookieName')}
                  value={config.cookie_name}
                  disabled={!canWrite}
                  hint={t('pages.oidc.cookieNameHint')}
                  onChange={(e) => patch({ cookie_name: e.target.value })}
                />
                <Input
                  label={t('pages.oidc.sessionTtl')}
                  type="number"
                  min={OIDC_MIN_SESSION_TTL_SECONDS}
                  max={OIDC_MAX_SESSION_TTL_SECONDS}
                  value={config.session_ttl_seconds}
                  disabled={!canWrite}
                  hint={t('pages.oidc.sessionTtlHint')}
                  onChange={(e) =>
                    patch({
                      session_ttl_seconds: Math.min(
                        OIDC_MAX_SESSION_TTL_SECONDS,
                        Math.max(
                          OIDC_MIN_SESSION_TTL_SECONDS,
                          Number(e.target.value) || 0,
                        ),
                      ),
                    })
                  }
                />
              </CardBody>
            </Card>
          </div>

          {/* Notes */}
          <div className="flex flex-col gap-6">
            <Card>
              <CardBody className="flex flex-col gap-2 text-xs text-fg-subtle">
                <p className="flex items-center gap-2 text-[13px] font-medium text-fg">
                  <LockSimple weight="duotone" className="h-4 w-4" />
                  {t('pages.oidc.notes')}
                </p>
                <p>{t('pages.oidc.noteOrder')}</p>
                <p>{t('pages.oidc.notePkce')}</p>
                <p>{t('pages.oidc.noteExempt')}</p>
              </CardBody>
            </Card>

            <Card>
              <CardBody className="flex items-center gap-3 text-xs text-fg-subtle">
                <ShieldCheck weight="duotone" className="h-5 w-5 shrink-0 text-fg-muted" />
                <span>{t('pages.oidc.enabledHint')}</span>
              </CardBody>
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}

export default OidcPanel
