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
import { Select } from '@/components/ui/Select'
import {
  siteOidcApi,
  siteOidcKeys,
  defaultSiteOidc,
  oidcProviderApi,
  oidcProviderKeys,
} from '@/api/siteOidc'
import { useCanWrite } from '@/hooks'
import {
  OIDC_ACCESS_MODES,
  OIDC_ACCESS_OPERATORS,
  OIDC_AUTH_MODES,
  OIDC_MAX_ACCESS_RULES,
  OIDC_MAX_SESSION_TTL_SECONDS,
  OIDC_MIN_COOKIE_SECRET_LENGTH,
  OIDC_MIN_SESSION_TTL_SECONDS,
  OIDC_SECRET_MASK,
  type OidcAccessMode,
  type OidcAccessOperator,
  type OidcAccessRule,
  type OidcAuthMode,
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
  const [claims, setClaims] = useState<OidcHeaderClaim[]>([])
  const [rules, setRules] = useState<OidcAccessRule[]>([])
  const [cookieSecret, setCookieSecret] = useState<SecretState>({
    value: '',
    stored: false,
    cleared: false,
  })
  const [dirty, setDirty] = useState(false)
  const [revealed, setRevealed] = useState<{ cookie: boolean }>({ cookie: false })

  const configQuery = useQuery({
    queryKey: siteOidcKeys.detail(siteId),
    queryFn: () => siteOidcApi.get(siteId),
    enabled: Boolean(siteId),
  })

  // Providers are deployment-wide and live on the Account page; this panel
  // only picks one, so the list is read here rather than duplicated.
  const providersQuery = useQuery({
    queryKey: oidcProviderKeys.all,
    queryFn: oidcProviderApi.list,
    retry: false,
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
      setClaims(serverConfig.claims_to_headers)
      setRules(serverConfig.access_rules)
      setCookieSecret(secretFrom(serverConfig.cookie_secret))
      setDirty(false)
      setRevealed({ cookie: false })
    } else if (loadFailed) {
      const fallback = defaultSiteOidc(siteId)
      setConfig(fallback)
      setClaims([])
      setRules([])
      setCookieSecret({ value: '', stored: false, cleared: false })
      setDirty(false)
    }
  }

  const patch = (part: Partial<SiteOidc>) => {
    setConfig((c) => (c ? { ...c, ...part } : c))
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

  const updateRule = (index: number, part: Partial<OidcAccessRule>) => {
    setRules((current) =>
      current.map((row, i) => (i === index ? { ...row, ...part } : row)),
    )
    setDirty(true)
  }

  const addRule = () => {
    setRules((current) => [
      ...current,
      { claim: '', operator: 'eq' as OidcAccessOperator, value: '' },
    ])
    setDirty(true)
  }

  const removeRule = (index: number) => {
    setRules((current) => current.filter((_, i) => i !== index))
    setDirty(true)
  }

  const patchSecret = (part: Partial<SecretState>) => {
    // Typing tracks `cleared` alongside the text: emptying the box drops the
    // stored secret, typing into it (or leaving it alone) keeps or replaces it.
    const next =
      part.value === undefined ? part : { ...part, cleared: part.value === '' }
    setCookieSecret((current) => ({ ...current, ...next }))
    setDirty(true)
  }

  const toggleReveal = () => {
    setRevealed((current) => ({ cookie: !current.cookie }))
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
      // Rules the user left half-filled are dropped rather than sent: the API
      // would reject them, and an empty row is a row they started and moved
      // away from. A rule with an operator that reads no value keeps its
      // blank value on purpose.
      const cleanedRules = rules
        .map((rule) => ({
          claim: rule.claim.trim(),
          operator: rule.operator,
          value: rule.operator === 'exists' ? '' : rule.value.trim(),
        }))
        .filter(
          (rule) =>
            rule.claim !== '' &&
            (rule.operator === 'exists' || rule.value !== ''),
        )
      return siteOidcApi.update(siteId, {
        enabled: payload.enabled,
        provider_id: payload.provider_id,
        cookie_secret: toSecret(cookieSecret),
        redirect_path: payload.redirect_path,
        logout_path: payload.logout_path,
        redirect_url: payload.redirect_url,
        cookie_name: payload.cookie_name.trim(),
        session_ttl_seconds: payload.session_ttl_seconds,
        claims_to_headers: claims.filter(
          (row) => row.claim.trim() !== '' && row.header.trim() !== '',
        ),
        access_mode: payload.access_mode,
        access_rules: cleanedRules,
      })
    },
    onSuccess: (saved) => {
      setConfig(saved)
      setClaims(saved.claims_to_headers)
      setRules(saved.access_rules)
      setCookieSecret(secretFrom(saved.cookie_secret))
      setDirty(false)
      setRevealed({ cookie: false })
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
  const enforcing =
    config !== null && config.access_mode !== 'allow_all'
  const usableRuleCount = rules.filter(
    (rule) =>
      rule.claim.trim() !== '' &&
      (rule.operator === 'exists' || rule.value.trim() !== ''),
  ).length
  const blockedReason = config?.enabled
    ? // A `local` site has no provider, so requiring one would make the mode
      // impossible to save.
      config.auth_mode !== 'local' && config.provider_id === null
      ? t('pages.oidc.providerRequired')
      : // No client_secret requirement: a public client (PKCE only) has
        // none, and the control plane accepts that.
        cookieSecret.cleared || (cookieSecret.value === '' && !cookieSecret.stored)
        ? t('pages.oidc.secretRequired')
        : effectiveCookieSecret.length < OIDC_MIN_COOKIE_SECRET_LENGTH
          ? t('pages.oidc.cookieSecretTooShort')
          : // An enforcing mode with no usable rule denies everyone,
            // including the operator; the API refuses it too.
            enforcing && usableRuleCount === 0
            ? t('pages.oidc.accessRulesRequired')
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
                {/* How visitors sign in. `oidc` is the default and the
                    pre-local-accounts behaviour, so leaving it alone keeps a
                    site working exactly as before. */}
                <Select
                  label={t('pages.oidc.authMode')}
                  hint={t('pages.oidc.authModeHint')}
                  value={config.auth_mode}
                  disabled={!canWrite}
                  onChange={(event) =>
                    patch({ auth_mode: event.target.value as OidcAuthMode })
                  }
                  options={OIDC_AUTH_MODES.map((mode) => ({
                    value: mode,
                    label: t(`pages.oidc.authMode_${mode}`),
                  }))}
                />
                <p className="-mt-2 text-xs text-fg-subtle">
                  {t(`pages.oidc.authModeDetail_${config.auth_mode}`)}
                </p>
                {/* The issuer and client credentials live on the Account
                    page: they belong to the provider, which several sites
                    share. This panel picks one and adds what is per-site.
                    A `local` site has no provider, so the picker is hidden
                    rather than shown as a required field it is not. */}
                {config.auth_mode !== 'local' && (
                <Select
                  label={t('pages.oidc.provider')}
                  hint={t('pages.oidc.providerPickerHint')}
                  value={config.provider_id ?? ''}
                  disabled={!canWrite}
                  onChange={(event) =>
                    patch({
                      provider_id:
                        event.target.value === '' ? null : event.target.value,
                    })
                  }
                  options={[
                    { value: '', label: t('pages.oidc.providerNone') },
                    ...(providersQuery.data ?? [])
                      .filter(
                        (provider) =>
                          provider.enabled ||
                          provider.id === config.provider_id,
                      )
                      .map((provider) => ({
                        value: provider.id,
                        label: provider.enabled
                          ? provider.name
                          : `${provider.name} (${t('common.disabled')})`,
                      })),
                  ]}
                />
                )}
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
                      onClick={toggleReveal}
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
                  onChange={(e) => patchSecret({ value: e.target.value })}
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

            {/* Access rules — who may enter, once they are signed in. */}
            <Card>
              <CardHeader
                title={t('pages.oidc.access')}
                description={t('pages.oidc.accessHint')}
              />
              <CardBody className="flex flex-col gap-4">
                <Select
                  label={t('pages.oidc.accessMode')}
                  value={config.access_mode}
                  disabled={!canWrite}
                  onChange={(event) =>
                    patch({
                      access_mode: event.target.value as OidcAccessMode,
                    })
                  }
                  options={OIDC_ACCESS_MODES.map((mode) => ({
                    value: mode,
                    label: t(`pages.oidc.accessMode_${mode}`),
                  }))}
                />
                <p className="text-xs text-fg-subtle">
                  {t(`pages.oidc.accessModeHint_${config.access_mode}`)}
                </p>

                {config.access_mode !== 'allow_all' && (
                  <div className="flex flex-col gap-3">
                    {rules.map((rule, index) => (
                      <div key={index} className="flex items-start gap-2">
                        <Input
                          className="flex-1"
                          label={index === 0 ? t('pages.oidc.ruleClaim') : undefined}
                          value={rule.claim}
                          disabled={!canWrite}
                          autoComplete="off"
                          placeholder="groups"
                          onChange={(e) =>
                            updateRule(index, { claim: e.target.value })
                          }
                        />
                        <Select
                          containerClassName="w-36"
                          label={index === 0 ? t('pages.oidc.ruleOperator') : undefined}
                          value={rule.operator}
                          disabled={!canWrite}
                          onChange={(event) =>
                            updateRule(index, {
                              operator: event.target
                                .value as OidcAccessOperator,
                            })
                          }
                          options={OIDC_ACCESS_OPERATORS.map((operator) => ({
                            value: operator,
                            label: t(`pages.oidc.operator_${operator}`),
                          }))}
                        />
                        {/* `exists` reads no value, so the field would be a
                            box the operator cannot fill meaningfully. */}
                        {rule.operator !== 'exists' && (
                          <Input
                            className="flex-1"
                            label={index === 0 ? t('pages.oidc.ruleValue') : undefined}
                            value={rule.value}
                            disabled={!canWrite}
                            autoComplete="off"
                            placeholder="waf-admins"
                            onChange={(e) =>
                              updateRule(index, { value: e.target.value })
                            }
                          />
                        )}
                        {canWrite && (
                          <Button
                            className={index === 0 ? 'mt-6' : undefined}
                            variant="ghost"
                            aria-label={t('common.remove')}
                            onClick={() => removeRule(index)}
                            icon={<Trash weight="duotone" className="h-4 w-4" />}
                          />
                        )}
                      </div>
                    ))}
                    {canWrite && (
                      <div>
                        <Button
                          variant="secondary"
                          disabled={rules.length >= OIDC_MAX_ACCESS_RULES}
                          onClick={addRule}
                          icon={<Plus weight="duotone" className="h-4 w-4" />}
                        >
                          {t('pages.oidc.addRule')}
                        </Button>
                      </div>
                    )}
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
