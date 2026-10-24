import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash } from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { useToast } from '@/components/ui/Toast'
import { oidcProviderApi, oidcProviderKeys } from '@/api/siteOidc'
import {
  OIDC_ALWAYS_SCOPE,
  OIDC_MAX_PROVIDER_NAME_LENGTH,
  OIDC_SECRET_MASK,
} from '@/api/types'
import type { OidcProvider } from '@/api/types'

/**
 * Identity providers, managed once for the whole deployment.
 *
 * A provider is the issuer plus the client credentials registered there. The
 * same realm usually fronts several sites, so storing it once means rotating
 * a client secret is one edit rather than one per site. Sites reference a
 * provider from their own access-control tab and add the access rules that
 * decide which signed-in users may enter.
 *
 * The client secret is masked on the way out, so the field starts empty and a
 * placeholder shows the mask: leaving it alone keeps the stored secret, and
 * emptying a field that held one is the deliberate way to drop it.
 */

interface FormState {
  name: string
  issuer: string
  clientId: string
  clientSecret: string
  scopes: string
  enabled: boolean
  /** True once the user emptied the secret field of a stored value. */
  clearedSecret: boolean
}

const EMPTY_FORM: FormState = {
  name: '',
  issuer: '',
  clientId: '',
  clientSecret: '',
  scopes: '',
  enabled: true,
  clearedSecret: false,
}

function formFrom(provider: OidcProvider): FormState {
  return {
    name: provider.name,
    issuer: provider.issuer,
    clientId: provider.client_id,
    // Left blank: a placeholder shows the mask, and a blank field keeps the
    // stored secret rather than replacing it with the literal mask.
    clientSecret: '',
    scopes: provider.scopes
      .filter((scope) => scope !== OIDC_ALWAYS_SCOPE)
      .join(' '),
    enabled: provider.enabled,
    clearedSecret: false,
  }
}

export function OidcProvidersCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [editing, setEditing] = useState<OidcProvider | null>(null)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState<FormState>(EMPTY_FORM)
  const [confirming, setConfirming] = useState<OidcProvider | null>(null)

  const list = useQuery({
    queryKey: oidcProviderKeys.all,
    queryFn: oidcProviderApi.list,
    retry: false,
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: oidcProviderKeys.all })
    // A rename or a disable changes what each site's picker shows.
    void queryClient.invalidateQueries({ queryKey: ['site-oidc'] })
  }

  const save = useMutation({
    mutationFn: async () => {
      const scopes = form.scopes
        .split(/[\s,]+/)
        .map((scope) => scope.trim())
        .filter(Boolean)
      // Absent means "keep what is stored"; `''` clears it. An empty field on
      // a provider that has no stored secret is simply absent too.
      const secret = form.clearedSecret
        ? ''
        : form.clientSecret.trim() === ''
          ? undefined
          : form.clientSecret.trim()
      const body = {
        name: form.name.trim(),
        issuer: form.issuer.trim(),
        client_id: form.clientId.trim(),
        scopes,
        enabled: form.enabled,
      }
      if (editing) {
        return oidcProviderApi.update(editing.id, {
          ...body,
          ...(secret === undefined ? {} : { client_secret: secret }),
        })
      }
      return oidcProviderApi.create({
        ...body,
        ...(secret === undefined ? {} : { client_secret: secret }),
      })
    },
    onSuccess: () => {
      toast.success(
        editing
          ? t('pages.account.oidcProviderSaved')
          : t('pages.account.oidcProviderCreated'),
      )
      setEditing(null)
      setCreating(false)
      invalidate()
    },
    onError: (error: unknown) => {
      toast.error(error instanceof Error ? error.message : String(error))
    },
  })

  const remove = useMutation({
    mutationFn: (provider: OidcProvider) =>
      oidcProviderApi.remove(provider.id),
    onSuccess: () => {
      toast.success(t('pages.account.oidcProviderDeleted'))
      setConfirming(null)
      invalidate()
    },
    onError: (error: unknown) => {
      // A `409` names how many sites still point here; showing it is the
      // whole point of refusing rather than letting them go unconfigured.
      toast.error(error instanceof Error ? error.message : String(error))
    },
  })

  const openCreate = () => {
    setForm(EMPTY_FORM)
    setEditing(null)
    setCreating(true)
  }

  const openEdit = (provider: OidcProvider) => {
    setForm(formFrom(provider))
    setCreating(false)
    setEditing(provider)
  }

  const close = () => {
    setCreating(false)
    setEditing(null)
  }

  const open = creating || editing !== null
  const blockedReason =
    form.name.trim() === ''
      ? t('pages.account.oidcProviderNameRequired')
      : form.issuer.trim() === ''
        ? t('pages.account.oidcProviderIssuerRequired')
        : form.clientId.trim() === ''
          ? t('pages.account.oidcProviderClientIdRequired')
          : undefined

  return (
    <Card>
      <CardHeader
        title={t('pages.account.oidcProviders')}
        description={t('pages.account.oidcProvidersHint')}
        action={
          canWrite ? (
            <Button
              size="sm"
              variant="secondary"
              icon={<Plus weight="bold" className="h-4 w-4" />}
              onClick={openCreate}
            >
              {t('pages.account.oidcProviderAdd')}
            </Button>
          ) : undefined
        }
      />
      <CardBody>
        {list.isError ? (
          <ErrorState
            variant="inline"
            error={list.error}
            onRetry={() => void list.refetch()}
            retrying={list.isFetching}
          />
        ) : list.data && list.data.length > 0 ? (
          <ul className="flex flex-col">
            {list.data.map((provider) => (
              <li
                key={provider.id}
                className="flex items-center justify-between gap-3 border-b border-border py-3 last:border-b-0"
              >
                <div className="flex min-w-0 flex-col gap-0.5">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-sm font-medium text-fg-strong">
                      {provider.name}
                    </span>
                    {!provider.enabled && (
                      <Badge tone="neutral">
                        {t('pages.account.oidcProviderDisabled')}
                      </Badge>
                    )}
                    {provider.site_count > 0 && (
                      <span className="text-xs text-fg-subtle">
                        {t('pages.account.oidcProviderSiteCount', {
                          count: provider.site_count,
                        })}
                      </span>
                    )}
                  </div>
                  <span className="truncate pw-mono text-xs text-fg-subtle">
                    {provider.issuer}
                  </span>
                </div>
                {canWrite && (
                  <div className="flex shrink-0 items-center gap-1">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => openEdit(provider)}
                    >
                      {t('common.edit')}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={<Trash weight="duotone" className="h-4 w-4" />}
                      aria-label={t('common.delete')}
                      onClick={() => setConfirming(provider)}
                    />
                  </div>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState
            title={t('pages.account.oidcProvidersEmpty')}
            description={t('pages.account.oidcProvidersEmptyHint')}
          />
        )}
      </CardBody>

      <Dialog
        open={open}
        onClose={close}
        title={
          editing
            ? t('pages.account.oidcProviderEdit')
            : t('pages.account.oidcProviderAdd')
        }
        footer={
          <>
            <Button variant="ghost" onClick={close}>
              {t('common.cancel')}
            </Button>
            <Button
              loading={save.isPending}
              disabled={Boolean(blockedReason)}
              title={blockedReason}
              onClick={() => save.mutate()}
            >
              {editing ? t('common.save') : t('common.create')}
            </Button>
          </>
        }
      >
        <ProviderForm
          key={editing?.id ?? 'new'}
          form={form}
          setForm={setForm}
          stored={editing}
        />
      </Dialog>

      <ConfirmDialog
        open={confirming !== null}
        title={t('pages.account.oidcProviderDeleteTitle')}
        description={t('pages.account.oidcProviderDeleteMessage', {
          name: confirming?.name ?? '',
        })}
        confirmLabel={t('common.delete')}
        tone="danger"
        loading={remove.isPending}
        onClose={() => setConfirming(null)}
        onConfirm={() => confirming && remove.mutate(confirming)}
      />
    </Card>
  )
}

function ProviderForm({
  form,
  setForm,
  stored,
}: {
  form: FormState
  setForm: (updater: (current: FormState) => FormState) => void
  stored: OidcProvider | null
}) {
  const { t } = useTranslation()

  // The dialog is remounted per provider (`key` on the caller), so this starts
  // fresh each time and a revealed field cannot carry over to the next form.
  const [reveal, setReveal] = useState(false)

  const patch = (part: Partial<FormState>) =>
    setForm((current) => ({ ...current, ...part }))

  const hasStoredSecret = stored?.client_secret === OIDC_SECRET_MASK

  return (
    <div className="flex flex-col gap-4">
      <Input
        label={t('pages.account.oidcProviderName')}
        hint={t('pages.account.oidcProviderNameHint')}
        value={form.name}
        maxLength={OIDC_MAX_PROVIDER_NAME_LENGTH}
        required
        autoFocus
        onChange={(event) => patch({ name: event.target.value })}
      />

      <Input
        label={t('pages.account.oidcProviderIssuer')}
        hint={t('pages.account.oidcProviderIssuerHint')}
        value={form.issuer}
        placeholder="https://keycloak.example.com/realms/main"
        required
        onChange={(event) => patch({ issuer: event.target.value })}
      />

      <Input
        label={t('pages.account.oidcProviderClientId')}
        value={form.clientId}
        required
        onChange={(event) => patch({ clientId: event.target.value })}
      />

      <div className="flex items-end gap-2">
        <div className="flex-1">
          <Input
            type={reveal ? 'text' : 'password'}
            label={t('pages.account.oidcProviderClientSecret')}
            hint={
              hasStoredSecret
                ? t('pages.account.oidcProviderSecretStored')
                : t('pages.account.oidcProviderSecretHint')
            }
            value={form.clientSecret}
            placeholder={hasStoredSecret ? OIDC_SECRET_MASK : ''}
            autoComplete="new-password"
            onChange={(event) =>
              patch({
                clientSecret: event.target.value,
                // Typing a value replaces it; emptying the field is the one
                // way to drop a stored secret.
                clearedSecret:
                  hasStoredSecret && event.target.value.trim() === '',
              })
            }
          />
        </div>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          className="mb-6"
          onClick={() => setReveal((current) => !current)}
        >
          {reveal ? t('common.hide') : t('common.show')}
        </Button>
      </div>

      <Input
        label={t('pages.account.oidcProviderScopes')}
        hint={t('pages.account.oidcProviderScopesHint')}
        value={form.scopes}
        placeholder="email profile"
        onChange={(event) => patch({ scopes: event.target.value })}
      />

      <Switch
        checked={form.enabled}
        onCheckedChange={(checked) => patch({ enabled: checked })}
        label={t('pages.account.oidcProviderEnabled')}
        description={t('pages.account.oidcProviderEnabledHint')}
      />
    </div>
  )
}