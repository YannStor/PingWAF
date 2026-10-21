import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Lock } from '@phosphor-icons/react'
import { Dialog } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { useToast } from '@/components/ui/Toast'
import { sitesApi, siteKeys } from '@/api/sites'
import { errorMessage } from '@/api/errors'
import type { CreatePoolRequest, UpdatePoolRequest, UpstreamPool } from '@/api/types'
import {
  ADDRESS_FAMILY_OPTIONS,
  emptyPoolForm,
  isHashKeyType,
  LB_OPTION_KEYS,
  poolFormFromPool,
  poolHealthCheckPayload,
  validatePoolHealthCheck,
  verifyCertPayload,
  VERIFY_CERT_OPTIONS,
  type AddressFamilyOption,
  type PoolFormState,
  type VerifyCertMode,
} from './types'

export type PoolDialogRequest = { mode: 'create' } | { mode: 'edit'; pool: UpstreamPool }

export function PoolDialog({
  siteId,
  request,
  onClose,
}: {
  siteId: string
  request: PoolDialogRequest
  onClose: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const editing = request.mode === 'edit' ? request.pool : null
  const [form, setForm] = useState<PoolFormState>(() =>
    request.mode === 'edit' ? poolFormFromPool(request.pool) : emptyPoolForm(),
  )
  const [error, setError] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: (data: { id?: string; create?: CreatePoolRequest; update?: UpdatePoolRequest }) =>
      data.id
        ? sitesApi.updatePool(siteId, data.id, data.update ?? {})
        : sitesApi.createPool(siteId, data.create!),
    onSuccess: (pool, vars) => {
      toast.success(
        vars.id ? t('pages.basic.poolUpdated') : t('pages.basic.poolCreated'),
        pool.name,
      )
      void queryClient.invalidateQueries({ queryKey: siteKeys.all })
      onClose()
    },
    onError: (e) => setError(errorMessage(e)),
  })

  const submit = () => {
    setError(null)
    const name = form.name.trim()
    if (!name || name.length > 100) {
      setError(t('pages.basic.errors.nameRequired'))
      return
    }

    const lbType = form.lbType
    const hashKey = form.hashKey.trim()
    let lbAlgorithm = lbType
    if (isHashKeyType(lbType)) {
      if (!hashKey) {
        setError(t('pages.basic.errors.lbKeyRequired'))
        return
      }
      lbAlgorithm = `${lbType}:${hashKey}`
    }
    if (lbAlgorithm.length > 64) {
      setError(t('pages.basic.errors.lbKeyRequired'))
      return
    }

    let sni: string | null = null
    if (form.httpsOrigin) {
      sni = form.sni.trim().toLowerCase()
      if (!sni) {
        setError(t('pages.basic.errors.sniRequired'))
        return
      }
      if (sni.length > 255) {
        setError(t('pages.basic.errors.sniTooLong'))
        return
      }
      if (sni === '$host' || sni.includes('://') || sni.includes(':')) {
        setError(t('pages.basic.errors.sniInvalid'))
        return
      }
    }

    // Inline validation only while the probe is enabled — the fields are
    // hidden otherwise, and an error the user cannot see or fix would make
    // the dialog unsavable. poolHealthCheckPayload normalizes hidden
    // out-of-range values to the server defaults so submission always passes.
    if (form.healthCheckEnabled) {
      const healthError = validatePoolHealthCheck(form)
      if (healthError) {
        setError(t(`pages.basic.errors.${healthError}`))
        return
      }
    }
    const healthCheck = poolHealthCheckPayload(form)

    if (editing) {
      // Empty SNI clears the field server-side, disabling HTTPS origin.
      save.mutate({
        id: editing.id,
        update: {
          name,
          lb_algorithm: lbAlgorithm,
          sni: sni ?? '',
          verify_cert: sni ? verifyCertPayload(form.verifyCert) : null,
          address_family: form.addressFamily,
          ...healthCheck,
        },
      })
      return
    }

    save.mutate({
      create: {
        name,
        lb_algorithm: lbAlgorithm,
        sni,
        verify_cert: sni ? verifyCertPayload(form.verifyCert) : null,
        address_family: form.addressFamily,
        ...healthCheck,
      },
    })
  }

  return (
    <Dialog
      open
      onClose={save.isPending ? () => undefined : onClose}
      title={editing ? t('pages.basic.editPool') : t('pages.basic.addPool')}
      description={
        editing ? t('pages.basic.poolEditDescription') : t('pages.basic.poolCreateDescription')
      }
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={save.isPending}>
            {t('common.cancel')}
          </Button>
          <Button variant="primary" onClick={submit} loading={save.isPending}>
            {editing ? t('common.save') : t('common.create')}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <Input
          label={t('pages.basic.poolName')}
          value={form.name}
          placeholder={t('pages.basic.poolNamePlaceholder')}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          autoFocus
          required
        />
        <Select
          label={t('pages.basic.lbAlgorithm')}
          value={form.lbType}
          hint={t('pages.basic.lbHint')}
          options={LB_OPTION_KEYS.map((o) => ({ value: o.value, label: t(o.labelKey) }))}
          onChange={(e) => setForm((f) => ({ ...f, lbType: e.target.value }))}
        />
        {isHashKeyType(form.lbType) && (
          <Input
            label={t('pages.basic.lbKey')}
            value={form.hashKey}
            placeholder="x-user-id"
            hint={t('pages.basic.lbKeyHint')}
            onChange={(e) => setForm((f) => ({ ...f, hashKey: e.target.value }))}
            required
          />
        )}
        <Switch
          checked={form.httpsOrigin}
          onCheckedChange={(httpsOrigin) => setForm((f) => ({ ...f, httpsOrigin }))}
          label={t('pages.basic.httpsOrigin')}
          description={t('pages.basic.httpsOriginHint')}
        />
        {form.httpsOrigin && (
          <Input
            label={t('pages.basic.sni')}
            value={form.sni}
            placeholder="origin.example.com"
            hint={t('pages.basic.sniHint')}
            prefixIcon={<Lock weight="duotone" />}
            onChange={(e) => setForm((f) => ({ ...f, sni: e.target.value }))}
            required
          />
        )}
        {/* Always visible — a hidden field read as "the option is gone".
            Disabled while the origin is HTTP: without SNI there is no TLS
            handshake, so there is nothing to verify. */}
        <Select
          label={t('pages.basic.verifyCert')}
          value={form.verifyCert}
          hint={
            form.httpsOrigin
              ? t('pages.basic.verifyCertHint')
              : t('pages.basic.verifyCertDisabledHint')
          }
          disabled={!form.httpsOrigin}
          options={VERIFY_CERT_OPTIONS.map((o) => ({
            value: o.value,
            label: t(o.labelKey),
          }))}
          onChange={(e) =>
            setForm((f) => ({
              ...f,
              verifyCert: e.target.value as VerifyCertMode,
            }))
          }
        />
        {/* Which address family the agent resolves origin names to — pins
            IPv4 or IPv6 for origins reachable on only one stack. */}
        <Select
          label={t('pages.basic.addressFamily', 'Address family')}
          value={form.addressFamily}
          hint={t('pages.basic.addressFamilyHint', 'auto prefers IPv4')}
          options={ADDRESS_FAMILY_OPTIONS.map((o) => ({
            value: o.value,
            label: t(o.labelKey, o.value),
          }))}
          onChange={(e) =>
            setForm((f) => ({
              ...f,
              addressFamily: e.target.value as AddressFamilyOption,
            }))
          }
        />
        <Switch
          checked={form.healthCheckEnabled}
          onCheckedChange={(healthCheckEnabled) =>
            setForm((f) => ({ ...f, healthCheckEnabled }))
          }
          label={t('pages.basic.healthCheck')}
          description={t('pages.basic.healthCheckHint')}
        />
        {form.healthCheckEnabled && (
          <>
            <Input
              label={t('pages.basic.healthCheckPath')}
              value={form.healthCheckPath}
              placeholder="/healthz"
              hint={t('pages.basic.healthCheckPathHint')}
              onChange={(e) => setForm((f) => ({ ...f, healthCheckPath: e.target.value }))}
              required
            />
            <div className="grid grid-cols-2 gap-3">
              <Input
                label={t('pages.basic.healthCheckInterval')}
                value={form.healthCheckInterval}
                hint={t('pages.basic.healthCheckIntervalHint')}
                inputMode="numeric"
                onChange={(e) =>
                  setForm((f) => ({ ...f, healthCheckInterval: e.target.value }))
                }
                required
              />
              <Input
                label={t('pages.basic.healthCheckTimeout')}
                value={form.healthCheckTimeout}
                hint={t('pages.basic.healthCheckTimeoutHint')}
                inputMode="numeric"
                onChange={(e) =>
                  setForm((f) => ({ ...f, healthCheckTimeout: e.target.value }))
                }
                required
              />
              <Input
                label={t('pages.basic.healthCheckUnhealthy')}
                value={form.healthCheckUnhealthy}
                hint={t('pages.basic.healthCheckUnhealthyHint')}
                inputMode="numeric"
                onChange={(e) =>
                  setForm((f) => ({ ...f, healthCheckUnhealthy: e.target.value }))
                }
                required
              />
              <Input
                label={t('pages.basic.healthCheckHealthy')}
                value={form.healthCheckHealthy}
                hint={t('pages.basic.healthCheckHealthyHint')}
                inputMode="numeric"
                onChange={(e) =>
                  setForm((f) => ({ ...f, healthCheckHealthy: e.target.value }))
                }
                required
              />
            </div>
          </>
        )}
        {error && (
          <p
            role="alert"
            className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
          >
            {error}
          </p>
        )}
      </div>
    </Dialog>
  )
}
