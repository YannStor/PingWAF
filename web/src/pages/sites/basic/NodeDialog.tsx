import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Globe } from '@phosphor-icons/react'
import { Dialog } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { useToast } from '@/components/ui/Toast'
import { sitesApi, siteKeys } from '@/api/sites'
import { errorMessage } from '@/api/errors'
import type {
  CreateUpstreamRequest,
  UpdateUpstreamRequest,
  Upstream,
  UpstreamPool,
} from '@/api/types'
import { emptyNodeForm, parseOriginAddress, type NodeFormState } from './types'

export type NodeDialogRequest =
  | { mode: 'create'; poolId: string }
  | { mode: 'edit'; node: Upstream }

export function NodeDialog({
  siteId,
  request,
  pools,
  onClose,
}: {
  siteId: string
  request: NodeDialogRequest
  pools: UpstreamPool[]
  onClose: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const editing = request.mode === 'edit' ? request.node : null
  const [form, setForm] = useState<NodeFormState>(() =>
    request.mode === 'edit'
      ? {
          address: request.node.address,
          weight: String(request.node.weight),
          poolId: request.node.pool_id,
        }
      : emptyNodeForm(request.poolId),
  )
  const [error, setError] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: (data: { id?: string; payload: CreateUpstreamRequest | UpdateUpstreamRequest }) =>
      data.id
        ? sitesApi.updateUpstream(siteId, data.id, data.payload as UpdateUpstreamRequest)
        : sitesApi.createUpstream(siteId, data.payload as CreateUpstreamRequest),
    onSuccess: (node, vars) => {
      toast.success(
        vars.id ? t('pages.basic.nodeUpdated') : t('pages.basic.nodeCreated'),
        node.address,
      )
      void queryClient.invalidateQueries({ queryKey: siteKeys.all })
      onClose()
    },
    onError: (e) => setError(errorMessage(e)),
  })

  const submit = () => {
    setError(null)
    const parsed = parseOriginAddress(form.address)
    if ('error' in parsed) {
      setError(t(`pages.basic.${parsed.error}`))
      return
    }
    const address = parsed.address
    const weight = Number(form.weight)
    if (!Number.isInteger(weight) || weight < 1 || weight > 10_000) {
      setError(t('pages.basic.errors.weightInvalid'))
      return
    }
    if (!form.poolId || !pools.some((p) => p.id === form.poolId)) {
      setError(t('pages.basic.errors.poolRequired'))
      return
    }

    if (editing) {
      save.mutate({ id: editing.id, payload: { address, weight, pool_id: form.poolId } })
      return
    }
    save.mutate({ payload: { address, weight, pool_id: form.poolId } })
  }

  return (
    <Dialog
      open
      onClose={save.isPending ? () => undefined : onClose}
      title={editing ? t('pages.basic.editNode') : t('pages.basic.addNode')}
      description={t('pages.basic.nodeDialogDescription')}
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
          label={t('pages.basic.nodeAddress')}
          value={form.address}
          placeholder="http://10.0.0.1:8080"
          hint={t('pages.basic.nodeAddressHint')}
          prefixIcon={<Globe weight="duotone" />}
          className="pw-mono"
          onChange={(e) => setForm((f) => ({ ...f, address: e.target.value }))}
          autoFocus
          required
        />
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Input
            label={t('pages.basic.nodeWeight')}
            type="number"
            min={1}
            max={10000}
            value={form.weight}
            hint={t('pages.basic.nodeWeightHint')}
            onChange={(e) => setForm((f) => ({ ...f, weight: e.target.value }))}
            required
          />
        </div>
        <Select
          label={t('pages.basic.nodePool')}
          value={form.poolId}
          options={pools.map((p) => ({
            value: p.id,
            label: p.is_default ? `${p.name} (${t('pages.basic.defaultBadge')})` : p.name,
          }))}
          onChange={(e) => setForm((f) => ({ ...f, poolId: e.target.value }))}
        />
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
