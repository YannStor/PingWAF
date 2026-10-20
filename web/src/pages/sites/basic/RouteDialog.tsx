import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Dialog } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { useToast } from '@/components/ui/Toast'
import { sitesApi, siteKeys } from '@/api/sites'
import { errorMessage } from '@/api/errors'
import type {
  CreateRouteRequest,
  IpGroupResponse,
  Route,
  UpdateRouteRequest,
  UpstreamPool,
} from '@/api/types'
import { emptyRouteForm, isValidRewritePath, type RouteFormState } from './types'

export type RouteDialogRequest =
  | { mode: 'create'; poolId: string }
  | { mode: 'edit'; route: Route }

export function RouteDialog({
  siteId,
  request,
  pools,
  gateableGroups,
  ipGroupById,
  onClose,
}: {
  siteId: string
  request: RouteDialogRequest
  pools: UpstreamPool[]
  /** Groups the server accepts as a route gate: enabled with ranges. */
  gateableGroups: IpGroupResponse[]
  ipGroupById: Map<string, IpGroupResponse>
  onClose: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const editing = request.mode === 'edit' ? request.route : null
  const [form, setForm] = useState<RouteFormState>(() =>
    request.mode === 'edit'
      ? {
          name: request.route.name,
          matchType: request.route.match_type,
          path: request.route.path,
          priority:
            request.route.priority === null ? '' : String(request.route.priority),
          poolId: request.route.pool_id,
          ipGroupId: request.route.ip_group_id ?? '',
          enabled: request.route.enabled,
          rewritePath: request.route.rewrite_path ?? '',
          stripPrefix: request.route.strip_prefix ?? false,
        }
      : emptyRouteForm(request.poolId),
  )
  const [error, setError] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: (data: { id?: string; create?: CreateRouteRequest; update?: UpdateRouteRequest }) =>
      data.id
        ? sitesApi.updateRoute(siteId, data.id, data.update ?? {})
        : sitesApi.createRoute(siteId, data.create!),
    onSuccess: (route, vars) => {
      toast.success(
        vars.id ? t('pages.basic.routeUpdated') : t('pages.basic.routeCreated'),
        route.name,
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
    const matchType = form.matchType
    const path = form.path.trim()
    if (!path || path.length > 512) {
      setError(t('pages.basic.errors.pathRequired'))
      return
    }
    if (matchType === 'regex') {
      try {
        new RegExp(path)
      } catch {
        setError(t('pages.basic.errors.regexInvalid'))
        return
      }
    } else {
      if (!path.startsWith('/')) {
        setError(t('pages.basic.errors.pathStartSlash'))
        return
      }
      if (path.startsWith('=') || path.startsWith('~')) {
        setError(t('pages.basic.errors.pathSpecial'))
        return
      }
      if (matchType === 'prefix' && path === '/') {
        setError(t('pages.basic.errors.pathRootPrefix'))
        return
      }
    }

    let priority: number | null = null
    if (form.priority.trim() !== '') {
      const parsed = Number(form.priority)
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 60_000) {
        setError(t('pages.basic.errors.priorityInvalid'))
        return
      }
      priority = parsed
    }

    if (!form.poolId || !pools.some((p) => p.id === form.poolId)) {
      setError(t('pages.basic.errors.poolRequired'))
      return
    }

    const rewrite = form.rewritePath.trim()
    if (rewrite && !isValidRewritePath(rewrite)) {
      setError(t('errors.validation'))
      return
    }
    // The rewrite wins over stripping, and both only apply to prefix matches
    // (the server rejects `strip_prefix` on other match types with a 400).
    const rewritePath = form.matchType === 'prefix' && rewrite ? rewrite : null
    const stripPrefix =
      form.matchType === 'prefix' && !rewritePath && form.stripPrefix

    if (editing) {
      save.mutate({
        id: editing.id,
        update: {
          name,
          match_type: matchType,
          path,
          // `0` clears the priority back to the auto weight server-side.
          priority: priority ?? 0,
          enabled: form.enabled,
          pool_id: form.poolId,
          ip_group_id: form.ipGroupId === '' ? null : form.ipGroupId,
          strip_prefix: stripPrefix,
          rewrite_path: rewritePath,
        },
      })
      return
    }

    save.mutate({
      create: {
        name,
        match_type: matchType,
        path,
        priority,
        enabled: form.enabled,
        pool_id: form.poolId,
        ip_group_id: form.ipGroupId === '' ? null : form.ipGroupId,
        strip_prefix: stripPrefix,
        rewrite_path: rewritePath,
      },
    })
  }

  return (
    <Dialog
      open
      onClose={save.isPending ? () => undefined : onClose}
      title={editing ? t('pages.basic.editRoute') : t('pages.basic.addRoute')}
      description={t('pages.basic.routeDialogDescription')}
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
          label={t('pages.basic.routeName')}
          value={form.name}
          placeholder={t('pages.basic.routeNamePlaceholder')}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          autoFocus
          required
        />
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Select
            label={t('pages.basic.matchType')}
            value={form.matchType}
            options={[
              { value: 'prefix', label: t('pages.basic.match.prefix') },
              { value: 'exact', label: t('pages.basic.match.exact') },
              { value: 'regex', label: t('pages.basic.match.regex') },
            ]}
            onChange={(e) => setForm((f) => ({ ...f, matchType: e.target.value }))}
          />
          <Input
            label={t('pages.basic.routePath')}
            value={form.path}
            placeholder={form.matchType === 'regex' ? '^/static/.*' : '/api'}
            hint={
              form.matchType === 'regex'
                ? t('pages.basic.pathRegexHint')
                : t('pages.basic.routePathHint')
            }
            className="pw-mono"
            onChange={(e) => setForm((f) => ({ ...f, path: e.target.value }))}
            required
          />
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Input
            label={t('pages.basic.priority')}
            type="number"
            min={1}
            max={60000}
            value={form.priority}
            placeholder={t('pages.basic.auto')}
            hint={t('pages.basic.priorityHint')}
            onChange={(e) => setForm((f) => ({ ...f, priority: e.target.value }))}
          />
          <Select
            label={t('pages.basic.targetPool')}
            value={form.poolId}
            options={pools.map((p) => ({
              value: p.id,
              label: p.is_default ? `${p.name} (${t('pages.basic.defaultBadge')})` : p.name,
            }))}
            onChange={(e) => setForm((f) => ({ ...f, poolId: e.target.value }))}
          />
        </div>
        <Select
          label={t('pages.basic.ipGroup')}
          value={form.ipGroupId}
          options={[
            { value: '', label: t('pages.basic.ipGroupNone') },
            ...gateableGroups.map((g) => ({ value: g.id, label: g.name })),
            ...(editing?.ip_group_id && !gateableGroups.some((g) => g.id === editing.ip_group_id)
              ? [
                  {
                    value: editing.ip_group_id,
                    label: `${ipGroupById.get(editing.ip_group_id)?.name ?? editing.ip_group_id} (${t('pages.basic.ipGroupUnusable')})`,
                  },
                ]
              : []),
          ]}
          hint={t('pages.basic.ipGroupHint')}
          onChange={(e) => setForm((f) => ({ ...f, ipGroupId: e.target.value }))}
        />
        <Input
          label={t('pages.routes.rewritePath')}
          value={form.rewritePath}
          placeholder="/v1"
          hint={t('pages.routes.rewritePathHint')}
          className="pw-mono"
          disabled={form.matchType !== 'prefix'}
          onChange={(e) => setForm((f) => ({ ...f, rewritePath: e.target.value }))}
        />
        <Switch
          checked={form.stripPrefix}
          onCheckedChange={(stripPrefix) => setForm((f) => ({ ...f, stripPrefix }))}
          disabled={form.matchType !== 'prefix' || form.rewritePath.trim() !== ''}
          label={t('pages.routes.stripPrefix')}
          description={
            form.rewritePath.trim() !== ''
              ? t('pages.routes.rewritePathHint')
              : t('pages.routes.stripPrefixHint')
          }
        />
        <Switch
          checked={form.enabled}
          onCheckedChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
          label={t('common.enabled')}
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
