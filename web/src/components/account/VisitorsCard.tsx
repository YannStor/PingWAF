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
import { Textarea } from '@/components/ui/Textarea'
import { useToast } from '@/components/ui/Toast'
import { visitorApi, visitorKeys } from '@/api/siteOidc'
import { sitesApi, siteKeys } from '@/api/sites'
import type { Visitor } from '@/api/types'
import {
  EMPTY_VISITOR_FORM as EMPTY_FORM,
  VISITOR_REMARK_MAX_LENGTH,
  createVisitorPayload,
  updateVisitorPayload,
  visitorFormFrom as formFrom,
  type VisitorFormState as FormState,
} from './visitorForm'

/**
 * Visitor accounts, managed for the whole deployment.
 *
 * A visitor is a person a protected site admits — not a console operator. They
 * sign in at the site's own login page (rendered by the data plane) and never
 * reach this page, so the console only creates the account and grants it
 * sites. The grants are what decide which sites are reachable after signing
 * in; a visitor with no grant can authenticate but enter nowhere.
 *
 * No read path returns a password, so the edit form has no mask to send back:
 * leaving the field empty keeps the stored password, and typing one replaces
 * it. That is deliberately unlike the OIDC provider card, where the console
 * holds a credential it never uses itself.
 */

export function VisitorsCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const toast = useToast()
  const [editing, setEditing] = useState<Visitor | null>(null)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState<FormState>(EMPTY_FORM)
  const [confirming, setConfirming] = useState<Visitor | null>(null)

  const visitorsQuery = useQuery({
    queryKey: visitorKeys.all,
    queryFn: visitorApi.list,
  })

  // The grant picker needs the site list; a failure here degrades to "no
  // sites to pick" rather than taking the whole card down.
  const sitesQuery = useQuery({
    queryKey: siteKeys.list({}),
    queryFn: () => sitesApi.list({}),
    retry: false,
  })
  const sites = sitesQuery.data?.items ?? []

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: visitorKeys.all })

  const save = useMutation({
    mutationFn: (payload: { id: string | null; form: FormState }) => {
      const { id, form } = payload
      if (id === null) {
        return visitorApi.create(createVisitorPayload(form))
      }
      return visitorApi.update(id, updateVisitorPayload(form))
    },
    onSuccess: (_saved, variables) => {
      toast.success(
        variables.id === null
          ? t('pages.account.visitorCreated')
          : t('pages.account.visitorSaved'),
      )
      setCreating(false)
      setEditing(null)
      invalidate()
    },
  })

  const remove = useMutation({
    mutationFn: (visitor: Visitor) => visitorApi.remove(visitor.id),
    onSuccess: () => {
      toast.success(t('pages.account.visitorDeleted'))
      setConfirming(null)
      invalidate()
    },
  })

  const openCreate = () => {
    setForm(EMPTY_FORM)
    setCreating(true)
  }

  const openEdit = (visitor: Visitor) => {
    setForm(formFrom(visitor))
    setEditing(visitor)
  }

  const dialogOpen = creating || editing !== null
  const blockedReason =
    form.email.trim() === ''
      ? t('pages.account.visitorEmailRequired')
      : creating && form.password.length < 8
        ? t('pages.account.visitorPasswordRequired')
        : undefined

  return (
    <Card>
      <CardHeader
        title={t('pages.account.visitors')}
        description={t('pages.account.visitorsHint')}
        action={
          canWrite ? (
            <Button
              variant="secondary"
              onClick={openCreate}
              icon={<Plus weight="duotone" className="h-4 w-4" />}
            >
              {t('pages.account.visitorAdd')}
            </Button>
          ) : undefined
        }
      />
      <CardBody>
        {visitorsQuery.isError ? (
          <ErrorState
            variant="inline"
            error={visitorsQuery.error}
            onRetry={() => void visitorsQuery.refetch()}
            retrying={visitorsQuery.isFetching}
          />
        ) : (visitorsQuery.data ?? []).length === 0 ? (
          <EmptyState
            title={t('pages.account.visitorsEmpty')}
            description={t('pages.account.visitorsEmptyHint')}
          />
        ) : (
          <ul className="flex flex-col">
            {(visitorsQuery.data ?? []).map((visitor) => (
              <li
                key={visitor.id}
                className="flex items-center justify-between gap-4 border-t border-border py-3 first:border-t-0"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-sm font-medium text-fg-strong">
                      {visitor.email}
                    </span>
                    {visitor.disabled && (
                      <Badge tone="neutral" size="sm">
                        {t('pages.account.visitorDisabledBadge')}
                      </Badge>
                    )}
                  </div>
                  <div className="mt-0.5 text-xs text-fg-subtle">
                    {visitor.name !== '' && <span>{visitor.name} · </span>}
                    {t('pages.account.visitorSiteCount', {
                      count: visitor.site_ids.length,
                    })}
                  </div>
                  {visitor.remark !== '' && (
                    <p className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-fg-subtle">
                      {visitor.remark}
                    </p>
                  )}
                </div>
                {canWrite && (
                  <div className="flex shrink-0 items-center gap-1">
                    <Button variant="ghost" onClick={() => openEdit(visitor)}>
                      {t('common.edit')}
                    </Button>
                    <Button
                      variant="ghost"
                      aria-label={t('common.delete')}
                      onClick={() => setConfirming(visitor)}
                      icon={<Trash weight="duotone" className="h-4 w-4" />}
                    />
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardBody>

      <Dialog
        open={dialogOpen}
        onClose={() => {
          setCreating(false)
          setEditing(null)
        }}
        title={
          creating
            ? t('pages.account.visitorAdd')
            : t('pages.account.visitorEdit')
        }
        footer={
          <>
            <Button
              variant="secondary"
              onClick={() => {
                setCreating(false)
                setEditing(null)
              }}
            >
              {t('common.cancel')}
            </Button>
            <Button
              onClick={() =>
                save.mutate({ id: editing?.id ?? null, form })
              }
              disabled={Boolean(blockedReason)}
              loading={save.isPending}
            >
              {t('common.save')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          {blockedReason && (
            <p className="text-xs text-fg-danger" role="alert">
              {blockedReason}
            </p>
          )}
          <Input
            label={t('pages.account.visitorEmail')}
            hint={t('pages.account.visitorEmailHint')}
            type="email"
            value={form.email}
            // The handle identifies the account, so it is fixed after
            // creation: changing it would silently orphan the visitor's
            // sessions and passkeys.
            disabled={!creating}
            autoComplete="off"
            onChange={(event) =>
              setForm((current) => ({
                ...current,
                email: event.target.value,
              }))
            }
          />
          <Input
            label={
              creating
                ? t('pages.account.visitorPassword')
                : t('pages.account.visitorPasswordNew')
            }
            hint={
              creating
                ? t('pages.account.visitorPasswordHint')
                : t('pages.account.visitorPasswordKeep')
            }
            type="password"
            value={form.password}
            autoComplete="new-password"
            onChange={(event) =>
              setForm((current) => ({
                ...current,
                password: event.target.value,
              }))
            }
          />
          <Input
            label={t('pages.account.visitorName')}
            value={form.name}
            autoComplete="off"
            onChange={(event) =>
              setForm((current) => ({ ...current, name: event.target.value }))
            }
          />
          <Textarea
            label={t('pages.account.visitorRemark')}
            hint={t('pages.account.visitorRemarkHint', {
              max: VISITOR_REMARK_MAX_LENGTH,
            })}
            value={form.remark}
            rows={3}
            maxLength={VISITOR_REMARK_MAX_LENGTH}
            onChange={(event) =>
              setForm((current) => ({ ...current, remark: event.target.value }))
            }
          />
          <Switch
            checked={form.disabled}
            onCheckedChange={(disabled) =>
              setForm((current) => ({ ...current, disabled }))
            }
            label={t('pages.account.visitorDisabled')}
            description={t('pages.account.visitorDisabledHint')}
          />
          <div className="flex flex-col gap-2">
            <span className="text-[13px] font-medium text-fg-strong">
              {t('pages.account.visitorSites')}
            </span>
            <p className="text-xs text-fg-subtle">
              {t('pages.account.visitorSitesHint')}
            </p>
            {sites.length === 0 ? (
              <p className="text-xs text-fg-subtle">
                {t('pages.account.visitorsEmptyHint')}
              </p>
            ) : (
              <div className="flex max-h-56 flex-col gap-1 overflow-y-auto rounded-md border border-border p-2">
                {sites.map((site) => {
                  const checked = form.siteIds.includes(site.id)
                  return (
                    <label
                      key={site.id}
                      className="flex cursor-pointer items-center gap-3 rounded px-2 py-1.5 hover:bg-recessed"
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={(event) =>
                          setForm((current) => ({
                            ...current,
                            siteIds: event.target.checked
                              ? [...current.siteIds, site.id]
                              : current.siteIds.filter((id) => id !== site.id),
                          }))
                        }
                      />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[13px] text-fg-strong">
                          {site.name}
                        </span>
                        <span className="block truncate text-xs text-fg-subtle">
                          {site.domain}
                        </span>
                      </span>
                    </label>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      </Dialog>

      <ConfirmDialog
        open={confirming !== null}
        title={t('pages.account.visitorDeleteTitle')}
        description={t('pages.account.visitorDeleteMessage', {
          email: confirming?.email ?? '',
        })}
        confirmLabel={t('common.delete')}
        loading={remove.isPending}
        onClose={() => setConfirming(null)}
        onConfirm={() => confirming && remove.mutate(confirming)}
      />
    </Card>
  )
}