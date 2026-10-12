import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fingerprint, PencilSimple, Plus, Trash, Warning } from '@phosphor-icons/react'
import { Card, CardBody, CardFooter, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Dialog } from '@/components/ui/Dialog'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { passkeyKeys, passkeysApi } from '@/api/passkeys'
import { errorMessage } from '@/api/errors'
import { isPasskeyCancellation, passkeysSupported } from '@/lib/webauthn'
import { formatDateTime, formatRelative } from '@/lib/format'
import type { PasskeySummary } from '@/api/types'

/**
 * Passkeys bound to the signed-in account.
 *
 * Every account manages its own credentials, so the card is not gated on the
 * admin role — a viewer may sign in with a passkey too. Lives on the
 * /profile page; the Settings page only keeps the deployment-wide switch.
 */
export function PasskeysCard() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [addOpen, setAddOpen] = useState(false)
  const [name, setName] = useState('')
  const [addError, setAddError] = useState<string | null>(null)
  const [pendingRename, setPendingRename] = useState<PasskeySummary | null>(null)
  const [renameTo, setRenameTo] = useState('')
  const [pendingDelete, setPendingDelete] = useState<PasskeySummary | null>(null)

  const supported = passkeysSupported()

  const query = useQuery({
    queryKey: passkeyKeys.list(),
    queryFn: () => passkeysApi.list(),
    enabled: supported,
  })
  const passkeys = query.data ?? []

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: passkeyKeys.all })

  const add = useMutation({
    mutationFn: (label: string) => passkeysApi.register(label),
    // Dismissing the browser prompt is not an API failure worth a toast.
    meta: { silentToast: true },
    onSuccess: () => {
      setAddOpen(false)
      setName('')
      setAddError(null)
      invalidate()
      toast.success(t('pages.settings.passkeyAdded'))
    },
    onError: (err) => {
      if (isPasskeyCancellation(err)) return
      setAddError(errorMessage(err))
    },
  })

  const rename = useMutation({
    mutationFn: (passkey: PasskeySummary) => passkeysApi.rename(passkey.id, renameTo.trim()),
    onSuccess: () => {
      setPendingRename(null)
      invalidate()
      toast.success(t('pages.settings.passkeyRenamed'))
    },
  })

  const remove = useMutation({
    mutationFn: (passkey: PasskeySummary) => passkeysApi.remove(passkey.id),
    onSuccess: () => {
      setPendingDelete(null)
      invalidate()
      toast.success(t('pages.settings.passkeyRemoved'))
    },
  })

  const columns: Column<PasskeySummary>[] = useMemo(
    () => [
      {
        key: 'name',
        header: t('common.name'),
        accessor: (p) => p.name,
        sortable: true,
        cell: (p) => (
          <div className="flex min-w-0 items-center gap-2">
            <Fingerprint weight="duotone" className="h-4 w-4 shrink-0 text-fg-subtle" />
            <span className="truncate text-[13px] font-medium text-fg-strong">{p.name}</span>
          </div>
        ),
      },
      {
        key: 'created_at',
        header: t('pages.settings.passkeyCreated'),
        accessor: (p) => p.created_at,
        sortable: true,
        width: '1%',
        cell: (p) => (
          <span className="text-[13px] text-fg-subtle">{formatDateTime(p.created_at)}</span>
        ),
      },
      {
        key: 'last_used_at',
        header: t('pages.settings.passkeyLastUsed'),
        accessor: (p) => p.last_used_at,
        width: '1%',
        cell: (p) => (
          <span className="text-[13px] text-fg-subtle">{formatRelative(p.last_used_at)}</span>
        ),
      },
      {
        key: 'row-actions',
        header: '',
        align: 'right',
        width: '1%',
        cell: (p) => (
          <div className="flex items-center justify-end gap-1">
            <Button
              size="icon"
              variant="ghost"
              aria-label={t('pages.settings.renamePasskey')}
              onClick={() => {
                setRenameTo(p.name)
                setPendingRename(p)
              }}
              icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
            />
            <Button
              size="icon"
              variant="ghost"
              className="hover:text-fg-danger"
              aria-label={t('pages.settings.deletePasskeyTitle')}
              onClick={() => setPendingDelete(p)}
              icon={<Trash weight="duotone" className="h-4 w-4" />}
            />
          </div>
        ),
      },
    ],
    [t],
  )

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.passkeys')}
        description={t('pages.settings.passkeysDescription')}
        action={
          supported && passkeys.length > 0 ? (
            <Button
              size="sm"
              variant="secondary"
              icon={<Plus weight="bold" className="h-4 w-4" />}
              onClick={() => setAddOpen(true)}
            >
              {t('pages.settings.addPasskey')}
            </Button>
          ) : undefined
        }
      />
      <CardBody className={passkeys.length === 0 ? undefined : 'p-0'}>
        {!supported ? (
          <p className="flex items-start gap-2 text-sm text-fg-subtle">
            <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg-warning" />
            {t('pages.settings.passkeyUnsupported')}
          </p>
        ) : query.isError && !query.data ? (
          <ErrorState
            variant="inline"
            error={query.error}
            onRetry={() => query.refetch()}
            retrying={query.isFetching}
          />
        ) : query.isPending ? (
          <SkeletonRows rows={2} columns={3} />
        ) : passkeys.length === 0 ? (
          <EmptyState
            className="py-10"
            icon={<Fingerprint weight="duotone" className="h-8 w-8" />}
            title={t('pages.settings.noPasskeys')}
            description={t('pages.settings.noPasskeysDescription')}
            action={
              <Button
                variant="primary"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={() => setAddOpen(true)}
              >
                {t('pages.settings.addPasskey')}
              </Button>
            }
          />
        ) : (
          <Table columns={columns} data={passkeys} rowKey={(p) => p.id} dense />
        )}
      </CardBody>

      {supported && (
        <CardFooter className="justify-start text-left text-xs text-fg-subtle">
          {t('pages.settings.passkeysDomainHint')}
        </CardFooter>
      )}

      {/* Bind a new authenticator */}
      <Dialog
        open={addOpen}
        onClose={add.isPending ? () => undefined : () => setAddOpen(false)}
        title={t('pages.settings.addPasskey')}
        description={t('pages.settings.passkeysDescription')}
        footer={
          <>
            <Button
              variant="ghost"
              onClick={() => setAddOpen(false)}
              disabled={add.isPending}
            >
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              loading={add.isPending}
              disabled={!name.trim()}
              onClick={() => add.mutate(name.trim())}
            >
              {t('pages.settings.addPasskey')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <Input
            label={t('pages.settings.passkeyName')}
            value={name}
            autoFocus
            placeholder={t('pages.settings.passkeyNamePlaceholder')}
            error={addError ?? undefined}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
      </Dialog>

      {/* Rename */}
      <Dialog
        open={pendingRename !== null}
        onClose={() => setPendingRename(null)}
        title={t('pages.settings.renamePasskey')}
        description={t('pages.settings.renamePasskeyDescription')}
        footer={
          <>
            <Button variant="ghost" onClick={() => setPendingRename(null)}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              loading={rename.isPending}
              disabled={!renameTo.trim()}
              onClick={() => pendingRename && rename.mutate(pendingRename)}
            >
              {t('common.save')}
            </Button>
          </>
        }
      >
        <Input
          label={t('pages.settings.passkeyName')}
          value={renameTo}
          autoFocus
          onChange={(e) => setRenameTo(e.target.value)}
        />
      </Dialog>

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete)}
        title={t('pages.settings.deletePasskeyTitle')}
        description={t('pages.settings.deletePasskeyDescription')}
        confirmLabel={t('common.delete')}
        loading={remove.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDelete.name}</p>
            <p className="mt-0.5 text-xs text-fg-subtle">
              {formatDateTime(pendingDelete.created_at)}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </Card>
  )
}

export default PasskeysCard
