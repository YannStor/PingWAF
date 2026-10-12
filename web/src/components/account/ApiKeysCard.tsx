import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  BookOpen,
  Copy,
  Key,
  Plus,
  Trash,
  Warning,
} from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { PillMultiSelect } from '@/components/ui/MultiSelect'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { KEY_PERMISSIONS, keyKeys, keysApi } from '@/api/keys'
import { cn } from '@/lib/utils'
import { formatDateTime, formatRelative, fromLocalInputValue, toLocalInputValue } from '@/lib/format'
import type { ApiKey, CreateApiKeyRequest } from '@/api/types'

/** Public REST reference shipped with the repository. */
const API_DOCS_URL = 'https://github.com/shuaiZend/PingWAF/blob/main/docs/api.md'

/**
 * API key administration (global configuration).
 *
 * System-minted keys (bootstrap, agent enrollment) are labelled "system"
 * instead of a creator account, and deleting one demands typing the key's
 * full name: a mistaken revocation strands agent (re-)registration.
 */
export function ApiKeysCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [dialogOpen, setDialogOpen] = useState(false)
  const [name, setName] = useState('')
  const [permissions, setPermissions] = useState<string[]>(['agent', 'read'])
  const [expiresAt, setExpiresAt] = useState('')
  const [secret, setSecret] = useState<ApiKey | null>(null)
  const [pendingRevoke, setPendingRevoke] = useState<ApiKey | null>(null)
  // Typed confirmation for system keys; empty for regular keys.
  const [confirmName, setConfirmName] = useState('')

  const keysQuery = useQuery({
    queryKey: keyKeys.list(),
    queryFn: () => keysApi.list(),
    select: (page) => page.items,
  })

  const keys = keysQuery.data ?? []

  const create = useMutation({
    mutationFn: (data: CreateApiKeyRequest) => keysApi.create(data),
    onSuccess: (created) => {
      setDialogOpen(false)
      setName('')
      setPermissions(['agent', 'read'])
      setExpiresAt('')
      setSecret(created)
      void queryClient.invalidateQueries({ queryKey: keyKeys.all })
    },
  })

  const revoke = useMutation({
    mutationFn: (id: string) => keysApi.revoke(id),
    onSuccess: (_data, id) => {
      toast.success(t('pages.settings.keyRevoked'), keys.find((k) => k.id === id)?.name)
      setPendingRevoke(null)
      void queryClient.invalidateQueries({ queryKey: keyKeys.all })
    },
  })

  /** Two-step flow for system keys: first confirm, then type the name. */
  const requestRevoke = (key: ApiKey) => {
    setConfirmName('')
    setPendingRevoke(key)
  }

  const isSystem = pendingRevoke?.is_system ?? false
  const confirmDisabled = isSystem && confirmName.trim() !== (pendingRevoke?.name ?? '')

  const columns: Column<ApiKey>[] = useMemo(
    () => [
      {
        key: 'name',
        header: t('common.name'),
        accessor: (k) => k.name,
        sortable: true,
        cell: (k) => (
          <div className="min-w-0">
            <p className="truncate text-[13px] font-medium text-fg-strong">{k.name}</p>
            <p className="pw-mono truncate text-xs text-fg-subtle">{k.key_prefix}…</p>
          </div>
        ),
      },
      {
        key: 'creator',
        header: t('pages.settings.keyCreator'),
        width: '1%',
        cell: (k) =>
          k.is_system ? (
            <Badge tone="info" size="sm">
              {t('pages.settings.keySystem')}
            </Badge>
          ) : k.creator ? (
            <span className="pw-mono text-[13px] text-fg-subtle">{k.creator}</span>
          ) : (
            <span className="text-[13px] text-fg-subtle">—</span>
          ),
      },
      {
        key: 'permissions',
        header: t('pages.settings.permissions'),
        width: '1%',
        cell: (k) => (
          <div className="flex flex-wrap gap-1">
            {(k.permissions ?? []).map((p) => (
              <Badge key={p} tone={p === 'write' ? 'warning' : p === 'agent' ? 'brand' : 'neutral'}>
                {p}
              </Badge>
            ))}
          </div>
        ),
      },
      {
        key: 'expires_at',
        header: t('pages.settings.expires'),
        accessor: (k) => k.expires_at ?? '',
        width: '1%',
        cell: (k) =>
          k.expires_at ? (
            <span
              className={cn(
                'text-[13px]',
                new Date(k.expires_at).getTime() < Date.now() ? 'text-fg-danger' : 'text-fg-subtle',
              )}
            >
              {formatDateTime(k.expires_at)}
            </span>
          ) : (
            <span className="text-[13px] text-fg-subtle">{t('pages.settings.neverExpires')}</span>
          ),
      },
      {
        key: 'last_used_at',
        header: t('pages.settings.lastUsed'),
        accessor: (k) => k.last_used_at ?? '',
        width: '1%',
        cell: (k) => (
          <span className="text-[13px] text-fg-subtle">
            {k.last_used_at ? formatRelative(k.last_used_at) : t('pages.settings.neverUsed')}
          </span>
        ),
      },
      {
        key: 'created_at',
        header: t('pages.settings.created'),
        accessor: (k) => k.created_at,
        sortable: true,
        width: '1%',
        cell: (k) => (
          <span className="text-[13px] text-fg-subtle">{formatDateTime(k.created_at)}</span>
        ),
      },
      {
        key: 'row-actions',
        header: '',
        align: 'right',
        width: '1%',
        cell: (k) => (
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('pages.settings.revoke')}
            disabled={!canWrite}
            onClick={() => requestRevoke(k)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        ),
      },
    ],
    [t, canWrite],
  )

  const copySecret = async () => {
    if (!secret?.key) return
    try {
      await navigator.clipboard.writeText(secret.key)
      toast.success(t('pages.settings.copied'))
    } catch {
      toast.error(t('pages.settings.copyFailed'))
    }
  }

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.apiKeys')}
        description={t('pages.settings.apiKeysDescription')}
        action={
          <div className="flex items-center gap-2">
            <a
              href={API_DOCS_URL}
              target="_blank"
              rel="noreferrer noopener"
              className={cn(
                'inline-flex h-8 items-center gap-1.5 rounded-md border border-line bg-elevated px-3',
                'text-[13px] font-medium text-fg shadow-sm transition-colors hover:bg-recessed',
              )}
            >
              <BookOpen weight="duotone" className="h-4 w-4" />
              {t('pages.settings.apiDocs')}
            </a>
            {canWrite && (
              <Button
                size="sm"
                variant="primary"
                icon={<Plus weight="bold" className="h-4 w-4" />}
                onClick={() => setDialogOpen(true)}
              >
                {t('common.create')}
              </Button>
            )}
          </div>
        }
      />
      <CardBody className="p-0">
        {keysQuery.isError && !keysQuery.data ? (
          <div className="p-4">
            <ErrorState
              variant="inline"
              error={keysQuery.error}
              onRetry={() => keysQuery.refetch()}
              retrying={keysQuery.isFetching}
            />
          </div>
        ) : keysQuery.isPending ? (
          <SkeletonRows rows={3} columns={5} />
        ) : keys.length === 0 ? (
          <EmptyState
            className="py-10"
            icon={<Key weight="duotone" className="h-8 w-8" />}
            title={t('pages.settings.noKeys')}
            description={t('pages.settings.noKeysDescription')}
            action={
              canWrite ? (
                <Button
                  variant="primary"
                  icon={<Plus weight="bold" className="h-4 w-4" />}
                  onClick={() => setDialogOpen(true)}
                >
                  {t('common.create')}
                </Button>
              ) : undefined
            }
          />
        ) : (
          <Table columns={columns} data={keys} rowKey={(k) => k.id} dense />
        )}
      </CardBody>

      {/* Create key */}
      <Dialog
        open={dialogOpen}
        onClose={create.isPending ? () => undefined : () => setDialogOpen(false)}
        title={t('pages.settings.createKey')}
        description={t('pages.settings.createKeyDescription')}
        footer={
          <>
            <Button variant="ghost" onClick={() => setDialogOpen(false)} disabled={create.isPending}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              loading={create.isPending}
              disabled={!name.trim() || permissions.length === 0}
              onClick={() =>
                create.mutate({
                  name: name.trim(),
                  permissions,
                  expires_at: expiresAt ? fromLocalInputValue(expiresAt) ?? null : null,
                })
              }
            >
              {t('common.create')}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Input
            label={t('common.name')}
            value={name}
            autoFocus
            placeholder={t('pages.settings.keyNamePlaceholder')}
            onChange={(e) => setName(e.target.value)}
            required
          />
          <PillMultiSelect
            label={t('pages.settings.permissions')}
            hint={t('pages.settings.permissionsHint')}
            min={1}
            value={permissions}
            onChange={setPermissions}
            options={KEY_PERMISSIONS.map((p) => ({
              value: p,
              label: t(`permissions.${p}`, p),
              hint: t(`permissions.${p}Hint`, ''),
            }))}
          />
          <Input
            type="datetime-local"
            label={t('pages.settings.expires')}
            value={expiresAt}
            hint={t('pages.settings.expiresHint')}
            min={toLocalInputValue(new Date())}
            onChange={(e) => setExpiresAt(e.target.value)}
          />
        </div>
      </Dialog>

      {/* One-time secret */}
      <Dialog
        open={secret !== null}
        onClose={() => setSecret(null)}
        title={t('pages.settings.keyCreated')}
        description={t('pages.settings.keyCreatedDescription')}
        footer={
          <>
            <Button variant="secondary" onClick={copySecret} icon={<Copy weight="duotone" className="h-4 w-4" />}>
              {t('pages.settings.copy')}
            </Button>
            <Button variant="primary" onClick={() => setSecret(null)}>
              {t('common.close')}
            </Button>
          </>
        }
      >
        {secret && (
          <div className="flex flex-col gap-3">
            <p className="text-[13px] text-fg-subtle">
              {t('pages.settings.keyName')}: <strong className="text-fg">{secret.name}</strong>
            </p>
            <p className="pw-mono break-all rounded-md border border-brand/40 bg-brand-soft px-3 py-2.5 text-[13px] font-medium text-brand">
              {secret.key}
            </p>
            <p className="flex items-start gap-2 text-xs text-fg-warning">
              <Warning weight="duotone" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {t('pages.settings.keyOnlyShownOnce')}
            </p>
          </div>
        )}
      </Dialog>

      <ConfirmDialog
        open={pendingRevoke !== null}
        onClose={() => setPendingRevoke(null)}
        onConfirm={() => pendingRevoke && revoke.mutate(pendingRevoke.id)}
        title={
          isSystem
            ? t('pages.settings.revokeSystemTitle')
            : t('pages.settings.revokeTitle')
        }
        description={
          isSystem
            ? t('pages.settings.revokeSystemDescription')
            : t('pages.settings.revokeDescription')
        }
        confirmLabel={t('pages.settings.revoke')}
        tone="danger"
        disabled={confirmDisabled}
        loading={revoke.isPending}
      >
        {pendingRevoke && (
          <div className="flex flex-col gap-3">
            <div className="rounded-md border border-line bg-recessed px-3 py-2">
              <p className="text-[13px] font-medium text-fg-strong">{pendingRevoke.name}</p>
              <p className="pw-mono mt-0.5 text-xs text-fg-subtle">{pendingRevoke.key_prefix}…</p>
            </div>
            {isSystem && (
              <Input
                label={t('pages.settings.revokeSystemConfirmLabel', {
                  name: pendingRevoke.name,
                })}
                value={confirmName}
                autoFocus
                className="pw-mono"
                placeholder={pendingRevoke.name}
                error={
                  confirmName.trim() !== '' && confirmDisabled
                    ? t('pages.settings.revokeSystemMismatch')
                    : undefined
                }
                onChange={(e) => setConfirmName(e.target.value)}
              />
            )}
          </div>
        )}
      </ConfirmDialog>
    </Card>
  )
}

export default ApiKeysCard
