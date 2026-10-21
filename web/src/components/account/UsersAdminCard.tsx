import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, PencilSimple, Plus, Prohibit, UserCircle } from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { usersApi, usersKeys } from '@/api/users'
import { useAuthStore } from '@/stores/authStore'
import { formatDateTime } from '@/lib/format'
import type { CreateUserRequest, UpdateUserRequest, User } from '@/api/types'

/** Mirrors the server-side minimum in `validate_password`. */
const MIN_PASSWORD = 8

/** Roles an administrator may assign; mirrors `models::role`. */
const USER_ROLES = ['admin', 'auditor', 'viewer'] as const

/**
 * Edit request plus the pre-computed "this change revokes our own session"
 * flag. The flag is decided at submit time because the store's profile may be
 * gone by the time the response lands (see the `onSuccess` handler).
 */
interface UpdateUserPayload {
  id: string
  data: UpdateUserRequest
  /** Omitted for the enable/disable toggles, which never touch credentials. */
  selfEmailChange?: boolean
}

/**
 * Dashboard user administration (global configuration).
 *
 * Shows the most recent successful login per account, resolved server-side
 * from the login history.
 */
export function UsersAdminCard() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const me = useAuthStore((s) => s.user)
  const setUser = useAuthStore((s) => s.setUser)
  const logout = useAuthStore((s) => s.logout)
  const navigate = useNavigate()

  const [createOpen, setCreateOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<string>('viewer')
  const [editing, setEditing] = useState<User | null>(null)
  const [editName, setEditName] = useState('')
  const [editEmail, setEditEmail] = useState('')
  const [editRole, setEditRole] = useState<string>('viewer')
  const [pendingDisable, setPendingDisable] = useState<User | null>(null)

  const usersQuery = useQuery({
    queryKey: usersKeys.list(),
    queryFn: () => usersApi.list(),
    select: (page) => page.items,
  })

  const users = usersQuery.data ?? []

  const create = useMutation({
    mutationFn: (data: CreateUserRequest) => usersApi.create(data),
    onSuccess: () => {
      setCreateOpen(false)
      setEmail('')
      setName('')
      setPassword('')
      setRole('viewer')
      void queryClient.invalidateQueries({ queryKey: usersKeys.all })
      toast.success(t('pages.account.users.created'))
    },
  })

  const update = useMutation({
    mutationFn: ({ id, data }: UpdateUserPayload) => usersApi.update(id, data),
    onSuccess: (updated, { selfEmailChange = false }) => {
      setEditing(null)
      setPendingDisable(null)
      void queryClient.invalidateQueries({ queryKey: usersKeys.all })
      if (selfEmailChange) {
        // The server bumped this account's token version, so the session we
        // are holding is already dead: close it deliberately instead of
        // letting the next request drop the operator out of nowhere.
        logout()
        queryClient.clear()
        toast.success(t('pages.settings.loginNameChanged'))
        navigate('/login', { replace: true })
        return
      }
      // A self-update (display name) must refresh the stored session profile.
      if (updated.id === me?.id) setUser(updated)
      toast.success(t('pages.account.users.updated'))
    },
  })

  const openEdit = (user: User) => {
    setEditing(user)
    setEditName(user.name ?? '')
    setEditEmail(user.email)
    setEditRole(USER_ROLES.includes(user.role as (typeof USER_ROLES)[number]) ? user.role : 'viewer')
  }

  const columns: Column<User>[] = useMemo(
    () => [
      {
        key: 'account',
        header: t('pages.account.users.colAccount'),
        accessor: (u) => u.email,
        cell: (u) => (
          <div className="min-w-0">
            <p className="flex items-center gap-2 truncate text-[13px] font-medium text-fg-strong">
              {u.email}
              {u.id === me?.id && (
                <Badge size="sm" tone="info">
                  {t('pages.account.users.you')}
                </Badge>
              )}
            </p>
            {u.name && <p className="truncate text-xs text-fg-subtle">{u.name}</p>}
          </div>
        ),
      },
      {
        key: 'role',
        header: t('pages.account.users.role'),
        width: '1%',
        cell: (u) => (
          <Badge tone={u.role === 'admin' ? 'brand' : u.role === 'auditor' ? 'info' : 'neutral'}>
            {t(`user.role.${u.role}`, u.role)}
          </Badge>
        ),
      },
      {
        key: 'status',
        header: t('pages.account.users.colStatus'),
        width: '1%',
        cell: (u) =>
          u.disabled ? (
            <Badge tone="danger">{t('pages.account.users.disabled')}</Badge>
          ) : (
            <Badge tone="success">{t('pages.account.users.active')}</Badge>
          ),
      },
      {
        key: 'last_login',
        header: t('pages.account.users.colLastLogin'),
        accessor: (u) => u.last_login_at ?? '',
        width: '1%',
        cell: (u) =>
          u.last_login_at ? (
            <div className="text-right">
              <p className="text-[13px] text-fg-subtle">{formatDateTime(u.last_login_at)}</p>
              {u.last_login_ip && (
                <p className="pw-mono text-xs text-fg-subtle">{u.last_login_ip}</p>
              )}
            </div>
          ) : (
            <span className="text-[13px] text-fg-subtle">
              {t('pages.account.users.neverLoggedIn')}
            </span>
          ),
      },
      {
        key: 'created_at',
        header: t('pages.settings.created'),
        accessor: (u) => u.created_at,
        sortable: true,
        width: '1%',
        cell: (u) => (
          <span className="text-[13px] text-fg-subtle">{formatDateTime(u.created_at)}</span>
        ),
      },
      {
        key: 'row-actions',
        header: '',
        align: 'right',
        width: '1%',
        cell: (u) => (
          <div className="flex items-center justify-end gap-1">
            <Button
              size="icon"
              variant="ghost"
              aria-label={t('pages.account.users.edit')}
              onClick={() => openEdit(u)}
              icon={<PencilSimple weight="duotone" className="h-4 w-4" />}
            />
            {u.id !== me?.id &&
              (u.disabled ? (
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label={t('pages.account.users.enable')}
                  disabled={update.isPending}
                  onClick={() => update.mutate({ id: u.id, data: { disabled: false } })}
                  icon={<Check weight="duotone" className="h-4 w-4" />}
                />
              ) : (
                <Button
                  size="icon"
                  variant="ghost"
                  className="hover:text-fg-danger"
                  aria-label={t('pages.account.users.disable')}
                  disabled={update.isPending}
                  onClick={() => setPendingDisable(u)}
                  icon={<Prohibit weight="duotone" className="h-4 w-4" />}
                />
              ))}
          </div>
        ),
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [t, me?.id, update.isPending],
  )

  return (
    <Card>
      <CardHeader
        title={t('pages.account.users.title')}
        description={t('pages.account.users.description')}
        action={
          <Button
            size="sm"
            variant="primary"
            icon={<Plus weight="bold" className="h-4 w-4" />}
            onClick={() => setCreateOpen(true)}
          >
            {t('pages.account.users.add')}
          </Button>
        }
      />
      <CardBody className="p-0">
        {usersQuery.isError && !usersQuery.data ? (
          <div className="p-4">
            <ErrorState
              variant="inline"
              error={usersQuery.error}
              onRetry={() => usersQuery.refetch()}
              retrying={usersQuery.isFetching}
            />
          </div>
        ) : usersQuery.isPending ? (
          <SkeletonRows rows={3} columns={4} />
        ) : users.length === 0 ? (
          <EmptyState
            className="py-10"
            icon={<UserCircle weight="duotone" className="h-8 w-8" />}
            title={t('pages.account.users.title')}
            description={t('pages.account.users.description')}
          />
        ) : (
          <Table columns={columns} data={users} rowKey={(u) => u.id} dense />
        )}
      </CardBody>

      {/* Create account */}
      <Dialog
        open={createOpen}
        onClose={create.isPending ? () => undefined : () => setCreateOpen(false)}
        title={t('pages.account.users.add')}
        description={t('pages.account.users.createdHint')}
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)} disabled={create.isPending}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              loading={create.isPending}
              disabled={!email.trim() || password.length === 0}
              onClick={() =>
                create.mutate({
                  email: email.trim(),
                  password,
                  name: name.trim() || undefined,
                  role,
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
            label={t('pages.account.users.email')}
            value={email}
            autoFocus
            placeholder="ops@example.com"
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <Input
            label={t('pages.settings.displayName')}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <Input
            type="password"
            label={t('pages.account.users.password')}
            value={password}
            autoComplete="new-password"
            hint={t('auth.passwordHint', { min: MIN_PASSWORD })}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <Select
            label={t('pages.account.users.role')}
            value={role}
            options={USER_ROLES.map((r) => ({ value: r, label: t(`user.role.${r}`, r) }))}
            onChange={(e) => setRole(e.target.value)}
          />
        </div>
      </Dialog>

      {/* Edit account */}
      <Dialog
        open={editing !== null}
        onClose={update.isPending ? () => undefined : () => setEditing(null)}
        title={t('pages.account.users.edit')}
        description={editing?.email}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditing(null)} disabled={update.isPending}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              loading={update.isPending}
              disabled={editing === null}
              onClick={() => {
                if (!editing) return
                const isSelf = editing.id === me?.id
                const data: UpdateUserRequest = { name: editName.trim() }
                if (editEmail.trim() !== editing.email) {
                  data.email = editEmail.trim()
                }
                if (!isSelf) data.role = editRole
                // Changing your own login name revokes every token we hold.
                // Without a loaded profile we cannot prove the target is
                // somebody else, so assume it is ours: closing the session on
                // purpose beats having it die on the next request.
                const selfEmailChange =
                  data.email !== undefined && (me?.id === undefined || isSelf)
                update.mutate({ id: editing.id, data, selfEmailChange })
              }}
            >
              {t('common.save')}
            </Button>
          </>
        }
      >
        {editing && (
          <div className="flex flex-col gap-4">
            <Input
              type="email"
              label={t('pages.settings.loginName')}
              value={editEmail}
              autoComplete="off"
              hint={t('pages.account.users.emailHint')}
              onChange={(e) => setEditEmail(e.target.value)}
            />
            <Input
              label={t('pages.settings.displayName')}
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
            />
            <Select
              label={t('pages.account.users.role')}
              value={editRole}
              disabled={editing.id === me?.id}
              hint={
                editing.id === me?.id
                  ? t('pages.account.users.selfRoleHint')
                  : undefined
              }
              options={USER_ROLES.map((r) => ({ value: r, label: t(`user.role.${r}`, r) }))}
              onChange={(e) => setEditRole(e.target.value)}
            />
          </div>
        )}
      </Dialog>

      <ConfirmDialog
        open={pendingDisable !== null}
        onClose={() => setPendingDisable(null)}
        onConfirm={() =>
          pendingDisable && update.mutate({ id: pendingDisable.id, data: { disabled: true } })
        }
        title={t('pages.account.users.disableTitle')}
        description={t('pages.account.users.disableDescription')}
        confirmLabel={t('pages.account.users.disable')}
        loading={update.isPending}
      >
        {pendingDisable && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="text-[13px] font-medium text-fg-strong">{pendingDisable.email}</p>
            {pendingDisable.name && (
              <p className="mt-0.5 text-xs text-fg-subtle">{pendingDisable.name}</p>
            )}
          </div>
        )}
      </ConfirmDialog>
    </Card>
  )
}

export default UsersAdminCard
