import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { EnvelopeSimple, Eye, EyeSlash, UserCircle } from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { useToast } from '@/components/ui/Toast'
import { authApi } from '@/api/auth'
import { errorMessage } from '@/api/errors'
import { useAuthStore } from '@/stores/authStore'

/** Mirrors the server-side minimum in `validate_password`. */
const MIN_PASSWORD = 8

/**
 * Personal account settings: display name, login name and password.
 *
 * Lives on the /profile page (top-right "account settings"); the /account
 * page in the sidebar only hosts global configuration.
 */
export function AccountCard() {
  const { t } = useTranslation()
  const toast = useToast()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const setUser = useAuthStore((s) => s.setUser)
  const logout = useAuthStore((s) => s.logout)

  const [name, setName] = useState('')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [email, setEmail] = useState('')
  const [emailPassword, setEmailPassword] = useState('')
  const [emailError, setEmailError] = useState<string | null>(null)

  // `null` until the first seed: a name/e-mail already present at mount must
  // still reach the form.
  const serverName = user?.name ?? ''
  const [lastServerName, setLastServerName] = useState<string | null>(null)
  if (serverName !== lastServerName) {
    setLastServerName(serverName)
    setName(serverName)
  }
  const serverEmail = user?.email ?? ''
  const [lastServerEmail, setLastServerEmail] = useState<string | null>(null)
  if (serverEmail !== lastServerEmail) {
    setLastServerEmail(serverEmail)
    setEmail(serverEmail)
  }

  const profile = useMutation({
    mutationFn: () => authApi.updateProfile({ name: name.trim() || null }),
    onSuccess: (updated) => {
      setUser(updated)
      void queryClient.invalidateQueries({ queryKey: ['auth'] })
      toast.success(t('pages.settings.profileSaved'))
    },
  })

  const loginName = useMutation({
    mutationFn: () =>
      authApi.updateProfile({
        email: email.trim(),
        current_password: emailPassword,
      }),
    meta: { silentToast: true },
    // The token bump on the server killed every session, including this one —
    // sign out and send the operator to the login form.
    onSuccess: () => {
      logout()
      navigate('/login')
      toast.success(t('pages.settings.loginNameChanged'))
    },
    onError: (err) => {
      const message = errorMessage(err)
      setEmailError(
        /current password is incorrect/i.test(message)
          ? t('pages.settings.passwordWrongCurrent')
          : message,
      )
    },
  })

  const submitLoginName = (event: FormEvent) => {
    event.preventDefault()
    if (loginName.isPending) return
    setEmailError(null)
    const trimmed = email.trim()
    if (trimmed === (user?.email ?? '')) {
      setEmailError(t('pages.settings.loginNameUnchanged'))
      return
    }
    if (!emailPassword) {
      setEmailError(t('pages.settings.loginNamePasswordRequired'))
      return
    }
    loginName.mutate()
  }

  const password = useMutation({
    mutationFn: () =>
      authApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    // A wrong current password is a 400 whose message belongs next to the
    // fields, not in a toast.
    meta: { silentToast: true },
    onSuccess: async () => {
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setPasswordError(null)
      // Re-sync the stored profile so the `must_change_password` gate clears
      // (and the role badge stays fresh) without a reload.
      try {
        setUser(await authApi.me())
      } catch {
        /* keep the stale profile; the next reload re-syncs */
      }
      toast.success(t('pages.settings.passwordChanged'))
    },
    onError: (err) => {
      const message = errorMessage(err)
      setPasswordError(
        /current password is incorrect/i.test(message)
          ? t('pages.settings.passwordWrongCurrent')
          : message,
      )
    },
  })

  const submitPassword = (event: FormEvent) => {
    event.preventDefault()
    if (password.isPending) return
    setPasswordError(null)
    if (newPassword.length < MIN_PASSWORD) {
      setPasswordError(t('auth.passwordTooShort', { min: MIN_PASSWORD }))
      return
    }
    if (newPassword === currentPassword) {
      setPasswordError(t('pages.settings.passwordUnchanged'))
      return
    }
    if (newPassword !== confirmPassword) {
      setPasswordError(t('pages.settings.passwordMismatch'))
      return
    }
    password.mutate()
  }

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.account')}
        description={user?.email}
        action={
          <Badge tone={user?.role === 'admin' ? 'brand' : 'neutral'}>
            {t(`user.role.${user?.role ?? 'viewer'}`, user?.role ?? '')}
          </Badge>
        }
      />
      <CardBody className="flex flex-col gap-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="min-w-0 flex-1">
            <Input
              label={t('pages.settings.displayName')}
              value={name}
              placeholder={user?.email ?? ''}
              prefixIcon={<UserCircle weight="duotone" />}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <Button
            variant="secondary"
            loading={profile.isPending}
            disabled={name.trim() === (user?.name ?? '')}
            onClick={() => profile.mutate()}
          >
            {t('common.save')}
          </Button>
        </div>

        <form onSubmit={submitLoginName} className="border-t border-line pt-4">
          <div className="grid max-w-3xl grid-cols-1 gap-4 sm:grid-cols-2">
            <Input
              type="email"
              label={t('pages.settings.loginName')}
              value={email}
              autoComplete="username"
              hint={t('pages.settings.loginNameHint')}
              prefixIcon={<EnvelopeSimple weight="duotone" />}
              error={emailError ?? undefined}
              onChange={(e) => setEmail(e.target.value)}
            />
            <Input
              type="password"
              label={t('pages.settings.currentPassword')}
              value={emailPassword}
              autoComplete="current-password"
              onChange={(e) => setEmailPassword(e.target.value)}
            />
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Button
              type="submit"
              variant="secondary"
              loading={loginName.isPending}
              disabled={email.trim() === (user?.email ?? '') || !emailPassword}
            >
              {t('common.save')}
            </Button>
          </div>
        </form>

        <div className="border-t border-line pt-4">
          <p className="mb-3 text-[13px] font-medium text-fg">
            {t('pages.settings.changePassword')}
          </p>
          <form onSubmit={submitPassword} className="flex flex-col gap-4">
            <div className="grid max-w-3xl grid-cols-1 gap-4 sm:grid-cols-3">
              <Input
                type="password"
                label={t('pages.settings.currentPassword')}
                value={currentPassword}
                autoComplete="current-password"
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
              <Input
                label={t('pages.settings.newPassword')}
                type={showPassword ? 'text' : 'password'}
                value={newPassword}
                autoComplete="new-password"
                hint={t('auth.passwordHint', { min: MIN_PASSWORD })}
                suffixIcon={
                  <button
                    type="button"
                    onClick={() => setShowPassword((s) => !s)}
                    aria-label={
                      showPassword ? t('auth.hidePassword') : t('auth.showPassword')
                    }
                    className="transition-colors hover:text-fg"
                  >
                    {showPassword ? (
                      <EyeSlash weight="duotone" />
                    ) : (
                      <Eye weight="duotone" />
                    )}
                  </button>
                }
                onChange={(e) => setNewPassword(e.target.value)}
              />
              <Input
                type={showPassword ? 'text' : 'password'}
                label={t('pages.settings.confirmPassword')}
                value={confirmPassword}
                autoComplete="new-password"
                error={
                  confirmPassword !== '' && confirmPassword !== newPassword
                    ? t('pages.settings.passwordMismatch')
                    : undefined
                }
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button
                type="submit"
                variant="secondary"
                loading={password.isPending}
                disabled={!currentPassword || !newPassword || !confirmPassword}
              >
                {t('pages.settings.updatePassword')}
              </Button>
              {passwordError && (
                <p role="alert" className="text-[13px] text-fg-danger">
                  {passwordError}
                </p>
              )}
            </div>
          </form>
        </div>
      </CardBody>
    </Card>
  )
}

export default AccountCard
