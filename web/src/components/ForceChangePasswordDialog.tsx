import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Eye, EyeSlash } from '@phosphor-icons/react'
import { Dialog } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { useToast } from '@/components/ui/Toast'
import { authApi } from '@/api/auth'
import { errorMessage } from '@/api/errors'
import { useAuthStore } from '@/stores/authStore'

/** Mirrors the server-side minimum in `validate_password`. */
const MIN_PASSWORD = 8


/**
 * Blocks the console behind a password replace until the first sign-in gate
 * clears. Not dismissible by design: while `must_change_password` is set the
 * server refuses every authenticated request except the auth endpoints, so
 * the console has nothing to show.
 *
 * A successful change is also a session change — the server bumps the
 * account's token version, which kills the access and refresh tokens this
 * dialog was opened with. The console therefore signs out and hands the
 * operator to the login form; calling `GET /auth/me` with the dead token (what
 * this used to do) turned a successful change into a bogus error.
 */
export function ForceChangePasswordDialog() {
  const { t } = useTranslation()
  const toast = useToast()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)

  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const open = user?.must_change_password === true

  const submit = useMutation({
    mutationFn: () =>
      authApi.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    meta: { silentToast: true },
    onSuccess: () => {
      // Credentials changed: drop the revoked session and its cached data
      // before the router takes over.
      logout()
      queryClient.clear()
      toast.success(t('pages.settings.passwordChangedSignIn'))
      navigate('/login', { replace: true })
    },
    onError: (err) => setError(errorMessage(err)),
  })

  const onSubmit = (event: FormEvent) => {
    event.preventDefault()
    if (submit.isPending) return
    setError(null)
    if (newPassword.length < MIN_PASSWORD) {
      setError(t('auth.passwordTooShort', { min: MIN_PASSWORD }))
      return
    }
    if (newPassword !== confirmPassword) {
      setError(t('pages.settings.passwordMismatch'))
      return
    }
    submit.mutate()
  }

  if (!open) return null

  return (
    // No `title`/`description` props: the Dialog header would render a close
    // button, and this one must not be dismissible.
    <Dialog open onClose={() => undefined}>
      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-base font-semibold text-fg-strong">
            {t('pages.account.forceChange.title')}
          </h2>
          <p className="text-[13px] text-fg-subtle">
            {t('pages.account.forceChange.description')}
          </p>
        </div>
        <Input
          type="password"
          label={t('pages.settings.currentPassword')}
          value={currentPassword}
          autoFocus
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
              aria-label={showPassword ? t('auth.hidePassword') : t('auth.showPassword')}
              className="transition-colors hover:text-fg"
            >
              {showPassword ? <EyeSlash weight="duotone" /> : <Eye weight="duotone" />}
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
        {error && (
          <p role="alert" className="text-[13px] text-fg-danger">
            {error}
          </p>
        )}
        <div className="flex justify-end">
          <Button
            type="submit"
            variant="primary"
            loading={submit.isPending}
            disabled={!currentPassword || !newPassword || !confirmPassword}
          >
            {t('pages.account.forceChange.submit')}
          </Button>
        </div>
      </form>
    </Dialog>
  )
}
