import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fingerprint } from '@phosphor-icons/react'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Switch } from '@/components/ui/Switch'
import { SkeletonRows } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { passkeyKeys, passkeysApi } from '@/api/passkeys'
import { errorMessage } from '@/api/errors'
import { useCanWrite } from '@/hooks'

/**
 * Deployment-wide passkey master switch (Settings page).
 *
 * Binding, renaming and removing credentials live on the /profile page
 * (top-right "account settings"); this card only decides whether passkey
 * login and registration are offered at all. The switch takes effect
 * immediately — the login form hides the passkey option without a restart.
 */
export function PasskeyToggleCard() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()

  const query = useQuery({
    queryKey: passkeyKeys.settings(),
    queryFn: () => passkeysApi.getSettings(),
  })
  const enabled = query.data?.enabled ?? false

  const update = useMutation({
    mutationFn: (next: boolean) => passkeysApi.updateSettings(next),
    onSuccess: (view) => {
      queryClient.setQueryData(passkeyKeys.settings(), view)
      toast.success(
        view.enabled
          ? t('pages.settings.passkeySwitchOn')
          : t('pages.settings.passkeySwitchOff'),
      )
    },
    onError: (err) => toast.error(errorMessage(err)),
  })

  return (
    <Card>
      <CardHeader
        title={t('pages.settings.passkeys')}
        description={t('pages.settings.passkeySwitchDescription')}
        action={<Fingerprint weight="duotone" className="h-5 w-5 text-fg-subtle" />}
      />
      <CardBody>
        {query.isError && !query.data ? (
          <ErrorState
            variant="inline"
            error={query.error}
            onRetry={() => query.refetch()}
            retrying={query.isFetching}
          />
        ) : query.isPending ? (
          <SkeletonRows rows={1} columns={1} />
        ) : (
          <Switch
            checked={enabled}
            disabled={!canWrite || update.isPending}
            onCheckedChange={(next) => update.mutate(next)}
            label={t('pages.settings.passkeySwitch')}
            description={t('pages.settings.passkeySwitchHint')}
          />
        )}
      </CardBody>
    </Card>
  )
}

export default PasskeyToggleCard
