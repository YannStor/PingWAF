import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/PageHeader'
import { UsersAdminCard } from '@/components/account/UsersAdminCard'
import { ApiKeysCard } from '@/components/account/ApiKeysCard'
import { OidcProvidersCard } from '@/components/account/OidcProvidersCard'
import { useAuthStore } from '@/stores/authStore'
import { useCanWrite } from '@/hooks'

/**
 * Global account administration: API keys, dashboard users and the identity
 * providers sites authenticate against.
 *
 * Personal settings (profile, password, passkeys) live on /profile, reached
 * from the top-right user menu — this page is global configuration only.
 *
 * The OIDC providers sit here rather than on a site because a provider is a
 * deployment-wide thing: one realm usually fronts several sites, and storing
 * its credentials once means rotating them is a single edit. A site's own
 * gate — which provider, which paths, which users may enter — stays on the
 * site's access-control tab.
 */
export function AccountPage() {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'

  return (
    <div className="animate-slide-up">
      <PageHeader title={t('pages.account.title')} description={t('pages.account.description')} />
      <div className="flex max-w-4xl flex-col gap-4">
        <ApiKeysCard canWrite={canWrite} />
        {isAdmin && <OidcProvidersCard canWrite={canWrite} />}
        {isAdmin && <UsersAdminCard />}
      </div>
    </div>
  )
}

export default AccountPage
