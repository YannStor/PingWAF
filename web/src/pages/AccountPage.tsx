import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/PageHeader'
import { UsersAdminCard } from '@/components/account/UsersAdminCard'
import { ApiKeysCard } from '@/components/account/ApiKeysCard'
import { useAuthStore } from '@/stores/authStore'
import { useCanWrite } from '@/hooks'

/**
 * Global account administration: API keys and dashboard users.
 *
 * Personal settings (profile, password, passkeys) live on /profile, reached
 * from the top-right user menu — this page is global configuration only.
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
        {isAdmin && <UsersAdminCard />}
      </div>
    </div>
  )
}

export default AccountPage
