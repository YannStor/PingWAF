import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/PageHeader'
import { AccountCard } from '@/components/account/AccountCard'
import { PasskeysCard } from '@/components/account/PasskeysCard'

/**
 * Personal account settings, reached from the top-right user menu
 * ("account settings"). Not in the sidebar: the sidebar's /account page
 * hosts only global configuration.
 */
export function ProfilePage() {
  const { t } = useTranslation()

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.profile.title')}
        description={t('pages.profile.description')}
      />
      <div className="flex max-w-4xl flex-col gap-4">
        <AccountCard />
        <PasskeysCard />
      </div>
    </div>
  )
}

export default ProfilePage
