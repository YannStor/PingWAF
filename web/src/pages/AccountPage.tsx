import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/PageHeader'
import { UsersAdminCard } from '@/components/account/UsersAdminCard'
import { ApiKeysCard } from '@/components/account/ApiKeysCard'
import { OidcProvidersCard } from '@/components/account/OidcProvidersCard'
import { VisitorsCard } from '@/components/account/VisitorsCard'
import { QuickNav } from '@/components/ui/QuickNav'
import { useAuthStore } from '@/stores/authStore'
import { useCanWrite } from '@/hooks'
import { accountSections } from './accountNav'

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
  const sections = useMemo(() => accountSections(isAdmin), [isAdmin])
  const navItems = useMemo(
    () => sections.map(({ id, labelKey }) => ({ id, label: t(labelKey) })),
    [sections, t],
  )

  const cardFor = (id: string) => {
    switch (id) {
      case 'oidc-providers':
        return <OidcProvidersCard canWrite={canWrite} />
      case 'visitors':
        return <VisitorsCard canWrite={canWrite} />
      case 'users':
        return <UsersAdminCard />
      default:
        return <ApiKeysCard canWrite={canWrite} />
    }
  }

  return (
    <div className="animate-slide-up">
      <PageHeader title={t('pages.account.title')} description={t('pages.account.description')} />
      <div className="flex max-w-6xl items-start gap-8">
        <QuickNav ariaLabel={t('pages.account.quickNav')} items={navItems} />
        <div className="flex min-w-0 max-w-4xl flex-1 flex-col gap-4">
          {sections.map(({ id }) => (
            <section key={id} id={id} className="scroll-mt-6">
              {cardFor(id)}
            </section>
          ))}
        </div>
      </div>
    </div>
  )
}

export default AccountPage
