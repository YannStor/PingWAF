export interface AccountSection {
  id: string
  labelKey: string
  adminOnly: boolean
}

/** Account sections in both visual and quick-navigation order. */
export const ACCOUNT_SECTIONS: readonly AccountSection[] = [
  {
    id: 'oidc-providers',
    labelKey: 'pages.account.oidcProviders',
    adminOnly: true,
  },
  {
    id: 'visitors',
    labelKey: 'pages.account.visitors',
    adminOnly: true,
  },
  {
    id: 'users',
    labelKey: 'pages.account.users.title',
    adminOnly: true,
  },
  {
    id: 'api-keys',
    labelKey: 'pages.settings.apiKeys',
    adminOnly: false,
  },
]

export function accountSections(isAdmin: boolean): AccountSection[] {
  return ACCOUNT_SECTIONS.filter((section) => isAdmin || !section.adminOnly)
}
