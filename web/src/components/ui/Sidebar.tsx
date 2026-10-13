import { NavLink } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  House,
  Globe,
  Lock,
  ChartLine,
  List,
  Desktop,
  Gear,
  FunnelSimple,
  Prohibit,
  UserCircle,
  FlowArrow,
  Bell,
  ClockCounterClockwise,
  type Icon,
} from '@phosphor-icons/react'
import { cn } from '@/lib/utils'

interface NavLeaf {
  to: string
  labelKey: string
  icon: Icon
}

export interface SidebarProps {
  collapsed: boolean
  onNavigate?: () => void
}

/**
 * Global navigation only. Site-scoped surfaces (basic, protection,
 * rate limiting, bot, access control, caching) live in the site detail
 * page's tab bar — the sidebar never duplicates them.
 */
export function Sidebar({ collapsed, onNavigate }: SidebarProps) {
  const { t } = useTranslation()

  const nav: NavLeaf[] = [
    { to: '/dashboard', labelKey: 'nav.dashboard', icon: House },
    { to: '/sites', labelKey: 'nav.sites', icon: Globe },
    { to: '/ip-groups', labelKey: 'nav.ipGroups', icon: FunnelSimple },
    { to: '/blocked-ips', labelKey: 'nav.blockedIps', icon: Prohibit },
    // SSL/TLS and traffic in the sidebar are the *global* surfaces; each site's
    // own certificates and traffic live in that site's tab bar.
    { to: '/ssl', labelKey: 'nav.ssl', icon: Lock },
    { to: '/traffic', labelKey: 'nav.traffic', icon: ChartLine },
    { to: '/logs', labelKey: 'nav.logs', icon: List },
    { to: '/agents', labelKey: 'nav.agents', icon: Desktop },
    { to: '/notifications', labelKey: 'nav.notifications', icon: Bell },
    { to: '/lifecycle', labelKey: 'nav.lifecycle', icon: FlowArrow },
    {
      to: '/config-versions',
      labelKey: 'nav.configVersions',
      icon: ClockCounterClockwise,
    },
    { to: '/account', labelKey: 'nav.account', icon: UserCircle },
    { to: '/settings', labelKey: 'nav.settings', icon: Gear },
  ]

  const linkBase =
    'group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors duration-150'
  const linkIdle = 'text-fg-subtle hover:bg-recessed hover:text-fg'
  const linkActive = 'bg-brand-soft text-brand'

  return (
    <nav className="flex h-full flex-col gap-0.5 overflow-y-auto px-2 py-3">
      {nav.map((entry) => {
        const IconCmp = entry.icon
        return (
          <NavLink
            key={entry.labelKey}
            to={entry.to}
            onClick={() => onNavigate?.()}
            title={collapsed ? t(entry.labelKey) : undefined}
            className={({ isActive }) =>
              cn(
                linkBase,
                isActive ? linkActive : linkIdle,
                collapsed && 'justify-center px-0',
              )
            }
          >
            <IconCmp weight="duotone" className="h-5 w-5 shrink-0" />
            {!collapsed && <span className="truncate">{t(entry.labelKey)}</span>}
          </NavLink>
        )
      })}
    </nav>
  )
}
