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
import { useAuthStore } from '@/stores/authStore'

interface NavLeaf {
  to: string
  labelKey: string
  icon: Icon
}

interface NavGroup {
  labelKey: string
  items: NavLeaf[]
}

export interface SidebarProps {
  collapsed: boolean
  onNavigate?: () => void
}

/** Top-level routes gated by `RequireAdmin` in the router — never rendered. */
const ADMIN_ONLY_PATHS = new Set(['/lifecycle', '/config-versions'])

/**
 * Global navigation only. Site-scoped surfaces (basic, protection,
 * rate limiting, bot, access control, caching) live in the site detail
 * page's tab bar — the sidebar never duplicates them.
 */
export function Sidebar({ collapsed, onNavigate }: SidebarProps) {
  const { t } = useTranslation()
  // Must mirror router/index.tsx's RequireAdmin: hidden, not merely blocked.
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'

  // Static grouping. SSL/TLS and traffic remain the *global* surfaces; each
  // site's own certificates and traffic live in that site's tab bar.
  const groups: NavGroup[] = [
    {
      labelKey: 'nav.group.overview',
      items: [{ to: '/dashboard', labelKey: 'nav.dashboard', icon: House }],
    },
    {
      labelKey: 'nav.group.trafficLogs',
      items: [
        { to: '/traffic', labelKey: 'nav.traffic', icon: ChartLine },
        { to: '/logs', labelKey: 'nav.logs', icon: List },
        { to: '/lifecycle', labelKey: 'nav.lifecycle', icon: FlowArrow },
      ],
    },
    {
      labelKey: 'nav.group.securityAssets',
      items: [
        { to: '/sites', labelKey: 'nav.sites', icon: Globe },
        { to: '/ip-groups', labelKey: 'nav.ipGroups', icon: FunnelSimple },
        { to: '/blocked-ips', labelKey: 'nav.blockedIps', icon: Prohibit },
        { to: '/ssl', labelKey: 'nav.ssl', icon: Lock },
      ],
    },
    {
      labelKey: 'nav.group.platform',
      items: [
        { to: '/agents', labelKey: 'nav.agents', icon: Desktop },
        { to: '/notifications', labelKey: 'nav.notifications', icon: Bell },
        {
          to: '/config-versions',
          labelKey: 'nav.configVersions',
          icon: ClockCounterClockwise,
        },
        { to: '/account', labelKey: 'nav.account', icon: UserCircle },
        { to: '/settings', labelKey: 'nav.settings', icon: Gear },
      ],
    },
  ]

  const linkBase =
    'group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors duration-150'
  const linkIdle = 'text-fg-subtle hover:bg-recessed hover:text-fg'
  const linkActive = 'bg-brand-soft text-brand'

  const renderLeaf = (entry: NavLeaf) => {
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
  }

  return (
    <nav className="flex h-full flex-col gap-3 overflow-y-auto px-2 py-3">
      {groups.map((group) => {
        const items = group.items.filter(
          (item) => isAdmin || !ADMIN_ONLY_PATHS.has(item.to),
        )
        if (items.length === 0) return null
        return (
          <div key={group.labelKey} className="flex flex-col gap-0.5">
            {!collapsed && (
              <p className="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wider text-fg-subtle/70">
                {t(group.labelKey)}
              </p>
            )}
            {items.map(renderLeaf)}
          </div>
        )
      })}
    </nav>
  )
}
