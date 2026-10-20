import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  List,
  MagnifyingGlass,
  MoonStars,
  Sun,
  CaretDown,
  UserCircle,
  SignOut,
  Translate,
  ShieldCheck,
  Sparkle,
  Pulse,
} from '@phosphor-icons/react'
import { cn } from '@/lib/utils'
import { Sidebar } from '@/components/ui/Sidebar'
import { Breadcrumb, type BreadcrumbItem } from '@/components/ui/Breadcrumb'
import { Button } from '@/components/ui/Button'
import { CommandPalette } from '@/components/CommandPalette'
import { useSitesList } from '@/hooks'
import { useThemeStore } from '@/stores/themeStore'
import { useAuthStore } from '@/stores/authStore'
import { useAssistantWidgetStore } from '@/stores/assistantWidgetStore'
import { AssistantWidget } from '@/components/assistant/AssistantWidget'
import { ForceChangePasswordDialog } from '@/components/ForceChangePasswordDialog'
import { supportedLanguages } from '@/i18n'

const langLabels: Record<string, string> = {
  en: 'English',
  zh: '中文',
  ja: '日本語',
}

// Map the first path segment(s) to a translation key for breadcrumbs.
const crumbKeys: Record<string, string> = {
  dashboard: 'pages.dashboard.title',
  sites: 'pages.sites.title',
  security: 'nav.security',
  waf: 'pages.waf.title',
  'rate-limiting': 'pages.rateLimiting.title',
  bot: 'pages.bot.title',
  cc: 'pages.cc.title',
  'ip-rules': 'pages.ipRules.title',
  caching: 'pages.caching.title',
  ssl: 'pages.ssl.title',
  traffic: 'pages.traffic.title',
  rules: 'nav.security',
  rewrite: 'pages.rewrite.title',
  'error-pages': 'pages.errorPages.title',
  account: 'pages.account.title',
  profile: 'pages.profile.title',
  system: 'system.title',
  settings: 'pages.settings.title',
  logs: 'pages.logs.title',
  assistant: 'pages.assistant.title',
  agents: 'pages.agents.title',
  lifecycle: 'pages.lifecycle.title',
}

// Sections that are pure path prefixes under a site (they redirect to their
// first child page) — the breadcrumb shows them as plain text, since they are
// groupings rather than destinations of their own.
const crumbSections = new Set(['security', 'rules'])

export function AppLayout() {
  const { t, i18n } = useTranslation()
  const location = useLocation()
  const navigate = useNavigate()
  const { resolved, toggle } = useThemeStore()
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.role === 'admin'
  const logout = useAuthStore((s) => s.logout)
  const toggleAssistant = useAssistantWidgetStore((s) => s.toggle)

  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [langMenuOpen, setLangMenuOpen] = useState(false)
  const userMenuRef = useRef<HTMLDivElement>(null)
  const langMenuRef = useRef<HTMLDivElement>(null)
  const userBtnRef = useRef<HTMLButtonElement>(null)
  const langBtnRef = useRef<HTMLButtonElement>(null)

  // Shared site list cache — reused by the command palette and breadcrumbs.
  const { data: sites } = useSitesList()

  // Close the mobile drawer on navigation (render-phase reset on prop change,
  // so the drawer never flashes open for the new page).
  const [lastPathname, setLastPathname] = useState(location.pathname)
  if (location.pathname !== lastPathname) {
    setLastPathname(location.pathname)
    setMobileOpen(false)
  }

  // Close dropdowns on outside click.
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setUserMenuOpen(false)
      }
      if (langMenuRef.current && !langMenuRef.current.contains(e.target as Node)) {
        setLangMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  // Cmd/Ctrl+K opens the command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((o) => !o)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  // Dropdown a11y: Esc closes and restores focus; ↑/↓ cycle menu items.
  const dropdownKeyDown = (e: ReactKeyboardEvent, close: () => void) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      close()
      ;(e.currentTarget as HTMLElement).querySelector<HTMLButtonElement>('[aria-expanded]')?.focus()
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const items = Array.from(
        (e.currentTarget as HTMLElement).querySelectorAll<HTMLButtonElement>(
          '[role="menuitem"]',
        ),
      )
      if (items.length === 0) return
      e.preventDefault()
      const idx = items.indexOf(document.activeElement as HTMLButtonElement)
      const next =
        e.key === 'ArrowDown'
          ? items[(idx + 1) % items.length]
          : items[(idx - 1 + items.length) % items.length]
      next?.focus()
    }
  }

  const crumbs = useMemo<BreadcrumbItem[]>(() => {
    const segments = location.pathname.split('/').filter(Boolean)
    const items: BreadcrumbItem[] = [{ label: t('app.name'), to: '/dashboard' }]
    let path = ''
    let prevSeg = ''
    for (const seg of segments) {
      path += `/${seg}`
      // Skip the raw site id segment; label it as the site name context.
      const key = crumbKeys[seg]
      if (key) {
        items.push({
          label: t(key),
          to: crumbSections.has(seg) ? undefined : path,
        })
      } else if (/^[a-zA-Z0-9_-]{8,}$/.test(seg)) {
        // Site detail pages: resolve the id to the site domain via the shared
        // sites list cache; fall back to the truncated id when not cached.
        const site = prevSeg === 'sites' ? sites?.find((s) => s.id === seg) : undefined
        items.push({ label: site?.domain || seg.slice(0, 8), to: path })
      }
      prevSeg = seg
    }
    return items
  }, [location.pathname, t, sites])

  const handleLogout = () => {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex h-full w-full overflow-hidden bg-base">
      {/* Desktop sidebar */}
      <aside
        className={cn(
          'relative z-20 hidden shrink-0 border-r border-line bg-elevated transition-[width] duration-200 ease-out md:block',
          collapsed ? 'w-16' : 'w-60',
        )}
      >
        <div className="flex h-full flex-col">
          <SidebarHeader collapsed={collapsed} />
          <Sidebar collapsed={collapsed} />
          <SidebarFooter
            collapsed={collapsed}
            onToggle={() => setCollapsed((c) => !c)}
          />
        </div>
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div
            className="absolute inset-0 animate-fade-in bg-overlay"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="absolute left-0 top-0 flex h-full w-60 flex-col border-r border-line bg-elevated shadow-lg">
            <SidebarHeader collapsed={false} />
            <Sidebar collapsed={false} onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-elevated/85 px-4 backdrop-blur">
          <Button
            size="icon"
            variant="ghost"
            className="md:hidden"
            aria-label="Open navigation"
            onClick={() => setMobileOpen(true)}
            icon={<List weight="bold" className="h-5 w-5" />}
          />

          <Breadcrumb items={crumbs} className="hidden min-w-0 sm:block" />

          <div className="ml-auto flex items-center gap-2">
            {/* Search trigger — opens the ⌘K command palette */}
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className="relative hidden h-9 w-64 cursor-pointer rounded-md border border-line bg-recessed text-left text-sm text-fg-subtle/70 transition-colors hover:border-focus focus:border-focus focus:outline-none lg:block"
            >
              <MagnifyingGlass
                weight="duotone"
                className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle"
              />
              <span className="pl-9">{t('search.placeholder')}</span>
              <kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 rounded border border-line bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-fg-subtle">
                ⌘K
              </kbd>
            </button>
            {/* Search trigger (compact screens) */}
            <Button
              size="icon"
              variant="ghost"
              aria-label={t('search.placeholder')}
              onClick={() => setPaletteOpen(true)}
              className="lg:hidden"
              icon={<MagnifyingGlass weight="duotone" className="h-5 w-5" />}
            />

            {/* Language */}
            <div className="relative" ref={langMenuRef} onKeyDown={(e) => dropdownKeyDown(e, () => setLangMenuOpen(false))}>
              <Button
                size="icon"
                variant="ghost"
                aria-label={t('user.language')}
                aria-haspopup="menu"
                aria-expanded={langMenuOpen}
                ref={langBtnRef}
                onClick={() => setLangMenuOpen((o) => !o)}
                icon={<Translate weight="duotone" className="h-5 w-5" />}
              />
              {langMenuOpen && (
                <DropdownMenu className="right-0 w-40">
                  {supportedLanguages.map((lng) => (
                    <DropdownItem
                      key={lng}
                      role="menuitem"
                      active={i18n.language?.startsWith(lng)}
                      onClick={() => {
                        void i18n.changeLanguage(lng)
                        setLangMenuOpen(false)
                        langBtnRef.current?.focus()
                      }}
                    >
                      {langLabels[lng]}
                    </DropdownItem>
                  ))}
                </DropdownMenu>
              )}
            </div>

            {/* Theme toggle */}
            <Button
              size="icon"
              variant="ghost"
              aria-label={t('theme.toggle')}
              title={t('theme.toggle')}
              onClick={toggle}
              icon={
                resolved === 'dark' ? (
                  <Sun weight="duotone" className="h-5 w-5" />
                ) : (
                  <MoonStars weight="duotone" className="h-5 w-5" />
                )
              }
            />

            {/* AI assistant panel */}
            <Button
              size="icon"
              variant="ghost"
              aria-label={t('pages.assistant.open')}
              title={t('pages.assistant.open')}
              onClick={toggleAssistant}
              icon={<Sparkle weight="duotone" className="h-5 w-5" />}
            />

            {/* User menu */}
            <div
              className="relative"
              ref={userMenuRef}
              onKeyDown={(e) => dropdownKeyDown(e, () => setUserMenuOpen(false))}
            >
              <button
                onClick={() => setUserMenuOpen((o) => !o)}
                aria-haspopup="menu"
                aria-expanded={userMenuOpen}
                aria-label={t('user.account')}
                ref={userBtnRef}
                className="flex items-center gap-1.5 rounded-md px-1.5 py-1 transition-colors hover:bg-recessed"
              >
                <UserCircle weight="duotone" className="h-7 w-7 text-brand" />
                <CaretDown weight="bold" className="h-3 w-3 text-fg-subtle" />
              </button>
              {userMenuOpen && (
                <DropdownMenu className="right-0 w-56">
                  <div className="border-b border-line px-3 py-2">
                    <p className="truncate text-sm font-medium text-fg-strong">
                      {user?.name ?? user?.email ?? t('user.anonymous')}
                    </p>
                    <p className="truncate text-xs text-fg-subtle">
                      {user?.email}
                      {user?.role ? ` · ${t(`user.role.${user.role}`, user.role)}` : ''}
                    </p>
                  </div>
                  <DropdownItem
                    icon={<UserCircle className="h-4 w-4" />}
                    onClick={() => {
                      setUserMenuOpen(false)
                      userBtnRef.current?.focus()
                      // Personal settings (profile, password, passkeys) —
                      // /account in the sidebar is global configuration only.
                      navigate('/profile')
                    }}
                  >
                    {t('user.account')}
                  </DropdownItem>
                  {/* System observability — admin-only (server also enforces AdminUser). */}
                  {isAdmin && (
                    <DropdownItem
                      role="menuitem"
                      icon={<Pulse weight="duotone" className="h-4 w-4" />}
                      onClick={() => {
                        setUserMenuOpen(false)
                        userBtnRef.current?.focus()
                        navigate('/system')
                      }}
                    >
                      {t('system.title')}
                    </DropdownItem>
                  )}
                  <DropdownItem
                    icon={<SignOut className="h-4 w-4" />}
                    onClick={() => {
                      setUserMenuOpen(false)
                      userBtnRef.current?.focus()
                      handleLogout()
                    }}
                  >
                    {t('user.signOut')}
                  </DropdownItem>
                </DropdownMenu>
              )}
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8">
            <Outlet />
          </div>
        </main>
      </div>

      {/* First sign-in gate: blocks the whole console until the password is
          replaced; the server refuses writes in the meantime. */}
      <ForceChangePasswordDialog />

      {/* Global ⌘K command palette — mounted only while open so its state
          (query / active row) starts fresh each time and focus is captured
          on mount and restored on unmount. */}
      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}

      {/* Floating AI assistant (ball + sliding panel, mounted for the whole
          signed-in layout; streaming state survives open/close cycles). */}
      <AssistantWidget />
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Sub-components                                                      */
/* ------------------------------------------------------------------ */

function SidebarHeader({ collapsed }: { collapsed: boolean }) {
  return (
    <Link
      to="/dashboard"
      className={cn(
        'flex h-14 shrink-0 items-center gap-2.5 border-b border-line px-4',
        collapsed && 'justify-center px-0',
      )}
    >
      <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand text-white">
        <ShieldCheck weight="fill" className="h-5 w-5" />
      </span>
      {!collapsed && (
        <span className="text-[15px] font-semibold tracking-tight text-fg-strong">
          PingWAF
        </span>
      )}
    </Link>
  )
}

function SidebarFooter({
  collapsed,
  onToggle,
}: {
  collapsed: boolean
  onToggle: () => void
}) {
  const { t } = useTranslation()
  return (
    <div className="shrink-0 border-t border-line p-2">
      <button
        onClick={onToggle}
        className={cn(
          'flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-fg-subtle transition-colors hover:bg-recessed hover:text-fg',
          collapsed && 'justify-center px-0',
        )}
        title={collapsed ? t('sidebar.expand') : t('sidebar.collapse')}
      >
        <CaretDown
          weight="bold"
          className={cn(
            'h-4 w-4 shrink-0 transition-transform duration-200',
            collapsed ? '-rotate-90' : 'rotate-90',
          )}
        />
        {!collapsed && <span>{t('sidebar.collapse')}</span>}
      </button>
    </div>
  )
}

function DropdownMenu({
  className,
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return (
    <div
      className={cn(
        'absolute z-50 mt-2 animate-scale-in overflow-hidden rounded-lg border border-line bg-elevated py-1 shadow-lg',
        className,
      )}
    >
      {children}
    </div>
  )
}

function DropdownItem({
  children,
  icon,
  onClick,
  active,
  role,
}: {
  children: ReactNode
  icon?: ReactNode
  onClick?: () => void
  active?: boolean
  role?: string
}) {
  return (
    <button
      onClick={onClick}
      role={role}
      className={cn(
        'flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm transition-colors',
        active ? 'bg-brand-soft text-brand' : 'text-fg hover:bg-recessed',
      )}
    >
      {icon}
      <span className="truncate">{children}</span>
    </button>
  )
}
