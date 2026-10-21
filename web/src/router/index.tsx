import {
  createBrowserRouter,
  Navigate,
  useLocation,
} from 'react-router-dom'
import type { ReactElement } from 'react'
import { AppLayout } from '@/layouts/AppLayout'
import { useAuthStore } from '@/stores/authStore'

import { LoginPage } from '@/pages/LoginPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { SitesListPage } from '@/pages/SitesListPage'
import { SiteDetailPage } from '@/pages/SiteDetailPage'
import { RateLimitingPage } from '@/pages/RateLimitingPage'
import { LogsPage } from '@/pages/LogsPage'
import { AgentsPage } from '@/pages/AgentsPage'
import { AssistantPage } from '@/pages/AssistantPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { NotificationsPage } from '@/pages/NotificationsPage'
import { AccountPage } from '@/pages/AccountPage'
import { ProfilePage } from '@/pages/ProfilePage'
import { SystemPage } from '@/pages/SystemPage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { BotPage as BotProtectionPage } from '@/pages/sites/BotPage'
import {
  ProtectionPage,
  LegacyProtectionRedirect,
} from '@/pages/sites/ProtectionPage'
import {
  AccessControlPage,
  LegacySecurityRedirect,
} from '@/pages/sites/AccessControlPage'
import { CachingPage } from '@/pages/sites/CachingPage'
import { SslPage } from '@/pages/sites/SslPage'
import { TrafficPage } from '@/pages/sites/TrafficPage'
import { ConfigVersionsPage } from '@/pages/ConfigVersionsPage'
import { GlobalSslPage } from '@/pages/GlobalSslPage'
import { GlobalTrafficPage } from '@/pages/GlobalTrafficPage'
import { IpGroupsPage } from '@/pages/IpGroupsPage'
import { BlockedIpsPage } from '@/pages/BlockedIpsPage'
import { RewritePage } from '@/pages/sites/RewritePage'
import { BasicPage } from '@/pages/sites/basic/BasicPage'
import { LifecyclePage } from '@/pages/LifecyclePage'
import { SiteSettingsPage } from '@/pages/placeholders'


/** Redirects unauthenticated users to the login page. */
function RequireAuth({ children }: { children: ReactElement }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const location = useLocation()
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }
  return children
}

/** Redirects non-admin users to the dashboard (the guards are server-backed too). */
function RequireAdmin({ children }: { children: ReactElement }) {
  const role = useAuthStore((s) => s.user?.role)
  if (role !== 'admin') {
    return <Navigate to="/dashboard" replace />
  }
  return children
}

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/',
    element: (
      <RequireAuth>
        <AppLayout />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <Navigate to="/dashboard" replace /> },
      { path: 'dashboard', element: <DashboardPage /> },
      { path: 'sites', element: <SitesListPage /> },
      {
        path: 'sites/:siteId',
        element: <SiteDetailPage />,
        children: [
          { index: true, element: <Navigate to="basic" replace /> },
          { path: 'basic', element: <BasicPage /> },
          // `security` and `rules` are path prefixes, not pages — breadcrumbs
          // render them as clickable segments, so landing on the prefix must
          // redirect to the section's first real page instead of 404-ing.
          { path: 'security', element: <Navigate to="security/protection" replace /> },
          { path: 'security/protection', element: <ProtectionPage /> },
          { path: 'security/rate-limiting', element: <RateLimitingPage /> },
          { path: 'security/bot', element: <BotProtectionPage /> },
          { path: 'security/access', element: <AccessControlPage /> },
          // WAF and CC were separate tabs before they were merged; keep old
          // links (including the `?rule=` deep link) working.
          {
            path: 'security/waf',
            element: <LegacyProtectionRedirect tab="custom" />,
          },
          {
            path: 'security/cc',
            element: <LegacyProtectionRedirect tab="cc" />,
          },
          // IP rules and geo were separate tabs before they were merged; keep
          // old links (including `?block=…` deep links) working.
          {
            path: 'security/ip-rules',
            element: <LegacySecurityRedirect tab="ip" />,
          },
          {
            path: 'security/geo',
            element: <LegacySecurityRedirect tab="geo" />,
          },
          { path: 'caching', element: <CachingPage /> },
          { path: 'ssl', element: <SslPage /> },
          { path: 'traffic', element: <TrafficPage /> },
          { path: 'rules', element: <Navigate to="rules/rewrite" replace /> },
          { path: 'rules/rewrite', element: <RewritePage /> },
          { path: 'settings', element: <SiteSettingsPage /> },
        ],
      },
      { path: 'logs', element: <LogsPage /> },
      { path: 'assistant', element: <AssistantPage /> },
      { path: 'agents', element: <AgentsPage /> },
      { path: 'ip-groups', element: <IpGroupsPage /> },
      { path: 'blocked-ips', element: <BlockedIpsPage /> },
      { path: 'lifecycle', element: <RequireAdmin><LifecyclePage /></RequireAdmin> },
      { path: 'config-versions', element: <RequireAdmin><ConfigVersionsPage /></RequireAdmin> },
      // Global surfaces. The per-site counterparts live under `/sites/:siteId`.
      { path: 'ssl', element: <GlobalSslPage /> },
      { path: 'traffic', element: <GlobalTrafficPage /> },
      { path: 'account', element: <AccountPage /> },
      // Personal settings (profile, password, passkeys) — reached from the
      // top-right user menu, deliberately absent from the sidebar.
      { path: 'profile', element: <ProfilePage /> },
      // System observability — admin-only read-only metrics from the user menu.
      { path: 'system', element: <RequireAdmin><SystemPage /></RequireAdmin> },
      { path: 'notifications', element: <NotificationsPage /> },
      { path: 'settings', element: <SettingsPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
])

export default router
