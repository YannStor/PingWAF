import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { sitesApi, siteKeys } from '@/api/sites'
import { useAuthStore } from '@/stores/authStore'
import type { SiteListQuery } from '@/api/types'

/**
 * Shared query hooks.
 *
 * Pages never call `fetch` directly — every read goes through TanStack Query so
 * caching, refetch-on-focus, deduplication and the global error toast apply
 * uniformly.
 */

/** The full site list, flattened out of the pagination envelope. */
export function useSitesList(query: SiteListQuery = {}) {
  return useQuery({
    queryKey: siteKeys.list(query),
    queryFn: () => sitesApi.list(query),
    select: (page) => page.items,
  })
}

/** `GET /sites/{id}` — site plus upstreams, SSL and rule counters. */
export function useSiteDetail(siteId: string | undefined) {
  return useQuery({
    queryKey: siteKeys.detail(siteId ?? ''),
    queryFn: () => sitesApi.get(siteId as string),
    enabled: Boolean(siteId),
  })
}

/**
 * True when the signed-in account may mutate anything.
 *
 * There are three roles: `admin` (full read/write), `auditor` (read-only, like
 * viewer) and `viewer` (read-only). Non-admins get a 403 on writes, so the
 * console disables the controls up front instead of letting them fail.
 */
export function useCanWrite(): boolean {
  const role = useAuthStore((s) => s.user?.role)
  return role === 'admin'
}

/** Defers a fast-changing value so typing does not fire a request per keystroke. */
export function useDebouncedValue<T>(value: T, delay = 350): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = window.setTimeout(() => setDebounced(value), delay)
    return () => window.clearTimeout(id)
  }, [value, delay])
  return debounced
}

/**
 * A clock that ticks on an interval — lets "3 minutes ago" columns stay honest
 * without a manual refresh. Pauses when the tab is hidden.
 */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = window.setInterval(() => {
      if (!document.hidden) setNow(Date.now())
    }, intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])
  return now
}

export { useWafSettingsMutation } from './useWafSettingsMutation'
