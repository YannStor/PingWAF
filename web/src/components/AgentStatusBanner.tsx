import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { Warning } from '@phosphor-icons/react'
import { agentKeys, agentsApi, countByStatus } from '@/api/agents'
import type { Agent } from '@/api/types'

/**
 * Z5: degraded-fleet warning shown on the site detail header. Shares the
 * agents list cache with AgentsPage (same key family) with a short staleTime
 * so the banner is cheap to mount. Renders nothing while every node is
 * healthy; when offline+degraded nodes exist, warns that config changes may
 * not reach the edge immediately.
 */
export function AgentStatusBanner({ siteId }: { siteId?: string }) {
  const { t } = useTranslation()

  const agentsQuery = useQuery({
    queryKey: agentKeys.list({ site_id: siteId || undefined }),
    queryFn: () => agentsApi.list({ site_id: siteId || undefined }),
    staleTime: 30_000,
  })

  const degraded = useMemo(() => {
    const items: Agent[] = agentsQuery.data?.items ?? []
    const counts = countByStatus(items)
    return (counts.offline ?? 0) + (counts.degraded ?? 0)
  }, [agentsQuery.data])

  if (agentsQuery.isPending || degraded === 0) return null

  return (
    <div className="mb-4 flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-[13px] text-fg">
      <Warning weight="duotone" className="mt-0.5 h-4 w-4 shrink-0 text-fg" />
      <p>{t('common.siteBanners.agentDegraded', { count: degraded })}</p>
    </div>
  )
}
