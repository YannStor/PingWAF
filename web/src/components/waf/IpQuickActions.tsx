import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Prohibit, ShieldCheck } from '@phosphor-icons/react'
import { blockedIpsApi, blockedIpKeys } from '@/api/blockedIps'
import { ipRuleKeys, ipRulesApi } from '@/api/ipRules'
import { Button, ConfirmDialog, useToast } from '@/components/ui'

type Action = 'block' | 'js_challenge'

export interface IpQuickActionsProps {
  /** The address the quick actions target (single IP, not a CIDR). */
  ip: string
  /**
   * Site the block/challenge applies to. The dashboard's cross-site list
   * passes the IP's most recently active site; site-scoped pages pass the
   * site from context. When null the buttons render disabled with a
   * tooltip explaining why.
   */
  siteId: string | null | undefined
}

/**
 * One-click "block" / "JS challenge" actions for a client IP row.
 *
 * Used by the dashboard's top-threat-IP table and the site traffic page's
 * top-client-IP table. Both actions confirm before firing (a stray click
 * must not block a legit scraper), invalidate the affected queries and
 * surface the result via toast.
 *
 * - Block: a dynamic block via `POST /blocked-ips/block`, fanned out to
 *   every agent (survives restarts, visible on the blocked-IPs page).
 * - JS challenge: a manual per-site IP rule with `action: "js_challenge"`
 *   (persisted, visible in the site's IP rules).
 */
export function IpQuickActions({ ip, siteId }: IpQuickActionsProps) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const [pending, setPending] = useState<Action | null>(null)

  const disabled = !siteId

  const invalidate = (site: string) => {
    void queryClient.invalidateQueries({ queryKey: blockedIpKeys.list(site) })
    void queryClient.invalidateQueries({ queryKey: blockedIpKeys.global })
    void queryClient.invalidateQueries({ queryKey: ipRuleKeys.all(site) })
  }

  const blockMutation = useMutation({
    mutationFn: (payload: { site: string }) =>
      blockedIpsApi.block({
        site_id: payload.site,
        ip,
        reason: t('components.ipQuickActions.reason'),
      }),
    onSuccess: (result, { site }) => {
      invalidate(site)
      toast.success(
        t('components.ipQuickActions.blockedTitle'),
        t('components.ipQuickActions.blockedDescription', {
          ip,
          agents: result.delivered,
        }),
      )
    },
    onError: (error) => {
      toast.error(
        t('components.ipQuickActions.failedTitle'),
        error instanceof Error ? error.message : undefined,
      )
    },
  })

  const challengeMutation = useMutation({
    mutationFn: (payload: { site: string }) =>
      ipRulesApi.create(payload.site, {
        name: t('components.ipQuickActions.challengeRuleName', { ip }),
        ip_ranges: [ip],
        action: 'js_challenge',
        enabled: true,
      }),
    onSuccess: (_rule, { site }) => {
      invalidate(site)
      toast.success(
        t('components.ipQuickActions.challengedTitle'),
        t('components.ipQuickActions.challengedDescription', { ip }),
      )
    },
    onError: (error) => {
      toast.error(
        t('components.ipQuickActions.failedTitle'),
        error instanceof Error ? error.message : undefined,
      )
    },
  })

  const busy = blockMutation.isPending || challengeMutation.isPending

  return (
    <>
      <div className="flex items-center justify-end gap-1">
        <Button
          variant="ghost"
          size="sm"
          icon={<Prohibit weight="regular" className="h-3.5 w-3.5" />}
          disabled={disabled || busy}
          title={
            disabled
              ? t('components.ipQuickActions.disabledHint')
              : t('components.ipQuickActions.blockLabel')
          }
          aria-label={t('components.ipQuickActions.blockLabel')}
          onClick={() => setPending('block')}
        >
          {t('components.ipQuickActions.blockLabel')}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          icon={<ShieldCheck weight="regular" className="h-3.5 w-3.5" />}
          disabled={disabled || busy}
          title={
            disabled
              ? t('components.ipQuickActions.disabledHint')
              : t('components.ipQuickActions.challengeLabel')
          }
          aria-label={t('components.ipQuickActions.challengeLabel')}
          onClick={() => setPending('js_challenge')}
        >
          {t('components.ipQuickActions.challengeLabel')}
        </Button>
      </div>

      <ConfirmDialog
        open={pending !== null}
        onClose={() => setPending(null)}
        onConfirm={() => {
          if (!siteId) return
          if (pending === 'block') {
            blockMutation.mutate({ site: siteId })
          } else if (pending === 'js_challenge') {
            challengeMutation.mutate({ site: siteId })
          }
          setPending(null)
        }}
        tone={pending === 'block' ? 'danger' : 'primary'}
        confirmLabel={
          pending === 'block'
            ? t('components.ipQuickActions.blockLabel')
            : t('components.ipQuickActions.challengeLabel')
        }
        title={
          pending === 'block'
            ? t('components.ipQuickActions.blockConfirmTitle', { ip })
            : t('components.ipQuickActions.challengeConfirmTitle', { ip })
        }
        description={
          pending === 'block'
            ? t('components.ipQuickActions.blockConfirmDescription')
            : t('components.ipQuickActions.challengeConfirmDescription')
        }
      >
        <p className="pw-mono text-[13px] text-fg-strong">{ip}</p>
      </ConfirmDialog>
    </>
  )
}
