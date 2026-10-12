import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Dialog } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Select } from '@/components/ui/Select'
import { useToast } from '@/components/ui/Toast'
import { ipGroupsApi, ipGroupKeys } from '@/api/ipGroups'

/**
 * Picks an IP group and appends one IP to its `ip_ranges` (read-append-PUT —
 * the API has no append endpoint, so the whole array round-trips).
 */
export function IpGroupPickerDialog({
  open,
  ip,
  onClose,
}: {
  open: boolean
  ip: string | null
  onClose: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const [groupId, setGroupId] = useState('')

  const groupsQuery = useQuery({
    queryKey: ipGroupKeys.list({}),
    queryFn: () => ipGroupsApi.list({ page_size: 200 }),
    enabled: open,
  })
  const groups = useMemo(() => groupsQuery.data?.items ?? [], [groupsQuery.data])

  const addMutation = useMutation({
    mutationFn: async () => {
      if (!ip || !groupId) throw new Error('missing target')
      const group = groups.find((g) => g.id === groupId)
      if (!group) throw new Error('group not found')
      const ranges = group.ip_ranges.includes(ip)
        ? group.ip_ranges
        : [...group.ip_ranges, ip]
      return ipGroupsApi.update(group.id, { ip_ranges: ranges })
    },
    onSuccess: (group) => {
      toast.success(t('pages.logs.ipGroupAdded'), `${ip} → ${group.name}`)
      void queryClient.invalidateQueries({ queryKey: ipGroupKeys.all })
      onClose()
    },
    onError: () => toast.error(t('pages.logs.ipGroupAddFailed')),
  })

  const handleClose = () => {
    if (addMutation.isPending) return
    setGroupId('')
    onClose()
  }

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      size="sm"
      title={t('pages.logs.ipGroupPicker.title')}
      description={t('pages.logs.ipGroupPicker.description', { ip: ip ?? '' })}
      footer={
        <>
          <Button variant="secondary" onClick={handleClose} disabled={addMutation.isPending}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={addMutation.isPending}
            disabled={!groupId}
            onClick={() => addMutation.mutate()}
          >
            {t('pages.logs.ipGroupPicker.confirm')}
          </Button>
        </>
      }
    >
      {groups.length === 0 && !groupsQuery.isPending ? (
        <p className="text-sm text-fg-subtle">{t('pages.logs.ipGroupPicker.empty')}</p>
      ) : (
        <Select
          label={t('pages.logs.ipGroupPicker.group')}
          value={groupId}
          options={[
            { value: '', label: t('pages.logs.ipGroupPicker.choose') },
            ...groups.map((g) => ({
              value: g.id,
              label: `${g.name} (${g.ip_ranges.length})`,
            })),
          ]}
          onChange={(e) => setGroupId(e.target.value)}
        />
      )}
    </Dialog>
  )
}

export default IpGroupPickerDialog
