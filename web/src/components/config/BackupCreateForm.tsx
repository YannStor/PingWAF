import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { useToast } from '@/components/ui/Toast'
import { configBackupsApi, configBackupKeys, type BackupScope, type BackupTarget } from '@/api/configBackups'
import { errorMessage } from '@/api/errors'
import { useSitesList } from '@/hooks'

export function BackupCreateForm({ targets, canWrite }: { targets: BackupTarget[]; canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const sites = useSitesList({ page: 1, page_size: 200 })
  const [scope, setScope] = useState<BackupScope>('deployment')
  const [siteId, setSiteId] = useState('')
  const [password, setPassword] = useState('')
  const [targetId, setTargetId] = useState('')

  const create = useMutation({
    mutationFn: () => configBackupsApi.create({
      scope,
      ...(scope === 'site' ? { site_id: siteId } : {}),
      password,
      ...(targetId ? { target_id: targetId } : {}),
    }),
    onSuccess: () => {
      toast.success(t('pages.backups.createSuccess'))
      setPassword('')
      void queryClient.invalidateQueries({ queryKey: configBackupKeys.backups })
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  if (!canWrite) return null
  const enabledTargets = targets.filter((target) => target.enabled)
  return (
    <div className="grid gap-3 rounded-md border border-line p-4 md:grid-cols-2">
      <Select
        label={t('pages.backups.backupScope')}
        value={scope}
        onChange={(event) => setScope(event.target.value as BackupScope)}
        options={[
          { value: 'deployment', label: t('pages.backups.scopeDeployment') },
          { value: 'global', label: t('pages.backups.scopeGlobal') },
          { value: 'site', label: t('pages.backups.scopeSite') },
        ]}
      />
      {scope === 'site' ? (
        <Select
          label={t('pages.backups.siteId')}
          value={siteId}
          onChange={(event) => setSiteId(event.target.value)}
          options={[
            { value: '', label: t('pages.backups.selectSite') },
            ...(sites.data ?? []).map((site) => ({ value: site.id, label: site.domain })),
          ]}
        />
      ) : <div />}
      <Input
        label={t('pages.backups.password')}
        hint={t('pages.backups.passwordHint')}
        type="password"
        autoComplete="new-password"
        value={password}
        onChange={(event) => setPassword(event.target.value)}
      />
      <Select
        label={t('pages.backups.uploadTarget')}
        value={targetId}
        onChange={(event) => setTargetId(event.target.value)}
        options={[
          { value: '', label: t('pages.backups.targetLocal') },
          ...enabledTargets.map((target) => ({ value: target.id, label: target.name })),
        ]}
      />
      <div className="md:col-span-2">
        <Button
          disabled={password.length < 12 || (scope === 'site' && !siteId)}
          loading={create.isPending}
          onClick={() => create.mutate()}
        >
          {t('pages.backups.createBackup')}
        </Button>
      </div>
    </div>
  )
}
