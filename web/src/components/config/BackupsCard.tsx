import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Upload } from '@phosphor-icons/react'
import { Badge, type BadgeTone } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { Select } from '@/components/ui/Select'
import { useToast } from '@/components/ui/Toast'
import { BackupRestoreDialog } from './BackupRestoreDialog'
import { configBackupsApi, configBackupKeys, type BackupSummary, type BackupTarget } from '@/api/configBackups'
import { errorMessage } from '@/api/errors'
import { formatDateTime } from '@/lib/format'

const STATUS_TONES: Record<string, BadgeTone> = {
  completed: 'success', created: 'neutral', uploading: 'info', failed: 'danger',
}

export function BackupsCard({ targets, canWrite }: { targets: BackupTarget[]; canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const [uploadTarget, setUploadTarget] = useState('')
  const [restoring, setRestoring] = useState<BackupSummary | null>(null)
  const [uploadingNew, setUploadingNew] = useState(false)
  const backups = useQuery({
    queryKey: configBackupKeys.backups,
    queryFn: configBackupsApi.list,
    refetchInterval: (query) =>
      (query.state.data ?? []).some((backup) => backup.status === 'uploading')
        ? 3000
        : false,
  })
  const targetsQuery = useQuery({ queryKey: configBackupKeys.targets, queryFn: configBackupsApi.listTargets })
  const upload = useMutation({
    mutationFn: ({ id, targetId }: { id: string; targetId: string }) => configBackupsApi.upload(id, targetId),
    onSuccess: () => {
      toast.success(t('pages.backups.uploadStarted'))
      void queryClient.invalidateQueries({ queryKey: configBackupKeys.backups })
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  const download = async (backup: BackupSummary) => {
    try {
      const payload = await configBackupsApi.download(backup.id)
      const blob = new Blob([payload], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = backup.file_name
      anchor.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      toast.error(errorMessage(error))
    }
  }

  return (
    <Card>
      <CardHeader
        title={t('pages.backups.backupsTitle')}
        description={t('pages.backups.backupsDescription')}
        action={canWrite ? <Button variant="secondary" onClick={() => setUploadingNew(true)} icon={<Upload weight="duotone" className="h-4 w-4" />}>{t('pages.backups.uploadBackup')}</Button> : undefined}
      />
      <CardBody className="flex flex-col gap-4">
        {backups.isError ? <ErrorState variant="inline" error={backups.error} onRetry={() => void backups.refetch()} /> : (backups.data ?? []).length === 0 ? (
          <EmptyState title={t('pages.backups.noBackups')} description={t('pages.backups.noBackupsHint')} />
        ) : (
          <>
            <div className="max-w-sm">
              <Select
                label={t('pages.backups.uploadTarget')}
                value={uploadTarget}
                onChange={(event) => setUploadTarget(event.target.value)}
                options={[
                  { value: '', label: t('pages.backups.selectTarget') },
                  ...targets.filter((target) => target.enabled).map((target) => ({ value: target.id, label: target.name })),
                ]}
              />
            </div>
            <ul className="flex flex-col">
              {(backups.data ?? []).map((backup) => (
                <li key={backup.id} className="flex items-center justify-between gap-3 border-t border-line py-3 first:border-t-0">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-sm font-medium text-fg-strong">{backup.file_name}</span>
                      <Badge size="sm" tone={STATUS_TONES[backup.status] ?? 'neutral'}>{backup.status}</Badge>
                    </div>
                    <p className="mt-0.5 text-xs text-fg-subtle">
                      {backup.scope} · {Math.ceil(backup.size_bytes / 1024)} KiB · {formatDateTime(backup.created_at)}
                    </p>
                    {backup.error && <p className="mt-1 text-xs text-fg-danger">{backup.error}</p>}
                  </div>
                  <div className="flex shrink-0 flex-wrap justify-end gap-1">
                    <Button variant="ghost" size="sm" onClick={() => void download(backup)} icon={<Download weight="duotone" className="h-4 w-4" />}>
                      {t('pages.backups.download')}
                    </Button>
                    {canWrite && (
                      <>
                        <Button variant="ghost" size="sm" disabled={!uploadTarget || backup.status === 'uploading'} loading={upload.isPending && upload.variables?.id === backup.id} onClick={() => upload.mutate({ id: backup.id, targetId: uploadTarget })}>
                          {t('pages.backups.upload')}
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setRestoring(backup)}>
                          {t('pages.backups.restore')}
                        </Button>
                      </>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
      </CardBody>
      <BackupRestoreDialog key={restoring?.id ?? 'restore'} open={restoring !== null} backup={restoring} onClose={() => setRestoring(null)} onRestored={() => void queryClient.invalidateQueries()} />
      <BackupRestoreDialog key="upload" open={uploadingNew} backup={null} onClose={() => setUploadingNew(false)} onRestored={() => void queryClient.invalidateQueries()} />
      {targetsQuery.isError && <p className="px-5 pb-4 text-xs text-fg-danger">{errorMessage(targetsQuery.error)}</p>}
    </Card>
  )
}
