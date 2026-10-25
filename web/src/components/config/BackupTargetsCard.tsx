import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash } from '@phosphor-icons/react'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorState } from '@/components/ErrorState'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { useToast } from '@/components/ui/Toast'
import { configBackupsApi, configBackupKeys, type BackupTarget, type BackupTargetKind } from '@/api/configBackups'
import { errorMessage } from '@/api/errors'

const INITIAL = {
  name: '', endpoint: '', bucket: '', region: 'us-east-1', prefix: '',
  repository: '', branch: 'main', apiUrl: 'https://api.github.com',
  accessKeyId: '', secretAccessKey: '', token: '', pathStyle: true,
}

export function BackupTargetsCard({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const [kind, setKind] = useState<BackupTargetKind>('s3')
  const [form, setForm] = useState(INITIAL)
  const [deleting, setDeleting] = useState<BackupTarget | null>(null)
  const targets = useQuery({ queryKey: configBackupKeys.targets, queryFn: configBackupsApi.listTargets })
  const patch = (value: Partial<typeof INITIAL>) => setForm((current) => ({ ...current, ...value }))
  const invalidate = () => queryClient.invalidateQueries({ queryKey: configBackupKeys.targets })

  const create = useMutation({
    mutationFn: () => {
      const config = kind === 's3' ? {
        endpoint: form.endpoint.trim(), bucket: form.bucket.trim(), region: form.region.trim(),
        prefix: form.prefix.trim(), path_style: form.pathStyle,
        access_key_id: form.accessKeyId.trim(), secret_access_key: form.secretAccessKey,
      } : {
        repository: form.repository.trim(), branch: form.branch.trim(), prefix: form.prefix.trim(),
        api_url: form.apiUrl.trim(), token: form.token,
      }
      return configBackupsApi.createTarget({ kind, name: form.name.trim(), config, enabled: true })
    },
    onSuccess: () => {
      toast.success(t('pages.backups.targetCreated'))
      setForm(INITIAL)
      void invalidate()
    },
    onError: (error) => toast.error(errorMessage(error)),
  })
  const test = useMutation({
    mutationFn: (id: string) => configBackupsApi.testTarget(id),
    onSuccess: () => toast.success(t('pages.backups.testSuccess')),
    onError: (error) => toast.error(errorMessage(error)),
  })
  const remove = useMutation({
    mutationFn: (id: string) => configBackupsApi.deleteTarget(id),
    onSuccess: () => { setDeleting(null); void invalidate() },
    onError: (error) => toast.error(errorMessage(error)),
  })
  const required = kind === 's3'
    ? !form.name.trim() || !form.endpoint.trim() || !form.bucket.trim() || !form.accessKeyId.trim() || !form.secretAccessKey
    : !form.name.trim() || !form.repository.trim() || !form.token

  return (
    <Card>
      <CardHeader title={t('pages.backups.targetsTitle')} description={t('pages.backups.targetsDescription')} />
      <CardBody className="flex flex-col gap-5">
        {canWrite && (
          <div className="grid gap-3 rounded-md border border-line p-4 md:grid-cols-2">
            <Select label={t('pages.backups.kind')} value={kind} onChange={(event) => setKind(event.target.value as BackupTargetKind)} options={[{ value: 's3', label: 'S3' }, { value: 'github', label: 'GitHub' }]} />
            <Input label={t('pages.backups.targetName')} value={form.name} onChange={(event) => patch({ name: event.target.value })} />
            {kind === 's3' ? (
              <>
                <Input label={t('pages.backups.endpoint')} value={form.endpoint} placeholder="https://s3.example.com" onChange={(event) => patch({ endpoint: event.target.value })} />
                <Input label={t('pages.backups.bucket')} value={form.bucket} onChange={(event) => patch({ bucket: event.target.value })} />
                <Input label={t('pages.backups.region')} value={form.region} onChange={(event) => patch({ region: event.target.value })} />
                <Input label={t('pages.backups.prefix')} value={form.prefix} onChange={(event) => patch({ prefix: event.target.value })} />
                <Input label={t('pages.backups.accessKeyId')} value={form.accessKeyId} onChange={(event) => patch({ accessKeyId: event.target.value })} />
                <Input label={t('pages.backups.secretAccessKey')} type="password" value={form.secretAccessKey} onChange={(event) => patch({ secretAccessKey: event.target.value })} />
                <Switch checked={form.pathStyle} onCheckedChange={(pathStyle) => patch({ pathStyle })} label={t('pages.backups.pathStyle')} />
              </>
            ) : (
              <>
                <Input label={t('pages.backups.repository')} placeholder="owner/repository" value={form.repository} onChange={(event) => patch({ repository: event.target.value })} />
                <Input label={t('pages.backups.branch')} value={form.branch} onChange={(event) => patch({ branch: event.target.value })} />
                <Input label={t('pages.backups.apiUrl')} value={form.apiUrl} onChange={(event) => patch({ apiUrl: event.target.value })} />
                <Input label={t('pages.backups.prefix')} value={form.prefix} onChange={(event) => patch({ prefix: event.target.value })} />
                <Input label={t('pages.backups.token')} type="password" value={form.token} onChange={(event) => patch({ token: event.target.value })} />
              </>
            )}
            <div className="md:col-span-2">
              <Button disabled={required} loading={create.isPending} onClick={() => create.mutate()} icon={<Plus weight="duotone" className="h-4 w-4" />}>
                {t('pages.backups.addTarget')}
              </Button>
            </div>
          </div>
        )}
        {targets.isError ? <ErrorState variant="inline" error={targets.error} onRetry={() => void targets.refetch()} /> : (targets.data ?? []).length === 0 ? (
          <EmptyState title={t('pages.backups.noTargets')} description={t('pages.backups.noTargetsHint')} />
        ) : (
          <ul className="flex flex-col">
            {(targets.data ?? []).map((target) => (
              <li key={target.id} className="flex items-center justify-between gap-3 border-t border-line py-3 first:border-t-0">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-sm font-medium text-fg-strong">{target.name}</span>
                    <Badge size="sm" tone="neutral">{target.kind === 's3' ? 'S3' : 'GitHub'}</Badge>
                    {!target.enabled && <Badge size="sm" tone="warning">{t('pages.backups.disabled')}</Badge>}
                  </div>
                  <p className="mt-0.5 text-xs text-fg-subtle">{target.config.has_credentials ? t('pages.backups.credentialsStored') : t('pages.backups.credentialsMissing')}</p>
                </div>
                <div className="flex shrink-0 gap-1">
                  <Button variant="ghost" size="sm" loading={test.isPending && test.variables === target.id} onClick={() => test.mutate(target.id)}>{t('pages.backups.test')}</Button>
                  {canWrite && <Button variant="ghost" size="sm" aria-label={t('common.delete')} onClick={() => setDeleting(target)} icon={<Trash weight="duotone" className="h-4 w-4" />} />}
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardBody>
      <ConfirmDialog open={deleting !== null} title={t('pages.backups.deleteTargetTitle')} description={t('pages.backups.deleteTargetDescription', { name: deleting?.name ?? '' })} confirmLabel={t('common.delete')} loading={remove.isPending} onClose={() => setDeleting(null)} onConfirm={() => deleting && remove.mutate(deleting.id)} />
    </Card>
  )
}
