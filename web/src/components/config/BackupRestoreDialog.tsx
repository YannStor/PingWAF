import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { useSitesList } from '@/hooks'
import type { BackupScope } from '@/api/configBackups'
import { useToast } from '@/components/ui/Toast'
import { configBackupsApi, type BackupPreview, type BackupSummary } from '@/api/configBackups'
import { errorMessage } from '@/api/errors'

export function BackupRestoreDialog({
  open,
  backup,
  onClose,
  onRestored,
}: {
  open: boolean
  backup: BackupSummary | null
  onClose: () => void
  onRestored: () => void
}) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const sites = useSitesList({ page: 1, page_size: 200 })
  const [scope, setScope] = useState<BackupScope>('deployment')
  const [siteId, setSiteId] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [password, setPassword] = useState('')
  const [preview, setPreview] = useState<BackupPreview | null>(null)
  const [uploaded, setUploaded] = useState<BackupSummary | null>(null)
  const previewGeneration = useRef(0)

  const invalidatePreview = () => {
    previewGeneration.current += 1
    setPreview(null)
    setUploaded(null)
  }
  const close = () => {
    setFile(null)
    setPassword('')
    setPreview(null)
    setUploaded(null)
    onClose()
  }

  const previewMutation = useMutation({
    mutationFn: async () => {
      const requestId = ++previewGeneration.current
      if (backup) {
        return {
          requestId,
          preview: await configBackupsApi.preview(backup.id, password),
          uploaded: null,
        }
      }
      if (!file) throw new Error(t('pages.backups.fileRequired'))
      const result = await configBackupsApi.uploadFile({
        file,
        password,
        scope,
        ...(scope === 'site' ? { siteId } : {}),
      })
      return { requestId, preview: result.preview, uploaded: result.backup }
    },
    onSuccess: (result) => {
      if (result.requestId !== previewGeneration.current) return
      setPreview(result.preview)
      setUploaded(result.uploaded)
      void queryClient.invalidateQueries({
        queryKey: ['config-backups'],
      })
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  const restoreMutation = useMutation({
    mutationFn: (id: string) => configBackupsApi.restore(id, password),
    onSuccess: (result) => {
      const warnings = result.warnings ?? []
      if (warnings.length > 0) {
        toast.error(
          t('pages.backups.restoreWarnings', {
            warnings: warnings.join('; '),
          }),
        )
      } else {
        toast.success(t('pages.backups.restoreSuccess'))
      }
      onRestored()
      close()
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  const restoreId = backup?.id ?? uploaded?.id
  return (
    <Dialog
      open={open}
      onClose={close}
      size="lg"
      title={backup ? t('pages.backups.restoreTitle') : t('pages.backups.uploadTitle')}
      description={t('pages.backups.preRestoreHint')}
      footer={
        <>
          <Button variant="secondary" onClick={close}>{t('common.cancel')}</Button>
          {!preview ? (
            <Button
              disabled={
                password.length < 12 ||
                (!backup && !file) ||
                (!backup && scope === 'site' && !siteId)
              }
              loading={previewMutation.isPending}
              onClick={() => previewMutation.mutate()}
            >
              {t('pages.backups.preview')}
            </Button>
          ) : (
            <Button
              disabled={!restoreId}
              loading={restoreMutation.isPending}
              onClick={() => restoreId && restoreMutation.mutate(restoreId)}
            >
              {t('pages.backups.confirmRestore')}
            </Button>
          )}
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {!backup && (
          <div className="grid gap-3 md:grid-cols-2">
            <Select
              label={t('pages.backups.backupScope')}
              value={scope}
              onChange={(event) => {
                invalidatePreview()
                setScope(event.target.value as BackupScope)
              }}
              options={[
                { value: 'deployment', label: t('pages.backups.scopeDeployment') },
                { value: 'global', label: t('pages.backups.scopeGlobal') },
                { value: 'site', label: t('pages.backups.scopeSite') },
              ]}
            />
            {scope === 'site' && (
              <Select
                label={t('pages.backups.siteId')}
                value={siteId}
                onChange={(event) => {
                  invalidatePreview()
                  setSiteId(event.target.value)
                }}
                options={[
                  { value: '', label: t('pages.backups.selectSite') },
                  ...(sites.data ?? []).map((site) => ({ value: site.id, label: site.domain })),
                ]}
              />
            )}
          </div>
        )}
        {!backup && (
          <div className="flex flex-col gap-1.5">
            <label className="text-[13px] font-medium text-fg" htmlFor="backup-file">
              {t('pages.backups.file')}
            </label>
            <input
              id="backup-file"
              type="file"
              accept=".json,.pwb.json,application/json"
              className="text-sm text-fg file:mr-3 file:rounded-md file:border file:border-line file:bg-recessed file:px-3 file:py-2 file:text-sm file:text-fg"
              onChange={(event) => {
                invalidatePreview()
                setFile(event.target.files?.[0] ?? null)
              }}
            />
          </div>
        )}
        <Input
          label={t('pages.backups.password')}
          hint={t('pages.backups.passwordHint')}
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(event) => {
            invalidatePreview()
            setPassword(event.target.value)
          }}
        />
        {preview && (
          <div className="flex flex-col gap-3">
            <h4 className="text-sm font-semibold text-fg-strong">{t('pages.backups.previewTitle')}</h4>
            <div className="max-h-72 overflow-auto rounded-md border border-line">
              <table className="w-full text-left text-xs">
                <thead className="bg-recessed text-fg-subtle">
                  <tr>
                    <th className="px-3 py-2">{t('pages.backups.table')}</th>
                    <th className="px-3 py-2">{t('pages.backups.before')}</th>
                    <th className="px-3 py-2">{t('pages.backups.after')}</th>
                    <th className="px-3 py-2">{t('pages.backups.added')}</th>
                    <th className="px-3 py-2">{t('pages.backups.removed')}</th>
                    <th className="px-3 py-2">{t('pages.backups.changed')}</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.tables.map((row) => (
                    <tr key={row.table} className="border-t border-line">
                      <td className="px-3 py-2 pw-mono">{row.table}</td>
                      <td className="px-3 py-2">{row.before}</td>
                      <td className="px-3 py-2">{row.after}</td>
                      <td className="px-3 py-2 text-fg-success">+{row.added}</td>
                      <td className="px-3 py-2 text-fg-danger">-{row.removed}</td>
                      <td className="px-3 py-2">{row.changed}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {preview.sites_to_remove.length > 0 && (
              <p className="text-xs text-fg-danger">
                {t('pages.backups.sitesToRemove', { count: preview.sites_to_remove.length })}
              </p>
            )}
            {preview.owner_changes.length > 0 && (
              <div className="rounded-md border border-line p-3 text-xs">
                <strong>{t('pages.backups.ownerChanges')}</strong>
                <ul className="mt-1 flex flex-col gap-1">
                  {preview.owner_changes.map((change) => (
                    <li key={change.site_id} className="pw-mono">
                      {change.site_id}: {change.from ?? '—'} → {change.to ?? '—'}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {preview.warnings.length > 0 && (
              <ul className="flex flex-col gap-1 text-xs text-fg-warning">
                {preview.warnings.map((warning) => <li key={warning}>{warning}</li>)}
              </ul>
            )}
          </div>
        )}
      </div>
    </Dialog>
  )
}
