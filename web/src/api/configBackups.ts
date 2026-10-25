import { apiClient } from './client'

export type BackupTargetKind = 's3' | 'github'
export type BackupScope = 'site' | 'global' | 'deployment'

export interface BackupTarget {
  id: string
  kind: BackupTargetKind
  name: string
  config: Record<string, unknown> & { has_credentials?: boolean }
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface BackupTargetRequest {
  kind: BackupTargetKind
  name: string
  config: Record<string, unknown>
  enabled: boolean
}

export interface BackupSummary {
  id: string
  scope: BackupScope
  site_id: string | null
  target_id: string | null
  status: 'created' | 'uploading' | 'completed' | 'failed' | string
  file_name: string
  manifest: Record<string, unknown>
  checksum: string
  error: string
  actor: string | null
  size_bytes: number
  created_at: string
  completed_at: string | null
}

export interface BackupTableChange {
  table: string
  before: number
  after: number
  added: number
  removed: number
  changed: number
}

export interface BackupPreview {
  scope: BackupScope
  tables: BackupTableChange[]
  sites_to_remove: string[]
  owner_changes: Array<{ site_id: string; from: string | null; to: string | null }>
  warnings: string[]
}

export interface BackupUploadPreview {
  backup: BackupSummary
  preview: BackupPreview
}

export const configBackupKeys = {
  targets: ['config-backup-targets'] as const,
  backups: ['config-backups'] as const,
}

export const configBackupsApi = {
  listTargets: () => apiClient.get<BackupTarget[]>('/config-backup-targets'),
  createTarget: (data: BackupTargetRequest) =>
    apiClient.post<BackupTarget>('/config-backup-targets', data),
  updateTarget: (
    id: string,
    data: Partial<Pick<BackupTargetRequest, 'name' | 'config' | 'enabled'>>,
  ) => apiClient.put<BackupTarget>(`/config-backup-targets/${id}`, data),
  deleteTarget: (id: string) =>
    apiClient.delete<{ deleted: boolean }>(`/config-backup-targets/${id}`),
  testTarget: (id: string) =>
    apiClient.post<{ ok: boolean }>(`/config-backup-targets/${id}/test`, {}),

  list: () => apiClient.get<BackupSummary[]>('/config-backups'),
  create: (data: {
    scope: BackupScope
    site_id?: string
    password: string
    target_id?: string
  }) => apiClient.post<BackupSummary>('/config-backups', data),
  get: (id: string) => apiClient.get<BackupSummary>(`/config-backups/${id}`),
  download: (id: string) =>
    apiClient.get<string>(`/config-backups/${id}/download`, { rawText: true }),
  upload: (id: string, targetId: string) =>
    apiClient.post<{ status: string }>(`/config-backups/${id}/upload`, {
      target_id: targetId,
    }),
  preview: (id: string, password: string) =>
    apiClient.post<BackupPreview>(`/config-backups/${id}/preview`, { password }),
  restore: (id: string, password: string) =>
    apiClient.post<{
      restored: boolean
      pre_restore_backup_id: string
      new_version: number | null
      warnings: string[]
    }>(`/config-backups/${id}/restore`, { password }),
  uploadFile: (data: {
    file: File
    password: string
    scope: BackupScope
    siteId?: string
  }) => {
    const form = new FormData()
    form.append('file', data.file)
    form.append('password', data.password)
    form.append('scope', data.scope)
    if (data.siteId) form.append('site_id', data.siteId)
    return apiClient.post<BackupUploadPreview>('/config-backups/upload', form)
  },
}

export default configBackupsApi
