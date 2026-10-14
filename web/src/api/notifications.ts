import { apiClient } from './client'

/** One configured delivery target for system alerts. */
export interface NotificationChannel {
  id: string
  name: string
  kind: 'email' | 'wecom' | 'dingtalk' | 'webhook'
  config: Record<string, unknown>
  /** Event types the channel subscribed to; empty receives everything. */
  events: string[]
  enabled: boolean
  created_at: string
  updated_at: string
}

export type NotificationChannelInput = {
  name: string
  kind: NotificationChannel['kind']
  config: Record<string, unknown>
  events: string[]
  enabled: boolean
}

/** Thresholds, per-event delivery toggles and suppression windows. */
export interface NotificationSettings {
  /** Noise master switch: false stops channel delivery (history stays). */
  enabled: boolean
  cpu_percent: number
  memory_percent: number
  disk_percent: number
  dedup_window_secs: number
  notify_agent_offline: boolean
  notify_agent_online: boolean
  notify_agent_resource: boolean
  notify_control_plane_resource: boolean
  notify_cert_expiry: boolean
  notify_cert_renewal_failed: boolean
  notify_config_sync_failed: boolean
  notify_site_failover_changed: boolean
  /** Gates both site.upstream_offline and site.upstream_abnormal. */
  notify_site_upstream: boolean
  notify_auth_login_anomaly: boolean
  cert_expiry_warn_days: number
}

/** One row of the alert history. */
export interface NotificationEvent {
  id: string
  event_type: string
  severity: 'info' | 'warning' | 'critical'
  title: string
  message: string
  details: Record<string, unknown> | null
  created_at: string
}

/** The event types the control plane can raise. */
export const NOTIFICATION_EVENT_TYPES = [
  'agent.offline',
  'agent.online',
  'agent.resource',
  'control_plane.resource',
  'cert.renewal_failed',
  'cert.expiring',
  'cert.expired',
  'config.sync_failed',
  'site.failover_changed',
  'site.upstream_offline',
  'site.upstream_abnormal',
  'auth.login_anomaly',
] as const

/** The placeholder the server substitutes for stored secrets. */
export const NOTIFICATION_SECRET_MASK = '***'

export const notificationKeys = {
  all: ['notifications'] as const,
  channels: () => [...notificationKeys.all, 'channels'] as const,
  settings: () => [...notificationKeys.all, 'settings'] as const,
  events: (offset?: number) =>
    [...notificationKeys.all, 'events', offset ?? 0] as const,
}

export const notificationsApi = {
  listChannels: () =>
    apiClient.get<NotificationChannel[]>('/notifications/channels'),

  createChannel: (payload: NotificationChannelInput) =>
    apiClient.post<NotificationChannel>('/notifications/channels', payload),

  updateChannel: (id: string, payload: NotificationChannelInput) =>
    apiClient.put<NotificationChannel>(
      `/notifications/channels/${id}`,
      payload,
    ),

  deleteChannel: (id: string) =>
    apiClient.delete<{ deleted: boolean }>(`/notifications/channels/${id}`),

  /** Sends a test alert through the channel; `ok` reports the delivery. */
  testChannel: (id: string) =>
    apiClient.post<{ ok: boolean; error?: string }>(
      `/notifications/channels/${id}/test`,
      {},
    ),

  getSettings: () =>
    apiClient.get<NotificationSettings>('/notifications/settings'),

  saveSettings: (settings: NotificationSettings) =>
    apiClient.put<NotificationSettings>('/notifications/settings', settings),

  listEvents: (limit = 100, offset = 0, eventType?: string) => {
    const params = new URLSearchParams()
    params.set('limit', String(limit))
    params.set('offset', String(offset))
    if (eventType) params.set('event_type', eventType)
    return apiClient.get<NotificationEvent[]>(
      `/notifications/events?${params.toString()}`,
    )
  },
}

/**
 * Replaces `***` placeholders with a marker the server understands, so a
 * save never overwrites a stored secret with the mask.
 */
export function unmaskSecrets(
  config: Record<string, unknown>,
): Record<string, unknown> {
  const output: Record<string, unknown> = { ...config }
  for (const key of ['smtp_pass', 'secret', 'secret_token']) {
    if (output[key] === NOTIFICATION_SECRET_MASK) {
      output[key] = '__REDACTED__'
    }
  }
  return output
}

export default notificationsApi
