import { apiClient } from './client'
import type {
  CertificateEvent,
  CertificateEventListQuery,
  CertificateListQuery,
  CertificateSummary,
  CertificateWithSite,
  CreateSslRequest,
  Page,
  SslCertificate,
  SslSettings,
  UpdateSslRequest,
  UpdateSslSettingsRequest,
} from './types'

/** `POST /sites/{site_id}/certificates/{id}/renew` ack. */
export interface RenewalAck {
  message: string
  certificate_id: string
  status: string
}

/**
 * SSL / TLS — two surfaces over the same certificate rows.
 *
 * - **Per site**: the certificates that site may serve and its TLS posture —
 *   HTTPS on/off, which certificate (or a self-signed one), mTLS, the TLS
 *   version window and HSTS.
 * - **Global** (`/certificates`): the same rows across every site the caller
 *   sees, which is what the SSL/TLS overview page lists, filters and renews.
 *
 * The private key is write-only: it can be uploaded but never read back.
 */
export const sslApi = {
  /* ── Per site ────────────────────────────────────────────────────── */
  list: (siteId: string) =>
    apiClient.get<Page<SslCertificate>>(`/sites/${siteId}/certificates`, {
      query: { page_size: 200 },
    }),

  create: (siteId: string, data: CreateSslRequest) =>
    apiClient.post<SslCertificate>(`/sites/${siteId}/certificates`, data),

  update: (siteId: string, id: string, data: UpdateSslRequest) =>
    apiClient.put<SslCertificate>(`/sites/${siteId}/certificates/${id}`, data),

  delete: (siteId: string, id: string) =>
    apiClient.delete<void>(`/sites/${siteId}/certificates/${id}`),

  /** Starts an out-of-band ACME renewal; ACME-managed certificates only. */
  renew: (siteId: string, id: string) =>
    apiClient.post<RenewalAck>(`/sites/${siteId}/certificates/${id}/renew`),

  getSettings: (siteId: string) =>
    apiClient.get<SslSettings>(`/sites/${siteId}/ssl-settings`),

  updateSettings: (siteId: string, data: UpdateSslSettingsRequest) =>
    apiClient.put<SslSettings>(`/sites/${siteId}/ssl-settings`, data),

  /* ── Global ──────────────────────────────────────────────────────── */
  listAll: (query: CertificateListQuery = {}) =>
    apiClient.get<Page<CertificateWithSite>>('/certificates', {
      query: { page_size: 200, ...query },
    }),

  summary: () => apiClient.get<CertificateSummary>('/certificates/summary'),

  /** Uploads a certificate, or applies for one, on a site's behalf. */
  createGlobal: (data: CreateSslRequest & { site_id: string }) =>
    apiClient.post<SslCertificate>('/certificates', data),

  updateGlobal: (id: string, data: UpdateSslRequest) =>
    apiClient.put<SslCertificate>(`/certificates/${id}`, data),

  deleteGlobal: (id: string) => apiClient.delete<void>(`/certificates/${id}`),

  renewGlobal: (id: string) =>
    apiClient.post<RenewalAck>(`/certificates/${id}/renew`),

  /* ── Certificate events ──────────────────────────────────────────── */
  listCertEvents: (certId: string, query: CertificateEventListQuery = {}) =>
    apiClient.get<Page<CertificateEvent>>(`/certificates/${certId}/events`, {
      query: { page_size: 50, ...query },
    }),

  listAllEvents: (query: CertificateEventListQuery = {}) =>
    apiClient.get<Page<CertificateEvent>>('/ssl-events', {
      query: { page_size: 50, ...query },
    }),
}

/**
 * Days until a certificate expires, or `null` when no expiry is recorded.
 * Negative values mean the certificate has already lapsed.
 */
export function daysUntilExpiry(expiresAt: string | null, now = Date.now()): number | null {
  if (!expiresAt) return null
  const ts = new Date(expiresAt).getTime()
  if (Number.isNaN(ts)) return null
  return Math.floor((ts - now) / 86_400_000)
}

/** Tone for an expiry badge: red < 7d, amber < 30d, green otherwise. */
export function expiryTone(
  days: number | null,
): 'danger' | 'warning' | 'success' | 'neutral' {
  if (days === null) return 'neutral'
  if (days < 7) return 'danger'
  if (days < 30) return 'warning'
  return 'success'
}

export const sslKeys = {
  all: ['ssl'] as const,
  site: (siteId: string) => [...sslKeys.all, 'site', siteId] as const,
  list: (siteId: string) => [...sslKeys.site(siteId), 'list'] as const,
  detail: (siteId: string, id: string) => [...sslKeys.site(siteId), 'detail', id] as const,
  settings: (siteId: string) => [...sslKeys.site(siteId), 'settings'] as const,
  global: (query?: CertificateListQuery) => [...sslKeys.all, 'global', query ?? {}] as const,
  summary: () => [...sslKeys.all, 'summary'] as const,
  events: (query?: CertificateEventListQuery) =>
    [...sslKeys.all, 'events', query ?? {}] as const,
  certEvents: (certId: string, query?: CertificateEventListQuery) =>
    [...sslKeys.all, 'cert', certId, 'events', query ?? {}] as const,
}

export default sslApi
