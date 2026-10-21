import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  ArrowsClockwise,
  Certificate,
  Check,
  Info,
  Lock,
  ShieldCheck,
  Trash,
  Warning,
} from '@phosphor-icons/react'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { Dialog } from '@/components/ui/Dialog'
import { Tabs } from '@/components/ui/Tabs'
import { Textarea } from '@/components/ui/Textarea'
import { Table, type Column } from '@/components/ui/Table'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { useUnsavedGuard } from '@/hooks/useUnsavedGuard'
import { EmptyState } from '@/components/ui/EmptyState'
import { SkeletonRows, SkeletonStat } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import { CertWarningsBadge } from '@/components/ssl/CertWarnings'
import { sslApi, sslKeys, daysUntilExpiry, expiryTone } from '@/api/ssl'
import { MtlsMaterial } from '@/pages/sites/MtlsMaterial'
import { useCanWrite, useNow } from '@/hooks'
import { cn } from '@/lib/utils'
import { formatDate, formatDateTime } from '@/lib/format'
import {
  TLS_VERSIONS,
  type SslCertificate,
  type SslSettings,

  type UpdateSslSettingsRequest,
} from '@/api/types'
import { sitesApi, siteKeys } from '@/api/sites'
import {
  verifyCertMode,
  verifyCertPayload,
  type VerifyCertMode,
} from './basic/types'

/** Largest HSTS lifetime the server accepts, in seconds (two years). */
const MAX_HSTS_AGE = 63_072_000

/** Pre-filled HSTS window when the switch is turned on: 180 days. */
const DEFAULT_HSTS_AGE = 15_552_000

/** Which card a save belongs to — the server merges, so each sends its fields. */
type SaveScope = 'https' | 'tls' | 'mtls'

interface HttpsDraft {
  https_enabled: boolean
  self_signed: boolean
  certificate_id: string | null
}

interface TlsDraft {
  min_tls_version: string
  max_tls_version: string | null
  hsts_enabled: boolean
  hsts_max_age: number
  always_use_https: boolean
  http1_enabled: boolean
  http2_enabled: boolean
}

interface MtlsDraft {
  mtls_enabled: boolean
  mtls_require_client_cert: boolean
  mtls_organization: string
}

interface PostureDrafts {
  https: HttpsDraft
  tls: TlsDraft
  mtls: MtlsDraft
}

const toHttpsDraft = (s: SslSettings): HttpsDraft => ({
  https_enabled: s.https_enabled,
  self_signed: s.self_signed,
  certificate_id: s.certificate_id,
})

const toTlsDraft = (s: SslSettings): TlsDraft => ({
  min_tls_version: String(s.min_tls_version),
  max_tls_version: s.max_tls_version ? String(s.max_tls_version) : null,
  hsts_enabled: s.hsts_enabled,
  hsts_max_age: s.hsts_max_age,
  always_use_https: s.always_use_https,
  http1_enabled: s.http1_enabled ?? true,
  http2_enabled: s.http2_enabled ?? true,
})

const toMtlsDraft = (s: SslSettings): MtlsDraft => ({
  mtls_enabled: s.mtls_enabled,
  mtls_require_client_cert: s.mtls_require_client_cert,
  mtls_organization: s.mtls_organization ?? '',
})

const toDrafts = (s: SslSettings): PostureDrafts => ({
  https: toHttpsDraft(s),
  tls: toTlsDraft(s),
  mtls: toMtlsDraft(s),
})

/** A label for the certificate picker: domain plus expiry, when recorded. */
function certOptionLabel(cert: SslCertificate): string {
  return cert.expires_at ? `${cert.domain} · ${formatDate(cert.expires_at)}` : cert.domain
}

/**
 * Site-wide origin certificate check — the middle tier of the pool → site →
 * global cascade. `null` ("follow the deployment default") leaves every pool
 * without its own pin on `Settings → Origin TLS verification`. Pools that
 * pin a value keep it; the Basic page shows each pool's effective state.
 */
function OriginVerifyCard({ siteId, canWrite }: { siteId: string; canWrite: boolean }) {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const siteQuery = useQuery({
    queryKey: siteKeys.detail(siteId),
    queryFn: () => sitesApi.get(siteId),
    enabled: Boolean(siteId),
  })
  const site = siteQuery.data?.site ?? null

  // Local draft, seeded once from the first server copy; unsaved edits must
  // survive background refetches (window focus, cache invalidation) — the
  // same seed-once pattern the SSL posture cards below use. Re-keyed on the
  // site id so navigating between sites re-seeds from that site's data.
  const [draft, setDraft] = useState<VerifyCertMode | null>(null)
  const [seededFor, setSeededFor] = useState<string | null>(null)
  if (site && seededFor !== site.id) {
    setSeededFor(site.id)
    setDraft(verifyCertMode(site.origin_verify_cert ?? null))
  }

  const save = useMutation({
    mutationFn: (mode: VerifyCertMode) =>
      sitesApi.update(siteId, { origin_verify_cert: verifyCertPayload(mode) }),
    onSuccess: (_data, mode) => {
      // The Basic page pools section shares this cache entry.
      queryClient.invalidateQueries({ queryKey: siteKeys.detail(siteId) })
      setDraft(mode)
      toast.success(t('pages.ssl.originVerify.saved'))
    },
  })

  const dirty =
    draft !== null &&
    site !== null &&
    draft !== verifyCertMode(site.origin_verify_cert ?? null)

  const unsavedDialog = useUnsavedGuard(dirty)

  return (
    <Card className="mb-6">
      <CardHeader
        title={t('pages.ssl.originVerify.title')}
        description={t('pages.ssl.originVerify.description')}
        action={
          canWrite && (
            <Button
              variant="primary"
              size="sm"
              loading={save.isPending}
              disabled={!dirty}
              onClick={() => draft && save.mutate(draft)}
            >
              {t('common.save')}
            </Button>
          )
        }
      />
      <CardBody className="flex flex-col gap-4">
        {unsavedDialog}
        {siteQuery.isPending && !draft ? (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <SkeletonStat />
            <SkeletonStat />
          </div>
        ) : (
          <>
            <Select
              label={t('pages.ssl.originVerify.label')}
              value={draft ?? 'inherit'}
              disabled={!canWrite}
              hint={t('pages.ssl.originVerify.cascadeHint')}
              options={[
                { value: 'inherit', label: t('pages.ssl.originVerify.inherit') },
                { value: 'verify', label: t('pages.ssl.originVerify.verify') },
                { value: 'skip', label: t('pages.ssl.originVerify.skip') },
              ]}
              onChange={(e) => setDraft(e.target.value as VerifyCertMode)}
            />
            <p className="flex items-start gap-1.5 text-xs text-fg-subtle">
              <Info weight="duotone" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {t('pages.ssl.originVerify.effectiveHint')}
            </p>
          </>
        )}
      </CardBody>
    </Card>
  )
}

/**
 * Per-site TLS posture: which certificate the site serves (an installed one or
 * a self-signed fallback), whether HTTPS and mTLS are on, the TLS version
 * window and HSTS. Issuing and uploading certificates lives on the global
 * SSL/TLS page; this page only points at it.
 */
export function SslPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const now = useNow(60_000)
  const { siteId = '' } = useParams<{ siteId: string }>()

  const [drafts, setDrafts] = useState<PostureDrafts | null>(null)
  const [hasClientCa, setHasClientCa] = useState(false)
  const [clientCa, setClientCa] = useState('')
  const [httpsError, setHttpsError] = useState<string | null>(null)
  const [tlsError, setTlsError] = useState<string | null>(null)
  const [mtlsError, setMtlsError] = useState<string | null>(null)
  const [protocolsError, setProtocolsError] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<SslCertificate | null>(null)
  const [details, setDetails] = useState<SslCertificate | null>(null)

  const certsQuery = useQuery({
    queryKey: sslKeys.list(siteId),
    queryFn: () => sslApi.list(siteId),
    select: (page) => page.items,
    enabled: Boolean(siteId),
  })

  const settingsQuery = useQuery({
    queryKey: sslKeys.settings(siteId),
    queryFn: () => sslApi.getSettings(siteId),
    enabled: Boolean(siteId),
  })

  const serverSettings = settingsQuery.data
  const serverMaxVersion = serverSettings?.max_tls_version ?? null

  // Each card edits its own draft so that saving one never discards what is
  // half-typed in another. The stored client CA is write-only — the GET only
  // reports whether one exists — so it is tracked as "configured" plus
  // whatever has been pasted since the last save.
  // `null` until the first seed: cached query data present at mount must still
  // reach the drafts.
  const [lastServerSettings, setLastServerSettings] = useState<typeof serverSettings | null>(null)
  if (serverSettings && serverSettings !== lastServerSettings) {
    setLastServerSettings(serverSettings)
    setHasClientCa(serverSettings.has_mtls_client_ca)
    setDrafts((prev) => prev ?? toDrafts(serverSettings))
  }

  const certs = useMemo(
    () =>
      [...(certsQuery.data ?? [])].sort((a, b) => {
        const da = daysUntilExpiry(a.expires_at, now) ?? Number.MAX_SAFE_INTEGER
        const db = daysUntilExpiry(b.expires_at, now) ?? Number.MAX_SAFE_INTEGER
        return da - db
      }),
    [certsQuery.data, now],
  )

  const currentCert = useMemo(
    () => certs.find((c) => c.id === drafts?.https.certificate_id) ?? null,
    [certs, drafts?.https.certificate_id],
  )

  const patchHttps = (part: Partial<HttpsDraft>) =>
    setDrafts((prev) => (prev ? { ...prev, https: { ...prev.https, ...part } } : prev))

  const patchTls = (part: Partial<TlsDraft>) =>
    setDrafts((prev) => (prev ? { ...prev, tls: { ...prev.tls, ...part } } : prev))

  const invalidateCerts = () => {
    void queryClient.invalidateQueries({ queryKey: sslKeys.list(siteId) })
  }

  /**
   * One mutation for all three cards: `scope` says which draft to refresh from
   * the response, so the fields of the other cards survive untouched.
   */
  const saveSettings = useMutation({
    mutationFn: ({
      payload,
    }: {
      scope: SaveScope
      payload: UpdateSslSettingsRequest
    }) => sslApi.updateSettings(siteId, payload),
    onSuccess: (saved, { scope, payload }) => {
      queryClient.setQueryData(sslKeys.settings(siteId), saved)
      setDrafts((prev) =>
        prev
          ? {
              https: scope === 'https' ? toHttpsDraft(saved) : prev.https,
              tls: scope === 'tls' ? toTlsDraft(saved) : prev.tls,
              mtls: scope === 'mtls' ? toMtlsDraft(saved) : prev.mtls,
            }
          : prev,
      )
      setHttpsError(null)
      setTlsError(null)
      setMtlsError(null)
      setProtocolsError(null)
      // The CA is never echoed back — drop the pasted copy once it is stored.
      if (scope === 'mtls' && payload.mtls_client_ca) setClientCa('')
      toast.success(t('pages.ssl.settingsSaved'))
    },
  })

  const savingScope = saveSettings.isPending ? saveSettings.variables?.scope ?? null : null

  const renew = useMutation({
    mutationFn: (cert: SslCertificate) => sslApi.renew(siteId, cert.id),
    onSuccess: (ack, cert) => {
      toast.success(t('pages.ssl.renewStarted'), ack.message || cert.domain)
      invalidateCerts()
    },
  })

  const remove = useMutation({
    mutationFn: (id: string) => sslApi.delete(siteId, id),
    onSuccess: (_data, id) => {
      toast.success(t('pages.ssl.certDeleted'), certs.find((c) => c.id === id)?.domain)
      // A deleted certificate must not stay selected, or the next save would
      // send an id the server no longer recognises.
      setDrafts((prev) =>
        prev && prev.https.certificate_id === id
          ? { ...prev, https: { ...prev.https, certificate_id: null } }
          : prev,
      )
      setPendingDelete(null)
      invalidateCerts()
    },
  })

  const saveHttps = () => {
    if (!drafts) return
    setHttpsError(null)
    saveSettings.mutate({
      scope: 'https',
      payload: {
        https_enabled: drafts.https.https_enabled,
        self_signed: drafts.https.self_signed,
        // Null means "leave unchanged" server-side; a self-signed choice
        // clears the stored id on the server regardless.
        certificate_id: drafts.https.certificate_id,
      },
    })
  }

  const saveTls = () => {
    if (!drafts) return
    setTlsError(null)
    setProtocolsError(null)
    const { min_tls_version, max_tls_version } = drafts.tls
    if (max_tls_version && Number(max_tls_version) < Number(min_tls_version)) {
      setTlsError(t('pages.ssl.versionRangeInvalid'))
      return
    }
    // At least one protocol must stay on — the server rejects the pair-off.
    if (!drafts.tls.http1_enabled && !drafts.tls.http2_enabled) {
      setProtocolsError(t('pages.ssl.protocolsRequired'))
      return
    }
    saveSettings.mutate({
      scope: 'tls',
      payload: {
        min_tls_version,
        max_tls_version,
        hsts_enabled: drafts.tls.hsts_enabled,
        hsts_max_age: drafts.tls.hsts_max_age,
        always_use_https: drafts.tls.always_use_https,
        http1_enabled: drafts.tls.http1_enabled,
        http2_enabled: drafts.tls.http2_enabled,
      },
    })
  }

  const saveMtls = () => {
    if (!drafts) return
    setMtlsError(null)
    const ca = clientCa.trim()
    if (drafts.mtls.mtls_enabled && !hasClientCa && !ca) {
      setMtlsError(t('pages.ssl.clientCaRequired'))
      return
    }
    const payload: UpdateSslSettingsRequest = {
      mtls_enabled: drafts.mtls.mtls_enabled,
      mtls_require_client_cert: drafts.mtls.mtls_require_client_cert,
    }
    if (ca) payload.mtls_client_ca = ca
    const organization = drafts.mtls.mtls_organization.trim()
    if (organization) payload.mtls_organization = organization
    saveSettings.mutate({ scope: 'mtls', payload })
  }

  const setAsCurrent = (cert: SslCertificate) => {
    saveSettings.mutate(
      { scope: 'https', payload: { self_signed: false, certificate_id: cert.id } },
      { onSuccess: () => toast.success(t('pages.ssl.currentSet'), cert.domain) },
    )
  }

  const isCurrent = (cert: SslCertificate) =>
    !drafts?.https.self_signed && drafts?.https.certificate_id === cert.id

  const columns: Column<SslCertificate>[] = [
    {
      key: 'domain',
      header: t('pages.ssl.domain'),
      accessor: (c) => c.domain,
      sortable: true,
      cell: (c) => (
        <div className="flex items-center gap-2">
          <span
            className={cn(
              'flex h-8 w-8 shrink-0 items-center justify-center rounded-md',
              isCurrent(c) ? 'bg-brand text-white' : 'bg-brand-soft text-brand',
            )}
          >
            <Lock weight="duotone" className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <p className="pw-mono truncate text-[13px] font-medium text-fg-strong">
                {c.domain}
              </p>
              {isCurrent(c) && (
                <Badge tone="brand" size="sm">
                  {t('pages.ssl.current')}
                </Badge>
              )}
              <CertWarningsBadge warnings={c.warnings} />
            </div>
            <p className="truncate text-xs text-fg-subtle">
              {c.issuer || t('pages.ssl.unknownIssuer')}
            </p>
          </div>
        </div>
      ),
    },
    {
      key: 'expires',
      header: t('pages.ssl.expires'),
      accessor: (c) => c.expires_at ?? '',
      width: '1%',
      cell: (c) => {
        const days = daysUntilExpiry(c.expires_at, now)
        const tone = expiryTone(days)
        return (
          <div className="flex flex-col items-start gap-1">
            <span className="text-[13px] text-fg">{formatDateTime(c.expires_at)}</span>
            {days !== null && (
              <Badge tone={tone} size="sm" dot>
                {days < 0 ? t('status.expired') : t('pages.ssl.daysLeft', { days })}
              </Badge>
            )}
          </div>
        )
      },
    },
    {
      key: 'auto_renew',
      header: t('pages.ssl.autoRenew'),
      accessor: (c) => (c.auto_renew ? 1 : 0),
      width: '1%',
      cell: (c) =>
        c.auto_renew ? (
          <Badge tone="success" size="sm">
            {t('common.enabled')}
          </Badge>
        ) : (
          <Badge tone="neutral" size="sm">
            {t('common.disabled')}
          </Badge>
        ),
    },
    {
      key: 'row-actions',
      header: '',
      align: 'right',
      width: '1%',
      cell: (c) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('common.details')}
            onClick={() => setDetails(c)}
            icon={<Info weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('pages.ssl.setAsCurrent')}
            disabled={!canWrite || isCurrent(c) || saveSettings.isPending}
            onClick={() => setAsCurrent(c)}
            icon={<Check weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            aria-label={t('pages.ssl.renew')}
            disabled={!canWrite || renew.isPending}
            onClick={() => renew.mutate(c)}
            icon={<ArrowsClockwise weight="duotone" className="h-4 w-4" />}
          />
          <Button
            size="icon"
            variant="ghost"
            className="hover:text-fg-danger"
            aria-label={t('common.delete')}
            disabled={!canWrite}
            onClick={() => setPendingDelete(c)}
            icon={<Trash weight="duotone" className="h-4 w-4" />}
          />
        </div>
      ),
    },
  ]

  const expiringSoon = certs.filter((c) => {
    const d = daysUntilExpiry(c.expires_at, now)
    return d !== null && d >= 0 && d < 30
  }).length

  const currentDays = currentCert ? daysUntilExpiry(currentCert.expires_at, now) : null

  return (
    <div className="animate-slide-up">
      <PageHeader
        title={t('pages.ssl.title')}
        description={t('pages.ssl.siteDescription')}
        actions={
          <Button
            variant="secondary"
            loading={certsQuery.isFetching || settingsQuery.isFetching}
            onClick={() => {
              void certsQuery.refetch()
              void settingsQuery.refetch()
            }}
            icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
          >
            {t('common.refresh')}
          </Button>
        }
      />

      {expiringSoon > 0 && (
        <div className="mb-4 flex items-center gap-3 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3">
          <ShieldCheck weight="duotone" className="h-5 w-5 shrink-0 text-warning" />
          <p className="text-sm text-fg">
            {t('pages.ssl.expiringWarning', { count: expiringSoon })}
          </p>
        </div>
      )}

      {/* Site-wide origin certificate check: the middle tier between the
          deployment default and each pool's own pin. */}
      <OriginVerifyCard siteId={siteId} canWrite={canWrite} />

      {/* HTTPS + certificate source — the posture that matters most */}
      <Card className="mb-6">
        <CardHeader
          title={t('pages.ssl.httpsCardTitle')}
          description={t('pages.ssl.httpsCardHint')}
          action={
            canWrite &&
            drafts && (
              <Button
                variant="primary"
                size="sm"
                loading={savingScope === 'https'}
                onClick={saveHttps}
              >
                {t('common.save')}
              </Button>
            )
          }
        />
        <CardBody className="flex flex-col gap-5">
          {settingsQuery.isPending && !drafts ? (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <SkeletonStat />
              <SkeletonStat />
            </div>
          ) : !drafts ? (
            <ErrorState
              variant="inline"
              error={settingsQuery.error}
              onRetry={() => settingsQuery.refetch()}
              retrying={settingsQuery.isFetching}
            />
          ) : (
            <>
              <Switch
                checked={drafts.https.https_enabled}
                disabled={!canWrite}
                onCheckedChange={(https_enabled) => patchHttps({ https_enabled })}
                label={t('pages.ssl.httpsEnabled')}
                description={t('pages.ssl.httpsEnabledHint')}
              />

              {/* At a glance: what this site serves right now (as edited). */}
              <div className="rounded-md border border-line bg-recessed px-4 py-3">
                <p className="text-xs text-fg-subtle">{t('pages.ssl.currentCertificate')}</p>
                <div className="mt-1.5 flex flex-wrap items-center gap-2">
                  {!drafts.https.https_enabled && (
                    <Badge tone="neutral" size="sm">
                      {t('pages.ssl.httpsOff')}
                    </Badge>
                  )}
                  {drafts.https.self_signed ? (
                    <Badge tone="warning" size="sm" dot>
                      {t('pages.ssl.selfSignedInUse')}
                    </Badge>
                  ) : currentCert ? (
                    <>
                      <span className="pw-mono text-[13px] font-medium text-fg-strong">
                        {currentCert.domain}
                      </span>
                      <span className="text-xs text-fg-subtle">
                        {currentCert.issuer || t('pages.ssl.unknownIssuer')}
                      </span>
                      {currentDays !== null && (
                        <Badge tone={expiryTone(currentDays)} size="sm" dot>
                          {currentDays < 0
                            ? t('status.expired')
                            : t('pages.ssl.daysLeft', { days: currentDays })}
                        </Badge>
                      )}
                    </>
                  ) : (
                    <span className="flex items-center gap-1.5 text-[13px] text-fg-subtle">
                      <Warning weight="duotone" className="h-4 w-4 shrink-0 text-warning" />
                      {t('pages.ssl.noCertificateWarning')}
                    </span>
                  )}
                </div>
              </div>

              <div className="flex flex-col gap-3">
                <p className="text-[13px] font-medium text-fg-subtle">
                  {t('pages.ssl.certSource')}
                </p>
                <Tabs
                  variant="pill"
                  value={drafts.https.self_signed ? 'self-signed' : 'certificate'}
                  onChange={(value) => {
                    const self_signed = value === 'self-signed'
                    patchHttps({
                      self_signed,
                      // Pre-select a usable installed certificate so the
                      // "use a certificate" mode is never empty by accident.
                      certificate_id:
                        !self_signed && !drafts.https.certificate_id
                          ? (certs.find((c) => c.status === 'active') ?? certs[0])?.id ?? null
                          : drafts.https.certificate_id,
                    })
                  }}
                  items={[
                    { value: 'self-signed', label: t('pages.ssl.selfSigned') },
                    { value: 'certificate', label: t('pages.ssl.useCertificate') },
                  ]}
                />

                {drafts.https.self_signed ? (
                  <p className="max-w-2xl text-xs leading-relaxed text-fg-subtle">
                    {t('pages.ssl.selfSignedHint')}
                  </p>
                ) : (
                  <div className="flex flex-col gap-2">
                    <Select
                      label={t('pages.ssl.certificate')}
                      value={drafts.https.certificate_id ?? ''}
                      disabled={!canWrite}
                      containerClassName="max-w-md"
                      hint={t('pages.ssl.certificateSelectHint')}
                      options={[
                        { value: '', label: t('pages.ssl.selectCertificate') },
                        ...certs.map((c) => ({ value: c.id, label: certOptionLabel(c) })),
                      ]}
                      onChange={(e) =>
                        patchHttps({ certificate_id: e.target.value || null })
                      }
                    />
                    {certs.length === 0 && (
                      <p className="text-xs leading-relaxed text-fg-subtle">
                        {t('pages.ssl.emptyDescription')} {t('pages.ssl.issueElsewhereHint')}
                      </p>
                    )}
                  </div>
                )}
              </div>

              <CardError message={httpsError} />
            </>
          )}
        </CardBody>
      </Card>

      {/* TLS version window + HSTS */}
      {drafts && (
        <Card className="mb-6">
          <CardHeader
            title={t('pages.ssl.settingsTitle')}
            description={t('pages.ssl.settingsHint')}
            action={
              canWrite && (
                <Button
                  variant="primary"
                  size="sm"
                  loading={savingScope === 'tls'}
                  onClick={saveTls}
                >
                  {t('common.save')}
                </Button>
              )
            }
          />
          <CardBody className="flex flex-col gap-5">
            <div className="grid max-w-2xl grid-cols-1 gap-4 sm:grid-cols-2">
              <Select
                label={t('pages.ssl.minVersion')}
                value={drafts.tls.min_tls_version}
                disabled={!canWrite}
                hint={t('pages.ssl.minVersionHint')}
                options={TLS_VERSIONS.map((v) => ({ value: v, label: `TLS ${v}` }))}
                onChange={(e) => patchTls({ min_tls_version: e.target.value })}
              />
              <Select
                label={t('pages.ssl.maxVersion')}
                value={drafts.tls.max_tls_version ?? ''}
                disabled={!canWrite}
                hint={t('pages.ssl.maxVersionHint')}
                options={[
                  { value: '', label: t('pages.ssl.noUpperBound') },
                  ...TLS_VERSIONS.map((v) => ({ value: v, label: `TLS ${v}` })),
                ]}
                onChange={(e) => patchTls({ max_tls_version: e.target.value || null })}
              />
            </div>
            {drafts.tls.max_tls_version === null && serverMaxVersion && (
              <p className="-mt-3 text-xs text-fg-subtle">{t('pages.ssl.maxVersionSticky')}</p>
            )}

            <Switch
              checked={drafts.tls.hsts_enabled}
              disabled={!canWrite}
              onCheckedChange={(hsts_enabled) =>
                patchTls({
                  hsts_enabled,
                  // A fresh switch would otherwise save max-age=0, which the
                  // edge reads as "send no header" — seed the common window.
                  hsts_max_age:
                    hsts_enabled && drafts.tls.hsts_max_age <= 0
                      ? DEFAULT_HSTS_AGE
                      : drafts.tls.hsts_max_age,
                })
              }
              label={t('pages.ssl.hsts')}
              description={t('pages.ssl.hstsHint')}
            />
            {drafts.tls.hsts_enabled && (
              <Input
                type="number"
                label={t('pages.ssl.hstsMaxAge')}
                value={drafts.tls.hsts_max_age}
                min={0}
                max={MAX_HSTS_AGE}
                step={86400}
                disabled={!canWrite}
                containerClassName="max-w-xs"
                hint={t('pages.ssl.hstsMaxAgeHint')}
                onChange={(e) => patchTls({ hsts_max_age: Number(e.target.value) })}
              />
            )}
            <Switch
              checked={drafts.tls.always_use_https}
              disabled={!canWrite}
              onCheckedChange={(always_use_https) => patchTls({ always_use_https })}
              label={t('pages.ssl.alwaysHttps')}
              description={t('pages.ssl.alwaysHttpsHint')}
            />

            <CardError message={tlsError} />
          </CardBody>
        </Card>
      )}

      {/* HTTP protocol switches — HTTP/1.1 vs HTTP/2 */}
      {drafts && (
        <Card className="mb-6">
          <CardHeader
            title={t('pages.ssl.protocolsTitle')}
            description={t('pages.ssl.protocolsHint')}
            action={
              canWrite && (
                <Button
                  variant="primary"
                  size="sm"
                  loading={savingScope === 'tls'}
                  disabled={!drafts.tls.http1_enabled && !drafts.tls.http2_enabled}
                  onClick={saveTls}
                >
                  {t('common.save')}
                </Button>
              )
            }
          />
          <CardBody className="flex flex-col gap-5">
            <Switch
              checked={drafts.tls.http1_enabled}
              disabled={!canWrite}
              onCheckedChange={(http1_enabled) => patchTls({ http1_enabled })}
              label={t('pages.ssl.http1Enabled')}
              description={t('pages.ssl.http1Hint')}
            />
            <Switch
              checked={drafts.tls.http2_enabled}
              disabled={!canWrite}
              onCheckedChange={(http2_enabled) => patchTls({ http2_enabled })}
              label={t('pages.ssl.http2Enabled')}
              description={t('pages.ssl.http2Hint')}
            />
            {drafts.tls.http2_enabled && (
              <p className="-mt-3 flex max-w-2xl items-start gap-1.5 text-xs text-fg-subtle">
                <Info weight="duotone" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                {t('pages.ssl.http2Info')}
              </p>
            )}
            {protocolsError && <CardError message={protocolsError} />}
          </CardBody>
        </Card>
      )}

      {/* Mutual TLS */}
      {drafts && (
        <Card className="mb-6">
          <CardHeader
            title={t('pages.ssl.mtlsTitle')}
            description={t('pages.ssl.mtlsHint')}
            action={
              canWrite && (
                <Button
                  variant="primary"
                  size="sm"
                  loading={savingScope === 'mtls'}
                  onClick={saveMtls}
                >
                  {t('common.save')}
                </Button>
              )
            }
          />
          <CardBody className="flex flex-col gap-5">
            <Switch
              checked={drafts.mtls.mtls_enabled}
              disabled={!canWrite}
              onCheckedChange={(mtls_enabled) => {
                setDrafts((prev) => (prev ? { ...prev, mtls: { ...prev.mtls, mtls_enabled } } : prev))
              }}
              label={t('pages.ssl.mtlsEnabled')}
              description={t('pages.ssl.mtlsEnabledHint')}
            />

            {drafts.mtls.mtls_enabled && !drafts.https.https_enabled && (
              <p className="flex items-center gap-1.5 text-xs text-fg-subtle">
                <Warning weight="duotone" className="h-4 w-4 shrink-0 text-warning" />
                {t('pages.ssl.mtlsNeedsHttps')}
              </p>
            )}

            {drafts.mtls.mtls_enabled && (
              <>
                <Switch
                  checked={drafts.mtls.mtls_require_client_cert}
                  disabled={!canWrite}
                  onCheckedChange={(mtls_require_client_cert) =>
                    setDrafts((prev) =>
                      prev ? { ...prev, mtls: { ...prev.mtls, mtls_require_client_cert } } : prev,
                    )
                  }
                  label={t('pages.ssl.mtlsRequire')}
                  description={t('pages.ssl.mtlsRequireHint')}
                />
                <Input
                  label={t('pages.ssl.mtlsOrganization')}
                  value={drafts.mtls.mtls_organization}
                  disabled={!canWrite}
                  containerClassName="max-w-2xl"
                  placeholder="Acme Corp"
                  hint={t('pages.ssl.mtlsOrganizationHint')}
                  onChange={(e) =>
                    setDrafts((prev) =>
                      prev
                        ? { ...prev, mtls: { ...prev.mtls, mtls_organization: e.target.value } }
                        : prev,
                    )
                  }
                />
              </>
            )}

            <div className="flex flex-wrap items-center gap-2">
              {hasClientCa ? (
                <Badge tone="success" size="sm" dot>
                  {t('pages.ssl.clientCaConfigured')}
                </Badge>
              ) : (
                <Badge tone="neutral" size="sm" dot>
                  {t('pages.ssl.clientCaNotSet')}
                </Badge>
              )}
              {clientCa.trim() !== '' && (
                <Badge tone="warning" size="sm">
                  {t('pages.ssl.clientCaPending')}
                </Badge>
              )}
            </div>

            {drafts.mtls.mtls_enabled && (
              <Textarea
                label={t('pages.ssl.clientCa')}
                mono
                rows={6}
                value={clientCa}
                disabled={!canWrite}
                containerClassName="max-w-2xl"
                placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
                hint={t('pages.ssl.clientCaHint')}
                onChange={(e) => setClientCa(e.target.value)}
              />
            )}

            <CardError message={mtlsError} />
          </CardBody>
        </Card>
      )}

      {/* Managed CAs and client certificates (admins only — the routes are write-scoped) */}
      {canWrite && siteId !== '' && <MtlsMaterial siteId={siteId} />}

      {/* Certificates installed on this site */}
      {certsQuery.isError && !certsQuery.data ? (
        <ErrorState
          error={certsQuery.error}
          onRetry={() => certsQuery.refetch()}
          retrying={certsQuery.isFetching}
        />
      ) : (
        <Card>
          <CardHeader
            title={t('pages.ssl.certificates')}
            description={t('pages.ssl.certificatesHint')}
            action={
              <Link to="/ssl">
                <Button variant="ghost" size="sm">
                  {t('pages.ssl.openGlobalSsl')}
                </Button>
              </Link>
            }
          />
          <CardBody className="p-0">
            {certsQuery.isPending ? (
              <SkeletonRows rows={3} columns={4} />
            ) : certs.length === 0 ? (
              <EmptyState
                className="border-0 py-12"
                icon={<Certificate weight="duotone" className="h-8 w-8" />}
                title={t('pages.ssl.empty')}
                description={t('pages.ssl.emptyDescription')}
              />
            ) : (
              <Table
                columns={columns}
                data={certs}
                rowKey={(c) => c.id}
                dense
                onRowClick={(c) => setDetails(c)}
              />
            )}
            <div className="flex items-center gap-2 border-t border-line px-5 py-3 text-xs text-fg-subtle">
              <Info weight="duotone" className="h-4 w-4 shrink-0" />
              <span>{t('pages.ssl.issueElsewhereHint')}</span>
            </div>
          </CardBody>
        </Card>
      )}

      {/* Certificate details */}
      <Dialog
        open={details !== null}
        onClose={() => setDetails(null)}
        size="md"
        title={t('pages.ssl.detailsTitle')}
        footer={
          <Button variant="secondary" onClick={() => setDetails(null)}>
            {t('common.close')}
          </Button>
        }
      >
        {details && (
          <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
            <Detail label={t('pages.ssl.domain')} value={details.domain} mono />
            {details.warnings && details.warnings.length > 0 && (
              <div className="sm:col-span-2">
                <p className="text-[13px] font-medium text-fg-warning">
                  {details.warnings.length > 1
                    ? t('pages.ssl.certDomainWarnings', { count: details.warnings.length })
                    : t('pages.ssl.certDomainWarning')}
                </p>
                <ul className="mt-1 list-inside list-disc text-xs text-fg-subtle">
                  {details.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              </div>
            )}
            <Detail label={t('pages.ssl.issuer')} value={details.issuer || '—'} />
            <Detail label={t('pages.ssl.expires')} value={formatDateTime(details.expires_at)} />
            <Detail
              label={t('pages.ssl.autoRenew')}
              value={details.auto_renew ? t('common.yes') : t('common.no')}
            />
            <Detail label={t('pages.ssl.acmeEmail')} value={details.acme_email || '—'} />
            <Detail
              label={t('pages.ssl.challengeType')}
              value={(details.acme_challenge_type || '—').toUpperCase()}
            />
            <Detail label={t('pages.ssl.dnsProvider')} value={details.acme_dns_provider || '—'} />
            <Detail label={t('pages.ssl.created')} value={formatDateTime(details.created_at)} />
          </dl>
        )}
      </Dialog>

      <ConfirmDialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => pendingDelete && remove.mutate(pendingDelete.id)}
        title={t('pages.ssl.deleteTitle')}
        description={t('pages.ssl.deleteDescription')}
        confirmLabel={t('common.delete')}
        loading={remove.isPending}
      >
        {pendingDelete && (
          <div className="rounded-md border border-line bg-recessed px-3 py-2">
            <p className="pw-mono text-[13px] font-medium text-fg-strong">
              {pendingDelete.domain}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </div>
  )
}

/** Inline validation notice for a card; server errors surface as toasts. */
function CardError({ message }: { message: string | null }) {
  if (!message) return null
  return (
    <p
      role="alert"
      className="rounded-md border border-danger/40 bg-danger/8 px-3 py-2 text-[13px] text-fg-danger"
    >
      {message}
    </p>
  )
}

function Detail({
  label,
  value,
  mono,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-fg-subtle">{label}</dt>
      <dd
        className={
          mono
            ? 'pw-mono mt-0.5 truncate text-[13px] font-medium text-fg-strong'
            : 'mt-0.5 truncate text-[13px] font-medium text-fg-strong'
        }
      >
        {value}
      </dd>
    </div>
  )
}

export default SslPage
