import { useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowClockwise,
  Plus,
  Trash,
  MagnifyingGlass,
  Check,
  Buildings,
  Minus,
} from '@phosphor-icons/react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { useUnsavedGuard } from '@/hooks/useUnsavedGuard'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { SkeletonStat } from '@/components/ui/Skeleton'
import { useToast } from '@/components/ui/Toast'
import { ErrorState } from '@/components/ErrorState'
import {
  geoApi,
  geoKeys,
  defaultGeoConfig,
  countriesByContinent,
  countryFlag,
  COUNTRY_NAMES,
  type CountryOption,
} from '@/api/geo'
import { useCanWrite } from '@/hooks'
import { cn } from '@/lib/utils'
import { formatCompactNumber, formatNumber } from '@/lib/format'
import {
  GEO_ACTIONS,
  GEO_MODES,
  type GeoConfig,
} from '@/api/types'

/** The geo restriction module of the site's access-control tab. */
export function GeoPanel() {
  const { t } = useTranslation()
  const toast = useToast()
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const { siteId = '' } = useParams<{ siteId: string }>()

  const [config, setConfig] = useState<GeoConfig | null>(null)
  const [dirty, setDirty] = useState(false)
  const [asnInput, setAsnInput] = useState('')

  const configQuery = useQuery({
    queryKey: geoKeys.config(siteId),
    queryFn: () => geoApi.get(siteId),
    enabled: Boolean(siteId),
  })

  const statsQuery = useQuery({
    queryKey: geoKeys.stats(siteId),
    queryFn: () => geoApi.stats(siteId),
    enabled: Boolean(siteId),
  })

  // Seed the form from the query (render-phase reset on new data / first
  // failure), so nothing flashes stale values on the first paint.
  const serverConfig = configQuery.data
  const loadFailed = configQuery.isError && Boolean(siteId)
  // `null` until the first seed: cached query data present at mount must still
  // reach the form.
  const [sync, setSync] = useState<{ config: typeof serverConfig; failed: boolean } | null>(null)
  if (!sync || sync.config !== serverConfig || sync.failed !== loadFailed) {
    setSync({ config: serverConfig, failed: loadFailed })
    if (serverConfig) {
      setConfig(serverConfig)
      setDirty(false)
    } else if (loadFailed) {
      setConfig(defaultGeoConfig(siteId))
    }
  }

  const patch = (part: Partial<GeoConfig>) => {
    setConfig((c) => (c ? { ...c, ...part } : c))
    setDirty(true)
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: geoKeys.all(siteId) })
  }

  const save = useMutation({
    mutationFn: (payload: GeoConfig) =>
      geoApi.update(siteId, {
        enabled: payload.enabled,
        mode: payload.mode,
        countries: payload.countries,
        blocked_asns: payload.blocked_asns,
        block_unknown: payload.block_unknown,
        action: payload.action,
      }),
    onSuccess: (saved) => {
      setConfig(saved)
      setDirty(false)
      toast.success(t('pages.geo.saved'))
      invalidate()
    },
  })

  const unsavedDialog = useUnsavedGuard(dirty)

  const statsData = useMemo(
    () =>
      [...(statsQuery.data ?? [])]
        .sort((a, b) => b.requests - a.requests)
        .slice(0, 10)
        .map((s) => ({
          country: `${countryFlag(s.country_code)} ${s.country_code}`,
          requests: s.requests,
        })),
    [statsQuery.data],
  )

  const addAsn = () => {
    if (!config) return
    // Stored as sent: "13335" and "AS13335" are both accepted by the edge.
    const asn = asnInput.trim().toUpperCase()
    if (!/^(AS)?\d{1,10}$/.test(asn)) {
      toast.warning(t('pages.geo.invalidAsn'))
      return
    }
    if (config.blocked_asns.includes(asn)) {
      toast.warning(t('pages.geo.duplicateAsn'))
      return
    }
    patch({ blocked_asns: [...config.blocked_asns, asn] })
    setAsnInput('')
  }

  const removeAsn = (asn: string) => {
    if (!config) return
    patch({ blocked_asns: config.blocked_asns.filter((a) => a !== asn) })
  }

  return (
    <div>
      {unsavedDialog}
      <div className="mb-4 flex items-center justify-end gap-2">
        <Button
          variant="secondary"
          loading={configQuery.isFetching}
          onClick={() => {
            configQuery.refetch()
            statsQuery.refetch()
          }}
          icon={<ArrowClockwise weight="duotone" className="h-4 w-4" />}
        >
          {t('common.refresh')}
        </Button>
        {canWrite && (
          <Button
            variant="primary"
            disabled={!dirty || save.isPending}
            loading={save.isPending}
            onClick={() => config && save.mutate(config)}
          >
            {t('common.save')}
          </Button>
        )}
      </div>

      {configQuery.isError && !config ? (
        <ErrorState
          error={configQuery.error}
          onRetry={() => configQuery.refetch()}
          retrying={configQuery.isFetching}
        />
      ) : config ? (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_360px]">
          <div className="flex flex-col gap-6">
            {/* Policy */}
            <Card>
              <CardHeader
                title={t('pages.geo.policy')}
                description={t('pages.geo.policyHint')}
                action={
                  <Badge tone={config.enabled ? 'success' : 'neutral'} dot size="sm">
                    {config.enabled ? t('common.enabled') : t('common.disabled')}
                  </Badge>
                }
              />
              <CardBody className="flex flex-col gap-5">
                <Switch
                  checked={config.enabled}
                  disabled={!canWrite}
                  onCheckedChange={(enabled) => patch({ enabled })}
                  label={t('pages.geo.enabled')}
                  description={t('pages.geo.enabledHint')}
                />
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <Select
                    label={t('pages.geo.mode')}
                    value={config.mode}
                    disabled={!canWrite}
                    options={GEO_MODES.map((m) => ({
                      value: m,
                      label: t(`geoModes.${m}`, m),
                    }))}
                    onChange={(e) => patch({ mode: e.target.value })}
                  />
                  <Select
                    label={t('pages.geo.action')}
                    value={config.action}
                    disabled={!canWrite}
                    hint={
                      config.action === 'basic_auth'
                        ? t('pages.basicAuth.ruleActionHint')
                        : t('pages.geo.actionHint')
                    }
                    options={GEO_ACTIONS.map((a) => ({
                      value: a,
                      label: t(`actions.${a}`, a),
                    }))}
                    onChange={(e) => patch({ action: e.target.value })}
                  />
                </div>
                <Switch
                  checked={config.block_unknown}
                  disabled={!canWrite}
                  onCheckedChange={(block_unknown) => patch({ block_unknown })}
                  label={t('pages.geo.blockUnknown')}
                  description={t('pages.geo.blockUnknownHint')}
                />
              </CardBody>
            </Card>

            {/* Countries */}
            <Card>
              <CardHeader
                title={t('pages.geo.countries')}
                description={
                  config.mode === 'allow_list'
                    ? t('pages.geo.countriesAllowHint')
                    : t('pages.geo.countriesBlockHint')
                }
                action={
                  <Badge tone={config.countries.length ? 'brand' : 'neutral'} size="sm">
                    {t('pages.geo.selected', { count: config.countries.length })}
                  </Badge>
                }
              />
              <CardBody>
                <CountryPicker
                  selected={config.countries}
                  disabled={!canWrite}
                  onChange={(countries) => patch({ countries })}
                />
              </CardBody>
            </Card>

            {/* ASNs */}
            <Card>
              <CardHeader
                title={t('pages.geo.blockedAsns')}
                description={t('pages.geo.blockedAsnsHint')}
                action={
                  <span className="flex items-center gap-1.5 text-xs text-fg-subtle">
                    <Buildings weight="duotone" className="h-4 w-4" />
                    {config.blocked_asns.length}
                  </span>
                }
              />
              <CardBody className="flex flex-col gap-4">
                {canWrite && (
                  <div className="flex flex-wrap items-end gap-2">
                    <Input
                      label={t('pages.geo.asn')}
                      value={asnInput}
                      placeholder="AS13335"
                      containerClassName="w-40"
                      hint={t('pages.geo.asnHint')}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault()
                          addAsn()
                        }
                      }}
                      onChange={(e) => setAsnInput(e.target.value)}
                    />
                    <Button
                      variant="secondary"
                      icon={<Plus weight="bold" className="h-4 w-4" />}
                      onClick={addAsn}
                    >
                      {t('common.add')}
                    </Button>
                  </div>
                )}
                {config.blocked_asns.length === 0 ? (
                  <p className="py-4 text-center text-sm text-fg-subtle">
                    {t('pages.geo.noAsns')}
                  </p>
                ) : (
                  <ul className="flex flex-wrap gap-1.5">
                    {config.blocked_asns.map((asn) => (
                      <li
                        key={asn}
                        className="inline-flex items-center gap-1.5 rounded-full border border-line bg-recessed/40 px-2.5 py-1"
                      >
                        <span className="pw-mono text-[13px] font-medium text-fg-strong">
                          {asn.startsWith('AS') ? asn : `AS${asn}`}
                        </span>
                        {canWrite && (
                          <button
                            type="button"
                            aria-label={`${t('common.delete')} ${asn}`}
                            onClick={() => removeAsn(asn)}
                            className="text-fg-subtle hover:text-fg-danger"
                          >
                            <Trash weight="bold" className="h-3 w-3" />
                          </button>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </CardBody>
            </Card>
          </div>

          {/* Stats sidebar */}
          <div className="flex flex-col gap-6">
            <Card>
              <CardHeader title={t('pages.geo.byCountry')} />
              <CardBody>
                {statsQuery.isPending ? (
                  <SkeletonStat />
                ) : statsData.length === 0 ? (
                  <p className="py-8 text-center text-sm text-fg-subtle">{t('common.noData')}</p>
                ) : (
                  <div className="h-80 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={statsData}
                        layout="vertical"
                        margin={{ top: 4, right: 16, left: 8, bottom: 0 }}
                      >
                        <CartesianGrid
                          strokeDasharray="3 3"
                          stroke="var(--color-border-line)"
                          horizontal={false}
                        />
                        <XAxis
                          type="number"
                          tick={{ fontSize: 11, fill: 'var(--color-text-subtle)' }}
                          tickLine={false}
                          axisLine={false}
                          tickFormatter={(v: number) => formatCompactNumber(v)}
                        />
                        <YAxis
                          type="category"
                          dataKey="country"
                          width={70}
                          tick={{ fontSize: 12, fill: 'var(--color-text-default)' }}
                          tickLine={false}
                          axisLine={false}
                        />
                        <Tooltip
                          contentStyle={{
                            background: 'var(--color-bg-elevated)',
                            border: '1px solid var(--color-border-line)',
                            borderRadius: 8,
                            fontSize: 12,
                            color: 'var(--color-text-default)',
                          }}
                          formatter={(v) => formatNumber(Number(v ?? 0))}
                          cursor={{ fill: 'var(--color-bg-recessed)' }}
                        />
                        <Bar
                          dataKey="requests"
                          name={t('pages.traffic.requests')}
                          fill="#f6821f"
                          radius={[0, 4, 4, 0]}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardBody>
            </Card>
          </div>
        </div>
      ) : null}
    </div>
  )
}

/**
 * Searchable, continent-grouped country multi-select.
 *
 * The full ISO list is long, so a search box plus grouped checkboxes beats a
 * native select — operators can type "ger" or scan Europe quickly.
 */
function CountryPicker({
  selected,
  onChange,
  disabled,
}: {
  selected: string[]
  onChange: (codes: string[]) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')

  const grouped = useMemo(() => {
    const q = query.trim().toLowerCase()
    return countriesByContinent()
      .map((g) => ({
        continent: g.continent,
        countries: g.countries.filter(
          (c) =>
            !q ||
            c.name.toLowerCase().includes(q) ||
            c.code.toLowerCase().includes(q),
        ),
      }))
      .filter((g) => g.countries.length > 0)
  }, [query])

  const toggle = (code: string) => {
    if (disabled) return
    onChange(
      selected.includes(code)
        ? selected.filter((c) => c !== code)
        : [...selected, code],
    )
  }

  /** Selects or clears every country of one continent — the filtered ones when searching. */
  const toggleContinent = (codes: string[], allSelected: boolean) => {
    if (disabled) return
    if (allSelected) {
      onChange(selected.filter((c) => !codes.includes(c)))
      return
    }
    const next = new Set(selected)
    codes.forEach((c) => next.add(c))
    onChange([...next])
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="relative">
        <MagnifyingGlass
          weight="duotone"
          className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle"
        />
        <input
          value={query}
          disabled={disabled}
          placeholder={t('pages.geo.searchCountries')}
          onChange={(e) => setQuery(e.target.value)}
          className="h-9 w-full rounded-md border border-line bg-elevated pl-9 pr-3 text-sm text-fg placeholder:text-fg-subtle/60 focus:border-focus focus:outline-none focus:ring-2 focus:ring-focus/25 disabled:cursor-not-allowed disabled:opacity-60"
        />
      </div>
      <div className="max-h-80 overflow-y-auto rounded-md border border-line">
        {grouped.length === 0 ? (
          <p className="py-6 text-center text-sm text-fg-subtle">
            {t('pages.geo.noCountriesFound')}
          </p>
        ) : (
          grouped.map((group) => {
            const codes = group.countries.map((c) => c.code)
            const selectedCount = codes.filter((c) => selected.includes(c)).length
            const allSelected = selectedCount === codes.length
            return (
            <div key={group.continent}>
              <div className="sticky top-0 z-10 flex items-center justify-between gap-2 bg-recessed px-3 py-1.5">
                <span className="text-[11px] font-semibold uppercase tracking-wide text-fg-subtle">
                  {t(`continents.${group.continent}`, group.continent)}
                  <span className="ml-1.5 font-normal normal-case tabular-nums text-fg-subtle/70">
                    {selectedCount}/{codes.length}
                  </span>
                </span>
                <button
                  type="button"
                  disabled={disabled}
                  aria-label={
                    allSelected
                      ? t('pages.geo.clearContinent', { continent: t(`continents.${group.continent}`, group.continent) })
                      : t('pages.geo.selectContinent', { continent: t(`continents.${group.continent}`, group.continent) })
                  }
                  onClick={() => toggleContinent(codes, allSelected)}
                  className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium text-link transition-colors hover:bg-elevated disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {allSelected ? (
                    <Minus weight="bold" className="h-3 w-3" />
                  ) : (
                    <Check weight="bold" className="h-3 w-3" />
                  )}
                  {allSelected ? t('pages.geo.clearContinentShort') : t('pages.geo.selectContinentShort')}
                </button>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2">
                {group.countries.map((c) => (
                  <CountryRow
                    key={c.code}
                    country={c}
                    selected={selected.includes(c.code)}
                    disabled={disabled}
                    onToggle={() => toggle(c.code)}
                  />
                ))}
              </div>
            </div>
            )
          })
        )}
      </div>
      {selected.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {selected.map((code) => (
            <span
              key={code}
              className="inline-flex items-center gap-1 rounded-full border border-brand/30 bg-brand/10 px-2 py-0.5 text-xs text-brand"
            >
              {countryFlag(code)} {COUNTRY_NAMES[code] ?? code}
              {!disabled && (
                <button
                  type="button"
                  aria-label={`${t('common.delete')} ${code}`}
                  onClick={() => toggle(code)}
                  className="text-brand/70 hover:text-brand"
                >
                  <Trash weight="bold" className="h-3 w-3" />
                </button>
              )}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

function CountryRow({
  country,
  selected,
  disabled,
  onToggle,
}: {
  country: CountryOption
  selected: boolean
  disabled?: boolean
  onToggle: () => void
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={selected}
      disabled={disabled}
      onClick={onToggle}
      className={cn(
        'flex items-center gap-2 px-3 py-1.5 text-left text-[13px] transition-colors disabled:cursor-not-allowed disabled:opacity-60',
        selected ? 'bg-brand-soft/60 text-fg-strong' : 'hover:bg-recessed text-fg',
      )}
    >
      <span
        className={cn(
          'flex h-4 w-4 shrink-0 items-center justify-center rounded border',
          selected ? 'border-brand bg-brand text-white' : 'border-fill',
        )}
      >
        {selected && <Check weight="bold" className="h-3 w-3" />}
      </span>
      <span className="text-base leading-none">{countryFlag(country.code)}</span>
      <span className="truncate">{country.name}</span>
    </button>
  )
}

export default GeoPanel
