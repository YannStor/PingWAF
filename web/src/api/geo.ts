import { apiClient } from './client'
import type { GeoConfig, GeoCountryStat, UpdateGeoRequest } from './types'

/**
 * Geo restrictions — `/api/v1/sites/{siteId}/geo`.
 *
 * Either deny a blocklist of countries (`mode: block_list`) or deny everything
 * except an allowlist (`mode: allow_list`). Matched traffic is subjected to
 * `action`. A list of ASNs can be denied independently of country. The whole
 * policy is inert until `enabled` is switched on.
 */
export const geoApi = {
  get: (siteId: string) => apiClient.get<GeoConfig>(`/sites/${siteId}/geo`),

  update: (siteId: string, data: UpdateGeoRequest) =>
    apiClient.put<GeoConfig>(`/sites/${siteId}/geo`, data),

  /** Requests per country over the trailing window, for the bar chart. */
  stats: (siteId: string) =>
    apiClient.get<GeoCountryStat[]>(`/sites/${siteId}/geo/stats`),

  /**
   * Requests per country aggregated across every visible site (admin: all,
   * tenant: owned) — drives the world map on the traffic pages.
   */
  globalStats: (params?: { hours?: number; limit?: number }) => {
    const qs = new URLSearchParams()
    if (params?.hours) qs.set('hours', String(params.hours))
    if (params?.limit) qs.set('limit', String(params.limit))
    const suffix = qs.size > 0 ? `?${qs.toString()}` : ''
    return apiClient.get<GeoCountryStat[]>(`/geo/global-stats${suffix}`)
  },
}

/** Defaults matching the server-side `GeoConfig::default()`. */
export function defaultGeoConfig(siteId: string): GeoConfig {
  return {
    site_id: siteId,
    enabled: false,
    mode: 'block_list',
    countries: [],
    blocked_asns: [],
    block_unknown: false,
    action: 'block',
  }
}

/* ────────────────────────────────────────────────────────────────
   Country reference (ISO 3166-1 alpha-2), grouped by continent
   ──────────────────────────────────────────────────────────────── */

export interface CountryOption {
  code: string
  name: string
  continent: string
}

export const CONTINENTS = [
  'Africa',
  'Asia',
  'Europe',
  'North America',
  'South America',
  'Oceania',
] as const

/** A curated country list — enough for real geo policies without a full dump. */
export const COUNTRIES: CountryOption[] = [
  // Africa
  { code: 'DZ', name: 'Algeria', continent: 'Africa' },
  { code: 'EG', name: 'Egypt', continent: 'Africa' },
  { code: 'ET', name: 'Ethiopia', continent: 'Africa' },
  { code: 'GH', name: 'Ghana', continent: 'Africa' },
  { code: 'KE', name: 'Kenya', continent: 'Africa' },
  { code: 'MA', name: 'Morocco', continent: 'Africa' },
  { code: 'NG', name: 'Nigeria', continent: 'Africa' },
  { code: 'ZA', name: 'South Africa', continent: 'Africa' },
  { code: 'TZ', name: 'Tanzania', continent: 'Africa' },
  { code: 'UG', name: 'Uganda', continent: 'Africa' },
  // Asia
  { code: 'BD', name: 'Bangladesh', continent: 'Asia' },
  { code: 'KH', name: 'Cambodia', continent: 'Asia' },
  { code: 'CN', name: 'China', continent: 'Asia' },
  { code: 'HK', name: 'Hong Kong', continent: 'Asia' },
  { code: 'IN', name: 'India', continent: 'Asia' },
  { code: 'ID', name: 'Indonesia', continent: 'Asia' },
  { code: 'IR', name: 'Iran', continent: 'Asia' },
  { code: 'IQ', name: 'Iraq', continent: 'Asia' },
  { code: 'IL', name: 'Israel', continent: 'Asia' },
  { code: 'JP', name: 'Japan', continent: 'Asia' },
  { code: 'JO', name: 'Jordan', continent: 'Asia' },
  { code: 'KZ', name: 'Kazakhstan', continent: 'Asia' },
  { code: 'KP', name: 'North Korea', continent: 'Asia' },
  { code: 'KR', name: 'South Korea', continent: 'Asia' },
  { code: 'KW', name: 'Kuwait', continent: 'Asia' },
  { code: 'LB', name: 'Lebanon', continent: 'Asia' },
  { code: 'MY', name: 'Malaysia', continent: 'Asia' },
  { code: 'MM', name: 'Myanmar', continent: 'Asia' },
  { code: 'NP', name: 'Nepal', continent: 'Asia' },
  { code: 'OM', name: 'Oman', continent: 'Asia' },
  { code: 'PK', name: 'Pakistan', continent: 'Asia' },
  { code: 'PH', name: 'Philippines', continent: 'Asia' },
  { code: 'QA', name: 'Qatar', continent: 'Asia' },
  { code: 'SA', name: 'Saudi Arabia', continent: 'Asia' },
  { code: 'SG', name: 'Singapore', continent: 'Asia' },
  { code: 'LK', name: 'Sri Lanka', continent: 'Asia' },
  { code: 'SY', name: 'Syria', continent: 'Asia' },
  { code: 'TW', name: 'Taiwan', continent: 'Asia' },
  { code: 'TH', name: 'Thailand', continent: 'Asia' },
  { code: 'TR', name: 'Türkiye', continent: 'Asia' },
  { code: 'AE', name: 'United Arab Emirates', continent: 'Asia' },
  { code: 'UZ', name: 'Uzbekistan', continent: 'Asia' },
  { code: 'VN', name: 'Vietnam', continent: 'Asia' },
  { code: 'YE', name: 'Yemen', continent: 'Asia' },
  // Europe
  { code: 'AL', name: 'Albania', continent: 'Europe' },
  { code: 'AT', name: 'Austria', continent: 'Europe' },
  { code: 'BY', name: 'Belarus', continent: 'Europe' },
  { code: 'BE', name: 'Belgium', continent: 'Europe' },
  { code: 'BA', name: 'Bosnia and Herzegovina', continent: 'Europe' },
  { code: 'BG', name: 'Bulgaria', continent: 'Europe' },
  { code: 'HR', name: 'Croatia', continent: 'Europe' },
  { code: 'CY', name: 'Cyprus', continent: 'Europe' },
  { code: 'CZ', name: 'Czechia', continent: 'Europe' },
  { code: 'DK', name: 'Denmark', continent: 'Europe' },
  { code: 'EE', name: 'Estonia', continent: 'Europe' },
  { code: 'FI', name: 'Finland', continent: 'Europe' },
  { code: 'FR', name: 'France', continent: 'Europe' },
  { code: 'DE', name: 'Germany', continent: 'Europe' },
  { code: 'GR', name: 'Greece', continent: 'Europe' },
  { code: 'HU', name: 'Hungary', continent: 'Europe' },
  { code: 'IS', name: 'Iceland', continent: 'Europe' },
  { code: 'IE', name: 'Ireland', continent: 'Europe' },
  { code: 'IT', name: 'Italy', continent: 'Europe' },
  { code: 'XK', name: 'Kosovo', continent: 'Europe' },
  { code: 'LV', name: 'Latvia', continent: 'Europe' },
  { code: 'LT', name: 'Lithuania', continent: 'Europe' },
  { code: 'LU', name: 'Luxembourg', continent: 'Europe' },
  { code: 'MT', name: 'Malta', continent: 'Europe' },
  { code: 'MD', name: 'Moldova', continent: 'Europe' },
  { code: 'ME', name: 'Montenegro', continent: 'Europe' },
  { code: 'NL', name: 'Netherlands', continent: 'Europe' },
  { code: 'MK', name: 'North Macedonia', continent: 'Europe' },
  { code: 'NO', name: 'Norway', continent: 'Europe' },
  { code: 'PL', name: 'Poland', continent: 'Europe' },
  { code: 'PT', name: 'Portugal', continent: 'Europe' },
  { code: 'RO', name: 'Romania', continent: 'Europe' },
  { code: 'RU', name: 'Russia', continent: 'Europe' },
  { code: 'RS', name: 'Serbia', continent: 'Europe' },
  { code: 'SK', name: 'Slovakia', continent: 'Europe' },
  { code: 'SI', name: 'Slovenia', continent: 'Europe' },
  { code: 'ES', name: 'Spain', continent: 'Europe' },
  { code: 'SE', name: 'Sweden', continent: 'Europe' },
  { code: 'CH', name: 'Switzerland', continent: 'Europe' },
  { code: 'UA', name: 'Ukraine', continent: 'Europe' },
  { code: 'GB', name: 'United Kingdom', continent: 'Europe' },
  // North America
  { code: 'CA', name: 'Canada', continent: 'North America' },
  { code: 'CR', name: 'Costa Rica', continent: 'North America' },
  { code: 'CU', name: 'Cuba', continent: 'North America' },
  { code: 'DO', name: 'Dominican Republic', continent: 'North America' },
  { code: 'SV', name: 'El Salvador', continent: 'North America' },
  { code: 'GT', name: 'Guatemala', continent: 'North America' },
  { code: 'HT', name: 'Haiti', continent: 'North America' },
  { code: 'HN', name: 'Honduras', continent: 'North America' },
  { code: 'JM', name: 'Jamaica', continent: 'North America' },
  { code: 'MX', name: 'Mexico', continent: 'North America' },
  { code: 'NI', name: 'Nicaragua', continent: 'North America' },
  { code: 'PA', name: 'Panama', continent: 'North America' },
  { code: 'PR', name: 'Puerto Rico', continent: 'North America' },
  { code: 'TT', name: 'Trinidad and Tobago', continent: 'North America' },
  { code: 'US', name: 'United States', continent: 'North America' },
  // South America
  { code: 'AR', name: 'Argentina', continent: 'South America' },
  { code: 'BO', name: 'Bolivia', continent: 'South America' },
  { code: 'BR', name: 'Brazil', continent: 'South America' },
  { code: 'CL', name: 'Chile', continent: 'South America' },
  { code: 'CO', name: 'Colombia', continent: 'South America' },
  { code: 'EC', name: 'Ecuador', continent: 'South America' },
  { code: 'GY', name: 'Guyana', continent: 'South America' },
  { code: 'PY', name: 'Paraguay', continent: 'South America' },
  { code: 'PE', name: 'Peru', continent: 'South America' },
  { code: 'SR', name: 'Suriname', continent: 'South America' },
  { code: 'UY', name: 'Uruguay', continent: 'South America' },
  { code: 'VE', name: 'Venezuela', continent: 'South America' },
  // Oceania
  { code: 'AU', name: 'Australia', continent: 'Oceania' },
  { code: 'FJ', name: 'Fiji', continent: 'Oceania' },
  { code: 'NZ', name: 'New Zealand', continent: 'Oceania' },
  { code: 'PG', name: 'Papua New Guinea', continent: 'Oceania' },
  { code: 'WS', name: 'Samoa', continent: 'Oceania' },
]

/** Lookup table: ISO code → country name. */
export const COUNTRY_NAMES: Record<string, string> = Object.fromEntries(
  COUNTRIES.map((c) => [c.code, c.name]),
)

/** Countries grouped by continent, preserving the {@link CONTINENTS} order. */
export function countriesByContinent(): { continent: string; countries: CountryOption[] }[] {
  return CONTINENTS.map((continent) => ({
    continent,
    countries: COUNTRIES.filter((c) => c.continent === continent),
  }))
}

/**
 * Renders a country code as a flag emoji using regional-indicator symbols.
 * Falls back to the upper-cased code for non-ISO inputs.
 */
export function countryFlag(code: string): string {
  const upper = code.trim().toUpperCase()
  if (!/^[A-Z]{2}$/.test(upper)) return upper || '🏳'
  return String.fromCodePoint(
    ...upper.split('').map((ch) => 0x1f1e6 - 65 + ch.charCodeAt(0)),
  )
}

export const geoKeys = {
  all: (siteId: string) => ['sites', siteId, 'geo'] as const,
  config: (siteId: string) => ['sites', siteId, 'geo', 'config'] as const,
  stats: (siteId: string) => ['sites', siteId, 'geo', 'stats'] as const,
  globalStats: (hours: number) => ['geo', 'global-stats', hours] as const,
}

export default geoApi
