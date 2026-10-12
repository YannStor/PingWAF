import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { geoEquirectangular, geoPath } from 'd3-geo'
import { feature } from 'topojson-client'
import type { Feature, FeatureCollection } from 'geojson'
import worldTopoJson from 'world-atlas/countries-110m.json'
import { COUNTRY_NAMES, countryFlag } from '@/api/geo'
import type { GeoCountryStat } from '@/api/types'
import { ISO_NUMERIC_TO_ALPHA2 } from './isoNumeric'
import { cn } from '@/lib/utils'
import { formatCompactNumber, formatNumber } from '@/lib/format'

/* The bundled world-atlas topology ships ISO 3166-1 *numeric* ids; the traffic
   stats use alpha-2 codes, so every feature is translated once up front. */
const world = feature(
  worldTopoJson as unknown as Parameters<typeof feature>[0],
  (worldTopoJson as unknown as { objects: { countries: never } }).objects
    .countries,
) as unknown as FeatureCollection

/** Heat opacity ladder over the brand colour — adapts to both themes. */
const HEAT_OPACITY = [0.18, 0.38, 0.58, 0.78, 0.95]

const MAP_WIDTH = 960
const MAP_HEIGHT = 480

interface Hover {
  x: number
  y: number
  code: string
  requests: number
}

/**
 * Choropleth of requests per country over an equirectangular world map.
 * Countries without traffic render in the recessed background colour; the
 * heat ladder is a sqrt scale so a dominant country does not flatten the
 * rest of the map into a single bucket.
 */
export function WorldMapChart({
  data,
  className,
}: {
  data: GeoCountryStat[]
  className?: string
}) {
  const { t } = useTranslation()
  const [hover, setHover] = useState<Hover | null>(null)

  const { byCode, max } = useMemo(() => {
    const byCode = new Map<string, number>()
    let max = 0
    for (const row of data) {
      if (!row.country_code) continue
      byCode.set(row.country_code.toUpperCase(), row.requests)
      max = Math.max(max, row.requests)
    }
    return { byCode, max }
  }, [data])

  const { paths, top } = useMemo(() => {
    const projection = geoEquirectangular()
    const path = geoPath(projection)
    // Fit on the land geometry implicitly: every country feature combined.
    projection.fitExtent(
      [
        [4, 4],
        [MAP_WIDTH - 4, MAP_HEIGHT - 4],
      ],
      world,
    )
    const top = [...data]
      .filter((d) => d.country_code)
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 8)
    const paths = world.features.map((f: Feature) => {
      const numericId = String(f.id ?? '')
      const code = ISO_NUMERIC_TO_ALPHA2[numericId] ?? ''
      const requests = byCode.get(code) ?? 0
      const step =
        requests > 0 && max > 0
          ? Math.min(
              HEAT_OPACITY.length - 1,
              Math.floor(
                (Math.sqrt(requests) / Math.sqrt(max)) * HEAT_OPACITY.length,
              ),
            )
          : -1
      return {
        code,
        requests,
        opacity: step >= 0 ? HEAT_OPACITY[step] : 0,
        d: path(f) ?? '',
      }
    })
    return { paths, top }
  }, [byCode, data, max])

  const nameOf = (code: string) => COUNTRY_NAMES[code] ?? code

  return (
    <div className={cn('relative', className)}>
      <div className="relative">
        <svg
          viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
          className="block h-auto w-full"
          role="img"
          aria-label={t('pages.traffic.geoMap.title')}
          onMouseLeave={() => setHover(null)}
        >
          {paths.map((p) => (
            <path
              key={p.code || p.d.slice(0, 32)}
              d={p.d}
              fill={
                p.opacity > 0 ? 'var(--color-bg-brand)' : 'var(--color-bg-recessed)'
              }
              fillOpacity={p.opacity > 0 ? p.opacity : 1}
              stroke="var(--color-border-line)"
              strokeWidth={0.5}
              className={cn(
                'transition-[fill-opacity]',
                p.requests > 0 && 'cursor-pointer hover:opacity-80',
              )}
              onMouseMove={(e) => {
                if (p.requests <= 0) {
                  setHover(null)
                  return
                }
                const rect = e.currentTarget.ownerSVGElement?.getBoundingClientRect()
                if (!rect) return
                setHover({
                  x: ((e.clientX - rect.left) / rect.width) * MAP_WIDTH,
                  y: ((e.clientY - rect.top) / rect.height) * MAP_HEIGHT,
                  code: p.code,
                  requests: p.requests,
                })
              }}
            />
          ))}
        </svg>

        {hover && (
          <div
            className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full rounded-md border border-line bg-elevated px-2.5 py-1.5 text-xs shadow-lg"
            style={{
              left: `${(hover.x / MAP_WIDTH) * 100}%`,
              top: `${(hover.y / MAP_HEIGHT) * 100 - 1.5}%`,
            }}
          >
            <span className="mr-1.5">{countryFlag(hover.code)}</span>
            <span className="font-medium text-fg-strong">
              {nameOf(hover.code)}
            </span>
            <span className="ml-2 tabular-nums text-fg-subtle">
              {formatNumber(hover.requests)}
            </span>
          </div>
        )}
      </div>

      {/* Legend + top countries */}
      <div className="mt-3 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-center gap-2 text-xs text-fg-subtle">
          <span>0</span>
          {HEAT_OPACITY.map((op) => (
            <span
              key={op}
              className="h-3 w-6 rounded-sm border border-line"
              style={{
                background: 'var(--color-bg-brand)',
                opacity: op,
              }}
            />
          ))}
          <span>{max > 0 ? formatCompactNumber(max) : '0'}</span>
        </div>
        {top.length > 0 && (
          <ol className="grid w-full max-w-md grid-cols-2 gap-x-6 gap-y-1 text-xs sm:w-auto">
            {top.map((row, i) => (
              <li key={row.country_code} className="flex items-center gap-2">
                <span className="w-4 shrink-0 text-right tabular-nums text-fg-subtle">
                  {i + 1}
                </span>
                <span className="leading-none">{countryFlag(row.country_code)}</span>
                <span className="min-w-0 flex-1 truncate text-fg">
                  {nameOf(row.country_code.toUpperCase())}
                </span>
                <span className="shrink-0 tabular-nums text-fg-subtle">
                  {formatCompactNumber(row.requests)}
                </span>
              </li>
            ))}
          </ol>
        )}
      </div>
    </div>
  )
}
