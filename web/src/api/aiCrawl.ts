import { apiClient } from './client'
import { RANGE_HOURS } from './traffic'
import type {
  AiBotCatalogEntry,
  AiCrawlPreview,
  AiCrawlSettings,
  AiCrawlerOverview,
  TrafficRange,
  UpdateAiCrawlSettingsRequest,
} from './types'

/** Ranges the analytics endpoint understands; narrower presets widen to 24h. */
export type AiCrawlAnalyticsRange = '24h' | '7d' | '30d'

export function aiCrawlRangeFor(range: TrafficRange): AiCrawlAnalyticsRange {
  const hours = RANGE_HOURS[range]
  if (hours <= 24) return '24h'
  if (hours <= 24 * 7) return '7d'
  return '30d'
}

/**
 * AI crawl control.
 *
 * `/ai-crawl/catalog` is deployment-wide static data — cache it long.
 * The per-site settings live under `/sites/{siteId}/ai-crawl` and save with a
 * single PUT whose `policies` array replaces the stored overrides wholesale.
 */
export const aiCrawlApi = {
  catalog: () => apiClient.get<AiBotCatalogEntry[]>('/ai-crawl/catalog'),

  get: (siteId: string) => apiClient.get<AiCrawlSettings>(`/sites/${siteId}/ai-crawl`),

  update: (siteId: string, data: UpdateAiCrawlSettingsRequest) =>
    apiClient.put<AiCrawlSettings>(`/sites/${siteId}/ai-crawl`, data),

  preview: (siteId: string, file: 'robots' | 'llms') =>
    apiClient.get<AiCrawlPreview>(`/sites/${siteId}/ai-crawl/preview`, {
      query: { file },
    }),

  aiCrawlerOverview: (siteId?: string, range: TrafficRange = '24h') =>
    apiClient.get<AiCrawlerOverview>('/analytics/ai-crawlers', {
      query: {
        ...(siteId ? { site_id: siteId } : {}),
        range: aiCrawlRangeFor(range),
        limit: 20,
      },
    }),
}

/** Body editor hard limit mirrored from the control plane. */
export const AI_CRAWL_MAX_BODY_BYTES = 64 * 1024
/** Bounds mirrored from the control plane. */
export const AI_CRAWL_MAX_CACHE_AGE = 86400

export function aiCrawlBodyTooLong(body: string): boolean {
  return new TextEncoder().encode(body).byteLength > AI_CRAWL_MAX_BODY_BYTES
}

export const aiCrawlKeys = {
  all: ['ai-crawl'] as const,
  catalog: () => ['ai-crawl', 'catalog'] as const,
  settings: (siteId: string) => ['sites', siteId, 'ai-crawl'] as const,
  preview: (siteId: string, file: 'robots' | 'llms') =>
    ['sites', siteId, 'ai-crawl', 'preview', file] as const,
  aiBots: (siteId?: string, range: TrafficRange = '24h') =>
    ['analytics', 'ai-crawlers', siteId ?? 'all', aiCrawlRangeFor(range)] as const,
}

export default aiCrawlApi
