import { apiClient } from './client'
import type {
  EsConfig,
  EsSettingsView,
  EsTestResult,
  GlobalCacheSettings,
  LogRetentionSettings,
  UpdateGlobalCacheSettingsRequest,
  UpdateLogRetentionRequest,
} from './types'

/** The placeholder the server substitutes for `password` / `api_key`. */
export const SECRET_MASK = '***'

/** A configuration shape safe to submit: masked secrets become `null`. */
export type EsConfigDraft = Omit<EsConfig, 'password' | 'api_key'> & {
  password: string | null
  api_key: string | null
}

/**
 * Elasticsearch settings — `/api/v1/settings/elasticsearch` (administrators only).
 *
 * The stored configuration lives in the server's config file; `PUT` validates
 * and probes the submitted shape and reports whether a restart is needed to
 * apply it. `POST …/test` without a body probes the *live* shipper, which is the
 * only way to re-check credentials that the API redacts.
 */
export const settingsApi = {
  getElasticsearch: () => apiClient.get<EsSettingsView>('/settings/elasticsearch'),

  saveElasticsearch: (config: EsConfigDraft) =>
    apiClient.put<EsSettingsView>('/settings/elasticsearch', config),

  /** Probes an arbitrary configuration (used by the form's Test button). */
  testElasticsearch: (config: EsConfigDraft) =>
    apiClient.post<EsTestResult>('/settings/elasticsearch/test', config),

  /** Probes the running shipper / stored config — no secrets required. */
  testLive: () => apiClient.post<EsTestResult>('/settings/elasticsearch/test'),

  /**
   * PostgreSQL log retention — `/api/v1/settings/log-retention` (administrators
   * only). How long the two log tables are kept; the background sweeper reads
   * this row every six hours. Elasticsearch keeps its own fixed 360-day window.
   */
  getLogRetention: () => apiClient.get<LogRetentionSettings>('/settings/log-retention'),

  saveLogRetention: (windows: UpdateLogRetentionRequest) =>
    apiClient.put<LogRetentionSettings>('/settings/log-retention', windows),

  /**
   * Cache ceiling — `/api/v1/settings/cache` (administrators only). The
   * largest single cacheable object, the total disk budget, the master
   * switch and the fallback edge TTL; everything rides inside each rule
   * bundle, so a save reaches the edges with the next push.
   */
  getCache: () => apiClient.get<GlobalCacheSettings>('/settings/cache'),

  saveCache: (payload: UpdateGlobalCacheSettingsRequest) =>
    apiClient.put<GlobalCacheSettings>('/settings/cache', payload),
}

/** Drops `***` placeholders so a save never overwrites a real secret with a mask. */
export function stripMaskedSecrets(config: EsConfig): EsConfigDraft {
  return {
    ...config,
    password: config.password === SECRET_MASK ? null : config.password,
    api_key: config.api_key === SECRET_MASK ? null : config.api_key,
  }
}

/** Blank form state matching the server-side `EsConfig::default()`. */
export function defaultEsConfig(): EsConfigDraft {
  return {
    urls: [],
    index_prefix: 'pingwaf',
    username: null,
    password: null,
    api_key: null,
    bulk_max_size: 1000,
    bulk_flush_interval_ms: 5000,
    max_body_size: 8192,
    enabled: false,
    buffer_dir: null,
    buffer_max_size_mb: 512,
    channel_capacity: 65536,
    request_timeout_secs: 30,
  }
}

export const settingsKeys = {
  all: ['settings'] as const,
  elasticsearch: () => [...settingsKeys.all, 'elasticsearch'] as const,
  logRetention: () => [...settingsKeys.all, 'log-retention'] as const,
  cache: () => [...settingsKeys.all, 'cache'] as const,
}

export default settingsApi
