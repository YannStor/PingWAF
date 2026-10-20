import { apiClient } from './client'
import type {
  ManagedRule,
  UpdateWafSettingsRequest,
  WafPosture,
  WafSettings,
} from './types'

/**
 * Site-level WAF grading settings — `/api/v1/sites/{siteId}/waf/settings`.
 *
 * One per-site record holding the engine switch, the advanced (strict + body
 * inspection) mode switch and the attack-category / backend-stack /
 * managed-rule monitor lists. `GET` creates the row with defaults when
 * absent; `PUT` has patch semantics.
 */
export const wafSettingsApi = {
  get: (siteId: string) =>
    apiClient.get<WafSettings>(`/sites/${siteId}/waf/settings`),

  update: (siteId: string, data: UpdateWafSettingsRequest) =>
    apiClient.put<WafSettings>(`/sites/${siteId}/waf/settings`, data),

  posture: (siteId: string) =>
    apiClient.get<WafPosture>(`/sites/${siteId}/waf/posture`),
}

/** Built-in managed rules catalogue — `/api/v1/managed-rules`. */
export const managedRulesApi = {
  list: () => apiClient.get<ManagedRule[]>('/managed-rules'),
}

/** Sensible defaults matching the server-side `find_or_create` row. */
export function defaultWafSettings(): WafSettings {
  return {
    id: '',
    site_id: '',
    waf_enabled: true,
    mode: 'off',
    paranoia_level: 2,
    advanced_mode: false,
    body_stage_timeout_secs: 30,
    monitor_categories: [],
    monitor_stacks: [],
    monitor_managed_rules: [],
    created_at: '',
    updated_at: '',
  }
}

export const wafSettingsKeys = {
  all: (siteId: string) => ['sites', siteId, 'waf-settings'] as const,
  settings: (siteId: string) =>
    ['sites', siteId, 'waf-settings', 'settings'] as const,
  posture: (siteId: string) =>
    ['sites', siteId, 'waf-settings', 'posture'] as const,
  managedRules: () => ['managed-rules'] as const,
}

export default wafSettingsApi
