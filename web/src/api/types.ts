/**
 * Wire types for the PingWAF control-plane REST API (`/api/v1`).
 *
 * Everything mirrors the Rust `serde` structs in `pingwaf-server/src/api/*`
 * exactly — field names are `snake_case` and enum-ish values are the short
 * lowercase strings persisted in PostgreSQL (`block`, `active`, `online`, …).
 */

/* ── Shared envelopes ─────────────────────────────────────────────── */

/** `api::common::Page<T>` — the envelope every list endpoint returns. */
export interface Page<T> {
  items: T[]
  total: number
  /** True when `total` is a lower bound — the log listings cap their count. */
  total_truncated?: boolean
  page: number
  page_size: number
}

/** `api::common::Pagination` query parameters. */
export interface PaginationQuery {
  page?: number
  page_size?: number
}

/* ── Auth ─────────────────────────────────────────────────────────── */

export type UserRole = 'admin' | 'auditor' | 'viewer'

/** `api::auth::UserResponse` */
export interface User {
  id: string
  email: string
  name: string | null
  role: UserRole | string
  /** First sign-in gate: the account must replace its password. */
  must_change_password: boolean
  /** Disabled accounts cannot sign in (admin user list only). */
  disabled: boolean
  created_at: string
  updated_at: string
  /** Most recent successful login (admin list only); absent when never. */
  last_login_at?: string
  last_login_ip?: string
}

export interface LoginRequest {
  email: string
  password: string
}

export interface RegisterRequest {
  email: string
  password: string
  name?: string
}

/** `api::auth::TokenResponse` */
export interface LoginResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user: User
}

/** `api::auth::AuthStatus` */
export interface AuthStatus {
  needs_setup: boolean
  registration_open: boolean
  /** Whether the login form should offer a passkey. */
  passkey_enabled: boolean
}

/** `api::passkeys::PasskeySummary` */
export interface PasskeySummary {
  id: string
  name: string
  created_at: string
  last_used_at: string
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

/** `api::users::CreateUserRequest` */
export interface CreateUserRequest {
  email: string
  password: string
  name?: string
  role?: string
}

/** `api::users::UpdateUserRequest` */
export interface UpdateUserRequest {
  name?: string
  email?: string
  role?: string
  disabled?: boolean
}

export interface UpdateProfileRequest {
  name?: string | null
  /** Changing the login name requires the current password. */
  email?: string
  current_password?: string
}

/* ── Sites ────────────────────────────────────────────────────────── */

export type SiteStatus = 'active' | 'paused' | 'pending'

/** `api::sites::SiteResponse` */
export interface Site {
  id: string
  name: string
  /** Primary hostname; certificate issuance and display default to it. */
  domain: string
  /** Extra hostnames served by the same site configuration. */
  alternate_domains: string[]
  status: SiteStatus | string
  plan: string
  /** Disk budget, in MiB, the agents may use for this site's cache. */
  cache_quota_mb: number
  /**
   * Site-level single-file cache cap in MiB (managed through the CacheSettings
   * panel); `null` follows the global ceiling.
   */
  cache_max_file_size_mb?: number | null
  /**
   * Per-content-type single-file caps in MiB (managed through the CacheSettings
   * panel), keyed `html/css/js/image/font/media/other`; missing keys follow
   * `cache_max_file_size_mb`.
   */
  cache_type_limits_mb?: Record<string, number> | null
  /** Site sits behind a CDN/proxy: derive the client IP from `trusted_header`. */
  trust_proxy_headers: boolean
  /** Forwarded header trusted when `trust_proxy_headers` is on. */
  trusted_header: string
  /** Trust only the most recent hop of `x-forwarded-for`. */
  trust_last_hop: boolean
  /** CIDR ranges whose direct peers may set the forwarded header. */
  trusted_proxy_ranges: string[]
  /** IP groups whose ranges merge into the trusted-proxy scope. */
  trusted_proxy_group_ids: string[]
  /**
   * Site-wide origin certificate check: `null` means every pool without
   * its own pin follows the deployment-wide `origin_settings.verify_cert`.
   */
  origin_verify_cert: boolean | null
  /**
   * Response body replacement policy; `null` when the site replaces nothing.
   */
  response_replace: ResponseReplaceConfig | null
  user_id: string
  created_at: string
  updated_at: string
}

/** `models::sites::site_upstreams::Model` */
export interface Upstream {
  id: string
  site_id: string
  pool_id: string
  address: string
  weight: number
  tls: boolean
  health_status: string
  created_at: string
}

/** `models::sites::site_upstream_pools::Model` */
export interface UpstreamPool {
  id: string
  site_id: string
  name: string
  /** `round_robin` or `hash:<type>[:<key>]`. */
  lb_algorithm: string
  /** Non-empty SNI enables HTTPS origin; `null` means plain HTTP. */
  sni: string | null
  /**
   * `null` means the pool has no opinion and follows the deployment-wide
   * `origin_settings.verify_cert`; `true`/`false` pin it.
   */
  verify_cert: boolean | null
  /** Active HTTP health check; off keeps the agent's default TCP probe. */
  health_check_enabled: boolean
  /** Probe path; always starts with `/`. */
  health_check_path: string
  /** Seconds between probe rounds (aligned to 10s grid steps by the agent). */
  health_check_interval_seconds: number
  /** Probe connect/read timeout in milliseconds. */
  health_check_timeout_ms: number
  /** Consecutive failed probes before a node is marked unhealthy. */
  health_check_unhealthy_threshold: number
  /** Consecutive successful probes before a node is marked healthy. */
  health_check_healthy_threshold: number
  /**
   * Address family the agent may resolve this pool's origin names to:
   * `auto` prefers IPv4, `ipv4`/`ipv6` pin one family. An IP literal origin
   * ignores it. Mirrors the DB CHECK constraint (`auto|ipv4|ipv6`).
   */
  address_family: 'auto' | 'ipv4' | 'ipv6' | string
  is_default: boolean
  created_at: string
  /**
   * Members inlined by `GET /sites/{id}/upstream-pools` (the list endpoints
   * embed each pool's nodes). Absent from create/update responses.
   */
  upstreams?: Upstream[]
}

/** `models::sites::site_routes::Model` */
export interface Route {
  id: string
  site_id: string
  name: string
  match_type: 'prefix' | 'exact' | 'regex' | string
  path: string
  priority: number | null
  enabled: boolean
  pool_id: string
  /** When set, the route only matches clients inside this IP group. */
  ip_group_id: string | null
  /** Strip the matched `path` prefix before proxying (prefix match only). */
  strip_prefix?: boolean
  /** When set, replaces the upstream path entirely; wins over `strip_prefix`. */
  rewrite_path?: string | null
  /**
   * Bare host name overriding the origin request's `Host` header;
   * `null`/absent follows the client's Host.
   */
  upstream_host?: string | null
  created_at: string
}

/** `api::sites::SslResponse` — never carries the private key. */
export interface SslConfig {
  id: string
  site_id: string
  domain: string
  issuer: string | null
  has_certificate: boolean
  has_private_key: boolean
  expires_at: string | null
  auto_renew: boolean
  acme_email: string | null
  acme_challenge_type: string | null
  acme_dns_provider: string | null
  acme_dns_config: unknown | null
  /* ── TLS posture (read-write symmetric with `PUT /sites/{id}/ssl`) ── */
  https_enabled: boolean
  min_tls_version: TlsVersion | string
  max_tls_version: TlsVersion | string | null
  self_signed: boolean
  certificate_id: string | null
  mtls_enabled: boolean
  has_mtls_client_ca: boolean
  mtls_organization: string | null
  mtls_require_client_cert: boolean
  hsts_enabled: boolean
  hsts_max_age: number
  always_use_https: boolean
  /** Serve HTTP/1.1 alongside HTTP/2 (default true). */
  http1_enabled: boolean
  /** Serve HTTP/2; multiplexes requests over one connection (default true). */
  http2_enabled: boolean
  created_at: string
}

/** `api::sites::SiteDetail` */
export interface SiteDetail {
  site: Site
  upstreams: Upstream[]
  ssl: SslConfig | null
  rule_count: number
  rule_group_count: number
  rate_limit_count: number
  cache_rule_count: number
}

export interface CreateSiteRequest {
  name: string
  domain: string
  /** Extra hostnames (wildcards allowed) the site also answers on. */
  alternate_domains?: string[]
  /**
   * Origin the site proxies to — a CDN/WAF hostname or the application itself.
   * Required: a site without an origin cannot serve traffic.
   */
  upstream_address: string
  upstream_tls?: boolean
  status?: string
  plan?: string
}

/** `POST /sites/{site_id}/clone` — duplicate a site under a new primary domain. */
export interface CloneSiteRequest {
  /** New primary hostname; must not collide with any existing site. */
  domain: string
  /** Extra hostnames for the clone (wildcards allowed). */
  alternate_domains?: string[]
  /** Display name; the server falls back to the source site's name when omitted. */
  name?: string
}

export interface UpdateSiteRequest {
  name?: string
  domain?: string
  /** Replaces the whole list; an empty array clears it. */
  alternate_domains?: string[]
  status?: string
  plan?: string
  /** Site sits behind a CDN/proxy: derive the client IP from `trusted_header`. */
  trust_proxy_headers?: boolean
  /** Forwarded header trusted when `trust_proxy_headers` is on. */
  trusted_header?: string
  /** Trust only the most recent hop of `x-forwarded-for`. */
  trust_last_hop?: boolean
  /** CIDR ranges whose direct peers may set the forwarded header. */
  trusted_proxy_ranges?: string[]
  /** IP groups whose ranges merge into the trusted-proxy scope. */
  trusted_proxy_group_ids?: string[]
  /**
   * Site-wide origin certificate check, as the middle tier of the
   * pool → site → global cascade. `null` clears the site's opinion
   * (pools follow the global default again).
   */
  origin_verify_cert?: boolean | null
  /**
   * Replaces the whole policy; `null` (or a config with no rules) clears it.
   */
  response_replace?: ResponseReplaceConfig | null
}

export interface CreateUpstreamRequest {
  address: string
  weight?: number
  tls?: boolean
  /** Omitted → the site's default pool. */
  pool_id?: string
}

export interface UpdateUpstreamRequest {
  address?: string
  weight?: number
  tls?: boolean
  pool_id?: string
  health_status?: string
}

export interface PoolHealthCheckFields {
  /** Off keeps the agent's default bare TCP probe. */
  health_check_enabled?: boolean
  /** Must start with `/`, no spaces, `?` or `#`; at most 255 characters. */
  health_check_path?: string
  /** Seconds between probe rounds (5-3600). */
  health_check_interval_seconds?: number
  /** Probe connect/read timeout in milliseconds (100-30000). */
  health_check_timeout_ms?: number
  /** Consecutive failures before a node is marked unhealthy (1-10). */
  health_check_unhealthy_threshold?: number
  /** Consecutive successes before a node is marked healthy (1-10). */
  health_check_healthy_threshold?: number
}

/** The `address_family` values the API accepts (`api::sites::normalize_address_family`). */
export type AddressFamily = 'auto' | 'ipv4' | 'ipv6'

export interface CreatePoolRequest extends PoolHealthCheckFields {
  name: string
  lb_algorithm?: string
  sni?: string | null
  /** Omitted = follow `origin_settings.verify_cert`. */
  verify_cert?: boolean | null
  /** Omitted = `auto` (server default: prefer IPv4). */
  address_family?: AddressFamily | string
}

export interface UpdatePoolRequest extends PoolHealthCheckFields {
  name?: string
  lb_algorithm?: string
  /** Empty string clears SNI (disables HTTPS origin). */
  sni?: string | null
  /**
   * Tri-state on purpose: omitting the key leaves the stored value alone,
   * `null` clears it so the pool follows `origin_settings.verify_cert`, and a
   * boolean pins it.
   */
  verify_cert?: boolean | null
  /** Omitted leaves the stored family alone; unknown values are rejected (400). */
  address_family?: AddressFamily | string
}

export interface CreateRouteRequest {
  name: string
  match_type: string
  path: string
  priority?: number | null
  enabled?: boolean
  pool_id: string
  /** Client IPs outside the group cannot reach this route. */
  ip_group_id?: string | null
  /** Strip the matched `path` prefix before proxying (prefix match only). */
  strip_prefix?: boolean
  /** `null` clears the rewrite; validated like the server (`/`-rooted, no `?`/`#`/space). */
  rewrite_path?: string | null
  /** Bare host name; validated like the server (no scheme/path/whitespace, ≤253 bytes). */
  upstream_host?: string | null
}

export interface UpdateRouteRequest {
  name?: string
  match_type?: string
  path?: string
  /** `0` clears the priority back to the auto weight. */
  priority?: number | null
  enabled?: boolean
  pool_id?: string
  /** `null` clears the gate so every client matches again. */
  ip_group_id?: string | null
  /** Strip the matched `path` prefix before proxying (prefix match only). */
  strip_prefix?: boolean
  /** `null` clears the rewrite; validated like the server (`/`-rooted, no `?`/`#`/space). */
  rewrite_path?: string | null
  /** Bare host name; `null` clears the override. */
  upstream_host?: string | null
}

/** One response-body replacement rule (maps onto pingap's `sub_filter`). */
export interface ResponseReplaceRule {
  /** Text (or regex when `is_regex`) searched in the response body. */
  pattern: string
  /** Non-empty replacement; `$1`/`$name` expand only for regex rules. */
  replacement: string
  is_regex: boolean
}

/** Site response-body replacement policy (`sites.response_replace` JSONB). */
export interface ResponseReplaceConfig {
  /** Regex the request path must match; empty applies to every path. */
  path: string
  /** Status codes the replacement applies to; empty applies to all. */
  status_codes: number[]
  rules: ResponseReplaceRule[]
}

export interface UpsertSslRequest {
  domain: string
  cert_pem?: string | null
  key_pem?: string | null
  issuer?: string | null
  expires_at?: string | null
  auto_renew?: boolean
  acme_email?: string | null
  acme_challenge_type?: string | null
  acme_dns_provider?: string | null
  acme_dns_config?: unknown | null
}

export interface SiteListQuery extends PaginationQuery {
  search?: string
  status?: string
}

/* ── WAF rule groups & rules ──────────────────────────────────────── */

/** `models::rules::action` */
export type RuleAction = 'block' | 'log' | 'challenge' | 'js_challenge' | 'allow'
/** `models::rules::mode` */
export type RuleMode = 'off' | 'monitor' | 'block'
/** `models::rules::phase` */
export type RulePhase = 'request' | 'response' | 'custom'

export const RULE_ACTIONS: RuleAction[] = [
  'block',
  'log',
  'challenge',
  'js_challenge',
  'allow',
]
export const RULE_MODES: RuleMode[] = ['off', 'monitor', 'block']
export const RULE_PHASES: RulePhase[] = ['request', 'response', 'custom']

/** `models::rules::rule_groups::Model` */
export interface RuleGroup {
  id: string
  site_id: string
  name: string
  phase: RulePhase | string
  priority: number
  enabled: boolean
  created_at: string
  updated_at: string
}

/** `models::rules::rules::Model` */
export interface Rule {
  id: string
  group_id: string | null
  site_id: string
  name: string
  description: string | null
  expression: string
  action: RuleAction | string
  severity: number
  tags: string[]
  enabled: boolean
  mode: RuleMode | string
  priority: number
  created_at: string
  updated_at: string
}

export interface CreateGroupRequest {
  name: string
  phase?: string
  priority?: number
  enabled?: boolean
}

export interface UpdateGroupRequest {
  name?: string
  phase?: string
  priority?: number
  enabled?: boolean
}

export interface CreateRuleRequest {
  name: string
  group_id?: string | null
  description?: string | null
  expression: string
  action?: string
  severity?: number
  tags?: string[]
  enabled?: boolean
  mode?: string
  priority?: number
}

export interface UpdateRuleRequest {
  name?: string
  group_id?: string | null
  /** `true` detaches the rule from its group. */
  clear_group?: boolean
  description?: string | null
  expression?: string
  action?: string
  severity?: number
  tags?: string[]
  enabled?: boolean
  mode?: string
  priority?: number
}

export interface RuleListQuery extends PaginationQuery {
  group_id?: string
  enabled?: boolean
  search?: string
}

/**
 * Site-level WAF posture derived on the frontend from the rule set, mirroring
 * `grpc::config::waf_config_to_proto`. There is no persisted site WAF record.
 */
export interface DerivedWafConfig {
  enabled: boolean
  mode: RuleMode
  paranoia_level: number
  active_rules: number
  total_rules: number
}

/** Attack families a site can downgrade to monitor-only (`pingwaf-waf::CategorySet`). */
export type WafCategory =
  | 'sqli'
  | 'xss'
  | 'rce'
  | 'lfi'
  | 'ssrf'
  | 'deser'
  | 'crlf'
  | 'xxe'
  | 'ssti'

/** Backend stacks a site can downgrade to monitor-only (`pingwaf-waf::StackSet`). */
export type WafStack = 'java' | 'php' | 'python' | 'node'

export const WAF_CATEGORIES: WafCategory[] = [
  'sqli',
  'xss',
  'rce',
  'lfi',
  'ssrf',
  'deser',
  'crlf',
  'xxe',
  'ssti',
]

export const WAF_STACKS: WafStack[] = ['java', 'php', 'python', 'node']

/** `models::waf_settings::Model` — the persisted site-level grading knobs. */
export interface WafSettings {
  id: string
  site_id: string
  /** Explicit engine switch; a missing server row means `true`. */
  waf_enabled: boolean
  /** Site-level enforcement mode: `off` | `monitor` | `block`. */
  mode: WafMode | string
  /** Detection sensitivity 1-4; decoupled from rule severity. */
  paranoia_level: number
  advanced_mode: boolean
  /** Body-stage inspection budget in seconds (1-30); 0/missing means 30. */
  body_stage_timeout_secs: number
  monitor_categories: WafCategory[] | string[]
  monitor_stacks: WafStack[] | string[]
  monitor_managed_rules: string[]
  created_at: string
  updated_at: string
}

/** Site enforcement mode, mirroring the proto `WafMode` enum. */
export type WafMode = 'off' | 'monitor' | 'block'

/** Patch semantics: omitted fields keep their current value. */
export interface UpdateWafSettingsRequest {
  waf_enabled?: boolean
  mode?: WafMode | string
  paranoia_level?: number
  advanced_mode?: boolean
  body_stage_timeout_secs?: number
  monitor_categories?: string[]
  monitor_stacks?: string[]
  monitor_managed_rules?: string[]
}

/** `api::waf_settings::WafPosture` — what the data plane enforces right now. */
export interface WafPosture {
  /** `"on"` / `"off"` — the explicit engine switch. */
  engine: 'on' | 'off' | string
  detection: {
    /** The managed ruleset is always loaded by the data plane. */
    managed: boolean
    custom: boolean
    deep_inspection: boolean
    under_attack: boolean
  }
  enforcement: {
    /** Explicit site-level enforcement mode: off | monitor | block. */
    mode: string
    /** Managed action per attack category (`sqli`, ...): block | monitor. */
    managed: Record<string, string>
    /** Aggregate custom-rule mode: block | monitor | off. */
    custom_rules: string
    /** Strongest rate-limit action, or `"off"`. */
    cc: string
    /** Bot protection action, or `"off"`. */
    bot: string
    observation_mode: boolean
  }
}

/** `api::waf_settings::ManagedRuleEntry` — one built-in managed rule. */
export interface ManagedRule {
  id: string
  name: string
  action: string
  severity: number
  tags: string[]
  stacks: string[]
  /** Attack family (`sqli`/`xss`/`rce`) whose category switch also drives this rule. */
  category: string | null
  strict_only: boolean
}

/* ── Rate limiting ────────────────────────────────────────────────── */

/** `models::rules::characteristic` */
export type RateLimitCharacteristic =
  | 'ip'
  | 'ip_nat'
  | 'host'
  | 'path'
  | 'header'
  | 'cookie'
  | 'query'
  | 'asn'
  | 'country'
  | 'ja3'

/** Characteristics selectable as bare pills; `header` / `cookie` / `query` are
 * only accepted in the parameterized `kind:name` form via the custom input. */
export const RATE_LIMIT_CHARACTERISTICS: RateLimitCharacteristic[] = [
  'ip',
  'ip_nat',
  'host',
  'path',
  'asn',
  'country',
  'ja3',
]

/** Characteristics the edge cannot key counters on yet: rules that use them
 * are stored but not enforced. */
export const RATE_LIMIT_CHARACTERISTICS_PENDING: RateLimitCharacteristic[] = [
  'ja3',
]

/** Valid forms for parameterized characteristics, e.g. `header:X-Api-Key`. */
const PARAMETERIZED_CHARACTERISTIC_RE = /^(header|cookie|query):[^\s]+$/i

export function isParameterizedCharacteristic(value: string): boolean {
  return PARAMETERIZED_CHARACTERISTIC_RE.test(value)
}

/** True for anything the rate-limit form can submit as a characteristic. */
export function isValidRateLimitCharacteristic(value: string): boolean {
  return (
    (RATE_LIMIT_CHARACTERISTICS as string[]).includes(value) ||
    isParameterizedCharacteristic(value)
  )
}

/** `models::rules::rate_limit_rules::Model` */
export interface RateLimitRule {
  id: string
  site_id: string
  name: string
  expression: string
  characteristics: string[]
  period_seconds: number
  threshold: number
  action: RuleAction | string
  mitigation_timeout_seconds: number
  enabled: boolean
  priority: number
  created_at: string
  updated_at: string
}

export interface CreateRateLimitRequest {
  name: string
  expression?: string
  characteristics?: string[]
  period_seconds?: number
  threshold?: number
  action?: string
  mitigation_timeout_seconds?: number
  enabled?: boolean
  priority?: number
}

export interface UpdateRateLimitRequest {
  name?: string
  expression?: string
  characteristics?: string[]
  period_seconds?: number
  threshold?: number
  action?: string
  mitigation_timeout_seconds?: number
  enabled?: boolean
  priority?: number
}

/* ── Cache rules ──────────────────────────────────────────────────── */

/** `models::rules::cache_rules::Model` */
export interface CacheRule {
  id: string
  site_id: string
  name: string
  match_expression: string
  edge_ttl_seconds: number
  browser_ttl_seconds: number
  cache_eligible: boolean
  respect_origin: boolean
  enabled: boolean
  created_at: string
}

/* ── Logs ─────────────────────────────────────────────────────────── */

/** `models::security_events::security_event::Model` */
export interface SecurityEvent {
  id: number
  site_id: string | null
  agent_id: string | null
  request_id: string | null
  timestamp: string
  client_ip: string
  method: string
  host: string | null
  path: string | null
  rule_id: string | null
  rule_name: string | null
  /** Which protection produced the event: `managed` / `waf` / `ip_geo` /
   * `bot` / `rate_limit` / `challenge`; null on pre-0.21 rows. */
  event_type: string | null
  action: string
  score: number | null
  waf_details: string | null
  country_code: string | null
  user_agent: string | null
  /**
   * Who made the request, when the site authenticated them: the OIDC
   * session's `sub`. `null` for anonymous traffic and for rows written
   * before the column existed.
   */
  user_identity: string | null
  created_at: string
}

/** `api::logs::AccessLogSummary` — the metadata-only list row. */
export interface AccessLogSummary {
  id: number
  site_id: string | null
  agent_id: string | null
  request_id: string | null
  timestamp: string
  client_ip: string
  method: string
  host: string | null
  path: string | null
  query_string: string | null
  status_code: number | null
  response_size: number | null
  upstream_addr: string | null
  upstream_latency_ms: number | null
  total_latency_ms: number | null
  cache_status: string | null
  user_agent: string | null
  referer: string | null
  country_code: string | null
  tls_version: string | null
  /** The authenticated caller's OIDC `sub`; `null` when anonymous. */
  user_identity: string | null
  request_body_size: number | null
  request_body_truncated: boolean | null
  scheme: string | null
  protocol: string | null
  response_body_size: number | null
  response_body_truncated: boolean | null
}

/**
 * `models::security_events::access_log::Model` — the full record served by
 * `GET /logs/access/{id}` (and by `GET /logs/access?full=true`). The list
 * endpoint returns [`AccessLogSummary`] rows; the four heavy fields are
 * absent there and optional here so both rows satisfy this type.
 */
export interface AccessLog extends AccessLogSummary {
  request_headers?: Record<string, string> | null
  request_body?: string | null
  response_headers?: Record<string, string> | null
  response_body?: string | null
}

/** `api::logs::SecurityQuery` */
export interface SecurityLogQuery extends PaginationQuery {
  site_id?: string
  from?: string
  to?: string
  client_ip?: string
  action?: string
  rule_id?: string
  event_type?: string
  /** Matches only rows with no owning site (no `Host` header on the wire). */
  unassigned?: boolean
  host?: string
  path?: string
  country_code?: string
  /** The authenticated caller's OIDC `sub` (exact match). */
  user_identity?: string
  request_id?: string
  q?: string
}

/** `api::logs::AccessQuery` */
export interface AccessLogQuery extends PaginationQuery {
  site_id?: string
  from?: string
  to?: string
  client_ip?: string
  method?: string
  status_code?: number
  status_class?: number
  host?: string
  path?: string
  cache_status?: string
  country_code?: string
  /** The authenticated caller's OIDC `sub` (exact match). */
  user_identity?: string
  min_latency_ms?: number
  request_id?: string
  /** Matches only rows with no owning site (no `Host` header on the wire). */
  unassigned?: boolean
  q?: string
}

/** Convenience alias used by the logs page. */
export type LogQueryParams = SecurityLogQuery &
  AccessLogQuery & {
    /** Access-log lists only: fetch full rows (headers + bodies). */
    full?: boolean
  }

/** `api::logs::PurgeResult` */
export interface PurgeResult {
  deleted_security_events: number
  deleted_access_logs: number
  cutoff: string
}

/* ── Analytics ────────────────────────────────────────────────────── */

export type AnalyticsInterval = 'minute' | 'hour' | 'day' | 'week'

/** `api::analytics::RangeQuery` */
export interface RangeQuery {
  site_id?: string
  from?: string
  to?: string
  interval?: AnalyticsInterval | string
  limit?: number
}

/** `api::analytics::ActiveVisitorsResponse` */
export interface ActiveVisitorsResponse {
  active_visitors: number
  window_minutes: number
  as_of: string
}

/** `api::analytics::ClientTypesResponse` */
export interface ClientTypesResponse {
  desktop: number
  mobile: number
  other: number
  total: number
  desktop_share: number
  mobile_share: number
  other_share: number
}

/** `api::analytics::Summary` */
export interface AnalyticsSummary {
  from: string
  to: string
  site_id: string | null
  requests: number
  unique_ips: number
  cache_hits: number
  cache_hit_rate: number
  /** Outbound bytes served straight from the edge cache in the window. */
  cache_saved_bytes: number
  avg_latency_ms: number
  max_latency_ms: number
  client_errors: number
  server_errors: number
  security_events: number
  blocked_requests: number
  distinct_attackers: number
  rules_triggered: number
}

/** `api::analytics::TimeBucket` */
export interface TimeBucket {
  bucket: string
  requests: number
  cache_hits: number
  cache_saved_bytes: number
  client_errors: number
  server_errors: number
  avg_latency_ms: number
  blocked: number
}

/** `api::analytics::TrafficBucket` — egress bytes inside one fixed-width window. */
export interface TrafficBucket {
  bucket: string
  bytes: number
}

/** `api::analytics::Traffic` — egress bandwidth over a window; never origin-pull. */
export interface TrafficSeries {
  from: string
  to: string
  site_id: string | null
  step_seconds: number
  total_bytes: number
  buckets: TrafficBucket[]
}

/** `api::analytics::TopRule` */
export interface TopRule {
  rule_id: string
  rule_name: string
  action: string
  hits: number
  unique_ips: number
}

/** `api::analytics::TopIp` */
export interface TopIp {
  client_ip: string
  country_code: string | null
  requests: number
  blocked: number
  /** Site the IP most recently requested; the target for quick actions. */
  top_site_id?: string | null
}

/** `api::analytics::TopPath` */
export interface TopPath {
  path: string
  requests: number
  cache_hits: number
  avg_latency_ms: number
}

/** `api::analytics::StatusCodeCount` */
export interface StatusCodeCount {
  status_code: number
  requests: number
}

/** `api::analytics::SiteOverview` */
export interface SiteOverview {
  site_id: string
  name: string
  domain: string
  status: string
  plan: string
  requests: number
  blocked: number
}

/** `api::analytics::SitesOverviewResponse` — `/analytics/sites` envelope. */
export interface SitesOverviewResponse {
  sites: SiteOverview[]
  /** True when the global view was capped at the server-side limit. */
  truncated?: boolean
}

/** `api::analytics::SiteTrafficBucket` — one point of one site's series. */
export interface SiteTrafficBucket {
  bucket: string
  site_id: string
  site_domain: string
  site_name: string
  requests: number
}

/* ── Agents ───────────────────────────────────────────────────────── */

/** `models::agents::status` */
export type AgentStatus = 'online' | 'offline' | 'degraded'

/** `api::agents::AgentResponse` */
export interface Agent {
  id: string
  site_id: string | null
  site_domain: string | null
  hostname: string
  ip_address: string
  /** Egress address as seen from the public internet; null when unknown. */
  public_ip: string | null
  /** LAN address, with loopback and container bridges filtered out. */
  private_ip: string | null
  version: string | null
  os_info: string | null
  cpu_cores: number | null
  /** Total physical memory; null = the agent never reported it. */
  total_memory_bytes: number | null
  /** Used memory (kept as `memory_bytes` for compatibility). */
  used_memory_bytes: number | null
  memory_bytes: number | null
  status: AgentStatus | string
  api_key_id: string | null
  config_hash: string | null
  last_heartbeat: string | null
  registered_at: string
  /** When the agent last applied a full site config; null = never. */
  last_config_sync_at: string | null
  /** When the agent last applied a per-site rule bundle; null = never. */
  last_policy_sync_at: string | null
  connected: boolean
  pending_commands: number
  /** Whether the gRPC control plane serves TLS; false = plaintext (degraded). */
  grpc_tls: boolean
}

export interface AgentListQuery extends PaginationQuery {
  site_id?: string
  status?: string
  search?: string
}

/**
 * `models::host_samples::Model` — one point of the agent's 5-second host probe.
 *
 * Network and disk totals are cumulative counters; consecutive rows are
 * differenced client-side to draw throughput.
 */
export interface HostSample {
  id: number
  agent_id: string
  sampled_at: string
  cpu_usage_percent: number | null
  load1: number | null
  load5: number | null
  load15: number | null
  memory_total_bytes: number | null
  memory_used_bytes: number | null
  memory_available_bytes: number | null
  swap_total_bytes: number | null
  swap_used_bytes: number | null
  disk_total_bytes: number | null
  disk_used_bytes: number | null
  net_rx_bytes: number | null
  net_tx_bytes: number | null
  disk_read_bytes: number | null
  disk_write_bytes: number | null
  process_count: number | null
  tcp_connections: number | null
  uptime_secs: number | null
  created_at: string
}

export interface AgentSamplesQuery extends PaginationQuery {
  from?: string
  to?: string
}

export type AgentCommand =
  | 'restart'
  | 'purge_cache'
  | 'block_ip'
  | 'unblock_ip'
  | 'reload'

/** `api::agents::CommandRequest` */
export interface AgentCommandRequest {
  command: AgentCommand | string
  site_id?: string | null
  ip_addresses?: string[]
  urls?: string[]
  tags?: string[]
  duration_seconds?: number | null
  reason?: string | null
  graceful?: boolean
}

/** `202 Accepted` body of `POST /agents/{id}/commands`. */
export interface AgentCommandResult {
  agent_id: string
  command: string
  delivered: boolean
  queued: boolean
}

/** `api::agents::EnrollRequest` */
export interface AgentEnrollRequest {
  name?: string
}

/** `api::agents::EnrollResponse` — the token is returned once and never stored. */
export interface AgentEnrollResponse {
  key_id: string
  /** Already embedded in `install_command`; the console does not show it. */
  token: string
  server_url: string
  install_command: string
}

/* ── Elasticsearch settings ───────────────────────────────────────── */

/** `es::config::EsConfig` — secrets come back masked as `***`. */
export interface EsConfig {
  urls: string[]
  index_prefix: string
  username: string | null
  password: string | null
  api_key: string | null
  bulk_max_size: number
  bulk_flush_interval_ms: number
  max_body_size: number
  enabled: boolean
  buffer_dir: string | null
  buffer_max_size_mb: number
  channel_capacity: number
  request_timeout_secs: number
}

/** `es::client::EsHealth` */
export interface EsHealth {
  status: string
  cluster_name?: string | null
  number_of_nodes?: number | null
  active_shards?: number | null
}

/** `api::settings::EsSettingsView` */
export interface EsSettingsView {
  config: EsConfig
  running: boolean
  health?: EsHealth | null
  requires_restart: boolean
}

/** `api::settings::EsTestResult` */
export interface EsTestResult {
  ok: boolean
  health?: EsHealth | null
  error?: string | null
  template_installed: boolean
}

/** `models::log_retention::Model` — the global PostgreSQL retention windows. */
export interface LogRetentionSettings {
  id: number
  /** Days a row of `access_logs` is kept before the sweeper deletes it. */
  access_log_retention_days: number
  /** Days a row of `security_events` is kept. */
  security_event_retention_days: number
  updated_at: string
}

/** `api::log_retention::UpdateLogRetentionRequest` */
export interface UpdateLogRetentionRequest {
  access_log_retention_days?: number
  security_event_retention_days?: number
}

/* ── Control-plane self-protection (port 9080) ────────────────────── */

/** `models::api_protection::api_protection_settings::Model`. */
export interface ApiProtectionSettings {
  id: number
  access_log_enabled: boolean
  access_log_retention_days: number
  ip_allowlist_enabled: boolean
  /** Inline addresses / CIDR ranges that may call the API. */
  ip_allowlist_ranges: string[]
  /** An `ip_groups` row whose ranges join the allowlist. */
  ip_allowlist_group_id: string | null
  waf_enabled: boolean
  /** `block` or `monitor`; monitor only records matches. */
  waf_mode: ApiProtectionWafMode | string
  updated_at: string
}

export type ApiProtectionWafMode = 'block' | 'monitor'

/** `api::api_protection::ApiProtectionView` */
export interface ApiProtectionView extends ApiProtectionSettings {
  /** Entries (inline plus group) the effective allowlist holds right now. */
  effective_allowlist_entries: number
}

/** `api::api_protection::UpdateApiProtectionRequest` */
export interface UpdateApiProtectionRequest {
  access_log_enabled?: boolean
  access_log_retention_days?: number
  ip_allowlist_enabled?: boolean
  ip_allowlist_ranges?: string[]
  /** Absent/`null` keeps the reference; `''` clears it; a UUID points at a group. */
  ip_allowlist_group_id?: string | null
  waf_enabled?: boolean
  waf_mode?: ApiProtectionWafMode | string
  /** Applies a change even when it excludes the calling connection. */
  force?: boolean
}

/** `models::api_protection::control_plane_access_logs::Model`. */
export interface ControlPlaneAccessLog {
  id: number
  request_id: string | null
  timestamp: string
  client_ip: string
  method: string
  host: string | null
  path: string
  query_string: string | null
  scheme: string | null
  protocol: string | null
  status_code: number | null
  latency_ms: number | null
  user_agent: string | null
  referer: string | null
  user_id: string | null
  user_email: string | null
  /** `allowed`, `blocked_allowlist`, `blocked_waf` or `observed_waf`. */
  action: string
  reason: string | null
}

/** `api::api_protection::ControlPlaneLogQuery` */
export interface ControlPlaneLogQuery extends PaginationQuery {
  from?: string
  to?: string
  client_ip?: string
  method?: string
  action?: string
  status_code?: number
  path?: string
  host?: string
  request_id?: string
  q?: string
}

/** `models::defense_settings::Model` — the global observation mode row. */
export interface DefenseSettings {
  id: number
  /** When true, every protection detects but nothing is enforced. */
  observation_mode: boolean
  /**
   * Default disconnected behaviour for sites whose failover policy is
   * `inherit`: true keeps proxying, false answers 503.
   */
  default_fail_open: boolean
  updated_at: string
}

/* ── Per-site failover policy ─────────────────────────────────────── */

/** How a site behaves while disconnected with no synced rule bundle. */
export type FailoverPolicy = 'inherit' | 'open' | 'closed'

/** `api::site_failover::FailoverSettings` — the site policy plus the
 * global default it inherits from. */
export interface FailoverSettings {
  failover_policy: FailoverPolicy
  default_fail_open: boolean
}

/* ── Control-plane certificate ────────────────────────────────────── */

export type TlsCertificateSource = 'self_signed' | 'uploaded'

/** `api::system_tls::TlsCertificateView` — never includes the private key. */
export interface TlsCertificateView {
  id: string
  source: TlsCertificateSource | string
  subject_dn: string
  common_name: string | null
  sans: string[]
  serial: string
  fingerprint_sha256: string
  not_before: string
  not_after: string
  created_at: string
  /** Days until `not_after`, negative once the certificate has expired. */
  expires_in_days: number
}

/** `api::system_tls::TlsStatusView` */
export interface TlsStatusView {
  /** Whether this process terminates TLS on the control-plane port. */
  enabled: boolean
  /** Whether a certificate is loaded in the running listener. */
  has_certificate: boolean
  certificate?: TlsCertificateView | null
  /** Names the self-signed generator uses for this deployment. */
  default_sans: string[]
  max_validity_days: number
}

export interface UploadControlPlaneCertificateRequest {
  /** PEM certificate, chain included when the issuer is not a root. */
  cert_pem: string
  /** PEM private key (PKCS#8, PKCS#1 or SEC1), matching the certificate. */
  key_pem: string
}

export interface GenerateControlPlaneCertificateRequest {
  common_name?: string
  sans?: string[]
  validity_days?: number
}

/* ── API keys ─────────────────────────────────────────────────────── */

export type ApiKeyPermission = 'agent' | 'read' | 'write'

/** `api::keys::ApiKeyResponse` — `key` is only set by `POST /keys`. */
export interface ApiKey {
  id: string
  user_id: string
  name: string
  key_prefix: string
  permissions: string[]
  expires_at: string | null
  last_used_at: string | null
  created_at: string
  /** Owning account's email; absent for system-minted keys. */
  creator?: string
  /** True when the key was minted by the system (bootstrap, enrollment). */
  is_system: boolean
  key?: string
}

export interface CreateApiKeyRequest {
  name: string
  permissions?: string[]
  expires_at?: string | null
}

/* ── Misc ─────────────────────────────────────────────────────────── */

/** `GET /api/v1/version` */
export interface VersionResponse {
  name: string
  version: string
  api: string
  registration_open: boolean
  /** Whether the gRPC control plane serves TLS; false = plaintext (degraded). */
  grpc_tls: boolean
}

/* ── SSL / TLS ────────────────────────────────────────────────────── */

/** ACME challenge types supported by the control plane. */
export type AcmeChallengeType = 'http-01' | 'dns-01'

export const ACME_CHALLENGE_TYPES: AcmeChallengeType[] = ['http-01', 'dns-01']

/** DNS providers wired into the ACME solver. */
export const ACME_DNS_PROVIDERS = [
  'cloudflare',
  'route53',
  'digitalocean',
  'aliyun',
  'dnspod',
  'cloudxns',
  'huawei',
  'manual',
] as const

export type TlsVersion = '1.0' | '1.1' | '1.2' | '1.3'

export const TLS_VERSIONS: TlsVersion[] = ['1.0', '1.1', '1.2', '1.3']

/** `api::ssl::cert_status` */
export type CertificateStatus = 'active' | 'pending' | 'expired' | 'failed'

export const CERTIFICATE_STATUSES: CertificateStatus[] = [
  'active',
  'pending',
  'expired',
  'failed',
]

/** `api::ssl::CertificateResponse` — never carries the private key. */
export interface SslCertificate {
  id: string
  site_id: string
  domain: string
  issuer: string | null
  not_before: string | null
  expires_at: string | null
  auto_renew: boolean
  acme_email: string | null
  acme_challenge_type: string
  acme_dns_provider: string | null
  acme_dns_config: unknown | null
  status: CertificateStatus | string
  /** Why the last ACME issuance was given up on; null while healthy. */
  failure_reason: string | null
  has_certificate: boolean
  has_private_key: boolean
  /**
   * Non-fatal notices from the server (e.g. a SAN not served by this site).
   * Saving is never rejected because of these.
   */
  warnings?: string[]
  created_at: string
  updated_at: string
}

/** `api::ssl::CertificateWithSite` — a row of the cross-site certificate list. */
export interface CertificateWithSite extends SslCertificate {
  site_domain: string
  site_name: string
}

/** `api::ssl::CertificateSummary` */
export interface CertificateSummary {
  total: number
  active: number
  pending: number
  failed: number
  expired: number
  expiring_soon: number
}

/** `api::ssl::GlobalListQuery` */
export interface CertificateListQuery extends PaginationQuery {
  site_id?: string
  status?: string
}

export interface CreateSslRequest {
  /** Required by the global `/certificates` endpoint, ignored by the per-site one. */
  site_id?: string
  domain: string
  /** ACME automation. */
  auto_renew?: boolean
  acme_email?: string | null
  acme_challenge_type?: AcmeChallengeType | string | null
  acme_dns_provider?: string | null
  acme_dns_config?: unknown | null
  /** Manual upload. */
  cert_pem?: string | null
  key_pem?: string | null
  issuer?: string | null
  not_before?: string | null
  expires_at?: string | null
  /** Global endpoint only: attach to the site and turn HTTPS on. */
  activate?: boolean
}

export type UpdateSslRequest = Partial<Omit<CreateSslRequest, 'site_id' | 'activate'>>

/** `api::ssl::SslSettingsResponse` — the site's TLS posture. */
export interface SslSettings {
  https_enabled: boolean
  min_tls_version: TlsVersion | string
  max_tls_version: TlsVersion | string | null
  self_signed: boolean
  certificate_id: string | null
  mtls_enabled: boolean
  has_mtls_client_ca: boolean
  mtls_organization: string | null
  mtls_require_client_cert: boolean
  hsts_enabled: boolean
  hsts_max_age: number
  always_use_https: boolean
  /** Serve HTTP/1.1 alongside HTTP/2; the server always reports it (default true). */
  http1_enabled: boolean
  /** Serve HTTP/2; multiplexes requests over one connection (default true). */
  http2_enabled: boolean
}

/** `api::sites::TlsPostureRequest` — the write side of `SslSettings`. */
export interface UpdateSslSettingsRequest {
  https_enabled?: boolean
  min_tls_version?: TlsVersion | string
  max_tls_version?: TlsVersion | string | null
  self_signed?: boolean
  certificate_id?: string | null
  mtls_enabled?: boolean
  mtls_client_ca?: string | null
  mtls_organization?: string | null
  mtls_require_client_cert?: boolean
  hsts_enabled?: boolean
  hsts_max_age?: number
  always_use_https?: boolean
  http1_enabled?: boolean
  http2_enabled?: boolean
}

/* ── Managed mTLS material ─────────────────────────────────────────── */

/** How a certificate authority ended up in the store. */
export type MtlsCaSource = 'generated' | 'imported'

/** `api::mtls::CaResponse` — a trust anchor configured for one site. */
export interface MtlsCa {
  id: string
  site_id: string
  name: string
  source: MtlsCaSource | string
  cert_pem: string
  /** Generated CAs can sign; imported ones are trust anchors only. */
  has_private_key: boolean
  subject_dn: string
  serial: string
  fingerprint_sha256: string
  expected_organization: string | null
  not_before: string
  not_after: string
  is_active: boolean
  created_at: string
  /** Client certificates issued from this CA, all statuses. */
  certificate_count: number
}

/** Creation response — `key_pem` is only ever returned here. */
export interface MtlsCaCreated extends MtlsCa {
  key_pem: string | null
}

export type MtlsCertStatus = 'active' | 'revoked'

/** `api::mtls::ClientCertResponse`. */
export interface MtlsClientCertificate {
  id: string
  site_id: string
  ca_id: string
  ca_name: string | null
  name: string
  common_name: string
  organization: string | null
  serial: string
  fingerprint_sha256: string
  cert_pem: string
  has_private_key: boolean
  not_before: string
  not_after: string
  status: MtlsCertStatus | string
  revoked_at: string | null
  revocation_reason: string | null
  created_at: string
}

/** Issue response — `key_pem` is only ever returned here. */
export interface MtlsClientCertIssued extends MtlsClientCertificate {
  key_pem: string | null
}

export interface CreateMtlsCaRequest {
  name: string
  /** When set, the CA is imported as-is instead of generated. */
  cert_pem?: string
  organization?: string
  validity_days?: number
}

export interface IssueMtlsClientCertRequest {
  ca_id: string
  name?: string
  common_name?: string
  organization?: string
  validity_days?: number
}

/* ── Certificate events ────────────────────────────────────────────── */

export type CertEventType =
  | 'created'
  | 'renewal_requested'
  | 'renewed'
  | 'failed'
  | 'issuance_failed'
  | 'deleted'
  | 'acme_raw'

export const CERT_EVENT_TYPES: CertEventType[] = [
  'created',
  'renewal_requested',
  'renewed',
  'failed',
  'issuance_failed',
  'deleted',
  'acme_raw',
]

export interface CertificateEvent {
  id: string
  certificate_id: string | null
  site_id: string | null
  event_type: CertEventType | string
  message: string
  details: Record<string, unknown> | null
  created_at: string
  domain: string | null
  site_domain: string | null
}

export interface CertificateEventListQuery extends PaginationQuery {
  certificate_id?: string
  event_type?: string
}

/* ── Cache rules ──────────────────────────────────────────────────── */

export interface CreateCacheRuleRequest {
  name: string
  match_expression?: string
  edge_ttl_seconds?: number
  browser_ttl_seconds?: number
  cache_eligible?: boolean
  respect_origin?: boolean
  enabled?: boolean
}

export type UpdateCacheRuleRequest = Partial<CreateCacheRuleRequest>

/**
 * `api::cache::CacheSettingsResponse`. The disk budget belongs to the site, not
 * to an individual rule — the agent enforces one ceiling per hostname, and all
 * of a site's hostnames share it.
 */
export interface CacheSettings {
  site_id: string
  quota_mb: number
  /** Site-level single-file cap in MiB; null follows the global ceiling. */
  max_file_size_mb: number | null
  /** Per-content-type single-file caps in MiB (html/css/js/image/font/media/other). */
  type_limits: Record<string, number> | null
  /** Extension-based cache policy (five families); null when unconfigured. */
  cache_type_policy: CacheTypePolicy | null
  /** The global single-file ceiling every site value is clamped against. */
  global_max_file_size_mb: number
  /** Resolved cap: min(global, max_file_size_mb?). */
  effective_max_file_size_mb: number
  /** True while at least one cache rule of the site is enabled. */
  cache_enabled: boolean
  rule_count: number
  enabled_rule_count: number
}

/** One content family of the extension-based cache type policy. */
export interface CacheTypeCategory {
  enabled: boolean
  edge_ttl_seconds: number
  browser_ttl_seconds: number
  extensions: string[]
}

/** Five fixed families, keyed web_assets/image/media/other/html. */
export type CacheTypePolicy = Record<
  'web_assets' | 'image' | 'media' | 'other' | 'html',
  CacheTypeCategory
>

export interface UpdateCacheSettingsRequest {
  quota_mb?: number
  /** Absent = unchanged; null = follow the global ceiling again. */
  max_file_size_mb?: number | null
  /** Absent = unchanged; empty object clears every override. */
  type_limits?: Record<string, number> | null
  /** Absent = unchanged; null removes the policy. */
  cache_type_policy?: CacheTypePolicy | null
}

/**
 * `models::cache_settings::Model` — the deployment-wide cache ceiling. All
 * knobs ride inside every rule bundle, so saving takes effect on the next
 * configuration push (which the API triggers immediately).
 */
export interface GlobalCacheSettings {
  max_file_size_mb: number
  max_space_mb: number
  master_enabled: boolean
  default_edge_ttl_seconds: number
}

export interface UpdateGlobalCacheSettingsRequest {
  max_file_size_mb?: number
  max_space_mb?: number
  master_enabled?: boolean
  default_edge_ttl_seconds?: number
}

/**
 * `models::origin_settings::Model` — the deployment-wide origin TLS default.
 *
 * `verify_cert` decides whether an origin that is reached over HTTPS must
 * present a certificate the trust store validates. It applies to every origin
 * pool that does not pin a `verify_cert` of its own, reaches the data plane as
 * `basic.origin_verify_cert`, and rides inside every rule bundle — so a save
 * takes effect on the configuration push the API triggers immediately.
 */
export interface OriginSettings {
  id: number
  verify_cert: boolean
  updated_at: string
}

export interface UpdateOriginSettingsRequest {
  verify_cert: boolean
}

/**
 * `api::cache::CacheStatusView`. The `configured_*` figures come from the
 * database; the rest comes from agent heartbeats and stays zero until one
 * reports — `reporting_edges === 0` is how the two are told apart.
 */
export interface CacheStatus {
  site_id: string
  domain: string
  configured_quota_mb: number
  enabled_rule_count: number
  reporting_edges: number
  disk_bytes: number
  quota_bytes_per_edge: number
  quota_bytes_total: number
  items: number
  evictions_total: number
  usage_percent: number
  last_reported_at: string | null
}

export interface PurgeCacheRequest {
  site_id: string
  /** Explicit URLs; ignored when `purge_all` is set. */
  urls?: string[]
  purge_all?: boolean
}

/** `api::cache::PurgeResponse` */
export interface PurgeCacheResult {
  site_id: string
  purge_all: boolean
  urls: number
  /** Agents the command reached over a live stream. */
  delivered: number
  /** Agents it was queued for; delivered on their next heartbeat. */
  queued: number
}

/* ── CC protection / challenge ────────────────────────────────────── */

/** Default challenge posture applied when CC protection trips. */
export type ChallengeLevel =
  | 'none'
  | 'non_interactive'
  | 'managed'
  | 'interactive'

export const CHALLENGE_LEVELS: ChallengeLevel[] = [
  'none',
  'non_interactive',
  'managed',
  'interactive',
]

export interface ChallengeConfig {
  enabled: boolean
  under_attack_mode: boolean
  default_level: ChallengeLevel | string
  /** Seconds a solved challenge stays valid for a client (60..86400). */
  clearance_duration_secs: number
  /** Requests/minute per IP before a challenge is issued (1..10000000). */
  rate_threshold: number
  exempt_paths: string[]
  browser_integrity_check: boolean
  tls_fingerprint_check: boolean
}

/** Patch semantics: omitted fields keep their current value (mirrors the server). */
export type UpdateChallengeRequest = Partial<ChallengeConfig>

/* ── IP access rules ──────────────────────────────────────────────── */

export type IpRuleAction =
  | 'block'
  | 'challenge'
  | 'js_challenge'
  | 'allow'
  /** Requires the site's basic auth credentials for the matched clients. */
  | 'basic_auth'

export const IP_RULE_ACTIONS: IpRuleAction[] = [
  'block',
  'challenge',
  'js_challenge',
  'allow',
  'basic_auth',
]

export interface IpRule {
  id: string
  site_id: string
  name: string
  /** Manual mode: explicit addresses/CIDRs. Empty in group mode. */
  ip_ranges: string[]
  /** Group mode: targets the referenced IP group's live ranges. */
  group_id: string | null
  group_name?: string | null
  action: IpRuleAction | string
  note: string | null
  enabled: boolean
  priority: number
  created_at: string
  updated_at: string
}

export interface CreateIpRuleRequest {
  name: string
  /** Exactly one of group_id / ip_ranges must be set. */
  group_id?: string
  ip_ranges?: string[]
  action?: IpRuleAction | string
  note?: string | null
  enabled?: boolean
  priority?: number
}

export interface BulkImportIpRequest {
  ip_ranges: string[]
  action?: IpRuleAction | string
  note?: string | null
  enabled?: boolean
}

export type UpdateIpRuleRequest = Partial<CreateIpRuleRequest>

/* ── Auto-blocked IPs (dynamic edge blocks) ───────────────────────── */

/**
 * One IP the edge currently refuses for a site: WAF/rate-limit auto-blocks
 * and server-issued block commands. The control plane mirrors each agent's
 * list from the heartbeat; several agents enforcing the same IP are folded
 * into a single row (`agent_count`).
 */
export interface BlockedIp {
  ip: string
  /** `single` = one address, `cidr` = a manual CIDR block (server-truncated). */
  kind?: 'single' | 'cidr'
  reason: string | null
  blocked_at: string
  /** null = permanent block (no automatic expiry). */
  expires_at: string | null
  agent_count: number
  /** Total security events recorded for this IP at this site. */
  attack_count: number
  last_attack_at: string | null
}

export interface UnblockIpResponse {
  ip: string
  /** `single` | `cidr` — matches what the caller passed to unblock. */
  kind?: 'single' | 'cidr'
  agents: number
  delivered: number
}

/**
 * One (site, IP) dynamic block as shown on the global blacklist page: the
 * per-site `BlockedIp` extended with the site's identity so rows from
 * different sites can be told apart.
 */
export interface GlobalBlockedIp {
  ip: string
  /** `single` = one address, `cidr` = a manual CIDR block. */
  kind?: 'single' | 'cidr'
  site_id: string
  site_name: string
  reason: string | null
  blocked_at: string
  /** null = permanent block (no automatic expiry). */
  expires_at: string | null
  agent_count: number
  attack_count: number
  last_attack_at: string | null
}

export interface ManualBlockIpRequest {
  site_id: string
  ip: string
  /** Seconds the block stays in force; 0/omitted = permanent until unblocked. */
  duration_seconds?: number
  reason?: string
}

export interface ManualBlockIpResponse {
  ip: string
  /** `single` or `cidr`, reflecting how the server parsed the input. */
  kind?: 'single' | 'cidr'
  site_id: string
  duration_seconds: number
  agents: number
  delivered: number
}

/* ── Rewrite rules ────────────────────────────────────────────────── */

export type RewriteDirection = 'request' | 'response'

export const REWRITE_DIRECTIONS: RewriteDirection[] = ['request', 'response']

/** Discriminated union of the operations a rewrite rule can perform. */
export type RewriteOperationType =
  | 'set_header'
  | 'add_header'
  | 'remove_header'
  | 'set_path'
  | 'regex_replace_path'
  | 'set_query_param'
  | 'remove_query_param'
  | 'replace_body'

export const REWRITE_OPERATION_TYPES: RewriteOperationType[] = [
  'set_header',
  'add_header',
  'remove_header',
  'set_path',
  'regex_replace_path',
  'set_query_param',
  'remove_query_param',
  'replace_body',
]

export interface RewriteOperation {
  type: RewriteOperationType | string
  /** Header name / query key / regex pattern / search string. */
  name?: string
  /** Header value / replacement / regex substitution. */
  value?: string
}

export interface RewriteRule {
  id: string
  site_id: string
  name: string
  direction: RewriteDirection | string
  /** Wirefilter-flavoured match expression; empty means "always". */
  condition_expr: string
  operations: RewriteOperation[]
  priority: number
  enabled: boolean
  created_at: string
}

export interface CreateRewriteRuleRequest {
  name: string
  direction?: RewriteDirection | string
  condition_expr?: string
  operations?: RewriteOperation[]
  priority?: number
  enabled?: boolean
}

export type UpdateRewriteRuleRequest = Partial<CreateRewriteRuleRequest>

/* ── Custom error pages ───────────────────────────────────────────── */

export type ErrorPageContentType = 'text/html' | 'application/json' | 'text/plain'

export const ERROR_PAGE_CONTENT_TYPES: ErrorPageContentType[] = [
  'text/html',
  'application/json',
  'text/plain',
]

/** Short labels for the content-type picker. */
export const ERROR_PAGE_CONTENT_TYPE_LABELS: Record<string, string> = {
  'text/html': 'HTML',
  'application/json': 'JSON',
  'text/plain': 'Text',
}

/** Status codes the console offers a custom page for out of the box. */
export const ERROR_PAGE_STATUS_CODES = [403, 429, 502, 503, 504] as const

export interface ErrorPage {
  id: string
  status_code: number
  name: string
  content_type: ErrorPageContentType | string
  body_template: string
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface UpsertErrorPageRequest {
  status_code: number
  name?: string
  content_type?: ErrorPageContentType | string
  body_template?: string
  enabled?: boolean
}

/* ── Bot protection ───────────────────────────────────────────────── */

export type BotAction = 'block' | 'challenge' | 'js_challenge' | 'log' | 'allow'

/** Actions the v1 data plane enforces; `js_challenge`/`allow` are accepted by
 * the API for compatibility but behave like `challenge`/`log`. */
export const BOT_ACTIONS: BotAction[] = ['block', 'challenge', 'log']

export interface BotConfig {
  id: string
  site_id: string
  enabled: boolean
  ua_analysis: boolean
  js_detection: boolean
  tls_fingerprint: boolean
  behavioral_analysis: boolean
  action: BotAction | string
  /** Case-insensitive User-Agent substrings of verified good bots. */
  known_bots_whitelist: string[]
  /** Verify known crawler user agents by their IP: a client inside the
   * referenced IP group's ranges always counts as a verified bot. */
  ip_verification_enabled: boolean
  /** IP group whose ranges are treated as verified crawler networks. */
  verified_ip_group_id: string | null
  /** Verify known crawler user agents by DNS reverse + forward lookups. */
  dns_verification_enabled: boolean
  updated_at: string
}

export type UpdateBotRequest = Partial<
  Pick<
    BotConfig,
    | 'enabled'
    | 'ua_analysis'
    | 'action'
    | 'known_bots_whitelist'
    | 'ip_verification_enabled'
    | 'verified_ip_group_id'
    | 'dns_verification_enabled'
  >
>

/* ── Geo restrictions ─────────────────────────────────────────────── */

export type GeoMode = 'block_list' | 'allow_list'

export const GEO_MODES: GeoMode[] = ['block_list', 'allow_list']

export type GeoAction =
  | 'block'
  | 'challenge'
  | 'js_challenge'
  /** Requires the site's basic auth credentials for the matched countries. */
  | 'basic_auth'

export const GEO_ACTIONS: GeoAction[] = [
  'block',
  'challenge',
  'js_challenge',
  'basic_auth',
]

export interface GeoConfig {
  site_id: string
  enabled: boolean
  /** `block_list` = deny listed countries, `allow_list` = deny everything except listed. */
  mode: GeoMode | string
  countries: string[]
  /** ASN numbers, optionally prefixed with `AS` (e.g. `AS13335`). */
  blocked_asns: string[]
  block_unknown: boolean
  action: GeoAction | string
}

export type UpdateGeoRequest = Partial<Omit<GeoConfig, 'site_id'>>

/* ── Basic authentication ─────────────────────────────────────────── */

/** One accepted credential. Passwords are masked with `***` in responses. */
export interface BasicAuthCredential {
  username: string
  password: string
}

export interface SiteBasicAuth {
  id: string
  site_id: string
  /** Gate every request of the site, not just the ones an access rule marks. */
  enabled: boolean
  /** Realm advertised in the `WWW-Authenticate` challenge. */
  realm: string
  credentials: BasicAuthCredential[]
  /** Seconds a failed attempt is delayed before the 401 is sent (0..10). */
  delay_seconds: number
  /** Strip the `Authorization` header once a request is authenticated. */
  hide_credentials: boolean
  created_at: string
  updated_at: string
}

export type UpdateBasicAuthRequest = Partial<
  Pick<
    SiteBasicAuth,
    | 'enabled'
    | 'realm'
    | 'credentials'
    | 'delay_seconds'
    | 'hide_credentials'
  >
>

/** Password sent back to keep the stored one unchanged. */
export const BASIC_AUTH_SECRET_MASK = '***'
/** Bounds mirrored from the control plane. */
export const BASIC_AUTH_MIN_DELAY_SECONDS = 0
export const BASIC_AUTH_MAX_DELAY_SECONDS = 10

export interface GeoCountryStat {
  country_code: string
  requests: number
}

/* ── Traffic analytics (site-scoped) ──────────────────────────────── */

/** Preset windows offered by the traffic page time-range selector. */
export type TrafficRange = '1h' | '6h' | '24h' | '7d' | '30d'

export const TRAFFIC_RANGES: TrafficRange[] = ['1h', '6h', '24h', '7d', '30d']

/** Everything the traffic page needs, resolved in one fan-out. */
export interface TrafficOverview {
  summary: AnalyticsSummary
  series: TimeBucket[]
  egress: TrafficSeries
  topPaths: TopPath[]
  topIps: TopIp[]
  topRules: TopRule[]
  statusCodes: StatusCodeCount[]
}

/* ── IP groups (blacklist / whitelist) ────────────────────────────── */

export type IpGroupAction = 'block' | 'allow'

export const IP_GROUP_ACTIONS: IpGroupAction[] = ['block', 'allow']

export interface IpGroup {
  id: string
  name: string
  description: string | null
  ip_ranges: string[]
  action: IpGroupAction | string
  is_global: boolean
  /** `builtin` (compiled-in snapshot), `url` (operator source), null = manual. */
  subscription_kind: 'builtin' | 'url' | null
  /** Whether the sync scheduler refreshes this group's subscription. */
  subscription_enabled: boolean
  source_url: string | null
  sync_interval_minutes: number | null
  last_synced_at: string | null
  /** Why the most recent subscription sync failed; null when it succeeded. */
  last_sync_error: string | null
  enabled: boolean
  created_at: string
  updated_at: string
}

/** Returned by list/show endpoints — flat model fields plus the associated site count. */
export interface IpGroupResponse extends IpGroup {
  site_count: number
}

export interface CreateIpGroupRequest {
  name: string
  description?: string | null
  ip_ranges: string[]
  action?: IpGroupAction | string
  is_global?: boolean
  source_url?: string | null
  sync_interval_minutes?: number | null
  enabled?: boolean
  subscription_enabled?: boolean
}

export type UpdateIpGroupRequest = Partial<CreateIpGroupRequest>

export interface IpGroupListQuery extends PaginationQuery {
  action?: string
  is_global?: boolean
  enabled?: boolean
}

/* ── AI assistant ─────────────────────────────────────────────────── */

/** `api::ai::AiSettingsView` — the API key comes back masked as `***`. */
export interface AiSettings {
  enabled: boolean
  base_url: string
  /** `***` when a key is stored, empty when none is. */
  api_key: string
  model: string
  /** The prompt in effect: the stored override, or the built-in default. */
  system_prompt: string
  temperature: number
  max_tool_rounds: number
  allow_write_tools: boolean
  updated_at: string
}

/** `api::ai::AiSettingsUpdate` — absent fields keep their stored value. */
export interface UpdateAiSettingsRequest {
  enabled?: boolean
  base_url?: string
  /** `null` keeps the stored key (the mask round-trip); `''` clears it. */
  api_key?: string | null
  model?: string
  /** Omitted keeps the stored override; `''` clears it (default applies). */
  system_prompt?: string
  temperature?: number
  max_tool_rounds?: number
  allow_write_tools?: boolean
}

/** `api::ai::AiTestResult` */
export interface AiTestResult {
  ok: boolean
  model: string
  reply?: string | null
  error?: string | null
}

/** `api::ai::ConversationSummary` */
export interface AiConversation {
  id: string
  /** Empty until the first message names the conversation. */
  title: string
  created_at: string
  updated_at: string
}

/** One entry of an assistant message's stored `tool_calls` array. */
export interface AiToolCallWire {
  id: string
  type: string
  function: { name: string; arguments: string }
}

/** `api::ai::MessageView` */
export interface AiMessage {
  id: string
  role: 'user' | 'assistant' | 'tool' | string
  content: string
  tool_calls?: AiToolCallWire[] | null
  tool_call_id?: string | null
  tool_name?: string | null
  created_at: string
}

/** `api::ai::ConversationDetail` */
export interface AiConversationDetail {
  id: string
  title: string
  created_at: string
  updated_at: string
  messages: AiMessage[]
}

/** One event of a chat turn (`ai::agent::ChatEvent`, SSE `data:` payloads). */
export type AiChatEvent =
  | { type: 'conversation'; id: string; title: string }
  | { type: 'delta'; text: string }
  | { type: 'tool_call'; id: string; name: string; arguments: unknown }
  | {
      type: 'tool_result'
      id: string
      name: string
      result: unknown
      is_error: boolean
    }
  | { type: 'done'; content: string }
  | { type: 'error'; message: string }

/* ── MCP server ───────────────────────────────────────────────────── */

/** `api::mcp::McpToolInfo` — one tool the hosted MCP endpoint exposes. */
export interface McpToolInfo {
  name: string
  write: boolean
}

/** `api::mcp::McpStatusView` — `GET /settings/mcp`. */
export interface McpStatus {
  path: string
  transport: string
  tools: McpToolInfo[]
  prompts: number
  resources: number
}

/* ── AI crawl control ─────────────────────────────────────────────── */

/** Per-family enforcement action. */
export type AiCrawlAction = 'allow' | 'monitor' | 'block'

/** Actions the family dropdown offers; `inherit` follows `default_action`. */
export type AiCrawlPolicyAction = 'inherit' | AiCrawlAction

export const AI_CRAWL_ACTIONS: AiCrawlAction[] = ['allow', 'monitor', 'block']
export const AI_CRAWL_POLICY_ACTIONS: AiCrawlPolicyAction[] = [
  'inherit',
  'allow',
  'monitor',
  'block',
]

/** Crawler families the data plane recognises (`GET /ai-crawl/catalog`). */
export interface AiBotCatalogEntry {
  id: string
  operator: string
  name: string
  /** `training` | `search` | `agent` | `other`. */
  category: string
  /** Case-insensitive User-Agent substrings identifying the family. */
  ua_substrings: string[]
}

/** One per-family override stored with the site settings. */
export interface AiBotPolicySetting {
  bot_id: string
  action: AiCrawlAction | string
}

/** `GET /sites/{siteId}/ai-crawl` — the site's AI crawl posture. */
export interface AiCrawlSettings {
  enabled: boolean
  default_action: AiCrawlAction | string
  /** `off` | `generate` — whether robots.txt / llms.txt are served. */
  robots_mode: string
  /** Custom body; empty means the template generator applies. */
  robots_body: string
  llms_mode: string
  llms_body: string
  /** Append the site's routes to the generated llms.txt. */
  llms_include_routes: boolean
  /** Cache-Control max-age for the generated files (0..86400). */
  cache_max_age: number
  content_signal_search: boolean
  content_signal_ai_train: boolean
  content_signal_ai_input: boolean
  policies: AiBotPolicySetting[]
}

/** `PUT /sites/{siteId}/ai-crawl` — every field optional; `policies` present
 * replaces the whole list (entries the caller omits fall back to inherit). */
export type UpdateAiCrawlSettingsRequest = Partial<
  Omit<AiCrawlSettings, 'policies'> & { policies?: AiBotPolicySetting[] }
>

/** `GET /sites/{siteId}/ai-crawl/preview?file=robots|llms` */
export interface AiCrawlPreview {
  mode: string
  content_type: string
  body: string
}

/** One family row of `/analytics/ai-crawlers`. */
export interface AiCrawlerRow {
  bot_id: string
  name: string
  category: string
  requests: number
  blocked: number
  last_seen: string | null
}

/* ── OIDC: identity providers and per-site gates ──────────────────── */

/**
 * An identity provider — `/api/v1/oidc/providers`.
 *
 * Provider credentials belong to the deployment, not to a site: one Keycloak
 * realm usually fronts several, so the client secret is stored once and sites
 * reference it. Managed from the Account page.
 */
export interface OidcProvider {
  id: string
  /** Unique display name, shown in the site's provider picker. */
  name: string
  /** A disabled provider cannot be selected by a site. */
  enabled: boolean
  /** Absolute http(s) URL, no trailing slash. */
  issuer: string
  client_id: string
  /** `'***'` when a secret is stored; `''` when none is. */
  client_secret: string
  scopes: string[]
  /** Sites whose gate points here, so a delete can say what it would affect. */
  site_count: number
  created_at: string
  updated_at: string
}

export interface CreateOidcProviderRequest {
  name: string
  enabled?: boolean
  issuer: string
  client_id: string
  client_secret?: string
  scopes?: string[]
}

export type UpdateOidcProviderRequest = Partial<CreateOidcProviderRequest>

/** One ID-token claim forwarded to the origin as a request header. */
export interface OidcHeaderClaim {
  claim: string
  header: string
}

/** How an access rule holds a claim against a value. */
export type OidcAccessOperator = 'eq' | 'ne' | 'contains' | 'in' | 'exists'

/** Every operator, for the rule editor's picker. */
export const OIDC_ACCESS_OPERATORS: OidcAccessOperator[] = [
  'eq',
  'ne',
  'contains',
  'in',
  'exists',
]

/** One access rule: a claim, how to hold it, and what to hold it against. */
export interface OidcAccessRule {
  claim: string
  operator: OidcAccessOperator
  /** Unused by `exists`; the API stores it empty there. */
  value: string
}

/** What a site does with a signed-in visitor who is not in the rules. */
/**
 * How a visitor signs in at a site.
 *
 * `access_mode` decides who may enter once signed in; this decides how they
 * sign in at all. `oidc` is the default and the pre-local-accounts behaviour,
 * so a site that never touches this keeps working as it did.
 */
export type OidcAuthMode = 'oidc' | 'local' | 'both'

export const OIDC_AUTH_MODES: OidcAuthMode[] = ['oidc', 'local', 'both']

export type OidcAccessMode = 'allow_all' | 'require_any' | 'require_all'

export const OIDC_ACCESS_MODES: OidcAccessMode[] = [
  'allow_all',
  'require_any',
  'require_all',
]

/**
 * Per-site OpenID Connect sign-in — `/api/v1/sites/{siteId}/oidc`.
 *
 * The provider's credentials are not here: a site points at one with
 * `provider_id` and carries only what differs per site.
 */
export interface SiteOidc {
  id: string
  site_id: string
  enabled: boolean
  /** The provider this site authenticates against; `null` = not chosen. */
  provider_id: string | null
  /** Its display name, so the picker needs no second request. */
  provider_name: string | null
  /** `'***'` when a secret is stored; `''` when none is. */
  cookie_secret: string
  redirect_path: string
  /** `''` = no logout endpoint. */
  logout_path: string
  /** `''` = derived from the request Host. */
  redirect_url: string
  cookie_name: string
  session_ttl_seconds: number
  claims_to_headers: OidcHeaderClaim[]
  auth_mode: OidcAuthMode
  access_mode: OidcAccessMode
  access_rules: OidcAccessRule[]
  created_at: string
  updated_at: string
}

/**
 * The `PUT` payload.
 *
 * `provider_id` is `string | null` rather than optional-and-nullable because
 * the two mean different things: omitting the key keeps the stored provider,
 * `null` clears it. The API reads them apart.
 */
export type UpdateOidcRequest = Partial<
  Pick<
    SiteOidc,
    | 'enabled'
    | 'cookie_secret'
    | 'redirect_path'
    | 'logout_path'
    | 'redirect_url'
    | 'cookie_name'
    | 'session_ttl_seconds'
    | 'claims_to_headers'
    | 'auth_mode'
    | 'access_mode'
    | 'access_rules'
  >
> & {
  provider_id?: string | null
}

/** Secret sent back to keep the stored one unchanged. */
export const OIDC_SECRET_MASK = '***'
/** Defaults and bounds mirrored from the control plane. */
export const OIDC_DEFAULT_REDIRECT_PATH = '/oauth2/callback'
export const OIDC_DEFAULT_COOKIE_NAME = 'pingap_oidc'
export const OIDC_DEFAULT_SESSION_TTL_SECONDS = 43200
export const OIDC_MIN_SESSION_TTL_SECONDS = 60
export const OIDC_MAX_SESSION_TTL_SECONDS = 31536000
export const OIDC_MIN_COOKIE_SECRET_LENGTH = 16
export const OIDC_MAX_PROVIDER_NAME_LENGTH = 128
export const OIDC_MAX_ACCESS_RULES = 32
/** `scopes` always contains `openid`; the control plane adds it. */
export const OIDC_ALWAYS_SCOPE = 'openid'

/** `GET /analytics/ai-crawlers` — AI crawler traffic overview. */
export interface AiCrawlerOverview {
  requests: number
  blocked: number
  /** Fraction of all requests in the window (0..1). */
  share: number
  families: number
  rows: AiCrawlerRow[]
}



/* ── Visitor accounts ─────────────────────────────────────────────── */

/**
 * A person a protected site admits — `/api/v1/visitors`.
 *
 * Distinct from a console operator: a visitor signs in at the site's own login
 * page and never reaches this console. `site_ids` is the set of sites they may
 * enter; only granted sites are reachable after signing in.
 */
export interface Visitor {
  id: string
  email: string
  name: string
  /** Operator-only note for recognising the account; never sent to the data plane. */
  remark: string
  disabled: boolean
  site_ids: string[]
  created_at: string
  updated_at: string
}

export interface CreateVisitorRequest {
  email: string
  password: string
  name?: string
  remark?: string
  disabled?: boolean
  site_ids?: string[]
}

export interface UpdateVisitorRequest {
  name?: string
  /** Empty clears the note; omitted preserves it. */
  remark?: string
  disabled?: boolean
  /** Absent leaves the stored password. */
  password?: string
  /** Replaces the whole grant list when present. */
  site_ids?: string[]
}
