/**
 * Deterministic demo data for the console screenshots.
 *
 * Field names follow `web/src/api/types.ts` exactly; values use the reserved
 * documentation domain (`example.com`) and RFC 5737 ranges, so nothing here
 * resembles production traffic.
 */

const SITE_ID = "site_demo0001";

/**
 * Timestamps are relative to the capture run so the console shows "just now"
 * instead of a stale date from whenever this fixture was written.
 */
const now = Date.now();
const ago = (seconds) => new Date(now - seconds * 1000).toISOString();
const hourBuckets = (count) =>
  Array.from({ length: count }, (_, index) => new Date(now - (count - 1 - index) * 3600_000).toISOString());

const user = {
  id: "usr_demo0001",
  email: "admin@example.com",
  name: "Demo Admin",
  role: "admin",
  must_change_password: false,
  disabled: false,
  created_at: "2025-01-06T08:00:00Z",
  updated_at: "2026-02-11T09:30:00Z",
  last_login_at: "2026-02-11T09:30:00Z",
  last_login_ip: "203.0.113.7",
};

const site = {
  id: SITE_ID,
  name: "Example Site",
  domain: "example.com",
  alternate_domains: ["www.example.com"],
  status: "active",
  plan: "pro",
  cache_quota_mb: 10240,
  cache_max_file_size_mb: 64,
  cache_type_limits_mb: null,
  trust_proxy_headers: true,
  trusted_header: "x-forwarded-for",
  trust_last_hop: true,
  trusted_proxy_ranges: ["192.0.2.0/24"],
  trusted_proxy_group_ids: [],
  origin_verify_cert: null,
  downstream_timeout_secs: 60,
  response_replace: null,
  user_id: user.id,
  created_at: "2025-11-02T10:00:00Z",
  updated_at: "2026-02-11T09:00:00Z",
};

const agent = {
  id: "agt_demo0001",
  site_id: SITE_ID,
  site_domain: "example.com",
  hostname: "edge-fra-01",
  ip_address: "192.0.2.10",
  public_ip: "203.0.113.7",
  private_ip: "198.51.100.20",
  version: "0.30.2",
  os_info: "Debian 12",
  cpu_cores: 8,
  total_memory_bytes: 17179869184,
  used_memory_bytes: 8589934592,
  memory_bytes: 8589934592,
  status: "online",
  api_key_id: "key_demo0001",
  config_hash: "9f2c1b",
  last_heartbeat: ago(22),
  registered_at: ago(60 * 86400),
  last_config_sync_at: ago(240),
  last_policy_sync_at: ago(235),
  connected: true,
  pending_commands: 0,
  grpc_tls: true,
};

const agentTwo = {
  ...agent,
  id: "agt_demo0002",
  hostname: "edge-sin-02",
  ip_address: "198.51.100.31",
  public_ip: "203.0.113.19",
  private_ip: "198.51.100.32",
  version: "0.30.2",
  status: "degraded",
  last_heartbeat: ago(95),
};

const ssl = {
  id: "cert_demo0001",
  site_id: SITE_ID,
  domain: "example.com",
  issuer: "Let's Encrypt",
  not_before: ago(30 * 86400),
  // Certificate shown as healthy: valid for another two months.
  expires_at: ago(-60 * 86400),
  auto_renew: true,
  acme_email: "ops@example.com",
  acme_challenge_type: "http-01",
  acme_dns_provider: null,
  acme_dns_config: null,
  status: "active",
  failure_reason: null,
  has_certificate: true,
  has_private_key: true,
  warnings: [],
  created_at: ago(30 * 86400),
  updated_at: ago(3600),
};

const page = (items, total = items.length) => ({
  items,
  total,
  page: 1,
  page_size: 200,
});

const analytics = {
  summary: {
    from: "2026-02-10T09:00:00.000Z",
    to: "2026-02-11T09:00:00.000Z",
    site_id: null,
    requests: 184320,
    unique_ips: 7421,
    cache_hits: 120455,
    cache_hit_rate: 0.6535,
    cache_saved_bytes: 8812345678,
    avg_latency_ms: 42.7,
    max_latency_ms: 1840,
    client_errors: 2310,
    server_errors: 187,
    security_events: 964,
    blocked_requests: 1288,
    distinct_attackers: 213,
    rules_triggered: 512,
  },
  requestsOverTime: Array.from({ length: 24 }, (_, hour) => ({
    bucket: hourBuckets(24)[hour],
    requests: 5200 + ((hour * 977) % 2800),
    cache_hits: 3400 + ((hour * 613) % 1900),
    cache_saved_bytes: 300000000 + hour * 1200000,
    client_errors: 40 + ((hour * 13) % 60),
    server_errors: (hour * 3) % 11,
    avg_latency_ms: 38 + ((hour * 7) % 14),
    blocked: 30 + ((hour * 11) % 45),
  })),
  traffic: {
    from: "2026-02-10T09:00:00.000Z",
    to: "2026-02-11T09:00:00.000Z",
    site_id: null,
    step_seconds: 3600,
    total_bytes: 1845493760,
    buckets: Array.from({ length: 24 }, (_, hour) => ({
      bucket: hourBuckets(24)[hour],
      bytes: 58000000 + hour * 2100000,
    })),
  },
  topIps: [
    { client_ip: "192.0.2.10", country_code: "US", requests: 4210, blocked: 118 },
    { client_ip: "198.51.100.20", country_code: "DE", requests: 3115, blocked: 84 },
    { client_ip: "203.0.113.42", country_code: "SG", requests: 2740, blocked: 361 },
    { client_ip: "192.0.2.88", country_code: "BR", requests: 1980, blocked: 22 },
    { client_ip: "198.51.100.77", country_code: "FR", requests: 1640, blocked: 9 },
  ],
  topRules: [
    { rule_id: "942100", rule_name: "SQL Injection Attack Detected", action: "block", hits: 214, unique_ips: 37 },
    { rule_id: "941100", rule_name: "XSS Attack Detected", action: "block", hits: 163, unique_ips: 29 },
    { rule_id: "930110", rule_name: "Path Traversal", action: "block", hits: 96, unique_ips: 18 },
    { rule_id: "PINGWAF-1020", rule_name: "Scanner user agent", action: "challenge", hits: 71, unique_ips: 12 },
  ],
  sitesOverTime: Array.from({ length: 24 }, (_, hour) => ({
    bucket: hourBuckets(24)[hour],
    site_id: SITE_ID,
    site_domain: "example.com",
    site_name: "Example Site",
    requests: 5200 + ((hour * 977) % 2800),
  })),
  topPaths: [
    { path: "/", requests: 41200, cache_hits: 37100, avg_latency_ms: 2.4 },
    { path: "/assets/app.js", requests: 28400, cache_hits: 27600, avg_latency_ms: 1.8 },
    { path: "/api/catalog", requests: 12900, cache_hits: 0, avg_latency_ms: 64.2 },
    { path: "/login", requests: 6100, cache_hits: 0, avg_latency_ms: 58.7 },
  ],
  statusCodes: [
    { status_code: 200, requests: 171000 },
    { status_code: 301, requests: 620 },
    { status_code: 403, requests: 1288 },
    { status_code: 404, requests: 1480 },
    { status_code: 502, requests: 63 },
  ],
  activeVisitors: { active_visitors: 412, window_minutes: 5, as_of: "2026-02-11T09:00:00Z" },
  clientTypes: {
    desktop: 118400,
    mobile: 61200,
    other: 4720,
    total: 184320,
    desktop_share: 0.6424,
    mobile_share: 0.3321,
    other_share: 0.0256,
  },
  sitesOverview: { sites: [{ ...site, requests: 184320, blocked: 1288 }], truncated: false },
};

const group = {
  id: "grp_demo0001",
  name: "Office allowlist",
  description: "corporate egress ranges",
  ip_ranges: ["192.0.2.0/24", "198.51.100.0/24"],
  action: "allow",
  is_global: true,
  subscription_kind: null,
  subscription_enabled: false,
  source_url: null,
  sync_interval_minutes: null,
  last_synced_at: null,
  last_sync_error: null,
  enabled: true,
  created_at: "2025-12-01T00:00:00Z",
  updated_at: "2026-01-09T00:00:00Z",
  site_count: 1,
};

const wafSettings = {
  id: "waf_demo0001",
  site_id: SITE_ID,
  waf_enabled: true,
  mode: "block",
  paranoia_level: 2,
  advanced_mode: true,
  body_stage_timeout_secs: 30,
  monitor_categories: ["xxe"],
  monitor_stacks: ["php"],
  monitor_managed_rules: [],
  created_at: "2025-11-02T10:00:00Z",
  updated_at: "2026-02-10T12:00:00Z",
};

const wafPosture = {
  engine: "on",
  detection: { managed: true, custom: true, deep_inspection: true, under_attack: false },
  enforcement: {
    mode: "block",
    managed: { sqli: "block", xss: "block", rce: "block" },
    custom_rules: "block",
    cc: "challenge",
    bot: "challenge",
    observation_mode: false,
  },
};

const challenge = {
  enabled: true,
  under_attack_mode: false,
  default_level: "non_interactive",
  clearance_duration_secs: 1800,
  rate_threshold: 100,
  exempt_paths: ["/api/health", "/ping"],
  browser_integrity_check: true,
  tls_fingerprint_check: false,
};

const managedRules = [
  { id: "942100", name: "SQL Injection Attack Detected", action: "block", severity: 3, tags: ["OWASP_CRS", "sqli"], stacks: ["php", "java"], category: "sqli", strict_only: false },
  { id: "941100", name: "XSS Attack Detected", action: "block", severity: 3, tags: ["OWASP_CRS", "xss"], stacks: ["php"], category: "xss", strict_only: false },
  { id: "930110", name: "Path Traversal Attack", action: "block", severity: 3, tags: ["OWASP_CRS", "traversal"], stacks: [], category: "traversal", strict_only: false },
  { id: "PINGWAF-1020", name: "Known scanner user agent", action: "challenge", severity: 2, tags: ["bot"], stacks: [], category: "scanner", strict_only: false },
];

const rules = page([
  {
    id: "rule_demo0001",
    group_id: "rg_demo0001",
    site_id: SITE_ID,
    name: "Block wp-login probing",
    description: "path based rule",
    expression: 'http.request.uri.path contains "/wp-login.php"',
    action: "block",
    severity: 3,
    tags: ["custom"],
    enabled: true,
    mode: "block",
    priority: 10,
    created_at: "2025-12-02T00:00:00Z",
    updated_at: "2026-01-04T00:00:00Z",
  },
  {
    id: "rule_demo0002",
    group_id: "rg_demo0001",
    site_id: SITE_ID,
    name: "Admin paths outside the office",
    description: "geo aware",
    expression: 'http.request.uri.path starts_with "/admin" and not ip.src in {192.0.2.0/24}',
    action: "challenge",
    severity: 2,
    tags: ["custom", "admin"],
    enabled: true,
    mode: "block",
    priority: 20,
    created_at: "2025-12-06T00:00:00Z",
    updated_at: "2026-01-06T00:00:00Z",
  },
], 2);

const ruleGroups = page([
  {
    id: "rg_demo0001",
    site_id: SITE_ID,
    name: "OWASP basics",
    phase: "request",
    priority: 100,
    enabled: true,
    created_at: "2025-11-02T10:00:00Z",
    updated_at: "2026-01-02T00:00:00Z",
  },
], 1);

const rateLimitRules = page([
  {
    id: "rl_demo0001",
    site_id: SITE_ID,
    name: "login brute force",
    expression: 'http.request.uri.path eq "/login"',
    characteristics: ["ip"],
    period_seconds: 60,
    threshold: 20,
    action: "block",
    mitigation_timeout_seconds: 600,
    enabled: true,
    priority: 50,
    created_at: "2025-12-05T00:00:00Z",
    updated_at: "2026-01-05T00:00:00Z",
  },
  {
    id: "rl_demo0002",
    site_id: SITE_ID,
    name: "catalog scraping",
    expression: 'http.request.uri.path starts_with "/api/catalog"',
    characteristics: ["ip", "header:x-api-key"],
    period_seconds: 60,
    threshold: 120,
    action: "js_challenge",
    mitigation_timeout_seconds: 300,
    enabled: true,
    priority: 60,
    created_at: "2025-12-08T00:00:00Z",
    updated_at: "2026-01-08T00:00:00Z",
  },
], 2);

const botConfig = {
  id: "bot_demo0001",
  site_id: SITE_ID,
  enabled: true,
  ua_analysis: true,
  js_detection: true,
  tls_fingerprint: false,
  behavioral_analysis: false,
  action: "challenge",
  known_bots_whitelist: ["Googlebot", "bingbot"],
  ip_verification_enabled: true,
  verified_ip_group_id: "grp_demo0001",
  dns_verification_enabled: false,
  updated_at: "2026-02-09T08:00:00Z",
};

const aiCrawlSettings = {
  enabled: true,
  default_action: "monitor",
  robots_mode: "generate",
  robots_body: "",
  llms_mode: "generate",
  llms_body: "",
  llms_include_routes: true,
  cache_max_age: 3600,
  content_signal_search: true,
  content_signal_ai_train: false,
  content_signal_ai_input: true,
  policies: [
    { bot_id: "gptbot", action: "block" },
    { bot_id: "claude-bot", action: "monitor" },
  ],
};

const aiCatalog = [
  { id: "gptbot", operator: "OpenAI", name: "GPTBot", category: "training", ua_substrings: ["GPTBot"] },
  { id: "claude-bot", operator: "Anthropic", name: "ClaudeBot", category: "training", ua_substrings: ["ClaudeBot"] },
  { id: "perplexitybot", operator: "Perplexity", name: "PerplexityBot", category: "search", ua_substrings: ["PerplexityBot"] },
];

const ipRules = page([
  {
    id: "ipr_demo0001",
    site_id: SITE_ID,
    name: "Block scanner range",
    ip_ranges: ["203.0.113.0/24"],
    group_id: null,
    group_name: null,
    action: "block",
    note: "observed credential stuffing",
    enabled: true,
    priority: 10,
    created_at: "2025-12-10T00:00:00Z",
    updated_at: "2026-01-10T00:00:00Z",
  },
  {
    id: "ipr_demo0002",
    site_id: SITE_ID,
    name: "Office allowlist",
    ip_ranges: ["192.0.2.0/24", "198.51.100.0/24"],
    group_id: "grp_demo0001",
    group_name: "Office allowlist",
    action: "allow",
    note: null,
    enabled: true,
    priority: 5,
    created_at: "2025-12-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
], 2);

const geo = {
  site_id: SITE_ID,
  enabled: true,
  mode: "block_list",
  countries: ["KP", "SY"],
  blocked_asns: ["AS64512"],
  block_unknown: false,
  action: "block",
};

const geoStats = [
  { country_code: "US", requests: 121400 },
  { country_code: "DE", requests: 18300 },
  { country_code: "SG", requests: 11200 },
  { country_code: "BR", requests: 6400 },
];

const cacheSettings = {
  site_id: SITE_ID,
  quota_mb: 10240,
  max_file_size_mb: 64,
  type_limits: { image: 8 },
  cache_type_policy: null,
  global_max_file_size_mb: 128,
  effective_max_file_size_mb: 64,
  cache_enabled: true,
  rule_count: 6,
  enabled_rule_count: 5,
};

const cacheRules = page([
  {
    id: "cr_demo0001",
    site_id: SITE_ID,
    name: "static assets",
    match_expression: 'http.request.uri.path matches "^/assets/"',
    edge_ttl_seconds: 86400,
    browser_ttl_seconds: 3600,
    cache_eligible: true,
    respect_origin: false,
    enabled: true,
    created_at: "2025-11-03T00:00:00Z",
  },
  {
    id: "cr_demo0002",
    site_id: SITE_ID,
    name: "catalog api",
    match_expression: 'http.request.uri.path starts_with "/api/catalog"',
    edge_ttl_seconds: 120,
    browser_ttl_seconds: 0,
    cache_eligible: true,
    respect_origin: true,
    enabled: true,
    created_at: "2025-11-04T00:00:00Z",
  },
], 2);

const cacheStatus = {
  site_id: SITE_ID,
  domain: "example.com",
  configured_quota_mb: 10240,
  enabled_rule_count: 5,
  reporting_edges: 2,
  disk_bytes: 3221225472,
  quota_bytes_per_edge: 10737418240,
  quota_bytes_total: 21474836480,
  items: 18234,
  evictions_total: 415,
  usage_percent: 15,
  last_reported_at: ago(45),
};

const sslSettings = {
  https_enabled: true,
  min_tls_version: "1.2",
  max_tls_version: "1.3",
  self_signed: false,
  certificate_id: "cert_demo0001",
  mtls_enabled: false,
  has_mtls_client_ca: false,
  mtls_organization: null,
  mtls_require_client_cert: false,
  hsts_enabled: true,
  hsts_max_age: 15552000,
  always_use_https: true,
  http1_enabled: true,
  http2_enabled: true,
};

const securityEvents = page([
  {
    id: 9001,
    site_id: SITE_ID,
    agent_id: agent.id,
    request_id: "req-7f3c9a01",
    timestamp: ago(72),
    client_ip: "192.0.2.10",
    method: "POST",
    host: "example.com",
    path: "/login",
    rule_id: "942100",
    rule_name: "SQL Injection Attack Detected",
    event_type: "managed",
    action: "block",
    score: 5,
    waf_details: "ARGS:id=1' OR '1'='1",
    country_code: "US",
    user_agent: "Mozilla/5.0 (compatible; DemoAgent/1.0)",
    user_identity: null,
    created_at: ago(72),
  },
  {
    id: 9000,
    site_id: SITE_ID,
    agent_id: agent.id,
    request_id: "req-7f3c9a00",
    timestamp: ago(150),
    client_ip: "203.0.113.42",
    method: "GET",
    host: "example.com",
    path: "/admin/config",
    rule_id: "PINGWAF-1010",
    rule_name: "Admin path probing",
    event_type: "custom",
    action: "challenge",
    score: 3,
    waf_details: "PATH=/admin/config",
    country_code: "SG",
    user_agent: "Mozilla/5.0 (compatible; DemoAgent/1.0)",
    user_identity: null,
    created_at: ago(150),
  },
], 964);

const accessLogs = page([
  {
    id: 51001,
    site_id: SITE_ID,
    agent_id: agent.id,
    request_id: "req-7f3c9a01",
    timestamp: ago(75),
    client_ip: "198.51.100.20",
    method: "GET",
    host: "example.com",
    path: "/index.html",
    query_string: "",
    status_code: 200,
    response_size: 18234,
    upstream_addr: "origin.example.com:8443",
    upstream_latency_ms: 38,
    total_latency_ms: 41,
    cache_status: "HIT",
    user_agent: "Mozilla/5.0 (compatible; DemoAgent/1.0)",
    referer: null,
    country_code: "US",
    tls_version: "TLSv1.3",
    user_identity: null,
    request_body_size: 0,
    request_body_truncated: false,
    scheme: "https",
    protocol: "HTTP/2.0",
    response_body_size: 18234,
    response_body_truncated: false,
  },
  {
    id: 51000,
    site_id: SITE_ID,
    agent_id: agent.id,
    request_id: "req-7f3c99ff",
    timestamp: ago(78),
    client_ip: "192.0.2.10",
    method: "GET",
    host: "example.com",
    path: "/api/catalog",
    query_string: "page=2",
    status_code: 403,
    response_size: 412,
    upstream_addr: "origin.example.com:8443",
    upstream_latency_ms: 0,
    total_latency_ms: 3,
    cache_status: "BYPASS",
    user_agent: "Mozilla/5.0 (compatible; DemoAgent/1.0)",
    referer: null,
    country_code: "US",
    tls_version: "TLSv1.3",
    user_identity: null,
    request_body_size: 0,
    request_body_truncated: false,
    scheme: "https",
    protocol: "HTTP/2.0",
    response_body_size: 412,
    response_body_truncated: false,
  },
], 184320);

const configVersions = [
  {
    id: 4021,
    scope: "site",
    site_id: SITE_ID,
    site_domain: "example.com",
    config_hash: "4b7d2e9a1c",
    source: "api",
    actor: "admin@example.com",
    summary: { site_rules: 12, cache_rules: 6, rate_limit_rules: 2 },
    created_at: ago(310),
  },
  {
    id: 4020,
    scope: "site",
    site_id: SITE_ID,
    site_domain: "example.com",
    config_hash: "9c1a7f0e2b",
    source: "cli",
    actor: "ci@pipeline.example.com",
    summary: { site_rules: 11, cache_rules: 6, rate_limit_rules: 2 },
    created_at: ago(54_000),
  },
  {
    id: 4019,
    scope: "global",
    site_id: null,
    site_domain: null,
    config_hash: "0d5e8b3c77",
    source: "rollback",
    actor: "admin@example.com",
    summary: { settings: 3 },
    created_at: ago(86_000),
  },
];

const mtlsCas = [
  {
    id: "ca_demo0001",
    site_id: SITE_ID,
    name: "Partner client CA",
    source: "generated",
    cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB…demo…\n-----END CERTIFICATE-----",
    has_private_key: true,
    subject_dn: "CN=PingWAF partner clients, O=Example Corp",
    serial: "4F:2A:9C:1D:00:11",
    fingerprint_sha256: "9C:1F:4E:2B:7A:88:03:DF:61:55:0E:9A:24:B7:1C:38",
    expected_organization: "Example Corp",
    not_before: ago(90 * 86400),
    not_after: ago(-275 * 86400),
    is_active: true,
    created_at: ago(90 * 86400),
    certificate_count: 2,
  },
];

const mtlsCerts = [
  {
    id: "mcert_demo0001",
    site_id: SITE_ID,
    ca_id: "ca_demo0001",
    ca_name: "Partner client CA",
    name: "acme-sync client",
    common_name: "acme-sync.example.com",
    organization: "Example Corp",
    serial: "7B:11:03:C4:9F:2E",
    fingerprint_sha256: "3A:77:0C:51:E8:22:9B:4D:66:10:F3:8C:07:2A:5E:91",
    cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB…client…\n-----END CERTIFICATE-----",
    has_private_key: false,
    not_before: ago(30 * 86400),
    not_after: ago(-150 * 86400),
    status: "active",
    revoked_at: null,
    revocation_reason: null,
    created_at: ago(30 * 86400),
  },
];

const blockedIps = [
  {
    ip: "203.0.113.42",
    kind: "single",
    reason: "SQL injection (PINGWAF-1001)",
    blocked_at: ago(1800),
    expires_at: ago(-5400),
    agent_count: 2,
    attack_count: 37,
    last_attack_at: ago(120),
  },
  {
    ip: "198.51.100.0/24",
    kind: "cidr",
    reason: "Credential stuffing on /login",
    blocked_at: ago(7200),
    expires_at: null,
    agent_count: 2,
    attack_count: 412,
    last_attack_at: ago(300),
  },
  {
    ip: "192.0.2.77",
    kind: "single",
    reason: "Rate limit exceeded (120 req/min)",
    blocked_at: ago(600),
    expires_at: null,
    agent_count: 1,
    attack_count: 9,
    last_attack_at: ago(90),
  },
];

const backupTargets = [
  {
    id: "tgt_demo0001",
    kind: "s3",
    name: "nightly",
    config: { bucket: "example-backups", region: "eu-central-1", has_credentials: true },
    enabled: true,
    created_at: "2025-12-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
];

const systemMetrics = {
  cpu: { process_cpu_percent: 0.084, host_cpu_percent: 0.213, cores: 8, collected_at_ms: 1770800000000 },
  memory: {
    rss_bytes: 115343360,
    virtual_bytes: 2147483648,
    total_memory_bytes: 17179869184,
    used_memory_bytes: 8589934592,
    rss: "110.0 MiB",
    total_memory: "16.0 GiB",
  },
};

function routes(pathname) {
  // Exact matches first, then prefixes — order matters for `/sites/{id}`.
  if (pathname === "/api/v1/auth/me") return user;
  if (pathname === "/api/v1/auth/status")
    return { needs_setup: false, registration_open: false, passkey_enabled: false };
  if (pathname === "/api/v1/auth/login")
    return {
      access_token: "demo-access-token",
      refresh_token: "demo-refresh-token",
      token_type: "Bearer",
      expires_in: 43200,
      user,
      role: "admin",
    };
  if (pathname === "/api/v1/sites") return page([site], 1);
  if (pathname === `/api/v1/sites/${SITE_ID}`)
    return {
      site,
      upstreams: [
        {
          id: "ups_demo0001",
          site_id: SITE_ID,
          pool_id: "pool_demo0001",
          address: "origin.example.com:8443",
          weight: 100,
          tls: true,
          health_status: "healthy",
          created_at: "2025-11-02T10:05:00Z",
        },
      ],
      ssl,
      rule_count: 12,
      rule_group_count: 3,
      rate_limit_count: 2,
      cache_rule_count: 6,
    };
  if (pathname === `/api/v1/sites/${SITE_ID}/upstream-pools`)
    return [
      {
        id: "pool_demo0001",
        site_id: SITE_ID,
        name: "primary",
        lb_algorithm: "round_robin",
        sni: "origin.example.com",
        verify_cert: true,
        health_check_enabled: true,
        health_check_path: "/healthz",
        health_check_interval_seconds: 10,
        health_check_timeout_ms: 2000,
        health_check_unhealthy_threshold: 3,
        health_check_healthy_threshold: 2,
        address_family: "auto",
        is_default: true,
        created_at: "2025-11-02T10:05:00Z",
        upstreams: [
          {
            id: "ups_demo0001",
            site_id: SITE_ID,
            pool_id: "pool_demo0001",
            address: "origin.example.com:8443",
            weight: 100,
            tls: true,
            health_status: "healthy",
            created_at: "2025-11-02T10:05:00Z",
          },
        ],
      },
    ];
  if (pathname === `/api/v1/sites/${SITE_ID}/upstreams`)
    return [
      {
        id: "ups_demo0001",
        site_id: SITE_ID,
        pool_id: "pool_demo0001",
        address: "origin.example.com:8443",
        weight: 100,
        tls: true,
        health_status: "healthy",
        created_at: "2025-11-02T10:05:00Z",
      },
    ];
  if (pathname === `/api/v1/sites/${SITE_ID}/routes`)
    return [
      {
        id: "rt_demo0001",
        site_id: SITE_ID,
        name: "default",
        match_type: "prefix",
        path: "/",
        priority: null,
        enabled: true,
        pool_id: "pool_demo0001",
        ip_group_id: null,
        strip_prefix: false,
        rewrite_path: null,
        upstream_host: null,
        created_at: "2025-11-02T10:06:00Z",
      },
    ];
  if (pathname === `/api/v1/sites/${SITE_ID}/waf/settings`) return wafSettings;
  if (pathname === `/api/v1/sites/${SITE_ID}/waf/posture`) return wafPosture;
  if (pathname === `/api/v1/sites/${SITE_ID}/challenge`) return challenge;
  if (pathname === `/api/v1/sites/${SITE_ID}/rules`) return rules;
  if (pathname === `/api/v1/sites/${SITE_ID}/rule-groups`) return ruleGroups;
  if (pathname === `/api/v1/sites/${SITE_ID}/rate-limit-rules`) return rateLimitRules;
  if (pathname === `/api/v1/sites/${SITE_ID}/bot-protection`) return botConfig;
  if (pathname === `/api/v1/sites/${SITE_ID}/ai-crawl`) return aiCrawlSettings;
  if (pathname === `/api/v1/sites/${SITE_ID}/ip-rules`) return ipRules;
  if (pathname === `/api/v1/sites/${SITE_ID}/geo`) return geo;
  if (pathname === `/api/v1/sites/${SITE_ID}/geo/stats`) return geoStats;
  if (pathname === `/api/v1/sites/${SITE_ID}/blocked-ips`) return blockedIps;
  if (pathname === `/api/v1/sites/${SITE_ID}/mtls/cas`) return mtlsCas;
  if (pathname === `/api/v1/sites/${SITE_ID}/mtls/certificates`) return mtlsCerts;
  if (pathname === "/api/v1/blocked-ips")
    return blockedIps.map((entry) => ({
      ...entry,
      site_id: SITE_ID,
      site_name: "example.com",
    }));
  if (pathname === `/api/v1/sites/${SITE_ID}/basic-auth`)
    return {
      id: "ba_demo0001",
      site_id: SITE_ID,
      enabled: false,
      realm: "Restricted",
      credentials: [],
      delay_seconds: 1,
      hide_credentials: false,
      created_at: "2025-12-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    };
  if (pathname === `/api/v1/sites/${SITE_ID}/oidc`)
    return {
      id: "oidc_demo0001",
      site_id: SITE_ID,
      enabled: false,
      provider_id: null,
      provider_name: null,
      cookie_secret: "",
      redirect_path: "/oidc/callback",
      logout_path: "",
      redirect_url: "",
      cookie_name: "pw_oidc",
      session_ttl_seconds: 3600,
      claims_to_headers: [],
      auth_mode: "oidc",
      access_mode: "allow_all",
      access_rules: [],
      created_at: "2025-12-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    };
  if (pathname === "/api/v1/oidc/providers") return [];
  if (pathname === `/api/v1/sites/${SITE_ID}/cache-settings`) return cacheSettings;
  if (pathname === `/api/v1/sites/${SITE_ID}/cache-rules`) return cacheRules;
  if (pathname === `/api/v1/cache/status/${SITE_ID}`) return cacheStatus;
  if (pathname === `/api/v1/sites/${SITE_ID}/certificates`) return page([ssl], 1);
  if (pathname === `/api/v1/sites/${SITE_ID}/ssl-settings`) return sslSettings;
  if (pathname === "/api/v1/managed-rules") return managedRules;
  if (pathname === "/api/v1/ip-groups") return page([group], 1);
  if (pathname === "/api/v1/ai-crawl/catalog") return aiCatalog;
  if (pathname === "/api/v1/agents") return page([agent, agentTwo], 2);
  if (pathname === "/api/v1/system/status")
    return { grpc_tls: true, grpc_tls_enabled: true, version: "0.30.2" };
  if (pathname === "/api/v1/version")
    return { version: "0.30.2", commit: "demo", build_time: ago(3600), grpc_tls: true };
  if (pathname === "/api/v1/system/metrics") return systemMetrics;
  if (pathname === "/api/v1/logs/security") return securityEvents;
  if (pathname === "/api/v1/logs/access") return accessLogs;
  if (pathname === "/api/v1/logs/control-plane") return page([], 0);
  if (pathname === "/api/v1/config-versions") return configVersions;
  if (pathname === "/api/v1/config-backup-targets") return backupTargets;
  if (pathname === "/api/v1/config-backups")
    return [
      {
        id: "bkp_demo0001",
        scope: "site",
        site_id: SITE_ID,
        target_id: "tgt_demo0001",
        status: "completed",
        file_name: "pingwaf-example-20261029.sql.gz",
        manifest: { tables: 7 },
        checksum: "sha256:5f2a9c",
        error: "",
        actor: "admin@example.com",
        size_bytes: 482133,
        created_at: ago(3200),
        completed_at: ago(3190),
      },
      {
        id: "bkp_demo0002",
        scope: "global",
        site_id: null,
        target_id: null,
        status: "created",
        file_name: "pingwaf-global-20261028.sql.gz",
        manifest: { tables: 12 },
        checksum: "sha256:1b7e04",
        error: "",
        actor: "ci@pipeline.example.com",
        size_bytes: 912400,
        created_at: ago(90_000),
        completed_at: null,
      },
    ];

  if (pathname === "/api/v1/analytics/summary") return analytics.summary;
  if (pathname === "/api/v1/analytics/requests-over-time") return analytics.requestsOverTime;
  if (pathname === "/api/v1/analytics/traffic") return analytics.traffic;
  if (pathname === "/api/v1/analytics/top-ips") return analytics.topIps;
  if (pathname === "/api/v1/analytics/top-rules") return analytics.topRules;
  if (pathname === "/api/v1/analytics/sites-over-time") return analytics.sitesOverTime;
  if (pathname === "/api/v1/analytics/top-paths") return analytics.topPaths;
  if (pathname === "/api/v1/analytics/status-codes") return analytics.statusCodes;
  if (pathname === "/api/v1/analytics/active-visitors") return analytics.activeVisitors;
  if (pathname === "/api/v1/analytics/client-types") return analytics.clientTypes;
  if (pathname === "/api/v1/analytics/sites") return analytics.sitesOverview;
  if (pathname === "/api/v1/analytics") return analytics.summary;

  // Unknown endpoints must still return JSON (401/404 would log the session
  // out); `grpc_tls` keeps the fleet banner quiet.
  return { grpc_tls: true };
}

export { routes, SITE_ID, user };
