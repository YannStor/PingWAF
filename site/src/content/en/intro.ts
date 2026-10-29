import type { IntroContent } from "../schema";

const intro = {
  meta: {
    title: "PingWAF — Distributed Web Application Firewall on Pingora",
    description:
      "Open-source WAF built on pingap and Cloudflare Pingora: one control plane, many edge agents, semantic attack detection, CC and bot defense, automatic TLS and an embedded console.",
  },
  hero: {
    badges: ["Apache-2.0", "Rust · Pingora", "Self-hosted"],
    title: "Cloudflare-class protection for",
    titleAccent: "infrastructure you own",
    lead: "PingWAF is a distributed, centrally controlled Web Application Firewall. Define sites, rules and policies once in the control plane; every edge agent enforces them within seconds — no reload, no downtime.",
    primary: { label: "Start in 5 minutes", path: "/quickstart/" },
    secondary: { label: "Read the docs", path: "/docs/" },
    stats: [
      { value: "4 phases", label: "Normalize → signatures → expressions → score" },
      { value: "7 RPCs", label: "gRPC control-plane protocol" },
      { value: "5 providers", label: "DNS-01 ACME integrations" },
    ],
    pills: [
      { icon: "shield-check", text: "SQLi · XSS · RCE · traversal" },
      { icon: "refresh", text: "Rules pushed in seconds" },
    ],
    shot: {
      key: "dashboard",
      url: "localhost:9080/dashboard",
      caption: "Traffic, attacks and agent health on the embedded dashboard.",
      alt: "PingWAF dashboard with request analytics, attack trends and agent status",
    },
  },
  proof: [
    {
      value: "Apache-2.0",
      label: "Open source, end to end",
      note: "No per-request pricing and no hosted dependency.",
    },
    {
      value: "Rust",
      label: "Memory-safe data plane",
      note: "Pingora + tokio in one self-contained binary.",
    },
    {
      value: "PostgreSQL",
      label: "Control-plane state",
      note: "Sites, rules, config snapshots and audit trail.",
    },
    {
      value: "gRPC",
      label: "Hot rule synchronisation",
      note: "Bidirectional streams, no process restarts.",
    },
  ],
  architecture: {
    eyebrow: "Architecture",
    title: "One control plane, many edge agents",
    lead: "The control plane is the single source of truth for configuration. Agents only carry traffic and enforce policy, so you can scale the data plane without touching state.",
    points: [
      {
        title: "The control plane owns state",
        body: "Sites, rules, certificates and configuration versions live in PostgreSQL behind an Axum REST API, a tonic gRPC service and the embedded console.",
      },
      {
        title: "Agents enforce at the edge",
        body: "Each agent keeps a disk-backed rule cache and keeps serving with the last known policy even when the control plane is unreachable.",
      },
      {
        title: "Changes land without a reload",
        body: "SyncRules pushes a new bundle over the existing bidirectional stream; agents swap it in memory while requests keep flowing.",
      },
    ],
    diagram: {
      lanes: [
        {
          label: "Clients",
          nodes: [{ title: "Browser / API client", meta: "HTTPS" }],
        },
        {
          label: "Data plane · agent",
          nodes: [
            { title: "Edge agent A", meta: ":80 / :443", accent: true },
            { title: "Edge agent B", meta: ":80 / :443", accent: true },
          ],
        },
        {
          label: "Control plane · server",
          nodes: [
            { title: "REST + dashboard", meta: ":9080" },
            { title: "gRPC ControlPlane", meta: ":9090" },
            { title: "PostgreSQL", meta: "SeaORM" },
            { title: "Elasticsearch", meta: "optional" },
          ],
        },
        {
          label: "Origin",
          nodes: [{ title: "Upstream pools", meta: "HTTP / HTTPS" }],
        },
      ],
      links: [
        "HTTP / HTTPS",
        "gRPC bidi streams · Heartbeat · ShipLogs · SyncRules",
        "proxied requests",
      ],
    },
    link: { label: "How the control plane works", path: "/docs/architecture/" },
  },
  capabilities: {
    eyebrow: "Capabilities",
    title: "Defense in depth, off by default",
    lead: "Every protection ships disabled and is enabled per site, so nothing changes your traffic behaviour until you ask it to.",
    items: [
      {
        icon: "shield",
        title: "Semantic WAF engine",
        body: "Signature and heuristic detection for SQL injection, XSS, RCE, path traversal and command injection.",
        points: [
          "libinjection heuristics + Aho-Corasick matching",
          "Cloudflare-style expression rules",
          "Pass / Monitor / Block / Challenge verdicts",
        ],
        link: { label: "WAF engine", path: "/features/#waf-engine" },
      },
      {
        icon: "bot",
        title: "CC & bot defense",
        body: "Absorb floods and separate real browsers from scripts with layered challenges.",
        points: [
          "JavaScript 5-second shield and proof of work",
          "HMAC-signed clearance cookies",
          "Verified-bot allow list per site",
        ],
        link: { label: "CC & bot defense", path: "/features/#cc-bot" },
      },
      {
        icon: "key",
        title: "Access control",
        body: "Decide who reaches the origin by address, region and request dimension.",
        points: [
          "IP rules with CIDR and CSV import",
          "Geo blocks by country and ASN",
          "Rate limits per IP, host, path or header",
        ],
        link: { label: "Access control", path: "/features/#access-control" },
      },
      {
        icon: "route",
        title: "Traffic & caching",
        body: "Route, balance and cache without leaving the console.",
        points: [
          "Origin pools with five balancing strategies",
          "Prefix, exact and regex routes",
          "Edge cache with quotas and SWR",
        ],
        link: { label: "Traffic & caching", path: "/features/#traffic-caching" },
      },
      {
        icon: "lock",
        title: "TLS & certificates",
        body: "Certificates issued at the edge and visible from one place.",
        points: [
          "ACME HTTP-01 and DNS-01 with renewal",
          "Per-site certificate status in heartbeats",
          "mTLS issuance and instant revocation",
        ],
        link: { label: "TLS & certificates", path: "/features/#tls" },
      },
      {
        icon: "activity",
        title: "Observability & console",
        body: "Every request is auditable, and every configuration change is reversible.",
        points: [
          "Request logs in Elasticsearch with WAL buffering",
          "Raw request/response capture for replay",
          "Config versioning with diff and rollback",
        ],
        link: { label: "Observability", path: "/features/#observability" },
      },
    ],
    link: { label: "All capabilities", path: "/features/" },
  },
  showcase: {
    eyebrow: "Inside the console",
    title: "Operations without a separate stack",
    lead: "The dashboard is compiled into the binary, so what you see is what the control plane knows.",
    shots: [
      {
        key: "waf",
        url: "localhost:9080/sites/example.com/security/protection",
        caption: "WAF rules and CC challenges are configured per site.",
        alt: "PingWAF site protection page with WAF rule tabs and challenge settings",
      },
      {
        key: "logs",
        url: "localhost:9080/logs",
        caption: "Request logs carry the verdict, score and matched rule.",
        alt: "PingWAF request log list with verdicts and matched rules",
      },
      {
        key: "ssl",
        url: "localhost:9080/sites/example.com/ssl",
        caption: "Certificate status and ACME events for each site.",
        alt: "PingWAF site TLS page with certificate status and ACME events",
      },
    ],
  },
  quickstart: {
    eyebrow: "Quick start",
    title: "From zero to a protected site",
    lead: "The bundled compose file starts the control plane, an agent and PostgreSQL. Sign in, add a site, and the edge starts enforcing.",
    steps: [
      { title: "Start the stack", body: "docker compose up -d pulls the published image and starts PostgreSQL." },
      { title: "Sign in", body: "Open https://localhost:9080 and use the seeded admin account." },
      { title: "Add a site", body: "Point a hostname at the agent and enable protections per site." },
    ],
    terminal: {
      title: "bash — pingwaf",
      lines: [
        "$ git clone https://github.com/shuaiZend/PingWAF.git",
        "$ cd PingWAF && docker compose up -d",
        "control plane  https://localhost:9080",
        "agent          :80 / :443",
        "postgres       :5432",
      ],
    },
    primary: { label: "Full quick start", path: "/quickstart/" },
    secondary: { label: "Deployment guide", path: "/docs/deployment/" },
  },
  cta: {
    title: "A WAF you can read, audit and own",
    lead: "Every rule, verdict and log line stays in your infrastructure — under a license that lets you change any of it.",
    primary: { label: "Get started", path: "/quickstart/" },
    secondary: { label: "Star on GitHub", path: "https://github.com/shuaiZend/PingWAF" },
  },
} satisfies IntroContent;

export default intro;
