import type { QuickStartContent } from "../schema";

const quickstart = {
  meta: {
    title: "Quick start — PingWAF",
    description:
      "Run PingWAF with Docker Compose or build it from source, sign in to the dashboard, add your first site and start enforcing rules at the edge.",
  },
  hero: {
    eyebrow: "Quick start",
    title: "Running in five minutes, protected in ten",
    lead: "Two supported paths: the bundled compose stack for evaluation, or a source build for production deployments you control.",
    badges: [
      { icon: "container", label: "Path A", value: "Docker Compose" },
      { icon: "code", label: "Path B", value: "Build from source" },
      { icon: "clock", label: "Time", value: "~5 minutes" },
      { icon: "database", label: "Store", value: "PostgreSQL 14+" },
    ],
    toc: [
      { id: "prerequisites", label: "Prerequisites" },
      { id: "docker", label: "Docker Compose" },
      { id: "source", label: "From source" },
      { id: "credentials", label: "First sign-in" },
      { id: "next", label: "Next steps" },
      { id: "troubleshooting", label: "Troubleshooting" },
    ],
  },
  prereq: {
    title: "Before you start",
    lead: "The compose path only needs Docker. A source build needs the Rust and Node toolchains plus protoc.",
    items: [
      {
        label: "Docker",
        value: "Engine 24+ with Compose v2",
        note: "Runs the control plane, one agent and PostgreSQL together.",
      },
      {
        label: "PostgreSQL",
        value: "14+ (16 recommended)",
        note: "Required by the control plane for sites, rules and versions.",
      },
      {
        label: "Ports",
        value: "9080 · 9090 · 80 · 443",
        note: "9080 serves the API and dashboard, 9090 the gRPC control plane.",
      },
      {
        label: "TLS",
        value: "Self-signed on first boot",
        note: "Replace it or trust it before you expose the console.",
      },
    ],
  },
  paths: {
    docker: {
      id: "docker",
      title: "Docker Compose",
      lead: "The compose file starts PingWAF in all-in-one mode next to PostgreSQL and pulls the published image.",
      steps: [
        {
          title: "Clone the repository",
          body: "The compose file and the example TOML config live in the repository root.",
          code: {
            lang: "bash",
            code: "git clone https://github.com/shuaiZend/PingWAF.git\ncd PingWAF",
          },
        },
        {
          title: "Start the stack",
          body: "Set JWT_SECRET and ADMIN_PASSWORD first if this host is reachable by anyone else.",
          code: {
            lang: "bash",
            code: "export JWT_SECRET=\"$(openssl rand -hex 32)\"\nexport ADMIN_PASSWORD=\"$(openssl rand -hex 16)\"\ndocker compose up -d",
          },
        },
        {
          title: "Open the dashboard",
          body: "The console is served over HTTPS with a certificate generated on first boot, so the browser warns until you trust it or upload your own under Settings.",
          code: {
            lang: "bash",
            code: "curl --connect-timeout 2 --max-time 3 http://localhost:9080/healthz\n# {\"status\":\"ok\",\"database\":\"up\"}",
          },
        },
        {
          title: "Add your first site",
          body: "Create a site with the hostname you will point at the agent, then enable the protections you want for that hostname only.",
        },
      ],
      note: "Prebuilt binaries are published for Linux amd64/arm64; the Docker image covers both architectures.",
      shot: {
        key: "sites",
        url: "localhost:9080/sites",
        caption: "The site list is where enforcement starts: one row per hostname.",
        alt: "Site list in the PingWAF console with traffic and protection state",
      },
    },
    source: {
      id: "source",
      title: "Build from source",
      lead: "Use this path when you need a custom build, a different feature set, or an auditable binary.",
      steps: [
        {
          title: "Install the toolchain",
          body: "protoc is mandatory: without it the proto crate falls back to placeholders and downstream crates fail to compile.",
          code: {
            lang: "bash",
            code: "# macOS\nbrew install protobuf\n\n# Debian / Ubuntu\nsudo apt install protobuf-compiler cmake",
          },
        },
        {
          title: "Build the dashboard",
          body: "The console is embedded into the binary, so it must be built first.",
          code: {
            lang: "bash",
            code: "cd web && npm ci && npm run build && cd ..",
          },
        },
        {
          title: "Build the binary",
          body: "The full feature set includes the WAF engine, challenges and certificate automation.",
          code: {
            lang: "bash",
            code: "cargo build --release --bin pingwaf --features full",
          },
        },
        {
          title: "Run all-in-one",
          body: "Point it at a PostgreSQL instance; the schema is created on first boot.",
          code: {
            lang: "bash",
            code: "./target/release/pingwaf all-in-one \\\n  --db-url \"postgres://pingwaf:pingwaf@localhost:5432/pingwaf\"",
          },
        },
      ],
      note: "On Linux you can skip the build: curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | sudo bash -s -- --mode all-in-one",
      shot: {
        key: "agents",
        url: "localhost:9080/agents",
        caption: "A source build can run as the control plane, then enroll agents from the fleet page.",
        alt: "Agent fleet page listing enrolled edge agents and heartbeat state",
      },
    },
  },
  credentials: {
    title: "First sign-in",
    lead: "The control plane seeds an administrator on first boot. The dashboard forces a password change before it is usable.",
    rows: [
      { label: "Dashboard", value: "https://localhost:9080" },
      { label: "Email", value: "admin@pingwaf.local" },
      { label: "Password", value: "pingwaf123" },
      { label: "JWT secret", value: "≥ 16 characters" },
    ],
    warning: {
      title: "Change the defaults before exposing anything",
      body: "PINGWAF_JWT_SECRET and PINGWAF_ADMIN_PASSWORD have working defaults. Set both, set PINGWAF_ALLOW_REGISTRATION=false, and keep 9080 on a private network or behind a VPN.",
    },
    shot: {
      key: "login",
      url: "localhost:9080/login",
      caption: "Sign in with the seeded administrator account; passkeys can be bound later from Settings.",
      alt: "PingWAF sign-in page with email and password fields",
    },
  },
  next: {
    title: "Next steps",
    lead: "Once the control plane answers, the rest is configuration.",
    cards: [
      {
        icon: "globe",
        title: "Create a site",
        body: "A site binds a hostname to origin pools, routes and the protections you enable for it.",
        link: { label: "Site model", path: "/docs/architecture/" },
      },
      {
        icon: "network",
        title: "Connect edge agents",
        body: "Run pingwaf server on the control node and pingwaf agent on each edge node; agents register over gRPC :9090.",
        link: { label: "Distributed deployment", path: "/docs/deployment/" },
      },
      {
        icon: "shield-check",
        title: "Turn protections on",
        body: "Enable the WAF engine, CC shield or bot policy per site — nothing is enforced until you do.",
        link: { label: "Capabilities", path: "/features/" },
      },
      {
        icon: "activity",
        title: "Ship logs somewhere",
        body: "Send request logs to Elasticsearch and keep raw captures in PostgreSQL for replay.",
        link: { label: "Observability", path: "/features/#observability" },
      },
    ],
  },
  troubleshooting: {
    title: "If something does not start",
    items: [
      {
        q: "The build fails in pingwaf-proto",
        a: "protoc is missing. Install protobuf-compiler (or brew install protobuf) and rebuild — the crate silently falls back to placeholder files without it.",
      },
      {
        q: "The browser refuses the dashboard certificate",
        a: "The console is HTTPS with a self-signed certificate. Trust the downloaded certificate, or upload your own under Settings → Control plane HTTPS. Set PINGWAF_TLS_SANS to the hostname you use.",
      },
      {
        q: "An agent never appears in the fleet",
        a: "Check that the agent can reach the gRPC control plane on :9090 (PINGWAF_SERVER_URL) and that it is not blocked by a firewall or TLS-terminating proxy.",
      },
      {
        q: "Port 443 is closed",
        a: "443 opens only after a certificate is issued or uploaded for a site. Until then the agent serves plain HTTP on port 80.",
      },
    ],
  },
  cta: {
    title: "Need the long version?",
    lead: "The deployment and architecture documents cover systemd, distributed topologies, configuration precedence and the full environment variable reference.",
    primary: { label: "Deployment guide", path: "/docs/deployment/" },
    secondary: { label: "GitHub", path: "https://github.com/shuaiZend/PingWAF" },
  },
} satisfies QuickStartContent;

export default quickstart;
