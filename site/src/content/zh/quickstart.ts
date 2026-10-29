import type { QuickStartContent } from "../schema";

const quickstart = {
  meta: {
    title: "快速上手 — PingWAF",
    description:
      "用 Docker Compose 或源码构建运行 PingWAF，登录控制台，添加第一个站点，并在边缘开始执行规则。",
  },
  hero: {
    eyebrow: "快速上手",
    title: "五分钟跑起来，十分钟完成防护",
    lead: "两条官方路径：用自带 compose 快速评估，或自行构建二进制用于生产环境。",
    badges: [
      { icon: "container", label: "方式 A", value: "Docker Compose" },
      { icon: "code", label: "方式 B", value: "源码构建" },
      { icon: "clock", label: "耗时", value: "约 5 分钟" },
      { icon: "database", label: "存储", value: "PostgreSQL 14+" },
    ],
    toc: [
      { id: "prerequisites", label: "前置条件" },
      { id: "docker", label: "Docker Compose" },
      { id: "source", label: "源码构建" },
      { id: "credentials", label: "首次登录" },
      { id: "next", label: "后续步骤" },
      { id: "troubleshooting", label: "故障排查" },
    ],
  },
  prereq: {
    title: "开始之前",
    lead: "compose 方式只需要 Docker；源码构建还需要 Rust、Node 工具链与 protoc。",
    items: [
      {
        label: "Docker",
        value: "Engine 24+ 与 Compose v2",
        note: "一次启动控制面、一个 Agent 与 PostgreSQL。",
      },
      {
        label: "PostgreSQL",
        value: "14+（推荐 16）",
        note: "控制面用它保存站点、规则与版本。",
      },
      {
        label: "端口",
        value: "9080 · 9090 · 80 · 443",
        note: "9080 提供 API 与控制台，9090 是 gRPC 控制面。",
      },
      {
        label: "TLS",
        value: "首次启动使用自签证书",
        note: "对外暴露控制台前请替换证书或先行信任。",
      },
    ],
  },
  paths: {
    docker: {
      id: "docker",
      title: "Docker Compose",
      lead: "compose 文件会以 all-in-one 模式启动 PingWAF，并同时拉起 PostgreSQL。",
      steps: [
        {
          title: "克隆仓库",
          body: "compose 文件与示例 TOML 配置都在仓库根目录。",
          code: {
            lang: "bash",
            code: "git clone https://github.com/shuaiZend/PingWAF.git\ncd PingWAF",
          },
        },
        {
          title: "启动服务",
          body: "如果这台主机可被他人访问，请先设置 JWT_SECRET 与 ADMIN_PASSWORD。",
          code: {
            lang: "bash",
            code: "export JWT_SECRET=\"$(openssl rand -hex 32)\"\nexport ADMIN_PASSWORD=\"$(openssl rand -hex 16)\"\ndocker compose up -d",
          },
        },
        {
          title: "打开控制台",
          body: "控制台使用首次启动生成的自签证书提供 HTTPS，浏览器会告警，直到你在设置中信任或上传自己的证书。",
          code: {
            lang: "bash",
            code: "curl --connect-timeout 2 --max-time 3 http://localhost:9080/healthz\n# {\"status\":\"ok\",\"database\":\"up\"}",
          },
        },
        {
          title: "添加第一个站点",
          body: "用准备解析到 Agent 的域名创建站点，然后只为这个域名开启需要的防护。",
        },
      ],
      note: "预编译二进制目前只发布 Linux amd64/arm64；Docker 镜像同时支持两种架构。",
      shot: {
        key: "sites",
        url: "localhost:9080/sites",
        caption: "站点列表是执行的起点：每个域名一行。",
        alt: "PingWAF 控制台站点列表，展示流量与防护状态",
      },
    },
    source: {
      id: "source",
      title: "源码构建",
      lead: "需要自定义构建、不同特性组合或可审计二进制时使用这条路径。",
      steps: [
        {
          title: "安装工具链",
          body: "protoc 是必需项：缺失时 proto crate 会退化为占位文件，后续 crate 编译失败。",
          code: {
            lang: "bash",
            code: "# macOS\nbrew install protobuf\n\n# Debian / Ubuntu\nsudo apt install protobuf-compiler cmake",
          },
        },
        {
          title: "构建控制台",
          body: "控制台会被嵌入二进制，因此必须先构建。",
          code: {
            lang: "bash",
            code: "cd web && npm ci && npm run build && cd ..",
          },
        },
        {
          title: "构建二进制",
          body: "full 特性包含 WAF 引擎、挑战与证书自动化。",
          code: {
            lang: "bash",
            code: "cargo build --release --bin pingwaf --features full",
          },
        },
        {
          title: "以 all-in-one 运行",
          body: "指向一个 PostgreSQL 实例即可，首次启动会自动建表。",
          code: {
            lang: "bash",
            code: "./target/release/pingwaf all-in-one \\\n  --db-url \"postgres://pingwaf:pingwaf@localhost:5432/pingwaf\"",
          },
        },
      ],
      note: "在 Linux 上可以跳过构建：curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | sudo bash -s -- --mode all-in-one",
      shot: {
        key: "agents",
        url: "localhost:9080/agents",
        caption: "源码构建可以先作为控制面运行，再从集群页面纳管 Agent。",
        alt: "Agent 集群页面，列出已接入的边缘 Agent 与心跳状态",
      },
    },
  },
  credentials: {
    title: "首次登录",
    lead: "控制面首次启动会创建管理员账号，控制台会在可用前强制要求修改密码。",
    rows: [
      { label: "控制台", value: "https://localhost:9080" },
      { label: "邮箱", value: "admin@pingwaf.local" },
      { label: "密码", value: "pingwaf123" },
      { label: "JWT 密钥", value: "≥ 16 个字符" },
    ],
    warning: {
      title: "对外暴露前务必修改默认值",
      body: "PINGWAF_JWT_SECRET 与 PINGWAF_ADMIN_PASSWORD 都有可用默认值。请同时设置它们、把 PINGWAF_ALLOW_REGISTRATION 设为 false，并让 9080 只在内网或 VPN 内可达。",
    },
    shot: {
      key: "login",
      url: "localhost:9080/login",
      caption: "使用初始管理员账号登录；之后可在设置中绑定 Passkey。",
      alt: "PingWAF 登录页，包含邮箱与密码输入框",
    },
  },
  next: {
    title: "后续步骤",
    lead: "控制面能响应之后，剩下的都是配置工作。",
    cards: [
      {
        icon: "globe",
        title: "创建站点",
        body: "站点把域名与源站池、路由以及你启用的防护绑定在一起。",
        link: { label: "站点模型", path: "/docs/architecture/" },
      },
      {
        icon: "network",
        title: "接入边缘 Agent",
        body: "控制节点运行 pingwaf server，边缘节点运行 pingwaf agent，Agent 通过 gRPC :9090 注册。",
        link: { label: "分布式部署", path: "/docs/deployment/" },
      },
      {
        icon: "shield-check",
        title: "开启防护",
        body: "按站点启用 WAF 引擎、CC 盾或 Bot 策略——在你开启之前不会有任何拦截。",
        link: { label: "能力总览", path: "/features/" },
      },
      {
        icon: "activity",
        title: "把日志接出去",
        body: "请求日志写入 Elasticsearch，原始报文留在 PostgreSQL 以便重放。",
        link: { label: "可观测性", path: "/features/#observability" },
      },
    ],
  },
  troubleshooting: {
    title: "启动不顺利时",
    items: [
      {
        q: "构建在 pingwaf-proto 阶段失败",
        a: "缺少 protoc。安装 protobuf-compiler（或 brew install protobuf）后重新构建——没有它时该 crate 会静默退化为占位文件。",
      },
      {
        q: "浏览器不信任控制台证书",
        a: "控制台默认使用自签证书提供 HTTPS。信任下载的证书，或在设置 → 控制面 HTTPS 上传自己的证书；用 PINGWAF_TLS_SANS 指定实际访问的主机名。",
      },
      {
        q: "Agent 一直不出现在集群里",
        a: "确认 Agent 能访问 :9090 的 gRPC 控制面（PINGWAF_SERVER_URL），且没有被防火墙或 TLS 终止代理拦截。",
      },
      {
        q: "443 端口没有监听",
        a: "只有当站点签发或上传证书后 443 才会开放；在此之前 Agent 只提供 80 端口的 HTTP。",
      },
    ],
  },
  cta: {
    title: "需要更完整的说明？",
    lead: "部署与架构文档覆盖 systemd、分布式拓扑、配置优先级以及完整的环境变量清单。",
    primary: { label: "部署指南", path: "/docs/deployment/" },
    secondary: { label: "GitHub", path: "https://github.com/shuaiZend/PingWAF" },
  },
} satisfies QuickStartContent;

export default quickstart;
