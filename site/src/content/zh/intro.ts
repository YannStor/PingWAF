import type { IntroContent } from "../schema";

const intro = {
  meta: {
    title: "PingWAF — 基于 Pingora 的分布式 Web 应用防火墙",
    description:
      "基于 pingap 与 Cloudflare Pingora 构建的开源 WAF：单一控制面、多个边缘 Agent、语义级攻击检测、CC 与 Bot 防护、自动 TLS 以及内嵌控制台。",
  },
  hero: {
    badges: ["Apache-2.0", "Rust · Pingora", "可自托管"],
    title: "Cloudflare 级别的防护",
    titleAccent: "放进你自己的基础设施",
    lead: "PingWAF 是一套分布式、集中管控的 Web 应用防火墙。站点、规则与策略只需在控制面定义一次，所有边缘 Agent 会在数秒内生效——无需重载，无需停服。",
    primary: { label: "5 分钟上手", path: "/quickstart/" },
    secondary: { label: "阅读文档", path: "/docs/" },
    stats: [
      { value: "4 个阶段", label: "归一化 → 签名 → 表达式 → 评分" },
      { value: "7 个 RPC", label: "控制面 gRPC 协议" },
      { value: "5 家服务商", label: "DNS-01 ACME 集成" },
    ],
    pills: [
      { icon: "shield-check", text: "SQLi · XSS · RCE · 路径穿越" },
      { icon: "refresh", text: "规则秒级下发" },
    ],
    shot: {
      key: "dashboard",
      url: "localhost:9080/dashboard",
      caption: "内嵌控制台里的流量、攻击与 Agent 健康度。",
      alt: "PingWAF 控制台仪表盘，展示请求分析、攻击趋势与 Agent 状态",
    },
  },
  proof: [
    {
      value: "Apache-2.0",
      label: "端到端开源",
      note: "没有按请求计费，也不依赖任何托管服务。",
    },
    {
      value: "Rust",
      label: "内存安全的数据面",
      note: "Pingora + tokio，单个自包含二进制。",
    },
    {
      value: "PostgreSQL",
      label: "控制面状态存储",
      note: "站点、规则、配置快照与审计记录。",
    },
    {
      value: "gRPC",
      label: "规则热同步",
      note: "双向流推送，进程无需重启。",
    },
  ],
  architecture: {
    eyebrow: "架构",
    title: "一个控制面，多个边缘 Agent",
    lead: "控制面是配置的唯一真源；Agent 只负责承载流量并执行策略，因此扩展数据面时不需要改动任何状态。",
    points: [
      {
        title: "控制面持有全部状态",
        body: "站点、规则、证书与配置版本都存放在 PostgreSQL，由 Axum REST API、tonic gRPC 服务与内嵌控制台对外提供。",
      },
      {
        title: "Agent 在边缘执行策略",
        body: "每个 Agent 都保留磁盘规则缓存，即使控制面不可达，也会按最后一次同步的策略继续提供服务。",
      },
      {
        title: "变更无需重载即可生效",
        body: "SyncRules 在既有双向流上推送新的配置包，Agent 在请求持续流动的同时完成内存替换。",
      },
    ],
    diagram: {
      lanes: [
        {
          label: "客户端",
          nodes: [{ title: "浏览器 / API 客户端", meta: "HTTPS" }],
        },
        {
          label: "数据面 · Agent",
          nodes: [
            { title: "边缘 Agent A", meta: ":80 / :443", accent: true },
            { title: "边缘 Agent B", meta: ":80 / :443", accent: true },
          ],
        },
        {
          label: "控制面 · Server",
          nodes: [
            { title: "REST + 控制台", meta: ":9080" },
            { title: "gRPC 控制面", meta: ":9090" },
            { title: "PostgreSQL", meta: "SeaORM" },
            { title: "Elasticsearch", meta: "可选" },
          ],
        },
        {
          label: "源站",
          nodes: [{ title: "上游地址池", meta: "HTTP / HTTPS" }],
        },
      ],
      links: [
        "HTTP / HTTPS",
        "gRPC 双向流 · Heartbeat · ShipLogs · SyncRules",
        "回源请求",
      ],
    },
    link: { label: "控制面如何工作", path: "/docs/architecture/" },
  },
  capabilities: {
    eyebrow: "核心能力",
    title: "纵深防御，默认全部关闭",
    lead: "所有防护默认关闭，按站点逐个开启；在你主动启用之前，流量行为不会有任何变化。",
    items: [
      {
        icon: "shield",
        title: "语义级 WAF 引擎",
        body: "针对 SQL 注入、XSS、RCE、路径穿越与命令注入的签名与启发式检测。",
        points: [
          "libinjection 启发式 + Aho-Corasick 多模式匹配",
          "Cloudflare 风格表达式规则",
          "Pass / Monitor / Block / Challenge 四种判决",
        ],
        link: { label: "WAF 引擎", path: "/features/#waf-engine" },
      },
      {
        icon: "bot",
        title: "CC 与 Bot 防护",
        body: "通过分层挑战吸收洪峰，把真实浏览器与脚本区分开。",
        points: [
          "JavaScript 5 秒盾与工作量证明",
          "HMAC 签名的放行 Cookie",
          "按站点维护已验证 Bot 白名单",
        ],
        link: { label: "CC 与 Bot 防护", path: "/features/#cc-bot" },
      },
      {
        icon: "key",
        title: "访问控制",
        body: "按地址、地域与请求维度决定谁能到达源站。",
        points: [
          "IP 规则支持 CIDR 与 CSV 导入",
          "按国家与 ASN 的地域封禁",
          "按 IP、主机、路径或请求头的限流",
        ],
        link: { label: "访问控制", path: "/features/#access-control" },
      },
      {
        icon: "route",
        title: "流量与缓存",
        body: "不必离开控制台就能完成路由、负载均衡与缓存。",
        points: [
          "地址池支持五种负载均衡策略",
          "前缀、精确与正则路由",
          "带配额与 SWR 的边缘缓存",
        ],
        link: { label: "流量与缓存", path: "/features/#traffic-caching" },
      },
      {
        icon: "lock",
        title: "TLS 与证书",
        body: "证书在边缘签发，状态集中可见。",
        points: [
          "ACME HTTP-01 与 DNS-01 自动续期",
          "心跳上报各站点证书状态",
          "mTLS 签发与即时吊销",
        ],
        link: { label: "TLS 与证书", path: "/features/#tls" },
      },
      {
        icon: "activity",
        title: "可观测性与控制台",
        body: "每个请求都可审计，每次配置变更都可回滚。",
        points: [
          "请求日志写入 Elasticsearch 并带 WAL 缓冲",
          "原始请求/响应留存，可重放为 curl",
          "配置版本可对比、可回滚",
        ],
        link: { label: "可观测性", path: "/features/#observability" },
      },
    ],
    link: { label: "全部能力", path: "/features/" },
  },
  showcase: {
    eyebrow: "控制台一览",
    title: "运维不需要另一套系统",
    lead: "控制台被编译进二进制，界面上看到的，就是控制面掌握的全部事实。",
    shots: [
      {
        key: "waf",
        url: "localhost:9080/sites/example.com/security/protection",
        caption: "WAF 规则与 CC 挑战按站点配置。",
        alt: "PingWAF 站点防护页面，展示 WAF 规则标签与挑战设置",
      },
      {
        key: "logs",
        url: "localhost:9080/logs",
        caption: "请求日志同时记录判决、评分与命中的规则。",
        alt: "PingWAF 请求日志列表，展示判决与命中规则",
      },
      {
        key: "ssl",
        url: "localhost:9080/sites/example.com/ssl",
        caption: "每个站点的证书状态与 ACME 事件。",
        alt: "PingWAF 站点 TLS 页面，展示证书状态与 ACME 事件",
      },
    ],
  },
  quickstart: {
    eyebrow: "快速上手",
    title: "从零到一个受保护的站点",
    lead: "仓库自带的 compose 文件会同时启动控制面、Agent 与 PostgreSQL。登录、添加站点，边缘立即开始执行策略。",
    steps: [
      { title: "启动整套服务", body: "docker compose up -d 会拉取已发布镜像并启动 PostgreSQL。" },
      { title: "登录控制台", body: "打开 https://localhost:9080，使用初始管理员账号登录。" },
      { title: "添加站点", body: "把域名解析到 Agent，然后按站点开启需要的防护。" },
    ],
    terminal: {
      title: "bash — pingwaf",
      lines: [
        "$ git clone https://github.com/shuaiZend/PingWAF.git",
        "$ cd PingWAF && docker compose up -d",
        "控制面  https://localhost:9080",
        "Agent   :80 / :443",
        "postgres :5432",
      ],
    },
    primary: { label: "完整快速上手", path: "/quickstart/" },
    secondary: { label: "部署指南", path: "/docs/deployment/" },
  },
  cta: {
    title: "一个你能读懂、能审计、能掌控的 WAF",
    lead: "每条规则、每个判决、每行日志都留在你的基础设施里，许可证允许你修改其中任何部分。",
    primary: { label: "立即开始", path: "/quickstart/" },
    secondary: { label: "在 GitHub 上加星", path: "https://github.com/shuaiZend/PingWAF" },
  },
} satisfies IntroContent;

export default intro;
