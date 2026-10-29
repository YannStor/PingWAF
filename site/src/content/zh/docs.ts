import type { DocsContent } from "../schema";

const docs = {
  meta: {
    title: "文档 — PingWAF",
    description:
      "架构、部署、WAF 引擎与 REST/gRPC API：在生产环境运行 PingWAF 所需的四篇文档。",
  },
  hero: {
    eyebrow: "文档",
    title: "读懂 PingWAF 的四篇文档",
    lead: "做选型先从架构看起，要安装就看部署，调规则则从 WAF 引擎开始。",
  },
  cards: [
    {
      slug: "architecture",
      icon: "network",
      title: "架构",
      lead: "控制面与数据面如何协作，gRPC 协议承载了哪些信息。",
      minutes: 8,
      topics: ["控制面", "数据面", "gRPC", "运行模式"],
    },
    {
      slug: "deployment",
      icon: "server",
      title: "部署",
      lead: "all-in-one 与分布式、Docker 与 systemd、端口与配置优先级。",
      minutes: 10,
      topics: ["Docker", "systemd", "端口", "环境变量"],
    },
    {
      slug: "waf-engine",
      icon: "shield",
      title: "WAF 引擎",
      lead: "四阶段流水线、表达式规则、判决与挑战流程。",
      minutes: 9,
      topics: ["流水线", "表达式", "判决", "挑战"],
    },
    {
      slug: "api",
      icon: "code",
      title: "API",
      lead: "用于自动化的 REST 接口、面向 Agent 的 gRPC 契约与认证方式。",
      minutes: 7,
      topics: ["REST", "gRPC", "认证", "自动化"],
    },
  ],
  sidebarLabel: "文档",
  screenshot: {
    key: "configVersions",
    url: "localhost:9080/config-versions",
    caption: "每次策略变更都是一个可对比、可回滚的版本。",
    alt: "配置版本列表，包含差异对比与回滚操作",
  },
  github: {
    title: "完整文档在仓库里",
    body: "快速上手、用户指南、HTTP 生命周期、ACME 细节、性能基准与安全策略，全部与代码一起版本化。",
    link: { label: "在 GitHub 浏览文档", path: "https://github.com/shuaiZend/PingWAF/tree/main/docs" },
  },
  backToHub: "全部文档",
  editLabel: "在 GitHub 上编辑此页",
};

export default docs;
