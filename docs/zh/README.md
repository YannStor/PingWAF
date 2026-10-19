# PingWAF 文档

欢迎查阅 PingWAF 文档索引。PingWAF 是基于 [`pingap`](https://github.com/vicanso/pingap) 与 Cloudflare
[`Pingora`](https://github.com/cloudflare/pingora) 构建的**分布式、集中控制的 Web 应用防火墙**。

> 项目主页：[`README_zh.md`](../../README_zh.md) · [English](../README.md)

## 🚀 快速上手

| 文档 | 内容 |
| --- | --- |
| [quick-start.md](../quick-start.md) | 从零到第一个受保护站点：环境要求、安装、首次运行 |
| [deployment.md](../deployment.md) | Docker Compose、二进制 + systemd、分布式（server + agent）拓扑 |
| [user-guide.md](../user-guide.md) | 控制台使用：站点、规则、策略、IP 访问控制、限流 |
| [http-lifecycle.md](./http-lifecycle.md) | 请求生命周期中各功能的作用阶段——WAF 检查顺序、缓存、错误页，以及如何据此排查问题 |
| [api.md](../api.md) | REST API 参考（基址 `https://<host>:9080/api/v1`） |
| [profiling.md](./profiling.md) | 系统观测与归因：`/system/metrics` CPU/内存快照、`/system/profile` 模块/方法归因 |

## 🧭 项目与社区

| 文档 | 内容 |
| --- | --- |
| [CONTRIBUTING.md](../../CONTRIBUTING.md) | 如何参与贡献——环境准备、工作流、代码风格 |
| [SECURITY.md](../../SECURITY.md) | 漏洞披露政策 |
| [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) | 社区行为准则 |
| [LICENSE](../../LICENSE) | Apache License 2.0 |

## 🏗️ 架构一览

```
客户端 ──HTTP/HTTPS──► 数据面 Agent (:80/:443)
                            │  gRPC 双向流（规则 / 日志 / 指标）
                            ▼
                     控制面 Server
                     ├─ REST API + 控制台 (:9080, HTTPS)
                     ├─ gRPC ControlPlane  (:9090)
                     ├─ PostgreSQL（状态）
                     └─ Elasticsearch（日志，可选）
```

用 `all-in-one` 在单进程内运行全部组件，或把控制面（`server`）与一个/多个边缘
Agent（`agent`）拆开部署。

## 📦 Crate 文档

PingWAF 在 `pingap` 代理基础之上新增了 **6 个 WAF 专属 crate**。

**WAF crate：**

| Crate | 职责 |
| --- | --- |
| [pingwaf-proto](../../pingwaf-proto) | 控制面 gRPC 协议定义（单一来源：`control_plane.proto`） |
| [pingwaf-server](../../pingwaf-server) | 控制面：Axum REST + tonic gRPC + SeaORM/PostgreSQL + ES 日志 + 内嵌前端 + Agent 健康监控 |
| [pingwaf-agent](../../pingwaf-agent) | 数据面 Agent：连接控制面、规则缓存 + 磁盘持久化、回传日志/指标、接收命令 |
| [pingwaf-waf](../../pingwaf-waf) | 检测引擎：归一化 → 签名 → 表达式 → 异常评分 |
| [pingwaf-challenge](../../pingwaf-challenge) | 动态挑战：JS 5 秒盾、交互式挑战、PoW、浏览器指纹、HMAC clearance cookie |
| `pingwaf-profiler`（无 README） | 模块/方法 CPU 与内存归因表，经 `/api/v1/system/profile` 提供 |
| `pingwaf-system`（无 README） | 进程/主机 CPU 快照与内存/cgroup 核算，经 `/api/v1/system/metrics` 提供 |

**代理基础（`pingap-*`）——每个 crate 都有自己的 README**，说明其职责边界、配置方式
与在依赖图中的位置：

| Crate | 职责 |
| --- | --- |
| [pingap-util](../../pingap-util/README.md) | 加密、IP 规则、PEM/base64、路径与格式化工具 |
| [pingap-core](../../pingap-core/README.md) | `Ctx`、`HttpResponse`、`Plugin` trait、后台服务、时钟辅助 |
| [pingap-config](../../pingap-config/README.md) | 配置模型、存储后端、TOML/HCL/KDL |
| [pingap-discovery](../../pingap-discovery/README.md) | 静态 / DNS / Docker / 透明代理后端发现 |
| [pingap-health](../../pingap-health/README.md) | TCP、HTTP(S)、gRPC、WS 与 WSS 健康检查 |
| [pingap-upstream](../../pingap-upstream/README.md) | 负载均衡、熔断、上游连接参数 |
| [pingap-location](../../pingap-location/README.md) | Host/路径匹配、重写、按 location 的限额 |
| [pingap-certificate](../../pingap-certificate/README.md) | 基于 SNI 的动态 TLS 证书存储 |
| [pingap-acme](../../pingap-acme/README.md) | Let's Encrypt HTTP-01 与 DNS-01 自动化 |
| [pingap-cache](../../pingap-cache/README.md) | 内存（TinyUFO）与文件缓存后端 |
| [pingap-plugin](../../pingap-plugin/README.md) | 内置插件——见[插件索引](plugins/) |
| [pingap-imageoptim](../../pingap-imageoptim/README.md) | PNG/JPEG → WebP/AVIF 转换 |
| [pingap-logger](../../pingap-logger/README.md) | 访问日志、文件/syslog 输出、轮转与压缩 |
| [pingap-performance](../../pingap-performance/README.md) | Prometheus 指标与进程自省 |
| [pingap-otel](../../pingap-otel/README.md) | OpenTelemetry 分布式追踪 |
| [pingap-sentry](../../pingap-sentry/README.md) | Sentry 错误上报 |
| [pingap-pyroscope](../../pingap-pyroscope/README.md) | 持续 CPU 剖析 |
| [pingap-webhook](../../pingap-webhook/README.md) | 运维通知（企业微信 / 钉钉 / HTTP） |
| [pingap-proxy](../../pingap-proxy/README.md) | 代理引擎：生命周期、路由、服务端配置 |

## 🔌 插件文档

每个插件都有独立页面，覆盖其配置键、可用示例以及部署前值得注意的边界条件：
[插件索引](plugins/)。

## 🌐 参考资料

- [modules.md](./guide/modules.md) — 本仓库的模块关系图（`pingap-*` 与 `pingwaf-*`）。
- [examples.md](./guide/examples.md) — 仓库内可直接运行的配置示例。
- [reverse-proxy-settings.md](./guide/reverse-proxy-settings.md) — 上游 Host 覆盖、downstream 超时与连接寿命、节点名称变更、缓存边界。
- [acme_chart.md](../acme_chart.md) — ACME / Let's Encrypt 签发流程。
- **英文文档** — [docs/README.md](../README.md)（home、plugins、crates、guide、[http-lifecycle](../http-lifecycle.md)）。
