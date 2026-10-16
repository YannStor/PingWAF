<div align="center">

# 🛡️ PingWAF

**基于 [`pingap`](https://github.com/vicanso/pingap) 与 Cloudflare [`Pingora`](https://github.com/cloudflare/pingora) 构建的分布式、集中控制的高性能 Web 应用防火墙（WAF）。**

语义级攻击检测 · Cloudflare 风格规则 · CC 与 Bot 防护 · TLS 自动签发 · 内嵌多语言控制台

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/shuaiZend/PingWAF/actions/workflows/ci.yml/badge.svg)](https://github.com/shuaiZend/PingWAF/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/docker-compose%20ready-2496ED?logo=docker&logoColor=white)](./docker-compose.yml)

**[English](./README.md) | [简体中文](./README_zh.md) | [Español](./README_es.md) | [Français](./README_fr.md)**

[快速开始](#-快速开始) · [架构概览](#-架构概览) · [核心特性](#-核心特性) · [文档导航](#-文档导航) · [参与贡献](./CONTRIBUTING.md)

</div>

---

## 📖 PingWAF 是什么？

**PingWAF** 是一款高性能的开源 **Web 应用防火墙（WAF）**，把 Cloudflare 级别的边缘安全能力带到你自己掌控的基础设施中。它构建于 [`pingap`](https://github.com/vicanso/pingap)——一款由 Cloudflare [`Pingora`](https://github.com/cloudflare/pingora) 网络框架驱动的生产级反向代理——之上，并在其上叠加了**分布式、集中控制**的安全层。

单一的**控制面（Control Plane）**负责定义站点、规则与策略；一个或多个**数据面（Data Plane）Agent** 在边缘执行它们。规则、日志与指标通过持久化的 **gRPC 双向流**在两者之间流转，因此在控制台修改策略后，几秒内即可下发到所有 Agent——无需重载、无需停机。

- 🎯 **语义级检测**——通过 `libinjection` + Aho-Corasick 签名匹配、异常评分以及 Cloudflare 风格表达式规则，覆盖 SQLi / XSS / RCE / 路径穿越 / 命令注入。
- 🕸️ **为分布式而生**——既可单进程运行全部能力（`all-in-one`），也可将数据面横向扩展为多个独立的边缘 Agent（`server` + `agent`）。
- 🧭 **开箱即用，默认关闭**——每一项防护能力默认关闭，按站点单独开启，让你对流量拥有完全的掌控。
- ⚡ **纯 Rust 打造**——内存安全、异步 I/O，单个自包含二进制文件，控制台已内嵌其中。

> PingWAF 是一个独立项目，与 Cloudflare 及 `pingap` 维护者均无关联，也未获其背书。详见[致谢](#-致谢)。

---

## 🏗️ 架构概览

```mermaid
graph TB
    Client[客户端 / 浏览器]

    subgraph ControlPlane["控制面 (pingwaf server)"]
        Dashboard[内嵌控制台 + REST API :9080]
        GRPC[gRPC ControlPlane 服务 :9090]
        PG[(PostgreSQL 14+)]
        ES[(Elasticsearch - 可选)]
    end

    subgraph DataPlane["数据面 (pingwaf agents)"]
        AgentA[边缘 Agent A :80 / :443]
        AgentB[边缘 Agent B :80 / :443]
    end

    Origin[源站 / 上游服务]

    Client -->|HTTP / HTTPS| AgentA
    Client -->|HTTP / HTTPS| AgentB
    AgentA <-->|gRPC 双向流| GRPC
    AgentB <-->|gRPC 双向流| GRPC
    Dashboard --> PG
    GRPC --> PG
    GRPC --> ES
    AgentA -->|安全流量| Origin
    AgentB -->|安全流量| Origin
```

控制面与数据面通过 `ControlPlane` gRPC 服务通信（定义于 [`control_plane.proto`](./pingwaf-proto/proto/control_plane.proto)），共包含 7 个 RPC：

| RPC | 类型 | 用途 |
| --- | --- | --- |
| `RegisterAgent` | 一元调用 | Agent 加入集群，获取 ID 与心跳间隔 |
| `Heartbeat` | 双向流 | 上行存活/统计/每站点证书状态，下行实时命令 |
| `SyncRules` | 服务端流 | 策略变更时将规则包推送到 Agent |
| `ShipLogs` | 客户端流 | 批量请求/攻击日志流式上报控制面 |
| `ShipCertEvents` | 客户端流 | Agent 捕获的 ACME 签发事件流式上报控制面 |
| `ShipMetrics` | 客户端流 | 批量流量指标流式上报控制面 |
| `GetSiteConfig` | 一元调用 | Agent 拉取单个站点的完整配置 |

**同一个二进制，两种部署形态：**

- **All-in-One（一体化）**——控制面 + 数据面运行于单进程。适合单节点、小型部署与本地评估。
- **Distributed（分布式）**——一个独立的 `server`（控制面）+ 多个边缘 `agent` 进程。适合集群、多地域部署与集中管理。

---

## ✨ 核心特性

### 🛡️ 安全检测
- **语义级 WAF 引擎**，覆盖 SQL 注入、XSS、RCE、路径穿越与命令注入——由 `libinjection` 启发式算法与 Aho-Corasick 多模式签名匹配驱动。
- **四阶段流水线**：`normalize`（请求归一化）→ `signatures`（签名 / libinjection）→ `expression`（规则表达式）→ `anomaly score`（加权异常评分）。
- **Cloudflare 风格表达式规则**——可编写形如 `http.request.uri.path contains "/admin" and ip.src in {1.2.3.0/24}` 的条件。
- **异常评分**，四种裁决结果：`Pass`（放行）、`Monitor`（观察）、`Block`（拦截）、`Challenge`（挑战）。
- **托管规则集**——可按站点开关的精选签名。

### 🤖 CC 与 Bot 防护
- **CC 防护 / 5 秒盾**——JavaScript 挑战、PoW（工作量证明）与交互式挑战，配合 HMAC 签名 clearance cookie。
- **Bot 防护**——验证 Bot 白名单直接放行、已知浏览器 UA 放行，其余流量按配置动作处置；TLS 指纹与行为分析在路线图中。

### 🚦 访问控制
- **IP 访问规则**——`block` / `allow` / `challenge` / `js_challenge`，支持 CIDR 网段、CSV 批量导入与命名规则。
- **全局 IP 分组**——可订阅的 CIDR 列表（纯文本、JSON 或 Cloudflare IP 段 API），按周期自动同步到所有站点，并记录同步错误。
- **Geo 地域限制**——按国家与 ASN（自治系统号）放行或拦截，支持"拦截未知国家"策略。
- **多维限流**——按 IP、主机、路径、ASN、国家以及请求头/Cookie/查询参数等维度计数限流。

### 🌊 流量管理
- **源站池与路由**——将上游节点组成源站池，支持负载均衡（轮询、最小连接、随机或按 IP/URL/路径/头部/Cookie/查询参数一致性哈希），并按前缀、精确匹配或正则路由请求；路由可限定到某个 IP 分组，从而让同一路径对办公网或合作方地址走不同的源站池。
- **边缘缓存**——按站点磁盘配额与 LRU 驱逐，支持 stale-while-revalidate 与浏览器 TTL 控制。
- **请求 / 响应改写**——头部、路径、查询参数、状态码与响应体查找替换。
- **自定义错误页**，基于 Tera 模板渲染；对 WAF 拦截、站点暂停等边缘生成的响应同样生效。
- **暂停站点**——在控制台一键暂停后，所有请求返回 `503` 维护页，证书照常握手、流量照常入日志。

### 🔐 TLS 与证书
- **ACME / Let's Encrypt 自动签发与续期**，直接在边缘完成（HTTP-01 与 DNS-01）。
- **多 DNS 提供商**支持 DNS-01（阿里云、Cloudflare、腾讯云 DNSPod、华为云、手动）。
- **每站点证书状态**（`valid` / `即将过期` / `expired`）通过心跳上报控制面，并提供可检索的 ACME 事件日志。
- **HSTS 与强制 HTTPS** 在边缘生效，`max-age` 默认半年（15552000 秒）。
- **双向 TLS（mTLS）**——控制面内生成或导入 CA、签发客户端证书，吊销即时在边缘生效；证书被吊销或签发给其他站点时一律拒绝。
- **HTTPS 回源证书校验是显式开关**——「系统设置 → 回源」提供全局默认值，单个回源池可覆盖。默认接受任意回源证书，自签名与内网 CA 环境升级后不受影响；源站持有受信任证书时应显式开启校验。

### 📊 可观测性
- **全量请求日志写入 Elasticsearch**，支持响应体截断与 WAL 缓冲以保证可靠性。
- **请求与响应原文采集**——PostgreSQL 中保存头部、请求/响应体前缀、真实大小与截断标记，可在控制台一键复制为 `curl` 命令复现请求。头部按原样保存（含 Cookie），以便安全复现场景。
- **Analytics 分析**面板，呈现流量与攻击趋势。
- Agent 健康、流量统计与缓存命中/驱逐指标通过心跳上报控制面。

### 🎛️ 管理控制台
- **JWT + bcrypt 认证**与**多租户**隔离。
- **Passkey 通行密钥登录**（WebAuthn）——在设置页绑定平台认证器或安全密钥后即可免密码登录。
- **内嵌多语言控制台**（English / 简体中文 / 日本語），通过 `rust-embed` 编译进二进制。
- **所有功能默认关闭**——按站点显式开启防护。
- **配置版本管理**——控制台可筛选列出全部配置快照，将任一版本与其前一版本逐表对比，并在二次确认后回滚。

---

## 🧱 技术栈

| 层次 | 技术 |
| --- | --- |
| 数据面 / 代理 | Rust · [`Pingora`](https://github.com/cloudflare/pingora) · [`pingap`](https://github.com/vicanso/pingap) |
| 控制面 API | [`Axum`](https://github.com/tokio-rs/axum)（REST）· [`tonic`](https://github.com/hyperium/tonic)（gRPC） |
| 持久化 | [`SeaORM`](https://www.sea-ql.org/SeaORM/) · PostgreSQL 14+（推荐 16） |
| 日志存储 | Elasticsearch（可选） |
| 控制台 | React 19 · Vite · Tailwind CSS v4（通过 `rust-embed` 内嵌） |
| WAF 引擎 | `libinjection` · Aho-Corasick · 表达式求值器 |

**核心 crate：**

| Crate | 职责 |
| --- | --- |
| [`pingwaf-proto`](./pingwaf-proto) | 控制面 gRPC 协议定义（单一来源：`control_plane.proto`） |
| [`pingwaf-server`](./pingwaf-server) | 控制面：Axum REST + tonic gRPC + SeaORM/PostgreSQL + ES 日志 + 内嵌前端 + Agent 健康监控 |
| [`pingwaf-agent`](./pingwaf-agent) | 数据面 Agent：连接控制面、规则缓存 + 磁盘持久化、回传日志/指标、接收命令 |
| [`pingwaf-waf`](./pingwaf-waf) | 检测引擎：归一化 → 签名 → 表达式 → 异常评分 |
| [`pingwaf-challenge`](./pingwaf-challenge) | 动态挑战子系统：JS 5 秒盾、交互式挑战、PoW、浏览器指纹、HMAC 签名 clearance cookie |
| [`pingwaf-pprof`](./pingwaf-pprof) | 内置剖析：`go tool pprof` CPU 剖析、SVG 火焰图、内存快照（CPU 采样仅限 Linux） |

---

## 🚀 快速开始

> **注意：** 预编译二进制目前仅提供 **Linux（amd64 / arm64）** 版本——见 [Releases 页面](https://github.com/shuaiZend/PingWAF/releases)。macOS 请使用源码编译（方式 B）。Docker 镜像支持两种架构。

### 方式 A —— Docker Compose（推荐）

仓库内置的 [`docker-compose.yml`](./docker-compose.yml) 会以 `all-in-one` 模式连同 PostgreSQL 一起启动 PingWAF，默认拉取 GHCR 预构建镜像（`ghcr.io/shuaizend/pingwaf:latest`）：

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF

# 启动控制面 + 数据面 + PostgreSQL
docker compose up -d
```

随后打开控制台：

- **地址：** https://localhost:9080
- **邮箱：** `admin@pingwaf.local`
- **密码：** `pingwaf123`

> ⚠️ **在任何生产环境使用前，请务必修改默认管理员密码与 `PINGWAF_JWT_SECRET`。**

控制台默认以 **HTTPS** 提供服务，首次启动自动生成自签名证书，浏览器会提示不受信任；
可在**设置 → 控制台 HTTPS** 下载该证书或上传正式证书替换。若访问使用的主机名不是
`localhost`，请通过 `PINGWAF_TLS_SANS` 指定，使生成的证书覆盖该主机名。

健康检查：`GET http://localhost:9080/healthz`（HTTP 与 HTTPS 均可访问；其余路径会 308 跳转到 `https://`）。

### 方式 B —— 源码编译

**环境要求**

| 工具 | 版本 | 说明 |
| --- | --- | --- |
| Rust | 1.96+（MSRV） | CI 跟随 stable；Docker 镜像与发布二进制使用 1.98.1 构建 |
| Node.js | 22 | 构建控制台所需 |
| `protoc` | 任意较新版本 | **必需**——用于 gRPC 代码生成 |
| `cmake` | 任意较新版本 | 构建 TLS 后端（OpenSSL）所需 |
| PostgreSQL | 14+（推荐 16） | 控制面数据存储 |

> ⚠️ **`protoc` 为必需项。** 若缺失，`pingwaf-proto` 会静默降级为占位文件，导致下游 crate 编译失败。请先安装：
>
> ```bash
> brew install protobuf                        # macOS
> sudo apt install protobuf-compiler cmake     # Debian / Ubuntu
> ```

**编译与运行**

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF

# 1. 构建内嵌控制台
cd web && npm ci && npm run build && cd ..

# 2. 构建 pingwaf 二进制
cargo build --release --bin pingwaf --features full

# 3. 以 all-in-one 模式运行
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

👉 完整流程（数据库准备、首个站点、分布式 Agent、systemd）请见 **[docs/quick-start.md](./docs/quick-start.md)**。

### 方式 C —— 安装脚本（Linux）

在 Linux 服务器上，一键脚本会下载预编译二进制并安装，可选配置 systemd 服务：

```bash
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | sudo bash -s -- --mode all-in-one
```

---

## 🧭 运行模式

PingWAF 是单一二进制（`pingwaf`），与 `pingap` 共享入口。它通过 CLI 子命令**或** `PINGWAF_MODE` 环境变量选择运行模式。

| 模式 | 命令 | 角色 |
| --- | --- | --- |
| **控制面** | `pingwaf server` | REST API + gRPC 服务 + 控制台 + PostgreSQL。不代理流量。 |
| **数据面** | `pingwaf agent` | 连接远端控制面，执行规则，在 :80/:443 代理流量。 |
| **All-in-One** | `pingwaf all-in-one` | 单进程同时运行上述两者（Agent 通过本地回环连接 Server）。 |

```bash
# 等价于 `pingwaf all-in-one`
PINGWAF_MODE=all-in-one ./pingwaf
```

---

## ⚙️ 配置说明

PingWAF 通过 **TOML 配置文件**、**`PINGWAF_*` 环境变量**与 **CLI 参数**进行配置，优先级依次升高（后者覆盖前者）。

```bash
pingwaf all-in-one --config /etc/pingwaf/pingwaf.toml

PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml pingwaf all-in-one   # 等价写法
```

> ℹ️ 仓库根目录的 [`pingwaf.toml`](./pingwaf.toml) 是可用的示例配置——用
> `--config` 指定后，其中 `[server]` / `[agent]` 两张表即会生效（启动时会打印
> `pingwaf: loaded N setting(s)`）。键名即 CLI 参数名（下划线形式，如
> `admin_addr`、`max_body_log_size`）；无法识别的键会被提示并忽略。

### 关键环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PINGWAF_CONFIG` | — | TOML 配置文件路径 |
| `PINGWAF_MODE` | — | `server`、`agent` 或 `all-in-one` |
| `PINGWAF_DB_URL` | `postgres://pingwaf:pingwaf@localhost:5432/pingwaf` | PostgreSQL DSN |
| `PINGWAF_ADMIN_ADDR` | `0.0.0.0:9080` | REST API + 控制台监听地址 |
| `PINGWAF_GRPC_ADDR` | `0.0.0.0:9090` | gRPC 控制面监听地址 |
| `PINGWAF_JWT_SECRET` | `change-me-in-production` | JWT 签名密钥（**≥ 16 字符**，生产必改） |
| `PINGWAF_ADMIN_EMAIL` | `admin@pingwaf.local` | 初始管理员邮箱 |
| `PINGWAF_ADMIN_PASSWORD` | `pingwaf123` | 初始管理员密码（**生产必改**） |
| `PINGWAF_ALLOW_REGISTRATION` | `true` | `POST /api/v1/auth/register` 是否接受注册（`docker-compose.yml` 已将其设为 `false`） |
| `PINGWAF_HEARTBEAT_INTERVAL` | `15` | 控制面在注册时下发给 Agent 的心跳间隔（秒）。Agent 侧的 `--heartbeat-interval-secs` 读取同一变量但回退值为 `30`，且仅在控制面未下发间隔时生效 |
| `PINGWAF_TLS_ENABLED` | `true` | REST API 与控制台是否以 HTTPS 提供服务（替换前为自签名证书）；置于 TLS 终止代理之后时设为 `false` |
| `PINGWAF_TLS_SANS` | 主机名、`localhost`、`127.0.0.1` | 生成的自签名证书所覆盖的 SAN 列表（逗号分隔） |
| `PINGWAF_PPROF_ENABLED` | 启用 | 设为 `0`（`false`/`off`/`no`，大小写不敏感）禁用 CPU 采集端点与 MCP `profile_cpu` 工具；只读的内存/指标快照仍可用——详见[性能剖析](./docs/zh/profiling.md#采集审计与开关) |
| `PINGWAF_SERVER_URL` | `http://localhost:9090` | *（agent）* 控制面 gRPC 地址 |
| `PINGWAF_API_KEY` | *（空）* | *（agent）* API Key；为空则通过本地回环自动注册 |
| `PINGWAF_CACHE_DIR` | `./data/cache` | *（agent）* 本地规则缓存目录 |
| `PINGWAF_ES_ENABLED` | `false` | 是否启用 Elasticsearch 日志投递 |
| `PINGWAF_ES_URLS` | *（空）* | 逗号分隔的 Elasticsearch 地址 |

### 默认端口

| 端口 | 用途 |
| --- | --- |
| `9080` | REST API + 内嵌控制台（HTTPS；健康检查 `GET /healthz`，HTTP 亦可访问） |
| `9090` | gRPC 控制面（Agent 连接此端口） |
| `80` / `443` | 代理流量（创建首个站点后绑定；`443` 在签发或上传证书后才会开启——此前仅 `80` 端口提供 HTTP 服务） |

👉 完整配置参考：**[docs/deployment.md](./docs/deployment.md)** 与 **[docs/api.md](./docs/api.md)**。

---

## 📚 文档导航

| 文档 | 内容 |
| --- | --- |
| [docs/quick-start.md](./docs/quick-start.md) | 从零开始，保护你的第一个站点 |
| [docs/deployment.md](./docs/deployment.md) | Docker、二进制 + systemd、分布式拓扑 |
| [docs/user-guide.md](./docs/user-guide.md) | 控制台使用、站点、规则与策略 |
| [docs/zh/http-lifecycle.md](./docs/zh/http-lifecycle.md) | 请求生命周期：各项功能在流水线中的执行阶段（WAF 检查顺序、缓存、错误页）与调试方法 |
| [docs/api.md](./docs/api.md) | REST API 参考（`https://<host>:9080/api/v1`） |
| [docs/README.md](./docs/README.md) | 完整文档索引 |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | 如何参与贡献 |
| [SECURITY.md](./SECURITY.md) | 漏洞披露政策 |
| [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) | 社区行为准则 |

---

## 🤝 参与贡献

欢迎贡献代码！在提交 Pull Request 前，请先阅读 **[CONTRIBUTING.md](./CONTRIBUTING.md)**；如需负责任地报告安全漏洞，请见 **[SECURITY.md](./SECURITY.md)**。

---

## 🙏 致谢

PingWAF 建立在优秀的开源项目之上：

- **[pingap](https://github.com/vicanso/pingap)**（作者 Tree Xie）——PingWAF 数据面所依托的反向代理基础（路由、插件、ACME、缓存、热重载）。
- **[Pingora](https://github.com/cloudflare/pingora)**（Cloudflare）——驱动 `pingap` 的异步网络框架。
- **[libinjection](https://github.com/client9/libinjection)**——WAF 引擎所使用的 SQLi/XSS 检测启发式算法。

PingWAF 是在上述项目之上的衍生作品，新增了 WAF 控制面、数据面 Agent 与检测引擎。它与上游依赖一样，采用相同的 **[Apache License 2.0](./LICENSE)** 分发，并保留了 `pingap`/`Pingora` 的原始版权声明。PingWAF 与 Cloudflare 及 `pingap` 项目**均无关联，也未获其背书**。

---

## 📄 License

PingWAF 基于 **[Apache License 2.0](./LICENSE)** 发布。
