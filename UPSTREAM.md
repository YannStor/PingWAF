# UPSTREAM.md — PingWAF 与上游 pingap 的维护边界

PingWAF 是 [`vicanso/pingap`](https://github.com/vicanso/pingap) 的**硬分叉**（hard fork），不是其下游集成或插件。本仓库与上游没有自动合并关系：`pingap-*` 系列代码虽继承自上游，但已为 WAF 场景深度改造（例如 `pingap-plugin/src/waf.rs` 整个请求检测链为 PingWAF 新增），上游的提交无法直接 rebase 进来。本文档说明两边各自的边界、同步方式与测试归属。

## Pingora 归属

代理层的异步网络底座是 Cloudflare 的 [Pingora](https://github.com/cloudflare/pingora)（当前 pin 在 0.9.0，见根 `Cargo.toml` 的 `[workspace.dependencies]`）——pingap 自身即构建于 Pingora 之上，PingWAF 继承了这一层次。对 Pingora 的归属说明与 pingap 的致谢一并保留：README（英文/中文）的 Acknowledgements 一节同时致谢 pingap 与 Pingora，上游版权声明与 Apache-2.0 许可（[LICENSE](./LICENSE)）继续随发布物保留。PingWAF 与 Cloudflare、pingap 维护者均无隶属或背书关系。

## 模块归属

| 归属 | 模块 | 说明 |
|---|---|---|
| **上游继承**（深度改造后维护） | `pingap-{acme,cache,certificate,config,core,discovery,health,imageoptim,location,logger,otel,performance,plugin,proxy,pyroscope,sentry,upstream,util,webhook}` | 反向代理底座：Pingora 生命周期、TLS/ACME、上游 LB、边缘缓存、插件框架及 `pingap-plugin/src/` 下的约 30 个内置插件 |
| **PingWAF 自有** | `pingwaf-{server,proto,agent,waf,challenge,pprof}` | 控制面（Axum API + SeaORM + gRPC 服务）、协议真源、数据面 agent、WAF 检测引擎、挑战子系统、剖析工具 |
| **PingWAF 自有** | `web/` | 内嵌管理控制台（PingWAF DB-backed 界面；`pingap-*` 配置结构体的管理页属 pingap 兼容模式遗留） |
| **PingWAF 自有** | `src/`（根 bin） | CLI 装配：`pingwaf`（对外发布）与 `pingap`（兼容模式入口）共用 `src/main.rs` |

继承部分的修改原则：只做 PingWAF 需要的最小改动，保持上游代码结构可辨识，便于日后人工对照上游修复。

## 上游同步流程

上游修复**按需人工搬运**，不做批量合并：

1. `git fetch upstream`（`upstream` remote 已指向 `vicanso/pingap`），定位相关修复提交：
   `git log upstream/master --oneline -- <pingap-xxx>/`
2. 评估该修复对本仓库仍适用（上游与本项目已分化的部分需人工裁决），`git cherry-pick` 或手工移植到对应 `pingap-*` crate。
3. 搬运后必须跑全量门禁：`make lint`、`make test`，涉及 TLS 的改动另跑 `make lint-rustls` / `make test-rustls`。
4. 在 CHANGELOG 记录来源（上游 commit hash）与适配说明。

同步频率：无固定周期；遇到上游安全修复或本仓库依赖的上游缺陷被修复时执行。**不要**将 `upstream/master` 直接 merge 进 `main`——两个项目的产品语义（配置面、发布物、服务名）已经分叉。

### 已移植：`oidc` 插件（2026-10）

- **来源**：上游 `pingap-plugin/src/oidc.rs`，逐字搬自 commit
  [`77ba8bfebe658827a7bff92acfd05068eb8bb954`](https://github.com/vicanso/pingap/commit/77ba8bfebe658827a7bff92acfd05068eb8bb954)（"feat: add DNS SRV discovery, RSA+ECDSA certificate pairs, OCSP stapling and the oidc plugin"，2026-10-09）。本仓库硬分叉此前缺失该插件——上游 `pingap-plugin/src/` 共 34 个文件，本地原有 31 个，缺 `oidc.rs` 与 `hmac_auth.rs`、`bandwidth_limit.rs`、`ja4_restriction.rs`、`maintenance.rs`、`mirror.rs`、`request_headers.rs`、`uri_block.rs`（其余 7 个尚未移植）。
- **随之补齐的上游共享符号**：`pingap-plugin/src/jwt.rs` 的 `ClaimMap` / `claim_header_value` / `strip_claim_headers` / `parse_claims_to_headers` 与 `JwksSource::new` / `verify_with`；`pingap-core/src/http_header.rs` 的 `protect_from_connection_header`；`pingap-util/src/crypto.rs` 的 `seal` / `unseal`；`pingap-core/src/ctx.rs` 的 `Features::original_uri`（及 `pingap-proxy/src/server.rs` 的设置点——location 改写时保留浏览器原始路径，否则站点配 rewrite 后 OIDC 回调路径失配）。
- **本地适配点（并非与上游完全一致）**：
  1. `Oidc::new` 的日志不打印 params——上游用 `pingap_config::masked_toml` 脱敏，本地未移植其 420 行的 `secrets.rs`，改为只记 `issuer` / `client_id`（两个 secret 绝不写日志）。
  2. 上游测试用 `JwksSource::with_ec_key`（本地无此方法），测试改为起本地 JWKS HTTP 服务、走真实 fetch 路径。
  3. 上游的 `original_uri` 本地原先缺失，本次一并移植（见上）。
  4. 新增上游没有的能力：登录失败与 IdP 不可达的**安全事件上报**（`site.oidc_login_failed` / `site.oidc_idp_unavailable`，经 `pingwaf-agent` 的 `SecurityEvent` 通道）及控制面告警桥接（通知开关 `notify_site_oidc_auth`）。

### 待移植：上游其余 7 个插件（2026-10 盘点）

上游 `pingap-plugin/src/` 现有 34 个文件，本仓库已移植 `oidc` 后为 32 个，下列 7 个仍缺失。特性描述取自上游 `pingap-plugin/docs/<name>.md` 与 `src/<name>.rs`（上游 `main` 分支，2026-10-23 核对）。**注意 `waf.rs` / `rewrite.rs` / `challenge.rs` / `bot_dns.rs` / `host_cache.rs` 是本仓库自有改造，不在上游清单内，勿混淆。**

| 插件 | 阶段 | 定位与核心特性 | 配置键 | 对 PingWAF 的价值 |
|---|---|---|---|---|
| `hmac_auth` | `request` | **HTTP Signatures（draft-cavage）请求签名**：签名覆盖 method/path/query + 配置指定的头 + 可选 body，因此**签名不可重放到另一路径或另一 body**（区别于本仓库已有的 `combined_auth`：那个只签「密钥+时间」，有效期内可用于任意请求）。`validate_body` 用 `Content-Digest`/`Digest` 校验 body，要求 `Content-Length`（无长度 → 411），在最后一片**送往上游之前**比对，签名不符则 401 且上游只拿到头、拿不到完整 body | `keys`（`key_id:secret`，必填）、`signed_headers`（默认 `["host","date"]`，`date` 可由 `x-date` 满足）、`clock_skew`（默认 `5m`，≥1s）、`validate_body`（默认 false）、`hide_credentials`（默认 false） | **中**：给机器对机器 API 提供防重放签名鉴权；`hmac-sha256` 依赖本地已有。与 WAF 无耦合 |
| `bandwidth_limit` | `request` | **出向带宽限速**：只声明速率，实际节流在写 body 处（proxy 转发上游/缓存响应时，在 `sub_filter` 之后、压缩之前；`directory` 流式发文件时由该插件节流）。按「已发送字节/已耗时」计算等待，**客户端自身读取慢不会二次减速**，空闲时间也不累积。header 从不被延迟 | `rate`（如 `"1mb"`，必填 >0）、`after`（默认 0，前 N 字节不限速）、`path`（正则，可选） | **中**：大文件站点防单客户端占满带宽。**需先移植上游 `Ctx::features.body_pace` 与 `BodyPace`（本地缺失）** |
| `ja4_restriction` | `request` | **按 JA4 TLS 指纹做 allow/deny**：按客户端 TLS 栈特征而非 `User-Agent` 判定（脚本自称 Chrome 但握手指纹暴露真实库）。指纹形如 `t13d1516h2_8daaf6152771_e5627efa2ab1`，模式为**非锚定**正则 | `ja4_list`（正则数组，必填）、`type`（`allow`/`deny`，默认 `allow`）、`message`（默认 `Request is forbidden`）、`dry_run`（默认 false） | **中低**：强鉴别手段，但**要求 server 开 `ja4 = true`**，而本地**完全没有 JA4 计算**（上游 `pingap-proxy` 的 JA4 能力本地缺失），移植成本高 |
| `maintenance` | `request` | **维护页 + 放行名单**：整个 location 回维护通知，同时放行维护人员（IP/CIDR 或共享密钥头，**常量时间比较**）。比 `mock` 多出「谁能进去看」这一层。通知标 `no-store` 以免维护结束后仍被缓存 | `enabled`（默认 true）、`status`（默认 503，400–599）、`retry_after`（duration）、`message`（默认 `Service is under maintenance`）、`html`（与 `message` 二选一）、`allow_ip_list`、`allow_header`（`Name: value`） | **高**：运维刚需，纯逻辑、**无新增上游依赖**，可独立移植 |
| `mirror` | `request` / `proxy_upstream` | **流量镜像（影子流量）**：把请求复制一份异步发到 `target`，**不影响主响应**。支持按 `percentage` 抽样、按 `methods` 过滤、body 上限 `max_body_size`、并发上限 `max_inflight`（默认 100）、`timeout`（默认 5s，不跟随重定向）。`compare = true` 时**比对镜像与上游的状态码**，不一致则计数并记日志——这是灰度/重构验证的核心手段。带 `x-pingap-mirror` 头的请求不再镜像，防两个代理互相镜像成环 | `target`（http/https URL，必填，禁 query）、`host`、`percentage`（默认 100，0–100）、`methods`、`max_body_size`（默认 0）、`timeout`（默认 5s）、`max_inflight`（默认 100）、`compare`（默认 false）、`step`（`request`/`proxy_upstream`） | **高**：规则上线前用真实流量做影子比对，与 WAF 规则验证天然契合。**需移植上游 `HandleRequestBody`、`LineBudget`（本地缺失；`ensure_client_ip` 本地已有）** |
| `request_headers` | `request` / `proxy_upstream` | **请求头增删改重命名**（`response_headers` 的反向版）：`add`/`remove`/`set`/`set_not_exists`/`rename` 五类操作，**执行顺序固定**（add → remove → set → set_not_exists → rename），与声明顺序无关。支持**动态变量**：`$hostname`/`$host`/`$scheme`/`$remote_addr`/`$client_ip`/`$forwarded_*`/`$ja4`/`$tls_client_*`/`$proxy_add_x_forwarded_for`/`$http_<name>`/`$<ENV>`/`:<ctx-key>`。拒绝为 `Content-Length`/`Transfer-Encoding`/`Host` 设规则（框架头与 HTTP/2 authority 重写语义） | `add_headers`、`set_headers`、`set_headers_not_exists`、`remove_headers`、`rename_headers`、`step`（默认 `request`） | **高**：比 location 的 `proxy_set_headers` 能力更强（能删、能改名、能条件设置），且与 OIDC 注入的 claim 头配合紧密。**无新增上游依赖**（变量解析本地已有部分能力） |
| `uri_block` | `request` | **按 URI 拦截扫描器**：`paths`/`queries` 正则 + `methods` 白名单。路径**匹配两次**（原样 + 归一化：解码一次、解析 `.`/`..`、`//` 合一、`\`→`/`、去掉 `;parameters`），所以 `\.env$` 能挡住 `/%2eenv`、`/public/../.env`、`//.env`；query 同样原样+解码各匹配一次 | `paths`、`queries`、`methods`（空=全部允许）、`status`（默认 403，400–599）、`message`（默认 `Request is blocked`）、`dry_run`（默认 false） | **中**：轻量扫描器过滤，与 WAF 有功能重叠但更便宜（在 WAF 之前短路，省下缓存查询与鉴权子请求）。上游明确说「它是过滤器，不是 WAF」 |

**移植成本提示**：上表「价值」列中标注的缺失符号（`Ctx::features.body_pace` + `BodyPace`、JA4 计算、`HandleRequestBody` + `LineBudget`）是隐藏成本，与插件本体无关。`maintenance`、`request_headers`、`uri_block` 三个**不依赖任何缺失的上游基础设施**，移植成本最低。

**移植时的通用注意**：
- 本地 `Plugin` trait 的方法名是 `handle_request` / `handle_response`（不是上游旧文档里的 `request_filter`）；`PluginStep` 是插件自己的字段，trait 上**没有** `plugin_step()`。
- `pingap-config` 的 `PluginCategory` 枚举**当前止于 `Challenge`**（`pingap-config/src/common.rs:103`）——`oidc` 插件没有加变体，它靠 `PluginConf` 的 `category` 字符串注册，所以新插件**未必需要**动这个枚举；只有在需要类型化引用时才加。
- `register_plugin!` 与 `PluginConf` 读取 helper 列表见 `pingap-plugin/src/lib.rs`；插件文档模板见 `pingap-plugin/docs/oidc.md`（英文）与 `docs/zh/plugins/oidc.md`（中文）。

## 构建与发布中的边界

- **对外发布物只有 `pingwaf`**：`release.yml` 构建 `--bin pingwaf`，`install.sh` 安装 `pingwaf` 二进制与 `pingwaf.service`，Docker 镜像为 `ghcr.io/shuaizend/pingwaf`。
- `pingap` bin 是上游兼容模式入口（读取上游风格的 `pingap.toml` 配置、复用 pingap-mode 管理页），**不随 release 发布**，仅用于本地兼容验证；`pingap.service` 已删除，勿再引入。
- 根 Cargo package 名为 `pingwaf`；上游版权与致谢保留在 README 的 Acknowledgements 一节与 Apache-2.0 LICENSE。

## 测试归属

CI 的 `cargo test --workspace` 与 `make test` **同时覆盖**两边，不按归属拆分运行——代理栈与 WAF 在同一请求链上（`pingap-proxy` → `pingap-plugin/waf.rs` → `pingwaf-waf`），拆分运行会造成集成盲区。归属仅用于定位：

| 改动落在 | 主要验证 | 说明 |
|---|---|---|
| `pingwaf-*`、`web/` | `cargo test -p <crate>` + 前端 `tsc -b` / `vitest run` | WAF/控制面/数据面逻辑 |
| `pingap-*` | `cargo test -p <crate>` + `make test`（链路集成） | 代理栈行为，注意与 WAF 插件的交互 |
| 请求链 / TLS / 发布物 | `make test` + `make lint-rustls` + `make test-rustls` | 双 TLS 后端与端到端链路 |

见 [CONTRIBUTING.md](./CONTRIBUTING.md) 的测试章节与 [CLAUDE.md](./CLAUDE.md) 的 Architecture 一节（含完整 crate 依赖链）。
