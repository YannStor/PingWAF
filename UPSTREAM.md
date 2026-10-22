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
