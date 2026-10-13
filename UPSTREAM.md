# UPSTREAM.md — PingWAF 与上游 pingap 的维护边界

PingWAF 是 [`vicanso/pingap`](https://github.com/vicanso/pingap) 的**硬分叉**（hard fork），不是其下游集成或插件。本仓库与上游没有自动合并关系：`pingap-*` 系列代码虽继承自上游，但已为 WAF 场景深度改造（例如 `pingap-plugin/src/waf.rs` 整个请求检测链为 PingWAF 新增），上游的提交无法直接 rebase 进来。本文档说明两边各自的边界、同步方式与测试归属。

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
