# CODEBUDDY.md

本文件由 CodeBuddy IDE 全文加载。**完整工程规范见根目录 `CLAUDE.md`（263 行，与仓库同步维护），执行任何开发任务前先阅读它**——包括构建命令、架构、feature 门控、配置加载、CI 门禁与文档同步规则。

## 项目速览

PingWAF：基于 `pingap`（Cloudflare Pingora 反向代理）的分布式、集中管控 Web 应用防火墙。

- **控制面** `pingwaf-server`：Axum REST API + tonic gRPC + SeaORM/PostgreSQL，内嵌 `web/` 控制台（rust-embed）
- **数据面** `pingwaf-agent`：gRPC 双向流同步规则（arc-swap 热更新）
- **WAF 引擎** `pingwaf-waf`：normalize → 签名（libinjection/Aho-Corasick）→ 表达式 → 异常评分
- **协议真源** `pingwaf-proto/proto/control_plane.proto`
- `pingap-*` 系列 crate 是真实存在的代理底座（**不是**过时名称）；`pingwaf-*` 是 WAF 层
- MSRV 1.96.0 / edition 2024；前端 React 19 + Vite + TS + Tailwind 4 + TanStack Query，i18n 三语（en/ja/zh）

## 常用命令

```bash
make lint          # CI 门禁：typos + clippy --features=full --all-targets -- -D warnings
make test          # 全量测试（需 full feature）
make check         # cargo check --features=full --all-targets（含磁盘护栏）
make build-web     # 前端构建并拷贝 dist
cd web && npx tsc -b && npx vitest run   # 前端类型检查与测试
```

## 多 Agent 协作（Tech Lead 必读）

本项目配置了 10 角色协作团队，角色定义在 `.codebuddy/agents/`（10 个文件），协作协议见项目规则 `pingwaf-multi-agent`。要点：

1. 主会话（你）= Tech Lead：拆分任务 → 只读调查可并行（批量子代理调用）→ 跨模块改动先冻结接口 → 涉及用户可见变更时按文档同步工作流委派 `pingwaf-doc-prompt`（`make check-docs` 为文档/提示词门禁）→ 集成后强制独立审查（Code Reviewer + Security Reviewer）。
2. 子代理通过 `task` 工具调度；用 `subagent_path` 指向 `.codebuddy/agents/<role>.md` 注入角色。
3. 模型路由意图表（会话内无法程序化指定模型，需用户在 IDE 模型选择器中为准）：

| 角色 | 目标模型 |
|---|---|
| Tech Lead / Architect / Bug Investigator / Security Reviewer / Code Reviewer | deepseek-v4.1-flash |
| Frontend Engineer / Test Engineer / Documentation & Agent Prompt Engineer | glm-5.3-flash |
| Rust Backend & WAF Engineer / CI/CD Engineer | glm-5.3-flashx |

4. 安全红线：未经用户明确授权，禁止 commit/push/release、`git reset --hard`、删除分支/tag、触碰生产 Secrets；不伪造测试结果；安全修复须考虑绕过与回归。
