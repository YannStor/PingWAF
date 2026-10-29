---
title: 架构
description: PingWAF 控制面与数据面如何协作，gRPC 协议承载什么，策略如何到达边缘。
minutes: 8
---

PingWAF 把系统拆成两个进程，它们共用同一个二进制。**控制面**持有全部状态；**数据面**承载流量并执行策略。数据面没有自己的数据库，也不应该给它一个。

## 控制面

`pingwaf server` 暴露三类接口：

| 接口 | 默认端口 | 用途 |
| --- | --- | --- |
| REST API + 控制台 | `9080`（HTTPS） | 站点、规则、日志、配置版本 |
| gRPC `ControlPlane` | `9090` | Agent 注册、心跳、规则同步、日志与指标上报 |
| PostgreSQL | `5432` | 唯一的持久化存储；请求日志可选使用 Elasticsearch |

控制台通过 `rust-embed` 编译进二进制，因此不存在需要与 API 保持同步的独立前端部署。

## 数据面

`pingwaf agent` 在 `:80` 与 `:443` 接收流量，执行 WAF 规则、终止 TLS 并反向代理到源站池。它在 `cache_dir` 下维护磁盘规则缓存，当缓存中的配置哈希变化时重建内存中的 provider，大约每五秒检查一次。请求始终通过 `ArcSwap` 读取当前 provider，所以策略变更从不需要重启。

## gRPC 契约

唯一真源是 `pingwaf-proto/proto/control_plane.proto`，服务由 7 个 RPC 组成：

| RPC | 类型 | 用途 |
| --- | --- | --- |
| `RegisterAgent` | 一元 | 加入集群；返回 `agent_id`、`agent_token`、心跳间隔与初始站点配置 |
| `Heartbeat` | 双向流 | 上报存活、统计与证书状态，下发命令 |
| `SyncRules` | 服务端流 | 配置变更后推送新规则包 |
| `ShipLogs` | 客户端流 | 批量上报请求与攻击日志 |
| `ShipCertEvents` | 客户端流 | ACME 签发与续期事件 |
| `ShipMetrics` | 客户端流 | 流量与缓存指标 |
| `GetSiteConfig` | 一元 | 拉取单个站点的完整配置 |

同一服务还承载挑战流程所需的访客登录、Passkey 与会话校验；这些调用使用 agent token 认证，并在控制面不可达时按拒绝处理——失败即不放行。

## 变更如何到达边缘

1. REST 写入（控制台或 API）把新配置保存到 PostgreSQL。
2. 控制面为受影响的作用域记录一份配置快照。
3. `notify_config_changed` 通过既有流向服务该站点的每个 Agent 推送新的 `SiteConfig`。
4. Agent 把配置包写入规则缓存，缓存哈希变化后在内存中完成替换。

## 故障行为

`fail_open` 决定 Agent 在无法连接控制面时的行为：

- `true`（默认）——按最后一次同步的策略继续服务。
- `false`——对没有同步规则的 host 返回 `503`。

站点级 failover 策略优先于全局默认值，且该选择会写入配置，重启后依然生效。

## 运行模式

| 模式 | 命令 | 职责 |
| --- | --- | --- |
| 控制面 | `pingwaf server` | API、gRPC、控制台与数据库；不代理流量 |
| 数据面 | `pingwaf agent` | 连接远端控制面，在 `:80`/`:443` 代理流量 |
| All-in-one | `pingwaf all-in-one` | 同一进程内同时承担两者，Agent 通过回环连接本地 server |

省略子命令时可用 `PINGWAF_MODE` 选择同样的模式。

## 配置版本

每次变更都按作用域版本化。保留策略为：每个作用域最多 50 个版本、30 天历史、快照不超过 2 MiB。回滚会先取咨询锁、写入 `pre-rollback` 快照、恢复上一状态，再把结果记录为新版本——因此回滚本身也可审计、可再回滚。

回滚可以在控制台触发，也可以执行 `pingwaf config rollback <id> --yes`。CLI 路径只记录版本，不会立即推送给 Agent；下一次配置变更或 Agent 重连后生效。
