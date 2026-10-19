# 反向代理基础设置（中文补充）

> 本页补充 2026-10-19 版本新增/变更的反向代理与缓存配置项。英文完整说明见
> [deployment（英文）](../../deployment.md) 与 [api（英文）](../../api.md)；本站其余页面结构与英文站一致。

## 1. 转发到上游的 Host（`upstream_host`）

- 配置位置：`conf/locations.toml` 的 location 段（控制面下发的 location 同字段）。
- 默认值：**不设置** → 保持客户端请求的 `Host`（历史行为，无需迁移）。
- 设置后：转发给上游的 `Host` 头固定为该值；**优先于** `proxy_set_headers`/`proxy_add_headers` 中的 Host 条目，避免同一语义两个来源。
- 取值要求：裸主机名（不含 `http://`、路径、空格），长度 ≤ 253。
- 典型用法：源站按虚拟主机分流，而回源域名固定。

```toml
[locations.app]
upstream = "origin"
upstream_host = "origin.internal.example.com"
```

## 2. downstream 超时与连接生命周期

`[servers.<name>]` 下的监听器级配置（客户端侧）：

| 键 | 默认 | 含义 |
|---|---|---|
| `downstream_read_timeout` | 未设置 | 两次读之间的最大间隔。未设置时慢客户端可长期占用连接；启动日志会提示缺失 |
| `downstream_write_timeout` | 未设置 | 两次写之间的最大间隔 |
| `downstream_connection_timeout` | 未设置 | **读超时上限（连接阶段）**。pingora 0.9 没有"仅首读"的钩子，因此生效值为 `min(该值, downstream_read_timeout)`：它只会**收紧**读超时，设置得比读超时更大时被忽略 |
| `keepalive_request_limit` | 未设置（pingora 默认不限） | 单条 keep-alive 连接最多处理的请求数；pingora 0.9 无 HTTP/1.1 空闲超时，这是**受支持**的连接寿命上限 |
| `h2_idle_timeout` | 未设置（不关闭） | HTTP/2 空闲连接关闭时间 |
| `tcp_idle` / `tcp_interval` / `tcp_probe_count` | 未设置 | 客户端连接的 TCP keepalive 探测 |

推荐起点（并非默认值）：读/写超时 `60s`；`downstream_connection_timeout` 取 `5s`–`10s`（必须小于读超时）；`keepalive_request_limit` 取 `1000` 量级用于限制连接年龄。

## 3. 节点名称（Node name）行为变更

`site_upstreams.name` 已从 API 与界面移除：

- 请求中带 `name`/`upstream_name` 会被忽略（不报错）；
- 响应中不再返回该字段；
- 数据库列保留（为后续"节点组"能力预留），写入时存的是地址的截断值（列宽 100）。

转发、负载均衡、健康检查与访问日志**从未**使用该字段——它们只看 `address` 与 `weight`。

## 4. 缓存策略（cache-settings）与缓存规则（cache-rules）的边界

| | 站点级策略（cache-settings） | 缓存规则（cache-rules） |
|---|---|---|
| 回答 | 本站点缓存**能力与预算** | **某一类请求**如何缓存 |
| 字段 | 总开关、单对象上限、站点磁盘预算、回退 TTL | 匹配条件、边缘 TTL、浏览器 TTL、允许缓存、遵循源站、启用 |
| 不再属于规则 | — | `disk_quota_mb`（请求忽略、响应不返回，列保留） |

磁盘预算的唯一来源：站点 `cache-settings.quota_mb`（缺省继承全局 `/settings/cache.max_space_mb`）。完整模型见仓库内 `.codebuddy/reports/cache-config-unification.md`。

## 5. 系统观测端点（替代已移除的 pprof）

| 端点 | 鉴权 | 说明 |
|---|---|---|
| `GET /api/v1/system/metrics` | 管理员 | 进程/宿主 CPU 与内存只读快照（1 秒复用） |
| `GET /api/v1/system/profile` | 管理员 | 按模块（proxy/waf/cache/plugin/db/control/other）与方法聚合的 CPU/内存归因 |

全部 pprof 端点、MCP `profile_cpu`/`profile_memory` 工具、`PINGWAF_PPROF_ENABLED`、`[basic] pprof_enabled`、仅回环诊断监听与 `mem-prof` 诊断镜像均已移除。迁移说明见 [profiling](../profiling.md)。
