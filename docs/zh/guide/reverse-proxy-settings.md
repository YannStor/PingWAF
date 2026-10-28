# 反向代理基础设置（中文补充）

> 本页补充 2026-10-19 版本新增/变更的反向代理与缓存配置项，以及运维（break-glass）命令。
> 英文完整说明见 [deployment（英文）](../../deployment.md) 与 [api（英文）](../../api.md)；本站其余页面结构与英文站一致。

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

管理面 `9080` 与数据面是两套监听器：控制台在协议探测阶段有 5 秒上限、TLS 握手有 10 秒上限，限制 128 个并发预握手和 512 个活跃 HTTP 连接，并对活跃连接应用 60 秒读写空闲超时；Pingora 数据面仍需显式配置上述下游超时。不要把 `9080` 直接暴露公网，建议只允许管理员 IP、VPN 或 SSH 隧道访问。

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

## 6. 维护命令（break-glass CLI）

`pingwaf` 的四组维护命令**直连 PostgreSQL**，不走 REST API，因此控制面停机、尚未初始化，或被自身 IP 白名单锁死时仍然可用——那正是需要它们的时候。四组都用 `--db-url` 连接（环境变量 `PINGWAF_DB_URL`，默认 `postgres://pingwaf:pingwaf@localhost:5432/pingwaf`），执行完即退出。任一命令的具体参数用 `pingwaf <command> --help` 查看——顶层 `pingwaf --help` 展示的是共享二进制的 `pingap` 兼容模式选项，并不列出这些子命令。

| 命令 | 用途 |
|---|---|
| `pingwaf user list` · `add-admin --email <addr> [--name <name>] [--password <pw>]` · `reset-password --email <addr> [--password <pw>]` | 控制台账号。省略密码时随机生成并只打印一次；`reset-password` 同时吊销该账号的会话 |
| `pingwaf mode observe` · `mode enforce` · `mode status` | 全局观察模式：全量检测、不拦截 |
| `pingwaf security status` · `security allowlist on\|off [--force]` | 9080 自我保护开关。`--force` 允许在白名单为空时启用（此时拒绝所有 API 调用方） |
| `pingwaf config history` · `config show` · `config rollback` | 配置版本历史（见下） |

### `pingwaf config`

```bash
pingwaf config history [--site <uuid|global>] [--limit <n>]   # 倒序，默认 20 条
pingwaf config show <version> [--json]                        # 元信息 + 快照摘要
pingwaf config rollback <version> [--yes]                     # 否则交互确认
```

`history` 按版本号倒序列出，可用 `--site` 过滤到单个站点（填站点 UUID）或整站部署级设置（填 `global`），`--limit` 控制打印条数（默认 20）。`show` 打印某版本的元信息与快照摘要，加 `--json` 输出完整快照。`rollback` 恢复某版本，并把这次恢复记为一个来源为 `cli` 的新版本，因此"回滚的回滚"同样成立、历史保持线性。

**CLI 回滚不会通知运行中的控制面。** 它直接写 PostgreSQL，agent 在下次全量同步或重启后才拿到恢复后的配置；需要立即下发到整个集群时，用控制台回滚（`POST /config-versions/{id}/rollback`，见 [api（英文）](../../api.md)）。
