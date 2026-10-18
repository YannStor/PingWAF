# PingWAF 系统观测与归因

PingWAF 在每个二进制中都内置了只读的自我观测：两个管理端点，分别报告进程当前的 CPU 与内存占用（`/system/metrics`），以及时间花在了哪里（模块与方法归因，`/system/profile`）。没有采样、没有栈回溯、没有分配器钩子、没有 sidecar，也没有需要单独部署的诊断镜像——一切在所有平台、所有构建下都可用。

> **从已移除的 pprof 端点迁移。** 早先版本提供 pprof 风格的 CPU 采样（`/api/v1/debug/pprof/*` 与数据面 `/api/pprof/*` 路由）、`mem-prof` 堆 dump 构建、MCP 工具 `profile_cpu`/`profile_memory`、`PINGWAF_DEBUG_LISTEN_ADDR` 回环监听，以及 `pprof_enabled` / `PINGWAF_PPROF_ENABLED` 开关。以上内容已**全部移除**。其中的观测部分由 `/api/v1/system/metrics` 承接；归因部分由 `/api/v1/system/profile` 取代，且采用刻意不同的记账方式——对应关系见「[与 pprof 的差异](#与-pprof-的差异)」。

两个端点都要求管理员 JWT Bearer token（与其余 API 相同的 `AdminUser` 鉴权）。

## `GET /api/v1/system/metrics`

进程/主机的 CPU 与内存瞬时快照。无采集会话、无状态：处理器读取操作系统本来就维护的计数器（`/proc` 或平台等价物，经阻塞任务执行以免卡住异步 worker），立即返回。

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:9080/api/v1/system/metrics"
```

**响应（200）：**

```json
{
  "cpu": {
    "process_cpu_percent": 12.5,
    "host_cpu_percent": 8.1,
    "cores": 4,
    "collected_at_ms": 1760000000000
  },
  "memory": {
    "rss_bytes": 120258048,
    "virtual_bytes": 805984256,
    "total_memory_bytes": 17179869184,
    "used_memory_bytes": 9663676416,
    "rss": "121.2 MB",
    "total_memory": "16.0 GB",
    "used_memory": "9.0 GB",
    "collected_at_ms": 1727443200000,
    "used_memory_scope": "system",
    "process_memory_scope": "process",
    "container_memory_used_bytes": 805306368,
    "container_memory_limit_bytes": 1073741824,
    "container_memory_used": "805.3 MB",
    "container_memory_limit": "1.0 GB",
    "container_memory_scope": "cgroup_v2"
  }
}
```

（数值仅为示意；结构即服务端返回的形状。）

### `cpu` — 进程与机器 CPU

| 字段 | 含义 |
| --- | --- |
| `process_cpu_percent` | 本进程 CPU 占用，按单核百分比计（多线程工作可超过 100） |
| `host_cpu_percent` | 全机各核心的平均 CPU 占用百分比 |
| `cores` | 机器 CPU 核心数 |
| `collected_at_ms` | 快照采集时刻（Unix 毫秒时间戳） |

### `memory` — 进程 RSS、主机内存与容器口径

| 字段 | 含义 |
| --- | --- |
| `rss_bytes` / `rss` | 本进程常驻内存（字节 / 人类可读）——进程占用卡片请使用它 |
| `virtual_bytes` | 本进程虚拟内存（字节） |
| `total_memory_bytes` / `total_memory` | **宿主机**内存总量（容器内即宿主总量，不是容器限额） |
| `used_memory_bytes` / `used_memory` | **宿主机**已用内存 |
| `used_memory_scope` / `process_memory_scope` | 口径标注：主机数值为 `"system"`，`rss` 为 `"process"` |
| `container_memory_used_bytes` / `container_memory_limit_bytes` | cgroup 用量与限额，**仅**在容器设置了内存限额时出现（否则为 `null`） |
| `container_memory_used` / `container_memory_limit` | 人类可读的容器用量与限额 |
| `container_memory_scope` | 容器数值来自的 cgroup 版本（`"cgroup_v1"` / `"cgroup_v2"`） |

容器字段存在时与 `docker stats` 显示一致，此时应优先于宿主机口径引用。

成本是一次系统表刷新（CPU + 内存）——足以支撑仪表盘轮询，也没有开关：它是普通管理端点，所有构建可用。

## `GET /api/v1/system/profile`

按模块与方法的 CPU/内存归因。这**不是**采样剖析——它是纯 Rust 插桩（`pingwaf-profiler`）：了解自己在做什么的代码，自己记账。

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:9080/api/v1/system/profile"
```

**响应（200）：**

```json
{
  "collected_at_ms": 1760000000000,
  "total_cpu_ms": 48213.4,
  "modules": [
    { "module": "proxy",   "cpu_ms": 30102.1, "cpu_share": 0.62, "mem_bytes": 41943040, "mem_share": 0.55, "calls": 102341, "avg_us": 294.1 },
    { "module": "waf",     "cpu_ms": 11101.2, "cpu_share": 0.23, "mem_bytes": 8388608,  "mem_share": 0.11, "calls": 98111,  "avg_us": 113.1 },
    { "module": "cache",   "cpu_ms": 4000.8,  "cpu_share": 0.08, "mem_bytes": 15728640, "mem_share": 0.21, "calls": 44120,  "avg_us": 90.7 },
    { "module": "plugin",  "cpu_ms": 1500.1,  "cpu_share": 0.03, "mem_bytes": 2097152,  "mem_share": 0.03, "calls": 30112,  "avg_us": 49.8 },
    { "module": "db",      "cpu_ms": 1000.6,  "cpu_share": 0.02, "mem_bytes": 1048576,  "mem_share": 0.01, "calls": 2140,   "avg_us": 467.6 },
    { "module": "control", "cpu_ms": 400.2,   "cpu_share": 0.01, "mem_bytes": 524288,   "mem_share": 0.01, "calls": 980,    "avg_us": 408.4 },
    { "module": "other",   "cpu_ms": 108.4,   "cpu_share": 0.00, "mem_bytes": 0,        "mem_share": 0.00, "calls": 210,    "avg_us": 516.2 }
  ],
  "methods": [
    { "method": "waf::evaluate",  "cpu_ms": 9200.4, "calls": 98111, "avg_us": 93.8 },
    { "method": "proxy::forward", "cpu_ms": 7100.9, "calls": 88430, "avg_us": 80.3 }
  ]
}
```

（数值仅为示意。）

### 归因机制

- **模块**——进程的功能域记录在定长的原子数组中。每个被插桩的作用域用一次 `fetch_add` 把耗时累加进所属模块；响应中始终出现 7 个模块：`proxy`、`waf`、`cache`、`plugin`、`db`、`control`、`other`（尚未插桩的部分）。
- **方法**——具名调用点（如 `"proxy::forward"`、`"waf::evaluate"`）用 `timed_method` 计时，存放在并发 map 中。只对关键热路径插桩，因为 map 查找才是开销所在。
- **内存**——**上报**而非拦截。拥有大块结构的模块（缓存容量、WAF body 缓冲、日志批次）自行发布当前字节数；没有分配器钩子，因此适配任何分配器与任何平台。`mem_bytes` 是「当前持有的字节数」，不是累计分配量。

### 响应字段

| 字段 | 含义 |
| --- | --- |
| `collected_at_ms` | 快照采集时刻（Unix 毫秒时间戳） |
| `total_cpu_ms` | 所有模块累计归因的 CPU 时间（毫秒） |
| `modules` | 固定 7 行，每模块一行，顺序固定（`proxy`、`waf`、`cache`、`plugin`、`db`、`control`、`other`） |
| `modules[].module` | 模块键 |
| `modules[].cpu_ms` | 归因到该模块的累计 CPU 时间（毫秒） |
| `modules[].cpu_share` | 占 `total_cpu_ms` 的比例，0.0–1.0 |
| `modules[].mem_bytes` / `mem_share` | 模块当前上报持有的字节数，及其占总量的比例 |
| `modules[].calls` / `avg_us` | 计时操作次数与平均每次微秒数 |
| `methods` | 方法行，最热在前，最多 40 行 |
| `methods[].method` | 调用点名称 |
| `methods[].cpu_ms` / `calls` / `avg_us` | 与模块行语义相同 |

计数器**自进程启动起累计**（仅重启时清零），因此读法是「启动以来时间花在哪」，不是「此刻哪里最热」。要看实时情况，可间隔数秒取两次快照、比较 `cpu_ms` 的差值——正差值最大的就是当前热点。通常值得关注的是 `waf`（规则求值）、`proxy`（上游转发）与 `cache`（缓存查找）。

### 开销

记账只是每个被插桩作用域上的几次 relaxed 原子加：没有采样信号、没有栈回溯、没有符号化，热路径上除方法 map 查找外没有额外分配。同一套记账在笔记本的 debug 构建和容器里 strip 过的 release 构建下行为一致，这也是该端点没有平台限制、没有 feature 开关、不需要诊断镜像的原因。端点本身天然有界——7 行模块、最多 40 行方法、KB 级 JSON——且由原子计数计算得出，轮询成本很低。

## 与 pprof 的差异

| 已移除 | 替代 |
| --- | --- |
| `GET /api/v1/debug/pprof/{profile,flamegraph,memory,heap}`、`.../cpu/{metrics,dashboard.svg,summary}`、`POST .../cpu/summary/import` | `GET /api/v1/system/metrics`（CPU + 内存快照）与 `GET /api/v1/system/profile`（归因） |
| 数据面 admin 路由 `GET {admin-path}/api/pprof/*` | 控制面上同样的两个端点 |
| MCP 工具 `profile_cpu` / `profile_memory` | 任意管理员客户端直接读取这两个端点 |
| 回环诊断监听（`PINGWAF_DEBUG_LISTEN_ADDR`） | 随其服务的端点一并移除 |
| `[basic] pprof_enabled` / `PINGWAF_PPROF_ENABLED` 开关 | 不再存在开关——观测端点就是普通管理端点 |
| `mem-prof` cargo feature 与 `Dockerfile.memprof` | 不再需要诊断镜像；归因在正式二进制中即可用。`release-perf` 构建与 `Dockerfile.perf` 镜像保留，供外部工具带外剖析 |

失去了什么、去哪里补：

- **逐函数火焰图 / 栈采样。** 产品内已不存在。使用 `/system/profile` 的模块与方法表：它们回答「哪个功能域、哪个被插桩的热路径占大头」——这正是旧 summary 端点最终被压缩成的那类答案。
- **jemalloc 堆 dump（`mem-prof`）。** 不再可用。用 `memory.rss_bytes` 与各模块 `mem_bytes` 量表观察*各子系统占用多少*；要回答*哪段代码在分配*，请在非生产副本上用带外方式挂外部剖析器（如 `valgrind`/`heaptrack`）。
- **`go tool pprof` 文件。** 端点不再产出 pprof protobuf，也没有可导入的对象（旧的 `summary/import` 端点已移除）。

如需持续在线剖析并上报服务器，Pyroscope 集成（`pingap-pyroscope`，`--features=pyro`）仍然可用——它与本次移除的端点无关。
