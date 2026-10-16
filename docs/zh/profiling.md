# PingWAF 内置性能剖析

PingWAF 在每个二进制中都内置了 pprof 风格的性能剖析——无需 sidecar、无需外部采集器，CPU 采样无需任何 cargo feature。（唯一的例外是堆归因：需要诊断用的 `mem-prof` 构建，见「[堆归因](#堆归因mem-prof-构建与-debugpprofheap)」。）用法类似 Go 的 `net/http/pprof`：请求一个端点，拿到一份剖析文件。

两个平面都支持：

| 平面 | 端点 | 鉴权 |
| --- | --- | --- |
| 控制面（`pingwaf-server`） | `GET /api/v1/debug/pprof/{profile,flamegraph,memory,heap}`、`GET /api/v1/debug/pprof/cpu/{metrics,dashboard.svg}` | 管理员 JWT Bearer token |
| 数据面（pingap admin 插件） | `GET {admin-path}/api/pprof/{profile,flamegraph,memory}` | admin 插件凭据 |

`heap` 仅存在于控制面，且仅在 `mem-prof` 诊断构建中可用（其余构建返回 `501`）——见「[堆归因](#堆归因mem-prof-构建与-debugpprofheap)」。

在控制台中，管理员也可以在「设置 → 关于」的**性能诊断**卡片里直接下载这三类文件（CPU 剖析、SVG 火焰图、内存快照），无需手工拼 URL。

## 端点

- `profile` — gzip 压缩的 pprof protobuf，与 `go tool pprof` 期望的线格式完全一致。采样时长 `seconds`（1-5，默认 5——默认值即硬上限，窗口无法通过查询参数放大），频率 `frequency` Hz（1-250，默认 99——避开整数以防止采样器与周期性任务同步）。
- `flamegraph` — 由 inferno 渲染的 SVG 火焰图，浏览器直接打开。
- `cpu/dashboard.svg` — 一次采集的自包含 SVG **仪表盘**：窗口内进程 CPU 占比、任务分布（按包含性样本占比排序的热点函数）、关键指标，以及颜色编码的状态徽章（`NORMAL` / `HIGH LOAD` / `IDLE` / `PLATFORM-LIMITED`）。与原始采集端点不同，它在非 Linux 平台**降级**而非报 501：渲染实时读数并标注 `PLATFORM-LIMITED`。加 `?refresh=<1-60>` 后 SVG 会内嵌一段脚本，在浏览器打开文件期间轮询 `cpu/metrics` 刷新实时行；由于该端点是 Bearer 鉴权，而保存后的文件无法携带请求头，调用方本次请求的 token 会被内嵌进轮询脚本（由 `refresh` 参数显式开启、响应 `no-store`，且仪表盘自身印有"勿外传"警示）。
- `cpu/metrics` — 轻量实时 CPU 快照（进程与主机占用、核心数），供仪表盘刷新脚本轮询；仅一次 sysinfo 刷新，不占用采样会话。它还携带 `profiling` 对象（见「采集审计与开关」）。
- `memory` — 进程 RSS 与系统内存的 JSON 快照，立即返回。`rss_bytes` 是本进程占用；`total_memory_bytes`/`used_memory_bytes` 是**宿主机**内存（容器内即宿主总量，不是容器限额），由 `used_memory_scope: "system"` 与 `process_memory_scope: "process"` 标注。在设置了内存限额的容器内，快照还会附带 cgroup 口径的 `container_memory_used_bytes`/`container_memory_limit_bytes`（`container_memory_scope: "cgroup_v1" | "cgroup_v2"`），与 `docker stats` 显示一致——存在时应优先于宿主机口径引用。资源卡片应使用 `rss_bytes` 展示进程占用。

采样是进程级单例：并发的第二个采集请求会收到 `409 Conflict`。报告符号化在异步运行时之外执行，因此一次采集的成本是一个睡眠中的请求加上采样器自身消耗的 CPU（99 Hz 约 1%）。

采样器按**进程 CPU 时间**触发（`SIGPROF` / `ITIMER_PROF`），而非墙钟。空闲进程的采集窗口内拿不到样本：此时端点不再返回空剖析，而是回答 `409 Conflict` 并给出引导——在负载下重试，或改用 `memory` 快照。若会话期间 CPU 时间增量不足墙钟时长的 1%，同样按此拒绝。

要在空闲进程上采集，可追加 `?selfload=true`（`profile`、`flamegraph` 与 `cpu/dashboard.svg` 均接受；控制台「性能诊断」卡片中该开关默认开启）。在整个采集窗口内，服务端会生成轻量的进程内负载——两个 tokio 任务在短暂自旋与让出之间交替——让按时间触发的采样器有帧可采。预期管理：selfload 剖析展示的是异步运行时与该合成负载，**不是**站点业务函数。它回答的是"采集链路是否可用"并提供运行时层面的基线；*内存*归因请用[堆端点](#堆归因mem-prof-构建与-debugpprofheap)，真实流量下的 CPU 归因则应在有流量时采集。

## 采集剖析

控制面：

```bash
go tool pprof -http=: http://localhost:9080/api/v1/debug/pprof/profile?seconds=5
```

数据面（剖析由二进制自带的 admin 插件提供，仅在传入 `--admin` 时挂载；请把
`<admin-addr>` / `<admin-path>` 换成你的实际值——例如 `make dev` 下为
`127.0.0.1:3018` 与 `/admin`——admin 插件鉴权用 `-H` 或浏览器会话）：

```bash
curl -u admin:password \
  "http://<admin-addr>/<admin-path>/api/pprof/profile?seconds=5" -o pingwaf-cpu.pb.gz
go tool pprof -http=: pingwaf-cpu.pb.gz
```

没有 Go 工具链时直接看火焰图：

```bash
curl -u admin:password \
  "http://<admin-addr>/<admin-path>/api/pprof/flamegraph?seconds=5" > flamegraph.svg
open flamegraph.svg
```

控制面 CPU 仪表盘（自包含 SVG；追加 `&refresh=5` 内嵌实时刷新脚本后在浏览器打开）：

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9080/api/v1/debug/pprof/cpu/dashboard.svg?seconds=5&refresh=5" \
  > cpu-dashboard.svg
open cpu-dashboard.svg
```

MCP `profile_cpu` 工具返回同一仪表盘（JSON 结果的 `svg` 字段），连同摘要与解读说明；60 秒内的重复调用会重放缓存的上次采集。

## 符号：用 `release-perf` 构建

默认 `release` profile 会 strip 调试符号，`release` 二进制的剖析里大多是 `Unknown` 帧。要可读的火焰图：

```bash
make release-perf        # cargo build --profile=release-perf --features=perf
```

`release-perf` 继承 `release` 但保留 `debug = 1` 且不 strip。它是诊断用构建——生产环境仍运行 strip 过的 `release` 二进制；排查问题时把 `release-perf` 二进制带到同一环境。

### 预构建 perf 镜像

Docker 部署有按需产线：在 Actions 页运行 **Release (perf image)** 工作流（或 `gh workflow run release-perf.yml`），它会用 `Dockerfile.perf`（同样的多阶段构建，`--profile release-perf`）发布 `ghcr.io/shuaizend/pingwaf:perf`（amd64）。临时用它替换常规镜像、复现负载、采集剖析，然后切回常规镜像——该镜像体积为常规版的 2-4 倍，且不进入版本 manifest。

## 堆归因：`mem-prof` 构建与 `/debug/pprof/heap`

CPU 火焰图回答的是"CPU 时间花在哪"。要回答"哪个函数在分配 / 占用内存"，正确的工具是堆剖析，以 `mem-prof` cargo feature 提供：

```bash
cargo build --profile=release-perf --features=mem-prof
```

`mem-prof` 把全局分配器从 mimalloc 切换为 tikv-jemallocator（启用堆剖析支持的 jemalloc）。这会改变分配器语义（与正式镜像不同），因此它是诊断构建而非生产构建——排查时与 `release-perf` 一样，把该二进制带到同一环境。启动进程时需设置 `MALLOC_CONF=prof:true`（jemalloc 的堆剖析默认关闭且按采样进行），然后请求 dump：

```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost:9080/api/v1/debug/pprof/heap" -o pingwaf-heap.prof
```

该端点触发一次 jemalloc `prof.dump`，把 jeprof 格式的 dump 作为附件返回——其中包含每条存活分配路径及其占用的字节数。用 `jeprof`（随 gperftools 发布；同源码修订版的任意构建均可用于符号化）渲染为调用图：

```bash
jeprof --svg <binary> pingwaf-heap.prof > heap.svg
```

行为要点：

- 与 `memory` 快照一样是只读端点——不占用采样会话、立即返回——但它受[调试采集开关](#采集审计与开关)管控：关闭采集的部署对 heap dump 同样返回 `503`。
- 非 `mem-prof` 构建上该端点返回 `501 Not Implemented`，并引导改用 `memory` 快照查看聚合用量。
- dump 只反映被采集的那一瞬间（`no-store`，不缓存）。
- 仅控制面提供：数据面 admin 插件只提供三个 CPU 采集端点，没有 heap dump。

## 读图

- 最宽的方块就是 CPU 时间所在；上方的方块是调用者。
- 数据面值得关注的是 `pingwaf_waf`（规则求值）、`pingap_proxy`（上游转发）与 `pingap_cache`（缓存查找）。
- 把负载下的采集与空闲时的采集对比，差值就是热点路径。

如需持续在线剖析并上报服务器，参见 Pyroscope 集成（`pingap-pyroscope`，`--features=pyro`）。内置端点用于按需排查。

## 采集审计与开关

剖析采集是可审计的。`GET /debug/pprof/cpu/metrics` 的响应中包含一个 `profiling` 对象，记录本进程生命周期内的采集统计：

```json
"profiling": {
  "total_started": 2,
  "last": { "finished_at_ms": 1760000000000, "duration_secs": 30.0, "outcome": "ok" }
}
```

- `total_started` — 进程启动以来开始的采样会话总数，含失败或中途放弃的会话。
- `last` — 最近一次结束（或放弃）的会话：`finished_at_ms`（Unix 毫秒时间戳）、`duration_secs`（采集窗口墙钟时长）、`outcome`——产出剖析文件时为 `ok`，否则为 `idle`、`no_samples`、`report_error`、`abandoned`、`load_guard`（被[负载守卫](#负载守卫)拒绝）或 `unsupported`。

每次采集结束（成功、被拒绝或放弃）时都会输出一条结构化 INFO 审计日志：

```text
profiling capture finished endpoint=… outcome=… rss=…
```

`rss` 是采集刚结束时的进程 RSS，便于把内存毛刺与采集活动关联排查。

可在部署层面通过 `conf/basic.toml` 的 `[basic] pprof_enabled` 配置键关闭采集——布尔值，默认 `true`（调试采集模式开启）。旧的环境变量 `PINGWAF_PPROF_ENABLED=0`（或 `false`/`off`/`no`，大小写不敏感）仍然有效，但仅作为回退：**仅当该配置键未显式设置时生效**，配置文件优先。修改后需重启进程生效。

开关关闭时，所有 CPU 采集入口都返回 `503 Service Unavailable`：控制面三个端点（`profile`、`flamegraph`、`cpu/dashboard.svg`）、数据面 admin 插件上的同一批采集端点、MCP `profile_cpu` 工具，以及[堆端点](#堆归因mem-prof-构建与-debugpprofheap)。只读快照端点不受影响——`memory` 与 `cpu/metrics` 在采集关闭时照常响应，这恰好是关闭采集后排障所需的视图。

**采集开销实测：** 在 v0.27.2（mimalloc）容器上完成 2 次 30s @ 99 Hz 采集后，进程 VmHWM 仅 79 MB——**在空闲进程上** pprof 采集本身不会造成内存毛刺。（当时的采集窗口早于现行 5 秒硬上限；窗口更小只会进一步缩小暴露面。）负载下的情况则完全不同（见「[负载守卫](#负载守卫)」）。排查 OOM 或内存毛刺时，先看 `/debug/pprof/cpu/metrics` 的 `profiling` 字段与采集审计日志，排除（或确认）采集活动后再查其他方向。

## 负载守卫

CPU 采集启动前（`profile`、`flamegraph`、`cpu/dashboard.svg` 三个端点与 MCP `profile_cpu` 工具均如此）会先检查进程 CPU 占用——即仪表盘轮询的实时快照中的单核百分比。超过单核 40% 时采集被直接拒绝：

- HTTP 端点返回 `503 Service Unavailable`，message 携带实测值与上限：`the process is busy (CPU N% of one core, limit 40%); profiling under load risks an out-of-memory kill — retry when the load drops`。
- MCP `profile_cpu` 工具返回等义错误文本。
- 审计日志记录 `outcome=load_guard`。
- 只读快照端点**不受守卫影响**——进程繁忙时 `memory` 与 `cpu/metrics` 照常响应。
- `?selfload=true` 的合成负载只在守卫通过之后才启动，且刻意保持轻量（短促自旋、间歇让出），因此开启它不会让繁忙进程绕过守卫。

守卫的由来：pprof-rs 采样器在其 `SIGPROF` 信号处理器内分配内存（该 crate 的已知设计限制）。空闲进程上采集无害（实测 VmHWM 79 MB），但采样繁忙进程可在 30-90 秒内使 RSS 从几十 MB 冲至 1GB 以上，直至被 OOM killer 击杀（2026-10-16 在演示实例上实测发生两次）。

> **警告——负载下采集可致进程 OOM。** 生产实例建议保持调试采集开关关闭（`[basic] pprof_enabled = false`；旧部署可用 `PINGWAF_PPROF_ENABLED=0`），仅在排查问题时于低峰期临时开启。宿主机建议 `transparent_hugepage=madvise`；容器建议配置内存限额（`mem_limit`），避免一次不当采集拖垮整机。

## 平台支持

CPU 采样**仅在 Linux 上提供**：采样信号处理器在 Linux 上使用 pprof-rs 自带的信号安全 DWARF 展开器。macOS 上展开需要经过 libunwind，它不是异步信号安全的，可能直接在处理器内中止进程（tikv/pprof-rs#36），因此采集端点在非 Linux 平台拒绝启动并返回 `501 Not Implemented`，而不是冒着进程崩溃的风险。`memory` 快照、`cpu/metrics` 与 `cpu/dashboard.svg` 的降级模式在所有平台可用。
