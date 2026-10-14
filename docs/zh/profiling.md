# PingWAF 内置性能剖析

PingWAF 在每个二进制中都内置了 pprof 风格的性能剖析——无需 sidecar、无需外部采集器、无需 cargo feature。用法类似 Go 的 `net/http/pprof`：请求一个端点，拿到一份剖析文件。

两个平面都支持：

| 平面 | 端点 | 鉴权 |
| --- | --- | --- |
| 控制面（`pingwaf-server`） | `GET /api/v1/debug/pprof/{profile,flamegraph,memory}` | 管理员 JWT Bearer token |
| 数据面（pingap admin 插件） | `GET {admin-path}/api/pprof/{profile,flamegraph,memory}` | admin 插件凭据 |

在控制台中，管理员也可以在「设置 → 关于」的**性能诊断**卡片里直接下载这三类文件（CPU 剖析、SVG 火焰图、内存快照），无需手工拼 URL。

## 端点

- `profile` — gzip 压缩的 pprof protobuf，与 `go tool pprof` 期望的线格式完全一致。采样时长 `seconds`（1-120，默认 30），频率 `frequency` Hz（1-1000，默认 99——避开整数以防止采样器与周期性任务同步）。
- `flamegraph` — 由 inferno 渲染的 SVG 火焰图，浏览器直接打开。
- `memory` — 进程 RSS 与系统内存的 JSON 快照，立即返回。`rss_bytes` 是本进程占用；`total_memory_bytes`/`used_memory_bytes` 是**宿主机**内存（容器内即宿主总量，不是容器限额），由 `used_memory_scope: "system"` 与 `process_memory_scope: "process"` 标注。资源卡片应使用 `rss_bytes` 展示进程占用。

采样是进程级单例：并发的第二个采集请求会收到 `409 Conflict`。报告符号化在异步运行时之外执行，因此一次采集的成本是一个睡眠中的请求加上采样器自身消耗的 CPU（99 Hz 约 1%）。

采样器按**进程 CPU 时间**触发（`SIGPROF` / `ITIMER_PROF`），而非墙钟。空闲进程的采集窗口内拿不到样本：此时端点不再返回空剖析，而是回答 `409 Conflict` 并给出引导——在负载下重试，或改用 `memory` 快照。若会话期间 CPU 时间增量不足墙钟时长的 1%，同样按此拒绝。

## 采集剖析

控制面：

```bash
go tool pprof -http=: http://localhost:9080/api/v1/debug/pprof/profile?seconds=30
```

数据面（剖析由二进制自带的 admin 插件提供，仅在传入 `--admin` 时挂载；请把
`<admin-addr>` / `<admin-path>` 换成你的实际值——例如 `make dev` 下为
`127.0.0.1:3018` 与 `/admin`——admin 插件鉴权用 `-H` 或浏览器会话）：

```bash
curl -u admin:password \
  "http://<admin-addr>/<admin-path>/api/pprof/profile?seconds=30" -o pingwaf-cpu.pb.gz
go tool pprof -http=: pingwaf-cpu.pb.gz
```

没有 Go 工具链时直接看火焰图：

```bash
curl -u admin:password \
  "http://<admin-addr>/<admin-path>/api/pprof/flamegraph?seconds=30" > flamegraph.svg
open flamegraph.svg
```

## 符号：用 `release-perf` 构建

默认 `release` profile 会 strip 调试符号，`release` 二进制的剖析里大多是 `Unknown` 帧。要可读的火焰图：

```bash
make release-perf        # cargo build --profile=release-perf --features=perf
```

`release-perf` 继承 `release` 但保留 `debug = 1` 且不 strip。它是诊断用构建——生产环境仍运行 strip 过的 `release` 二进制；排查问题时把 `release-perf` 二进制带到同一环境。

## 读图

- 最宽的方块就是 CPU 时间所在；上方的方块是调用者。
- 数据面值得关注的是 `pingwaf_waf`（规则求值）、`pingap_proxy`（上游转发）与 `pingap_cache`（缓存查找）。
- 把负载下的采集与空闲时的采集对比，差值就是热点路径。

如需持续在线剖析并上报服务器，参见 Pyroscope 集成（`pingap-pyroscope`，`--features=pyro`）。内置端点用于按需排查。

## 平台支持

CPU 采样**仅在 Linux 上提供**：采样信号处理器在 Linux 上使用 pprof-rs 自带的信号安全 DWARF 展开器。macOS 上展开需要经过 libunwind，它不是异步信号安全的，可能直接在处理器内中止进程（tikv/pprof-rs#36），因此采集端点在非 Linux 平台拒绝启动并返回 `501 Not Implemented`，而不是冒着进程崩溃的风险。`memory` 快照在所有平台可用。
