# cache

HTTP 响应缓存，后端可为内存 [TinyUFO](https://github.com/cloudflare/pingora/tree/main/tinyufo) 或文件存储，支持缓存键控制、惊群防护与 IP 限制的 `PURGE` 方法。

- **步骤：** `request`（固定）
- **注册名：** `cache`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `cache`。 |
| `directory` | string | `/tmp/pingwaf-cache` | 未设置时为文件缓存（该默认路径；容器内 `/tmp` 常为 tmpfs，生产应指向持久路径）。显式设为空或 `memory://…` 选内存后端；其他值作为文件缓存目录。 |
| `namespace` | string | — | 隔离条目；文件后端时成为子目录。 |
| `headers` | string[] | — | 追加到缓存键的请求头（变体缓存）。 |
| `vary_headers` | string[] | — | 源站 `Vary` 响应头的白名单：响应若列出了白名单之外的请求头则**整体不缓存**。不设则接受源站列出的全部。 |
| `max_ttl` | duration | — | 条目寿命上限，封顶上游 `Cache-Control`。 |
| `max_file_size` | bytesize | `1mb` | 大于此尺寸的响应不缓存。 |
| `lock` | duration | `1s` | 防惊群的缓存锁窗口。任意非零时长都有效；`0s` 关闭锁定。 |
| `lock_retries` | int | `2` | 等锁的请求在放弃、自行回源之前重新查询缓存的次数。 |
| `eviction` | bool | 缺席 | 键存在即启用 LRU 淘汰。 |
| `predictor` | bool | 缺席 | 键存在即启用可缓存性预测。 |
| `check_cache_control` | bool | `false` | 要求响应带 `Cache-Control`，否则不存储。 |
| `purge_ip_list` | string[] | `[]` | 允许发起 `PURGE` 的 IP / CIDR。既不是 IP 也不是 CIDR 的条目会在配置校验时报错。 |
| `skip` | string | — | 路径+查询串的正则；匹配的请求完全绕过缓存。 |

### 后端选择

```toml
directory = ""                                   # memory, default size
directory = "memory://pingap?max_size=100mb"     # memory, explicit size
directory = "/opt/pingap/cache"                  # file cache
directory = "/opt/pingap/cache?inactive=1h&reading_max=1000"
```

后端查询参数全集见 [pingap-cache](../crates/cache.md)。

## 示例

```toml
[plugins.httpCache]
category = "cache"
directory = "/opt/pingap/cache"
namespace = "web"
headers = ["Accept-Encoding"]
max_ttl = "1h"
max_file_size = "10mb"
lock = "2s"
eviction = true
predictor = true
purge_ip_list = ["127.0.0.1", "10.0.0.0/8"]
skip = "^/api/"

[locations.web]
upstream = "web"
path = "/"
plugins = ["httpCache"]
```

清理：

```bash
# 单个 URL（同时移除 GET 与 HEAD 两个变体）
curl -X PURGE http://127.0.0.1:6188/assets/app.js
# 204 No Content       -> 已移除（幂等：无缓存时同样返回 204）
# 403 Forbidden        -> IP 不在 purge_ip_list 中

# 整个 namespace（仅文件后端且配置了 namespace）
curl -X PURGE http://127.0.0.1:6188/*
# 200 "purged: 12, fail: 0"
# 501 Not Implemented  -> 未配置 namespace，或内存缓存后端
```

`PURGE /*` 清空该插件缓存的全部内容：namespace 在文件后端以目录形式存在，是精确 URL 之外唯一无需索引即可清除的粒度（存储文件名是完整键的哈希，URL 前缀在磁盘上没有对应结构）。清除会连同内存热层一起处理，且只作用于本机——多实例部署需要对每个节点分别发起。

## 行为

- 仅处理 `GET`、`HEAD` 与 `PURGE`；其他方法跳过插件。
- 缓存键由请求 URI、`namespace` 与所列 `headers` 的值推导。`PURGE` 会同时按 `GET` 与 `HEAD` 构建键，因此清理 `/x` 会移除两种方法创建的条目。若配置了 `headers`，`PURGE` 请求也要带上相同的头——它们是键的一部分。
- 会遵循源站的 `Vary` 响应头：它列出的请求头的每种取值组合在同一个键下存为独立变体，`Vary: *` 则视为不可缓存。`vary_headers` 把这一机制收窄到已知的一组请求头，因为 `Vary: Cookie` 或 `Vary: User-Agent` 意味着每个客户端一个变体。响应若列出了白名单之外的头，**不会**被裁剪成允许的子集，而是直接不缓存——丢弃某个 `Vary` 维度会让所有客户端共用同一份条目。因此 `vary_headers` 为空时，只有不带任何 `Vary` 的响应才会被缓存。`PURGE` 只清主槽位，其后的变体变得不可达，由淘汰或 inactive 扫描回收。
- `lock` 使同一键上的并发未命中等待第一个，而不是全部打到源站。
- 缓存读/写计数写入请求上下文，访问日志中可用 `{:cache_lookup_time}` / `{:cache_lock_time}`。

## 使用说明

- **`eviction` 需要有界后端。** 仅在后端报告非零 `max_size` 时接线，文件后端没有——因此 `eviction` 实际仅对内存有效。文件缓存条目由 inactive 扫描回收（`?inactive=…`）。
- **每个进程只有一个内存后端。** 第一个请求内存缓存的 `cache` 插件创建进程级单例；第二个声明不同 `max_size` 或 `mode` 时会静默复用第一个。用 `namespace` 分隔内容，不要再声明第二个 `directory`。
- 每个不同的 `lock` 时长会在进程生命周期内分配一把共享锁，因此重要的是不同取值的数量，而不是插件实例数。
- 按 `Accept-Encoding` 缓存时请搭配 [`accept_encoding`](accept_encoding.md)，否则变体数量会爆炸。
