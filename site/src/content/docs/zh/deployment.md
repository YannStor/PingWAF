---
title: 部署
description: Docker Compose 与源码构建、端口、配置优先级、systemd 单元以及分布式 Agent 部署。
minutes: 10
---

## 部署形态

**All-in-one** 在单个进程内同时运行控制面与一个数据面，适合单机、评估以及只需一个边缘的中小型部署。

**分布式** 运行一个 `pingwaf server` 与任意数量的 `pingwaf agent`。状态由控制面持有，Agent 除规则缓存外无状态，因此新增边缘节点无需触碰数据库。

## 端口

| 端口 | 用途 | 说明 |
| --- | --- | --- |
| `9080` | REST API + 控制台 | 使用自签证书提供 HTTPS，直到你替换它；请保持私有 |
| `9090` | gRPC 控制面 | Agent 在此连接；默认 TLS，`grpc_tls_mode = "off"` 会降级为明文 |
| `80` | 代理流量 | 创建首个站点后开始绑定 |
| `443` | 代理流量 | 证书签发或上传后才开放 |

`GET /healthz` 在 HTTP 与 HTTPS 下都会响应，适合作为 compose 健康检查与负载均衡探针；其余路径一律跳转 HTTPS。

## Docker Compose

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
```

compose 文件以 all-in-one 模式启动 `ghcr.io/shuaizend/pingwaf:latest`，并与 `postgres:16-alpine` 一起运行，发布 `80`、`443`、`9080` 与 `9090`。数据库端口默认只绑定 `127.0.0.1`。

> `hostname` 必须保持稳定。控制面按 hostname 与 API key 匹配重新注册，容器 ID 变化会留下「幽灵离线节点」。

## 源码构建

| 工具 | 版本 | 原因 |
| --- | --- | --- |
| Rust | 1.96+（MSRV） | 构建二进制 |
| Node.js | 26.12.1+ | 构建内嵌控制台，`web/.npmrc` 设置了 `engine-strict=true` |
| `protoc` | 较新版本 | gRPC 代码生成——**必需** |
| `cmake` | 较新版本 | 构建 TLS 后端 |
| PostgreSQL | 14+（推荐 16） | 控制面存储，角色需要建表权限 |

缺少 `protoc` 时 `pingwaf-proto` 会静默写入占位文件，随后下游 crate 编译失败——构建前先安装它。

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release --bin pingwaf --features full
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

在 Linux 上，`install.sh` 会下载预编译包、安装到 `/usr/local/bin`、生成 `/etc/pingwaf/pingwaf.toml` 与 systemd 单元，并自动启动 Agent（`--mode all-in-one|server|agent`，`--no-systemd` 可跳过单元安装）。

## 配置优先级

配置依次从 TOML 文件、`PINGWAF_*` 环境变量、CLI 参数读取，后者覆盖前者；未知 TOML 键会被报告并跳过。

```bash
pingwaf all-in-one --config /etc/pingwaf/pingwaf.toml
PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml pingwaf all-in-one   # 等价写法
```

`[server]` 表覆盖 `db_url`、`admin_addr`、`tls_enabled`、`tls_sans`、`grpc_addr`、`jwt_secret`、`admin_email` 与 `serve_frontend`；`[agent]` 表覆盖 `server_url`、`server_ca_cert`、`api_key`、`cache_dir`、`heartbeat_interval_secs`、日志批量参数、`fail_open` 与指标上报。

## 分布式 Agent

Agent 只需要三件事：控制面地址、认证方式与规则缓存目录。

```bash
PINGWAF_SERVER_URL="https://control.example.com:9090" \
PINGWAF_API_KEY="<enrollment key>" \
PINGWAF_CACHE_DIR="/var/lib/pingwaf/cache" \
pingwaf agent
```

纳管密钥在控制台创建（`POST /api/v1/agents/enroll` 会返回安装命令）。空的 `PINGWAF_API_KEY` 只在 all-in-one 模式的回环自动注册中有效。

## systemd

仓库自带的 `pingwaf.service` 以 `pingwaf` 用户运行，设置 `Restart=always`、`LimitNOFILE=65536`、`ProtectSystem=strict`，只允许写入 `/var/lib/pingwaf` 与 `/etc/pingwaf`。没有 reload 信号：配置变更由控制面应用，二进制或单元变更需要 `systemctl restart pingwaf`。

## 控制面 TLS

控制台从首次启动起就使用生成的自签证书提供 HTTPS。请在生成前用 `PINGWAF_TLS_SANS`（逗号分隔）指定实际访问的主机名，或在 **设置 → 控制面 HTTPS** 上传真实证书。若控制台位于 TLS 终止代理之后，设置 `PINGWAF_TLS_ENABLED=false`。
