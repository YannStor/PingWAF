---
title: API
description: REST 分组、认证、gRPC 控制面契约、API Key 与自动化入口。
minutes: 7
---

## REST

所有端点都在控制面地址的 `/api/v1` 下：`https://<host>:9080/api/v1`。认证使用 Bearer access token：

```bash
TOKEN=$(curl -s -X POST https://localhost:9080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@pingwaf.local","password":"..."}' | jq -r .access_token)

curl -s https://localhost:9080/api/v1/sites -H "Authorization: Bearer $TOKEN"
```

登录返回 `access_token`、`refresh_token`、`token_type: Bearer`、`expires_in`（43200 秒）与 `role`。只有 `/auth/login`、`/auth/register`、`/auth/status`、两步 Passkey 流程、`/health` 与 `/version` 无需认证；`/system/*` 还要求管理员身份。

## 端点分组

| 分组 | 代表端点 |
| --- | --- |
| 认证 | `POST /auth/login`、`POST /auth/refresh`、`GET|PUT /auth/me`、`PUT /auth/password` |
| 站点 | `GET|POST /sites`、`GET|PUT|DELETE /sites/{id}`、`POST /sites/{id}/clone` |
| 规则 | `GET|POST /sites/{id}/rules`、`GET|PUT|DELETE /sites/{id}/rules/{rule_id}`、`POST /sites/{id}/waf/defaults` |
| WAF | `GET|PUT /sites/{id}/waf/settings`、`GET /sites/{id}/waf/posture`、`GET /managed-rules` |
| 日志 | `GET /logs/security`、`GET /logs/access`、`GET /logs/access/{id}`、`DELETE /logs/purge` |
| Agent | `GET /agents`、`POST /agents/enroll`、`POST /agents/{id}/commands` |
| 配置版本 | `GET /config-versions`、`GET /config-versions/{id}`、`POST /config-versions/{id}/rollback`、`POST /config-versions/prune` |
| 系统 | `GET /system/metrics`、`/system/profile`、`/system/nodes`、`/system/status` |

站点级接口通过租户边界（`load_site_read` / `load_site_write`）读写，token 只能看到自己有权管理的站点。包含全部查询参数与响应结构的完整参考见仓库中的 `docs/api.md`。

## gRPC

Agent 使用 `9090` 上的 `ControlPlane` 服务，定义在 `pingwaf-proto/proto/control_plane.proto`。它承载 `RegisterAgent`、`Heartbeat`、`SyncRules`、`ShipLogs`、`ShipCertEvents`、`ShipMetrics`、`GetSiteConfig`，以及挑战流程使用的访客会话 RPC。TLS 为默认；`grpc_tls_mode = "off"` 只应在可信网络内使用。

## API Key

服务账号使用 `pwk_` 前缀的密钥认证，密钥以 128 位熵生成、以 bcrypt 哈希存储，明文只在创建时返回一次；每个密钥带有 `read` 或 `write` 作用域与过期时间。

```bash
curl -s -X POST https://localhost:9080/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"ci","scopes":["read"],"expires_in_days":90}'
```

## MCP

控制面在 `POST /mcp` 暴露 Streamable HTTP 的 MCP 端点（根路径，刻意不在 `/api/v1` 下）。它接受 `pwk_…` API Key 或 JWT；写操作还要求密钥拥有者是管理员。`GET` 与 `DELETE` 返回 `405`，请求体上限 256 KiB。这是让助手查看站点、规则与日志而无需交付控制台凭据的推荐方式。

## 通知

Webhook 通知通过 `PINGWAF_WEBHOOK_URL` 配置，通知路由可以从控制台读取当前配置。可以用它把安全事件投递到现有的告警链路。

## 自动化实践

- **配置可复盘** —— 每次变更后用 `GET /config-versions` 生成快照，并在应急脚本中用 `POST /config-versions/{id}/rollback` 回滚。
- **在 CI 中纳管边缘节点** —— `POST /agents/enroll` 返回安装命令，因此流水线本身不需要保存 API Key。
- **日志外送** —— 轮询 `/logs/security` 获取被拦截请求，或开启 Elasticsearch 上报后直接查询。
