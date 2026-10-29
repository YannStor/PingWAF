---
title: API
description: REST グループ、認証、gRPC コントロールプレーンの契約、API キー、自動化の入口。
minutes: 7
---

## REST

すべてのエンドポイントはコントロールプレーンのアドレス配下 `/api/v1` にあります：`https://<host>:9080/api/v1`。認証は Bearer トークンです。

```bash
TOKEN=$(curl -s -X POST https://localhost:9080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@pingwaf.local","password":"..."}' | jq -r .access_token)

curl -s https://localhost:9080/api/v1/sites -H "Authorization: Bearer $TOKEN"
```

ログインは `access_token`、`refresh_token`、`token_type: Bearer`、`expires_in`（43200 秒）、`role` を返します。認証不要なのは `/auth/login`、`/auth/register`、`/auth/status`、パスキーの 2 ステップ、`/health`、`/version` のみです。`/system/*` はさらに管理者権限を要求します。

## エンドポイントグループ

| グループ | 代表的なエンドポイント |
| --- | --- |
| 認証 | `POST /auth/login`、`POST /auth/refresh`、`GET|PUT /auth/me`、`PUT /auth/password` |
| サイト | `GET|POST /sites`、`GET|PUT|DELETE /sites/{id}`、`POST /sites/{id}/clone` |
| ルール | `GET|POST /sites/{id}/rules`、`GET|PUT|DELETE /sites/{id}/rules/{rule_id}`、`POST /sites/{id}/waf/defaults` |
| WAF | `GET|PUT /sites/{id}/waf/settings`、`GET /sites/{id}/waf/posture`、`GET /managed-rules` |
| ログ | `GET /logs/security`、`GET /logs/access`、`GET /logs/access/{id}`、`DELETE /logs/purge` |
| エージェント | `GET /agents`、`POST /agents/enroll`、`POST /agents/{id}/commands` |
| バージョン | `GET /config-versions`、`GET /config-versions/{id}`、`POST /config-versions/{id}/rollback` |
| システム | `GET /system/metrics`、`/system/profile`、`/system/nodes`、`/system/status` |

サイト単位の呼び出しはテナント境界（`load_site_read` / `load_site_write`）を通るため、トークンは管理権限のあるサイトだけを参照できます。パラメータとレスポンス形状を含む完全なリファレンスはリポジトリの `docs/api.md` です。

## gRPC

エージェントは `9090` の `ControlPlane` サービスを使います。定義は `pingwaf-proto/proto/control_plane.proto` にあり、`RegisterAgent`、`Heartbeat`、`SyncRules`、`ShipLogs`、`ShipCertEvents`、`ShipMetrics`、`GetSiteConfig` と、チャレンジに使う訪問者セッション RPC を含みます。既定は TLS で、`grpc_tls_mode = "off"` は信頼できるネットワーク専用です。

## API キー

サービスアカウントは `pwk_` 接頭辞のキーで認証します。128 ビットのエントロピーで生成し bcrypt ハッシュで保存され、平文は作成時に一度だけ表示されます。各キーは `read` または `write` スコープと有効期限を持ちます。

```bash
curl -s -X POST https://localhost:9080/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"ci","scopes":["read"],"expires_in_days":90}'
```

## MCP

コントロールプレーンは `POST /mcp`（ルートパス、意図的に `/api/v1` の外）で MCP の Streamable HTTP エンドポイントを提供します。`pwk_…` の API キーまたは JWT を受け付け、書き込みツールは所有者が管理者であることを要求します。`GET` と `DELETE` は `405` を返し、本文は 256 KiB までです。

## 通知

Webhook 通知は `PINGWAF_WEBHOOK_URL` で設定し、通知ルートからコンソールで現在の設定を確認できます。セキュリティイベントを既存のアラート基盤へ流すのに使えます。

## 自動化のレシピ

- **設定をレビュー可能に** — 変更後に `GET /config-versions` でスナップショットを取り、緊急時は `POST /config-versions/{id}/rollback` で戻します。
- **CI からエッジを登録** — `POST /agents/enroll` がインストールコマンドを返すため、パイプラインがキーを保持する必要はありません。
- **ログの外部送信** — ブロックされたリクエストは `/logs/security` を照会するか、Elasticsearch への送信を有効にして直接検索します。
