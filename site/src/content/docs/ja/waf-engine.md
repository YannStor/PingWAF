---
title: WAF エンジン
description: 4 フェーズのパイプライン、式ルール、異常スコア、判定、チャレンジの流れ。
minutes: 9
---

## パイプライン

WAF が有効なすべてのリクエストは 4 つのフェーズを通ります。

```
正規化 → シグネチャ → 式ルール → 異常スコア → 判定
```

1. **正規化** — URL の多重デコード（既定 3 層）、HTML エンティティのデコード、パスの畳み込み、query と cookie の分割。Strict モードではエスケープシーケンスもデコードします。
2. **シグネチャ** — Aho-Corasick の多パターン一致と libinjection の SQLi／XSS ヒューリスティックを、デコード後の各値に対して評価します。`Referer` と `User-Agent` の反射的一致は弱いシグナルに降格します。
3. **式ルール** — コンパイル済みの条件。Allow ルールによる短絡の後に評価します。
4. **異常スコア** — 一致を集約したスコアをしきい値と比較し、ただ 1 つの判定を出します。

## スコアと判定

重大度は OWASP 風の点数に変換します（critical 5、high 4、medium 3、low 2、informational 1）。既定の集約しきい値は **40**、パラノイアは **2**（1〜4）です。

| 判定 | 生成条件 |
| --- | --- |
| `Pass` | 一致なし、またはスコア 0 |
| `Monitor` | スコアは非 0 だがブロックしきい値未満 |
| `Block` | しきい値到達、または critical シグネチャがファストパスに一致 |
| `Challenge` | ルールがチャレンジを強制 |

ルールによる強制アクションはスコアより優先され、`Block` は `Challenge` より上位です。`fast_path_block_on_critical`（既定）では critical のステージ 1 シグネチャが即座にブロックし、ステージ 2 を省略します。Monitor モードは Block と Challenge を Monitor に降格し、`would_enforce` を記録して適用前の調整を可能にします。

## 式

文法は小さな再帰下降パーサで、`フィールド 演算子 値` を `and`、`or`、`not` で組み合わせます。値は文字列、数値、真偽値、集合です。

```
http.request.uri.path starts_with "/admin"
  and not ip.src in {10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8}

cf.waf.score.sqli ge 60

user_agent matches "(?i)(nikto|sqlmap|nmap|masscan|acunetix)"

http.request.method in {"TRACE" "TRACK"}
```

利用できるフィールドは `http.request.uri.path`、`http.request.uri.full`、`http.request.uri.query`、`http.request.method`、`http.request.headers[...]`、`http.request.cookies[...]`、`http.request.body`、`http.host`、`ip.src`、`ip.src.country`、`cf.waf.score`、`cf.waf.score.sqli`、`cf.waf.score.xss`、`cf.waf.score.rce`、`ssl`、`user_agent` です。

演算子は `eq`/`=`/`==`、`ne`/`!=`、`contains`、`not_contains`、`matches`、`in`、`starts_with`、`ends_with`、`lt`、`gt`、`le`、`ge`、そして `not <op>` 形式です。

## マネージドルール

バイナリには 15 個の `PINGWAF-xxxx` ルールが含まれ、設定されたレベルに応じて読み込まれます。インジェクション系、管理パスの露出、スキャナの UA、禁止メソッド、JNDI ペイロード、過大な URI を対象とします。解析に失敗したルールは警告付きでスキップされ、バンドル全体を無効化しません。

## チャレンジと CC 保護

| 設定 | 既定値 |
| --- | --- |
| `enabled` | `true` |
| `under_attack_mode` | `false` |
| `default_level` | `NonInteractive`（JavaScript 5 秒シールド） |
| `clearance_duration_secs` | `1800` |
| `rate_threshold` | 100 リクエスト/分/IP |
| `exempt_paths` | `/health`、`/ping` |
| `pow_difficulty` | `20` |

レベルは `None`、`NonInteractive`、`Managed`（リスクに応じて選択）、`Interactive` です。Proof of Work は SHA-256 の先頭ゼロ目標を使います。通過結果は `__pingwaf_clearance` に保存され、値は `base64(payload).base64(HMAC-SHA256)` で発行サイトに紐づくため、別ドメインへ再利用できません。

## ボットポリシー

サイト単位で `ua_analysis`、`js_detection`、`tls_fingerprint`、`behavioral_analysis`、アクション（`block`、`challenge`、`js_challenge`、`log`、`allow`）、既知ボットの許可リスト、IP と DNS の検証、任意の検証済み IP グループを設定します。レート制限の軸も同じで、`ip`、`ip_nat`、`host`、`path`、`asn`、`country`、`header:<name>`、`cookie:<name>`、`query:<name>` に対応します。

## しきい値の変更箇所

サイト単位の WAF 設定は `PUT /api/v1/sites/{site_id}/waf/settings` で書き込みます（`waf_enabled`、`mode`、`paranoia_level`、`advanced_mode`、監視フラグ、`body_stage_timeout_secs`）。同じ値が `WafConfig` の `anomaly_threshold` と `paranoia_level` としてエージェントへ届きます。
