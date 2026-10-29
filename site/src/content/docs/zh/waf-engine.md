---
title: WAF 引擎
description: 四阶段检测流水线、表达式规则、异常评分、判决与挑战流程。
minutes: 9
---

## 流水线

开启 WAF 的每个请求都会经过四个阶段：

```
归一化 → 签名 → 表达式规则 → 异常评分 → 判决
```

1. **归一化** —— 多层 URL 解码（默认 3 层，`max_decode_layers`）、HTML 实体解码、路径折叠、query 与 cookie 拆分；严格模式还会解码转义序列。
2. **签名** —— Aho-Corasick 多模式匹配，加上 libinjection 的 SQLi/XSS 启发式，对每个解码后的值求值；`Referer` 与 `User-Agent` 中的反射型命中会降级为弱信号。
3. **表达式规则** —— 编译后的条件，在 Allow 规则短路之后求值。
4. **异常评分** —— 命中聚合成分数，与阈值比较后产出唯一判决。

## 评分与判决

严重度按 OWASP 风格映射为分值：critical 5、high 4、medium 3、low 2、informational 1。默认聚合阈值是 **40**，paranoia 等级 **2**（范围 1–4）。

| 判决 | 产生条件 |
| --- | --- |
| `Pass` | 无命中，或评分为零 |
| `Monitor` | 评分非零但低于拦截阈值 |
| `Block` | 评分达到阈值，或 critical 签名命中快路径 |
| `Challenge` | 规则强制挑战，客户端必须先通过 |

规则强制动作优先于评分，且 `Block` 优先于 `Challenge`。开启 `fast_path_block_on_critical`（默认）时，critical 级 Stage-1 签名直接拦截并跳过 Stage 2。Monitor 模式（`WafMode::Monitor`）会把 Block 与 Challenge 降级为 Monitor，并在详情中标注 `would_enforce`，便于先观察再启用。

## 表达式

语法是一个小型递归下降解析器：`字段 运算符 值`，可用 `and`、`or`、`not` 组合，值可以是字符串、数字、布尔或集合。

```
http.request.uri.path starts_with "/admin"
  and not ip.src in {10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8}

cf.waf.score.sqli ge 60

user_agent matches "(?i)(nikto|sqlmap|nmap|masscan|acunetix)"

http.request.method in {"TRACE" "TRACK"}

http.request.headers["user-agent"] contains "${jndi:"
```

可用字段包括 `http.request.uri.path`、`http.request.uri.full`、`http.request.uri.query`、`http.request.method`、`http.request.headers[...]`、`http.request.cookies[...]`、`http.request.body`、`http.host`、`ip.src`、`ip.src.country`、`cf.waf.score`、`cf.waf.score.sqli`、`cf.waf.score.xss`、`cf.waf.score.rce`、`ssl` 与 `user_agent`。

运算符：`eq`/`=`/`==`、`ne`/`!=`、`contains`、`not_contains`、`matches`、`in`、`starts_with`、`ends_with`、`lt`、`gt`、`le`、`ge`，以及 `not <op>` 形式。

## 托管规则

二进制内置 15 条 `PINGWAF-xxxx` 规则，按配置的级别装载。它们覆盖注入族、管理路径暴露、扫描器 UA、禁用方法、JNDI payload 与超长 URI。单条托管规则解析失败只会告警跳过，不会让整个规则包失效。

## 挑战与 CC 防护

| 配置项 | 默认值 |
| --- | --- |
| `enabled` | `true` |
| `under_attack_mode` | `false` |
| `default_level` | `NonInteractive`（JavaScript 5 秒盾） |
| `clearance_duration_secs` | `1800` |
| `rate_threshold` | 100 请求/分钟/IP |
| `exempt_paths` | `/health`、`/ping` |
| `browser_integrity_check` | `true` |
| `pow_difficulty` | `20` |
| `submission_max_age_secs` | `300` |

挑战等级为 `None`、`NonInteractive`、`Managed`（按请求风险自动选择）与 `Interactive`。工作量证明使用 SHA-256 前导零目标。通过结果存入 `__pingwaf_clearance` Cookie，值为 `base64(payload).base64(HMAC-SHA256)`，并绑定签发站点，因此无法重放到其他域名。

## Bot 策略

Bot 防护按站点配置：`ua_analysis`、`js_detection`、`tls_fingerprint`、`behavioral_analysis`、动作（`block`、`challenge`、`js_challenge`、`log`、`allow`）、已知 Bot 白名单、IP 与 DNS 校验，以及可选的已验证 IP 组。限流维度与之一致——`ip`、`ip_nat`、`host`、`path`、`asn`、`country`、`header:<name>`、`cookie:<name>`、`query:<name>`，动作为 `block`、`log`、`challenge`、`js_challenge` 与 `allow`。

## 在哪里调整阈值

站点级 WAF 设置通过 `PUT /api/v1/sites/{site_id}/waf/settings` 写入：`waf_enabled`、`mode`、`paranoia_level`、`advanced_mode`、monitor 开关与 `body_stage_timeout_secs`。这些值会随 `WafConfig` 的 `anomaly_threshold` 与 `paranoia_level` 下发给 Agent。
