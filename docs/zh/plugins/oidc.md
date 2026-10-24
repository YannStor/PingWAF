# oidc

面向浏览器流量的 OpenID Connect 登录：未认证的浏览器被送往所配置的身份提供方（授权码流程 + PKCE），带着校验通过的 ID token 返回，并以加密会话 Cookie 的形式落地——本侧不存储任何会话。

- **步骤：** 仅 `request`（配置为其他 `step` 会在启动时报错）
- **注册名：** `oidc`

## 登录流程

1. 浏览器请求页面但没有有效会话。若该请求是一次导航（浏览器会跟随的 `GET`），则被重定向（302）到提供方的授权端点，携带 PKCE（`S256`）、`state` 与 `nonce`。
2. 提供方把浏览器送回 `redirect_path` 并附上授权码。该码在令牌端点换取 ID token，其签名用提供方的 JWKS 校验，同时校验 `iss`、`aud`、`exp` 与 `nonce`。
3. 保留的 claim（`sub` 以及 `claims_to_headers` 点名的全部）被封存进加密 Cookie：密钥为 `SHA-256(cookie_secret || 0x00 || issuer || 0x00 || client_id)`，算法为 AES-256-GCM-SIV，每个值使用新的随机 nonce。共享该密钥的每个实例都能读取此 Cookie，因此会话在重启后依然有效，也不需要共享存储。
4. 后续携带有效会话的请求会把配置的 claim 注入配置的请求头并放行；会话过期后浏览器再次被重定向到提供方。

非导航请求（脚本的 `fetch`、表单 `POST`，以及一切非 `GET`）无法跟随重定向：没有会话时会直接得到 `401 Login required`。

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `oidc`。 |
| `issuer` | string | — | 必填。提供方的 http(s) URL；会去掉尾斜杠。发现文档必须自称完全一致的 issuer。 |
| `client_id` | string | — | 必填。在提供方注册的客户端 ID。 |
| `client_secret` | string | — | 客户端密钥。public client 可为空。 |
| `cookie_secret` | string | — | 必填，至少 16 字符。与 `issuer`、`client_id` 一起派生会话 Cookie 密钥。 |
| `redirect_path` | string | `/oauth2/callback` | 提供方回跳的路径。必须是以 `/` 开头的纯路径，不含查询串或片段。 |
| `logout_path` | string | 无 | 结束会话的路径。必须与 `redirect_path` 不同；不设置即没有登出端点。 |
| `redirect_url` | string | 无 | 回跳地址对外呈现的完整 URL，用于请求里推不出来的场景（前置代理或 CDN 之后）。必须是 http(s) URL 且其 path 等于 `redirect_path`。 |
| `scopes` | string[] | `[openid]` | 请求的 scope。`openid` 恒存在且恒在首位。 |
| `cookie_name` | string | `pingap_oidc` | 会话 Cookie 名。仅字母、数字、`.`、`_`、`-`；不得以 `__Host-` 开头（登录 Cookie 作用域是 `redirect_path` 而非 `/`）。 |
| `session_ttl` | duration | `12h` | 会话时长。至少 `1m`。 |
| `claims_to_headers` | string[] | — | 注入请求头的 ID token claim，形如 `claim:X-Header`（如 `email:X-Auth-Email`）。header 名不得为 `Content-Length`、`Transfer-Encoding`、`Host`、`Connection`。 |

## 示例

### Keycloak

```toml
[plugins.oidcAuth]
category = "oidc"
issuer = "https://keycloak.example.com/realms/main"
client_id = "pingap"
client_secret = "change-me"
cookie_secret = "0123456789abcdef0123456789abcdef"
redirect_path = "/oauth2/callback"
logout_path = "/oauth2/logout"
scopes = ["openid", "profile", "email"]
claims_to_headers = ["email:X-Auth-Email", "preferred_username:X-Auth-User"]

[locations.app]
upstream = "app"
path = "/"
plugins = ["oidcAuth"]
```

在 Keycloak 上把 `https://app.example.com/oauth2/callback` 注册为该客户端的回跳 URI——scheme 与主机名取自请求（`redirect_url` 未设置），路径来自 `redirect_path`。

### CDN 后的通用提供方

```toml
[plugins.oidcAuth]
category = "oidc"
issuer = "https://accounts.example.com"
client_id = "web"
cookie_secret = "0123456789abcdef0123456789abcdef"
redirect_url = "https://app.example.com/oauth2/callback"
session_ttl = "30m"
```

`redirect_url` 固定了告知提供方的回跳地址：CDN 或内层代理之后的请求 `Host` 并不是客户端注册时用的地址。其 path 必须等于 `redirect_path`。

## 响应

| 情形 | 状态码 | 响应体 |
| --- | --- | --- |
| 无会话，导航请求 | 302 | 重定向到提供方 |
| 无会话，非导航请求 | 401 | `Login required` |
| 发起登录时提供方不可达 | 502 | `Login is not available` |
| 回调没有 code，或该登录并非在此发起 / 已完成 / 已过期 | 400 | 具体原因 |
| 提供方拒绝了本次登录 | 403 | `Login refused: <错误名>` |
| 换码或 ID token 校验失败 | 502 | `Login failed` |

## 可观测性

两类登录失败会作为安全事件上报，并由控制面转成告警：

| 事件 | 级别 | 时机 |
| --- | --- | --- |
| `site.oidc_login_failed` | warning | 登录无法完成：client secret 错误、授权码被重放、`state` 不匹配、ID token 无效。 |
| `site.oidc_idp_unavailable` | critical | 提供方不可达（discovery、JWKS 或令牌端点），所有人都无法完成登录。 |

未认证浏览器被重定向到提供方属于正常流量，不上报。告警投递由 `notify_site_oidc_auth` 通知开关控制（默认开启），同时覆盖这两个事件。

注意 `site.oidc_login_failed` 可被任意匿名访客触发——向回调路径提交伪造的 `code` 与 `state` 即可。告警按站点、按渠道在通知去重窗口内合并，因此一次突发只会产生一条消息而不会淹没渠道；真实故障仍会因告警持续复现而被看到。

## 使用要点

- 回程**对 PKCE（`S256`）、`state` 与 `nonce` 全部校验**；ID token 的签名用提供方 JWKS 的密钥验证，并校验 `iss`、`aud`（即 client id）、`exp`（含 `nbf`）以及本次登录的 `nonce`，时钟容差 60 秒。
- **发现文档必须与配置的 `issuer` 完全一致**——自称其他名字的提供方会被拒绝，令牌绝不会发给冒充者的端点。
- 提供方的自我描述（discovery）缓存一小时；失败时以 10 秒冷却单飞重取；对它的每个 HTTP 请求超时 10 秒。进行中的登录 10 分钟后过期。
- claim 头是插件专属的：认证之前会先剥掉客户端在这些名字（包括把 `-` 换成 `_` 的同名变体）上发送的一切，客户端无法伪造身份；`protect_from_connection_header` 还能防止客户端用 `Connection: X-Auth-Email` 把 claim 头从到达上游的路上摘走。
- `client_secret` 与 `cookie_secret` 绝不写入日志；构造函数只记录 `issuer` 与 `client_id`，失败详情只使用封闭集合内的原因名。
- 不带 `kid` 的 ID token 会依次尝试提供方发布的每一把密钥（单密钥提供方可能省略 `kid`）。`alg` 仍被限定为非对称算法，`iss`/`aud`/`exp`/`nonce` 的校验完全相同。
- `claims_to_headers` 拒绝会改变请求语义的头：`Content-Length`、`Transfer-Encoding`、`Host`、`Connection`，以及 `Authorization`、`Cookie`、`Set-Cookie`、`X-Forwarded-For`、`X-Forwarded-Proto`、`X-Real-IP`。
- 未配置 `redirect_url` 时，回调地址由请求的 `Host` 推导，会话 Cookie 的 `Secure` 则由连接是否经 TLS 到达决定。若置于终止 TLS 的反向代理或负载均衡之后，插件看到的是明文 HTTP，此时**必须显式配置 `redirect_url`**——否则注册的 `http://` 回调通常会被提供方拒绝，Cookie 也会失去 `Secure`。
- 会话 Cookie 带 `HttpOnly; SameSite=Lax` 与 `Max-Age`，站点走 TLS 时再加 `Secure`。会话 Cookie 作用域为 `/`；携带进行中登录的短时 Cookie 作用域为 `redirect_path`，已完成（或被放弃）的会被清除。
- 请求 `logout_path` 会清除会话 Cookie 与遗留的登录 Cookie，并在 discovery 提供了 `end_session_endpoint` 时重定向到它（附 client id）——否则返回 `200 Logged out`。
- 回调匹配的是浏览器请求的路径，而非改写后的路径：location 的改写（如 `strip_prefix`）无法把回调从插件脚下挪走（`Ctx::features::original_uri`）。
- 会话必须装进一个 Cookie（约 4 KB）；装不下的 claim 会让登录失败，而不是被截断。
- 两个共享 `cookie_secret` 但 `issuer` 或 `client_id` 不同的插件派生出不同的密钥，读不到彼此的 Cookie。
