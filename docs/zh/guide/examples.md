# 示例

本仓库 [`examples/`](../../../examples/) 目录下的可直接运行配置：

- [static-serve](../../../examples/static-serve)
- [api-gateway](../../../examples/api-gateway)
- [web-socket](../../../examples/web-socket)
- [grpc-web](../../../examples/grpc-web)
- [transparent-proxy](../../../examples/transparent-proxy)

## Grpc-Web

- 非加密 grpc-server
- Commonjs 静态示例
- 本地信任的 `127.0.0.1` 开发证书

关键配置点如下：

- `[upstreams.grpc-server]` 应选择 h2 alpn
- `[servers.grpc-web]` 应选择 grpc-web 模块
- `[locations.grpc-server]` 应启用 `grpc_web`

```bash
cargo run -- -c=./examples/grpc-web.toml --admin=127.0.0.1:3018
```

## Transparent Proxy

- 上游发现方式应为 `transparent`
- HTTPS 时上游 SNI 应设为 `$host`
- 证书应设为所有域名的默认证书

```bash
sudo cargo run -- -c=./examples/transparent-proxy.toml --admin=127.0.0.1:3018
```

```bash
curl -kv --resolve '*:443:127.0.0.1' 'https://cn.bing.com/'
```
