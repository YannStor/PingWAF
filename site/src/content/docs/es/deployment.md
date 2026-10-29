---
title: Despliegue
description: Docker Compose y compilación propia, puertos, precedencia de configuración, systemd y agentes distribuidos.
minutes: 10
---

## Formas de despliegue

**All-in-one** ejecuta el plano de control y un plano de datos en un proceso: ideal para un nodo único, evaluación o despliegues pequeños.

**Distribuido** ejecuta un `pingwaf server` y cualquier número de `pingwaf agent`. El estado vive en el plano de control y los agentes solo guardan su caché de reglas, así que puedes añadir nodos sin tocar la base de datos.

## Puertos

| Puerto | Uso | Notas |
| --- | --- | --- |
| `9080` | API REST + consola | HTTPS con certificado autofirmado hasta que lo reemplaces; mantenlo privado |
| `9090` | Plano gRPC | Los agentes se conectan aquí; TLS por defecto, `grpc_tls_mode = "off"` lo degrada |
| `80` | Tráfico proxificado | Se enlaza al crear el primer sitio |
| `443` | Tráfico proxificado | Se abre tras emitir o subir un certificado |

`GET /healthz` responde por HTTP y HTTPS, que es lo que deben sondear el healthcheck del compose y tu balanceador.

## Docker Compose

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
```

El compose arranca `ghcr.io/shuaizend/pingwaf:latest` en modo all-in-one junto a `postgres:16-alpine` y publica `80`, `443`, `9080` y `9090`. El puerto de base de datos se enlaza a `127.0.0.1`.

> Mantén `hostname` estable: el plano de control empareja reinscripciones por hostname más API key, y un ID de contenedor cambiante deja agentes fantasma offline.

## Compilación desde el código

| Herramienta | Versión | Motivo |
| --- | --- | --- |
| Rust | 1.96+ (MSRV) | El binario |
| Node.js | 26.12.1+ | Compila la consola embebida (`engine-strict`) |
| `protoc` | reciente | Generación gRPC, **obligatorio** |
| `cmake` | reciente | Backend TLS |
| PostgreSQL | 14+ (16 recomendado) | Almacén del plano de control |

Sin `protoc`, `pingwaf-proto` escribe marcadores de posición y los crates posteriores no compilan.

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release --bin pingwaf --features full
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

En Linux, `install.sh` descarga el paquete, instala en `/usr/local/bin`, escribe `/etc/pingwaf/pingwaf.toml` y la unidad systemd, y arranca el agente (`--no-systemd` lo omite).

## Precedencia de configuración

Se lee primero el TOML, luego las variables `PINGWAF_*` y por último los flags de CLI; lo posterior gana. Las claves desconocidas se reportan y se ignoran.

```bash
pingwaf all-in-one --config /etc/pingwaf/pingwaf.toml
PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml pingwaf all-in-one
```

`[server]` cubre `db_url`, `admin_addr`, `tls_enabled`, `tls_sans`, `grpc_addr`, `jwt_secret`, `admin_email` y `serve_frontend`. `[agent]` cubre `server_url`, `server_ca_cert`, `api_key`, `cache_dir`, `heartbeat_interval_secs`, lotes de logs, `fail_open` y envío de métricas.

## Agentes distribuidos

```bash
PINGWAF_SERVER_URL="https://control.example.com:9090" \
PINGWAF_API_KEY="<enrollment key>" \
PINGWAF_CACHE_DIR="/var/lib/pingwaf/cache" \
pingwaf agent
```

Las claves de enrolamiento se crean desde la consola (`POST /api/v1/agents/enroll` devuelve el comando de instalación). Un `PINGWAF_API_KEY` vacío solo vale para el auto-registro por loopback en all-in-one.

## systemd y TLS

La unidad incluida ejecuta como usuario `pingwaf` con `Restart=always`, `LimitNOFILE=65536` y `ProtectSystem=strict`, con escritura limitada a `/var/lib/pingwaf` y `/etc/pingwaf`. No hay señal de reload: los cambios llegan por el plano de control y un cambio de binario o unidad requiere `systemctl restart pingwaf`.

La consola usa HTTPS desde el primer arranque con un certificado autofirmado. Define `PINGWAF_TLS_SANS` con el hostname real antes de generarlo, sube un certificado en **Ajustes → HTTPS del plano de control**, o pon `PINGWAF_TLS_ENABLED=false` si hay un proxy que termina TLS.
