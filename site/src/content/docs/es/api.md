---
title: API
description: Grupos REST, autenticación, contrato gRPC del plano de control, API keys y automatización.
minutes: 7
---

## REST

Todos los endpoints viven bajo `/api/v1` en la dirección del plano de control: `https://<host>:9080/api/v1`. La autenticación usa un token Bearer:

```bash
TOKEN=$(curl -s -X POST https://localhost:9080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@pingwaf.local","password":"..."}' | jq -r .access_token)

curl -s https://localhost:9080/api/v1/sites -H "Authorization: Bearer $TOKEN"
```

El login devuelve `access_token`, `refresh_token`, `token_type: Bearer`, `expires_in` (43200 segundos) y `role`. Solo `/auth/login`, `/auth/register`, `/auth/status`, los dos pasos de passkey, `/health` y `/version` están abiertos. `/system/*` requiere además administrador.

## Grupos de endpoints

| Grupo | Endpoints representativos |
| --- | --- |
| Auth | `POST /auth/login`, `POST /auth/refresh`, `GET|PUT /auth/me`, `PUT /auth/password` |
| Sitios | `GET|POST /sites`, `GET|PUT|DELETE /sites/{id}`, `POST /sites/{id}/clone` |
| Reglas | `GET|POST /sites/{id}/rules`, `GET|PUT|DELETE /sites/{id}/rules/{rule_id}`, `POST /sites/{id}/waf/defaults` |
| WAF | `GET|PUT /sites/{id}/waf/settings`, `GET /sites/{id}/waf/posture`, `GET /managed-rules` |
| Logs | `GET /logs/security`, `GET /logs/access`, `GET /logs/access/{id}`, `DELETE /logs/purge` |
| Agentes | `GET /agents`, `POST /agents/enroll`, `POST /agents/{id}/commands` |
| Versiones | `GET /config-versions`, `GET /config-versions/{id}`, `POST /config-versions/{id}/rollback` |
| Sistema | `GET /system/metrics`, `/system/profile`, `/system/nodes`, `/system/status` |

Las llamadas por sitio pasan por el límite de tenant (`load_site_read` / `load_site_write`), de modo que un token solo ve los sitios que puede gestionar. La referencia completa, con parámetros y formas de respuesta, es `docs/api.md` en el repositorio.

## gRPC

Los agentes usan el servicio `ControlPlane` en el puerto `9090`, definido en `pingwaf-proto/proto/control_plane.proto`: `RegisterAgent`, `Heartbeat`, `SyncRules`, `ShipLogs`, `ShipCertEvents`, `ShipMetrics`, `GetSiteConfig` y los RPC de sesión de visitantes del flujo de desafíos. TLS es el valor por defecto; `grpc_tls_mode = "off"` solo para redes de confianza.

## API keys

Las cuentas de servicio se autentican con claves `pwk_`, generadas con 128 bits de entropía y almacenadas como hash bcrypt; el texto plano se muestra una vez. Cada clave lleva ámbito `read` o `write` y fecha de caducidad.

```bash
curl -s -X POST https://localhost:9080/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"ci","scopes":["read"],"expires_in_days":90}'
```

## MCP

El plano de control expone un endpoint MCP Streamable HTTP en `POST /mcp` (ruta raíz, deliberadamente fuera de `/api/v1`). Acepta una API key `pwk_…` o un JWT; las herramientas de escritura exigen además que el propietario sea administrador. `GET` y `DELETE` devuelven `405` y el cuerpo está limitado a 256 KiB.

## Notificaciones

Las notificaciones webhook se configuran con `PINGWAF_WEBHOOK_URL` y las rutas de notificaciones muestran la configuración actual desde la consola, para enviar eventos de seguridad a tu sistema de alertas.

## Recetas de automatización

- **Configuración revisable** — toma una instantánea con `GET /config-versions` tras cada cambio y revierte con `POST /config-versions/{id}/rollback`.
- **Enrolar nodos desde CI** — `POST /agents/enroll` devuelve el comando de instalación, así la tubería no guarda claves.
- **Exportar logs** — consulta `/logs/security` para peticiones bloqueadas o habilita el envío a Elasticsearch.
