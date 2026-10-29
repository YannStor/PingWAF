---
title: Arquitectura
description: Cómo encajan el plano de control y el de datos, qué transporta gRPC y cómo llega la política al edge.
minutes: 8
---

PingWAF se divide en dos procesos que comparten un único binario. El **plano de control** posee todo el estado; el **plano de datos** transporta tráfico y aplica políticas. El plano de datos no tiene base de datos propia, ni debe tenerla.

## Plano de control

`pingwaf server` expone tres superficies:

| Superficie | Puerto | Uso |
| --- | --- | --- |
| API REST + consola | `9080` (HTTPS) | Sitios, reglas, logs, versiones de configuración |
| gRPC `ControlPlane` | `9090` | Registro de agentes, heartbeat, sincronización, logs y métricas |
| PostgreSQL | `5432` | Único almacén duradero; Elasticsearch es opcional para logs |

La consola se compila en el binario con `rust-embed`, así que no hay un frontend separado que mantener sincronizado con la API.

## Plano de datos

`pingwaf agent` acepta tráfico en `:80` y `:443`, evalúa reglas WAF, termina TLS y hace proxy a los grupos de origen. Mantiene una caché de reglas en disco bajo `cache_dir` y reconstruye su proveedor en memoria cuando cambia el hash de esa caché, aproximadamente cada cinco segundos. Las peticiones siempre leen el proveedor actual mediante `ArcSwap`, así que un cambio de política nunca requiere reinicio.

## Contrato gRPC

La fuente única es `pingwaf-proto/proto/control_plane.proto`, con siete RPC:

| RPC | Tipo | Uso |
| --- | --- | --- |
| `RegisterAgent` | unario | Une el agente a la flota; devuelve `agent_id`, `agent_token`, intervalo de heartbeat y configuración inicial |
| `Heartbeat` | flujo bidireccional | Liveness, estadísticas y estado de certificados; comandos hacia el agente |
| `SyncRules` | flujo del servidor | Nuevos paquetes de reglas tras cada cambio |
| `ShipLogs` | flujo del cliente | Logs de petición y ataque por lotes |
| `ShipCertEvents` | flujo del cliente | Eventos de emisión y renovación ACME |
| `ShipMetrics` | flujo del cliente | Métricas de tráfico y caché |
| `GetSiteConfig` | unario | Configuración completa de un sitio |

El mismo servicio atiende el login de visitantes, passkeys y validación de sesión del flujo de desafíos; esas llamadas se autentican con el token de agente y fallan cerradas si el plano de control no responde.

## Cómo llega un cambio al edge

1. Una escritura REST guarda la configuración en PostgreSQL.
2. El plano de control registra una instantánea del ámbito afectado.
3. `notify_config_changed` empuja un nuevo `SiteConfig` a cada agente que sirve ese sitio.
4. El agente persiste el paquete en su caché, el hash cambia y el proveedor se sustituye en memoria.

## Comportamiento ante fallos

`fail_open` decide qué hace un agente sin plano de control: `true` (por defecto) sigue sirviendo con la última política sincronizada; `false` devuelve `503` a los hosts sin reglas sincronizadas. La política por sitio prevalece sobre el valor global y se guarda en la configuración.

## Modos de ejecución

| Modo | Comando | Rol |
| --- | --- | --- |
| Plano de control | `pingwaf server` | API, gRPC, consola y base de datos; no hace proxy |
| Plano de datos | `pingwaf agent` | Conecta al plano remoto y hace proxy en `:80`/`:443` |
| All-in-one | `pingwaf all-in-one` | Ambos en un proceso; el agente usa loopback |

`PINGWAF_MODE` selecciona el mismo modo cuando se omite el subcomando.

## Versiones de configuración

Cada cambio se versiona por ámbito, con retención de 50 versiones por ámbito, 30 días y instantáneas de hasta 2 MiB. Un rollback toma un bloqueo de asesoramiento, escribe una instantánea `pre-rollback`, restaura el estado anterior y registra el resultado como una versión nueva: el rollback es auditable y reversible.
