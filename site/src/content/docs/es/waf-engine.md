---
title: Motor WAF
description: El pipeline de cuatro fases, reglas de expresión, puntuación de anomalía, veredictos y desafíos.
minutes: 9
---

## El pipeline

Cada petición con WAF activo pasa por cuatro fases:

```
normalizar → firmas → reglas de expresión → puntuación de anomalía → veredicto
```

1. **Normalizar** — decodificación repetida de URL (tres capas por defecto), decodificación de entidades HTML, plegado de rutas y separación de query y cookies; el modo estricto decodifica además secuencias de escape.
2. **Firmas** — coincidencia multipatrón Aho-Corasick más heurísticas libinjection para SQLi y XSS sobre cada valor decodificado. Las coincidencias reflejadas en `Referer` y `User-Agent` se degradan a señal débil.
3. **Reglas de expresión** — condiciones compiladas que se evalúan después de que las reglas Allow hayan podido cortocircuitar.
4. **Puntuación** — las coincidencias se agregan en un score que se compara con el umbral para producir un único veredicto.

## Puntuación y veredictos

La severidad se traduce a puntos estilo OWASP: crítica 5, alta 4, media 3, baja 2, informativa 1. El umbral por defecto es **40** con paranoia **2** (rango 1–4).

| Veredicto | Cuándo se produce |
| --- | --- |
| `Pass` | Sin coincidencias o score cero |
| `Monitor` | Score distinto de cero pero bajo el umbral |
| `Block` | Score en el umbral, o firma crítica en la ruta rápida |
| `Challenge` | Una regla fuerza desafío |

Las acciones forzadas por regla ganan al score y `Block` prevalece sobre `Challenge`. Con `fast_path_block_on_critical` (por defecto) una firma crítica de la etapa 1 bloquea de inmediato. El modo Monitor degrada Block y Challenge a Monitor y anota `would_enforce` para ajustar antes de aplicar.

## Expresiones

Gramática de descenso recursivo: `campo operador valor`, combinable con `and`, `or` y `not`, con valores de cadena, número, booleano o conjunto.

```
http.request.uri.path starts_with "/admin"
  and not ip.src in {10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8}

cf.waf.score.sqli ge 60

user_agent matches "(?i)(nikto|sqlmap|nmap|masscan|acunetix)"

http.request.method in {"TRACE" "TRACK"}
```

Campos disponibles: `http.request.uri.path`, `http.request.uri.full`, `http.request.uri.query`, `http.request.method`, `http.request.headers[...]`, `http.request.cookies[...]`, `http.request.body`, `http.host`, `ip.src`, `ip.src.country`, `cf.waf.score`, `cf.waf.score.sqli`, `cf.waf.score.xss`, `cf.waf.score.rce`, `ssl`, `user_agent`.

Operadores: `eq`/`=`/`==`, `ne`/`!=`, `contains`, `not_contains`, `matches`, `in`, `starts_with`, `ends_with`, `lt`, `gt`, `le`, `ge`, además de las formas `not <op>`.

## Reglas gestionadas

El binario incluye quince reglas `PINGWAF-xxxx` que se cargan según el nivel configurado: familias de inyección, exposición de rutas de administración, user agents de escáner, métodos prohibidos, payloads JNDI y URIs sobredimensionadas. Una regla que no parsea se omite con aviso, sin invalidar el paquete.

## Desafíos y protección CC

| Ajuste | Valor por defecto |
| --- | --- |
| `enabled` | `true` |
| `under_attack_mode` | `false` |
| `default_level` | `NonInteractive` (escudo JS de 5 s) |
| `clearance_duration_secs` | `1800` |
| `rate_threshold` | 100 peticiones/minuto/IP |
| `exempt_paths` | `/health`, `/ping` |
| `pow_difficulty` | `20` |

Los niveles son `None`, `NonInteractive`, `Managed` (elige por riesgo) e `Interactive`. El proof of work usa SHA-256 con objetivo de ceros iniciales. El paso se guarda en `__pingwaf_clearance`, con valor `base64(payload).base64(HMAC-SHA256)` ligado al sitio emisor, imposible de reutilizar en otro dominio.

## Política de bots

Se configura por sitio: `ua_analysis`, `js_detection`, `tls_fingerprint`, `behavioral_analysis`, acción (`block`, `challenge`, `js_challenge`, `log`, `allow`), lista de bots conocidos, verificación IP y DNS, y grupo de IP verificado opcional. Los límites de tasa usan las mismas dimensiones: `ip`, `ip_nat`, `host`, `path`, `asn`, `country`, `header:<name>`, `cookie:<name>`, `query:<name>`.

## Dónde cambiar los umbrales

Los ajustes WAF por sitio se escriben con `PUT /api/v1/sites/{site_id}/waf/settings`: `waf_enabled`, `mode`, `paranoia_level`, `advanced_mode`, flags de monitorización y `body_stage_timeout_secs`. Los mismos valores viajan a los agentes en `WafConfig` con `anomaly_threshold` y `paranoia_level`.
