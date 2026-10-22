<div align="center">

# 🛡️ PingWAF

**Un firewall de aplicaciones web (WAF) distribuido y de control centralizado, construido sobre [`pingap`](https://github.com/vicanso/pingap) y [`Pingora`](https://github.com/cloudflare/pingora) de Cloudflare.**

Detección semántica de ataques · Reglas al estilo Cloudflare · Defensa CC y Bot · TLS automático · Panel integrado multilingüe

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/shuaiZend/PingWAF/actions/workflows/ci.yml/badge.svg)](https://github.com/shuaiZend/PingWAF/actions/workflows/ci.yml)

**[English](./README.md) | [简体中文](./README_zh.md) | [Español](./README_es.md) | [Français](./README_fr.md)**

</div>

---

## 📖 ¿Qué es PingWAF?

**PingWAF** es un **WAF** (firewall de aplicaciones web) de código abierto y alto rendimiento que lleva la seguridad de borde de nivel Cloudflare a tu propia infraestructura. Está construido sobre [`pingap`](https://github.com/vicanso/pingap) — un proxy inverso de producción impulsado por el framework de red [`Pingora`](https://github.com/cloudflare/pingora) de Cloudflare — y añade sobre él una capa de seguridad **distribuida y de control centralizado**.

Un único **plano de control** define sitios, reglas y políticas; uno o varios **agentes del plano de datos** las aplican en el borde. Las reglas, los registros y las métricas fluyen entre ambos mediante **flujos gRPC bidireccionales persistentes**, de modo que un cambio de política realizado en el panel llega a todos los agentes en segundos, sin recargas ni tiempos de inactividad.

- 🎯 **Detección semántica** — SQLi / XSS / RCE / path traversal / inyección de comandos mediante `libinjection`, coincidencia de firmas Aho-Corasick, puntuación de anomalías y reglas de expresión al estilo Cloudflare.
- 🕸️ **Distribuido por diseño** — ejecuta todo en un solo proceso (`all-in-one`) o escala el plano de datos con agentes independientes (`server` + `agent`).
- 🧭 **Todo incluido, desactivado por defecto** — cada protección se envía desactivada y se habilita por sitio: tú mantienes el control total de tu tráfico.
- ⚡ **Rust de principio a fin** — seguridad de memoria, E/S asíncrona y un único binario autocontenido con el panel integrado.

> PingWAF es un proyecto independiente. No está afiliado a ni respaldado por Cloudflare ni por los mantenedores de `pingap`.

---

## ✨ Funcionalidades principales

- **Motor WAF semántico** — pipeline de cuatro fases (normalización → firmas → expresiones → puntuación de anomalías) con veredictos `Pass`, `Monitor`, `Block` y `Challenge`.
- **Protección CC / escudo de 5 segundos** — desafíos JavaScript, Proof-of-Work e interactivos, con cookies de autorización firmadas con HMAC.
- **Protección contra bots** — lista blanca de bots verificados, paso para navegadores conocidos y una acción configurable para el resto.
- **Reglas de acceso IP** — `block` / `allow` / `challenge` / `js_challenge`, con rangos CIDR, importación CSV y **grupos IP globales** sincronizados por suscripción (p. ej. los rangos de Cloudflare).
- **Restricción geográfica** — permitir o bloquear por país y por número de sistema autónomo (ASN).
- **Limitación de tasa multidimensional** — por IP, host, ruta, ASN, país, o según una cabecera, cookie o parámetro de consulta.
- **Pools de origen y rutas** — balanceo de carga round-robin, mínimas conexiones, aleatorio o por hash consistente, con rutas por prefijo, coincidencia exacta o regex.
- **Caché en el borde** — cuotas de disco por sitio, `stale-while-revalidate` y control del TTL del navegador.
- **Reescritura de peticiones/respuestas** y **páginas de error personalizadas** con plantillas Tera.
- **TLS automático** — emisión y renovación ACME / Let's Encrypt en el borde (HTTP-01 y DNS-01 con Aliyun, Cloudflare, Tencent Cloud DNSPod, Huawei Cloud o manual), con estado de certificado por sitio informado al plano de control. La verificación del certificado del origen HTTPS es un interruptor explícito (Ajustes → Origen), con valor por defecto global y anulación por pool.
- **Observabilidad** — registros completos en Elasticsearch (opcional), vistas previas de cabeceras y cuerpo en PostgreSQL, y analíticas de tráfico y ataques.
- **Panel integrado multilingüe** (English / 简体中文 / 日本語), autenticación JWT + bcrypt, aislamiento multiusuario y **versionado de configuración** (listar, comparar tabla por tabla y revertir con confirmación).

---

## 🚀 Inicio rápido

### Opción A — Docker Compose (recomendada)

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF

# Inicia el plano de control + plano de datos + PostgreSQL (imagen preconstruida de GHCR)
docker compose up -d
```

Abre el panel:

- **URL:** https://localhost:9080 (certificado autofirmado; súbelo o reemplázalo en Ajustes → HTTPS del plano de control)
- **Correo:** `admin@pingwaf.local`
- **Contraseña:** `pingwaf123`

> ⚠️ **Cambia la contraseña del administrador y `PINGWAF_JWT_SECRET` antes de usarlo en producción.**

### Opción B — Compilar desde el código fuente

En macOS (o si prefieres compilar) se requieren **Rust 1.96+**, **Node.js 26.12.1+**, `protoc` y `cmake`:

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF
cd web && npm ci && npm run build && cd ..
cargo build --release --bin pingwaf --features full
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

### Opción C — Script de instalación (Linux)

Los binarios precompilados para **Linux (amd64 / arm64)** están disponibles en [Releases](https://github.com/shuaiZend/PingWAF/releases):

```bash
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | sudo bash -s -- --mode all-in-one
```

### Puertos predeterminados

| Puerto | Propósito |
| --- | --- |
| `9080` | API REST + panel integrado por HTTPS (salud: `GET /healthz`, también en HTTP) |
| `9090` | Plano de control gRPC (los agentes se conectan aquí) |
| `80` / `443` | Tráfico proxificado (se vinculan al crear el primer sitio; el `443` solo se abre tras emitir o subir un certificado — hasta entonces únicamente el `80` sirve HTTP) |

---

## 🧭 Documentación

| Documento | Contenido |
| --- | --- |
| [docs/quick-start.md](./docs/quick-start.md) | De cero a tu primer sitio protegido |
| [docs/deployment.md](./docs/deployment.md) | Docker, binario + systemd, topologías distribuidas |
| [docs/user-guide.md](./docs/user-guide.md) | Guía del panel, sitios, reglas y políticas |
| [docs/api.md](./docs/api.md) | Referencia de la API REST (`https://<host>:9080/api/v1`) |
| [docs/README.md](./docs/README.md) | Índice completo de la documentación |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | Cómo contribuir |
| [SECURITY.md](./SECURITY.md) | Política de divulgación de vulnerabilidades |

---

## 📄 Licencia

PingWAF se distribuye bajo la **[Apache License 2.0](./LICENSE)**. Es un trabajo derivado de `pingap` / `Pingora` y conserva sus avisos de copyright originales; no está afiliado a ni respaldado por Cloudflare ni por el proyecto `pingap`.
