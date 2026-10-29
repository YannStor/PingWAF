---
title: Déploiement
description: Docker Compose et compilation, ports, précédence de configuration, systemd et agents distribués.
minutes: 10
---

## Formes de déploiement

**All-in-one** exécute le plan de contrôle et un plan de données dans un seul processus : idéal pour un nœud unique, une évaluation ou un petit déploiement.

**Distribué** exécute un `pingwaf server` et autant de `pingwaf agent` que nécessaire. L'état reste dans le plan de contrôle et les agents ne conservent que leur cache de règles : ajouter une périphérie ne touche pas la base.

## Ports

| Port | Usage | Remarques |
| --- | --- | --- |
| `9080` | API REST + console | HTTPS auto-signé jusqu'au remplacement ; à garder privé |
| `9090` | Plan gRPC | Les agents s'y connectent ; TLS par défaut, `grpc_tls_mode = "off"` dégrade |
| `80` | Trafic relayé | Lié dès le premier site créé |
| `443` | Trafic relayé | Ouvert après émission ou import d'un certificat |

`GET /healthz` répond en HTTP et HTTPS : c'est ce que doivent sonder le healthcheck compose et votre répartiteur.

## Docker Compose

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
```

Le compose démarre `ghcr.io/shuaizend/pingwaf:latest` en all-in-one à côté de `postgres:16-alpine` et publie `80`, `443`, `9080` et `9090`. Le port de la base est lié à `127.0.0.1`.

> Gardez `hostname` stable : le plan de contrôle apparie les réenregistrements par hostname et API key ; un ID de conteneur changeant laisse des agents fantômes hors ligne.

## Compilation

| Outil | Version | Raison |
| --- | --- | --- |
| Rust | 1.96+ (MSRV) | Le binaire |
| Node.js | 26.12.1+ | Compile la console embarquée (`engine-strict`) |
| `protoc` | récent | Génération gRPC, **obligatoire** |
| `cmake` | récent | Backend TLS |
| PostgreSQL | 14+ (16 recommandé) | Stockage du plan de contrôle |

Sans `protoc`, `pingwaf-proto` écrit des fichiers factices et les crates suivants ne compilent pas.

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release --bin pingwaf --features full
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

Sur Linux, `install.sh` télécharge l'archive, installe dans `/usr/local/bin`, écrit `/etc/pingwaf/pingwaf.toml` et l'unité systemd, puis démarre l'agent (`--no-systemd` pour l'éviter).

## Précédence de configuration

Lecture du TOML, puis des variables `PINGWAF_*`, puis des options CLI ; le dernier canal gagne. Les clés inconnues sont signalées puis ignorées.

```bash
pingwaf all-in-one --config /etc/pingwaf/pingwaf.toml
PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml pingwaf all-in-one
```

`[server]` couvre `db_url`, `admin_addr`, `tls_enabled`, `tls_sans`, `grpc_addr`, `jwt_secret`, `admin_email` et `serve_frontend`. `[agent]` couvre `server_url`, `server_ca_cert`, `api_key`, `cache_dir`, `heartbeat_interval_secs`, les lots de journaux, `fail_open` et l'envoi de métriques.

## Agents distribués

```bash
PINGWAF_SERVER_URL="https://control.example.com:9090" \
PINGWAF_API_KEY="<enrollment key>" \
PINGWAF_CACHE_DIR="/var/lib/pingwaf/cache" \
pingwaf agent
```

Les clés d'enrôlement se créent depuis la console (`POST /api/v1/agents/enroll` renvoie la commande d'installation). Un `PINGWAF_API_KEY` vide ne vaut que pour l'auto-enregistrement en boucle locale en all-in-one.

## systemd et TLS

L'unité fournie s'exécute sous l'utilisateur `pingwaf` avec `Restart=always`, `LimitNOFILE=65536` et `ProtectSystem=strict`, avec écriture limitée à `/var/lib/pingwaf` et `/etc/pingwaf`. Aucun signal de reload : les changements viennent du plan de contrôle, et un changement de binaire ou d'unité demande `systemctl restart pingwaf`.

La console sert du HTTPS dès le premier démarrage avec un certificat auto-signé. Renseignez `PINGWAF_TLS_SANS` avec le hostname réel avant génération, importez votre certificat via **Réglages → HTTPS du plan de contrôle**, ou passez `PINGWAF_TLS_ENABLED=false` derrière un proxy terminant TLS.
