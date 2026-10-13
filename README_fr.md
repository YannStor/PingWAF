<div align="center">

# 🛡️ PingWAF

**Un pare-feu d'applications web (WAF) distribué à contrôle centralisé, construit sur [`pingap`](https://github.com/vicanso/pingap) et [`Pingora`](https://github.com/cloudflare/pingora) de Cloudflare.**

Détection sémantique des attaques · Règles à la Cloudflare · Défense CC et bots · TLS automatique · Console intégrée multilingue

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/shuaiZend/PingWAF/actions/workflows/ci.yml/badge.svg)](https://github.com/shuaiZend/PingWAF/actions/workflows/ci.yml)

**[English](./README.md) | [简体中文](./README_zh.md) | [Español](./README_es.md) | [Français](./README_fr.md)**

</div>

---

## 📖 Qu'est-ce que PingWAF ?

**PingWAF** est un **WAF** (pare-feu d'applications web) open source et performant qui apporte la sécurité de bord de niveau Cloudflare à votre propre infrastructure. Il est construit sur [`pingap`](https://github.com/vicanso/pingap) — un reverse proxy de production propulsé par le framework réseau [`Pingora`](https://github.com/cloudflare/pingora) de Cloudflare — et y ajoute une couche de sécurité **distribuée à contrôle centralisé**.

Un unique **plan de contrôle** définit les sites, les règles et les politiques ; un ou plusieurs **agents du plan de données** les appliquent en périphérie. Les règles, les journaux et les métriques circulent entre les deux via des **flux gRPC bidirectionnels persistants** : un changement de politique effectué dans la console atteint tous les agents en quelques secondes, sans rechargement ni interruption de service.

- 🎯 **Détection sémantique** — SQLi / XSS / RCE / path traversal / injection de commandes via `libinjection`, correspondance de signatures Aho-Corasick, scoring d'anomalies et règles d'expression à la Cloudflare.
- 🕸️ **Distribué par conception** — exécutez tout dans un seul processus (`all-in-one`) ou passez le plan de données à l'échelle avec des agents indépendants (`server` + `agent`).
- 🧭 **Complet, mais désactivé par défaut** — chaque protection est livrée désactivée et s'active par site : vous gardez le contrôle total de votre trafic.
- ⚡ **100 % Rust** — sûreté mémoire, E/S asynchrones et un binaire unique autocontenu avec la console embarquée.

> PingWAF est un projet indépendant. Il n'est ni affilié à, ni approuvé par Cloudflare ou les mainteneurs de `pingap`.

---

## ✨ Fonctionnalités principales

- **Moteur WAF sémantique** — pipeline en quatre phases (normalisation → signatures → expressions → scoring d'anomalies) avec les verdicts `Pass`, `Monitor`, `Block` et `Challenge`.
- **Protection CC / bouclier de 5 secondes** — défis JavaScript, Proof-of-Work et interactifs, avec cookies d'autorisation signés en HMAC.
- **Protection anti-bots** — liste blanche des bots vérifiés, passage des navigateurs connus et action configurable pour le reste.
- **Règles d'accès IP** — `block` / `allow` / `challenge` / `js_challenge`, avec plages CIDR, import CSV et **groupes IP globaux** synchronisés par abonnement (p. ex. les plages Cloudflare).
- **Restriction géographique** — autoriser ou bloquer par pays et par numéro de système autonome (ASN).
- **Limitation de débit multidimensionnelle** — par IP, hôte, chemin, ASN, pays, ou selon un en-tête, un cookie ou un paramètre de requête.
- **Pools d'origine et routes** — équilibrage de charge round-robin, moindres connexions, aléatoire ou par hachage cohérent, avec routage par préfixe, correspondance exacte ou regex.
- **Cache en périphérie** — quotas disque par site, `stale-while-revalidate` et contrôle du TTL navigateur.
- **Réécriture requêtes/réponses** et **pages d'erreur personnalisées** avec des modèles Tera.
- **TLS automatique** — émission et renouvellement ACME / Let's Encrypt en périphérie (HTTP-01 et DNS-01 avec Aliyun, Cloudflare, Tencent Cloud DNSPod, Huawei Cloud ou manuel), avec état du certificat par site remonté au plan de contrôle. La vérification du certificat de l'origine HTTPS est un interrupteur explicite (Paramètres → Origine), avec une valeur par défaut globale et une dérogation par pool.
- **Observabilité** — journaux complets dans Elasticsearch (optionnel), aperçus des en-têtes et du corps en PostgreSQL, et analytiques du trafic et des attaques.
- **Console intégrée multilingue** (English / 简体中文 / 日本語), authentification JWT + bcrypt, isolation multi-locataires et **versionnage de la configuration** (lister, comparer table par table et revenir en arrière après confirmation).

---

## 🚀 Démarrage rapide

### Option A — Docker Compose (recommandée)

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF

# Démarre le plan de contrôle + le plan de données + PostgreSQL (image préconstruite depuis GHCR)
docker compose up -d
```

Ouvrez la console :

- **URL :** https://localhost:9080 (certificat auto-signé ; remplacez-le dans Réglages → HTTPS du plan de contrôle)
- **E-mail :** `admin@pingwaf.local`
- **Mot de passe :** `pingwaf123`

> ⚠️ **Changez le mot de passe administrateur et `PINGWAF_JWT_SECRET` avant toute utilisation en production.**

### Option B — Compiler depuis les sources

Sur macOS (ou si vous préférez compiler), il faut **Rust 1.96+**, **Node.js 22**, `protoc` et `cmake` :

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF
cd web && npm ci && npm run build && cd ..
cargo build --release --bin pingwaf --features full
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

### Option C — Script d'installation (Linux)

Les binaires préconstruits pour **Linux (amd64 / arm64)** sont disponibles dans les [Releases](https://github.com/shuaiZend/PingWAF/releases) :

```bash
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | sudo bash -s -- --mode all-in-one
```

### Ports par défaut

| Port | Rôle |
| --- | --- |
| `9080` | API REST + console intégrée en HTTPS (santé : `GET /healthz`, aussi en HTTP) |
| `9090` | Plan de contrôle gRPC (les agents s'y connectent) |
| `80` / `443` | Trafic proxifié (liés à la création du premier site ; le `443` ne s'ouvre qu'après l'émission ou le téléversement d'un certificat — jusque-là seul le `80` sert du HTTP) |

---

## 🧭 Documentation

| Document | Contenu |
| --- | --- |
| [docs/quick-start.md](./docs/quick-start.md) | De zéro à votre premier site protégé |
| [docs/deployment.md](./docs/deployment.md) | Docker, binaire + systemd, topologies distribuées |
| [docs/user-guide.md](./docs/user-guide.md) | Guide de la console, sites, règles et politiques |
| [docs/api.md](./docs/api.md) | Référence de l'API REST (`https://<host>:9080/api/v1`) |
| [docs/README.md](./docs/README.md) | Index complet de la documentation |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | Comment contribuer |
| [SECURITY.md](./SECURITY.md) | Politique de divulgation des vulnérabilités |

---

## 📄 Licence

PingWAF est distribué sous **[Apache License 2.0](./LICENSE)**. Il s'agit d'une œuvre dérivée de `pingap` / `Pingora` qui conserve leurs mentions de copyright d'origine ; il n'est ni affilié à, ni approuvé par Cloudflare ou le projet `pingap`.
