---
title: API
description: Groupes REST, authentification, contrat gRPC du plan de contrôle, clés d'API et automatisation.
minutes: 7
---

## REST

Tous les endpoints vivent sous `/api/v1` à l'adresse du plan de contrôle : `https://<host>:9080/api/v1`. L'authentification utilise un jeton Bearer :

```bash
TOKEN=$(curl -s -X POST https://localhost:9080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@pingwaf.local","password":"..."}' | jq -r .access_token)

curl -s https://localhost:9080/api/v1/sites -H "Authorization: Bearer $TOKEN"
```

La connexion renvoie `access_token`, `refresh_token`, `token_type: Bearer`, `expires_in` (43200 secondes) et `role`. Seuls `/auth/login`, `/auth/register`, `/auth/status`, les deux étapes passkey, `/health` et `/version` sont ouverts. `/system/*` exige en plus un administrateur.

## Groupes d'endpoints

| Groupe | Endpoints représentatifs |
| --- | --- |
| Auth | `POST /auth/login`, `POST /auth/refresh`, `GET|PUT /auth/me`, `PUT /auth/password` |
| Sites | `GET|POST /sites`, `GET|PUT|DELETE /sites/{id}`, `POST /sites/{id}/clone` |
| Règles | `GET|POST /sites/{id}/rules`, `GET|PUT|DELETE /sites/{id}/rules/{rule_id}`, `POST /sites/{id}/waf/defaults` |
| WAF | `GET|PUT /sites/{id}/waf/settings`, `GET /sites/{id}/waf/posture`, `GET /managed-rules` |
| Journaux | `GET /logs/security`, `GET /logs/access`, `GET /logs/access/{id}`, `DELETE /logs/purge` |
| Agents | `GET /agents`, `POST /agents/enroll`, `POST /agents/{id}/commands` |
| Versions | `GET /config-versions`, `GET /config-versions/{id}`, `POST /config-versions/{id}/rollback` |
| Système | `GET /system/metrics`, `/system/profile`, `/system/nodes`, `/system/status` |

Les appels par site passent par la frontière de locataire (`load_site_read` / `load_site_write`) : un jeton ne voit que les sites qu'il peut gérer. La référence complète, avec paramètres et formes de réponse, est `docs/api.md` dans le dépôt.

## gRPC

Les agents utilisent le service `ControlPlane` sur le port `9090`, défini dans `pingwaf-proto/proto/control_plane.proto` : `RegisterAgent`, `Heartbeat`, `SyncRules`, `ShipLogs`, `ShipCertEvents`, `ShipMetrics`, `GetSiteConfig`, plus les RPC de session visiteur du flux de défis. TLS est la valeur par défaut ; `grpc_tls_mode = "off"` ne vaut que pour un réseau de confiance.

## Clés d'API

Les comptes de service s'authentifient avec des clés préfixées `pwk_`, générées avec 128 bits d'entropie et stockées en hash bcrypt ; le texte en clair n'apparaît qu'à la création. Chaque clé porte une portée `read` ou `write` et une expiration.

```bash
curl -s -X POST https://localhost:9080/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"ci","scopes":["read"],"expires_in_days":90}'
```

## MCP

Le plan de contrôle expose un endpoint MCP Streamable HTTP sur `POST /mcp` (chemin racine, volontairement hors de `/api/v1`). Il accepte une clé `pwk_…` ou un JWT ; les outils d'écriture exigent en plus que le propriétaire soit administrateur. `GET` et `DELETE` renvoient `405` et le corps est limité à 256 Kio.

## Notifications

Les notifications webhook se configurent avec `PINGWAF_WEBHOOK_URL`, et les routes de notification exposent la configuration courante depuis la console, pour envoyer les événements de sécurité vers votre chaîne d'alerte.

## Recettes d'automatisation

- **Configuration révisable** — prenez un instantané via `GET /config-versions` après chaque changement et restaurez avec `POST /config-versions/{id}/rollback`.
- **Enrôler des nœuds depuis la CI** — `POST /agents/enroll` renvoie la commande d'installation, la CI ne stocke donc aucune clé.
- **Exporter les journaux** — interrogez `/logs/security` pour les requêtes bloquées ou activez l'envoi vers Elasticsearch.
