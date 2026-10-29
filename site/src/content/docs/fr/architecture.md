---
title: Architecture
description: Comment le plan de contrôle et le plan de données s'articulent, ce que transporte gRPC et comment la politique atteint la périphérie.
minutes: 8
---

PingWAF se compose de deux processus partageant un même binaire. Le **plan de contrôle** détient tout l'état ; le **plan de données** achemine le trafic et applique les politiques. Le plan de données n'a pas de base de données et ne doit pas en avoir.

## Plan de contrôle

`pingwaf server` expose trois surfaces :

| Surface | Port | Usage |
| --- | --- | --- |
| API REST + console | `9080` (HTTPS) | Sites, règles, journaux, versions de configuration |
| gRPC `ControlPlane` | `9090` | Enregistrement des agents, heartbeat, synchronisation, journaux et métriques |
| PostgreSQL | `5432` | Seul stockage durable ; Elasticsearch est optionnel pour les journaux |

La console est compilée dans le binaire via `rust-embed` : aucun frontend séparé à maintenir en phase avec l'API.

## Plan de données

`pingwaf agent` accepte le trafic sur `:80` et `:443`, évalue les règles WAF, termine TLS et relaie vers les pools d'origine. Il conserve un cache de règles sur disque sous `cache_dir` et reconstruit son fournisseur en mémoire dès que le hash change, environ toutes les cinq secondes. Les requêtes lisent toujours le fournisseur courant via `ArcSwap` : un changement de politique n'exige jamais de redémarrage.

## Contrat gRPC

La source unique est `pingwaf-proto/proto/control_plane.proto`, avec sept RPC :

| RPC | Type | Usage |
| --- | --- | --- |
| `RegisterAgent` | unaire | Rejoint la flotte ; renvoie `agent_id`, `agent_token`, intervalle de heartbeat et configuration initiale |
| `Heartbeat` | flux bidirectionnel | Vivacité, statistiques et état des certificats ; commandes vers l'agent |
| `SyncRules` | flux serveur | Nouveaux paquets de règles après chaque changement |
| `ShipLogs` | flux client | Journaux de requêtes et d'attaques par lots |
| `ShipCertEvents` | flux client | Événements d'émission et de renouvellement ACME |
| `ShipMetrics` | flux client | Métriques de trafic et de cache |
| `GetSiteConfig` | unaire | Configuration complète d'un site |

Le même service répond aux connexions visiteurs, aux passkeys et à la validation de session du flux de défis ; ces appels s'authentifient avec le token d'agent et échouent en refus si le plan de contrôle est injoignable.

## Comment un changement atteint la périphérie

1. Une écriture REST enregistre la configuration dans PostgreSQL.
2. Le plan de contrôle capture un instantané de la portée concernée.
3. `notify_config_changed` pousse un nouveau `SiteConfig` à chaque agent servant ce site.
4. L'agent persiste le paquet, le hash change et le fournisseur est remplacé en mémoire.

## Comportement en cas de panne

`fail_open` décide de la conduite d'un agent sans plan de contrôle : `true` (par défaut) continue de servir avec la dernière politique synchronisée ; `false` renvoie `503` pour les hôtes sans règles synchronisées. La politique par site prime sur la valeur globale et est enregistrée dans la configuration.

## Modes d'exécution

| Mode | Commande | Rôle |
| --- | --- | --- |
| Plan de contrôle | `pingwaf server` | API, gRPC, console, base de données ; ne relaie pas de trafic |
| Plan de données | `pingwaf agent` | Se connecte au plan distant et relaie sur `:80`/`:443` |
| All-in-one | `pingwaf all-in-one` | Les deux dans un processus, l'agent passe par la boucle locale |

`PINGWAF_MODE` sélectionne le même mode quand la sous-commande est omise.

## Versions de configuration

Chaque changement est versionné par portée, avec rétention de 50 versions par portée, 30 jours et des instantanés jusqu'à 2 MiB. Un rollback prend un verrou consultatif, écrit un instantané `pre-rollback`, restaure l'état précédent puis enregistre le résultat comme nouvelle version : le rollback est auditable et réversible.
