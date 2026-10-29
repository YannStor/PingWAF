---
title: Moteur WAF
description: Le pipeline en quatre phases, les règles d'expression, le score d'anomalie, les verdicts et les défis.
minutes: 9
---

## Le pipeline

Chaque requête dont le WAF est actif traverse quatre phases :

```
normaliser → signatures → règles d'expression → score d'anomalie → verdict
```

1. **Normaliser** — décodage d'URL répété (trois couches par défaut), décodage des entités HTML, repliement de chemin, séparation query et cookies ; le mode strict décode aussi les séquences d'échappement.
2. **Signatures** — correspondance multi-motifs Aho-Corasick et heuristiques libinjection pour SQLi et XSS sur chaque valeur décodée. Les correspondances réfléchies dans `Referer` et `User-Agent` sont dégradées en signal faible.
3. **Règles d'expression** — conditions compilées, évaluées après que les règles Allow ont pu court-circuiter.
4. **Score d'anomalie** — les correspondances s'agrègent en un score comparé au seuil pour produire un verdict unique.

## Score et verdicts

La sévérité se traduit en points de style OWASP : critique 5, élevée 4, moyenne 3, faible 2, informative 1. Le seuil par défaut est **40** avec paranoïa **2** (1 à 4).

| Verdict | Quand il est produit |
| --- | --- |
| `Pass` | Aucune correspondance ou score nul |
| `Monitor` | Score non nul mais sous le seuil de blocage |
| `Block` | Score au seuil, ou signature critique sur le chemin rapide |
| `Challenge` | Une règle impose un défi |

Les actions imposées par une règle priment sur le score et `Block` prime sur `Challenge`. Avec `fast_path_block_on_critical` (par défaut), une signature critique de l'étape 1 bloque immédiatement. Le mode Monitor rétrograde Block et Challenge en Monitor et note `would_enforce` pour régler avant d'appliquer.

## Expressions

Grammaire à descente récursive : `champ opérateur valeur`, combinable avec `and`, `or`, `not`, les valeurs pouvant être chaîne, nombre, booléen ou ensemble.

```
http.request.uri.path starts_with "/admin"
  and not ip.src in {10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8}

cf.waf.score.sqli ge 60

user_agent matches "(?i)(nikto|sqlmap|nmap|masscan|acunetix)"

http.request.method in {"TRACE" "TRACK"}
```

Champs disponibles : `http.request.uri.path`, `http.request.uri.full`, `http.request.uri.query`, `http.request.method`, `http.request.headers[...]`, `http.request.cookies[...]`, `http.request.body`, `http.host`, `ip.src`, `ip.src.country`, `cf.waf.score`, `cf.waf.score.sqli`, `cf.waf.score.xss`, `cf.waf.score.rce`, `ssl`, `user_agent`.

Opérateurs : `eq`/`=`/`==`, `ne`/`!=`, `contains`, `not_contains`, `matches`, `in`, `starts_with`, `ends_with`, `lt`, `gt`, `le`, `ge`, ainsi que les formes `not <op>`.

## Règles gérées

Le binaire embarque quinze règles `PINGWAF-xxxx` chargées selon le niveau configuré : familles d'injection, exposition de chemins d'administration, user agents de scanners, méthodes interdites, charges JNDI et URI surdimensionnées. Une règle qui ne se parse pas est ignorée avec un avertissement, sans invalider le paquet.

## Défis et protection CC

| Réglage | Valeur par défaut |
| --- | --- |
| `enabled` | `true` |
| `under_attack_mode` | `false` |
| `default_level` | `NonInteractive` (bouclier JS 5 s) |
| `clearance_duration_secs` | `1800` |
| `rate_threshold` | 100 requêtes/minute/IP |
| `exempt_paths` | `/health`, `/ping` |
| `pow_difficulty` | `20` |

Les niveaux sont `None`, `NonInteractive`, `Managed` (choix selon le risque) et `Interactive`. La preuve de travail utilise SHA-256 avec une cible de zéros initiaux. Le passage est stocké dans `__pingwaf_clearance`, valeur `base64(payload).base64(HMAC-SHA256)` liée au site émetteur, donc non rejouable ailleurs.

## Politique anti-bots

Configurée par site : `ua_analysis`, `js_detection`, `tls_fingerprint`, `behavioral_analysis`, action (`block`, `challenge`, `js_challenge`, `log`, `allow`), liste de bots connus, vérification IP et DNS, et groupe d'IP vérifiées optionnel. Les limites de débit partagent ces dimensions : `ip`, `ip_nat`, `host`, `path`, `asn`, `country`, `header:<name>`, `cookie:<name>`, `query:<name>`.

## Où régler les seuils

Les réglages WAF par site s'écrivent via `PUT /api/v1/sites/{site_id}/waf/settings` : `waf_enabled`, `mode`, `paranoia_level`, `advanced_mode`, options de surveillance et `body_stage_timeout_secs`. Les mêmes valeurs parviennent aux agents dans `WafConfig` avec `anomaly_threshold` et `paranoia_level`.
