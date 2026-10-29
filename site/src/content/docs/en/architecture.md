---
title: Architecture
description: How the PingWAF control plane and data plane fit together, what the gRPC protocol carries, and how policy reaches the edge.
minutes: 8
---

PingWAF splits into two processes that share one binary. The **control plane** owns all state; the **data plane** carries traffic and enforces policy. The data plane has no database of its own — and must not be given one.

## Control plane

`pingwaf server` exposes three surfaces:

| Surface | Default port | Purpose |
| --- | --- | --- |
| REST API + dashboard | `9080` (HTTPS) | Sites, rules, logs, configuration versions |
| gRPC `ControlPlane` | `9090` | Agent registration, heartbeats, rule sync, log and metric ingestion |
| PostgreSQL | `5432` | The only durable store; Elasticsearch is optional for request logs |

The dashboard is compiled into the binary with `rust-embed`, so there is no separate frontend deployment to keep in sync with the API.

## Data plane

`pingwaf agent` accepts traffic on `:80` and `:443`, evaluates WAF rules, terminates TLS and proxies to origin pools. It keeps a disk-backed rule cache under `cache_dir` and rebuilds its in-memory provider whenever the cached configuration hash changes — roughly every five seconds. Requests always read the current provider through `ArcSwap`, so a policy change never requires a restart.

## The gRPC contract

The single source of truth is `pingwaf-proto/proto/control_plane.proto`. Seven RPCs make up the service:

| RPC | Kind | Purpose |
| --- | --- | --- |
| `RegisterAgent` | unary | Join the fleet; receives `agent_id`, an `agent_token`, the heartbeat interval and initial site configs |
| `Heartbeat` | bidirectional stream | Liveness, stats and certificate status up; commands down |
| `SyncRules` | server stream | New rule bundles pushed after any configuration change |
| `ShipLogs` | client stream | Batched request and attack logs |
| `ShipCertEvents` | client stream | ACME issuance and renewal events |
| `ShipMetrics` | client stream | Traffic and cache metrics |
| `GetSiteConfig` | unary | Pull the full configuration for one site |

The same service also answers visitor login, passkey and session checks used by the challenge flow. Those calls are authenticated with the agent token and fail closed: if the control plane is unreachable, the request is not admitted.

## How a change reaches the edge

1. A REST write (dashboard or API) stores the new configuration in PostgreSQL.
2. The control plane records a configuration snapshot for the affected scope.
3. `notify_config_changed` pushes a fresh `SiteConfig` to every agent serving that site over the existing stream.
4. The agent persists the bundle to its rule cache, the cache hash changes, and the provider is swapped in memory.

## Failure behaviour

`fail_open` decides what an agent does when the control plane cannot be reached:

- `true` (default) — keep serving with the last synchronised policy.
- `false` — return `503` for hosts that have no synchronised rules.

The site-level failover policy takes precedence over the global default, and the choice is recorded in configuration so it survives restarts.

## Run modes

| Mode | Command | Role |
| --- | --- | --- |
| Control plane | `pingwaf server` | API, gRPC, dashboard, database. Does not proxy traffic |
| Data plane | `pingwaf agent` | Connects to a remote control plane and proxies on `:80`/`:443` |
| All-in-one | `pingwaf all-in-one` | Both in one process; the agent talks to the local server over loopback |

`PINGWAF_MODE` selects the same mode when the subcommand is omitted.

## Configuration versions

Every change is versioned per scope. Retention keeps at most 50 versions per scope, 30 days of history, and snapshots up to 2 MiB. A rollback takes an advisory lock, writes a `pre-rollback` snapshot, restores the previous state, then records the result as a new version — so a rollback is itself auditable and reversible.

Rollbacks can be triggered from the console or with `pingwaf config rollback <id> --yes`. The CLI path records the version but does not push to agents immediately; the next configuration change or agent reconnect applies it.
