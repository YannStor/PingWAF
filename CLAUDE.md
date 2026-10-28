# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

PingWAF is a distributed, centrally-controlled Web Application Firewall built on `pingap`, a Cloudflare-Pingora-based reverse proxy. The `pingap` proxy engine plus all reusable logic lives in the `pingap-*` workspace crates; the WAF layer adds seven `pingwaf-*` crates (`proto`, `server`, `agent`, `waf`, `challenge`, `profiler`, `system`). The binary lives in `src/`; the top-level `src/pingwaf.rs` translates the DB-backed control-plane model into a `pingap` config. MSRV is `1.96.0` (Rust edition 2024). Pingora is `0.9.0` from crates.io; only the `lb`/`cache` features are enabled there, and the TLS backend feature (pingora's `openssl` or `rustls`) is added by pingap's own top-level `openssl` / `tls-rustls` features. The three `pingora*` entries in `[workspace.dependencies]` must always name the same version, or cargo resolves two copies of `pingora-core`.

The workspace is a **hard fork** of upstream `pingap`: inherited crates are maintained here, synced from upstream manually per fix. Ownership, sync procedure and test ownership are documented in [UPSTREAM.md](./UPSTREAM.md).

**Build the pingora `Server` with `Server::new_with_opt_and_conf`, never `Server::new` followed by assigning `my_server.configuration`.** Since 0.8.1 the constructor snapshots the configuration into a private `Bootstrap`, and that snapshot — not `Server::configuration` — is what the receiving half of a hot upgrade reads `upgrade_sock` from. A later assignment silently leaves the two halves on different sockets.

### Versioning

The binary and every crate share one version, declared once in `[workspace.package]`; members inherit it with `version.workspace = true`. The internal `pingap-*` dependencies live in `[workspace.dependencies]`, so a member depends on a sibling with `{ workspace = true }`.

**Bumping the version means editing two places in the root `Cargo.toml`**: `workspace.package.version`, and the `version = "..."` on each `pingap-*` entry in `[workspace.dependencies]` — cargo has no way to inherit the package version into a dependency requirement. `publish.sh` then publishes all crates at the new version in dependency order.

## Common commands

```bash
# Bacon-driven dev loop (uses --autoreload + admin UI on :3018)
make dev                 # bacon run -- --features=full -- -c=... --admin=...

# Lint (CI gate — runs typos + clippy --features=full --all-targets -- -D warnings)
make lint

# Format
make fmt

# Full test suite (requires the `full` feature set)
make test                # cargo test --workspace --features=full
make test-rustls         # same suite built with the rustls TLS backend (also: make lint-rustls)

# One package / one test (use cargo directly, not make)
cargo test -p pingap-proxy
cargo test -p pingap-core util::tests::test_now_ms -- --nocapture

# Benchmarks (criterion)
make bench               # workspace-wide
make bench-all           # explicit list (pingap-core, pingap-logger, pingap-location)

# Release builds — see Makefile for the matrix
make release             # default features
make release-full        # tracing + imageoptim
make release-perf        # release-perf profile, includes pyroscope agent

# Local builds — route through these, not bare `cargo`, so the disk guard runs
make build               # cargo build
make check               # cargo check --features=full --all-targets

# Reclaim target/ on demand (the guard also does this on its own; see below)
make sweep-dry           # report what would be removed
make sweep               # drop incremental caches + stale intermediates

# Web admin assets (rust-embed'd into the binary at build time)
make build-web           # cd web && npm ci && npm run build, then cp dist ../

# Pre-commit hook (runs `make lint`)
make hooks               # cp hooks/* .git/hooks/
```

Bacon shortcuts: `bacon` (check), `bacon clippy-all`, `bacon test`, `bacon test -- some::path`, `bacon nextest`, `bacon doc-open`.

### Build footprint and binary size

**Every binary that is actually shipped or run comes from the size-optimized profile.** `[profile.release]` is deliberately tuned for size, not speed — `opt-level = "z"`, `codegen-units = 1`, `lto = true`, `strip = true`, `panic = "abort"`. That is not a guess: a full 0.21.0 replay bench (33877 samples, four configs) showed byte-identical verdicts and conserved p95 latency at `opt-level = "z"` for a binary ~36% smaller than the previous `opt-level = 3`. Leave it alone; `release-perf` exists only for the profiler builds (`perf` / `pyro`) that need symbols. The dev profile is kept lean for the same reason — the debug binary is ~214 MB against ~31 MB for the release one, a 7x difference that shows up directly in `target/`:

- `[profile.dev] debug = "line-tables-only"`, and `[profile.dev.package."*"] debug = false` — dependencies carry no DWARF (nobody steps through them), workspace members keep line tables so a panic still reports `file:line`.
- `[profile.test]` repeats both and adds `incremental = false`: incremental caches are only ever written for workspace members and nothing collects them, so `cargo test --workspace` would otherwise pile up one per feature set and test binary.

**Do not mix feature sets casually.** Cargo keys artifacts on `(crate, feature set, profile)`, so every extra combination — `--features=full`, `--no-default-features --features=tls-rustls,full`, `-p pingap-plugin --features=geo` — is another full copy of the dependency graph inside `target/`. Prefer `full` for local work and leave the rustls / geo variants to `make lint-rustls`, `make test-rustls` and CI.

**Route local builds through `make build` / `make check`, not bare `cargo`.** Those run `check-target` first, which keeps `target/` under `TARGET_MAX_GB` (default 20 GB) by dropping the incremental caches and the intermediates older than `TARGET_SWEEP_DAYS` (default 3 days) via `scripts/sweep-target.sh`, falling back to `cargo clean` only if that is still not enough. `make sweep` / `make sweep-dry` run the same prune by hand — worth doing after a session that crossed feature sets. Bare `cargo build` / `cargo check` and bacon bypass the guard entirely, which is exactly how this repo reached 47 GB in October 2026: `deps/` held 2055 rlibs for only 583 distinct crates (`pingap_core` alone had 41 copies) plus 21000 object files, none of it incremental cache. An editor running `cargo check` in the background (`rust-analyzer`) writes to `target/` the same way and is likewise unguarded.

## Architecture

The dependency layering (see `docs/modules.md` for the full mermaid graph) is roughly:

```
util -> core -> {discovery, config, logger, location, cache, certificate, upstream, plugin, health}
                        |
                        v
              acme, performance, otel, sentry, pyroscope, imageoptim, webhook
                        |
                        v
                     proxy <- top binary (`src/main.rs`)
```

- `pingap-core` — `HttpResponse`, `Ctx`, plugin traits, clock helpers (`now_sec`/`now_ms`), `BackgroundTaskService`. Every other crate depends on it.
- `pingap-config` — `PingapConfig` model plus storage backends (`file_storage.rs`, `etcd_storage.rs`) chosen at runtime by URL prefix (`file://`, `etcd://`). Supports TOML, HCL (`hcl.rs`), and KDL (`kdl.rs`) input formats.
- `pingap-proxy` — implements pingora's `ProxyHttp`. The request lifecycle in `pingap-proxy/src/server.rs` calls (in order) `early_request_filter` -> `request_filter` -> `proxy_upstream_filter` -> `upstream_request_filter` -> `upstream_response_filter` -> `logging`. Each step matches the `PluginStep` enum in `pingap-core/src/plugin.rs` (`EarlyRequest`, `Request`, `ProxyUpstream`, `UpstreamResponse`, `Response`); a plugin runs at most one step per request.
- `pingap-plugin` — built-in plugins. Add new ones by implementing the `Plugin` trait from `pingap-core` and registering them via the plugin factory.
- `pingap-upstream` — pingora `Backends` + load-balancing wiring; gets its backend set from `pingap-discovery` (static / DNS / Docker labels / transparent) and `pingap-health` for active checks.
- `src/main.rs` — argument parsing, config bootstrap, daemonization, server assembly. The `src/process/` and `src/plugin/` modules handle hot reload + the admin plugin.
- `build.rs` — uses `vergen = "10.0.3"` + `vergen-git2 = "10.0.3"` to embed `VERGEN_GIT_SHA` into the binary's `--version`. **Both crates must stay on matching majors**; if you see `Add` trait-bound errors from `vergen_lib`, the lockfile has pulled mismatched versions — refresh it. The emitter runs with `default_on_error()`: vergen 10 otherwise leaves `VERGEN_GIT_SHA` unset when there is no `.git` (source export, crates.io tarball) and `env!()` stops compiling; with it the value is `VERGEN_IDEMPOTENT_OUTPUT`, which `git_hash()` in `src/main.rs` reports as `unknown`.
- `examples/` — working configs to copy from: `api-gateway`, `grpc-web`, `static-serve`, `transparent-proxy`, `web-socket`.

### Hot reload vs auto-restart

`src/main.rs` branches on `pingap_config::ConfigManager::support_observer()`. **etcd** returns `true` and pushes changes via a `WatchStream` (`pingap-config/src/etcd_storage.rs`) wired through `new_observer_service`. **File** storage returns `false` and is polled by `new_auto_restart_service` (`src/process/auto_restart.rs`) on a fixed interval. Both feed the same `reload_handle` — the difference is only the delivery mechanism. `--autoreload` keeps the process and swaps config in place; `--autorestart` performs a zero-downtime graceful restart for changes that need a fresh listener.

**Agent rule-cache persistence (`pingwaf-agent/src/cache/`) is crash-safe — keep it that way.** Every file goes through `persist::write_atomic` (same-directory temp + fsync + rename) under `persist_lock`; `persist_to_disk` rolls a validated `sites.json` to `sites.json.bak` before overwriting, and `load_from_disk` validates format version + CRC32/length (stamped in `metadata.json`) with the fallback chain primary → backup → empty-rules-plus-warning. Cache health rides the heartbeat as `cache_persist_healthy` / `cache_status_reason`. A new cache file must join the lock, write atomically, and extend the validation — a plain `fs::write` here reintroduces the torn-snapshot bug. The strategy is deliberately fail-open: the control plane re-pushes the full bundle right after connect, so the snapshot only bridges disconnects.


The restart hand-over (`src/process/common.rs::restart_now`) is readiness-driven, not timer-driven, and the channel is pingap's own. `restart_now` binds a unix socket at `<upgrade_sock>.ready`, spawns the replacement with `-d -u` and `PINGAP_READY_SOCK` in its environment, and waits: the new process runs `ReadyNotifyService` (added in `main.rs`, and made a dependency of the bootstrap service) which connects to that socket right before bootstrap asks the old process for the listening sockets. Only then does the old process send itself SIGQUIT; if the spawned process exits non-zero, the daemon it forked disappears (watched through the shared pid file), or `basic.restart_ready_timeout` passes, the restart is abandoned and the old process keeps serving. This cannot deadlock because the report precedes `load_fds`. It relies on `Server::bootstrap_as_a_service()`: every listening service is added with `.add_dependency(&bootstrap_handle)` so it builds its sockets from the inherited fds instead of binding fresh ones.

**Do not switch to pingora's `daemon_wait_for_ready`.** Its parent side waits on a tokio SIGUSR1 listener, and tokio's signal wake-up pipe is process-global. pingap creates a tokio runtime before the fork (config loading), so the daemon inherits that pipe (verified with `lsof`: parent and daemon hold the same unix socket pair), its runtimes drain the wake-up, and the parent never sees the signal: it waits the full timeout and exits 1 while the daemon runs fine. pingora's own `graceful_upgrade` example, which creates no runtime before the fork, works on the same machine.

### Daemonization and background threads

Pingora forks inside `Server::run()` (what `run_forever()` wraps) for daemon mode, **after** `bootstrap()` and **before** the service runtimes start. `fork()` only carries the calling thread, so **any `std::thread` started before that point does not exist in the daemon**, and any handle to it is a handle to nothing — joining one gives `EINVAL`. Long-lived threads must be started from a pingora `BackgroundService`, which runs post-fork, not from a `#[ctor]` or from `run()`.

This is why `now_sec()`/`now_ms()` read the system clock directly (`SystemTime::now()`, ~18ns) instead of caching it in a background-updated global. The coarse clock that used to back them saved ~17ns per call but needed a thread, and the only per-request caller left was `ttl_lru_limit`; the fork-safety machinery it required had already caused one real bug (admin auth reading an hours-stale timestamp in daemon mode).

`main.rs` runs the server with `Server::run(RunArgs::default())` rather than `run_forever()`: `run` returns once every runtime has exited, which is where `webhook::flush_pending_before_exit()` posts the webhook batch a fast shutdown (SIGINT, no shutdown broadcast) would otherwise drop, before `process::exit(0)`. Graceful shutdowns are covered earlier by `WebhookFlushService`, which flushes when the shutdown watch flips.

### Plugin step contract

`PluginStep` is matched to the pingora callback by `pingap-proxy/src/server.rs`. Plugins return `RequestPluginResult` (`Skipped` / `Continue` / `Respond(HttpResponse)`) or `ResponsePluginResult`. Respect the configured `step` value — running a request plugin at `Response` is silently a no-op.

A location resolves its plugin names once and caches the `Arc<[NamedPlugin]>` (`Location::plugins_for`), keyed on `PluginProvider::version()`; a request only bumps the reference count. Any `PluginProvider` whose plugins can change must return a new version after every replacement (the binary's provider bumps it in `store`), or locations keep serving the old instances.

### Config formats

The same configuration can be expressed in TOML (canonical, see `conf/*.toml`), HCL (`conf/test.hcl`), or KDL (`conf/test.kdl`). `--to-hcl` and `--to-kdl` round-trip the loaded config. The `--sync <url>` flag pushes the loaded config to a different backend (e.g. file -> etcd). `--template` prints a starter TOML and exits.

## Features and feature gates

The top-level `[features]` block in `Cargo.toml`:

- `default` = `openssl`.
- `openssl` / `tls-rustls` — the TLS backend, exactly one of them. Each forwards pingora's `openssl` or `rustls` feature plus the same-named feature of `pingap-acme`, `pingap-certificate`, `pingap-performance`, `pingap-proxy` and `pingap-upstream`; those five carry `default = ["openssl"]` themselves (so `cargo test -p <crate>` keeps working) and are depended on with `default-features = false` in `[workspace.dependencies]` so the root's choice wins. Only `pingap-certificate` (`LoadedCertificate`, `GlobalCertificate`) and `pingap-upstream` (`new_ca`) contain backend-specific code, and both `compile_error!` when neither or both features are on. Build the rustls variant with `cargo build --no-default-features --features tls-rustls[,full]`; `make lint-rustls` / `make test-rustls` are its CI gates. Under rustls the per-server `tls_min_version`, `tls_max_version`, `tls_cipher_list` and `tls_ciphersuites` are rejected by `validate_servers_tls_for_backend` at config validation (pingora's rustls listener fixes TLS 1.2/1.3 and rustls' default suites), `TlsAccept::certificate_callback` is never invoked (certificates come from `GlobalCertificate`'s `ResolvesServerCert` impl), and the rustls crypto provider is aws-lc-rs via `install_default_crypto_provider()` early in `main`. `pingap_certificate::TLS_BACKEND` names the backend at runtime (`--version`, startup log, admin `/basic` features).

  Note that rustls is **also** in the default (OpenSSL) build: the control plane terminates dashboard HTTPS with it (`pingwaf-server/src/tls.rs`, with the provider pinned in `pingwaf-server/src/pki/tls.rs`) and `reqwest`, `lettre`, `instant-acme` and `tonic` (etcd client, OTLP exporter) all speak it outbound, so a rustls advisory is never "only the rustls variant". The requirement in `[workspace.dependencies]` is therefore `0.23.46` — the release that closes RUSTSEC-2026-0346/0347/0348/0349, one after the 0.23.45 fix for RUSTSEC-2026-0285 — and it spells out the feature set (`default-features = false`) instead of inheriting rustls' defaults, so an upstream default change cannot silently reshape the TLS stack. `pingwaf-server` takes the workspace requirement and only adds `ring`.
- `tracing` — turns on `pingap-otel` + `pingap-sentry`, and the `tracing` feature on `pingap-cache`, `pingap-core`, `pingap-performance`, `pingap-proxy`, and pingora's `sentry`. **`pingap-cache/tracing` also pulls in `prometheus`** — needed for any code touching cache metrics.
- `imageoptim` — `pingap-imageoptim` (png/jpeg/webp/avif).
- `full` = `tracing` + `imageoptim`. Required by `make test` and `make lint`.
- `pyro` — pyroscope agent.
- `perf` = `pyro` + `full`, paired with the `release-perf` profile (keeps debug info, no strip).

When adding a feature-gated module, mirror the wiring in both the workspace `Cargo.toml` and the consuming crate's `Cargo.toml`, and gate the `use`/registration with `#[cfg(feature = "...")]`.

## Configuration loading and env vars

`src/main.rs::parse_arguments()` overlays CLI args with `PINGAP_*` env vars. Anything not on the CLI falls back to env: `PINGAP_CONF`, `PINGAP_DAEMON`, `PINGAP_UPGRADE`, `PINGAP_LOG`, `PINGAP_ADMIN_ADDR`/`PINGAP_ADMIN_USER`/`PINGAP_ADMIN_PASSWORD` (these three combine into `--admin user:pass@addr` with base64-encoded creds). Other env vars used at runtime: `PINGAP_DISABLE_ACME`, and `$ENV:...` interpolations inside HCL configs (e.g. `$ENV:PINGAP_DNS_SERVICE_URL`).

CLI flags worth knowing: `-c/--conf <url>`, `-d/--daemon`, `-u/--upgrade` (hot upgrade from a running instance), `-t/--test` (validate config and exit), `-a/--autorestart` (graceful restart on config change), `--autoreload` (hot reload only — preferred for containers), `--cp` (control-panel mode, admin only).

## Lint and code style notes

- `clippy.toml` denies unwrap outside tests, sets `cognitive-complexity-threshold = 10`, and pins `msrv = "1.96.0"`. The root `Cargo.toml` adds `unwrap_used = "deny"`.
- CI runs `cargo clippy --features=full --all-targets --all -- --deny=warnings` plus `typos`. Run `make lint` before pushing.
- The git pre-commit hook (installed via `make hooks`) just runs `make lint`.
- `typos.toml` excludes `*.md` and `*.toml` from the spell check — typos in those file types will not be caught by `make lint`.

## CI gates

`.github/workflows/ci.yml` runs every gate listed below on pushes to `main` and on pull requests; any one of them failing breaks the build. It has eight jobs: `changes` (paths filter), `rust` (fmt / clippy `--features full -D warnings` / `cargo nextest run --workspace --features full --no-fail-fast` plus `cargo test --doc` / `typos`, on the MSRV and stable legs), `rustls` (clippy + nextest with `--no-default-features --features tls-rustls,full`), `web` (`npm ci` / `npm run lint` / `npm test` / `npm run build` in `web/`), `dockerfile` (builds only the `frontend-builder` stage of `Dockerfile` and `Dockerfile.perf`, `push: false`), `release-binary` (`cargo build --release --bin pingwaf --features full`), `docs` (`./scripts/check-docs-prompts.sh`, always runs, even on docs-only PRs), and `docker`, which packs the `release-binary` artifact into the amd64 image and pushes the `ghcr.io/shuaizend/pingwaf:main` **snapshot** tag — `release-binary` and `docker` only run on pushes to `main`, never on a PR. The versioned `:latest` / `:<major.minor>` / `:<version>` multi-arch manifests are published by `release.yml` (tag-triggered), which also builds the tarballs `install.sh` downloads.

Every cargo build in `ci.yml`, `release.yml`, `Dockerfile` and `Dockerfile.perf` carries `--locked`, so a manifest that no longer agrees with the committed `Cargo.lock` fails the build instead of silently resolving a different dependency set — the failure mode behind a security floor that exists in the manifest but not in what actually gets compiled. `cargo fmt` and `cargo audit` are deliberately unchanged: fmt does not resolve dependencies, and `cargo audit` reads the committed lock file rather than re-resolving the graph. Reproduce locally with the corresponding command (`make lint` / `make test` wrap the same cargo calls without `--locked`; add it when running cargo directly):

Note that CI and the release pipeline build `Dockerfile.runtime` from a prebuilt binary, and only `release-perf.yml` (manual dispatch) builds `Dockerfile.perf` in full. The source `Dockerfile`'s Rust build stage is therefore never built by a workflow — the `dockerfile` job compiles only its `frontend-builder` stage, which is where the cheap mistakes live (the `.npmrc` COPY, the pinned Node tag, `npm ci` under `engine-strict`). A change to the Rust stage reaches production without a CI check; verify it with `docker build .` locally.

| Gate | Local equivalent |
|---|---|
| `cargo fmt --all -- --check` | `make fmt` (auto-fixes) or run the check directly |
| `make lint` (typos + clippy `--features=full -D warnings`) | `make lint` |
| `cargo machete` (local only — no workflow runs it) | `cargo install cargo-machete@0.9.1 && cargo machete` — `Cargo.toml` whitelists `humantime-serde`, `hcl-rs`, `kdl` in `[package.metadata.cargo-machete]` |
| `cargo nextest run --workspace --features full` + `cargo test --doc` | `make test` (`cargo test --workspace --features=full`) |
| `cargo clippy` + `cargo nextest run` with `--no-default-features --features tls-rustls,full` | `make lint-rustls && make test-rustls` |
| `cargo msrv list` (local only — no workflow runs it) | `cargo install cargo-msrv --version 0.18.4 && cargo msrv list` |
| `cargo llvm-cov` (local only — no workflow runs it) | `make cov` |
| `cargo build --release --bin pingwaf --features full` (`release-binary` job) | `make release-full` |
| `make release-all` (builds `pingwaf-full`, then `pingwaf`) | `make release-all` |
| `make build-web` (web assets; the `web` job runs the same npm steps in `web/`, without the copy to the repo root) | `make build-web` |

### Release toolchain vs MSRV

The MSRV (`rust-version` in `Cargo.toml`, `msrv` in `clippy.toml`) is a floor that CI proves on `stable`. Release binaries are built with a **pinned recent stable**, deliberately newer: the `dtolnay/rust-toolchain@1.98.1` pin in `.github/workflows/release.yml` and the `FROM rust:1.98.1-bookworm` line in the `Dockerfile` are one setting and move together.

`release.yml` triggers on a `v*` tag and releases **Linux only** (`shuaiZend/PingWAF` does not ship macOS or Windows binaries). Two matrix legs (`linux/amd64`, `linux/arm64`) each build `--features tracing` with the default OpenSSL backend and publish **two archives per arch**: `pingwaf-linux-<arch>.tar.xz` (primary, smaller) and `pingwaf-linux-<arch>.tar.gz` (legacy fallback), each with a `.sha256` sidecar. `install.sh` resolves `pingwaf-${OS}-${ARCH}.${ext}` for `ext` in `tar.xz` then `tar.gz` from the release URL — the names must not drift. There is no rustls tarball and no `PINGAP_TLS` selection in `install.sh`.

The `docker` and `docker-manifest` jobs then build per-arch images from `Dockerfile.runtime` and merge them into `ghcr.io/shuaizend/pingwaf:{<version>,<major.minor>,latest}`.

## Web admin

`web/` is the React 19 + Vite + Tailwind dashboard. `pingwaf-server` embeds `../web/dist` via `rust-embed`, so after editing it run `make build-web` (which rebuilds `web/dist` and copies it to the repo root) before compiling. Two separate admin surfaces exist and must not be confused:

- **PingWAF console** (`web/`) — talks to the Axum REST API on `PINGWAF_ADMIN_ADDR` (default `0.0.0.0:9080`). This is the DB-driven console; pages live in `web/src/pages/` and API bindings in `web/src/api/`.
- **pingap admin plugin** (`src/plugin/admin.rs`, plus the older `web/` pages under `src/plugin/`) — only mounted when the binary runs in pingap mode with `--admin user:pass@host:port[/prefix]`; `make dev` puts it on `127.0.0.1:3018`. It serves an embedded rust-embed asset bundle and the `{admin-path}/api/pprof/*` endpoints.

**If you add a field to a `pingap-config` struct** (`BasicConf`, `ServerConf`, `LocationConf`, `UpstreamConf`, `CertificateConf`, `StorageConf`) **or to a plugin's config, and you are maintaining that pingap-mode admin**, the field is not done until the admin can show and edit it: add the field to the matching interface in `web/src/states/config.ts` and an item to the page in `web/src/pages/` (`Basic.tsx`, `Servers.tsx`, `Locations.tsx`, `Upstreams.tsx`, `Certificates.tsx`, `Storages.tsx`); for a plugin field, add it to that plugin's builder in `web/src/plugin-fields.ts`, with labels in both `web/src/i18n/en.ts` and `web/src/i18n/zh.ts`. Pick the control by the Rust type: `Option<bool>` -> `RADIOS` + `newBooleanOptions()` with `defaultValue: conf.field` (never `|| null`, that turns an explicit `false` into Unset); enum-like `Option<String>` -> `RADIOS`/`SELECT` + `newStringOptions(..., withNone = true)` with `defaultValue: conf.field || ""` so an unset field stays unset instead of being saved as the first option; `Option<Vec<String>>` of free-form entries (`name` or `name:value`) -> `TEXTS`, and only use `KV_LIST` when every entry really is `key<sep>value` (its placeholder is `"key hint : value hint"`, split on `" : "`); numbers -> `NUMBER`; durations/sizes -> `TEXT` with the `newZodDuration()`/`newZodBytes()` schema entry.

**The PingWAF console (`web/`) is a separate, DB-backed surface**: it edits the `pingwaf-server` models (`pingwaf-server/src/models/*`, exposed through `pingwaf-server/src/api/*`), **not** the `pingap-config` structs. There, the rule is: every field a `pingwaf-server` API returns or accepts should have a control in `web/src/api/types.ts` + the matching page, with its label in `web/src/i18n/locales/{en,zh,ja}/common.json` (all three locales).

The pages save an entry by merging the form values over the loaded entry (`{ ...loaded, ...value }`) because the server replaces the whole entry with what it receives; keep that merge when touching `onSave`, and keep it before `omitEmptyArrayString` so a field cleared in the form is still removed. Verify a new item end to end in the admin (`make dev`, or `make build-web` then run the binary with `--admin`): the value renders, an edit is saved, and clearing it removes the key from the config file.

### Global settings rows

A deployment-wide switch that the data plane must see belongs in a single-row
settings table named `<topic>_settings` (`defense_settings`,
`cache_settings`, `origin_settings`), each with `id = 1`, a `load()` that
lazily inserts the default row on first read, a `GET`/`PUT /settings/<topic>`
pair in `pingwaf-server/src/api/`, and a `notify_all_config_changed` call on
update so the new value reaches the agents in the next rule bundle. Adding one
meant touching, in order: a migration (`pingwaf-server/src/migration/`), the
model, the API module and its entry in `api/mod.rs`, the `RuleBundle` field in
`pingwaf-proto/proto/control_plane.proto`, the agent's cache struct, and the
control-plane-to-`pingap-config` translation in `src/pingwaf.rs`. The value
also has to be folded into the global config snapshot in
`pingwaf-server/src/config_history.rs`, or the config-version page cannot see
it change.

**`BasicConf::origin_verify_cert` and `UpstreamConf::verify_cert` are
tri-state, and the third state is the point**: `Some(true)` verifies,
`Some(false)` accepts any certificate, `None` means "no opinion, defer". For a
pool, `None` defers to the global switch; for the global switch, `None` leaves
the decision to pingora (which verifies). Two consequences worth remembering:
a `bool` default would destroy the distinction and silently pin the lenient
behaviour, which is exactly why the migration for the field had to reset
stored `false` values to `NULL`; and the global default must be folded into
each upstream's `hash_key` input **before** the key is computed, with the
change also compared explicitly in `src/process/auto_restart.rs`, or toggling
it changes nothing for upstreams that are already running.

## Documentation site (`website/`)

**Any behaviour change must be reflected in the docs the site is built from.** The site is not written separately — `scripts/build-website.sh` assembles it from files in the repo into a **VitePress** site (`website/package.json`, `website/BUILD.md`), so a feature that changes a config key, a default, a CLI flag or a plugin's behaviour is only documented once those source files are updated.

There is **no `pages.yml` workflow**: the site is built and published by `scripts/build-website.sh` under whatever Pages pipeline the deployment uses; check `.github/workflows/` before assuming an automated deploy exists.

Linking rules:

- **In repo files read on GitHub** (`README.md`, `README_zh.md`, `docs/README.md`) use plain relative paths (`./docs/quick-start.md`); they must resolve on github.com.
- **Between pages of the same language** use plain relative markdown (`plugins/jwt.md`).
- **`docs/zh/**` pages that need an English-only page** must climb out of the tree (`../user-guide.md`, `../api.md`) — those pages have no `docs/zh/` counterpart, and a bare `./user-guide.md` is a dead link.

### What to edit

| Change | Update |
| --- | --- |
| Plugin config key / default / behaviour | `pingap-plugin/docs/<plugin>.md` **and** `docs/zh/plugins/<plugin>.md` (only for plugins that have a Chinese page) |
| New plugin | both of the above, plus the index table in `pingap-plugin/README.md` and `docs/zh/plugins/README.md`, plus the sidebar lists in `scripts/build-website.sh` |
| Crate-level feature | `pingap-<crate>/README.md` **and** `docs/zh/crates/<crate>.md` |
| CLI flag / env var / quick start | `README.md`, `README_zh.md`, `docs/quick-start.md`, `docs/deployment.md` |
| Architecture / ACME flow / examples | `docs/modules.md`, `docs/acme_chart.md`, `examples/README.md` and their `docs/zh/guide/*` counterparts |
| WAF control plane / agent / dashboard | `docs/user-guide.md`, `docs/api.md`, `README.md` and `README_zh.md` |
| Agent roles / collaboration protocol / prompt regression checklist | `.codebuddy/agents/*.md`, `.codebuddy/agents/PROMPT_REGRESSION.md`, `.codebuddy/rules/pingwaf-multi-agent/RULE.mdc`, `CODEBUDDY.md` — gate with `make check-docs` (**note:** `.codebuddy/` is local-only IDE tooling, gitignored and not shipped with the repo; only `CODEBUDDY.md` is committed) |

The Chinese tree is a **maintained translation**, not a generated one: adding an English page without its `docs/zh/` counterpart leaves a gap in the Chinese site. `docs/zh/README.md` is the Chinese home page and must stay a PingWAF page — it must never fall back to upstream pingap content.

### Build and preview

```bash
./scripts/build-website.sh
cd website && npm run docs:dev        # VitePress dev server; / is English, /zh/ is Chinese
```

Generated (gitignored — never edit directly): `website/index.md`, `website/plugins/`, `website/crates/`, `website/guide/`, `website/zh/`. The `website/en/`, `website/README.md`, `website/_sidebar.md`, `website/_navbar.md` and `website/assets/*` entries that `.gitignore` still lists are docsify leftovers the script only deletes.

Hand-maintained and tracked: `website/BUILD.md`, `website/package.json`, `website/package-lock.json`, `website/.nojekyll`, `website/public/`, and the VitePress config `website/.vitepress/config.mts` plus `website/.vitepress/theme/`. Only `website/.vitepress/{dist,cache}/` and `website/node_modules/` are ignored.

A Pages deploy would need to rerun the script and publish on pushes that touch `website/**`, `scripts/build-website.sh`, `pingap-*/README.md`, `pingap-plugin/docs/**`, `docs/**`, `examples/README.md`, `README.md` or `README_zh.md`. **No workflow does this today** — `website/BUILD.md` documents the manual steps and flags the missing `pages.yml`.
