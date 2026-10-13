# Contributing to PingWAF

Thank you for your interest in PingWAF! 🦀

PingWAF is a distributed, centrally managed Web Application Firewall built on
[pingap](https://github.com/vicanso/pingap) and Cloudflare's
[Pingora](https://github.com/cloudflare/pingora). It is a Rust workspace with a
React dashboard, and there is plenty of interesting work: proxy behaviour, WAF
rules, gRPC control-plane protocol, database migrations, observability, docs
and i18n.

This document explains how to set up a development environment, the conventions
we follow, and how to get a change merged.

**Contents**

- [Code of Conduct](#code-of-conduct)
- [Reporting Bugs and Requesting Features](#reporting-bugs-and-requesting-features)
- [Security Issues](#security-issues)
- [Development Environment](#development-environment)
- [Project Layout](#project-layout)
- [Running PingWAF Locally](#running-pingwaf-locally)
- [Code Style](#code-style)
- [Testing](#testing)
- [Dependencies and MSRV](#dependencies-and-msrv)
- [Frontend Conventions](#frontend-conventions)
- [Commit Conventions](#commit-conventions)
- [Branch and Pull Request Workflow](#branch-and-pull-request-workflow)
- [Contributor License Agreement](#contributor-license-agreement)
- [Getting Help](#getting-help)
- [中文速览](#中文速览)

---

## Code of Conduct

This project adopts the
[Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). By participating
you agree to uphold it. Report unacceptable behaviour as described in that
document.

## Reporting Bugs and Requesting Features

Use [GitHub Issues](https://github.com/shuaiZend/PingWAF/issues).

**Before opening an issue**, search existing issues and read
[`docs/quick-start.md` → Troubleshooting](./docs/quick-start.md#troubleshooting)
and [`docs/deployment.md` → Troubleshooting](./docs/deployment.md#troubleshooting).
Many reported problems (missing `protoc`, ports 80/443 not listening until a
site exists, stale `pingwaf-proto` build cache) are already documented there.

**For a bug report, include:**

1. PingWAF version (`pingwaf --version`) and the git commit you built from
2. Operating system, architecture, and how you installed it (Docker Compose,
   source build, systemd)
3. Run mode: `all-in-one`, `server` or `agent`
4. The exact command line and environment variables used (redact secrets)
5. Steps to reproduce, expected behaviour, actual behaviour
6. Relevant logs — re-run with `RUST_LOG=debug` and paste the output
7. Your configuration (sites, rules, upstreams) if the issue is behavioural

**For a feature request**, describe the problem you are solving, the behaviour
you want, and any alternative you considered.

> ⚠️ **Open an issue before writing a large new feature.** This keeps your work
> aligned with the project roadmap and saves you time.
>
> ⚠️ **Do not open a PR solely to fix typos, formatting or grammar** in docs
> and comments. We batch those, or fold them into a related change.

## Security Issues

**Do not open a public issue for a vulnerability.** Follow the private
disclosure process in [`SECURITY.md`](./SECURITY.md).

## Development Environment

### Toolchain

| Tool | Version | Needed for |
| --- | --- | --- |
| Rust | **1.96+** (MSRV; CI also runs 1.97 and stable) | Everything |
| Node.js | **22** | Building/linting the dashboard |
| protoc | any recent release | Generating `pingwaf-proto` gRPC stubs |
| cmake, clang/libclang | — | Native dependencies (e.g. TLS/ML crates) |
| pkg-config, OpenSSL dev headers | — | The default `openssl` TLS backend |
| nasm | — | Assembling optimised TLS/crypto code |
| PostgreSQL | **14+** (16 recommended) | Running the control plane |
| typos-cli, cargo-machete, cargo-msrv | latest | Lint gates (typos runs in CI; the other two are local checks) |

```bash
# macOS
xcode-select --install
brew install rustup-init protobuf cmake pkg-config openssl nasm node@22
rustup-init -y && source "$HOME/.cargo/env"

# Debian / Ubuntu
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev \
    cmake clang libclang-dev protobuf-compiler nasm curl git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs

# Optional CI-equivalent tooling
cargo install typos-cli
cargo install cargo-machete@0.9.1
cargo install cargo-msrv --version 0.18.4
```

> ⚠️ **Install `protoc` before your first `cargo build`.** If it is missing,
> [`pingwaf-proto/build.rs`](./pingwaf-proto/build.rs) writes a placeholder
> instead of the real gRPC code and only emits a `cargo:warning`. The failure
> surfaces later as baffling "cannot find type" errors in `pingwaf-server` and
> `pingwaf-agent`. Recover with:
>
> ```bash
> cargo clean -p pingwaf-proto
> ```

### Get the code

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF

# Install the pre-commit hook (runs `make lint`)
make hooks
```

### Build

```bash
# Dashboard assets — embedded into the Rust binary at compile time from web/dist
cd web && npm ci && npm run build && cd ..
# or, for the pingap admin plugin assets in ./dist:
make build-web

# The PingWAF binary (full feature set: tracing + imageoptim)
cargo build --bin pingwaf --features full

# Release build
cargo build --release --bin pingwaf --features full

# The rustls TLS backend instead of OpenSSL
cargo build --bin pingwaf --no-default-features --features tls-rustls,full
```

> Local builds are tuned for a small `target/`: dependencies are compiled
> without debug info and workspace members keep line tables only, so a checkout
> stays a few GB instead of tens of GB. `make clean` drops the cache outright,
> and the heavy targets (`lint`, `test`, `cov`, `bench`, `release*`) clean up
> automatically once `target/` passes `TARGET_MAX_GB` (20 GB by default;
> override per invocation, e.g. `make test TARGET_MAX_GB=50`): first the
> incremental caches, then the whole directory if that is not enough.

## Project Layout

| Path | What lives there |
| --- | --- |
| `src/` | Binary entry points (`pingap`, `pingwaf`), CLI parsing, process management |
| `pingwaf-server/` | Control plane: Axum REST API, dashboard serving, gRPC server, SeaORM entities and migrations |
| `pingwaf-agent/` | Data plane agent: gRPC client, config, local rule cache, heartbeat and log shipping |
| `pingwaf-proto/` | `control_plane.proto` and the generated gRPC stubs (needs `protoc`) |
| `pingwaf-waf/` | Detection engine: input normalisation, Aho-Corasick + libinjection-style SQLi/XSS fast path, expression rule engine with anomaly scoring (`WafVerdict`) |
| `pingwaf-challenge/` | JS challenge, clearance cookies, browser fingerprinting |
| `pingwaf-pprof/` | pprof-style profiling endpoints: CPU profile and SVG flamegraph (CPU sampling is Linux-only), memory snapshot |
| `pingap-*` | The inherited proxy stack: cache, certificates, ACME, config, plugins, proxy, upstream, logging, observability |
| `web/` | React 19 + TypeScript + Vite dashboard (Tailwind v4, Zustand, TanStack Query, i18next) |
| `docs/` | English documentation; `docs/zh/` holds the Chinese mirror |
| `conf/`, `examples/` | Sample proxy configurations |

Shared dependencies are pinned once in the root `Cargo.toml` under
`[workspace.dependencies]`; member crates reference them with
`{ workspace = true }`. Do not add a second version of a crate in a member
manifest.

## Running PingWAF Locally

Fastest: Docker Compose (`pingwaf` all-in-one + `postgres:16-alpine`).

```bash
export POSTGRES_PASSWORD="$(openssl rand -hex 16)"
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d --build
curl -sf http://localhost:9080/healthz      # {"status":"ok","database":"up"} (health answers on HTTP too)
```

Native, against a local PostgreSQL:

```bash
docker run -d --name pingwaf-postgres \
  -e POSTGRES_USER=pingwaf -e POSTGRES_PASSWORD=pingwaf -e POSTGRES_DB=pingwaf \
  -p 5432:5432 postgres:16-alpine

cargo run --bin pingwaf --features full -- all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

Dashboard: <https://localhost:9080> — default credentials
`admin@pingwaf.local` / `pingwaf123` unless you overrode them.

Configuration comes from CLI flags and `PINGWAF_*` environment variables; CLI
flags win. See [`docs/quick-start.md`](./docs/quick-start.md#configuration-cheat-sheet)
and [`docs/deployment.md`](./docs/deployment.md#configuration-reference).

## Code Style

**Rust**

```bash
make fmt        # cargo fmt --all
make lint       # typos + cargo clippy --features=full --all-targets --all -- --deny=warnings
make lint-rustls
```

- Formatting is enforced by [`.rustfmt.toml`](./.rustfmt.toml): `max_width = 80`,
  `edition = "2024"`, `match_block_trailing_comma = true`. CI runs
  `cargo fmt --all -- --check`.
- Clippy is configured in [`clippy.toml`](./clippy.toml): `msrv = "1.96.0"`,
  `cognitive-complexity-threshold = 10`, `allow-unwrap-in-tests = true`.
- `clippy::unwrap_used` is **denied** workspace-wide. Use `?`, `expect()` with a
  real justification, or handle the error. Panicking in request paths is a bug.
- Errors use domain enums with `snafu`; the Axum layer converts them into a
  uniform API response. Follow the existing pattern rather than inventing new
  error types.
- CI runs `typos` and `cargo machete` (unused dependencies) — both must pass.

**Frontend**

```bash
cd web
npm ci
npm run lint    # eslint
npm run build   # tsc -b && vite build (strict TypeScript)
```

## Testing

```bash
make test            # cargo test --workspace --features=full
make test-rustls     # same suite on the rustls TLS backend
make cov             # cargo llvm-cov --workspace --html --open
cargo test -p pingwaf-server        # a single crate
```

- CI runs the suite on Rust **1.96.0**, **1.97.0** and **stable** (one matrix
  job per toolchain). The rustls TLS backend gets its own CI job: the clippy
  gate plus the **full test suite** on
  `--no-default-features --features=tls-rustls,full` — the CI equivalents of
  `make lint-rustls` / `make test-rustls`.
- The workspace is a hard fork of upstream `pingap`. Before porting changes
  across the fork boundary, read [UPSTREAM.md](./UPSTREAM.md) — it documents
  which crates are inherited, the manual sync procedure, and test ownership.
- Add tests for new logic. Integration tests that need PostgreSQL should be
  gated so they skip cleanly when no database is configured.
- `cargo msrv list` (`make msrv`) verifies the declared MSRV still holds.

## Dependencies and MSRV

- **MSRV is Rust 1.96.** Raising it is a separate, discussed change — CI pins
  the MSRV toolchain on purpose.
- Dependabot updates GitHub Actions only. **Rust crates are not auto-updated**,
  because Dependabot ignores `rust-version` and cannot follow git-pinned
  dependencies. Bump crates manually and re-run the full gate.
- Keep these families on a single minor version to avoid duplicate resolution
  and type mismatches: `pingora`/`pingora-limits`/`pingora-runtime`,
  `tonic`/`tonic-prost`/`tonic-prost-build`/`prost`/`prost-types`,
  `sea-orm`/`sea-orm-migration`.
- TLS backend is selected by feature, never by adding a second TLS crate:
  `openssl` (default) or `tls-rustls`.
- Run `cargo audit` before proposing a dependency change. Accepted exceptions
  live in [`.cargo/audit.toml`](./.cargo/audit.toml), each with a written
  rationale and a removal condition.

## Frontend Conventions

React 19 + TypeScript (strict) + Vite, styled with Tailwind v4 semantic design
tokens; state via Zustand, data fetching via TanStack Query.

- Every user-facing string goes through i18next. Add the key to **all three**
  locale files: `web/src/i18n/locales/en|zh|ja/common.json`.
- Keep the Cloudflare-style design language: orange brand accent, semantic
  tokens, dark/light themes, responsive layout.
- Talk to the backend through `https://<host>:9080/api/v1` with the JWT bearer
  (`curl -k` until the self-signed certificate is trusted)
  token, as documented in [`docs/api.md`](./docs/api.md).

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/); the
changelog is generated from them by `git-cliff` ([`cliff.toml`](./cliff.toml)).
Non-conventional commits are filtered out of the changelog, so please conform.

```
<type>(<scope>): <subject>

<body — what changed and why, wrapped at 72 characters>

<footer — BREAKING CHANGE: …, Closes #123>
```

| Type | Use for |
| --- | --- |
| `feat` | A new feature |
| `fix` | A bug fix |
| `perf` | A performance improvement |
| `refactor` | Internal restructuring, no behaviour change |
| `docs` | Documentation only |
| `style` | Formatting only |
| `test` | Adding or fixing tests |
| `chore`, `ci` | Tooling, build, CI |
| `revert` | Reverting a previous commit |

Scope is the crate or area: `proxy`, `waf`, `agent`, `server`, `proto`, `web`,
`cache`, `tls`, `docker`, `deps`. Subject line: imperative mood, lowercase, no
trailing period, ≤ 72 characters.

Examples from the history:

```
fix(proxy): keep location counters straight, classify downstream errors
perf(performance): cache process info, stop leaking metric labels
docs(proxy): move the error template placeholders into a code block
```

Mark breaking changes with `!` after the scope or a `BREAKING CHANGE:` footer.

## Branch and Pull Request Workflow

1. **Fork** the repository and create a topic branch from `main`:
   `git checkout -b fix/waf-rule-phase`.
2. **Discuss first** for new features — open an issue and get a 👍.
3. **Implement** in small, reviewable commits. One logical change per PR.
4. **Verify locally** before pushing:

   ```bash
   make fmt
   make lint
   make test
   cd web && npm run lint && npm run build && cd ..
   ```

5. **Push** and open a PR against `main`. Fill in the
   [PR template](./.github/PULL_REQUEST_TEMPLATE.md): description, type of
   change, and the developer checklist (fmt, clippy, builds, CLA).
6. **CI** must pass: fmt, clippy (`--deny warnings`), typos, the test suite
   on three toolchains (1.96.0 / 1.97.0 / stable), and the rustls gate
   (clippy + full tests). `cargo-machete` and `make msrv` are local hygiene
   checks, not CI gates.
7. **Review**: at least one maintainer approval. Address comments with new
   commits; squash on merge if asked.
8. **After merge**, delete the topic branch.

Keep PRs focused. A PR that mixes a feature, a refactor and dependency bumps is
much slower to review — split it.

## Contributor License Agreement

Contributions are covered by the project CLA: [`CLA.md`](./CLA.md). In short:

1. **You retain copyright** of your original contributions.
2. **You grant** the project a perpetual, worldwide, non-exclusive,
   royalty-free licence to use, modify and distribute them under Apache-2.0.
3. **You declare** the work is original and that you have the right to license
   it (including employer permission where applicable).

Confirm your acceptance by ticking the CLA checkbox in the pull request
template. We do not currently require a `Signed-off-by` (DCO) trailer, but
adding one with `git commit -s` is welcome.

PingWAF is licensed under [Apache-2.0](./LICENSE). New source files should carry
the standard Apache-2.0 header used throughout the workspace.

## Getting Help

- Documentation: [`docs/quick-start.md`](./docs/quick-start.md),
  [`docs/user-guide.md`](./docs/user-guide.md),
  [`docs/api.md`](./docs/api.md),
  [`docs/deployment.md`](./docs/deployment.md),
  [`docs/modules.md`](./docs/modules.md)
- Per-crate READMEs for the proxy stack (`pingap-proxy/README.md`,
  `pingap-plugin/README.md`, `pingap-cache/README.md`, …) and
  [`docs/modules.md`](./docs/modules.md)
- GitHub Issues and Discussions

---

## 中文速览

欢迎贡献 PingWAF！

1. **环境**：Rust ≥ 1.96、Node 22、`protoc`（**必装**，缺失会静默生成占位文件导致
   `pingwaf-server` / `pingwaf-agent` 编译失败，需 `cargo clean -p pingwaf-proto`
   重新生成）、cmake、clang、pkg-config、libssl-dev、nasm、PostgreSQL ≥ 14。
2. **构建**：先 `cd web && npm ci && npm run build`（前端资源在编译期通过
   rust-embed 打进二进制），再 `cargo build --bin pingwaf --features full`。
   本地构建已针对 `target/` 体积调优（依赖不保留调试信息）；`make clean`
   可随时清理，`target/` 超过 `TARGET_MAX_GB`（默认 20 GB）时 `make lint` /
   `test` / `release` 等目标会自动先删 incremental 缓存、必要时再整目录清理。
3. **本地运行**：`cargo run --bin pingwaf --features full -- all-in-one
   --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"`，
   控制台 <https://localhost:9080>（自签名证书），默认账号 `admin@pingwaf.local` / `pingwaf123`。
4. **提交前**：`make fmt`、`make lint`、`make test`，前端 `npm run lint`。
   `clippy::unwrap_used` 全局 deny，请勿在请求路径中 panic。
5. **提交信息**：遵循 Conventional Commits（`feat/fix/perf/refactor/docs/test/chore`），
   scope 用 crate 或领域名，例如 `fix(waf): …`；changelog 由 git-cliff 自动生成。
6. **PR**：fork → 从 `main` 建分支 → 填写 PR 模板并勾选 CLA（见 [CLA.md](./CLA.md)）→ CI 全绿。
   新特性请先开 Issue 讨论；不要提交纯拼写/格式修正的 PR。
7. **安全漏洞**：请勿公开提 Issue，按 [SECURITY.md](./SECURITY.md) 私密披露。
8. **行为准则**：参与即表示同意 [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)。
