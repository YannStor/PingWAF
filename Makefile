# The single version every crate inherits, read straight out of the manifest.
# Scoped to the `[workspace.package]` section because the root `[package]` says
# `version.workspace = true` and `[workspace.dependencies]` repeats a version
# per member, so an unscoped match would find the wrong line.
#
# Not `cargo pkgid`: that reads Cargo.lock, which still holds the old number in
# the one moment this is for - just after the manifest was bumped, before any
# cargo command has refreshed the lock.
VERSION := $(shell awk '/^\[workspace\.package\]/{f=1;next} \
	f&&/^version = /{gsub(/"/,"",$$3);print $$3;exit}' Cargo.toml)

lint:
	typos
	cargo clippy --features=full --all-targets --all -- --deny=warnings

# Same gate for the rustls TLS backend
lint-rustls:
	cargo clippy --no-default-features --features=tls-rustls,full --all-targets --all -- --deny=warnings
	# `geo` is not part of `full`, so it needs its own pass or it silently rots.
	cargo clippy -p pingap-plugin --features=geo --all-targets -- --deny=warnings

fmt:
	cargo fmt --all

# ── Build hygiene ────────────────────────────────────────────────────────────
# Cargo never garbage-collects target/: every feature set, test binary and
# profile keeps its own artifacts forever — one checkout of this repo reached
# 108 GB that way. An October 2026 sweep still found 47 GB there, and none of it
# was incremental cache (that directory was empty): deps/ held 2055 rlibs for
# only 583 distinct crates — `pingap_core` alone had 41 copies — plus 21000
# object files, all of it duplication between feature sets.
#
# The guarded targets below run `check-target` first. Once target/ exceeds
# TARGET_MAX_GB, `scripts/sweep-target.sh` drops the incremental caches and the
# intermediate artifacts older than TARGET_SWEEP_DAYS, and only if that is still
# not enough does it fall back to a full `cargo clean`. Each step is safe —
# cargo rebuilds whatever a later build needs — so the only thing being traded
# away is rebuild time. Override per invocation (`make test TARGET_MAX_GB=50`).
#
# Bare `cargo build` / `cargo check` / bacon bypass all of this, which is how
# this repo got to 47 GB in the first place: use `make build` / `make check`,
# and run `make sweep` after a session that crossed feature sets. `dev` stays
# exempt on purpose: bacon owns that loop and the incremental cache keeps it
# fast.
TARGET_MAX_GB ?= 20
TARGET_SWEEP_DAYS ?= 3

GUARDED := lint lint-rustls test test-rustls cov bench bench-all bloat \
	build check \
	release release-full release-rustls-full release-all release-perf \
	release-pyro

.PHONY: $(GUARDED) check-target sweep sweep-dry

$(GUARDED): check-target

check-target:
	@used=$$(du -sm target 2>/dev/null | cut -f1); \
	limit=$$(( $(TARGET_MAX_GB) * 1024 )); \
	if [ -n "$$used" ] && [ "$$used" -gt "$$limit" ]; then \
		echo "target/ uses $${used} MB, over TARGET_MAX_GB=$(TARGET_MAX_GB): sweeping"; \
		./scripts/sweep-target.sh --quiet --days $(TARGET_SWEEP_DAYS); \
		used=$$(du -sm target 2>/dev/null | cut -f1); \
		if [ -n "$$used" ] && [ "$$used" -gt "$$limit" ]; then \
			echo "still $${used} MB: cargo clean"; \
			cargo clean; \
		fi; \
	fi

# The guard's prune, on demand, without the budget check.
sweep:
	./scripts/sweep-target.sh --days $(TARGET_SWEEP_DAYS)

# Same, but only report what would be removed.
sweep-dry:
	./scripts/sweep-target.sh --dry-run --days $(TARGET_SWEEP_DAYS)

# Local builds. Bare `cargo build` / `cargo check` work too, but only these run
# the disk guard first.
build:
	cargo build

check:
	cargo check --features=full --all-targets

# Removes the build cache and the copied root `dist/`; `web/dist` is kept
# because pingwaf-server embeds it at compile time.
clean:
	cargo clean
	rm -rf dist

build-web:
	rm -rf dist \
	&& cd web \
	&& npm ci && npm run build \
	&& cp -rf dist ../


bench-all:
	cargo bench -p pingap-core
	cargo bench -p pingap-logger
	cargo bench -p pingap-location

bench:
	cargo bench

dev:
	bacon run --  --features=full -- -c="~/tmp/pingap?separation=true&enable_history=true" --admin=pingap:123123@127.0.0.1:3018 --autoreload

devfile:
	bacon run --  --features=full -- -c="~/tmp/pingap.toml" --admin=pingap:123123@127.0.0.1:3018 --autoreload

devetcd:
	bacon run -- -- -c="etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s&enable_history=true" --admin=127.0.0.1:3018 --autoreload

mermaid:
	cargo run --bin generate-mermaid

udeps:
	cargo +nightly udeps

msrv:
	cargo msrv list


bloat:
	cargo bloat --release --crates --bin pingwaf

outdated:
	cargo outdated

unused-features:
	unused-features analyze

test:
	cargo test --workspace --features=full

# Same suite on the rustls TLS backend
test-rustls:
	cargo test --workspace --no-default-features --features=tls-rustls,full

cov:
	cargo llvm-cov --workspace --html --open

release:
	cargo build --release
	ls -lh target/release

release-full:
	cargo build --release --features=full
	ls -lh target/release

# The full feature set on the rustls TLS backend (no OpenSSL in the binary)
release-rustls-full:
	cargo build --release --no-default-features --features=tls-rustls,full
	ls -lh target/release


release-all:
	cargo build --release --features=full
	mv target/release/pingwaf target/release/pingwaf-full
	cargo build --release
	ls -lh target/release

release-perf:
	cargo build --profile=release-perf --features=perf
	ls -lh target/release-perf
release-pyro:
	cargo build --profile=release-perf --features=pyro
	ls -lh target/release-perf

publish:
	make build-web
	cargo publish --registry crates-io --no-verify

hooks:
	cp hooks/* .git/hooks/

# CHANGELOG.md is written by hand, one section per release, in the same style
# as the ones above it: a short "why" per entry, not the commit subjects. It is
# deliberately NOT generated from the commit log — the notes explain what was
# wrong and what changed for an operator, which a subject line does not. See
# CONTRIBUTING.md ("Release notes").
#
# `version` therefore only reports what a release still owes, and fails when the
# section for $(VERSION) is missing, so a bump cannot land a version whose notes
# were never written. Nothing here edits CHANGELOG.md, and git-cliff is not
# invoked even when installed (it would print its own template, not the file).
# The commit list is best-effort: it says so when it cannot be produced, rather
# than printing nothing and looking like "no commits were missed".
version:
	@set -e; \
	v="$(VERSION)"; \
	[ -n "$$v" ] || { echo "Cargo.toml has no [workspace.package] version" >&2; exit 1; }; \
	[ -f CHANGELOG.md ] || { echo "CHANGELOG.md is missing" >&2; exit 1; }; \
	if grep -q "^## \[PingWAF $$v\]" CHANGELOG.md; then \
	  echo "CHANGELOG.md has a section for $$v"; \
	else \
	  echo "CHANGELOG.md has no '## [PingWAF $$v]' section — write it before tagging." >&2; \
	  exit 1; \
	fi; \
	last="$$(git describe --tags --abbrev=0 2>/dev/null || echo '')"; \
	echo "--- commit subjects since $$last (for reference only) ---"; \
	if [ -z "$$last" ]; then \
	  git log --oneline 2>/dev/null || echo "(could not read the commit log)"; \
	elif [ "$$(git rev-parse HEAD)" = "$$(git rev-parse "$$last^{commit}" 2>/dev/null)" ]; then \
	  echo "(HEAD is $$last itself; nothing committed since that tag)"; \
	else \
	  git log --oneline "$$last..HEAD" 2>/dev/null || echo "(could not read the commit log)"; \
	fi

.PHONY: version

# Bump both places the version lives: [workspace.package] and the per-member
# requirements in [workspace.dependencies]. `make bump V=1.2.3` sets it outright.
bump-major:
	./scripts/bump-version.sh major

bump-minor:
	./scripts/bump-version.sh minor

bump-patch:
	./scripts/bump-version.sh patch

bump:
	@test -n "$(V)" || { echo "usage: make bump V=1.2.3"; exit 1; }
	./scripts/bump-version.sh $(V)

# Fails when the two places disagree, which builds from a path checkout hide.
check-version:
	./scripts/bump-version.sh --check

# Static consistency checks for docs and agent prompts: frontmatter, model
# names, cross references, markdown links. No toolchain deps, runs anywhere.
# Not in GUARDED: touches no cargo artifacts, so the disk guard is pointless.
check-docs:
	./scripts/check-docs-prompts.sh

.PHONY: check-docs
