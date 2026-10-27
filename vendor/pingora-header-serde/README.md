# vendored pingora-header-serde

Source: crates.io `pingora-header-serde 0.9.0`
VCS revision: `702f69015e53f7244d6ad2e743de571d859a70a4` (`path_in_vcs = "pingora-header-serde"`)

Local patch: only `Cargo.toml` / `Cargo.toml.orig` dependency versions were
advanced from `zstd 0.13.1` / `zstd-safe 7.1.0` to `zstd 0.14.3` /
`zstd-safe 8.2.0`. The zstd APIs used by this crate are present in 0.14.3.

Reason: Pingora 0.9's `pingora-header-serde` pins `zstd ^0.13.1`; zstd 0.13.3
and zstd-safe 7.3.0 carry the October 2026 RUSTSEC unsound set. This path patch
lets the workspace resolve the fixed zstd 0.14.3 / zstd-safe 8.2.0 while
Pingora has no newer release.

Remove when Pingora publishes a release using zstd 0.14.
