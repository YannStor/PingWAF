// Allocator retention policy.
//
// mimalloc keeps freed pages for `mi_option_purge_delay` milliseconds
// before returning them to the OS. The shipped images pinned that delay at
// 1000 ms for every machine (mimalloc's own default is 10 ms) — on a 1 GB
// host the retained pages are the difference between comfortable and OOM
// (see the 2026-10-15/17 post-mortems: RSS was allocator high-water
// retention, not live objects).
//
// This module derives the delay from the *actual* memory ceiling (cgroup
// limit, then host total) and lets an operator override it:
//
//   PINGWAF_MALLOC_PURGE_DELAY_MS   explicit, preferred
//   MIMALLOC_PURGE_DELAY            standard mimalloc env, still honoured
//   automatic: <1GB → 0 ms, 1-4GB → 250 ms, 4-16GB → 500 ms, >16GB → 1000 ms
//
// The value is applied through mimalloc's runtime API (`mi_option_set`),
// which works the same for containers and bare-metal systemd units — no
// reliance on environment timing (Rust std allocates before `main`).

use std::sync::Once;

use tracing::info;

/// `mi_option_t` ordinal of `mi_option_purge_delay`, pinned to the mimalloc
/// v2 enum bundled by libmimalloc-sys 0.1.49 (show_errors … eager_commit_
/// delay=14, purge_delay=15). Re-check on dependency upgrades — the
/// compile-time pin below is intentional.
#[cfg(not(feature = "mem-prof"))]
const MI_OPTION_PURGE_DELAY: std::os::raw::c_int = 15;

#[cfg(not(feature = "mem-prof"))]
unsafe extern "C" {
    /// mimalloc v2 runtime option setter (statically linked into this
    /// binary by the `mimalloc` crate).
    fn mi_option_set(option: std::os::raw::c_int, value: std::os::raw::c_long);
    /// Read-back, used by the startup log so operators can verify the
    /// effective value without guessing.
    fn mi_option_get(option: std::os::raw::c_int) -> std::os::raw::c_long;
}

const MIB: u64 = 1024 * 1024;

/// Purge delay (ms) bucketed by the memory ceiling. Zero means "return
/// freed pages immediately" — a little more CPU for a materially lower RSS
/// on small hosts.
pub fn purge_delay_for(total_bytes: u64) -> i64 {
    match total_bytes / MIB {
        0..=1023 => 0,
        1024..=4095 => 250,
        4096..=16384 => 500,
        _ => 1000,
    }
}

/// Explicit operator override. `PINGWAF_*` wins over the standard mimalloc
/// variable so a deployment can pin its own value without relying on the
/// image default; `-1` (never purge) is accepted but logged.
fn env_override() -> Option<(i64, &'static str)> {
    for (key, source) in [
        (
            "PINGWAF_MALLOC_PURGE_DELAY_MS",
            "env:PINGWAF_MALLOC_PURGE_DELAY_MS",
        ),
        ("MIMALLOC_PURGE_DELAY", "env:MIMALLOC_PURGE_DELAY"),
    ] {
        let Ok(raw) = std::env::var(key) else {
            continue;
        };
        match raw.trim().parse::<i64>() {
            Ok(value) if value >= -1 => return Some((value, source)),
            _ => info!(
                key,
                raw = %raw,
                "ignoring unparsable allocator retention override"
            ),
        }
    }
    None
}

/// Applies the retention policy once per process. Safe to call from both
/// entry points (all-in-one and the pingap-compatible one).
pub fn apply() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let total = pingwaf_pprof::total_bytes();
        let (delay, source) = match env_override() {
            Some(pair) => pair,
            None => (purge_delay_for(total.unwrap_or(0)), "adaptive"),
        };

        #[cfg(not(feature = "mem-prof"))]
        let effective = {
            // SAFETY: mi_option_set is mimalloc v2's documented runtime API
            // and the allocator is statically linked into this binary. The
            // ordinal is pinned to libmimalloc-sys 0.1.49 (see the const).
            unsafe {
                mi_option_set(MI_OPTION_PURGE_DELAY, delay);
                mi_option_get(MI_OPTION_PURGE_DELAY)
            }
        };
        #[cfg(feature = "mem-prof")]
        let effective = {
            // Diagnostic builds use jemalloc; its decay is compiled in by
            // the mem-prof image, nothing to tune here.
            delay
        };

        // Startup diagnostics: stderr is the only reliable channel this
        // early (tracing may not be initialised yet).
        eprintln!(
            "pingwaf: allocator retention purge_delay={effective}ms \
             (total={}MiB, source={source})",
            total.map(|bytes| bytes / MIB).unwrap_or(0)
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_delay_buckets() {
        // Unknown ceiling (probe failed) maps to the most aggressive bucket:
        // returning pages early is the safe side for OOM.
        assert_eq!(purge_delay_for(0), 0);
        assert_eq!(purge_delay_for(512 * MIB), 0);
        assert_eq!(purge_delay_for(1023 * MIB), 0);
        assert_eq!(purge_delay_for(1024 * MIB), 250);
        assert_eq!(purge_delay_for(2 * 1024 * MIB), 250);
        assert_eq!(purge_delay_for(4096 * MIB), 500);
        assert_eq!(purge_delay_for(16 * 1024 * MIB), 500);
        assert_eq!(purge_delay_for(17 * 1024 * MIB), 1000);
        assert_eq!(purge_delay_for(64 * 1024 * MIB), 1000);
    }

    #[test]
    fn purge_delay_is_monotonic() {
        let mut last = -1;
        for mib in [128_u64, 512, 1024, 2048, 4096, 8192, 16384, 32768] {
            let delay = purge_delay_for(mib * MIB);
            assert!(delay >= last, "delay must not shrink as memory grows");
            last = delay;
        }
    }
}
