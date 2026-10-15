//! Bounded per-host caches for control-plane-compiled artifacts.
//!
//! Sites can match wildcard or alternate domains, so any Host header an
//! internet scanner invents may resolve — and each resolved host used to
//! cache one compiled artifact (WAF context, challenge engine, error pages,
//! rewrite rules, cache rules) with no eviction path once its site kept
//! matching. Random scanner hosts therefore accumulated forever.
//!
//! Every per-host cache shares this small helper: entries carry a
//! `last_used` unix timestamp that hits refresh, and a CAS-gated sweep (at
//! most one O(N) walk per interval per plugin) drops entries idle beyond
//! [`HOST_CACHE_TTL_SECS`] and evicts the least-recently-used entries beyond
//! [`HOST_CACHE_MAX_ENTRIES`]. The hot path pays one relaxed atomic load
//! plus one relaxed store on a hit.

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

/// Entries idle longer than this are dropped on the next sweep. Long enough
/// that a legitimate site briefly idle for minutes is never rebuilt, short
/// enough that scanner garbage is gone minutes after its last request.
pub const HOST_CACHE_TTL_SECS: u64 = 600;

/// Soft cap on cached hosts per map: the sweep evicts the least-recently-used
/// entries beyond it, so the bound converges within one sweep interval rather
/// than being enforced at insert time. Generous for real deployments
/// (control-plane site counts are far smaller) while bounding worst-case
/// memory per host entry.
pub const HOST_CACHE_MAX_ENTRIES: usize = 1024;

/// Minimum wall-clock seconds between two sweeps of one map. The CAS gate
/// makes concurrent sweeps impossible; the interval keeps the O(N) walk rare
/// even when every request lands on an uncached host.
pub const HOST_CACHE_SWEEP_INTERVAL_SECS: u64 = 60;

/// Unix seconds — shared by all host-cache call sites so timestamps written
/// by one plugin are comparable with those of another.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Sweep gate for one plugin instance's per-host cache.
#[derive(Default)]
pub struct HostCacheSweep(AtomicU64);

impl HostCacheSweep {
    /// Prune `map`: drop entries whose `last_used` (unix seconds, read via
    /// `last_used`) is older than the TTL, then evict oldest-first beyond
    /// the hard cap. At most one caller per sweep interval performs the
    /// walk; every other caller returns after a single atomic load.
    pub fn prune<V>(
        &self,
        map: &DashMap<String, V>,
        now: u64,
        last_used: impl Fn(&V) -> u64,
    ) {
        let last = self.0.load(Ordering::Relaxed);
        if now.saturating_sub(last) < HOST_CACHE_SWEEP_INTERVAL_SECS {
            return;
        }
        if self
            .0
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            // A concurrent caller won the sweep; its walk covers us too.
            return;
        }
        let cutoff = now.saturating_sub(HOST_CACHE_TTL_SECS);
        map.retain(|_, value| last_used(value) > cutoff);
        let excess = map.len().saturating_sub(HOST_CACHE_MAX_ENTRIES);
        if excess > 0 {
            let mut by_age: Vec<(String, u64)> = map
                .iter()
                .map(|entry| (entry.key().clone(), last_used(entry.value())))
                .collect();
            by_age.sort_unstable_by_key(|(_, used)| *used);
            for (host, _) in by_age.into_iter().take(excess) {
                map.remove(&host);
            }
        }
    }
}

/// Refresh a cache hit's `last_used` timestamp. Relaxed ordering: the value
/// only feeds TTL eviction, so a stale read costs nothing that matters.
pub fn touch(last_used: &AtomicU64, now: u64) {
    last_used.store(now, Ordering::Relaxed);
}

#[cfg(test)]
impl HostCacheSweep {
    /// Test hook: re-arm the gate so the next [`HostCacheSweep::prune`]
    /// runs its walk immediately.
    pub(crate) fn reset(&self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Entry(AtomicU64);

    #[test]
    fn prune_drops_idle_entries_and_enforces_the_cap() {
        let sweep = HostCacheSweep::default();
        let map: DashMap<String, Entry> = DashMap::new();
        let now = unix_now();
        for i in 0..4 {
            map.insert(
                format!("host-{i}"),
                Entry(AtomicU64::new(now.saturating_sub(i * 100))),
            );
        }

        // All four are within the TTL: nothing dropped, gate armed at `now`.
        sweep.prune(&map, now, |e| e.0.load(Ordering::Relaxed));
        assert_eq!(map.len(), 4);

        // Within the sweep interval the walk is skipped entirely.
        map.insert("stale".to_string(), Entry(AtomicU64::new(0)));
        sweep.prune(&map, now + 1, |e| e.0.load(Ordering::Relaxed));
        assert_eq!(map.len(), 5);

        // After the interval the idle entry is dropped.
        sweep.prune(&map, now + HOST_CACHE_SWEEP_INTERVAL_SECS, |e| {
            e.0.load(Ordering::Relaxed)
        });
        assert_eq!(map.len(), 4);
        assert!(!map.contains_key("stale"));

        // Past the cap the least-recently-used entries go first.
        for i in 0..HOST_CACHE_MAX_ENTRIES {
            map.insert(format!("cap-{i}"), Entry(AtomicU64::new(now)));
        }
        sweep.prune(&map, now + 2 * HOST_CACHE_SWEEP_INTERVAL_SECS, |e| {
            e.0.load(Ordering::Relaxed)
        });
        assert!(map.len() <= HOST_CACHE_MAX_ENTRIES);
        assert!(!map.contains_key("host-3"));
        assert!(map.contains_key("cap-0"));
    }

    #[test]
    fn touch_refreshes_the_idle_clock() {
        let stamp = AtomicU64::new(7);
        touch(&stamp, 42);
        assert_eq!(stamp.load(Ordering::Relaxed), 42);
    }
}
