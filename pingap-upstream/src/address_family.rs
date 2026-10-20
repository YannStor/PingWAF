// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Address-family selection for upstream nodes.
//!
//! The [`AddressFamily`] type itself is owned by `pingap-discovery` — the
//! filtering belongs where the addresses are resolved, not where the
//! backends are built — and re-exported here so the rest of this crate and
//! its dependents keep a single spelling.
//!
//! A static upstream resolves a domain **once**, in `pingap-discovery`, and
//! the family filter is applied there (see its `new_static_discovery`).
//! What remains in this module is what a **transparent** upstream needs:
//! [`select_family`] narrows a resolved address set to one family, and
//! [`resolve_preferred`] does the same on the request path behind a bounded
//! cache so a transparent upstream does not pay a lookup per request.

pub use pingap_discovery::AddressFamily;

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::debug;

/// Narrows a resolved address set to `family`, dropping duplicates and
/// keeping the resolver's order.
///
/// [`AddressFamily::Auto`] answers with the IPv4 addresses whenever there is
/// at least one, and falls back to the IPv6 addresses only for an
/// IPv6-only host. That asymmetry is the whole point: an AAAA backend on a
/// host without an IPv6 route is a backend that can never be healthy, so
/// preferring it - or keeping it alongside the working A records - only
/// adds failure modes. The fallback keeps an IPv6-only origin reachable.
#[must_use]
pub fn select_family(
    addrs: impl IntoIterator<Item = IpAddr>,
    family: AddressFamily,
) -> Vec<IpAddr> {
    let mut ipv4: Vec<IpAddr> = Vec::new();
    let mut ipv6: Vec<IpAddr> = Vec::new();
    for ip in addrs {
        let bucket = if ip.is_ipv4() { &mut ipv4 } else { &mut ipv6 };
        if !bucket.contains(&ip) {
            bucket.push(ip);
        }
    }
    match family {
        AddressFamily::Ipv4 => ipv4,
        AddressFamily::Ipv6 => ipv6,
        AddressFamily::Auto if ipv4.is_empty() => ipv6,
        AddressFamily::Auto => ipv4,
    }
}

/// `(host, port, family)` → resolved address and expiry. The family is part
/// of the key because the same name answers differently per family.
type ResolveKey = (String, u16, AddressFamily);

/// How long a resolved address stays cached. The window keeps a DNS change
/// visible within half a minute, the same budget the transparent-host cache
/// this replaces used.
pub const RESOLVE_TTL: Duration = Duration::from_secs(30);

/// Hard ceiling on the cache, so random `Host` values cannot grow it forever.
pub const RESOLVE_CACHE_MAX: usize = 4096;

static RESOLVE_CACHE: LazyLock<DashMap<ResolveKey, (IpAddr, Instant)>> =
    LazyLock::new(DashMap::new);

/// Reads a cached address. An expired entry is dropped on the way out: the
/// cache has no sweeper thread, so eviction is paid by whoever trips over
/// the entry rather than by a timer.
fn cache_get(key: &ResolveKey, now: Instant) -> Option<IpAddr> {
    // The guard must be released before `remove`, or the write on the same
    // shard deadlocks behind this read.
    let (ip, deadline) = {
        let entry = RESOLVE_CACHE.get(key)?;
        *entry
    };
    if deadline > now {
        return Some(ip);
    }
    RESOLVE_CACHE.remove(key);
    None
}

/// Writes a resolved address, keeping the map under [`RESOLVE_CACHE_MAX`].
fn cache_put(key: ResolveKey, ip: IpAddr, now: Instant) {
    if RESOLVE_CACHE.len() >= RESOLVE_CACHE_MAX {
        RESOLVE_CACHE.retain(|_, (_, deadline)| *deadline > now);
        if RESOLVE_CACHE.len() >= RESOLVE_CACHE_MAX {
            // Nothing had expired: the ceiling bounds memory, and reusing
            // the whole cache is cheaper than evicting key by key.
            debug!(
                target: crate::LOG_TARGET,
                size = RESOLVE_CACHE_MAX,
                "address family cache is full, dropping every entry"
            );
            RESOLVE_CACHE.clear();
        }
    }
    RESOLVE_CACHE.insert(key, (ip, now + RESOLVE_TTL));
}

/// Resolves `host` to one address of `family`, cached for [`RESOLVE_TTL`].
///
/// Failures are not cached, so a name that starts resolving after the fact is
/// picked up on the next request rather than after a full TTL. `None` means
/// the name does not resolve *or* has no address of the requested family.
pub async fn resolve_preferred(
    host: &str,
    port: u16,
    family: AddressFamily,
) -> Option<IpAddr> {
    let key = (host.to_string(), port, family);
    let now = Instant::now();
    if let Some(ip) = cache_get(&key, now) {
        return Some(ip);
    }
    let addrs = match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => addrs.map(|addr| addr.ip()).collect::<Vec<_>>(),
        Err(e) => {
            debug!(
                target: crate::LOG_TARGET,
                host,
                port,
                error = %e,
                "resolve host by address family fail"
            );
            return None;
        },
    };
    let ip = *select_family(addrs, family).first()?;
    cache_put(key, ip, now);
    Some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// The cache is process-wide, so the cache tests must not interleave
    /// with each other (the bound test empties it).
    static CACHE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test address must parse")
    }

    fn v4() -> IpAddr {
        ip("192.0.2.10")
    }

    fn v4_second() -> IpAddr {
        ip("192.0.2.11")
    }

    fn v6() -> IpAddr {
        ip("2001:db8::10")
    }

    #[test]
    fn address_family_parse_accepts_the_three_values() {
        assert_eq!(Some(AddressFamily::Auto), AddressFamily::parse("auto"));
        assert_eq!(Some(AddressFamily::Ipv4), AddressFamily::parse(" IPv4 "));
        assert_eq!(Some(AddressFamily::Ipv6), AddressFamily::parse("ipv6"));
        assert_eq!(None, AddressFamily::parse(""));
        assert_eq!(None, AddressFamily::parse("dual"));
        // Round trip: the API accepts exactly what this renders.
        for family in [
            AddressFamily::Auto,
            AddressFamily::Ipv4,
            AddressFamily::Ipv6,
        ] {
            assert_eq!(Some(family), AddressFamily::parse(family.as_str()));
        }
    }

    #[test]
    fn legacy_ipv4_only_maps_to_a_family_and_never_widens() {
        assert_eq!(
            AddressFamily::Ipv4,
            AddressFamily::from_ipv4_only(Some(true))
        );
        assert_eq!(
            AddressFamily::Auto,
            AddressFamily::from_ipv4_only(Some(false))
        );
        assert_eq!(AddressFamily::Auto, AddressFamily::from_ipv4_only(None));
    }

    #[test]
    fn select_family_auto_prefers_ipv4() {
        // The reported 503: a dual-stack answer on a host without an IPv6
        // route must not produce an AAAA backend.
        assert_eq!(
            vec![v4(), v4_second()],
            select_family([v6(), v4(), v4_second()], AddressFamily::Auto)
        );
    }

    #[test]
    fn select_family_auto_falls_back_to_ipv6() {
        // An IPv6-only origin stays reachable instead of losing its address.
        assert_eq!(vec![v6()], select_family([v6()], AddressFamily::Auto));
    }

    #[test]
    fn select_family_filters_each_pinned_family() {
        let addrs = [v6(), v4()];
        assert_eq!(vec![v4()], select_family(addrs, AddressFamily::Ipv4));
        assert_eq!(vec![v6()], select_family(addrs, AddressFamily::Ipv6));
        // No address of the requested family is an empty set, not a fallback:
        // `ipv6` on an IPv4-only host must fail loudly instead of silently
        // connecting over the family the operator excluded.
        assert!(select_family([v4()], AddressFamily::Ipv6).is_empty());
        assert!(select_family([v6()], AddressFamily::Ipv4).is_empty());
    }

    #[test]
    fn select_family_dedupes_preserving_order() {
        assert_eq!(
            vec![v4(), v4_second()],
            select_family([v4(), v4(), v4_second(), v4()], AddressFamily::Ipv4)
        );
    }

    #[test]
    fn address_family_accepts_matches_its_family() {
        assert!(AddressFamily::Auto.accepts(v4()));
        assert!(AddressFamily::Auto.accepts(v6()));
        assert!(AddressFamily::Ipv4.accepts(v4()));
        assert!(!AddressFamily::Ipv4.accepts(v6()));
        assert!(AddressFamily::Ipv6.accepts(v6()));
        assert!(!AddressFamily::Ipv6.accepts(v4()));
    }

    #[test]
    fn resolve_cache_expires_after_ttl() {
        let _guard = CACHE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = ("ttl.example".to_string(), 443, AddressFamily::Auto);
        let now = Instant::now();
        cache_put(key.clone(), v4(), now);

        assert_eq!(Some(v4()), cache_get(&key, now));
        // Still inside the window right before the deadline.
        assert_eq!(
            Some(v4()),
            cache_get(&key, now + RESOLVE_TTL - Duration::from_millis(1))
        );
        // Past it: `None` and the entry is gone, not merely ignored.
        assert_eq!(None, cache_get(&key, now + RESOLVE_TTL));
        assert!(!RESOLVE_CACHE.contains_key(&key));
    }

    #[test]
    fn resolve_cache_is_bounded() {
        let _guard = CACHE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        for i in 0..=RESOLVE_CACHE_MAX {
            let key =
                (format!("bounded-{i}.example"), 443, AddressFamily::Auto);
            cache_put(key, v4(), now);
        }
        assert!(
            RESOLVE_CACHE.len() <= RESOLVE_CACHE_MAX,
            "cache grew past its ceiling: {}",
            RESOLVE_CACHE.len()
        );
        RESOLVE_CACHE.clear();
    }

    #[test]
    fn resolve_cache_keeps_families_apart() {
        let _guard = CACHE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let name = "split.example".to_string();
        cache_put((name.clone(), 443, AddressFamily::Ipv4), v4(), now);
        cache_put((name.clone(), 443, AddressFamily::Ipv6), v6(), now);

        assert_eq!(
            Some(v4()),
            cache_get(&(name.clone(), 443, AddressFamily::Ipv4), now)
        );
        assert_eq!(
            Some(v6()),
            cache_get(&(name, 443, AddressFamily::Ipv6), now)
        );
        RESOLVE_CACHE.clear();
    }
}
