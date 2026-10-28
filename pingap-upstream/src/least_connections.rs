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

//! Least-connections selection for pingora's load balancer.
//!
//! pingora ships round robin, consistent hash and random, but not least
//! connections. This module implements the `BackendSelection` trait against a
//! counter map that lives *outside* the selection: pingora rebuilds the whole
//! selector whenever the backend set changes, so only a map shared through
//! `Config` survives those rebuilds. The proxy increments the counter when a
//! request picks a backend (`acquire`) and decrements it once the request
//! finishes (`release`) — the same lifecycle pingap's per-upstream
//! `processing` gauge follows.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use pingora::lb::Backend;
use pingora::lb::selection::{BackendIter, BackendSelection};

/// In-flight request counters per backend address.
///
/// Shared between the load balancer's selectors (which read the counts to
/// pick a backend) and pingap's upstream (which updates them around each
/// request). Counters start at zero; a `release` for an address that never
/// acquired is a no-op.
#[derive(Default)]
pub struct InflightCounters {
    counts: Mutex<HashMap<String, i64>>,
}

impl InflightCounters {
    /// Marks one in-flight request for the backend.
    pub fn acquire(&self, addr: &str) {
        // Recover from a poisoned lock instead of panicking on every later
        // request; the counter is advisory and a torn update is harmless.
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry(addr.to_string()).or_insert(0) += 1;
    }

    /// Marks one finished request for the backend.
    pub fn release(&self, addr: &str) {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = counts.get_mut(addr) {
            *count -= 1;
        }
    }

    /// Reads one counter; only the tests need the per-key form now that
    /// selection goes through [`snapshot`].
    #[cfg(test)]
    fn load(&self, addr: &str) -> i64 {
        self.counts
            .lock()
            .expect("inflight counters poisoned")
            .get(addr)
            .copied()
            .unwrap_or(0)
    }

    /// One-lock snapshot of every counter. Selecting a backend used to take
    /// the same global lock once per candidate (and allocate a String per
    /// lock); cloning the (small) map once per selection replaces N lock
    /// acquisitions with one and removes the per-candidate allocation
    /// (2026-10-18 audit).
    fn snapshot(&self) -> HashMap<String, i64> {
        self.counts
            .lock()
            .expect("inflight counters poisoned")
            .clone()
    }
}

/// Selects the backend with the fewest in-flight requests.
pub struct LeastConnections {
    /// Address strings of `backends`, computed once so a selection does not
    /// allocate one String per candidate.
    addrs: Box<[String]>,
    backends: Box<[Backend]>,
    inflight: Arc<InflightCounters>,
    /// Breaks ties between equally loaded backends so repeated selections
    /// rotate instead of always picking the first one.
    offset: AtomicUsize,
}

impl BackendSelection for LeastConnections {
    type Iter = LeastConnectionsIterator;
    type Config = Arc<InflightCounters>;

    fn build(backends: &BTreeSet<Backend>) -> Self {
        Self::build_with_config(
            backends,
            &Arc::new(InflightCounters::default()),
        )
    }

    fn build_with_config(
        backends: &BTreeSet<Backend>,
        inflight: &Self::Config,
    ) -> Self {
        Self {
            addrs: backends
                .iter()
                .map(|backend| backend.addr.to_string())
                .collect(),
            backends: Vec::from_iter(backends.iter().cloned())
                .into_boxed_slice(),
            inflight: Arc::clone(inflight),
            offset: AtomicUsize::new(0),
        }
    }

    fn iter(self: &Arc<Self>, _key: &[u8]) -> Self::Iter
    where
        Self::Iter: BackendIter,
    {
        let len = self.backends.len();
        let offset = if len == 0 {
            0
        } else {
            self.offset.fetch_add(1, Ordering::Relaxed) % len
        };
        // Sort once per selection: ascending in-flight count, ties walking
        // the backends starting from the rotating offset. One snapshot (one
        // lock) and no per-candidate String allocation.
        let counts = self.inflight.snapshot();
        let mut order: Vec<usize> = (0..len).collect();
        order.sort_by_key(|&i| {
            (
                counts.get(&self.addrs[i]).copied().unwrap_or(0),
                (i + len - offset) % len,
            )
        });
        LeastConnectionsIterator {
            selection: Arc::clone(self),
            order,
            pos: 0,
        }
    }
}

/// Walks the backends of a [`LeastConnections`] selection, least loaded
/// first.
pub struct LeastConnectionsIterator {
    selection: Arc<LeastConnections>,
    order: Vec<usize>,
    pos: usize,
}

impl BackendIter for LeastConnectionsIterator {
    fn next(&mut self) -> Option<&Backend> {
        let index = *self.order.get(self.pos)?;
        self.pos += 1;
        Some(&self.selection.backends[index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(addr: &str) -> Backend {
        Backend::new(addr).unwrap()
    }

    #[test]
    fn iterators_yield_backends_least_loaded_first() {
        let inflight = Arc::new(InflightCounters::default());
        let mut backends = BTreeSet::new();
        backends.insert(backend("10.0.0.1:80"));
        backends.insert(backend("10.0.0.2:80"));
        backends.insert(backend("10.0.0.3:80"));
        let selection =
            Arc::new(LeastConnections::build_with_config(&backends, &inflight));

        // All counters equal: backends come out in address order.
        let mut iter = selection.iter(b"");
        assert_eq!(iter.next().unwrap().addr.to_string(), "10.0.0.1:80");
        assert_eq!(iter.next().unwrap().addr.to_string(), "10.0.0.2:80");
        assert_eq!(iter.next().unwrap().addr.to_string(), "10.0.0.3:80");
        assert!(iter.next().is_none());

        // Loading the first backend pushes the others to the front.
        inflight.acquire("10.0.0.1:80");
        inflight.acquire("10.0.0.1:80");
        let mut iter = selection.iter(b"");
        assert_eq!(iter.next().unwrap().addr.to_string(), "10.0.0.2:80");
        // Releasing puts all counters level again; the rotating tie-break
        // moves the head forward instead of always starting at the same
        // backend, so only the full set is deterministic here.
        inflight.release("10.0.0.1:80");
        inflight.release("10.0.0.1:80");
        let mut iter = selection.iter(b"");
        let mut served: Vec<String> = Vec::new();
        while let Some(backend) = iter.next() {
            served.push(backend.addr.to_string());
        }
        served.sort();
        assert_eq!(
            served,
            vec![
                "10.0.0.1:80".to_string(),
                "10.0.0.2:80".to_string(),
                "10.0.0.3:80".to_string()
            ]
        );
    }

    #[test]
    fn acquire_and_release_track_counts() {
        let counters = InflightCounters::default();
        counters.acquire("10.0.0.1:80");
        counters.acquire("10.0.0.1:80");
        assert_eq!(counters.load("10.0.0.1:80"), 2);
        counters.release("10.0.0.1:80");
        assert_eq!(counters.load("10.0.0.1:80"), 1);
        // Releasing an unknown backend is a no-op.
        counters.release("10.0.0.9:80");
        assert_eq!(counters.load("10.0.0.9:80"), 0);
    }
}
