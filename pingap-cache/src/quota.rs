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

//! Per-domain disk quota accounting.
//!
//! [`FileCache`] already keeps a *global* on-disk budget (`max_size`) for the
//! whole backend directory. That is the wrong granularity for a multi-tenant
//! edge: one noisy domain can consume the entire budget and starve every other
//! site sharing the box. [`DiskQuotaManager`] is the per-domain ledger that
//! sits next to it - the namespace of a cache key (the site domain) is the
//! accounting unit, and each domain gets its own ceiling and its own LRU
//! eviction.
//!
//! Hot path rules, because this is called from every cache write and hit:
//! - counters are `AtomicU64` with relaxed ordering, so a read is a load;
//! - a domain with no configured quota is not even entered into the map, so
//!   untracked traffic costs one failed hash lookup and nothing else;
//! - eviction (the only part that touches the disk) happens off the request
//!   path, and only one task per domain runs it at a time.
//!
//! Usage is rebuilt from the cache directory on startup ([`DiskQuotaManager::load`]),
//! so a restart does not reset a domain to "empty" and allow a large overshoot
//! before the ledger catches up. Quota ceilings themselves are persisted next
//! to the cache in `.quota.json`.
//!
//! Ceilings can also arrive *before* the ledger does: the agent learns them
//! from the control plane the moment it connects, while the ledger is created
//! by the first file cache backend. [`set_quota`] parks those until the ledger
//! shows up, so the ordering of the two never decides whether a limit is
//! enforced at all.

use crate::LOG_TARGET;
use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

/// Bytes in one mebibyte; quotas are configured in MB.
pub const BYTES_PER_MB: u64 = 1024 * 1024;

/// File the quota ceilings are persisted to, inside the cache directory.
const QUOTA_FILE: &str = ".quota.json";

/// Hard cap on how many entries one eviction pass considers, so a domain with
/// a million cached objects costs a bounded amount of work per pass. The pass
/// repeats on the next write if it was not enough.
const EVICTION_SCAN_LIMIT: usize = 10_000;

/// Wall clock seconds, used for the LRU timestamps. `0` for the (impossible)
/// pre-epoch case rather than panicking or wrapping.
#[inline]
fn now_secs() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

/// Snapshot of one domain's quota, shaped for the control plane API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuotaInfo {
    /// Domain (cache namespace) the quota applies to.
    pub domain: String,
    /// Ceiling in MB; `0` means unlimited.
    pub max_mb: u64,
    /// Current usage in MB.
    pub current_mb: f64,
    /// Number of tracked cache entries.
    pub item_count: u64,
    /// `current / max * 100`, or `0` when the quota is unlimited.
    pub usage_percent: f64,
}

/// Counters for one domain, shaped for status reporting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainQuotaStatus {
    pub domain: String,
    /// Ceiling in bytes; `0` means unlimited.
    pub max_bytes: u64,
    pub current_bytes: u64,
    pub item_count: u64,
    /// Entries removed by quota eviction since start.
    pub evictions_total: u64,
}

/// Outcome of one [`DiskQuotaManager::evict_to_fit`] pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvictionResult {
    pub evicted_count: usize,
    pub freed_bytes: u64,
}

/// Outcome of a purge request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeResult {
    pub purged_count: usize,
    pub freed_bytes: u64,
}

/// One tracked cache object.
///
/// `last_accessed` is atomic so a cache hit only needs a shared reference:
/// updating the LRU clock must not take a write lock on the entry map on the
/// hottest path there is.
pub struct CacheEntry {
    /// Size on disk in bytes.
    pub size_bytes: u64,
    /// When the entry was first recorded.
    pub created_at: DateTime<Utc>,
    /// Unix seconds of the last read or write.
    pub last_accessed: AtomicU64,
    /// Path relative to the cache root. `None` means the default layout
    /// `<domain>/<key>`; it is only set when a directory scan found the file
    /// somewhere else (a `levels=` sharded backend).
    rel_path: Option<PathBuf>,
}

impl CacheEntry {
    fn new(
        size_bytes: u64,
        created_at: DateTime<Utc>,
        rel_path: Option<PathBuf>,
    ) -> Self {
        Self {
            size_bytes,
            created_at,
            last_accessed: AtomicU64::new(now_secs()),
            rel_path,
        }
    }

    #[inline]
    fn accessed(&self) -> u64 {
        self.last_accessed.load(Ordering::Relaxed)
    }

    #[inline]
    fn touch(&self) {
        self.last_accessed.store(now_secs(), Ordering::Relaxed);
    }
}

impl std::fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheEntry")
            .field("size_bytes", &self.size_bytes)
            .field("created_at", &self.created_at)
            .field("last_accessed", &self.accessed())
            .finish()
    }
}

/// Ledger for a single domain.
pub struct DomainUsage {
    /// Current disk usage in bytes.
    pub current_bytes: AtomicU64,
    /// Maximum allowed bytes; `0` means unlimited.
    pub max_bytes: AtomicU64,
    /// Number of cached items.
    pub item_count: AtomicU64,
    /// Entries evicted to stay under quota.
    pub evictions_total: AtomicU64,
    /// LRU tracking: cache key -> entry.
    pub entries: DashMap<String, CacheEntry>,
    /// Set while an eviction pass owns this domain, so a burst of over-quota
    /// writes costs one pass instead of one per write.
    evicting: AtomicBool,
}

impl DomainUsage {
    fn new(max_bytes: u64) -> Self {
        Self {
            current_bytes: AtomicU64::new(0),
            max_bytes: AtomicU64::new(max_bytes),
            item_count: AtomicU64::new(0),
            evictions_total: AtomicU64::new(0),
            entries: DashMap::new(),
            evicting: AtomicBool::new(false),
        }
    }

    #[inline]
    fn max(&self) -> u64 {
        self.max_bytes.load(Ordering::Relaxed)
    }

    #[inline]
    fn current(&self) -> u64 {
        self.current_bytes.load(Ordering::Relaxed)
    }

    /// Whether the domain is over its ceiling. An unlimited domain never is.
    #[inline]
    pub fn is_over_quota(&self) -> bool {
        let max = self.max();
        max > 0 && self.current() > max
    }

    fn add_bytes(&self, delta: u64) {
        let _ = self.current_bytes.try_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |cur| Some(cur.saturating_add(delta)),
        );
    }

    fn sub_bytes(&self, delta: u64) {
        // Saturating: the ledger is an estimate (files can vanish behind our
        // back) and must never wrap into a value that makes every write look
        // over quota.
        let _ = self.current_bytes.try_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |cur| Some(cur.saturating_sub(delta)),
        );
    }

    fn status(&self, domain: &str) -> DomainQuotaStatus {
        DomainQuotaStatus {
            domain: domain.to_string(),
            max_bytes: self.max(),
            current_bytes: self.current(),
            item_count: self.item_count.load(Ordering::Relaxed),
            evictions_total: self.evictions_total.load(Ordering::Relaxed),
        }
    }

    fn quota(&self, domain: &str) -> QuotaInfo {
        let max = self.max();
        let current = self.current();
        QuotaInfo {
            domain: domain.to_string(),
            max_mb: max / BYTES_PER_MB,
            current_mb: current as f64 / BYTES_PER_MB as f64,
            item_count: self.item_count.load(Ordering::Relaxed),
            usage_percent: if max == 0 {
                0.0
            } else {
                (current as f64 / max as f64) * 100.0
            },
        }
    }
}

/// Tracks disk usage per domain and enforces quotas.
///
/// Cheap to clone is not needed: one instance is shared behind an `Arc` (or
/// through [`global_disk_quota`]).
pub struct DiskQuotaManager {
    /// Per-domain usage tracking.
    ///
    /// `Arc` rather than a plain value because the eviction and purge methods
    /// are `async`: holding a `DashMap` guard across an `.await` would both
    /// risk deadlock and make the future non-`Send`. Cloning the `Arc` under
    /// the (short) read guard and dropping the guard before any await keeps
    /// the futures `Send` and the map unlocked during disk work.
    domain_usage: DashMap<String, Arc<DomainUsage>>,
    /// Base cache directory.
    cache_dir: PathBuf,
}

/// Persisted form of the quota ceilings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct QuotaFile {
    /// domain -> ceiling in MB.
    domains: HashMap<String, u64>,
}

impl DiskQuotaManager {
    /// Creates a manager rooted at `cache_dir`. Nothing is read from disk yet;
    /// call [`DiskQuotaManager::load`] to rebuild the ledger.
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            domain_usage: DashMap::new(),
            cache_dir,
        }
    }

    /// Base directory the cache files live under.
    #[inline]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// File a domain's quota ceiling is persisted to.
    #[inline]
    fn quota_file(&self) -> PathBuf {
        self.cache_dir.join(QUOTA_FILE)
    }

    /// Absolute path of one entry. Entries discovered by a scan keep the path
    /// they were found at; anything recorded at runtime uses the default
    /// `<cache_dir>/<domain>/<key>` layout of `FileCache`.
    fn entry_path(
        &self,
        domain: &str,
        key: &str,
        entry: Option<&CacheEntry>,
    ) -> PathBuf {
        match entry.and_then(|e| e.rel_path.clone()) {
            Some(rel) => self.cache_dir.join(rel),
            None => self.key_path(domain, key),
        }
    }

    /// Path for a key with no recorded entry yet.
    fn key_path(&self, domain: &str, key: &str) -> PathBuf {
        self.cache_dir.join(domain).join(key)
    }

    /// The ledger for `domain`, if this manager tracks it at all.
    ///
    /// The `Arc` is cloned and the map guard dropped before returning, so the
    /// caller may `.await` freely.
    fn domain(&self, domain: &str) -> Option<Arc<DomainUsage>> {
        self.domain_usage.get(domain).map(|v| Arc::clone(v.value()))
    }

    /// The ledger for `domain`, creating it (with no ceiling) when missing.
    fn ensure_domain(&self, domain: &str) -> Arc<DomainUsage> {
        Arc::clone(
            self.domain_usage
                .entry(domain.to_string())
                .or_insert_with(|| Arc::new(DomainUsage::new(0)))
                .value(),
        )
    }

    /// Set quota for a domain (in MB). `0` removes the ceiling.
    ///
    /// The new ceiling is persisted, so it survives a restart even before any
    /// traffic re-establishes it.
    pub fn set_quota(&self, domain: &str, max_mb: u64) {
        let usage = self.ensure_domain(domain);
        let max_bytes = max_mb.saturating_mul(BYTES_PER_MB);
        let previous = usage.max_bytes.swap(max_bytes, Ordering::Relaxed);
        if previous != max_bytes {
            info!(
                target: LOG_TARGET,
                domain,
                max_mb,
                current_bytes = usage.current(),
                item_count = usage.item_count.load(Ordering::Relaxed),
                "set domain cache disk quota"
            );
            self.persist_quotas();
        }
    }

    /// Sets several ceilings at once (the agent applies a whole rule bundle).
    pub fn set_quotas<I, K>(&self, quotas: I)
    where
        I: IntoIterator<Item = (K, u64)>,
        K: AsRef<str>,
    {
        for (domain, max_mb) in quotas {
            self.set_quota(domain.as_ref(), max_mb);
        }
    }

    /// Get current quota for a domain.
    pub fn get_quota(&self, domain: &str) -> Option<QuotaInfo> {
        self.domain(domain).map(|u| u.quota(domain))
    }

    /// Every domain this manager tracks, sorted for stable API output.
    ///
    /// This includes the domains a startup scan found on disk without anybody
    /// configuring a limit for them; see [`Self::quota_domains`] for the
    /// narrower set.
    pub fn domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self
            .domain_usage
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        domains.sort();
        domains
    }

    /// Record a new cache entry, returns true if eviction is needed.
    ///
    /// Untracked domains (no quota ever configured) cost one hash lookup and
    /// return `false`, so enabling quotas for one site does not add work for
    /// the others.
    pub fn record_write(
        &self,
        domain: &str,
        key: &str,
        size_bytes: u64,
    ) -> bool {
        let Some(usage) = self.domain(domain) else {
            return false;
        };
        // Replacing an existing object must not double count it.
        let replaced = usage.entries.insert(
            key.to_string(),
            CacheEntry::new(size_bytes, Utc::now(), None),
        );
        match replaced {
            Some(old) => {
                usage.sub_bytes(old.size_bytes);
                usage.add_bytes(size_bytes);
            },
            None => {
                usage.add_bytes(size_bytes);
                usage.item_count.fetch_add(1, Ordering::Relaxed);
            },
        }
        usage.is_over_quota()
    }

    /// Record cache access (for LRU). A shared reference is enough because the
    /// timestamp is atomic.
    pub fn record_access(&self, domain: &str, key: &str) {
        let Some(usage) = self.domain(domain) else {
            return;
        };
        if let Some(entry) = usage.entries.get(key) {
            entry.touch();
        }
    }

    /// Record cache removal.
    ///
    /// `size_bytes` is the caller's idea of what went away; the recorded entry
    /// wins when there is one, because it is the size that was counted.
    pub fn record_remove(&self, domain: &str, key: &str, size_bytes: u64) {
        let Some(usage) = self.domain(domain) else {
            return;
        };
        let removed = usage.entries.remove(key);
        let freed = removed
            .as_ref()
            .map(|(_, e)| e.size_bytes)
            .unwrap_or(size_bytes);
        usage.sub_bytes(freed);
        if removed.is_some() {
            usage.item_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get entries to evict (LRU order) to bring usage under quota.
    ///
    /// The ordering is approximate by design: entries written before the last
    /// restart all carry their file timestamp, and a hit only bumps a relaxed
    /// counter. Exactness would need a real LRU structure under a lock on
    /// every read, which is not a trade worth making for a disk budget.
    pub fn get_eviction_candidates(&self, domain: &str) -> Vec<String> {
        let Some(usage) = self.domain(domain) else {
            return Vec::new();
        };
        let max = usage.max();
        if max == 0 {
            return Vec::new();
        }
        let current = usage.current();
        if current <= max {
            return Vec::new();
        }
        let mut must_free = current - max;

        let mut entries: Vec<(String, u64, u64)> = usage
            .entries
            .iter()
            .take(EVICTION_SCAN_LIMIT)
            .map(|e| (e.key().clone(), e.accessed(), e.size_bytes))
            .collect();
        // Oldest first. Ties keep the map's iteration order, which is fine for
        // an approximate LRU.
        entries.sort_by_key(|(_, accessed, _)| *accessed);

        let mut candidates = Vec::new();
        for (key, _, size) in entries {
            if must_free == 0 {
                break;
            }
            must_free = must_free.saturating_sub(size);
            candidates.push(key);
        }
        candidates
    }

    /// Perform eviction until under quota.
    ///
    /// Only one pass runs per domain at a time; a caller that loses the race
    /// returns an empty result instead of queueing up behind it, because the
    /// winner is about to bring the domain back under the ceiling anyway.
    pub async fn evict_to_fit(&self, domain: &str) -> EvictionResult {
        let Some(usage) = self.domain(domain) else {
            return EvictionResult::default();
        };
        if !usage.is_over_quota() {
            return EvictionResult::default();
        }
        if usage
            .evicting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return EvictionResult::default();
        }

        let result = self.evict_pass(domain, &usage).await;
        usage.evicting.store(false, Ordering::Release);

        if result.evicted_count > 0 {
            usage
                .evictions_total
                .fetch_add(result.evicted_count as u64, Ordering::Relaxed);
            info!(
                target: LOG_TARGET,
                domain,
                evicted = result.evicted_count,
                freed_bytes = result.freed_bytes,
                current_bytes = usage.current(),
                max_bytes = usage.max(),
                "evicted cache entries for domain disk quota"
            );
        }
        result
    }

    /// One LRU pass. Split out so the `evicting` flag is always released.
    async fn evict_pass(
        &self,
        domain: &str,
        usage: &DomainUsage,
    ) -> EvictionResult {
        let mut result = EvictionResult::default();
        for key in self.get_eviction_candidates(domain) {
            if !usage.is_over_quota() {
                break;
            }
            // Snapshot the path and size while holding the entry guard, then
            // drop it: the await below must not hold a lock on the map.
            let (path, size) = match usage.entries.get(&key) {
                Some(entry) => (
                    self.entry_path(domain, &key, Some(&*entry)),
                    entry.size_bytes,
                ),
                None => (self.key_path(domain, &key), 0),
            };
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {
                    self.record_remove(domain, &key, size);
                    result.evicted_count += 1;
                    result.freed_bytes += size;
                },
                // Already gone: the ledger is simply stale, drop the entry.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    self.record_remove(domain, &key, size);
                },
                Err(e) => {
                    warn!(
                        target: LOG_TARGET,
                        domain,
                        key,
                        file = %path.display(),
                        error = %e,
                        "evict cache entry for domain quota fail"
                    );
                },
            }
        }
        result
    }

    /// Get usage stats for all domains.
    pub fn get_all_usage(&self) -> Vec<DomainQuotaStatus> {
        let mut stats: Vec<DomainQuotaStatus> = self
            .domain_usage
            .iter()
            .map(|entry| entry.value().status(entry.key()))
            .collect();
        stats.sort_by(|a, b| a.domain.cmp(&b.domain));
        stats
    }

    /// Get usage for a specific domain.
    pub fn get_usage(&self, domain: &str) -> Option<DomainQuotaStatus> {
        self.domain(domain).map(|u| u.status(domain))
    }

    /// Purge all cache for a domain.
    ///
    /// Deletes the domain's whole directory, so it also catches entries the
    /// ledger does not know about (written by another process sharing the
    /// cache root, or before the last restart).
    pub async fn purge_domain(&self, domain: &str) -> PurgeResult {
        if !is_safe_component(domain) {
            warn!(target: LOG_TARGET, domain, "refusing to purge invalid domain");
            return PurgeResult::default();
        }
        let dir = self.cache_dir.join(domain);
        // Measured before deletion so the freed total is real even for files
        // the ledger never saw.
        let files = list_files(dir.clone()).await;
        let mut result = PurgeResult::default();
        for (path, len) in &files {
            match tokio::fs::remove_file(path).await {
                Ok(()) => {
                    result.purged_count += 1;
                    result.freed_bytes += len;
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => {
                    warn!(
                        target: LOG_TARGET,
                        domain,
                        file = %path.display(),
                        error = %e,
                        "purge cache file fail"
                    );
                },
            }
        }
        // Best effort: drop the now empty level directories and the domain
        // directory itself. A concurrent write recreates what it needs.
        let cleanup = dir.clone();
        let _ =
            tokio::task::spawn_blocking(move || remove_empty_dirs(&cleanup))
                .await;

        if let Some(usage) = self.domain(domain) {
            usage.entries.clear();
            usage.current_bytes.store(0, Ordering::Relaxed);
            usage.item_count.store(0, Ordering::Relaxed);
        }
        info!(
            target: LOG_TARGET,
            domain,
            purged = result.purged_count,
            freed_bytes = result.freed_bytes,
            "purged domain cache"
        );
        result
    }

    /// Purge specific URLs.
    ///
    /// The caller supplies cache keys (the storage layer hashes URLs into
    /// them), so this is an exact-key purge: only keys present in the ledger
    /// can be removed.
    pub async fn purge_urls(
        &self,
        domain: &str,
        urls: &[String],
    ) -> PurgeResult {
        if !is_safe_component(domain) {
            warn!(target: LOG_TARGET, domain, "refusing to purge invalid domain");
            return PurgeResult::default();
        }
        let mut result = PurgeResult::default();
        for key in urls {
            let Some(usage) = self.domain(domain) else {
                break;
            };
            let (path, size) = match usage.entries.get(key.as_str()) {
                Some(entry) => (
                    self.entry_path(domain, key, Some(&*entry)),
                    entry.size_bytes,
                ),
                // Not tracked: fall back to the default layout, the file may
                // still be there from before the last restart.
                None => (self.key_path(domain, key), 0),
            };
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {
                    self.record_remove(domain, key, size);
                    result.purged_count += 1;
                    result.freed_bytes += size;
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    self.record_remove(domain, key, size);
                },
                Err(e) => {
                    warn!(
                        target: LOG_TARGET,
                        domain,
                        key = %key,
                        file = %path.display(),
                        error = %e,
                        "purge cache entry fail"
                    );
                },
            }
        }
        info!(
            target: LOG_TARGET,
            domain,
            requested = urls.len(),
            purged = result.purged_count,
            freed_bytes = result.freed_bytes,
            "purged domain cache urls"
        );
        result
    }

    /// Rebuilds the ledger from disk: quota ceilings from `.quota.json`, entry
    /// sizes and access times from a walk of the cache directory.
    ///
    /// Called once at startup. Without it a restart would report every domain
    /// as empty and allow a full quota of overshoot before the first eviction.
    pub async fn load(&self) {
        self.load_quotas();

        let root = self.cache_dir.clone();
        let scanned =
            tokio::task::spawn_blocking(move || scan_cache_dir(&root))
                .await
                .unwrap_or_default();
        self.apply_scan(scanned);
        // Last, after `load_quotas`: that replays the ceilings persisted in
        // `.quota.json` and would otherwise overwrite whatever the control
        // plane asked for while no backend existed yet.
        PENDING_QUOTAS.flush_into(self);
    }

    /// Blocking variant of [`DiskQuotaManager::load`], for startup paths that
    /// are not on a runtime yet. The walk is the same; it just runs on the
    /// calling thread.
    pub fn load_sync(&self) {
        self.load_quotas();
        self.apply_scan(scan_cache_dir(&self.cache_dir));
        PENDING_QUOTAS.flush_into(self);
    }

    /// Folds a directory scan into the ledger.
    fn apply_scan(
        &self,
        scanned: HashMap<String, Vec<(String, u64, u64, PathBuf)>>,
    ) {
        let mut domains = 0usize;
        let mut entries = 0usize;
        let mut bytes = 0u64;
        for (domain, found) in scanned {
            let usage = self.ensure_domain(&domain);
            for (key, size, accessed, rel_path) in found {
                let created = Utc
                    .timestamp_opt(accessed as i64, 0)
                    .single()
                    .unwrap_or_else(Utc::now);
                let entry = CacheEntry::new(size, created, Some(rel_path));
                // A failed atime lookup (noatime mounts, UNIX_EPOCH) yields 0;
                // storing it made every restored entry look like the oldest
                // candidate and inverted the LRU order after a restart
                // (2026-10-18 audit). Keep the entry's creation time instead.
                if accessed > 0 {
                    entry.last_accessed.store(accessed, Ordering::Relaxed);
                }
                usage.entries.insert(key, entry);
                usage.add_bytes(size);
                usage.item_count.fetch_add(1, Ordering::Relaxed);
                entries += 1;
                bytes += size;
            }
            domains += 1;
        }
        info!(
            target: LOG_TARGET,
            cache_dir = %self.cache_dir.display(),
            domains,
            entries,
            bytes,
            "restored cache disk quota ledger from disk"
        );
    }

    /// Reads the persisted ceilings. Missing or corrupt is not an error: the
    /// worst case is that quotas are re-applied by the next config push.
    fn load_quotas(&self) {
        let path = self.quota_file();
        let Ok(raw) = std::fs::read(&path) else {
            return;
        };
        match serde_json::from_slice::<QuotaFile>(&raw) {
            Ok(file) => {
                let count = file.domains.len();
                for (domain, max_mb) in file.domains {
                    let usage = self.ensure_domain(&domain);
                    usage.max_bytes.store(
                        max_mb.saturating_mul(BYTES_PER_MB),
                        Ordering::Relaxed,
                    );
                }
                debug!(
                    target: LOG_TARGET,
                    domains = count,
                    "loaded cache disk quotas"
                );
            },
            Err(e) => {
                warn!(
                    target: LOG_TARGET,
                    file = %path.display(),
                    error = %e,
                    "cache disk quota file is corrupt, ignoring"
                );
            },
        }
    }

    /// Writes the ceilings back. Best effort and synchronous: the payload is a
    /// few hundred bytes and this only runs when a quota actually changes.
    fn persist_quotas(&self) {
        let domains: HashMap<String, u64> = self
            .domain_usage
            .iter()
            .map(|entry| {
                (entry.key().clone(), entry.value().max() / BYTES_PER_MB)
            })
            .collect();
        let file = QuotaFile { domains };
        let Ok(raw) = serde_json::to_vec_pretty(&file) else {
            return;
        };
        let path = self.quota_file();
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            warn!(
                target: LOG_TARGET,
                file = %path.display(),
                error = %e,
                "create cache dir for quota file fail"
            );
            return;
        }
        if let Err(e) = std::fs::write(&path, raw) {
            warn!(
                target: LOG_TARGET,
                file = %path.display(),
                error = %e,
                "persist cache disk quotas fail"
            );
        }
    }

    /// Empties the ledger for a domain without touching the disk.
    ///
    /// Used when something else already deleted the files (a namespace purge
    /// through the storage layer) and only the accounting has to catch up.
    pub fn reset_domain(&self, domain: &str) {
        let Some(usage) = self.domain(domain) else {
            return;
        };
        usage.entries.clear();
        usage.current_bytes.store(0, Ordering::Relaxed);
        usage.item_count.store(0, Ordering::Relaxed);
    }

    /// Drops the ledger for a domain entirely (the site was removed).
    pub fn forget_domain(&self, domain: &str) {
        if self.domain_usage.remove(domain).is_some() {
            debug!(target: LOG_TARGET, domain, "dropped cache disk quota ledger");
            self.persist_quotas();
        }
    }

    /// Every domain with a non-zero ceiling, sorted.
    ///
    /// Narrower than [`Self::domains`]: a domain whose bytes are merely
    /// accounted for, because a scan found its files, has no quota to lose and
    /// must not show up in a "which ceilings should I drop" sweep.
    pub fn quota_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self
            .domain_usage
            .iter()
            .filter(|entry| entry.value().max() > 0)
            .map(|entry| entry.key().clone())
            .collect();
        domains.sort();
        domains
    }
}

/// Whether `name` is safe to join onto the cache root. Rejects empty names and
/// anything that could escape the directory - the same rule
/// [`FileCache::purge_namespace`] applies.
fn is_safe_component(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
}

/// `(path, len)` for every regular file under `dir`, skipping the in-flight
/// temporaries that still belong to their writer.
async fn list_files(dir: PathBuf) -> Vec<(PathBuf, u64)> {
    tokio::task::spawn_blocking(move || {
        WalkDir::new(&dir)
            .into_iter()
            .filter_map(|item| item.ok())
            .filter(|item| item.file_type().is_file())
            .filter(|item| {
                item.path().extension().is_none_or(|ext| ext != "tmp")
            })
            .filter_map(|item| {
                let len = item.metadata().ok()?.len();
                Some((item.into_path(), len))
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

/// Removes every empty directory under `dir`, deepest first. Best effort.
fn remove_empty_dirs(dir: &Path) {
    let mut dirs: Vec<PathBuf> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|item| item.ok())
        .filter(|item| item.file_type().is_dir())
        .map(|item| item.into_path())
        .collect();
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir in dirs {
        let _ = std::fs::remove_dir(&dir);
    }
}

/// Walks the cache root and groups what it finds by domain (the first path
/// component under the root, which is the namespace the file backend uses).
///
/// Returns `domain -> (key, size, accessed_unix, relative_path)`.
fn scan_cache_dir(
    root: &Path,
) -> HashMap<String, Vec<(String, u64, u64, PathBuf)>> {
    let mut found: HashMap<String, Vec<(String, u64, u64, PathBuf)>> =
        HashMap::new();
    if !root.is_dir() {
        return found;
    }
    for item in WalkDir::new(root).into_iter().filter_map(|item| item.ok()) {
        if !item.file_type().is_file() {
            continue;
        }
        let path = item.path();
        if path.extension().is_some_and(|ext| ext == "tmp") {
            continue;
        }
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        // `<domain>/[levels.../]<key>`; a file directly in the root belongs to
        // no domain and is not accounted for.
        let mut components = rel.components();
        let Some(domain) = components.next() else {
            continue;
        };
        if components.next().is_none() {
            continue;
        }
        let domain = domain.as_os_str().to_string_lossy().into_owned();
        if !is_safe_component(&domain) {
            continue;
        }
        let Some(key) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Ok(metadata) = item.metadata() else {
            continue;
        };
        let accessed = metadata
            .accessed()
            .or_else(|_| metadata.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        found.entry(domain).or_default().push((
            key.to_string(),
            metadata.len(),
            accessed,
            rel.to_path_buf(),
        ));
    }
    found
}

// ─── Process-wide instance ─────────────────────────────────────────────────

static GLOBAL_QUOTA: OnceLock<DiskQuotaManager> = OnceLock::new();

/// Returns the process-wide quota manager, or `None` when the cache was never
/// configured with a disk quota. The hot path checks this first so a
/// deployment without quotas pays one `OnceLock` load.
pub fn global_disk_quota() -> Option<&'static DiskQuotaManager> {
    GLOBAL_QUOTA.get()
}

/// Ceilings asked for while there was still no ledger to put them in.
///
/// The agent learns a site's `disk_quota_mb` from the control plane as soon as
/// it connects; the ledger is created later, by the first file cache backend.
/// Parking the requests in between keeps that ordering from deciding whether a
/// limit is enforced at all.
///
/// A plain `Mutex` is enough: this is touched when a rule bundle arrives or a
/// cache plugin is (re)built, never on the request path.
#[derive(Default)]
struct PendingQuotas(Mutex<HashMap<String, u64>>);

impl PendingQuotas {
    /// The map. A poisoned lock is recovered rather than treated as "no
    /// quotas": every method below leaves the map consistent, so a panic
    /// elsewhere is no reason to start dropping limits.
    fn map(&self) -> MutexGuard<'_, HashMap<String, u64>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Remembers `max_mb` for `domain`. `0` means "no ceiling", which is the
    /// default, so it clears the entry instead of storing it.
    fn park(&self, domain: &str, max_mb: u64) {
        if domain.is_empty() {
            return;
        }
        let mut map = self.map();
        if max_mb == 0 {
            map.remove(domain);
        } else {
            map.insert(domain.to_string(), max_mb);
        }
    }

    /// Drops whatever was parked for `domain`.
    fn forget(&self, domain: &str) {
        self.map().remove(domain);
    }

    /// The parked ceiling for `domain`, if any.
    fn get(&self, domain: &str) -> Option<u64> {
        self.map().get(domain).copied()
    }

    /// Every parked domain, sorted.
    fn domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self.map().keys().cloned().collect();
        domains.sort();
        domains
    }

    /// Replays the parked ceilings into `manager` and empties the map.
    fn flush_into(&self, manager: &DiskQuotaManager) {
        let parked: Vec<(String, u64)> = {
            let mut map = self.map();
            if map.is_empty() {
                return;
            }
            let parked: Vec<(String, u64)> = map
                .iter()
                .map(|(domain, mb)| (domain.clone(), *mb))
                .collect();
            map.clear();
            parked
        };
        for (domain, max_mb) in &parked {
            manager.set_quota(domain, *max_mb);
        }
        info!(
            target: LOG_TARGET,
            domains = parked.len(),
            "applied cache disk quotas parked before the backend existed"
        );
    }
}

static PENDING_QUOTAS: LazyLock<PendingQuotas> =
    LazyLock::new(PendingQuotas::default);

/// Sets a domain's ceiling in MB - `0` meaning unlimited - whether or not a
/// ledger exists yet.
///
/// This is the entry point for everything outside this crate (the cache
/// plugin, the agent's rule bundles), because both can run before the first
/// file backend creates the ledger.
pub fn set_quota(domain: &str, max_mb: u64) {
    if domain.is_empty() {
        return;
    }
    // Parked *before* the ledger is looked up, not after. Draining the parked
    // map is the last step of a ledger load, so this order means a concurrent
    // initialisation either picks the ceiling up or loses the race to the call
    // below; the reverse order could strand it in the map until the next rule
    // bundle happened to re-assert it.
    PENDING_QUOTAS.park(domain, max_mb);
    match global_disk_quota() {
        Some(quota) => {
            PENDING_QUOTAS.forget(domain);
            quota.set_quota(domain, max_mb);
        },
        None => {
            debug!(
                target: LOG_TARGET,
                domain,
                max_mb,
                "parked cache disk quota until a file cache backend exists"
            );
        },
    }
}

/// Stops tracking `domain` entirely, whether its ceiling was applied or is
/// still parked. For a site whose cache rules were deleted, so it does not
/// keep a budget nobody asked for.
pub fn forget_quota(domain: &str) {
    PENDING_QUOTAS.forget(domain);
    if let Some(quota) = global_disk_quota() {
        quota.forget_domain(domain);
    }
}

/// Every domain with a configured ceiling, from the ledger and from the parked
/// requests alike, sorted and deduplicated for stable API output.
pub fn tracked_domains() -> Vec<String> {
    merged_domains(global_disk_quota(), &PENDING_QUOTAS)
}

/// The ceiling configured for `domain` in MB, or `None` if it never was.
///
/// Falls back to the parked requests, so a caller running before the first
/// file backend still sees what the control plane asked for.
pub fn configured_quota_mb(domain: &str) -> Option<u64> {
    configured_quota(global_disk_quota(), &PENDING_QUOTAS, domain)
}

/// Union of both sources. Split out so the merge can be tested without
/// touching the process-wide statics.
fn merged_domains(
    manager: Option<&DiskQuotaManager>,
    pending: &PendingQuotas,
) -> Vec<String> {
    let mut domains = manager.map(|m| m.quota_domains()).unwrap_or_default();
    domains.extend(pending.domains());
    domains.sort();
    domains.dedup();
    domains
}

/// See [`configured_quota_mb`].
fn configured_quota(
    manager: Option<&DiskQuotaManager>,
    pending: &PendingQuotas,
    domain: &str,
) -> Option<u64> {
    manager
        .and_then(|m| m.get_quota(domain))
        .map(|info| info.max_mb)
        .or_else(|| pending.get(domain))
}

/// Creates (once) the process-wide quota manager rooted at `cache_dir`.
///
/// Subsequent calls with a different directory return the existing instance:
/// the ledger is per cache root and a second root would need a second manager,
/// which no current deployment has.
///
/// The manager is empty until [`DiskQuotaManager::load`] runs - which is also
/// what replays the ceilings [`set_quota`] parked while no ledger existed, so
/// creating one without loading it leaves those unenforced.
pub fn init_global_disk_quota(
    cache_dir: impl Into<PathBuf>,
) -> &'static DiskQuotaManager {
    let dir = cache_dir.into();
    if let Some(existing) = GLOBAL_QUOTA.get() {
        if existing.cache_dir() != dir.as_path() {
            warn!(
                target: LOG_TARGET,
                configured = %dir.display(),
                active = %existing.cache_dir().display(),
                "cache disk quota manager already initialised with another directory"
            );
        }
        return existing;
    }
    let manager = DiskQuotaManager::new(dir.clone());
    match GLOBAL_QUOTA.set(manager) {
        Ok(()) => {},
        // Lost a race with another initialiser; theirs is just as good.
        Err(returned) => {
            let _ = returned;
        },
    }
    let manager = GLOBAL_QUOTA
        .get()
        .expect("quota manager was just initialised");
    info!(
        target: LOG_TARGET,
        cache_dir = %manager.cache_dir().display(),
        "init cache disk quota manager"
    );
    manager
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    /// Writes `<root>/<domain>/<key>` and returns its size.
    fn write_entry(root: &Path, domain: &str, key: &str, size: usize) {
        let dir = root.join(domain);
        std::fs::create_dir_all(&dir).expect("create domain dir");
        std::fs::write(dir.join(key), vec![b'x'; size]).expect("write entry");
    }

    /// Points one entry's LRU clock at `secs`, so ordering assertions do not
    /// depend on wall clock resolution.
    fn touch(manager: &DiskQuotaManager, domain: &str, key: &str, secs: u64) {
        manager
            .domain(domain)
            .expect("domain")
            .entries
            .get(key)
            .expect("entry")
            .last_accessed
            .store(secs, Ordering::Relaxed);
    }

    #[test]
    fn untracked_domains_cost_nothing() {
        let manager =
            DiskQuotaManager::new(PathBuf::from("/tmp/pingwaf-quota-test"));
        // No quota was ever set, so writes are not accounted for and never
        // ask for an eviction.
        assert_eq!(false, manager.record_write("example.com", "k", 1024));
        assert_eq!(None, manager.get_quota("example.com"));
        assert_eq!(None, manager.get_usage("example.com"));
        manager.record_access("example.com", "k");
        manager.record_remove("example.com", "k", 1024);
        assert_eq!(true, manager.get_all_usage().is_empty());
    }

    #[test]
    fn quota_is_reported_in_mb_and_percent() {
        let dir = TempDir::new().expect("tempdir");
        let manager = DiskQuotaManager::new(dir.path().to_path_buf());
        manager.set_quota("example.com", 1);

        let quota = manager.get_quota("example.com").expect("quota");
        assert_eq!(1, quota.max_mb);
        assert_eq!(0.0, quota.current_mb);
        assert_eq!(0.0, quota.usage_percent);

        // 512 KiB of a 1 MiB ceiling is exactly 50%.
        assert_eq!(
            false,
            manager.record_write("example.com", "a", BYTES_PER_MB / 2)
        );
        let quota = manager.get_quota("example.com").expect("quota");
        assert_eq!(0.5, quota.current_mb);
        assert_eq!(50.0, quota.usage_percent);
        assert_eq!(1, quota.item_count);

        // Overwriting the same key must not double count.
        assert_eq!(
            false,
            manager.record_write("example.com", "a", BYTES_PER_MB / 2)
        );
        assert_eq!(
            BYTES_PER_MB / 2,
            manager
                .get_usage("example.com")
                .expect("usage")
                .current_bytes
        );
        assert_eq!(
            1,
            manager.get_usage("example.com").expect("usage").item_count
        );
    }

    #[test]
    fn over_quota_write_requests_eviction() {
        let dir = TempDir::new().expect("tempdir");
        let manager = DiskQuotaManager::new(dir.path().to_path_buf());
        manager.set_quota("example.com", 1);

        assert_eq!(
            false,
            manager.record_write("example.com", "a", BYTES_PER_MB)
        );
        assert_eq!(true, manager.record_write("example.com", "b", 1));

        // Removal brings it back under.
        manager.record_remove("example.com", "b", 1);
        assert_eq!(false, manager.record_write("example.com", "c", 0));
    }

    #[test]
    fn eviction_candidates_are_lru_ordered() {
        let dir = TempDir::new().expect("tempdir");
        let manager = DiskQuotaManager::new(dir.path().to_path_buf());
        manager.set_quota("example.com", 1);

        for key in ["old", "mid", "new"] {
            manager.record_write("example.com", key, BYTES_PER_MB / 2);
        }
        // Grow "old" by one byte so the domain sits one byte past 1.5 MiB.
        manager.record_write("example.com", "old", BYTES_PER_MB / 2 + 1);

        // Force distinct LRU timestamps and make "old" the most recent.
        touch(&manager, "example.com", "old", 100);
        touch(&manager, "example.com", "mid", 50);
        touch(&manager, "example.com", "new", 10);

        // Against a 1 MiB ceiling, dropping "new" frees 0.5 MiB and leaves the
        // domain half a mebibyte and one byte over, so "mid" has to go too.
        // "old" is the freshest entry and must survive.
        let candidates = manager.get_eviction_candidates("example.com");
        assert_eq!(vec!["new".to_string(), "mid".to_string()], candidates);
    }

    #[tokio::test]
    async fn evict_to_fit_frees_disk_and_updates_counters() {
        let dir = TempDir::new().expect("tempdir");
        let manager = DiskQuotaManager::new(dir.path().to_path_buf());
        manager.set_quota("example.com", 1);
        write_entry(
            dir.path(),
            "example.com",
            "a",
            (BYTES_PER_MB / 2) as usize,
        );
        write_entry(
            dir.path(),
            "example.com",
            "b",
            (BYTES_PER_MB / 2) as usize,
        );
        manager.record_write("example.com", "a", BYTES_PER_MB / 2);
        manager.record_write("example.com", "b", BYTES_PER_MB / 2);
        // One byte over: exactly one entry has to go, and "a" is the oldest.
        manager.record_write("example.com", "c", 1);
        touch(&manager, "example.com", "a", 1);

        let result = manager.evict_to_fit("example.com").await;
        assert_eq!(1, result.evicted_count);
        assert_eq!(BYTES_PER_MB / 2, result.freed_bytes);
        assert_eq!(false, dir.path().join("example.com").join("a").exists());
        assert_eq!(true, dir.path().join("example.com").join("b").exists());

        let usage = manager.get_usage("example.com").expect("usage");
        assert_eq!(1, usage.evictions_total);
        assert_eq!(BYTES_PER_MB / 2 + 1, usage.current_bytes);
    }

    #[tokio::test]
    async fn purge_domain_removes_everything() {
        let dir = TempDir::new().expect("tempdir");
        let manager = DiskQuotaManager::new(dir.path().to_path_buf());
        manager.set_quota("example.com", 10);
        manager.set_quota("other.com", 10);
        write_entry(dir.path(), "example.com", "a", 100);
        write_entry(dir.path(), "example.com", "b", 200);
        write_entry(dir.path(), "other.com", "c", 400);
        manager.record_write("example.com", "a", 100);
        manager.record_write("example.com", "b", 200);
        manager.record_write("other.com", "c", 400);

        let result = manager.purge_domain("example.com").await;
        assert_eq!(2, result.purged_count);
        assert_eq!(300, result.freed_bytes);
        assert_eq!(false, dir.path().join("example.com").exists());
        assert_eq!(true, dir.path().join("other.com").join("c").exists());

        let usage = manager.get_usage("example.com").expect("usage");
        assert_eq!(0, usage.current_bytes);
        assert_eq!(0, usage.item_count);
        // The ceiling survives a purge.
        assert_eq!(10, manager.get_quota("example.com").expect("quota").max_mb);
    }

    #[tokio::test]
    async fn purge_rejects_paths_that_escape_the_cache_root() {
        let dir = TempDir::new().expect("tempdir");
        let manager = DiskQuotaManager::new(dir.path().to_path_buf());
        write_entry(dir.path(), "example.com", "a", 100);
        // `..` would delete the parent of the cache root.
        assert_eq!(0, manager.purge_domain("..").await.purged_count);
        assert_eq!(0, manager.purge_domain("").await.purged_count);
        assert_eq!(true, dir.path().join("example.com").join("a").exists());
    }

    #[tokio::test]
    async fn purge_urls_only_touches_the_named_keys() {
        let dir = TempDir::new().expect("tempdir");
        let manager = DiskQuotaManager::new(dir.path().to_path_buf());
        manager.set_quota("example.com", 10);
        write_entry(dir.path(), "example.com", "a", 100);
        write_entry(dir.path(), "example.com", "b", 200);
        manager.record_write("example.com", "a", 100);
        manager.record_write("example.com", "b", 200);

        let result =
            manager.purge_urls("example.com", &["a".to_string()]).await;
        assert_eq!(1, result.purged_count);
        assert_eq!(100, result.freed_bytes);
        assert_eq!(false, dir.path().join("example.com").join("a").exists());
        assert_eq!(true, dir.path().join("example.com").join("b").exists());
        assert_eq!(
            200,
            manager
                .get_usage("example.com")
                .expect("usage")
                .current_bytes
        );
    }

    #[tokio::test]
    async fn load_rebuilds_usage_and_quotas_from_disk() {
        let dir = TempDir::new().expect("tempdir");
        write_entry(dir.path(), "example.com", "a", 1024);
        write_entry(dir.path(), "example.com", "b", 2048);
        write_entry(dir.path(), "other.com", "c", 4096);

        let first = DiskQuotaManager::new(dir.path().to_path_buf());
        first.set_quota("example.com", 5);
        first.load().await;
        let usage = first.get_usage("example.com").expect("usage");
        assert_eq!(3072, usage.current_bytes);
        assert_eq!(2, usage.item_count);
        assert_eq!(5 * BYTES_PER_MB, usage.max_bytes);

        // A restart keeps both the usage and the ceiling.
        let second = DiskQuotaManager::new(dir.path().to_path_buf());
        second.load().await;
        let usage = second.get_usage("example.com").expect("usage");
        assert_eq!(3072, usage.current_bytes);
        assert_eq!(5, second.get_quota("example.com").expect("quota").max_mb);
        assert_eq!(
            4096,
            second.get_usage("other.com").expect("usage").current_bytes
        );
        // Two domains tracked, sorted for stable output.
        assert_eq!(
            vec!["example.com".to_string(), "other.com".to_string()],
            second.domains()
        );
    }

    #[test]
    fn forget_domain_drops_the_ledger_and_the_ceiling() {
        let dir = TempDir::new().expect("tempdir");
        let manager = DiskQuotaManager::new(dir.path().to_path_buf());
        manager.set_quota("example.com", 5);
        manager.record_write("example.com", "a", 10);
        manager.forget_domain("example.com");
        assert_eq!(None, manager.get_usage("example.com"));
        assert_eq!(true, manager.domains().is_empty());
    }

    /// The parked ceilings are what let the agent configure a site before the
    /// proxy has built a cache backend, so they must reach the ledger intact -
    /// and exactly once.
    #[test]
    fn parked_quotas_are_replayed_into_a_ledger() {
        let dir = TempDir::new().expect("tempdir");
        let pending = PendingQuotas::default();
        let manager = DiskQuotaManager::new(dir.path().to_path_buf());

        pending.park("a.example", 8);
        assert_eq!(None, manager.get_quota("a.example"));
        assert_eq!(vec!["a.example".to_string()], pending.domains());

        pending.flush_into(&manager);
        assert_eq!(8, manager.get_quota("a.example").expect("quota").max_mb);
        // Drained, so a second replay cannot resurrect a ceiling that was
        // cleared in between.
        assert_eq!(true, pending.domains().is_empty());
        manager.set_quota("a.example", 1);
        pending.flush_into(&manager);
        assert_eq!(1, manager.get_quota("a.example").expect("quota").max_mb);

        // A later parked ceiling replaces the one in force.
        pending.park("a.example", 16);
        pending.flush_into(&manager);
        assert_eq!(16, manager.get_quota("a.example").expect("quota").max_mb);
    }

    /// `0` means unlimited, which is also the default, so parking it must
    /// clear rather than store: otherwise a site whose quota was removed while
    /// no backend existed would get the limit back on the next load.
    #[test]
    fn parking_zero_clears_a_parked_ceiling() {
        let pending = PendingQuotas::default();
        pending.park("a.example", 4);
        pending.park("b.example", 4);
        pending.park("a.example", 0);
        // An empty domain names nothing, so it is not remembered either.
        pending.park("", 4);
        assert_eq!(vec!["b.example".to_string()], pending.domains());
        assert_eq!(None, configured_quota(None, &pending, "a.example"));
        assert_eq!(Some(4), configured_quota(None, &pending, "b.example"));

        pending.forget("b.example");
        assert_eq!(true, pending.domains().is_empty());
    }

    /// "Which ceilings should I drop" has to cover the ledger *and* the
    /// requests still parked, or a site removed before the backend came up
    /// would keep its budget forever. A domain whose bytes are merely
    /// accounted for is not one of them.
    #[test]
    fn tracked_domains_merge_the_ledger_and_the_parked_requests() {
        let dir = TempDir::new().expect("tempdir");
        write_entry(dir.path(), "scanned.example", "k", 10);

        let pending = PendingQuotas::default();
        let manager = DiskQuotaManager::new(dir.path().to_path_buf());
        manager.load_sync();
        manager.set_quota("b.example", 1);
        pending.park("a.example", 2);
        pending.park("b.example", 3);

        // On disk, but nobody configured a limit for it.
        assert_eq!(
            true,
            manager.domains().contains(&"scanned.example".to_string())
        );
        assert_eq!(
            vec!["a.example".to_string(), "b.example".to_string()],
            merged_domains(Some(&manager), &pending)
        );
        // Before the ledger exists, the parked requests are all there is.
        assert_eq!(
            vec!["a.example".to_string(), "b.example".to_string()],
            merged_domains(None, &pending)
        );

        // The ledger wins for a domain both sources know, the parked copy is
        // the fallback for one it does not.
        assert_eq!(
            Some(1),
            configured_quota(Some(&manager), &pending, "b.example")
        );
        assert_eq!(
            Some(2),
            configured_quota(Some(&manager), &pending, "a.example")
        );
        assert_eq!(Some(2), configured_quota(None, &pending, "a.example"));
        assert_eq!(
            None,
            configured_quota(Some(&manager), &pending, "c.example")
        );
    }

    /// `load` replays the parked ceilings *after* reading `.quota.json`, so
    /// what the control plane just said wins over what the previous run
    /// persisted. This drives the same two steps, in the same order.
    #[test]
    fn a_parked_ceiling_wins_over_the_persisted_one() {
        let dir = TempDir::new().expect("tempdir");
        // A previous run persisted 8 MB and exited.
        DiskQuotaManager::new(dir.path().to_path_buf())
            .set_quota("example.com", 8);

        // On the way back up, the agent hears 16 MB before any cache backend
        // exists to hold it.
        let pending = PendingQuotas::default();
        pending.park("example.com", 16);

        let manager = DiskQuotaManager::new(dir.path().to_path_buf());
        manager.load_sync();
        assert_eq!(8, manager.get_quota("example.com").expect("quota").max_mb);
        pending.flush_into(&manager);
        assert_eq!(16, manager.get_quota("example.com").expect("quota").max_mb);
    }
}
