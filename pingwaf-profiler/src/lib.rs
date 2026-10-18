//! Module- and method-level CPU/memory attribution for PingWAF.
//!
//! The alternative to a profiler that samples stacks: the code that knows
//! what it is doing accounts for itself.
//!
//! * **Modules** are the six functional areas of the process — proxy, waf,
//!   cache, plugin, db, control — recorded in a fixed array of atomics, so
//!   recording costs one relaxed add and no allocation.
//! * **Methods** are named call sites (`"proxy::handle_request"`, …) kept in
//!   a concurrent map; instrument only the hot paths that matter, since a
//!   map lookup is the expensive part.
//! * **Memory** is *reported*, not intercepted: modules that own large
//!   structures (cache capacity, WAF body buffers, log batches) publish
//!   their current byte count with [`set_memory`]/[`add_memory`]. Nothing
//!   hooks the allocator, so this works with any allocator and on any
//!   platform.
//!
//! There is no sampling and no symbolisation: an accounting call is a few
//! nanoseconds and works the same in a debug build on a laptop and a release
//! build in a container, which is exactly what the removed pprof path could
//! not offer.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::Serialize;

/// The functional areas attribution is grouped into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Module {
    /// Request intake, connection handling, upstream forwarding.
    Proxy,
    /// WAF rule evaluation, body inspection, decisions.
    Waf,
    /// Cache lookup, storage, eviction and purge.
    Cache,
    /// The plugin chain around WAF (rewrite, headers, compression, …).
    Plugin,
    /// Database queries issued through the control plane.
    Db,
    /// Control-plane HTTP/gRPC handlers.
    Control,
    /// Anything not yet instrumented.
    Other,
}

impl Module {
    /// Every module, in the order the snapshot presents them.
    pub const ALL: [Module; 7] = [
        Module::Proxy,
        Module::Waf,
        Module::Cache,
        Module::Plugin,
        Module::Db,
        Module::Control,
        Module::Other,
    ];

    /// Stable key used in the snapshot.
    pub fn key(self) -> &'static str {
        match self {
            Module::Proxy => "proxy",
            Module::Waf => "waf",
            Module::Cache => "cache",
            Module::Plugin => "plugin",
            Module::Db => "db",
            Module::Control => "control",
            Module::Other => "other",
        }
    }

    fn index(self) -> usize {
        match self {
            Module::Proxy => 0,
            Module::Waf => 1,
            Module::Cache => 2,
            Module::Plugin => 3,
            Module::Db => 4,
            Module::Control => 5,
            Module::Other => 6,
        }
    }
}

#[derive(Default)]
struct ModuleCounters {
    cpu_ns: AtomicU64,
    mem_bytes: AtomicI64,
    calls: AtomicU64,
}

static MODULES: [ModuleCounters; 7] = [
    ModuleCounters::new(),
    ModuleCounters::new(),
    ModuleCounters::new(),
    ModuleCounters::new(),
    ModuleCounters::new(),
    ModuleCounters::new(),
    ModuleCounters::new(),
];

impl ModuleCounters {
    const fn new() -> Self {
        Self {
            cpu_ns: AtomicU64::new(0),
            mem_bytes: AtomicI64::new(0),
            calls: AtomicU64::new(0),
        }
    }
}

struct MethodCounters {
    cpu_ns: AtomicU64,
    calls: AtomicU64,
}

static METHODS: LazyLock<DashMap<&'static str, MethodCounters>> =
    LazyLock::new(DashMap::new);

/// Accumulates CPU time (nanoseconds) attributed to `module`.
pub fn record_cpu(module: Module, ns: u64) {
    if ns == 0 {
        return;
    }
    MODULES[module.index()]
        .cpu_ns
        .fetch_add(ns, Ordering::Relaxed);
    MODULES[module.index()]
        .calls
        .fetch_add(1, Ordering::Relaxed);
}

/// Replaces the module's "currently held bytes" gauge (cache capacity, body
/// buffers, log batches). Saturates at zero so a racing subtraction cannot
/// wrap into an absurd number.
pub fn set_memory(module: Module, bytes: u64) {
    MODULES[module.index()]
        .mem_bytes
        .store(bytes.min(i64::MAX as u64) as i64, Ordering::Relaxed);
}

/// Adds `delta` bytes (negative for release) to the module's held-bytes
/// gauge.
pub fn add_memory(module: Module, delta: i64) {
    if delta == 0 {
        return;
    }
    MODULES[module.index()]
        .mem_bytes
        .fetch_add(delta, Ordering::Relaxed);
}

/// Times the scope it lives in and attributes it to `module` on drop.
pub struct Timer {
    module: Module,
    started: Instant,
}

impl Drop for Timer {
    fn drop(&mut self) {
        record_cpu(self.module, self.started.elapsed().as_nanos() as u64);
    }
}

/// Starts a module timer; bind it to `_timer` so it lives for the scope.
pub fn timed(module: Module) -> Timer {
    Timer {
        module,
        started: Instant::now(),
    }
}

/// Times the scope it lives in and attributes it to a named method.
pub struct MethodTimer {
    name: &'static str,
    started: Instant,
}

impl Drop for MethodTimer {
    fn drop(&mut self) {
        let ns = self.started.elapsed().as_nanos() as u64;
        if ns == 0 {
            return;
        }
        match METHODS.get_mut(self.name) {
            Some(counters) => {
                counters.cpu_ns.fetch_add(ns, Ordering::Relaxed);
                counters.calls.fetch_add(1, Ordering::Relaxed);
            },
            None => {
                // First observation of this call site: insert once, then the
                // hot path only takes the shard write lock above.
                METHODS.insert(
                    self.name,
                    MethodCounters {
                        cpu_ns: AtomicU64::new(ns),
                        calls: AtomicU64::new(1),
                    },
                );
            },
        }
    }
}

/// Starts a method timer; bind it to `_timer` so it lives for the scope.
pub fn timed_method(name: &'static str) -> MethodTimer {
    MethodTimer {
        name,
        started: Instant::now(),
    }
}

/// Times `$body` as a method named `$name` (a `&'static str`).
#[macro_export]
macro_rules! profile_method {
    ($name:literal, $body:block) => {{
        let _timer = $crate::timed_method($name);
        $body
    }};
}

/// One module row of a snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleView {
    /// Module key (`proxy`, `waf`, …).
    pub module: &'static str,
    /// Cumulative CPU time attributed to the module, in milliseconds.
    pub cpu_ms: f64,
    /// Share of the total attributed CPU time, 0.0–1.0.
    pub cpu_share: f64,
    /// Bytes the module currently reports as held.
    pub mem_bytes: u64,
    /// Share of the total held bytes across modules, 0.0–1.0.
    pub mem_share: f64,
    /// Number of timed operations attributed to the module.
    pub calls: u64,
    /// Average microseconds per timed operation.
    pub avg_us: f64,
}

/// One method row of a snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct MethodView {
    /// Call-site name.
    pub method: &'static str,
    /// Cumulative CPU time in milliseconds.
    pub cpu_ms: f64,
    /// Number of timed calls.
    pub calls: u64,
    /// Average microseconds per call.
    pub avg_us: f64,
}

/// Bounded, allocation-light view of the accounting tables.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileSnapshot {
    /// Unix epoch milliseconds at which the snapshot was taken.
    pub collected_at_ms: u64,
    /// Total attributed CPU time across modules, in milliseconds.
    pub total_cpu_ms: f64,
    /// Module rows (all modules, hottest first is left to the caller).
    pub modules: Vec<ModuleView>,
    /// Method rows, hottest first, capped at [`Self::MAX_METHODS`].
    pub methods: Vec<MethodView>,
}

impl ProfileSnapshot {
    /// How many method rows a snapshot carries: enough to find a hotspot,
    /// small enough that the JSON stays KB-scale.
    pub const MAX_METHODS: usize = 40;

    /// Reads the accounting tables into a snapshot.
    pub fn collect() -> Self {
        let mut modules = Vec::with_capacity(Module::ALL.len());
        let mut total_cpu_ns = 0u64;
        let mut total_mem = 0u64;
        for module in Module::ALL {
            let counters = &MODULES[module.index()];
            let cpu_ns = counters.cpu_ns.load(Ordering::Relaxed);
            total_cpu_ns = total_cpu_ns.saturating_add(cpu_ns);
            total_mem = total_mem.saturating_add(
                counters.mem_bytes.load(Ordering::Relaxed).max(0) as u64,
            );
            let calls = counters.calls.load(Ordering::Relaxed);
            modules.push(ModuleView {
                module: module.key(),
                cpu_ms: cpu_ns as f64 / 1_000_000.0,
                cpu_share: 0.0,
                mem_bytes: counters.mem_bytes.load(Ordering::Relaxed).max(0)
                    as u64,
                mem_share: 0.0,
                calls,
                avg_us: if calls == 0 {
                    0.0
                } else {
                    cpu_ns as f64 / calls as f64 / 1_000.0
                },
            });
        }
        for row in &mut modules {
            row.cpu_share = if total_cpu_ns == 0 {
                0.0
            } else {
                row.cpu_ms * 1_000_000.0 / total_cpu_ns as f64
            };
            row.mem_share = if total_mem == 0 {
                0.0
            } else {
                row.mem_bytes as f64 / total_mem as f64
            };
        }
        let mut methods: Vec<MethodView> = METHODS
            .iter()
            .map(|entry| {
                let cpu_ns = entry.value().cpu_ns.load(Ordering::Relaxed);
                let calls = entry.value().calls.load(Ordering::Relaxed);
                MethodView {
                    method: entry.key(),
                    cpu_ms: cpu_ns as f64 / 1_000_000.0,
                    calls,
                    avg_us: if calls == 0 {
                        0.0
                    } else {
                        cpu_ns as f64 / calls as f64 / 1_000.0
                    },
                }
            })
            .collect();
        methods.sort_by(|a, b| {
            b.cpu_ms
                .partial_cmp(&a.cpu_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        methods.truncate(Self::MAX_METHODS);
        Self {
            collected_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or_default(),
            total_cpu_ms: total_cpu_ns as f64 / 1_000_000.0,
            modules,
            methods,
        }
    }

    /// Resets every counter. Exposed for tests and for an operator-triggered
    /// "start a fresh window".
    pub fn reset() {
        for counters in &MODULES {
            counters.cpu_ns.store(0, Ordering::Relaxed);
            counters.mem_bytes.store(0, Ordering::Relaxed);
            counters.calls.store(0, Ordering::Relaxed);
        }
        METHODS.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accounting tables are process-global, so these tests must not run
    /// concurrently (a parallel test's timers would land in another test's
    /// snapshot).
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn module_timers_accumulate_and_share() {
        let _guard = serial();
        ProfileSnapshot::reset();
        {
            let _timer = timed(Module::Waf);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let snapshot = ProfileSnapshot::collect();
        let waf = snapshot
            .modules
            .iter()
            .find(|row| row.module == "waf")
            .expect("waf row");
        assert_eq!(waf.calls, 1);
        assert!(waf.cpu_ms > 0.0, "timer recorded time");
        // Round-tripping ns → ms → share is exact mathematically but not in
        // binary floating point; EPSILON is too tight for a platform-neutral
        // assertion (it flipped between toolchains).
        assert!((waf.cpu_share - 1.0).abs() < 1e-9);
    }

    #[test]
    fn memory_gauges_are_reported_and_shared() {
        let _guard = serial();
        ProfileSnapshot::reset();
        set_memory(Module::Cache, 1024);
        add_memory(Module::Cache, 1024);
        set_memory(Module::Waf, 2048);
        let snapshot = ProfileSnapshot::collect();
        let cache = snapshot
            .modules
            .iter()
            .find(|row| row.module == "cache")
            .expect("cache row");
        let waf = snapshot
            .modules
            .iter()
            .find(|row| row.module == "waf")
            .expect("waf row");
        assert_eq!(cache.mem_bytes, 2048);
        assert_eq!(waf.mem_bytes, 2048);
        assert!((cache.mem_share - 0.5).abs() < 1e-9);
    }

    #[test]
    fn method_rows_are_sorted_and_capped() {
        let _guard = serial();
        ProfileSnapshot::reset();
        for index in 0..(ProfileSnapshot::MAX_METHODS + 10) {
            let name: &'static str =
                Box::leak(format!("m{index}").into_boxed_str());
            let _timer = timed_method(name);
            if index % 2 == 0 {
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        }
        let snapshot = ProfileSnapshot::collect();
        assert_eq!(snapshot.methods.len(), ProfileSnapshot::MAX_METHODS);
        assert!(snapshot.methods[0].cpu_ms >= snapshot.methods[1].cpu_ms);
    }
}
