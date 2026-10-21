//! Module- and method-level **wall-clock** attribution for PingWAF.
//!
//! The alternative to a profiler that samples stacks: the code that knows
//! what it is doing accounts for itself.
//!
//! * **Modules** are the functional areas of the process — proxy, waf (and its
//!   normalize / signature / expression / body stages), cache, plugin, db,
//!   control, log, agent, http-client, other — recorded in a fixed array of
//!   atomics, so recording costs one relaxed add and no allocation.
//! * **Methods** are the instrumented call sites (`"proxy::request_filter"`,
//!   …). The set is fixed at compile time ([`Method`]), so recording a method
//!   is an array index — no hash, no lock, no allocation. A method also rolls
//!   up into its [`Module`], so a call site is instrumented once and two rows
//!   are accounted for.
//! * **Memory** is *reported*, not intercepted: modules and methods that own
//!   large structures (cache capacity, WAF body buffers, log batches, agent
//!   snapshots) publish their current byte count with
//!   [`set_memory`]/[`add_memory`] and [`add_method_memory`], and a
//!   [`track_memory`] guard releases it on drop. Nothing hooks the allocator,
//!   so this works with any allocator and on any platform.
//! * **Disk** is still collected internally by [`set_disk_bytes`], but it is
//!   no longer part of the snapshot: the dashboard's module table reports
//!   memory only. Keeping the on-disk gauge separate is deliberate — a cache
//!   that holds gigabytes on disk and one that holds them in memory need
//!   completely different fixes, and folding the filesystem's bytes into the
//!   memory figure is what made the table claim the process used them.
//!
//! There is no sampling and no symbolisation: an accounting call is a few
//! nanoseconds and works the same in a debug build on a laptop and a release
//! build in a container, which is exactly what the removed pprof path could
//! not offer.
//!
//! # What the numbers are — and what they are not
//!
//! Every timer here is [`Instant`]-based, so it measures **wall-clock time
//! spent inside the timed scope**, not CPU cycles. A scope that awaits a
//! database query, a lock or the upstream reports that wait as well; when the
//! executor deschedules the task the clock keeps running. Reading `cpu_ms` as
//! "CPU time" is what made `control::http` look like 90 % CPU when it was
//! really "90 % of the attributed wall time, most of it waiting".
//!
//! The snapshot therefore publishes each figure twice: under the historical
//! `cpu_ms` / `cpu_share` names — kept so existing dashboards keep parsing —
//! and under `elapsed_ms` / `elapsed_share`, which say what is measured. Both
//! pairs always carry the same value; the `cpu_*` pair is a deprecated alias
//! waiting for its consumers to migrate.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// The functional areas attribution is grouped into.
///
/// The WAF stages (`WafNormalize`, `WafSignature`, `WafExpression`, `WafBody`)
/// are **nested** inside `Waf`: the `waf::handle_request` timer spans all of
/// them, so their time is also counted in the `waf` row. Read the stage rows
/// as a breakdown of `waf` — never add them to it, or the shares exceed 1.
///
/// `#[repr(usize)]` on purpose: [`Module::index`] is then a cast, and
/// [`Module::ALL`] is written in discriminant order so a slot's index is its
/// position in the snapshot.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Module {
    /// Request intake, connection handling, upstream forwarding.
    Proxy = 0,
    /// WAF rule evaluation, body inspection, decisions — the stages that are
    /// not split out below, kept so older instrumentation still lands here.
    Waf = 1,
    /// Cache lookup, storage, eviction and purge.
    Cache = 2,
    /// The plugin chain around WAF (rewrite, headers, compression, …).
    Plugin = 3,
    /// Database queries issued through the control plane.
    Db = 4,
    /// Control-plane HTTP/gRPC handlers.
    Control = 5,
    /// Anything not yet instrumented.
    Other = 6,
    /// WAF normalization: decoding, path/query canonicalisation.
    WafNormalize = 7,
    /// WAF signature matching (libinjection, Aho-Corasick rule sets).
    WafSignature = 8,
    /// WAF expression evaluation.
    WafExpression = 9,
    /// WAF request-body buffering and staged inspection.
    WafBody = 10,
    /// Access/security log assembly, batching and flush.
    Log = 11,
    /// Agent configuration sync: received bundles, snapshots, rule tables.
    Agent = 12,
    /// Outbound HTTP client (webhooks, ACME, notifications).
    HttpClient = 13,
}

impl Module {
    /// Every module, in the order the snapshot presents them.
    pub const ALL: [Module; 14] = [
        Module::Proxy,
        Module::Waf,
        Module::Cache,
        Module::Plugin,
        Module::Db,
        Module::Control,
        Module::Other,
        Module::WafNormalize,
        Module::WafSignature,
        Module::WafExpression,
        Module::WafBody,
        Module::Log,
        Module::Agent,
        Module::HttpClient,
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
            Module::WafNormalize => "waf_normalize",
            Module::WafSignature => "waf_signature",
            Module::WafExpression => "waf_expression",
            Module::WafBody => "waf_body",
            Module::Log => "log",
            Module::Agent => "agent",
            Module::HttpClient => "http_client",
        }
    }

    /// Slot of the module's counters in [`MODULES`].
    #[inline]
    fn index(self) -> usize {
        self as usize
    }
}

/// The instrumented call sites.
///
/// A closed set, deliberately: the previous string-keyed map cost a hash and
/// a `DashMap` shard lock per recorded call site (per request, on the hot
/// path), and bought an extensibility nobody used — every call site in the
/// workspace is listed here. Adding one is a variant plus an entry in
/// [`Method::ALL`]; [`Method::Other`] is the escape hatch for a scope that
/// does not deserve a variant.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `pingap-proxy` `request_filter` — the whole per-request pipeline.
    ProxyRequestFilter = 0,
    /// `pingap-plugin` WAF `handle_request` — rule evaluation and decision.
    WafHandleRequest = 1,
    /// `pingap-plugin` cache `handle_request` — lookup, PURGE, settings.
    CacheHandleRequest = 2,
    /// `pingap-plugin` rewrite `handle_request` — rule evaluation and rewrite.
    PluginRewrite = 3,
    /// Control plane `persist_heartbeat` — the agent heartbeat write.
    DbPersistHeartbeat = 4,
    /// Control-plane REST request (`/api/v1`), recorded by the middleware.
    ControlHttp = 5,
    /// Reserved: a scope without a named call site. Rolls up into
    /// [`Module::Other`] and is never recorded today; it exists so the slot
    /// layout is complete and a new call site has a home before it earns a
    /// variant.
    Other = 6,
    /// `pingwaf-waf` normalization: decoding and canonicalisation.
    WafNormalize = 7,
    /// `pingwaf-waf` signature matching.
    WafSignature = 8,
    /// `pingwaf-waf` expression evaluation.
    WafExpression = 9,
    /// `pingwaf-waf` request-body read/staging.
    WafBodyRead = 10,
    /// Cache lookup (hit path).
    CacheLookup = 11,
    /// Cache store (miss path).
    CacheStore = 12,
    /// `pingap-plugin` sub_filter: response body rewriting.
    PluginSubFilter = 13,
    /// `pingap-plugin` challenge: page issuance and verification.
    PluginChallenge = 14,
    /// Control-plane access-log persistence.
    DbPersistLogs = 15,
    /// Control-plane security-event persistence.
    DbPersistEvents = 16,
    /// Control-plane gRPC stream (agent sync).
    ControlGrpcStream = 17,
    /// Agent-side configuration sync and snapshot rebuild.
    AgentSync = 18,
    /// Access-log batch flush.
    LogFlush = 19,
    /// Upstream connection establishment (connect + TLS).
    ProxyUpstreamConnect = 20,
}

impl Method {
    /// Every method, in slot order. Length must stay `<=`
    /// [`ProfileSnapshot::MAX_METHODS`] or the snapshot truncates rows.
    pub const ALL: [Method; 21] = [
        Method::ProxyRequestFilter,
        Method::WafHandleRequest,
        Method::CacheHandleRequest,
        Method::PluginRewrite,
        Method::DbPersistHeartbeat,
        Method::ControlHttp,
        Method::Other,
        Method::WafNormalize,
        Method::WafSignature,
        Method::WafExpression,
        Method::WafBodyRead,
        Method::CacheLookup,
        Method::CacheStore,
        Method::PluginSubFilter,
        Method::PluginChallenge,
        Method::DbPersistLogs,
        Method::DbPersistEvents,
        Method::ControlGrpcStream,
        Method::AgentSync,
        Method::LogFlush,
        Method::ProxyUpstreamConnect,
    ];

    /// Call-site name used in the snapshot.
    ///
    /// These strings are the ones the string-keyed table used, so a dashboard
    /// that matches on `"waf::handle_request"` keeps working unchanged.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::ProxyRequestFilter => "proxy::request_filter",
            Method::WafHandleRequest => "waf::handle_request",
            Method::CacheHandleRequest => "cache::handle_request",
            Method::PluginRewrite => "plugin::rewrite",
            Method::DbPersistHeartbeat => "db::persist_heartbeat",
            Method::ControlHttp => "control::http",
            Method::Other => "other::unattributed",
            Method::WafNormalize => "waf::normalize",
            Method::WafSignature => "waf::signature",
            Method::WafExpression => "waf::expression",
            Method::WafBodyRead => "waf::body_read",
            Method::CacheLookup => "cache::lookup",
            Method::CacheStore => "cache::store",
            Method::PluginSubFilter => "plugin::sub_filter",
            Method::PluginChallenge => "plugin::challenge",
            Method::DbPersistLogs => "db::persist_logs",
            Method::DbPersistEvents => "db::persist_events",
            Method::ControlGrpcStream => "control::grpc_stream",
            Method::AgentSync => "agent::sync",
            Method::LogFlush => "log::flush",
            Method::ProxyUpstreamConnect => "proxy::upstream_connect",
        }
    }

    /// The module this call site rolls up into.
    pub fn module(self) -> Module {
        match self {
            Method::ProxyRequestFilter => Module::Proxy,
            Method::WafHandleRequest => Module::Waf,
            Method::CacheHandleRequest => Module::Cache,
            Method::PluginRewrite => Module::Plugin,
            Method::DbPersistHeartbeat => Module::Db,
            Method::ControlHttp => Module::Control,
            Method::Other => Module::Other,
            Method::WafNormalize => Module::WafNormalize,
            Method::WafSignature => Module::WafSignature,
            Method::WafExpression => Module::WafExpression,
            Method::WafBodyRead => Module::WafBody,
            Method::CacheLookup => Module::Cache,
            Method::CacheStore => Module::Cache,
            Method::PluginSubFilter => Module::Plugin,
            Method::PluginChallenge => Module::Plugin,
            Method::DbPersistLogs => Module::Db,
            Method::DbPersistEvents => Module::Db,
            Method::ControlGrpcStream => Module::Control,
            Method::AgentSync => Module::Agent,
            Method::LogFlush => Module::Log,
            Method::ProxyUpstreamConnect => Module::Proxy,
        }
    }

    /// Slot of the method's counters in [`METHODS`].
    #[inline]
    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Default)]
struct ModuleCounters {
    /// Wall-clock nanoseconds accumulated from the module's timers.
    ///
    /// Named `elapsed_` rather than `cpu_`: see the crate docs — an
    /// [`Instant`] measures time, not cycles.
    elapsed_ns: AtomicU64,
    mem_bytes: AtomicI64,
    /// High-water mark of `mem_bytes` since process start (or the last
    /// [`ProfileSnapshot::reset`]). `fetch_max`, relaxed — same cost class
    /// as the current-value update, no allocation, no lock.
    mem_peak_bytes: AtomicI64,
    /// Bytes the module currently keeps **on disk**. A separate slot from
    /// `mem_bytes`: the cache backend used to publish its on-disk usage into
    /// the memory gauge, so the module table reported the filesystem's bytes
    /// as resident memory.
    disk_bytes: AtomicU64,
    calls: AtomicU64,
}

/// One slot per [`Module`], indexed by discriminant — which is only sound while
/// the length tracks [`Module::ALL`], so it is taken from there instead of
/// being written out. With a literal, adding a module to `ALL` left the table
/// short and the first `record_cpu` for the new variant panicked inside the
/// request path (a `#[repr(usize)]` cast is an unchecked index).
///
/// The residual hole — a variant added to the enum but not to `ALL` — cannot be
/// closed without a derive macro (`ALL` cannot enumerate itself); the unit
/// tests pin `ALL`'s order and the module roll-up of every call site, so a
/// misordered or forgotten entry fails there rather than in production.
static MODULES: [ModuleCounters; Module::ALL.len()] =
    [const { ModuleCounters::new() }; Module::ALL.len()];

impl ModuleCounters {
    const fn new() -> Self {
        Self {
            elapsed_ns: AtomicU64::new(0),
            mem_bytes: AtomicI64::new(0),
            mem_peak_bytes: AtomicI64::new(0),
            disk_bytes: AtomicU64::new(0),
            calls: AtomicU64::new(0),
        }
    }
}

struct MethodCounters {
    elapsed_ns: AtomicU64,
    /// Bytes the call site currently holds. Only scopes that own a buffer
    /// report here; a method whose work allocates and drops within the call
    /// stays at zero.
    mem_bytes: AtomicI64,
    /// High-water mark of `mem_bytes`, same policy as the module slot.
    mem_peak_bytes: AtomicI64,
    calls: AtomicU64,
}

impl MethodCounters {
    const fn new() -> Self {
        Self {
            elapsed_ns: AtomicU64::new(0),
            mem_bytes: AtomicI64::new(0),
            mem_peak_bytes: AtomicI64::new(0),
            calls: AtomicU64::new(0),
        }
    }
}

/// One slot per [`Method`], indexed by discriminant: recording is a bounds
/// check plus two relaxed adds. Sized from [`Method::ALL`] for the reason given
/// on [`MODULES`].
static METHODS: [MethodCounters; Method::ALL.len()] =
    [const { MethodCounters::new() }; Method::ALL.len()];

/// Accumulates wall-clock time (nanoseconds) attributed to `module`.
///
/// The name is historical — this records elapsed time, not CPU time (see the
/// crate docs). [`MethodTimer`] performs the same module-slot updates inline
/// in its `Drop` (it cannot go through here: the zero-length guard has to
/// agree across both rows), which is what makes a module's totals the sum of
/// its methods.
pub fn record_cpu(module: Module, ns: u64) {
    if ns == 0 {
        return;
    }
    MODULES[module.index()]
        .elapsed_ns
        .fetch_add(ns, Ordering::Relaxed);
    MODULES[module.index()]
        .calls
        .fetch_add(1, Ordering::Relaxed);
}

/// Replaces the module's "currently held bytes" gauge (cache capacity, body
/// buffers, log batches). Saturates at zero so a racing subtraction cannot
/// wrap into an absurd number.
pub fn set_memory(module: Module, bytes: u64) {
    let counters = &MODULES[module.index()];
    let value = bytes.min(i64::MAX as u64) as i64;
    counters.mem_bytes.store(value, Ordering::Relaxed);
    counters.mem_peak_bytes.fetch_max(value, Ordering::Relaxed);
}

/// Adds `delta` bytes (negative for release) to the module's held-bytes
/// gauge.
pub fn add_memory(module: Module, delta: i64) {
    if delta == 0 {
        return;
    }
    let counters = &MODULES[module.index()];
    let current = counters.mem_bytes.fetch_add(delta, Ordering::Relaxed);
    // Track the high-water mark of the value *after* the add; a transient
    // negative cannot lower the peak (`fetch_max` keeps the running max).
    counters
        .mem_peak_bytes
        .fetch_max(current.saturating_add(delta), Ordering::Relaxed);
}

/// Replaces the module's **on-disk** footprint (cache files, spill files).
///
/// Kept apart from [`set_memory`] on purpose: the cache backend's on-disk
/// usage is what the filesystem holds, not what the process holds, and
/// folding it into the memory gauge is what made the module table report
/// "cache memory ≈ cache disk usage". A module with nothing on disk leaves
/// this at zero.
pub fn set_disk_bytes(module: Module, bytes: u64) {
    MODULES[module.index()]
        .disk_bytes
        .store(bytes, Ordering::Relaxed);
}

/// Records `ns` nanoseconds directly against `method` and its module.
///
/// [`timed_method`] is preferred for a scope that can own a guard; this is for
/// a span that ends in the middle of a function, where a guard's drop point
/// would be the end of the function instead.
pub fn record_method(method: Method, ns: u64) {
    if ns == 0 {
        return;
    }
    let counters = &METHODS[method.index()];
    counters.elapsed_ns.fetch_add(ns, Ordering::Relaxed);
    counters.calls.fetch_add(1, Ordering::Relaxed);
    let module = &MODULES[method.module().index()];
    module.elapsed_ns.fetch_add(ns, Ordering::Relaxed);
    module.calls.fetch_add(1, Ordering::Relaxed);
}

/// Adds `delta` bytes (negative for release) to a method's held-bytes gauge.
///
/// The method figure is what lets the dashboard name the call site behind a
/// module's memory, not just the module.
pub fn add_method_memory(method: Method, delta: i64) {
    if delta == 0 {
        return;
    }
    let counters = &METHODS[method.index()];
    let current = counters.mem_bytes.fetch_add(delta, Ordering::Relaxed);
    counters
        .mem_peak_bytes
        .fetch_max(current.saturating_add(delta), Ordering::Relaxed);
}

/// Releases the bytes it was created with on drop, from both the method row
/// and its module roll-up.
///
/// Bind it to a named local for as long as the buffer is held:
/// `let _buf_guard = track_method_memory(Method::WafBodyRead, bytes);`
pub struct MemoryGuard {
    method: Option<Method>,
    module: Module,
    bytes: u64,
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        let delta = -(self.bytes.min(i64::MAX as u64) as i64);
        add_memory(self.module, delta);
        if let Some(method) = self.method {
            add_method_memory(method, delta);
        }
    }
}

/// Reports `bytes` as held by `method` (and its module) until the guard drops.
pub fn track_method_memory(method: Method, bytes: u64) -> MemoryGuard {
    if bytes > 0 {
        add_memory(method.module(), bytes as i64);
        add_method_memory(method, bytes as i64);
    }
    MemoryGuard {
        method: Some(method),
        module: method.module(),
        bytes,
    }
}

/// Reports `bytes` as held by a module that has no dedicated method row.
pub fn track_memory(module: Module, bytes: u64) -> MemoryGuard {
    if bytes > 0 {
        add_memory(module, bytes as i64);
    }
    MemoryGuard {
        method: None,
        module,
        bytes,
    }
}

/// Times the scope it lives in and attributes it to `module` on drop.
///
/// For a scope that *is* a known call site prefer [`timed_method`]: it books
/// the module row as well, so one instrumentation point covers both. Keep
/// this for a module-level scope that has no method of its own.
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

/// Times the scope it lives in and attributes it to a [`Method`] — and to
/// that method's [`Module`] — on drop.
pub struct MethodTimer {
    method: Method,
    started: Instant,
}

impl Drop for MethodTimer {
    fn drop(&mut self) {
        let ns = self.started.elapsed().as_nanos() as u64;
        if ns == 0 {
            return;
        }
        // Four relaxed adds, no hash and no lock. The named-method slot is
        // the detail row; the module slot is the roll-up the module table
        // shows. Booking both here is what removes the second timer the
        // middleware used to run over the same scope: two clocks and two sets
        // of atomics per request bought nothing, because the two tables were
        // always fed the same nanoseconds (2026-10 attribution review).
        let method = &METHODS[self.method.index()];
        method.elapsed_ns.fetch_add(ns, Ordering::Relaxed);
        method.calls.fetch_add(1, Ordering::Relaxed);
        let module = &MODULES[self.method.module().index()];
        module.elapsed_ns.fetch_add(ns, Ordering::Relaxed);
        module.calls.fetch_add(1, Ordering::Relaxed);
    }
}

/// Starts a method timer; bind it to `_timer` so it lives for the scope.
#[inline]
pub fn timed_method(method: Method) -> MethodTimer {
    MethodTimer {
        method,
        started: Instant::now(),
    }
}

/// Times `$body` as `$method` (a [`Method`]).
#[macro_export]
macro_rules! profile_method {
    ($method:expr, $body:block) => {{
        let _timer = $crate::timed_method($method);
        $body
    }};
}

/// One module row of a snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleView {
    /// Module key (`proxy`, `waf`, …).
    pub module: &'static str,
    /// Cumulative **wall-clock** time attributed to the module, in
    /// milliseconds.
    ///
    /// Historical name: this is elapsed time, not CPU time — see the crate
    /// docs. Same value as [`Self::elapsed_ms`].
    pub cpu_ms: f64,
    /// Share of the total attributed wall-clock time, 0.0–1.0. Same value as
    /// [`Self::elapsed_share`].
    pub cpu_share: f64,
    /// Cumulative wall-clock time attributed to the module, in milliseconds.
    /// Same value as [`Self::cpu_ms`], under the name that matches what is
    /// measured.
    pub elapsed_ms: f64,
    /// Share of the total attributed wall-clock time, 0.0–1.0. Same value as
    /// [`Self::cpu_share`].
    pub elapsed_share: f64,
    /// Bytes the module currently reports as held **in memory**.
    pub mem_bytes: u64,
    /// Share of the total held bytes across modules, 0.0–1.0.
    pub mem_share: f64,
    /// High-water mark of [`Self::mem_bytes`] since process start (or the
    /// last reset). Stays above zero after the current value drops, so a
    /// gauge sampled between reports still shows what the module held.
    pub mem_peak_bytes: u64,
    /// Share of the sum of all modules' [`Self::mem_peak_bytes`], 0.0–1.0.
    /// 0.0 when the total peak is 0.
    pub mem_peak_share: f64,
    /// Number of timed operations attributed to the module.
    pub calls: u64,
    /// Average microseconds per timed operation.
    pub avg_us: f64,
}

/// One method row of a snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct MethodView {
    /// Call-site name ([`Method::as_str`]).
    pub method: &'static str,
    /// Cumulative **wall-clock** time in milliseconds.
    ///
    /// Historical name: this is elapsed time, not CPU time — see the crate
    /// docs. Same value as [`Self::elapsed_ms`].
    pub cpu_ms: f64,
    /// Share of the total attributed wall-clock time, 0.0–1.0. Same value as
    /// [`Self::elapsed_share`].
    pub cpu_share: f64,
    /// Cumulative wall-clock time in milliseconds. Same value as
    /// [`Self::cpu_ms`].
    pub elapsed_ms: f64,
    /// Share of the total attributed wall-clock time, 0.0–1.0. Same value as
    /// [`Self::cpu_share`].
    pub elapsed_share: f64,
    /// Bytes this call site currently reports as held.
    pub mem_bytes: u64,
    /// Share of the method's module memory, 0.0–1.0. Zero when the module
    /// reports nothing, so a method's share never divides by zero.
    pub mem_share: f64,
    /// High-water mark of [`Self::mem_bytes`] since process start (or the
    /// last reset).
    pub mem_peak_bytes: u64,
    /// Share of the sum of all modules' peak bytes, 0.0–1.0. 0.0 when the
    /// total peak is 0.
    pub mem_peak_share: f64,
    /// Number of timed calls.
    pub calls: u64,
    /// Average microseconds per call.
    pub avg_us: f64,
}

/// Bounded, allocation-light view of the accounting tables.
///
/// Every time figure is **wall-clock** (`Instant`-based), not CPU: a handler
/// that waits on the database contributes its wait. Treat the shares as "of
/// the time we attributed", not "of the CPU the process burned".
#[derive(Debug, Clone, Serialize)]
pub struct ProfileSnapshot {
    /// Unix epoch milliseconds at which the snapshot was taken.
    pub collected_at_ms: u64,
    /// Total attributed wall-clock time across modules, in milliseconds.
    ///
    /// Historical name: see the crate docs. Same value as
    /// [`Self::total_elapsed_ms`].
    pub total_cpu_ms: f64,
    /// Total attributed wall-clock time across modules, in milliseconds.
    /// Same value as [`Self::total_cpu_ms`].
    pub total_elapsed_ms: f64,
    /// Module rows (all modules, hottest first is left to the caller).
    pub modules: Vec<ModuleView>,
    /// Method rows, hottest first, capped at [`Self::MAX_METHODS`]. A method
    /// that never ran has no row.
    pub methods: Vec<MethodView>,
}

impl ProfileSnapshot {
    /// How many method rows a snapshot carries. With the method set fixed at
    /// compile time this is a ceiling that cannot be reached today (asserted
    /// in the tests); it stays so growing [`Method`] past it truncates
    /// predictably instead of inflating the JSON.
    pub const MAX_METHODS: usize = 40;

    /// Reads the accounting tables into a snapshot.
    pub fn collect() -> Self {
        let mut modules = Vec::with_capacity(Module::ALL.len());
        let mut total_elapsed_ns = 0u64;
        let mut total_mem = 0u64;
        let mut total_mem_peak = 0u64;
        // Per-module memory, so a method row can express its share of the
        // module it rolls up into.
        let mut module_mem = [0u64; Module::ALL.len()];
        for module in Module::ALL {
            let counters = &MODULES[module.index()];
            let elapsed_ns = counters.elapsed_ns.load(Ordering::Relaxed);
            total_elapsed_ns = total_elapsed_ns.saturating_add(elapsed_ns);
            let mem_bytes =
                counters.mem_bytes.load(Ordering::Relaxed).max(0) as u64;
            // Guard against a `store` interleaving between the two loads: the
            // peak is a high-water mark, so it can never sit below the value
            // currently held.
            let mem_peak_bytes =
                (counters.mem_peak_bytes.load(Ordering::Relaxed).max(0) as u64)
                    .max(mem_bytes);
            total_mem = total_mem.saturating_add(mem_bytes);
            total_mem_peak = total_mem_peak.saturating_add(mem_peak_bytes);
            module_mem[module.index()] = mem_bytes;
            let calls = counters.calls.load(Ordering::Relaxed);
            let elapsed_ms = elapsed_ns as f64 / 1_000_000.0;
            modules.push(ModuleView {
                module: module.key(),
                cpu_ms: elapsed_ms,
                cpu_share: 0.0,
                elapsed_ms,
                elapsed_share: 0.0,
                mem_bytes,
                mem_share: 0.0,
                mem_peak_bytes,
                mem_peak_share: 0.0,
                calls,
                avg_us: if calls == 0 {
                    0.0
                } else {
                    elapsed_ns as f64 / calls as f64 / 1_000.0
                },
            });
        }
        for row in &mut modules {
            let share = if total_elapsed_ns == 0 {
                0.0
            } else {
                row.elapsed_ms * 1_000_000.0 / total_elapsed_ns as f64
            };
            row.cpu_share = share;
            row.elapsed_share = share;
            row.mem_share = if total_mem == 0 {
                0.0
            } else {
                row.mem_bytes as f64 / total_mem as f64
            };
            row.mem_peak_share = if total_mem_peak == 0 {
                0.0
            } else {
                row.mem_peak_bytes as f64 / total_mem_peak as f64
            };
        }
        let mut methods: Vec<MethodView> = Method::ALL
            .iter()
            .filter_map(|method| {
                let counters = &METHODS[method.index()];
                let calls = counters.calls.load(Ordering::Relaxed);
                // `Drop` skips a zero-length measurement, so `calls == 0`
                // means "never observed": no row, exactly like the old
                // string-keyed table which only held recorded names.
                if calls == 0 {
                    return None;
                }
                let elapsed_ns = counters.elapsed_ns.load(Ordering::Relaxed);
                let elapsed_ms = elapsed_ns as f64 / 1_000_000.0;
                let share = if total_elapsed_ns == 0 {
                    0.0
                } else {
                    elapsed_ms * 1_000_000.0 / total_elapsed_ns as f64
                };
                let mem_bytes =
                    counters.mem_bytes.load(Ordering::Relaxed).max(0) as u64;
                let mem_peak_bytes =
                    (counters.mem_peak_bytes.load(Ordering::Relaxed).max(0)
                        as u64)
                        .max(mem_bytes);
                let module_total = module_mem[method.module().index()];
                Some(MethodView {
                    method: method.as_str(),
                    cpu_ms: elapsed_ms,
                    cpu_share: share,
                    elapsed_ms,
                    elapsed_share: share,
                    mem_bytes,
                    mem_share: if module_total == 0 {
                        0.0
                    } else {
                        mem_bytes as f64 / module_total as f64
                    },
                    mem_peak_bytes,
                    mem_peak_share: if total_mem_peak == 0 {
                        0.0
                    } else {
                        mem_peak_bytes as f64 / total_mem_peak as f64
                    },
                    calls,
                    avg_us: elapsed_ns as f64 / calls as f64 / 1_000.0,
                })
            })
            .collect();
        methods.sort_by(|a, b| {
            b.elapsed_ms
                .partial_cmp(&a.elapsed_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        methods.truncate(Self::MAX_METHODS);
        let total_elapsed_ms = total_elapsed_ns as f64 / 1_000_000.0;
        Self {
            collected_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or_default(),
            total_cpu_ms: total_elapsed_ms,
            total_elapsed_ms,
            modules,
            methods,
        }
    }

    /// Resets every counter. Exposed for tests and for an operator-triggered
    /// "start a fresh window".
    pub fn reset() {
        for counters in &MODULES {
            counters.elapsed_ns.store(0, Ordering::Relaxed);
            counters.mem_bytes.store(0, Ordering::Relaxed);
            counters.mem_peak_bytes.store(0, Ordering::Relaxed);
            counters.disk_bytes.store(0, Ordering::Relaxed);
            counters.calls.store(0, Ordering::Relaxed);
        }
        for counters in &METHODS {
            counters.elapsed_ns.store(0, Ordering::Relaxed);
            counters.mem_bytes.store(0, Ordering::Relaxed);
            counters.mem_peak_bytes.store(0, Ordering::Relaxed);
            counters.calls.store(0, Ordering::Relaxed);
        }
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
        // The elapsed_* aliases carry the same numbers: the rename is a
        // labelling fix, not a change of measurement.
        assert_eq!(waf.elapsed_ms, waf.cpu_ms);
        assert_eq!(waf.elapsed_share, waf.cpu_share);
        assert_eq!(snapshot.total_elapsed_ms, snapshot.total_cpu_ms);
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

    /// The cache backend used to publish its **on-disk** byte count through
    /// [`set_memory`], so the module table said "cache memory ≈ cache disk
    /// usage". The disk gauge is still recorded, but it must never leak into
    /// the memory figure or the snapshot (the row no longer has a disk field
    /// at all — that part is a compile-time guarantee).
    #[test]
    fn disk_gauge_stays_out_of_the_snapshot() {
        let _guard = serial();
        ProfileSnapshot::reset();
        set_memory(Module::Cache, 1024);
        set_disk_bytes(Module::Cache, 8 * 1024 * 1024);
        let snapshot = ProfileSnapshot::collect();
        let cache = snapshot
            .modules
            .iter()
            .find(|row| row.module == "cache")
            .expect("cache row");
        assert_eq!(1024, cache.mem_bytes, "the disk gauge must not leak in");
        assert!((cache.mem_share - 1.0).abs() < 1e-9);
        // The on-disk figure is still kept internally for cache accounting.
        assert_eq!(
            8 * 1024 * 1024,
            MODULES[Module::Cache.index()]
                .disk_bytes
                .load(Ordering::Relaxed)
        );

        // A reset clears the memory gauge, and an empty snapshot has no NaN
        // shares.
        ProfileSnapshot::reset();
        let snapshot = ProfileSnapshot::collect();
        for row in &snapshot.modules {
            assert_eq!(0, row.mem_bytes);
            assert_eq!(0.0, row.mem_share);
        }
    }

    /// The peak gauge must survive a drop of the current value: a set of 100
    /// followed by a set of 0 reports `mem_bytes == 0` (current semantics
    /// unchanged) but keeps `mem_peak_bytes == 100` (high-water, L1-001/C3).
    #[test]
    fn memory_peak_survives_a_drop_to_zero() {
        let _guard = serial();
        ProfileSnapshot::reset();
        set_memory(Module::Cache, 100);
        set_memory(Module::Cache, 0);
        let snapshot = ProfileSnapshot::collect();
        let cache = snapshot
            .modules
            .iter()
            .find(|row| row.module == "cache")
            .expect("cache row");
        assert_eq!(0, cache.mem_bytes, "current value semantics unchanged");
        assert_eq!(100, cache.mem_peak_bytes, "peak is kept");
        assert!(cache.mem_peak_share > 0.0);

        // A reset clears the peak as well as the current value.
        ProfileSnapshot::reset();
        let snapshot = ProfileSnapshot::collect();
        let cache = snapshot
            .modules
            .iter()
            .find(|row| row.module == "cache")
            .expect("cache row");
        assert_eq!(0, cache.mem_peak_bytes);
        assert_eq!(0.0, cache.mem_peak_share);
    }

    /// Method rows keep their own peak: a guard's release must not erase the
    /// high-water mark the call site reached.
    #[test]
    fn method_memory_peak_survives_release() {
        let _guard = serial();
        ProfileSnapshot::reset();
        {
            let _timer = timed_method(Method::WafBodyRead);
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        drop(track_method_memory(Method::WafBodyRead, 4096));
        let snapshot = ProfileSnapshot::collect();
        let row = snapshot
            .methods
            .iter()
            .find(|row| row.method == Method::WafBodyRead.as_str())
            .expect("body_read row");
        assert_eq!(0, row.mem_bytes, "released");
        assert_eq!(4096, row.mem_peak_bytes, "peak kept after release");
    }

    /// A method row carries the bytes its call site holds, and the guard
    /// releases them on drop — otherwise the profile would only ever grow.
    #[test]
    fn method_memory_is_reported_and_released() {
        let _guard = serial();
        ProfileSnapshot::reset();
        // A method with no calls has no row at all, so give it one. The
        // sleep keeps the measurement above zero: a zero-length scope is
        // deliberately dropped by `MethodTimer::drop` and the row would not
        // exist (which made this test flaky under parallel execution).
        {
            let _timer = timed_method(Method::WafBodyRead);
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        let held = track_method_memory(Method::WafBodyRead, 4096);

        let snapshot = ProfileSnapshot::collect();
        let row = snapshot
            .methods
            .iter()
            .find(|row| row.method == Method::WafBodyRead.as_str())
            .expect("body_read row");
        assert_eq!(4096, row.mem_bytes);
        assert!((row.mem_share - 1.0).abs() < 1e-9);
        let module = snapshot
            .modules
            .iter()
            .find(|row| row.module == "waf_body")
            .expect("waf_body row");
        assert_eq!(4096, module.mem_bytes, "method memory rolls up");

        drop(held);
        let snapshot = ProfileSnapshot::collect();
        let row = snapshot
            .methods
            .iter()
            .find(|row| row.method == Method::WafBodyRead.as_str())
            .expect("the row survives, its memory does not");
        assert_eq!(0, row.mem_bytes);
        assert_eq!(0, snapshot.modules[Module::WafBody.index()].mem_bytes);
    }

    /// A method row's slot, its snapshot name and its module must all line up
    /// with [`Method::ALL`]: the array index *is* the identity here, so a
    /// misordered variant would silently attribute one call site's time to
    /// another's name.
    #[test]
    fn method_indices_are_stable_and_unique() {
        assert_eq!(Method::ALL.len(), 21);
        let mut names = std::collections::HashSet::new();
        for (index, method) in Method::ALL.iter().enumerate() {
            assert_eq!(
                method.index(),
                index,
                "Method::ALL must be in discriminant order at {}",
                method.as_str()
            );
            assert!(names.insert(method.as_str()), "duplicate method name");
            assert_eq!(
                method.module().index(),
                Module::ALL
                    .iter()
                    .position(|module| module == &method.module())
                    .expect("module is listed in Module::ALL"),
                "module slot must match the module's position"
            );
        }

        // The roll-up each call site reports into, one by one: this is the
        // contract the `/system/profile` module table relies on.
        assert_eq!(Method::ProxyRequestFilter.module(), Module::Proxy);
        assert_eq!(Method::WafHandleRequest.module(), Module::Waf);
        assert_eq!(Method::CacheHandleRequest.module(), Module::Cache);
        assert_eq!(Method::PluginRewrite.module(), Module::Plugin);
        assert_eq!(Method::DbPersistHeartbeat.module(), Module::Db);
        assert_eq!(Method::ControlHttp.module(), Module::Control);
        assert_eq!(Method::Other.module(), Module::Other);

        // Names are the ones the string-keyed table published, so existing
        // dashboards keep matching rows.
        assert_eq!(
            Method::ProxyRequestFilter.as_str(),
            "proxy::request_filter"
        );
        assert_eq!(Method::WafHandleRequest.as_str(), "waf::handle_request");
        assert_eq!(
            Method::CacheHandleRequest.as_str(),
            "cache::handle_request"
        );
        assert_eq!(Method::PluginRewrite.as_str(), "plugin::rewrite");
        assert_eq!(
            Method::DbPersistHeartbeat.as_str(),
            "db::persist_heartbeat"
        );
        assert_eq!(Method::ControlHttp.as_str(), "control::http");
    }

    /// A module's slot is its discriminant, so `Module::ALL` must be complete
    /// and in order: the tables are sized from it, a forgotten variant would
    /// index past the end on the request path, and a misordered one would
    /// attribute its time to another module's row.
    #[test]
    fn module_all_covers_every_slot_in_order() {
        assert_eq!(MODULES.len(), Module::ALL.len());
        for (index, module) in Module::ALL.iter().enumerate() {
            assert_eq!(
                module.index(),
                index,
                "{} is out of discriminant order",
                module.key()
            );
        }
        // The last discriminant has a slot: `ALL` did not stop short.
        assert_eq!(
            Module::ALL.len(),
            Module::HttpClient.index() + 1,
            "Module::ALL is missing a variant; MODULES would be indexed out of bounds"
        );
        // The method table is sized the same way.
        assert_eq!(METHODS.len(), Method::ALL.len());
        assert_eq!(
            Method::ALL.len(),
            Method::ProxyUpstreamConnect.index() + 1,
            "Method::ALL is missing a variant; METHODS would be indexed out of bounds"
        );
    }

    /// One timer, two rows: the module total must be exactly the sum of the
    /// methods that rolled up into it — otherwise `control` would either lose
    /// the handler time or double it (the bug the double instrumentation had).
    #[test]
    fn module_totals_equal_the_sum_of_its_methods() {
        let _guard = serial();
        ProfileSnapshot::reset();
        for _ in 0..3 {
            let _timer = timed_method(Method::ControlHttp);
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        let snapshot = ProfileSnapshot::collect();
        let control = snapshot
            .modules
            .iter()
            .find(|row| row.module == "control")
            .expect("control row");
        let rows: Vec<&MethodView> = snapshot
            .methods
            .iter()
            .filter(|row| row.method == Method::ControlHttp.as_str())
            .collect();
        assert_eq!(rows.len(), 1, "one row per method, not one per call");
        assert_eq!(control.calls, 3);
        assert_eq!(rows[0].calls, control.calls);
        assert!((rows[0].elapsed_ms - control.elapsed_ms).abs() < 1e-9);
        // Nothing else was timed, so control is all of the attributed time.
        assert!((control.elapsed_share - 1.0).abs() < 1e-9);
    }

    #[test]
    fn method_rows_are_sorted_and_capped() {
        let _guard = serial();
        ProfileSnapshot::reset();
        // The method set is closed, so the cap can only ever be approached.
        // Assert the invariant that keeps it unreachable instead of pushing
        // 50 fake names through the table.
        assert!(
            Method::ALL.len() <= ProfileSnapshot::MAX_METHODS,
            "MAX_METHODS must cover every instrumented method"
        );
        for method in [
            Method::ProxyRequestFilter,
            Method::WafHandleRequest,
            Method::CacheHandleRequest,
        ] {
            let _timer = timed_method(method);
            // Every call site needs a non-zero measurement: `Drop` skips a
            // timer that stops inside the same clock tick.
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        let snapshot = ProfileSnapshot::collect();
        assert_eq!(snapshot.methods.len(), 3);
        // Non-increasing by construction; asserting the order rather than a
        // particular winner keeps the test off the scheduler.
        let mut previous = f64::INFINITY;
        for row in &snapshot.methods {
            assert!(row.elapsed_ms <= previous, "rows are hottest-first");
            assert_eq!(row.elapsed_ms, row.cpu_ms);
            assert_eq!(row.elapsed_share, row.cpu_share);
            assert!(row.calls >= 1);
            previous = row.elapsed_ms;
        }
        // A method that never ran gets no row.
        assert!(snapshot
            .methods
            .iter()
            .all(|row| row.method != Method::Other.as_str()));
    }
}
