//! Read-only system observation for PingWAF.
//!
//! Two snapshots and one admission floor:
//!
//! * [`cpu_snapshot`] — this process's CPU usage and the machine average
//!   (sysinfo, 1 s reuse so concurrent pollers share one refresh).
//! * [`memory_snapshot`] — process RSS/virtual, host RAM, and the container
//!   memory accounting when a cgroup limit applies.
//! * [`memory_guard`] — best-effort available-memory estimation and the
//!   admission floor callers can gate expensive work on.
//!
//! There is deliberately no sampling, no flamegraph, no heap dump and no
//! dependency on an external profiler here: this crate only reads counters
//! the operating system already keeps. CPU/memory attribution by module and
//! method lives in `pingwaf-profiler`.

pub mod cgroup;
pub mod cpu;
pub mod memory;
pub mod memory_guard;

pub use cpu::{cpu_snapshot, CpuLiveStats};
pub use memory::{memory_snapshot, MemorySnapshot};
pub use memory_guard::{
    available_bytes, ensure_admission, memory_pressure_now, total_bytes, Error,
    MIN_AVAILABLE_BYTES,
};
