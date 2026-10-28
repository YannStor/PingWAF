//! Memory admission floor.
//!
//! Best-effort available-memory estimation callers can gate work on: the
//! 2026-10-17 incident showed that on a 2GB box an expensive in-process
//! operation could spike RSS past what the host could bear and get the
//! container OOM-killed. [`ensure_admission`] refuses start when the floor
//! is already crossed; [`memory_pressure_now`] answers the same question for
//! long-running callers that want to bail out mid-way.
//!
//! Detection order: cgroup v2 (`memory.max` / `memory.current` — the
//! container's own limit), then cgroup v1, then the host's `MemAvailable`
//! via sysinfo. `None` (no limit discoverable) means "allow".

/// Minimum bytes that must be available for a capture to be admitted
/// (started) or allowed to continue (watchdog soft floor).
pub const MIN_AVAILABLE_BYTES: u64 = 400 * 1024 * 1024;

/// Best-effort available-memory estimate in bytes; `None` when no limit
/// can be discovered (admission then allows).
pub fn available_bytes() -> Option<u64> {
    cgroup_v2().or_else(cgroup_v1).or_else(sysinfo_available)
}

/// Memory ceiling in bytes: the cgroup limit when one is set, otherwise
/// the host total. Used by the allocator retention policy to size its
/// purge delay; `None` when nothing is discoverable.
pub fn total_bytes() -> Option<u64> {
    cgroup_v2_limit()
        .or_else(cgroup_v1_limit)
        .or_else(host_total)
}

fn cgroup_v2_limit() -> Option<u64> {
    parse_limit(&std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?)
}

fn cgroup_v1_limit() -> Option<u64> {
    parse_limit(
        &std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
            .ok()?,
    )
}

fn host_total() -> Option<u64> {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    let total = sys.total_memory();
    (total > 0).then_some(total)
}

fn cgroup_v2() -> Option<u64> {
    let max = cgroup_v2_limit()?;
    let current: u64 = std::fs::read_to_string("/sys/fs/cgroup/memory.current")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    // `current > max` means the cgroup is already over its limit. Returning
    // `None` here made the caller fall back to host-wide free memory, which
    // reported "plenty" exactly when the container was about to be killed.
    Some(max.saturating_sub(current))
}

fn cgroup_v1() -> Option<u64> {
    let limit = cgroup_v1_limit()?;
    let usage: u64 =
        std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")
            .ok()?
            .trim()
            .parse()
            .ok()?;
    Some(limit.saturating_sub(usage))
}

fn sysinfo_available() -> Option<u64> {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    Some(sys.available_memory())
}

/// `"max"` (cgroup v2 unlimited) and absurd v1 sentinel values mean "no
/// limit" → `None`; anything else parses as a byte count.
fn parse_limit(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed == "max" {
        return None;
    }
    let value: u64 = trimmed.parse().ok()?;
    // v1 encodes "unlimited" as a value near i64::MAX.
    if value > (1_u64 << 60) {
        None
    } else {
        Some(value)
    }
}

/// Whether the memory soft floor is crossed right now — the watchdog
/// aborts an in-flight capture when this holds.
pub fn memory_pressure_now() -> bool {
    matches!(available_bytes(), Some(available) if available < MIN_AVAILABLE_BYTES)
}

/// Admission check for starting a capture: below the floor the encode
/// phase after the window would push the host into an OOM kill.
pub fn ensure_admission() -> Result<(), Error> {
    match available_bytes() {
        Some(available) if available < MIN_AVAILABLE_BYTES => {
            Err(Error::MemoryPressure)
        },
        _ => Ok(()),
    }
}

/// Admission refusal. Deliberately a value type: callers map it onto their
/// own response shape (HTTP 503, a plugin error string, a log line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Available memory is below [`MIN_AVAILABLE_BYTES`].
    MemoryPressure,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MemoryPressure => write!(
                f,
                "memory pressure: available memory is below the admission floor"
            ),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_limit_handles_sentinels() {
        assert_eq!(parse_limit("max"), None);
        assert_eq!(parse_limit("  max \n"), None);
        // v1 "unlimited" sentinel (near i64::MAX).
        assert_eq!(parse_limit("9223372036854771712"), None);
        assert_eq!(parse_limit("2147483648"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_limit("not-a-number"), None);
    }

    #[test]
    fn available_bytes_returns_a_reading() {
        // Smoke: on any machine one of the three detectors answers.
        // A `None` result is also valid (no cgroup + sysinfo failure),
        // but a value must be sane when present.
        if let Some(available) = available_bytes() {
            assert!(available > 0);
        }
    }

    #[test]
    fn total_bytes_is_plausible() {
        if let Some(total) = total_bytes() {
            assert!(total > 16 * 1024 * 1024, "ceiling {total} is absurd");
        }
    }

    #[test]
    fn pressure_threshold_is_the_documented_floor() {
        assert_eq!(MIN_AVAILABLE_BYTES, 400 * 1024 * 1024);
    }
}
