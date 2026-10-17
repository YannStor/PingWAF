//! Memory admission gate for captures.
//!
//! The 2026-10-17 incident showed that on a 2GB box a single capture's
//! encode phase could spike RSS past what the host could bear and get the
//! container OOM-killed — the 40% CPU guard never sees memory. This module
//! refuses to start (or continues) a capture when the available-memory
//! floor is crossed.
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

fn cgroup_v2() -> Option<u64> {
    let max = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?;
    let max = parse_limit(&max)?;
    let current: u64 = std::fs::read_to_string("/sys/fs/cgroup/memory.current")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    max.checked_sub(current)
}

fn cgroup_v1() -> Option<u64> {
    let limit =
        std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
            .ok()?;
    let limit = parse_limit(&limit)?;
    let usage: u64 =
        std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")
            .ok()?
            .trim()
            .parse()
            .ok()?;
    limit.checked_sub(usage)
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
pub fn ensure_admission() -> Result<(), crate::ProfileError> {
    match available_bytes() {
        Some(available) if available < MIN_AVAILABLE_BYTES => {
            Err(crate::ProfileError::MemoryPressure)
        },
        _ => Ok(()),
    }
}

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
    fn pressure_threshold_is_the_documented_floor() {
        assert_eq!(MIN_AVAILABLE_BYTES, 400 * 1024 * 1024);
    }
}
