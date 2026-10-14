//! Container (cgroup) memory detection for the memory snapshot.
//!
//! `docker stats` and every other container runtime report the *cgroup*
//! numbers, not the host totals that `/proc/meminfo` exposes inside the
//! container. Before this module the snapshot's `used/total_memory_bytes`
//! came from sysinfo — which reads `/proc/meminfo` and therefore shows the
//! *host's* RAM even inside a container — so the dashboard disagreed with
//! `docker stats`. This module reads the cgroup filesystem (v2 first, then
//! v1) so the snapshot can carry the same figures `docker stats` does.
//!
//! All parsers are pure functions, unit-tested on every platform; only the
//! file reads in [`container_memory`] are Linux-only.

use serde::{Deserialize, Serialize};

/// Which cgroup hierarchy version provided the numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupVersion {
    /// The legacy per-controller hierarchy (`memory.usage_in_bytes` etc.).
    V1,
    /// The unified hierarchy (`memory.current` / `memory.max`).
    V2,
}

impl CgroupVersion {
    /// Stable scope label used by the snapshot JSON and the frontend.
    pub fn scope_label(self) -> &'static str {
        match self {
            CgroupVersion::V1 => "cgroup_v1",
            CgroupVersion::V2 => "cgroup_v2",
        }
    }
}

/// Container memory figures as reported by the cgroup filesystem — the same
/// numbers `docker stats` shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerMemory {
    /// Hierarchy version the numbers came from.
    pub version: CgroupVersion,
    /// Current usage: v2 `memory.current`, v1 `memory.usage_in_bytes`.
    pub used_bytes: u64,
    /// Configured limit: v2 `memory.max`, v1 `memory.limit_in_bytes`.
    /// `None` when the cgroup has no limit set.
    pub limit_bytes: Option<u64>,
}

/// cgroup v1 writes "infinity" (or a u64 sentinel close to `u64::MAX`) when
/// no limit is configured; anything at or above half the address space is
/// treated as unlimited.
const V1_UNLIMITED_FLOOR: u64 = u64::MAX / 2;

/// Parses a whitespace-only u64 payload (`"12345\n"` → `12345`).
fn parse_cgroup_u64(content: &str) -> Option<u64> {
    content.trim().parse::<u64>().ok()
}

/// Parses cgroup v2 `memory.max`: `"max"` means no limit, a number is the
/// limit in bytes.
pub fn parse_v2_limit(content: &str) -> Option<u64> {
    let trimmed = content.trim();
    if trimmed.eq_ignore_ascii_case("max") {
        return None;
    }
    parse_cgroup_u64(trimmed)
}

/// Parses cgroup v1 `memory.limit_in_bytes`: `"infinity"` (or the huge
/// sentinel the kernel writes) means no limit.
pub fn parse_v1_limit(content: &str) -> Option<u64> {
    let trimmed = content.trim();
    if trimmed.eq_ignore_ascii_case("infinity") {
        return None;
    }
    match parse_cgroup_u64(trimmed) {
        Some(n) if n < V1_UNLIMITED_FLOOR => Some(n),
        _ => None,
    }
}

/// Extracts the unified-hierarchy path from `/proc/self/cgroup` content:
/// the line starting with `0::`. Returns `None` on v1-only systems.
///
/// ```text
/// unified_path("0::/\n") == Some("/")
/// unified_path("11:memory:/d\n0::/system.slice/app.scope\n") == Some("/system.slice/app.scope")
/// ```
pub fn unified_path(proc_cgroup: &str) -> Option<&str> {
    for line in proc_cgroup.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(rest);
        }
    }
    None
}

/// Extracts the cgroup v1 path of the `memory` controller from
/// `/proc/self/cgroup` content. The controller list is comma-separated and
/// `memory` must be one of its entries.
///
/// ```text
/// v1_memory_path("11:memory:/docker/abc\n") == Some("/docker/abc")
/// v1_memory_path("3:cpu,blkio:/x\n") == None
/// ```
pub fn v1_memory_path(proc_cgroup: &str) -> Option<&str> {
    for line in proc_cgroup.lines() {
        let mut parts = line.splitn(3, ':');
        // Layout: hierarchy-id : controller-list : cgroup-path
        let _hierarchy = parts.next()?;
        let Some(controllers) = parts.next() else {
            continue;
        };
        let Some(path) = parts.next() else { continue };
        if controllers.split(',').any(|c| c == "memory") {
            return Some(path);
        }
    }
    None
}

/// Reads a file to a trimmed string; `None` on any I/O or UTF-8 failure.
#[cfg(target_os = "linux")]
fn read_trimmed(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

/// Joins a cgroup root mount with a relative cgroup path from
/// `/proc/self/cgroup`, tolerating both `/` and `/nested/path` forms.
#[cfg(target_os = "linux")]
fn cgroup_dir(root: &str, path: &str) -> std::path::PathBuf {
    std::path::Path::new(root).join(path.trim_start_matches('/'))
}

/// Reads the container's memory figures from the cgroup filesystem.
///
/// Returns `None` when the process is not inside a memory-limited cgroup:
/// non-Linux platforms, unreadable cgroup files, or a cgroup with **no
/// memory limit set** (v2 `memory.max = max`, v1 `limit_in_bytes =
/// infinity`). Without a limit the cgroup numbers are just the host's
/// numbers, which the snapshot's host-scoped fields already carry —
/// reporting them twice under a container label would mislead the
/// dashboard the same way the original bug did.
pub fn container_memory() -> Option<ContainerMemory> {
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
    #[cfg(target_os = "linux")]
    {
        container_memory_linux()
    }
}

#[cfg(target_os = "linux")]
fn container_memory_linux() -> Option<ContainerMemory> {
    let proc_cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;

    // Unified hierarchy first: every current distro mounts v2 at
    // /sys/fs/cgroup; containers usually see it as their own root.
    if let Some(path) = unified_path(&proc_cgroup) {
        for root in [
            cgroup_dir("/sys/fs/cgroup", path),
            // Private cgroup namespace: /proc/self/cgroup says "/" but some
            // runtimes still mount the subtree elsewhere — try the plain
            // root as a fallback.
            std::path::PathBuf::from("/sys/fs/cgroup"),
        ] {
            let used_path = root.join("memory.current");
            let Some(used_raw) = read_trimmed(&used_path) else {
                continue;
            };
            let Some(limit_raw) = read_trimmed(&root.join("memory.max")) else {
                continue;
            };
            // A limit of "max" means the container (or the whole host) has
            // no memory boundary: fall through to host scope, not a fake
            // container figure.
            let Some(limit) = parse_v2_limit(&limit_raw) else {
                continue;
            };
            let used = parse_cgroup_u64(&used_raw)?;
            return Some(ContainerMemory {
                version: CgroupVersion::V2,
                used_bytes: used,
                limit_bytes: Some(limit),
            });
        }
    }

    // Legacy per-controller hierarchy.
    if let Some(path) = v1_memory_path(&proc_cgroup) {
        for root in [
            cgroup_dir("/sys/fs/cgroup/memory", path),
            cgroup_dir("/sys/fs/cgroup", path),
        ] {
            let Some(used_raw) =
                read_trimmed(&root.join("memory.usage_in_bytes"))
            else {
                continue;
            };
            let Some(limit_raw) =
                read_trimmed(&root.join("memory.limit_in_bytes"))
            else {
                continue;
            };
            let Some(limit) = parse_v1_limit(&limit_raw) else {
                continue;
            };
            let used = parse_cgroup_u64(&used_raw)?;
            return Some(ContainerMemory {
                version: CgroupVersion::V1,
                used_bytes: used,
                limit_bytes: Some(limit),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_limit_parsing() {
        assert_eq!(parse_v2_limit("max\n"), None);
        assert_eq!(parse_v2_limit("MAX"), None);
        assert_eq!(parse_v2_limit("1073741824\n"), Some(1_073_741_824));
        assert_eq!(parse_v2_limit("0"), Some(0));
        assert_eq!(parse_v2_limit("not a number"), None);
    }

    #[test]
    fn v1_limit_parsing() {
        assert_eq!(parse_v1_limit("infinity\n"), None);
        // The kernel's unlimited sentinel for v1 is a huge number; it must
        // not be reported as a real limit.
        assert_eq!(parse_v1_limit(&format!("{}\n", u64::MAX)), None);
        assert_eq!(parse_v1_limit("536870912\n"), Some(536_870_912));
    }

    #[test]
    fn unified_path_extraction() {
        assert_eq!(unified_path("0::/\n"), Some("/"));
        assert_eq!(
            unified_path("11:memory:/docker/abc\n0::/system.slice/app.scope\n"),
            Some("/system.slice/app.scope"),
        );
        // No v2 hierarchy present.
        assert_eq!(unified_path("11:memory:/docker/abc\n"), None);
        assert_eq!(unified_path(""), None);
    }

    #[test]
    fn v1_memory_path_extraction() {
        assert_eq!(
            v1_memory_path("11:memory:/docker/abc\n"),
            Some("/docker/abc")
        );
        // Multi-controller line where memory is one of them.
        assert_eq!(
            v1_memory_path("3:cpu,memory:/user.slice\n"),
            Some("/user.slice")
        );
        // memory not in the controller list.
        assert_eq!(v1_memory_path("3:cpu,blkio:/x\n"), None);
        // Malformed lines are skipped, not fatal.
        assert_eq!(v1_memory_path("garbage\n11:memory:/ok\n"), Some("/ok"));
    }

    #[test]
    fn scope_labels_are_stable() {
        assert_eq!(CgroupVersion::V1.scope_label(), "cgroup_v1");
        assert_eq!(CgroupVersion::V2.scope_label(), "cgroup_v2");
    }

    // Off-Linux the answer is always "not a container".
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn container_memory_absent_off_linux() {
        assert!(container_memory().is_none());
    }
}
