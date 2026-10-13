//! Crash-safe persistence primitives for the agent's rule cache.
//!
//! Every cache file is written through [`write_atomic`]: the payload lands in
//! a same-directory temp file (same filesystem, so the final rename is
//! atomic), is fsynced, and is then renamed over the destination. A crash or
//! power loss can therefore leave the previous snapshot intact, but never a
//! half-written file under the real name.
//!
//! [`CacheHealth`] tracks the outcome of the latest disk load so the
//! heartbeat can report a degraded cache instead of failing silently.

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use anyhow::Context;

/// Format version stamped into `metadata.json` and checked on load.
///
/// Bump when the on-disk snapshot layout changes incompatibly; an agent that
/// reads a *higher* version discards the snapshot and rebuilds from the
/// control plane rather than misreading the newer layout. Lower versions are
/// rejected too — there is no down-migration; the control plane re-push
/// overwrites such snapshots on the next sync.
pub const CACHE_FORMAT_VERSION: u32 = 1;

/// Uniqueness for temp file names so two `write_atomic` calls in the same
/// process can never target the same temp path, even unsynchronized.
static TEMP_SEQ: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Writes `bytes` to `path` atomically: temp file in the same directory,
/// fsync, rename over the destination, then a directory fsync so the rename
/// itself survives a power cut.
///
/// The temp file name embeds the pid and a sequence number so a stale temp
/// file left by a crashed process can never collide with a live one; a
/// failed rename removes it.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::sync::atomic::Ordering;

    let dir = path
        .parent()
        .context(format!("{:?} has no parent directory", path))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("cache-file");
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp =
        dir.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));

    let result = (|| -> anyhow::Result<()> {
        let mut file = std::fs::File::create(&tmp)
            .with_context(|| format!("creating temp file {:?}", tmp))?;
        file.write_all(bytes)
            .with_context(|| format!("writing temp file {:?}", tmp))?;
        file.sync_all()
            .with_context(|| format!("fsyncing temp file {:?}", tmp))?;
        drop(file);
        std::fs::rename(&tmp, path)
            .with_context(|| format!("renaming {:?} to {:?}", tmp, path))?;
        Ok(())
    })();

    if let Err(err) = result {
        // The original error matters more; clearing the temp file is
        // best-effort housekeeping.
        if let Err(cleanup) = std::fs::remove_file(&tmp) {
            tracing::debug!(file = %tmp.display(), error = %cleanup, "failed to remove temp file");
        }
        return Err(err);
    }

    // Best-effort: the rename is already ordered before any later write on
    // the same handle, and some filesystems reject directory fsync.
    match std::fs::File::open(dir) {
        Ok(dir_handle) => {
            if let Err(err) = dir_handle.sync_all() {
                tracing::debug!(dir = %dir.display(), error = %err, "directory fsync unsupported");
            }
        },
        Err(err) => {
            tracing::debug!(dir = %dir.display(), error = %err, "could not reopen directory for fsync");
        },
    }

    Ok(())
}

/// Returns an error when the metadata stamps a format this build cannot read.
pub fn check_format_version(stamped: u32) -> Result<(), String> {
    if stamped == CACHE_FORMAT_VERSION {
        Ok(())
    } else {
        Err(format!(
            "cache format version {stamped} is not supported (this build reads {CACHE_FORMAT_VERSION})"
        ))
    }
}

/// CRC32 of a snapshot payload, matching the stamp written into metadata.
pub fn content_crc32(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

/// True when the payload length and CRC both match the metadata stamps.
pub fn content_matches(
    bytes: &[u8],
    expected_crc: u32,
    expected_len: u64,
) -> bool {
    bytes.len() as u64 == expected_len && content_crc32(bytes) == expected_crc
}

/// Where the in-memory rules last came from.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum LoadSource {
    /// No snapshot on disk (fresh node, or every snapshot failed validation).
    #[default]
    Fresh,
    /// Loaded from the primary `sites.json`.
    Disk,
    /// Loaded from the `sites.json.bak` roll-over after the primary failed.
    Backup,
}

impl LoadSource {
    pub fn as_str(self) -> &'static str {
        match self {
            LoadSource::Fresh => "fresh",
            LoadSource::Disk => "disk",
            LoadSource::Backup => "backup",
        }
    }
}

impl fmt::Display for LoadSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of the latest cache load, for the heartbeat and logging.
#[derive(Debug)]
pub struct CacheHealth {
    healthy: AtomicBool,
    source: Mutex<LoadSource>,
    reason: Mutex<Option<String>>,
}

/// Point-in-time copy of [`CacheHealth`].
#[derive(Debug, Clone)]
pub struct CacheHealthStatus {
    pub healthy: bool,
    pub source: LoadSource,
    pub reason: Option<String>,
}

impl Default for CacheHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheHealth {
    pub fn new() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            source: Mutex::new(LoadSource::Fresh),
            reason: Mutex::new(None),
        }
    }

    /// Records the outcome of the latest load attempt.
    ///
    /// `healthy` stays true for a backup restore (the mechanism worked; the
    /// reason string carries the degraded detail) and false only when no
    /// usable snapshot could be loaded at all.
    pub fn record(
        &self,
        healthy: bool,
        source: LoadSource,
        reason: Option<String>,
    ) {
        self.healthy.store(healthy, Ordering::Relaxed);
        if let Ok(mut slot) = self.source.lock() {
            *slot = source;
        }
        if let Ok(mut slot) = self.reason.lock() {
            *slot = reason;
        }
    }

    pub fn status(&self) -> CacheHealthStatus {
        CacheHealthStatus {
            healthy: self.healthy.load(Ordering::Relaxed),
            source: self
                .source
                .lock()
                .map(|source| *source)
                .unwrap_or_default(),
            reason: self.reason.lock().ok().and_then(|reason| reason.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_file_without_temp_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sites.json");

        write_atomic(&path, b"hello").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "temp file must be gone: {leftovers:?}");
    }

    #[test]
    fn atomic_write_replaces_previous_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sites.json");

        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn atomic_write_cleans_temp_file_when_rename_fails() {
        let dir = tempfile::tempdir().unwrap();

        // Simulate a failed rename: point the destination at a non-empty
        // directory so rename cannot replace it, then confirm the temp file
        // was cleaned up. (An *empty* directory would let the rename through
        // on macOS, so the directory must be occupied.)
        let dest = dir.path().join("occupied-dir");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("occupant"), b"x").unwrap();

        let err = write_atomic(&dest, b"x").unwrap_err();
        assert!(err.to_string().contains("renaming"), "unexpected: {err}");
        let leftovers: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(
            leftovers.len() == 1,
            "only the occupied directory must remain: {leftovers:?}"
        );
        let only = leftovers[0].as_ref().unwrap();
        assert!(
            only.file_name().to_string_lossy().starts_with("occupied"),
            "unexpected entry: {:?}",
            only.file_name()
        );
    }

    #[test]
    fn atomic_write_reports_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-such-subdir").join("sites.json");
        let err = write_atomic(&path, b"x").unwrap_err();
        assert!(
            err.to_string().contains("creating temp file"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn format_version_accepts_current_and_rejects_other() {
        assert!(check_format_version(CACHE_FORMAT_VERSION).is_ok());
        let err = check_format_version(CACHE_FORMAT_VERSION + 999).unwrap_err();
        assert!(err.contains("not supported"));
    }

    #[test]
    fn content_check_detects_single_byte_corruption() {
        let payload = b"{\"sites\":{}}".to_vec();
        let crc = content_crc32(&payload);
        let len = payload.len() as u64;

        assert!(content_matches(&payload, crc, len));

        let mut torn = payload.clone();
        torn.truncate(torn.len() - 1);
        assert!(
            !content_matches(&torn, crc, len),
            "torn write must mismatch"
        );

        let mut flipped = payload.clone();
        flipped[0] ^= 0x01;
        assert!(
            !content_matches(&flipped, crc, len),
            "flipped byte must mismatch"
        );
    }

    #[test]
    fn health_tracks_load_outcomes() {
        let health = CacheHealth::new();
        assert!(health.status().healthy);
        assert_eq!(health.status().source, LoadSource::Fresh);

        health.record(
            true,
            LoadSource::Backup,
            Some("restored from backup".to_string()),
        );
        let status = health.status();
        assert!(status.healthy);
        assert_eq!(status.source, LoadSource::Backup);
        assert_eq!(status.reason.as_deref(), Some("restored from backup"));

        health.record(false, LoadSource::Fresh, Some("unusable".to_string()));
        let status = health.status();
        assert!(!status.healthy);
        assert_eq!(status.source, LoadSource::Fresh);
        assert_eq!(status.reason.as_deref(), Some("unusable"));
    }

    #[test]
    fn health_clears_reason_on_clean_load() {
        let health = CacheHealth::new();
        health.record(false, LoadSource::Fresh, Some("broken".to_string()));
        health.record(true, LoadSource::Disk, None);

        let status = health.status();
        assert!(status.healthy);
        assert_eq!(status.source, LoadSource::Disk);
        assert_eq!(status.reason, None);
    }
}
