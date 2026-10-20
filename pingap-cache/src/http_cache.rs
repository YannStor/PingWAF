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

use super::LOG_TARGET;
use super::{Error, PAGE_SIZE, Result};
use crate::get_file_backends;
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use pingap_core::BackgroundTask;
use pingap_core::Error as ServiceError;
use pingora::cache::key::CacheHashKey;
use pingora::cache::storage::MissFinishType;
use pingora::cache::storage::{HandleHit, HandleMiss};
use pingora::cache::trace::SpanHandle;
use pingora::cache::{
    CacheKey, CacheMeta, HitHandler, MissHandler, PurgeOutcome, PurgeTarget,
    PurgeType, Storage,
};
use std::any::Any;
use std::io::SeekFrom;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing::{error, info};

/// The two halves of a serialized `CacheMeta`. `Bytes` so that parsing a
/// cache file and cloning an object out of the memory layer copy nothing.
type BinaryMeta = (Bytes, Bytes);

/// Represents a cached object containing metadata and body content
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CacheObject {
    /// Tuple containing two metadata byte vectors (meta0, meta1)
    pub meta: BinaryMeta,
    /// The actual cached content
    pub body: Bytes,
}

// Maximum size for a single cached object (40MB)
static MAX_OBJECT_CACHE_SIZE: usize = 10 * 1024 * PAGE_SIZE;

impl CacheObject {
    pub fn get_weight(&self) -> u16 {
        let size = self.body.len() + self.meta.0.len() + self.meta.1.len();
        if size <= PAGE_SIZE {
            return 1;
        }
        if size >= MAX_OBJECT_CACHE_SIZE {
            return u16::MAX;
        }
        (size / PAGE_SIZE) as u16
    }
}

/// Bytes of a cache file header: two `u32` meta lengths.
pub(crate) const META_SIZE_LENGTH: usize = 8;

/// The `(meta0, meta1)` lengths declared by a cache file header.
///
/// One definition for both readers — the whole-file parser below and the
/// header-only reader the streaming path uses — so they cannot disagree on
/// what a valid header is or on where the body starts (`META_SIZE_LENGTH +
/// meta0 + meta1`).
pub(crate) fn parse_meta_sizes(header: &[u8]) -> Result<(usize, usize)> {
    if header.len() < META_SIZE_LENGTH {
        return Err(Error::Invalid {
            message: format!(
                "cache object is truncated, {} bytes is shorter than the header",
                header.len()
            ),
        });
    }
    let meta0 =
        u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let meta1 =
        u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    Ok((meta0 as usize, meta1 as usize))
}

/// Creates a CacheObject from bytes with the following format:
/// - First 4 bytes: meta0 size (u32)
/// - Next 4 bytes: meta1 size (u32)
/// - Next meta0_size bytes: meta0 data
/// - Next meta1_size bytes: meta1 data
/// - Remaining bytes: body data
///
/// Fallible on purpose: the bytes come from a cache file, and a cache file can
/// be shorter than its header claims (a crash or a full disk mid write). The
/// declared sizes MUST be checked against what is actually there -
/// `Bytes::split_to` panics on out of range, and with `panic = "abort"` in the
/// release profile that panic would take the whole process down on every hit
/// of the poisoned key, restart after restart, until someone deletes the file.
impl TryFrom<Bytes> for CacheObject {
    type Error = Error;
    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        let (meta0_size, meta1_size) = parse_meta_sizes(&value)?;
        // Zero-copy: the header is dropped from the front, the rest is shared.
        let mut data = value.slice(META_SIZE_LENGTH..);
        let meta_size = meta0_size.saturating_add(meta1_size);
        if meta_size > data.len() {
            return Err(Error::Invalid {
                message: format!(
                    "cache object is truncated, meta claims {meta_size} bytes but only {} are present",
                    data.len()
                ),
            });
        }

        let meta0 = data.split_to(meta0_size);
        let meta1 = data.split_to(meta1_size);

        Ok(Self {
            meta: (meta0, meta1),
            body: data,
        })
    }
}
/// Converts a CacheObject into bytes with the following format:
/// - First 4 bytes: meta0 size (u32)
/// - Next 4 bytes: meta1 size (u32)
/// - Next meta0_size bytes: meta0 data
/// - Next meta1_size bytes: meta1 data
/// - Remaining bytes: body data
impl From<CacheObject> for Bytes {
    fn from(value: CacheObject) -> Self {
        let meta_size =
            value.meta.0.len() + value.meta.1.len() + META_SIZE_LENGTH;
        let mut buf = BytesMut::with_capacity(value.body.len() + meta_size);
        buf.put_u32(value.meta.0.len() as u32);
        buf.put_u32(value.meta.1.len() as u32);
        // `put_slice`, not `extend`: `Extend` goes through the byte
        // iterator and copies one byte at a time.
        buf.put_slice(&value.meta.0);
        buf.put_slice(&value.meta.1);
        buf.put_slice(&value.body);

        buf.into()
    }
}

/// Largest body still handed over as one in-memory `Bytes`.
///
/// A hit above this is streamed off the disk instead of being read into the
/// heap: `fs::read` + `Bytes::from` costs the object's size in peak memory per
/// concurrent hit, so ten clients on a 200 MB file means 2 GB of heap that the
/// cache "does not hold". Below the threshold the file is small enough that one
/// allocation is cheaper than a seek plus a chunk loop.
pub const INLINE_MAX_BYTES: usize = 256 * 1024;

/// Bytes a streamed hit reads per `read_body` call.
///
/// Bounds the buffer a served hit holds: pingora writes each chunk downstream
/// before asking for the next one, so the peak is one chunk, not one object.
pub const STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Byte gauges of one storage backend, mirrored into the process-wide
/// `pingwaf_profiler::Module::Cache` row.
///
/// The attribution row is per process while one process can host several file
/// backends (one per configured directory). Each backend therefore keeps its
/// own exact figures and contributes **deltas** to the process-wide totals:
/// every backend publishing its own absolute figure would let the last writer
/// win and show one directory's usage as the whole cache's.
///
/// `index_bytes` and `in_flight_bytes` are signed because they are adjusted in
/// both directions; the published figure clamps at zero, so a racing
/// subtraction cannot show an absurd number.
///
/// Two instances over the *same* directory would each report that directory's
/// bytes; `new_cache_backend` keeps one backend per directory, so that only
/// happens in tests. Publishing reads the totals and stores them, so two
/// backends publishing at the same instant can transiently publish a stale
/// sum — the next publish corrects it, and a gauge nobody samples twice is
/// not worth a lock.
#[derive(Debug, Default)]
pub struct CacheGauges {
    index_bytes: AtomicI64,
    in_flight_bytes: AtomicI64,
    disk_bytes: AtomicU64,
}

/// Process-wide totals behind `Module::Cache`, adjusted by deltas.
static GLOBAL_INDEX_BYTES: AtomicI64 = AtomicI64::new(0);
static GLOBAL_IN_FLIGHT_BYTES: AtomicI64 = AtomicI64::new(0);
static GLOBAL_DISK_BYTES: AtomicI64 = AtomicI64::new(0);

/// Publishes the process-wide totals to the attribution tables.
///
/// Memory and disk are published separately and never summed together: what
/// the cache holds in the heap and what it holds on the filesystem are two
/// different numbers with two different fixes.
fn publish_cache_row() {
    let index = GLOBAL_INDEX_BYTES.load(Ordering::Relaxed).max(0);
    let in_flight = GLOBAL_IN_FLIGHT_BYTES.load(Ordering::Relaxed).max(0);
    pingwaf_profiler::set_memory(
        pingwaf_profiler::Module::Cache,
        index.saturating_add(in_flight) as u64,
    );
    pingwaf_profiler::set_disk_bytes(
        pingwaf_profiler::Module::Cache,
        GLOBAL_DISK_BYTES.load(Ordering::Relaxed).max(0) as u64,
    );
}

impl CacheGauges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Metadata bytes the backend holds for the objects in its in-process
    /// hot layer (cache key plus both metadata halves).
    pub fn index_bytes(&self) -> u64 {
        self.index_bytes.load(Ordering::Relaxed).max(0) as u64
    }

    /// Bytes of read buffers the backend currently holds.
    pub fn in_flight_bytes(&self) -> u64 {
        self.in_flight_bytes.load(Ordering::Relaxed).max(0) as u64
    }

    /// Bytes the backend currently occupies on disk.
    pub fn disk_bytes(&self) -> u64 {
        self.disk_bytes.load(Ordering::Relaxed)
    }

    /// Adjusts the index gauge, here and in the process-wide total.
    pub(crate) fn add_index(&self, delta: i64) {
        if delta == 0 {
            return;
        }
        self.index_bytes.fetch_add(delta, Ordering::Relaxed);
        GLOBAL_INDEX_BYTES.fetch_add(delta, Ordering::Relaxed);
        publish_cache_row();
    }

    /// Adjusts the in-flight gauge, here and in the process-wide total.
    pub(crate) fn add_in_flight(&self, delta: i64) {
        if delta == 0 {
            return;
        }
        self.in_flight_bytes.fetch_add(delta, Ordering::Relaxed);
        GLOBAL_IN_FLIGHT_BYTES.fetch_add(delta, Ordering::Relaxed);
        publish_cache_row();
    }

    /// Replaces the backend's on-disk footprint. The process-wide total moves
    /// by the difference so several backends sum instead of overwriting each
    /// other.
    pub(crate) fn set_disk(&self, bytes: u64) {
        let bytes = bytes.min(i64::MAX as u64);
        let previous = self.disk_bytes.swap(bytes, Ordering::Relaxed);
        let delta = bytes as i64 - previous.min(i64::MAX as u64) as i64;
        if delta == 0 {
            return;
        }
        GLOBAL_DISK_BYTES.fetch_add(delta, Ordering::Relaxed);
        publish_cache_row();
    }
}

/// Holds `bytes` against a backend's in-flight gauge for as long as it lives.
///
/// Decrementing at the end of the read by hand leaks the figure on every early
/// return, every `?` and every cancelled request — which is exactly the case
/// the gauge exists to make visible. `Drop` is the one path a cancelled future
/// cannot skip.
#[derive(Debug)]
pub struct InFlightGuard {
    gauges: Arc<CacheGauges>,
    bytes: u64,
}

impl InFlightGuard {
    pub(crate) fn new(gauges: Arc<CacheGauges>, bytes: u64) -> Self {
        let bytes = bytes.min(i64::MAX as u64);
        gauges.add_in_flight(bytes as i64);
        Self { gauges, bytes }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.gauges.add_in_flight(-(self.bytes as i64));
    }
}

/// What a cache hit hands back: the body itself, or a handle to where it is.
#[derive(Debug)]
pub enum CachedPayload {
    /// The whole body, already in memory.
    Inline(Bytes),
    /// The body is still on disk. `file` is open and positioned at `offset`,
    /// from where `len` bytes are the body, read in
    /// [`STREAM_CHUNK_BYTES`]-sized pieces.
    Stream {
        file: tokio::fs::File,
        offset: u64,
        len: u64,
        /// Keeps the chunk buffer of this open handle accounted; released
        /// when the hit is dropped, finished or fails.
        in_flight: InFlightGuard,
    },
}

impl CachedPayload {
    /// Body length in bytes.
    pub fn len(&self) -> usize {
        match self {
            Self::Inline(body) => body.len(),
            Self::Stream { len, .. } => {
                usize::try_from(*len).unwrap_or(usize::MAX)
            },
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads the whole body into memory.
    ///
    /// The streaming path exists to avoid this on the request path. It stays
    /// for the callers that need the body as a value — the metadata update
    /// rewrites the object, and the tests compare contents.
    pub(crate) async fn into_bytes(
        self,
        gauges: &Arc<CacheGauges>,
    ) -> Result<Bytes> {
        match self {
            Self::Inline(body) => Ok(body),
            Self::Stream {
                mut file,
                offset,
                len,
                in_flight,
            } => {
                let size = usize::try_from(len).map_err(|_| Error::Invalid {
                    message: format!(
                        "cache object body of {len} bytes does not fit this platform"
                    ),
                })?;
                // What this materialisation is about to hold, on top of the
                // chunk buffer the handle was already charged for.
                let _guard = InFlightGuard::new(Arc::clone(gauges), len);
                drop(in_flight);
                file.seek(SeekFrom::Start(offset))
                    .await
                    .map_err(|e| Error::Io { source: e })?;
                let mut buf = vec![0u8; size];
                file.read_exact(&mut buf)
                    .await
                    .map_err(|e| Error::Io { source: e })?;
                Ok(Bytes::from(buf))
            },
        }
    }
}

/// A cache hit: the stored metadata plus where the body lives.
#[derive(Debug)]
pub struct CachedEntry {
    pub meta: BinaryMeta,
    pub payload: CachedPayload,
}

#[derive(Debug)]
pub struct HttpCacheStats {
    pub reading: u32,
    pub writing: u32,
}

#[derive(Debug, Clone)]
pub struct HttpCacheClearStats {
    pub success: i32,
    pub fail: i32,
    pub description: String,
}

/// Storage interface for HTTP caching operations
///
/// This trait defines the core operations needed to implement a storage backend
/// for HTTP caching. Implementations must be both `Send` and `Sync` to support
/// concurrent access.
#[async_trait]
pub trait HttpCacheStorage: Sync + Send {
    /// Retrieves a cached object from storage
    /// Returns None if not found or Some(CacheObject) if present
    ///
    /// Always a materialised body: a backend that can stream still reads a
    /// large object into memory here. Use [`Self::get_entry`] on the response
    /// path.
    async fn get(
        &self,
        key: &str,
        namespace: &[u8],
    ) -> Result<Option<CacheObject>>;

    /// Retrieves a cache hit without forcing the body into memory.
    ///
    /// The default wraps [`Self::get`], so a backend with no streaming path
    /// keeps working unchanged; the file backend overrides it to hand back an
    /// open file for bodies above [`INLINE_MAX_BYTES`]. This is the entry
    /// point the pingora `Storage` adapter uses — [`Self::get`] is what
    /// callers that need the bytes as a value still use.
    async fn get_entry(
        &self,
        key: &str,
        namespace: &[u8],
    ) -> Result<Option<CachedEntry>> {
        Ok(self.get(key, namespace).await?.map(|obj| CachedEntry {
            meta: obj.meta,
            payload: CachedPayload::Inline(obj.body),
        }))
    }

    /// Stores a cache object with the given key and namespace
    async fn put(
        &self,
        key: &str,
        namespace: &[u8],
        data: CacheObject,
    ) -> Result<()>;

    /// Removes a cached object from storage.
    ///
    /// # Arguments
    /// * `key` - The unique identifier for the cached object
    /// * `namespace` - The namespace to scope the cache key
    ///
    /// # Returns
    /// * `Result<Option<CacheObject>>` - The removed object if it existed
    async fn remove(
        &self,
        _key: &str,
        _namespace: &[u8],
    ) -> Result<Option<CacheObject>> {
        Ok(None)
    }

    /// Clears cached objects accessed before the specified time.
    ///
    /// # Arguments
    /// * `access_before` - Remove items last accessed before this timestamp
    ///
    /// # Returns
    /// * `Result<HttpCacheClearStats>` - Clear stats
    async fn clear(
        &self,
        _access_before: std::time::SystemTime,
    ) -> Result<HttpCacheClearStats> {
        Ok(HttpCacheClearStats {
            success: -1,
            fail: -1,
            description: "".to_string(),
        })
    }

    /// Removes every cached object in `namespace`.
    ///
    /// Storage keys are hashes, so this is only possible where the namespace
    /// survives as structure - the file backend keeps it as a directory. The
    /// default says "unsupported" (`Ok(None)`) rather than pretending: the
    /// memory backend has no way to enumerate its entries, and a purge that
    /// silently does nothing would leave stale content being served with no
    /// indication why.
    async fn purge_namespace(
        &self,
        _namespace: &str,
    ) -> Result<Option<HttpCacheClearStats>> {
        Ok(None)
    }

    /// Returns current storage statistics.
    ///
    /// # Returns
    /// * `Option<HttpCacheStats>` - Current read/write statistics if available
    fn stats(&self) -> Option<HttpCacheStats> {
        None
    }

    /// Returns the inactive duration for the cache storage.
    ///
    /// # Returns
    /// * `Option<Duration>` - The inactive duration for the cache storage
    fn inactive(&self) -> Option<Duration> {
        None
    }
}

/// Sweeps every file backend's inactive files, once every 60 ticks. A
/// backend whose sweep fails is logged and the others still get theirs.
async fn do_file_storage_clear(count: u32) -> bool {
    if !count.is_multiple_of(60) {
        return false;
    }
    for backend in get_file_backends() {
        let cache = &backend.cache;
        let Some(inactive) = cache.inactive() else {
            continue;
        };
        let Some(access_before) = SystemTime::now().checked_sub(inactive)
        else {
            continue;
        };
        match cache.clear(access_before).await {
            Ok(stats) => info!(
                target: LOG_TARGET,
                success = stats.success,
                fail = stats.fail,
                description = stats.description,
            ),
            Err(e) => error!(
                target: LOG_TARGET,
                error = %e,
                directory = backend.directory.as_deref(),
                "clear cache file fail"
            ),
        }
    }
    true
}

struct StorageClearTask {}

#[async_trait]
impl BackgroundTask for StorageClearTask {
    async fn execute(&self, count: u32) -> Result<bool, ServiceError> {
        Ok(do_file_storage_clear(count).await)
    }
}

pub fn new_storage_clear_service() -> Option<Box<dyn BackgroundTask>> {
    Some(Box::new(StorageClearTask {}))
}

pub struct HttpCache {
    pub directory: Option<String>,
    pub cache: Arc<dyn HttpCacheStorage>,
    pub max_size: u64,
}

impl HttpCache {
    #[inline]
    pub fn stats(&self) -> Option<HttpCacheStats> {
        self.cache.stats()
    }
    pub fn max_size(&self) -> u64 {
        self.max_size
    }
}

/// Where a hit's body comes from.
enum HitBody {
    /// The whole body is in memory; a read hands out a slice of it.
    Inline(Bytes),
    /// The body is still on disk; a read hands out one chunk of it. The
    /// guard is held here so the in-flight budget is released whenever the
    /// hit is dropped, finished or fails.
    Stream {
        file: tokio::fs::File,
        /// Byte offset of the body inside the file.
        offset: u64,
        _in_flight: InFlightGuard,
    },
}

/// Handles cache hits by managing access to cached content
pub struct CompleteHit {
    /// Where the body lives
    body: HitBody,
    /// Total body length; ranges are clamped to it
    len: usize,
    /// Whether the ranged body has been handed out
    done: bool,
    /// Start position for range requests
    range_start: usize,
    /// End position for range requests
    range_end: usize,
    /// Next body byte a streamed read returns, relative to the body start
    position: usize,
    /// A streamed read must reposition the file before it reads. pingora's
    /// `seek` is synchronous and `tokio::fs::File::seek` is not, so the
    /// reposition is deferred to the next (async) `read_body`.
    seek_pending: bool,
}

impl CompleteHit {
    fn new(payload: CachedPayload) -> Self {
        let len = payload.len();
        let body = match payload {
            CachedPayload::Inline(body) => HitBody::Inline(body),
            CachedPayload::Stream {
                file,
                offset,
                len: _,
                in_flight,
            } => HitBody::Stream {
                file,
                offset,
                _in_flight: in_flight,
            },
        };
        Self {
            body,
            len,
            done: false,
            range_start: 0,
            range_end: len,
            position: 0,
            seek_pending: false,
        }
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> Result<()> {
        if start >= self.len {
            return Err(Error::Invalid {
                message: format!(
                    "seek start out of range {start} >= {}",
                    self.len
                ),
            });
        }
        self.range_start = start;
        // end over the actual last byte is allowed, we just need to return the
        // actual bytes; no end means "to the end of the body", so a handler
        // reused for several ranges cannot inherit a stale ceiling.
        self.range_end = match end {
            Some(end) => std::cmp::min(self.len, end),
            None => self.len,
        };
        // seek resets read so that one handler can be used for multiple ranges
        self.done = false;
        self.position = start;
        self.seek_pending = true;
        Ok(())
    }
}

#[async_trait]
impl HandleHit for CompleteHit {
    async fn read_body(&mut self) -> pingora::Result<Option<Bytes>> {
        if self.done {
            return Ok(None);
        }
        match &mut self.body {
            HitBody::Inline(body) => {
                self.done = true;
                Ok(Some(body.slice(self.range_start..self.range_end)))
            },
            HitBody::Stream { file, offset, .. } => {
                if self.seek_pending {
                    file.seek(SeekFrom::Start(
                        offset.saturating_add(self.range_start as u64),
                    ))
                    .await
                    .map_err(|e| Error::Io { source: e })?;
                    self.position = self.range_start;
                    self.seek_pending = false;
                }
                if self.position >= self.range_end {
                    self.done = true;
                    return Ok(None);
                }
                let want =
                    (self.range_end - self.position).min(STREAM_CHUNK_BYTES);
                let mut buf = vec![0u8; want];
                match file.read_exact(&mut buf).await {
                    Ok(_) => {},
                    // The file lost bytes behind our back (purged, evicted,
                    // or rewritten smaller). Ending the body is the same
                    // answer the read path gives a torn file - a shorter
                    // response, not a 5xx on a hit.
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        error!(
                            target: LOG_TARGET,
                            error = %e,
                            "cache file is shorter than its header, end body early"
                        );
                        self.done = true;
                        return Ok(None);
                    },
                    Err(e) => return Err(Error::Io { source: e }.into()),
                }
                self.position += want;
                Ok(Some(Bytes::from(buf)))
            },
        }
    }
    async fn finish(
        self: Box<Self>, // because self is always used as a trait object
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<()> {
        Ok(())
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(
        &mut self,
        start: usize,
        end: Option<usize>,
    ) -> pingora::Result<()> {
        self.seek(start, end)?;
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

/// Handles cache misses by collecting and storing new content
pub struct ObjectMissHandler {
    /// Metadata to store with the cached content
    meta: BinaryMeta,
    /// Buffer for collecting the body content
    body: BytesMut,
    /// Cache key for storing the final object
    key: String,
    /// Primary key for storing the final object
    primary_key: String,
    /// Namespace for storing the final object
    namespace: Vec<u8>,
    /// Reference to the storage backend
    cache: Arc<dyn HttpCacheStorage>,
}

#[async_trait]
impl HandleMiss for ObjectMissHandler {
    async fn write_body(
        &mut self,
        data: bytes::Bytes,
        _eof: bool,
    ) -> pingora::Result<()> {
        self.body.extend_from_slice(&data);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<MissFinishType> {
        let size = self.body.len(); // FIXME: this just body size, also track meta size
        info!(
            target: LOG_TARGET,
            key = self.key,
            primary_key = self.primary_key,
            namespace = std::str::from_utf8(&self.namespace).ok(),
            size,
            "put data to cache"
        );
        let _ = self
            .cache
            .put(
                &self.key,
                &self.namespace,
                CacheObject {
                    meta: self.meta,
                    body: self.body.into(),
                },
            )
            .await?;

        Ok(MissFinishType::Created(size))
    }
}

#[async_trait]
impl Storage for HttpCache {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        let namespace = key.user_tag().as_bytes();
        let hash = key.combined();
        // `get_entry`, not `get`: a body above `INLINE_MAX_BYTES` comes back
        // as an open file and is streamed, so a hit on a large object costs a
        // chunk of memory instead of the object's size.
        let Some(entry) = self.cache.get_entry(&hash, namespace).await? else {
            return Ok(None);
        };
        let meta = CacheMeta::deserialize(&entry.meta.0, &entry.meta.1)?;
        Ok(Some((meta, Box::new(CompleteHit::new(entry.payload)))))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<MissHandler> {
        // Size the body buffer from Content-Length when there is one, capped
        // at the largest object worth caching: the header is the origin's
        // word, not a reason to reserve gigabytes up front.
        let capacity = meta
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()?.parse::<usize>().ok())
            .unwrap_or(5 * 1024)
            .min(MAX_OBJECT_CACHE_SIZE);
        let hash = key.combined();
        let (meta0, meta1) = meta.serialize()?;
        let miss_handler = ObjectMissHandler {
            meta: (meta0.into(), meta1.into()),
            key: hash,
            primary_key: key.primary_key_str().unwrap_or_default().to_string(),
            namespace: key.user_tag().as_bytes().to_vec(),
            cache: self.cache.clone(),
            body: BytesMut::with_capacity(capacity),
        };
        Ok(Box::new(miss_handler))
    }

    async fn purge(
        &'static self,
        target: PurgeTarget<'_>,
        _type: PurgeType,
        _trace: &SpanHandle,
    ) -> pingora::Result<PurgeOutcome> {
        // This usually purges the primary key because, without a lookup,
        // the variance key is usually empty.
        let key = target.key();
        let hash = key.combined();
        // The namespace rides in user_tag, which a CompactCacheKey keeps, so
        // the purge reaches the same partition the entry was written to.
        let cache_removed =
            match self.cache.remove(&hash, key.user_tag().as_bytes()).await {
                Ok(result) => result.is_some(),
                Err(_) => false,
            };
        // These storages have no per-entry identity beyond the key itself,
        // so an active purge has no CacheEntryId to report.
        Ok(if cache_removed {
            PurgeOutcome::Purged(None)
        } else {
            PurgeOutcome::NotFound
        })
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<bool> {
        let namespace = key.user_tag().as_bytes();
        let hash = key.combined();
        if let Some(mut obj) = self.cache.get(&hash, namespace).await? {
            let (meta0, meta1) = meta.serialize()?;
            obj.meta = (meta0.into(), meta1.into());
            let _ = self.cache.put(&hash, namespace, obj).await?;
            Ok(true)
        } else {
            Err(Error::Invalid {
                message: "no meta found".to_string(),
            }
            .into())
        }
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tiny::{CacheMode, TinyUfoCache};
    use bytes::{Bytes, BytesMut};
    use pingora::cache::storage::{HitHandler, MissHandler};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    #[test]
    fn test_cache_object_round_trip() {
        let obj = CacheObject {
            meta: (Bytes::from_static(b"meta0"), Bytes::from_static(b"meta1")),
            body: Bytes::from_static(b"cache body"),
        };
        let buf: Bytes = obj.clone().into();
        assert_eq!(obj, CacheObject::try_from(buf).unwrap());
    }

    #[test]
    fn test_cache_object_rejects_truncated_bytes() {
        // What a crash or a full disk mid write leaves behind: every prefix of
        // a valid encoding. None of them may panic - with `panic = "abort"`
        // that would abort the process on every hit of the poisoned key.
        let full: Bytes = CacheObject {
            meta: (Bytes::from_static(b"meta0"), Bytes::from_static(b"meta1")),
            body: Bytes::from_static(b"cache body"),
        }
        .into();
        for len in 0..full.len() {
            let truncated = full.slice(0..len);
            let result = CacheObject::try_from(truncated);
            // Anything shorter than header + both metas must be rejected;
            // only the body may legitimately be shorter (its length is not
            // recorded, so a torn body is indistinguishable from a short one).
            if len < META_SIZE_LENGTH + b"meta0meta1".len() {
                assert_eq!(true, result.is_err(), "len {len} must be rejected");
            }
        }

        // Sizes that overflow when added must not wrap around the check.
        let mut evil = BytesMut::new();
        evil.put_u32(u32::MAX);
        evil.put_u32(u32::MAX);
        evil.extend_from_slice(b"tiny");
        assert_eq!(true, CacheObject::try_from(Bytes::from(evil)).is_err());
    }

    #[tokio::test]
    async fn test_complete_hit() {
        let body = Bytes::from_static(b"Hello World!");
        let size = body.len();
        let mut handle: HitHandler =
            Box::new(CompleteHit::new(CachedPayload::Inline(body)));
        let body = handle.read_body().await.unwrap();
        assert_eq!(true, body.is_some());
        assert_eq!(b"Hello World!", body.unwrap().as_ref());

        handle.seek(1, Some(size - 1)).unwrap();
        let body = handle.read_body().await.unwrap();
        assert_eq!(true, body.is_some());
        assert_eq!(b"ello World", body.unwrap().as_ref());
    }

    /// A streamed hit hands out one chunk per `read_body` — that is the loop
    /// pingora drives while it writes the downstream body — and its seek
    /// repositions the file instead of slicing a buffer that does not exist.
    #[tokio::test]
    async fn streamed_hit_reads_in_chunks_and_seeks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("object");
        let body: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        let mut bytes = BytesMut::new();
        bytes.put_u32(3);
        bytes.put_u32(5);
        bytes.put_slice(b"abc");
        bytes.put_slice(b"12345");
        bytes.put_slice(&body);
        std::fs::write(&path, &bytes).unwrap();

        let offset = (META_SIZE_LENGTH + 3 + 5) as u64;
        let mut file = tokio::fs::File::open(&path).await.unwrap();
        file.seek(SeekFrom::Start(offset)).await.unwrap();
        let gauges = Arc::new(CacheGauges::new());
        let mut handle: HitHandler =
            Box::new(CompleteHit::new(CachedPayload::Stream {
                file,
                offset,
                len: body.len() as u64,
                in_flight: InFlightGuard::new(
                    Arc::clone(&gauges),
                    STREAM_CHUNK_BYTES as u64,
                ),
            }));
        assert_eq!(STREAM_CHUNK_BYTES as u64, gauges.in_flight_bytes());

        let mut read = Vec::with_capacity(body.len());
        let mut chunks = 0;
        while let Some(chunk) = handle.read_body().await.unwrap() {
            assert!(
                chunk.len() <= STREAM_CHUNK_BYTES,
                "a chunk must never exceed the buffer: {}",
                chunk.len()
            );
            chunks += 1;
            read.extend_from_slice(&chunk);
        }
        assert_eq!(body, read, "the streamed bytes are the body");
        assert!(
            chunks >= 3,
            "200 KiB must arrive as several chunks, got {chunks}"
        );
        // EOF is sticky.
        assert_eq!(true, handle.read_body().await.unwrap().is_none());

        // A range: seek is honoured on the next read, out of the file.
        handle.seek(1024, Some(2048)).unwrap();
        let chunk = handle.read_body().await.unwrap().unwrap();
        assert_eq!(&body[1024..2048], chunk.as_ref());
        assert_eq!(true, handle.read_body().await.unwrap().is_none());

        // Dropping the hit releases the chunk budget, not only on success.
        drop(handle);
        assert_eq!(0, gauges.in_flight_bytes());
    }

    /// The pingora-facing path: `Storage::lookup` on a file backend returns a
    /// hit handler that streams, so a large cached object never becomes one
    /// heap allocation on the response path.
    #[tokio::test]
    async fn lookup_streams_a_large_object() {
        use pingora::cache::trace::Span;
        use pingora::http::ResponseHeader;

        let dir = tempfile::tempdir().unwrap();
        // No hot layer: the hit has to come off the disk.
        let backend = crate::file::FileCache::new(
            dir.path().to_str().unwrap_or_default(),
        )
        .unwrap();
        // `Storage::lookup` takes `&'static self`.
        let storage: &'static HttpCache = Box::leak(Box::new(HttpCache {
            directory: Some(dir.path().to_string_lossy().to_string()),
            cache: Arc::new(backend),
            max_size: 0,
        }));

        let body = Bytes::from(vec![7u8; INLINE_MAX_BYTES * 2]);
        let meta = CacheMeta::new(
            SystemTime::now() + Duration::from_secs(60),
            SystemTime::now(),
            0,
            0,
            ResponseHeader::build(200, None).unwrap(),
        );
        let (meta0, meta1) = meta.serialize().unwrap();
        let key = CacheKey::new("primary", "");
        storage
            .cache
            .put(
                &key.combined(),
                key.user_tag().as_bytes(),
                CacheObject {
                    meta: (meta0.into(), meta1.into()),
                    body: body.clone(),
                },
            )
            .await
            .unwrap();

        let span = Span::inactive();
        let (meta, mut hit) = storage
            .lookup(&key, &span.handle())
            .await
            .unwrap()
            .expect("a cache hit");
        assert_eq!(200, meta.response_header().status.as_u16());

        let mut read = Vec::with_capacity(body.len());
        while let Some(chunk) = hit.read_body().await.unwrap() {
            assert!(chunk.len() <= STREAM_CHUNK_BYTES);
            read.extend_from_slice(&chunk);
        }
        assert_eq!(body, read, "the response body is the cached object");
    }

    #[tokio::test]
    async fn test_object_miss_handler() {
        let key = "key";

        let cache = Arc::new(TinyUfoCache::new(CacheMode::Normal, 10));
        let obj = ObjectMissHandler {
            meta: (Bytes::from_static(b"Hello"), Bytes::from_static(b"World")),
            body: BytesMut::new(),
            key: key.to_string(),
            primary_key: "".to_string(),
            namespace: b"".to_vec(),
            cache: cache.clone(),
        };
        let mut handle: MissHandler = Box::new(obj);

        handle
            .write_body(Bytes::from_static(b"Hello World!"), true)
            .await
            .unwrap();
        handle.finish().await.unwrap();

        let data = cache.get(key, b"").await.unwrap().unwrap();
        assert_eq!("Hello World!", std::str::from_utf8(&data.body).unwrap());
    }

    #[test]
    fn test_cache_object_get_weight() {
        // data less than one page
        let obj = CacheObject {
            meta: (Bytes::from_static(b"Hello"), Bytes::from_static(b"World")),
            body: Bytes::from_static(b"Hello World!"),
        };
        assert_eq!(1, obj.get_weight());

        let obj = CacheObject {
            meta: (Bytes::from_static(b"Hello"), Bytes::from_static(b"World")),
            body: vec![0; PAGE_SIZE * 2].into(),
        };
        assert_eq!(2, obj.get_weight());

        // data larger than max size
        let obj = CacheObject {
            meta: (Bytes::from_static(b"Hello"), Bytes::from_static(b"World")),
            body: vec![0; MAX_OBJECT_CACHE_SIZE + 1].into(),
        };
        assert_eq!(u16::MAX, obj.get_weight());
    }
}
