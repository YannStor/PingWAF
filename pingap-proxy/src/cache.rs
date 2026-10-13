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

//! Cache-control interpretation and cache-timing response headers, split out
//! of the `Server` `ProxyHttp` implementation to keep `server.rs` focused.
//! These are free functions (they never touched `Server`'s state).

use pingap_core::Ctx;
use pingora::cache::NoCacheReason;
use pingora::cache::cache_control::{
    CacheControl, DirectiveKey, DirectiveMap, DirectiveValue,
    InterpretCacheControl,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::time::Duration;

#[cfg(feature = "tracing")]
use crate::tracing::update_otel_cache_attrs;

/// Applies the cache-control policy to `c`, flooring the freshness at
/// `max_ttl` when the origin announces none, capping it when the origin
/// asks for more, and rejecting responses that must not be cached.
///
/// `has_expires` reports whether the response carries an `Expires` header
/// (valid or not): pingora's freshness calculation falls back to it after
/// the directives, so a response with one must not be floored — the header
/// decides, even when it says "in the past".
pub(crate) fn process_cache_control(
    c: &mut CacheControl,
    max_ttl: Option<Duration>,
    has_expires: bool,
) -> Result<(), NoCacheReason> {
    // no-cache, no-store, private
    if c.no_cache() || c.no_store() || c.private() {
        return Err(NoCacheReason::OriginNotCache);
    }

    // max-age=0
    if c.max_age().ok().flatten() == Some(0) {
        return Err(NoCacheReason::OriginNotCache);
    }

    // The origin announces no usable freshness (no max-age / s-maxage —
    // a bare `public`, `must-revalidate`, a malformed directive…) and no
    // Expires to fall back on. Without a ceiling configured this keeps the
    // historical behaviour of refusing to cache; with one, it floors the
    // freshness at the ceiling instead of pingora's 1-second default — a
    // "cache for N seconds" rule must not silently degrade to 1s just
    // because the origin stays silent.
    if c.fresh_duration().is_none() && !has_expires {
        let Some(d) = max_ttl else {
            return Err(NoCacheReason::OriginNotCache);
        };
        set_s_maxage(c, d);
        return Ok(());
    }

    // set cache max ttl
    if let Some(d) = max_ttl
        && c.fresh_duration().unwrap_or_default() > d
    {
        set_s_maxage(c, d);
    }

    Ok(())
}

/// Overwrites the `s-maxage` directive with `d`.
fn set_s_maxage(c: &mut CacheControl, d: Duration) {
    let s_maxage_value =
        itoa::Buffer::new().format(d.as_secs()).as_bytes().to_vec();
    c.directives
        .insert(DirectiveKey::SMaxAge, Some(DirectiveValue(s_maxage_value)));
}

/// Builds the cache-control used when the origin sends none at all: the
/// configured ceiling becomes the freshness directly (see
/// [`process_cache_control`] for the with-header counterpart).
pub(crate) fn floor_cache_control(max_ttl: Duration) -> CacheControl {
    let mut c = CacheControl {
        directives: DirectiveMap::new(),
        allow_float_seconds: false,
    };
    set_s_maxage(&mut c, max_ttl);
    c
}

/// Whether the response carries any `Expires` header (valid or not).
pub(crate) fn has_expires_header(resp: &ResponseHeader) -> bool {
    resp.headers.get("expires").is_some()
}

/// Adds the `x-cache-status` / `x-cache-lookup` / `x-cache-lock` headers (and,
/// under `tracing`, the matching OpenTelemetry attributes).
#[inline]
pub(crate) fn handle_cache_headers(
    session: &Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut Ctx,
) {
    let cache_status = session.cache.phase().as_str();
    let _ = upstream_response.insert_header("x-cache-status", cache_status);

    // A matched cache rule may pin what browsers are told, independently of
    // the edge's own freshness (the stored meta keeps the origin's
    // Cache-Control). pingora runs this filter on hits and misses alike, so
    // both get the browser-facing TTL. `Expires` is dropped with it, since a
    // stale `Expires` next to the override would send contradictory hints.
    if let Some(secs) = ctx.cache.as_ref().and_then(|cache| cache.browser_ttl)
        && secs > 0
    {
        let mut buffer = itoa::Buffer::new();
        let mut value_bytes = Vec::with_capacity(24);
        value_bytes.extend_from_slice(b"public, max-age=");
        value_bytes
            .extend_from_slice(buffer.format(u64::from(secs)).as_bytes());
        let _ = upstream_response.insert_header("Cache-Control", value_bytes);
        let _ = upstream_response.remove_header("Expires");
    }

    // process lookup duration
    let lookup_duration_str = process_cache_timing(
        session.cache.lookup_duration(),
        "x-cache-lookup",
        upstream_response,
        &mut ctx.timing.cache_lookup,
    );

    // process lock duration
    let lock_duration_str = process_cache_timing(
        session.cache.lock_duration(),
        "x-cache-lock",
        upstream_response,
        &mut ctx.timing.cache_lock,
    );

    #[cfg(not(feature = "tracing"))]
    {
        let _ = lookup_duration_str;
        let _ = lock_duration_str;
    }

    // (optional) process OpenTelemetry
    #[cfg(feature = "tracing")]
    update_otel_cache_attrs(
        ctx,
        cache_status,
        lookup_duration_str,
        lock_duration_str,
    );
}

/// Writes a `<n>ms` timing header, records it on `ctx_field`, and returns the
/// human-readable duration (only used under `tracing`).
#[inline]
pub(crate) fn process_cache_timing(
    duration_opt: Option<Duration>,
    header_name: &'static str,
    resp: &mut ResponseHeader,
    ctx_field: &mut Option<i32>,
) -> String {
    if let Some(d) = duration_opt {
        let ms = d.as_millis() as i32;

        // use itoa to avoid format! heap memory allocation
        let mut buffer = itoa::Buffer::new();
        let mut value_bytes = Vec::with_capacity(6);
        value_bytes.extend_from_slice(buffer.format(ms).as_bytes());
        value_bytes.extend_from_slice(b"ms");

        let _ = resp.insert_header(header_name, value_bytes);
        *ctx_field = Some(ms);

        #[cfg(feature = "tracing")]
        return humantime::Duration::from(d).to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cc_from(value: &str) -> CacheControl {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Cache-Control", value).unwrap();
        CacheControl::from_resp_headers(&resp).unwrap()
    }

    #[test]
    fn test_process_cache_control_floor() {
        // Freshness announced: origin wins while under the ceiling.
        let mut c = cc_from("public, max-age=10");
        process_cache_control(&mut c, Some(Duration::from_secs(600)), false)
            .unwrap();
        assert_eq!(Some(Duration::from_secs(10)), c.fresh_duration());

        // Over the ceiling: capped.
        let mut c = cc_from("public, max-age=31536000");
        process_cache_control(
            &mut c,
            Some(Duration::from_secs(7 * 86400)),
            false,
        )
        .unwrap();
        assert_eq!(Some(Duration::from_secs(7 * 86400)), c.fresh_duration());

        // No freshness directive, no Expires: floored at the ceiling.
        let mut c = cc_from("public");
        process_cache_control(&mut c, Some(Duration::from_secs(600)), false)
            .unwrap();
        assert_eq!(Some(Duration::from_secs(600)), c.fresh_duration());

        // No freshness directive but an Expires header: left alone — the
        // header decides, even when it says "in the past".
        let mut c = cc_from("public");
        process_cache_control(&mut c, Some(Duration::from_secs(600)), true)
            .unwrap();
        assert_eq!(None, c.fresh_duration());

        // No freshness directive and no ceiling configured: historical
        // behaviour (refuse) is kept for static deployments.
        let mut c = cc_from("public");
        assert!(process_cache_control(&mut c, None, false).is_err());

        // Hard rejections are unchanged.
        assert!(
            process_cache_control(
                &mut cc_from("no-store"),
                Some(Duration::from_secs(600)),
                false
            )
            .is_err()
        );
        assert!(
            process_cache_control(
                &mut cc_from("max-age=0"),
                Some(Duration::from_secs(600)),
                false
            )
            .is_err()
        );
    }

    #[test]
    fn test_floor_cache_control() {
        let c = floor_cache_control(Duration::from_secs(600));
        assert_eq!(Some(Duration::from_secs(600)), c.fresh_duration());
    }
}
