//! Fixed-window rate limiting for the authentication endpoints.
//!
//! Login, registration, token refresh and password change are the surfaces
//! where a caller with no credentials can make the server spend a bcrypt
//! hash per request; left unbounded they are the cheapest way to exhaust its
//! CPU. Counts live in process memory and are keyed by the real TCP peer
//! address, never by forwarding headers, so the limit cannot be dodged by
//! spoofing `X-Forwarded-For`.
//!
//! The table is capped; entries expire with their own bucket's window, and
//! when the cap is hit anyway the endpoints fail closed (429) rather than
//! admitting peers without tracking — an untracked login still costs a
//! bcrypt hash, so failing open would silently disable the limit exactly
//! when a flood needs it most.
//!
//! Deployments behind one shared NAT exit (offices, campus networks) all
//! present the same address and can hit the limits with legitimate traffic;
//! the limits are generous, but such operators should give the dashboard a
//! dedicated ingress address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use super::error::error_response;
use super::self_protection::peer_addr;

/// Login attempts (password and passkey) per minute.
const LOGIN: Rate = Rate {
    window: Duration::from_secs(60),
    limit: 10,
};
/// Account registrations per hour; sign-ups are rare, probes are not.
const REGISTER: Rate = Rate {
    window: Duration::from_secs(60 * 60),
    limit: 5,
};
/// Refresh-token exchanges per minute; a dashboard polls this on schedule.
const REFRESH: Rate = Rate {
    window: Duration::from_secs(60),
    limit: 30,
};
/// Password changes per minute; each one verifies the current password.
const PASSWORD: Rate = Rate {
    window: Duration::from_secs(60),
    limit: 10,
};
/// `/mcp` calls per minute. API-key callers still cost a bcrypt verify, and
/// the endpoint sits outside `/api/v1`, so it needs its own bucket.
const MCP: Rate = Rate {
    window: Duration::from_secs(60),
    limit: 60,
};
/// `RegisterAgent` attempts per minute per peer. The RPC is unauthenticated
/// by design (the key is the credential), so each attempt costs a DB lookup
/// plus a bcrypt verify without a cap.
const AGENT_REGISTRATION: Rate = Rate {
    window: Duration::from_secs(60),
    limit: 20,
};

#[derive(Clone, Copy)]
struct Rate {
    window: Duration,
    limit: u32,
}

type Counters = HashMap<(&'static str, IpAddr), Entry>;

struct Entry {
    window_start: Instant,
    /// This entry's own bucket window. Entries become reclaimable
    /// `window` after their window started, so a 60-second login slot is
    /// reclaimable after 60 seconds instead of lingering for the widest
    /// bucket's hour.
    window: Duration,
    count: u32,
}

/// Upper bound on tracked (bucket, peer) pairs. Peers are real sockets, so
/// growth is bounded by the network; the cap keeps a flood of unique peers
/// from growing memory without bound. When the table is full the
/// credential endpoints **fail closed** — rejecting the peer with a
/// 429 — rather than admitting it untracked, because an untracked login
/// still costs a bcrypt hash per request.
const MAX_ENTRIES: usize = 10_000;

/// One-shot latch so the "table full" transition logs once per episode
/// instead of once per rejected request.
static TABLE_FULL_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

static COUNTERS: LazyLock<Mutex<Counters>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The limiter bucket for a request, or `None` when the path is unlimited.
///
/// Passkey logins replace password logins for the same accounts, so they
/// share the login bucket; passkey *registration* mutates an
/// already-authenticated session and stays unlimited.
fn bucket_for(
    method: &axum::http::Method,
    path: &str,
) -> Option<(&'static str, Rate)> {
    match (method.as_str(), path) {
        // The hosted MCP endpoint lives outside `/api/v1` but performs the
        // same API-key verification, so it gets the same treatment.
        (_, "/mcp") => Some(("mcp", MCP)),
        ("POST", "/auth/login")
        | ("POST", "/auth/passkey/login/begin")
        | ("POST", "/auth/passkey/login/finish") => Some(("login", LOGIN)),
        ("POST", "/auth/register") => Some(("register", REGISTER)),
        ("POST", "/auth/refresh") => Some(("refresh", REFRESH)),
        ("PUT", "/auth/password") => Some(("password", PASSWORD)),
        _ => None,
    }
}

/// Counts one request. Returns `Err(seconds until the window resets)` once
/// the peer exceeds the bucket's limit — or, when the table is full with
/// unexpired entries, `Err(seconds until the oldest window frees a slot)`.
fn consume(
    counters: &mut Counters,
    bucket: &'static str,
    rate: Rate,
    ip: IpAddr,
    now: Instant,
) -> Result<(), u64> {
    if !counters.contains_key(&(bucket, ip)) && counters.len() >= MAX_ENTRIES {
        // Reclaim with each entry's own window, not the widest bucket's:
        // most slots are 60-second windows and must not be held hostage
        // for an hour by the registration bucket's span.
        counters.retain(|_, entry| {
            now.duration_since(entry.window_start) < entry.window
        });
        if counters.len() >= MAX_ENTRIES {
            // Still full: a genuine flood of unique peers. Admitting the
            // peer would silently disable the limit on exactly the
            // endpoints whose per-request cost (a bcrypt hash) makes them
            // the cheapest way to exhaust the CPU, so the request fails
            // closed until the oldest window expires.
            if !TABLE_FULL_WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    bucket,
                    "rate-limit table full; rejecting new peers until \
                     their windows expire"
                );
            }
            // Retry hint: the soonest an existing entry expires and frees
            // a slot for this peer.
            let soonest = counters
                .values()
                .map(|entry| {
                    entry
                        .window
                        .saturating_sub(now.duration_since(entry.window_start))
                })
                .min()
                .unwrap_or(rate.window);
            return Err(soonest.as_secs().max(1));
        }
        if TABLE_FULL_WARNED.swap(false, Ordering::Relaxed) {
            tracing::info!("rate-limit table has headroom again");
        }
    }

    let entry = counters.entry((bucket, ip)).or_insert(Entry {
        window_start: now,
        window: rate.window,
        count: 0,
    });
    if now.duration_since(entry.window_start) >= entry.window {
        entry.window_start = now;
        entry.count = 0;
    }
    entry.count += 1;
    if entry.count > rate.limit {
        let remaining = entry
            .window
            .saturating_sub(now.duration_since(entry.window_start));
        return Err(remaining.as_secs().max(1));
    }
    Ok(())
}

/// Counts one gRPC `RegisterAgent` attempt for `ip`.
///
/// Returns the retry hint (seconds) once the peer exceeds the bucket.
pub(crate) fn consume_agent_registration(ip: IpAddr) -> Result<(), u64> {
    let mut counters = COUNTERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    consume(
        &mut counters,
        "agent-register",
        AGENT_REGISTRATION,
        ip,
        Instant::now(),
    )
}

/// `axum` middleware limiting the credential endpoints; see the module docs.
pub(crate) async fn auth_rate_limit(request: Request, next: Next) -> Response {
    let Some((bucket, rate)) =
        bucket_for(request.method(), request.uri().path())
    else {
        return next.run(request).await;
    };
    let Some(ip) = peer_addr(&request).map(|addr| addr.ip()) else {
        tracing::debug!(
            path = request.uri().path(),
            "rate limit skipped: connection has no peer address"
        );
        return next.run(request).await;
    };

    let verdict = {
        let mut counters =
            COUNTERS.lock().expect("rate-limit counters poisoned");
        consume(&mut counters, bucket, rate, ip, Instant::now())
    };

    match verdict {
        Ok(()) => next.run(request).await,
        Err(retry_after) => {
            tracing::warn!(bucket, %ip, retry_after, "authentication attempt rate limited");
            let mut response = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                // The body carries the same wait the header does: clients
                // that surface only the JSON message still tell the user
                // how long the cooldown lasts.
                &format!("too many attempts; retry in {retry_after} seconds"),
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
            response
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ConnInfo;
    use axum::extract::connect_info::ConnectInfo;
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    fn request(
        method: axum::http::Method,
        path: &str,
        peer_ip: &str,
    ) -> Request {
        Request::builder()
            .method(method)
            .uri(path)
            .extension(ConnectInfo(ConnInfo {
                tls: false,
                peer_addr: format!("{peer_ip}:5000").parse().unwrap(),
            }))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[test]
    fn only_credential_endpoints_are_limited() {
        assert!(bucket_for(&axum::http::Method::POST, "/auth/login").is_some());
        assert!(bucket_for(
            &axum::http::Method::POST,
            "/auth/passkey/login/begin"
        )
        .is_some());
        assert!(bucket_for(
            &axum::http::Method::POST,
            "/auth/passkey/login/finish"
        )
        .is_some());
        assert!(
            bucket_for(&axum::http::Method::POST, "/auth/register").is_some()
        );
        assert!(
            bucket_for(&axum::http::Method::POST, "/auth/refresh").is_some()
        );
        assert!(
            bucket_for(&axum::http::Method::PUT, "/auth/password").is_some()
        );

        // Read-only or already-authenticated surfaces stay unlimited.
        assert!(bucket_for(&axum::http::Method::GET, "/auth/status").is_none());
        assert!(bucket_for(&axum::http::Method::GET, "/auth/me").is_none());
        assert!(bucket_for(
            &axum::http::Method::POST,
            "/auth/passkey/register/begin"
        )
        .is_none());
        assert!(bucket_for(
            &axum::http::Method::POST,
            "/auth/passkey/register/finish"
        )
        .is_none());
        assert!(bucket_for(&axum::http::Method::POST, "/auth/other").is_none());
        assert!(bucket_for(&axum::http::Method::PUT, "/auth/password/reset")
            .is_none());
    }

    #[test]
    fn the_window_resets_after_expiry() {
        let mut counters = Counters::new();
        let start = Instant::now();
        for _ in 0..LOGIN.limit {
            assert!(consume(
                &mut counters,
                "login",
                LOGIN,
                ip("10.77.0.1"),
                start
            )
            .is_ok());
        }
        assert!(
            consume(&mut counters, "login", LOGIN, ip("10.77.0.1"), start)
                .is_err()
        );

        let later = start + LOGIN.window;
        assert!(
            consume(&mut counters, "login", LOGIN, ip("10.77.0.1"), later)
                .is_ok()
        );
    }

    #[test]
    fn peers_and_buckets_are_counted_independently() {
        let mut counters = Counters::new();
        let now = Instant::now();
        for _ in 0..LOGIN.limit {
            assert!(consume(
                &mut counters,
                "login",
                LOGIN,
                ip("10.77.0.2"),
                now
            )
            .is_ok());
        }
        assert!(consume(&mut counters, "login", LOGIN, ip("10.77.0.2"), now)
            .is_err());

        // A different peer and a different bucket each start fresh.
        assert!(consume(&mut counters, "login", LOGIN, ip("10.77.0.3"), now)
            .is_ok());
        assert!(consume(
            &mut counters,
            "register",
            REGISTER,
            ip("10.77.0.2"),
            now
        )
        .is_ok());
    }

    #[test]
    fn the_retry_hint_reports_seconds_left_in_the_window() {
        let mut counters = Counters::new();
        let rate = Rate {
            window: Duration::from_secs(60),
            limit: 1,
        };
        let start = Instant::now();
        assert!(
            consume(&mut counters, "login", rate, ip("10.77.0.4"), start)
                .is_ok()
        );

        let retry = consume(
            &mut counters,
            "login",
            rate,
            ip("10.77.0.4"),
            start + Duration::from_secs(10),
        )
        .unwrap_err();
        assert!((49..=50).contains(&retry), "{retry}");
    }

    #[test]
    fn a_flood_of_unique_peers_is_rejected_until_windows_expire() {
        let mut counters = Counters::new();
        let now = Instant::now();
        let hour = Rate {
            window: Duration::from_secs(3600),
            limit: 1,
        };
        for i in 0..MAX_ENTRIES {
            counters.insert(
                ("register", ip(&format!("10.78.{}.{}", i / 256, i % 256))),
                Entry {
                    window_start: now,
                    window: hour.window,
                    count: 1,
                },
            );
        }

        // Fresh peer, full table, nothing reclaimable: rejected with a
        // bounded retry hint instead of admitted untracked — admitting it
        // would silently disable the limit on the credential endpoints,
        // whose per-request bcrypt cost is exactly what the flood is after.
        let fresh =
            consume(&mut counters, "register", hour, ip("10.79.0.1"), now);
        let retry = fresh.expect_err("a full table must fail closed");
        assert!(
            (1..=3600).contains(&retry),
            "retry hint must be within the widest window, got {retry}"
        );
        assert_eq!(counters.len(), MAX_ENTRIES, "no slot was consumed");

        // Once the windows expire the entries are reclaimable and the
        // peer is tracked again.
        let later = now + hour.window;
        assert!(consume(
            &mut counters,
            "register",
            hour,
            ip("10.79.0.2"),
            later
        )
        .is_ok());
        assert!(counters.contains_key(&("register", ip("10.79.0.2"))));
    }

    /// Entries expire with their own bucket's window: a table full of
    /// 60-second login slots becomes reclaimable after 60 seconds even
    /// though the registration bucket's hour has not passed — the
    /// pre-fix behavior held them for the widest window.
    #[test]
    fn short_window_entries_do_not_linger_for_the_widest_bucket() {
        let mut counters = Counters::new();
        let now = Instant::now();
        // One long-window registration slot …
        counters.insert(
            ("register", ip("10.80.0.1")),
            Entry {
                window_start: now,
                window: REGISTER.window,
                count: 1,
            },
        );
        // … and the rest 60-second login slots.
        for i in 0..MAX_ENTRIES - 1 {
            counters.insert(
                ("login", ip(&format!("10.81.{}.{}", i / 256, i % 256))),
                Entry {
                    window_start: now,
                    window: LOGIN.window,
                    count: 1,
                },
            );
        }

        let later = now + LOGIN.window + Duration::from_secs(1);
        // Every login slot is expired and reclaimable at `later` — an
        // hour before the registration window ends.
        assert!(
            consume(&mut counters, "login", LOGIN, ip("10.82.0.1"), later)
                .is_ok()
        );
        assert_eq!(
            counters.len(),
            2,
            "only the register slot and the new peer remain"
        );
    }

    /// Drives the middleware through the same shape production uses — a
    /// nested `/api/v1` — so the path comparison is exercised against the
    /// prefix-stripped URI the middleware actually receives.
    #[tokio::test]
    async fn limited_endpoints_reject_after_the_limit() {
        let app = Router::new().nest(
            "/api/v1",
            Router::new()
                .route("/auth/login", post(|| async { "ok" }))
                .route("/auth/status", get(|| async { "ok" }))
                .layer(axum::middleware::from_fn(auth_rate_limit)),
        );

        for _ in 0..LOGIN.limit {
            let response = app
                .clone()
                .oneshot(request(
                    axum::http::Method::POST,
                    "/api/v1/auth/login",
                    "10.80.0.1",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let response = app
            .clone()
            .oneshot(request(
                axum::http::Method::POST,
                "/api/v1/auth/login",
                "10.80.0.1",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().get(header::RETRY_AFTER).is_some());

        // A different peer is unaffected, and unlimited paths stay open.
        let response = app
            .clone()
            .oneshot(request(
                axum::http::Method::POST,
                "/api/v1/auth/login",
                "10.80.0.2",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .oneshot(request(
                axum::http::Method::GET,
                "/api/v1/auth/status",
                "10.80.0.1",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
