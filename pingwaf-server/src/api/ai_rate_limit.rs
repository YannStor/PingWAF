//! Per-user fixed-window rate limiting for the AI assistant endpoints.
//!
//! Unlike [`crate::api::rate_limit`] (an IP-keyed middleware for anonymous
//! credential endpoints), the AI endpoints run *after* authentication and
//! already resolved an [`crate::auth::AuthUser`], so the limiter is an
//! explicit handler-side check keyed by user id. That matters because the
//! chat surface is open to every signed-in user: a shared office NAT would
//! let one IP-keyed limit throttle legitimate colleagues, while a
//! user-keyed limit charges the abuser alone.
//!
//! The real cost being bounded is provider token spend: every chat turn is
//! at least one paid LLM call, so `send_message` is the tight bucket.
//! Counts live in process memory; the key space is bounded by the user
//! table and windows are short, so no reaper is needed.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::error::ApiError;

/// Chat turns (LLM calls) per user per minute.
const CHAT: Rate = Rate {
    window: Duration::from_secs(60),
    limit: 10,
};
/// Conversation creations per user per minute.
const CREATE: Rate = Rate {
    window: Duration::from_secs(60),
    limit: 10,
};

#[derive(Clone, Copy)]
struct Rate {
    window: Duration,
    limit: u32,
}

type Counters = HashMap<(&'static str, Uuid), Entry>;

struct Entry {
    window_start: Instant,
    count: u32,
}

/// Hard cap on the counter table. Keys are `(bucket, user_id)`, so growth
/// is bounded by the user count in practice; the sweep keeps the table
/// honest and matches the login limiter's policy (10_000 + retain).
const MAX_ENTRIES: usize = 10_000;

static COUNTERS: LazyLock<Mutex<Counters>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The bucket for a named limiter, or `None` when callers pass an unknown
/// bucket name (kept total so a typo cannot panic in production).
fn rate_for(bucket: &str) -> Option<Rate> {
    match bucket {
        "ai_chat" => Some(CHAT),
        "ai_create" => Some(CREATE),
        _ => None,
    }
}

/// Counts one call. Returns `Err(seconds until the window resets)` once the
/// user exceeds the bucket's limit.
fn consume(
    counters: &mut Counters,
    bucket: &'static str,
    rate: Rate,
    user: Uuid,
    now: Instant,
) -> Result<(), u64> {
    let entry = counters.entry((bucket, user)).or_insert(Entry {
        window_start: now,
        count: 0,
    });
    if now.duration_since(entry.window_start) >= rate.window {
        entry.window_start = now;
        entry.count = 0;
    }
    entry.count += 1;
    if entry.count > rate.limit {
        let remaining = rate
            .window
            .saturating_sub(now.duration_since(entry.window_start));
        return Err(remaining.as_secs().max(1));
    }
    Ok(())
}

/// Handler-side check: charges one unit to `(bucket, user_id)` and fails
/// with `429 Too Many Requests` when the user's window is exhausted.
pub(crate) fn check_user_limit(
    bucket: &'static str,
    user_id: Uuid,
) -> Result<(), ApiError> {
    let Some(rate) = rate_for(bucket) else {
        return Ok(());
    };
    let verdict = {
        let mut counters =
            COUNTERS.lock().expect("ai rate-limit counters poisoned");
        let now = Instant::now();
        if counters.len() >= MAX_ENTRIES {
            // Drop entries whose window already reset — they would be
            // re-created lazily on the next call for that user.
            counters.retain(|(bucket, _), entry| {
                rate_for(bucket)
                    .map(|r| now.duration_since(entry.window_start) < r.window)
                    .unwrap_or(false)
            });
        }
        consume(&mut counters, bucket, rate, user_id, now)
    };
    verdict.map_err(|retry_after| {
        tracing::warn!(
            bucket,
            %user_id,
            retry_after,
            "AI assistant request rate limited"
        );
        ApiError::TooManyRequests(format!(
            "too many requests; retry in {retry_after}s"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(seed: u8) -> Uuid {
        let mut bytes = [0u8; 16];
        bytes[0] = seed;
        Uuid::from_bytes(bytes)
    }

    #[test]
    fn the_window_resets_after_expiry() {
        let mut counters = Counters::new();
        let start = Instant::now();
        for _ in 0..CHAT.limit {
            assert!(
                consume(&mut counters, "ai_chat", CHAT, user(1), start).is_ok()
            );
        }
        assert!(
            consume(&mut counters, "ai_chat", CHAT, user(1), start).is_err()
        );
        let later = start + CHAT.window;
        assert!(consume(&mut counters, "ai_chat", CHAT, user(1), later).is_ok());
    }

    #[test]
    fn users_and_buckets_are_counted_independently() {
        let mut counters = Counters::new();
        let now = Instant::now();
        for _ in 0..CHAT.limit {
            assert!(
                consume(&mut counters, "ai_chat", CHAT, user(2), now).is_ok()
            );
        }
        assert!(consume(&mut counters, "ai_chat", CHAT, user(2), now).is_err());
        // A different user and a different bucket each start fresh.
        assert!(consume(&mut counters, "ai_chat", CHAT, user(3), now).is_ok());
        assert!(
            consume(&mut counters, "ai_create", CREATE, user(2), now).is_ok()
        );
    }

    #[test]
    fn the_check_fails_closed_into_a_429_for_known_buckets() {
        // Known buckets charge the caller.
        assert!(check_user_limit("ai_create", user(4)).is_ok());
        // Unknown bucket names are admitted (total, not panicking).
        assert!(check_user_limit("nonsense", user(4)).is_ok());
    }
}
