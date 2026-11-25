// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Outbound issuance budget - the flood valve on the upstream CA
//! (CERTBUDGET-1, acme DESIGN §4.2c).
//!
//! The exposure map decides WHICH names may be publicly signed; it does
//! not bound HOW MANY orders actually leave the box. That bound matters
//! because a public CA's limits are not per hostname:
//!
//! - Let's Encrypt production allows **50 certificates per REGISTERED
//!   DOMAIN per week**, shared by every account and customer on that
//!   domain. One runaway retry loop can consume a whole week's allowance
//!   for every tenant under it.
//! - The new-order limit is 300 per account per 3 hours; the duplicate-
//!   certificate limit is 5 per exact SAN set per week.
//!
//! A hostname allowlist was the original answer and is the wrong shape:
//! environments are created at runtime per tenant, so a hand-maintained
//! list is stale the moment a tenant enrolls. The budget below needs no
//! per-name configuration at all - it bounds the TOTAL burn, which is
//! exactly the quantity the CA meters.
//!
//! Three windows, cheapest first:
//!
//! | window | default | stops |
//! |---|---|---|
//! | per hostname / 24h | 3 | a single domain's retry loop |
//! | per hour (all) | 30 | a burst from a cold fleet / bad rollout |
//! | per week (all) | 40 | an afternoon-long storm that eats the 50/wk cap |
//!
//! Counters live in Valkey under `acme:budget:*` (acme already holds
//! `~acme:*` + `INCR`/`EXPIRE` in its ACL, so no grant change is needed)
//! and survive a process restart - an in-memory counter would reset with
//! the fleet, which is exactly when a retry storm happens.
//!
//! **Valkey outage ⇒ in-memory fallback.** The guard never *blocks*
//! issuance because the counter store is down (that would turn a cache
//! blip into a fleet-wide cert outage), but it also never *disables*
//! itself: the process-local window keeps bounding the burn, and the
//! degraded mode is logged at `warn` on every admission.
//!
//! **The CA's own answer is the last line of defence.** [`note_rate_limited`]
//! records a cooling window when the upstream returns
//! `urn:ietf:params:acme:error:rateLimited`, so the fleet stops ordering
//! before the budget arithmetic has a chance to disagree with reality.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Valkey key namespace for the counters. Covered by acme's existing
/// `~acme:*` ACL grant - no new permission is required.
const KEY_NS: &str = "acme:budget";

/// How long a `rateLimited` answer parks ALL upstream ordering. The CA's
/// own `Retry-After` wins when it sends one; this is the floor for a
/// response that omits it.
pub const RATE_LIMIT_COOLDOWN_S: u64 = 3600;

/// The budgets in force for one admission decision.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Maximum upstream orders attributable to ONE hostname per 24h.
    /// A failed fetch loop re-orders every backoff cycle; without this
    /// a single dead domain can drain the week's allowance alone.
    pub per_host_per_day: u64,
    /// Maximum upstream orders in any rolling hour, across all names.
    pub per_hour: u64,
    /// Maximum upstream orders in any rolling week, across all names.
    /// Sits below Let's Encrypt's 50/registered-domain/week so renewals
    /// and manual recovery always have headroom.
    pub per_week: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            per_host_per_day: 3,
            per_hour: 30,
            per_week: 40,
        }
    }
}

/// The outcome of an admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Within every window - the caller may place the upstream order.
    Admitted,
    /// Refused; the value is the `Retry-After` hint in seconds.
    Refused {
        /// Seconds the caller should wait before retrying.
        retry_after: u64,
    },
}

/// Why an admission was refused - carried into the log line and the
/// ACME problem detail so an operator can tell a storm from a
/// misconfiguration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    /// The hostname's own 24h window is exhausted.
    Host,
    /// The global hourly window is exhausted.
    Hour,
    /// The global weekly window is exhausted.
    Week,
    /// The upstream answered `rateLimited`; everything is parked.
    Cooldown,
}

impl Window {
    /// Stable lowercase name for logs and problem details.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Hour => "hour",
            Self::Week => "week",
            Self::Cooldown => "cooldown",
        }
    }
}

/// A refusal with its reason and retry hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// Which window tripped.
    pub window: Window,
    /// `Retry-After` hint in seconds.
    pub retry_after: u64,
}

/// Process-local fallback counters: `key -> (count, first_seen, ttl)`.
/// Used only when Valkey is unreachable; bounded by the same windows so
/// the guard degrades rather than disappears.
fn local() -> &'static Mutex<HashMap<String, (u64, Instant, std::time::Duration)>> {
    static LOCAL: OnceLock<Mutex<HashMap<String, (u64, Instant, std::time::Duration)>>> =
        OnceLock::new();
    LOCAL.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The windowed keys for one admission, with their TTLs.
///
/// Keys are epoch-derived rather than calendar-derived: `ts/3600` and
/// `ts/604800` are monotonic, need no timezone, and roll over on their
/// own. The TTL is one window longer than the bucket so a counter never
/// expires while its bucket is still current.
fn windows(host: &str, now: u64) -> [(String, u64); 3] {
    let hour = now / 3600;
    let week = now / 604_800;
    // The hostname is hashed so an arbitrary (client-supplied) SNI can
    // never inject a key separator or grow the key past Valkey's limit.
    let host_digest = {
        use sha2::Digest;
        let d = sha2::Sha256::digest(host.as_bytes());
        hex::encode(&d[..8])
    };
    [
        (format!("{KEY_NS}:h:{host_digest}"), 86_400 + 3600),
        (format!("{KEY_NS}:hour:{hour}"), 3600 + 600),
        (format!("{KEY_NS}:week:{week}"), 604_800 + 86_400),
    ]
}

/// Increment one counter and return its new value.
///
/// Returns `None` when the store is unavailable - the caller then falls
/// back to the process-local window. Deliberately does NOT fail the
/// admission: a Valkey blip must not stop renewals.
async fn bump(client: &glide::GlideClient, key: &str, ttl: u64) -> Option<u64> {
    use glide::AsyncCommands as _;
    let n: i64 = client.incr(key, 1i64).await.ok()?;
    // Best-effort TTL: a lost EXPIRE leaks one small key, an unguarded
    // counter window would be far worse. `NX` semantics are not needed -
    // re-setting the TTL on every bump shortens nothing, because the TTL
    // is always longer than the bucket being counted.
    let _: Result<bool, _> = client.expire(key, ttl as i64).await;
    Some(n.max(0) as u64)
}

/// Increment a process-local counter, returning its new value.
fn bump_local(key: &str, ttl: std::time::Duration) -> u64 {
    let mut map = local().lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    let count = {
        let entry = map.entry(key.to_string()).or_insert((0, now, ttl));
        if now.duration_since(entry.1) >= entry.2 {
            *entry = (0, now, ttl);
        }
        entry.0 += 1;
        entry.0
    };
    // Prune opportunistically so an unreachable store cannot let the
    // fallback map grow without bound (the SNI key space is
    // client-controlled).
    if map.len() > 4096 {
        map.retain(|_, (_, seen, ttl)| now.duration_since(*seen) < *ttl);
    }
    count
}

/// Try to admit ONE upstream order for `host`.
///
/// Call this at the ORDER site, AFTER the reuse-before-mint lookup: a
/// cached certificate ends the order without touching the upstream, so
/// it must never consume budget.
///
/// The counters are incremented as part of the decision - a refused
/// admission still records the attempt, so a client that ignores the
/// 429 cannot spin the counters down. The windows are cheap on purpose:
/// one `INCR` + `EXPIRE` per admitted order is negligible beside a
/// round-trip to a public CA.
pub async fn admit(
    valkey_url: &str,
    workload: &str,
    host: &str,
    budget: Budget,
) -> Result<(), Refusal> {
    let now = now_secs();
    let keys = windows(host, now);

    // Cooling window first: a `rateLimited` answer parks everything, and
    // the arithmetic below must not argue with the CA.
    if let Some(retry_after) = cooldown_remaining(valkey_url, workload).await {
        tracing::warn!(
            host,
            retry_after,
            "acme budget: upstream rateLimited cooldown active - refusing order"
        );
        return Err(Refusal {
            window: Window::Cooldown,
            retry_after,
        });
    }

    let client = sentin8::middleware::valkey_client(valkey_url, workload).await.ok();

    let (host_count, hour_count, week_count) = match &client {
        Some(c) => {
            let h = bump(c, &keys[0].0, keys[0].1).await;
            let ho = bump(c, &keys[1].0, keys[1].1).await;
            let w = bump(c, &keys[2].0, keys[2].1).await;
            match (h, ho, w) {
                (Some(h), Some(ho), Some(w)) => (h, ho, w),
                _ => {
                    tracing::warn!(
                        host,
                        "acme budget: Valkey counter unavailable - falling back to the process-local window"
                    );
                    local_triple(&keys, host)
                }
            }
        }
        None => {
            tracing::warn!(
                host,
                "acme budget: Valkey unreachable - falling back to the process-local window"
            );
            local_triple(&keys, host)
        }
    };

    if host_count > budget.per_host_per_day {
        return Err(Refusal {
            window: Window::Host,
            retry_after: 86_400,
        });
    }
    if hour_count > budget.per_hour {
        return Err(Refusal {
            window: Window::Hour,
            retry_after: 600,
        });
    }
    if week_count > budget.per_week {
        // Report the remaining time in the bucket rather than a flat
        // week - the caller retries as soon as the window rolls.
        let week_left = 604_800 - (now % 604_800);
        return Err(Refusal {
            window: Window::Week,
            retry_after: week_left,
        });
    }
    Ok(())
}

/// The three counts from the process-local fallback.
fn local_triple(keys: &[(String, u64); 3], _host: &str) -> (u64, u64, u64) {
    (
        bump_local(&keys[0].0, std::time::Duration::from_secs(keys[0].1)),
        bump_local(&keys[1].0, std::time::Duration::from_secs(keys[1].1)),
        bump_local(&keys[2].0, std::time::Duration::from_secs(keys[2].1)),
    )
}

/// Seconds left in an active `rateLimited` cooling window, if any.
async fn cooldown_remaining(valkey_url: &str, workload: &str) -> Option<u64> {
    let key = format!("{KEY_NS}:cooldown");
    if let Ok(client) = sentin8::middleware::valkey_client(valkey_url, workload).await {
        use glide::AsyncCommands as _;
        if let Ok(reply) = client.ttl(&key).await {
            if let glide::IntegerReplyOrNoOp::IntegerReply(secs) = reply {
                if secs > 0 {
                    return Some(secs as u64);
                }
            }
        }
    }
    // Local fallback cooldown (the Valkey outage path).
    let mut map = local().lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    if let Some((_, started, ttl)) = map.get(&key) {
        let elapsed = now.duration_since(*started);
        if elapsed < *ttl {
            return Some((ttl.as_secs()).saturating_sub(elapsed.as_secs()));
        }
    }
    let _ = &mut map;
    None
}

/// Record that the upstream answered `rateLimited` (CERTBUDGET-1).
///
/// Parks ALL upstream ordering for `retry_after` seconds. Called from the
/// relay's error path when the problem type names the rate-limit error -
/// the CA's own signal is authoritative, and it arrives precisely when
/// the local arithmetic was too optimistic.
pub async fn note_rate_limited(valkey_url: &str, workload: &str, retry_after: u64) {
    let secs = retry_after.max(RATE_LIMIT_COOLDOWN_S);
    let key = format!("{KEY_NS}:cooldown");
    let mut stored = false;
    if let Ok(client) = sentin8::middleware::valkey_client(valkey_url, workload).await {
        use glide::AsyncCommands as _;
        let value = now_secs().to_string();
        let set: Result<(), _> = client.set_ex(&key, &value, secs).await;
        if set.is_ok() {
            stored = true;
        }
    }
    if !stored {
        let mut map = local().lock().unwrap_or_else(|p| p.into_inner());
        map.insert(
            key,
            (1, Instant::now(), std::time::Duration::from_secs(secs)),
        );
    }
    tracing::error!(
        retry_after = secs,
        stored_in_valkey = stored,
        "acme budget: upstream rateLimited - ALL upstream ordering parked"
    );
}

/// Whether an upstream problem detail names the ACME rate-limit error.
///
/// RFC 8555 §6.6 problem documents carry
/// `"type": "urn:ietf:params:acme:error:rateLimited"`; the relay keeps
/// the body text, so a substring test is both sufficient and immune to
/// a partial JSON parse.
pub fn is_rate_limited(detail: &str) -> bool {
    detail.contains("rateLimited")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Valkey-outage path is the one that must never stop issuance,
    /// so it is the fallback the unit tests exercise (no live Valkey).
    const DEAD_URL: &str = "valkeys://127.0.0.1:1/0";

    /// The process-local fallback is deliberately process-global (one
    /// process owns one budget), so window tests must not observe each
    /// other's counts. Serialise them and start from empty.
    fn isolated() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        local().lock().unwrap_or_else(|p| p.into_inner()).clear();
        guard
    }

    #[test]
    fn windows_are_epoch_derived_and_roll_over() {
        // Same host, same bucket -> identical keys.
        let a = windows("auth.cert.conformance-local.example", 1_700_000_000);
        let b = windows("auth.cert.conformance-local.example", 1_700_000_100);
        assert_eq!(a[1].0, b[1].0, "same hour bucket shares a key");

        // A later bucket differs - the counter rolls without a sweeper.
        let c = windows(
            "auth.cert.conformance-local.example",
            1_700_000_000 + 604_800,
        );
        assert_ne!(a[2].0, c[2].0, "next week bucket is a different key");
        // The hour bucket also advances (the +604800 delta crosses many).
        assert_ne!(a[1].0, c[1].0, "next hour bucket is a different key");

        // The hostname key is a digest: two distinct names never collide
        // into one bucket, and neither leaks the raw name into the key.
        let d = windows("other.example", 1_700_000_000);
        assert_ne!(a[0].0, d[0].0);
        assert!(!a[0].0.contains("example"), "raw hostname must not be in the key");

        // TTLs always outlive the bucket they count.
        assert!(a[0].1 > 86_400);
        assert!(a[1].1 > 3600);
        assert!(a[2].1 > 604_800);
    }

    #[test]
    fn rate_limited_detection() {
        assert!(is_rate_limited(
            r#"{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many"}"#
        ));
        assert!(!is_rate_limited(
            r#"{"type":"urn:ietf:params:acme:error:malformed"}"#
        ));
        assert!(!is_rate_limited(""));
    }

    /// Without Valkey the guard must still bound the burn - it degrades to
    /// the process-local window rather than disappearing.
    #[tokio::test]
    async fn fallback_refuses_after_the_host_window() {
        let _g = isolated();
        let host = "fallback-host-window.example";
        let budget = Budget {
            per_host_per_day: 2,
            per_hour: 1000,
            per_week: 1000,
        };
        // Two admissions fill the 24h host window.
        for _ in 0..2 {
            assert!(admit(DEAD_URL, "acme-cron", host, budget).await.is_ok());
        }
        // The third is refused, and says which window tripped.
        match admit(DEAD_URL, "acme-cron", host, budget).await {
            Err(r) => {
                assert_eq!(r.window, Window::Host);
                assert_eq!(r.retry_after, 86_400);
            }
            Ok(()) => panic!("the host window must bound a dead-store fallback"),
        }
    }

    /// The hourly window bounds a BURST across many distinct names - the
    /// shape a cold fleet or a bad rollout produces.
    #[tokio::test]
    async fn fallback_refuses_after_the_hourly_window() {
        let _g = isolated();
        let budget = Budget {
            per_host_per_day: 1000,
            per_hour: 3,
            per_week: 1000,
        };
        let prefix = format!("hourly-{}", now_secs());
        for i in 0..3 {
            let host = format!("{prefix}-{i}.example");
            assert!(admit(DEAD_URL, "acme-cron", &host, budget).await.is_ok());
        }
        let host = format!("{prefix}-overflow.example");
        match admit(DEAD_URL, "acme-cron", &host, budget).await {
            Err(r) => assert_eq!(r.window, Window::Hour),
            Ok(()) => panic!("the hourly window must bound a burst of distinct names"),
        }
    }

    /// The weekly window is the one that protects Let's Encrypt's
    /// 50/registered-domain/week allowance.
    #[tokio::test]
    async fn fallback_refuses_after_the_weekly_window() {
        let _g = isolated();
        let budget = Budget {
            per_host_per_day: 1000,
            per_hour: 1000,
            per_week: 2,
        };
        let prefix = format!("weekly-{}", now_secs());
        for i in 0..2 {
            let host = format!("{prefix}-{i}.example");
            assert!(admit(DEAD_URL, "acme-cron", &host, budget).await.is_ok());
        }
        let host = format!("{prefix}-overflow.example");
        match admit(DEAD_URL, "acme-cron", &host, budget).await {
            Err(r) => {
                assert_eq!(r.window, Window::Week);
                // The retry hint is the time left in the bucket, not a
                // flat week - the caller resumes as soon as it rolls.
                assert!(r.retry_after > 0 && r.retry_after <= 604_800);
            }
            Ok(()) => panic!("the weekly window must bound total burn"),
        }
    }
}
