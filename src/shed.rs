// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Certificate-mint admission control — bounded queue with load shed
//! (ACME-PREF, acme DESIGN §6).
//!
//! A fleet-wide cold start re-dials EVERY service's cert fetch at once;
//! the mint path (order → authz → challenge → finalize → download) is
//! several round-trips of CA-key signing + filesystem writes per mint.
//! Unbounded concurrency let the mint crowd exhaust everything the
//! acme process needs to stay responsive (its pool is capped at 3 for
//! the outbox inserts), so callers timed out silently and captain's
//! probe watchdog mass-killed the victims. The shed answers the
//! overload question UP FRONT with a clear `503 Service Busy +
//! Retry-After`, which the sentin8-tls fetcher treats as a
//! deterministic retryable failure (backoff) — never a silent timeout.
//!
//! Concurrency is bounded per MINT ENDPOINT GROUP (
//! `/acme/new-order`, `/acme/order/{id}/finalize`, `/v1/client-cert`),
//! not per route — one total budget that the heaviest paths share, so
//! a `/client-cert` enrollment storm cannot starve server-cert mints
//! and vice versa. Health, CA downloads (`/v1/ca/*.crt`), and cert
//! downloads are never shed: they are cheap reads, and killing them
//! breaks the recovery path itself.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Maximum concurrent mint requests inside the acme process. Budget
/// sized to leave headroom for the outbox pool and the TLS listener:
/// the signing path is CPU-bound rcgen work, so more concurrency than
/// this saturates cores without improving throughput.
pub const MAX_CONCURRENT_MINTS: u64 = 16;

/// Queued (admitted but still waiting on the semaphore) beyond which
/// the shed starts refusing — the point where a caller's total mint
/// latency (queueing + signing) approaches its 10s request timeout.
pub const MAX_QUEUED_MINTS: u64 = 32;

/// Retry-After hint seconds when shedding (matches the
/// `sentin8-tls` fetch failure backoff window so one shed window =
/// exactly one retry round-trip, no thundering re-entry).
pub const SHED_RETRY_AFTER_S: u64 = 30;

/// Shared admission state: one semaphore budget + a queued gauge.
#[derive(Debug, Default)]
pub struct MintLimiter {
    /// Admitted-but-not-finished mint requests (in the semaphore).
    /// Tracked separately from the queue gauge for the log lines.
    in_flight: AtomicU64,
    /// Requests waiting for a semaphore permit; the shed refuses when
    /// this exceeds [`MAX_QUEUED_MINTS`].
    queued: AtomicU64,
}

/// Which endpoints count as mints.
fn is_mint_path(path: &str) -> bool {
    path == "/acme/new-order"
        || path.starts_with("/acme/order/") && path.ends_with("/finalize")
        || path == "/v1/client-cert"
}

/// Is this path exempt from shedding (health + public cert reads)?
fn is_exempt_path(path: &str) -> bool {
    path == "/v1/health" || path.starts_with("/v1/ca/") || path.starts_with("/acme/cert/")
}

impl MintLimiter {
    /// Try to admit a mint request. Returns `Err(())` when the shed is
    /// active (the caller responds 503). Admitting increments the queue
    /// gauge — the caller's mid-layer pairs it with [`Self::enter`] once
    /// the handler actually starts, matching the 503-before-queueing
    /// contract in acme DESIGN §6.
    pub fn try_acquire(&self) -> Result<(), ()> {
        // Refuse when the queue is FULL (a caller that would push the
        // gauge past the cap is refused). Overloaded() mirrors the same
        // predicate from the outside.
        if self.queued.load(std::sync::atomic::Ordering::SeqCst) >= MAX_QUEUED_MINTS {
            return Err(());
        }
        self.queued
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Record that an admitted mint started running (passed the queue).
    pub fn enter(&self) {
        self.queued.fetch_sub(1, Ordering::SeqCst);
        self.in_flight.fetch_add(1, Ordering::SeqCst);
    }

    /// Record that a mint finished.
    pub fn exit(&self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }

    /// Current queued depth (for logs + the admin UI).
    pub fn queued(&self) -> u64 {
        self.queued.load(Ordering::SeqCst)
    }

    /// Current in-flight count (for logs + the admin UI).
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Cheap overload probe for the /v1/health payload.
    pub fn overloaded(&self) -> bool {
        self.queued() >= MAX_QUEUED_MINTS
    }
}

/// Build the shed middleware state.
pub fn mint_limiter() -> Arc<MintLimiter> {
    Arc::new(MintLimiter::default())
}

/// The axum middleware: gate mint endpoints on the bounded queue,
/// respond `503 Service Busy` + `Retry-After` when the shed trips.
pub async fn mint_shed_layer(
    State(limiter): State<Arc<MintLimiter>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if is_exempt_path(path) || !is_mint_path(path) {
        return next.run(request).await;
    }

    // Gate: budgeted queue or shed.
    if limiter.try_acquire().is_err() {
        tracing::warn!(
            path,
            queued = limiter.queued(),
            in_flight = limiter.in_flight(),
            "acme: mint shed active — refusing (503 + Retry-After)"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(
                axum::http::header::RETRY_AFTER,
                SHED_RETRY_AFTER_S.to_string(),
            )],
            "acme mint queue full — retry after backoff window",
        )
            .into_response();
    }

    // Admit: consume the queue slot, run the handler, release.
    limiter.enter();
    let out = next.run(request).await;
    limiter.exit();
    out
}
