//! rDNS worker pool + shared token-bucket rate limiter.
//!
//! Each worker is a dedicated OS thread that blocks on the request channel,
//! waits for a token from the shared limiter, then performs one blocking
//! `getnameinfo` via `dns_lookup`. Results funnel back to the ECS world
//! through the result channel.
//!
//! The split between "decide what to do" (main thread, `request_lookups`)
//! and "do the slow thing" (workers, here) mirrors `core/processes` so the
//! UI stays responsive even when DNS is misbehaving.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvError, Sender, TrySendError};
use dns_lookup::lookup_addr;

use crate::core::common::spawn_named;
use crate::core::dns::RdnsStatus;
use crate::core::flows::ipclass::{IpClass, classify};

/// Outcome of one lookup, shipped main-ward via the result channel.
pub type RdnsResult = (IpAddr, RdnsStatus);

/// Shared token bucket. All workers share one instance behind `Arc<Mutex<…>>`
/// so the global QPS cap is honoured regardless of `worker_threads`.
///
/// `tokens` are accrued continuously at `qps` per second up to a 1-second
/// burst capacity. A worker that wants to issue a query takes one token; if
/// fewer than 1 is available, the worker sleeps for the deficit.
pub struct RateLimiter {
    qps: f32,
    tokens: f32,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(qps: f32) -> Self {
        Self {
            qps: qps.max(1.0),
            // Start with a full bucket so the first burst (typically the
            // initial population of flows) goes out at line rate, not slowly.
            tokens: qps.max(1.0),
            last_refill: Instant::now(),
        }
    }

    /// Returns the duration the caller must sleep before a token is available.
    /// On return, one token has been deducted — the caller must proceed with
    /// the query rather than re-checking.
    fn take(&mut self) -> Duration {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f32();
        // Refill, but cap at 1 second of burst capacity. Without the cap, a
        // long-idle bucket could let a thousand queries through in a
        // millisecond.
        self.tokens = (self.tokens + elapsed * self.qps).min(self.qps);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Duration::ZERO
        } else {
            let deficit = 1.0 - self.tokens;
            self.tokens = 0.0;
            Duration::from_secs_f32(deficit / self.qps)
        }
    }
}

/// Spawn one worker thread. The thread terminates when the request channel
/// disconnects (i.e. when `RdnsRequestTx` is dropped from the world at
/// process exit).
pub fn spawn(
    n: usize,
    req_rx: Receiver<IpAddr>,
    res_tx: Sender<RdnsResult>,
    rate: Arc<Mutex<RateLimiter>>,
    failure_threshold: u32,
    failure_backoff_seconds: u64,
) {
    let name = format!("dns-{n}");
    let backoff = Duration::from_secs(failure_backoff_seconds);
    spawn_named(&name, move || {
        run(req_rx, res_tx, rate, failure_threshold, backoff);
    });
}

fn run(
    req_rx: Receiver<IpAddr>,
    res_tx: Sender<RdnsResult>,
    rate: Arc<Mutex<RateLimiter>>,
    failure_threshold: u32,
    backoff: Duration,
) {
    let mut consecutive_failures: u32 = 0;
    loop {
        let ip = match req_rx.recv() {
            Ok(ip) => ip,
            Err(RecvError) => return, // channel closed → process exiting
        };

        // Non-public IPs short-circuit before consuming a token: we never
        // touch the network for them, so they don't count against the rate
        // cap and don't reset/increment the failure counter.
        let class = classify(ip);
        if class.is_skippable() {
            send_or_drop(&res_tx, (ip, RdnsStatus::Private));
            continue;
        }

        // Acquire a token (may sleep).
        let wait = rate.lock().expect("RateLimiter poisoned").take();
        if wait > Duration::ZERO {
            std::thread::sleep(wait);
        }

        let status = match lookup_addr(&ip) {
            Ok(host) if host.is_empty() || host == ip.to_string() => {
                // libc returns the textual IP when no PTR exists; treat that
                // as `NxDomain` so the overlay can render `(no PTR)`.
                RdnsStatus::NxDomain
            }
            Ok(host) => RdnsStatus::Resolved(host),
            Err(_) => RdnsStatus::Failed,
        };

        match &status {
            RdnsStatus::Failed => {
                consecutive_failures = consecutive_failures.saturating_add(1);
            }
            RdnsStatus::Resolved(_) | RdnsStatus::NxDomain => {
                consecutive_failures = 0;
            }
            // Other variants are unreachable here (Private is handled above,
            // Pending/Disabled never come out of the worker).
            _ => {}
        }

        send_or_drop(&res_tx, (ip, status));

        // Failure backoff: once we've crossed the threshold, sleep before
        // accepting the next request. A subsequent success resets the
        // counter so we don't stay in backoff forever after one outage.
        if consecutive_failures >= failure_threshold {
            tracing::warn!(
                "dns worker: {} consecutive failures, backing off {:?}",
                consecutive_failures,
                backoff,
            );
            std::thread::sleep(backoff);
        }

        // Suppress noise from the IpClass match coverage at compile time.
        let _ = IpClass::PublicV4;
    }
}

/// `try_send` and drop on `Full` — a stalled main thread shouldn't block the
/// worker, and the cache entry will get re-queried on TTL expiry anyway.
fn send_or_drop(tx: &Sender<RdnsResult>, item: RdnsResult) {
    match tx.try_send(item) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            tracing::trace!("dns result channel full, dropping outcome");
        }
        Err(TrySendError::Disconnected(_)) => {
            // Main thread is gone — but the request channel's RecvError
            // will catch this on the next iteration too. Don't panic.
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn qps_floored_to_1() {
        // qps=0.5 is treated as 1.0; the first take must return ZERO.
        let mut r = RateLimiter::new(0.5);
        assert_eq!(r.take(), Duration::ZERO);
    }

    #[test]
    fn fresh_bucket_full_first_take_returns_zero() {
        let mut r = RateLimiter::new(5.0);
        assert_eq!(r.take(), Duration::ZERO, "bucket starts full");
    }

    #[test]
    fn ceil_qps_takes_return_zero_then_next_requires_wait() {
        // With qps=3.0 the bucket starts at 3.0 tokens: the first 3 calls
        // must all return ZERO; the 4th (made immediately) must return > ZERO.
        let mut r = RateLimiter::new(3.0);
        for i in 0..3 {
            assert_eq!(r.take(), Duration::ZERO, "take #{i} should return ZERO");
        }
        assert!(r.take() > Duration::ZERO, "4th take should require wait");
    }

    #[test]
    fn qps1_first_zero_second_nonzero() {
        let mut r = RateLimiter::new(1.0);
        assert_eq!(r.take(), Duration::ZERO);
        assert!(r.take() > Duration::ZERO);
    }

    #[test]
    fn wait_duration_roughly_one_over_qps() {
        // After draining qps=2.0 (2 free takes), the 3rd take should report
        // ~0.5 s of wait (1 token / 2 qps). We allow a generous ±20 % band to
        // stay robust against scheduler jitter.
        let mut r = RateLimiter::new(2.0);
        r.take(); // token 1
        r.take(); // token 2
        let wait = r.take();
        let secs = wait.as_secs_f32();
        assert!(
            (0.4..=0.6).contains(&secs),
            "expected ~0.5 s wait, got {secs:.3} s"
        );
    }
}
