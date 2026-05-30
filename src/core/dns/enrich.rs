//! ECS systems that bridge the rDNS worker pool and the `RdnsCache`.
//!
//! The work is split across three systems so the hot path stays cheap:
//!   * `request_lookups` — fires only for *newly-spawned* flows (`Added<FlowKey>`),
//!     queueing src/dst on first sight.
//!   * `refresh_stale_dns` — gated by a `Local<Timer>`; walks the cache on a
//!     slow cadence and re-enqueues entries past `cache_ttl_seconds`.
//!   * `apply_results` — drains whatever the workers produced since the last
//!     tick and writes outcomes back into the cache.
//!
//! All three run in `PreUpdate` after `ingest`, so newly-spawned flows are
//! visible immediately and the overlay sees fresh data on the very next render.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use bevy_ecs::prelude::*;
use crossbeam_channel::TrySendError;

use crate::core::dns::{RdnsCache, RdnsEntry, RdnsRequestTx, RdnsResultRx, RdnsStatus};
use crate::core::flows::components::FlowKey;
use crate::core::settings::settings;

/// Cadence of the TTL sweep. Hot-path enqueues already happen on flow spawn,
/// so this only handles re-resolution of long-lived entries — a sweep every
/// few seconds is plenty. Wired into the scheduler via
/// `.run_if(on_timer(TTL_SWEEP_INTERVAL))` in `core/dns/mod.rs`, so the
/// system's `ResMut<RdnsCache>` slot is only reserved on firing ticks.
pub const TTL_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Queue lookups for every *newly-spawned* flow's src/dst. Run on the hot
/// path every tick, but the `Added<FlowKey>` filter keeps it O(new-flows)
/// rather than O(all-flows). The slow-path TTL refresh lives in
/// `refresh_stale_dns`.
pub fn request_lookups(
    tx: Res<RdnsRequestTx>,
    mut cache: ResMut<RdnsCache>,
    new_flows: Query<&FlowKey, Added<FlowKey>>,
) {
    let now = Instant::now();
    let mut dropped_for_full: u32 = 0;

    for key in new_flows.iter() {
        maybe_enqueue(key.src_ip, &tx.0, &mut cache, now, &mut dropped_for_full);
        maybe_enqueue(key.dst_ip, &tx.0, &mut cache, now, &mut dropped_for_full);
    }

    if dropped_for_full > 0 {
        // One warn per tick is enough — the same IP will be retried by the
        // TTL sweep and quiet the log naturally as soon as the workers
        // catch up.
        tracing::warn!(
            "dns request queue full, dropped {} enqueues this tick",
            dropped_for_full
        );
    }
}

/// Slow-cadence refresher: walks the cache, finds entries past
/// `cache_ttl_seconds`, and re-enqueues them. Skips `Pending` (still in
/// flight) and `Private` (we never query non-routable IPs). Gated by
/// `on_timer(TTL_SWEEP_INTERVAL)` at the registration site, so the body
/// only runs on the firing tick.
pub fn refresh_stale_dns(tx: Res<RdnsRequestTx>, mut cache: ResMut<RdnsCache>) {
    let now = Instant::now();
    let ttl = Duration::from_secs(settings().dns.cache_ttl_seconds);

    // Collect first to avoid holding an immutable borrow of `cache` while we
    // mutate it below. The vec is bounded by the cache size, which is itself
    // bounded by the LRU cap in `RdnsCache`.
    let stale: Vec<IpAddr> = cache
        .iter()
        .filter(|(_, entry)| match entry.status {
            // In flight already, or we never query these.
            RdnsStatus::Pending | RdnsStatus::Private => false,
            _ => now.duration_since(entry.last_lookup) >= ttl,
        })
        .map(|(ip, _)| *ip)
        .collect();

    if stale.is_empty() {
        return;
    }

    let mut dropped_for_full: u32 = 0;
    for ip in stale {
        match tx.0.try_send(ip) {
            Ok(()) => {
                cache.insert(
                    ip,
                    RdnsEntry {
                        status: RdnsStatus::Pending,
                        last_lookup: now,
                    },
                );
            }
            Err(TrySendError::Full(_)) => {
                dropped_for_full += 1;
            }
            Err(TrySendError::Disconnected(_)) => return,
        }
    }

    if dropped_for_full > 0 {
        tracing::warn!(
            "dns ttl sweep: queue full, dropped {} re-enqueues",
            dropped_for_full
        );
    }
}

fn maybe_enqueue(
    ip: IpAddr,
    tx: &crossbeam_channel::Sender<IpAddr>,
    cache: &mut RdnsCache,
    now: Instant,
    dropped_for_full: &mut u32,
) {
    // A new flow may still reference an IP we already know about (another
    // flow saw it first). Skip if we have any non-stale entry — the TTL
    // sweep handles re-resolution from that point.
    if cache.contains_key(&ip) {
        return;
    }

    match tx.try_send(ip) {
        Ok(()) => {
            cache.insert(
                ip,
                RdnsEntry {
                    status: RdnsStatus::Pending,
                    last_lookup: now,
                },
            );
        }
        Err(TrySendError::Full(_)) => {
            // Leave the cache as-is so the TTL sweep retries on the next
            // pass once the workers catch up.
            *dropped_for_full += 1;
        }
        Err(TrySendError::Disconnected(_)) => {
            // Workers are gone (process tearing down). Nothing more to do.
        }
    }
}

/// Drain whatever the workers produced and write the outcomes into the
/// cache. Non-blocking; cheap when idle.
pub fn apply_results(rx: Res<RdnsResultRx>, mut cache: ResMut<RdnsCache>) {
    let now = Instant::now();
    while let Ok((ip, status)) = rx.0.try_recv() {
        cache.insert(
            ip,
            RdnsEntry {
                status,
                last_lookup: now,
            },
        );
    }
}
