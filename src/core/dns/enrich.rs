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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use bevy_ecs::system::RunSystemOnce;

    use super::*;
    use crate::core::flows::test_support::flow_key;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, last))
    }

    // --- request_lookups ---

    #[test]
    fn request_lookups_enqueues_both_src_and_dst_and_caches_pending() {
        let (req_tx, req_rx) = crossbeam_channel::unbounded::<IpAddr>();
        let mut world = World::new();
        world.insert_resource(RdnsRequestTx(req_tx));
        world.insert_resource(RdnsCache::with_cap(100));

        let key = flow_key("1.2.3.4", 1000, "5.6.7.8", 443, 6);
        world.spawn(key);

        world.run_system_once(request_lookups).unwrap();

        // Both endpoints must be in the request channel.
        let mut received: Vec<IpAddr> = std::iter::from_fn(|| req_rx.try_recv().ok()).collect();
        received.sort();
        let mut expected = vec![
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            "5.6.7.8".parse::<IpAddr>().unwrap(),
        ];
        expected.sort();
        assert_eq!(received, expected);

        // Both must be recorded in the cache as Pending.
        let cache = world.resource::<RdnsCache>();
        for ip in &expected {
            assert!(
                matches!(cache.get(ip).map(|e| &e.status), Some(RdnsStatus::Pending)),
                "{ip} should be Pending in cache"
            );
        }
    }

    #[test]
    fn request_lookups_skips_ips_already_in_cache() {
        let (req_tx, req_rx) = crossbeam_channel::unbounded::<IpAddr>();
        let cached_ip = ip(10);
        let mut world = World::new();
        world.insert_resource(RdnsRequestTx(req_tx));
        let mut cache = RdnsCache::with_cap(100);
        // Pre-populate so request_lookups skips the src IP.
        cache.insert(cached_ip, RdnsEntry {
            status: RdnsStatus::Resolved("cached.example".to_string()),
            last_lookup: Instant::now(),
        });
        world.insert_resource(cache);

        // Flow whose src = cached IP; dst is fresh.
        let fresh_ip = ip(20);
        let key = crate::core::flows::components::FlowKey {
            src_ip: cached_ip,
            src_port: 1000,
            dst_ip: fresh_ip,
            dst_port: 443,
            proto: 6,
        };
        world.spawn(key);

        world.run_system_once(request_lookups).unwrap();

        // Only the fresh dst IP should be enqueued.
        let received: Vec<IpAddr> = std::iter::from_fn(|| req_rx.try_recv().ok()).collect();
        assert!(!received.contains(&cached_ip), "already-cached IP must not be re-enqueued");
        assert!(received.contains(&fresh_ip), "fresh IP must be enqueued");
    }

    // --- apply_results ---

    #[test]
    fn apply_results_writes_resolved_hostname_to_cache() {
        let (res_tx, res_rx) = crossbeam_channel::unbounded::<(IpAddr, RdnsStatus)>();
        let target = ip(1);
        res_tx.send((target, RdnsStatus::Resolved("host.example.com".to_string()))).unwrap();
        drop(res_tx);

        let mut world = World::new();
        world.insert_resource(RdnsResultRx(res_rx));
        world.insert_resource(RdnsCache::with_cap(100));

        world.run_system_once(apply_results).unwrap();

        assert_eq!(
            world.resource::<RdnsCache>().hostname(&target),
            Some("host.example.com")
        );
    }

    #[test]
    fn apply_results_drains_all_pending_results() {
        let (res_tx, res_rx) = crossbeam_channel::unbounded::<(IpAddr, RdnsStatus)>();
        for i in 1..=3u8 {
            res_tx.send((ip(i), RdnsStatus::NxDomain)).unwrap();
        }
        drop(res_tx);

        let mut world = World::new();
        world.insert_resource(RdnsResultRx(res_rx));
        world.insert_resource(RdnsCache::with_cap(100));

        world.run_system_once(apply_results).unwrap();

        let cache = world.resource::<RdnsCache>();
        for i in 1..=3u8 {
            assert!(cache.contains_key(&ip(i)), "ip({i}) should be in cache after apply_results");
        }
    }
}
