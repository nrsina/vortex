//! Reverse-DNS enrichment.
//!
//! Mirrors the shape of `core/processes`: a dedicated worker pool runs the
//! blocking lookups on its own OS threads (so the UI never stalls on libc's
//! uncontrollable timeout), with results funneled back to the ECS world via
//! a bounded channel and surfaced through the `RdnsCache` resource.
//!
//! Lookup strategy is eager: `request_lookups` queues both endpoints of every
//! newly-spawned flow on first sight. Cache deduplication by IP and an
//! `ipclass` short-circuit for non-routable addresses keep that cheap. Three
//! mitigations protect against pathological cases:
//!   1. Bounded request queue — caps memory under flood, warns on overflow.
//!   2. Token-bucket QPS cap — shared across workers, smooths bursts.
//!   3. Per-thread failure backoff — sleeps after N consecutive failures so
//!      we don't hammer a dead resolver.
//!
//! See `ARCHITECTURE.md` for the data-flow diagram.

pub mod enrich;
pub mod worker;

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bevy_app::{App, Plugin, Update};
use bevy_ecs::prelude::*;
use bevy_ecs::schedule::common_conditions::resource_exists;
use bevy_time::common_conditions::on_timer;
use crossbeam_channel::{Receiver, Sender};
use rustc_hash::FxHashMap;

use crate::core::settings::settings;
use enrich::{TTL_SWEEP_INTERVAL, apply_results, refresh_stale_dns, request_lookups};
use worker::{RateLimiter, RdnsResult};

/// Status of a single IP's reverse-DNS lookup. The cache holds one of these
/// per IP regardless of how many flows reference it.
#[derive(Debug, Clone)]
pub enum RdnsStatus {
    /// Queued or in-flight. Renders as `(resolving…)`.
    Pending,
    /// PTR returned a hostname.
    Resolved(String),
    /// Lookup completed but returned no PTR record (or libc rejected it).
    /// We distinguish this from `Failed` in case a future UI wants to render
    /// them differently — for now they both render as `(no PTR)` / `(failed)`.
    NxDomain,
    /// Lookup errored (network unreachable, resolver refused, timeout, etc).
    Failed,
    /// IP is non-routable (loopback, RFC1918, link-local, multicast, …) — we
    /// short-circuited the worker and never sent a query.
    Private,
}

#[derive(Debug, Clone)]
pub struct RdnsEntry {
    pub status: RdnsStatus,
    /// When the last lookup completed (or when `Pending` was first set).
    /// `request_lookups` uses this to decide whether to re-query after TTL.
    pub last_lookup: Instant,
}

/// Single source of truth for hostname state across the app. Both the inline
/// dst-column substitution (dashboard + processes tree) and the details
/// overlay read from this map.
///
/// Implements a bounded LRU: once `cap` entries are present, inserting a new
/// key evicts the front of `order` (the oldest insertion). Re-inserting the
/// same key (a TTL refresh or a status transition like `Pending → Resolved`)
/// does *not* reorder — the cost of an O(n) `VecDeque` scan per cache write
/// outweighs the value of perfect LRU semantics for our access pattern, which
/// is dominated by once-per-IP writes.
#[derive(Resource)]
pub struct RdnsCache {
    map: FxHashMap<IpAddr, RdnsEntry>,
    /// Front = oldest, back = newest. Only tracks first insertion of each key.
    order: VecDeque<IpAddr>,
    cap: usize,
}

impl Default for RdnsCache {
    fn default() -> Self {
        // Unbounded fallback used when DNS is disabled. The cache will simply
        // never have entries written to it, so `usize::MAX` cap is harmless.
        Self::with_cap(usize::MAX)
    }
}

impl RdnsCache {
    pub fn with_cap(cap: usize) -> Self {
        Self {
            map: FxHashMap::default(),
            order: VecDeque::new(),
            cap,
        }
    }

    /// Insert (or overwrite) an entry. New keys may evict the oldest entry
    /// when `cap` is exceeded. Returns the evicted IP if any, for logging.
    pub fn insert(&mut self, ip: IpAddr, entry: RdnsEntry) -> Option<IpAddr> {
        let mut evicted = None;
        if !self.map.contains_key(&ip) {
            // First time we see this IP. Make room before pushing.
            while self.map.len() >= self.cap {
                if let Some(oldest) = self.order.pop_front() {
                    self.map.remove(&oldest);
                    evicted.get_or_insert(oldest);
                } else {
                    break;
                }
            }
            self.order.push_back(ip);
        }
        self.map.insert(ip, entry);
        evicted
    }

    pub fn get(&self, ip: &IpAddr) -> Option<&RdnsEntry> {
        self.map.get(ip)
    }

    pub fn contains_key(&self, ip: &IpAddr) -> bool {
        self.map.contains_key(ip)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&IpAddr, &RdnsEntry)> {
        self.map.iter()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Render-friendly accessor: returns the hostname when `Resolved`, else
    /// `None`. Used by `dst_label` to decide whether to substitute.
    pub fn hostname(&self, ip: &IpAddr) -> Option<&str> {
        match self.map.get(ip).map(|e| &e.status) {
            Some(RdnsStatus::Resolved(h)) => Some(h.as_str()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, last))
    }

    fn resolved(host: &str) -> RdnsEntry {
        RdnsEntry { status: RdnsStatus::Resolved(host.to_string()), last_lookup: Instant::now() }
    }

    fn pending() -> RdnsEntry {
        RdnsEntry { status: RdnsStatus::Pending, last_lookup: Instant::now() }
    }

    #[test]
    fn insert_and_get_round_trips() {
        let mut cache = RdnsCache::with_cap(10);
        cache.insert(ip(1), resolved("example.com"));
        let e = cache.get(&ip(1)).expect("entry should be present");
        assert!(matches!(&e.status, RdnsStatus::Resolved(h) if h == "example.com"));
    }

    #[test]
    fn contains_key_true_after_insert() {
        let mut cache = RdnsCache::with_cap(10);
        assert!(!cache.contains_key(&ip(1)));
        cache.insert(ip(1), pending());
        assert!(cache.contains_key(&ip(1)));
    }

    #[test]
    fn hostname_returns_resolved_hostname() {
        let mut cache = RdnsCache::with_cap(10);
        cache.insert(ip(1), resolved("host.example.com"));
        assert_eq!(cache.hostname(&ip(1)), Some("host.example.com"));
    }

    #[test]
    fn hostname_returns_none_for_non_resolved_statuses() {
        let mut cache = RdnsCache::with_cap(10);
        cache.insert(ip(1), pending());
        assert_eq!(cache.hostname(&ip(1)), None);
        // NxDomain also returns None.
        cache.insert(ip(2), RdnsEntry { status: RdnsStatus::NxDomain, last_lookup: Instant::now() });
        assert_eq!(cache.hostname(&ip(2)), None);
    }

    #[test]
    fn insert_new_key_evicts_oldest_at_cap() {
        let mut cache = RdnsCache::with_cap(2);
        assert_eq!(cache.insert(ip(1), resolved("one.example")), None);
        assert_eq!(cache.insert(ip(2), resolved("two.example")), None);
        // Third insert should evict ip(1), the oldest.
        let evicted = cache.insert(ip(3), resolved("three.example"));
        assert_eq!(evicted, Some(ip(1)));
        assert!(!cache.contains_key(&ip(1)), "evicted key must be gone");
        assert!(cache.contains_key(&ip(2)));
        assert!(cache.contains_key(&ip(3)));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn update_existing_does_not_evict_and_stays_at_cap() {
        let mut cache = RdnsCache::with_cap(2);
        cache.insert(ip(1), pending());
        cache.insert(ip(2), pending());
        // Updating ip(1) from Pending → Resolved must not evict anything.
        let evicted = cache.insert(ip(1), resolved("updated.example"));
        assert_eq!(evicted, None, "re-insert of existing key must not evict");
        assert_eq!(cache.len(), 2, "map must not grow beyond cap");
        assert!(cache.contains_key(&ip(1)));
        assert!(cache.contains_key(&ip(2)));
    }

    #[test]
    fn update_existing_overwrites_entry() {
        let mut cache = RdnsCache::with_cap(10);
        cache.insert(ip(1), pending());
        cache.insert(ip(1), resolved("after.example"));
        assert_eq!(cache.hostname(&ip(1)), Some("after.example"));
    }
}

/// Depth of the worker → main result channel. Small and drop-newest on
/// `Full`: stale results are worthless and a stalled main thread shouldn't OOM
/// us — the cache entry stays `Pending` and the next TTL sweep retries.
const RESULT_CHANNEL_CAPACITY: usize = 256;

/// Producer half of the main → worker request channel. Bounded so a flood
/// can't grow memory unboundedly; `request_lookups` warns on `Full` and
/// re-tries on the next tick.
#[derive(Resource)]
pub struct RdnsRequestTx(pub Sender<IpAddr>);

/// Consumer half of the worker → main result channel.
#[derive(Resource)]
pub struct RdnsResultRx(pub Receiver<RdnsResult>);

pub struct DnsPlugin;

impl Plugin for DnsPlugin {
    fn build(&self, app: &mut App) {
        let cfg = settings().dns;
        // Cache always exists — the overlay's hostname lookups must not panic
        // when DNS is disabled. When enabled, build it with the configured
        // LRU cap so long sessions on busy hosts don't grow it unbounded.
        let cache = if cfg.enabled {
            RdnsCache::with_cap(cfg.cache_cap)
        } else {
            RdnsCache::default()
        };
        app.insert_resource(cache);

        if !cfg.enabled {
            tracing::info!("rDNS enrichment disabled via [dns].enabled = false");
            return;
        }

        let (req_tx, req_rx) = crossbeam_channel::bounded::<IpAddr>(cfg.request_queue_cap);
        let (res_tx, res_rx) =
            crossbeam_channel::bounded::<RdnsResult>(RESULT_CHANNEL_CAPACITY);

        let rate = Arc::new(Mutex::new(RateLimiter::new(cfg.dns_qps_cap as f32)));
        for n in 0..cfg.worker_threads {
            worker::spawn(
                n,
                req_rx.clone(),
                res_tx.clone(),
                Arc::clone(&rate),
                cfg.failure_backoff_threshold,
                cfg.failure_backoff_seconds,
            );
        }
        // Drop the original sender so workers terminate cleanly at process
        // exit (when `RdnsRequestTx` is dropped from the world).
        drop(res_tx);

        app.insert_resource(RdnsRequestTx(req_tx));
        app.insert_resource(RdnsResultRx(res_rx));

        // These run in `Update` (not `PreUpdate`) so they overlap the heaviest
        // `Update` system, `aggregate::tick`, under the parallel executor —
        // their resources (`RdnsCache`, `FlowKey`-read) are disjoint from its
        // (`TrafficStats`/`Timeline`). Cross-phase ordering after `ingest`
        // (which stays in `PreUpdate`) is automatic, so no explicit `.after`
        // edge is needed — `Added<FlowKey>` still fires here because `ingest`'s
        // spawns are flushed at the `PreUpdate` phase end.
        //
        // Ordering: queue new-flow lookups first, then drain results — keeps
        // cache state coherent within a tick. `refresh_stale_dns` is gated by
        // `on_timer(TTL_SWEEP_INTERVAL)`, so on idle ticks (149 of every 150
        // at 30 Hz) it doesn't reserve the `ResMut<RdnsCache>` slot and the
        // other two get clean sequential access. All three are gated on the
        // request/result resources existing so they're cleanly skipped when
        // DNS is disabled.
        app.add_systems(
            Update,
            (
                request_lookups.run_if(resource_exists::<RdnsRequestTx>),
                apply_results
                    .after(request_lookups)
                    .run_if(resource_exists::<RdnsResultRx>),
                refresh_stale_dns
                    .run_if(resource_exists::<RdnsRequestTx>)
                    .run_if(on_timer(TTL_SWEEP_INTERVAL)),
            ),
        );

        tracing::info!(
            "rDNS enabled (workers = {}, qps_cap = {}, ttl = {}s, queue_cap = {})",
            cfg.worker_threads,
            cfg.dns_qps_cap,
            cfg.cache_ttl_seconds,
            cfg.request_queue_cap,
        );
    }
}
