use std::net::IpAddr;
use std::time::Instant;

use bevy_ecs::prelude::Component;

use crate::core::flows::LocalAddrs;
use crate::core::flows::dpi::AppKind;


#[derive(Component, Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

/// Which way a (unidirectional) flow points relative to this host, classified
/// once at spawn from `LocalAddrs`. We deliberately do *not* canonicalize the
/// two opposing 5-tuples of a connection into one row (see the plan's
/// non-goals); instead each flow is tagged independently, and the directional
/// throughput rollup in `aggregate::tick` sums tx vs rx across all flows.
#[derive(Component, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// Source is one of our addresses → we're sending.
    Outbound,
    /// Destination is one of our addresses → we're receiving.
    Inbound,
    /// Both endpoints are local (loopback / host-to-host on the same machine).
    Local,
    /// Neither endpoint is ours — forwarded/observed traffic (e.g. on `any`
    /// or in promiscuous mode), or we couldn't enumerate local addrs.
    #[default]
    Unknown,
}

impl Direction {
    /// Classify a flow from the set of this host's addresses.
    pub fn classify(key: &FlowKey, local: &LocalAddrs) -> Self {
        match (local.contains(&key.src_ip), local.contains(&key.dst_ip)) {
            (true, true) => Direction::Local,
            (true, false) => Direction::Outbound,
            (false, true) => Direction::Inbound,
            (false, false) => Direction::Unknown,
        }
    }

    /// Lower-case label for the details overlay.
    pub fn label(&self) -> &'static str {
        match self {
            Direction::Outbound => "outbound",
            Direction::Inbound => "inbound",
            Direction::Local => "local",
            Direction::Unknown => "unknown",
        }
    }
}

#[derive(Component, Default, Debug, Clone)]
pub struct TrafficStats {
    pub bytes: u64,
    pub packets: u64,
    pub bps: f32,
    pub bytes_since_last_tick: u64,
}

#[derive(Component, Debug)]
pub struct Timeline {
    pub buckets: [u32; 60],
    pub head: u8,
    pub current_bucket_bytes: u32,
    pub last_rotate: Instant,
}

impl Default for Timeline {
    fn default() -> Self {
        Self {
            buckets: [0; 60],
            head: 0,
            current_bucket_bytes: 0,
            last_rotate: Instant::now(),
        }
    }
}

/// Per-flow metadata that doesn't fit the bandwidth-stats hot path. Carries the
/// most recent protocol summary string (e.g. `"TCP [S.]"`, `"UDP len=512"`) and
/// the DPI-extracted app-layer host (TLS SNI / first DNS query name). rDNS lives
/// separately in `RdnsCache` (IP-keyed, shared across flows).
#[derive(Component, Default, Debug, Clone)]
pub struct Metadata {
    pub last_summary: Option<String>,
    /// App-layer hostname the client asked for, with its source kind. Set once
    /// on first sighting by `ingest` and never overwritten (the handshake/query
    /// that produced it can't change for the flow's lifetime).
    pub app_host: Option<(AppKind, String)>,
}

#[derive(Component, Debug)]
pub struct LastSeen(pub Instant);

impl Default for LastSeen {
    fn default() -> Self {
        Self(Instant::now())
    }
}

/// Wall-clock instant the flow first appeared. Stable for the lifetime of the
/// entity; used as the dashboard's tiebreaker when no explicit sort column is
/// chosen so rows render in insertion order instead of jumping around.
#[derive(Component, Debug, Clone, Copy)]
pub struct FirstSeen(pub Instant);

impl Default for FirstSeen {
    fn default() -> Self {
        Self(Instant::now())
    }
}

/// Marker stamped on a flow that has gone silent past `idle_timeout_seconds`
/// (see `cleanup::expire_idle`). The entity *and* its `FlowIndex` entry
/// survive — this only flags the flow out of the "active" set so it renders
/// dimmed and can be filtered. `ingest` removes the marker again if traffic
/// returns (flow revival), and `cleanup::evict_expired` is the sole place an
/// expired flow is finally despawned, once the retained set exceeds the cap.
#[derive(Component, Debug)]
pub struct Expired;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(src: IpAddr, dst: IpAddr) -> FlowKey {
        FlowKey {
            src_ip: src,
            dst_ip: dst,
            src_port: 1234,
            dst_port: 443,
            proto: 6,
        }
    }

    #[test]
    fn classifies_direction_from_local_addrs() {
        let me = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let peer = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let local = LocalAddrs([me].into_iter().collect());

        // src is ours → we're sending; dst is ours → we're receiving.
        assert_eq!(Direction::classify(&key(me, peer), &local), Direction::Outbound);
        assert_eq!(Direction::classify(&key(peer, me), &local), Direction::Inbound);
        // Both ours = loopback/host-local; neither ours = observed/forwarded.
        assert_eq!(Direction::classify(&key(me, me), &local), Direction::Local);
        assert_eq!(
            Direction::classify(&key(peer, peer), &local),
            Direction::Unknown
        );
    }
}
