//! Shared constructors for `#[cfg(test)]` modules across `core::flows`.
//! Add a helper here only once a second caller appears — no premature helpers.

use std::net::IpAddr;

use super::{LocalAddrs, components::{FlowKey, TrafficStats}};

/// Build a `FlowKey` from string IPs, ports, and proto number.
pub fn flow_key(src: &str, sport: u16, dst: &str, dport: u16, proto: u8) -> FlowKey {
    FlowKey {
        src_ip: src.parse().expect("valid src IP"),
        dst_ip: dst.parse().expect("valid dst IP"),
        src_port: sport,
        dst_port: dport,
        proto,
    }
}

/// Build a `LocalAddrs` from a slice of IP strings.
pub fn local_addrs(ips: &[&str]) -> LocalAddrs {
    LocalAddrs(
        ips.iter()
            .map(|s| s.parse::<IpAddr>().expect("valid IP"))
            .collect(),
    )
}

/// Build a `TrafficStats` with the given cumulative and rate values.
pub fn traffic_stats(bytes: u64, bps: f32, packets: u64) -> TrafficStats {
    TrafficStats { bytes, bps, packets, bytes_since_last_tick: 0 }
}
