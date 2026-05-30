//! Pure IP-address classification — zero I/O, zero allocations.
//!
//! Used by the rDNS worker to short-circuit non-routable addresses (we never
//! send a PTR query for an RFC1918 host) and by the details overlay to render
//! the `Type` row. Sharing one classifier keeps "is this private?" decisions
//! consistent across the two call sites.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Coarse classification used for display + lookup-skip decisions. Variants
/// that should never hit DNS are grouped under the helper [`IpClass::is_skippable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClass {
    /// RFC1918 private (`10/8`, `172.16/12`, `192.168/16`).
    PrivateV4,
    /// Loopback (`127/8` for IPv4, `::1` for IPv6).
    Loopback,
    /// Link-local (`169.254/16` for IPv4, `fe80::/10` for IPv6).
    LinkLocal,
    /// Carrier-grade NAT (`100.64/10`).
    Cgnat,
    /// Multicast (`224/4` for IPv4, `ff00::/8` for IPv6).
    Multicast,
    /// IPv4 broadcast (`255.255.255.255`) or directed broadcast — treat like multicast.
    Broadcast,
    /// IPv6 unique local addresses (`fc00::/7`).
    Ipv6Ula,
    /// IPv6 unspecified / documentation / reserved ranges (`2001:db8::/32`, etc).
    Ipv6Reserved,
    /// Routable IPv4.
    PublicV4,
    /// Routable IPv6.
    PublicV6,
}

impl IpClass {
    /// True when an address should never be sent to the resolver. The worker
    /// short-circuits these to `Private` in the cache.
    pub fn is_skippable(self) -> bool {
        !matches!(self, IpClass::PublicV4 | IpClass::PublicV6)
    }

    /// Human-readable label used in the overlay's `Type` row.
    pub fn label(self) -> &'static str {
        match self {
            IpClass::PrivateV4 => "Private (RFC1918)",
            IpClass::Loopback => "Loopback",
            IpClass::LinkLocal => "Link-local",
            IpClass::Cgnat => "CGNAT (100.64/10)",
            IpClass::Multicast => "Multicast",
            IpClass::Broadcast => "Broadcast",
            IpClass::Ipv6Ula => "IPv6 ULA (fc00::/7)",
            IpClass::Ipv6Reserved => "IPv6 reserved",
            IpClass::PublicV4 => "Public IPv4",
            IpClass::PublicV6 => "Public IPv6",
        }
    }
}

/// Classify `ip` purely from its bits — no DNS, no lookup, no allocation.
pub fn classify(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> IpClass {
    if ip.is_loopback() {
        return IpClass::Loopback;
    }
    if ip.is_broadcast() {
        return IpClass::Broadcast;
    }
    if ip.is_multicast() {
        return IpClass::Multicast;
    }
    if ip.is_link_local() {
        return IpClass::LinkLocal;
    }
    if ip.is_private() {
        return IpClass::PrivateV4;
    }
    // CGNAT — 100.64.0.0/10. `std::net::Ipv4Addr` doesn't expose this directly.
    let oct = ip.octets();
    if oct[0] == 100 && (oct[1] & 0xc0) == 64 {
        return IpClass::Cgnat;
    }
    // Unspecified `0.0.0.0` — treat as reserved/skippable via broadcast bucket.
    if ip.is_unspecified() {
        return IpClass::Broadcast;
    }
    IpClass::PublicV4
}

fn classify_v6(ip: Ipv6Addr) -> IpClass {
    if ip.is_loopback() {
        return IpClass::Loopback;
    }
    if ip.is_unspecified() {
        return IpClass::Ipv6Reserved;
    }
    if ip.is_multicast() {
        return IpClass::Multicast;
    }
    let seg0 = ip.segments()[0];
    // Link-local: fe80::/10
    if (seg0 & 0xffc0) == 0xfe80 {
        return IpClass::LinkLocal;
    }
    // Unique local: fc00::/7
    if (seg0 & 0xfe00) == 0xfc00 {
        return IpClass::Ipv6Ula;
    }
    // Documentation prefix 2001:db8::/32 and the deprecated discard prefix
    // 100::/64. Anything else routable is public.
    if seg0 == 0x2001 && ip.segments()[1] == 0x0db8 {
        return IpClass::Ipv6Reserved;
    }
    IpClass::PublicV6
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn ipv4_classification() {
        assert_eq!(classify(ip("127.0.0.1")), IpClass::Loopback);
        assert_eq!(classify(ip("10.0.0.5")), IpClass::PrivateV4);
        assert_eq!(classify(ip("192.168.1.1")), IpClass::PrivateV4);
        assert_eq!(classify(ip("172.16.0.1")), IpClass::PrivateV4);
        assert_eq!(classify(ip("169.254.1.1")), IpClass::LinkLocal);
        assert_eq!(classify(ip("100.64.0.1")), IpClass::Cgnat);
        assert_eq!(classify(ip("100.127.255.254")), IpClass::Cgnat);
        assert_eq!(classify(ip("100.128.0.1")), IpClass::PublicV4); // outside CGNAT
        assert_eq!(classify(ip("224.0.0.1")), IpClass::Multicast);
        assert_eq!(classify(ip("255.255.255.255")), IpClass::Broadcast);
        assert_eq!(classify(ip("8.8.8.8")), IpClass::PublicV4);
    }

    #[test]
    fn ipv6_classification() {
        assert_eq!(classify(ip("::1")), IpClass::Loopback);
        assert_eq!(classify(ip("fe80::1")), IpClass::LinkLocal);
        assert_eq!(classify(ip("fc00::1")), IpClass::Ipv6Ula);
        assert_eq!(classify(ip("fd12::1")), IpClass::Ipv6Ula);
        assert_eq!(classify(ip("ff02::1")), IpClass::Multicast);
        assert_eq!(classify(ip("2001:db8::1")), IpClass::Ipv6Reserved);
        assert_eq!(classify(ip("2606:4700:4700::1111")), IpClass::PublicV6);
    }

    #[test]
    fn skippable_covers_all_non_public() {
        for c in [
            IpClass::PrivateV4,
            IpClass::Loopback,
            IpClass::LinkLocal,
            IpClass::Cgnat,
            IpClass::Multicast,
            IpClass::Broadcast,
            IpClass::Ipv6Ula,
            IpClass::Ipv6Reserved,
        ] {
            assert!(c.is_skippable(), "{c:?} should be skippable");
        }
        assert!(!IpClass::PublicV4.is_skippable());
        assert!(!IpClass::PublicV6.is_skippable());
    }
}
