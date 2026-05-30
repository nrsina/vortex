//! Cross-screen helpers shared by the dashboard, picker, and processes
//! modules. Anything here must be screen-agnostic — types or functions that
//! belong to a single screen should live in that screen's module instead.

use std::net::IpAddr;

use ratatui::{
    style::{Modifier, Style},
    widgets::Cell,
};

use crate::core::common::{IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};
use crate::core::dns::RdnsCache;
use crate::core::flows::components::{Direction, FlowKey};
use crate::screens::theme;

/// Sort direction shared by every sortable table in the app. Lives here (not
/// inside any one screen's `state.rs`) so screens don't have to depend on
/// each other to talk about the same concept.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}

impl SortDirection {
    pub fn toggle(self) -> Self {
        match self {
            SortDirection::Asc => SortDirection::Desc,
            SortDirection::Desc => SortDirection::Asc,
        }
    }
}

/// Glyph used to mark the currently-sorted column in a table header.
pub fn sort_arrow(direction: SortDirection) -> &'static str {
    match direction {
        SortDirection::Asc => "▲",
        SortDirection::Desc => "▼",
    }
}

/// Build a header `Cell` for a sortable column. When `is_sorted` is true the
/// label is suffixed with the asc/desc arrow and rendered in the accent colour
/// (bold) so the active sort key reads at a glance — the one accent doing
/// double duty as "this is the active control".
pub fn sort_header_cell(label: &str, is_sorted: bool, direction: SortDirection) -> Cell<'static> {
    if is_sorted {
        Cell::from(format!("{label} {}", sort_arrow(direction))).style(
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Cell::from(label.to_string())
    }
}

/// Map an IP protocol number to a short human-readable name. Used by both
/// flow-listing screens so the abbreviations stay consistent.
pub fn proto_name(p: u8) -> &'static str {
    match p {
        IPPROTO_TCP => "TCP",
        IPPROTO_UDP => "UDP",
        IPPROTO_ICMP => "ICMP",
        _ => "?",
    }
}

/// Width budget for IP address/hostname columns in the dashboard and
/// processes-tree. Picked to fit a typical PTR (~25 chars) plus the sort
/// arrow decoration without crowding the rest of the columns. Applied to
/// both src and dst columns.
pub const IP_COL_WIDTH: usize = 28;

/// Resolve a flow endpoint IP to the string we'll display in the table.
/// When `names_mode` is on (the default) and rDNS has a `Resolved` entry,
/// returns the hostname (middle-ellipsized if it exceeds [`IP_COL_WIDTH`]).
/// Otherwise returns the raw IP — so the column is never blank.
///
/// Pulled out into `screens::common` so both src and dst columns, across
/// the dashboard and processes-tree renderer, call the exact same function.
pub fn ip_label(ip: IpAddr, rdns: &RdnsCache, names_mode: bool) -> String {
    if !names_mode {
        return ip.to_string();
    }
    match rdns.hostname(&ip) {
        Some(host) => ellipsize_middle(host, IP_COL_WIDTH),
        None => ip.to_string(),
    }
}

/// Middle-ellipsize `s` so it fits `max` chars. Preserves the first leading
/// label and the TLD (the two most identity-bearing pieces of a hostname)
/// and replaces the middle with `…`.
pub fn ellipsize_middle(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    if max <= 1 {
        return "…".to_string();
    }
    // Reserve one char for the ellipsis itself. Split the remainder so the
    // tail is at least as long as the head (TLD-ish info matters more).
    let budget = max - 1;
    let tail_len = budget / 2 + budget % 2;
    let head_len = budget - tail_len;
    let head: String = s.chars().take(head_len).collect();
    let tail: String = s.chars().skip(count - tail_len).collect();
    format!("{head}…{tail}")
}

/// Canonical identity shared by the two opposing 5-tuples of one connection.
/// `FlowKey`s are *directed*, so a TCP/UDP connection shows up as two flows
/// (one per direction). Ordering the two `(ip, port)` endpoints deterministically
/// means a flow and its reverse map to the *same* `ConnKey`, which is how the
/// connection view groups them. Screen-agnostic so both the dashboard and the
/// processes tree pair flows with identical logic.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct ConnKey {
    pub proto: u8,
    pub lo: (IpAddr, u16),
    pub hi: (IpAddr, u16),
}

/// Group key pairing a flow with its reverse (`src↔dst`, `sport↔dport`, same
/// proto). `IpAddr`/tuple `Ord` gives a stable lo/hi split.
pub fn conn_key(k: &FlowKey) -> ConnKey {
    let a = (k.src_ip, k.src_port);
    let b = (k.dst_ip, k.dst_port);
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    ConnKey { proto: k.proto, lo, hi }
}

/// A flow's endpoints oriented as `(local, remote)` for the merged connection
/// row. `local` is whichever side is *this host*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoints {
    pub local: (IpAddr, u16),
    pub remote: (IpAddr, u16),
}

/// Orient one flow's endpoints for display. `Direction` (classified once at
/// spawn against `LocalAddrs`) tells us which side is us:
/// - `Outbound`: we sent it → `src` is local.
/// - `Inbound`: we received it → `dst` is local.
/// - `Local`/`Unknown`: no single "us" (loopback / promiscuous / `any`), so
///   fall back to the canonical lower endpoint as `local` to stay deterministic
///   — both halves still agree, so tx/rx assignment (`lo→hi` = tx) is stable.
pub fn orient(k: &FlowKey, dir: Direction) -> Endpoints {
    match dir {
        Direction::Outbound => Endpoints {
            local: (k.src_ip, k.src_port),
            remote: (k.dst_ip, k.dst_port),
        },
        Direction::Inbound => Endpoints {
            local: (k.dst_ip, k.dst_port),
            remote: (k.src_ip, k.src_port),
        },
        Direction::Local | Direction::Unknown => {
            let ck = conn_key(k);
            Endpoints {
                local: ck.lo,
                remote: ck.hi,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::core::common::IPPROTO_TCP;

    fn key(src: (u8, u16), dst: (u8, u16)) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, src.0)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, dst.0)),
            src_port: src.1,
            dst_port: dst.1,
            proto: IPPROTO_TCP,
        }
    }

    #[test]
    fn conn_key_pairs_reverse_flows() {
        // A flow and its reverse (the two halves of one connection) must hash
        // to the same ConnKey so the connection view groups them.
        let out = key((20, 52344), (1, 443));
        let inn = key((1, 443), (20, 52344));
        assert_eq!(conn_key(&out), conn_key(&inn));
        // A different connection must not collide.
        let other = key((20, 52344), (2, 443));
        assert_ne!(conn_key(&out), conn_key(&other));
    }

    #[test]
    fn orient_uses_direction_for_local_side() {
        let out = key((20, 52344), (1, 443));
        // Outbound: src is us.
        let e = orient(&out, Direction::Outbound);
        assert_eq!(e.local, (out.src_ip, out.src_port));
        assert_eq!(e.remote, (out.dst_ip, out.dst_port));
        // Inbound (the reverse flow): dst is us — same local endpoint.
        let inn = key((1, 443), (20, 52344));
        let e2 = orient(&inn, Direction::Inbound);
        assert_eq!(e2.local, e.local);
        assert_eq!(e2.remote, e.remote);
    }

    #[test]
    fn orient_unknown_falls_back_to_canonical() {
        // Neither endpoint local: both halves orient to the same lo/hi split.
        let a = key((20, 52344), (1, 443));
        let b = key((1, 443), (20, 52344));
        let ea = orient(&a, Direction::Unknown);
        let eb = orient(&b, Direction::Unknown);
        assert_eq!(ea, eb);
        assert_eq!(ea.local, conn_key(&a).lo);
        assert_eq!(ea.remote, conn_key(&a).hi);
    }

    #[test]
    fn ellipsize_short_unchanged() {
        assert_eq!(ellipsize_middle("example.com", 28), "example.com");
    }

    #[test]
    fn ellipsize_long_middle() {
        let s = "lhr25s27-in-f14.1e100.net.something.long";
        let out = ellipsize_middle(s, 28);
        assert_eq!(out.chars().count(), 28);
        assert!(out.contains('…'));
        assert!(out.starts_with("lhr25s27"));
        assert!(out.ends_with(".long"));
    }
}
