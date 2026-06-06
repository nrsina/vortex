//! Connection-view merging for the dashboard.
//!
//! `FlowKey`s are directed, so a connection appears as two opposing flows.
//! When `UiPrefs.aggregate` is on, this module folds those two `FlowRow`s into
//! a single `ConnRow` (local ↔ remote, ↑ tx / ↓ rx / total). It's pure
//! data-shaping over the already-built `FlowRow` vec — the raw per-flow path
//! (`rows.rs` + `render::render_table`) is left completely untouched, so the
//! toggle has zero effect when off.
//!
//! The pairing/orientation primitives (`conn_key`, `orient`) live in
//! `screens::common` so the processes tree pairs flows with identical logic.

use std::cmp::Ordering;
use std::net::IpAddr;
use std::time::Instant;

use rustc_hash::FxHashMap;

use crate::core::flows::components::FlowKey;
use crate::core::flows::dpi::AppKind;
use crate::screens::common::{ConnKey, SortDirection, conn_key, orient};
use crate::screens::dashboard::state::{FlowRow, SortColumn};

/// One merged connection: the two opposing unidirectional flows rolled up into
/// a local/remote pair with a directional tx/rx split.
#[derive(Debug, Clone)]
pub struct ConnRow {
    pub proto: u8,
    /// This host's endpoint (or the canonical lower endpoint for traffic with
    /// no local side — see `orient`).
    pub local: (IpAddr, u16),
    pub remote: (IpAddr, u16),
    /// Bytes/bps sent *from* `local` (the outbound half).
    pub tx_bytes: u64,
    pub tx_bps: f32,
    /// Bytes/bps received *at* `local` (the inbound half).
    pub rx_bytes: u64,
    pub rx_bps: f32,
    pub packets: u64,
    /// Earliest first-seen across the pair.
    pub first_seen: Instant,
    /// Latest last-seen across the pair.
    pub last_seen: Instant,
    /// True only when *every* half is expired — a connection is live while
    /// either direction is.
    pub expired: bool,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub app_host: Option<(AppKind, String)>,
    pub last_summary: Option<String>,
    /// Underlying directed flow keys for the details overlay (either may be
    /// `None` for a half-open connection seen in one direction only).
    pub tx_key: Option<FlowKey>,
    pub rx_key: Option<FlowKey>,
}

impl ConnRow {
    pub fn total_bytes(&self) -> u64 {
        self.tx_bytes + self.rx_bytes
    }
    pub fn total_bps(&self) -> f32 {
        self.tx_bps + self.rx_bps
    }
}

/// Fold the per-flow rows into one row per connection, grouped by `conn_key`.
/// Insertion order is preserved (first-seen connection first) so the `Fixed`
/// sort stays stable, matching the per-flow path.
pub fn merge_flow_rows(rows: Vec<FlowRow>) -> Vec<ConnRow> {
    let mut out: Vec<ConnRow> = Vec::new();
    let mut index: FxHashMap<ConnKey, usize> = FxHashMap::default();

    for row in rows {
        let ck = conn_key(&row.key);
        let ep = orient(&row.key, row.direction);
        // The half whose source *is* the local endpoint is the tx (sending)
        // direction; the other is rx. Both halves agree on `ep.local`, so this
        // assignment is consistent across the pair.
        let is_tx = (row.key.src_ip, row.key.src_port) == ep.local;

        let idx = *index.entry(ck).or_insert_with(|| {
            out.push(ConnRow {
                proto: row.key.proto,
                local: ep.local,
                remote: ep.remote,
                tx_bytes: 0,
                tx_bps: 0.0,
                rx_bytes: 0,
                rx_bps: 0.0,
                packets: 0,
                first_seen: row.first_seen,
                last_seen: row.last_seen,
                // Seeded true, AND-ed with each half below.
                expired: true,
                pid: None,
                process_name: None,
                app_host: None,
                last_summary: None,
                tx_key: None,
                rx_key: None,
            });
            out.len() - 1
        });
        let c = &mut out[idx];

        c.packets += row.stats.packets;
        if is_tx {
            c.tx_bytes += row.stats.bytes;
            c.tx_bps += row.stats.bps;
            c.tx_key = Some(row.key);
        } else {
            c.rx_bytes += row.stats.bytes;
            c.rx_bps += row.stats.bps;
            c.rx_key = Some(row.key);
        }
        // First attributed half wins (the two directions share one socket, so
        // they normally agree on PID).
        if c.pid.is_none() {
            c.pid = row.pid;
            c.process_name = row.process_name.clone();
        }
        // SNI/DNS host usually rides the outbound half; take the first non-None.
        if c.app_host.is_none() {
            c.app_host = row.app_host.clone();
        }
        // Keep the protocol summary from the more-recently-active half. Computed
        // against the pre-update `last_seen` so the comparison is meaningful.
        if row.last_summary.is_some() && row.last_seen >= c.last_seen {
            c.last_summary = row.last_summary.clone();
        }
        c.first_seen = c.first_seen.min(row.first_seen);
        c.last_seen = c.last_seen.max(row.last_seen);
        c.expired = c.expired && row.expired;
    }

    out
}

/// Stable sort of merged connection rows. Reuses the dashboard's `SortColumn`
/// enum unchanged — only the values read change to the merged equivalents:
/// src/dst → local/remote, bps/bytes/pkts → totals, first/last → min/max.
pub fn sort_conns(conns: &mut [ConnRow], column: SortColumn, direction: SortDirection) {
    conns.sort_by(|a, b| {
        let primary = match column {
            SortColumn::Fixed => Ordering::Equal,
            SortColumn::SrcIp => a.local.0.cmp(&b.local.0),
            SortColumn::SrcPort => a.local.1.cmp(&b.local.1),
            SortColumn::DstIp => a.remote.0.cmp(&b.remote.0),
            SortColumn::DstPort => a.remote.1.cmp(&b.remote.1),
            SortColumn::Proto => a.proto.cmp(&b.proto),
            SortColumn::Process => conn_process_sort_key(a).cmp(&conn_process_sort_key(b)),
            SortColumn::Bps => a
                .total_bps()
                .partial_cmp(&b.total_bps())
                .unwrap_or(Ordering::Equal),
            SortColumn::Bytes => a.total_bytes().cmp(&b.total_bytes()),
            SortColumn::Packets => a.packets.cmp(&b.packets),
            SortColumn::FirstSeen => a.first_seen.cmp(&b.first_seen),
            SortColumn::LastPacket => a.last_seen.cmp(&b.last_seen),
        };
        let primary = if column == SortColumn::Fixed {
            primary
        } else if direction == SortDirection::Desc {
            primary.reverse()
        } else {
            primary
        };
        primary.then_with(|| a.first_seen.cmp(&b.first_seen))
    });
}

/// Process ordering for merged rows; mirrors `rows::process_sort_key`
/// (attributed first by name then PID, unattributed last).
fn conn_process_sort_key(row: &ConnRow) -> (u8, &str, u32) {
    match row.pid {
        Some(pid) => (0, row.process_name.as_deref().unwrap_or(""), pid),
        None => (1, "", u32::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use crate::core::common::IPPROTO_TCP;
    use crate::core::flows::components::Direction;
    use crate::core::flows::test_support::{flow_key, traffic_stats};
    use crate::screens::common::SortDirection;
    use crate::screens::dashboard::state::{FlowRow, SortColumn};

    /// `Instant` `secs_ago` seconds in the past.
    fn t(secs_ago: u64) -> Instant {
        Instant::now() - Duration::from_secs(secs_ago)
    }

    #[allow(clippy::too_many_arguments)]
    fn make_row(
        key: FlowKey,
        direction: Direction,
        bytes: u64,
        bps: f32,
        packets: u64,
        first_seen: Instant,
        last_seen: Instant,
        expired: bool,
    ) -> FlowRow {
        FlowRow {
            key,
            stats: traffic_stats(bytes, bps, packets),
            direction,
            last_summary: None,
            app_host: None,
            first_seen,
            last_seen,
            expired,
            pid: None,
            process_name: None,
        }
    }

    fn make_conn(
        local_port: u16,
        remote_port: u16,
        tx_bytes: u64,
        rx_bytes: u64,
        first_seen: Instant,
    ) -> ConnRow {
        ConnRow {
            proto: IPPROTO_TCP,
            local: (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), local_port),
            remote: (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), remote_port),
            tx_bytes,
            tx_bps: tx_bytes as f32,
            rx_bytes,
            rx_bps: rx_bytes as f32,
            packets: 0,
            first_seen,
            last_seen: first_seen,
            expired: false,
            pid: None,
            process_name: None,
            app_host: None,
            last_summary: None,
            tx_key: None,
            rx_key: None,
        }
    }

    // --- merge_flow_rows ---

    #[test]
    fn merge_opposing_flows_correct_tx_rx_split() {
        let out_key = flow_key("10.0.0.1", 52000, "10.0.0.2", 443, IPPROTO_TCP);
        let inn_key = flow_key("10.0.0.2", 443, "10.0.0.1", 52000, IPPROTO_TCP);
        let now = Instant::now();
        let conns = merge_flow_rows(vec![
            make_row(out_key, Direction::Outbound, 1000, 100.0, 10, now, now, false),
            make_row(inn_key, Direction::Inbound,  500,  50.0,  5, now, now, false),
        ]);
        assert_eq!(conns.len(), 1);
        let c = &conns[0];
        assert_eq!(c.tx_bytes, 1000);
        assert_eq!(c.rx_bytes, 500);
        assert!((c.tx_bps - 100.0).abs() < 0.001);
        assert!((c.rx_bps - 50.0).abs() < 0.001);
        assert_eq!(c.packets, 15);
        assert!(!c.expired);
        assert_eq!(c.tx_key, Some(out_key));
        assert_eq!(c.rx_key, Some(inn_key));
    }

    #[test]
    fn merge_half_open_leaves_rx_key_none() {
        // Only the outbound direction seen — rx side stays zero, rx_key is None.
        let out_key = flow_key("10.0.0.1", 52001, "10.0.0.2", 80, IPPROTO_TCP);
        let now = Instant::now();
        let conns = merge_flow_rows(vec![
            make_row(out_key, Direction::Outbound, 200, 20.0, 2, now, now, false),
        ]);
        assert_eq!(conns.len(), 1);
        let c = &conns[0];
        assert_eq!(c.tx_bytes, 200);
        assert_eq!(c.rx_bytes, 0);
        assert_eq!(c.tx_key, Some(out_key));
        assert_eq!(c.rx_key, None);
    }

    #[test]
    fn merge_expired_is_and_of_halves() {
        let now = Instant::now();
        // Both expired → conn is expired.
        let ka = flow_key("10.0.0.1", 52002, "10.0.0.2", 443, IPPROTO_TCP);
        let kb = flow_key("10.0.0.2", 443, "10.0.0.1", 52002, IPPROTO_TCP);
        let both_exp = merge_flow_rows(vec![
            make_row(ka, Direction::Outbound, 0, 0.0, 0, now, now, true),
            make_row(kb, Direction::Inbound,  0, 0.0, 0, now, now, true),
        ]);
        assert!(both_exp[0].expired, "both halves expired → conn expired");

        // One active half → conn is not expired.
        let kc = flow_key("10.0.0.1", 52003, "10.0.0.2", 443, IPPROTO_TCP);
        let kd = flow_key("10.0.0.2", 443, "10.0.0.1", 52003, IPPROTO_TCP);
        let one_alive = merge_flow_rows(vec![
            make_row(kc, Direction::Outbound, 0, 0.0, 0, now, now, true),
            make_row(kd, Direction::Inbound,  0, 0.0, 0, now, now, false),
        ]);
        assert!(!one_alive[0].expired, "one active half → conn not expired");
    }

    #[test]
    fn merge_first_and_last_seen_are_min_max() {
        let out_key = flow_key("10.0.0.1", 52004, "10.0.0.2", 443, IPPROTO_TCP);
        let inn_key = flow_key("10.0.0.2", 443, "10.0.0.1", 52004, IPPROTO_TCP);
        // Outbound: first_seen=10s ago, last_seen=2s ago (more recent activity).
        // Inbound:  first_seen=8s ago,  last_seen=5s ago.
        // Expected: first_seen = 10s ago (earliest), last_seen = 2s ago (latest).
        let out_first = t(10);
        let out_last  = t(2);
        let inn_first = t(8);
        let inn_last  = t(5);
        let conns = merge_flow_rows(vec![
            make_row(out_key, Direction::Outbound, 0, 0.0, 0, out_first, out_last,  false),
            make_row(inn_key, Direction::Inbound,  0, 0.0, 0, inn_first, inn_last, false),
        ]);
        assert_eq!(conns[0].first_seen, out_first, "first_seen should be the earliest");
        assert_eq!(conns[0].last_seen,  out_last,  "last_seen should be the most recent");
    }

    #[test]
    fn merge_preserves_insertion_order() {
        // Three distinct connections; output must follow the order in which each
        // connection's first flow was encountered, not any other ordering.
        let now = Instant::now();
        let ka = flow_key("10.0.0.1", 60001, "10.0.0.2", 443,  IPPROTO_TCP);
        let kb = flow_key("10.0.0.1", 60002, "10.0.0.2", 80,   IPPROTO_TCP);
        let kc = flow_key("10.0.0.1", 60003, "10.0.0.2", 8080, IPPROTO_TCP);
        let conns = merge_flow_rows(vec![
            make_row(ka, Direction::Outbound, 0, 0.0, 0, now, now, false),
            make_row(kb, Direction::Outbound, 0, 0.0, 0, now, now, false),
            make_row(kc, Direction::Outbound, 0, 0.0, 0, now, now, false),
        ]);
        assert_eq!(conns.len(), 3);
        assert_eq!(conns[0].tx_key, Some(ka));
        assert_eq!(conns[1].tx_key, Some(kb));
        assert_eq!(conns[2].tx_key, Some(kc));
    }

    // --- sort_conns ---

    #[test]
    fn sort_conns_by_total_bytes_desc() {
        let now = Instant::now();
        let mut conns = vec![
            make_conn(1, 443, 100, 0, now),   // total 100
            make_conn(2, 443, 300, 0, now),   // total 300
            make_conn(3, 443, 200, 0, now),   // total 200
        ];
        sort_conns(&mut conns, SortColumn::Bytes, SortDirection::Desc);
        let totals: Vec<u64> = conns.iter().map(|c| c.total_bytes()).collect();
        assert_eq!(totals, vec![300, 200, 100]);
    }

    #[test]
    fn sort_conns_by_total_bytes_asc() {
        let now = Instant::now();
        let mut conns = vec![
            make_conn(1, 443, 300, 0, now),
            make_conn(2, 443, 100, 0, now),
            make_conn(3, 443, 200, 0, now),
        ];
        sort_conns(&mut conns, SortColumn::Bytes, SortDirection::Asc);
        let totals: Vec<u64> = conns.iter().map(|c| c.total_bytes()).collect();
        assert_eq!(totals, vec![100, 200, 300]);
    }

    #[test]
    fn sort_conns_by_dst_port_asc() {
        let now = Instant::now();
        let mut conns = vec![
            make_conn(1, 8080, 0, 0, now),
            make_conn(2, 443,  0, 0, now),
            make_conn(3, 80,   0, 0, now),
        ];
        sort_conns(&mut conns, SortColumn::DstPort, SortDirection::Asc);
        let ports: Vec<u16> = conns.iter().map(|c| c.remote.1).collect();
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn sort_conns_fixed_orders_by_first_seen_ascending() {
        // Fixed is direction-less: always oldest first_seen first.
        let mut conns = vec![
            make_conn(1, 443, 0, 0, t(10)), // oldest
            make_conn(2, 443, 0, 0, t(5)),
            make_conn(3, 443, 0, 0, t(1)),  // newest
        ];
        // Shuffle: put newest first.
        conns.reverse();
        sort_conns(&mut conns, SortColumn::Fixed, SortDirection::Asc);
        // After sort: oldest (t(10)) first, newest (t(1)) last.
        assert!(conns[0].first_seen < conns[1].first_seen);
        assert!(conns[1].first_seen < conns[2].first_seen);
    }
}
