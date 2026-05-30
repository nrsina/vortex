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
