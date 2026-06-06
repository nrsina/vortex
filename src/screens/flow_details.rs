//! Build the flat list of `DetailRow`s the details overlay renders.
//!
//! Shared by the dashboard and the processes-tree screen so the overlay
//! looks identical wherever it's opened from. The caller is responsible
//! for collecting the inputs (live ECS queries vs. frozen snapshots);
//! this module does pure data-shaping.

use std::net::IpAddr;
use std::time::Instant;

use crate::core::dns::{RdnsCache, RdnsStatus};
use crate::core::flows::components::{Direction, FlowKey, Timeline, TrafficStats};
use crate::core::flows::dpi::AppKind;
use crate::core::flows::ipclass::classify;
use crate::core::flows::service::well_known;
use crate::core::processes::{ProcessStats, ProcessTable};
use crate::core::settings::settings;
use crate::screens::widgets::{
    DetailRow, format_bps, format_bytes, format_clock, format_duration_since,
};
use crate::screens::common::proto_name;

/// Everything the overlay needs to render a single flow. Cheap to assemble
/// for both live and frozen paths.
pub struct FlowDetailsInput<'a> {
    pub key: FlowKey,
    pub direction: Direction,
    pub stats: &'a TrafficStats,
    pub first_seen: Instant,
    pub last_seen: Option<Instant>,
    pub last_summary: Option<&'a str>,
    /// DPI-extracted app-layer host (TLS SNI / DNS qname) with its kind, for
    /// the `sni` / `dns query` row. `None` when DPI is disabled or found none.
    pub app_host: Option<(AppKind, &'a str)>,
    pub timeline: Option<&'a Timeline>,
    pub pid: Option<u32>,
    pub table: &'a ProcessTable,
    pub pstats: &'a ProcessStats,
    pub rdns: &'a RdnsCache,
}

/// Build the rows the overlay will paint. Each section is preceded by a
/// `SectionHeader` divider so users can scan vertically.
pub fn flow_details_rows<'a>(
    input: &'a FlowDetailsInput<'a>,
    timeline_buf: &'a mut Vec<u64>,
) -> Vec<DetailRow<'a>> {
    let mut rows: Vec<DetailRow<'a>> = Vec::with_capacity(28);

    rows.push(DetailRow::SectionHeader { title: "Endpoints" });
    rows.push(DetailRow::Pair {
        label_a: "src",
        value_a: input.key.src_ip.to_string(),
        label_b: "dst",
        value_b: input.key.dst_ip.to_string(),
    });
    rows.push(DetailRow::Pair {
        label_a: "host",
        value_a: hostname_label(input.key.src_ip, input.rdns),
        label_b: "host",
        value_b: hostname_label(input.key.dst_ip, input.rdns),
    });
    rows.push(DetailRow::Pair {
        label_a: "port",
        value_a: port_label(input.key.src_port, input.key.proto),
        label_b: "port",
        value_b: port_label(input.key.dst_port, input.key.proto),
    });
    rows.push(DetailRow::Pair {
        label_a: "type",
        value_a: classify(input.key.src_ip).label().to_string(),
        label_b: "type",
        value_b: classify(input.key.dst_ip).label().to_string(),
    });
    rows.push(DetailRow::Blank);

    rows.push(DetailRow::SectionHeader { title: "Flow" });
    rows.push(DetailRow::Single {
        label: "protocol",
        value: format!("{} ({})", proto_name(input.key.proto), input.key.proto),
    });
    rows.push(DetailRow::Single {
        label: "direction",
        value: input.direction.label().to_string(),
    });
    rows.push(DetailRow::Single {
        label: "first seen",
        value: format!(
            "{}  ({} ago)",
            format_clock(input.first_seen),
            format_duration_since(input.first_seen)
        ),
    });
    if let Some(ls) = input.last_seen {
        rows.push(DetailRow::Single {
            label: "last packet",
            value: format!(
                "{}  ({} ago)",
                format_clock(ls),
                format_duration_since(ls)
            ),
        });
        let dur = ls.saturating_duration_since(input.first_seen);
        rows.push(DetailRow::Single {
            label: "duration",
            value: humanize_duration(dur),
        });
    }
    rows.push(DetailRow::Single {
        label: "total",
        value: format!(
            "{} · {} packets",
            format_bytes(input.stats.bytes),
            with_thousands(input.stats.packets)
        ),
    });
    rows.push(DetailRow::Single {
        label: "rate",
        value: format_bps(input.stats.bps),
    });
    if let Some(tl) = input.timeline {
        fill_timeline_buf(timeline_buf, tl);
        rows.push(DetailRow::Sparkline {
            label: "history",
            data: timeline_buf.as_slice(),
        });
    }
    // App-layer host the client asked for (TLS SNI / DNS query) — surfaced
    // above the protocol-flags `last` line since it's the more meaningful
    // "what is this flow talking to?" signal.
    if let Some((kind, host)) = input.app_host {
        rows.push(DetailRow::Single {
            label: kind.label(),
            value: host.to_string(),
        });
    }
    if let Some(s) = input.last_summary {
        rows.push(DetailRow::Single {
            label: "last",
            value: s.to_string(),
        });
    }
    rows.push(DetailRow::Blank);

    rows.push(DetailRow::SectionHeader { title: "Process" });
    push_process_section(&mut rows, input.pid, input.table, input.pstats);

    rows
}

/// Everything the overlay needs to render a merged connection (both opposing
/// flows rolled up). Mirrors `FlowDetailsInput` but carries an explicit
/// local/remote orientation and a per-direction tx/rx split.
pub struct ConnDetailsInput<'a> {
    pub local: (IpAddr, u16),
    pub remote: (IpAddr, u16),
    pub proto: u8,
    pub first_seen: Instant,
    pub last_seen: Option<Instant>,
    pub tx_bytes: u64,
    pub tx_bps: f32,
    pub rx_bytes: u64,
    pub rx_bps: f32,
    pub packets: u64,
    pub tx_timeline: Option<&'a Timeline>,
    pub rx_timeline: Option<&'a Timeline>,
    pub app_host: Option<(AppKind, &'a str)>,
    pub last_summary: Option<&'a str>,
    pub pid: Option<u32>,
    pub table: &'a ProcessTable,
    pub pstats: &'a ProcessStats,
    pub rdns: &'a RdnsCache,
}

/// Build the overlay rows for a merged connection. Shares the endpoint/process
/// helpers with `flow_details_rows`; the Flow section shows the directional
/// tx/rx split and one sparkline per observed direction. `tx_buf`/`rx_buf` are
/// scratch buffers the caller owns so the sparkline slices outlive this call.
pub fn conn_details_rows<'a>(
    input: &'a ConnDetailsInput<'a>,
    tx_buf: &'a mut Vec<u64>,
    rx_buf: &'a mut Vec<u64>,
) -> Vec<DetailRow<'a>> {
    let mut rows: Vec<DetailRow<'a>> = Vec::with_capacity(28);

    rows.push(DetailRow::SectionHeader { title: "Endpoints" });
    rows.push(DetailRow::Pair {
        label_a: "local",
        value_a: input.local.0.to_string(),
        label_b: "remote",
        value_b: input.remote.0.to_string(),
    });
    rows.push(DetailRow::Pair {
        label_a: "host",
        value_a: hostname_label(input.local.0, input.rdns),
        label_b: "host",
        value_b: hostname_label(input.remote.0, input.rdns),
    });
    rows.push(DetailRow::Pair {
        label_a: "port",
        value_a: port_label(input.local.1, input.proto),
        label_b: "port",
        value_b: port_label(input.remote.1, input.proto),
    });
    rows.push(DetailRow::Pair {
        label_a: "type",
        value_a: classify(input.local.0).label().to_string(),
        label_b: "type",
        value_b: classify(input.remote.0).label().to_string(),
    });
    rows.push(DetailRow::Blank);

    rows.push(DetailRow::SectionHeader { title: "Flow" });
    rows.push(DetailRow::Single {
        label: "protocol",
        value: format!("{} ({})", proto_name(input.proto), input.proto),
    });
    rows.push(DetailRow::Single {
        label: "first seen",
        value: format!(
            "{}  ({} ago)",
            format_clock(input.first_seen),
            format_duration_since(input.first_seen)
        ),
    });
    if let Some(ls) = input.last_seen {
        rows.push(DetailRow::Single {
            label: "last packet",
            value: format!("{}  ({} ago)", format_clock(ls), format_duration_since(ls)),
        });
        rows.push(DetailRow::Single {
            label: "duration",
            value: humanize_duration(ls.saturating_duration_since(input.first_seen)),
        });
    }
    rows.push(DetailRow::Single {
        label: "↑ tx",
        value: format!("{} · {}", format_bytes(input.tx_bytes), format_bps(input.tx_bps)),
    });
    rows.push(DetailRow::Single {
        label: "↓ rx",
        value: format!("{} · {}", format_bytes(input.rx_bytes), format_bps(input.rx_bps)),
    });
    rows.push(DetailRow::Single {
        label: "total",
        value: format!(
            "{} · {} packets",
            format_bytes(input.tx_bytes + input.rx_bytes),
            with_thousands(input.packets)
        ),
    });
    // One sparkline per observed direction so up/down history reads separately.
    if let Some(tl) = input.tx_timeline {
        fill_timeline_buf(tx_buf, tl);
        rows.push(DetailRow::Sparkline {
            label: "↑ history",
            data: tx_buf.as_slice(),
        });
    }
    if let Some(tl) = input.rx_timeline {
        fill_timeline_buf(rx_buf, tl);
        rows.push(DetailRow::Sparkline {
            label: "↓ history",
            data: rx_buf.as_slice(),
        });
    }
    if let Some((kind, host)) = input.app_host {
        rows.push(DetailRow::Single {
            label: kind.label(),
            value: host.to_string(),
        });
    }
    if let Some(s) = input.last_summary {
        rows.push(DetailRow::Single {
            label: "last",
            value: s.to_string(),
        });
    }
    rows.push(DetailRow::Blank);

    rows.push(DetailRow::SectionHeader { title: "Process" });
    push_process_section(&mut rows, input.pid, input.table, input.pstats);

    rows
}

/// Rotate a flow's 60-second `Timeline` ring into `buf` with the newest sample
/// on the right (and the in-progress bucket appended), ready for a sparkline.
/// Shared so per-flow and per-direction history render identically.
fn fill_timeline_buf(buf: &mut Vec<u64>, tl: &Timeline) {
    // `head` indexes the *next* bucket to write, so the oldest sample lives
    // there; skip it and append `current_bucket_bytes` so a just-arrived burst
    // is visible immediately rather than lagging a full second behind the
    // next `aggregate::tick` rotation.
    buf.clear();
    buf.reserve(60);
    let head = tl.head as usize;
    for i in 1..60 {
        let idx = (head + i) % 60;
        buf.push(tl.buckets[idx] as u64);
    }
    buf.push(tl.current_bucket_bytes as u64);
}

/// Append the shared "Process" rows (name/pid/user/status/exe/cmd) for `pid`,
/// or a "not attributed" notice. Used by both the per-flow and connection
/// overlays so the process block looks identical.
fn push_process_section<'a>(
    rows: &mut Vec<DetailRow<'a>>,
    pid: Option<u32>,
    table: &ProcessTable,
    pstats: &ProcessStats,
) {
    match pid.and_then(|pid| table.0.get(&pid).map(|i| (pid, i))) {
        Some((pid, info)) => {
            let agg = pstats.by_pid.get(&pid);
            rows.push(DetailRow::Pair {
                label_a: "name",
                value_a: info.name.clone(),
                label_b: "parent",
                value_b: info
                    .ppid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "—".to_string()),
            });
            rows.push(DetailRow::Pair {
                label_a: "pid",
                value_a: pid.to_string(),
                label_b: "user",
                value_b: info.user.clone().unwrap_or_else(|| "—".to_string()),
            });
            rows.push(DetailRow::Pair {
                label_a: "status",
                value_a: if info.alive { "alive" } else { "exited" }.to_string(),
                label_b: "proc bps",
                value_b: agg
                    .map(|a| format_bps(a.bps))
                    .unwrap_or_else(|| "—".to_string()),
            });
            rows.push(DetailRow::Single {
                label: "total conns",
                value: agg
                    .map(|a| a.conn_count.to_string())
                    .unwrap_or_else(|| "—".to_string()),
            });
            // `exe` and `cmd` get their own full-width wrapping rows so the
            // entire path / command line is visible — pairing them with a
            // right column truncated the value at PAIR_HALF_MAX (~56 cells)
            // and hid the part of the path users opened the overlay to see.
            rows.push(DetailRow::Wrapped {
                label: "exe",
                value: info
                    .exe
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "—".to_string()),
            });
            rows.push(DetailRow::Wrapped {
                label: "cmd",
                value: if info.cmdline.is_empty() {
                    "—".to_string()
                } else {
                    info.cmdline.join(" ")
                },
            });
        }
        None => {
            rows.push(DetailRow::Single {
                label: "status",
                value: "Not attributed (process exited before snapshot, or socket missed)"
                    .to_string(),
            });
        }
    }
}

/// Render an IP's hostname status as a human string, including the
/// `(disabled)` case when `[dns].enabled = false`.
fn hostname_label(ip: IpAddr, rdns: &RdnsCache) -> String {
    if !settings().dns.enabled {
        return "(disabled)".to_string();
    }
    match rdns.get(&ip).map(|e| &e.status) {
        Some(RdnsStatus::Resolved(h)) => h.clone(),
        Some(RdnsStatus::Pending) => "(resolving…)".to_string(),
        Some(RdnsStatus::NxDomain) => "(no PTR)".to_string(),
        Some(RdnsStatus::Failed) => "(lookup failed)".to_string(),
        Some(RdnsStatus::Private) => "(private network)".to_string(),
        None => {
            // Either we haven't queued the lookup yet (rare — request_lookups
            // runs every tick) or the worker hasn't picked it up. Surface a
            // distinct hint instead of pretending we already know.
            "(pending)".to_string()
        }
    }
}

pub(crate) fn port_label(port: u16, proto: u8) -> String {
    match well_known(port, proto) {
        Some(name) => format!("{port} ({name})"),
        None => port.to_string(),
    }
}

pub(crate) fn humanize_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs >= 86_400 {
        format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3600)
    } else if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}.{:03}s", secs, d.subsec_millis())
    }
}

pub(crate) fn with_thousands(n: u64) -> String {
    // Tiny thousands-separator helper; pulls in no dep. `1234567` → `1,234,567`.
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use crate::core::common::{IPPROTO_TCP, IPPROTO_UDP};

    // --- with_thousands ---

    #[test]
    fn with_thousands_small_no_separator() {
        assert_eq!(with_thousands(0), "0");
        assert_eq!(with_thousands(999), "999");
    }

    #[test]
    fn with_thousands_exactly_one_comma() {
        assert_eq!(with_thousands(1_000), "1,000");
        assert_eq!(with_thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn with_thousands_boundaries() {
        assert_eq!(with_thousands(999_999), "999,999");
        assert_eq!(with_thousands(1_000_000), "1,000,000");
    }

    // --- humanize_duration ---

    #[test]
    fn humanize_duration_sub_minute() {
        assert_eq!(humanize_duration(Duration::from_millis(500)), "0.500s");
        assert_eq!(humanize_duration(Duration::from_secs(1)), "1.000s");
        assert_eq!(humanize_duration(Duration::from_secs(59)), "59.000s");
    }

    #[test]
    fn humanize_duration_minutes_and_seconds() {
        assert_eq!(humanize_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(humanize_duration(Duration::from_secs(3599)), "59m 59s");
    }

    #[test]
    fn humanize_duration_hours_and_minutes() {
        assert_eq!(humanize_duration(Duration::from_secs(3600)), "1h 0m");
        assert_eq!(humanize_duration(Duration::from_secs(7261)), "2h 1m");
    }

    #[test]
    fn humanize_duration_days_and_hours() {
        assert_eq!(humanize_duration(Duration::from_secs(86_400)), "1d 0h");
        assert_eq!(humanize_duration(Duration::from_secs(90_061)), "1d 1h");
    }

    // --- port_label ---

    #[test]
    fn port_label_known_port_annotated() {
        assert_eq!(port_label(443, IPPROTO_TCP), "443 (https)");
        assert_eq!(port_label(53, IPPROTO_UDP), "53 (dns)");
    }

    #[test]
    fn port_label_unknown_port_bare_number() {
        assert_eq!(port_label(54321, IPPROTO_TCP), "54321");
    }

    #[test]
    fn port_label_proto_specific_service() {
        // port 514: syslog on UDP, shell on TCP
        assert_eq!(port_label(514, IPPROTO_UDP), "514 (syslog)");
        assert_eq!(port_label(514, IPPROTO_TCP), "514 (shell)");
    }
}
