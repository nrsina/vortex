//! Shared rendering for the flow / connection details overlay.
//!
//! Both the dashboard and the processes screen open the same overlay, and both
//! must keep it **pinned to one flow/connection** for as long as it's open —
//! the overlay is looked up by a captured `FlowKey`, never by a list index, so
//! it can't drift when the table re-sorts, new flows arrive, or the selected
//! flow expires. Centralising the render here (rather than duplicating it per
//! screen) guarantees the behaviour is identical wherever it's opened from.
//!
//! Both entry points read **live** ECS state by key (the `paused` flag only
//! changes the panel title); the entity survives expiry — it's only truly gone
//! once `evict_expired` hard-removes it past the cap — so an expired flow still
//! renders here. When the entity is genuinely gone we paint a short notice.

use std::net::IpAddr;
use std::time::Instant;

use bevy_ecs::prelude::*;
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::Line,
    widgets::Paragraph,
};

use crate::core::dns::RdnsCache;
use crate::core::flows::components::{
    Direction, FirstSeen, FlowKey, LastSeen, Metadata, Timeline, TrafficStats,
};
use crate::core::processes::{FlowProcess, ProcessStats, ProcessTable};
use crate::screens::common::{ConnKey, conn_key, orient};
use crate::screens::flow_details::{
    ConnDetailsInput, FlowDetailsInput, conn_details_rows, flow_details_rows,
};
use crate::screens::theme;
use crate::screens::widgets::details;

/// Render the per-flow details overlay for `target`, looked up live by key.
/// Falls back to an "(expired)" notice if the flow's entity is gone.
///
/// The query (spelled out rather than aliased — `Query` is invariant over its
/// data, so a `&'static`-typed alias wouldn't accept the callers' world-lifetime
/// queries) is the same 8-tuple both screens already own, so each hands its own
/// query straight through.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn render_flow_overlay(
    frame: &mut Frame,
    area: Rect,
    target: FlowKey,
    paused: bool,
    query: &Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Timeline,
        &Direction,
        Option<&FlowProcess>,
    )>,
    table: &ProcessTable,
    pstats: &ProcessStats,
    rdns: &RdnsCache,
) {
    let found = query.iter().find(|(k, _, _, _, _, _, _, _)| **k == target);
    let Some((key, stats, meta, first_seen, last_seen, timeline, direction, fp)) = found else {
        notice(
            frame,
            area,
            "Flow details (gone)",
            "This flow has been evicted since the overlay opened. Press esc to return.",
        );
        return;
    };

    let input = FlowDetailsInput {
        key: *key,
        direction: *direction,
        stats,
        first_seen: first_seen.0,
        last_seen: Some(last_seen.0),
        last_summary: meta.last_summary.as_deref(),
        app_host: meta.app_host.as_ref().map(|(k, h)| (*k, h.as_str())),
        timeline: Some(timeline),
        pid: fp.map(|f| f.pid),
        table,
        pstats,
        rdns,
    };
    let mut timeline_buf: Vec<u64> = Vec::with_capacity(60);
    let rows = flow_details_rows(&input, &mut timeline_buf);
    details(frame, area, title("Flow details", paused), &rows);
}

/// Render the merged-connection details overlay for the connection that
/// `target` belongs to. Both opposing halves are re-folded by `conn_key` from
/// the live query, so the tx/rx split stays accurate as packets keep flowing.
/// Falls back to an "(expired)" notice if neither half remains.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn render_conn_overlay(
    frame: &mut Frame,
    area: Rect,
    target: FlowKey,
    paused: bool,
    query: &Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Timeline,
        &Direction,
        Option<&FlowProcess>,
    )>,
    table: &ProcessTable,
    pstats: &ProcessStats,
    rdns: &RdnsCache,
) {
    let ck: ConnKey = conn_key(&target);

    let mut endpoints: Option<((IpAddr, u16), (IpAddr, u16))> = None;
    let (mut tx_bytes, mut tx_bps) = (0u64, 0.0f32);
    let (mut rx_bytes, mut rx_bps) = (0u64, 0.0f32);
    let mut packets = 0u64;
    let mut first_seen: Option<Instant> = None;
    let mut last_seen: Option<Instant> = None;
    let mut tx_timeline: Option<&Timeline> = None;
    let mut rx_timeline: Option<&Timeline> = None;
    let mut pid: Option<u32> = None;
    let mut app_host = None;
    let mut last_summary = None;

    for (k, stats, meta, fs, ls, tl, dir, fp) in query.iter() {
        if conn_key(k) != ck {
            continue;
        }
        let ep = orient(k, *dir);
        if endpoints.is_none() {
            endpoints = Some((ep.local, ep.remote));
        }
        packets += stats.packets;
        // The half whose src is the local endpoint is tx; the other is rx.
        if (k.src_ip, k.src_port) == ep.local {
            tx_bytes += stats.bytes;
            tx_bps += stats.bps;
            tx_timeline = Some(tl);
        } else {
            rx_bytes += stats.bytes;
            rx_bps += stats.bps;
            rx_timeline = Some(tl);
        }
        first_seen = Some(first_seen.map_or(fs.0, |x| x.min(fs.0)));
        last_seen = Some(last_seen.map_or(ls.0, |x| x.max(ls.0)));
        if pid.is_none() {
            pid = fp.map(|f| f.pid);
        }
        if app_host.is_none() {
            app_host = meta.app_host.as_ref().map(|(k, h)| (*k, h.as_str()));
        }
        if last_summary.is_none() {
            last_summary = meta.last_summary.as_deref();
        }
    }

    let Some((local, remote)) = endpoints else {
        notice(
            frame,
            area,
            "Connection details (gone)",
            "This connection has been evicted since the overlay opened. Press esc to return.",
        );
        return;
    };

    let input = ConnDetailsInput {
        local,
        remote,
        proto: target.proto,
        first_seen: first_seen.unwrap_or_else(Instant::now),
        last_seen,
        tx_bytes,
        tx_bps,
        rx_bytes,
        rx_bps,
        packets,
        tx_timeline,
        rx_timeline,
        app_host,
        last_summary,
        pid,
        table,
        pstats,
        rdns,
    };
    let mut tx_buf: Vec<u64> = Vec::with_capacity(60);
    let mut rx_buf: Vec<u64> = Vec::with_capacity(60);
    let rows = conn_details_rows(&input, &mut tx_buf, &mut rx_buf);
    details(frame, area, title("Connection details", paused), &rows);
}

/// Title suffix: `(paused)` while the screen is frozen, `(live)` otherwise.
/// Overlay data is always live (looked up by key) — pause just labels it.
fn title(base: &'static str, paused: bool) -> &'static str {
    // Tiny match keeps the &'static return type without per-frame allocation.
    match (base, paused) {
        ("Flow details", true) => "Flow details (paused)",
        ("Flow details", false) => "Flow details (live)",
        ("Connection details", true) => "Connection details (paused)",
        _ => "Connection details (live)",
    }
}

/// Paint a bordered panel with a one-line muted message (the flow/connection
/// was evicted after the overlay opened).
fn notice(frame: &mut Frame, area: Rect, panel_title: &str, msg: &str) {
    let block = theme::panel(panel_title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let p = Paragraph::new(Line::from(msg)).style(Style::default().fg(theme::MUTED));
    frame.render_widget(p, inner);
}
