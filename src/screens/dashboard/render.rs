use std::cmp::Ordering;

use bevy_ecs::prelude::*;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::Style,
    widgets::{Cell, Row, Table, TableState},
};

use crate::core::dns::RdnsCache;
use crate::core::flows::LiveMetrics;
use crate::core::flows::components::{
    Direction, Expired, FirstSeen, FlowKey, LastSeen, Metadata, Timeline, TrafficStats,
};
use crate::core::processes::{FlowProcess, ProcessStats, ProcessTable};
use crate::core::terminal::context::TerminalContext;
use crate::screens::widgets::{
    HelpEntry, KeyHint, filter_bar, filter_row_height, footer, format_bps, format_bytes,
    format_count, format_duration_since, header, help, list_scrollbar,
};
use crate::screens::common::{IP_COL_WIDTH, SortDirection, ip_label, proto_name, sort_header_cell};
use crate::screens::dashboard::conn::{ConnRow, merge_flow_rows, sort_conns};
use crate::screens::dashboard::rows::{current_rows, format_process, process_label, process_sort_key};
use crate::screens::dashboard::state::{DashboardState, FlowRow, SortColumn};
use crate::screens::details_overlay::{render_conn_overlay, render_flow_overlay};
use crate::screens::prefs::UiPrefs;
use crate::screens::theme;

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn dashboard_draw(
    mut ctx: ResMut<TerminalContext>,
    mut state: ResMut<DashboardState>,
    prefs: Res<UiPrefs>,
    metrics: Res<LiveMetrics>,
    table: Res<ProcessTable>,
    pstats: Res<ProcessStats>,
    rdns: Res<RdnsCache>,
    flows: Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Timeline,
        &Direction,
        Option<&FlowProcess>,
    )>,
    rows_query: Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Direction,
        Has<Expired>,
        Option<&FlowProcess>,
    )>,
) -> Result {
    ctx.0.draw(|frame| {
        render(
            frame,
            &mut state,
            &prefs,
            &metrics,
            &table,
            &pstats,
            &rdns,
            &flows,
            &rows_query,
        )
    })?;
    Ok(())
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn render(
    frame: &mut Frame,
    state: &mut DashboardState,
    prefs: &UiPrefs,
    metrics: &LiveMetrics,
    table: &ProcessTable,
    pstats: &ProcessStats,
    rdns: &RdnsCache,
    flows: &Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Timeline,
        &Direction,
        Option<&FlowProcess>,
    )>,
    rows_query: &Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Direction,
        Has<Expired>,
        Option<&FlowProcess>,
    )>,
) {
    // The filter row collapses to zero height when no filter is active so the
    // dashboard's vertical real estate is unchanged in the common case.
    let filter_h = filter_row_height(&state.filter);

    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(filter_h),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(frame.area());

    // Interface-wide live summary: the directional throughput split and flow
    // counts come from `LiveMetrics` (rolled up in `aggregate::tick`), so they
    // keep moving even while the table is paused. `total` = active + retained
    // expired flows; both are host-wide and can exceed the rows shown when a
    // BPF filter or the show-expired toggle hides some. The header is identical
    // in both the per-flow and the merged-connection view.
    let iface = state.selected_interface.as_deref().unwrap_or("?");
    let total = metrics.active_flows + metrics.expired_flows;
    let mut right = format!(
        "↑ {}  ↓ {}  ·  {} active · {} total  ·  {iface}",
        format_bps(metrics.tx_bps),
        format_bps(metrics.rx_bps),
        format_count(metrics.active_flows as u64),
        format_count(total as u64),
    );
    if metrics.dropped_total > 0 {
        right.push_str(&format!("  ·  drops {}", format_count(metrics.dropped_total)));
    }
    if state.paused {
        right.push_str("  ·  PAUSED");
    }
    header(frame, chunks[0], "dashboard", Some(&right));

    if filter_h > 0 {
        filter_bar(frame, chunks[1], &state.filter);
    }

    // `current_rows` returns the frozen snapshot when paused, otherwise a
    // freshly built vec from the live ECS query. The show-expired filter and
    // the cursor clamp run against whichever set is actually shown, so the
    // selection always indexes into the visible rows.
    let entries_all: Vec<FlowRow> = current_rows(state, rows_query, table);

    if prefs.show_help {
        help(frame, chunks[2], "dashboard", &help_entries());
    } else if state.show_details {
        // Details overlay is pinned to the flow/connection captured on Enter
        // (`state.details_flow`) and looked up live by key — independent of the
        // table's current sort/filter, so it can't drift as rows churn or the
        // flow expires. The connection variant re-folds both halves by
        // conn_key. Built by the shared `details_overlay` module so this is
        // byte-for-byte identical to the processes screen's overlay.
        if let Some(target) = state.details_flow {
            if prefs.aggregate {
                render_conn_overlay(frame, chunks[2], target, state.paused, flows, table, pstats, rdns);
            } else {
                render_flow_overlay(frame, chunks[2], target, state.paused, flows, table, pstats, rdns);
            }
        }
    } else if prefs.aggregate {
        // Merged connection view (`a`): fold each connection's two opposing
        // flows into one row. A connection is expired only when *both* halves
        // are, so `e` hides it only once fully idle.
        let mut conns = merge_flow_rows(entries_all);
        if !prefs.show_expired {
            conns.retain(|c| !c.expired);
        }
        state.selected = state.selected.min(conns.len().saturating_sub(1));
        render_conn_table(frame, chunks[2], state, prefs, rdns, &mut conns);
    } else {
        // Raw per-flow view (unchanged): hide expired flows unless `e` is on.
        let mut entries = entries_all;
        if !prefs.show_expired {
            entries.retain(|r| !r.expired);
        }
        state.selected = state.selected.min(entries.len().saturating_sub(1));
        render_table(frame, chunks[2], state, prefs, rdns, &mut entries);
    }

    // While the details overlay is open the screen is pinned to one
    // flow/connection, so the table-manipulation hints would be misleading —
    // show only the keys that still act (the key handler enforces the same).
    if state.show_details {
        footer(
            frame,
            chunks[3],
            &[KeyHint::new("esc/b", "back"), KeyHint::new("q", "quit")],
        );
    } else {
        footer(
            frame,
            chunks[3],
            &[
                KeyHint::new("↑/↓", "select"),
                KeyHint::new("enter", "details"),
                KeyHint::new("n", "names"),
                KeyHint::new("e", "expired"),
                KeyHint::new("a", "aggregate"),
                KeyHint::new("s", "sort"),
                KeyHint::new("S", "dir"),
                KeyHint::new("space", "pause"),
                KeyHint::new("p", "processes"),
                KeyHint::new("?", "help"),
                KeyHint::new("esc/b", "back"),
                KeyHint::new("q", "quit"),
            ],
        );
    }
}

/// Dashboard-specific key reference shown in the help overlay. The `esc/b`
/// hint mentions the picker because that's where this screen pops back to —
/// the other screens populate their own list with their own back target.
fn help_entries() -> Vec<HelpEntry<'static>> {
    vec![
        HelpEntry::new("?", "toggle this help"),
        HelpEntry::new("q / Ctrl-C", "quit"),
        HelpEntry::new("esc / b", "back to interface picker"),
        HelpEntry::new("enter", "show flow details overlay"),
        HelpEntry::new("n", "toggle hostname/IP in src and dst columns"),
        HelpEntry::new("e", "show/hide expired (idle) flows"),
        HelpEntry::new("a", "aggregate flows into connections (↑ tx / ↓ rx)"),
        HelpEntry::new("space", "toggle pause (display-only freeze)"),
        HelpEntry::new("j / ↓", "select next"),
        HelpEntry::new("k / ↑", "select previous"),
        HelpEntry::new("s", "cycle sort column (fixed → src ip → … → last pkt)"),
        HelpEntry::new("S", "toggle sort direction (asc/desc)"),
        HelpEntry::new("p", "open processes view"),
    ]
}

fn render_table(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    state: &DashboardState,
    prefs: &UiPrefs,
    rdns: &RdnsCache,
    entries: &mut [FlowRow],
) {
    sort_entries(entries, state.sort_column, state.sort_direction);

    let rows: Vec<Row> = entries
        .iter()
        .map(|r| {
            // Expired rows are dimmed via a row-wide MUTED style; the bps cell
            // therefore drops its accent (a dead flow reads 0 B/s anyway).
            let bps_cell = if r.expired {
                Cell::from(format_bps(r.stats.bps))
            } else {
                Cell::from(format_bps(r.stats.bps)).style(Style::default().fg(theme::ACCENT))
            };
            let row = Row::new(vec![
                Cell::from(ip_label(r.key.src_ip, rdns, prefs.names_mode)),
                Cell::from(r.key.src_port.to_string()),
                Cell::from(ip_label(r.key.dst_ip, rdns, prefs.names_mode)),
                Cell::from(r.key.dst_port.to_string()),
                Cell::from(proto_name(r.key.proto)),
                Cell::from(process_label(r)),
                bps_cell,
                Cell::from(format_bytes(r.stats.bytes)),
                Cell::from(r.stats.packets.to_string()),
                // Relative "ago" times — `last pkt` doubles as a staleness
                // read-out, so expired flows (> idle timeout) are obvious.
                Cell::from(format_duration_since(r.first_seen)),
                Cell::from(format_duration_since(r.last_seen)),
                Cell::from(r.last_summary.clone().unwrap_or_default()),
            ]);
            if r.expired {
                row.style(Style::default().fg(theme::MUTED))
            } else {
                row
            }
        })
        .collect();

    // Widths leave room for the `▲`/`▼` decoration on the sorted column
    // header — the arrow plus a space adds 2 chars, and ▲/▼ are ambiguous
    // East-Asian-Width glyphs that some terminals render double-wide, so we
    // budget a little extra padding on the narrower numeric columns. The
    // dst column widened to `DST_COL_WIDTH` to fit a typical hostname; the
    // info column shrinks correspondingly since it's the least dense.
    let widths = [
        Constraint::Length(IP_COL_WIDTH as u16),
        Constraint::Length(8),
        Constraint::Length(IP_COL_WIDTH as u16),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(22),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(13), // first seen (relative) + room for sort arrow
        Constraint::Length(12), // last pkt (relative) + room for sort arrow
        Constraint::Length(14),
    ];

    let header_row = sorted_header_row(state.sort_column, state.sort_direction);

    let table_widget = Table::new(rows, widths)
        .header(header_row)
        .block(theme::panel("Flows"))
        .row_highlight_style(theme::row_highlight());

    let selected = if entries.is_empty() {
        None
    } else {
        Some(state.selected.min(entries.len().saturating_sub(1)))
    };
    let mut table_state = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table_widget, area, &mut table_state);

    // Flow rows are a single line each, so the data-row region (inner height
    // minus the 1-line header) is exactly the count of visible flows. The thumb
    // tracks the selected row, not the scroll offset (see `list_scrollbar`).
    let visible = area.height.saturating_sub(3) as usize;
    let cursor = state.selected.min(entries.len().saturating_sub(1));
    list_scrollbar(frame, area, 1, entries.len(), visible, cursor);
}

/// Stable sort entries by the chosen column. `Fixed` falls back to FirstSeen
/// ascending — newer flows append to the bottom so previously-rendered rows
/// stay where the user last saw them.
pub(crate) fn sort_entries(entries: &mut [FlowRow], column: SortColumn, direction: SortDirection) {
    entries.sort_by(|a, b| {
        let primary = match column {
            SortColumn::Fixed => Ordering::Equal,
            SortColumn::SrcIp => a.key.src_ip.cmp(&b.key.src_ip),
            SortColumn::SrcPort => a.key.src_port.cmp(&b.key.src_port),
            SortColumn::DstIp => a.key.dst_ip.cmp(&b.key.dst_ip),
            SortColumn::DstPort => a.key.dst_port.cmp(&b.key.dst_port),
            SortColumn::Proto => a.key.proto.cmp(&b.key.proto),
            SortColumn::Process => process_sort_key(a).cmp(&process_sort_key(b)),
            SortColumn::Bps => a
                .stats
                .bps
                .partial_cmp(&b.stats.bps)
                .unwrap_or(Ordering::Equal),
            SortColumn::Bytes => a.stats.bytes.cmp(&b.stats.bytes),
            SortColumn::Packets => a.stats.packets.cmp(&b.stats.packets),
            // Older instants are "less", so ascending = oldest first.
            SortColumn::FirstSeen => a.first_seen.cmp(&b.first_seen),
            SortColumn::LastPacket => a.last_seen.cmp(&b.last_seen),
        };
        let primary = if column == SortColumn::Fixed {
            // Fixed is direction-less; ignore the user's asc/desc choice.
            primary
        } else if direction == SortDirection::Desc {
            primary.reverse()
        } else {
            primary
        };
        // FirstSeen tiebreaker keeps equal-keyed rows in a stable order so
        // they don't shuffle every tick when stats are identical.
        primary.then_with(|| a.first_seen.cmp(&b.first_seen))
    });
}

/// Build the header row, decorating the currently-sorted column with an
/// up/down arrow so the user can tell at a glance what's in effect.
fn sorted_header_row(column: SortColumn, direction: SortDirection) -> Row<'static> {
    const TITLES: [(SortColumn, &str); 11] = [
        (SortColumn::SrcIp, "src ip"),
        (SortColumn::SrcPort, "sport"),
        (SortColumn::DstIp, "dst ip"),
        (SortColumn::DstPort, "dport"),
        (SortColumn::Proto, "proto"),
        (SortColumn::Process, "process"),
        (SortColumn::Bps, "bps"),
        (SortColumn::Bytes, "bytes"),
        (SortColumn::Packets, "pkts"),
        (SortColumn::FirstSeen, "first seen"),
        (SortColumn::LastPacket, "last pkt"),
    ];
    let mut cells: Vec<Cell> = TITLES
        .iter()
        .map(|(c, label)| sort_header_cell(label, *c == column, direction))
        .collect();
    cells.push(Cell::from("info"));
    Row::new(cells).style(theme::table_header())
}

/// Render the merged connection table (`a`). Parallel to `render_table` but on
/// `ConnRow`s: src/dst become local/remote and the bps/bytes columns split into
/// `↑ tx` / `↓ rx` / `total`. `render_table` and the per-flow path are
/// untouched, so toggling back is a clean swap.
fn render_conn_table(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    state: &DashboardState,
    prefs: &UiPrefs,
    rdns: &RdnsCache,
    conns: &mut [ConnRow],
) {
    sort_conns(conns, state.sort_column, state.sort_direction);

    let rows: Vec<Row> = conns
        .iter()
        .map(|c| {
            // `total` carries the accent (the headline number); a fully-idle
            // connection drops it since it reads 0 throughput anyway.
            let total_cell = if c.expired {
                Cell::from(format_bytes(c.total_bytes()))
            } else {
                Cell::from(format_bytes(c.total_bytes())).style(Style::default().fg(theme::ACCENT))
            };
            let row = Row::new(vec![
                Cell::from(ip_label(c.local.0, rdns, prefs.names_mode)),
                Cell::from(c.local.1.to_string()),
                Cell::from(ip_label(c.remote.0, rdns, prefs.names_mode)),
                Cell::from(c.remote.1.to_string()),
                Cell::from(proto_name(c.proto)),
                Cell::from(format_process(c.pid, c.process_name.as_deref())),
                Cell::from(format_bytes(c.tx_bytes)),
                Cell::from(format_bytes(c.rx_bytes)),
                total_cell,
                Cell::from(c.packets.to_string()),
                Cell::from(format_duration_since(c.first_seen)),
                Cell::from(format_duration_since(c.last_seen)),
            ]);
            if c.expired {
                row.style(Style::default().fg(theme::MUTED))
            } else {
                row
            }
        })
        .collect();

    let widths = [
        Constraint::Length(IP_COL_WIDTH as u16), // local
        Constraint::Length(8),                   // lport
        Constraint::Length(IP_COL_WIDTH as u16), // remote
        Constraint::Length(8),                   // rport
        Constraint::Length(8),                   // proto
        Constraint::Length(22),                  // process
        Constraint::Length(11),                  // ↑ tx
        Constraint::Length(11),                  // ↓ rx
        Constraint::Length(11),                  // total
        Constraint::Length(8),                   // pkts
        Constraint::Length(13),                  // first seen
        Constraint::Length(12),                  // last pkt
    ];

    let table_widget = Table::new(rows, widths)
        .header(conn_header_row(state.sort_column, state.sort_direction))
        .block(theme::panel("Connections"))
        .row_highlight_style(theme::row_highlight());

    let selected = if conns.is_empty() {
        None
    } else {
        Some(state.selected.min(conns.len().saturating_sub(1)))
    };
    let mut table_state = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table_widget, area, &mut table_state);

    let visible = area.height.saturating_sub(3) as usize;
    let cursor = state.selected.min(conns.len().saturating_sub(1));
    list_scrollbar(frame, area, 1, conns.len(), visible, cursor);
}

/// Header for the connection table. `tx`/`rx` aren't independently sortable;
/// `total` carries the bandwidth-sort arrow (`Bytes` = total volume, `Bps` =
/// total live rate), so cycling either bandwidth sort decorates it.
fn conn_header_row(column: SortColumn, direction: SortDirection) -> Row<'static> {
    use SortColumn::*;
    let cell = |c: SortColumn, label: &str| sort_header_cell(label, c == column, direction);
    let total_sorted = column == Bytes || column == Bps;
    Row::new(vec![
        cell(SrcIp, "local"),
        cell(SrcPort, "lport"),
        cell(DstIp, "remote"),
        cell(DstPort, "rport"),
        cell(Proto, "proto"),
        cell(Process, "process"),
        Cell::from("↑ tx"),
        Cell::from("↓ rx"),
        sort_header_cell("total", total_sorted, direction),
        cell(Packets, "pkts"),
        cell(FirstSeen, "first seen"),
        cell(LastPacket, "last pkt"),
    ])
    .style(theme::table_header())
}

