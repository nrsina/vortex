use bevy_ecs::prelude::*;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Text},
    widgets::{Cell, Paragraph, Row, Table, TableState},
};

use crate::core::dns::RdnsCache;
use crate::core::flows::components::{
    Direction, Expired, FirstSeen, FlowKey, LastSeen, Metadata, Timeline, TrafficStats,
};
use crate::core::processes::{FlowProcess, ProcessStats, ProcessTable};
use crate::core::terminal::context::TerminalContext;
use crate::screens::common::{SortDirection, ip_label, proto_name, sort_header_cell};
use crate::screens::dashboard::state::DashboardState;
use crate::screens::details_overlay::{render_conn_overlay, render_flow_overlay};
use crate::screens::prefs::UiPrefs;
use crate::screens::processes::state::{FrozenProcessRow, ProcSortColumn, ProcessesState};
use crate::screens::processes::tree::{ChildRow, child_rows, current_parents, sort_parents};
use crate::screens::theme;
use crate::screens::widgets::{
    HelpEntry, KeyHint, filter_bar, filter_row_height, footer, format_bps, format_bytes, header,
    help, list_scrollbar,
};

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn processes_draw(
    mut ctx: ResMut<TerminalContext>,
    mut state: ResMut<ProcessesState>,
    prefs: Res<UiPrefs>,
    dash: Res<DashboardState>,
    stats: Res<ProcessStats>,
    table: Res<ProcessTable>,
    rdns: Res<RdnsCache>,
    flows: Query<(
        &FlowKey,
        &TrafficStats,
        &FlowProcess,
        &FirstSeen,
        &Direction,
        Has<Expired>,
    )>,
    // Separate read-only query for the details overlay: we only iterate it
    // when `show_details`, so the main tree-building path stays untouched.
    overlay_q: Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Timeline,
        &Direction,
        Option<&FlowProcess>,
    )>,
) -> Result {
    ctx.0.draw(|frame| {
        render(
            frame, &mut state, &prefs, &dash, &stats, &table, &rdns, &flows, &overlay_q,
        )
    })?;
    Ok(())
}

/// A single row in the flattened tree. References borrow from the
/// `parents: Vec<FrozenProcessRow>` built at the top of `render_tree` —
/// owning the data there means live and frozen paths share the same
/// rendering code, and the references stay valid for the duration of the
/// draw.
enum DisplayRow<'a> {
    Process {
        parent: &'a FrozenProcessRow,
        is_expanded: bool,
    },
    /// A child line: either a raw directed flow or a merged connection,
    /// depending on `UiPrefs.aggregate` (see `tree::ChildRow`).
    Child(&'a ChildRow),
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn render(
    frame: &mut Frame,
    state: &mut ProcessesState,
    prefs: &UiPrefs,
    dash: &DashboardState,
    stats: &ProcessStats,
    table: &ProcessTable,
    rdns: &RdnsCache,
    flows: &Query<(
        &FlowKey,
        &TrafficStats,
        &FlowProcess,
        &FirstSeen,
        &Direction,
        Has<Expired>,
    )>,
    overlay_q: &Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Timeline,
        &Direction,
        Option<&FlowProcess>,
    )>,
) {
    // Filter row collapses to height 0 when no BPF filter is active so the
    // common case keeps the same vertical real estate as before. The filter
    // itself is stored on `DashboardState` — the pcap-level filter is applied
    // upstream of both screens, so flows (and therefore processes) are already
    // restricted to matching connections; showing the expression here is just
    // surfacing what's in effect.
    let filter_h = filter_row_height(&dash.filter);

    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(filter_h),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(frame.area());

    // Build the parent list from either the frozen snapshot (paused) or live
    // ECS state. Both paths produce owned `FrozenProcessRow` values so the
    // tree-flattening code below doesn't need to know which source it has.
    let parents: Vec<FrozenProcessRow> = current_parents(state, stats, table, flows);

    let proc_count = parents.len();
    let pause = if state.paused { " · PAUSED" } else { "" };
    let iface = dash.selected_interface.as_deref().unwrap_or("?");
    let right = format!("iface: {iface} · procs: {proc_count}{pause}");
    header(frame, chunks[0], "processes", Some(&right));

    if filter_h > 0 {
        filter_bar(frame, chunks[1], &dash.filter);
    }

    if prefs.show_help {
        help(frame, chunks[2], "processes", &help_entries());
    } else if state.show_details {
        render_details(
            frame, chunks[2], state, prefs, table, stats, rdns, overlay_q,
        );
    } else {
        render_tree(frame, chunks[2], state, prefs, rdns, &parents);
    }

    // While the details overlay is open the screen is pinned to one
    // flow/connection, so the tree-manipulation hints would be misleading —
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
                KeyHint::new("enter", "expand / details"),
                KeyHint::new("n", "names"),
                KeyHint::new("e", "expired"),
                KeyHint::new("a", "aggregate"),
                KeyHint::new("s", "sort"),
                KeyHint::new("S", "dir"),
                KeyHint::new("w", if state.wrap { "wrap·on" } else { "wrap" }),
                KeyHint::new("space", "pause"),
                KeyHint::new("?", "help"),
                KeyHint::new("esc/b", "back"),
                KeyHint::new("q", "quit"),
            ],
        );
    }
}

/// Key reference for the processes screen. `esc/b` here pops back to the
/// dashboard (not the picker) — that distinction is what makes per-screen
/// help worth having.
fn help_entries() -> Vec<HelpEntry<'static>> {
    vec![
        HelpEntry::new("?", "toggle this help"),
        HelpEntry::new("q / Ctrl-C", "quit"),
        HelpEntry::new("esc / b", "back to dashboard"),
        HelpEntry::new("space", "toggle pause (display-only freeze)"),
        HelpEntry::new("j / ↓", "select next"),
        HelpEntry::new("k / ↑", "select previous"),
        HelpEntry::new("enter", "parent: expand/collapse · child: show details"),
        HelpEntry::new("n", "toggle hostname/IP in child rows"),
        HelpEntry::new("e", "show/hide expired (idle) flow children"),
        HelpEntry::new("a", "aggregate flows into connections (↑ tx / ↓ rx)"),
        HelpEntry::new("s", "cycle sort column (fixed → pid → … → user)"),
        HelpEntry::new("S", "toggle sort direction (asc/desc)"),
        HelpEntry::new("w", "wrap long cmdline strings"),
    ]
}

/// Paint the details overlay for the captured `details_flow`, pinned by key.
/// Defers to the shared `details_overlay` module so the overlay is identical
/// to the dashboard's: looked up live by `FlowKey` (so it stays fixed on one
/// flow/connection and survives expiry), connection-merged when `a` is on.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn render_details(
    frame: &mut Frame,
    area: Rect,
    state: &ProcessesState,
    prefs: &UiPrefs,
    table: &ProcessTable,
    pstats: &ProcessStats,
    rdns: &RdnsCache,
    overlay_q: &Query<(
        &FlowKey,
        &TrafficStats,
        &Metadata,
        &FirstSeen,
        &LastSeen,
        &Timeline,
        &Direction,
        Option<&FlowProcess>,
    )>,
) {
    let Some(target) = state.details_flow else {
        // Defensive: show_details was set without a flow key. Render an empty
        // overlay and let the user press Esc.
        frame.render_widget(theme::panel("Flow details"), area);
        return;
    };

    // In the connection view the captured `details_flow` is one half of a
    // connection; render the merged overlay (both directions) instead.
    if prefs.aggregate {
        render_conn_overlay(
            frame,
            area,
            target,
            state.paused,
            overlay_q,
            table,
            pstats,
            rdns,
        );
    } else {
        render_flow_overlay(
            frame,
            area,
            target,
            state.paused,
            overlay_q,
            table,
            pstats,
            rdns,
        );
    }
}

fn render_tree(
    frame: &mut Frame,
    area: Rect,
    state: &mut ProcessesState,
    prefs: &UiPrefs,
    rdns: &RdnsCache,
    parents_in: &[FrozenProcessRow],
) {
    // 1. Sort parents by the user's chosen column. We sort a local copy so
    //    the underlying slice (which may be the frozen snapshot owned by
    //    state) stays in its canonical order — re-pressing `s` re-sorts
    //    from the same baseline.
    let mut parents: Vec<FrozenProcessRow> = parents_in.to_vec();
    sort_parents(&mut parents, state.sort_column, state.sort_direction);

    // Build each parent's visible child rows (expired filtered, and — when `a`
    // is on — opposing flows merged into connections). Kept in a vec so the
    // borrowed `DisplayRow`s below stay valid. Mirrored in `keys.rs` so the
    // flattened-tree cursor counts the same rows that are drawn.
    let child_lists: Vec<Vec<ChildRow>> = parents
        .iter()
        .map(|p| {
            child_rows(
                p,
                prefs.show_expired,
                prefs.aggregate,
                state.sort_column,
                state.sort_direction,
            )
        })
        .collect();

    // 2. Build the flat display vector.
    let mut rows: Vec<DisplayRow> = Vec::new();
    for (parent, children) in parents.iter().zip(&child_lists) {
        let is_expanded = state.expanded.contains(&parent.pid);
        rows.push(DisplayRow::Process {
            parent,
            is_expanded,
        });
        if is_expanded {
            for ch in children {
                rows.push(DisplayRow::Child(ch));
            }
        }
    }

    // Compute the cmd column's rendered width so wrapping splits at exactly
    // the visible boundary. Inner area = `area` minus the 2-char block border;
    // 8 separators (1 char each, ratatui's default `column_spacing`) sit
    // between the 9 columns; the 8 fixed columns sum to 125. Anything left
    // belongs to the cmd column, with a 20-char floor matching the
    // `Constraint::Min(20)` below.
    const FIXED_COLS_TOTAL: u16 = 2 + 8 + 74 + 9 + 12 + 10 + 12 + 8;
    const COL_SEPARATORS: u16 = 8;
    const BORDER_WIDTH: u16 = 2;
    let cmd_width = area
        .width
        .saturating_sub(BORDER_WIDTH + COL_SEPARATORS + FIXED_COLS_TOTAL)
        .max(20) as usize;

    // 3. Project each variant into a 9-cell Row. Process rows in wrap mode
    //    grow their height to fit the wrapped cmdline.
    let table_rows: Vec<Row> = rows
        .iter()
        .map(|r| match r {
            DisplayRow::Process {
                parent,
                is_expanded,
            } => {
                let marker = if *is_expanded { "▾" } else { "▸" };
                // The status column carries the canonical alive/dead indicator
                // with the design's success/error glyphs (`✓`/`✗`), so the row
                // reads at a glance even before the colour registers.
                let (status_text, status_style) = if parent.alive {
                    ("✓ alive", Style::default().fg(theme::SUCCESS))
                } else {
                    ("✗ dead", Style::default().fg(theme::ERROR))
                };
                // In wrap mode, fold the cmdline onto multiple lines and grow
                // the row to match. Outside wrap mode, leave the cell as a
                // single line so ratatui truncates as before.
                let (cmd_cell, row_height) = if state.wrap && !parent.cmd.is_empty() {
                    let lines = wrap_cmd(&parent.cmd, cmd_width);
                    let height = lines.len().min(u16::MAX as usize) as u16;
                    let text = Text::from(lines.into_iter().map(Line::from).collect::<Vec<_>>());
                    (Cell::from(text), height.max(1))
                } else {
                    (Cell::from(parent.cmd.clone()), 1)
                };
                Row::new(vec![
                    // Disclosure triangle: a structural control, so it reads in
                    // supporting grey rather than competing with data for the
                    // one accent colour.
                    Cell::from(marker).style(Style::default().fg(theme::SECONDARY)),
                    Cell::from(parent.pid.to_string()),
                    Cell::from(parent.name.clone()).style(
                        Style::default()
                            .fg(theme::FOREGROUND)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Cell::from(parent.agg.conn_count.to_string()),
                    Cell::from(format_bps(parent.agg.bps))
                        .style(Style::default().fg(theme::ACCENT)),
                    Cell::from(format_bytes(parent.agg.bytes)),
                    Cell::from(parent.user.clone().unwrap_or_default())
                        .style(Style::default().fg(theme::SECONDARY)),
                    Cell::from(status_text).style(status_style),
                    cmd_cell.style(Style::default().fg(theme::MUTED)),
                ])
                .height(row_height)
            }
            DisplayRow::Child(ch) => {
                // Child rows tuck endpoint info plus protocol into the "name"
                // column so the tree shape reads at a glance. user/status/cmd
                // are blank — they have no per-flow meaning. Endpoint labels
                // flip between hostname and IP via `UiPrefs.names_mode`. A raw
                // flow renders `src → dst:dport`; a merged connection renders
                // `local ⇄ remote:rport` with combined throughput.
                let (endpoint, bps, bytes, expired) = match ch {
                    ChildRow::Flow {
                        key,
                        stats,
                        expired,
                    } => (
                        format!(
                            "  └ {} {} → {}:{}",
                            proto_name(key.proto),
                            ip_label(key.src_ip, rdns, prefs.names_mode),
                            ip_label(key.dst_ip, rdns, prefs.names_mode),
                            key.dst_port
                        ),
                        stats.bps,
                        stats.bytes,
                        *expired,
                    ),
                    ChildRow::Conn {
                        proto,
                        local,
                        remote,
                        bytes,
                        bps,
                        expired,
                        ..
                    } => (
                        format!(
                            "  └ {} {} ⇄ {}:{}",
                            proto_name(*proto),
                            ip_label(local.0, rdns, prefs.names_mode),
                            ip_label(remote.0, rdns, prefs.names_mode),
                            remote.1
                        ),
                        *bps,
                        *bytes,
                        *expired,
                    ),
                };
                // Expired children render dimmed: endpoint drops to MUTED, the
                // bps cell drops its accent (a dead flow reads 0 B/s), and the
                // row style mutes the remaining cells.
                let endpoint_fg = if expired {
                    theme::MUTED
                } else {
                    theme::SECONDARY
                };
                let bps_cell = if expired {
                    Cell::from(format_bps(bps))
                } else {
                    Cell::from(format_bps(bps)).style(Style::default().fg(theme::ACCENT))
                };
                let row = Row::new(vec![
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(endpoint).style(Style::default().fg(endpoint_fg)),
                    Cell::from(""),
                    bps_cell,
                    Cell::from(format_bytes(bytes)),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                ]);
                if expired {
                    row.style(Style::default().fg(theme::MUTED))
                } else {
                    row
                }
            }
        })
        .collect();

    let widths = [
        Constraint::Length(2),  // expand marker
        Constraint::Length(8),  // pid
        Constraint::Length(64), // name / endpoint — fits "  └ PROTO src → dst:port" with two
        // 28-char (IP_COL_WIDTH) hostnames + a 5-digit port, so the port is never truncated
        Constraint::Length(9),  // conns
        Constraint::Length(12), // bps
        Constraint::Length(10), // bytes
        Constraint::Length(12), // user
        Constraint::Length(8),  // status (alive/dead)
        Constraint::Min(20),    // cmdline
    ];
    let header_row = header_row(state.sort_column, state.sort_direction);

    if rows.is_empty() {
        let msg = Paragraph::new(Line::from(
            " no attributed processes yet — packets need to flow through an \
             owned socket for the snapshot thread to pick them up.",
        ))
        .style(Style::default().fg(theme::MUTED))
        .block(theme::panel("Processes"));
        frame.render_widget(msg, area);
        return;
    }

    // Clamp selection to the live row count so collapsing a long expansion
    // doesn't leave the cursor pointing past the end.
    if state.selected >= rows.len() {
        state.selected = rows.len() - 1;
    }
    let mut ts = TableState::default().with_selected(Some(state.selected));

    let table_widget = Table::new(table_rows, widths)
        .header(header_row)
        .block(theme::panel("Processes"))
        .row_highlight_style(theme::row_highlight());
    frame.render_stateful_widget(table_widget, area, &mut ts);

    // Most tree rows are a single line; wrapped cmdlines are the exception, so
    // treating the data-row region as the visible-item count is a close-enough
    // approximation for sizing the thumb. `content_len` is the flattened
    // parent+child row count so the thumb tracks the full expanded tree, and it
    // follows the selected row (see `list_scrollbar`). `state.selected` was
    // clamped to `rows.len()` just above.
    let visible = area.height.saturating_sub(3) as usize;
    list_scrollbar(frame, area, 1, rows.len(), visible, state.selected);
}

fn header_row(column: ProcSortColumn, direction: SortDirection) -> Row<'static> {
    // `Fixed` is direction-less so no column gets the arrow decoration —
    // matches dashboard behavior.
    let label = |c: ProcSortColumn, l: &str| -> Cell<'static> {
        let is_sorted = c == column && column != ProcSortColumn::Fixed;
        sort_header_cell(l, is_sorted, direction)
    };
    Row::new(vec![
        Cell::from(""),
        label(ProcSortColumn::Pid, "pid"),
        label(ProcSortColumn::Name, "name"),
        label(ProcSortColumn::ConnCount, "conns"),
        label(ProcSortColumn::Bps, "bps"),
        label(ProcSortColumn::Bytes, "bytes"),
        label(ProcSortColumn::User, "user"),
        Cell::from("status"),
        Cell::from("cmd"),
    ])
    .style(theme::table_header())
}

/// Greedy word-wrap for cmdline strings. Prefers to break on whitespace; if a
/// single token is longer than `width` (paths, base64 args), it's hard-split
/// so we never overflow the column. Returns at least one (possibly empty)
/// line so the row always has a height of 1.
fn wrap_cmd(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;
    for word in text.split_whitespace() {
        let wlen = word.chars().count();
        if current_len == 0 {
            // First word on the line: hard-split if it alone exceeds width.
            if wlen > width {
                push_hard_split(&mut lines, word, width);
            } else {
                current.push_str(word);
                current_len = wlen;
            }
        } else if current_len + 1 + wlen <= width {
            current.push(' ');
            current.push_str(word);
            current_len += 1 + wlen;
        } else {
            lines.push(std::mem::take(&mut current));
            current_len = 0;
            if wlen > width {
                push_hard_split(&mut lines, word, width);
            } else {
                current.push_str(word);
                current_len = wlen;
            }
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Split an overlong token into `width`-sized chunks. Used when a single
/// whitespace-free argument (e.g. a long path or hash) won't fit on its own
/// line, so we'd rather break mid-token than blow past the column edge.
fn push_hard_split(lines: &mut Vec<String>, word: &str, width: usize) {
    let mut chunk = String::new();
    let mut len = 0usize;
    for ch in word.chars() {
        if len == width {
            lines.push(std::mem::take(&mut chunk));
            len = 0;
        }
        chunk.push(ch);
        len += 1;
    }
    if !chunk.is_empty() {
        lines.push(chunk);
    }
}
