use bevy_ecs::prelude::*;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};

use crate::core::flows::capture::ProbeStatus;
use crate::core::terminal::context::TerminalContext;
use crate::screens::theme;
use crate::screens::widgets::{HelpEntry, KeyHint, footer, header, help, list_scrollbar, rate_sparkline};
use crate::screens::picker::state::PickerState;

/// Two-line data rows give the text cells some breathing room and let the
/// 1-row sparkline (rendered at the bottom row of each cell) sit visually
/// separated from the row above.
const ROW_HEIGHT: u16 = 2;

/// Blank lines added below each row via `Row::bottom_margin` to visually
/// separate sparklines from one another.
const ROW_GAP: u16 = 1;

/// Column widths for the interface table. Kept as a module-level constant
/// because the sparkline overlay needs to reproduce the same column layout to
/// land on the "trend" cell — defining the widths once keeps the two call
/// sites in sync.
const COLUMN_WIDTHS: [Constraint; 6] = [
    Constraint::Length(14), // interface
    Constraint::Length(18), // ipv4
    Constraint::Length(40), // ipv6
    Constraint::Length(34), // status
    Constraint::Length(14), // traffic (pkt/s text)
    Constraint::Length(24), // trend (sparkline)
];

pub fn picker_draw(mut ctx: ResMut<TerminalContext>, picker: Res<PickerState>) -> Result {
    ctx.0.draw(|frame| render(frame, &picker))?;
    Ok(())
}

pub fn render(frame: &mut Frame, state: &PickerState) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Min(0),    // interface table
        Constraint::Length(3), // BPF filter input (with border)
        Constraint::Length(1), // error line
        Constraint::Length(1), // footer
    ])
    .split(frame.area());

    let right = format!("{} interfaces", state.interfaces.len());
    header(frame, chunks[0], "select interface", Some(&right));

    // Help overlay replaces the interface table; the filter input + error line
    // stay visible so the user can still see what's typed below the help text.
    if state.show_help {
        help(frame, chunks[1], "picker", &help_entries());
    } else {
        render_table(frame, chunks[1], state);
    }
    render_filter(frame, chunks[2], state);
    render_error(frame, chunks[3], state);

    let hints: &[KeyHint<'_>] = if state.editing_filter {
        &[
            KeyHint::new("type", "edit filter"),
            KeyHint::new("backspace", "delete"),
            KeyHint::new("enter", "apply & open"),
            KeyHint::new("esc", "cancel edit"),
            KeyHint::new("ctrl-c", "quit"),
        ]
    } else {
        &[
            KeyHint::new("↑/↓", "navigate"),
            KeyHint::new("enter", "open"),
            KeyHint::new("f", "filter"),
            KeyHint::new("r", "rescan"),
            KeyHint::new("?", "help"),
            KeyHint::new("q", "quit"),
        ]
    };
    footer(frame, chunks[4], hints);
}

/// Key reference for the picker screen. No `back` entry — the picker is the
/// app's entry point; the only way out is `q`.
fn help_entries() -> Vec<HelpEntry<'static>> {
    vec![
        HelpEntry::new("?", "toggle this help"),
        HelpEntry::new("q / Ctrl-C", "quit"),
        HelpEntry::new("j / ↓", "select next interface"),
        HelpEntry::new("k / ↑", "select previous interface"),
        HelpEntry::new("enter", "open dashboard for selected interface"),
        HelpEntry::new("f / /", "edit BPF filter"),
        HelpEntry::new("r", "rescan interfaces"),
    ]
}

fn render_filter(frame: &mut Frame, area: Rect, state: &PickerState) {
    let (border_style, title) = if state.editing_filter {
        (
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
            "BPF filter (editing)",
        )
    } else {
        (
            Style::default().fg(theme::BORDER),
            "BPF filter (press 'f' to edit, e.g. `tcp port 443`)",
        )
    };

    let body = if state.editing_filter {
        // Trailing block-cursor glyph so the user can see where typing lands.
        Line::from(vec![
            Span::raw(state.filter.clone()),
            Span::styled("▏", Style::default().fg(theme::ACCENT)),
        ])
    } else if state.filter.is_empty() {
        Line::from(Span::styled(
            "(none — capturing all traffic)",
            Style::default().fg(theme::MUTED),
        ))
    } else {
        Line::from(Span::styled(
            state.filter.clone(),
            Style::default().fg(theme::ACCENT),
        ))
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(theme::SECONDARY).add_modifier(Modifier::BOLD),
        ));
    frame.render_widget(Paragraph::new(body).block(block), area);
}

fn render_error(frame: &mut Frame, area: Rect, state: &PickerState) {
    let line = match &state.last_error {
        Some(msg) => Line::from(format!(" error: {msg}"))
            .style(Style::default().fg(theme::ERROR).add_modifier(Modifier::BOLD)),
        None => Line::from(""),
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn render_table(frame: &mut Frame, area: Rect, state: &PickerState) {
    let rows: Vec<Row> = state
        .interfaces
        .iter()
        .map(|i| {
            // Inactive interfaces aren't enqueued for probing, so they'd be
            // permanently `Pending` if we looked them up in the probe map.
            // Render a quiet placeholder instead — the link/connection state
            // is already visible in the `status` column.
            let traffic = if !i.is_active() {
                Cell::from("—").style(Style::default().fg(theme::MUTED))
            } else {
                let probe = state
                    .probe
                    .get(&i.name)
                    .cloned()
                    .unwrap_or(ProbeStatus::Pending);
                probe_cell(&probe)
            };
            // Status wraps over the row's two cells: link flags on top, the
            // connection status (dimmed as secondary detail) on the row below.
            let [status_top, status_bottom] = i.status_lines();
            let status = Cell::from(Text::from(vec![
                Line::from(status_top),
                Line::from(Span::styled(
                    status_bottom,
                    Style::default().fg(theme::MUTED),
                )),
            ]));
            Row::new(vec![
                Cell::from(i.name.clone()).style(
                    Style::default()
                        .fg(theme::FOREGROUND)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(format_addr(i.ipv4)),
                Cell::from(format_addr(i.ipv6)),
                status,
                traffic,
                // Sparkline is painted on top of this cell as a separate
                // widget; leaving the cell empty avoids it bleeding through.
                Cell::from(""),
            ])
            .height(ROW_HEIGHT)
            .bottom_margin(ROW_GAP)
        })
        .collect();

    let header_row = Row::new(vec![
        "interface",
        "ipv4",
        "ipv6",
        "status",
        "traffic",
        "trend",
    ])
    .style(theme::table_header());

    let table = Table::new(rows, COLUMN_WIDTHS)
        .header(header_row)
        .block(theme::panel("Interfaces"))
        .row_highlight_style(theme::row_highlight());

    let selected = if state.interfaces.is_empty() {
        None
    } else {
        Some(state.selected.min(state.interfaces.len() - 1))
    };
    let mut ts = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table, area, &mut ts);

    // `Table` updates `ts.offset()` so the selected row stays visible. The
    // sparkline overlay paints by row position, so it has to skip the same
    // prefix of interfaces the table scrolled past — otherwise the charts
    // stay glued to the top while the rows underneath move.
    render_sparkline_overlay(frame, area, state, ts.offset());

    // Each interface occupies `ROW_HEIGHT + ROW_GAP` cells, so the visible
    // interface count is the data-row region divided by that stride. The thumb
    // tracks the selected interface (see `list_scrollbar`).
    let track_cells = area.height.saturating_sub(3) as usize;
    let visible = track_cells / (ROW_HEIGHT + ROW_GAP) as usize;
    let cursor = state.selected.min(state.interfaces.len().saturating_sub(1));
    list_scrollbar(frame, area, 1, state.interfaces.len(), visible, cursor);
}

/// Paint a `Sparkline` widget onto each visible row's `trend` column. The
/// `Table` widget renders cell content as `Text`, so to use ratatui's actual
/// `Sparkline` we render the table first, then overlay the widget on the
/// cell's rect — reproducing the table's column layout with the same widths
/// and a matching 1-cell column spacing. The chart fills the full `ROW_HEIGHT`
/// of the (text-free) trend cell, giving the log-scaled bars twice the
/// vertical resolution of a single row.
fn render_sparkline_overlay(frame: &mut Frame, area: Rect, state: &PickerState, offset: usize) {
    if state.interfaces.is_empty() || offset >= state.interfaces.len() {
        return;
    }
    // Strip the bordered block so we're working in the table's inner area.
    let inner = Block::default().borders(Borders::ALL).inner(area);
    // One-line header sits on the first row of the inner area; everything
    // below belongs to data rows.
    if inner.height <= 1 {
        return;
    }
    let rows_area = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: inner.height - 1,
    };

    // Replay the table's column split so the sparkline lands exactly under
    // the "trend" header. `Table` uses `spacing(1)` between columns by
    // default; the same applied here keeps the two layouts aligned.
    let columns = Layout::horizontal(COLUMN_WIDTHS)
        .spacing(1)
        .split(rows_area);
    let trend_col = columns[5];
    if trend_col.width == 0 {
        return;
    }

    for (visible_idx, iface) in state.interfaces.iter().skip(offset).enumerate() {
        let row_top = trend_col
            .y
            .saturating_add((visible_idx as u16) * (ROW_HEIGHT + ROW_GAP));
        let row_bottom_excl = trend_col.y.saturating_add(trend_col.height);
        if row_top >= row_bottom_excl {
            break;
        }
        // Inactive interfaces have no probe history; skip them so the cell
        // stays as the "—" placeholder rendered by the table.
        if !iface.is_active() {
            continue;
        }
        let Some(history) = state.traffic_history.get(&iface.name) else {
            continue;
        };
        if history.is_empty() {
            continue;
        }

        // Fill the whole text-free trend cell (`ROW_HEIGHT` rows), clamped to
        // whatever height is left before the table's bottom edge.
        let height = ROW_HEIGHT.min(row_bottom_excl - row_top);
        let cell_rect = Rect {
            x: trend_col.x,
            y: row_top,
            width: trend_col.width,
            height,
        };
        // Shared log-scaled builder: auto-scales to the visible window so a
        // burst no longer squashes steady traffic to the baseline. No `.max()`
        // pin — an all-time peak (the original design) made a busy interface
        // look idle until it went fully quiet.
        let sparkline = rate_sparkline(
            history.iter().copied(),
            trend_col.width as usize,
            theme::ACCENT,
        );
        frame.render_widget(sparkline, cell_rect);
    }
}

fn probe_cell(status: &ProbeStatus) -> Cell<'static> {
    // Status glyphs from the design icon set: `○` pending, `▶` running/active,
    // `·` idle/info, `✗` error. All single-width so the column stays aligned.
    match status {
        ProbeStatus::Pending => {
            Cell::from("○ scanning…").style(Style::default().fg(theme::MUTED))
        }
        ProbeStatus::Sampled { pps } if *pps >= 1.0 => {
            Cell::from(format!("▶ {pps:.0} pkt/s")).style(Style::default().fg(theme::SUCCESS))
        }
        ProbeStatus::Sampled { .. } => {
            Cell::from("· idle").style(Style::default().fg(theme::MUTED))
        }
        ProbeStatus::Error(msg) => {
            // Only show a short hint; the full message is in the log.
            let _ = msg;
            Cell::from("✗ n/a").style(Style::default().fg(theme::ERROR))
        }
    }
}

fn format_addr(addr: Option<std::net::IpAddr>) -> String {
    match addr {
        Some(a) => a.to_string(),
        None => "—".into(),
    }
}
