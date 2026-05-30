//! Shared "details overlay" widget.
//!
//! Like `help`, it fills the content area passed in by the caller (rather
//! than computing a floating centered rect). The caller assembles a `Vec`
//! of `DetailRow`s — the widget paints each row on its own line, splitting
//! the row's `Rect` horizontally for `Pair` rows and using ratatui's
//! `Sparkline` for `Sparkline` rows.
//!
//! Used by both the dashboard and the processes screen via the
//! `screens::flow_details::flow_details_rows` builder, so the layout stays
//! identical across the two entry points.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use super::rate_sparkline;
use crate::screens::theme;

/// One renderable row in the details overlay. The variants encode the only
/// shapes the overlay currently needs — adding a new shape is a single new
/// arm in `details()`.
pub enum DetailRow<'a> {
    /// `label    value` — single column.
    Single { label: &'a str, value: String },
    /// `label_a  value_a  │  label_b  value_b` — two columns side by side.
    Pair {
        label_a: &'a str,
        value_a: String,
        label_b: &'a str,
        value_b: String,
    },
    /// Like `Single`, but the value wraps onto additional lines if it would
    /// overflow the row width. Used for long values (paths, command lines)
    /// where truncation hides information the user came here to see.
    /// Continuation lines align under the value's first character.
    Wrapped { label: &'a str, value: String },
    /// `label    ▂▃▅▆█▇▆…` — a small inline sparkline anchored to the right.
    Sparkline { label: &'a str, data: &'a [u64] },
    /// `─ Title ─────` — section divider, makes the overlay scannable.
    SectionHeader { title: &'a str },
    /// Vertical breathing room.
    Blank,
}

const LABEL_WIDTH: u16 = 12;

/// Max width per `Pair` half. On a 4K terminal a naïve 50/50 split pushes
/// the right column hundreds of cells away from the left, so the eye has
/// to travel across a huge gap to relate `src` to `dst` (or `name` to
/// `parent`). Capping each half keeps the pair visually clustered on the
/// left while still accommodating IPv6 addresses + service-name suffixes.
const PAIR_HALF_MAX: u16 = 56;

/// Max width of the inline sparkline row. The 60-bucket `Timeline` ring
/// renders at one bar per cell; padding the absent left side with `▁`
/// gives a continuous baseline, but stretching the chart across an entire
/// 4K width would leave a very thin band of activity floating in a sea of
/// baseline. 50 cells keeps the chart compact while still showing the
/// majority of the 60-second history at one-bar-per-second resolution.
const SPARKLINE_MAX: u16 = 50;

/// Render the details overlay into `area`. `title` appears in the top border.
/// The widget consumes the entire `area` — caller controls placement.
pub fn details(frame: &mut Frame, area: Rect, title: &str, rows: &[DetailRow<'_>]) {
    let block = theme::panel(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Most rows are one line tall; `Wrapped` rows grow vertically to fit
    // the wrapped value at the current width.
    let mut constraints: Vec<Constraint> = rows
        .iter()
        .map(|row| Constraint::Length(row_height(row, inner.width)))
        .collect();
    // Spacer + hint row at the bottom.
    constraints.push(Constraint::Min(0));
    constraints.push(Constraint::Length(1));
    let row_rects = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    for (i, row) in rows.iter().enumerate() {
        render_row(frame, row_rects[i], row);
    }

    // Close hint occupies the final 1-line rect. Muted, bold-free (no italic —
    // the design doc avoids italic in terminals).
    let hint = Paragraph::new(Line::from(Span::styled(
        "  press esc to close",
        Style::default().fg(theme::MUTED),
    )));
    frame.render_widget(hint, *row_rects.last().expect("hint row reserved above"));
}

/// How many vertical cells a row needs at the given total width. Only
/// `Wrapped` rows are variable; everything else is a single line.
fn row_height(row: &DetailRow<'_>, total_width: u16) -> u16 {
    match row {
        DetailRow::Wrapped { value, .. } => {
            let label_w = LABEL_WIDTH + 4;
            let value_w = total_width.saturating_sub(label_w).max(1);
            wrapped_line_count(value, value_w)
        }
        // Two rows so the log-scaled chart gets twice the vertical resolution.
        DetailRow::Sparkline { .. } => 2,
        _ => 1,
    }
}

/// Mirror ratatui's `WordWrapper` logic just enough to know how many lines
/// a value will occupy at the given width. Words shorter than `width` wrap
/// at whitespace boundaries; words longer than `width` (typical for file
/// paths) break at character boundaries.
///
/// We re-implement this rather than calling `Paragraph::line_count`, which
/// is gated behind ratatui's `unstable-rendered-line-info` feature.
fn wrapped_line_count(value: &str, width: u16) -> u16 {
    if width == 0 {
        return 1;
    }
    let w = width as usize;
    let mut lines: usize = 1;
    let mut col: usize = 0;
    for word in value.split_whitespace() {
        let wlen = word.chars().count().max(1);
        if wlen > w {
            // Long token (e.g. a path with no spaces) breaks at the
            // character boundary once it exceeds the remaining width.
            let avail = w.saturating_sub(col);
            let rem = wlen.saturating_sub(avail);
            lines += rem.div_ceil(w);
            col = rem % w;
        } else {
            let sep = if col == 0 { 0 } else { 1 };
            if col + sep + wlen <= w {
                col += sep + wlen;
            } else {
                lines += 1;
                col = wlen;
            }
        }
    }
    (lines as u16).max(1)
}

fn render_row(frame: &mut Frame, area: Rect, row: &DetailRow<'_>) {
    match row {
        DetailRow::Blank => {}
        DetailRow::SectionHeader { title } => {
            // Section divider: the title reads as supporting text, the rule
            // recedes into the dim border colour.
            let line = Line::from(vec![
                Span::styled("─ ", Style::default().fg(theme::BORDER)),
                Span::styled(
                    title.to_string(),
                    Style::default()
                        .fg(theme::SECONDARY)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {}", "─".repeat(80)),
                    Style::default().fg(theme::BORDER),
                ),
            ]);
            frame.render_widget(Paragraph::new(line), area);
        }
        DetailRow::Single { label, value } => {
            frame.render_widget(Paragraph::new(single_line(label, value)), area);
        }
        DetailRow::Wrapped { label, value } => {
            // Fixed-width label column on the left, wrapping value column on
            // the right. Continuation lines naturally line up under the
            // value's first character, keeping the label visually anchored
            // only to the first line.
            let label_w = LABEL_WIDTH + 4;
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(label_w), Constraint::Min(1)])
                .split(area);
            let pad = (LABEL_WIDTH as usize).saturating_sub(label.chars().count());
            let label_line = Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    label.to_string(),
                    Style::default()
                        .fg(theme::SECONDARY)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" ".repeat(pad + 2)),
            ]);
            frame.render_widget(Paragraph::new(label_line), split[0]);
            frame.render_widget(
                Paragraph::new(value.clone())
                    .wrap(Wrap { trim: false })
                    .style(Style::default().fg(theme::FOREGROUND)),
                split[1],
            );
        }
        DetailRow::Pair {
            label_a,
            value_a,
            label_b,
            value_b,
        } => {
            // Cap each half at PAIR_HALF_MAX so on wide terminals the two
            // columns stay clustered on the left instead of drifting to the
            // far edges. On narrow terminals fall back to a 50/50 split
            // (minus the 1-cell separator), with a floor that keeps the
            // label fully visible.
            let avail = area.width.saturating_sub(1);
            let half = (avail / 2).clamp(LABEL_WIDTH + 4, PAIR_HALF_MAX);
            let halves = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(half),
                    Constraint::Length(1),
                    Constraint::Length(half),
                    Constraint::Min(0),
                ])
                .split(area);
            frame.render_widget(Paragraph::new(single_line(label_a, value_a)), halves[0]);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "│",
                    Style::default().fg(theme::BORDER),
                ))),
                halves[1],
            );
            frame.render_widget(Paragraph::new(single_line(label_b, value_b)), halves[2]);
        }
        DetailRow::Sparkline { label, data } => {
            // Label on the left, sparkline next, then any remaining cells
            // stay empty so the chart doesn't spread thin across a 4K
            // terminal. The sparkline width itself is capped by
            // SPARKLINE_MAX for the same reason.
            let label_w = LABEL_WIDTH + 4;
            let chart_w = area
                .width
                .saturating_sub(label_w)
                .min(SPARKLINE_MAX);
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(label_w),
                    Constraint::Length(chart_w),
                    Constraint::Min(0),
                ])
                .split(area);
            // Label sits on the top row of the now 2-row-tall sparkline cell.
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        label.to_string(),
                        Style::default()
                            .fg(theme::SECONDARY)
                            .add_modifier(Modifier::BOLD),
                    ),
                ])),
                split[0],
            );
            // Shared log-scaled builder — same scaling as the picker's
            // per-interface trend cell so a burst doesn't flatten the rest.
            // Accent colour: the one decorative hue, used for all charts.
            let sparkline =
                rate_sparkline(data.iter().copied(), split[1].width as usize, theme::ACCENT);
            frame.render_widget(sparkline, split[1]);
        }
    }
}

fn single_line<'a>(label: &'a str, value: &'a str) -> Line<'a> {
    let pad = (LABEL_WIDTH as usize).saturating_sub(label.chars().count());
    Line::from(vec![
        Span::raw("  "),
        Span::styled(
            label.to_string(),
            Style::default()
                .fg(theme::SECONDARY)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" ".repeat(pad + 2)),
        Span::styled(value.to_string(), Style::default().fg(theme::FOREGROUND)),
    ])
}
