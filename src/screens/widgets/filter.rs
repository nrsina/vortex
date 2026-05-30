use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::screens::theme;

/// Render a one-line "filter: <expr>" indicator into `area`. Shared by the
/// dashboard and processes screens so the active BPF expression is shown
/// consistently across both views. The caller is responsible for collapsing
/// the row to zero height when the filter string is empty (see
/// `filter_row_height`) — this function unconditionally renders into whatever
/// rect it's given.
pub fn filter_bar(frame: &mut Frame, area: Rect, filter: &str) {
    let line = Line::from(vec![
        Span::styled(" filter: ", Style::default().fg(theme::MUTED)),
        Span::styled(
            filter.to_string(),
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

/// Height the filter row should claim in a screen's vertical layout. Returns
/// 1 when a filter is active and 0 otherwise so the row collapses entirely
/// when there's nothing to show — keeping the common (no-filter) case visually
/// identical to before.
pub fn filter_row_height(filter: &str) -> u16 {
    if filter.is_empty() { 0 } else { 1 }
}
