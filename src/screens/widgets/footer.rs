use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::screens::theme;

/// One key-binding hint: `("q", "quit")` renders as ` q quit `.
pub struct KeyHint<'a> {
    pub key: &'a str,
    pub action: &'a str,
}

impl<'a> KeyHint<'a> {
    pub const fn new(key: &'a str, action: &'a str) -> Self {
        Self { key, action }
    }
}

/// Render a one-line key-hints footer. Hints are concatenated with two-space
/// separators; keys read in bright foreground, their actions recede into muted
/// grey so the row sits quietly at the bottom of the screen.
pub fn footer(frame: &mut Frame, area: Rect, hints: &[KeyHint<'_>]) {
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(hints.len() * 4 + 1);
    spans.push(Span::raw(" "));
    for (i, h) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            h.key.to_string(),
            Style::default()
                .fg(theme::PRIMARY)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            h.action.to_string(),
            Style::default().fg(theme::MUTED),
        ));
    }
    let para = Paragraph::new(Line::from(spans)).style(Style::default().fg(theme::MUTED));
    frame.render_widget(para, area);
}
