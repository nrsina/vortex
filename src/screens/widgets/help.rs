use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::screens::theme;

/// One row in the help overlay: a key (left) and its action description.
pub struct HelpEntry<'a> {
    pub key: &'a str,
    pub description: &'a str,
}

impl<'a> HelpEntry<'a> {
    pub const fn new(key: &'a str, description: &'a str) -> Self {
        Self { key, description }
    }
}

/// Render a centered help overlay listing the keys available on a specific
/// screen. The caller supplies a screen-scoped title and only the bindings
/// relevant to that screen — keeping the overlay contextual rather than a
/// global cheat-sheet.
///
/// Keys are padded to the widest key in the list so descriptions line up in a
/// tidy column regardless of how short or long the individual keys are.
pub fn help(frame: &mut Frame, area: Rect, title: &str, entries: &[HelpEntry<'_>]) {
    // Width of the widest key so the description column aligns. `chars().count()`
    // (rather than `len()`) keeps multi-byte glyphs like `↑` from inflating the
    // padding past their rendered width.
    let key_col = entries
        .iter()
        .map(|e| e.key.chars().count())
        .max()
        .unwrap_or(0);

    let mut lines: Vec<Line> = Vec::with_capacity(entries.len() + 2);
    lines.push(Line::from(""));
    for entry in entries {
        let pad = key_col.saturating_sub(entry.key.chars().count());
        lines.push(Line::from(vec![
            Span::raw("  "),
            // Keys read in bright primary bold — matching the footer so the
            // "this is a key you press" cue is identical wherever it appears.
            Span::styled(
                entry.key.to_string(),
                Style::default()
                    .fg(theme::PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" ".repeat(pad + 3)),
            Span::styled(
                entry.description.to_string(),
                Style::default().fg(theme::SECONDARY),
            ),
        ]));
    }
    lines.push(Line::from(""));
    // Bold (not italic) close hint — the design doc avoids italic in terminals.
    lines.push(Line::from(Span::styled(
        "  press ? or esc to close",
        Style::default().fg(theme::MUTED),
    )));

    frame.render_widget(
        Paragraph::new(lines).block(theme::panel(&format!("{title} — keys"))),
        area,
    );
}
