use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::screens::theme;

/// Render a one-line page header. `title` is the screen name, shown left;
/// `right` is optional contextual text (selected interface, flow count, …)
/// shown on the right edge of the same line.
///
/// Minimal aesthetic (per `tui_design.md`): no background bar. The `Vortex`
/// brand mark carries the one accent colour, the screen name is supporting
/// text, and the right-hand context recedes into muted grey.
pub fn header(frame: &mut Frame, area: Rect, title: &str, right: Option<&str>) {
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(right_width(right))])
            .areas(area);

    let left = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            "Vortex",
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ·  ", Style::default().fg(theme::MUTED)),
        Span::styled(title.to_string(), Style::default().fg(theme::SECONDARY)),
    ]));
    frame.render_widget(left, left_area);

    if let Some(r) = right {
        let right_para = Paragraph::new(Line::from(Span::styled(
            format!("{r} "),
            Style::default().fg(theme::MUTED),
        )));
        frame.render_widget(right_para, right_area);
    }
}

fn right_width(right: Option<&str>) -> u16 {
    right.map(|s| s.chars().count() as u16 + 1).unwrap_or(0)
}
