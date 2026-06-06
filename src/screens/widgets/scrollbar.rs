//! Shared vertical scrollbar for the app's bordered list/table screens.
//!
//! The picker, dashboard, and processes screens all render a `Table` inside a
//! bordered `Block` and scroll it via `TableState`. None of them surfaced a
//! scroll position, so a long list gave no hint of how much was off-screen.
//! `list_scrollbar` paints a scrollbar onto the block's right border so all
//! three share one look and one behaviour.
//!
//! We render the bar **by hand** rather than reaching for ratatui's
//! `Scrollbar`. That widget rounds the thumb's top and bottom edges
//! independently, so the *length* between them flickers by ±1 cell as the
//! cursor moves (a true thumb of, say, 1.4 cells renders as 1 or 2 depending
//! on position). Computing the thumb length ourselves — once, from the list
//! and viewport sizes only — keeps it rock-steady while scrolling; it changes
//! only when the list itself grows or shrinks.
//!
//! The thumb is driven by the **selected row** (the cursor): its top sits at
//! the track top for the first row and flush against the track bottom for the
//! last row, moving smoothly in between. The bar is always drawn while the
//! list is non-empty — even when everything fits, where the thumb fills the
//! whole track — so it's a constant, predictable affordance.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
};

use crate::screens::theme;

/// Paint a vertical scrollbar on the right border of a bordered table.
///
/// * `area` — the full bordered rect handed to the `Table`/`Block`. The
///   scrollbar lands on its rightmost column (the border), so the table's
///   width is unaffected.
/// * `header_rows` — cells occupied by a non-scrolling table header at the top
///   (1 for all three screens). The track starts below them so the thumb maps
///   to the scrollable region only, not the header.
/// * `content_len` — total number of scrollable items (rows / interfaces).
/// * `visible_items` — how many items fit in the viewport at once. Sets the
///   thumb's (constant) length; for variable-height rows an approximation is
///   fine since the thumb is a hint, not a measurement.
/// * `selected` — index of the currently-selected item (the cursor). The thumb
///   tracks this so it moves on every key-press and reaches the bottom on the
///   last row.
pub fn list_scrollbar(
    frame: &mut Frame,
    area: Rect,
    header_rows: u16,
    content_len: usize,
    visible_items: usize,
    selected: usize,
) {
    // Cells available to scrollable content: inner height (minus the two
    // border rows) minus the fixed header.
    let track_cells = area
        .height
        .saturating_sub(2)
        .saturating_sub(header_rows) as usize;

    // No room to draw, or an empty list — nothing meaningful to show. We do
    // *not* bail when the list merely fits: the bar is always present so it's a
    // stable affordance, just with a full-length thumb.
    if track_cells == 0 || content_len == 0 {
        return;
    }

    let (thumb_len, thumb_top) = thumb_geometry(track_cells, content_len, visible_items, selected);

    // Draw down the right border column: a `│` track glyph that blends into
    // the block border, with a solid `█` thumb over `[thumb_top, +thumb_len)`.
    let x = area.x + area.width - 1;
    let y0 = area.y + 1 + header_rows;
    let track_style = Style::default().fg(theme::BORDER);
    let thumb_style = Style::default().fg(theme::ACCENT);
    let buf = frame.buffer_mut();
    for i in 0..track_cells {
        let (symbol, style) = if i >= thumb_top && i < thumb_top + thumb_len {
            ("█", thumb_style)
        } else {
            ("│", track_style)
        };
        buf.set_string(x, y0 + i as u16, symbol, style);
    }
}

/// Pure geometry for the scrollbar thumb: `(thumb_len, thumb_top)`.
///
/// Extracted so the positioning math can be unit-tested without a `Frame`.
/// `visible_items` is floored to 1 to avoid division by zero.
pub(crate) fn thumb_geometry(
    track_cells: usize,
    content_len: usize,
    visible_items: usize,
    selected: usize,
) -> (usize, usize) {
    let visible = visible_items.max(1);

    // Thumb length: proportional to visible/total, rounded to nearest, clamped.
    // Depends only on list/viewport sizes so it stays constant while scrolling.
    let thumb_len = if content_len <= visible {
        track_cells
    } else {
        ((track_cells * visible + content_len / 2) / content_len).clamp(1, track_cells)
    };

    // Thumb top: 0 for the first item, `travel` for the last.
    let travel = track_cells - thumb_len;
    let max_pos = content_len - 1;
    let sel = selected.min(max_pos);
    // `checked_div` handles the single-item list (max_pos == 0) where the thumb
    // fills the whole track and never moves.
    let thumb_top = (sel * travel + max_pos / 2).checked_div(max_pos).unwrap_or(0);

    (thumb_len, thumb_top)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 20-item list, 5 visible, 10-cell track → thumb_len = (10*5 + 10)/20 = 3.
    fn base_geometry(selected: usize) -> (usize, usize) {
        thumb_geometry(10, 20, 5, selected)
    }

    #[test]
    fn thumb_fills_track_when_all_content_visible() {
        // When the whole list fits in the viewport the thumb occupies the full track.
        let (len, top) = thumb_geometry(8, 5, 10, 0);
        assert_eq!(len, 8, "thumb_len should equal track_cells");
        assert_eq!(top, 0);
    }

    #[test]
    fn thumb_length_constant_while_scrolling() {
        // thumb_len must not change as the cursor moves — only resizes with list size.
        let (len0, _) = base_geometry(0);
        let (len_mid, _) = base_geometry(10);
        let (len_last, _) = base_geometry(19);
        assert_eq!(len0, len_mid);
        assert_eq!(len0, len_last);
    }

    #[test]
    fn thumb_at_top_for_first_item() {
        let (_, top) = base_geometry(0);
        assert_eq!(top, 0, "first item should place thumb at track top");
    }

    #[test]
    fn thumb_at_bottom_for_last_item() {
        // `travel = track_cells - thumb_len`; last item should pin the thumb
        // flush against the track bottom.
        let (len, top) = base_geometry(19);
        let travel = 10 - len;
        assert_eq!(top, travel, "last item should place thumb at track bottom");
    }

    #[test]
    fn thumb_clamped_to_at_least_one_cell() {
        // Very long list, very small viewport: thumb must be at least 1 cell.
        let (len, _) = thumb_geometry(5, 10_000, 1, 0);
        assert!(len >= 1);
    }

    #[test]
    fn single_item_list_thumb_fills_track_and_stays_at_top() {
        // With only one item there's nowhere to scroll; thumb fills the track.
        let (len, top) = thumb_geometry(6, 1, 1, 0);
        assert_eq!(len, 6);
        assert_eq!(top, 0);
    }
}
