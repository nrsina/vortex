//! Shared sparkline builder for bursty rate data (packets/s, bytes/s).
//!
//! Network rate samples span orders of magnitude — a few packets/s of idle
//! chatter sitting next to a multi-thousand-packet burst. A plain linear
//! sparkline auto-scales to the largest sample in its window, so the instant
//! one burst lands every other sample becomes `value / burst ≈ 0` and
//! collapses onto the baseline: the chart reads as a single lonely column.
//!
//! The fix is a natural-log value transform before charting. `ln(1 + v)`
//! compresses the dynamic range so steady low traffic stays visible right
//! next to a spike, while the spike is still clearly the tallest bar.
//!
//! Shared by the picker's per-interface trend cell and the flow-details
//! overlay so both charts scale identically.

use ratatui::{
    style::{Color, Style},
    widgets::Sparkline,
};

/// Multiplier applied after the log transform before casting back to `u64`.
/// The sparkline auto-scales to its own window max, so a constant factor
/// cancels out of the displayed bar ratios — this only preserves integer
/// resolution that would otherwise be lost truncating the small `f64` logs.
const LOG_SCALE: f64 = 1000.0;

/// Natural-log compress a single rate sample. `v = 0` maps to `0` (a blank
/// column), and growth is logarithmic from there, so each order of magnitude
/// occupies a roughly equal slice of the chart's height.
fn log_scale(v: u64) -> u64 {
    (((v as f64) + 1.0).ln() * LOG_SCALE) as u64
}

/// Build a log-scaled sparkline from `samples` (oldest → newest). The newest
/// `width` samples are shown with the newest on the right; older history
/// scrolls off the left, and a short history is left-padded so the chart
/// stays right-aligned.
///
/// The widget keeps ratatui's default bar set, whose `empty` glyph is a
/// space. That matters for charts taller than one row: with a `▁` empty
/// glyph the renderer paints a phantom baseline in the cells *above* every
/// partial bar (it fills each column top-to-bottom, drawing `empty` for the
/// unfilled rows). A space leaves those cells clean.
pub fn rate_sparkline<I>(samples: I, width: usize, color: Color) -> Sparkline<'static>
where
    I: DoubleEndedIterator<Item = u64>,
{
    // Most recent `width` samples, newest first.
    let recent: Vec<u64> = samples.rev().take(width).collect();
    let pad = width.saturating_sub(recent.len());
    // Pad the absent left side with `None`, then the recent window oldest →
    // newest so the latest sample lands on the right edge.
    let data: Vec<Option<u64>> = std::iter::repeat_n(None, pad)
        .chain(recent.into_iter().rev().map(|v| Some(log_scale(v))))
        .collect();

    Sparkline::default()
        .data(data)
        .style(Style::default().fg(color))
        // Absent (left-pad) columns render blank, matching the empty glyph,
        // so an unfilled history reads as empty space rather than a wall.
        .absent_value_symbol(" ")
}
