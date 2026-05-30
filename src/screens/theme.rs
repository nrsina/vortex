//! Central theme — the single source of truth for the app's colours and the
//! handful of shared styles built from them.
//!
//! Derived from `tui_design.md` ("Minimal — TUI Design System"): a monochrome
//! palette on a near-black background with **one** accent (blue). Every screen
//! and widget pulls its colours from here so the look stays consistent and a
//! palette tweak is a one-file change — no more `Color::Cyan`/`Color::Yellow`
//! literals sprinkled across the render code.
//!
//! Colours use `Color::Indexed` with the exact ANSI-256 values from the design
//! doc. The doc targets "256-color minimum", and indexed values render
//! predictably across terminals without the TrueColor-vs-256 downsampling
//! surprises of `Color::Rgb`.
//!
//! ## Usage rules (from the design doc)
//! - **One accent per view.** [`ACCENT`] (blue) is the only decorative accent —
//!   used for live values (bps), sparklines, the scroll thumb, the sorted
//!   column, the active filter, and focus cues. Don't reach for a second hue.
//! - **Status colours are semantic, not decorative.** [`SUCCESS`]/[`WARNING`]/
//!   [`ERROR`] mark state (alive/dead, errors) and nothing else.
//! - **Text hierarchy comes from the neutral scale**, not from colour:
//!   [`FOREGROUND`] for body, [`SECONDARY`] for supporting text, [`MUTED`] for
//!   hints/disabled.
//! - **Emphasis is bold or (sparingly) reverse — never italic.**
//!
//! This module is the design system's palette *reference*: it intentionally
//! defines every semantic role from `tui_design.md`, including a few not yet
//! wired to a feature (a forced [`BACKGROUND`], a [`WARNING`] state, a
//! [`SURFACE`] card fill). Keeping the full set named here means future work
//! reaches for the right colour instead of inventing a new literal — hence the
//! module-wide `dead_code` allowance.
#![allow(dead_code)]

use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders},
};

// ── Semantic palette ────────────────────────────────────────────────────────

/// Near-black main background (`#0a0a0a`). Used where we explicitly paint a
/// surface; the terminal's own background shows through unstyled cells.
pub const BACKGROUND: Color = Color::Indexed(232);
/// Default body text (`#ededed`).
pub const FOREGROUND: Color = Color::Indexed(255);
/// Brightest text — key actions / focus states (`#ffffff`).
pub const PRIMARY: Color = Color::Indexed(15);
/// Supporting text — labels, secondary columns (`#888888`).
pub const SECONDARY: Color = Color::Indexed(245);
/// The one accent: links, highlights, live values (`#0070f3`, blue).
pub const ACCENT: Color = Color::Indexed(33);
/// Positive status — alive, active traffic (`#00c853`, green).
pub const SUCCESS: Color = Color::Indexed(41);
/// Caution status (`#f5a623`, yellow). Reserved for genuine warnings.
pub const WARNING: Color = Color::Indexed(214);
/// Error status — failures, dead processes (`#ee0000`, red).
pub const ERROR: Color = Color::Indexed(196);
/// Disabled text, hints, placeholders, dividers (`#555555`).
pub const MUTED: Color = Color::Indexed(240);
/// Panel / card fill, subtle backgrounds (`#1a1a1a`).
pub const SURFACE: Color = Color::Indexed(234);
/// Panel borders and dividers — dim so the frame recedes (neutral `#2a2a2a`).
pub const BORDER: Color = Color::Indexed(238);

// ── Shared styles ─────────────────────────────────────────────────────────

/// A bordered panel with a dim single-line frame and its title embedded in the
/// top border (design "Panels / Cards"). Every titled box in the app — the
/// interface table, the flows table, the process tree — is built from this so
/// borders and titles never drift between screens.
pub fn panel(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(SECONDARY).add_modifier(Modifier::BOLD),
        ))
}

/// Selected-row background. A step brighter than [`SURFACE`] so the cursor
/// reads clearly against any dark terminal background without resorting to a
/// loud reverse bar (design: "use bold or reverse sparingly").
const SELECTION_BG: Color = Color::Indexed(238);

/// Highlight applied to the selected row of a table. A subtle fill plus bold
/// keeps the live-updating tables calm while still marking the cursor clearly.
pub fn row_highlight() -> Style {
    Style::default()
        .bg(SELECTION_BG)
        .add_modifier(Modifier::BOLD)
}

/// Style for a table column header — bold supporting text.
pub fn table_header() -> Style {
    Style::default().fg(SECONDARY).add_modifier(Modifier::BOLD)
}
