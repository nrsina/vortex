//! Shared UI preferences that apply across multiple screens.
//!
//! Today the Dashboard and Processes screens have identical toggles for
//! "show resolved hostnames in the dst column" (`n`) and "show the help
//! overlay" (`?`). Keeping each screen's bool in its own state resource
//! meant the two screens drifted out of sync — toggle names on one, the
//! other still shows IPs.
//!
//! Centralising those two flags here means a single source of truth for
//! the user's preference, and any future screen that gains the same toggle
//! plugs in for free.
//!
//! NOT shared on purpose:
//! - `paused`: each screen owns a screen-specific `frozen` snapshot, so
//!   pausing means different things per screen.
//! - `PickerState.show_help`: the picker is a distinct screen with its
//!   own help text and lifecycle (it's the entry point, not a peer of the
//!   live screens), so its overlay flag lives with picker state.

use bevy_app::{App, Plugin};
use bevy_ecs::prelude::*;

/// Cross-screen toggles. Inserted as a resource once by `UiPrefsPlugin`
/// and read/written by both Dashboard and Processes key handlers.
#[derive(Resource, Debug)]
pub struct UiPrefs {
    /// When true, screens that have a destination IP column substitute
    /// resolved hostnames where available. Toggled by `n`.
    pub names_mode: bool,
    /// When true, screens render the shared help overlay in place of
    /// their main content. Toggled by `?`; `esc` dismisses it.
    pub show_help: bool,
    /// When true, screens include expired (idle past timeout) flows in their
    /// flow lists, rendered dimmed. When false (default) expired flows are
    /// hidden, matching the pre-retention visual behaviour. Toggled by `e`.
    pub show_expired: bool,
    /// When true, screens collapse the two opposing unidirectional flows of a
    /// connection into a single `local ↔ remote` row with an ↑ tx / ↓ rx /
    /// total split (see `screens::common::conn_key` / `orient`). When false
    /// (default) each directed flow is listed separately. Toggled by `a`;
    /// shared so the dashboard and processes tree agree on the view.
    pub aggregate: bool,
}

impl Default for UiPrefs {
    fn default() -> Self {
        Self {
            // Match the previous per-screen defaults.
            names_mode: true,
            show_help: false,
            // Hide expired flows by default so the live view stays uncluttered;
            // `e` reveals them.
            show_expired: false,
            // Start in the raw per-flow view; `a` opts into the merged
            // connection view.
            aggregate: false,
        }
    }
}

pub struct UiPrefsPlugin;

impl Plugin for UiPrefsPlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(UiPrefs::default());
    }
}
