use bevy_app::{App, Plugin};
use bevy_state::app::{AppExtStates, StatesPlugin};
use bevy_state::prelude::{OnEnter, States};

use crate::core::terminal::input::drain_pending_keys;

pub mod common;
pub mod dashboard;
pub mod details_overlay;
pub mod flow_details;
pub mod picker;
pub mod prefs;
pub mod processes;
pub mod theme;
pub mod widgets;

pub use dashboard::DashboardPlugin;
pub use picker::PickerPlugin;
pub use prefs::UiPrefsPlugin;
pub use processes::ProcessesScreenPlugin;

/// Top-level screen shown by the app. Registered as a Bevy state via
/// `init_state` in `ScreensPlugin`. Screen-gated systems use
/// `run_if(in_state(Screen::X))`; transitions are performed by writing
/// `NextState<Screen>`.
#[derive(States, Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Screen {
    #[default]
    Picker,
    Dashboard,
    Processes,
}

pub struct ScreensPlugin;

impl Plugin for ScreensPlugin {
    fn build(&self, app: &mut App) {
        app.add_plugins(StatesPlugin)
            .init_state::<Screen>()
            .add_plugins(UiPrefsPlugin)
            .add_plugins(PickerPlugin)
            .add_plugins(DashboardPlugin)
            .add_plugins(ProcessesScreenPlugin)
            // Drop pending key events on screen transitions so the key that
            // triggered the transition isn't re-handled by the next screen.
            .add_systems(OnEnter(Screen::Picker), drain_pending_keys)
            .add_systems(OnEnter(Screen::Dashboard), drain_pending_keys)
            .add_systems(OnEnter(Screen::Processes), drain_pending_keys);
    }
}
