pub mod keys;
pub mod populate;
pub mod render;
pub mod state;

use bevy_app::{App, Plugin, PostUpdate, PreUpdate};
use bevy_ecs::prelude::*;
use bevy_state::prelude::{OnEnter, in_state};

use crate::core::terminal::InputReady;
use crate::screens::Screen;
use keys::picker_keys;
use populate::{drain_probe, ensure_probe_running, populate_interfaces, probe_attached};
use render::picker_draw;
use state::PickerState;

#[derive(SystemSet, Debug, Clone, PartialEq, Eq, Hash)]
struct PickerSystems;

pub struct PickerPlugin;

impl Plugin for PickerPlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(PickerState::default());

        app.configure_sets(PreUpdate, PickerSystems.run_if(in_state(Screen::Picker)));
        app.configure_sets(PostUpdate, PickerSystems.run_if(in_state(Screen::Picker)));

        // Populate the interface list whenever we enter the picker — both at
        // startup (the default state) and on back-navigation — so the first
        // frame already has a list. There is no periodic re-list; the user
        // presses `r` to rescan.
        app.add_systems(OnEnter(Screen::Picker), populate_interfaces);

        app.add_systems(
            PreUpdate,
            (
                // Every-tick probe guard: respawns the probe whenever the
                // handle is missing (after teardown, after r-rescan, after
                // active-set change), in front of `drain_probe` so a freshly
                // spawned probe can deposit samples in the same tick.
                ensure_probe_running.before(drain_probe),
                // Skipped entirely when no probe is attached, so it doesn't
                // sit in the PickerState serial chain on those ticks.
                drain_probe.run_if(probe_attached),
                picker_keys.in_set(InputReady),
            )
                .in_set(PickerSystems),
        );
        app.add_systems(PostUpdate, picker_draw.in_set(PickerSystems));
    }
}
