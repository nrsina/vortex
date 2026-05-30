pub mod keys;
pub mod render;
pub mod state;
pub mod tree;

use bevy_app::{App, Plugin, PostUpdate, PreUpdate};
use bevy_ecs::prelude::*;
use bevy_state::prelude::in_state;

use crate::core::terminal::InputReady;
use crate::screens::Screen;
use keys::processes_keys;
use render::processes_draw;
use state::ProcessesState;

#[derive(SystemSet, Debug, Clone, PartialEq, Eq, Hash)]
struct ProcessesSystems;

pub struct ProcessesScreenPlugin;

impl Plugin for ProcessesScreenPlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(ProcessesState::default());

        app.configure_sets(
            PreUpdate,
            ProcessesSystems.run_if(in_state(Screen::Processes)),
        );
        app.configure_sets(
            PostUpdate,
            ProcessesSystems.run_if(in_state(Screen::Processes)),
        );

        app.add_systems(
            PreUpdate,
            processes_keys.in_set(InputReady).in_set(ProcessesSystems),
        );
        app.add_systems(PostUpdate, processes_draw.in_set(ProcessesSystems));
    }
}
