pub mod context;
pub mod global_keys;
pub mod input;
pub mod panic_hook;

pub use input::InputReady;

use bevy_app::{App, Plugin, PreUpdate};
use bevy_ecs::prelude::*;

use context::TerminalContext;
use global_keys::global_keys;
use input::{KeyEvent, MouseEvent, ResizeEvent, poll_crossterm};

pub struct TerminalPlugin;

impl Plugin for TerminalPlugin {
    fn build(&self, app: &mut App) {
        panic_hook::install();
        app.add_message::<KeyEvent>()
            .add_message::<MouseEvent>()
            .add_message::<ResizeEvent>()
            .add_systems(PreUpdate, poll_crossterm)
            .configure_sets(PreUpdate, InputReady.after(poll_crossterm))
            .add_systems(PreUpdate, global_keys.in_set(InputReady))
            .world_mut()
            .insert_resource(TerminalContext::init().expect("failed to initialize terminal"));
    }
}
