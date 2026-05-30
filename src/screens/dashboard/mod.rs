pub mod conn;
pub mod keys;
pub mod render;
pub mod rows;
pub mod state;

use bevy_app::{App, Plugin, PostUpdate, PreUpdate};
use bevy_ecs::prelude::*;
use bevy_state::prelude::in_state;

use crate::core::terminal::InputReady;
use crate::screens::Screen;
use keys::dashboard_keys;
use render::dashboard_draw;
use state::DashboardState;

#[derive(SystemSet, Debug, Clone, PartialEq, Eq, Hash)]
struct DashboardSystems;

pub struct DashboardPlugin;

impl Plugin for DashboardPlugin {
    fn build(&self, app: &mut App) {
        app.insert_resource(DashboardState::default());

        app.configure_sets(
            PreUpdate,
            DashboardSystems.run_if(in_state(Screen::Dashboard)),
        );
        app.configure_sets(
            PostUpdate,
            DashboardSystems.run_if(in_state(Screen::Dashboard)),
        );

        app.add_systems(
            PreUpdate,
            dashboard_keys.in_set(InputReady).in_set(DashboardSystems),
        );
        app.add_systems(PostUpdate, dashboard_draw.in_set(DashboardSystems));
    }
}
