pub mod common;
pub mod dns;
pub mod flows;
pub mod logging;
pub mod processes;
pub mod settings;
pub mod terminal;

use bevy_app::{App, Plugin};

pub struct CorePlugin;

impl Plugin for CorePlugin {
    fn build(&self, app: &mut App) {
        app.add_plugins(terminal::TerminalPlugin)
            .add_plugins(flows::FlowsPlugin)
            .add_plugins(processes::ProcessesPlugin)
            .add_plugins(dns::DnsPlugin);
    }
}
