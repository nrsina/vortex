use anyhow::Result;
use bevy_app::{App, ScheduleRunnerPlugin, TaskPoolPlugin};
use bevy_time::TimePlugin;
use std::time::Duration;
use tracing_appender::rolling::Rotation;

mod core;
mod screens;

use crate::core::CorePlugin;
use crate::core::logging;
use crate::core::settings::settings;
use crate::screens::ScreensPlugin;

fn main() -> Result<()> {
    let _log_guard = logging::file_logging(Rotation::DAILY, "log");
    tracing::info!("Starting application...");
    let settings = settings();
    tracing::info!("Configuration: {:?}", settings);

    // Capture is started on demand when the user picks an interface in the
    // picker screen; see `screens::picker::keys::open_selected_interface`.
    App::new()
        // `TaskPoolPlugin` creates the global Compute/IO/Async task pools. The
        // multi-threaded ECS executor (enabled via the `bevy_ecs/multi_threaded`
        // feature) dispatches non-conflicting systems onto the Compute pool, so
        // this must be installed before any schedule runs. Sizes the compute
        // pool from `available_parallelism`; tunable later via `TaskPoolOptions`.
        .add_plugins(TaskPoolPlugin::default())
        .add_plugins(ScheduleRunnerPlugin::run_loop(Duration::from_secs_f32(
            1.0 / settings.tick_rate_hz as f32,
        )))
        // `TimePlugin` installs the `Time` resource so systems can tick
        // `bevy_time::Timer`s with `time.delta()`. Must be added before
        // `CorePlugin` so downstream plugins can register systems that read
        // `Res<Time>`.
        .add_plugins(TimePlugin)
        .add_plugins(CorePlugin)
        .add_plugins(ScreensPlugin)
        .run();

    Ok(())
}
