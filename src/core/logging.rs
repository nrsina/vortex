use crate::core::settings::settings;
use tracing_appender::{
    non_blocking::WorkerGuard,
    rolling::{RollingFileAppender, Rotation},
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt};

const LOGS_DIR: &str = "logs";

pub fn file_logging(rotation: Rotation, log_file: &str) -> WorkerGuard {
    let _ = std::fs::create_dir(LOGS_DIR);
    let file_appender = RollingFileAppender::new(rotation, LOGS_DIR, log_file);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let level = match settings().debug_enabled {
        true => tracing::Level::DEBUG,
        false => tracing::Level::INFO,
    };
    let env_filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env()
        .expect("Logging environment filter must be valid");
    let subscriber = tracing_subscriber::registry().with(env_filter).with(
        fmt::Layer::new()
            .compact()
            .with_ansi(false)
            .with_writer(non_blocking),
    );
    tracing::subscriber::set_global_default(subscriber)
        .expect("A global subscriber should be set successfully");
    guard
}
