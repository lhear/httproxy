use serde::Deserialize;
use tracing_appender::{non_blocking::WorkerGuard, rolling};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct LogConfig {
    pub file_path: Option<String>,
    pub level: String,
    pub max_backups: usize,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            file_path: None,
            level: "info".to_string(),
            max_backups: 7,
        }
    }
}

pub fn init_tracing(log_cfg: &LogConfig) -> Option<WorkerGuard> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_cfg.level));

    let (layer, guard) = if let Some(path_str) = &log_cfg.file_path {
        let file_path = std::path::Path::new(path_str);
        let directory = file_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let _ = std::fs::create_dir_all(directory);

        let file_appender = rolling::Builder::new()
            .max_log_files(log_cfg.max_backups)
            .rotation(rolling::Rotation::DAILY)
            .filename_prefix(
                file_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("app.log"),
            )
            .build(directory)
            .expect("failed to initialize rolling log file");

        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let layer = fmt::layer()
            .json()
            .with_span_list(false)
            .with_current_span(true)
            .flatten_event(true)
            .with_writer(non_blocking)
            .with_ansi(false)
            .with_target(false)
            .with_timer(tracing_subscriber::fmt::time::ChronoUtc::new(
                "%Y-%m-%dT%H:%M:%S%.6f".to_string(),
            ))
            .boxed();

        (layer, Some(guard))
    } else {
        let layer = fmt::layer()
            .json()
            .with_span_list(false)
            .with_current_span(true)
            .flatten_event(true)
            .with_writer(std::io::stdout)
            .with_ansi(true)
            .with_target(false)
            .with_timer(tracing_subscriber::fmt::time::ChronoUtc::new(
                "%Y-%m-%dT%H:%M:%S%.6f".to_string(),
            ))
            .boxed();
        (layer, None)
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .init();
    guard
}
