use serde::Deserialize;
use tracing_appender::{non_blocking::WorkerGuard, rolling};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

const TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.6fZ";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_MAX_BACKUPS: usize = 7;
const DEFAULT_LOG_EXTENSION: &str = "log";
const NON_BLOCKING_BUFFER_LINES: usize = 1024;

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
            level: DEFAULT_LOG_LEVEL.to_owned(),
            max_backups: DEFAULT_MAX_BACKUPS,
        }
    }
}

macro_rules! json_fmt_layer {
    ($writer:expr, $ansi:expr) => {
        fmt::layer()
            .json()
            .with_span_list(false)
            .with_current_span(true)
            .flatten_event(true)
            .with_target(false)
            .with_ansi($ansi)
            .with_timer(tracing_subscriber::fmt::time::ChronoUtc::new(
                TIME_FORMAT.to_owned(),
            ))
            .with_writer($writer)
    };
}

pub fn init_tracing(log_cfg: &LogConfig) -> Option<WorkerGuard> {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(f) => f,
        Err(_) => EnvFilter::try_new(&log_cfg.level).unwrap_or_else(|_| EnvFilter::new("info")),
    };
    match &log_cfg.file_path {
        Some(path_str) => {
            let (non_blocking, guard) = build_file_writer(path_str, log_cfg.max_backups);
            tracing_subscriber::registry()
                .with(filter)
                .with(json_fmt_layer!(non_blocking, false))
                .init();
            Some(guard)
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(json_fmt_layer!(std::io::stdout, true))
                .init();
            None
        }
    }
}

fn build_file_writer(
    path_str: &str,
    max_backups: usize,
) -> (tracing_appender::non_blocking::NonBlocking, WorkerGuard) {
    let file_path = std::path::Path::new(path_str);
    let directory = file_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let _ = std::fs::create_dir_all(directory);
    let file_stem = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("httproxy");
    let file_extension = file_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or(DEFAULT_LOG_EXTENSION);
    let file_appender = rolling::Builder::new()
        .max_log_files(max_backups)
        .rotation(rolling::Rotation::DAILY)
        .filename_prefix(file_stem)
        .filename_suffix(file_extension)
        .build(directory)
        .expect("failed to initialize rolling log file appender");
    tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(NON_BLOCKING_BUFFER_LINES)
        .finish(file_appender)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_writer_creates_rotating_file() {
        let dir = std::env::temp_dir().join(format!("httproxy_log_test_{}", std::process::id()));
        let path = dir.join("app.log");
        let (_, guard) = build_file_writer(path.to_str().unwrap(), 3);
        assert!(dir.exists());
        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_writer_without_extension_uses_fallback_suffix() {
        let dir = std::env::temp_dir().join(format!("httproxy_log_noext_{}", std::process::id()));
        let path = dir.join("noext");
        let (_, guard) = build_file_writer(path.to_str().unwrap(), 3);
        assert!(dir.exists());
        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
