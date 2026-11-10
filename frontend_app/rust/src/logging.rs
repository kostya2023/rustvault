use std::sync::Once;

#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::{fs::OpenOptions, sync::OnceLock};

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static INIT: Once = Once::new();

#[cfg(any(target_os = "windows", target_os = "linux"))]
static LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

/// Initializes the standard log bridge exactly once.
///
/// `LogTracer` forwards records produced by the `log` facade into the
/// `tracing` subscriber. There is deliberately no reverse custom layer:
/// forwarding tracing events back into `log` would create a recursion loop.
/// Desktop builds write to a timestamped file in the OS temp directory.
/// Android keeps the formatter on stderr, which is collected by logcat.
pub(crate) fn init() {
    INIT.call_once(|| {
        let _ = tracing_log::LogTracer::init();
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,rust_lib_frontend_app=debug"));

        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            if let Ok(file) = create_desktop_log_file() {
                let (writer, guard) = tracing_appender::non_blocking(file);
                let _ = LOG_GUARD.set(guard);
                let _ = tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().with_target(true).with_writer(writer))
                    .try_init();
            } else {
                init_stderr(filter);
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        init_stderr(filter);

        tracing::info!(component = "rust", "Rust logging initialized");
    });
}

fn init_stderr(filter: EnvFilter) {
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true))
        .try_init();
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn create_desktop_log_file() -> std::io::Result<std::fs::File> {
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S%.3fZ");
    let path = std::env::temp_dir().join(format!("rustvault_{timestamp}.log"));
    OpenOptions::new().create(true).append(true).open(path)
}
