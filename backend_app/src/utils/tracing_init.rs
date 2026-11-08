use std::{fmt, io::IsTerminal, panic};

use tracing::{
    Event, Level, Subscriber, error,
    field::{Field, Visit},
};
use tracing_subscriber::{
    EnvFilter,
    fmt::{
        FmtContext,
        format::{FormatEvent, FormatFields, Writer},
        time::{FormatTime, SystemTime as LogSystemTime},
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

pub fn tracing_init() {
    tracing_subscriber::registry()
        .with(build_filter())
        .with(
            tracing_subscriber::fmt::layer()
                .event_format(ConsoleFormatter)
                .with_ansi(std::io::stdout().is_terminal())
                .with_writer(std::io::stdout),
        )
        .init();

    install_panic_hook();
}

fn build_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,backend_app=debug"))
}

struct ConsoleFormatter;

#[derive(Default)]
struct EventFields {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl EventFields {
    fn push(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value.trim_matches('"').to_owned());
        } else {
            self.fields.push((field.name().to_owned(), value));
        }
    }
}

impl Visit for EventFields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value.to_owned());
    }
}

impl<S, N> FormatEvent<S, N> for ConsoleFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();
        let mut fields = EventFields::default();

        event.record(&mut fields);

        // Timestamp.
        LogSystemTime.format_time(&mut writer)?;
        write!(&mut writer, " ")?;

        // Colored log level.
        let (label, color) = match *metadata.level() {
            Level::ERROR => ("ERROR", "\x1b[1;31m"),
            Level::WARN => ("WARN", "\x1b[1;33m"),
            Level::INFO => ("INFO", "\x1b[1;32m"),
            Level::DEBUG => ("DEBUG", "\x1b[1;36m"),
            Level::TRACE => ("TRACE", "\x1b[2m"),
        };

        if writer.has_ansi_escapes() {
            write!(&mut writer, "{color}{label:<5}\x1b[0m")?;
        } else {
            write!(&mut writer, "{label:<5}")?;
        }

        // Event message.
        let message = fields.message.as_deref().unwrap_or(metadata.name());

        write!(&mut writer, " {message}")?;

        // Every field gets its own line.
        for (name, value) in fields.fields {
            writeln!(&mut writer)?;
            write!(&mut writer, "    {name} = {value}")?;
        }

        writeln!(&mut writer)
    }
}

fn install_panic_hook() {
    panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>");

        let location = info
            .location()
            .map(|location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column(),
                )
            })
            .unwrap_or_else(|| "<unknown>".to_owned());

        let message = if let Some(message) = info.payload().downcast_ref::<&str>() {
            (*message).to_owned()
        } else if let Some(message) = info.payload().downcast_ref::<String>() {
            message.clone()
        } else {
            "<non-string panic>".to_owned()
        };

        error!(
            target: "panic",
            thread = thread_name,
            location = %location,
            panic.message = %message,
            "Application panicked"
        );
    }));
}
