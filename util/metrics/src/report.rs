use crate::{
    counter::{Counter, CounterUsize},
    gauge::{Gauge, GaugeUsize},
    meter::{Meter, StandardMeter},
    metrics::is_enabled,
    registry::DEFAULT_REGISTRY,
};
use std::{
    fs::OpenOptions,
    io::Write,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub trait Reporter: Send {
    fn report(&self) -> Result<(), String>;
}

pub fn report_async<R: 'static + Reporter>(reporter: R, interval: Duration) {
    if !is_enabled() {
        return;
    }

    thread::spawn(move || loop {
        thread::sleep(interval);

        if let Err(e) = reporter.report() {
            eprintln!("Exit metrics reporting due to error: {}", e);
            break;
        }
    });
}

pub struct FileReporter {
    file_path: String,
}

impl FileReporter {
    pub fn new(file_path: String) -> Self { FileReporter { file_path } }
}

impl Reporter for FileReporter {
    fn report(&self) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("invalid system time {:?}", e))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.file_path.as_str())
            .map_err(|e| format!("failed to open file, {:?}", e))?;

        for (name, metric) in DEFAULT_REGISTRY.read().get_all() {
            file.write(
                format!(
                    "{}, {}, {}, {}\n",
                    now.as_millis(),
                    name,
                    metric.get_type(),
                    metric.get_value()
                )
                .as_bytes(),
            )
            .map_err(|e| format!("failed to write file, {:?}", e))?;
        }

        Ok(())
    }
}

pub trait Reportable {
    fn get_value(&self) -> String;
}

impl Reportable for CounterUsize {
    fn get_value(&self) -> String { format!("{}", self.count()) }
}

impl Reportable for GaugeUsize {
    fn get_value(&self) -> String { format!("{}", self.value()) }
}

impl Reportable for StandardMeter {
    fn get_value(&self) -> String {
        let snapshot = self.snapshot();
        format!(
            "{{count: {}, m1: {:.2}, m5: {:.2}, m15: {:.2}, mean: {:.2}}}",
            snapshot.count(),
            snapshot.rate1(),
            snapshot.rate5(),
            snapshot.rate15(),
            snapshot.rate_mean()
        )
    }
}
