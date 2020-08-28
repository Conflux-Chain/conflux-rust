// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    counter::{Counter, CounterUsize},
    gauge::{Gauge, GaugeUsize},
    histogram::Histogram,
    meter::{Meter, StandardMeter},
    metrics::is_enabled,
    registry::{DEFAULT_GROUPING_REGISTRY, DEFAULT_REGISTRY},
};
use lazy_static::lazy_static;
use rand::Rng;
use std::{
    fs::OpenOptions,
    io::Write,
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

lazy_static! {
    static ref REPORT_TIME: Arc<dyn Gauge<usize>> =
        GaugeUsize::register("metrics_report_time");
    static ref REPORT_FAILURE_COUNTER: Arc<dyn Counter<usize>> =
        CounterUsize::register("metrics_report_failures");
}

pub trait Reporter: Send {
    fn report(&self) -> Result<bool, String>;
}

pub fn report_async<R: 'static + Reporter>(reporter: R, interval: Duration) {
    if !is_enabled() {
        return;
    }

    thread::spawn(move || loop {
        // sleep random time on different nodes to reduce competition.
        thread::sleep(
            interval.mul_f64(0.5 + rand::thread_rng().gen_range(0.0, 1.0)),
        );

        let start = Instant::now();

        match reporter.report() {
            Ok(true) => REPORT_TIME.update(start.elapsed().as_nanos() as usize),
            Ok(false) => REPORT_FAILURE_COUNTER.inc(1),
            Err(e) => {
                eprintln!("Exit metrics reporting due to error: {}", e);
                return;
            }
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
    fn report(&self) -> Result<bool, String> {
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

        for (group_name, metrics) in DEFAULT_GROUPING_REGISTRY.read().get_all()
        {
            let agg_metric: Vec<String> = metrics
                .iter()
                .map(|(name, metric)| metric.get_value_with_group(name))
                .collect();
            file.write(
                format!(
                    "{}, {}, Group, {{{}}}\n",
                    now.as_millis(),
                    group_name,
                    agg_metric.join(", ")
                )
                .as_bytes(),
            )
            .map_err(|e| format!("failed to write file, {:?}", e))?;
        }

        Ok(true)
    }
}

pub trait Reportable {
    fn get_value(&self) -> String;
    fn get_value_with_group(&self, name: &String) -> String;
}

impl Reportable for CounterUsize {
    fn get_value(&self) -> String { format!("{}", self.count()) }

    fn get_value_with_group(&self, name: &String) -> String {
        format!("{}: {}", name, self.count())
    }
}

impl Reportable for GaugeUsize {
    fn get_value(&self) -> String { format!("{}", self.value()) }

    fn get_value_with_group(&self, name: &String) -> String {
        format!("{}: {}", name, self.value())
    }
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

    fn get_value_with_group(&self, name: &String) -> String {
        let snapshot = self.snapshot();
        format!(
            "{0}.count: {1}, {0}.m1: {2:.2}, {0}.m5: {3:.2}, {0}.m15: {4:.2}, {0}.mean: {5:.2}",
            name,
            snapshot.count(),
            snapshot.rate1(),
            snapshot.rate5(),
            snapshot.rate15(),
            snapshot.rate_mean()
        )
    }
}

impl<T: Histogram> Reportable for T {
    fn get_value(&self) -> String {
        let snapshot = self.snapshot();
        format!(
            "{{count: {}, min: {}, mean: {:.2}, max: {}, stddev: {:.2}, variance: {:.2}, p50: {}, p75: {}, p90: {}, p95: {}, p99: {}, p999: {}}}",
            snapshot.count(),
            snapshot.min(),
            snapshot.mean(),
            snapshot.max(),
            snapshot.stddev(),
            snapshot.variance(),
            snapshot.percentile(0.5),
            snapshot.percentile(0.75),
            snapshot.percentile(0.9),
            snapshot.percentile(0.95),
            snapshot.percentile(0.99),
            snapshot.percentile(0.999),
        )
    }

    fn get_value_with_group(&self, name: &String) -> String {
        let snapshot = self.snapshot();
        format!(
            "{0}.count: {1}, {0}.min: {2}, {0}.mean: {3:.2}, {0}.max: {4}, {0}.stddev: {5:.2}, {0}.variance: {6:.2}, {0}.p50: {7}, {0}.p75: {8}, {0}.p90: {9}, {0}.p95: {10}, {0}.p99: {11}, {0}.p999: {12}",
            name,
            snapshot.count(),
            snapshot.min(),
            snapshot.mean(),
            snapshot.max(),
            snapshot.stddev(),
            snapshot.variance(),
            snapshot.percentile(0.5),
            snapshot.percentile(0.75),
            snapshot.percentile(0.9),
            snapshot.percentile(0.95),
            snapshot.percentile(0.99),
            snapshot.percentile(0.999),
        )
    }
}
