// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    report::{report_async, FileReporter, Reportable},
    report_influxdb::{InfluxdbReportable, InfluxdbReporter},
};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub static ORDER: Ordering = Ordering::Relaxed;

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn is_enabled() -> bool { ENABLED.load(ORDER) }

fn enable() { ENABLED.store(true, ORDER); }

pub trait Metric: Send + Sync + Reportable + InfluxdbReportable {
    fn get_type(&self) -> &str;
}

pub struct MetricsConfiguration {
    pub enabled: bool,
    pub report_interval: Duration,

    pub file_report_output: Option<String>,

    pub influxdb_report_host: Option<String>,
    pub influxdb_report_db: String,
    pub influxdb_report_username: Option<String>,
    pub influxdb_report_password: Option<String>,
    pub influxdb_report_node: Option<String>,
}

pub fn initialize(config: MetricsConfiguration) {
    if !config.enabled {
        return;
    }

    enable();

    // file reporter
    if let Some(output) = config.file_report_output {
        let reporter = FileReporter::new(output);
        report_async(reporter, config.report_interval);
    }

    // influxdb reporter
    if let Some(host) = config.influxdb_report_host {
        let mut auth = None;

        if let Some(username) = config.influxdb_report_username {
            if let Some(password) = config.influxdb_report_password {
                auth = Some((username, password));
            }
        }

        let mut reporter = match auth {
            Some((username, password)) => InfluxdbReporter::with_auth(
                host,
                config.influxdb_report_db,
                username,
                password,
            ),
            None => InfluxdbReporter::new(host, config.influxdb_report_db),
        };

        if let Some(node) = config.influxdb_report_node {
            reporter.add_tag("node".into(), node);
        }

        report_async(reporter, config.report_interval);
    }
}
