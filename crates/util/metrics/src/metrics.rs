// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    report::{report_async, FileReporter, Reportable},
    report_influxdb::{InfluxdbReportable, InfluxdbReporter},
    report_prometheus::{PrometheusReportable, PrometheusReporter},
};
use cfx_tasks::TaskExecutor;
use duration_str::deserialize_duration;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub static ORDER: Ordering = Ordering::Relaxed;

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn is_enabled() -> bool { ENABLED.load(ORDER) }

pub fn enable() { ENABLED.store(true, ORDER); }

pub trait Metric:
    Send + Sync + Reportable + InfluxdbReportable + PrometheusReportable
{
    fn get_type(&self) -> &str;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct MetricsConfiguration {
    pub enabled: bool,

    #[serde(deserialize_with = "deserialize_duration")]
    pub report_interval: Duration,

    pub file_report_output: Option<String>,

    pub influxdb_report_host: Option<String>,
    pub influxdb_report_db: String,
    pub influxdb_report_username: Option<String>,
    pub influxdb_report_password: Option<String>,
    pub influxdb_report_node: Option<String>,
    pub prometheus_listen_addr: Option<String>,
}

impl Default for MetricsConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            report_interval: Duration::from_secs(10),
            file_report_output: None,
            influxdb_report_host: None,
            influxdb_report_db: "".into(),
            influxdb_report_username: None,
            influxdb_report_password: None,
            influxdb_report_node: None,
            prometheus_listen_addr: None,
        }
    }
}

pub fn initialize(config: MetricsConfiguration, executor: TaskExecutor) {
    info!("Initializing metrics with config: {:?}", config);
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

    // prometheus reporter

    if let Some(addr) = config.prometheus_listen_addr {
        match PrometheusReporter::new(&addr, executor) {
            Ok(reporter) => {
                info!("Initializing PrometheusReporter to listen on {}", addr);
                match reporter.start_http_server() {
                    Ok(_) => {
                        info!("PrometheusReporter started successfully");
                    }
                    Err(e) => {
                        error!("Failed to start PrometheusReporter: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to initialize PrometheusReporter: {}", e);
            }
        }
    }
}
