// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    counter::{Counter, CounterUsize},
    gauge::{Gauge, GaugeUsize},
    histogram::Histogram,
    meter::{Meter, StandardMeter},
    registry::{DEFAULT_GROUPING_REGISTRY, DEFAULT_REGISTRY},
    report::Reporter,
};
use influx_db_client::{
    reqwest::ClientBuilder as HttpClientBuilder, Client, Point, Points,
    Precision, Value,
};
use log::debug;
use std::{collections::HashMap, convert::TryInto, time::Duration};
use tokio::runtime::{Builder, Runtime};

const REPORT_TIMEOUT_SECONDS: u64 = 30;

pub struct InfluxdbReporter {
    runtime: Runtime,
    client: Client,
    tags: HashMap<String, String>, // e.g. node=Node_0, region=east_asia
}

impl InfluxdbReporter {
    pub fn new<T: Into<String>>(host: T, db: T) -> Self {
        let mut http_client_builder = HttpClientBuilder::new();
        http_client_builder = http_client_builder
            .timeout(Duration::from_secs(REPORT_TIMEOUT_SECONDS))
            .pool_idle_timeout(Duration::from_secs(REPORT_TIMEOUT_SECONDS));
        let http_client = http_client_builder
            .build()
            .expect("http client build error");
        let client = Client::new_with_client(
            host.into().as_str().try_into().expect("wrong url"),
            db,
            http_client,
        );
        InfluxdbReporter {
            runtime: Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
            client,
            tags: HashMap::new(),
        }
    }

    pub fn with_auth<T: Into<String>, R: Into<String>>(
        host: T, db: T, username: R, password: R,
    ) -> Self {
        InfluxdbReporter {
            runtime: Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
            client: Client::new(
                host.into().as_str().try_into().expect("wrong url"),
                db,
            )
            .set_authentication(username, password),
            tags: HashMap::new(),
        }
    }

    pub fn add_tag(&mut self, key: String, value: String) {
        self.tags.insert(key, value);
    }
}

impl Reporter for InfluxdbReporter {
    fn report(&self) -> Result<bool, String> {
        let mut points = Points::create_new(Vec::new());

        for (name, metric) in DEFAULT_REGISTRY.read().get_all() {
            let mut point = Point::new(name);
            point = metric.add_field(point, None);

            for (k, v) in &self.tags {
                point = point.add_tag(k.clone(), Value::String(v.clone()));
            }

            points = points.push(point);
        }

        for (group_name, metrics) in DEFAULT_GROUPING_REGISTRY.read().get_all()
        {
            let mut point = Point::new(group_name);

            for (metric_name, metric) in metrics {
                point = metric.add_field(point, Some(metric_name));
            }

            for (k, v) in &self.tags {
                point = point.add_tag(k.clone(), Value::String(v.clone()));
            }

            points = points.push(point);
        }

        if let Err(e) = self.runtime.block_on(self.client.write_points(
            points,
            Some(Precision::Milliseconds),
            None,
        )) {
            debug!("failed to write points to influxdb, {:?}", e);
            Ok(false)
        } else {
            Ok(true)
        }
    }
}

pub trait InfluxdbReportable {
    fn add_field(&self, point: Point, prefix: Option<&String>) -> Point;
}

fn field(name: &str, prefix: Option<&String>) -> String {
    match prefix {
        None => name.into(),
        Some(prefix) => {
            let mut field = prefix.clone();
            field.push_str(".");
            field.push_str(name);
            field
        }
    }
}

impl InfluxdbReportable for CounterUsize {
    fn add_field(&self, point: Point, prefix: Option<&String>) -> Point {
        point.add_field(
            field("count", prefix),
            Value::Integer(self.count() as i64),
        )
    }
}

impl InfluxdbReportable for GaugeUsize {
    fn add_field(&self, point: Point, prefix: Option<&String>) -> Point {
        point.add_field(
            field("value", prefix),
            Value::Integer(self.value() as i64),
        )
    }
}

impl InfluxdbReportable for StandardMeter {
    fn add_field(&self, point: Point, prefix: Option<&String>) -> Point {
        let snapshot = self.snapshot();
        point
            .add_field(
                field("count", prefix),
                Value::Integer(snapshot.count() as i64),
            )
            .add_field(field("m1", prefix), Value::Float(snapshot.rate1()))
            .add_field(field("m5", prefix), Value::Float(snapshot.rate5()))
            .add_field(field("m15", prefix), Value::Float(snapshot.rate15()))
            .add_field(
                field("mean", prefix),
                Value::Float(snapshot.rate_mean()),
            )
    }
}

impl<T: Histogram> InfluxdbReportable for T {
    fn add_field(&self, point: Point, prefix: Option<&String>) -> Point {
        let snapshot = self.snapshot();
        point
            .add_field(
                field("count", prefix),
                Value::Integer(snapshot.count() as i64),
            )
            .add_field(
                field("min", prefix),
                Value::Integer(snapshot.min() as i64),
            )
            .add_field(field("mean", prefix), Value::Float(snapshot.mean()))
            .add_field(
                field("max", prefix),
                Value::Integer(snapshot.max() as i64),
            )
            .add_field(field("stddev", prefix), Value::Float(snapshot.stddev()))
            .add_field(
                field("variance", prefix),
                Value::Float(snapshot.variance()),
            )
            .add_field(
                field("p50", prefix),
                Value::Integer(snapshot.percentile(0.5) as i64),
            )
            .add_field(
                field("p75", prefix),
                Value::Integer(snapshot.percentile(0.75) as i64),
            )
            .add_field(
                field("p90", prefix),
                Value::Integer(snapshot.percentile(0.9) as i64),
            )
            .add_field(
                field("p95", prefix),
                Value::Integer(snapshot.percentile(0.95) as i64),
            )
            .add_field(
                field("p99", prefix),
                Value::Integer(snapshot.percentile(0.99) as i64),
            )
            .add_field(
                field("p999", prefix),
                Value::Integer(snapshot.percentile(0.999) as i64),
            )
    }
}
