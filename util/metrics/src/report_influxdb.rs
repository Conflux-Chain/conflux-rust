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
use influx_db_client::{Client, Point, Points, Precision, Value};
use log::debug;
use std::collections::HashMap;

pub struct InfluxdbReporter {
    client: Client,
    tags: HashMap<String, String>, // e.g. node=Node_0, region=east_asia
}

impl InfluxdbReporter {
    pub fn new<T: ToString>(host: T, db: T) -> Self {
        InfluxdbReporter {
            client: Client::new(host, db),
            tags: HashMap::new(),
        }
    }

    pub fn with_auth<T: ToString, R: Into<String>>(
        host: T, db: T, username: R, password: R,
    ) -> Self {
        InfluxdbReporter {
            client: Client::new(host, db)
                .set_authentication(username, password),
            tags: HashMap::new(),
        }
    }

    pub fn add_tag(&mut self, key: String, value: String) {
        self.tags.insert(key, value);
    }
}

impl Reporter for InfluxdbReporter {
    fn report(&self) -> Result<(), String> {
        let mut points = Points::create_new(Vec::new());

        for (name, metric) in DEFAULT_REGISTRY.read().get_all() {
            let mut point = Point::new(name);
            metric.add_field(&mut point, None);

            for (k, v) in &self.tags {
                point.add_tag(k.clone(), Value::String(v.clone()));
            }

            points.push(point);
        }

        for (group_name, metrics) in DEFAULT_GROUPING_REGISTRY.read().get_all()
        {
            let mut point = Point::new(group_name);

            for (metric_name, metric) in metrics {
                metric.add_field(&mut point, Some(metric_name));
            }

            for (k, v) in &self.tags {
                point.add_tag(k.clone(), Value::String(v.clone()));
            }

            points.push(point);
        }

        if let Err(e) = self.client.write_points(
            points,
            Some(Precision::Milliseconds),
            None,
        ) {
            debug!("failed to write points to influxdb, {:?}", e);
        }

        Ok(())
    }
}

pub trait InfluxdbReportable {
    fn add_field(&self, point: &mut Point, prefix: Option<&String>);
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
    fn add_field(&self, point: &mut Point, prefix: Option<&String>) {
        point.add_field(
            field("count", prefix),
            Value::Integer(self.count() as i64),
        );
    }
}

impl InfluxdbReportable for GaugeUsize {
    fn add_field(&self, point: &mut Point, prefix: Option<&String>) {
        point.add_field(
            field("value", prefix),
            Value::Integer(self.value() as i64),
        );
    }
}

impl InfluxdbReportable for StandardMeter {
    fn add_field(&self, point: &mut Point, prefix: Option<&String>) {
        let snapshot = self.snapshot();
        point.add_field(
            field("count", prefix),
            Value::Integer(snapshot.count() as i64),
        );
        point.add_field(field("m1", prefix), Value::Float(snapshot.rate1()));
        point.add_field(field("m5", prefix), Value::Float(snapshot.rate5()));
        point.add_field(field("m15", prefix), Value::Float(snapshot.rate15()));
        point.add_field(
            field("mean", prefix),
            Value::Float(snapshot.rate_mean()),
        );
    }
}

impl<T: Histogram> InfluxdbReportable for T {
    fn add_field(&self, point: &mut Point, prefix: Option<&String>) {
        let snapshot = self.snapshot();
        point.add_field(
            field("count", prefix),
            Value::Integer(snapshot.count() as i64),
        );
        point.add_field(
            field("min", prefix),
            Value::Integer(snapshot.min() as i64),
        );
        point.add_field(field("mean", prefix), Value::Float(snapshot.mean()));
        point.add_field(
            field("max", prefix),
            Value::Integer(snapshot.max() as i64),
        );
        point.add_field(
            field("stddev", prefix),
            Value::Float(snapshot.stddev()),
        );
        point.add_field(
            field("variance", prefix),
            Value::Float(snapshot.variance()),
        );
        point.add_field(
            field("p50", prefix),
            Value::Integer(snapshot.percentile(0.5) as i64),
        );
        point.add_field(
            field("p75", prefix),
            Value::Integer(snapshot.percentile(0.75) as i64),
        );
        point.add_field(
            field("p90", prefix),
            Value::Integer(snapshot.percentile(0.9) as i64),
        );
        point.add_field(
            field("p95", prefix),
            Value::Integer(snapshot.percentile(0.95) as i64),
        );
        point.add_field(
            field("p99", prefix),
            Value::Integer(snapshot.percentile(0.99) as i64),
        );
        point.add_field(
            field("p999", prefix),
            Value::Integer(snapshot.percentile(0.999) as i64),
        );
    }
}
