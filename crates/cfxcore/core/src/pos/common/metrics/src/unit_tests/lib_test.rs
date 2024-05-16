// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::*;
use assert_approx_eq::assert_approx_eq;
use once_cell::sync::Lazy;
use prometheus::{
    core::Collector, proto::MetricFamily, Counter, IntCounter, Opts, Registry,
};
use rusty_fork::rusty_fork_test;

pub static INT_COUNTER: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("INT_COUNTER", "An integer counter").unwrap()
});

rusty_fork_test! {
#[test]
fn gather_metrics_test() {
    let iterations = 12;
    for _ in 0..iterations {
        INT_COUNTER.inc();
    }

    let buffer = get_all_metrics_as_serialized_string().unwrap();
    let log = String::from_utf8(buffer).unwrap();

    assert!(log.contains(&iterations.to_string()));
    assert!(log.contains(INT_COUNTER.collect()[0].get_name()));
}
}

// To test if the placeholder static metrics registered in Registry, a counter
// type metric, has been successfully published to prometheus and the result
// gathered reflect the value change.
#[test]
fn publish_metrics_test() {
    let counter_opts = Opts::new("diem_test_counter", "diem test counter help");
    let counter = Counter::with_opts(counter_opts).unwrap();

    let r = Registry::new();
    r.register(Box::new(counter.clone())).unwrap();
    counter.inc();

    let metric_families = r.gather();

    assert_eq!(metric_families.len(), 1);
    let m: &MetricFamily = metric_families.get(0).unwrap();
    assert_eq!("diem test counter help", m.get_help());
    assert_eq!("diem_test_counter", m.get_name());

    let metrics = m.get_metric();
    assert_eq!(metrics.len(), 1);
    assert_approx_eq!(1.0, metrics.get(0).unwrap().get_counter().get_value());
}

rusty_fork_test! {
#[test]
fn get_all_metrics_test() {
    INT_COUNTER.inc();

    let metrics = get_all_metrics();
    assert_eq!(metrics.len(), 1);
    for (k, v) in metrics {
        assert_eq!(
            v.parse::<i32>().unwrap(), 1,
            "{} has unexpected value {}",
            k,
            v
        );
    }
}
}
