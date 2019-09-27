// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use criterion::{criterion_group, criterion_main, Criterion};
use metrics::{register_meter, CounterUsize, GaugeUsize, Sample};

fn bench_counter(c: &mut Criterion) {
    let counter = CounterUsize::register("a");
    let nums = [3, 7, 4, 1, 9, 5, 6, 0, 2, 8];
    c.bench_function("counter_10_times", move |b| {
        b.iter(|| {
            for n in nums.iter() {
                counter.inc(*n);
            }
            counter.count()
        });
    });
}

fn bench_gauge(c: &mut Criterion) {
    let gauge = GaugeUsize::register("b");
    let nums = [3, 7, 4, 1, 9, 5, 6, 0, 2, 8];
    c.bench_function("gauge_10_times", move |b| {
        b.iter(|| {
            for n in nums.iter() {
                gauge.update(*n);
            }
            gauge.value()
        });
    });
}

fn bench_histogram(c: &mut Criterion) {
    let histogram = Sample::ExpDecay(0.015).register("c", 1024);
    let nums = [3, 7, 4, 1, 9, 5, 6, 0, 2, 8];
    c.bench_function("histogram_10_times", move |b| {
        b.iter(|| {
            for n in nums.iter() {
                histogram.update(*n);
            }
            histogram.count()
        });
    });
}

fn bench_meter(c: &mut Criterion) {
    let meter = register_meter("d");
    let nums = [3, 7, 4, 1, 9, 5, 6, 0, 2, 8];
    c.bench_function("meter_10_times", move |b| {
        b.iter(|| {
            for n in nums.iter() {
                meter.mark(*n);
            }
            meter.count()
        });
    });
}

criterion_group!(
    benches,
    bench_counter,
    bench_gauge,
    bench_histogram,
    bench_meter
);
criterion_main!(benches);
