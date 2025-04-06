// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    metrics::{is_enabled, Metric},
    registry::{DEFAULT_GROUPING_REGISTRY, DEFAULT_REGISTRY},
};
use parking_lot::RwLock;
use rand::{thread_rng, Rng};
use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    sync::Arc,
    time::{Duration, Instant},
};

pub trait Histogram: Send + Sync {
    fn count(&self) -> usize { 0 }
    fn max(&self) -> u64 { 0 }
    fn mean(&self) -> f64 { 0.0 }
    fn min(&self) -> u64 { 0 }
    fn percentile(&self, _p: f64) -> u64 { 0 }
    fn snapshot(&self) -> Arc<dyn Histogram> { Arc::new(Snapshot::default()) }
    fn stddev(&self) -> f64 { self.variance().sqrt() }
    fn sum(&self) -> u64 { 0 }
    fn update(&self, _v: u64) {}
    fn variance(&self) -> f64 { 0.0 }
    fn update_since(&self, start_time: Instant) {
        self.update(
            Instant::now()
                .saturating_duration_since(start_time)
                .as_nanos() as u64,
        );
    }
}

pub enum Sample {
    Uniform,
    ExpDecay(f64),
}

impl Sample {
    pub fn register(
        &self, name: &str, reservoir_size: usize,
    ) -> Arc<dyn Histogram> {
        if !is_enabled() {
            return Arc::new(NoopHistogram);
        }

        assert!(reservoir_size > 0);

        match *self {
            Sample::Uniform => {
                let sample = Arc::new(UniformSample::new(reservoir_size));
                DEFAULT_REGISTRY
                    .write()
                    .register(name.into(), sample.clone());
                sample
            }
            Sample::ExpDecay(alpha) => {
                let sample =
                    Arc::new(ExpDecaySample::new(alpha, reservoir_size));
                DEFAULT_REGISTRY
                    .write()
                    .register(name.into(), sample.clone());
                sample
            }
        }
    }

    pub fn register_with_group(
        &self, group: &str, name: &str, reservoir_size: usize,
    ) -> Arc<dyn Histogram> {
        if !is_enabled() {
            return Arc::new(NoopHistogram);
        }

        assert!(reservoir_size > 0);

        match *self {
            Sample::Uniform => {
                let sample = Arc::new(UniformSample::new(reservoir_size));
                DEFAULT_GROUPING_REGISTRY.write().register(
                    group.into(),
                    name.into(),
                    sample.clone(),
                );
                sample
            }
            Sample::ExpDecay(alpha) => {
                let sample =
                    Arc::new(ExpDecaySample::new(alpha, reservoir_size));
                DEFAULT_GROUPING_REGISTRY.write().register(
                    group.into(),
                    name.into(),
                    sample.clone(),
                );
                sample
            }
        }
    }
}

struct NoopHistogram;
impl Histogram for NoopHistogram {}

#[derive(Default, Clone)]
struct Snapshot {
    count: usize,
    values: Vec<u64>,
}

impl Histogram for Snapshot {
    fn count(&self) -> usize { self.count }

    fn max(&self) -> u64 { self.values.iter().max().cloned().unwrap_or(0) }

    fn mean(&self) -> f64 {
        if self.values.is_empty() {
            0.0
        } else {
            self.sum() as f64 / self.values.len() as f64
        }
    }

    fn min(&self) -> u64 { self.values.iter().min().cloned().unwrap_or(0) }

    fn percentile(&self, p: f64) -> u64 { sample_percentile(&self.values, p) }

    fn snapshot(&self) -> Arc<dyn Histogram> { Arc::new(self.clone()) }

    fn sum(&self) -> u64 { self.values.iter().sum() }

    fn variance(&self) -> f64 { sample_variance(&self.values) }
}

fn sample_percentile(sorted_values: &Vec<u64>, p: f64) -> u64 {
    assert!(p > 0.0 && p < 1.0);
    if sorted_values.is_empty() {
        return 0;
    }

    let pos = (sorted_values.len() - 1) as f64 * p;
    sorted_values.get(pos as usize).cloned().unwrap_or(0)
}

fn sample_variance(values: &Vec<u64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let sum: u64 = values.iter().sum();
    let mean = sum as f64 / values.len() as f64;

    let mut sum = 0.0;
    for v in values {
        let d = *v as f64 - mean;
        sum += d * d;
    }

    sum / values.len() as f64
}

/// A uniform sample using Vitter's Algorithm R. (http://www.cs.umd.edu/~samir/498/vitter.pdf)
pub struct UniformSample {
    reservoir_size: usize,
    data: RwLock<Snapshot>,
}

impl UniformSample {
    pub fn new(reservoir_size: usize) -> Self {
        UniformSample {
            reservoir_size,
            data: RwLock::new(Snapshot {
                count: 0,
                values: Vec::with_capacity(reservoir_size),
            }),
        }
    }
}

impl Histogram for UniformSample {
    fn count(&self) -> usize { self.data.read().count() }

    fn max(&self) -> u64 { self.data.read().max() }

    fn mean(&self) -> f64 { self.data.read().mean() }

    fn min(&self) -> u64 { self.data.read().min() }

    fn percentile(&self, p: f64) -> u64 {
        let mut data = self.data.write();
        data.values.sort();
        sample_percentile(&data.values, p)
    }

    fn snapshot(&self) -> Arc<dyn Histogram> {
        Arc::new(self.data.read().clone())
    }

    fn sum(&self) -> u64 { self.data.read().sum() }

    fn update(&self, v: u64) {
        let mut data = self.data.write();

        data.count += 1;

        if data.values.len() < self.reservoir_size {
            data.values.push(v);
        } else {
            let mut rng = thread_rng();
            let r = rng.gen_range(0, data.count);

            // replace probability is reservoir_size/1+count
            if let Some(replaced) = data.values.get_mut(r) {
                *replaced = v;
            }
        }
    }

    fn variance(&self) -> f64 { self.data.read().variance() }
}

impl Metric for UniformSample {
    fn get_type(&self) -> &str { "Histogram" }
}

const RESCALE_THRESHOLD: Duration = Duration::from_secs(3600);

struct ExpDecaySampleData {
    count: usize,
    t0: Instant,
    t1: Instant,
    values: BinaryHeap<ExpDecaySampleItem>,
}

/// ExpDecaySample is an exponentially-decaying sample using a forward-decaying
/// priority reservoir. See Cormode et al's "Forward Decay: A Practical Time
/// Decay Model for Streaming Systems".
///
/// <http://dimacs.rutgers.edu/~graham/pubs/papers/fwddecay.pdf>
struct ExpDecaySample {
    alpha: f64,
    reservoir_size: usize,
    data: RwLock<ExpDecaySampleData>,
}

impl ExpDecaySample {
    fn new(alpha: f64, reservoir_size: usize) -> Self {
        let now = Instant::now();
        ExpDecaySample {
            alpha,
            reservoir_size,
            data: RwLock::new(ExpDecaySampleData {
                count: 0,
                t0: now,
                t1: now + RESCALE_THRESHOLD,
                values: BinaryHeap::with_capacity(reservoir_size),
            }),
        }
    }
}

impl Histogram for ExpDecaySample {
    fn count(&self) -> usize { self.data.read().count }

    fn max(&self) -> u64 {
        let data = self.data.read();
        data.values.iter().map(|item| item.v).max().unwrap_or(0)
    }

    fn mean(&self) -> f64 {
        let data = self.data.read();

        if data.values.is_empty() {
            return 0.0;
        }

        let sum: u64 = data.values.iter().map(|item| item.v).sum();
        sum as f64 / data.values.len() as f64
    }

    fn min(&self) -> u64 {
        let data = self.data.read();
        data.values.iter().map(|item| item.v).min().unwrap_or(0)
    }

    fn percentile(&self, p: f64) -> u64 {
        let data = self.data.read();
        let mut values: Vec<u64> =
            data.values.iter().map(|item| item.v).collect();
        values.sort();
        sample_percentile(&values, p)
    }

    fn snapshot(&self) -> Arc<dyn Histogram> {
        let data = self.data.read();
        let mut values: Vec<u64> =
            data.values.iter().map(|item| item.v).collect();
        values.sort();
        Arc::new(Snapshot {
            count: data.count,
            values,
        })
    }

    fn sum(&self) -> u64 {
        let data = self.data.read();
        data.values.iter().map(|item| item.v).sum()
    }

    fn update(&self, v: u64) {
        let mut data = self.data.write();

        data.count += 1;

        if data.values.len() == self.reservoir_size {
            data.values.pop();
        }

        let now = Instant::now();
        let k = (now - data.t0).as_nanos() as f64
            / Duration::from_secs(1).as_nanos() as f64
            * self.alpha;
        let k = k.exp() * rand::thread_rng().gen_range(0.0, 1.0);
        if k.is_normal() {
            data.values.push(ExpDecaySampleItem { k, v });
        }

        if now > data.t1 {
            let items: Vec<ExpDecaySampleItem> = data.values.drain().collect();
            let t0 = data.t0;

            data.t0 = now;
            data.t1 = now + RESCALE_THRESHOLD;
            for mut item in items {
                let k = (now - t0).as_nanos() as f64
                    / Duration::from_secs(1).as_nanos() as f64
                    * (-self.alpha);
                item.k *= k.exp();
                if k.is_normal() {
                    data.values.push(item);
                }
            }
        }
    }

    fn variance(&self) -> f64 {
        let data = self.data.read();
        let values: Vec<u64> = data.values.iter().map(|item| item.v).collect();
        sample_variance(&values)
    }
}

impl Metric for ExpDecaySample {
    fn get_type(&self) -> &str { "Histogram" }
}

struct ExpDecaySampleItem {
    k: f64,
    v: u64,
}

impl PartialEq for ExpDecaySampleItem {
    fn eq(&self, other: &Self) -> bool { self.k.eq(&other.k) }
}

impl Eq for ExpDecaySampleItem {}

impl PartialOrd for ExpDecaySampleItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExpDecaySampleItem {
    // for k, the smaller, the bigger
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .k
            .partial_cmp(&self.k)
            .expect("k should be comparable")
    }
}
