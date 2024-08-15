// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    ewma::EWMA,
    metrics::{is_enabled, Metric, ORDER},
    registry::{DEFAULT_GROUPING_REGISTRY, DEFAULT_REGISTRY},
};
use lazy_static::lazy_static;
use parking_lot::{Mutex, RwLock};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
    time::Instant,
};
use chrono::Duration;
use timer::Timer;

// Meters count events to produce exponentially-weighted moving average rates
// at one-, five-, and fifteen-minutes and a mean rate.
pub trait Meter: Send + Sync {
    fn count(&self) -> usize { 0 }
    fn mark(&self, _n: usize) {}
    fn rate1(&self) -> f64 { 0.0 }
    fn rate5(&self) -> f64 { 0.0 }
    fn rate15(&self) -> f64 { 0.0 }
    fn rate_mean(&self) -> f64 { 0.0 }
    fn snapshot(&self) -> Arc<dyn Meter> { Arc::new(MeterSnapshot::default()) }
    fn stop(&self) {}
}

struct NoopMeter;
impl Meter for NoopMeter {}

pub fn register_meter(name: &str) -> Arc<dyn Meter> {
    if !is_enabled() {
        return Arc::new(NoopMeter);
    }

    let meter = Arc::new(StandardMeter::new(name.into()));
    DEFAULT_REGISTRY
        .write()
        .register(name.into(), meter.clone());
    ARBITER.meters.lock().insert(name.into(), meter.clone());

    meter
}

pub fn register_meter_with_group(group: &str, name: &str) -> Arc<dyn Meter> {
    if !is_enabled() {
        return Arc::new(NoopMeter);
    }

    let mut full_meter_name = String::from(group);
    full_meter_name.push('_');
    full_meter_name.push_str(name);

    let meter = Arc::new(StandardMeter::new(full_meter_name.clone()));
    DEFAULT_GROUPING_REGISTRY.write().register(
        group.into(),
        name.into(),
        meter.clone(),
    );

    let mut meters = ARBITER.meters.lock();
    assert_eq!(meters.contains_key(&full_meter_name), false);
    meters.insert(full_meter_name, meter.clone());

    meter
}

#[derive(Default, Clone)]
struct MeterSnapshot {
    count: usize,
    rates: [u64; 4], // m1, m5, m15 and mean
}

impl Meter for MeterSnapshot {
    fn count(&self) -> usize { self.count }

    fn rate1(&self) -> f64 { f64::from_bits(self.rates[0]) }

    fn rate5(&self) -> f64 { f64::from_bits(self.rates[1]) }

    fn rate15(&self) -> f64 { f64::from_bits(self.rates[2]) }

    fn rate_mean(&self) -> f64 { f64::from_bits(self.rates[3]) }

    fn snapshot(&self) -> Arc<dyn Meter> { Arc::new(self.clone()) }
}

pub struct StandardMeter {
    name: String,
    snapshot: RwLock<MeterSnapshot>,
    ewmas: [EWMA; 3],
    start_time: Instant,
    stopped: AtomicBool,
}

impl StandardMeter {
    fn new(name: String) -> Self {
        StandardMeter {
            name,
            snapshot: RwLock::new(MeterSnapshot::default()),
            ewmas: [EWMA::new(1.0), EWMA::new(5.0), EWMA::new(15.0)],
            start_time: Instant::now(),
            stopped: AtomicBool::new(false),
        }
    }

    fn tick(&self) {
        let mut snapshot = self.snapshot.write();

        for i in 0..3 {
            self.ewmas[i].tick();
            snapshot.rates[i] = f64::to_bits(self.ewmas[i].rate());
        }

        let rate_mean_nano =
            snapshot.count as f64 / self.start_time.elapsed().as_nanos() as f64;
        snapshot.rates[3] = f64::to_bits(rate_mean_nano * 1e9);
    }
}

impl Meter for StandardMeter {
    fn count(&self) -> usize { self.snapshot.read().count }

    fn mark(&self, n: usize) {
        if self.stopped.load(ORDER) {
            return;
        }

        let mut snapshot = self.snapshot.write();
        snapshot.count += n;

        self.ewmas[0].update(n);
        self.ewmas[1].update(n);
        self.ewmas[2].update(n);

        let rate_mean_nano =
            snapshot.count as f64 / self.start_time.elapsed().as_nanos() as f64;
        snapshot.rates[3] = f64::to_bits(rate_mean_nano * 1e9);
    }

    fn rate1(&self) -> f64 { f64::from_bits(self.snapshot.read().rates[0]) }

    fn rate5(&self) -> f64 { f64::from_bits(self.snapshot.read().rates[1]) }

    fn rate15(&self) -> f64 { f64::from_bits(self.snapshot.read().rates[2]) }

    fn rate_mean(&self) -> f64 { f64::from_bits(self.snapshot.read().rates[3]) }

    fn snapshot(&self) -> Arc<dyn Meter> {
        Arc::new(self.snapshot.read().clone())
    }

    fn stop(&self) {
        if let Ok(false) =
            self.stopped.compare_exchange(false, true, ORDER, ORDER)
        {
            ARBITER.meters.lock().remove(&self.name);
        }
    }
}

impl Metric for StandardMeter {
    fn get_type(&self) -> &str { "Meter" }
}

impl Drop for StandardMeter {
    fn drop(&mut self) { self.stop(); }
}

lazy_static! {
    static ref ARBITER: MeterArbiter = MeterArbiter::default();
}

/// MeterArbiter ticks meters every 5s from a single thread.
/// meters are references in a set for future stopping.
struct MeterArbiter {
    meters: Arc<Mutex<HashMap<String, Arc<StandardMeter>>>>,
    timer: Timer,
}

unsafe impl Send for MeterArbiter {}
unsafe impl Sync for MeterArbiter {}

impl Default for MeterArbiter {
    fn default() -> Self {
        let arbiter = MeterArbiter {
            meters: Arc::new(Mutex::new(HashMap::new())),
            timer: Timer::new(),
        };

        let meters = arbiter.meters.clone();
        arbiter
            .timer
            .schedule_repeating(Duration::seconds(5), move || {
                for (_, meter) in meters.lock().iter() {
                    meter.tick();
                }
            })
            .ignore();

        arbiter
    }
}

/// A struct used to measure time in metrics.
pub struct MeterTimer {
    meter: &'static dyn Meter,
    start: Instant,
}

impl MeterTimer {
    /// Call this to measure the time to run to the end of the current scope.
    /// It will add the time from the function called till the returned
    /// instance is dropped to `meter`.
    pub fn time_func(meter: &'static dyn Meter) -> Self {
        Self {
            meter,
            start: Instant::now(),
        }
    }
}

impl Drop for MeterTimer {
    fn drop(&mut self) {
        self.meter
            .mark((Instant::now() - self.start).as_nanos() as usize)
    }
}
