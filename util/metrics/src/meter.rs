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
use time::Duration;
use timer::Timer;

// Meters count events to produce exponentially-weighted moving average rates
// at one-, five-, and fifteen-minutes and a mean rate.
pub trait Meter: Send + Sync {
    fn count(&self) -> u64 { 0 }
    fn mark(&self, _n: u64) {}
    fn rate1(&self) -> f64 { 0.0 }
    fn rate5(&self) -> f64 { 0.0 }
    fn rate15(&self) -> f64 { 0.0 }
    fn rate_mean(&self) -> f64 { 0.0 }
    fn snapshot(&self) -> MeterSnapshot { MeterSnapshot::default() }
    fn stop(&self) {}
}

struct NoopMeter;
impl Meter for NoopMeter {}

pub fn register_meter(name: &'static str) -> Arc<Meter> {
    if !is_enabled() {
        return Arc::new(NoopMeter);
    }

    let meter = Arc::new(StandardMeter::new(name));
    DEFAULT_REGISTRY
        .write()
        .register(name.into(), meter.clone());
    ARBITER.meters.lock().insert(name, meter.clone());

    meter
}

pub fn register_meter_with_group(
    group: &'static str, name: &'static str,
) -> Arc<Meter> {
    if !is_enabled() {
        return Arc::new(NoopMeter);
    }

    let meter = Arc::new(StandardMeter::new(name));
    DEFAULT_GROUPING_REGISTRY.write().register(
        group.into(),
        name.into(),
        meter.clone(),
    );
    ARBITER.meters.lock().insert(name, meter.clone());

    meter
}

#[derive(Default, Clone)]
pub struct MeterSnapshot {
    count: u64,
    rates: [u64; 4], // m1, m5, m15 and mean
}

impl Meter for MeterSnapshot {
    fn count(&self) -> u64 { self.count }

    fn rate1(&self) -> f64 { f64::from_bits(self.rates[0]) }

    fn rate5(&self) -> f64 { f64::from_bits(self.rates[1]) }

    fn rate15(&self) -> f64 { f64::from_bits(self.rates[2]) }

    fn rate_mean(&self) -> f64 { f64::from_bits(self.rates[3]) }

    fn snapshot(&self) -> MeterSnapshot { self.clone() }
}

pub struct StandardMeter {
    name: &'static str,
    snapshot: RwLock<MeterSnapshot>,
    ewmas: [EWMA; 3],
    start_time: Instant,
    stopped: AtomicBool,
}

impl StandardMeter {
    fn new(name: &'static str) -> Self {
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
    fn count(&self) -> u64 { self.snapshot.read().count }

    fn mark(&self, n: u64) {
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

    fn snapshot(&self) -> MeterSnapshot { self.snapshot.read().clone() }

    fn stop(&self) {
        if !self.stopped.compare_and_swap(false, true, ORDER) {
            ARBITER.meters.lock().remove(self.name);
        }
    }
}

impl Metric for StandardMeter {
    fn get_type(&self) -> &'static str { "Meter" }
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
    meters: Arc<Mutex<HashMap<&'static str, Arc<StandardMeter>>>>,
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
