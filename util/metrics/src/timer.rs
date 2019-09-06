use crate::{
    histogram::{Histogram, Sample},
    meter::{register_meter_with_group, Meter},
    metrics::is_enabled,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub trait Timer: Send + Sync {
    fn update(&self, _d: Duration) {}

    fn update_since(&self, start_time: Instant) {
        self.update(start_time.elapsed());
    }
}

fn register_timer_exp_decay(
    group: &str, counter_name: &str, time_name: &str,
) -> Arc<dyn Timer> {
    if !is_enabled() {
        Arc::new(NoopTimer)
    } else {
        Arc::new(StandardTimer {
            meter: register_meter_with_group(group, counter_name),
            histogram: Sample::ExpDecay(0.015)
                .register_with_group(group, time_name, 1024),
        })
    }
}

pub fn register_timer(name: &str) -> Arc<dyn Timer> {
    register_timer_exp_decay(name, "counter", "time_expdec")
}

pub fn register_timer_with_group(group: &str, name: &str) -> Arc<dyn Timer> {
    let counter_name = format!("{}_counter", name);
    let time_name = format!("{}_time_expdec", name);
    register_timer_exp_decay(group, counter_name.as_str(), time_name.as_str())
}

struct NoopTimer;
impl Timer for NoopTimer {}

struct StandardTimer {
    meter: Arc<dyn Meter>,
    histogram: Arc<dyn Histogram>,
}

impl Timer for StandardTimer {
    fn update(&self, d: Duration) {
        self.meter.mark(1);
        self.histogram.update(d.as_nanos() as u64);
    }
}
