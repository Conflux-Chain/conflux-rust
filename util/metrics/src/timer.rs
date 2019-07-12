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
    fn update_since(&self, _start: Instant) {}
}

pub fn register_timer(name: &'static str) -> Arc<Timer> {
    if !is_enabled() {
        Arc::new(NoopTimer)
    } else {
        Arc::new(StandardTimer {
            meter: register_meter_with_group(name, "meter"),
            histogram: Sample::ExpDecay(0.015)
                .register_with_group(name, "expdec", 1024),
        })
    }
}

struct NoopTimer;
impl Timer for NoopTimer {}

struct StandardTimer {
    meter: Arc<Meter>,
    histogram: Arc<Histogram>,
}

impl Timer for StandardTimer {
    fn update(&self, d: Duration) {
        self.meter.mark(1);
        self.histogram.update(d.as_millis() as usize);
    }

    fn update_since(&self, start: Instant) { self.update(start.elapsed()); }
}
