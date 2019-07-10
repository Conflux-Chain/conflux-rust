use crate::Gauge;
use std::time::Instant;

pub struct GaugeTimer {
    gauge: &'static Gauge<usize>,
    start: Instant,
}

impl GaugeTimer {
    pub fn time_func(gauge: &'static Gauge<usize>) -> Self {
        Self {
            gauge,
            start: Instant::now(),
        }
    }
}

impl Drop for GaugeTimer {
    fn drop(&mut self) {
        self.gauge
            .update((Instant::now() - self.start).as_micros() as usize)
    }
}
