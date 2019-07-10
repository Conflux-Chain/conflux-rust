use crate::Meter;
use std::time::Instant;

pub struct MeterTimer {
    meter: &'static Meter,
    start: Instant,
}

impl MeterTimer {
    pub fn time_func(meter: &'static Meter) -> Self {
        Self {
            meter,
            start: Instant::now(),
        }
    }
}

impl Drop for MeterTimer {
    fn drop(&mut self) {
        self.meter
            .mark((Instant::now() - self.start).as_micros() as usize)
    }
}
