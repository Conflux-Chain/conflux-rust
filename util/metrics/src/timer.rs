use crate::Meter;
use std::time::Instant;

/// A struct used to measure time in metrics.
pub struct MeterTimer {
    meter: &'static Meter,
    start: Instant,
}

impl MeterTimer {
    /// Call this to measure the time to run to the end of the current scope.
    /// It will add the time from the function called till the returned
    /// instance is dropped to `meter`.
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
