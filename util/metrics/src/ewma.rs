use crate::metrics::ORDER;
use std::sync::atomic::{AtomicBool, AtomicU64};

/// EWMAs continuously calculate an exponentially-weighted moving average based
/// on an outside source of clock ticks.
pub struct EWMA {
    uncounted: AtomicU64,
    alpha: f64,
    rate: AtomicU64,
    init: AtomicBool,
}

impl EWMA {
    /// Constructs a new EWMA for a n-minutes moving average.
    pub fn new(n: f64) -> Self {
        EWMA::new_with_alpha(1.0 - (-5.0 / 60.0 / n).exp())
    }

    fn new_with_alpha(alpha: f64) -> Self {
        EWMA {
            uncounted: AtomicU64::new(0),
            alpha,
            rate: AtomicU64::new(0),
            init: AtomicBool::new(false),
        }
    }

    /// Rate returns the moving average rate of events per second.
    pub fn rate(&self) -> f64 { f64::from_bits(self.rate.load(ORDER)) * 1e9 }

    /// Update adds n uncounted events.
    pub fn update(&self, n: u64) { self.uncounted.fetch_add(n, ORDER); }

    /// Ticks the clock to update the moving average. It assumes it is called
    /// every 5 seconds.
    pub fn tick(&self) {
        let count = self.uncounted.swap(0, ORDER) as f64;
        let instant_rate = count / 5e9;

        if self.init.compare_and_swap(false, true, ORDER) {
            let mut current_rate = f64::from_bits(self.rate.load(ORDER));
            current_rate += self.alpha * (instant_rate - current_rate);
            self.rate.store(f64::to_bits(current_rate), ORDER);
        } else {
            self.rate.store(f64::to_bits(instant_rate), ORDER);
        }
    }
}
