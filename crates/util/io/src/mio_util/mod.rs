#![allow(unused)]
mod event_loop;
mod handler;
mod io;
mod notify;
use mio_extras::channel;
pub use mio_extras::timer;

pub use event_loop::{EventLoop, EventLoopBuilder, Sender};
pub use handler::Handler;
pub use notify::NotifyError;

mod convert {
    use std::time::Duration;

    const NANOS_PER_MILLI: u32 = 1_000_000;
    const MILLIS_PER_SEC: u64 = 1_000;

    /// Convert a `Duration` to milliseconds, rounding up and saturating at
    /// `u64::MAX`.
    ///
    /// The saturating is fine because `u64::MAX` milliseconds are still many
    /// million years.
    pub fn millis(duration: Duration) -> u64 {
        // Round up.
        let millis =
            (duration.subsec_nanos() + NANOS_PER_MILLI - 1) / NANOS_PER_MILLI;
        duration
            .as_secs()
            .saturating_mul(MILLIS_PER_SEC)
            .saturating_add(u64::from(millis))
    }
}
