mod gauge;
mod report;

pub use self::{gauge::Gauge, report::report_file};

use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn is_enabled() -> bool { ENABLED.load(Ordering::SeqCst) }

pub fn enable() { ENABLED.store(true, Ordering::SeqCst); }
