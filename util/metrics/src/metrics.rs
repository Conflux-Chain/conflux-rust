// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::report::Reportable;
use std::sync::atomic::{AtomicBool, Ordering};

pub static ORDER: Ordering = Ordering::Relaxed;

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn is_enabled() -> bool { ENABLED.load(ORDER) }

pub fn enable() { ENABLED.store(true, ORDER); }

pub trait Metric: Send + Sync + Reportable {
    fn get_type(&self) -> &str;
}
