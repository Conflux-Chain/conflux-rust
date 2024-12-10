// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use lazy_static::lazy_static;
/// This module can trigger random process crashes during testing.
/// This is only used to insert crashes before db modifications.
use log::info;

use parking_lot::Mutex;
use rand::{thread_rng, Rng};
lazy_static! {
    /// The process exit code set for random crash.
    pub static ref CRASH_EXIT_CODE: Mutex<i32> = Mutex::new(100);
    /// The probability to trigger a random crash.
    /// Set to `None` to disable random crash.
    pub static ref CRASH_EXIT_PROBABILITY: Mutex<Option<f64>> =
        Mutex::new(None);
}

/// Randomly crash with the probability and exit code already set.
pub fn random_crash_if_enabled(exit_str: &str) {
    if let Some(p) = *CRASH_EXIT_PROBABILITY.lock() {
        if thread_rng().gen_bool(p) {
            info!("exit before {}", exit_str);
            std::process::exit(*CRASH_EXIT_CODE.lock());
        }
    }
}
