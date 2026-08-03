// Copyright 2026 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    backtrace::Backtrace,
    panic::{self, PanicHookInfo},
};

/// Install a process-wide panic hook that preserves the default stderr
/// output, mirrors the message to the log4rs-backed application log, and
/// flushes the logger before returning so the panic message is durable
/// before the panicking thread unwinds.
///
/// Must be called after `log4rs::init_*` so that `log::error!` reaches
/// the configured appenders.
pub fn setup() {
    panic::set_hook(Box::new(|pi: &PanicHookInfo<'_>| {
        let backtrace = Backtrace::force_capture();
        eprintln!("panic: {pi}\nbacktrace:\n{backtrace}");
        log::error!("panic: {pi}\nbacktrace: {backtrace}");
        log::logger().flush();
    }));
}
