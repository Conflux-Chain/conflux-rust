// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
// NOTICE: Code has revised accordingly by Conflux Foundation.

#![forbid(unsafe_code)]

use backtrace::Backtrace;
use diem_logger::prelude::*;
use serde::Serialize;
use std::panic::{self, PanicInfo};

#[derive(Debug, Serialize)]
pub struct CrashInfo {
    details: String,
    backtrace: String,
}

/// Invoke to ensure process exits on a thread panic.
///
/// Tokio's default behavior is to catch panics and ignore them.  Invoking this
/// function will ensure that all subsequent thread panics (even Tokio threads)
/// will report the details/backtrace and then exit.
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicInfo<'_>) {
    // The Display formatter for a PanicInfo contains the message, payload and
    // location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    eprintln!("{}", toml::to_string_pretty(&info).unwrap());
    diem_error!(
        "{crash_info}",
        crash_info = toml::to_string_pretty(&info).unwrap()
    );

    // Wait till the logs have been flushed
    diem_logger::flush();
}
