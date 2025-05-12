#[macro_use]
extern crate log;

mod blocktest;
mod cmd;
mod error;
mod statetest;
mod util;

use clap::Parser;
use cmd::MainCmd;
pub use error::{StateMismatch, TestError, TestErrorKind};
use log::LevelFilter;

fn init_logger(level_filter: LevelFilter) {
    env_logger::Builder::new()
        .target(env_logger::Target::Stdout)
        .filter(None, LevelFilter::Off)
        .filter_module("evm_spec_tester", level_filter)
        .format_timestamp(None) // Optional: add timestamp
        // .format_level(true)     // show log level
        // .format_module_path(true)  // show module path
        .init();
}

fn main() {
    let cmd = MainCmd::parse();
    init_logger(cmd.verbose.log_level_filter());
    let success = cmd.run();
    if !success {
        std::process::exit(1);
    }
}
