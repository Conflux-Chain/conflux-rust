#[macro_use]
extern crate log;

mod statetest;

use statetest::command::StateTestCmd;
use structopt::StructOpt;

fn init_logger(verbosity: u8) {
    use log::LevelFilter;

    const BASE_LEVEL: u8 = 2;

    let level = match BASE_LEVEL + verbosity {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .target(env_logger::Target::Stdout)
        .filter(None, LevelFilter::Off)
        .filter_module("evm_spec_tester", level)
        .format_timestamp(None) // Optional: add timestamp
        // .format_level(true)     // show log level
        // .format_module_path(true)  // show module path
        .init();
}

fn main() {
    let cmd = StateTestCmd::from_args();
    init_logger(cmd.verbose);
    let success = cmd.run();
    if !success {
        std::process::exit(1);
    }
}
