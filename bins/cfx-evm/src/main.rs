mod cmd;
mod statetest_types;

use clap::Parser;
use cmd::{Error, MainCmd};

fn main() -> Result<(), Error> {
    MainCmd::parse().run().inspect_err(|e| println!("{e:?}"))
}
