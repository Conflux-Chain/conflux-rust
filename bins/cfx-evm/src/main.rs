use clap::Parser;
mod cmd;

use cmd::{Error, MainCmd};

fn main() -> Result<(), Error> {
    MainCmd::parse().run().inspect_err(|e| println!("{e:?}"))
}
