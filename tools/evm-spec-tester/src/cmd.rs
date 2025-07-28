use crate::{blocktest::BlockchainTestCmd, statetest::command::StateTestCmd};
use clap::{Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, Verbosity};

/// A command line tool for running Ethereum spec tests
#[derive(Parser, Debug)]
#[command(infer_subcommands = true)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct MainCmd {
    /// Verbosity level (can be used multiple times)
    /// Check detail at https://docs.rs/clap-verbosity-flag/3.0.2/clap_verbosity_flag/
    #[command(flatten)]
    pub verbose: Verbosity<InfoLevel>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
#[command(infer_subcommands = true)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Execute state tests of ethereum execution spec tests
    Statetest(StateTestCmd),
    /// Execute blockchain tests of ethereum execution spec tests
    Blocktest(BlockchainTestCmd),
}

impl MainCmd {
    pub fn run(self) -> bool {
        match self.command {
            Commands::Statetest(cmd) => cmd.run(),
            Commands::Blocktest(cmd) => cmd.run(),
        }
    }
}
