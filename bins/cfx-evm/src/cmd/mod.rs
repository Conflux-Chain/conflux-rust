mod statetest;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(infer_subcommands = true)]
#[allow(clippy::large_enum_variant)]
pub enum MainCmd {
    Statetest(statetest::Cmd),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Statetest(#[from] statetest::Error),
    // #[error(transparent)]
    // EvmRunnerErrors(#[from] evmrunner::Errors),
    // #[error("Eof validation failed: {:?}/{total_tests}",
    // total_tests-failed_test)] EofValidation {
    //     failed_test: usize,
    //     total_tests: usize,
    // },
    #[error("Custom error: {0}")]
    Custom(&'static str),
}

impl MainCmd {
    pub fn run(&self) -> Result<(), Error> {
        match self {
            Self::Statetest(cmd) => cmd.run()?,
        }
        Ok(())
    }
}
