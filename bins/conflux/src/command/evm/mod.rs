mod statetest;

pub use statetest::StateTestCmd;

pub enum EvmCommand {
    Statetest(statetest::StateTestCmd),
}

impl EvmCommand {
    pub fn run(&self) -> Result<String, String> {
        match self {
            EvmCommand::Statetest(cmd) => cmd.run(),
        }
    }
}
