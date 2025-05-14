mod unit_tester;

use crate::{test_cmd_runner::EestTestCmdTrait, util::make_configuration};
pub use unit_tester::BlockchainUnitTester;

use cfx_config::Configuration;
use clap::Args;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// ethereum statetest doc: https://eest.ethereum.org/main/consuming_tests/state_test/
#[derive(Args, Debug, Clone)]
pub struct BlockchainTestCmd {
    /// Paths to blockchain test files or directories
    #[arg(required = true)]
    pub(super) paths: Vec<PathBuf>,

    /// Conflux client configuration
    #[arg(short, long, value_parser = make_configuration, default_value = "", help = "Path to the configuration file")]
    pub(super) config: Arc<Configuration>,

    /// Only run tests matching this string
    #[arg(short, long, value_name = "Matches")]
    pub(super) matches: Option<String>,
}

impl EestTestCmdTrait for BlockchainTestCmd {
    fn get_matches(&self) -> &Option<String> { &self.matches }

    fn get_paths(&self) -> &Vec<PathBuf> { &self.paths }

    fn get_config(&self) -> &Arc<Configuration> { &self.config }

    fn skip_test(&self, _path: &Path) -> bool { false }
}
