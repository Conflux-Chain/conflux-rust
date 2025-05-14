mod unit_tester;

use cfx_config::Configuration;
use clap::Args;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    test_cmd_runner::EestTestCmdTrait,
    util::{contains_meta_dir, make_configuration},
};
pub use unit_tester::StateUnitTester;

/// ethereum statetest doc: https://eest.ethereum.org/main/consuming_tests/state_test/
#[derive(Args, Debug, Clone)]
pub struct StateTestCmd {
    /// Paths to state test files or directories
    #[arg(required = true)]
    pub(super) paths: Vec<PathBuf>,

    /// Conflux client configuration
    #[arg(short, long, value_parser = make_configuration, default_value = "", help = "Path to the configuration file")]
    pub(super) config: Arc<Configuration>,

    /// Only run tests matching this string
    #[arg(short, long, value_name = "Matches")]
    pub(super) matches: Option<String>,
}

impl EestTestCmdTrait for StateTestCmd {
    fn get_matches(&self) -> &Option<String> { &self.matches }

    fn get_paths(&self) -> &Vec<PathBuf> { &self.paths }

    fn get_config(&self) -> &Arc<Configuration> { &self.config }

    fn skip_test(&self, path: &Path) -> bool {
        if contains_meta_dir(path) {
            return true;
        }

        let name = path.file_name().unwrap().to_str().unwrap();

        matches!(
            name,
            // Tests not valid at Prague
            "intrinsicCancun.json"

        // Unreasonable test cases and also skipped by revm (fails in revm)
        | "RevertInCreateInInitCreate2Paris.json"
        | "create2collisionStorageParis.json"
        | "dynamicAccountOverwriteEmpty_Paris.json"
        | "InitCollisionParis.json"
        | "RevertInCreateInInit_Paris.json"

        // ## These tests are passing, but they take a lot of time to execute so we are going to skip them.
        // | "loopExp.json"
        // | "Call50000_sha256.json"
        // | "static_Call50000_sha256.json"
        | "loopMul.json"
        | "CALLBlake2f_MaxRounds.json"
        )
    }
}
