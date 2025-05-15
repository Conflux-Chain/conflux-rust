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

    fn skip_test(&self, path: &Path) -> bool {
        let folder_to_skip = [
            "eip7002_el_triggerable_withdrawals", /* conflux do not support
                                                   * 7002 */
            "eip4788_beacon_root/beacon_root_contract",
            "eip4844_blobs",
        ];
        let path_str = path.to_str().unwrap();
        for folder in folder_to_skip {
            if path_str.contains(folder) {
                return true;
            }
        }

        let name_to_skip: Vec<&str> = vec![];
        let file_name = path.file_name().unwrap().to_str().unwrap();
        for name in name_to_skip {
            if name == file_name {
                return true;
            }
        }

        false
    }
}
