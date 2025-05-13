use crate::util::{find_all_json_tests, make_configuration};
use cfx_config::Configuration;
use clap::Args;
use std::{path::PathBuf, sync::Arc};

/// ethereum statetest doc: https://eest.ethereum.org/main/consuming_tests/state_test/
#[derive(Args, Debug)]
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

impl BlockchainTestCmd {
    pub fn run(&self) -> bool {
        for path in &self.paths {
            if !path.exists() {
                panic!("Path not exists: {:?}", path);
            }

            let test_files = find_all_json_tests(path);

            if test_files.is_empty() {
                error!("No fixtures found in directory: {:?}", path);
                continue;
            }

            if let Err(_) = self.run_file_tests(test_files, path) {
                warn!("Failed to run tests in directory: {:?}", path);
                continue;
            }
        }

        true
    }

    fn run_file_tests(
        &self, test_files: Vec<PathBuf>, path: &PathBuf,
    ) -> Result<(), String> {
        info!(
            "Running {} TestSuites in {}",
            test_files.len(),
            path.display()
        );

        Ok(())
    }
}
