mod unit_tester;
mod util;

use crate::{
    util::{find_all_json_tests, make_configuration},
    TestError,
};
use cfx_config::Configuration;
use cfx_executor::machine::{Machine, VmFactory};
use cfxcore::verification::VerificationConfig;
use clap::Args;
use eest_types::BlockchainTestSuite;
use itertools::Itertools;
use std::{path::PathBuf, sync::Arc};
use unit_tester::UnitTester;

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
        let mut success = true;
        for path in &self.paths {
            if !path.exists() {
                panic!("Path not exists: {:?}", path);
            }

            let test_files = find_all_json_tests(path);

            if test_files.is_empty() {
                error!("No fixtures found in directory: {:?}", path);
                continue;
            }

            match self.run_file_tests(test_files, path) {
                Ok(true) => {}
                Ok(false) => {
                    success = false;
                }
                Err(_) => {
                    success = false;
                    warn!("Failed to run tests in directory: {:?}", path);
                    continue;
                }
            }
        }

        success
    }

    fn run_file_tests(
        &self, test_files: Vec<PathBuf>, path: &PathBuf,
    ) -> Result<bool, String> {
        info!(
            "Running {} BlockTestSuites in {}",
            test_files.len(),
            path.display()
        );

        let mut success = true;
        let machine = {
            let vm_factory = VmFactory::new(1024 * 32);
            Arc::new(Machine::new_with_builtin(
                self.config.common_params(),
                vm_factory,
            ))
        };

        let verification = self.config.verification_config(machine.clone());

        let mut skipped_suite = 0;
        let mut load_err_suite = 0;

        let mut success_units = 0;
        let mut skipped_units = 0;
        let mut total_executions = 0;

        let mut error_list = vec![];

        for path in test_files {
            // currently, no skip
            if false {
                skipped_suite += 1;
                continue;
            }

            let (success_cnt, skipped_cnt, transact_cnt, errors) =
                match SuiteTester::load(&path) {
                    Ok(tester) => tester.run(
                        &machine,
                        &verification,
                        self.matches.as_deref(),
                    ),
                    Err(err_msg) => {
                        warn!(
                            "TestSuite load failed. path: {:?}, error: {}",
                            path, err_msg
                        );
                        success = false;
                        load_err_suite += 1;
                        continue;
                    }
                };

            success_units += success_cnt;
            skipped_units += skipped_cnt;
            total_executions += transact_cnt;

            error_list.extend(errors);
        }

        let error_units = error_list.len();

        for (path, units) in
            &error_list.into_iter().chunk_by(|err| err.path.clone())
        {
            success = false;
            println!("\nPath {path} fails:");
            for TestError { name, kind, .. } in units {
                println!("\t{name}: {kind}");
            }
        }

        println!("\n\nSkipped TestSuites: {}", skipped_suite);
        println!("Load Failed TestSuites: {}", load_err_suite);
        println!("Success Units: {}", success_units);
        println!("Skipped Units: {}", skipped_units);
        println!("Error Units  : {}", error_units);
        println!("Total Executions: {}", total_executions);

        Ok(success)
    }
}

struct SuiteTester {
    path: String,
    suite: BlockchainTestSuite,
}

impl SuiteTester {
    pub fn load(path: &PathBuf) -> Result<Self, String> {
        let s = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let suite: BlockchainTestSuite =
            serde_json::from_str(&s).map_err(|e| e.to_string())?;

        let path = path.to_string_lossy().into_owned();
        Ok(Self { path, suite })
    }

    fn run(
        self, machine: &Machine, verification: &VerificationConfig,
        matches: Option<&str>,
    ) -> (usize, usize, usize, Vec<TestError>) {
        if matches.is_some() {
            trace!("Running TestUnit: {}", self.path);
        } else {
            debug!("Running TestUnit: {}", self.path);
        }

        let mut error_list = vec![];
        let mut success_cnt = 0;
        let mut skipped_cnt = 0;
        let mut transact_cnt = 0;

        for (name, test) in self.suite.0 {
            let unit_tester = UnitTester::new(&self.path, name, test);
            match unit_tester.run(&machine, verification, matches) {
                Ok(cnt) => {
                    transact_cnt += cnt;
                    if cnt > 0 {
                        success_cnt += 1;
                    } else {
                        skipped_cnt += 1;
                    }
                }
                Err(e) => error_list.push(e),
            }
        }

        (success_cnt, skipped_cnt, transact_cnt, error_list)
    }
}
