pub(crate) mod command;
mod error;
mod unit_tester;
mod utils;

pub use error::TestError;

use cfx_config::Configuration;
use eest_types::StateTestSuite;
use itertools::Itertools;
use std::{path::PathBuf, sync::Arc};

use crate::util::find_all_json_tests;
use command::StateTestCmd;
use unit_tester::UnitTester;
use utils::skip_test;

impl StateTestCmd {
    /// Runs `statetest` command.
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
        let mut success = true;
        info!(
            "Running {} TestSuites in {}",
            test_files.len(),
            path.display()
        );

        let mut skipped_suite = 0;
        let mut load_err_suite = 0;

        let mut success_units = 0;
        let mut skipped_units = 0;
        let mut total_executions = 0;

        let mut error_list = vec![];

        for path in test_files {
            if skip_test(&path) {
                skipped_suite += 1;
                continue;
            }

            let (success_cnt, skipped_cnt, transact_cnt, errors) =
                match SuiteTester::load(&path, self.config.clone()) {
                    Ok(tester) => tester.run(self.matches.as_deref()),
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
    suite: StateTestSuite,
    config: Arc<Configuration>,
}

impl SuiteTester {
    pub fn load(
        path: &PathBuf, config: Arc<Configuration>,
    ) -> Result<Self, String> {
        let s = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let suite: StateTestSuite =
            serde_json::from_str(&s).map_err(|e| e.to_string())?;

        let path = path.to_string_lossy().into_owned();
        Ok(Self {
            path,
            suite,
            config,
        })
    }

    fn run(
        self, matches: Option<&str>,
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
        for (name, unit) in self.suite.0 {
            let unit_tester =
                UnitTester::new(&self.path, name, unit, self.config.clone());
            match unit_tester.run(matches) {
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
