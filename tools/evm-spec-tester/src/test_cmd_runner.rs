use crate::{
    suite_tester::{SuiteTester, UnitTester},
    util::find_all_json_tests,
    TestError,
};

use cfx_config::Configuration;
use cfx_executor::machine::{Machine, VmFactory};
use itertools::Itertools;
use serde::de::DeserializeOwned;
use std::{
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};

pub trait EestTestCmdTrait {
    fn skip_test(&self, path: &Path) -> bool;

    fn get_paths(&self) -> &Vec<PathBuf>;

    fn get_config(&self) -> &Arc<Configuration>;

    fn get_matches(&self) -> &Option<String>;
}

pub struct EestTestCmdRunner<T, U, C> {
    _phantom_t: PhantomData<T>,
    _phantom_u: PhantomData<U>,
    _phantom_c: PhantomData<C>,
}

impl<T, U, C> EestTestCmdRunner<T, U, C>
where
    T: DeserializeOwned,
    U: UnitTester<TestUnit = T>,
    C: EestTestCmdTrait + Clone,
{
    /// Runs `statetest` command.
    pub fn run(cmd: C) -> bool {
        let mut success = true;
        for path in cmd.get_paths() {
            if !path.exists() {
                panic!("Path not exists: {:?}", path);
            }

            let test_files = find_all_json_tests(path);

            if test_files.is_empty() {
                error!("No fixtures found in directory: {:?}", path);
                continue;
            }

            match Self::run_file_tests(test_files, path, cmd.clone()) {
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
        test_files: Vec<PathBuf>, path: &PathBuf, cmd: C,
    ) -> Result<bool, String> {
        let mut success = true;
        info!(
            "Running {} TestSuites in {}",
            test_files.len(),
            path.display()
        );

        let machine = {
            let vm_factory = VmFactory::new(1024 * 32);
            Arc::new(Machine::new_with_builtin(
                cmd.get_config().common_params(),
                vm_factory,
            ))
        };

        let verification =
            cmd.get_config().verification_config(machine.clone());

        let mut skipped_suite = 0;
        let mut load_err_suite = 0;

        let mut success_units = 0;
        let mut skipped_units = 0;
        let mut total_executions = 0;

        let mut error_list = vec![];

        for path in test_files {
            if cmd.skip_test(&path) {
                skipped_suite += 1;
                continue;
            }

            let (success_cnt, skipped_cnt, transact_cnt, errors) =
                match SuiteTester::<T, U>::load(&path) {
                    Ok(tester) => tester.run(
                        &machine,
                        &verification,
                        cmd.get_matches().as_deref(),
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
        println!("Total Executions: {}\n", total_executions);

        Ok(success)
    }
}
