use crate::TestError;
use cfx_executor::machine::Machine;
use cfxcore::verification::VerificationConfig;
use serde::{de::DeserializeOwned, Deserialize};
use std::{collections::BTreeMap, marker::PhantomData, path::PathBuf};

pub trait UnitTester {
    type TestUnit;

    fn new(path: &String, name: String, unit: Self::TestUnit) -> Self;

    fn run(
        &self, machine: &Machine, verification: &VerificationConfig,
        matches: Option<&str>,
    ) -> Result<usize, TestError>;
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct TestSuite<T>(pub BTreeMap<String, T>);

pub struct SuiteTester<T, U> {
    path: String,
    suite: TestSuite<T>,
    _marker: PhantomData<U>,
}

impl<T, U> SuiteTester<T, U>
where
    T: DeserializeOwned,
    U: UnitTester<TestUnit = T>,
{
    pub fn load(path: &PathBuf) -> Result<Self, String> {
        let s = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let suite: TestSuite<T> =
            serde_json::from_str(&s).map_err(|e| e.to_string())?;

        let path = path.to_string_lossy().into_owned();
        Ok(Self {
            path,
            suite,
            _marker: PhantomData,
        })
    }

    pub fn run(
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
        for (name, unit) in self.suite.0 {
            let unit_tester = U::new(&self.path, name, unit);
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
