mod post_transact;
mod pre_transact;

use super::{
    error::{TestError, TestErrorKind},
    utils::extract_155_chain_id_from_raw_tx,
};
use cfx_executor::{
    executive::{ExecutionOutcome, ExecutiveContext, TransactOptions},
    machine::Machine,
    state::State,
};
use cfx_vm_types::Env;
use cfxcore::verification::VerificationConfig;
use primitives::SignedTransaction;
use statetest_types::{SpecName, Test, TestUnit};

pub struct UnitTester {
    path: String,
    name: String,
    unit: TestUnit,
}

impl UnitTester {
    pub fn new(path: &String, name: String, unit: TestUnit) -> Self {
        UnitTester {
            path: path.clone(),
            name,
            unit,
        }
    }

    fn err(&self, kind: TestErrorKind) -> TestError {
        TestError {
            name: self.name.clone(),
            path: self.path.clone(),
            kind,
        }
    }

    pub fn run(
        &self, machine: &Machine, verification: &VerificationConfig,
        matches: Option<&str>, target_fork: Option<&str>,
    ) -> Result<bool, TestError> {
        if !matches.map_or(true, |pat| {
            format!("{}::{}", &self.path, &self.name).contains(pat)
        }) {
            return Ok(false);
        }

        if matches.is_some() {
            info!("Running TestUnit: {}", self.name);
        } else {
            trace!("Running TestUnit: {}", self.name);
        }

        let mut non_empty_unit = false;

        // running each spec's tests
        for (&spec_name, tests) in &self.unit.post {
            // Constantinople was immediately extended by Petersburg.
            // There isn't any production Constantinople transaction
            // so we don't support it and skip right to Petersburg.
            if spec_name == SpecName::Constantinople {
                continue;
            }

            if let Some(target_fork_str) = target_fork {
                if format!("{:?}", spec_name) != target_fork_str {
                    continue;
                }
            }

            // running each test
            for single_test in tests.iter() {
                self.execute_single_test(single_test, machine, verification)?;
                non_empty_unit = true;
            }
        }

        Ok(non_empty_unit)
    }

    fn execute_single_test(
        &self, test: &Test, machine: &Machine,
        verification: &VerificationConfig,
    ) -> Result<(), TestError> {
        let mut state = pre_transact::make_state(&self.unit.pre);

        let Some(tx) = pre_transact::make_tx(
            &self.unit.transaction,
            &test.indexes,
            self.unit.config.chainid,
            extract_155_chain_id_from_raw_tx(&test.txbytes).is_none(),
        ) else {
            // if self.unit.transaction.tx_type(test.indexes.data).is_none() {
            //     trace!(
            //         "\tSkipping test because of unkonwn tx type: {}",
            //         self.name.clone()
            //     );
            // }
            return Ok(());
        };

        pre_transact::check_tx_bytes(
            test.txbytes.as_ref().map(|x| &x.0[..]),
            &tx,
        )
        .map_err(|kind| self.err(kind))?;

        let env = pre_transact::make_block_env(
            machine,
            &self.unit.env,
            self.unit.config.chainid,
            tx.hash(),
        );

        let check_res =
            pre_transact::check_tx_common(machine, &env, &tx, verification);

        let check_pass = post_transact::match_common_check_error(
            check_res,
            test.expect_exception.as_ref(),
        )
        .map_err(|kind| self.err(kind))?;
        if !check_pass {
            return Ok(());
        }

        let transact_options = pre_transact::make_transact_options(true);

        let outcome =
            self.transact(machine, &env, &mut state, &tx, transact_options);

        let Some(executed) = post_transact::extract_executed(
            outcome,
            test.expect_exception.as_ref(),
        )
        .map_err(|kind| self.err(kind))?
        else {
            // TODO: error matched
            return Ok(());
        };

        post_transact::check_execution_outcome(
            &tx,
            &executed,
            &state,
            &self.unit,
            &test.state,
        )
        .map_err(|kind| self.err(kind))?;

        Ok(())
    }

    fn transact(
        &self, machine: &Machine, env: &Env, state: &mut State,
        transaction: &SignedTransaction, options: TransactOptions<()>,
    ) -> ExecutionOutcome {
        let spec = machine.spec(env.number, env.epoch_height);

        let evm = ExecutiveContext::new(state, env, &machine, &spec);
        let outcome = evm.transact(transaction, options).expect("db error");
        state.update_state_post_tx_execution(false);
        outcome
    }
}
