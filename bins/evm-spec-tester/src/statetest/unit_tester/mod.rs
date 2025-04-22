mod post_transact;
mod pre_transact;

use super::{
    error::{TestError, TestErrorKind},
    utils::extract_155_chain_id_from_raw_tx,
};
use cfx_executor::{
    executive::{
        gas_required_for, ExecutionOutcome, ExecutiveContext, TransactOptions,
        TxDropError,
    },
    machine::Machine,
    state::State,
};
use cfx_types::U256;
use cfx_vm_types::Env;
use primitives::{transaction::Action, SignedTransaction};
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
        &self, machine: &Machine, matches: Option<&str>,
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
            if spec_name != SpecName::Prague {
                continue;
            }

            // TODO Enable the appropriate Conflux CIPs based on the
            // spec_name.

            // running each test
            for single_test in tests.iter() {
                self.execute_single_test(single_test, machine)?;
                non_empty_unit = true;
            }
        }

        Ok(non_empty_unit)
    }

    fn execute_single_test(
        &self, test: &Test, machine: &Machine,
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

        // TODO: check logs hash is same

        Ok(())
    }

    fn transact(
        &self, machine: &Machine, env: &Env, state: &mut State,
        transaction: &SignedTransaction, options: TransactOptions<()>,
    ) -> ExecutionOutcome {
        let spec = machine.spec(env.number, env.epoch_height);

        // intrinsic gas check
        let tx_intrinsic_gas = gas_required_for(
            transaction.action() == Action::Create,
            &transaction.data(),
            transaction.access_list(),
            transaction.authorization_len(),
            &spec,
        );

        if transaction.gas_limit() < &U256::from(tx_intrinsic_gas) {
            return ExecutionOutcome::NotExecutedDrop(
                TxDropError::NotEnoughGasLimit {
                    expected: tx_intrinsic_gas.into(),
                    got: *transaction.gas_limit(),
                },
            );
        }

        // if transaction.gas_limit() <
        // &U256::from(eip7623_gas(&transaction.data())) {     return
        // ExecutionOutcome::NotExecutedDrop(
        //         TxDropError::NotEnoughGasLimit {
        //             expected: eip7623_gas(&transaction.data()).into(),
        //             got: *transaction.gas_limit(),
        //         },
        //     );
        // }

        let evm = ExecutiveContext::new(state, env, &machine, &spec);
        let outcome = evm.transact(transaction, options).expect("db error");
        state.update_state_post_tx_execution(false);
        outcome
    }
}
