mod post_transact;
mod pre_transact;

use post_transact::is_unsupport_reason;
pub use post_transact::{match_fail_single_reason, TestOutcome};

use crate::{
    suite_tester::UnitTester,
    util::{
        extract_155_chain_id_from_raw_tx, make_state, make_transact_options,
    },
    TestError, TestErrorKind,
};
use cfx_executor::{
    executive::{ExecutionOutcome, ExecutiveContext, TransactOptions},
    machine::Machine,
    state::State,
};
use cfx_vm_types::Env;
use cfxcore::verification::VerificationConfig;
use eest_types::{SpecId, SpecName, StateTest, StateTestUnit};
use primitives::SignedTransaction;

pub struct StateUnitTester {
    path: String,
    name: String,
    unit: StateTestUnit,
}

impl StateUnitTester {
    fn err(&self, kind: TestErrorKind) -> TestError {
        TestError {
            name: self.name.clone(),
            path: self.path.clone(),
            kind,
        }
    }

    fn execute_single_test(
        &self, test: &StateTest, machine: &Machine,
        verification: &VerificationConfig,
    ) -> Result<(), TestError> {
        let mut state = make_state(&self.unit.pre);

        let Some(tx) = pre_transact::make_tx(
            &self.unit.transaction,
            &test.indexes,
            self.unit.config.chainid,
            extract_155_chain_id_from_raw_tx(&test.txbytes).is_none(),
        ) else {
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

        if let Err(e) =
            pre_transact::check_tx_common(machine, &env, &tx, verification)
        {
            return post_transact::process_consensus_check_fail(
                e,
                test.expect_exception.as_ref(),
            )
            .map_err(|kind| self.err(kind));
        }

        let transact_options = make_transact_options(true);

        let outcome =
            self.transact(machine, &env, &mut state, &tx, transact_options);

        let maybe_executed = post_transact::extract_executed(
            outcome,
            test.expect_exception.as_ref(),
        )
        .map_err(|kind| self.err(kind))?;

        if let Some(ref executed) = maybe_executed {
            post_transact::distribute_tx_fee_to_miner(
                &mut state,
                &executed,
                &env.author,
            );
        }

        let gas_used = maybe_executed
            .as_ref()
            .map(|e| e.gas_used)
            .unwrap_or_default();
        post_transact::check_execution_outcome(
            &tx,
            &state,
            &self.unit,
            &test.state,
            gas_used,
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

impl UnitTester for StateUnitTester {
    type TestUnit = StateTestUnit;

    fn new(path: &String, name: String, unit: Self::TestUnit) -> Self {
        StateUnitTester {
            path: path.clone(),
            name,
            unit,
        }
    }

    fn run(
        &self, machine: &Machine, verification: &VerificationConfig,
        matches: Option<&str>,
    ) -> Result<usize, TestError> {
        if !matches.map_or(true, |pat| {
            format!("{}::{}", &self.path, &self.name).contains(pat)
        }) {
            return Ok(0);
        }

        if matches.is_some() {
            info!("Running TestUnit: {}", self.name);
        } else {
            trace!("Running TestUnit: {}", self.name);
        }

        let Some((spec, tests)) = pick_spec(self.unit.post.iter()) else {
            return Ok(0);
        };

        let mut transact_cnt = 0;
        // running each test
        for single_test in tests.iter() {
            if is_unsupport_reason(&single_test.expect_exception) {
                continue;
            }
            if matches.is_some() {
                info!("Running item with spec {:?}", spec);
            }
            self.execute_single_test(single_test, machine, verification)?;
            transact_cnt += 1;
        }

        Ok(transact_cnt)
    }
}

fn pick_spec<'a, T>(
    specs: impl Iterator<Item = (&'a SpecName, &'a T)>,
) -> Option<(&'a SpecName, &'a T)> {
    specs
        .filter_map(|spec| {
            let spec_id = spec.0.to_spec_id();
            if spec_id <= SpecId::PRAGUE {
                Some((spec, spec_id))
            } else {
                None
            }
        })
        .fold(None, |acc, (spec, spec_id)| match acc {
            Some((_, old_spec_id)) if spec_id > old_spec_id => {
                Some((spec, spec_id))
            }
            Some((old_spec, old_spec_id)) if spec_id == old_spec_id => {
                warn!(
                    "Duplicate spec with the same id: {:?} {:?}",
                    old_spec.0, spec.0
                );
                acc
            }
            Some(_) => acc,
            None => Some((spec, spec_id)),
        })
        .map(|(spec, _)| spec)
}
