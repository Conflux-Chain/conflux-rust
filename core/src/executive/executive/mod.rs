// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
pub mod estimation;
pub mod executed;
pub mod execution_outcome;
mod fresh_executive;
mod pre_checked_executive;

use estimation::TransactOptions;
use executed::Executed;
use execution_outcome::ExecutionError;
use fresh_executive::FreshExecutive;
use pre_checked_executive::PreCheckedExecutive;

pub use execution_outcome::ExecutionOutcome;
pub use pre_checked_executive::contract_address;

use crate::{
    machine::Machine,
    state::State,
    vm::{Env, Spec},
};

use cfx_statedb::Result as DbResult;

use primitives::SignedTransaction;

/// Transaction executor.
pub struct ExecutiveContext<'a> {
    state: &'a mut State,
    env: &'a Env,
    machine: &'a Machine,
    spec: &'a Spec,
}

impl<'a> ExecutiveContext<'a> {
    pub fn new(
        state: &'a mut State, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec,
    ) -> Self
    {
        ExecutiveContext {
            state,
            env,
            machine,
            spec,
        }
    }

    pub fn transact(
        self, tx: &SignedTransaction, options: TransactOptions,
    ) -> DbResult<ExecutionOutcome> {
        let fresh_exec = FreshExecutive::new(self, tx, options);

        let pre_checked_exec = match fresh_exec.check_all()? {
            Ok(executive) => executive,
            Err(execution_outcome) => return Ok(execution_outcome),
        };

        pre_checked_exec.execute_transaction()
    }
}

pub fn gas_required_for(is_create: bool, data: &[u8], spec: &Spec) -> u64 {
    data.iter().fold(
        (if is_create {
            spec.tx_create_gas
        } else {
            spec.tx_gas
        }) as u64,
        |g, b| {
            g + (match *b {
                0 => spec.tx_data_zero_gas,
                _ => spec.tx_data_non_zero_gas,
            }) as u64
        },
    )
}

#[cfg(test)]
pub mod test_util {
    use crate::{
        evm::FinalizationResult,
        executive::frame::accrue_substate,
        observer::TracerTrait,
        state::Substate,
        vm::{self, ActionParams},
    };
    use cfx_statedb::Result as DbResult;

    use super::{pre_checked_executive::exec_vm, ExecutiveContext};

    impl<'a> ExecutiveContext<'a> {
        pub fn call_for_test(
            &mut self, params: ActionParams, substate: &mut Substate,
            tracer: &mut dyn TracerTrait,
        ) -> DbResult<vm::Result<FinalizationResult>>
        {
            let mut frame_result = exec_vm(self, params, tracer)?;
            accrue_substate(substate, &mut frame_result);

            Ok(frame_result.map(Into::into))
        }
    }
}
