// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
pub mod executed;
pub mod execution_outcome;
mod fresh_executive;
mod pre_checked_executive;
#[cfg(test)]
mod tests;
pub mod transact_options;

use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, AddressSpaceUtil, AddressWithSpace, Space, H256,
    U256,
};
use cfx_vm_types::{CreateContractAddress, Env, Spec};
use primitives::SignedTransaction;

use fresh_executive::FreshExecutive;
use pre_checked_executive::PreCheckedExecutive;

pub use executed::{revert_reason_decode, Executed};
pub use execution_outcome::{ExecutionError, ExecutionOutcome, TxDropError};
pub use transact_options::{
    ChargeCollateral, TransactOptions, TransactSettings,
};

use crate::{
    executive_observe::ExecutiveObserve, machine::Machine, state::State,
};

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

    pub fn transact<O: ExecutiveObserve>(
        self, tx: &SignedTransaction, options: TransactOptions<O>,
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

pub fn contract_address(
    address_scheme: CreateContractAddress, block_number: u64,
    sender: &AddressWithSpace, nonce: &U256, code: &[u8],
) -> (AddressWithSpace, Option<H256>)
{
    let (mut address, code_hash) = cfx_vm_types::contract_address(
        address_scheme,
        block_number,
        &sender.address,
        nonce,
        code,
    );
    if sender.space == Space::Native {
        address.set_contract_type_bits();
    }
    (address.with_space(sender.space), code_hash)
}

#[cfg(test)]
pub mod test_util {
    use crate::{
        executive_observe::TracerTrait, frame::accrue_substate, state::Substate,
    };
    use cfx_statedb::Result as DbResult;
    use cfx_vm_interpreter::FinalizationResult;
    use cfx_vm_types::{self as vm, ActionParams};

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
