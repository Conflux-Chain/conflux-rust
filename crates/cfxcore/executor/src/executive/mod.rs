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

use cfx_rpc_eth_types::BlockOverrides;
use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, AddressSpaceUtil, AddressWithSpace, Space,
    SpaceMap, H256, U256,
};
use cfx_vm_types::{ConsensusGasSpec, CreateContractAddress, Env, Spec};
use primitives::{AccessList, SignedTransaction};

use fresh_executive::FreshExecutive;
use pre_checked_executive::PreCheckedExecutive;

pub use executed::Executed;
pub use execution_outcome::{ExecutionError, ExecutionOutcome, TxDropError};
pub use transact_options::{
    ChargeCollateral, TransactOptions, TransactSettings,
};

use crate::{
    executive_observer::ExecutiveObserver, machine::Machine, state::State,
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
    ) -> Self {
        ExecutiveContext {
            state,
            env,
            machine,
            spec,
        }
    }

    #[inline(never)]
    pub fn transact<O: ExecutiveObserver>(
        self, tx: &SignedTransaction, options: TransactOptions<O>,
    ) -> DbResult<ExecutionOutcome> {
        // Transaction should execute on an empty cache
        assert!(self.state.cache.get_mut().is_empty());

        info!(
            "Execute_transaction {:?} (height {})",
            tx.hash, self.env.epoch_height
        );
        let fresh_exec = FreshExecutive::new(self, tx, options);

        let pre_checked_exec = match fresh_exec.check_all()? {
            Ok(executive) => executive,
            Err(execution_outcome) => {
                info!("Execute_transaction Not Execute.");
                return Ok(execution_outcome);
            }
        };

        let ans = pre_checked_exec.execute_transaction()?;
        info!("Execute_transaction Done.");
        if let Some(_executed) = ans.try_as_executed() {
            // info!("{:?}", executed);
        }
        Ok(ans)
    }

    pub fn apply_env_overrides(
        env: &mut Env, block_override: Box<BlockOverrides>,
    ) {
        if let Some(number) = block_override.number {
            env.number = number.as_u64();
        }
        if let Some(difficulty) = block_override.difficulty {
            env.difficulty = difficulty;
        }
        if let Some(timestamp) = block_override.time {
            env.timestamp = timestamp;
        }
        if let Some(gas_limit) = block_override.gas_limit {
            env.gas_limit = U256::from(gas_limit);
        }
        if let Some(author) = block_override.coinbase {
            env.author = author;
        }
        if let Some(_random) = block_override.random {
            // conflux doesn't have random(prevRandao)
        }
        if let Some(base_fee) = block_override.base_fee {
            env.base_gas_price = SpaceMap::new(base_fee, base_fee); // use same base_fee for both spaces
        }

        if let Some(_block_hash) = &block_override.block_hash {
            // TODO impl
        }
    }
}

#[inline]
pub fn gas_required_for(
    is_create: bool, data: &[u8], access_list: Option<&AccessList>,
    authorization_len: usize, spec: &ConsensusGasSpec,
) -> u64 {
    let init_gas = (if is_create {
        spec.tx_create_gas
    } else {
        spec.tx_gas
    }) as u64;

    let byte_gas = |b: &u8| {
        (match *b {
            0 => spec.tx_data_zero_gas,
            _ => spec.tx_data_non_zero_gas,
        }) as u64
    };
    let data_gas: u64 = data.iter().map(byte_gas).sum();
    let data_word = (data.len() as u64 + 31) / 32;

    // CIP-645i: EIP-3860: Limit and meter initcode
    let initcode_gas = if spec.cip645.eip3860 && is_create {
        data_word * spec.init_code_word_gas as u64
    } else {
        0
    };

    let access_gas: u64 = if let Some(acc) = access_list {
        let address_gas =
            acc.len() as u64 * spec.access_list_address_gas as u64;

        let storage_key_num =
            acc.iter().map(|e| e.storage_keys.len() as u64).sum::<u64>();
        let storage_key_gas =
            storage_key_num * spec.access_list_storage_key_gas as u64;

        address_gas + storage_key_gas
    } else {
        0
    };

    let authorization_gas = spec.per_empty_account_cost as u64
        * spec.evm_gas_ratio as u64
        * authorization_len as u64;

    init_gas + data_gas + access_gas + authorization_gas + initcode_gas
}

pub fn eip7623_required_gas(data: &[u8], spec: &ConsensusGasSpec) -> u64 {
    if !spec.eip7623 {
        return 0;
    }

    let byte_floor_gas = |b: &u8| {
        (match *b {
            0 => spec.tx_data_floor_zero_gas,
            _ => spec.tx_data_floor_non_zero_gas,
        }) as u64
    };

    spec.tx_gas as u64 + data.iter().map(byte_floor_gas).sum::<u64>()
}

pub fn contract_address(
    address_scheme: CreateContractAddress, block_number: u64,
    sender: &AddressWithSpace, nonce: &U256, code: &[u8],
) -> (AddressWithSpace, H256) {
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
        executive_observer::TracerTrait, stack::accrue_substate,
        substate::Substate,
    };
    use cfx_statedb::Result as DbResult;
    use cfx_vm_interpreter::FinalizationResult;
    use cfx_vm_types::{self as vm, ActionParams};

    use super::{pre_checked_executive::exec_vm, ExecutiveContext};

    impl<'a> ExecutiveContext<'a> {
        pub fn call_for_test(
            &mut self, params: ActionParams, substate: &mut Substate,
            tracer: &mut dyn TracerTrait,
        ) -> DbResult<vm::Result<FinalizationResult>> {
            let mut frame_result = exec_vm(self, params, tracer)?;
            accrue_substate(substate, &mut frame_result);

            Ok(frame_result.map(Into::into))
        }
    }
}
