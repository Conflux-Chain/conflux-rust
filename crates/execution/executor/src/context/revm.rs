#![allow(unused, dead_code)]

use super::Context;
use alloy_type_conversions::*;
use cfx_statedb::Result as DbResult;
use cfx_types::AddressSpaceUtil;
use cfx_vm_types::Context as ContextTrait;
use revm_context_interface::journaled_state::AccountLoad;
use revm_interpreter::{SStoreResult, SelfDestructResult, StateLoad};
use revm_primitives::{Address, Bytes, Log, B256, U256};

pub(crate) struct EvmHost<'a> {
    context: Context<'a>,
    error: DbResult<()>,
}

impl<'a> EvmHost<'a> {
    pub fn new(context: Context<'a>) -> Self {
        Self {
            context,
            error: Ok(()),
        }
    }

    pub fn take_db_error(&mut self) -> DbResult<()> {
        std::mem::replace(&mut self.error, Ok(()))
    }
}

fn unwrap_db_error(e: cfx_vm_types::Error) -> cfx_statedb::Error {
    match e {
        cfx_vm_types::Error::StateDbError(e) => e.0,
        _ => unreachable!(),
    }
}

const COLD: bool = true;

impl<'a> revm_interpreter::Host for EvmHost<'a> {
    fn basefee(&self) -> U256 { todo!() }

    fn blob_gasprice(&self) -> U256 { todo!() }

    fn gas_limit(&self) -> U256 { todo!() }

    fn difficulty(&self) -> U256 { todo!() }

    fn prevrandao(&self) -> Option<U256> { todo!() }

    fn block_number(&self) -> u64 { todo!() }

    fn timestamp(&self) -> U256 { todo!() }

    fn beneficiary(&self) -> Address { todo!() }

    fn chain_id(&self) -> U256 { todo!() }

    fn effective_gas_price(&self) -> U256 { todo!() }

    fn caller(&self) -> Address { todo!() }

    fn blob_hash(&self, number: usize) -> Option<U256> { todo!() }

    fn initcode_by_hash(&mut self, hash: B256) -> Option<Bytes> { todo!() }

    fn max_initcode_size(&self) -> usize { todo!() }

    fn block_hash(&mut self, number: u64) -> Option<B256> {
        match self.context.blockhash(&cfx_types::U256::from(number)) {
            Ok(hash) => Some(to_alloy_h256(hash)),
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                None
            }
        }
    }

    fn selfdestruct(
        &mut self, address: Address, target: Address,
    ) -> Option<StateLoad<SelfDestructResult>> {
        todo!()
    }

    fn log(&mut self, log: Log) { todo!() }

    fn sstore(
        &mut self, address: Address, key: U256, value: U256,
    ) -> Option<StateLoad<SStoreResult>> {
        todo!()
    }

    fn sload(
        &mut self, address: Address, key: U256,
    ) -> Option<StateLoad<U256>> {
        todo!()
    }

    fn tstore(&mut self, address: Address, key: U256, value: U256) { todo!() }

    fn tload(&mut self, address: Address, key: U256) -> U256 { todo!() }

    fn balance(&mut self, address: Address) -> Option<StateLoad<U256>> {
        match self.context.balance(&from_alloy_address(address)) {
            Ok(balance) => Some(StateLoad::new(to_alloy_u256(balance), COLD)),
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                None
            }
        }
    }

    fn load_account_delegated(
        &mut self, address: Address,
    ) -> Option<StateLoad<AccountLoad>> {
        todo!()
    }

    fn load_account_code(
        &mut self, address: Address,
    ) -> Option<StateLoad<Bytes>> {
        todo!()
    }

    fn load_account_code_hash(
        &mut self, address: Address,
    ) -> Option<StateLoad<B256>> {
        todo!()
    }
}
