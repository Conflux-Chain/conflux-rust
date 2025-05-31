#![allow(unused, dead_code)]

use crate::try_loaded;

use super::Context;
use alloy_type_conversions::*;
use cfx_statedb::Result as DbResult;
use cfx_types::AddressSpaceUtil;
use cfx_vm_types::{extract_7702_payload, Context as ContextTrait};
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
    fn basefee(&self) -> U256 {
        let basefee = self.context.env.base_gas_price[self.context.space];
        to_alloy_u256(basefee)
    }

    fn blob_gasprice(&self) -> U256 { todo!() }

    fn gas_limit(&self) -> U256 { to_alloy_u256(self.context.env.gas_limit) }

    fn difficulty(&self) -> U256 { to_alloy_u256(self.context.env.difficulty) }

    fn prevrandao(&self) -> Option<U256> { todo!() }

    fn block_number(&self) -> u64 { self.context.env.number }

    fn timestamp(&self) -> U256 {
        revm_primitives::U256::from(self.context.env.timestamp)
    }

    fn beneficiary(&self) -> Address {
        to_alloy_address(self.context.env.author)
    }

    fn chain_id(&self) -> U256 {
        revm_primitives::U256::from(self.context.chain_id())
    }

    fn effective_gas_price(&self) -> U256 { todo!() }

    fn caller(&self) -> Address {
        to_alloy_address(self.context.origin.address)
    }

    fn blob_hash(&self, number: usize) -> Option<U256> { todo!() }

    fn initcode_by_hash(&mut self, hash: B256) -> Option<Bytes> { todo!() }

    fn max_initcode_size(&self) -> usize {
        self.context.spec().init_code_data_limit
    }

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
        let address = from_alloy_address(address);

        let is_cold = !self.context.is_warm_account(address);

        let is_empty = match self
            .context
            .state
            .is_eip158_empty(&address.with_space(self.context.space))
        {
            Ok(is_empty) => is_empty,
            Err(e) => {
                self.error = Err(e);
                return None;
            }
        };

        let mut account_load = StateLoad::new(
            AccountLoad {
                is_delegate_account_cold: None,
                is_empty,
            },
            is_cold,
        );

        // Core space does not support-7702
        if self.context.space == cfx_types::Space::Native {
            return Some(account_load);
        }

        let account_code = match self
            .context
            .state
            .code(&address.with_space(self.context.space))
        {
            Ok(code) => code,
            Err(e) => {
                self.error = Err(e);
                return None;
            }
        };

        // check if the account is a 7702 account
        if let Some(address) = account_code
            .as_ref()
            .and_then(|x| extract_7702_payload(&**x))
        {
            let is_cold = !self.context.is_warm_account(address);
            account_load.is_delegate_account_cold = Some(is_cold);
        }

        Some(account_load)
    }

    fn load_account_code(
        &mut self, address: Address,
    ) -> Option<StateLoad<Bytes>> {
        match self.context.extcode(&from_alloy_address(address)) {
            Ok(code_option) => {
                let bytes = code_option
                    .map(|code| to_alloy_bytes(code.as_ref().clone()))
                    .unwrap_or_else(|| Bytes::default());
                let is_cold =
                    !self.context.is_warm_account(from_alloy_address(address));

                Some(StateLoad::new(bytes, is_cold))
            }
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                None
            }
        }
    }

    fn load_account_code_hash(
        &mut self, address: Address,
    ) -> Option<StateLoad<B256>> {
        match self.context.extcodehash(&from_alloy_address(address)) {
            Ok(hash) => {
                let is_cold =
                    !self.context.is_warm_account(from_alloy_address(address));

                Some(StateLoad::new(to_alloy_h256(hash), is_cold))
            }
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                None
            }
        }
    }
}
