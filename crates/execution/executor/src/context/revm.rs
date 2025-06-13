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
        revm_primitives::U256::from(
            self.context.env.chain_id[&self.context.space],
        )
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
        let address = from_alloy_address(address);
        let target_address = from_alloy_address(target);
        let is_cold = !self.context.is_warm_account(target_address);

        let is_empty = match self
            .context
            .state
            .is_eip158_empty(&target_address.with_evm_space())
        {
            Ok(exists) => exists,
            Err(e) => {
                self.error = Err(e);
                return None;
            }
        };

        let contract_address_with_space =
            self.context.origin.address.with_space(self.context.space);

        let balance =
            match self.context.state.balance(&contract_address_with_space) {
                Ok(balance) => balance,
                Err(e) => {
                    self.error = Err(e);
                    return None;
                }
            };

        let previously_destroyed = self
            .context
            .substate
            .suicides
            .contains(&address.with_space(self.context.space));

        if let Err(e) = self.context.suicide(&target_address) {
            self.error = Err(unwrap_db_error(e));
            return None;
        }

        Some(StateLoad {
            data: SelfDestructResult {
                had_value: !balance.is_zero(),
                target_exists: !is_empty,
                previously_destroyed,
            },
            is_cold,
        })
    }

    fn log(&mut self, log: Log) {
        let data_topics = log.data.topics();
        let mut topics = Vec::with_capacity(data_topics.len());

        topics.extend(data_topics.iter().map(|topic| from_alloy_h256(*topic)));

        let data = log.data.data;
        self.context.log(topics, &data);
    }

    fn sstore(
        &mut self, address: Address, key: U256, value: U256,
    ) -> Option<StateLoad<SStoreResult>> {
        let value_cfx_u256 = from_alloy_u256(value);

        let present = self.sload(address, key)?;

        if self.error.is_err() {
            return None;
        }

        let key_bytes: [u8; 32] = key.to_be_bytes();

        let original_value = match self.context.origin_storage_at(&key_bytes) {
            Ok(Some(original_value)) => to_alloy_u256(original_value),
            Ok(None) => U256::ZERO,
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                return None;
            }
        };

        let sstore_result = SStoreResult {
            original_value,
            present_value: present.data,
            new_value: value,
        };

        if present.data == value {
            return Some(StateLoad::new(sstore_result, present.is_cold));
        };

        if let Err(e) =
            self.context.set_storage(key_bytes.to_vec(), value_cfx_u256)
        {
            self.error = Err(unwrap_db_error(e));
            return None;
        }

        Some(StateLoad::new(sstore_result, present.is_cold))
    }

    fn sload(
        &mut self, address: Address, key: U256,
    ) -> Option<StateLoad<U256>> {
        let key_bytes = key.to_be_bytes();

        let key_h256 = cfx_types::H256::from(key_bytes);

        let is_cold = match self.context.is_warm_storage_entry(&key_h256) {
            Ok(is_warm) => !is_warm,
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                return None;
            }
        };

        let value = match self.context.storage_at(&key_bytes) {
            Ok(current_value) => to_alloy_u256(current_value),
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                return None;
            }
        };

        Some(StateLoad::new(value, is_cold))
    }

    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        let key = key.to_be_bytes_vec();
        let value = from_alloy_u256(value);

        self.context
            .transient_set_storage(key, value)
            .map_err(|e| {
                self.error = Err(unwrap_db_error(e));
            })
            .ok();
    }

    fn tload(&mut self, address: Address, key: U256) -> U256 {
        let key = key.to_be_bytes_vec();
        match self.context.transient_storage_at(&key) {
            Ok(value) => to_alloy_u256(value),
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                U256::ZERO
            }
        }
    }

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
        let address = from_alloy_address(address);
        let is_cold = !self.context.is_warm_account(address);

        match self.context.extcode(&address) {
            Ok(code_option) => {
                let bytes = code_option
                    .map(|code| to_alloy_bytes(code.as_ref().clone()))
                    .unwrap_or_else(|| Bytes::default());
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
        let address = from_alloy_address(address);
        let is_cold = !self.context.is_warm_account(address);
        match self.context.extcodehash(&address) {
            Ok(hash) => Some(StateLoad::new(to_alloy_h256(hash), is_cold)),
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                None
            }
        }
    }
}
