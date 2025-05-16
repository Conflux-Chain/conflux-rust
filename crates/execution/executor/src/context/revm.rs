#![allow(unused, dead_code)]

use super::Context;
use alloy_type_conversions::*;
use cfx_statedb::Result as DbResult;
use cfx_types::AddressSpaceUtil;
use cfx_vm_types::Context as ContextTrait;
use revm_interpreter::primitives::{Address, Bytes, Env, Log, B256, U256};

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
    fn env(&self) -> &Env { todo!() }

    fn env_mut(&mut self) -> &mut Env { todo!() }

    fn load_account(
        &mut self, address: Address,
    ) -> Option<revm_interpreter::LoadAccountResult> {
        match self
            .context
            .exists_and_not_null(&from_alloy_address(address))
        {
            Ok(exists) => Some(revm_interpreter::LoadAccountResult {
                is_cold: COLD,
                is_empty: !exists,
            }),
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                None
            }
        }
    }

    fn block_hash(&mut self, number: U256) -> Option<B256> {
        match self.context.blockhash(&from_alloy_u256(number)) {
            Ok(hash) => Some(to_alloy_h256(hash)),
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                None
            }
        }
    }

    fn balance(&mut self, address: Address) -> Option<(U256, bool)> {
        match self.context.balance(&from_alloy_address(address)) {
            Ok(balance) => Some((to_alloy_u256(balance), COLD)),
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                None
            }
        }
    }

    fn code(&mut self, address: Address) -> Option<(Bytes, bool)> {
        match self.context.extcode(&from_alloy_address(address)) {
            Ok(None) => Some((Bytes::new(), COLD)),
            Ok(Some(code)) => Some((Bytes::copy_from_slice(&**code), COLD)),
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                None
            }
        }
    }

    fn code_hash(&mut self, address: Address) -> Option<(B256, bool)> {
        match self.context.extcodehash(&from_alloy_address(address)) {
            Ok(hash) => Some((to_alloy_h256(hash), COLD)),
            Err(e) => {
                self.error = Err(unwrap_db_error(e));
                None
            }
        }
    }

    fn sload(&mut self, address: Address, index: U256) -> Option<(U256, bool)> {
        let receiver =
            from_alloy_address(address).with_space(self.context.space);
        let key = index.to_be_bytes::<32>();
        match self.context.state.storage_at(&receiver, &key) {
            Ok(value) => Some((to_alloy_u256(value), COLD)),
            Err(e) => {
                self.error = Err(e);
                None
            }
        }
    }

    fn sstore(
        &mut self, address: Address, index: U256, value: U256,
    ) -> Option<revm_interpreter::SStoreResult> {
        // TODO: who checks static flag in revm?
        todo!()
    }

    fn tload(&mut self, address: Address, index: U256) -> U256 { todo!() }

    fn tstore(&mut self, address: Address, index: U256, value: U256) { todo!() }

    fn log(&mut self, log: Log) { todo!() }

    fn selfdestruct(
        &mut self, address: Address, target: Address,
    ) -> Option<revm_interpreter::SelfDestructResult> {
        todo!()
    }
}
