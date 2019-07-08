// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Transaction execution environment.
use super::executive::*;
use crate::{
    bytes::Bytes,
    machine::Machine,
    state::{CleanupMode, State, Substate},
    vm::{
        self, ActionParams, ActionValue, CallType, Context as ContextTrait,
        ContractCreateResult, CreateContractAddress, EnvInfo,
        MessageCallResult, ReturnData, Spec, TrapKind,
    },
};
use cfx_types::{Address, H256, U256};
use primitives::transaction::UNSIGNED_SENDER;
use std::sync::Arc;

/// Policy for handling output data on `RETURN` opcode.
pub enum OutputPolicy {
    /// Return reference to fixed sized output.
    /// Used for message calls.
    Return,
    /// Init new contract as soon as `RETURN` is called.
    InitContract,
}

/// Transaction properties that externalities need to know about.
pub struct OriginInfo {
    address: Address,
    origin: Address,
    gas_price: U256,
    value: U256,
}

impl OriginInfo {
    /// Populates origin info from action params.
    pub fn from(params: &ActionParams) -> Self {
        OriginInfo {
            address: params.address.clone(),
            origin: params.origin.clone(),
            gas_price: params.gas_price,
            value: match params.value {
                ActionValue::Transfer(val) | ActionValue::Apparent(val) => val,
            },
        }
    }
}

/// Implementation of evm context.
#[allow(dead_code)]
pub struct Context<'a, 'b: 'a> {
    state: &'a mut State<'b>,
    env: &'a EnvInfo,
    depth: usize,
    stack_depth: usize,
    origin: &'a OriginInfo,
    substate: &'a mut Substate,
    machine: &'a Machine,
    spec: &'a Spec,
    output: OutputPolicy,
    static_flag: bool,
}

impl<'a, 'b: 'a> Context<'a, 'b> {
    /// Basic `Context` constructor.
    pub fn new(
        state: &'a mut State<'b>, env: &'a EnvInfo, machine: &'a Machine,
        spec: &'a Spec, depth: usize, stack_depth: usize,
        origin: &'a OriginInfo, substate: &'a mut Substate,
        output: OutputPolicy, static_flag: bool,
    ) -> Self
    {
        Context {
            state,
            env,
            depth,
            stack_depth,
            origin,
            substate,
            machine,
            spec,
            output,
            static_flag,
        }
    }
}

impl<'a, 'b: 'a> ContextTrait for Context<'a, 'b> {
    fn initial_storage_at(&self, key: &H256) -> vm::Result<H256> {
        self.state
            .checkpoint_storage_at(0, &self.origin.address, key)
            .map(|v| v.unwrap_or(H256::zero()))
            .map_err(Into::into)
    }

    fn storage_at(&self, key: &H256) -> vm::Result<H256> {
        self.state
            .storage_at(&self.origin.address, key)
            .map_err(Into::into)
    }

    fn set_storage(&mut self, key: H256, value: H256) -> vm::Result<()> {
        if self.static_flag {
            Err(vm::Error::MutableCallInStaticContext)
        } else {
            self.state
                .set_storage(&self.origin.address, key, value)
                .map_err(Into::into)
        }
    }

    fn is_static(&self) -> bool { return self.static_flag; }

    fn exists(&self, address: &Address) -> vm::Result<bool> {
        self.state.exists(address).map_err(Into::into)
    }

    fn exists_and_not_null(&self, address: &Address) -> vm::Result<bool> {
        self.state.exists_and_not_null(address).map_err(Into::into)
    }

    fn origin_balance(&self) -> vm::Result<U256> {
        self.balance(&self.origin.address).map_err(Into::into)
    }

    fn balance(&self, address: &Address) -> vm::Result<U256> {
        self.state.balance(address).map_err(Into::into)
    }

    fn blockhash(&mut self, _number: &U256) -> H256 {
        // TODO: I have no idea why we need this function
        H256::default()
    }

    fn create(
        &mut self, gas: &U256, value: &U256, code: &[u8],
        address_scheme: CreateContractAddress, trap: bool,
    ) -> ::std::result::Result<ContractCreateResult, TrapKind>
    {
        assert!(trap);

        // create new contract address
        let (address, code_hash) = match self.state.nonce(&self.origin.address)
        {
            Ok(nonce) => self::contract_address(
                address_scheme,
                &self.origin.address,
                &nonce,
                &code,
            ),
            Err(e) => {
                debug!(target: "context", "Database corruption encountered: {:?}", e);
                return Ok(ContractCreateResult::Failed);
            }
        };

        // prepare the params
        let params = ActionParams {
            code_address: address.clone(),
            address: address.clone(),
            sender: self.origin.address.clone(),
            origin: self.origin.origin.clone(),
            gas: *gas,
            gas_price: self.origin.gas_price,
            value: ActionValue::Transfer(*value),
            code: Some(Arc::new(code.to_vec())),
            code_hash,
            data: None,
            call_type: CallType::None,
            params_type: vm::ParamsType::Embedded,
        };

        if !self.static_flag {
            if !self.spec.keep_unsigned_nonce
                || params.sender != UNSIGNED_SENDER
            {
                if let Err(e) = self.state.inc_nonce(&self.origin.address) {
                    debug!(target: "ext", "Database corruption encountered: {:?}", e);
                    return Ok(ContractCreateResult::Failed);
                }
            }
        }

        return Err(TrapKind::Create(params, address));
    }

    fn call(
        &mut self, gas: &U256, sender_address: &Address,
        receive_address: &Address, value: Option<U256>, data: &[u8],
        code_address: &Address, call_type: CallType, trap: bool,
    ) -> ::std::result::Result<MessageCallResult, TrapKind>
    {
        trace!(target: "context", "call");

        assert!(trap);

        let code_with_hash = self.state.code(code_address).and_then(|code| {
            self.state.code_hash(code_address).map(|hash| (code, hash))
        });

        let (code, code_hash) = match code_with_hash {
            Ok((code, hash)) => (code, hash),
            Err(_) => return Ok(MessageCallResult::Failed),
        };

        let mut params = ActionParams {
            sender: sender_address.clone(),
            address: receive_address.clone(),
            value: ActionValue::Apparent(self.origin.value),
            code_address: code_address.clone(),
            origin: self.origin.origin.clone(),
            gas: *gas,
            gas_price: self.origin.gas_price,
            code,
            code_hash,
            data: Some(data.to_vec()),
            call_type,
            params_type: vm::ParamsType::Separate,
        };

        if let Some(value) = value {
            params.value = ActionValue::Transfer(value);
        }

        return Err(TrapKind::Call(params));
    }

    fn extcode(&self, address: &Address) -> vm::Result<Option<Arc<Bytes>>> {
        Ok(self.state.code(address)?)
    }

    fn extcodehash(&self, address: &Address) -> vm::Result<Option<H256>> {
        Ok(self.state.code_hash(address)?)
    }

    fn extcodesize(&self, address: &Address) -> vm::Result<Option<usize>> {
        Ok(self.state.code_size(address)?)
    }

    fn ret(
        self, gas: &U256, data: &ReturnData, apply_state: bool,
    ) -> vm::Result<U256>
    where Self: Sized {
        match self.output {
            OutputPolicy::Return => Ok(*gas),
            OutputPolicy::InitContract if apply_state => {
                let return_cost = U256::from(data.len())
                    * U256::from(self.spec.create_data_gas);
                if return_cost > *gas
                    || data.len() > self.spec.create_data_limit
                {
                    return match self.spec.exceptional_failed_code_deposit {
                        true => Err(vm::Error::OutOfGas),
                        false => Ok(*gas),
                    };
                }
                self.state.init_code(&self.origin.address, data.to_vec())?;
                Ok(*gas - return_cost)
            }
            OutputPolicy::InitContract => Ok(*gas),
        }
    }

    fn log(&mut self, topics: Vec<H256>, data: &[u8]) -> vm::Result<()> {
        use primitives::log_entry::LogEntry;

        if self.static_flag {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        let address = self.origin.address.clone();
        self.substate.logs.push(LogEntry {
            address,
            topics,
            data: data.to_vec(),
        });

        Ok(())
    }

    fn suicide(&mut self, refund_address: &Address) -> vm::Result<()> {
        if self.static_flag {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        let address = self.origin.address.clone();
        let balance = self.balance(&address)?;
        if &address == refund_address {
            self.state.sub_balance(
                &address,
                &balance,
                &mut CleanupMode::NoEmpty,
            )?;
        } else {
            trace!(target: "context", "Suiciding {} -> {} (xfer: {})", address, refund_address, balance);
            self.state.transfer_balance(
                &address,
                refund_address,
                &balance,
                self.substate.to_cleanup_mode(&self.spec),
            )?;
        }

        self.substate.suicides.insert(address);

        Ok(())
    }

    fn spec(&self) -> &Spec { &self.spec }

    fn env_info(&self) -> &EnvInfo { &self.env }

    fn depth(&self) -> usize { self.depth }

    fn add_sstore_refund(&mut self, value: usize) {
        self.substate.sstore_clears_refund += value as i128;
    }

    fn sub_sstore_refund(&mut self, value: usize) {
        self.substate.sstore_clears_refund -= value as i128;
    }

    fn trace_next_instruction(
        &mut self, _pc: usize, _instruction: u8, _current_gas: U256,
    ) -> bool {
        // TODO
        false
    }

    fn trace_prepare_execute(
        &mut self, _pc: usize, _instruction: u8, _gas_cost: U256,
        _mem_written: Option<(usize, usize)>,
        _store_written: Option<(U256, U256)>,
    )
    {
        // TODO
    }

    fn trace_executed(
        &mut self, _gas_used: U256, _stack_push: &[U256], _mem: &[u8],
    ) {
        // TODO
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::{
        statedb::StateDb,
        storage::{
            new_storage_manager_for_testing, state::StateTrait, StorageManager,
            StorageManagerTrait,
        },
        test_helpers::get_state_for_genesis_write,
        vm::EnvInfo,
        vm_factory::VmFactory,
    };
    use cfx_types::{Address, U256};
    use std::ops::Deref;

    #[allow(dead_code)]
    fn get_test_origin() -> OriginInfo {
        OriginInfo {
            address: Address::zero(),
            origin: Address::zero(),
            gas_price: U256::zero(),
            value: U256::zero(),
        }
    }

    #[allow(dead_code)]
    fn get_test_env_info() -> EnvInfo {
        EnvInfo {
            number: 100,
            author: 0.into(),
            timestamp: 0,
            difficulty: 0.into(),
            last_hashes: Arc::new(vec![]),
            gas_used: 0.into(),
            gas_limit: 0.into(),
        }
    }

    struct TestSetup {
        storage_manager: Option<Box<StorageManager>>,
        state: Option<State<'static>>,
    }

    impl TestSetup {
        fn init_state(&mut self, storage_manager: &'static StorageManager) {
            self.state = Some(get_state_for_genesis_write(storage_manager));
        }

        fn new() -> Self {
            let storage_manager = Box::new(new_storage_manager_for_testing());

            let mut setup = Self {
                storage_manager: None,
                state: None,
            };
            setup.storage_manager = Some(storage_manager);
            setup.init_state(unsafe {
                &*(setup.storage_manager.as_ref().unwrap().as_ref()
                    as *const StorageManager)
            });

            setup
        }
    }

    #[test]
    fn can_be_created() { let _setup = TestSetup::new(); }
}
