// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Transaction execution environment.
use super::{executive::*, suicide as suicide_impl, InternalContractMap};
use crate::{
    bytes::Bytes,
    machine::Machine,
    state::{State, Substate},
    trace,
    vm::{
        self, ActionParams, ActionValue, CallType, Context as ContextTrait,
        ContractCreateResult, CreateContractAddress, Env, MessageCallResult,
        ReturnData, Spec, TrapKind,
    },
};
use cfx_parameters::staking::{
    code_collateral_units, DRIPS_PER_STORAGE_COLLATERAL_UNIT,
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
#[derive(Debug)]
pub struct OriginInfo {
    address: Address,
    /// This is the address of original sender of the transaction.
    original_sender: Address,
    /// This is the address of account who will pay collateral for storage in
    /// the whole execution.
    storage_owner: Address,
    /// The upper bound of `collateral_for_storage` for `original_sender`
    storage_limit_in_drip: U256,
    gas_price: U256,
    value: U256,
}

impl OriginInfo {
    /// Populates origin info from action params.
    pub fn from(params: &ActionParams) -> Self {
        OriginInfo {
            address: params.address,
            original_sender: params.original_sender,
            storage_owner: params.storage_owner,
            storage_limit_in_drip: params.storage_limit_in_drip,
            gas_price: params.gas_price,
            value: match params.value {
                ActionValue::Transfer(val) | ActionValue::Apparent(val) => val,
            },
        }
    }

    pub fn recipient(&self) -> &Address { &self.address }
}

/// Implementation of evm context.
#[allow(dead_code)]
pub struct Context<'a> {
    state: &'a mut State,
    env: &'a Env,
    depth: usize,
    // The stack_depth is never read in context, even before this commit.
    stack_depth: usize,
    origin: &'a OriginInfo,
    substate: &'a mut Substate,
    machine: &'a Machine,
    spec: &'a Spec,
    output: OutputPolicy,
    static_flag: bool,
    internal_contract_map: &'a InternalContractMap,
}

impl<'a> Context<'a> {
    /// Basic `Context` constructor.
    pub fn new(
        state: &'a mut State, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, depth: usize, stack_depth: usize,
        origin: &'a OriginInfo, substate: &'a mut Substate,
        output: OutputPolicy, static_flag: bool,
        internal_contract_map: &'a InternalContractMap,
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
            internal_contract_map,
        }
    }
}

impl<'a> ContextTrait for Context<'a> {
    fn storage_at(&self, key: &Vec<u8>) -> vm::Result<U256> {
        self.substate
            .storage_at(self.state, &self.origin.address, key)
            .map_err(Into::into)
    }

    fn set_storage(&mut self, key: Vec<u8>, value: U256) -> vm::Result<()> {
        if self.is_static_or_reentrancy() {
            Err(vm::Error::MutableCallInStaticContext)
        } else {
            self.substate
                .set_storage(
                    self.state,
                    &self.origin.address,
                    key,
                    value,
                    self.origin.storage_owner,
                )
                .map_err(Into::into)
        }
    }

    fn is_static_or_reentrancy(&self) -> bool {
        self.static_flag
            || self
                .substate
                .contracts_in_callstack
                .borrow()
                .in_reentrancy()
    }

    fn is_static(&self) -> bool { self.static_flag }

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

    fn blockhash(&mut self, number: &U256) -> H256 {
        // In Conflux, we only maintain the block hash of the previous block.
        // For other block numbers, it always returns zero.
        if U256::from(self.env().number) == number + 1 {
            self.env().last_hash.clone()
        } else {
            H256::default()
        }
    }

    fn create(
        &mut self, gas: &U256, value: &U256, code: &[u8],
        address_scheme: CreateContractAddress, trap: bool,
    ) -> cfx_statedb::Result<
        ::std::result::Result<ContractCreateResult, TrapKind>,
    >
    {
        // create new contract address
        let (address, code_hash) = self::contract_address(
            address_scheme,
            self.env.number.into(),
            &self.origin.address,
            &self.state.nonce(&self.origin.address)?,
            &code,
        );

        // For a contract address already with code, we do not allow overlap the
        // address. This should generally not happen. Unless we enable
        // account dust in future. We add this check just in case it
        // helps in future.
        if self.state.is_contract_with_code(&address) {
            debug!("Contract address conflict!");
            return Ok(Ok(ContractCreateResult::Failed));
        }

        // prepare the params
        let params = ActionParams {
            code_address: address.clone(),
            address: address.clone(),
            sender: self.origin.address.clone(),
            original_sender: self.origin.original_sender,
            storage_owner: self.origin.storage_owner,
            storage_limit_in_drip: self.origin.storage_limit_in_drip,
            gas: *gas,
            gas_price: self.origin.gas_price,
            value: ActionValue::Transfer(*value),
            code: Some(Arc::new(code.to_vec())),
            code_hash,
            data: None,
            call_type: CallType::None,
            params_type: vm::ParamsType::Embedded,
        };

        if !self.is_static_or_reentrancy() {
            if !self.spec.keep_unsigned_nonce
                || params.sender != UNSIGNED_SENDER
            {
                self.state.inc_nonce(&self.origin.address)?;
            }
        }

        if trap {
            return Ok(Err(TrapKind::Create(params, address)));
        }

        // The following code is only reachable in test mode.
        let mut ex = Executive::from_parent(
            self.state,
            self.env,
            self.machine,
            self.spec,
            self.depth,
            self.static_flag,
            self.internal_contract_map,
        );
        let mut tracer = trace::NoopTracer;
        let out = ex.create_with_stack_depth(
            params,
            self.substate,
            self.stack_depth + 1,
            &mut tracer,
        );
        Ok(Ok(into_contract_create_result(
            out,
            &address,
            self.substate,
        )))
    }

    fn call(
        &mut self, gas: &U256, sender_address: &Address,
        receive_address: &Address, value: Option<U256>, data: &[u8],
        code_address: &Address, call_type: CallType, trap: bool,
    ) -> cfx_statedb::Result<::std::result::Result<MessageCallResult, TrapKind>>
    {
        trace!(target: "context", "call");

        assert!(trap);

        let (code, code_hash) = if let Some(contract) =
            self.internal_contract_map.contract(code_address)
        {
            (Some(contract.code()), Some(contract.code_hash()))
        } else {
            (
                self.state.code(code_address)?,
                self.state.code_hash(code_address)?,
            )
        };

        let mut params = ActionParams {
            sender: *sender_address,
            address: *receive_address,
            value: ActionValue::Apparent(self.origin.value),
            code_address: *code_address,
            original_sender: self.origin.original_sender,
            storage_owner: self.origin.storage_owner,
            storage_limit_in_drip: self.origin.storage_limit_in_drip,
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

        return Ok(Err(TrapKind::Call(params)));
    }

    fn extcode(&self, address: &Address) -> vm::Result<Option<Arc<Bytes>>> {
        if let Some(contract) = self.internal_contract_map.contract(address) {
            Ok(Some(contract.code()))
        } else {
            Ok(self.state.code(address)?)
        }
    }

    fn extcodehash(&self, address: &Address) -> vm::Result<Option<H256>> {
        if let Some(contract) = self.internal_contract_map.contract(address) {
            Ok(Some(contract.code_hash()))
        } else {
            Ok(self.state.code_hash(address)?)
        }
    }

    fn extcodesize(&self, address: &Address) -> vm::Result<Option<usize>> {
        if let Some(contract) = self.internal_contract_map.contract(address) {
            Ok(Some(contract.code_size()))
        } else {
            Ok(self.state.code_size(address)?)
        }
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
                let collateral_units_for_code =
                    code_collateral_units(data.len());
                let collateral_in_drips = U256::from(collateral_units_for_code)
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
                debug!("ret()  collateral_for_code={:?}", collateral_in_drips);
                self.substate.record_storage_occupy(
                    &self.origin.storage_owner,
                    collateral_units_for_code,
                );

                self.state.init_code(
                    &self.origin.address,
                    data.to_vec(),
                    self.origin.storage_owner,
                )?;

                Ok(*gas - return_cost)
            }
            OutputPolicy::InitContract => Ok(*gas),
        }
    }

    fn log(&mut self, topics: Vec<H256>, data: &[u8]) -> vm::Result<()> {
        use primitives::log_entry::LogEntry;

        if self.is_static_or_reentrancy() {
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
        if self.is_static_or_reentrancy() {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        suicide_impl(
            &self.origin.address,
            refund_address,
            &mut self.state,
            &self.spec,
            &mut self.substate,
        )
    }

    fn spec(&self) -> &Spec { &self.spec }

    fn env(&self) -> &Env { &self.env }

    fn chain_id(&self) -> u64 {
        self.machine
            .params()
            .chain_id
            .read()
            .get_chain_id(self.env.epoch_height) as u64
    }

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

    fn is_reentrancy(&self, _caller: &Address, callee: &Address) -> bool {
        self.substate
            .contracts_in_callstack
            .borrow()
            .reentrancy_happens_when_push(callee)
    }
}

#[cfg(test)]
mod tests {
    use super::{Context, InternalContractMap, OriginInfo, OutputPolicy};
    use crate::{
        machine::{new_machine_with_builtin, Machine},
        state::{State, Substate},
        test_helpers::get_state_for_genesis_write,
        vm::{
            CallType, Context as ContextTrait, ContractCreateResult,
            CreateContractAddress, Env, Spec,
        },
    };
    use cfx_parameters::consensus::TRANSACTION_DEFAULT_EPOCH_BOUND;
    use cfx_storage::{
        new_storage_manager_for_testing, tests::FakeStateManager,
    };
    use cfx_types::{address_util::AddressUtil, Address, H256, U256};
    use std::str::FromStr;

    fn get_test_origin() -> OriginInfo {
        let mut sender = Address::zero();
        sender.set_user_account_type_bits();
        OriginInfo {
            address: sender,
            original_sender: sender,
            storage_owner: Address::zero(),
            gas_price: U256::zero(),
            value: U256::zero(),
            storage_limit_in_drip: U256::MAX,
        }
    }

    fn get_test_env() -> Env {
        Env {
            number: 100,
            author: Address::from_low_u64_be(0),
            timestamp: 0,
            difficulty: 0.into(),
            last_hash: H256::zero(),
            accumulated_gas_used: 0.into(),
            gas_limit: 0.into(),
            epoch_height: 0,
            transaction_epoch_bound: TRANSACTION_DEFAULT_EPOCH_BOUND,
        }
    }

    // storage_manager is apparently unused but it must be held to keep the
    // database directory.
    #[allow(unused)]
    struct TestSetup {
        storage_manager: FakeStateManager,
        state: State,
        machine: Machine,
        internal_contract_map: InternalContractMap,
        spec: Spec,
        substate: Substate,
        env: Env,
    }

    impl TestSetup {
        fn new() -> Self {
            let storage_manager = new_storage_manager_for_testing();
            let state = get_state_for_genesis_write(&*storage_manager);
            let machine = new_machine_with_builtin(Default::default());
            let env = get_test_env();
            let spec = machine.spec(env.number);
            let internal_contract_map = InternalContractMap::new();

            let mut setup = Self {
                storage_manager,
                state,
                machine,
                internal_contract_map,
                spec,
                substate: Substate::new(),
                env,
            };
            setup
                .state
                .init_code(&Address::zero(), vec![], Address::zero())
                .ok();

            setup
        }
    }

    #[test]
    fn can_be_created() {
        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let origin = get_test_origin();

        let ctx = Context::new(
            state,
            &setup.env,
            &setup.machine,
            &setup.spec,
            0, /* depth */
            0, /* stack_depth */
            &origin,
            &mut setup.substate,
            OutputPolicy::InitContract,
            false, /* static_flag */
            &setup.internal_contract_map,
        );

        assert_eq!(ctx.env().number, 100);
    }

    #[test]
    fn can_return_block_hash_no_env() {
        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let origin = get_test_origin();

        let mut ctx = Context::new(
            state,
            &setup.env,
            &setup.machine,
            &setup.spec,
            0, /* depth */
            0, /* stack_depth */
            &origin,
            &mut setup.substate,
            OutputPolicy::InitContract,
            false, /* static_flag */
            &setup.internal_contract_map,
        );

        let hash = ctx.blockhash(
            &"0000000000000000000000000000000000000000000000000000000000120000"
                .parse::<U256>()
                .unwrap(),
        );

        assert_eq!(hash, H256::zero());
    }

    //    #[test]
    //    fn can_return_block_hash() {
    //        let test_hash = H256::from(
    //
    // "afafafafafafafafafafafbcbcbcbcbcbcbcbcbcbeeeeeeeeeeeeedddddddddd",
    //        );
    //        let test_env_number = 0x120001;
    //
    //        let mut setup = TestSetup::new();
    //        {
    //            let env = &mut setup.env;
    //            env.number = test_env_number;
    //            let mut last_hashes = (*env.last_hashes).clone();
    //            last_hashes.push(test_hash.clone());
    //            env.last_hashes = Arc::new(last_hashes);
    //        }
    //        let state = &mut setup.state;
    //        let origin = get_test_origin();
    //
    //        let mut ctx = Context::new(
    //            state,
    //            &setup.env,
    //            &setup.machine,
    //            &setup.spec,
    //            0,
    //            0,
    //            &origin,
    //            &mut setup.substate,
    //            OutputPolicy::InitContract,
    //            false,
    //        );
    //
    //        let hash = ctx.blockhash(
    //
    // &"0000000000000000000000000000000000000000000000000000000000120000"
    //                .parse::<U256>()
    //                .unwrap(),
    //        );
    //
    //        assert_eq!(test_hash, hash);
    //    }

    #[test]
    #[should_panic]
    fn can_call_fail_empty() {
        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let origin = get_test_origin();

        let mut ctx = Context::new(
            state,
            &setup.env,
            &setup.machine,
            &setup.spec,
            0, /* depth */
            0, /* stack_depth */
            &origin,
            &mut setup.substate,
            OutputPolicy::InitContract,
            false, /* static_flag */
            &setup.internal_contract_map,
        );

        // this should panic because we have no balance on any account
        ctx.call(
        &"0000000000000000000000000000000000000000000000000000000000120000"
            .parse::<U256>()
            .unwrap(),
        &Address::zero(),
        &Address::zero(),
        Some(
            "0000000000000000000000000000000000000000000000000000000000150000"
                .parse::<U256>()
                .unwrap(),
        ),
        &[],
        &Address::zero(),
        CallType::Call,
        false,
    )
            .unwrap()
    .ok()
    .unwrap();
    }

    #[test]
    fn can_log() {
        let log_data = vec![120u8, 110u8];
        let log_topics = vec![H256::from_str(
            "af0fa234a6af46afa23faf23bcbc1c1cb4bcb7bcbe7e7e7ee3ee2edddddddddd",
        )
        .unwrap()];

        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let origin = get_test_origin();

        {
            let mut ctx = Context::new(
                state,
                &setup.env,
                &setup.machine,
                &setup.spec,
                0, /* depth */
                0, /* stack_depth */
                &origin,
                &mut setup.substate,
                OutputPolicy::InitContract,
                false, /* static_flag */
                &setup.internal_contract_map,
            );
            ctx.log(log_topics, &log_data).unwrap();
        }

        assert_eq!(setup.substate.logs.len(), 1);
    }

    #[test]
    fn can_suicide() {
        let mut refund_account = Address::zero();
        refund_account.set_user_account_type_bits();

        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let mut origin = get_test_origin();

        let mut contract_address = Address::zero();
        contract_address.set_contract_type_bits();
        origin.address = contract_address;
        state
            .new_contract(&contract_address, U256::zero(), U256::one())
            .expect(&concat!(file!(), ":", line!(), ":", column!()));
        state
            .init_code(
                &contract_address,
                // Use empty code in test because we don't have storage
                // collateral balance.
                "".into(),
                contract_address,
            )
            .expect(&concat!(file!(), ":", line!(), ":", column!()));

        {
            let mut ctx = Context::new(
                state,
                &setup.env,
                &setup.machine,
                &setup.spec,
                0, /* depth */
                0, /* stack_depth */
                &origin,
                &mut setup.substate,
                OutputPolicy::InitContract,
                false, /* static_flag */
                &setup.internal_contract_map,
            );
            ctx.suicide(&refund_account).unwrap();
        }

        assert_eq!(setup.substate.suicides.len(), 1);
    }

    #[test]
    fn can_create() {
        use std::str::FromStr;

        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let origin = get_test_origin();

        let address = {
            let mut ctx = Context::new(
                state,
                &setup.env,
                &setup.machine,
                &setup.spec,
                0, /* depth */
                0, /* stack_depth */
                &origin,
                &mut setup.substate,
                OutputPolicy::InitContract,
                false, /* static_flag */
                &setup.internal_contract_map,
            );
            match ctx
                .create(
                    &U256::max_value(),
                    &U256::zero(),
                    &[],
                    CreateContractAddress::FromSenderNonceAndCodeHash,
                    false,
                )
                .expect("no db error")
            {
                Ok(ContractCreateResult::Created(address, _)) => address,
                _ => panic!(
                    "Test create failed; expected Created, got Failed/Reverted"
                ),
            }
        };

        assert_eq!(
            address,
            Address::from_str("81dc73d9d80f5312901eb62cc4a3ed6ea4ca14e2")
                .unwrap()
        );
    }

    #[test]
    fn can_create2() {
        use std::str::FromStr;

        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let origin = get_test_origin();

        let address = {
            let mut ctx = Context::new(
                state,
                &setup.env,
                &setup.machine,
                &setup.spec,
                0, /* depth */
                0, /* stack_depth */
                &origin,
                &mut setup.substate,
                OutputPolicy::InitContract,
                false, /* static_flag */
                &setup.internal_contract_map,
            );

            match ctx
                .create(
                    &U256::max_value(),
                    &U256::zero(),
                    &[],
                    CreateContractAddress::FromSenderSaltAndCodeHash(
                        H256::default(),
                    ),
                    false,
                )
                .expect("no db error")
            {
                Ok(ContractCreateResult::Created(address, _)) => address,
                _ => panic!(
                "Test create failed; expected Created, got Failed/Reverted."
            ),
            }
        };

        assert_eq!(
            address,
            Address::from_str("84c100a15081f02b9efae8267a69f73bf15e75fa")
                .unwrap()
        );
    }

}
