// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Transaction execution environment.
use crate::{
    executive::contract_address,
    executive_observer::TracerTrait,
    internal_contract::{
        block_hash_slot, epoch_hash_slot, suicide as suicide_impl,
        InternalRefContext,
    },
    machine::Machine,
    return_if,
    stack::{CallStackInfo, FrameLocal, RuntimeRes},
    state::State,
    substate::Substate,
};
use cfx_bytes::Bytes;
use cfx_parameters::staking::{
    code_collateral_units, DRIPS_PER_STORAGE_COLLATERAL_UNIT,
};
use cfx_types::{
    Address, AddressSpaceUtil, AddressWithSpace, BigEndianHash, Space, H256,
    U256,
};
use cfx_vm_types::{
    self as vm, ActionParams, ActionValue, CallType, Context as ContextTrait,
    ContractCreateResult, CreateContractAddress, CreateType, Env, Error,
    MessageCallResult, ReturnData, Spec, TrapKind,
};
use primitives::transaction::UNSIGNED_SENDER;
use std::sync::Arc;
use vm::BlockHashSource;

/// Transaction properties that externalities need to know about.
#[derive(Debug)]
pub struct OriginInfo {
    address: Address,
    /// This is the address of original sender of the transaction.
    original_sender: Address,
    /// This is the address of account who will pay collateral for storage in
    /// the whole execution.
    storage_owner: Address,
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
            gas_price: params.gas_price,
            value: match params.value {
                ActionValue::Transfer(val) | ActionValue::Apparent(val) => val,
            },
        }
    }

    pub fn recipient(&self) -> &Address { &self.address }
}

pub struct Context<'a> {
    space: Space,
    env: &'a Env,
    depth: usize,
    create_address: &'a Option<Address>,
    origin: &'a OriginInfo,
    substate: &'a mut Substate,
    machine: &'a Machine,
    spec: &'a Spec,
    static_flag: bool,

    state: &'a mut State,
    callstack: &'a mut CallStackInfo,
    tracer: &'a mut dyn TracerTrait,
}

impl<'a> Context<'a> {
    pub fn new<'b, 'c>(
        frame_local: &'a mut FrameLocal<'b>,
        runtime_resources: &'a mut RuntimeRes<'c>,
    ) -> Self {
        let space = frame_local.space;
        let env = &frame_local.env;
        let depth = frame_local.depth;
        let create_address = &frame_local.create_address;
        let origin = &frame_local.origin;
        let substate = &mut frame_local.substate;
        let machine = frame_local.machine;
        let spec = frame_local.spec;
        let static_flag = frame_local.static_flag;

        let state = &mut *runtime_resources.state;
        let callstack = &mut *runtime_resources.callstack;
        let tracer = &mut *runtime_resources.tracer;
        Context {
            space,
            env,
            depth,
            create_address,
            origin,
            substate,
            machine,
            spec,
            static_flag,
            state,
            callstack,
            tracer,
        }
    }

    fn blockhash_from_env(&self, number: &U256) -> H256 {
        if self.space == Space::Ethereum && self.spec.cip98 {
            return if U256::from(self.env().epoch_height) == number + 1 {
                self.env().last_hash.clone()
            } else {
                H256::default()
            };
        }

        // In Conflux, we only maintain the block hash of the previous block.
        // For other block numbers, it always returns zero.
        if U256::from(self.env().number) == number + 1 {
            self.env().last_hash.clone()
        } else {
            H256::default()
        }
    }

    fn blockhash_from_state(&self, number: &U256) -> vm::Result<H256> {
        return_if!(number > &U256::from(u64::MAX));

        let number = number.as_u64();

        let state_res = match self.space {
            Space::Native => {
                return_if!(number < self.spec.cip133_b);
                return_if!(number > self.env.number);
                return_if!(number
                    .checked_add(65536)
                    .map_or(false, |n| n <= self.env.number));
                self.state.get_system_storage(&block_hash_slot(number))?
            }
            Space::Ethereum => {
                return_if!(number < self.spec.cip133_e);
                return_if!(number > self.env.epoch_height);
                return_if!(number
                    .checked_add(65536)
                    .map_or(false, |n| n <= self.env.epoch_height));
                self.state.get_system_storage(&epoch_hash_slot(number))?
            }
        };

        Ok(BigEndianHash::from_uint(&state_res))
    }
}

impl<'a> ContextTrait for Context<'a> {
    fn storage_at(&self, key: &Vec<u8>) -> vm::Result<U256> {
        let receiver = AddressWithSpace {
            address: self.origin.address,
            space: self.space,
        };
        self.state.storage_at(&receiver, key).map_err(Into::into)
    }

    fn set_storage(&mut self, key: Vec<u8>, value: U256) -> vm::Result<()> {
        let receiver = AddressWithSpace {
            address: self.origin.address,
            space: self.space,
        };
        if self.is_static_or_reentrancy() {
            Err(vm::Error::MutableCallInStaticContext)
        } else {
            self.state
                .set_storage(
                    &receiver,
                    key,
                    value,
                    self.origin.storage_owner,
                    &mut self.substate,
                )
                .map_err(Into::into)
        }
    }

    fn transient_storage_at(&self, key: &Vec<u8>) -> vm::Result<U256> {
        let receiver = AddressWithSpace {
            address: self.origin.address,
            space: self.space,
        };
        self.state
            .transient_storage_at(&receiver, key)
            .map_err(Into::into)
    }

    fn transient_set_storage(
        &mut self, key: Vec<u8>, value: U256,
    ) -> vm::Result<()> {
        let receiver = AddressWithSpace {
            address: self.origin.address,
            space: self.space,
        };
        if self.is_static_or_reentrancy() {
            Err(vm::Error::MutableCallInStaticContext)
        } else {
            self.state
                .transient_set_storage(&receiver, key, value)
                .map_err(Into::into)
        }
    }

    fn exists(&self, address: &Address) -> vm::Result<bool> {
        let address = AddressWithSpace {
            address: *address,
            space: self.space,
        };
        self.state.exists(&address).map_err(Into::into)
    }

    fn exists_and_not_null(&self, address: &Address) -> vm::Result<bool> {
        let address = AddressWithSpace {
            address: *address,
            space: self.space,
        };
        self.state.exists_and_not_null(&address).map_err(Into::into)
    }

    fn origin_balance(&self) -> vm::Result<U256> {
        self.balance(&self.origin.address).map_err(Into::into)
    }

    fn balance(&self, address: &Address) -> vm::Result<U256> {
        let address = AddressWithSpace {
            address: *address,
            space: self.space,
        };
        self.state.balance(&address).map_err(Into::into)
    }

    fn blockhash(&mut self, number: &U256) -> vm::Result<H256> {
        match self.blockhash_source() {
            BlockHashSource::Env => Ok(self.blockhash_from_env(number)),
            BlockHashSource::State => self.blockhash_from_state(number),
        }
    }

    fn create(
        &mut self, gas: &U256, value: &U256, code: &[u8],
        address_scheme: CreateContractAddress,
    ) -> cfx_statedb::Result<
        ::std::result::Result<ContractCreateResult, TrapKind>,
    > {
        let caller = AddressWithSpace {
            address: self.origin.address,
            space: self.space,
        };

        let create_type = CreateType::from_address_scheme(&address_scheme);
        // create new contract address
        let (address_with_space, code_hash) = self::contract_address(
            address_scheme,
            self.env.number.into(),
            &caller,
            &self.state.nonce(&caller)?,
            &code,
        );

        let address = address_with_space.address;

        // For a contract address already with code, we do not allow overlap the
        // address. This should generally not happen. Unless we enable
        // account dust in future. We add this check just in case it
        // helps in future.
        if self.space == Space::Native
            && self.state.is_contract_with_code(&address_with_space)?
        {
            debug!("Contract address conflict!");
            let err = Error::ConflictAddress(address.clone());
            return Ok(Ok(ContractCreateResult::Failed(err)));
        }

        // prepare the params
        let params = ActionParams {
            space: self.space,
            code_address: address.clone(),
            address: address.clone(),
            sender: self.origin.address.clone(),
            original_sender: self.origin.original_sender,
            storage_owner: self.origin.storage_owner,
            gas: *gas,
            gas_price: self.origin.gas_price,
            value: ActionValue::Transfer(*value),
            code: Some(Arc::new(code.to_vec())),
            code_hash,
            data: None,
            call_type: CallType::None,
            create_type,
            params_type: vm::ParamsType::Embedded,
        };

        if !self.is_static_or_reentrancy() {
            if !self.spec.keep_unsigned_nonce
                || params.sender != UNSIGNED_SENDER
            {
                self.state.inc_nonce(&caller)?;
            }
        }

        return Ok(Err(TrapKind::Create(params)));
    }

    fn call(
        &mut self, gas: &U256, sender_address: &Address,
        receive_address: &Address, value: Option<U256>, data: &[u8],
        code_address: &Address, call_type: CallType,
    ) -> cfx_statedb::Result<::std::result::Result<MessageCallResult, TrapKind>>
    {
        trace!(target: "context", "call");

        let code_address_with_space = code_address.with_space(self.space);

        let (code, code_hash) = if let Some(contract) = self
            .machine
            .internal_contracts()
            .contract(&code_address_with_space, self.spec)
        {
            (Some(contract.code()), contract.code_hash())
        } else {
            (
                self.state.code(&code_address_with_space)?,
                self.state.code_hash(&code_address_with_space)?,
            )
        };

        let mut params = ActionParams {
            space: self.space,
            sender: *sender_address,
            address: *receive_address,
            value: ActionValue::Apparent(self.origin.value),
            code_address: *code_address,
            original_sender: self.origin.original_sender,
            storage_owner: self.origin.storage_owner,
            gas: *gas,
            gas_price: self.origin.gas_price,
            code,
            code_hash,
            data: Some(data.to_vec()),
            call_type,
            create_type: CreateType::None,
            params_type: vm::ParamsType::Separate,
        };

        if let Some(value) = value {
            params.value = ActionValue::Transfer(value);
        }

        return Ok(Err(TrapKind::Call(params)));
    }

    fn extcode(&self, address: &Address) -> vm::Result<Option<Arc<Bytes>>> {
        let address = address.with_space(self.space);
        if let Some(contract) = self
            .machine
            .internal_contracts()
            .contract(&address, self.spec)
        {
            Ok(Some(contract.code()))
        } else {
            Ok(self.state.code(&address)?)
        }
    }

    fn extcodehash(&self, address: &Address) -> vm::Result<H256> {
        let address = address.with_space(self.space);

        if let Some(contract) = self
            .machine
            .internal_contracts()
            .contract(&address, self.spec)
        {
            Ok(contract.code_hash())
        } else {
            Ok(self.state.code_hash(&address)?)
        }
    }

    fn extcodesize(&self, address: &Address) -> vm::Result<usize> {
        let address = address.with_space(self.space);

        if let Some(contract) = self
            .machine
            .internal_contracts()
            .contract(&address, self.spec)
        {
            Ok(contract.code_size())
        } else {
            Ok(self.state.code_size(&address)?)
        }
    }

    fn log(&mut self, topics: Vec<H256>, data: &[u8]) -> vm::Result<()> {
        use primitives::log_entry::LogEntry;

        if self.is_static_or_reentrancy() {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        self.tracer.log(&self.origin.address, &topics, data);

        let address = self.origin.address.clone();
        self.substate.logs.push(LogEntry {
            address,
            topics,
            data: data.to_vec(),
            space: self.space,
        });

        Ok(())
    }

    fn ret(
        mut self, gas: &U256, data: &ReturnData, apply_state: bool,
    ) -> vm::Result<U256>
    where Self: Sized {
        let caller = self.origin.address.with_space(self.space);

        if self.create_address.is_none() || !apply_state {
            return Ok(*gas);
        }

        self.insert_create_address_to_substate();

        let create_data_gas = self.spec.create_data_gas
            * match self.space {
                Space::Native => 1,
                Space::Ethereum => self.spec.evm_gas_ratio,
            };
        let return_cost = U256::from(data.len()) * create_data_gas;
        if return_cost > *gas || data.len() > self.spec.create_data_limit {
            return match self.spec.exceptional_failed_code_deposit {
                true => Err(vm::Error::OutOfGas),
                false => Ok(*gas),
            };
        }

        if self.space == Space::Native {
            let collateral_units_for_code = code_collateral_units(data.len());
            let collateral_in_drips = U256::from(collateral_units_for_code)
                * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
            debug!("ret()  collateral_for_code={:?}", collateral_in_drips);
            self.substate.record_storage_occupy(
                &self.origin.storage_owner,
                collateral_units_for_code,
            );
        }

        let owner = if self.space == Space::Native {
            self.origin.storage_owner
        } else {
            Address::zero()
        };

        self.state.init_code(&caller, data.to_vec(), owner)?;
        Ok(*gas - return_cost)
    }

    fn suicide(&mut self, refund_address: &Address) -> vm::Result<()> {
        if self.is_static_or_reentrancy() {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        let contract_address = self.origin.address;
        let contract_address_with_space =
            self.origin.address.with_space(self.space);
        let balance = self.state.balance(&contract_address_with_space)?;
        self.tracer
            .selfdestruct(&contract_address, refund_address, balance);

        suicide_impl(
            &contract_address_with_space,
            &refund_address.with_space(self.space),
            self.state,
            &self.spec,
            &mut self.substate,
            self.tracer,
        )
    }

    fn spec(&self) -> &Spec { &self.spec }

    fn env(&self) -> &Env { &self.env }

    fn space(&self) -> Space { self.space }

    fn chain_id(&self) -> u64 { self.env.chain_id[&self.space] as u64 }

    fn depth(&self) -> usize { self.depth }

    // fn trace_next_instruction(
    //     &mut self, _pc: usize, _instruction: u8, _current_gas: U256,
    // ) -> bool {
    //     // TODO
    //     false
    // }

    // fn trace_prepare_execute(
    //     &mut self, _pc: usize, _instruction: u8, _gas_cost: U256,
    //     _mem_written: Option<(usize, usize)>,
    //     _store_written: Option<(U256, U256)>,
    // ) {
    //     // TODO
    // }

    // fn trace_executed(
    //     &mut self, _gas_used: U256, _stack_push: &[U256], _mem: &[u8],
    // ) {
    //     // TODO
    // }

    fn trace_step(&mut self, interpreter: &dyn vm::InterpreterInfo) {
        self.tracer.step(interpreter);
    }

    fn trace_step_end(&mut self, interpreter: &dyn vm::InterpreterInfo) {
        self.tracer.step_end(interpreter);
    }

    fn opcode_trace_enabled(&self) -> bool {
        let mut enabled = false;
        self.tracer.do_trace_opcode(&mut enabled);
        enabled
    }

    fn is_static(&self) -> bool { self.static_flag }

    fn is_static_or_reentrancy(&self) -> bool {
        self.static_flag || self.callstack.in_reentrancy(self.spec)
    }

    fn blockhash_source(&self) -> vm::BlockHashSource {
        let from_state = match self.space {
            Space::Native => self.env.number >= self.spec.cip133_b,
            Space::Ethereum => self.env.epoch_height >= self.spec.cip133_e,
        };
        if from_state {
            BlockHashSource::State
        } else {
            BlockHashSource::Env
        }
    }
}

impl<'a> Context<'a> {
    pub fn internal_ref(&mut self) -> InternalRefContext {
        InternalRefContext {
            env: self.env,
            spec: self.spec,
            callstack: self.callstack,
            state: self.state,
            substate: &mut self.substate,
            static_flag: self.static_flag,
            depth: self.depth,
            tracer: self.tracer,
        }
    }

    pub fn insert_create_address_to_substate(&mut self) {
        if let Some(create_address) = self.create_address {
            self.substate
                .contracts_created
                .push(create_address.with_space(self.space));
        }
    }
}

/// TODO: Move this code to a seperated file. So we can distinguish function
/// calls from test.
#[cfg(test)]
mod tests {
    use super::{FrameLocal, OriginInfo};
    use crate::{
        machine::Machine,
        stack::{CallStackInfo, OwnedRuntimeRes},
        state::{get_state_for_genesis_write, State},
        substate::Substate,
    };
    use cfx_parameters::consensus::TRANSACTION_DEFAULT_EPOCH_BOUND;
    use cfx_types::{
        address_util::AddressUtil, Address, AddressSpaceUtil, Space, H256, U256,
    };
    use cfx_vm_types::{Context as ContextTrait, Env, Spec};
    use std::{collections::BTreeMap, str::FromStr};

    fn get_test_origin() -> OriginInfo {
        let mut sender = Address::zero();
        sender.set_user_account_type_bits();
        OriginInfo {
            address: sender,
            original_sender: sender,
            storage_owner: Address::zero(),
            gas_price: U256::zero(),
            value: U256::zero(),
        }
    }

    fn get_test_env() -> Env {
        Env {
            chain_id: BTreeMap::from([
                (Space::Native, 0),
                (Space::Ethereum, 0),
            ]),
            number: 100,
            author: Address::from_low_u64_be(0),
            timestamp: 0,
            difficulty: 0.into(),
            last_hash: H256::zero(),
            accumulated_gas_used: 0.into(),
            gas_limit: 0.into(),
            epoch_height: 0,
            pos_view: None,
            finalized_epoch: None,
            transaction_epoch_bound: TRANSACTION_DEFAULT_EPOCH_BOUND,
            base_gas_price: Default::default(),
            burnt_gas_price: Default::default(),
        }
    }

    // storage_manager is apparently unused but it must be held to keep the
    // database directory.
    #[allow(unused)]
    struct TestSetup {
        state: State,
        machine: Machine,
        spec: Spec,
        substate: Substate,
        env: Env,
        callstack: CallStackInfo,
    }

    impl TestSetup {
        fn new() -> Self {
            let state = get_state_for_genesis_write();
            let machine = Machine::new_with_builtin(
                Default::default(),
                Default::default(),
            );
            let env = get_test_env();
            let spec = machine.spec_for_test(env.number);
            let callstack = CallStackInfo::new();

            let mut setup = Self {
                // storage_manager,
                state,
                machine,
                spec,
                substate: Substate::new(),
                env,
                callstack,
            };
            setup
                .state
                .init_code(
                    &Address::zero().with_native_space(),
                    vec![],
                    Address::zero(),
                )
                .ok();

            setup
        }
    }

    #[test]
    fn can_be_created() {
        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let origin = get_test_origin();

        let mut lctx = FrameLocal::new(
            Space::Native,
            &setup.env,
            &setup.machine,
            &setup.spec,
            0, /* depth */
            origin,
            setup.substate,
            None,
            false, /* static_flag */
        );
        let mut owned_res = OwnedRuntimeRes::from(state);
        let mut resources = owned_res.as_res();
        let ctx = lctx.make_vm_context(&mut resources);

        assert_eq!(ctx.env().number, 100);
    }

    #[test]
    fn can_return_block_hash_no_env() {
        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let origin = get_test_origin();

        let mut lctx = FrameLocal::new(
            Space::Native,
            &setup.env,
            &setup.machine,
            &setup.spec,
            0, /* depth */
            origin,
            setup.substate,
            None,
            false, /* static_flag */
        );
        let mut owned_res = OwnedRuntimeRes::from(state);
        let mut resources = owned_res.as_res();
        let mut ctx = lctx.make_vm_context(&mut resources);

        let hash = ctx.blockhash(
            &"0000000000000000000000000000000000000000000000000000000000120000"
                .parse::<U256>()
                .unwrap(),
        ).unwrap();

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

    // #[test]
    // #[should_panic]
    // fn can_call_fail_empty() {
    //     let mut setup = TestSetup::new();
    //     let state = &mut setup.state;
    //     let origin = get_test_origin();
    //     let mut callstack = CallStackInfo::default();
    //
    //     let mut lctx = LocalContext::new(
    //         &setup.env,
    //         &setup.machine,
    //         &setup.spec,
    //         0, /* depth */
    //         0, /* stack_depth */
    //         origin,
    //         setup.substate,
    //         true,  /* is_create */
    //         false, /* static_flag */
    //         &setup.internal_contract_map,
    //     );
    //     let mut ctx = lctx.activate(state, &mut callstack);
    //
    //     // this should panic because we have no balance on any account
    //     ctx.call(
    //     &"0000000000000000000000000000000000000000000000000000000000120000"
    //         .parse::<U256>()
    //         .unwrap(),
    //     &Address::zero(),
    //     &Address::zero(),
    //     Some(
    //         "0000000000000000000000000000000000000000000000000000000000150000"
    //             .parse::<U256>()
    //             .unwrap(),
    //     ),
    //     &[],
    //     &Address::zero(),
    //     CallType::Call,
    //     false,
    // )
    //         .unwrap()
    // .unwrap();
    // }

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
            let mut lctx = FrameLocal::new(
                Space::Native,
                &setup.env,
                &setup.machine,
                &setup.spec,
                0, /* depth */
                origin,
                setup.substate,
                None,
                false, /* static_flag */
            );

            {
                let mut owned_res = OwnedRuntimeRes::from(state);
                let mut resources = owned_res.as_res();

                let mut ctx = lctx.make_vm_context(&mut resources);
                ctx.log(log_topics, &log_data).unwrap();
            }

            assert_eq!(lctx.substate.logs.len(), 1);
        }
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
        let contract_address_w_space = contract_address.with_native_space();
        state
            .new_contract_with_code(&contract_address_w_space, U256::zero())
            .expect(&concat!(file!(), ":", line!(), ":", column!()));
        state
            .init_code(
                &contract_address_w_space,
                // Use empty code in test because we don't have storage
                // collateral balance.
                "".into(),
                contract_address,
            )
            .expect(&concat!(file!(), ":", line!(), ":", column!()));

        {
            let mut lctx = FrameLocal::new(
                Space::Native,
                &setup.env,
                &setup.machine,
                &setup.spec,
                0, /* depth */
                origin,
                setup.substate,
                None,
                false, /* static_flag */
            );
            let mut owned_res = OwnedRuntimeRes::from(state);
            let mut resources = owned_res.as_res();
            let mut ctx = lctx.make_vm_context(&mut resources);
            ctx.suicide(&refund_account).unwrap();
            assert_eq!(lctx.substate.suicides.len(), 1);
        }
    }

    //TODO: It seems create function only has non-trapped call in test. We
    // remove non-trapped call.
    /*
    #[test]
    fn can_create() {
        use std::str::FromStr;

        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let origin = get_test_origin();
        let mut callstack = CallStackInfo::default();

        let address = {
            let mut lctx = LocalContext::new(
                &setup.env,
                &setup.machine,
                &setup.spec,
                0, /* depth */
                0, /* stack_depth */
                origin,
                setup.substate,
                true,  /* is_create */
                false, /* static_flag */
                &setup.internal_contract_map,
            );
            let mut ctx = lctx.activate(state, &mut callstack);
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
        let mut callstack = CallStackInfo::default();

        let address = {
            let mut lctx = LocalContext::new(
                &setup.env,
                &setup.machine,
                &setup.spec,
                0, /* depth */
                0, /* stack_depth */
                origin,
                setup.substate,
                true,  /* is_create */
                false, /* static_flag */
                &setup.internal_contract_map,
            );
            let mut ctx = lctx.activate(state, &mut callstack);

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
    }*/
}
