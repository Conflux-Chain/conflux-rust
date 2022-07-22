// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Transaction execution environment.
use super::{
    executive::*,
    internal_contract::{suicide as suicide_impl, InternalRefContext},
};
use crate::{
    bytes::Bytes,
    machine::Machine,
    observer::VmObserve,
    state::CallStackInfo,
    vm::{
        self, ActionParams, ActionValue, CallType, Context as ContextTrait,
        ContractCreateResult, CreateContractAddress, CreateType, Env, Error,
        MessageCallResult, ReturnData, Spec, TrapKind,
    },
};
use cfx_parameters::staking::{
    code_collateral_units, DRIPS_PER_STORAGE_COLLATERAL_UNIT,
};
use cfx_state::{StateTrait, SubstateMngTrait, SubstateTrait};
use cfx_types::{
    Address, AddressSpaceUtil, AddressWithSpace, Space, H256, U256,
};
use primitives::transaction::UNSIGNED_SENDER;
use std::sync::Arc;

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

/// Implementation of EVM context.
pub struct Context<
    'a, /* Lifetime of transaction executive. */
    'b, /* Lifetime of call-create executive. */
    Substate: SubstateTrait,
> {
    state: &'b mut dyn StateTrait<Substate = Substate>,
    callstack: &'b mut CallStackInfo,
    local_part: &'b mut LocalContext<'a, Substate>,
}

/// The `LocalContext` only contains the parameters can be owned by an
/// executive. It will be never change during the lifetime of its corresponding
/// executive.
pub struct LocalContext<'a, Substate: SubstateTrait> {
    pub space: Space,
    pub env: &'a Env,
    pub depth: usize,
    pub is_create: bool,
    pub origin: OriginInfo,
    pub substate: Substate,
    pub machine: &'a Machine,
    pub spec: &'a Spec,
    pub static_flag: bool,
}

impl<'a, 'b, Substate: SubstateTrait> LocalContext<'a, Substate> {
    pub fn new(
        space: Space, env: &'a Env, machine: &'a Machine, spec: &'a Spec,
        depth: usize, origin: OriginInfo, substate: Substate, is_create: bool,
        static_flag: bool,
    ) -> Self
    {
        LocalContext {
            space,
            env,
            depth,
            origin,
            substate,
            machine,
            spec,
            is_create,
            static_flag,
        }
    }

    /// The `LocalContext` only contains the parameters can be owned by an
    /// executive. For the parameters shared between executives (like `&mut
    /// State`), the executive should activate `LocalContext` by passing in
    /// these parameters.
    pub fn activate(
        &'b mut self, state: &'b mut dyn StateTrait<Substate = Substate>,
        callstack: &'b mut CallStackInfo,
    ) -> Context<'a, 'b, Substate>
    {
        Context {
            state,
            local_part: self,
            callstack,
        }
    }
}

impl<'a, 'b, Substate: SubstateMngTrait> ContextTrait
    for Context<'a, 'b, Substate>
{
    fn storage_at(&self, key: &Vec<u8>) -> vm::Result<U256> {
        let caller = AddressWithSpace {
            address: self.local_part.origin.address,
            space: self.local_part.space,
        };
        self.local_part
            .substate
            .storage_at(self.state.as_state_ops(), &caller, key)
            .map_err(Into::into)
    }

    fn set_storage(&mut self, key: Vec<u8>, value: U256) -> vm::Result<()> {
        let caller = AddressWithSpace {
            address: self.local_part.origin.address,
            space: self.local_part.space,
        };
        if self.is_static_or_reentrancy() {
            Err(vm::Error::MutableCallInStaticContext)
        } else {
            self.local_part
                .substate
                .set_storage(
                    self.state.as_mut_state_ops(),
                    &caller,
                    key,
                    value,
                    self.local_part.origin.storage_owner,
                )
                .map_err(Into::into)
        }
    }

    fn exists(&self, address: &Address) -> vm::Result<bool> {
        let address = AddressWithSpace {
            address: *address,
            space: self.local_part.space,
        };
        self.state.exists(&address).map_err(Into::into)
    }

    fn exists_and_not_null(&self, address: &Address) -> vm::Result<bool> {
        let address = AddressWithSpace {
            address: *address,
            space: self.local_part.space,
        };
        self.state.exists_and_not_null(&address).map_err(Into::into)
    }

    fn origin_balance(&self) -> vm::Result<U256> {
        self.balance(&self.local_part.origin.address)
            .map_err(Into::into)
    }

    fn balance(&self, address: &Address) -> vm::Result<U256> {
        let address = AddressWithSpace {
            address: *address,
            space: self.local_part.space,
        };
        self.state.balance(&address).map_err(Into::into)
    }

    fn blockhash(&mut self, number: &U256) -> H256 {
        if self.local_part.space == Space::Ethereum
            && self.local_part.spec.cip98
        {
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

    fn create(
        &mut self, gas: &U256, value: &U256, code: &[u8],
        address_scheme: CreateContractAddress,
    ) -> cfx_statedb::Result<
        ::std::result::Result<ContractCreateResult, TrapKind>,
    >
    {
        let caller = AddressWithSpace {
            address: self.local_part.origin.address,
            space: self.local_part.space,
        };

        let create_type = CreateType::from_address_scheme(&address_scheme);
        // create new contract address
        let (address_with_space, code_hash) = self::contract_address(
            address_scheme,
            self.local_part.env.number.into(),
            &caller,
            &self.state.nonce(&caller)?,
            &code,
        );

        let address = address_with_space.address;

        // For a contract address already with code, we do not allow overlap the
        // address. This should generally not happen. Unless we enable
        // account dust in future. We add this check just in case it
        // helps in future.
        if self.local_part.space == Space::Native
            && self.state.is_contract_with_code(&address_with_space)?
        {
            debug!("Contract address conflict!");
            let err = Error::ConflictAddress(address.clone());
            return Ok(Ok(ContractCreateResult::Failed(err)));
        }

        // prepare the params
        let params = ActionParams {
            space: self.local_part.space,
            code_address: address.clone(),
            address: address.clone(),
            sender: self.local_part.origin.address.clone(),
            original_sender: self.local_part.origin.original_sender,
            storage_owner: self.local_part.origin.storage_owner,
            gas: *gas,
            gas_price: self.local_part.origin.gas_price,
            value: ActionValue::Transfer(*value),
            code: Some(Arc::new(code.to_vec())),
            code_hash,
            data: None,
            call_type: CallType::None,
            create_type,
            params_type: vm::ParamsType::Embedded,
        };

        if !self.is_static_or_reentrancy() {
            if !self.local_part.spec.keep_unsigned_nonce
                || params.sender != UNSIGNED_SENDER
            {
                self.state.inc_nonce(
                    &caller,
                    // The sender of a CREATE call is guaranteed to exist,
                    // therefore the start_nonce below
                    // doesn't matter.
                    &self.local_part.spec.contract_start_nonce,
                )?;
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

        let code_address_with_space =
            code_address.with_space(self.local_part.space);

        let (code, code_hash) = if let Some(contract) = self
            .local_part
            .machine
            .internal_contracts()
            .contract(&code_address_with_space, self.local_part.spec)
        {
            (Some(contract.code()), Some(contract.code_hash()))
        } else {
            (
                self.state.code(&code_address_with_space)?,
                self.state.code_hash(&code_address_with_space)?,
            )
        };

        let mut params = ActionParams {
            space: self.local_part.space,
            sender: *sender_address,
            address: *receive_address,
            value: ActionValue::Apparent(self.local_part.origin.value),
            code_address: *code_address,
            original_sender: self.local_part.origin.original_sender,
            storage_owner: self.local_part.origin.storage_owner,
            gas: *gas,
            gas_price: self.local_part.origin.gas_price,
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
        let address = address.with_space(self.local_part.space);
        if let Some(contract) = self
            .local_part
            .machine
            .internal_contracts()
            .contract(&address, self.local_part.spec)
        {
            Ok(Some(contract.code()))
        } else {
            Ok(self.state.code(&address)?)
        }
    }

    fn extcodehash(&self, address: &Address) -> vm::Result<Option<H256>> {
        let address = address.with_space(self.local_part.space);

        if let Some(contract) = self
            .local_part
            .machine
            .internal_contracts()
            .contract(&address, self.local_part.spec)
        {
            Ok(Some(contract.code_hash()))
        } else {
            Ok(self.state.code_hash(&address)?)
        }
    }

    fn extcodesize(&self, address: &Address) -> vm::Result<Option<usize>> {
        let address = address.with_space(self.local_part.space);

        if let Some(contract) = self
            .local_part
            .machine
            .internal_contracts()
            .contract(&address, self.local_part.spec)
        {
            Ok(Some(contract.code_size()))
        } else {
            Ok(self.state.code_size(&address)?)
        }
    }

    fn log(&mut self, topics: Vec<H256>, data: &[u8]) -> vm::Result<()> {
        use primitives::log_entry::LogEntry;

        if self.is_static_or_reentrancy() {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        let address = self.local_part.origin.address.clone();
        self.local_part.substate.logs_mut().push(LogEntry {
            address,
            topics,
            data: data.to_vec(),
            space: self.local_part.space,
        });

        Ok(())
    }

    fn ret(
        self, gas: &U256, data: &ReturnData, apply_state: bool,
    ) -> vm::Result<U256>
    where Self: Sized {
        let caller = self
            .local_part
            .origin
            .address
            .with_space(self.local_part.space);

        match self.local_part.is_create {
            false => Ok(*gas),
            true if apply_state => {
                let create_data_gas = self.local_part.spec.create_data_gas
                    * match self.local_part.space {
                        Space::Native => 1,
                        Space::Ethereum => self.local_part.spec.evm_gas_ratio,
                    };
                let return_cost = U256::from(data.len()) * create_data_gas;
                if return_cost > *gas
                    || data.len() > self.local_part.spec.create_data_limit
                {
                    return match self
                        .local_part
                        .spec
                        .exceptional_failed_code_deposit
                    {
                        true => Err(vm::Error::OutOfGas),
                        false => Ok(*gas),
                    };
                }

                if self.local_part.space == Space::Native {
                    let collateral_units_for_code =
                        code_collateral_units(data.len());
                    let collateral_in_drips =
                        U256::from(collateral_units_for_code)
                            * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
                    debug!(
                        "ret()  collateral_for_code={:?}",
                        collateral_in_drips
                    );
                    self.local_part.substate.record_storage_occupy(
                        &self.local_part.origin.storage_owner,
                        collateral_units_for_code,
                    );
                }

                let owner = if self.local_part.space == Space::Native {
                    self.local_part.origin.storage_owner
                } else {
                    Address::zero()
                };

                self.state.init_code(&caller, data.to_vec(), owner)?;

                Ok(*gas - return_cost)
            }
            true => Ok(*gas),
        }
    }

    fn suicide(
        &mut self, refund_address: &Address, tracer: &mut dyn VmObserve,
        account_start_nonce: U256,
    ) -> vm::Result<()>
    {
        if self.is_static_or_reentrancy() {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        suicide_impl(
            &self
                .local_part
                .origin
                .address
                .with_space(self.local_part.space),
            &refund_address.with_space(self.local_part.space),
            self.state.as_mut_state_ops(),
            &self.local_part.spec,
            &mut self.local_part.substate,
            tracer,
            account_start_nonce,
        )
    }

    fn spec(&self) -> &Spec { &self.local_part.spec }

    fn env(&self) -> &Env { &self.local_part.env }

    fn space(&self) -> Space { self.local_part.space }

    fn chain_id(&self) -> u64 {
        let space = self.local_part.space;
        self.local_part
            .machine
            .params()
            .chain_id
            .read()
            .get_chain_id(self.local_part.env.epoch_height)
            .in_space(space) as u64
    }

    fn depth(&self) -> usize { self.local_part.depth }

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

    fn is_static(&self) -> bool { self.local_part.static_flag }

    fn is_static_or_reentrancy(&self) -> bool {
        self.local_part.static_flag
            || self.callstack.in_reentrancy(self.local_part.spec)
    }

    fn internal_ref(&mut self) -> InternalRefContext {
        InternalRefContext {
            env: self.local_part.env,
            spec: self.local_part.spec,
            callstack: self.callstack,
            state: self.state.as_mut_state_ops(),
            substate: &mut self.local_part.substate,
            static_flag: self.local_part.static_flag,
            depth: self.local_part.depth,
        }
    }
}

/// TODO: Move this code to a seperated file. So we can distinguish function
/// calls from test.
#[cfg(test)]
mod tests {
    use super::{LocalContext, OriginInfo};
    use crate::{
        machine::{new_machine_with_builtin, Machine},
        state::{CallStackInfo, State, Substate},
        test_helpers::get_state_for_genesis_write,
        vm::{Context as ContextTrait, Env, Spec},
    };
    use cfx_parameters::consensus::TRANSACTION_DEFAULT_EPOCH_BOUND;
    use cfx_state::{
        state_trait::StateOpsTrait, substate_trait::SubstateMngTrait,
    };
    use cfx_storage::{
        new_storage_manager_for_testing, tests::FakeStateManager,
    };
    use cfx_types::{
        address_util::AddressUtil, Address, AddressSpaceUtil, Space, H256, U256,
    };
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
            pos_view: None,
            finalized_epoch: None,
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
        spec: Spec,
        substate: Substate,
        env: Env,
        callstack: CallStackInfo,
    }

    impl TestSetup {
        fn new() -> Self {
            let storage_manager = new_storage_manager_for_testing();
            let state = get_state_for_genesis_write(&*storage_manager);
            let machine = new_machine_with_builtin(
                Default::default(),
                Default::default(),
            );
            let env = get_test_env();
            let spec = machine.spec(env.number);
            let callstack = CallStackInfo::new();

            let mut setup = Self {
                storage_manager,
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
        let mut callstack = CallStackInfo::new();

        let mut lctx = LocalContext::new(
            Space::Native,
            &setup.env,
            &setup.machine,
            &setup.spec,
            0, /* depth */
            origin,
            setup.substate,
            true,  /* is_create */
            false, /* static_flag */
        );
        let ctx = lctx.activate(state, &mut callstack);

        assert_eq!(ctx.env().number, 100);
    }

    #[test]
    fn can_return_block_hash_no_env() {
        let mut setup = TestSetup::new();
        let state = &mut setup.state;
        let origin = get_test_origin();
        let mut callstack = CallStackInfo::new();

        let mut lctx = LocalContext::new(
            Space::Native,
            &setup.env,
            &setup.machine,
            &setup.spec,
            0, /* depth */
            origin,
            setup.substate,
            true,  /* is_create */
            false, /* static_flag */
        );
        let mut ctx = lctx.activate(state, &mut callstack);

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
        let mut callstack = CallStackInfo::new();

        {
            let mut lctx = LocalContext::new(
                Space::Native,
                &setup.env,
                &setup.machine,
                &setup.spec,
                0, /* depth */
                origin,
                setup.substate,
                true,  /* is_create */
                false, /* static_flag */
            );
            let mut ctx = lctx.activate(state, &mut callstack);
            ctx.log(log_topics, &log_data).unwrap();
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
        let mut callstack = CallStackInfo::new();

        let mut contract_address = Address::zero();
        contract_address.set_contract_type_bits();
        origin.address = contract_address;
        let contract_address_w_space = contract_address.with_native_space();
        state
            .new_contract_with_code(
                &contract_address_w_space,
                U256::zero(),
                U256::one(),
            )
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
            let mut lctx = LocalContext::new(
                Space::Native,
                &setup.env,
                &setup.machine,
                &setup.spec,
                0, /* depth */
                origin,
                setup.substate,
                true,  /* is_create */
                false, /* static_flag */
            );
            let mut ctx = lctx.activate(state, &mut callstack);
            let mut tracer = ();
            ctx.suicide(
                &refund_account,
                &mut tracer,
                setup.machine.spec(setup.env.number).account_start_nonce,
            )
            .unwrap();
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
