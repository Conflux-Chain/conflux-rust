// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{context::OriginInfo, Executed, ExecutionError};
use crate::{
    builtin::Builtin,
    bytes::Bytes,
    evm::{FinalizationResult, Finalize},
    executive::{
        context::LocalContext,
        executed::{ExecutionOutcome, ToRepackError, TxDropError},
        internal_contract::InternalContractTrait,
        vm_exec::{BuiltinExec, InternalContractExec, NoopExec},
        CollateralCheckResultToVmResult,
    },
    hash::keccak,
    machine::Machine,
    observer::{
        tracer::ExecutiveTracer, AddressPocket, GasMan, StateTracer, VmObserve,
    },
    state::{
        cleanup_mode, settle_collateral_for_all, CallStackInfo, State, Substate,
    },
    verification::VerificationConfig,
    vm::{
        self, ActionParams, ActionValue, CallType, CreateContractAddress,
        CreateType, Env, Exec, ExecTrapError, ExecTrapResult, GasLeft,
        ResumeCall, ResumeCreate, ReturnData, Spec, TrapError, TrapResult,
    },
    vm_factory::VmFactory,
};
use cfx_parameters::{consensus::ONE_CFX_IN_DRIP, staking::*};
use cfx_state::{CleanupMode, CollateralCheckResult};
use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, AddressWithSpace,
    Space, H256, U256, U512, U64,
};
use primitives::{
    receipt::StorageChange, storage::STORAGE_LAYOUT_REGULAR_V0,
    transaction::Action, NativeTransaction, SignedTransaction, StorageLayout,
    Transaction,
};
use rlp::RlpStream;
use std::{
    cmp::{max, min},
    collections::HashSet,
    convert::{TryFrom, TryInto},
    ops::Shl,
    sync::Arc,
};

/// Calculate new contract address.
pub fn contract_address(
    address_scheme: CreateContractAddress, _block_number: U64,
    sender: &AddressWithSpace, nonce: &U256, code: &[u8],
) -> (AddressWithSpace, Option<H256>)
{
    let code_hash = keccak(code);
    let (address, code_hash) = match address_scheme {
        CreateContractAddress::FromSenderNonce => {
            assert_eq!(sender.space, Space::Ethereum);
            let mut rlp = RlpStream::new_list(2);
            rlp.append(&sender.address);
            rlp.append(nonce);
            let h = Address::from(keccak(rlp.as_raw()));
            (h, Some(code_hash))
        }
        CreateContractAddress::FromBlockNumberSenderNonceAndCodeHash => {
            unreachable!("Inactive setting");
            // let mut buffer = [0u8; 1 + 8 + 20 + 32 + 32];
            // let (lead_bytes, rest) = buffer.split_at_mut(1);
            // let (block_number_bytes, rest) = rest.split_at_mut(8);
            // let (sender_bytes, rest) =
            // rest.split_at_mut(Address::len_bytes());
            // let (nonce_bytes, code_hash_bytes) =
            //     rest.split_at_mut(H256::len_bytes());
            // // In Conflux, we take block_number and CodeHash into address
            // // calculation. This is required to enable us to clean
            // // up unused user account in future.
            // lead_bytes[0] = 0x0;
            // block_number.to_little_endian(block_number_bytes);
            // sender_bytes.copy_from_slice(&sender.address[..]);
            // nonce.to_little_endian(nonce_bytes);
            // code_hash_bytes.copy_from_slice(&code_hash[..]);
            // // In Conflux, we use the first four bits to indicate the type of
            // // the address. For contract address, the bits will be
            // // set to 0x8.
            // let mut h = Address::from(keccak(&buffer[..]));
            // h.set_contract_type_bits();
            // (h, Some(code_hash))
        }
        CreateContractAddress::FromSenderNonceAndCodeHash => {
            assert_eq!(sender.space, Space::Native);
            let mut buffer = [0u8; 1 + 20 + 32 + 32];
            // In Conflux, we append CodeHash to determine the address as well.
            // This is required to enable us to clean up unused user account in
            // future.
            buffer[0] = 0x0;
            buffer[1..(1 + 20)].copy_from_slice(&sender.address[..]);
            nonce.to_little_endian(&mut buffer[(1 + 20)..(1 + 20 + 32)]);
            buffer[(1 + 20 + 32)..].copy_from_slice(&code_hash[..]);
            // In Conflux, we use the first four bits to indicate the type of
            // the address. For contract address, the bits will be
            // set to 0x8.
            let mut h = Address::from(keccak(&buffer[..]));
            h.set_contract_type_bits();
            (h, Some(code_hash))
        }
        CreateContractAddress::FromSenderSaltAndCodeHash(salt) => {
            let mut buffer = [0u8; 1 + 20 + 32 + 32];
            buffer[0] = 0xff;
            buffer[1..(1 + 20)].copy_from_slice(&sender.address[..]);
            buffer[(1 + 20)..(1 + 20 + 32)].copy_from_slice(&salt[..]);
            buffer[(1 + 20 + 32)..].copy_from_slice(&code_hash[..]);
            // In Conflux, we use the first bit to indicate the type of the
            // address. For contract address, the bits will be set to 0x8.
            let mut h = Address::from(keccak(&buffer[..]));
            if sender.space == Space::Native {
                h.set_contract_type_bits();
            }
            (h, Some(code_hash))
        }
    };
    return (address.with_space(sender.space), code_hash);
}

/// Convert a finalization result into a VM message call result.
pub fn into_message_call_result(
    result: vm::Result<ExecutiveResult>,
) -> vm::MessageCallResult {
    match result {
        Ok(ExecutiveResult {
            gas_left,
            return_data,
            apply_state: true,
            ..
        }) => vm::MessageCallResult::Success(gas_left, return_data),
        Ok(ExecutiveResult {
            gas_left,
            return_data,
            apply_state: false,
            ..
        }) => vm::MessageCallResult::Reverted(gas_left, return_data),
        Err(err) => vm::MessageCallResult::Failed(err),
    }
}

/// Convert a finalization result into a VM contract create result.
pub fn into_contract_create_result(
    result: vm::Result<ExecutiveResult>,
) -> vm::ContractCreateResult {
    match result {
        Ok(ExecutiveResult {
            space,
            gas_left,
            apply_state: true,
            create_address,
            ..
        }) => {
            // Move the change of contracts_created in substate to
            // process_return.
            let address = create_address
                .expect("ExecutiveResult for Create executive should be some.");
            let address = AddressWithSpace { address, space };
            vm::ContractCreateResult::Created(address, gas_left)
        }
        Ok(ExecutiveResult {
            gas_left,
            apply_state: false,
            return_data,
            ..
        }) => vm::ContractCreateResult::Reverted(gas_left, return_data),
        Err(err) => vm::ContractCreateResult::Failed(err),
    }
}

/// Transaction execution options.
pub struct TransactOptions {
    pub observer: Observer,
    pub check_settings: TransactCheckSettings,
}

impl TransactOptions {
    pub fn exec_with_tracing() -> Self {
        Self {
            observer: Observer::with_tracing(),
            check_settings: TransactCheckSettings::all_checks(),
        }
    }

    pub fn exec_with_no_tracing() -> Self {
        Self {
            observer: Observer::with_no_tracing(),
            check_settings: TransactCheckSettings::all_checks(),
        }
    }

    pub fn estimate_first_pass(request: EstimateRequest) -> Self {
        Self {
            observer: Observer::virtual_call(),
            check_settings: TransactCheckSettings::from_estimate_request(
                request,
                ChargeCollateral::EstimateSender,
            ),
        }
    }

    pub fn estimate_second_pass(request: EstimateRequest) -> Self {
        Self {
            observer: Observer::virtual_call(),
            check_settings: TransactCheckSettings::from_estimate_request(
                request,
                ChargeCollateral::EstimateSponsor,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ChargeCollateral {
    Normal,
    EstimateSender,
    EstimateSponsor,
}

#[derive(Debug, Clone, Copy)]
pub struct EstimateRequest {
    pub has_sender: bool,
    pub has_gas_limit: bool,
    pub has_gas_price: bool,
    pub has_nonce: bool,
    pub has_storage_limit: bool,
}

impl EstimateRequest {
    fn recheck_gas_fee(&self) -> bool { self.has_sender && self.has_gas_price }

    fn charge_gas(&self) -> bool {
        self.has_sender && self.has_gas_limit && self.has_gas_price
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TransactCheckSettings {
    pub charge_collateral: ChargeCollateral,
    pub charge_gas: bool,
    pub real_execution: bool,
    pub check_epoch_height: bool,
}

impl TransactCheckSettings {
    fn all_checks() -> Self {
        Self {
            charge_collateral: ChargeCollateral::Normal,
            charge_gas: true,
            real_execution: true,
            check_epoch_height: true,
        }
    }

    fn from_estimate_request(
        request: EstimateRequest, charge_collateral: ChargeCollateral,
    ) -> Self {
        Self {
            charge_collateral,
            charge_gas: request.charge_gas(),
            real_execution: false,
            check_epoch_height: false,
        }
    }
}

pub struct Observer {
    pub tracer: Option<ExecutiveTracer>,
    pub gas_man: Option<GasMan>,
    _noop: (),
}

impl Observer {
    pub fn as_vm_observe<'a>(&'a mut self) -> Box<dyn VmObserve + 'a> {
        match (self.tracer.as_mut(), self.gas_man.as_mut()) {
            (Some(tracer), Some(gas_man)) => Box::new((tracer, gas_man)),
            (Some(tracer), None) => Box::new(tracer),
            (None, Some(gas_man)) => Box::new(gas_man),
            (None, None) => Box::new(&mut self._noop),
        }
    }

    pub fn as_state_tracer(&mut self) -> &mut dyn StateTracer {
        match self.tracer.as_mut() {
            None => &mut self._noop,
            Some(tracer) => tracer,
        }
    }

    fn with_tracing() -> Self {
        Observer {
            tracer: Some(ExecutiveTracer::default()),
            gas_man: None,
            _noop: (),
        }
    }

    fn with_no_tracing() -> Self {
        Observer {
            tracer: None,
            gas_man: None,
            _noop: (),
        }
    }

    fn virtual_call() -> Self {
        Observer {
            tracer: Some(ExecutiveTracer::default()),
            gas_man: Some(GasMan::default()),
            _noop: (),
        }
    }
}

enum CallCreateExecutiveKind<'a> {
    Transfer,
    CallBuiltin(&'a Builtin),
    CallInternalContract(&'a Box<dyn InternalContractTrait>),
    ExecCall,
    ExecCreate,
}

pub struct CallCreateExecutive<'a> {
    context: LocalContext<'a>,
    factory: &'a VmFactory,
    status: ExecutiveStatus,
    create_address: Option<Address>,
    kind: CallCreateExecutiveKind<'a>,
}

pub enum ExecutiveStatus {
    Input(ActionParams),
    Running,
    ResumeCall(Box<dyn ResumeCall>),
    ResumeCreate(Box<dyn ResumeCreate>),
    Done,
}

impl<'a> CallCreateExecutive<'a> {
    /// Create a new call executive using raw data.
    pub fn new_call_raw(
        params: ActionParams, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, factory: &'a VmFactory, depth: usize,
        parent_static_flag: bool,
    ) -> Self
    {
        trace!(
            "Executive::call(params={:?}) self.env={:?}, parent_static={}",
            params,
            env,
            parent_static_flag,
        );

        let static_flag =
            parent_static_flag || params.call_type == CallType::StaticCall;

        let substate = Substate::new();
        // This logic is moved from function exec.
        let origin = OriginInfo::from(&params);
        let code_address = AddressWithSpace {
            address: params.code_address,
            space: params.space,
        };

        // Builtin is located for both Conflux Space and EVM Space.
        let kind =
            if let Some(builtin) = machine.builtin(&code_address, env.number) {
                trace!("CallBuiltin");
                CallCreateExecutiveKind::CallBuiltin(builtin)
            } else if let Some(internal) =
                machine.internal_contracts().contract(&code_address, spec)
            {
                debug!(
                    "CallInternalContract: address={:?} data={:?}",
                    code_address, params.data
                );
                CallCreateExecutiveKind::CallInternalContract(internal)
            } else {
                if params.code.is_some() {
                    trace!("ExecCall");
                    CallCreateExecutiveKind::ExecCall
                } else {
                    trace!("Transfer");
                    CallCreateExecutiveKind::Transfer
                }
            };
        let context = LocalContext::new(
            params.space,
            env,
            machine,
            spec,
            depth,
            origin,
            substate,
            /* is_create: */ false,
            static_flag,
        );
        Self {
            context,
            factory,
            // Instead of put params to Exective kind, we put it into status.
            status: ExecutiveStatus::Input(params),
            create_address: None,
            kind,
        }
    }

    /// Create a new create executive using raw data.
    pub fn new_create_raw(
        params: ActionParams, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, factory: &'a VmFactory, depth: usize,
        static_flag: bool,
    ) -> Self
    {
        trace!(
            "Executive::create(params={:?}) self.env={:?}, static={}",
            params,
            env,
            static_flag
        );

        let origin = OriginInfo::from(&params);

        let kind = CallCreateExecutiveKind::ExecCreate;

        let substate = Substate::new();

        let context = LocalContext::new(
            params.space,
            env,
            machine,
            spec,
            depth,
            origin,
            substate,
            /* is_create */ true,
            static_flag,
        );

        Self {
            context,
            create_address: Some(params.code_address),
            status: ExecutiveStatus::Input(params),
            factory,
            kind,
        }
    }

    /// This executive always contain an unconfirmed substate, returns a mutable
    /// reference to it.
    pub fn unconfirmed_substate(&mut self) -> &mut Substate {
        &mut self.context.substate
    }

    /// Get the recipient of this executive. The recipient is the address whose
    /// state will change.
    pub fn get_recipient(&self) -> &Address { &self.context.origin.recipient() }

    fn check_static_flag(
        params: &ActionParams, static_flag: bool, is_create: bool,
    ) -> vm::Result<()> {
        // This is the function check whether contract creation or value
        // transferring happens in static context at callee executive. However,
        // it is meaningless because the caller has checked this constraint
        // before message call. Currently, if we panic when this
        // function returns error, all the tests can still pass.
        // So we no longer check the logic for reentrancy here,
        // TODO: and later we will check if we can safely remove this function.
        if is_create {
            if static_flag {
                return Err(vm::Error::MutableCallInStaticContext);
            }
        } else {
            if static_flag
                && (params.call_type == CallType::StaticCall
                    || params.call_type == CallType::Call)
                && params.value.value() > U256::zero()
            {
                return Err(vm::Error::MutableCallInStaticContext);
            }
        }

        Ok(())
    }

    fn transfer_exec_balance(
        params: &ActionParams, spec: &Spec, state: &mut State,
        substate: &mut Substate,
    ) -> DbResult<()>
    {
        let sender = AddressWithSpace {
            address: params.sender,
            space: params.space,
        };
        let receiver = AddressWithSpace {
            address: params.address,
            space: params.space,
        };
        if let ActionValue::Transfer(val) = params.value {
            state.transfer_balance(
                &sender,
                &receiver,
                &val,
                cleanup_mode(substate, &spec),
            )?;
        }

        Ok(())
    }

    fn transfer_exec_balance_and_init_contract(
        params: &ActionParams, spec: &Spec, state: &mut State,
        substate: &mut Substate, storage_layout: Option<StorageLayout>,
    ) -> DbResult<()>
    {
        let sender = AddressWithSpace {
            address: params.sender,
            space: params.space,
        };
        let receiver = AddressWithSpace {
            address: params.address,
            space: params.space,
        };
        if let ActionValue::Transfer(val) = params.value {
            // It is possible to first send money to a pre-calculated
            // contract address.
            let prev_balance = state.balance(&receiver)?;
            state.sub_balance(
                &sender,
                &val,
                &mut cleanup_mode(substate, &spec),
            )?;
            let admin = if params.space == Space::Native {
                params.original_sender
            } else {
                Address::zero()
            };
            state.new_contract_with_admin(
                &receiver,
                &admin,
                val.saturating_add(prev_balance),
                storage_layout,
                spec.cip107,
            )?;
        } else {
            // In contract creation, the `params.value` should never be
            // `Apparent`.
            unreachable!();
        }

        Ok(())
    }

    /// When the executive (the inner EVM) returns, this function will process
    /// the rest tasks: If the execution successes, this function collects
    /// storage collateral change from the cache to substate, merge substate to
    /// its parent and settles down bytecode for newly created contract. If the
    /// execution fails, this function reverts state and drops substate.
    fn process_return(
        mut self, result: vm::Result<GasLeft>, state: &mut State,
        callstack: &mut CallStackInfo, tracer: &mut dyn VmObserve,
    ) -> DbResult<vm::Result<ExecutiveResult>>
    {
        let context = self.context.activate(state, callstack);
        // The post execution task in spec is completed here.
        let finalized_result = result.finalize(context);
        let finalized_result = vm::separate_out_db_error(finalized_result)?;

        self.status = ExecutiveStatus::Done;

        let apply_state =
            finalized_result.as_ref().map_or(false, |r| r.apply_state);
        let maybe_substate;
        if apply_state {
            let mut substate = self.context.substate;
            state.collect_ownership_changed(&mut substate)?; /* only fail for db error. */
            if let Some(create_address) = self.create_address {
                substate
                    .contracts_created
                    .push(create_address.with_space(self.context.space));
            }
            maybe_substate = Some(substate);
            state.discard_checkpoint();
        } else {
            maybe_substate = None;
            state.revert_to_checkpoint();
        }

        let create_address = self.create_address;
        let executive_result = finalized_result.map(|result| {
            ExecutiveResult::new(result, create_address, maybe_substate)
        });
        if self.context.is_create {
            tracer.record_create_result(&executive_result);
        } else {
            tracer.record_call_result(&executive_result);
        }

        callstack.pop();

        Ok(executive_result)
    }

    /// If the executive triggers a sub-call during execution, this function
    /// outputs a trap error with sub-call parameters and return point.
    fn process_trap(
        mut self, trap_err: ExecTrapError,
    ) -> ExecutiveTrapError<'a> {
        match trap_err {
            TrapError::Call(subparams, resume) => {
                self.status = ExecutiveStatus::ResumeCall(resume);
                TrapError::Call(subparams, self)
            }
            TrapError::Create(subparams, resume) => {
                self.status = ExecutiveStatus::ResumeCreate(resume);
                TrapError::Create(subparams, self)
            }
        }
    }

    /// Execute the executive. If a sub-call/create action is required, a
    /// resume trap error is returned. The caller is then expected to call
    /// `resume` to continue the execution.
    pub fn exec(
        mut self, state: &mut State, callstack: &mut CallStackInfo,
        tracer: &mut dyn VmObserve,
    ) -> DbResult<ExecutiveTrapResult<'a, ExecutiveResult>>
    {
        let status =
            std::mem::replace(&mut self.status, ExecutiveStatus::Running);
        let params = if let ExecutiveStatus::Input(params) = status {
            params
        } else {
            panic!("Status should be input parameter")
        };

        let is_create = self.create_address.is_some();
        assert_eq!(is_create, self.context.is_create);

        // By technical specification and current implementation, the EVM should
        // guarantee the current executive satisfies static_flag.
        Self::check_static_flag(&params, self.context.static_flag, is_create)
            .expect("check_static_flag should always success because EVM has checked it.");

        // Trace task
        if is_create {
            debug!(
                "CallCreateExecutiveKind::ExecCreate: contract_addr = {:?}",
                params.address
            );
            tracer.record_create(&params);
        } else {
            tracer.record_call(&params);
        }

        // Make checkpoint for this executive, callstack is always maintained
        // with checkpoint.
        state.checkpoint();

        let contract_address = self.get_recipient().clone();
        callstack
            .push(contract_address.with_space(self.context.space), is_create);

        // Pre execution: transfer value and init contract.
        let spec = self.context.spec;
        if is_create {
            Self::transfer_exec_balance_and_init_contract(
                &params,
                spec,
                state,
                // It is a bug in the Parity version.
                &mut self.context.substate,
                Some(STORAGE_LAYOUT_REGULAR_V0),
            )?
        } else {
            Self::transfer_exec_balance(
                &params,
                spec,
                state,
                &mut self.context.substate,
            )?
        };

        // Fetch execution model and execute
        let exec: Box<dyn Exec> = match self.kind {
            CallCreateExecutiveKind::Transfer => {
                Box::new(NoopExec { gas: params.gas })
            }
            CallCreateExecutiveKind::CallBuiltin(builtin) => {
                Box::new(BuiltinExec { builtin, params })
            }
            CallCreateExecutiveKind::CallInternalContract(internal) => {
                Box::new(InternalContractExec { internal, params })
            }
            CallCreateExecutiveKind::ExecCall
            | CallCreateExecutiveKind::ExecCreate => {
                let factory = self.context.machine.vm_factory();
                factory.create(params, self.context.spec, self.context.depth)
            }
        };
        let mut context = self.context.activate(state, callstack);
        let output = exec.exec(&mut context, tracer);

        // Post execution.
        self.process_output(output, state, callstack, tracer)
    }

    pub fn resume(
        mut self, mut result: vm::Result<ExecutiveResult>, state: &mut State,
        callstack: &mut CallStackInfo, tracer: &mut dyn VmObserve,
    ) -> DbResult<ExecutiveTrapResult<'a, ExecutiveResult>>
    {
        let status =
            std::mem::replace(&mut self.status, ExecutiveStatus::Running);

        accrue_substate(self.unconfirmed_substate(), &mut result);

        // Process resume tasks, which is defined in Instruction Set
        // Specification of tech-specification.
        let exec = match status {
            ExecutiveStatus::ResumeCreate(resume) => {
                let result = into_contract_create_result(result);
                resume.resume_create(result)
            }
            ExecutiveStatus::ResumeCall(resume) => {
                let result = into_message_call_result(result);
                resume.resume_call(result)
            }
            ExecutiveStatus::Input(_)
            | ExecutiveStatus::Done
            | ExecutiveStatus::Running => {
                panic!("Incorrect executive status in resume");
            }
        };

        let mut context = self.context.activate(state, callstack);
        let output = exec.exec(&mut context, tracer);

        // Post execution.
        self.process_output(output, state, callstack, tracer)
    }

    #[inline]
    fn process_output(
        self, output: ExecTrapResult<GasLeft>, state: &mut State,
        callstack: &mut CallStackInfo, tracer: &mut dyn VmObserve,
    ) -> DbResult<ExecutiveTrapResult<'a, ExecutiveResult>>
    {
        // Convert the `ExecTrapResult` (result of evm) to `ExecutiveTrapResult`
        // (result of self).
        let trap_result = match output {
            TrapResult::Return(result) => TrapResult::Return(
                self.process_return(result, state, callstack, tracer)?,
            ),
            TrapResult::SubCallCreate(trap_err) => {
                TrapResult::SubCallCreate(self.process_trap(trap_err))
            }
        };
        Ok(trap_result)
    }

    /// Execute the top call-create executive. This function handles resume
    /// traps and sub-level tracing. The caller is expected to handle
    /// current-level tracing.
    pub fn consume(
        self, state: &'a mut State, top_substate: &mut Substate,
        tracer: &mut dyn VmObserve,
    ) -> DbResult<vm::Result<FinalizationResult>>
    {
        let mut callstack = CallStackInfo::new();
        let mut executive_stack: Vec<Self> = Vec::new();

        let mut last_res = self.exec(state, &mut callstack, tracer)?;

        loop {
            last_res = match last_res {
                TrapResult::Return(mut result) => {
                    let parent = match executive_stack.pop() {
                        Some(x) => x,
                        None => {
                            accrue_substate(top_substate, &mut result);
                            return Ok(result.map(Into::into));
                        }
                    };

                    parent.resume(result, state, &mut callstack, tracer)?
                }
                TrapResult::SubCallCreate(trap_err) => {
                    let (callee, caller) = Self::from_trap_error(trap_err);
                    executive_stack.push(caller);

                    callee.exec(state, &mut callstack, tracer)?
                }
            }
        }
    }

    /// Output callee executive and caller executive from trap kind error.
    pub fn from_trap_error(trap_err: ExecutiveTrapError<'a>) -> (Self, Self) {
        match trap_err {
            TrapError::Call(params, parent) => (
                /* callee */
                CallCreateExecutive::new_call_raw(
                    params,
                    parent.context.env,
                    parent.context.machine,
                    parent.context.spec,
                    parent.factory,
                    parent.context.depth + 1,
                    parent.context.static_flag,
                ),
                /* caller */ parent,
            ),
            TrapError::Create(params, parent) => (
                /* callee */
                CallCreateExecutive::new_create_raw(
                    params,
                    parent.context.env,
                    parent.context.machine,
                    parent.context.spec,
                    parent.factory,
                    parent.context.depth + 1,
                    parent.context.static_flag,
                ),
                /* callee */ parent,
            ),
        }
    }
}

pub fn accrue_substate(
    parent_substate: &mut Substate, result: &mut vm::Result<ExecutiveResult>,
) {
    if let Ok(frame_return) = result {
        if let Some(substate) = std::mem::take(&mut frame_return.substate) {
            parent_substate.accrue(substate);
        }
    }
}

/// The result contains more data than finalization result.
#[derive(Debug)]
pub struct ExecutiveResult {
    /// Space
    pub space: Space,
    /// Final amount of gas left.
    pub gas_left: U256,
    /// Apply execution state changes or revert them.
    pub apply_state: bool,
    /// Return data buffer.
    pub return_data: ReturnData,
    /// Create address.
    pub create_address: Option<Address>,
    /// Substate.
    pub substate: Option<Substate>,
}

impl Into<FinalizationResult> for ExecutiveResult {
    fn into(self) -> FinalizationResult {
        FinalizationResult {
            space: self.space,
            gas_left: self.gas_left,
            apply_state: self.apply_state,
            return_data: self.return_data,
        }
    }
}

impl ExecutiveResult {
    fn new(
        result: FinalizationResult, create_address: Option<Address>,
        substate: Option<Substate>,
    ) -> Self
    {
        ExecutiveResult {
            space: result.space,
            gas_left: result.gas_left,
            apply_state: result.apply_state,
            return_data: result.return_data,
            create_address,
            substate,
        }
    }
}

/// Trap result returned by executive.
pub type ExecutiveTrapResult<'a, T> =
    vm::TrapResult<T, CallCreateExecutive<'a>, CallCreateExecutive<'a>>;

pub type ExecutiveTrapError<'a> =
    vm::TrapError<CallCreateExecutive<'a>, CallCreateExecutive<'a>>;

pub type Executive<'a> = ExecutiveGeneric<'a>;

/// Transaction executor.
pub struct ExecutiveGeneric<'a> {
    pub state: &'a mut State,
    env: &'a Env,
    machine: &'a Machine,
    spec: &'a Spec,
    depth: usize,
    static_flag: bool,
}

struct SponsorCheckOutput {
    sender_intended_cost: U512,
    total_cost: U512,
    gas_sponsored: bool,
    storage_sponsored: bool,
    storage_sponsor_eligible: bool,
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

impl<'a> ExecutiveGeneric<'a> {
    /// Basic constructor.
    pub fn new(
        state: &'a mut State, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec,
    ) -> Self
    {
        ExecutiveGeneric {
            state,
            env,
            machine,
            spec,
            depth: 0,
            static_flag: false,
        }
    }

    pub fn create(
        &mut self, params: ActionParams, substate: &mut Substate,
        tracer: &mut dyn VmObserve,
    ) -> DbResult<vm::Result<FinalizationResult>>
    {
        let vm_factory = self.machine.vm_factory();
        let result = CallCreateExecutive::new_create_raw(
            params,
            self.env,
            self.machine,
            self.spec,
            &vm_factory,
            self.depth,
            self.static_flag,
        )
        .consume(self.state, substate, tracer)?;

        Ok(result)
    }

    pub fn call(
        &mut self, params: ActionParams, substate: &mut Substate,
        tracer: &mut dyn VmObserve,
    ) -> DbResult<vm::Result<FinalizationResult>>
    {
        let vm_factory = self.machine.vm_factory();
        let result = CallCreateExecutive::new_call_raw(
            params,
            self.env,
            self.machine,
            self.spec,
            &vm_factory,
            self.depth,
            self.static_flag,
        )
        .consume(self.state, substate, tracer)?;

        Ok(result)
    }

    pub fn transact_virtual(
        &mut self, mut tx: SignedTransaction, request: EstimateRequest,
    ) -> DbResult<ExecutionOutcome> {
        let is_native_tx = tx.space() == Space::Native;
        let request_storage_limit = tx.storage_limit();

        if !request.has_sender {
            let mut random_hex = Address::random();
            if is_native_tx {
                random_hex.set_user_account_type_bits();
            }
            tx.sender = random_hex;
            tx.public = None;

            // If the sender is not specified, give it enough balance: 1 billion
            // CFX.
            let balance_inc = min(
                tx.value().saturating_add(
                    U256::from(1_000_000_000) * ONE_CFX_IN_DRIP,
                ),
                U256::one().shl(128),
            );

            self.state.add_balance(
                &random_hex.with_space(tx.space()),
                &balance_inc,
                CleanupMode::NoEmpty,
            )?;
            // Make sure statistics are also correct and will not violate any
            // underlying assumptions.
            self.state.add_total_issued(balance_inc);
            if tx.space() == Space::Ethereum {
                self.state.add_total_evm_tokens(balance_inc);
            }
        }

        if request.has_nonce {
            self.state.set_nonce(&tx.sender(), &tx.nonce())?;
        } else {
            *tx.nonce_mut() = self.state.nonce(&tx.sender())?;
        }

        let balance = self.state.balance(&tx.sender())?;

        // For the same transaction, the storage limit paid by user and the
        // storage limit paid by the sponsor are different values. So
        // this function will
        //
        // 1. First Pass: Assuming the sponsor pays for storage collateral,
        // check if the transaction will fail for
        // NotEnoughBalanceForStorage.
        //
        // 2. Second Pass: If it does, executes the transaction again assuming
        // the user pays for the storage collateral. The resultant
        // storage limit must be larger than the maximum storage limit
        // can be afford by the sponsor, to guarantee the user pays for
        // the storage limit.

        // First pass
        self.state.checkpoint();
        let sender_pay_executed = match self
            .transact(&tx, TransactOptions::estimate_first_pass(request))?
        {
            ExecutionOutcome::Finished(executed) => executed,
            res => {
                return Ok(res);
            }
        };
        debug!(
            "Transaction estimate first pass outcome {:?}",
            sender_pay_executed
        );
        self.state.revert_to_checkpoint();

        // Second pass
        let mut contract_pay_executed: Option<Executed> = None;
        let mut native_to_contract: Option<Address> = None;
        let mut sponsor_for_collateral_eligible = false;
        if let Transaction::Native(NativeTransaction {
            action: Action::Call(ref to),
            ..
        }) = tx.unsigned
        {
            if to.is_contract_address() {
                native_to_contract = Some(*to);
                let has_sponsor = self
                    .state
                    .sponsor_for_collateral(&to)?
                    .map_or(false, |x| !x.is_zero());

                if has_sponsor
                    && (self
                        .state
                        .check_contract_whitelist(&to, &tx.sender().address)?
                        || self
                            .state
                            .check_contract_whitelist(&to, &Address::zero())?)
                {
                    sponsor_for_collateral_eligible = true;

                    self.state.checkpoint();
                    let res = self.transact(
                        &tx,
                        TransactOptions::estimate_second_pass(request),
                    )?;
                    self.state.revert_to_checkpoint();

                    contract_pay_executed = match res {
                        ExecutionOutcome::Finished(executed) => Some(executed),
                        res => {
                            warn!("Should unreachable because two pass estimations should have the same output. \
                                Now we have: first pass success {:?}, second pass fail {:?}", sender_pay_executed, res);
                            None
                        }
                    };
                    debug!(
                        "Transaction estimate second pass outcome {:?}",
                        contract_pay_executed
                    );
                }
            }
        };

        let overwrite_storage_limit =
            |mut executed: Executed, max_sponsor_storage_limit: u64| {
                debug!("Transaction estimate overwrite the storage limit to overcome sponsor_balance_for_collateral.");
                executed.estimated_storage_limit = max(
                    executed.estimated_storage_limit,
                    max_sponsor_storage_limit + 64,
                );
                executed
            };

        let mut executed = if !sponsor_for_collateral_eligible {
            sender_pay_executed
        } else {
            let sponsor_balance_for_collateral =
                self.state.sponsor_balance_for_collateral(
                    native_to_contract.as_ref().unwrap(),
                )?;
            let max_sponsor_storage_limit = (sponsor_balance_for_collateral
                / *DRIPS_PER_STORAGE_COLLATERAL_UNIT)
                .as_u64();
            if let Some(contract_pay_executed) = contract_pay_executed {
                if max_sponsor_storage_limit
                    >= contract_pay_executed.estimated_storage_limit
                {
                    contract_pay_executed
                } else {
                    overwrite_storage_limit(
                        sender_pay_executed,
                        max_sponsor_storage_limit,
                    )
                }
            } else {
                overwrite_storage_limit(
                    sender_pay_executed,
                    max_sponsor_storage_limit,
                )
            }
        };

        // Revise the gas used in result, if we estimate the transaction with a
        // default large enough gas.
        if !request.has_gas_limit {
            let estimated_gas_limit = executed.estimated_gas_limit.unwrap();
            executed.gas_charged = max(
                estimated_gas_limit - estimated_gas_limit / 4,
                executed.gas_used,
            );
            executed.fee = executed.gas_charged.saturating_mul(*tx.gas_price());
        }

        // If we don't charge gas, recheck the current gas_fee is ok for
        // sponsorship.
        if !request.charge_gas()
            && request.has_gas_price
            && executed.gas_sponsor_paid
        {
            let enough_balance = executed.fee
                <= self
                    .state
                    .sponsor_balance_for_gas(&native_to_contract.unwrap())?;
            let enough_bound = executed.fee
                <= self
                    .state
                    .sponsor_gas_bound(&native_to_contract.unwrap())?;
            if !(enough_balance && enough_bound) {
                debug!("Transaction estimate unset \"sponsor_paid\" because of not enough sponsor balance / gas bound.");
                executed.gas_sponsor_paid = false;
            }
        }

        // If the request has a sender, recheck the balance requirement matched.
        if request.has_sender {
            // Unwrap safety: in given TransactOptions, this value must be
            // `Some(_)`.
            let gas_fee =
                if request.recheck_gas_fee() && !executed.gas_sponsor_paid {
                    executed
                        .estimated_gas_limit
                        .unwrap()
                        .saturating_mul(*tx.gas_price())
                } else {
                    0.into()
                };
            let storage_collateral = if !executed.storage_sponsor_paid {
                U256::from(executed.estimated_storage_limit)
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
            } else {
                0.into()
            };
            let value_and_fee = tx
                .value()
                .saturating_add(gas_fee)
                .saturating_add(storage_collateral);
            if balance < value_and_fee {
                return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                    ExecutionError::NotEnoughCash {
                        required: value_and_fee.into(),
                        got: balance.into(),
                        actual_gas_cost: min(balance, gas_fee),
                        max_storage_limit_cost: storage_collateral,
                    },
                    executed,
                ));
            }
        }

        if request.has_storage_limit {
            let storage_limit = request_storage_limit.unwrap();
            if storage_limit < executed.estimated_storage_limit {
                return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                    ExecutionError::VmError(vm::Error::ExceedStorageLimit),
                    executed,
                ));
            }
        }

        return Ok(ExecutionOutcome::Finished(executed));
    }

    fn sponsor_check(
        &self, tx: &SignedTransaction, spec: &Spec, sender_balance: U512,
        gas_cost: U512, storage_cost: U256, settings: &TransactCheckSettings,
    ) -> DbResult<Result<SponsorCheckOutput, ExecutionOutcome>>
    {
        let sender = tx.sender();
        // Check if contract will pay transaction fee for the sender.
        let mut code_address = Address::zero();
        let mut gas_sponsor_eligible = false;
        let mut storage_sponsor_eligible = false;

        if let Action::Call(ref address) = tx.action() {
            if !spec.is_valid_address(address) {
                return Ok(Err(ExecutionOutcome::NotExecutedDrop(
                    TxDropError::InvalidRecipientAddress(*address),
                )));
            }
            if self
                .state
                .is_contract_with_code(&address.with_native_space())?
            {
                code_address = *address;
                if self
                    .state
                    .check_contract_whitelist(&code_address, &sender.address)?
                {
                    // No need to check for gas sponsor account existence.
                    gas_sponsor_eligible = gas_cost
                        <= U512::from(
                            self.state.sponsor_gas_bound(&code_address)?,
                        );
                    storage_sponsor_eligible = self
                        .state
                        .sponsor_for_collateral(&code_address)?
                        .is_some();
                }
            }
        }

        let code_address = code_address;
        let gas_sponsor_eligible = gas_sponsor_eligible;
        let storage_sponsor_eligible = storage_sponsor_eligible;

        // Sender pays for gas when sponsor runs out of balance.
        let sponsor_balance_for_gas =
            U512::from(self.state.sponsor_balance_for_gas(&code_address)?);
        let gas_sponsored =
            gas_sponsor_eligible && sponsor_balance_for_gas >= gas_cost;

        let sponsor_balance_for_storage =
            self.state.sponsor_balance_for_collateral(&code_address)?
                + self
                    .state
                    .avaliable_storage_point_for_collateral(&code_address)?;
        let storage_sponsored = match settings.charge_collateral {
            ChargeCollateral::Normal => {
                storage_sponsor_eligible
                    && storage_cost <= sponsor_balance_for_storage
            }
            ChargeCollateral::EstimateSender => false,
            ChargeCollateral::EstimateSponsor => true,
        };

        let sender_intended_cost = {
            let mut sender_intended_cost = U512::from(tx.value());

            if !gas_sponsor_eligible {
                sender_intended_cost += gas_cost;
            }
            if !storage_sponsor_eligible {
                sender_intended_cost += storage_cost.into();
            }
            sender_intended_cost
        };
        let total_cost = {
            let mut total_cost = U512::from(tx.value());
            if !gas_sponsored {
                total_cost += gas_cost
            }
            if !storage_sponsored {
                total_cost += storage_cost.into();
            }
            total_cost
        };
        // Sponsor is allowed however sender do not have enough balance to pay
        // for the extra gas because sponsor has run out of balance in
        // the mean time.
        //
        // Sender is not responsible for the incident, therefore we don't fail
        // the transaction.
        if sender_balance >= sender_intended_cost && sender_balance < total_cost
        {
            let gas_sponsor_balance = if gas_sponsor_eligible {
                sponsor_balance_for_gas
            } else {
                0.into()
            };

            let storage_sponsor_balance = if storage_sponsor_eligible {
                sponsor_balance_for_storage
            } else {
                0.into()
            };

            return Ok(Err(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::NotEnoughCashFromSponsor {
                    required_gas_cost: gas_cost,
                    gas_sponsor_balance,
                    required_storage_cost: storage_cost,
                    storage_sponsor_balance,
                },
            )));
        }

        return Ok(Ok(SponsorCheckOutput {
            sender_intended_cost,
            total_cost,
            gas_sponsored,
            storage_sponsored,
            // Only for backward compatible for a early bug.
            // The receipt reported `storage_sponsor_eligible` instead of
            // `storage_sponsored`.
            storage_sponsor_eligible,
        }));
    }

    pub fn transact(
        &mut self, tx: &SignedTransaction, options: TransactOptions,
    ) -> DbResult<ExecutionOutcome> {
        let TransactOptions {
            mut observer,
            check_settings,
        } = options;

        let spec = &self.spec;
        let sender = tx.sender();
        let nonce = self.state.nonce(&sender)?;

        // Validate transaction nonce
        if *tx.nonce() < nonce {
            return Ok(ExecutionOutcome::NotExecutedDrop(
                TxDropError::OldNonce(nonce, *tx.nonce()),
            ));
        } else if *tx.nonce() > nonce {
            return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::InvalidNonce {
                    expected: nonce,
                    got: *tx.nonce(),
                },
            ));
        }

        // Validate transaction epoch height.
        if let Transaction::Native(ref tx) = tx.transaction.transaction.unsigned
        {
            if check_settings.check_epoch_height
                && VerificationConfig::check_transaction_epoch_bound(
                    tx,
                    self.env.epoch_height,
                    self.env.transaction_epoch_bound,
                ) != 0
            {
                return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                    ToRepackError::EpochHeightOutOfBound {
                        block_height: self.env.epoch_height,
                        set: tx.epoch_height,
                        transaction_epoch_bound: self
                            .env
                            .transaction_epoch_bound,
                    },
                ));
            }
        }

        let base_gas_required =
            gas_required_for(tx.action() == &Action::Create, &tx.data(), spec);
        assert!(
            *tx.gas() >= base_gas_required.into(),
            "We have already checked the base gas requirement when we received the block."
        );

        let balance = self.state.balance(&sender)?;
        let gas_cost = if check_settings.charge_gas {
            tx.gas().full_mul(*tx.gas_price())
        } else {
            0.into()
        };
        let storage_cost =
            if let (Transaction::Native(tx), ChargeCollateral::Normal) = (
                &tx.transaction.transaction.unsigned,
                check_settings.charge_collateral,
            ) {
                U256::from(tx.storage_limit)
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
            } else {
                U256::zero()
            };

        let sender_balance = U512::from(balance);

        let SponsorCheckOutput {
            sender_intended_cost,
            total_cost,
            gas_sponsored,
            storage_sponsored,
            storage_sponsor_eligible,
        } = if sender.space == Space::Native {
            match self.sponsor_check(
                tx,
                &spec,
                sender_balance,
                gas_cost,
                storage_cost,
                &check_settings,
            )? {
                Ok(res) => res,
                Err(err) => {
                    return Ok(err);
                }
            }
        } else {
            let sender_cost = U512::from(tx.value()) + gas_cost;
            SponsorCheckOutput {
                sender_intended_cost: sender_cost,
                total_cost: sender_cost,
                gas_sponsored: false,
                storage_sponsored: false,
                storage_sponsor_eligible: false,
            }
        };

        let mut tx_substate = Substate::new();
        if sender_balance < sender_intended_cost {
            // Sender is responsible for the insufficient balance.
            // Sub tx fee if not enough cash, and substitute all remaining
            // balance if balance is not enough to pay the tx fee
            let actual_gas_cost: U256 =
                U512::min(gas_cost, sender_balance).try_into().unwrap();

            // We don't want to bump nonce for non-existent account when we
            // can't charge gas fee. In this case, the sender account will
            // not be created if it does not exist.
            if !self.state.exists(&sender)? && check_settings.real_execution {
                return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                    ToRepackError::SenderDoesNotExist,
                ));
            }
            self.state.inc_nonce(&sender)?;
            self.state.sub_balance(
                &sender,
                &actual_gas_cost,
                &mut cleanup_mode(&mut tx_substate, &spec),
            )?;
            observer.as_state_tracer().trace_internal_transfer(
                AddressPocket::Balance(sender.address.with_space(tx.space())),
                AddressPocket::GasPayment,
                actual_gas_cost,
            );
            if tx.space() == Space::Ethereum {
                self.state.sub_total_evm_tokens(actual_gas_cost);
            }

            return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::NotEnoughCash {
                    required: total_cost,
                    got: sender_balance,
                    actual_gas_cost: actual_gas_cost.clone(),
                    max_storage_limit_cost: storage_cost,
                },
                Executed::not_enough_balance_fee_charged(
                    tx,
                    &actual_gas_cost,
                    gas_sponsored,
                    storage_sponsored,
                    observer.tracer.map_or(Default::default(), |t| t.drain()),
                    &self.spec,
                ),
            ));
        } else {
            // From now on sender balance >= total_cost, even if the sender
            // account does not exist (since she may be sponsored). Transaction
            // execution is guaranteed. Note that inc_nonce() will create a
            // new account if the account does not exist.
            self.state.inc_nonce(&sender)?;
        }

        // Subtract the transaction fee from sender or contract.
        let gas_cost = U256::try_from(gas_cost).unwrap();
        // For tracer only when tx is sponsored.
        let code_address = match tx.action() {
            Action::Create => Address::zero(),
            Action::Call(ref address) => *address,
        };

        if !gas_sponsored {
            observer.as_state_tracer().trace_internal_transfer(
                AddressPocket::Balance(sender.address.with_space(tx.space())),
                AddressPocket::GasPayment,
                gas_cost,
            );
            self.state.sub_balance(
                &sender,
                &U256::try_from(gas_cost).unwrap(),
                &mut cleanup_mode(&mut tx_substate, &spec),
            )?;
        // Don't subtract total_evm_balance here. It is maintained properly in
        // `finalize`.
        } else {
            observer.as_state_tracer().trace_internal_transfer(
                AddressPocket::SponsorBalanceForGas(code_address),
                AddressPocket::GasPayment,
                gas_cost,
            );

            self.state.sub_sponsor_balance_for_gas(
                &code_address,
                &U256::try_from(gas_cost).unwrap(),
            )?;
        }

        let init_gas = tx.gas() - base_gas_required;

        // Find the `storage_owner` in this execution.
        let storage_owner = if storage_sponsored {
            code_address
        } else {
            sender.address
        };

        // No matter who pays the collateral, we only focuses on the storage
        // limit of sender.
        let total_storage_limit =
            self.state.collateral_for_storage(&sender.address)? + storage_cost;

        // Initialize the checkpoint for transaction execution. This checkpoint
        // can be reverted by "deploying contract on conflict address" or "not
        // enough balance for storage".
        self.state.checkpoint();
        observer.as_state_tracer().checkpoint();
        let mut substate = Substate::new();

        let res = match tx.action() {
            Action::Create => {
                let address_scheme = match tx.space() {
                    Space::Native => {
                        CreateContractAddress::FromSenderNonceAndCodeHash
                    }
                    Space::Ethereum => CreateContractAddress::FromSenderNonce,
                };
                let (new_address, _code_hash) = contract_address(
                    address_scheme,
                    self.env.number.into(),
                    &sender,
                    &nonce,
                    &tx.data(),
                );

                // For a contract address already with code, we do not allow
                // overlap the address. This should generally
                // not happen. Unless we enable account dust in
                // future. We add this check just in case it
                // helps in future.
                if sender.space == Space::Native
                    && self.state.is_contract_with_code(&new_address)?
                {
                    observer.as_state_tracer().revert_to_checkpoint();
                    self.state.revert_to_checkpoint();
                    return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                        ExecutionError::VmError(vm::Error::ConflictAddress(
                            new_address.address.clone(),
                        )),
                        Executed::execution_error_fully_charged(
                            tx,
                            gas_sponsored,
                            storage_sponsored,
                            observer
                                .tracer
                                .map_or(Default::default(), |t| t.drain()),
                            &spec,
                        ),
                    ));
                }

                let params = ActionParams {
                    space: sender.space,
                    code_address: new_address.address,
                    code_hash: None,
                    address: new_address.address,
                    sender: sender.address,
                    original_sender: sender.address,
                    storage_owner,
                    gas: init_gas,
                    gas_price: *tx.gas_price(),
                    value: ActionValue::Transfer(*tx.value()),
                    code: Some(Arc::new(tx.data().clone())),
                    data: None,
                    call_type: CallType::None,
                    create_type: CreateType::CREATE,
                    params_type: vm::ParamsType::Embedded,
                };
                self.create(
                    params,
                    &mut substate,
                    &mut *observer.as_vm_observe(),
                )?
            }
            Action::Call(ref address) => {
                let address = address.with_space(sender.space);
                let params = ActionParams {
                    space: sender.space,
                    code_address: address.address,
                    address: address.address,
                    sender: sender.address,
                    original_sender: sender.address,
                    storage_owner,
                    gas: init_gas,
                    gas_price: *tx.gas_price(),
                    value: ActionValue::Transfer(*tx.value()),
                    code: self.state.code(&address)?,
                    code_hash: self.state.code_hash(&address)?,
                    data: Some(tx.data().clone()),
                    call_type: CallType::Call,
                    create_type: CreateType::None,
                    params_type: vm::ParamsType::Separate,
                };
                self.call(
                    params,
                    &mut substate,
                    &mut *observer.as_vm_observe(),
                )?
            }
        };

        // Charge collateral and process the checkpoint.
        let (result, output) = {
            let res = res.and_then(|finalize_res| {
                let dry_run = !matches!(
                    check_settings.charge_collateral,
                    ChargeCollateral::Normal
                );

                // For a ethereum space tx, this function has no op.
                let mut res = settle_collateral_for_all(
                    &mut self.state,
                    &substate,
                    observer.as_state_tracer(),
                    &self.spec,
                    dry_run,
                )?;
                if res.ok() {
                    res = self.state.check_storage_limit(
                        &sender.address,
                        &total_storage_limit,
                        dry_run,
                    )?;
                }
                res.into_vm_result().and(Ok(finalize_res))
            });
            let out = match &res {
                Ok(res) => {
                    observer.as_state_tracer().discard_checkpoint();
                    self.state.discard_checkpoint();
                    tx_substate.accrue(substate);
                    res.return_data.to_vec()
                }
                Err(vm::Error::StateDbError(_)) => {
                    // The whole epoch execution fails. No need to revert state.
                    Vec::new()
                }
                Err(_) => {
                    observer.as_state_tracer().revert_to_checkpoint();
                    self.state.revert_to_checkpoint();
                    Vec::new()
                }
            };
            (res, out)
        };

        let refund_receiver = if gas_sponsored {
            Some(code_address)
        } else {
            None
        };

        let estimated_gas_limit = observer
            .gas_man
            .as_ref()
            .map(|g| g.gas_required() * 7 / 6 + base_gas_required);

        Ok(self.finalize(
            tx,
            tx_substate,
            result,
            output,
            refund_receiver,
            /* Storage sponsor paid */
            if self.spec.cip78a {
                storage_sponsored
            } else {
                storage_sponsor_eligible
            },
            observer,
            estimated_gas_limit,
        )?)
    }

    // TODO: maybe we can find a better interface for doing the suicide
    // post-processing.
    fn kill_process(
        &mut self, suicides: &HashSet<AddressWithSpace>,
        tracer: &mut dyn StateTracer, spec: &Spec,
    ) -> DbResult<Substate>
    {
        let mut substate = Substate::new();
        for address in suicides {
            if let Some(code_size) = self.state.code_size(address)? {
                // Only refund the code collateral when code exists.
                // If a contract suicides during creation, the code will be
                // empty.
                if address.space == Space::Native {
                    let code_owner = self
                        .state
                        .code_owner(address)?
                        .expect("code owner exists");
                    substate.record_storage_release(
                        &code_owner,
                        code_collateral_units(code_size),
                    );
                }
            }

            if address.space == Space::Native {
                self.state.record_storage_and_whitelist_entries_release(
                    &address.address,
                    &mut substate,
                )?;
            }
        }

        let res = settle_collateral_for_all(
            &mut self.state,
            &substate,
            tracer,
            spec,
            false,
        )?;
        // Kill process does not occupy new storage entries.
        // The storage recycling process should never occupy new collateral.
        assert_eq!(res, CollateralCheckResult::Valid);

        for contract_address in suicides
            .iter()
            .filter(|x| x.space == Space::Native)
            .map(|x| &x.address)
        {
            let sponsor_for_gas =
                self.state.sponsor_for_gas(contract_address)?;
            let sponsor_for_collateral =
                self.state.sponsor_for_collateral(contract_address)?;
            let sponsor_balance_for_gas =
                self.state.sponsor_balance_for_gas(contract_address)?;
            let sponsor_balance_for_collateral = self
                .state
                .sponsor_balance_for_collateral(contract_address)?;

            if let Some(ref sponsor_address) = sponsor_for_gas {
                tracer.trace_internal_transfer(
                    AddressPocket::SponsorBalanceForGas(*contract_address),
                    AddressPocket::Balance(sponsor_address.with_native_space()),
                    sponsor_balance_for_gas.clone(),
                );
                self.state.add_balance(
                    &sponsor_address.with_native_space(),
                    &sponsor_balance_for_gas,
                    cleanup_mode(&mut substate, self.spec),
                )?;
                self.state.sub_sponsor_balance_for_gas(
                    contract_address,
                    &sponsor_balance_for_gas,
                )?;
            }
            if let Some(ref sponsor_address) = sponsor_for_collateral {
                tracer.trace_internal_transfer(
                    AddressPocket::SponsorBalanceForStorage(*contract_address),
                    AddressPocket::Balance(sponsor_address.with_native_space()),
                    sponsor_balance_for_collateral.clone(),
                );

                self.state.add_balance(
                    &sponsor_address.with_native_space(),
                    &sponsor_balance_for_collateral,
                    cleanup_mode(&mut substate, self.spec),
                )?;
                self.state.sub_sponsor_balance_for_collateral(
                    contract_address,
                    &sponsor_balance_for_collateral,
                )?;
            }
        }

        for contract_address in suicides {
            if contract_address.space == Space::Native {
                let contract_address = contract_address.address;
                let staking_balance =
                    self.state.staking_balance(&contract_address)?;
                tracer.trace_internal_transfer(
                    AddressPocket::StakingBalance(contract_address),
                    AddressPocket::MintBurn,
                    staking_balance.clone(),
                );
                self.state.sub_total_issued(staking_balance);
            }

            let contract_balance = self.state.balance(contract_address)?;
            tracer.trace_internal_transfer(
                AddressPocket::Balance(*contract_address),
                AddressPocket::MintBurn,
                contract_balance.clone(),
            );

            self.state.remove_contract(contract_address)?;
            self.state.sub_total_issued(contract_balance);
            if contract_address.space == Space::Ethereum {
                self.state.sub_total_evm_tokens(contract_balance);
            }
        }

        Ok(substate)
    }

    /// Finalizes the transaction (does refunds and suicides).
    fn finalize(
        &mut self, tx: &SignedTransaction, mut substate: Substate,
        result: vm::Result<FinalizationResult>, output: Bytes,
        refund_receiver: Option<Address>, storage_sponsor_paid: bool,
        mut observer: Observer, estimated_gas_limit: Option<U256>,
    ) -> DbResult<ExecutionOutcome>
    {
        let gas_left = match result {
            Ok(FinalizationResult { gas_left, .. }) => gas_left,
            _ => 0.into(),
        };

        // gas_used is only used to estimate gas needed
        let gas_used = tx.gas() - gas_left;
        // gas_left should be smaller than 1/4 of gas_limit, otherwise
        // 3/4 of gas_limit is charged.
        let charge_all = (gas_left + gas_left + gas_left) >= gas_used;
        let (gas_charged, fees_value, refund_value) = if charge_all {
            let gas_refunded = tx.gas() >> 2;
            let gas_charged = tx.gas() - gas_refunded;
            (
                gas_charged,
                gas_charged.saturating_mul(*tx.gas_price()),
                gas_refunded.saturating_mul(*tx.gas_price()),
            )
        } else {
            (
                gas_used,
                gas_used.saturating_mul(*tx.gas_price()),
                gas_left.saturating_mul(*tx.gas_price()),
            )
        };

        if let Some(r) = refund_receiver {
            observer.as_state_tracer().trace_internal_transfer(
                AddressPocket::GasPayment,
                AddressPocket::SponsorBalanceForGas(r),
                refund_value.clone(),
            );
            self.state.add_sponsor_balance_for_gas(&r, &refund_value)?;
        } else {
            observer.as_state_tracer().trace_internal_transfer(
                AddressPocket::GasPayment,
                AddressPocket::Balance(tx.sender()),
                refund_value.clone(),
            );
            self.state.add_balance(
                &tx.sender(),
                &refund_value,
                cleanup_mode(&mut substate, self.spec),
            )?;
        };

        if tx.space() == Space::Ethereum {
            self.state.sub_total_evm_tokens(fees_value);
        }

        // perform suicides

        let subsubstate = self.kill_process(
            &substate.suicides,
            observer.as_state_tracer(),
            &self.spec,
        )?;
        substate.accrue(subsubstate);

        // TODO should be added back after enabling dust collection
        // Should be executed once per block, instead of per transaction?
        //
        // When enabling this feature, remember to check touched set in
        // functions like "add_collateral_for_storage()" in "State"
        // struct.

        //        // perform garbage-collection
        //        let min_balance = if spec.kill_dust != CleanDustMode::Off {
        //            Some(U256::from(spec.tx_gas) * tx.gas_price())
        //        } else {
        //            None
        //        };
        //
        //        self.state.kill_garbage(
        //            &substate.touched,
        //            spec.kill_empty,
        //            &min_balance,
        //            spec.kill_dust == CleanDustMode::WithCodeAndStorage,
        //        )?;

        match result {
            Err(vm::Error::StateDbError(e)) => bail!(e.0),
            Err(exception) => Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(exception),
                Executed::execution_error_fully_charged(
                    tx,
                    refund_receiver.is_some(),
                    storage_sponsor_paid,
                    observer.tracer.map_or(Default::default(), |t| t.drain()),
                    &self.spec,
                ),
            )),
            Ok(r) => {
                let mut storage_collateralized = Vec::new();
                let mut storage_released = Vec::new();

                if r.apply_state {
                    let mut affected_address: Vec<_> = substate
                        .keys_for_collateral_changed()
                        .iter()
                        .cloned()
                        .collect();
                    affected_address.sort();
                    for address in affected_address {
                        let (inc, sub) =
                            substate.get_collateral_change(&address);
                        if inc > 0 {
                            storage_collateralized.push(StorageChange {
                                address: *address,
                                collaterals: inc.into(),
                            });
                        } else if sub > 0 {
                            storage_released.push(StorageChange {
                                address: *address,
                                collaterals: sub.into(),
                            });
                        }
                    }
                }

                let trace =
                    observer.tracer.map_or(Default::default(), |t| t.drain());

                let estimated_storage_limit =
                    if let Some(x) = storage_collateralized.first() {
                        x.collaterals.as_u64()
                    } else {
                        0
                    };

                let executed = Executed {
                    gas_used,
                    gas_charged,
                    fee: fees_value,
                    gas_sponsor_paid: refund_receiver.is_some(),
                    logs: substate.logs.to_vec(),
                    contracts_created: substate.contracts_created.to_vec(),
                    storage_sponsor_paid,
                    storage_collateralized,
                    storage_released,
                    output,
                    trace,
                    estimated_gas_limit,
                    estimated_storage_limit,
                };

                if r.apply_state {
                    Ok(ExecutionOutcome::Finished(executed))
                } else {
                    // Transaction reverted by vm instruction.
                    Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                        ExecutionError::VmError(vm::Error::Reverted),
                        executed,
                    ))
                }
            }
        }
    }
}
