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
        executed::{ExecutionOutcome, ToRepackError},
        vm_exec::{BuiltinExec, InternalContractExec, NoopExec},
        CollateralCheckResultToVmResult, InternalContractTrait, TxDropError,
    },
    hash::keccak,
    machine::Machine,
    state::{cleanup_mode, CallStackInfo, State, Substate},
    trace::{self, trace::ExecTrace, Tracer},
    verification::VerificationConfig,
    vm::{
        self, ActionParams, ActionValue, CallType, CreateContractAddress, Env,
        Exec, ExecTrapError, ExecTrapResult, GasLeft, ResumeCall, ResumeCreate,
        ReturnData, Spec, TrapError, TrapResult,
    },
    vm_factory::VmFactory,
};
use cfx_parameters::staking::*;
use cfx_state::{
    state_trait::StateOpsTrait, substate_trait::SubstateMngTrait, CleanupMode,
    CollateralCheckResult, StateTrait, SubstateTrait,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{address_util::AddressUtil, Address, H256, U256, U512, U64};
use primitives::{
    receipt::StorageChange,
    storage::STORAGE_LAYOUT_REGULAR_V0,
    transaction::{Action, TransactionType},
    SignedTransaction, StorageLayout,
};
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    sync::Arc,
};

/// Calculate new contract address.
pub fn contract_address(
    address_scheme: CreateContractAddress, block_number: U64, sender: &Address,
    nonce: &U256, code: &[u8],
) -> (Address, Option<H256>)
{
    let code_hash = keccak(code);
    match address_scheme {
        CreateContractAddress::FromBlockNumberSenderNonceAndCodeHash => {
            let mut buffer = [0u8; 1 + 8 + 20 + 32 + 32];
            let (lead_bytes, rest) = buffer.split_at_mut(1);
            let (block_number_bytes, rest) = rest.split_at_mut(8);
            let (sender_bytes, rest) = rest.split_at_mut(Address::len_bytes());
            let (nonce_bytes, code_hash_bytes) =
                rest.split_at_mut(H256::len_bytes());
            // In Conflux, we take block_number and CodeHash into address
            // calculation. This is required to enable us to clean
            // up unused user account in future.
            lead_bytes[0] = 0x0;
            block_number.to_little_endian(block_number_bytes);
            sender_bytes.copy_from_slice(&sender[..]);
            nonce.to_little_endian(nonce_bytes);
            code_hash_bytes.copy_from_slice(&code_hash[..]);
            // In Conflux, we use the first four bits to indicate the type of
            // the address. For contract address, the bits will be
            // set to 0x8.
            let mut h = Address::from(keccak(&buffer[..]));
            h.set_contract_type_bits();
            (h, Some(code_hash))
        }
        CreateContractAddress::FromSenderNonceAndCodeHash => {
            let mut buffer = [0u8; 1 + 20 + 32 + 32];
            // In Conflux, we append CodeHash to determine the address as well.
            // This is required to enable us to clean up unused user account in
            // future.
            buffer[0] = 0x0;
            &mut buffer[1..(1 + 20)].copy_from_slice(&sender[..]);
            nonce.to_little_endian(&mut buffer[(1 + 20)..(1 + 20 + 32)]);
            &mut buffer[(1 + 20 + 32)..].copy_from_slice(&code_hash[..]);
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
            &mut buffer[1..(1 + 20)].copy_from_slice(&sender[..]);
            &mut buffer[(1 + 20)..(1 + 20 + 32)].copy_from_slice(&salt[..]);
            &mut buffer[(1 + 20 + 32)..].copy_from_slice(&code_hash[..]);
            // In Conflux, we use the first bit to indicate the type of the
            // address. For contract address, the bits will be set to 0x8.
            let mut h = Address::from(keccak(&buffer[..]));
            h.set_contract_type_bits();
            (h, Some(code_hash))
        }
    }
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
            gas_left,
            apply_state: true,
            create_address,
            ..
        }) => {
            // Move the change of contracts_created in substate to
            // process_return.
            let address = create_address
                .expect("ExecutiveResult for Create executive should be some.");
            vm::ContractCreateResult::Created(address.clone(), gas_left)
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
#[derive(Copy, Clone, PartialEq)]
pub struct TransactOptions<T> {
    /// Enable call tracing.
    pub tracer: T,
}

impl<T> TransactOptions<T> {
    /// Create new `TransactOptions` with given tracer and VM tracer.
    pub fn new(tracer: T) -> Self { TransactOptions { tracer } }
}

impl TransactOptions<trace::ExecutiveTracer> {
    /// Creates new `TransactOptions` with default tracing and no VM tracing.
    pub fn with_tracing() -> Self {
        TransactOptions {
            tracer: trace::ExecutiveTracer::default(),
        }
    }
}

impl TransactOptions<trace::NoopTracer> {
    /// Creates new `TransactOptions` without any tracing.
    pub fn with_no_tracing() -> Self {
        TransactOptions {
            tracer: trace::NoopTracer,
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
pub struct CallCreateExecutive<'a, Substate: SubstateMngTrait> {
    context: LocalContext<'a, Substate>,
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

impl<'a, Substate: SubstateMngTrait> CallCreateExecutive<'a, Substate> {
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

        // if destination is builtin, try to execute it
        let kind = if let Some(builtin) =
            machine.builtin(&params.code_address, env.number)
        {
            trace!("CallBuiltin");
            CallCreateExecutiveKind::CallBuiltin(builtin)
        } else if let Some(internal) = machine
            .internal_contracts()
            .contract(&params.code_address, spec)
        {
            debug!(
                "CallInternalContract: address={:?} data={:?}",
                params.code_address, params.data
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
        params: &ActionParams, spec: &Spec, state: &mut dyn StateOpsTrait,
        substate: &mut dyn SubstateTrait, account_start_nonce: U256,
    ) -> DbResult<()>
    {
        if let ActionValue::Transfer(val) = params.value {
            state.transfer_balance(
                &params.sender,
                &params.address,
                &val,
                cleanup_mode(substate, &spec),
                account_start_nonce,
            )?;
        }

        Ok(())
    }

    fn transfer_exec_balance_and_init_contract(
        params: &ActionParams, spec: &Spec, state: &mut dyn StateOpsTrait,
        substate: &mut dyn SubstateTrait,
        storage_layout: Option<StorageLayout>, contract_start_nonce: U256,
    ) -> DbResult<()>
    {
        if let ActionValue::Transfer(val) = params.value {
            // It is possible to first send money to a pre-calculated
            // contract address.
            let prev_balance = state.balance(&params.address)?;
            state.sub_balance(
                &params.sender,
                &val,
                &mut cleanup_mode(substate, &spec),
            )?;
            state.new_contract_with_admin(
                &params.address,
                &params.original_sender,
                val.saturating_add(prev_balance),
                contract_start_nonce,
                storage_layout,
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
    fn process_return<State: StateTrait<Substate = Substate>>(
        mut self, result: vm::Result<GasLeft>, state: &mut State,
        parent_substate: &mut Substate, callstack: &mut CallStackInfo,
        tracer: &mut dyn Tracer<Output = trace::trace::ExecTrace>,
    ) -> vm::Result<ExecutiveResult>
    {
        let context = self.context.activate(state, callstack);
        // The post execution task in spec is completed here.
        let finalized_result = result.finalize(context);
        let executive_result = finalized_result
            .map(|result| ExecutiveResult::new(result, self.create_address));

        self.status = ExecutiveStatus::Done;

        let executive_result = vm::separate_out_db_error(executive_result)?;

        if self.context.is_create {
            tracer.prepare_trace_create_result(&executive_result);
        } else {
            tracer.prepare_trace_call_result(&executive_result);
        }

        let apply_state =
            executive_result.as_ref().map_or(false, |r| r.apply_state);
        if apply_state {
            let mut substate = self.context.substate;
            state.collect_ownership_changed(&mut substate)?; /* only fail for db error. */
            if let Some(create_address) = self.create_address {
                substate.contracts_created_mut().push(create_address);
            }

            state.discard_checkpoint();
            // See my comments in resume function.
            parent_substate.accrue(substate);
        } else {
            state.revert_to_checkpoint();
        }
        callstack.pop();

        executive_result
    }

    /// If the executive triggers a sub-call during execution, this function
    /// outputs a trap error with sub-call parameters and return point.
    fn process_trap(
        mut self, trap_err: ExecTrapError,
    ) -> ExecutiveTrapError<'a, Substate> {
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
    pub fn exec<State: StateTrait<Substate = Substate>>(
        mut self, state: &mut State, parent_substate: &mut Substate,
        callstack: &mut CallStackInfo,
        tracer: &mut dyn Tracer<Output = trace::trace::ExecTrace>,
    ) -> ExecutiveTrapResult<'a, ExecutiveResult, Substate>
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
            tracer.prepare_trace_create(&params);
        } else {
            tracer.prepare_trace_call(&params);
        }

        // Make checkpoint for this executive, callstack is always maintained
        // with checkpoint.
        state.checkpoint();
        callstack.push(self.get_recipient().clone(), is_create);

        // Pre execution: transfer value and init contract.
        let spec = self.context.spec;
        let db_result = if is_create {
            Self::transfer_exec_balance_and_init_contract(
                &params,
                spec,
                state,
                // It is a bug in the Parity version.
                &mut self.context.substate,
                Some(STORAGE_LAYOUT_REGULAR_V0),
                spec.contract_start_nonce,
            )
        } else {
            Self::transfer_exec_balance(
                &params,
                spec,
                state,
                &mut self.context.substate,
                spec.account_start_nonce,
            )
        };
        if let Err(err) = db_result {
            return TrapResult::Return(Err(err.into()));
        }

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
        self.process_output(output, state, parent_substate, callstack, tracer)
    }

    pub fn resume<State: StateTrait<Substate = Substate>>(
        mut self, result: vm::Result<ExecutiveResult>, state: &mut State,
        parent_substate: &mut Substate, callstack: &mut CallStackInfo,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> ExecutiveTrapResult<'a, ExecutiveResult, Substate>
    {
        let status =
            std::mem::replace(&mut self.status, ExecutiveStatus::Running);

        // TODO: Substate from sub-call should have been merged here by
        // specification. But we have merged it in function `process_return`.
        // If we put `substate.accrue` back to here, we can save the maintenance
        // for `parent_substate` in `exec`, `resume`, `process_return` and
        // `consume`. It will also make the implementation with
        // specification: substate is in return value and its caller's duty to
        // merge callee's substate. However, Substate is a trait
        // currently, such change will make too many functions has generic
        // parameters or trait parameter. So I put off this plan until
        // substate is no longer a trait.

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
        self.process_output(output, state, parent_substate, callstack, tracer)
    }

    #[inline]
    fn process_output<State: StateTrait<Substate = Substate>>(
        self, output: ExecTrapResult<GasLeft>, state: &mut State,
        parent_substate: &mut Substate, callstack: &mut CallStackInfo,
        tracer: &mut dyn Tracer<Output = trace::trace::ExecTrace>,
    ) -> ExecutiveTrapResult<'a, ExecutiveResult, Substate>
    {
        // Convert the `ExecTrapResult` (result of evm) to `ExecutiveTrapResult`
        // (result of self).
        match output {
            TrapResult::Return(result) => {
                TrapResult::Return(self.process_return(
                    result,
                    state,
                    parent_substate,
                    callstack,
                    tracer,
                ))
            }
            TrapResult::SubCallCreate(trap_err) => {
                TrapResult::SubCallCreate(self.process_trap(trap_err))
            }
        }
    }

    /// Execute the top call-create executive. This function handles resume
    /// traps and sub-level tracing. The caller is expected to handle
    /// current-level tracing.
    pub fn consume<State: StateTrait<Substate = Substate>>(
        self, state: &'a mut State, top_substate: &mut Substate,
        tracer: &mut dyn Tracer<Output = trace::trace::ExecTrace>,
    ) -> vm::Result<FinalizationResult>
    {
        let mut callstack = CallStackInfo::default();
        let mut executive_stack: Vec<Self> = Vec::new();

        let mut last_res =
            self.exec(state, top_substate, &mut callstack, tracer);

        loop {
            match last_res {
                TrapResult::Return(result) => {
                    let result = vm::separate_out_db_error(result)?;

                    let parent = match executive_stack.pop() {
                        Some(x) => x,
                        None => {
                            return result.map(|result| result.into());
                        }
                    };

                    let parent_substate = executive_stack
                        .last_mut()
                        .map_or(&mut *top_substate, |parent| {
                            parent.unconfirmed_substate()
                        });

                    last_res = parent.resume(
                        result,
                        state,
                        parent_substate,
                        &mut callstack,
                        tracer,
                    );
                }
                TrapResult::SubCallCreate(trap_err) => {
                    let (callee, caller) = Self::from_trap_error(trap_err);
                    executive_stack.push(caller);

                    let parent_substate = executive_stack
                        .last_mut()
                        .expect(
                            "Last executive is `caller`, it will never be None",
                        )
                        .unconfirmed_substate();

                    last_res = callee.exec(
                        state,
                        parent_substate,
                        &mut callstack,
                        tracer,
                    );
                }
            }
        }
    }

    /// Output callee executive and caller executive from trap kind error.
    pub fn from_trap_error(
        trap_err: ExecutiveTrapError<'a, Substate>,
    ) -> (Self, Self) {
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

/// The result contains more data than finalization result.
#[derive(Debug)]
pub struct ExecutiveResult {
    /// Final amount of gas left.
    pub gas_left: U256,
    /// Apply execution state changes or revert them.
    pub apply_state: bool,
    /// Return data buffer.
    pub return_data: ReturnData,
    /// Create address.
    pub create_address: Option<Address>,
}

impl Into<FinalizationResult> for ExecutiveResult {
    fn into(self) -> FinalizationResult {
        FinalizationResult {
            gas_left: self.gas_left,
            apply_state: self.apply_state,
            return_data: self.return_data,
        }
    }
}

impl ExecutiveResult {
    fn new(
        result: FinalizationResult, create_address: Option<Address>,
    ) -> Self {
        ExecutiveResult {
            gas_left: result.gas_left,
            apply_state: result.apply_state,
            return_data: result.return_data,
            create_address,
        }
    }
}

/// Trap result returned by executive.
pub type ExecutiveTrapResult<'a, T, Substate> = vm::TrapResult<
    T,
    CallCreateExecutive<'a, Substate>,
    CallCreateExecutive<'a, Substate>,
>;

pub type ExecutiveTrapError<'a, Substate> = vm::TrapError<
    CallCreateExecutive<'a, Substate>,
    CallCreateExecutive<'a, Substate>,
>;

pub type Executive<'a> = ExecutiveGeneric<'a, Substate, State>;

/// Transaction executor.
pub struct ExecutiveGeneric<
    'a,
    Substate: SubstateTrait,
    State: StateTrait<Substate = Substate>,
> {
    pub state: &'a mut State,
    env: &'a Env,
    machine: &'a Machine,
    spec: &'a Spec,
    depth: usize,
    static_flag: bool,
}

impl<
        'a,
        Substate: SubstateMngTrait,
        State: StateTrait<Substate = Substate>,
    > ExecutiveGeneric<'a, Substate, State>
{
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

    pub fn create(
        &mut self, params: ActionParams, substate: &mut Substate,
        tracer: &mut dyn Tracer<Output = trace::trace::ExecTrace>,
    ) -> vm::Result<FinalizationResult>
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
        .consume(self.state, substate, tracer);

        result
    }

    pub fn call(
        &mut self, params: ActionParams, substate: &mut Substate,
        tracer: &mut dyn Tracer<Output = trace::trace::ExecTrace>,
    ) -> vm::Result<FinalizationResult>
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
        .consume(self.state, substate, tracer);

        result
    }

    pub fn transact_virtual(
        &mut self, tx: &SignedTransaction,
    ) -> DbResult<ExecutionOutcome> {
        let sender = tx.sender();
        let balance = self.state.balance(&sender)?;
        // Give the sender a sufficient balance.
        let needed_balance = U256::MAX / U256::from(2);
        self.state.set_nonce(&sender, &tx.nonce)?;
        if balance < needed_balance {
            self.state.add_balance(
                &sender,
                &(needed_balance - balance),
                CleanupMode::NoEmpty,
                self.spec.account_start_nonce,
            )?;
        }
        let options = TransactOptions::with_tracing();
        self.transact(tx, options)
    }

    pub fn transact<T>(
        &mut self, tx: &SignedTransaction, mut options: TransactOptions<T>,
    ) -> DbResult<ExecutionOutcome>
    where T: Tracer<Output = trace::trace::ExecTrace> {
        let spec = &self.spec;
        let sender = tx.sender();
        let nonce = self.state.nonce(&sender)?;

        // Validate transaction nonce
        if tx.nonce < nonce {
            return Ok(ExecutionOutcome::NotExecutedDrop(
                TxDropError::OldNonce(nonce, tx.nonce),
            ));
        } else if tx.nonce > nonce {
            return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::InvalidNonce {
                    expected: nonce,
                    got: tx.nonce,
                },
            ));
        }

        // Validate transaction epoch height.
        let eth_like_tx = spec.cip72
            && tx.transaction_type() == TransactionType::EthereumLike;
        if !eth_like_tx
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
                    transaction_epoch_bound: self.env.transaction_epoch_bound,
                },
            ));
        }

        let base_gas_required =
            Self::gas_required_for(tx.action == Action::Create, &tx.data, spec);
        assert!(
            tx.gas >= base_gas_required.into(),
            "We have already checked the base gas requirement when we received the block."
        );
        let init_gas = tx.gas - base_gas_required;

        let balance = self.state.balance(&sender)?;
        let gas_cost = tx.gas.full_mul(tx.gas_price);

        // Check if contract will pay transaction fee for the sender.
        let mut code_address = Address::zero();
        let mut gas_sponsored = false;
        let mut storage_sponsored = false;
        match tx.action {
            Action::Call(ref address) => {
                if !address.is_valid_address() {
                    return Ok(ExecutionOutcome::NotExecutedDrop(
                        TxDropError::InvalidRecipientAddress(*address),
                    ));
                }
                if address.is_contract_address() {
                    code_address = *address;
                    if self
                        .state
                        .check_commission_privilege(&code_address, &sender)?
                    {
                        // No need to check for gas sponsor account existence.
                        gas_sponsored = gas_cost
                            <= U512::from(
                                self.state.sponsor_gas_bound(&code_address)?,
                            );
                        storage_sponsored = self
                            .state
                            .sponsor_for_collateral(&code_address)?
                            .is_some();
                    }
                }
            }
            Action::Create => {}
        };

        let mut total_cost = U512::from(tx.value);

        // Sender pays for gas when sponsor runs out of balance.
        let gas_sponsor_balance = if gas_sponsored {
            U512::from(self.state.sponsor_balance_for_gas(&code_address)?)
        } else {
            0.into()
        };
        let gas_free_of_charge =
            gas_sponsored && gas_sponsor_balance >= gas_cost;

        if !gas_free_of_charge {
            total_cost += gas_cost
        }

        // Since the Ethereum transactions do not contain storage limit. All the
        // storage limit will be regarded as u64::MAX. The EthereumLike
        // transaction should bypass the balance for storage check in
        // pre-execution.
        let minimum_drip_required_for_storage = if eth_like_tx {
            U256::zero()
        } else {
            U256::from(tx.storage_limit) * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
        };
        // No matter who pays the collateral, we only focuses on the storage
        // limit of sender.
        let total_storage_limit = if eth_like_tx {
            U256::MAX
        } else {
            self.state.collateral_for_storage(&sender)?
                + minimum_drip_required_for_storage
        };

        let storage_sponsor_balance = if storage_sponsored {
            self.state.sponsor_balance_for_collateral(&code_address)?
        } else {
            0.into()
        };

        // Find the `storage_owner` in this execution.
        let storage_owner = {
            if storage_sponsored
                && minimum_drip_required_for_storage <= storage_sponsor_balance
            {
                // sponsor will pay for collateral for storage
                code_address
            } else {
                // sender will pay for collateral for storage
                total_cost += minimum_drip_required_for_storage.into();
                sender
            }
        };

        let balance512 = U512::from(balance);
        let mut sender_intended_cost = U512::from(tx.value);
        if !gas_sponsored {
            sender_intended_cost += gas_cost
        }
        if !storage_sponsored {
            sender_intended_cost += minimum_drip_required_for_storage.into()
        };
        // Sponsor is allowed however sender do not have enough balance to pay
        // for the extra gas because sponsor has run out of balance in
        // the mean time.
        //
        // Sender is not responsible for the incident, therefore we don't fail
        // the transaction.
        if balance512 >= sender_intended_cost && balance512 < total_cost {
            return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::NotEnoughCashFromSponsor {
                    required_gas_cost: gas_cost,
                    gas_sponsor_balance,
                    required_storage_cost: minimum_drip_required_for_storage,
                    storage_sponsor_balance,
                },
            ));
        }

        let mut tx_substate = Substate::new();
        if balance512 < sender_intended_cost {
            // Sender is responsible for the insufficient balance.
            // Sub tx fee if not enough cash, and substitute all remaining
            // balance if balance is not enough to pay the tx fee
            let actual_gas_cost: U256;

            actual_gas_cost = if gas_cost > balance512 {
                balance512
            } else {
                gas_cost
            }
            .try_into()
            .unwrap();
            // We don't want to bump nonce for non-existent account when we
            // can't charge gas fee. In this case, the sender account will
            // not be created if it does not exist.
            if !self.state.exists(&sender)? {
                return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                    ToRepackError::SenderDoesNotExist,
                ));
            }
            self.state
                .inc_nonce(&sender, &self.spec.account_start_nonce)?;
            self.state.sub_balance(
                &sender,
                &actual_gas_cost,
                &mut cleanup_mode(&mut tx_substate, &spec),
            )?;

            return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::NotEnoughCash {
                    required: total_cost,
                    got: balance512,
                    actual_gas_cost: actual_gas_cost.clone(),
                    max_storage_limit_cost: minimum_drip_required_for_storage,
                },
                Executed::not_enough_balance_fee_charged(tx, &actual_gas_cost),
            ));
        } else {
            // From now on sender balance >= total_cost, even if the sender
            // account does not exist (since she may be sponsored). Transaction
            // execution is guaranteed. Note that inc_nonce() will create a
            // new account if the account does not exist.
            self.state
                .inc_nonce(&sender, &self.spec.account_start_nonce)?;
        }

        // Subtract the transaction fee from sender or contract.
        if !gas_free_of_charge {
            self.state.sub_balance(
                &sender,
                &U256::try_from(gas_cost).unwrap(),
                &mut cleanup_mode(&mut tx_substate, &spec),
            )?;
        } else {
            self.state.sub_sponsor_balance_for_gas(
                &code_address,
                &U256::try_from(gas_cost).unwrap(),
            )?;
        }

        self.state.checkpoint();
        let mut substate = Substate::new();

        let res = match tx.action {
            Action::Create => {
                let (new_address, _code_hash) = contract_address(
                    CreateContractAddress::FromSenderNonceAndCodeHash,
                    self.env.number.into(),
                    &sender,
                    &nonce,
                    &tx.data,
                );

                // For a contract address already with code, we do not allow
                // overlap the address. This should generally
                // not happen. Unless we enable account dust in
                // future. We add this check just in case it
                // helps in future.
                if self.state.is_contract_with_code(&new_address)? {
                    self.state.revert_to_checkpoint();
                    return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                        ExecutionError::VmError(vm::Error::ConflictAddress(
                            new_address.clone(),
                        )),
                        Executed::execution_error_fully_charged(tx),
                    ));
                }

                let params = ActionParams {
                    code_address: new_address,
                    code_hash: None,
                    address: new_address,
                    sender,
                    original_sender: sender,
                    storage_owner,
                    gas: init_gas,
                    gas_price: tx.gas_price,
                    value: ActionValue::Transfer(tx.value),
                    code: Some(Arc::new(tx.data.clone())),
                    data: None,
                    call_type: CallType::None,
                    params_type: vm::ParamsType::Embedded,
                };
                self.create(params, &mut substate, &mut options.tracer)
            }
            Action::Call(ref address) => {
                let params = ActionParams {
                    code_address: *address,
                    address: *address,
                    sender,
                    original_sender: sender,
                    storage_owner,
                    gas: init_gas,
                    gas_price: tx.gas_price,
                    value: ActionValue::Transfer(tx.value),
                    code: self.state.code(address)?,
                    code_hash: self.state.code_hash(address)?,
                    data: Some(tx.data.clone()),
                    call_type: CallType::Call,
                    params_type: vm::ParamsType::Separate,
                };
                self.call(params, &mut substate, &mut options.tracer)
            }
        };

        let (result, output) = {
            let res = res.and_then(|finalize_res| {
                // TODO: in fact, we don't need collect again here. But this is
                // only the performance optimization and we put it in the later
                // PR.
                self.state
                    .collect_and_settle_collateral(
                        &sender,
                        &total_storage_limit,
                        &mut substate,
                        self.spec.account_start_nonce,
                    )?
                    .into_vm_result()
                    .and(Ok(finalize_res))
            });
            let out = match &res {
                Ok(res) => {
                    self.state.discard_checkpoint();
                    tx_substate.accrue(substate);
                    res.return_data.to_vec()
                }
                Err(vm::Error::StateDbError(_)) => {
                    // The whole epoch execution fails. No need to revert state.
                    Vec::new()
                }
                Err(_) => {
                    self.state.revert_to_checkpoint();
                    Vec::new()
                }
            };
            (res, out)
        };

        let refund_receiver = if gas_free_of_charge {
            Some(code_address)
        } else {
            None
        };

        let storage_sponsor_paid = if self.spec.cip78 {
            storage_owner == code_address
        } else {
            storage_sponsored
        };

        Ok(self.finalize(
            tx,
            tx_substate,
            result,
            output,
            refund_receiver,
            storage_sponsor_paid,
            options.tracer.drain(),
        )?)
    }

    // TODO: maybe we can find a better interface for doing the suicide
    // post-processing.
    fn kill_process(
        &mut self, suicides: &HashSet<Address>,
    ) -> DbResult<Substate> {
        let mut substate = Substate::new();
        for address in suicides {
            if let Some(code_size) = self.state.code_size(address)? {
                // Only refund the code collateral when code exists.
                // If a contract suicides during creation, the code will be
                // empty.
                let code_owner =
                    self.state.code_owner(address)?.expect("code owner exists");
                substate.record_storage_release(
                    &code_owner,
                    code_collateral_units(code_size),
                );
            }

            self.state.record_storage_and_whitelist_entries_release(
                address,
                &mut substate,
            )?;
        }

        let res = self.state.settle_collateral_for_all(
            &substate,
            self.spec.account_start_nonce,
        )?;
        // The storage recycling process should never occupy new collateral.
        assert_eq!(res, CollateralCheckResult::Valid);

        for contract_address in suicides {
            let sponsor_for_gas =
                self.state.sponsor_for_gas(contract_address)?;
            let sponsor_for_collateral =
                self.state.sponsor_for_collateral(contract_address)?;
            let sponsor_balance_for_gas =
                self.state.sponsor_balance_for_gas(contract_address)?;
            let sponsor_balance_for_collateral = self
                .state
                .sponsor_balance_for_collateral(contract_address)?;

            if sponsor_for_gas.is_some() {
                self.state.add_balance(
                    sponsor_for_gas.as_ref().unwrap(),
                    &sponsor_balance_for_gas,
                    cleanup_mode(&mut substate, self.spec),
                    self.spec.account_start_nonce,
                )?;
                self.state.sub_sponsor_balance_for_gas(
                    contract_address,
                    &sponsor_balance_for_gas,
                )?;
            }
            if sponsor_for_collateral.is_some() {
                self.state.add_balance(
                    sponsor_for_collateral.as_ref().unwrap(),
                    &sponsor_balance_for_collateral,
                    cleanup_mode(&mut substate, self.spec),
                    self.spec.account_start_nonce,
                )?;
                self.state.sub_sponsor_balance_for_collateral(
                    contract_address,
                    &sponsor_balance_for_collateral,
                )?;
            }
        }

        for contract_address in suicides {
            let burnt_balance = self.state.balance(contract_address)?
                + self.state.staking_balance(contract_address)?;
            self.state.remove_contract(contract_address)?;
            self.state.subtract_total_issued(burnt_balance);
        }

        Ok(substate)
    }

    /// Finalizes the transaction (does refunds and suicides).
    fn finalize(
        &mut self, tx: &SignedTransaction, mut substate: Substate,
        result: vm::Result<FinalizationResult>, output: Bytes,
        refund_receiver: Option<Address>, storage_sponsor_paid: bool,
        trace: Vec<ExecTrace>,
    ) -> DbResult<ExecutionOutcome>
    {
        let gas_left = match result {
            Ok(FinalizationResult { gas_left, .. }) => gas_left,
            _ => 0.into(),
        };

        // gas_used is only used to estimate gas needed
        let gas_used = tx.gas - gas_left;
        // gas_left should be smaller than 1/4 of gas_limit, otherwise
        // 3/4 of gas_limit is charged.
        let charge_all = (gas_left + gas_left + gas_left) >= gas_used;
        let (gas_charged, fees_value, refund_value) = if charge_all {
            let gas_refunded = tx.gas >> 2;
            let gas_charged = tx.gas - gas_refunded;
            (
                gas_charged,
                gas_charged * tx.gas_price,
                gas_refunded * tx.gas_price,
            )
        } else {
            (gas_used, gas_used * tx.gas_price, gas_left * tx.gas_price)
        };

        if let Some(r) = refund_receiver {
            self.state.add_sponsor_balance_for_gas(&r, &refund_value)?;
        } else {
            self.state.add_balance(
                &tx.sender(),
                &refund_value,
                cleanup_mode(&mut substate, self.spec),
                self.spec.account_start_nonce,
            )?;
        };

        // perform suicides

        let subsubstate = self.kill_process(&substate.suicides())?;
        substate.accrue(subsubstate);

        // TODO should be added back after enabling dust collection
        // Should be executed once per block, instead of per transaction?
        //
        // When enabling this feature, remember to check touched set in
        // functions like "add_collateral_for_storage()" in "State"
        // struct.

        //        // perform garbage-collection
        //        let min_balance = if spec.kill_dust != CleanDustMode::Off {
        //            Some(U256::from(spec.tx_gas) * tx.gas_price)
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
                Executed::execution_error_fully_charged(tx),
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
                            substate.get_collateral_change(address);
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

                let executed = Executed {
                    gas_used,
                    gas_charged,
                    fee: fees_value,
                    gas_sponsor_paid: refund_receiver.is_some(),
                    logs: substate.logs().to_vec(),
                    contracts_created: substate.contracts_created().to_vec(),
                    storage_sponsor_paid,
                    storage_collateralized,
                    storage_released,
                    output,
                    trace,
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
