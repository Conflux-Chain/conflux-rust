// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{context::OriginInfo, InternalContractMap};
use crate::{
    evm::{FinalizationResult, Finalize},
    executive::{
        context::LocalContext,
        vm_exec::{BuiltinExec, InternalContractExec, NoopExec},
    },
    machine::Machine,
    state::{cleanup_mode, CallStackInfo},
    trace::{self, trace::ExecTrace, Tracer},
    vm::{
        self, ActionParams, ActionValue, CallType, Env, Exec, ExecTrapError,
        GasLeft, ResumeCall, ResumeCreate, ReturnData, Spec, TrapError,
        TrapResult,
    },
    vm_factory::VmFactory,
};
use cfx_state::{
    state_trait::StateOpsTrait, substate_trait::SubstateMngTrait, StateTrait,
    SubstateTrait,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, U256};
use primitives::{storage::STORAGE_LAYOUT_REGULAR_V0, StorageLayout};

pub struct CallCreateExecutive<'a, Substate: SubstateMngTrait> {
    context: LocalContext<'a, Substate>,
    factory: &'a VmFactory,
    status: ExecutiveStatus,
    create_address: Option<Address>,
    kind: CallCreateExecutiveKind,
}

enum CallCreateExecutiveKind {
    Transfer,
    CallBuiltin,
    CallInternalContract,
    ExecCall,
    ExecCreate,
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
        internal_contract_map: &'a InternalContractMap,
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
        let origin = OriginInfo::from(&params);

        // if destination is builtin, try to execute it
        let kind = if let Some(builtin) =
            machine.builtin(&params.code_address, env.number)
        {
            // Engines aren't supposed to return builtins until activation, but
            // prefer to fail rather than silently break consensus.
            if !builtin.is_active(env.number) {
                panic!("Consensus failure: engine implementation prematurely enabled built-in at {}", params.code_address);
            }
            trace!("CallBuiltin");
            CallCreateExecutiveKind::CallBuiltin
        } else if let Some(_) =
            internal_contract_map.contract(&params.code_address)
        {
            debug!(
                "CallInternalContract: address={:?} data={:?}",
                params.code_address, params.data
            );
            CallCreateExecutiveKind::CallInternalContract
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
            /* is_create */ false,
            static_flag,
            internal_contract_map,
        );
        Self {
            context,
            factory,
            status: ExecutiveStatus::Input(params),
            create_address: None,
            kind,
        }
    }

    /// Create a new create executive using raw data.
    pub fn new_create_raw(
        params: ActionParams, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, factory: &'a VmFactory, depth: usize,
        static_flag: bool, internal_contract_map: &'a InternalContractMap,
    ) -> Self
    {
        trace!(
            "Executive::create(params={:?}) self.env={:?}, static={}",
            params,
            env,
            static_flag
        );

        let contract_in_creation = params.code_address;
        let origin = OriginInfo::from(&params);

        let substate = Substate::new();

        let kind = CallCreateExecutiveKind::ExecCreate;

        let context = LocalContext::new(
            env,
            machine,
            spec,
            depth,
            origin,
            substate,
            /* is_create */ true,
            static_flag,
            internal_contract_map,
        );

        Self {
            context,
            status: ExecutiveStatus::Input(params),
            factory,
            create_address: Some(contract_in_creation),
            kind,
        }
    }

    /// Output callee executive and caller executive from trap kind error.
    pub fn from_trap_error(
        trap_err: ExecutiveTrapError<'a, Substate>,
    ) -> (Self, Self) {
        match trap_err {
            TrapError::Call(params, parent) => (
                CallCreateExecutive::new_call_raw(
                    params,
                    parent.context.env,
                    parent.context.machine,
                    parent.context.spec,
                    parent.factory,
                    parent.context.depth + 1,
                    parent.context.static_flag,
                    parent.context.internal_contract_map,
                ),
                parent,
            ),
            TrapError::Create(params, parent) => (
                CallCreateExecutive::new_create_raw(
                    params,
                    parent.context.env,
                    parent.context.machine,
                    parent.context.spec,
                    parent.factory,
                    parent.context.depth + 1,
                    parent.context.static_flag,
                    parent.context.internal_contract_map,
                ),
                parent,
            ),
        }
    }

    /// Returns the substate in this executive
    pub fn unconfirmed_substate(&mut self) -> &mut Substate {
        &mut self.context.substate
    }

    /// Get the recipient of this executive. The receipent is the address whose
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

    /// If the executive triggers an sub-call during execution, this function
    /// will put return point and out put a trap error.
    fn handle_trap_err(
        mut self, trap_err: ExecTrapError,
        _tracer: &mut dyn Tracer<Output = trace::trace::ExecTrace>,
    ) -> ExecutiveTrapError<'a, Substate>
    {
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

    /// If the executive triggers an return during execution, this function will
    /// put return point and out put a trap error.
    fn process_return<State: StateTrait<Substate = Substate>>(
        mut self, result: vm::Result<GasLeft>, state: &mut State,
        substate: &mut Substate, callstack: &mut CallStackInfo,
        tracer: &mut dyn Tracer<Output = trace::trace::ExecTrace>,
    ) -> vm::Result<ExecutiveResult>
    {
        let context = self.context.activate(state, callstack);
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

        let apply_state = match &executive_result {
            Ok(ExecutiveResult {
                apply_state: true, ..
            }) => true,
            _ => false,
        };

        if apply_state {
            // The following line will only fail for db error.
            state.collect_ownership_changed(&mut self.context.substate)?;
            if let Some(create_address) = self.create_address {
                self.context
                    .substate
                    .contracts_created_mut()
                    .push(create_address);
            }

            state.discard_checkpoint();
            substate.accrue(self.context.substate);
        } else {
            state.revert_to_checkpoint();
        }
        callstack.pop();

        executive_result
    }

    /// Execute the executive. If a sub-call/create action is required, a
    /// resume trap error is returned. The caller is then expected to call
    /// `resume_call` or `resume_create` to continue the execution.
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

        Self::check_static_flag(&params, self.context.static_flag, is_create)
            .expect("check_static_flag should always success here");

        state.checkpoint();
        callstack.push(self.get_recipient().clone(), is_create);

        // Pre Execution
        let spec = self.context.spec;
        let db_result = if is_create {
            tracer.prepare_trace_create(&params);
            Self::transfer_exec_balance_and_init_contract(
                &params,
                spec,
                state,
                &mut self.context.substate,
                Some(STORAGE_LAYOUT_REGULAR_V0),
                spec.contract_start_nonce(self.context.env.number),
            )
        } else {
            tracer.prepare_trace_call(&params);
            Self::transfer_exec_balance(
                &params,
                spec,
                state,
                &mut self.context.substate,
                spec.account_start_nonce(self.context.env.number),
            )
        };

        if let Err(err) = db_result {
            return TrapResult::Return(Err(err.into()));
        }

        let exec: Box<dyn Exec> = match self.kind {
            CallCreateExecutiveKind::Transfer => {
                Box::new(NoopExec { gas: params.gas })
            }
            CallCreateExecutiveKind::CallBuiltin => {
                let builtin = self.context.machine.builtin(&params.code_address, self.context.env.number).expect("Builtin is_some is checked when creating this kind in new_call_raw; qed");
                Box::new(BuiltinExec { builtin, params })
            }
            CallCreateExecutiveKind::CallInternalContract => {
                let contract =  self.context.internal_contract_map.contract(&params.code_address).expect("InternalContract is_some is checked when creating this kind in new_call_raw; qed");
                Box::new(InternalContractExec { contract, params })
            }
            CallCreateExecutiveKind::ExecCall => {
                let factory = self.context.machine.vm_factory();
                factory.create(params, self.context.spec, self.context.depth)
            }
            CallCreateExecutiveKind::ExecCreate => {
                debug!(
                    "CallCreateExecutiveKind::ExecCreate: contract_addr = {:?}",
                    params.address
                );

                let factory = self.context.machine.vm_factory();
                factory.create(params, self.context.spec, self.context.depth)
            }
        };

        let mut context = self.context.activate(state, callstack);
        match exec.exec(&mut context, tracer) {
            TrapResult::Return(result) => {
                TrapResult::Return(self.process_return(
                    result,
                    state,
                    parent_substate,
                    callstack,
                    tracer,
                ))
            }
            TrapResult::SubCallCreate(trap_err) => TrapResult::SubCallCreate(
                self.handle_trap_err(trap_err, tracer),
            ),
        }
    }

    pub fn resume<State: StateTrait<Substate = Substate>>(
        mut self, result: vm::Result<ExecutiveResult>, state: &mut State,
        substate: &mut Substate, callstack: &mut CallStackInfo,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> ExecutiveTrapResult<'a, ExecutiveResult, Substate>
    {
        let status =
            std::mem::replace(&mut self.status, ExecutiveStatus::Running);
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
        match exec.exec(&mut context, tracer) {
            TrapResult::Return(result) => TrapResult::Return(
                self.process_return(result, state, substate, callstack, tracer),
            ),
            TrapResult::SubCallCreate(trap_err) => TrapResult::SubCallCreate(
                self.handle_trap_err(trap_err, tracer),
            ),
        }
    }

    /// Execute and consume the current executive. This function handles resume
    /// traps and sub-level tracing. The caller is expected to handle
    /// current-level tracing.
    pub fn consume<State: StateTrait<Substate = Substate>>(
        self, state: &'a mut State, top_substate: &mut Substate,
        tracer: &mut dyn Tracer<Output = trace::trace::ExecTrace>,
    ) -> vm::Result<FinalizationResult>
    {
        let mut address_stack = CallStackInfo::default();
        let mut last_res =
            self.exec(state, top_substate, &mut address_stack, tracer);

        let mut executive_stack: Vec<CallCreateExecutive<'a, Substate>> =
            Vec::new();

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
                        &mut address_stack,
                        tracer,
                    );
                }
                TrapResult::SubCallCreate(trap_err) => {
                    let (callee, caller) = Self::from_trap_error(trap_err);
                    executive_stack.push(caller);

                    let parent_substate = executive_stack
                        .last_mut().expect("Last executive is `caller`, it will neven be empty").unconfirmed_substate();
                    last_res = callee.exec(
                        state,
                        parent_substate,
                        &mut address_stack,
                        tracer,
                    );
                }
            }
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
