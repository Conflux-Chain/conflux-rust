// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    context::{Context, OriginInfo, OutputPolicy},
    Executed, ExecutionError, InternalContractMap,
};
use crate::{
    bytes::{Bytes, BytesRef},
    evm::{FinalizationResult, Finalize},
    executive::{
        executed::{ExecutionOutcome, ToRepackError},
        TxDropError,
    },
    hash::keccak,
    machine::Machine,
    state::{
        CallStackInfo, CleanupMode, CollateralCheckResult, State, Substate,
    },
    statedb::Result as DbResult,
    verification::VerificationConfig,
    vm::{
        self, ActionParams, ActionValue, CallType, CreateContractAddress, Env,
        ExecTrapResult, GasLeft, ResumeCall, ResumeCreate, ReturnData, Spec,
        TrapError,
    },
    vm_factory::VmFactory,
};
use cfx_parameters::staking::*;
use cfx_types::{address_util::AddressUtil, Address, H256, U256, U512};
use primitives::{
    receipt::StorageChange, storage::STORAGE_LAYOUT_REGULAR_V0,
    transaction::Action, SignedTransaction, StorageLayout,
};
use std::{
    cell::RefCell,
    collections::HashSet,
    convert::{TryFrom, TryInto},
    rc::Rc,
    sync::Arc,
};

/// Returns new address created from address, nonce, and code hash
pub fn contract_address(
    address_scheme: CreateContractAddress, sender: &Address, nonce: &U256,
    code: &[u8],
) -> (Address, Option<H256>)
{
    match address_scheme {
        CreateContractAddress::FromSenderNonceAndCodeHash => {
            let mut buffer = [0u8; 1 + 20 + 32 + 32];
            // In Conflux, we append CodeHash to determine the address as well.
            // This is required to enable us to clean up unused user account in
            // future.
            let code_hash = keccak(code);
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
            let code_hash = keccak(code);
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
    result: vm::Result<FinalizationResult>,
) -> vm::MessageCallResult {
    match result {
        Ok(FinalizationResult {
            gas_left,
            return_data,
            apply_state: true,
        }) => vm::MessageCallResult::Success(gas_left, return_data),
        Ok(FinalizationResult {
            gas_left,
            return_data,
            apply_state: false,
        }) => vm::MessageCallResult::Reverted(gas_left, return_data),
        _ => vm::MessageCallResult::Failed,
    }
}

/// Convert a finalization result into a VM contract create result.
pub fn into_contract_create_result(
    result: vm::Result<FinalizationResult>, address: &Address,
    substate: &mut Substate,
) -> vm::ContractCreateResult
{
    match result {
        Ok(FinalizationResult {
            gas_left,
            apply_state: true,
            ..
        }) => {
            substate.contracts_created.push(address.clone());
            vm::ContractCreateResult::Created(address.clone(), gas_left)
        }
        Ok(FinalizationResult {
            gas_left,
            apply_state: false,
            return_data,
        }) => vm::ContractCreateResult::Reverted(gas_left, return_data),
        _ => vm::ContractCreateResult::Failed,
    }
}

enum CallCreateExecutiveKind {
    Transfer(ActionParams),
    CallBuiltin(ActionParams),
    CallInternalContract(ActionParams, Substate),
    ExecCall(ActionParams, Substate),
    ExecCreate(ActionParams, Substate),
    ResumeCall(OriginInfo, Box<dyn ResumeCall>, Substate),
    ResumeCreate(OriginInfo, Box<dyn ResumeCreate>, Substate),
    // A temporally status to handle the ownership check in rust.
    // It should only appear in function `enact_output`.
    Moved,
}

pub struct CallCreateExecutive<'a> {
    env: &'a Env,
    machine: &'a Machine,
    spec: &'a Spec,
    factory: &'a VmFactory,
    depth: usize,
    stack_depth: usize,
    static_flag: bool,
    is_create: bool,
    gas: U256,
    kind: CallCreateExecutiveKind,
    internal_contract_map: &'a InternalContractMap,
}

impl<'a> CallCreateExecutive<'a> {
    /// Create a new call executive using raw data.
    pub fn new_call_raw(
        params: ActionParams, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, factory: &'a VmFactory, depth: usize,
        stack_depth: usize, parent_static_flag: bool,
        internal_contract_map: &'a InternalContractMap,
        contracts_in_callstack: Rc<RefCell<CallStackInfo>>,
    ) -> Self
    {
        trace!(
            "Executive::call(params={:?}) self.env={:?}, parent_static={}",
            params,
            env,
            parent_static_flag
        );

        let gas = params.gas;
        let static_flag =
            parent_static_flag || params.call_type == CallType::StaticCall;

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
            CallCreateExecutiveKind::CallBuiltin(params)
        } else if let Some(_) =
            internal_contract_map.contract(&params.code_address)
        {
            debug!(
                "CallInternalContract: address={:?} data={:?}",
                params.code_address, params.data
            );
            CallCreateExecutiveKind::CallInternalContract(
                params,
                Substate::with_call_stack(contracts_in_callstack),
            )
        } else {
            if params.code.is_some() {
                trace!("ExecCall");
                CallCreateExecutiveKind::ExecCall(
                    params,
                    Substate::with_call_stack(contracts_in_callstack),
                )
            } else {
                trace!("Transfer");
                CallCreateExecutiveKind::Transfer(params)
            }
        };
        Self {
            env,
            machine,
            spec,
            factory,
            depth,
            stack_depth,
            static_flag,
            kind,
            gas,
            is_create: false,
            internal_contract_map,
        }
    }

    /// Create a new create executive using raw data.
    pub fn new_create_raw(
        params: ActionParams, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, factory: &'a VmFactory, depth: usize,
        stack_depth: usize, static_flag: bool,
        internal_contract_map: &'a InternalContractMap,
        contracts_in_callstack: Rc<RefCell<CallStackInfo>>,
    ) -> Self
    {
        trace!(
            "Executive::create(params={:?}) self.env={:?}, static={}",
            params,
            env,
            static_flag
        );

        let gas = params.gas;

        let kind = CallCreateExecutiveKind::ExecCreate(
            params,
            Substate::with_call_stack(contracts_in_callstack),
        );

        Self {
            env,
            machine,
            spec,
            factory,
            depth,
            stack_depth,
            static_flag,
            kind,
            gas,
            is_create: true,
            internal_contract_map,
        }
    }

    /// If this executive contains an unconfirmed substate, returns a mutable
    /// reference to it.
    pub fn unconfirmed_substate(&mut self) -> Option<&mut Substate> {
        match self.kind {
            CallCreateExecutiveKind::ExecCall(_, ref mut unsub) => Some(unsub),
            CallCreateExecutiveKind::ExecCreate(_, ref mut unsub) => {
                Some(unsub)
            }
            CallCreateExecutiveKind::ResumeCreate(_, _, ref mut unsub) => {
                Some(unsub)
            }
            CallCreateExecutiveKind::ResumeCall(_, _, ref mut unsub) => {
                Some(unsub)
            }
            CallCreateExecutiveKind::CallInternalContract(_, ref mut unsub) => {
                Some(unsub)
            }
            CallCreateExecutiveKind::Transfer(..)
            | CallCreateExecutiveKind::CallBuiltin(..) => None,
            CallCreateExecutiveKind::Moved => {
                panic!("A temporally status in function `enact_output`, should not appear during execution.");
            }
        }
    }

    pub fn get_recipient(&self) -> &Address {
        match &self.kind {
            CallCreateExecutiveKind::ExecCall(params, _)
            | CallCreateExecutiveKind::ExecCreate(params, _)
            | CallCreateExecutiveKind::CallInternalContract(params, _)
            | CallCreateExecutiveKind::Transfer(params)
            | CallCreateExecutiveKind::CallBuiltin(params) => &params.address,
            CallCreateExecutiveKind::ResumeCreate(origin, ..)
            | CallCreateExecutiveKind::ResumeCall(origin, ..) => {
                origin.recipient()
            }
            CallCreateExecutiveKind::Moved => {
                panic!("A temporally status in function `enact_output`, should not appear during execution.");
            }
        }
    }

    fn check_static_flag(
        params: &ActionParams, static_flag: bool, is_create: bool,
    ) -> vm::Result<()> {
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
        if let ActionValue::Transfer(val) = params.value {
            state.transfer_balance(
                &params.sender,
                &params.address,
                &val,
                substate.to_cleanup_mode(&spec),
            )?;
        }

        Ok(())
    }

    fn transfer_exec_balance_and_init_contract(
        params: &ActionParams, spec: &Spec, state: &mut State,
        substate: &mut Substate, storage_layout: Option<StorageLayout>,
    ) -> vm::Result<()>
    {
        if let ActionValue::Transfer(val) = params.value {
            // It is possible to first send money to a pre-calculated
            // contract address.
            let prev_balance = state.balance(&params.address)?;
            state.sub_balance(
                &params.sender,
                &val,
                &mut substate.to_cleanup_mode(&spec),
            )?;
            state.new_contract_with_admin(
                &params.address,
                &params.original_sender,
                val.saturating_add(prev_balance),
                state.contract_start_nonce(),
                storage_layout,
            )?;
        } else {
            // In contract creation, the `params.value` should never be
            // `Apparent`.
            unreachable!();
        }

        Ok(())
    }

    fn enact_output(
        mut self, output: ExecTrapResult<FinalizationResult>,
        origin: OriginInfo, state: &mut State, substate: &mut Substate,
        mut unconfirmed_substate: Substate,
    ) -> ExecutiveTrapResult<'a, FinalizationResult>
    {
        // You should avoid calling functions for self here, since `self.kind`
        // is moved temporally.

        // TODO: `ExecTrapResult` is a nested `Result`. It is ambiguous to deal
        // with result like `Ok(Err(e))`. I plan to rename it in a separated PR.

        // In case the execution is done and the state will be reverted, there
        // will be no need be collect ownership.

        // We check it here only for performance. Even if we regard all the case
        // as ``need_collect_ownership'', the result should be same. But we
        // don't want to execute heavy function collect_ownership_changed if it
        // is unnecessary.
        let need_collect_ownership = match &output {
            Ok(Err(_))
            | Ok(Ok(FinalizationResult {
                apply_state: false, ..
            })) => false,
            _ => true,
        };
        let output = if need_collect_ownership {
            match state.collect_ownership_changed(&mut unconfirmed_substate) {
                Ok(_) => output,
                Err(db_err) => Ok(Err(db_err.into())),
            }
        } else {
            output
        };

        match output {
            Ok(result) => match result {
                // The whole epoch execution fails. No need to revert state.
                Err(vm::Error::StateDbError(_)) => Ok(result),
                Err(_)
                | Ok(FinalizationResult {
                    apply_state: false, ..
                }) => {
                    state.revert_to_checkpoint();
                    Ok(result)
                }
                Ok(_) => {
                    state.discard_checkpoint();
                    substate.accrue(unconfirmed_substate);

                    Ok(result)
                }
            },
            Err(trap_err) => match trap_err {
                TrapError::Call(subparams, resume) => {
                    self.kind = CallCreateExecutiveKind::ResumeCall(
                        origin,
                        resume,
                        unconfirmed_substate,
                    );
                    Err(TrapError::Call(subparams, self))
                }
                TrapError::Create(subparams, address, resume) => {
                    self.kind = CallCreateExecutiveKind::ResumeCreate(
                        origin,
                        resume,
                        unconfirmed_substate,
                    );
                    Err(TrapError::Create(subparams, address, self))
                }
            },
        }
    }

    /// Creates `Context` from `Executive`.
    fn as_context<'any>(
        state: &'any mut State, env: &'any Env, machine: &'any Machine,
        spec: &'any Spec, depth: usize, stack_depth: usize, static_flag: bool,
        origin: &'any OriginInfo, substate: &'any mut Substate,
        output: OutputPolicy, internal_contract_map: &'any InternalContractMap,
    ) -> Context<'any>
    {
        Context::new(
            state,
            env,
            machine,
            spec,
            depth,
            stack_depth,
            origin,
            substate,
            output,
            static_flag,
            internal_contract_map,
        )
    }

    /// Execute the executive. If a sub-call/create action is required, a
    /// resume trap error is returned. The caller is then expected to call
    /// `resume_call` or `resume_create` to continue the execution.
    pub fn exec(
        mut self, state: &mut State, substate: &mut Substate,
    ) -> ExecutiveTrapResult<'a, FinalizationResult> {
        match self.kind {
            CallCreateExecutiveKind::Transfer(ref params) => {
                assert!(!self.is_create);

                let mut inner = || {
                    Self::check_static_flag(
                        params,
                        self.static_flag,
                        self.is_create,
                    )?;
                    Self::transfer_exec_balance(
                        params, self.spec, state, substate,
                    )?;

                    Ok(FinalizationResult {
                        gas_left: params.gas,
                        return_data: ReturnData::empty(),
                        apply_state: true,
                    })
                };

                Ok(inner())
            }

            CallCreateExecutiveKind::CallBuiltin(ref params) => {
                assert!(!self.is_create);

                let mut inner = || {
                    let builtin = self.machine.builtin(&params.code_address, self.env.number).expect("Builtin is_some is checked when creating this kind in new_call_raw; qed");

                    Self::check_static_flag(
                        &params,
                        self.static_flag,
                        self.is_create,
                    )?;
                    state.checkpoint();
                    Self::transfer_exec_balance(
                        &params, self.spec, state, substate,
                    )?;

                    let default = [];
                    let data = if let Some(ref d) = params.data {
                        d as &[u8]
                    } else {
                        &default as &[u8]
                    };

                    let cost = builtin.cost(data);
                    if cost <= params.gas {
                        let mut builtin_out_buffer = Vec::new();
                        let result = {
                            let mut builtin_output =
                                BytesRef::Flexible(&mut builtin_out_buffer);
                            builtin.execute(data, &mut builtin_output)
                        };
                        if let Err(e) = result {
                            state.revert_to_checkpoint();

                            Err(e.into())
                        } else {
                            state.discard_checkpoint();

                            let out_len = builtin_out_buffer.len();
                            Ok(FinalizationResult {
                                gas_left: params.gas - cost,
                                return_data: ReturnData::new(
                                    builtin_out_buffer,
                                    0,
                                    out_len,
                                ),
                                apply_state: true,
                            })
                        }
                    } else {
                        state.revert_to_checkpoint();
                        Err(vm::Error::OutOfGas)
                    }
                };

                Ok(inner())
            }

            CallCreateExecutiveKind::CallInternalContract(
                params,
                mut unconfirmed_substate,
            ) => {
                assert!(!self.is_create);

                let static_flag = self.static_flag;
                let is_create = self.is_create;
                let spec = self.spec;
                let internal_contract_map = self.internal_contract_map;

                let mut pre_inner = || {
                    Self::check_static_flag(
                        &params,
                        static_flag,
                        is_create,
                    )?;
                    state.checkpoint();
                    Self::transfer_exec_balance(
                        &params, spec, state, substate,
                    )?;
                    Ok(())
                };

                match pre_inner() {
                    Ok(()) => (),
                    Err(err) => return Ok(Err(err)),
                }

                let origin = OriginInfo::from(&params);

                let result = if params.call_type != CallType::Call {
                    Err(vm::Error::InternalContract(
                        "Incorrect call type.",
                    ))
                } else if let Some(contract) =
                    internal_contract_map.contract(&params.code_address)
                {
                    contract.execute(
                        &params,
                        &spec,
                        state,
                        &mut unconfirmed_substate,
                    )
                } else {
                    Ok(GasLeft::Known(params.gas))
                };
                debug!("Internal Call Result: {:?}", result);

                let context = Self::as_context(
                    state,
                    self.env,
                    self.machine,
                    self.spec,
                    self.depth,
                    self.stack_depth,
                    self.static_flag,
                    &origin,
                    &mut unconfirmed_substate,
                    OutputPolicy::Return,
                    self.internal_contract_map,
                );
                let out = Ok(result.finalize(context));
                self.kind = CallCreateExecutiveKind::Moved;
                self.enact_output(
                    out,
                    origin,
                    state,
                    substate,
                    unconfirmed_substate,
                )
            }

            CallCreateExecutiveKind::ExecCall(
                params,
                mut unconfirmed_substate,
            ) => {
                assert!(!self.is_create);

                {
                    let static_flag = self.static_flag;
                    let is_create = self.is_create;
                    let spec = self.spec;

                    let mut pre_inner = || {
                        Self::check_static_flag(
                            &params,
                            static_flag,
                            is_create,
                        )?;
                        state.checkpoint();
                        Self::transfer_exec_balance(
                            &params, spec, state, substate,
                        )?;
                        Ok(())
                    };

                    match pre_inner() {
                        Ok(()) => (),
                        Err(err) => return Ok(Err(err)),
                    }
                }

                let origin = OriginInfo::from(&params);
                let exec = self.factory.create(params, self.spec, self.depth);

                let out = {
                    let mut context = Self::as_context(
                        state,
                        self.env,
                        self.machine,
                        self.spec,
                        self.depth,
                        self.stack_depth,
                        self.static_flag,
                        &origin,
                        &mut unconfirmed_substate,
                        OutputPolicy::Return,
                        self.internal_contract_map,
                    );
                    match exec.exec(&mut context) {
                        Ok(val) => Ok(val.finalize(context)),
                        Err(err) => Err(err),
                    }
                };

                self.kind = CallCreateExecutiveKind::Moved;
                self.enact_output(
                    out,
                    origin,
                    state,
                    substate,
                    unconfirmed_substate,
                )
            }

            CallCreateExecutiveKind::ExecCreate(
                params,
                mut unconfirmed_substate,
            ) => {
                debug!(
                    "CallCreateExecutiveKind::ExecCreate: contract_addr = {:?}",
                    params.address
                );
                assert!(self.is_create);

                {
                    let static_flag = self.static_flag;
                    let is_create = self.is_create;
                    let spec = self.spec;

                    let mut pre_inner = || {
                        Self::check_static_flag(
                            &params,
                            static_flag,
                            is_create,
                        )?;
                        state.checkpoint();
                        Self::transfer_exec_balance_and_init_contract(
                            &params,
                            spec,
                            state,
                            substate,
                            Some(STORAGE_LAYOUT_REGULAR_V0),
                        )?;
                        Ok(())
                    };

                    match pre_inner() {
                        Ok(()) => (),
                        Err(err) => return Ok(Err(err)),
                    }
                }

                let origin = OriginInfo::from(&params);
                let exec = self.factory.create(params, self.spec, self.depth);

                let out = {
                    let mut context = Self::as_context(
                        state,
                        self.env,
                        self.machine,
                        self.spec,
                        self.depth,
                        self.stack_depth,
                        self.static_flag,
                        &origin,
                        &mut unconfirmed_substate,
                        OutputPolicy::InitContract,
                        self.internal_contract_map,
                    );
                    match exec.exec(&mut context) {
                        Ok(val) => Ok(val.finalize(context)),
                        Err(err) => Err(err),
                    }
                };

                self.kind = CallCreateExecutiveKind::Moved;
                self.enact_output(
                    out,
                    origin,
                    state,
                    substate,
                    unconfirmed_substate,
                )
            }

            CallCreateExecutiveKind::ResumeCall(..)
            | CallCreateExecutiveKind::ResumeCreate(..) => {
                panic!("This executive has already been executed once.")
            }

            CallCreateExecutiveKind::Moved => {
                panic!("A temporally status in function `enact_output`, should not appear during execution.")
            }
        }
    }

    /// Resume execution from a call trap previously trapped by `exec'.
    pub fn resume_call(
        mut self, result: vm::MessageCallResult, state: &mut State,
        substate: &mut Substate,
    ) -> ExecutiveTrapResult<'a, FinalizationResult>
    {
        match self.kind {
            CallCreateExecutiveKind::ResumeCall(
                origin,
                resume,
                mut unconfirmed_substate,
            ) => {
                let out = {
                    let exec = resume.resume_call(result);

                    let mut context = Self::as_context(
                        state,
                        self.env,
                        self.machine,
                        self.spec,
                        self.depth,
                        self.stack_depth,
                        self.static_flag,
                        &origin,
                        &mut unconfirmed_substate,
                        if self.is_create {
                            OutputPolicy::InitContract
                        } else {
                            OutputPolicy::Return
                        },
                        self.internal_contract_map,
                    );
                    match exec.exec(&mut context) {
                        Ok(val) => Ok(val.finalize(context)),
                        Err(err) => Err(err),
                    }
                };

                self.kind = CallCreateExecutiveKind::Moved;
                self.enact_output(
                    out,
                    origin,
                    state,
                    substate,
                    unconfirmed_substate,
                )
            }
            CallCreateExecutiveKind::ResumeCreate(..) => {
                panic!("Resumable as create, but called resume_call")
            }
            CallCreateExecutiveKind::Transfer(..)
            | CallCreateExecutiveKind::CallBuiltin(..)
            | CallCreateExecutiveKind::CallInternalContract(..)
            | CallCreateExecutiveKind::ExecCall(..)
            | CallCreateExecutiveKind::ExecCreate(..) => {
                panic!("Not resumable")
            }
            CallCreateExecutiveKind::Moved => {
                panic!("A temporally status in function `enact_output`, should not appear during execution.")
            }
        }
    }

    /// Resume execution from a create trap previously trapped by `exec`.
    pub fn resume_create(
        mut self, result: vm::ContractCreateResult, state: &mut State,
        substate: &mut Substate,
    ) -> ExecutiveTrapResult<'a, FinalizationResult>
    {
        match self.kind {
            CallCreateExecutiveKind::ResumeCreate(
                origin,
                resume,
                mut unconfirmed_substate,
            ) => {
                let out = {
                    let exec = resume.resume_create(result);

                    let mut context = Self::as_context(
                        state,
                        self.env,
                        self.machine,
                        self.spec,
                        self.depth,
                        self.stack_depth,
                        self.static_flag,
                        &origin,
                        &mut unconfirmed_substate,
                        if self.is_create {
                            OutputPolicy::InitContract
                        } else {
                            OutputPolicy::Return
                        },
                        self.internal_contract_map,
                    );
                    match exec.exec(&mut context) {
                        Ok(val) => Ok(val.finalize(context)),
                        Err(err) => Err(err),
                    }
                };

                self.kind = CallCreateExecutiveKind::Moved;
                self.enact_output(
                    out,
                    origin,
                    state,
                    substate,
                    unconfirmed_substate,
                )
            }
            CallCreateExecutiveKind::ResumeCall(..) => {
                panic!("Resumable as call, but called resume_create")
            }
            CallCreateExecutiveKind::Transfer(..)
            | CallCreateExecutiveKind::CallBuiltin(..)
            | CallCreateExecutiveKind::CallInternalContract(..)
            | CallCreateExecutiveKind::ExecCall(..)
            | CallCreateExecutiveKind::ExecCreate(..) => {
                panic!("Not resumable")
            }
            CallCreateExecutiveKind::Moved => {
                panic!("A temporally status in function `enact_output`, should not appear during execution.")
            }
        }
    }

    /// Execute and consume the current executive. This function handles resume
    /// traps and sub-level tracing. The caller is expected to handle
    /// current-level tracing.
    pub fn consume(
        self, state: &mut State, top_substate: &mut Substate,
    ) -> vm::Result<FinalizationResult> {
        let mut last_res =
            Some((false, self.gas, self.exec(state, top_substate)));

        let mut callstack: Vec<(Option<Address>, CallCreateExecutive<'a>)> =
            Vec::new();

        loop {
            match last_res {
                None => {
                    let current = callstack.pop();
                    top_substate.pop_callstack();
                    match current {
                        Some((_, exec)) => {
                            let second_last = callstack.last_mut();
                            let parent_substate = match second_last {
                                Some((_, ref mut second_last)) => second_last.unconfirmed_substate().expect("Current stack value is created from second last item; second last item must be call or create; qed"),
                                None => top_substate,
                            };

                            last_res = Some((exec.is_create, exec.gas, exec.exec(state, parent_substate)));
                        }
                        None => panic!("When callstack only had one item and it was executed, this function would return; callstack never reaches zero item; qed"),
                    }
                }
                Some((is_create, _gas, Ok(val))) => {
                    let current = callstack.pop();
                    top_substate.pop_callstack();

                    match current {
                        Some((address, mut exec)) => {
                            if is_create {
                                let address = address.expect("If the last executed status was from a create executive, then the destination address was pushed to the callstack; address is_some if it is_create; qed");

                                let second_last = callstack.last_mut();
                                let parent_substate = match second_last {
                                    Some((_, ref mut second_last)) => second_last.unconfirmed_substate().expect("Current stack value is created from second last item; second last item must be call or create; qed"),
                                    None => top_substate,
                                };

                                let contract_create_result = into_contract_create_result(val, &address, exec.unconfirmed_substate().expect("Executive is resumed from a create; it has an unconfirmed substate; qed"));
                                last_res = Some((
                                    exec.is_create,
                                    exec.gas,
                                    exec.resume_create(
                                        contract_create_result,
                                        state,
                                        parent_substate,
                                    ),
                                ));
                            } else {
                                let second_last = callstack.last_mut();
                                let parent_substate = match second_last {
                                    Some((_, ref mut second_last)) => second_last.unconfirmed_substate().expect("Current stack value is created from second last item; second last item must be call or create; qed"),
                                    None => top_substate,
                                };

                                last_res = Some((
                                    exec.is_create,
                                    exec.gas,
                                    exec.resume_call(
                                        into_message_call_result(val),
                                        state,
                                        parent_substate,
                                    ),
                                ));
                            }
                        }
                        None => return val,
                    }
                }
                Some((_, _, Err(TrapError::Call(subparams, resume)))) => {
                    let sub_exec = CallCreateExecutive::new_call_raw(
                        subparams,
                        resume.env,
                        resume.machine,
                        resume.spec,
                        resume.factory,
                        resume.depth + 1,
                        resume.stack_depth,
                        resume.static_flag,
                        resume.internal_contract_map,
                        top_substate.contracts_in_callstack.clone(),
                    );

                    top_substate.push_callstack(resume.get_recipient().clone());
                    callstack.push((None, resume));
                    top_substate
                        .push_callstack(sub_exec.get_recipient().clone());
                    callstack.push((None, sub_exec));
                    last_res = None;
                }
                Some((
                    _,
                    _,
                    Err(TrapError::Create(subparams, address, resume)),
                )) => {
                    let sub_exec = CallCreateExecutive::new_create_raw(
                        subparams,
                        resume.env,
                        resume.machine,
                        resume.spec,
                        resume.factory,
                        resume.depth + 1,
                        resume.stack_depth,
                        resume.static_flag,
                        resume.internal_contract_map,
                        top_substate.contracts_in_callstack.clone(),
                    );

                    top_substate.push_callstack(resume.get_recipient().clone());
                    callstack.push((Some(address), resume));
                    top_substate
                        .push_callstack(sub_exec.get_recipient().clone());
                    callstack.push((None, sub_exec));
                    last_res = None;
                }
            }
        }
    }
}

/// Trap result returned by executive.
pub type ExecutiveTrapResult<'a, T> =
    vm::TrapResult<T, CallCreateExecutive<'a>, CallCreateExecutive<'a>>;

/// Trap error for executive.
//pub type ExecutiveTrapError<'a> =
//    vm::TrapError<CallCreateExecutive<'a>, CallCreateExecutive<'a>>;

/// Transaction executor.
pub struct Executive<'a> {
    pub state: &'a mut State,
    env: &'a Env,
    machine: &'a Machine,
    spec: &'a Spec,
    depth: usize,
    static_flag: bool,
    internal_contract_map: &'a InternalContractMap,
}

impl<'a> Executive<'a> {
    /// Basic constructor.
    pub fn new(
        state: &'a mut State, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, internal_contract_map: &'a InternalContractMap,
    ) -> Self
    {
        Executive {
            state,
            env,
            machine,
            spec,
            depth: 0,
            static_flag: false,
            internal_contract_map,
        }
    }

    /// Populates executive from parent properties. Increments executive depth.
    pub fn from_parent(
        state: &'a mut State, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, parent_depth: usize, static_flag: bool,
        internal_contract_map: &'a InternalContractMap,
    ) -> Self
    {
        Executive {
            state,
            env,
            machine,
            spec,
            depth: parent_depth + 1,
            static_flag,
            internal_contract_map,
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

    pub fn create_with_stack_depth(
        &mut self, params: ActionParams, substate: &mut Substate,
        stack_depth: usize,
    ) -> vm::Result<FinalizationResult>
    {
        let _address = params.address;
        let _gas = params.gas;

        let vm_factory = self.state.vm_factory();
        let result = CallCreateExecutive::new_create_raw(
            params,
            self.env,
            self.machine,
            self.spec,
            &vm_factory,
            self.depth,
            stack_depth,
            self.static_flag,
            self.internal_contract_map,
            substate.contracts_in_callstack.clone(),
        )
        .consume(self.state, substate);

        result
    }

    pub fn create(
        &mut self, params: ActionParams, substate: &mut Substate,
    ) -> vm::Result<FinalizationResult> {
        self.create_with_stack_depth(params, substate, 0)
    }

    pub fn call_with_stack_depth(
        &mut self, params: ActionParams, substate: &mut Substate,
        stack_depth: usize,
    ) -> vm::Result<FinalizationResult>
    {
        let vm_factory = self.state.vm_factory();

        let result = CallCreateExecutive::new_call_raw(
            params,
            self.env,
            self.machine,
            self.spec,
            &vm_factory,
            self.depth,
            stack_depth,
            self.static_flag,
            self.internal_contract_map,
            substate.contracts_in_callstack.clone(),
        )
        .consume(self.state, substate);

        result
    }

    pub fn call(
        &mut self, params: ActionParams, substate: &mut Substate,
    ) -> vm::Result<FinalizationResult> {
        self.call_with_stack_depth(params, substate, 0)
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
            )?;
        }
        self.transact(tx)
    }

    pub fn transact(
        &mut self, tx: &SignedTransaction,
    ) -> DbResult<ExecutionOutcome> {
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
        match VerificationConfig::verify_transaction_epoch_height(
            tx,
            self.env.epoch_height,
            self.env.transaction_epoch_bound,
        ) {
            Err(_) => {
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
            Ok(()) => {}
        }

        let base_gas_required = Executive::gas_required_for(
            tx.action == Action::Create,
            &tx.data,
            spec,
        );
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

        let tx_storage_limit_in_drip =
            U256::from(tx.storage_limit) * *COLLATERAL_PER_BYTE;
        let storage_sponsor_balance = if storage_sponsored {
            self.state.sponsor_balance_for_collateral(&code_address)?
        } else {
            0.into()
        };
        // No matter who pays the collateral, we only focuses on the storage
        // limit of sender.
        let total_storage_limit = self.state.collateral_for_storage(&sender)?
            + tx_storage_limit_in_drip;
        // Find the `storage_owner` in this execution.
        let storage_owner = {
            if storage_sponsored
                && tx_storage_limit_in_drip <= storage_sponsor_balance
            {
                // sponsor will pay for collateral for storage
                code_address
            } else {
                // sender will pay for collateral for storage
                total_cost += tx_storage_limit_in_drip.into();
                sender
            }
        };

        let balance512 = U512::from(balance);
        let mut sender_intended_cost = U512::from(tx.value);
        if !gas_sponsored {
            sender_intended_cost += gas_cost
        }
        if !storage_sponsored {
            sender_intended_cost += tx_storage_limit_in_drip.into()
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
                    required_storage_cost: tx_storage_limit_in_drip,
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
            self.state.inc_nonce(&sender)?;
            self.state.sub_balance(
                &sender,
                &actual_gas_cost,
                &mut tx_substate.to_cleanup_mode(&spec),
            )?;

            return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::NotEnoughCash {
                    required: total_cost,
                    got: balance512,
                    actual_gas_cost: actual_gas_cost.clone(),
                    max_storage_limit_cost: tx_storage_limit_in_drip,
                },
                Executed::not_enough_balance_fee_charged(tx, &actual_gas_cost),
            ));
        } else {
            // From now on sender balance >= total_cost, even if the sender
            // account does not exist (since she may be sponsored). Transaction
            // execution is guaranteed. Note that inc_nonce() will create a
            // new account if the account does not exist.
            self.state.inc_nonce(&sender)?;
        }

        // Subtract the transaction fee from sender or contract.
        if !gas_free_of_charge {
            self.state.sub_balance(
                &sender,
                &U256::try_from(gas_cost).unwrap(),
                &mut tx_substate.to_cleanup_mode(&spec),
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
                    &sender,
                    &nonce,
                    &tx.data,
                );

                // For a contract address already with code, we do not allow
                // overlap the address. This should generally
                // not happen. Unless we enable account dust in
                // future. We add this check just in case it
                // helps in future.
                if self.state.is_contract_with_code(&new_address) {
                    self.state.revert_to_checkpoint();
                    return Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                        ExecutionError::ContractAddressConflict,
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
                    storage_limit_in_drip: total_storage_limit,
                };
                self.create(params, &mut substate)
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
                    storage_limit_in_drip: total_storage_limit,
                };
                self.call(params, &mut substate)
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

        Ok(self.finalize(
            tx,
            tx_substate,
            result,
            output,
            refund_receiver,
            storage_sponsored,
        )?)
    }

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
                substate.record_storage_release(&code_owner, code_size as u64);
            }

            self.state
                .record_storage_entries_release(address, &mut substate)?;
        }

        let res = self.state.settle_collateral_for_all(&substate)?;
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
                    substate.to_cleanup_mode(self.spec),
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
                    substate.to_cleanup_mode(self.spec),
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
                substate.to_cleanup_mode(self.spec),
            )?;
        };

        // perform suicides

        let subsubstate = self.kill_process(&substate.suicides)?;
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
                                amount: inc,
                            });
                        } else if sub > 0 {
                            storage_released.push(StorageChange {
                                address: *address,
                                amount: sub,
                            });
                        }
                    }
                }

                let executed = Executed {
                    gas_used,
                    gas_charged,
                    fee: fees_value,
                    gas_sponsor_paid: refund_receiver.is_some(),
                    logs: substate.logs,
                    contracts_created: substate.contracts_created,
                    storage_sponsor_paid,
                    storage_collateralized,
                    storage_released,
                    output,
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
