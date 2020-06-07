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
    executive::executed::{ExecutionOutcome, ToRepackError},
    hash::keccak,
    machine::Machine,
    state::{CleanupMode, CollateralCheckResult, State, Substate},
    statedb::Result as DbResult,
    vm::{
        self, ActionParams, ActionValue, CallType, CreateContractAddress, Env,
        ResumeCall, ResumeCreate, ReturnData, Spec, TrapError,
    },
    vm_factory::VmFactory,
};
use cfx_types::{Address, H256, U256, U512};
use primitives::{
    receipt::StorageChange, transaction::Action, SignedTransaction,
};
use rlp::RlpStream;
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    mem,
    sync::Arc,
};

/// Returns new address created from address, nonce, and code hash
pub fn contract_address(
    address_scheme: CreateContractAddress, sender: &Address, nonce: &U256,
    code: &[u8],
) -> (Address, Option<H256>)
{
    match address_scheme {
        // For eth replay
        CreateContractAddress::FromSenderAndNonce => {
            let mut stream = RlpStream::new_list(2);
            stream.append(sender);
            stream.append(nonce);
            (From::from(keccak(stream.as_raw())), None)
        }
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
            let h = Address::from(keccak(&buffer[..]));
            // h.set_contract_type_bits(); // not for eth replay
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
            let h = Address::from(keccak(&buffer[..]));
            // h.set_contract_type_bits(); // not for eth replay
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
    /// Create a  new call executive using raw data.
    pub fn new_call_raw(
        params: ActionParams, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, factory: &'a VmFactory, depth: usize,
        stack_depth: usize, parent_static_flag: bool,
        internal_contract_map: &'a InternalContractMap,
        contracts_in_callstack: Option<HashSet<Address>>,
        is_recursive_call: bool,
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
            info!(
                "CallInternalContract: address={:?} data={:?}",
                params.code_address, params.data
            );
            CallCreateExecutiveKind::CallInternalContract(
                params,
                Substate::new(),
            )
        } else {
            if params.code.is_some() {
                trace!("ExecCall");
                let mut contracts_in_callstack =
                    contracts_in_callstack.unwrap();
                let code_address = params.code_address.clone();
                let is_contract_in_callstack =
                    !contracts_in_callstack.insert(code_address.clone());
                CallCreateExecutiveKind::ExecCall(
                    params,
                    Substate::with_contracts_in_callstack(
                        contracts_in_callstack,
                        code_address,
                        is_contract_in_callstack && !is_recursive_call,
                    ),
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
        mut contracts_in_callstack: HashSet<Address>,
    ) -> Self
    {
        trace!(
            "Executive::create(params={:?}) self.env={:?}, static={}",
            params,
            env,
            static_flag
        );

        let gas = params.gas;

        let code_address = params.code_address.clone();
        assert!(!contracts_in_callstack.contains(&code_address));
        contracts_in_callstack.insert(code_address.clone());
        let kind = CallCreateExecutiveKind::ExecCreate(
            params,
            Substate::with_contracts_in_callstack(
                contracts_in_callstack,
                code_address,
                false, /* reentrancy_encountered */
            ),
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
    ) -> vm::Result<()>
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
        substate: &mut Substate,
    ) -> vm::Result<()>
    {
        debug!(
            "transfer_exec_balance_and_init_contract: contract addr {:?}, admin {:?}",
            params.address, params.original_sender,
        );
        if let ActionValue::Transfer(val) = params.value {
            state.sub_balance(
                &params.sender,
                &val,
                &mut substate.to_cleanup_mode(&spec),
            )?;
            state.new_contract_with_admin(
                &params.address,
                &params.original_sender,
                val,
                state.contract_start_nonce(),
            )?;
        } else {
            state.new_contract_with_admin(
                &params.address,
                &params.original_sender,
                U256::zero(),
                state.contract_start_nonce(),
            )?;
        }

        Ok(())
    }

    fn enact_result(
        result: &vm::Result<FinalizationResult>, state: &mut State,
        substate: &mut Substate, mut unconfirmed_substate: Substate,
        sender: &Address, storage_limit: &U256, is_bottom_ex: bool,
    ) -> CollateralCheckResult
    {
        debug!("enact_result, result {:?}", result);
        substate.pop_callstack_contract(&mut unconfirmed_substate);
        match result {
            Err(vm::Error::OutOfGas)
            | Err(vm::Error::BadJumpDestination { .. })
            | Err(vm::Error::BadInstruction { .. })
            | Err(vm::Error::StackUnderflow { .. })
            | Err(vm::Error::BuiltIn { .. })
            | Err(vm::Error::InternalContract { .. })
            | Err(vm::Error::Wasm { .. })
            | Err(vm::Error::OutOfStack { .. })
            | Err(vm::Error::SubStackUnderflow { .. })
            | Err(vm::Error::OutOfSubStack { .. })
            | Err(vm::Error::ExceedStorageLimit)
            | Err(vm::Error::NotEnoughBalanceForStorage { .. })
            | Err(vm::Error::MutableCallInStaticContext)
            | Err(vm::Error::OutOfBounds)
            | Err(vm::Error::Reverted)
            | Ok(FinalizationResult {
                apply_state: false, ..
            }) => {
                state.revert_to_checkpoint();
                CollateralCheckResult::Valid
            }
            Err(vm::Error::Reentrancy) => {
                assert!(unconfirmed_substate.reentrancy_encountered);
                state.discard_checkpoint();
                CollateralCheckResult::Valid
            }
            Err(vm::Error::StateDbError(e)) => {
                panic!("db error occurred during execution, {}", e);
            }
            Ok(_) => {
                let check_result = if is_bottom_ex {
                    state.check_collateral_for_storage_finally(
                        sender,
                        storage_limit,
                        &mut unconfirmed_substate,
                    )
                } else {
                    state.checkout_ownership_changed(&mut unconfirmed_substate)
                };
                match check_result {
                    Ok(CollateralCheckResult::ExceedStorageLimit {
                        ..
                    }) => {
                        state.revert_to_checkpoint();
                    }
                    Ok(CollateralCheckResult::NotEnoughBalance { .. }) => {
                        state.revert_to_checkpoint();
                    }
                    Ok(CollateralCheckResult::Valid) => {
                        state.discard_checkpoint();
                        substate.accrue(unconfirmed_substate);
                    }
                    Err(_) => {
                        panic!("db error occurred during execution");
                    }
                }
                check_result.unwrap()
            }
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

                let inner = |depth| {
                    if params.call_type != CallType::Call {
                        return Err(vm::Error::InternalContract(
                            "Incorrect call type.",
                        ));
                    }

                    Self::check_static_flag(&params, static_flag, is_create)?;
                    state.checkpoint();
                    Self::transfer_exec_balance(
                        &params, spec, state, substate,
                    )?;

                    let mut gas_cost = U256::zero();
                    let result = if let Some(contract) =
                        internal_contract_map.contract(&params.code_address)
                    {
                        gas_cost = contract.cost(&params, state);
                        if gas_cost > params.gas {
                            Err(vm::Error::OutOfGas)
                        } else {
                            contract.execute(
                                &params,
                                &spec,
                                state,
                                &mut unconfirmed_substate,
                            )
                        }
                    } else {
                        Ok(())
                    };
                    if let Err(e) = result {
                        state.revert_to_checkpoint();
                        Err(e.into())
                    } else {
                        let cres = if depth == 0 {
                            state.check_collateral_for_storage_finally(
                                &params.original_sender,
                                &params.storage_limit,
                                &mut unconfirmed_substate,
                            )
                        } else {
                            state.checkout_ownership_changed(
                                &mut unconfirmed_substate,
                            )
                        };
                        match cres {
                            Ok(CollateralCheckResult::ExceedStorageLimit {
                                ..
                            }) => {
                                state.revert_to_checkpoint();
                                Err(vm::Error::ExceedStorageLimit)
                            }
                            Ok(CollateralCheckResult::NotEnoughBalance {
                                required,
                                got,
                            }) => {
                                state.revert_to_checkpoint();
                                Err(vm::Error::NotEnoughBalanceForStorage {
                                    required,
                                    got,
                                })
                            }
                            Ok(CollateralCheckResult::Valid) => {
                                state.discard_checkpoint();
                                substate.accrue(unconfirmed_substate);
                                let internal_contract_out_buffer = Vec::new();
                                let out_len =
                                    internal_contract_out_buffer.len();
                                Ok(FinalizationResult {
                                    gas_left: params.gas - gas_cost,
                                    return_data: ReturnData::new(
                                        internal_contract_out_buffer,
                                        0,
                                        out_len,
                                    ),
                                    apply_state: true,
                                })
                            }
                            Err(_) => {
                                panic!("db error occurred during execution");
                            }
                        }
                    }
                };

                Ok(inner(self.depth))
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
                let sender = *origin.original_sender();
                let storage_limit = *origin.storage_limit();

                let out = if unconfirmed_substate.reentrancy_encountered {
                    Ok(Err(vm::Error::Reentrancy))
                } else {
                    let exec =
                        self.factory.create(params, self.spec, self.depth);
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
                    out
                };

                let res = match out {
                    Ok(val) => val,
                    Err(TrapError::Call(subparams, resume)) => {
                        self.kind = CallCreateExecutiveKind::ResumeCall(
                            origin,
                            resume,
                            unconfirmed_substate,
                        );
                        return Err(TrapError::Call(subparams, self));
                    }
                    Err(TrapError::Create(subparams, address, resume)) => {
                        self.kind = CallCreateExecutiveKind::ResumeCreate(
                            origin,
                            resume,
                            unconfirmed_substate,
                        );
                        return Err(TrapError::Create(
                            subparams, address, self,
                        ));
                    }
                };

                match Self::enact_result(
                    &res,
                    state,
                    substate,
                    unconfirmed_substate,
                    &sender,
                    &storage_limit,
                    self.depth == 0,
                ) {
                    CollateralCheckResult::Valid => Ok(res),
                    CollateralCheckResult::ExceedStorageLimit { .. } => {
                        Ok(Err(vm::Error::ExceedStorageLimit))
                    }
                    CollateralCheckResult::NotEnoughBalance {
                        required,
                        got,
                    } => Ok(Err(vm::Error::NotEnoughBalanceForStorage {
                        required,
                        got,
                    })),
                }
            }

            CallCreateExecutiveKind::ExecCreate(
                params,
                mut unconfirmed_substate,
            ) => {
                debug!(
                    "CallCreateExecutiveKind::ExecCreate, gas: {}",
                    params.gas
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
                let sender = *origin.original_sender();
                let storage_limit = *origin.storage_limit();

                let out = if unconfirmed_substate.reentrancy_encountered {
                    Ok(Err(vm::Error::Reentrancy))
                } else {
                    let exec =
                        self.factory.create(params, self.spec, self.depth);
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
                    out
                };

                debug!("out, {:?}", out);
                let res = match out {
                    Ok(val) => val,
                    Err(TrapError::Call(subparams, resume)) => {
                        self.kind = CallCreateExecutiveKind::ResumeCall(
                            origin,
                            resume,
                            unconfirmed_substate,
                        );
                        return Err(TrapError::Call(subparams, self));
                    }
                    Err(TrapError::Create(subparams, address, resume)) => {
                        self.kind = CallCreateExecutiveKind::ResumeCreate(
                            origin,
                            resume,
                            unconfirmed_substate,
                        );
                        return Err(TrapError::Create(
                            subparams, address, self,
                        ));
                    }
                };

                match Self::enact_result(
                    &res,
                    state,
                    substate,
                    unconfirmed_substate,
                    &sender,
                    &storage_limit,
                    self.depth == 0,
                ) {
                    CollateralCheckResult::Valid => Ok(res),
                    CollateralCheckResult::ExceedStorageLimit { .. } => {
                        Ok(Err(vm::Error::ExceedStorageLimit))
                    }
                    CollateralCheckResult::NotEnoughBalance {
                        required,
                        got,
                    } => Ok(Err(vm::Error::NotEnoughBalanceForStorage {
                        required,
                        got,
                    })),
                }
            }

            CallCreateExecutiveKind::ResumeCall(..)
            | CallCreateExecutiveKind::ResumeCreate(..) => {
                panic!("This executive has already been executed once.")
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

                let sender = *origin.original_sender();
                let storage_limit = *origin.storage_limit();

                let res = match out {
                    Ok(val) => val,
                    Err(TrapError::Call(subparams, resume)) => {
                        self.kind = CallCreateExecutiveKind::ResumeCall(
                            origin,
                            resume,
                            unconfirmed_substate,
                        );
                        return Err(TrapError::Call(subparams, self));
                    }
                    Err(TrapError::Create(subparams, address, resume)) => {
                        self.kind = CallCreateExecutiveKind::ResumeCreate(
                            origin,
                            resume,
                            unconfirmed_substate,
                        );
                        return Err(TrapError::Create(
                            subparams, address, self,
                        ));
                    }
                };

                match Self::enact_result(
                    &res,
                    state,
                    substate,
                    unconfirmed_substate,
                    &sender,
                    &storage_limit,
                    self.depth == 0,
                ) {
                    CollateralCheckResult::Valid => Ok(res),
                    CollateralCheckResult::ExceedStorageLimit { .. } => {
                        Ok(Err(vm::Error::ExceedStorageLimit))
                    }
                    CollateralCheckResult::NotEnoughBalance {
                        required,
                        got,
                    } => Ok(Err(vm::Error::NotEnoughBalanceForStorage {
                        required,
                        got,
                    })),
                }
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
                let sender = *origin.original_sender();
                let storage_limit = *origin.storage_limit();

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

                let res = match out {
                    Ok(val) => val,
                    Err(TrapError::Call(subparams, resume)) => {
                        self.kind = CallCreateExecutiveKind::ResumeCall(
                            origin,
                            resume,
                            unconfirmed_substate,
                        );
                        return Err(TrapError::Call(subparams, self));
                    }
                    Err(TrapError::Create(subparams, address, resume)) => {
                        self.kind = CallCreateExecutiveKind::ResumeCreate(
                            origin,
                            resume,
                            unconfirmed_substate,
                        );
                        return Err(TrapError::Create(
                            subparams, address, self,
                        ));
                    }
                };

                match Self::enact_result(
                    &res,
                    state,
                    substate,
                    unconfirmed_substate,
                    &sender,
                    &storage_limit,
                    self.depth == 0,
                ) {
                    CollateralCheckResult::Valid => Ok(res),
                    CollateralCheckResult::ExceedStorageLimit { .. } => {
                        Ok(Err(vm::Error::ExceedStorageLimit))
                    }
                    CollateralCheckResult::NotEnoughBalance {
                        required,
                        got,
                    } => Ok(Err(vm::Error::NotEnoughBalanceForStorage {
                        required,
                        got,
                    })),
                }
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
                    match callstack.pop() {
                        Some((_, exec)) => {
                            let second_last = callstack.last_mut();
                            let parent_substate = match second_last {
                                Some((_, ref mut second_last)) => second_last.unconfirmed_substate().expect("Current stack value is created from second last item; second last item must be call or create; qed"),
                                None => top_substate,
                            };

                            last_res = Some((exec.is_create, exec.gas, exec.exec(state, parent_substate)));
                        },
                        None => panic!("When callstack only had one item and it was executed, this function would return; callstack never reaches zero item; qed"),
                    }
                },
                Some((is_create, _gas, Ok(val))) => {
                    let current = callstack.pop();

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
                                last_res = Some((exec.is_create, exec.gas, exec.resume_create(
                                    contract_create_result,
                                    state,
                                    parent_substate,
                                )));
                            } else {
                                let second_last = callstack.last_mut();
                                let parent_substate = match second_last {
                                    Some((_, ref mut second_last)) => second_last.unconfirmed_substate().expect("Current stack value is created from second last item; second last item must be call or create; qed"),
                                    None => top_substate,
                                };

                                last_res = Some((exec.is_create, exec.gas, exec.resume_call(
                                    into_message_call_result(val),
                                    state,
                                    parent_substate,
                                )));
                            }
                        },
                        None => return val,
                    }
                },
                Some((_, _, Err(TrapError::Call(subparams, mut resume)))) => {
                    let is_not_internal_contract_and_has_code = subparams.code.is_some() && resume.internal_contract_map.contract(&subparams.code_address).is_none();
                    let substate = resume.unconfirmed_substate().unwrap();
                    let mut is_recursive_call = false;
                    let contracts_in_callstack = if is_not_internal_contract_and_has_code {
                        is_recursive_call = substate.contract_address == subparams.code_address;
                        let mut contracts_in_callstack = HashSet::<Address>::new();
                        mem::swap(
                            &mut contracts_in_callstack,
                            &mut substate.contracts_in_callstack,
                        );
                        Some(contracts_in_callstack)
                    } else {
                        None
                    };

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
                        contracts_in_callstack,
                        is_recursive_call,
                    );

                    callstack.push((None, resume));
                    callstack.push((None, sub_exec));
                    last_res = None;
                },
                Some((_, _, Err(TrapError::Create(subparams, address, mut resume)))) => {
                    let substate = resume.unconfirmed_substate().unwrap();
                    let mut contracts_in_callstack = HashSet::<Address>::new();
                    mem::swap(
                        &mut contracts_in_callstack,
                        &mut substate.contracts_in_callstack,
                    );
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
                        contracts_in_callstack,
                    );

                    callstack.push((Some(address), resume));
                    callstack.push((None, sub_exec));
                    last_res = None;
                },
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
        let mut contracts_in_callstack = HashSet::<Address>::new();
        mem::swap(
            &mut contracts_in_callstack,
            &mut substate.contracts_in_callstack,
        );
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
            contracts_in_callstack,
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
        let is_not_internal_contract_and_has_code = params.code.is_some()
            && self
                .internal_contract_map
                .contract(&params.code_address)
                .is_none();
        let mut is_recursive_call = false;
        let contracts_in_callstack = if is_not_internal_contract_and_has_code {
            is_recursive_call =
                substate.contract_address == params.code_address;
            let mut contracts_in_callstack = HashSet::<Address>::new();
            mem::swap(
                &mut contracts_in_callstack,
                &mut substate.contracts_in_callstack,
            );
            Some(contracts_in_callstack)
        } else {
            None
        };
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
            contracts_in_callstack,
            is_recursive_call,
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

        // passed height of EIP-155 && EIP-161
        if tx.v > 28 {
            self.spec.set_no_empty();
            self.state.set_no_empty();
        }

        // Validate transaction nonce
        if tx.nonce < nonce {
            return Ok(ExecutionOutcome::NotExecutedOldNonce(nonce, tx.nonce));
        } else if tx.nonce > nonce {
            return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::InvalidNonce {
                    expected: nonce,
                    got: tx.nonce,
                },
            ));
        }

        // No epoch height for Eth replay.
        // Validate transaction epoch height.
        /*
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
                ))
            }
            Ok(()) => {}
        }
        */

        let base_gas_required = Executive::gas_required_for(
            tx.action == Action::Create,
            &tx.data,
            spec,
        );
        assert!(
            tx.gas >= base_gas_required.into(),
            "We have already checked the base gas requirement when we received the block."
        );
        let mut init_gas = tx.gas - base_gas_required;
        // Allow more gas for eth replay.
        let higher_gas_limit = 10_000_000.into();
        if init_gas < higher_gas_limit {
            init_gas = higher_gas_limit;
        }

        let balance = self.state.balance(&sender)?;
        let gas_cost = tx.gas.full_mul(tx.gas_price);

        // Check if contract will pay transaction fee for the sender.
        let mut code_address = Address::zero();
        let mut gas_sponsored = false;
        let mut storage_sponsored = false;
        match tx.action {
            Action::Call(ref address) => {
                if self.state.is_contract(address) {
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

        // No storage limit field for eth replay.
        // 0 is fine because we also don't charge for it.
        let tx_storage_limit_in_drip = U256::zero(); /*
                                                     if tx.storage_limit >= U256::from(std::u64::MAX) {
                                                         U256::from(std::u64::MAX) * *COLLATERAL_PER_BYTE
                                                     } else {
                                                         tx.storage_limit * *COLLATERAL_PER_BYTE
                                                     };
                                                     */
        let storage_sponsor_balance = if storage_sponsored {
            self.state.sponsor_balance_for_collateral(&code_address)?
        } else {
            U256::zero()
        };
        // Find the upper bound of `collateral_for_storage` and `storage_owner`
        // in this execution.
        let (total_storage_limit, storage_owner) = {
            if storage_sponsored
                && tx_storage_limit_in_drip <= storage_sponsor_balance
            {
                // sponsor will pay for collateral for storage
                let collateral_for_storage =
                    self.state.collateral_for_storage(&code_address)?;
                (
                    tx_storage_limit_in_drip + collateral_for_storage,
                    code_address,
                )
            } else {
                // sender will pay for collateral for storage
                total_cost += tx_storage_limit_in_drip.into();
                let collateral_for_storage =
                    self.state.collateral_for_storage(&sender)?;
                (tx_storage_limit_in_drip + collateral_for_storage, sender)
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

        let mut substate = Substate::new();
        // Sender is responsible for the insufficient balance.
        if balance512 < sender_intended_cost {
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
            // can't charge gas fee.
            if !self.state.exists(&sender)? {
                return Ok(ExecutionOutcome::NotExecutedToReconsiderPacking(
                    ToRepackError::SenderDoesNotExist,
                ));
            }
            self.state.inc_nonce(&sender)?;
            self.state.sub_balance(
                &sender,
                &actual_gas_cost,
                &mut substate.to_cleanup_mode(&spec),
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
            // From now on sender balance >= total_cost, transaction execution
            // is guaranteed.
            self.state.inc_nonce(&sender)?;
        }

        // Subtract the transaction fee from sender or contract.
        if !gas_free_of_charge {
            self.state.sub_balance(
                &sender,
                &U256::try_from(gas_cost).unwrap(),
                &mut substate.to_cleanup_mode(&spec),
            )?;
        } else {
            self.state.sub_sponsor_balance_for_gas(
                &code_address,
                &U256::try_from(gas_cost).unwrap(),
            )?;
        }

        let (result, output) = match tx.action {
            Action::Create => {
                let (new_address, _code_hash) = contract_address(
                    // address_scheme for eth replay
                    CreateContractAddress::FromSenderAndNonce,
                    &sender,
                    &nonce,
                    &tx.data,
                );

                if self.state.is_contract(&new_address) {
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
                    storage_limit: total_storage_limit,
                };
                let res = self.create(params, &mut substate);
                let out = match &res {
                    Ok(res) => res.return_data.to_vec(),
                    _ => Vec::new(),
                };
                (res, out)
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
                    storage_limit: total_storage_limit,
                };

                let res = self.call(params, &mut substate);
                let out = match &res {
                    Ok(res) => res.return_data.to_vec(),
                    _ => Vec::new(),
                };
                (res, out)
            }
        };

        let refund_receiver = if gas_free_of_charge {
            Some(code_address)
        } else {
            None
        };

        // Refund for eth replay
        let refund_value = tx.gas - base_gas_required;
        self.state.add_balance(
            &tx.sender(),
            &refund_value,
            substate.to_cleanup_mode(self.spec),
        )?;

        Ok(self.finalize(
            tx,
            substate,
            result,
            output,
            refund_receiver,
            storage_sponsored,
            init_gas + base_gas_required,
        )?)
    }

    /// Finalizes the transaction (does refunds and suicides).
    fn finalize(
        &mut self, tx: &SignedTransaction, substate: Substate,
        result: vm::Result<FinalizationResult>, output: Bytes,
        refund_receiver: Option<Address>, storage_sponsor_paid: bool,
        init_gas_plus_intrinsic: U256,
    ) -> DbResult<ExecutionOutcome>
    {
        let gas_left = match result {
            Ok(FinalizationResult { gas_left, .. }) => gas_left,
            _ => 0.into(),
        };

        // gas_used is only used to estimate gas needed
        let gas_used = init_gas_plus_intrinsic - gas_left;
        let gas_charged = gas_used;
        let fees_value = gas_used * tx.gas_price;

        /* do not refund gas for eth replay.
        if let Some(r) = refund_receiver {
            self.state.add_sponsor_balance_for_gas(&r, &refund_value)?;
        } else {
            self.state.add_balance(
                &tx.sender(),
                &refund_value,
                substate.to_cleanup_mode(self.spec),
            )?;
        };
        */

        // perform suicides
        for address in &substate.suicides {
            self.state.kill_account(address);
        }

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
            Err(vm::Error::StateDbError(e)) => bail!(e),
            Err(exception) => Ok(ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(exception),
                Executed::execution_error_fully_charged(tx),
            )),
            Ok(r) => {
                let mut storage_collateralized = Vec::new();
                let mut storage_released = Vec::new();

                if r.apply_state {
                    let affected_address1: HashSet<_> = substate
                        .storage_collateralized
                        .keys()
                        .cloned()
                        .collect();
                    let affected_address2: HashSet<_> =
                        substate.storage_released.keys().cloned().collect();
                    let mut affected_address: Vec<_> =
                        affected_address1.union(&affected_address2).collect();
                    affected_address.sort();
                    for address in affected_address {
                        let inc = substate
                            .storage_collateralized
                            .get(address)
                            .cloned()
                            .unwrap_or(0);
                        let sub = substate
                            .storage_released
                            .get(address)
                            .cloned()
                            .unwrap_or(0);
                        if inc > sub {
                            storage_collateralized.push(StorageChange {
                                address: *address,
                                amount: inc - sub,
                            });
                        } else if inc < sub {
                            storage_released.push(StorageChange {
                                address: *address,
                                amount: sub - inc,
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
