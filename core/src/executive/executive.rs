// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    context::{Context, OriginInfo, OutputPolicy},
    Executed, ExecutionError, ExecutionResult,
};
use crate::{
    bytes::{Bytes, BytesRef},
    evm::{FinalizationResult, Finalize},
    hash::keccak,
    machine::Machine,
    state::{CleanupMode, State, Substate},
    vm::{
        self, ActionParams, ActionValue, CallType, CleanDustMode,
        CreateContractAddress, Env, ResumeCall, ResumeCreate, ReturnData, Spec,
        TrapError,
    },
    vm_factory::VmFactory,
};
use cfx_types::{Address, H256, U256, U512};
use primitives::{transaction::Action, SignedTransaction};
use std::{convert::TryFrom, str::FromStr, sync::Arc};

lazy_static! {
    pub static ref STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS: Address =
        Address::from_str("443c409373ffd5c0bec1dddb7bec830856757b65").unwrap();
    pub static ref COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("5ad036480160591706c831f0da19d1a424e39469").unwrap();
    pub static ref STORAGE_COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("d7ca63b239c537ada331614df304b6ce3caa11f4").unwrap();
    pub static ref INTERNAL_CONTRACT_CODE: Bytes = vec![0u8, 0u8, 0u8, 0u8];
    pub static ref INTERNAL_CONTRACT_CODE_HASH: H256 =
        keccak([0u8, 0u8, 0u8, 0u8]);
}

/// Returns new address created from address, nonce, and code hash
pub fn contract_address(
    address_scheme: CreateContractAddress, sender: &Address, nonce: &U256,
    code: &[u8],
) -> (Address, Option<H256>)
{
    use rlp::RlpStream;

    match address_scheme {
        CreateContractAddress::FromSenderAndNonce => {
            let mut stream = RlpStream::new_list(2);
            stream.append(sender);
            stream.append(nonce);
            (From::from(keccak(stream.as_raw())), None)
        }
        CreateContractAddress::FromSenderSaltAndCodeHash(salt) => {
            let code_hash = keccak(code);
            let mut buffer = [0u8; 1 + 20 + 32 + 32];
            buffer[0] = 0xff;
            &mut buffer[1..(1 + 20)].copy_from_slice(&sender[..]);
            &mut buffer[(1 + 20)..(1 + 20 + 32)].copy_from_slice(&salt[..]);
            &mut buffer[(1 + 20 + 32)..].copy_from_slice(&code_hash[..]);
            (From::from(keccak(&buffer[..])), Some(code_hash))
        }
        CreateContractAddress::FromSenderAndCodeHash => {
            let code_hash = keccak(code);
            let mut buffer = [0u8; 20 + 32];
            &mut buffer[..20].copy_from_slice(&sender[..]);
            &mut buffer[20..].copy_from_slice(&code_hash[..]);
            (From::from(keccak(&buffer[..])), Some(code_hash))
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

pub fn is_internal_contract(address: &Address) -> bool {
    *address == *STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS
        || *address == *COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS
        || *address == *STORAGE_COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS
}

enum CallCreateExecutiveKind {
    Transfer(ActionParams),
    CallBuiltin(ActionParams),
    CallInternalContract(ActionParams),
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
}

impl<'a> CallCreateExecutive<'a> {
    /// Create a  new call executive using raw data.
    pub fn new_call_raw(
        params: ActionParams, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, factory: &'a VmFactory, depth: usize,
        stack_depth: usize, parent_static_flag: bool,
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
        } else if is_internal_contract(&params.code_address) {
            info!("CallInternalContract: {:?}", params.data);
            CallCreateExecutiveKind::CallInternalContract(params)
        } else {
            if params.code.is_some() {
                trace!("ExecCall");
                CallCreateExecutiveKind::ExecCall(params, Substate::new())
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
        }
    }

    /// Create a new create executive using raw data.
    pub fn new_create_raw(
        params: ActionParams, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, factory: &'a VmFactory, depth: usize,
        stack_depth: usize, static_flag: bool,
    ) -> Self
    {
        trace!(
            "Executive::create(params={:?}) self.env={:?}, static={}",
            params,
            env,
            static_flag
        );

        let gas = params.gas;

        let kind = CallCreateExecutiveKind::ExecCreate(params, Substate::new());

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
            CallCreateExecutiveKind::Transfer(..)
            | CallCreateExecutiveKind::CallBuiltin(..)
            | CallCreateExecutiveKind::CallInternalContract(..) => None,
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

    fn deposit(
        params: &ActionParams, state: &mut State, val: &U256, deposit_time: u64,
    ) -> vm::Result<()> {
        if state.balance(&params.sender)? < *val {
            Err(vm::Error::InternalContract("not enough balance to deposit"))
        } else {
            state.deposit(&params.sender, &val, deposit_time)?;
            Ok(())
        }
    }

    fn withdraw(
        params: &ActionParams, state: &mut State, val: &U256,
    ) -> vm::Result<()> {
        if state.bank_balance(&params.sender)?
            - state.storage_balance(&params.sender)?
            < *val
        {
            Err(vm::Error::InternalContract(
                "not enough bank balance to withdraw",
            ))
        } else {
            state.withdraw(&params.sender, &val)?;
            Ok(())
        }
    }

    fn transfer_exec_balance_and_init_contract(
        params: &ActionParams, spec: &Spec, state: &mut State,
        substate: &mut Substate,
    ) -> vm::Result<()>
    {
        let nonce_offset = if spec.no_empty { 1 } else { 0 }.into();
        let balance = state.balance(&params.address)?;
        if let ActionValue::Transfer(val) = params.value {
            state.sub_balance(
                &params.sender,
                &val,
                &mut substate.to_cleanup_mode(&spec),
            )?;
            state.new_contract(&params.address, val + balance, nonce_offset)?;
        } else {
            state.new_contract(&params.address, balance, nonce_offset)?;
        }

        Ok(())
    }

    fn enact_result(
        result: &vm::Result<FinalizationResult>, env: &'a Env,
        state: &mut State, substate: &mut Substate,
        unconfirmed_substate: Substate,
    )
    {
        match *result {
            Err(vm::Error::OutOfGas)
            | Err(vm::Error::BadJumpDestination { .. })
            | Err(vm::Error::BadInstruction { .. })
            | Err(vm::Error::StackUnderflow { .. })
            | Err(vm::Error::BuiltIn { .. })
            | Err(vm::Error::InternalContract { .. })
            | Err(vm::Error::Wasm { .. })
            | Err(vm::Error::OutOfStack { .. })
            | Err(vm::Error::OutOfStaking)
            | Err(vm::Error::MutableCallInStaticContext)
            | Err(vm::Error::OutOfBounds)
            | Err(vm::Error::Reverted)
            | Ok(FinalizationResult {
                apply_state: false, ..
            }) => {
                state.revert_to_checkpoint();
            }
            Ok(_) | Err(vm::Error::Internal(_)) => {
                if state.check_storage_balance(env.timestamp) {
                    state.discard_checkpoint();
                    substate.accrue(unconfirmed_substate);
                } else {
                    // FIXME: return error details.
                    state.revert_to_checkpoint();
                }
            }
        }
    }

    /// Creates `Context` from `Executive`.
    fn as_context<'any>(
        state: &'any mut State, env: &'any Env, machine: &'any Machine,
        spec: &'any Spec, depth: usize, stack_depth: usize, static_flag: bool,
        origin: &'any OriginInfo, substate: &'any mut Substate,
        output: OutputPolicy,
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
        )
    }

    /// Implementation of deposit and withdraw tokens in bank.
    fn exec_storage_interest_staking_contract(
        params: &ActionParams, state: &mut State, gas_cost: &U256,
        timestamp: u64,
    ) -> vm::Result<()>
    {
        // FIXME: make sure params.sender is a normal account.
        if *gas_cost > params.gas {
            return Err(vm::Error::OutOfGas);
        }
        let data = if let Some(ref d) = params.data {
            d as &[u8]
        } else {
            return Err(vm::Error::InternalContract("invalid data"));
        };

        if data[0..4] == [182, 181, 95, 37] {
            // The first 4 bytes of
            // keccak('deposit(uint256)') is
            // `0xb6b55f25`.
            // 4 bytes `Method ID` + 32 bytes `amount`
            if data.len() != 36 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let amount = U256::from(&data[4..36]);
                Self::deposit(params, state, &amount, timestamp)
            }
        } else if data[0..4] == [46, 26, 125, 77] {
            // The first 4 bytes of
            // keccak('withdraw(uint256)') is `0x2e1a7d4d`.
            // 4 bytes `Method ID` + 32 bytes `amount`.
            if data.len() != 36 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let amount = U256::from(&data[4..36]);
                Self::withdraw(params, state, &amount)
            }
        } else {
            Ok(())
        }
    }

    fn exec_commission_privilege_control_contract(
        params: &ActionParams, state: &mut State, gas_cost: &U256,
    ) -> vm::Result<()> {
        // FIXME: params.sender should be address of a contract.
        if *gas_cost > params.gas {
            return Err(vm::Error::OutOfGas);
        }
        let data = if let Some(ref d) = params.data {
            d as &[u8]
        } else {
            return Err(vm::Error::InternalContract("invalid data"));
        };

        if data[0..4] == [219, 203, 249, 80] {
            // The first 4 bytes of keccak('commission_balance(uint256)')
            // is `0xdbcbf950`.
            // 4 bytes `Method ID` + 32 bytes `balance`.
            if data.len() != 36 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let contract_address = params.sender;
                let balance = U256::from(&data[4..36]);
                Ok(state.set_commission_balance(
                    &contract_address,
                    &params.original_sender,
                    &balance,
                )?)
            }
        } else if data[0..4] == [254, 21, 21, 108] {
            // The first 4 bytes of keccak('add_privilege(address[])') is
            // `0xfe15156c`.
            // 4 bytes `Method ID` + 32 bytes location + 32 bytes `length` + ...
            if data.len() < 68 && data.len() % 32 != 4 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let contract_address = params.sender;
                let location = U256::from(&data[4..36]);
                let expected_length = U256::from(&data[36..68]);
                let actual_length = (data.len() - 68) / 32;
                if location != U256::from(32)
                    || U256::from(actual_length) != expected_length
                {
                    Err(vm::Error::InternalContract("invalid length"))
                } else {
                    let mut offset = 68;
                    for _ in 0..actual_length {
                        let user_addr = Address::from_slice(
                            &data[offset + 12..offset + 32],
                        );
                        state.add_commission_privilege(
                            &COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS,
                            contract_address,
                            params.original_sender,
                            user_addr,
                        )?;
                        offset += 32;
                    }
                    Ok(())
                }
            }
        } else if data[0..4] == [68, 192, 189, 33] {
            // The first 4 bytes of keccak('remove_privilege(address[])')
            // is `0x44c0bd21`.
            // 4 bytes `Method ID` + 32 bytes location + 32 bytes `length` + ...
            if data.len() < 68 && data.len() % 32 != 4 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let contract_address = params.sender;
                let location = U256::from(&data[4..36]);
                let expected_length = U256::from(&data[36..68]);
                let actual_length = (data.len() - 68) / 32;
                if location != U256::from(32)
                    || U256::from(actual_length) != expected_length
                {
                    Err(vm::Error::InternalContract("invalid length"))
                } else {
                    let mut offset = 68;
                    for _ in 0..actual_length {
                        let user_addr = Address::from_slice(
                            &data[offset + 12..offset + 32],
                        );
                        state.remove_commission_privilege(
                            &COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS,
                            contract_address,
                            params.original_sender,
                            user_addr,
                        )?;
                        offset += 32;
                    }
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }

    fn exec_storage_commission_privilege_control_contract(
        params: &ActionParams, state: &mut State, gas_cost: &U256,
    ) -> vm::Result<()> {
        // FIXME: params.sender should be address of a contract.
        if *gas_cost > params.gas {
            return Err(vm::Error::OutOfGas);
        }
        let data = if let Some(ref d) = params.data {
            d as &[u8]
        } else {
            return Err(vm::Error::InternalContract("invalid data"));
        };

        if data[0..4] == [254, 21, 21, 108] {
            // The first 4 bytes of keccak('add_privilege(address[])') is
            // `0xfe15156c`.
            // 4 bytes `Method ID` + 32 bytes location + 32 bytes `length` + ...
            if data.len() < 68 && data.len() % 32 != 4 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let contract_address = params.sender;
                let location = U256::from(&data[4..36]);
                let expected_length = U256::from(&data[36..68]);
                let actual_length = (data.len() - 68) / 32;
                if location != U256::from(32)
                    || U256::from(actual_length) != expected_length
                {
                    Err(vm::Error::InternalContract("invalid length"))
                } else {
                    let mut offset = 68;
                    for _ in 0..actual_length {
                        let user_addr = Address::from_slice(
                            &data[offset + 12..offset + 32],
                        );
                        state.add_commission_privilege(
                            &STORAGE_COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS,
                            contract_address,
                            params.original_sender,
                            user_addr,
                        )?;
                        offset += 32;
                    }
                    Ok(())
                }
            }
        } else if data[0..4] == [68, 192, 189, 33] {
            // The first 4 bytes of keccak('remove_privilege(address[])')
            // is `0x44c0bd21`.
            // 4 bytes `Method ID` + 32 bytes location + 32 bytes `length` + ...
            if data.len() < 68 && data.len() % 32 != 4 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let contract_address = params.sender;
                let location = U256::from(&data[4..36]);
                let expected_length = U256::from(&data[36..68]);
                let actual_length = (data.len() - 68) / 32;
                if location != U256::from(32)
                    || U256::from(actual_length) != expected_length
                {
                    Err(vm::Error::InternalContract("invalid length"))
                } else {
                    let mut offset = 68;
                    for _ in 0..actual_length {
                        let user_addr = Address::from_slice(
                            &data[offset + 12..offset + 32],
                        );
                        state.remove_commission_privilege(
                            &STORAGE_COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS,
                            contract_address,
                            params.original_sender,
                            user_addr,
                        )?;
                        offset += 32;
                    }
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
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

            CallCreateExecutiveKind::CallInternalContract(ref params) => {
                assert!(!self.is_create);

                let mut inner = || {
                    if params.call_type != CallType::Call {
                        return Err(vm::Error::InternalContract(
                            "Incorrect call type.",
                        ));
                    }

                    Self::check_static_flag(
                        &params,
                        self.static_flag,
                        self.is_create,
                    )?;
                    state.checkpoint();
                    Self::transfer_exec_balance(
                        &params, self.spec, state, substate,
                    )?;

                    // FIXME: Implement the correct pricer!
                    let gas_cost = U256::zero();
                    let result = if params.code_address
                        == *STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS
                    {
                        Self::exec_storage_interest_staking_contract(
                            &params,
                            state,
                            &gas_cost,
                            self.env.timestamp,
                        )
                    } else if params.code_address
                        == *COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS
                    {
                        Self::exec_commission_privilege_control_contract(
                            &params, state, &gas_cost,
                        )
                    } else if params.code_address == *STORAGE_COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS {
                        Self::exec_storage_commission_privilege_control_contract(
                            &params, state, &gas_cost,
                        )
                    } else {
                        Ok(())
                    };
                    if let Err(e) = result {
                        state.revert_to_checkpoint();
                        Err(e.into())
                    } else if state.check_storage_balance(self.env.timestamp) {
                        state.discard_checkpoint();
                        let internal_contract_out_buffer = Vec::new();
                        let out_len = internal_contract_out_buffer.len();
                        Ok(FinalizationResult {
                            gas_left: params.gas - gas_cost,
                            return_data: ReturnData::new(
                                internal_contract_out_buffer,
                                0,
                                out_len,
                            ),
                            apply_state: true,
                        })
                    } else {
                        state.revert_to_checkpoint();
                        // FIXME: add more details.
                        Err(vm::Error::OutOfStaking)
                    }
                };

                Ok(inner())
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

                Self::enact_result(
                    &res,
                    &self.env,
                    state,
                    substate,
                    unconfirmed_substate,
                );
                Ok(res)
            }

            CallCreateExecutiveKind::ExecCreate(
                params,
                mut unconfirmed_substate,
            ) => {
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

                Self::enact_result(
                    &res,
                    &self.env,
                    state,
                    substate,
                    unconfirmed_substate,
                );
                Ok(res)
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

                Self::enact_result(
                    &res,
                    &self.env,
                    state,
                    substate,
                    unconfirmed_substate,
                );
                Ok(res)
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

                Self::enact_result(
                    &res,
                    &self.env,
                    state,
                    substate,
                    unconfirmed_substate,
                );
                Ok(res)
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
                    );

                    callstack.push((None, resume));
                    callstack.push((None, sub_exec));
                    last_res = None;
                },
                Some((_, _, Err(TrapError::Create(subparams, address, resume)))) => {
                    let sub_exec = CallCreateExecutive::new_create_raw(
                        subparams,
                        resume.env,
                        resume.machine,
                        resume.spec,
                        resume.factory,
                        resume.depth + 1,
                        resume.stack_depth,
                        resume.static_flag
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
}

impl<'a> Executive<'a> {
    /// Basic constructor.
    pub fn new(
        state: &'a mut State, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec,
    ) -> Self
    {
        Executive {
            state,
            env,
            machine,
            spec,
            depth: 0,
            static_flag: false,
        }
    }

    /// Populates executive from parent properties. Increments executive depth.
    pub fn from_parent(
        state: &'a mut State, env: &'a Env, machine: &'a Machine,
        spec: &'a Spec, parent_depth: usize, static_flag: bool,
    ) -> Self
    {
        Executive {
            state,
            env,
            machine,
            spec,
            depth: parent_depth + 1,
            static_flag,
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
        let mut call_exec = CallCreateExecutive::new_call_raw(
            params,
            self.env,
            self.machine,
            self.spec,
            &vm_factory,
            self.depth,
            stack_depth,
            self.static_flag,
        );
        match call_exec.kind {
            CallCreateExecutiveKind::ExecCall(ref params, ref mut substate) => {
                // This is the acutal gas_cost for the caller.
                let gas = match &params.data {
                    Some(ref data) => {
                        params.gas
                            + Self::gas_required_for(
                                false, /* is_create */
                                data, self.spec,
                            )
                    }
                    None => params.gas,
                };
                // If the sender has `commission_privilege` and the contract has
                // enough `commission_balance`, we will refund `gas_cost` to the
                // sender and use `commission_balance` to pay the `gas_cost`.
                let gas_cost = gas * params.gas_price;
                let has_privilege = self.state.check_commission_privilege(
                    &COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS,
                    &params.code_address,
                    &params.sender,
                )?;
                if has_privilege {
                    let balance = self.state.balance(&params.code_address)?;
                    let commission_balance =
                        self.state.commission_balance(&params.code_address)?;
                    if gas_cost <= commission_balance && gas_cost <= balance {
                        self.state.checkpoint();
                        // FIXME: If there are some db errors, should we panic
                        // here?
                        self.state.sub_commission_balance(
                            &params.code_address,
                            &gas_cost,
                        )?;
                        assert!(self
                            .state
                            .check_storage_balance(self.env.timestamp));
                        self.state.sub_balance(
                            &params.code_address,
                            &gas_cost,
                            &mut substate.to_cleanup_mode(&self.spec),
                        )?;
                        self.state.discard_checkpoint();
                        self.state.add_balance(
                            &params.sender,
                            &gas_cost,
                            substate.to_cleanup_mode(&self.spec),
                        )?;
                    }
                }
            }
            _ => {}
        }

        let result = call_exec.consume(self.state, substate);

        result
    }

    pub fn call(
        &mut self, params: ActionParams, substate: &mut Substate,
    ) -> vm::Result<FinalizationResult> {
        self.call_with_stack_depth(params, substate, 0)
    }

    pub fn transact_virtual(
        &mut self, tx: &SignedTransaction,
    ) -> ExecutionResult<Executed> {
        let sender = tx.sender();
        let balance = self.state.balance(&sender)?;
        let needed_balance =
            tx.value.saturating_add(tx.gas.saturating_mul(tx.gas_price));
        if balance < needed_balance {
            // give the sender a sufficient balance
            self.state.add_balance(
                &sender,
                &(needed_balance - balance),
                CleanupMode::NoEmpty,
            )?;
        }
        let mut nonce_increased = false;
        self.transact(tx, &mut nonce_increased)
    }

    pub fn transact(
        &mut self, tx: &SignedTransaction, nonce_increased: &mut bool,
    ) -> ExecutionResult<Executed> {
        *nonce_increased = false;
        let sender = tx.sender();
        let nonce = self.state.nonce(&sender)?;

        let spec = self.spec;
        let base_gas_required = U256::from(Self::gas_required_for(
            match tx.action {
                Action::Create => true,
                Action::Call(_) => false,
            },
            &tx.data,
            spec,
        ));

        if tx.gas < base_gas_required {
            return Err(ExecutionError::NotEnoughBaseGas {
                required: base_gas_required,
                got: tx.gas,
            });
        }

        if !tx.is_unsigned()
            && spec.kill_dust != CleanDustMode::Off
            && !self.state.exists(&sender)?
        {
            return Err(ExecutionError::SenderMustExist);
        }

        let init_gas = tx.gas - base_gas_required;

        // Validate transaction nonce
        if tx.nonce != nonce {
            return Err(ExecutionError::InvalidNonce {
                expected: nonce,
                got: tx.nonce,
            });
        }

        // This should never happen because we have checked block gas limit
        // before SyncGraph Validate if transaction fits into give block
        if self.env.gas_used + tx.gas > self.env.gas_limit {
            return Err(ExecutionError::BlockGasLimitReached {
                gas_limit: self.env.gas_limit,
                gas_used: self.env.gas_used,
                gas: tx.gas,
            });
        }

        let balance = self.state.balance(&sender)?;
        let gas_cost = tx.gas.full_mul(tx.gas_price);
        let total_cost = U512::from(tx.value) + gas_cost;

        // Increase nonce even sender does not have enough balance
        if !spec.keep_unsigned_nonce || !tx.is_unsigned() {
            self.state.inc_nonce(&sender)?;
            *nonce_increased = true;
        }

        let mut substate = Substate::new();
        // Avoid unaffordable transactions
        let balance512 = U512::from(balance);
        if balance512 < total_cost {
            // Sub tx fee if not enough cash, and substitute all remaining
            // balance if balance is not enough to pay the tx fee
            let actual_cost = if gas_cost > balance512 {
                balance512
            } else {
                gas_cost
            };
            self.state.sub_balance(
                &sender,
                &U256::try_from(actual_cost).unwrap(),
                &mut substate.to_cleanup_mode(&spec),
            )?;
            return Err(ExecutionError::NotEnoughCash {
                required: total_cost,
                got: balance512,
            });
        }

        self.state.sub_balance(
            &sender,
            &U256::try_from(gas_cost).unwrap(),
            &mut substate.to_cleanup_mode(&spec),
        )?;

        let (result, output) = match tx.action {
            Action::Create => {
                let (new_address, _code_hash) = contract_address(
                    CreateContractAddress::FromSenderAndNonce,
                    &sender,
                    &nonce,
                    &tx.data,
                );
                let params = ActionParams {
                    code_address: new_address,
                    code_hash: None,
                    address: new_address,
                    sender,
                    original_sender: sender,
                    original_receiver: new_address,
                    gas: init_gas,
                    gas_price: tx.gas_price,
                    value: ActionValue::Transfer(tx.value),
                    code: Some(Arc::new(tx.data.clone())),
                    data: None,
                    call_type: CallType::None,
                    params_type: vm::ParamsType::Embedded,
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
                    original_receiver: *address,
                    gas: init_gas,
                    gas_price: tx.gas_price,
                    value: ActionValue::Transfer(tx.value),
                    code: self.state.code(address)?,
                    code_hash: self.state.code_hash(address)?,
                    data: Some(tx.data.clone()),
                    call_type: CallType::Call,
                    params_type: vm::ParamsType::Separate,
                };

                let res = self.call(params, &mut substate);
                let out = match &res {
                    Ok(res) => res.return_data.to_vec(),
                    _ => Vec::new(),
                };
                (res, out)
            }
        };

        Ok(self.finalize(tx, substate, result, output)?)
    }

    /// Finalizes the transaction (does refunds and suicides).
    fn finalize(
        &mut self, tx: &SignedTransaction, substate: Substate,
        result: vm::Result<FinalizationResult>, output: Bytes,
    ) -> ExecutionResult<Executed>
    {
        let gas_left = match result {
            Ok(FinalizationResult { gas_left, .. }) => gas_left,
            _ => 0.into(),
        };

        // gas_used is only used to estimate gas needed
        let gas_used = tx.gas - gas_left;
        let fees_value = tx.gas * tx.gas_price;

        // perform suicides
        for address in &substate.suicides {
            // If the `bank_balance` of the address is not zero, it means it
            // owns some storages. We should not kill this account, unless all
            // the storages are released.
            //
            // FIXME: some db errors should be handled here.
            assert!(self.state.exists(address)?);
            if self.state.bank_balance(address)?.is_zero() {
                self.state.kill_account(address);
            }
        }

        // TODO should be added back after enabling dust collection
        // Should be executed once per block, instead of per transaction?

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
            Err(vm::Error::Internal(msg)) => Err(ExecutionError::Internal(msg)),
            Err(exception) => Ok(Executed {
                exception: Some(exception),
                gas: tx.gas,
                gas_used: tx.gas,
                fee: fees_value,
                cumulative_gas_used: self.env.gas_used + tx.gas,
                logs: vec![],
                contracts_created: vec![],
                output,
            }),
            Ok(r) => Ok(Executed {
                exception: if r.apply_state {
                    None
                } else {
                    Some(vm::Error::Reverted)
                },
                gas: tx.gas,
                gas_used,
                fee: fees_value,
                cumulative_gas_used: self.env.gas_used + tx.gas,
                logs: substate.logs,
                contracts_created: substate.contracts_created,
                output,
            }),
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::{
        evm::{Factory, VMType},
        machine::Machine,
        parameters::consensus_internal::{
            CONFLUX_TOKEN, RENTAL_PRICE_PER_STORAGE_KEY,
        },
        state::{CleanupMode, State, Substate},
        statedb::StateDb,
        storage::{
            tests::new_state_manager_for_unit_test, StorageManager,
            StorageManagerTrait,
        },
        test_helpers::{
            get_state_for_genesis_write,
            get_state_for_genesis_write_with_factory,
        },
    };
    use cfx_types::{Address, BigEndianHash, H256, U256, U512};
    use keylib::{Generator, Random};
    use primitives::Transaction;
    use rustc_hex::FromHex;
    use std::{cmp, str::FromStr};

    fn make_byzantium_machine(max_depth: usize) -> Machine {
        let mut machine = crate::machine::new_machine_with_builtin();
        machine.set_spec_creation_rules(Box::new(move |s, _| {
            s.max_depth = max_depth
        }));
        machine
    }

    #[test]
    fn test_contract_address() {
        let address =
            Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6")
                .unwrap();
        let expected_address =
            Address::from_str("3f09c73a5ed19289fb9bdc72f1742566df146f56")
                .unwrap();
        assert_eq!(
            expected_address,
            contract_address(
                CreateContractAddress::FromSenderAndNonce,
                &address,
                &U256::from(88),
                &[]
            )
            .0
        );
    }

    #[test]
    fn test_sender_balance() {
        let factory = Factory::new(VMType::Interpreter, 1024 * 32);
        let sender =
            Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6")
                .unwrap();
        let address = contract_address(
            CreateContractAddress::FromSenderAndNonce,
            &sender,
            &U256::zero(),
            &[],
        )
        .0;
        let mut params = ActionParams::default();
        params.address = address;
        params.sender = sender;
        params.original_sender = sender;
        params.original_receiver = address;
        params.gas = U256::from(100_000);
        params.code = Some(Arc::new("3331600055".from_hex().unwrap()));
        params.value = ActionValue::Transfer(U256::from(0x7));
        let storage_manager = new_state_manager_for_unit_test();
        let mut state =
            get_state_for_genesis_write_with_factory(&storage_manager, factory);
        state
            .add_balance(
                &sender,
                &U256::from(CONFLUX_TOKEN),
                CleanupMode::NoEmpty,
            )
            .ok();
        state
            .deposit(
                &sender,
                &U256::from(CONFLUX_TOKEN),
                1, /* duration_in_sec */
            )
            .ok();
        state
            .add_balance(&sender, &U256::from(0x100u64), CleanupMode::NoEmpty)
            .unwrap();
        let env = Env::default();
        let machine = make_byzantium_machine(0);
        let spec = machine.spec(env.number);
        let mut substate = Substate::new();

        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.create(params, &mut substate).unwrap()
        };

        assert_eq!(gas_left, U256::from(79_595));
        assert_eq!(
            state.storage_at(&address, &H256::zero()).unwrap(),
            BigEndianHash::from_uint(&U256::from(0xf9u64))
        );
        assert_eq!(state.balance(&sender).unwrap(), U256::from(0xf9));
        assert_eq!(state.balance(&address).unwrap(), U256::from(0x7));
        assert_eq!(substate.contracts_created.len(), 0);
    }

    #[test]
    fn test_create_contract_out_of_depth() {
        let factory = Factory::new(VMType::Interpreter, 1024 * 32);

        // code:
        //
        // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
        // 29 bytes? 60 00 - push 0
        // 52
        // 60 1d - push 29
        // 60 03 - push 3
        // 60 17 - push 17
        // f0 - create
        // 60 00 - push 0
        // 55 sstore
        //
        // other code:
        //
        // 60 10 - push 16
        // 80 - duplicate first stack item
        // 60 0c - push 12
        // 60 00 - push 0
        // 39 - copy current code to memory
        // 60 00 - push 0
        // f3 - return

        let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

        let sender =
            Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681")
                .unwrap();
        let address = contract_address(
            CreateContractAddress::FromSenderAndNonce,
            &sender,
            &U256::zero(),
            &[],
        )
        .0;

        let mut params = ActionParams::default();
        params.address = address;
        params.sender = sender;
        params.original_sender = sender;
        params.original_receiver = address;
        params.gas = U256::from(100_000);
        params.code = Some(Arc::new(code));
        params.value = ActionValue::Transfer(U256::from(100));

        let storage_manager = new_state_manager_for_unit_test();
        let mut state =
            get_state_for_genesis_write_with_factory(&storage_manager, factory);
        state
            .add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty)
            .unwrap();
        let env = Env::default();
        let machine = make_byzantium_machine(0);
        let spec = machine.spec(env.number);
        let mut substate = Substate::new();

        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.create(params, &mut substate).unwrap()
        };

        assert_eq!(gas_left, U256::from(62_976));
        assert_eq!(substate.contracts_created.len(), 0);
    }

    #[test]
    // Tracing is not suported in JIT
    fn test_call_to_create() {
        // code:
        //
        // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
        // 29 bytes? 60 00 - push 0
        // 52
        // 60 1d - push 29
        // 60 03 - push 3
        // 60 17 - push 23
        // f0 - create
        // 60 00 - push 0
        // 55 sstore
        //
        // other code:
        //
        // 60 10 - push 16
        // 80 - duplicate first stack item
        // 60 0c - push 12
        // 60 00 - push 0
        // 39 - copy current code to memory
        // 60 00 - push 0
        // f3 - return

        let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

        let sender =
            Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681")
                .unwrap();
        let address = contract_address(
            CreateContractAddress::FromSenderAndNonce,
            &sender,
            &U256::zero(),
            &[],
        )
        .0;
        // TODO: add tests for 'callcreate'
        //let next_address = contract_address(&address, &U256::zero());
        let mut params = ActionParams::default();
        params.address = address;
        params.code_address = address;
        params.sender = sender;
        params.original_sender = sender;
        params.original_receiver = address;
        params.gas = U256::from(100_000);
        params.code = Some(Arc::new(code));
        params.value = ActionValue::Transfer(U256::from(100));
        params.call_type = CallType::Call;

        let storage_manager = new_state_manager_for_unit_test();
        let mut state = get_state_for_genesis_write(&storage_manager);
        state
            .add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty)
            .unwrap();
        let env = Env::default();
        let machine = make_byzantium_machine(5);
        let spec = machine.spec(env.number);
        let mut substate = Substate::new();

        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params, &mut substate).unwrap()
        };

        assert_eq!(gas_left, U256::from(44_752));
    }

    #[test]
    fn test_revert() {
        let factory = Factory::new(VMType::Interpreter, 1024 * 32);

        let contract_address =
            Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681")
                .unwrap();
        let sender =
            Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6")
                .unwrap();

        let code = "6c726576657274656420646174616000557f726576657274206d657373616765000000000000000000000000000000000000600052600e6000fd".from_hex().unwrap();
        let returns = "726576657274206d657373616765".from_hex().unwrap();

        let storage_manager = new_state_manager_for_unit_test();
        let mut state = get_state_for_genesis_write_with_factory(
            &storage_manager,
            factory.clone(),
        );
        state
            .add_balance(
                &sender,
                &U256::from_str("152d02c7e14af68000000").unwrap(),
                CleanupMode::NoEmpty,
            )
            .unwrap();
        state
            .commit(BigEndianHash::from_uint(&U256::from(1)))
            .unwrap();

        let mut params = ActionParams::default();
        params.address = contract_address;
        params.sender = sender;
        params.original_sender = sender;
        params.original_receiver = contract_address;
        params.gas = U256::from(20025);
        params.code = Some(Arc::new(code));
        params.value = ActionValue::Transfer(U256::zero());
        let env = Env::default();
        let machine = crate::machine::new_machine_with_builtin();
        let spec = machine.spec(env.number);
        let mut substate = Substate::new();

        let mut output = [0u8; 14];
        let FinalizationResult {
            gas_left: result,
            return_data,
            ..
        } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params, &mut substate).unwrap()
        };
        (&mut output)
            .copy_from_slice(&return_data[..(cmp::min(14, return_data.len()))]);

        assert_eq!(result, U256::from(1));
        assert_eq!(output[..], returns[..]);
        assert_eq!(
            state
                .storage_at(
                    &contract_address,
                    &BigEndianHash::from_uint(&U256::zero())
                )
                .unwrap(),
            BigEndianHash::from_uint(&U256::from(0))
        );
    }

    #[test]
    fn test_keccak() {
        let factory = Factory::new(VMType::Interpreter, 1024 * 32);

        let code = "6064640fffffffff20600055".from_hex().unwrap();

        let sender =
            Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6")
                .unwrap();
        let address = contract_address(
            CreateContractAddress::FromSenderAndNonce,
            &sender,
            &U256::zero(),
            &[],
        )
        .0;
        // TODO: add tests for 'callcreate'
        //let next_address = contract_address(&address, &U256::zero());
        let mut params = ActionParams::default();
        params.address = address;
        params.sender = sender;
        params.original_sender = sender;
        params.original_receiver = address;
        params.gas = U256::from(0x0186a0);
        params.code = Some(Arc::new(code));
        params.value =
            ActionValue::Transfer(U256::from_str("0de0b6b3a7640000").unwrap());

        let storage_manager = new_state_manager_for_unit_test();
        let mut state =
            get_state_for_genesis_write_with_factory(&storage_manager, factory);
        state
            .add_balance(
                &sender,
                &U256::from_str("152d02c7e14af6800000").unwrap(),
                CleanupMode::NoEmpty,
            )
            .unwrap();
        let env = Env::default();
        let machine = make_byzantium_machine(0);
        let spec = machine.spec(env.number);
        let mut substate = Substate::new();

        let result = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.create(params, &mut substate)
        };

        match result {
            Err(_) => {}
            _ => panic!("Expected OutOfGas"),
        }
    }

    #[test]
    fn test_not_enough_cash() {
        let factory = Factory::new(VMType::Interpreter, 1024 * 32);

        let keypair = Random.generate().unwrap();
        let t = Transaction {
            action: Action::Create,
            value: U256::from(18),
            data: "3331600055".from_hex().unwrap(),
            gas: U256::from(100_000),
            gas_price: U256::one(),
            nonce: U256::zero(),
        }
        .sign(keypair.secret());
        let sender = t.sender();

        let storage_manager = new_state_manager_for_unit_test();
        let mut state =
            get_state_for_genesis_write_with_factory(&storage_manager, factory);
        state
            .add_balance(&sender, &U256::from(100_017), CleanupMode::NoEmpty)
            .unwrap();
        let mut env = Env::default();
        env.gas_limit = U256::from(100_000);
        let machine = make_byzantium_machine(0);
        let spec = machine.spec(env.number);

        let res = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            let mut nonce_increased = false;
            ex.transact(&t, &mut nonce_increased)
        };

        match res {
            Err(ExecutionError::NotEnoughCash { required, got })
                if required == U512::from(100_018)
                    && got == U512::from(100_017) =>
            {
                ()
            }
            _ => assert!(false, "Expected not enough cash error. {:?}", res),
        }
    }

    #[test]
    fn test_deposit_withdraw() {
        let factory = Factory::new(VMType::Interpreter, 1024 * 32);
        let sender = Address::zero();
        let storage_manager = new_state_manager_for_unit_test();
        let mut state =
            get_state_for_genesis_write_with_factory(&storage_manager, factory);
        let env = Env::default();
        let machine = make_byzantium_machine(0);
        let spec = machine.spec(env.number);
        let mut substate = Substate::new();
        state
            .add_balance(
                &sender,
                &U256::from(1_000_000_000_000u64),
                CleanupMode::NoEmpty,
            )
            .unwrap();

        let mut params = ActionParams::default();
        params.code_address = STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS.clone();
        params.address = params.code_address;
        params.sender = sender;
        params.original_sender = sender;
        params.original_receiver = params.code_address;
        params.gas = U256::from(100000);
        params.data = Some("b6b55f25000000000000000000000000000000000000000000000000000000174876e800".from_hex().unwrap());

        // wrong call type
        let result = Executive::new(&mut state, &env, &machine, &spec)
            .call(params.clone(), &mut substate);
        assert!(result.is_err());
        assert_eq!(
            state.balance(&sender).unwrap(),
            U256::from(1_000_000_000_000u64)
        );
        assert_eq!(state.bank_balance(&sender).unwrap(), U256::from(0));

        // everything is fine
        params.call_type = CallType::Call;
        let result = Executive::new(&mut state, &env, &machine, &spec)
            .call(params.clone(), &mut substate);
        assert!(result.is_ok());
        assert_eq!(
            state.balance(&sender).unwrap(),
            U256::from(900_000_000_000u64)
        );
        assert_eq!(
            state.bank_balance(&sender).unwrap(),
            U256::from(100_000_000_000u64)
        );

        // empty data
        params.data = None;
        let result = Executive::new(&mut state, &env, &machine, &spec)
            .call(params.clone(), &mut substate);
        assert!(result.is_err());
        assert_eq!(
            state.balance(&sender).unwrap(),
            U256::from(900_000_000_000u64)
        );
        assert_eq!(
            state.bank_balance(&sender).unwrap(),
            U256::from(100_000_000_000u64)
        );

        // less data
        params.data = Some("b6b55f25000000000000000000000000000000000000000000000000000000174876e8".from_hex().unwrap());
        let result = Executive::new(&mut state, &env, &machine, &spec)
            .call(params.clone(), &mut substate);
        assert!(result.is_err());
        assert_eq!(
            state.balance(&sender).unwrap(),
            U256::from(900_000_000_000u64)
        );
        assert_eq!(
            state.bank_balance(&sender).unwrap(),
            U256::from(100_000_000_000u64)
        );

        // more data
        params.data = Some("b6b55f25000000000000000000000000000000000000000000000000000000174876e80000".from_hex().unwrap());
        let result = Executive::new(&mut state, &env, &machine, &spec)
            .call(params.clone(), &mut substate);
        assert!(result.is_err());
        assert_eq!(
            state.balance(&sender).unwrap(),
            U256::from(900_000_000_000u64)
        );
        assert_eq!(
            state.bank_balance(&sender).unwrap(),
            U256::from(100_000_000_000u64)
        );

        // withdraw
        params.data = Some("2e1a7d4d0000000000000000000000000000000000000000000000000000000ba43b7400".from_hex().unwrap());
        let result = Executive::new(&mut state, &env, &machine, &spec)
            .call(params.clone(), &mut substate);
        assert!(result.is_ok());
        assert_eq!(
            state.balance(&sender).unwrap(),
            U256::from(950_000_000_000u64)
        );
        assert_eq!(
            state.bank_balance(&sender).unwrap(),
            U256::from(50_000_000_000u64)
        );
    }

    #[test]
    fn test_commission_privilege() {
        // code:
        //
        // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
        // 29 bytes? 60 00 - push 0
        // 52
        // 60 1d - push 29
        // 60 03 - push 3
        // 60 17 - push 23
        // f0 - create
        // 60 00 - push 0
        // 55 sstore

        let privilege_control_address =
            &COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS;
        let factory = Factory::new(VMType::Interpreter, 1024 * 32);
        let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

        let sender = Address::from_low_u64_ne(0);
        let caller1 = Address::from_low_u64_le(1);
        let caller2 = Address::from_low_u64_le(2);
        let caller3 = Address::from_low_u64_le(3);
        let address = contract_address(
            CreateContractAddress::FromSenderAndNonce,
            &sender,
            &U256::zero(),
            &[],
        )
        .0;
        let mut params = ActionParams::default();
        params.address = address;
        params.code_address = address;
        params.sender = sender;
        params.original_sender = sender;
        params.original_receiver = address;
        params.gas = U256::from(100_000);
        params.gas_price = U256::from(1);
        params.code = Some(Arc::new(code));
        params.value = ActionValue::Transfer(U256::from(1000000));

        let storage_manager = new_state_manager_for_unit_test();
        let mut state =
            get_state_for_genesis_write_with_factory(&storage_manager, factory);
        let env = Env::default();
        let machine = make_byzantium_machine(0);
        let spec = machine.spec(env.number);
        let mut substate = Substate::new();

        state
            .add_balance(
                &sender,
                &U256::from(2_000_000_000_000_000_000u64),
                CleanupMode::NoEmpty,
            )
            .unwrap();
        state
            .deposit(&sender, &U256::from(1_000_000_000_000_000_000u64), 100)
            .unwrap();
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.create(params.clone(), &mut substate).unwrap()
        };

        assert_eq!(gas_left, U256::from(62_976));
        assert_eq!(substate.contracts_created.len(), 0);
        assert_eq!(state.balance(&address).unwrap(), U256::from(1_000_000));

        state
            .add_balance(&caller1, &U256::from(100_000), CleanupMode::NoEmpty)
            .unwrap();
        state
            .add_balance(&caller2, &U256::from(100_000), CleanupMode::NoEmpty)
            .unwrap();
        state
            .add_balance(&caller3, &U256::from(100_000), CleanupMode::NoEmpty)
            .unwrap();
        // add commission privilege to caller1 and caller2
        state
            .add_commission_privilege(
                privilege_control_address,
                address,
                sender,
                caller1,
            )
            .unwrap();
        state
            .add_commission_privilege(
                privilege_control_address,
                address,
                sender,
                caller2,
            )
            .unwrap();
        assert!(state
            .check_commission_privilege(
                privilege_control_address,
                &address,
                &caller1
            )
            .unwrap());
        assert!(state
            .check_commission_privilege(
                privilege_control_address,
                &address,
                &caller2
            )
            .unwrap());
        assert!(!state
            .check_commission_privilege(
                privilege_control_address,
                &address,
                &caller3
            )
            .unwrap());
        // set commission balance to 110000
        state
            .set_commission_balance(&address, &sender, &U256::from(110_000))
            .unwrap();
        assert_eq!(
            state.commission_balance(&address).unwrap(),
            U256::from(110_000)
        );

        params.call_type = CallType::Call;
        params.value = ActionValue::Transfer(U256::from(0));
        assert_eq!(state.balance(&caller3).unwrap(), U256::from(100_000));
        // call with no commission privilege
        params.sender = caller3;
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params.clone(), &mut substate).unwrap()
        };
        assert_eq!(gas_left, U256::from(62_976));
        assert_eq!(state.balance(&caller3).unwrap(), U256::from(100_000));
        assert_eq!(
            state.commission_balance(&address).unwrap(),
            U256::from(110_000)
        );

        assert_eq!(state.balance(&caller1).unwrap(), U256::from(100_000));
        // call with commission privilege and enough commission balance
        params.sender = caller1;
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params.clone(), &mut substate).unwrap()
        };
        assert_eq!(gas_left, U256::from(62_976));
        assert_eq!(state.balance(&caller1).unwrap(), U256::from(200_000));
        assert_eq!(
            state.commission_balance(&address).unwrap(),
            U256::from(10_000)
        );

        assert_eq!(state.balance(&caller2).unwrap(), U256::from(100_000));
        // call with commission privilege and not enough commission balance
        params.sender = caller2;
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params.clone(), &mut substate).unwrap()
        };
        assert_eq!(gas_left, U256::from(62_976));
        assert_eq!(state.balance(&caller2).unwrap(), U256::from(100_000));
        assert_eq!(
            state.commission_balance(&address).unwrap(),
            U256::from(10_000)
        );

        // add more commission balance
        state
            .set_commission_balance(&address, &sender, &U256::from(200_000))
            .unwrap();
        assert_eq!(
            state.commission_balance(&address).unwrap(),
            U256::from(200_000)
        );

        assert_eq!(state.balance(&caller2).unwrap(), U256::from(100_000));
        // call with commission privilege and enough commission balance
        params.sender = caller2;
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params.clone(), &mut substate).unwrap()
        };
        assert_eq!(gas_left, U256::from(62_976));
        assert_eq!(state.balance(&caller2).unwrap(), U256::from(200_000));
        assert_eq!(
            state.commission_balance(&address).unwrap(),
            U256::from(100_000)
        );

        // add commission privilege to caller3
        state
            .add_commission_privilege(
                privilege_control_address,
                address,
                sender,
                caller3,
            )
            .unwrap();
        assert!(state
            .check_commission_privilege(
                privilege_control_address,
                &address,
                &caller3
            )
            .unwrap());
        assert_eq!(state.balance(&caller3).unwrap(), U256::from(100_000));
        // call with commission privilege and enough commission balance
        params.sender = caller3;
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params.clone(), &mut substate).unwrap()
        };
        assert_eq!(gas_left, U256::from(62_976));
        assert_eq!(state.balance(&caller3).unwrap(), U256::from(200_000));
        assert_eq!(state.commission_balance(&address).unwrap(), U256::from(0));
    }

    #[test]
    fn test_storage_commission_privilege() {
        // code:
        //
        // 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push
        // 29 bytes? 60 01 - push 0
        // 52
        // 33 - caller
        // 60 01 - push 1
        // 55 sstore

        let privilege_control_address =
            &STORAGE_COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS;
        let factory = Factory::new(VMType::Interpreter, 1024 * 32);
        let code = "7c601080600c6000396000f3006000355415600957005b6020356000355560005233600155".from_hex().unwrap();

        let sender = Address::from_low_u64_ne(1);
        let caller1 = Address::from_low_u64_le(2);
        let caller2 = Address::from_low_u64_le(3);
        let caller3 = Address::from_low_u64_le(4);
        let address = contract_address(
            CreateContractAddress::FromSenderAndNonce,
            &sender,
            &U256::zero(),
            &[],
        )
        .0;
        let mut params = ActionParams::default();
        params.address = address;
        params.code_address = address;
        params.sender = sender;
        params.original_sender = sender;
        params.original_receiver = address;
        params.gas = U256::from(100_000);
        params.gas_price = U256::from(1);
        params.code = Some(Arc::new(code));
        params.value =
            ActionValue::Transfer(U256::from(RENTAL_PRICE_PER_STORAGE_KEY));

        let storage_manager = new_state_manager_for_unit_test();
        let mut state =
            get_state_for_genesis_write_with_factory(&storage_manager, factory);
        let env = Env::default();
        let machine = make_byzantium_machine(0);
        let spec = machine.spec(env.number);
        let mut substate = Substate::new();

        state
            .add_balance(
                &sender,
                &U256::from(2_000_000_000_000_000_000u64),
                CleanupMode::NoEmpty,
            )
            .unwrap();
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.create(params.clone(), &mut substate).unwrap()
        };

        assert_eq!(gas_left, U256::from(79983));
        assert_eq!(substate.contracts_created.len(), 0);
        assert_eq!(
            state.balance(&address).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );

        state
            .add_balance(
                &caller1,
                &U256::from(RENTAL_PRICE_PER_STORAGE_KEY),
                CleanupMode::NoEmpty,
            )
            .unwrap();
        state
            .add_balance(
                &caller2,
                &U256::from(RENTAL_PRICE_PER_STORAGE_KEY),
                CleanupMode::NoEmpty,
            )
            .unwrap();
        state
            .add_balance(
                &caller3,
                &U256::from(RENTAL_PRICE_PER_STORAGE_KEY),
                CleanupMode::NoEmpty,
            )
            .unwrap();

        // add privilege to caller1 and caller2
        state.checkpoint();
        state
            .add_commission_privilege(
                privilege_control_address,
                address,
                sender,
                caller1,
            )
            .unwrap();
        state
            .add_commission_privilege(
                privilege_control_address,
                address,
                sender,
                caller2,
            )
            .unwrap();
        assert!(state.check_storage_balance(0 /* timestamp */));
        state.discard_checkpoint();
        assert!(state
            .check_commission_privilege(
                privilege_control_address,
                &address,
                &caller1
            )
            .unwrap());
        assert!(state
            .check_commission_privilege(
                privilege_control_address,
                &address,
                &caller2
            )
            .unwrap());
        assert!(!state
            .check_commission_privilege(
                privilege_control_address,
                &address,
                &caller3
            )
            .unwrap());

        params.call_type = CallType::Call;
        params.value = ActionValue::Transfer(U256::from(0));

        // call with no privilege
        assert_eq!(
            state.balance(&caller3).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        params.sender = caller3;
        params.original_sender = caller3;
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params.clone(), &mut substate).unwrap()
        };
        assert_eq!(gas_left, U256::from(94983));
        assert_eq!(state.balance(&caller3).unwrap(), U256::from(0));
        assert_eq!(
            state.bank_balance(&caller3).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        assert_eq!(
            state.storage_balance(&caller3).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );

        // call with privilege
        assert_eq!(
            state.balance(&caller1).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        params.sender = caller1;
        params.original_sender = caller1;
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params.clone(), &mut substate).unwrap()
        };
        assert_eq!(gas_left, U256::from(94983));
        assert_eq!(
            state.balance(&caller1).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        assert_eq!(state.bank_balance(&caller1).unwrap(), U256::from(0));
        assert_eq!(state.storage_balance(&caller1).unwrap(), U256::from(0));
        assert_eq!(state.balance(&address).unwrap(), U256::from(0));
        assert_eq!(
            state.bank_balance(&address).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        assert_eq!(
            state.storage_balance(&address).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        assert_eq!(state.balance(&caller3).unwrap(), U256::from(0));
        assert_eq!(
            state.bank_balance(&caller3).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        assert_eq!(state.storage_balance(&caller3).unwrap(), U256::from(0));

        // another caller call with commission privilege
        assert_eq!(
            state.balance(&caller2).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        params.sender = caller2;
        params.original_sender = caller2;
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params.clone(), &mut substate).unwrap()
        };
        assert_eq!(gas_left, U256::from(94983));
        assert_eq!(
            state.balance(&caller2).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        assert_eq!(state.bank_balance(&caller2).unwrap(), U256::from(0));
        assert_eq!(state.storage_balance(&caller2).unwrap(), U256::from(0));
        assert_eq!(state.balance(&address).unwrap(), U256::from(0));
        assert_eq!(
            state.bank_balance(&address).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        assert_eq!(
            state.storage_balance(&address).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );

        // remove privilege from caller1
        state
            .remove_commission_privilege(
                privilege_control_address,
                address,
                sender,
                caller1,
            )
            .unwrap();
        assert!(!state
            .check_commission_privilege(
                privilege_control_address,
                &address,
                &caller1
            )
            .unwrap());
        assert_eq!(
            state.balance(&caller1).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        params.sender = caller1;
        params.original_sender = caller1;
        let FinalizationResult { gas_left, .. } = {
            let mut ex = Executive::new(&mut state, &env, &machine, &spec);
            ex.call(params.clone(), &mut substate).unwrap()
        };
        assert_eq!(gas_left, U256::from(94983));
        assert_eq!(state.balance(&caller1).unwrap(), U256::from(0));
        assert_eq!(
            state.bank_balance(&caller1).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        assert_eq!(
            state.storage_balance(&caller1).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        assert_eq!(
            state.balance(&address).unwrap(),
            U256::from(RENTAL_PRICE_PER_STORAGE_KEY)
        );
        assert_eq!(state.bank_balance(&address).unwrap(), U256::from(0));
        assert_eq!(state.storage_balance(&address).unwrap(), U256::from(0));
    }
}
