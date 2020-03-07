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
    parameters::staking::*,
    state::{CleanupMode, CollateralCheckResult, State, Substate},
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
        Address::from_str("843c409373ffd5c0bec1dddb7bec830856757b65").unwrap();
    pub static ref COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("8ad036480160591706c831f0da19d1a424e39469").unwrap();
    pub static ref STORAGE_COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("87ca63b239c537ada331614df304b6ce3caa11f4").unwrap();
    pub static ref ADMIN_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("6060de9e1568e69811c4a398f92c3d10949dc891").unwrap();
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
            // In Conflux, we use the first four bits to indicate the type of
            // the address. For contract address, the bits will be
            // set to 0x8.
            let mut h = Address::from(keccak(stream.as_raw()));
            h.as_bytes_mut()[0] &= 0x0f;
            h.as_bytes_mut()[0] |= 0x80;
            (h, None)
        }
        CreateContractAddress::FromSenderSaltAndCodeHash(salt) => {
            let code_hash = keccak(code);
            let mut buffer = [0u8; 1 + 20 + 32 + 32];
            buffer[0] = 0xff;
            &mut buffer[1..(1 + 20)].copy_from_slice(&sender[..]);
            &mut buffer[(1 + 20)..(1 + 20 + 32)].copy_from_slice(&salt[..]);
            &mut buffer[(1 + 20 + 32)..].copy_from_slice(&code_hash[..]);
            // In Conflux, we use the first bit to indicate the type of the
            // address. For contract address, the bit will be set
            // one.
            let mut h = Address::from(keccak(&buffer[..]));
            h.as_bytes_mut()[0] &= 0x0f;
            h.as_bytes_mut()[0] |= 0x80;
            (h, Some(code_hash))
        }
        CreateContractAddress::FromSenderAndCodeHash => {
            let code_hash = keccak(code);
            let mut buffer = [0u8; 20 + 32];
            &mut buffer[..20].copy_from_slice(&sender[..]);
            &mut buffer[20..].copy_from_slice(&code_hash[..]);
            // In Conflux, we use the first bit to indicate the type of the
            // address. For contract address, the bit will be set
            // one.
            let mut h = Address::from(keccak(&buffer[..]));
            h.as_bytes_mut()[0] &= 0x0f;
            h.as_bytes_mut()[0] |= 0x80;
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

pub fn is_internal_contract(address: &Address) -> bool {
    *address == *STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS
        || *address == *COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS
        || *address == *STORAGE_COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS
        || *address == *ADMIN_CONTROL_CONTRACT_ADDRESS
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
        params: &ActionParams, state: &mut State, val: &U256,
    ) -> vm::Result<()> {
        // FIXME: we should find a reasonable lowerbound.
        if *val < U256::one() {
            Err(vm::Error::InternalContract("invalid deposit amount"))
        } else if state.balance(&params.sender)? < *val {
            Err(vm::Error::InternalContract("not enough balance to deposit"))
        } else {
            state.deposit(&params.sender, &val)?;
            Ok(())
        }
    }

    fn withdraw(
        params: &ActionParams, state: &mut State, val: &U256,
    ) -> vm::Result<()> {
        if state.withdrawable_staking_balance(&params.sender)? < *val {
            Err(vm::Error::InternalContract(
                "not enough withdrawable staking balance to withdraw",
            ))
        } else {
            state.withdraw(&params.sender, &val)?;
            Ok(())
        }
    }

    fn lock(
        params: &ActionParams, state: &mut State, val: &U256,
        duration_in_day: u64,
    ) -> vm::Result<()>
    {
        if duration_in_day == 0
            || duration_in_day
                > (std::u64::MAX - state.block_number()) / BLOCKS_PER_DAY
        {
            Err(vm::Error::InternalContract("invalid lock duration"))
        } else if state.staking_balance(&params.sender)? < *val {
            Err(vm::Error::InternalContract(
                "not enough staking balance to lock",
            ))
        } else {
            state.lock(&params.sender, val, duration_in_day)?;
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
            state.new_contract_with_admin(
                &params.address,
                &params.sender,
                val + balance,
                nonce_offset,
            )?;
        } else {
            state.new_contract_with_admin(
                &params.address,
                &params.sender,
                balance,
                nonce_offset,
            )?;
        }

        Ok(())
    }

    fn enact_result(
        result: &vm::Result<FinalizationResult>, state: &mut State,
        substate: &mut Substate, unconfirmed_substate: Substate,
        sender: &Address, storage_limit: &U256,
    ) -> CollateralCheckResult
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
            Ok(_) | Err(vm::Error::Internal(_)) => {
                let check_result =
                    state.check_collateral_for_storage(sender, storage_limit);
                match check_result {
                    CollateralCheckResult::ExceedStorageLimit { .. } => {
                        state.revert_to_checkpoint();
                    }
                    CollateralCheckResult::NotEnoughBalance { .. } => {
                        state.revert_to_checkpoint();
                    }
                    CollateralCheckResult::Valid => {
                        state.discard_checkpoint();
                        substate.accrue(unconfirmed_substate);
                    }
                }
                check_result
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
    ) -> vm::Result<()> {
        if state.is_contract(&params.sender) {
            return Err(vm::Error::InternalContract(
                "contract accounts are not allowed to deposit or withdraw",
            ));
        }
        if *gas_cost > params.gas {
            return Err(vm::Error::OutOfGas);
        }
        let data = if let Some(ref d) = params.data {
            d as &[u8]
        } else {
            return Err(vm::Error::InternalContract("invalid data"));
        };

        if data[0..4] == [0xb6, 0xb5, 0x5f, 0x25] {
            // The first 4 bytes of
            // keccak('deposit(uint256)') is
            // `0xb6b55f25`.
            // 4 bytes `Method ID` + 32 bytes `amount`
            if data.len() != 36 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let amount = U256::from(&data[4..36]);
                Self::deposit(params, state, &amount)
            }
        } else if data[0..4] == [0x2e, 0x1a, 0x7d, 0x4d] {
            // The first 4 bytes of
            // keccak('withdraw(uint256)') is `0x2e1a7d4d`.
            // 4 bytes `Method ID` + 32 bytes `amount`.
            if data.len() != 36 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let amount = U256::from(&data[4..36]);
                Self::withdraw(params, state, &amount)
            }
        } else if data[0..4] == [0x13, 0x38, 0x73, 0x6f] {
            // The first 4 bytes of
            // keccak('lock(uint256,uint256)') is `0x1338736f`.
            // 4 bytes `Method ID` + 32 bytes `amount` + 32 bytes
            // `duration_in_day`.
            if data.len() != 68 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let amount = U256::from(&data[4..36]);
                let duration_in_day = U256::from(&data[36..68]).low_u64();
                Self::lock(params, state, &amount, duration_in_day)
            }
        } else {
            Ok(())
        }
    }

    fn exec_admin_control_contract(
        params: &ActionParams, state: &mut State, gas_cost: &U256,
    ) -> vm::Result<()> {
        if *gas_cost > params.gas {
            return Err(vm::Error::OutOfGas);
        }
        let data = if let Some(ref d) = params.data {
            d as &[u8]
        } else {
            return Err(vm::Error::InternalContract("invalid data"));
        };

        debug!(
            "exec_admin_contrl_contract params={:?} |data|={:?}",
            params,
            data.len()
        );
        debug!(
            "sig: {:?} {:?} {:?} {:?}",
            data[0], data[1], data[2], data[3]
        );
        if data[0..4] == [0x73, 0xe8, 0x0c, 0xba] {
            // The first 4 bytes of keccak('set_admin(address,address') is
            // 0x73e80cba 4 bytes `Method ID` + 20 bytes
            // `contract_address` + 20 bytes `new_admin_address`
            if data.len() != 68 {
                Err(vm::Error::InternalContract("invalid data"))
            } else {
                let contract_address = Address::from_slice(&data[16..36]);
                let new_admin_address = Address::from_slice(&data[48..68]);
                debug!(
                    "contract_address={:?} new_admin_address={:?}",
                    contract_address, new_admin_address
                );
                Ok(state.set_admin(
                    &params.original_sender,
                    &contract_address,
                    &new_admin_address,
                )?)
            }
        } else {
            Ok(())
        }
    }

    fn exec_commission_privilege_control_contract(
        params: &ActionParams, state: &mut State, gas_cost: &U256,
    ) -> vm::Result<()> {
        if !state.is_contract(&params.sender) {
            return Err(vm::Error::InternalContract(
                "normal account is not allowed to set commission_privilege",
            ));
        }
        if *gas_cost > params.gas {
            return Err(vm::Error::OutOfGas);
        }
        let data = if let Some(ref d) = params.data {
            d as &[u8]
        } else {
            return Err(vm::Error::InternalContract("invalid data"));
        };

        if data[0..4] == [0xdb, 0xcb, 0xf9, 0x50] {
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
        } else if data[0..4] == [0xfe, 0x15, 0x15, 0x6c] {
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
        } else if data[0..4] == [0x44, 0xc0, 0xbd, 0x21] {
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
        if !state.is_contract(&params.sender) {
            return Err(vm::Error::InternalContract("normal account is not allowed to set storage_commission_privilege"));
        }
        if *gas_cost > params.gas {
            return Err(vm::Error::OutOfGas);
        }
        let data = if let Some(ref d) = params.data {
            d as &[u8]
        } else {
            return Err(vm::Error::InternalContract("invalid data"));
        };

        if data[0..4] == [0xfe, 0x15, 0x15, 0x6c] {
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
        } else if data[0..4] == [0x44, 0xc0, 0xbd, 0x21] {
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
                    } else if params.code_address == *ADMIN_CONTROL_CONTRACT_ADDRESS {
                        Self::exec_admin_control_contract(&params, state, &gas_cost)
                    } else {
                        Ok(())
                    };
                    if let Err(e) = result {
                        state.revert_to_checkpoint();
                        Err(e.into())
                    } else {
                        match state.check_collateral_for_storage(
                            &params.original_sender,
                            &params.storage_limit,
                        ) {
                            CollateralCheckResult::ExceedStorageLimit {
                                ..
                            } => {
                                state.revert_to_checkpoint();
                                Err(vm::Error::ExceedStorageLimit)
                            }
                            CollateralCheckResult::NotEnoughBalance {
                                required,
                                got,
                            } => {
                                state.revert_to_checkpoint();
                                Err(vm::Error::NotEnoughBalanceForStorage {
                                    required,
                                    got,
                                })
                            }
                            CollateralCheckResult::Valid => {
                                state.discard_checkpoint();
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
                        }
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
                let sender = *origin.original_sender();
                let storage_limit = *origin.storage_limit();

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

                match Self::enact_result(
                    &res,
                    state,
                    substate,
                    unconfirmed_substate,
                    &sender,
                    &storage_limit,
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
                let sender = *origin.original_sender();
                let storage_limit = *origin.storage_limit();

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

                match Self::enact_result(
                    &res,
                    state,
                    substate,
                    unconfirmed_substate,
                    &sender,
                    &storage_limit,
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
                        self.state.sub_commission_balance(
                            &params.code_address,
                            &gas_cost,
                        )?;
                        assert_eq!(
                            self.state.check_collateral_for_storage(
                                &params.original_sender,
                                &params.storage_limit
                            ),
                            CollateralCheckResult::Valid
                        );
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

        let collateral_for_storage =
            self.state.collateral_for_storage(&sender)?;
        let storage_limit =
            if tx.storage_limit <= U256::MAX - collateral_for_storage {
                tx.storage_limit + collateral_for_storage
            } else {
                U256::MAX
            };

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
                    storage_limit,
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
                    storage_limit,
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
            self.state.kill_account(address);
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
