use crate::{
    executive::{contract_address, gas_required_for},
    executive_observer::AddressPocket,
    internal_bail,
    stack::{
        Context, Executable, ExecutableOutcome, FrameResult, FrameReturn,
        Resumable,
    },
    substate::cleanup_mode,
};

use cfx_parameters::block::CROSS_SPACE_GAS_RATIO;
use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, Space, H256, U256,
};
use cfx_vm_interpreter::Finalize;
use cfx_vm_types::{
    self as vm, ActionParams, ActionValue, CallType, Context as _,
    CreateContractAddress, CreateType, GasLeft, ParamsType, Spec,
};
use solidity_abi::ABIEncodable;
use std::{marker::PhantomData, sync::Arc};

use super::super::{
    components::{InternalRefContext, InternalTrapResult, SolidityEventTrait},
    contracts::cross_space::{
        CallEvent, CreateEvent, ReturnEvent, WithdrawEvent,
    },
};

pub fn create_gas(context: &InternalRefContext, code: &[u8]) -> DbResult<U256> {
    let code_length = code.len();

    let transaction_gas =
        gas_required_for(/* is_create */ true, code, None, context.spec)
            + context.spec.tx_gas as u64;

    let create_gas = U256::from(context.spec.create_gas);

    let address_mapping_gas = context.spec.sha3_gas * 2;

    let create_log_gas = {
        let log_data_length =
            H256::len_bytes() * 4 + (code_length + 31) / 32 * 32;
        context.spec.log_gas
            + 3 * context.spec.log_topic_gas
            + context.spec.log_data_gas * log_data_length
    };

    let return_log_gas = {
        let log_data_length = H256::len_bytes();
        context.spec.log_gas
            + context.spec.log_topic_gas
            + context.spec.log_data_gas * log_data_length
    };

    Ok(create_gas
        + transaction_gas
        + address_mapping_gas
        + create_log_gas
        + return_log_gas)
}

pub fn call_gas(
    receiver: Address, params: &ActionParams, context: &InternalRefContext,
    data: &[u8],
) -> DbResult<U256> {
    let data_length = data.len();

    let transaction_gas =
        gas_required_for(/* is_create */ false, data, None, context.spec)
            + context.spec.tx_gas as u64;

    let new_account = !context
        .state
        .exists_and_not_null(&receiver.with_evm_space())?;
    let new_account_gas = if new_account {
        context.spec.call_new_account_gas * context.spec.evm_gas_ratio
    } else {
        0
    };

    let transfer_gas = if params.value.value() > U256::zero() {
        context.spec.call_value_transfer_gas
    } else {
        0
    };

    let call_gas =
        U256::from(context.spec.call_gas) + new_account_gas + transfer_gas;

    let address_mapping_gas = context.spec.sha3_gas * 2;

    let call_log_gas = {
        let log_data_length =
            H256::len_bytes() * 4 + (data_length + 31) / 32 * 32;
        context.spec.log_gas
            + 3 * context.spec.log_topic_gas
            + context.spec.log_data_gas * log_data_length
    };

    let return_log_gas = {
        let log_data_length = H256::len_bytes();
        context.spec.log_gas
            + context.spec.log_topic_gas
            + context.spec.log_data_gas * log_data_length
    };

    Ok(call_gas
        + transaction_gas
        + address_mapping_gas
        + call_log_gas
        + return_log_gas)
}

pub fn static_call_gas(spec: &Spec) -> U256 {
    let call_gas = U256::from(spec.call_gas);
    let address_mapping_gas = spec.sha3_gas * 2;

    call_gas + address_mapping_gas
}

pub fn withdraw_gas(spec: &Spec) -> U256 {
    let call_gas = U256::from(spec.call_value_transfer_gas);
    let transaction_gas = spec.tx_gas;
    let address_mapping_gas = spec.sha3_gas;
    let log_gas = spec.log_gas
        + spec.log_topic_gas * 3
        + spec.log_data_gas * H256::len_bytes() * 2;

    call_gas + transaction_gas + address_mapping_gas + log_gas
}

#[derive(Clone)]
pub struct Resume {
    pub params: ActionParams,
    pub gas_retained: U256,
    pub wait_return_log: bool,
}

impl Resumable for Resume {
    fn resume(self: Box<Self>, result: FrameResult) -> Box<dyn Executable> {
        let frame_return = match result {
            Ok(r) => r,
            Err(e) => {
                return Box::new(PassResult {
                    params: self.params,
                    result: Err(e),
                    apply_state: false,
                    wait_return_log: self.wait_return_log,
                });
            }
        };

        let gas_left = self.gas_retained + frame_return.gas_left;
        let apply_state = frame_return.apply_state;

        let data = match frame_return {
            FrameReturn {
                apply_state: true,
                create_address: Some(create_address),
                ..
            } => create_address.0.abi_encode().into(),
            FrameReturn {
                apply_state: true,
                return_data,
                create_address: None,
                ..
            } => return_data.to_vec().abi_encode().into(),
            FrameReturn {
                apply_state: false,
                return_data,
                ..
            } => return_data,
        };

        Box::new(PassResult {
            params: self.params,
            apply_state,
            result: Ok(GasLeft::NeedsReturn {
                gas_left,
                data,
                apply_state,
            }),
            wait_return_log: self.wait_return_log,
        })
    }
}

pub struct PassResult {
    params: ActionParams,
    result: vm::Result<GasLeft>,
    apply_state: bool,
    wait_return_log: bool,
}

impl Executable for PassResult {
    fn execute(
        self: Box<Self>, mut context: Context,
    ) -> DbResult<ExecutableOutcome> {
        if self.wait_return_log {
            ReturnEvent::log(
                &(),
                &self.apply_state,
                &self.params,
                &mut context.internal_ref(),
            )
            .expect("Must have no static flag");
        }

        let result = self
            .result
            .and_then(|r| r.charge_return_data_gas(context.spec()))
            .finalize(context);
        Ok(ExecutableOutcome::Return(result))
    }
}

pub fn process_trap<T>(
    result: vm::Result<(ActionParams, Box<dyn Resumable>)>,
    _phantom: PhantomData<T>,
) -> InternalTrapResult<T> {
    match result {
        Ok((p, r)) => InternalTrapResult::Invoke(p, r),
        Err(err) => InternalTrapResult::Return(Err(err)),
    }
}

pub fn call_to_evmcore(
    receiver: Address, data: Vec<u8>, call_type: CallType,
    params: &ActionParams, gas_left: U256, context: &mut InternalRefContext,
) -> vm::Result<(ActionParams, Box<dyn Resumable>)> {
    if context.depth >= context.spec.max_depth {
        internal_bail!("Exceed Depth");
    }

    let value = params.value.value();

    let call_gas = gas_left / CROSS_SPACE_GAS_RATIO
        + if value > U256::zero() {
            U256::from(context.spec.call_stipend)
        } else {
            U256::zero()
        };
    let reserved_gas = gas_left - gas_left / CROSS_SPACE_GAS_RATIO;

    let mapped_sender = params.sender.evm_map();
    let mapped_origin = params.original_sender.evm_map();

    context.state.transfer_balance(
        &params.address.with_native_space(),
        &mapped_sender,
        &value,
        cleanup_mode(context.substate, context.spec),
    )?;
    context.state.add_total_evm_tokens(value);
    context.tracer.trace_internal_transfer(
        AddressPocket::Balance(params.address.with_native_space()),
        AddressPocket::Balance(mapped_sender),
        params.value.value(),
    );

    let address = receiver.with_evm_space();

    let code = context.state.code(&address)?;
    let code_hash = context.state.code_hash(&address)?;

    let next_params = ActionParams {
        space: Space::Ethereum,
        sender: mapped_sender.address,
        address: address.address,
        value: ActionValue::Transfer(value),
        code_address: address.address,
        original_sender: mapped_origin.address,
        storage_owner: mapped_sender.address,
        gas: call_gas,
        gas_price: params.gas_price,
        code,
        code_hash,
        data: Some(data.clone()),
        call_type,
        create_type: CreateType::None,
        params_type: vm::ParamsType::Separate,
    };

    let mut wait_return_log = false;

    if call_type == CallType::Call {
        let nonce = context.state.nonce(&mapped_sender)?;
        context.state.inc_nonce(&mapped_sender)?;
        CallEvent::log(
            &(mapped_sender.address.0, address.address.0),
            &(value, nonce, data),
            params,
            context,
        )?;
        wait_return_log = true;
    }

    Ok((
        next_params,
        Box::new(Resume {
            params: params.clone(),
            gas_retained: reserved_gas,
            wait_return_log,
        }),
    ))
}

pub fn create_to_evmcore(
    init: Vec<u8>, salt: Option<H256>, params: &ActionParams, gas_left: U256,
    context: &mut InternalRefContext,
) -> vm::Result<(ActionParams, Box<dyn Resumable>)> {
    if context.depth >= context.spec.max_depth {
        internal_bail!("Exceed Depth");
    }

    let call_gas = gas_left / CROSS_SPACE_GAS_RATIO
        + if params.value.value() > U256::zero() {
            U256::from(context.spec.call_stipend)
        } else {
            U256::zero()
        };
    let reserved_gas = gas_left - gas_left / CROSS_SPACE_GAS_RATIO;

    let mapped_sender = params.sender.evm_map();
    let mapped_origin = params.original_sender.evm_map();

    let value = params.value.value();
    context.state.transfer_balance(
        &params.address.with_native_space(),
        &mapped_sender,
        &value,
        cleanup_mode(context.substate, context.spec),
    )?;
    context.state.add_total_evm_tokens(value);
    context.tracer.trace_internal_transfer(
        AddressPocket::Balance(params.address.with_native_space()),
        AddressPocket::Balance(mapped_sender),
        params.value.value(),
    );

    let (address_scheme, create_type) = match salt {
        None => (CreateContractAddress::FromSenderNonce, CreateType::CREATE),
        Some(salt) => (
            CreateContractAddress::FromSenderSaltAndCodeHash(salt),
            CreateType::CREATE2,
        ),
    };
    let (address_with_space, code_hash) = contract_address(
        address_scheme,
        context.env.number.into(),
        &mapped_sender,
        &context.state.nonce(&mapped_sender)?,
        &init,
    );
    let address = address_with_space.address;

    let next_params = ActionParams {
        space: Space::Ethereum,
        code_address: address,
        address,
        sender: mapped_sender.address,
        original_sender: mapped_origin.address,
        storage_owner: Address::zero(),
        gas: call_gas,
        gas_price: params.gas_price,
        value: ActionValue::Transfer(value),
        code: Some(Arc::new(init.clone())),
        code_hash,
        data: None,
        call_type: CallType::None,
        create_type,
        params_type: ParamsType::Embedded,
    };

    let nonce = context.state.nonce(&mapped_sender)?;
    context.state.inc_nonce(&mapped_sender)?;
    CreateEvent::log(
        &(mapped_sender.address.0, address.0),
        &(value, nonce, init),
        params,
        context,
    )?;

    Ok((
        next_params,
        Box::new(Resume {
            params: params.clone(),
            gas_retained: reserved_gas,
            wait_return_log: true,
        }),
    ))
}

pub fn withdraw_from_evmcore(
    sender: Address, value: U256, params: &ActionParams,
    context: &mut InternalRefContext,
) -> vm::Result<()> {
    let mapped_address = sender.evm_map();
    let balance = context.state.balance(&mapped_address)?;
    if balance < value {
        internal_bail!(
            "Not enough balance for withdrawing from mapped address"
        );
    }
    context.state.transfer_balance(
        &mapped_address,
        &sender.with_native_space(),
        &value,
        cleanup_mode(context.substate, context.spec),
    )?;
    context.state.sub_total_evm_tokens(value);
    context.tracer.trace_internal_transfer(
        AddressPocket::Balance(mapped_address),
        AddressPocket::Balance(sender.with_native_space()),
        value,
    );

    let nonce = context.state.nonce(&mapped_address)?;
    context.state.inc_nonce(&mapped_address)?;
    WithdrawEvent::log(
        &(mapped_address.address.0, sender),
        &(value, nonce),
        params,
        context,
    )?;

    Ok(())
}

pub fn mapped_balance(
    address: Address, context: &mut InternalRefContext,
) -> vm::Result<U256> {
    Ok(context.state.balance(&address.evm_map())?)
}

pub fn mapped_nonce(
    address: Address, context: &mut InternalRefContext,
) -> vm::Result<U256> {
    Ok(context.state.nonce(&address.evm_map())?)
}
