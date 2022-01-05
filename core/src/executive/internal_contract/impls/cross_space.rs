use crate::{
    evm::{
        ActionParams, CallType, Context, ContractCreateResult,
        CreateContractAddress, GasLeft, MessageCallResult, ReturnData,
    },
    executive::{contract_address, InternalRefContext},
    state::cleanup_mode,
    trace::Tracer,
    vm::{
        self, ActionValue, CreateType, Exec, ExecTrapError as ExecTrap,
        ExecTrapResult, ParamsType, ResumeCall, ResumeCreate, TrapResult,
    },
};
use cfx_statedb::Result as DbResult;
use cfx_types::{
    Address, AddressSpaceUtil, AddressWithSpace, Space, H256, U256,
};
use keccak_hash::keccak;
use solidity_abi::ABIEncodable;
use std::{marker::PhantomData, sync::Arc};

pub fn create_gas(
    context: &InternalRefContext, hash_length: usize,
) -> DbResult<U256> {
    let base_gas = U256::from(context.spec.create_gas);
    let hash_words = (hash_length + 31) / 32;

    let keccak_code_gas =
        context.spec.sha3_gas + context.spec.sha3_word_gas * hash_words;

    let address_mapping_gas = context.spec.sha3_gas * 2;

    Ok(base_gas + keccak_code_gas + address_mapping_gas)
}

pub fn call_gas(
    receiver: Address, params: &ActionParams, context: &InternalRefContext,
    is_static: bool,
) -> DbResult<U256>
{
    let new_account_gas = if !is_static
        && context
            .state
            .exists_and_not_null(&receiver.with_evm_space())?
    {
        context.spec.call_new_account_gas
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

    let address_mapping_gas = context.spec.sha3_gas * 3;

    Ok(call_gas + address_mapping_gas)
}

pub struct Resume;

impl ResumeCreate for Resume {
    fn resume_create(
        self: Box<Self>, result: ContractCreateResult,
    ) -> Box<dyn Exec> {
        let pass_result = match result {
            ContractCreateResult::Created(address, gas_left) => {
                let encoded_output = address.address.0.abi_encode();
                let length = encoded_output.len();
                let return_data = ReturnData::new(encoded_output, 0, length);
                PassResult {
                    gas_left,
                    return_data: Ok(return_data),
                    apply_state: true,
                }
            }
            ContractCreateResult::Failed(err) => PassResult {
                gas_left: U256::zero(),
                return_data: Err(err),
                apply_state: false,
            },
            ContractCreateResult::Reverted(gas_left, data) => PassResult {
                gas_left,
                return_data: Ok(data),
                apply_state: false,
            },
        };
        Box::new(pass_result)
    }
}

impl ResumeCall for Resume {
    fn resume_call(
        self: Box<Self>, result: MessageCallResult,
    ) -> Box<dyn Exec> {
        let pass_result = match result {
            MessageCallResult::Success(gas_left, data) => PassResult {
                gas_left,
                return_data: Ok(data),
                apply_state: true,
            },
            MessageCallResult::Failed(err) => PassResult {
                gas_left: U256::zero(),
                return_data: Err(err),
                apply_state: false,
            },
            MessageCallResult::Reverted(gas_left, data) => PassResult {
                gas_left,
                return_data: Ok(data),
                apply_state: false,
            },
        };
        Box::new(pass_result)
    }
}

pub struct PassResult {
    gas_left: U256,
    return_data: Result<ReturnData, vm::Error>,
    apply_state: bool,
}

impl Exec for PassResult {
    fn exec(
        mut self: Box<Self>, context: &mut dyn Context,
        _tracer: &mut dyn Tracer,
    ) -> ExecTrapResult<GasLeft>
    {
        if let Ok(ref data) = self.return_data {
            let length = data.len();
            let return_cost =
                U256::from((length + 31) / 32 * context.spec().memory_gas);
            if self.gas_left < return_cost {
                self.gas_left = U256::zero();
                self.return_data = Err(vm::Error::OutOfGas);
                self.apply_state = false;
            } else {
                self.gas_left -= return_cost;
            }
        }

        let result = match self.return_data {
            Ok(data) => Ok(GasLeft::NeedsReturn {
                gas_left: self.gas_left,
                data,
                apply_state: self.apply_state,
            }),
            Err(err) => Err(err),
        };
        TrapResult::Return(result)
    }
}

pub fn evm_map(address: Address) -> AddressWithSpace {
    Address::from(keccak(&address)).with_evm_space()
}

pub fn process_trap<T>(
    result: Result<ExecTrap, vm::Error>, _phantom: PhantomData<T>,
) -> ExecTrapResult<T> {
    match result {
        Ok(trap) => TrapResult::SubCallCreate(trap),
        Err(err) => TrapResult::Return(Err(err)),
    }
}

pub fn call_to_evmcore(
    receiver: Address, data: Vec<u8>, call_type: CallType,
    params: &ActionParams, gas_left: U256, context: &mut InternalRefContext,
) -> Result<ExecTrap, vm::Error>
{
    if context.depth >= context.spec.max_depth {
        return Err(vm::Error::InternalContract("Exceed Depth".into()));
    }

    let call_gas = gas_left
        + if params.value.value() > U256::zero() {
            U256::from(context.spec.call_stipend)
        } else {
            U256::zero()
        };

    let mapped_sender = evm_map(params.sender);
    let mapped_origin = evm_map(params.original_sender);

    context.state.transfer_balance(
        &params.address.with_native_space(),
        &mapped_sender,
        &params.value.value(),
        cleanup_mode(context.substate, context.spec),
        context.spec.account_start_nonce,
    )?;

    let address = receiver.with_evm_space();

    let code = context.state.code(&address)?;
    let code_hash = context.state.code_hash(&address)?;

    let next_params = ActionParams {
        space: Space::Ethereum,
        sender: mapped_sender.address,
        address: address.address,
        value: ActionValue::Transfer(params.value.value()),
        code_address: address.address,
        original_sender: mapped_origin.address,
        storage_owner: mapped_sender.address,
        gas: call_gas,
        gas_price: params.gas_price,
        code,
        code_hash,
        data: Some(data),
        call_type,
        create_type: CreateType::None,
        params_type: vm::ParamsType::Separate,
    };

    context
        .state
        .inc_nonce(&mapped_sender, &context.spec.account_start_nonce)?;

    return Ok(ExecTrap::Call(next_params, Box::new(Resume)));
}

pub fn create_to_evmcore(
    init: Vec<u8>, salt: Option<H256>, params: &ActionParams, gas_left: U256,
    context: &mut InternalRefContext,
) -> Result<ExecTrap, vm::Error>
{
    if context.depth >= context.spec.max_depth {
        return Err(vm::Error::InternalContract("Exceed Depth".into()));
    }

    let call_gas = gas_left
        + if params.value.value() > U256::zero() {
            U256::from(context.spec.call_stipend)
        } else {
            U256::zero()
        };

    let mapped_sender = evm_map(params.sender);
    let mapped_origin = evm_map(params.original_sender);

    context.state.transfer_balance(
        &params.address.with_native_space(),
        &mapped_sender,
        &params.value.value(),
        cleanup_mode(context.substate, context.spec),
        context.spec.account_start_nonce,
    )?;

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
        value: ActionValue::Transfer(params.value.value()),
        code: Some(Arc::new(init)),
        code_hash,
        data: None,
        call_type: CallType::None,
        create_type,
        params_type: ParamsType::Embedded,
    };

    context
        .state
        .inc_nonce(&mapped_sender, &context.spec.account_start_nonce)?;

    return Ok(ExecTrap::Create(next_params, Box::new(Resume)));
}

pub fn withdraw_from_evmcore(
    sender: Address, value: U256, context: &mut InternalRefContext,
) -> vm::Result<()> {
    let mapped_address = evm_map(sender);
    let balance = context.state.balance(&mapped_address)?;
    if balance < value {
        return Err(vm::Error::InternalContract(
            "Not enough balance for withdrawing from mapped address".into(),
        ));
    }
    context.state.transfer_balance(
        &mapped_address,
        &sender.with_native_space(),
        &value,
        cleanup_mode(context.substate, context.spec),
        context.spec.account_start_nonce,
    )?;
    context
        .state
        .inc_nonce(&mapped_address, &context.spec.account_start_nonce)?;

    Ok(())
}

pub fn mapped_balance(
    address: Address, context: &mut InternalRefContext,
) -> vm::Result<U256> {
    Ok(context.state.balance(&evm_map(address))?)
}

pub fn mapped_nonce(
    address: Address, context: &mut InternalRefContext,
) -> vm::Result<U256> {
    Ok(context.state.nonce(&evm_map(address))?)
}
