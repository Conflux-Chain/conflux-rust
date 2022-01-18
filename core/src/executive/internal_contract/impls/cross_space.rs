use crate::{
    evm::{
        ActionParams, CallType, Context, ContractCreateResult,
        CreateContractAddress, GasLeft, MessageCallResult, ReturnData,
    },
    executive::{
        contract_address,
        executive::gas_required_for,
        internal_contract::contracts::{
            CallEvent, CreateEvent, ReturnEvent, WithdrawEvent,
        },
        InternalRefContext, SolidityEventTrait,
    },
    observer::{AddressPocket, VmObserve},
    state::cleanup_mode,
    vm::{
        self, ActionValue, CreateType, Exec, ExecTrapError as ExecTrap,
        ExecTrapResult, ParamsType, ResumeCall, ResumeCreate, Spec, TrapResult,
    },
};
use cfx_parameters::{
    block::CROSS_SPACE_GAS_RATIO,
    internal_contract_addresses::CROSS_SPACE_CONTRACT_ADDRESS,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{
    Address, AddressSpaceUtil, AddressWithSpace, Bloom, Space, H256, U256,
};
use keccak_hash::keccak;
use primitives::{
    receipt::{EVM_SPACE_FAIL, EVM_SPACE_SUCCESS},
    Action, LogEntry,
};
use solidity_abi::{ABIDecodable, ABIEncodable};
use std::{marker::PhantomData, sync::Arc};

pub fn create_gas(context: &InternalRefContext, code: &[u8]) -> DbResult<U256> {
    let code_length = code.len();

    let transaction_gas =
        gas_required_for(/* is_create */ true, code, context.spec);

    let create_gas = U256::from(context.spec.create_gas);

    let address_mapping_gas = context.spec.sha3_gas * 3;

    let create_log_gas = {
        let log_data_length = H256::len_bytes() * 5 + code_length;
        context.spec.log_gas
            + 3 * context.spec.log_topic_gas
            + context.spec.log_data_gas * log_data_length
    };

    let return_log_gas = {
        let log_data_length = H256::len_bytes() * 3;
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
) -> DbResult<U256>
{
    let data_length = data.len();

    let transaction_gas =
        gas_required_for(/* is_create */ false, data, context.spec);

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

    let address_mapping_gas = context.spec.sha3_gas * 4;

    let call_log_gas = {
        let log_data_length = H256::len_bytes() * 5 + data_length;
        context.spec.log_gas
            + 3 * context.spec.log_topic_gas
            + context.spec.log_data_gas * log_data_length
    };

    let return_log_gas = {
        let log_data_length = H256::len_bytes() * 3;
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
    let address_mapping_gas = spec.sha3_gas * 4;

    call_gas + address_mapping_gas
}

pub fn withdraw_gas(spec: &Spec) -> U256 {
    let call_gas = U256::from(spec.call_value_transfer_gas);
    let transaction_gas = spec.tx_gas;
    let address_mapping_gas = spec.sha3_gas;
    let log_gas = spec.log_gas
        + spec.log_topic_gas * 3
        + spec.log_data_gas * H256::len_bytes();

    call_gas + transaction_gas + address_mapping_gas + log_gas
}

#[derive(Clone)]
pub struct Resume {
    pub params: ActionParams,
    pub gas_retained: U256,
}

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
                    resume: *self,
                    gas_left,
                    return_data: Ok(return_data),
                    apply_state: true,
                }
            }
            ContractCreateResult::Failed(err) => PassResult {
                resume: *self,
                gas_left: U256::zero(),
                return_data: Err(err),
                apply_state: false,
            },
            ContractCreateResult::Reverted(gas_left, data) => PassResult {
                resume: *self,
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
            MessageCallResult::Success(gas_left, data) => {
                let encoded_output = data.to_vec().abi_encode();
                let length = encoded_output.len();
                let return_data = ReturnData::new(encoded_output, 0, length);
                PassResult {
                    resume: *self,
                    gas_left,
                    return_data: Ok(return_data),
                    apply_state: true,
                }
            }
            MessageCallResult::Failed(err) => PassResult {
                resume: *self,
                gas_left: U256::zero(),
                return_data: Err(err),
                apply_state: false,
            },
            MessageCallResult::Reverted(gas_left, data) => PassResult {
                resume: *self,
                gas_left,
                return_data: Ok(data),
                apply_state: false,
            },
        };
        Box::new(pass_result)
    }
}

pub struct PassResult {
    resume: Resume,
    gas_left: U256,
    return_data: Result<ReturnData, vm::Error>,
    apply_state: bool,
}

impl Exec for PassResult {
    fn exec(
        mut self: Box<Self>, context: &mut dyn Context,
        _tracer: &mut dyn VmObserve,
    ) -> ExecTrapResult<GasLeft>
    {
        let context = &mut context.internal_ref();
        let params = &self.resume.params;
        let static_flag = context.static_flag;

        let mut log_return = || {
            let mapped_sender = evm_map(params.sender);
            let nonce = context.state.nonce(&mapped_sender)?;
            context
                .state
                .inc_nonce(&mapped_sender, &context.spec.account_start_nonce)?;
            ReturnEvent::log(
                &(),
                &(nonce, self.gas_left, self.apply_state),
                &self.resume.params,
                context,
            )?;
            Ok(())
        };

        if !static_flag {
            let res = log_return();
            if let Err(e) = res {
                return TrapResult::Return(Err(e));
            }
        }

        let mut gas_returned = U256::zero();
        if let Ok(ref data) = self.return_data {
            let length = data.len();
            let return_cost =
                U256::from((length + 31) / 32 * context.spec.memory_gas);
            let gas_left = self.gas_left + self.resume.gas_retained;
            if gas_left < return_cost {
                gas_returned = U256::zero();
                self.return_data = Err(vm::Error::OutOfGas);
                self.apply_state = false;
            } else {
                gas_returned = gas_left - return_cost;
            }
        }

        let result = match self.return_data {
            Ok(data) => Ok(GasLeft::NeedsReturn {
                gas_left: gas_returned,
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
    tracer: &mut dyn VmObserve,
) -> Result<ExecTrap, vm::Error>
{
    if context.depth >= context.spec.max_depth {
        return Err(vm::Error::InternalContract("Exceed Depth".into()));
    }

    let value = params.value.value();

    let call_gas = gas_left / CROSS_SPACE_GAS_RATIO
        + if value > U256::zero() {
            U256::from(context.spec.call_stipend)
        } else {
            U256::zero()
        };
    let reserved_gas = gas_left - gas_left / CROSS_SPACE_GAS_RATIO;

    let mapped_sender = evm_map(params.sender);
    let mapped_origin = evm_map(params.original_sender);

    context.state.transfer_balance(
        &params.address.with_native_space(),
        &mapped_sender,
        &value,
        cleanup_mode(context.substate, context.spec),
        context.spec.account_start_nonce,
    )?;
    context.state.add_total_evm_tokens(value);
    tracer.trace_internal_transfer(
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

    if call_type == CallType::Call {
        let nonce = context.state.nonce(&mapped_sender)?;
        context
            .state
            .inc_nonce(&mapped_sender, &context.spec.account_start_nonce)?;
        CallEvent::log(
            &(mapped_sender.address.0, address.address.0),
            &(value, nonce, call_gas, data),
            params,
            context,
        )?;
    }

    return Ok(ExecTrap::Call(
        next_params,
        Box::new(Resume {
            params: params.clone(),
            gas_retained: reserved_gas,
        }),
    ));
}

pub fn create_to_evmcore(
    init: Vec<u8>, salt: Option<H256>, params: &ActionParams, gas_left: U256,
    context: &mut InternalRefContext, tracer: &mut dyn VmObserve,
) -> Result<ExecTrap, vm::Error>
{
    if context.depth >= context.spec.max_depth {
        return Err(vm::Error::InternalContract("Exceed Depth".into()));
    }

    let call_gas = gas_left / CROSS_SPACE_GAS_RATIO
        + if params.value.value() > U256::zero() {
            U256::from(context.spec.call_stipend)
        } else {
            U256::zero()
        };
    let reserved_gas = gas_left - gas_left / CROSS_SPACE_GAS_RATIO;

    let mapped_sender = evm_map(params.sender);
    let mapped_origin = evm_map(params.original_sender);

    let value = params.value.value();
    context.state.transfer_balance(
        &params.address.with_native_space(),
        &mapped_sender,
        &value,
        cleanup_mode(context.substate, context.spec),
        context.spec.account_start_nonce,
    )?;
    context.state.add_total_evm_tokens(value);
    tracer.trace_internal_transfer(
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
    context
        .state
        .inc_nonce(&mapped_sender, &context.spec.account_start_nonce)?;
    CreateEvent::log(
        &(mapped_sender.address.0, address.0),
        &(value, nonce, call_gas, init),
        params,
        context,
    )?;

    return Ok(ExecTrap::Create(
        next_params,
        Box::new(Resume {
            params: params.clone(),
            gas_retained: reserved_gas,
        }),
    ));
}

pub fn withdraw_from_evmcore(
    sender: Address, value: U256, params: &ActionParams,
    context: &mut InternalRefContext, tracer: &mut dyn VmObserve,
) -> vm::Result<()>
{
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
    context.state.subtract_total_evm_tokens(value);
    tracer.trace_internal_transfer(
        AddressPocket::Balance(mapped_address),
        AddressPocket::Balance(sender.with_native_space()),
        value,
    );

    let nonce = context.state.nonce(&mapped_address)?;
    context
        .state
        .inc_nonce(&mapped_address, &context.spec.account_start_nonce)?;
    WithdrawEvent::log(
        &(mapped_address.address.0, sender),
        &(params.value.value(), nonce),
        params,
        context,
    )?;

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

#[derive(Default)]
pub struct PhantomTransaction {
    pub from: Address,
    pub nonce: U256,
    pub action: Action,
    pub gas_limit: U256,
    pub value: U256,
    pub data: Vec<u8>,

    pub gas_used: U256,
    pub log_bloom: Bloom,
    pub logs: Vec<LogEntry>,
    pub outcome_status_in_evm: u8,
}

impl PhantomTransaction {
    fn simple_transfer(
        from: Address, to: Address, nonce: U256, value: U256, spec: &Spec,
    ) -> PhantomTransaction {
        PhantomTransaction {
            from,
            nonce,
            action: Action::Call(to),
            gas_limit: spec.tx_gas.into(),
            value,
            data: vec![],
            gas_used: spec.tx_gas.into(),
            outcome_status_in_evm: EVM_SPACE_SUCCESS,
            ..Default::default()
        }
    }
}

type Bytes20 = [u8; 20];

pub fn recover_phantom(
    logs: &[LogEntry], spec: &Spec, gas_price: U256,
) -> Vec<PhantomTransaction> {
    let mut phantom_txs: Vec<PhantomTransaction> = Default::default();
    let mut maybe_working_tx: Option<PhantomTransaction> = None;
    for log in logs.iter() {
        if log.address == *CROSS_SPACE_CONTRACT_ADDRESS {
            let event_sig = log.topics.first().unwrap();
            if event_sig == &CallEvent::EVENT_SIG
                || event_sig == &CreateEvent::EVENT_SIG
            {
                assert!(maybe_working_tx.is_none());

                let from = Address::from(
                    Bytes20::abi_decode(&log.topics[1].as_ref()).unwrap(),
                );
                let to = Address::from(
                    Bytes20::abi_decode(&log.topics[2].as_ref()).unwrap(),
                );
                let (value, nonce, gas_limit, data): (_, _, U256, Vec<u8>) =
                    ABIDecodable::abi_decode(&log.data).unwrap();

                let is_create = event_sig == &CreateEvent::EVENT_SIG;
                let gas_limit: U256 =
                    gas_limit + gas_required_for(is_create, &data, spec);
                let action = if is_create {
                    Action::Create
                } else {
                    Action::Call(to)
                };
                // The first phantom transaction for cross-space call, transfer
                // balance and gas fee from the zero address to the mapped
                // sender
                phantom_txs.push(PhantomTransaction::simple_transfer(
                    /* from */ Address::zero(),
                    /* to */ from,
                    U256::zero(), /* TODO: maintain nonce for the zero
                                   * address. */
                    value + gas_limit * gas_price,
                    spec,
                ));
                // The second phantom transaction for cross-space call, transfer
                // balance and gas fee from the zero address to the mapped
                // sender
                maybe_working_tx = Some(PhantomTransaction {
                    from,
                    nonce,
                    action,
                    value,
                    gas_limit,
                    data,
                    ..Default::default()
                });
            } else if event_sig == &WithdrawEvent::EVENT_SIG {
                let from = Address::from(
                    Bytes20::abi_decode(&log.topics[1].as_ref()).unwrap(),
                );
                let (value, nonce) =
                    ABIDecodable::abi_decode(&log.data).unwrap();
                // The only one transaction for the withdraw
                phantom_txs.push(PhantomTransaction::simple_transfer(
                    from,
                    Address::zero(),
                    nonce,
                    value,
                    spec,
                ));
            } else if event_sig == &ReturnEvent::EVENT_SIG {
                let (nonce, gas_left, success): (U256, U256, bool) =
                    ABIDecodable::abi_decode(&log.data).unwrap();

                let mut working_tx =
                    std::mem::take(&mut maybe_working_tx).unwrap();
                working_tx.gas_used = working_tx.gas_limit - gas_left;
                working_tx.outcome_status_in_evm = if success {
                    EVM_SPACE_SUCCESS
                } else {
                    EVM_SPACE_FAIL
                };
                working_tx.log_bloom = working_tx.logs.iter().fold(
                    Bloom::default(),
                    |mut b, l| {
                        b.accrue_bloom(&l.bloom());
                        b
                    },
                );
                let from = working_tx.from;
                // Complete the second transaction for cross-space call.
                phantom_txs.push(working_tx);
                // The third phantom transaction for cross-space call, transfer
                // unused gas fee to the zero address. To indicate it is
                // returned to the native space.
                phantom_txs.push(PhantomTransaction::simple_transfer(
                    from,
                    /* to */ Address::zero(),
                    nonce,
                    gas_left * gas_price,
                    spec,
                ));
            }
        } else if log.space == Space::Ethereum {
            if let Some(ref mut working_tx) = maybe_working_tx {
                working_tx.logs.push(log.clone());
            }
        }
    }
    return phantom_txs;
}
