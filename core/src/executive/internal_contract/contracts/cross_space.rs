// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    super::impls::cross_space::{
        call_gas, call_to_evmcore, create_gas, create_to_evmcore, process_trap,
        withdraw_from_evmcore,
    },
    macros::*,
    SolFnTable,
};
use crate::{
    evm::{ActionParams, CallType, Spec},
    executive::{
        internal_contract::impls::cross_space::{mapped_balance, mapped_nonce},
        InternalRefContext,
    },
    impl_function_type, make_function_table, make_solidity_contract,
    make_solidity_function,
    trace::Tracer,
    vm::{self, ExecTrapResult},
};
use cfx_parameters::internal_contract_addresses::CROSS_SPACE_CONTRACT_ADDRESS;
use cfx_types::{Address, H160, U256};
use std::marker::PhantomData;

type Bytes = Vec<u8>;
type Bytes20 = [u8; 20];

make_solidity_contract! {
    pub struct CrossSpaceCall(CROSS_SPACE_CONTRACT_ADDRESS, generate_fn_table, initialize: |params: &CommonParams| params.transition_numbers.cip90b, is_active: |spec: &Spec| spec.cip90);
}

fn generate_fn_table() -> SolFnTable {
    make_function_table!(
        CreateToEVM,
        Create2ToEVM,
        TransferToEVM,
        CallToEVM,
        StaticCallToEVM,
        Withdraw,
        MappedBalance,
        MappedNonce
    )
}

group_impl_is_active!(
    |spec: &Spec| spec.cip90,
    CreateToEVM,
    Create2ToEVM,
    TransferToEVM,
    CallToEVM,
    StaticCallToEVM,
    Withdraw,
    MappedBalance,
    MappedNonce
);

make_solidity_function! {
    struct CreateToEVM(Bytes, "createEVM(bytes)", Bytes20);
}

impl_function_type!(CreateToEVM, "payable_write");

impl UpfrontPaymentTrait for CreateToEVM {
    fn upfront_gas_payment(
        &self, _input: &Bytes, _params: &ActionParams,
        context: &InternalRefContext,
    ) -> DbResult<U256>
    {
        create_gas(context, 0)
    }
}

impl ExecutionTrait for CreateToEVM {
    fn execute_inner(
        &self, init: Bytes, params: &ActionParams, gas_left: U256,
        context: &mut InternalRefContext, _tracer: &mut dyn Tracer,
    ) -> ExecTrapResult<Bytes20>
    {
        let trap = create_to_evmcore(init, None, params, gas_left, context);
        process_trap(trap, PhantomData)
    }
}

make_solidity_function! {
    struct Create2ToEVM((Bytes,H256), "create2EVM(bytes,bytes32)", Bytes20);
}

impl_function_type!(Create2ToEVM, "payable_write");

impl UpfrontPaymentTrait for Create2ToEVM {
    fn upfront_gas_payment(
        &self, (ref init, _): &(Bytes, H256), _params: &ActionParams,
        context: &InternalRefContext,
    ) -> DbResult<U256>
    {
        create_gas(context, init.len())
    }
}
impl ExecutionTrait for Create2ToEVM {
    fn execute_inner(
        &self, (init, salt): (Bytes, H256), params: &ActionParams,
        gas_left: U256, context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer,
    ) -> ExecTrapResult<Bytes20>
    {
        let trap =
            create_to_evmcore(init, Some(salt), params, gas_left, context);
        process_trap(trap, PhantomData)
    }
}

make_solidity_function! {
    struct TransferToEVM(Bytes20, "transferEVM(bytes20)", Bytes);
}

impl_function_type!(TransferToEVM, "payable_write");

impl UpfrontPaymentTrait for TransferToEVM {
    fn upfront_gas_payment(
        &self, receiver: &Bytes20, params: &ActionParams,
        context: &InternalRefContext,
    ) -> DbResult<U256>
    {
        call_gas(H160(*receiver), params, context, false)
    }
}
impl ExecutionTrait for TransferToEVM {
    fn execute_inner(
        &self, to: Bytes20, params: &ActionParams, gas_left: U256,
        context: &mut InternalRefContext, _tracer: &mut dyn Tracer,
    ) -> ExecTrapResult<Bytes>
    {
        let trap = call_to_evmcore(
            H160(to),
            vec![],
            CallType::Call,
            params,
            gas_left,
            context,
        );
        process_trap(trap, PhantomData)
    }
}

make_solidity_function! {
    struct CallToEVM((Bytes20,Bytes), "callEVM(bytes20,bytes)", Bytes);
}

impl_function_type!(CallToEVM, "payable_write");

impl UpfrontPaymentTrait for CallToEVM {
    fn upfront_gas_payment(
        &self, (ref receiver, _): &(Bytes20, Bytes), params: &ActionParams,
        context: &InternalRefContext,
    ) -> DbResult<U256>
    {
        call_gas(H160(*receiver), params, context, false)
    }
}
impl ExecutionTrait for CallToEVM {
    fn execute_inner(
        &self, (to, data): (Bytes20, Bytes), params: &ActionParams,
        gas_left: U256, context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer,
    ) -> ExecTrapResult<Bytes>
    {
        let trap = call_to_evmcore(
            H160(to),
            data,
            CallType::Call,
            params,
            gas_left,
            context,
        );
        process_trap(trap, PhantomData)
    }
}

make_solidity_function! {
    struct StaticCallToEVM((Bytes20,Bytes), "staticCallEVM(bytes20,bytes)", Bytes);
}

impl_function_type!(StaticCallToEVM, "query");

impl UpfrontPaymentTrait for StaticCallToEVM {
    fn upfront_gas_payment(
        &self, (ref receiver, _): &(Bytes20, Bytes), params: &ActionParams,
        context: &InternalRefContext,
    ) -> DbResult<U256>
    {
        call_gas(H160(*receiver), params, context, true)
    }
}
impl ExecutionTrait for StaticCallToEVM {
    fn execute_inner(
        &self, (to, data): (Bytes20, Bytes), params: &ActionParams,
        gas_left: U256, context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer,
    ) -> ExecTrapResult<Bytes>
    {
        let trap = call_to_evmcore(
            H160(to),
            data,
            CallType::StaticCall,
            params,
            gas_left,
            context,
        );
        process_trap(trap, PhantomData)
    }
}

make_solidity_function! {
    struct Withdraw(U256, "withdrawFromMapped(uint256)");
}

impl_function_type!(Withdraw, "non_payable_write", gas: |spec: &Spec| spec.call_value_transfer_gas);

impl SimpleExecutionTrait for Withdraw {
    fn execute_inner(
        &self, value: U256, params: &ActionParams,
        context: &mut InternalRefContext, _tracer: &mut dyn Tracer,
    ) -> vm::Result<()>
    {
        withdraw_from_evmcore(params.sender, value, context)
    }
}

make_solidity_function! {
    struct MappedBalance(Address, "mappedBalance(address)", U256);
}

impl_function_type!(MappedBalance, "query", gas: |spec: &Spec| spec.balance_gas + spec.sha3_gas);

impl SimpleExecutionTrait for MappedBalance {
    fn execute_inner(
        &self, addr: Address, _params: &ActionParams,
        context: &mut InternalRefContext, _tracer: &mut dyn Tracer,
    ) -> vm::Result<U256>
    {
        mapped_balance(addr, context)
    }
}

make_solidity_function! {
    struct MappedNonce(Address, "mappedNonce(address)", U256);
}

impl_function_type!(MappedNonce, "query", gas: |spec: &Spec| spec.balance_gas + spec.sha3_gas);

impl SimpleExecutionTrait for MappedNonce {
    fn execute_inner(
        &self, addr: Address, _params: &ActionParams,
        context: &mut InternalRefContext, _tracer: &mut dyn Tracer,
    ) -> vm::Result<U256>
    {
        mapped_nonce(addr, context)
    }
}
