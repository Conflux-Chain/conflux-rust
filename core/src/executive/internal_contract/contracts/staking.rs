// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    super::impls::staking::*, ExecutionTrait, InterfaceTrait,
    InternalContractTrait, PreExecCheckConfTrait, SolFnTable,
    SolidityFunctionTrait, UpfrontPaymentTrait,
};
#[cfg(test)]
use crate::check_signature;
use crate::{
    evm::{ActionParams, Spec},
    executive::InternalRefContext,
    impl_function_type, make_function_table, make_solidity_contract,
    make_solidity_function,
    trace::{trace::ExecTrace, Tracer},
    vm,
};
use cfx_parameters::internal_contract_addresses::STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS;
use cfx_state::state_trait::StateOpsTrait;
use cfx_types::{Address, U256};
#[cfg(test)]
use rustc_hex::FromHex;

fn generate_fn_table() -> SolFnTable {
    make_function_table!(
        Deposit,
        Withdraw,
        VoteLock,
        GetStakingBalance,
        GetLockedStakingBalance,
        GetVotePower
    )
}

make_solidity_contract! {
    pub struct Staking(STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS, generate_fn_table);
}

make_solidity_function! {
    struct Deposit(U256,"deposit(uint256)");
}
impl_function_type!(Deposit, "non_payable_write");

impl UpfrontPaymentTrait for Deposit {
    fn upfront_gas_payment(
        &self, _: &Self::Input, params: &ActionParams, spec: &Spec,
        state: &dyn StateOpsTrait,
    ) -> U256
    {
        let length = state.deposit_list_length(&params.sender).unwrap_or(0);
        U256::from(2 * spec.sstore_reset_gas) * U256::from(length + 1)
    }
}

impl ExecutionTrait for Deposit {
    fn execute_inner(
        &self, input: U256, params: &ActionParams,
        context: &mut InternalRefContext,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        deposit(input, params, context.env, context.state, tracer)
    }
}

make_solidity_function! {
    struct Withdraw(U256,"withdraw(uint256)");
}
impl_function_type!(Withdraw, "non_payable_write");

impl UpfrontPaymentTrait for Withdraw {
    fn upfront_gas_payment(
        &self, _input: &Self::Input, params: &ActionParams, spec: &Spec,
        state: &dyn StateOpsTrait,
    ) -> U256
    {
        let length = state.deposit_list_length(&params.sender).unwrap_or(0);
        U256::from(2 * spec.sstore_reset_gas) * U256::from(length)
    }
}

impl ExecutionTrait for Withdraw {
    fn execute_inner(
        &self, input: U256, params: &ActionParams,
        context: &mut InternalRefContext,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        withdraw(input, params, context.env, context.state, tracer)
    }
}

make_solidity_function! {
    struct VoteLock((U256, U256), "voteLock(uint256,uint256)");
}
impl_function_type!(VoteLock, "non_payable_write");

impl UpfrontPaymentTrait for VoteLock {
    fn upfront_gas_payment(
        &self, _input: &Self::Input, params: &ActionParams, spec: &Spec,
        state: &dyn StateOpsTrait,
    ) -> U256
    {
        let length = state.vote_stake_list_length(&params.sender).unwrap_or(0);
        U256::from(2 * spec.sstore_reset_gas) * U256::from(length)
    }
}

impl ExecutionTrait for VoteLock {
    fn execute_inner(
        &self, inputs: (U256, U256), params: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        vote_lock(inputs.0, inputs.1, params, context.env, context.state)
    }
}

make_solidity_function! {
    struct GetStakingBalance(Address, "getStakingBalance(address)", U256);
}
impl_function_type!(GetStakingBalance, "query_with_default_gas");

impl ExecutionTrait for GetStakingBalance {
    fn execute_inner(
        &self, input: Address, _: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<U256>
    {
        Ok(context.state.staking_balance(&input)?)
    }
}

make_solidity_function! {
    struct GetLockedStakingBalance((Address,U256), "getLockedStakingBalance(address,uint256)", U256);
}
impl_function_type!(GetLockedStakingBalance, "query");

impl UpfrontPaymentTrait for GetLockedStakingBalance {
    fn upfront_gas_payment(
        &self, (address, _): &(Address, U256), _: &ActionParams, spec: &Spec,
        state: &dyn StateOpsTrait,
    ) -> U256
    {
        let length = state.vote_stake_list_length(address).unwrap_or(0);
        U256::from(spec.sload_gas) * U256::from(length + 1)
    }
}

impl ExecutionTrait for GetLockedStakingBalance {
    fn execute_inner(
        &self, (address, block_number): (Address, U256), _: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<U256>
    {
        Ok(get_locked_staking(
            address,
            block_number,
            context.env.number,
            context.state,
        )?)
    }
}

make_solidity_function! {
    struct GetVotePower((Address,U256), "getVotePower(address,uint256)", U256);
}
impl_function_type!(GetVotePower, "query");

impl UpfrontPaymentTrait for GetVotePower {
    fn upfront_gas_payment(
        &self, (address, _): &(Address, U256), _: &ActionParams, spec: &Spec,
        state: &dyn StateOpsTrait,
    ) -> U256
    {
        let length = state.vote_stake_list_length(address).unwrap_or(0);
        U256::from(spec.sload_gas) * U256::from(length + 1)
    }
}

impl ExecutionTrait for GetVotePower {
    fn execute_inner(
        &self, (address, block_number): (Address, U256), _: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<U256>
    {
        Ok(get_vote_power(
            address,
            block_number,
            context.env.number,
            context.state,
        )?)
    }
}

#[test]
fn test_staking_contract_sig_v2() {
    // Check the consistency between signature generated by rust code and java
    // sdk.
    check_signature!(GetStakingBalance, "b04ef9c2");
    check_signature!(GetLockedStakingBalance, "b3657ee7");
    check_signature!(GetVotePower, "c90abac8");
    check_signature!(Deposit, "b6b55f25");
    check_signature!(Withdraw, "2e1a7d4d");
    check_signature!(VoteLock, "44a51d6d");
}
