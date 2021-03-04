// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_parameters::internal_contract_addresses::STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS;

use super::{
    super::impls::staking::*, ExecutionTrait, InterfaceTrait,
    InternalContractTrait, PreExecCheckConfTrait, SolFnTable,
    SolidityFunctionTrait, UpfrontPaymentTrait,
};
#[cfg(test)]
use crate::check_signature;
use crate::{
    evm::{ActionParams, Spec},
    impl_function_type, make_function_table, make_solidity_contract,
    make_solidity_function,
    state::{StateGeneric, Substate},
    trace::{trace::ExecTrace, Tracer},
    vm::{self, Env},
};
use cfx_state::state_trait::StateOpsTrait;
use cfx_storage::StorageStateTrait;
use cfx_types::{Address, U256};
#[cfg(test)]
use rustc_hex::FromHex;

fn generate_fn_table<S: StorageStateTrait + Send + Sync + 'static>(
) -> SolFnTable<S> {
    make_function_table!(
        Deposit<S>,
        Withdraw<S>,
        VoteLock<S>,
        GetStakingBalance<S>,
        GetLockedStakingBalance<S>,
        GetVotePower<S>
    )
}

make_solidity_contract! {
    pub struct Staking(STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS, generate_fn_table);
}

make_solidity_function! {
    struct Deposit(U256,"deposit(uint256)");
}
impl_function_type!(Deposit, "non_payable_write");

impl<S: StorageStateTrait + Send + Sync> UpfrontPaymentTrait<S> for Deposit<S> {
    fn upfront_gas_payment(
        &self, _: &Self::Input, params: &ActionParams, spec: &Spec,
        state: &StateGeneric<S>,
    ) -> U256
    {
        let length = state.deposit_list_length(&params.sender).unwrap_or(0);
        U256::from(2 * spec.sstore_reset_gas) * U256::from(length + 1)
    }
}

impl<S: StorageStateTrait + Send + Sync> ExecutionTrait<S> for Deposit<S> {
    fn execute_inner(
        &self, input: U256, params: &ActionParams, env: &Env, _spec: &Spec,
        state: &mut StateGeneric<S>, _substate: &mut Substate,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        deposit(input, params, env, state, tracer)
    }
}

make_solidity_function! {
    struct Withdraw(U256,"withdraw(uint256)");
}
impl_function_type!(Withdraw, "non_payable_write");

impl<S: StorageStateTrait + Send + Sync> UpfrontPaymentTrait<S>
    for Withdraw<S>
{
    fn upfront_gas_payment(
        &self, _input: &Self::Input, params: &ActionParams, spec: &Spec,
        state: &StateGeneric<S>,
    ) -> U256
    {
        let length = state.deposit_list_length(&params.sender).unwrap_or(0);
        U256::from(2 * spec.sstore_reset_gas) * U256::from(length)
    }
}

impl<S: StorageStateTrait + Send + Sync> ExecutionTrait<S> for Withdraw<S> {
    fn execute_inner(
        &self, input: U256, params: &ActionParams, env: &Env, _spec: &Spec,
        state: &mut StateGeneric<S>, _substate: &mut Substate,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        withdraw(input, params, env, state, tracer)
    }
}

make_solidity_function! {
    struct VoteLock((U256, U256), "voteLock(uint256,uint256)");
}
impl_function_type!(VoteLock, "non_payable_write");

impl<S: StorageStateTrait + Send + Sync> UpfrontPaymentTrait<S>
    for VoteLock<S>
{
    fn upfront_gas_payment(
        &self, _input: &Self::Input, params: &ActionParams, spec: &Spec,
        state: &StateGeneric<S>,
    ) -> U256
    {
        let length = state.vote_stake_list_length(&params.sender).unwrap_or(0);
        U256::from(2 * spec.sstore_reset_gas) * U256::from(length)
    }
}

impl<S: StorageStateTrait + Send + Sync> ExecutionTrait<S> for VoteLock<S> {
    fn execute_inner(
        &self, inputs: (U256, U256), params: &ActionParams, env: &Env,
        _spec: &Spec, state: &mut StateGeneric<S>, _substate: &mut Substate,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        vote_lock(inputs.0, inputs.1, params, env, state)
    }
}

make_solidity_function! {
    struct GetStakingBalance(Address, "getStakingBalance(address)", U256);
}
impl_function_type!(GetStakingBalance, "query_with_default_gas");

impl<S: StorageStateTrait + Send + Sync> ExecutionTrait<S>
    for GetStakingBalance<S>
{
    fn execute_inner(
        &self, input: Address, _: &ActionParams, _env: &Env, _spec: &Spec,
        state: &mut StateGeneric<S>, _substate: &mut Substate,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<U256>
    {
        Ok(state.staking_balance(&input)?)
    }
}

make_solidity_function! {
    struct GetLockedStakingBalance((Address,U256), "getLockedStakingBalance(address,uint256)", U256);
}
impl_function_type!(GetLockedStakingBalance, "query");

impl<S: StorageStateTrait + Send + Sync> UpfrontPaymentTrait<S>
    for GetLockedStakingBalance<S>
{
    fn upfront_gas_payment(
        &self, (address, _): &(Address, U256), _: &ActionParams, spec: &Spec,
        state: &StateGeneric<S>,
    ) -> U256
    {
        let length = state.vote_stake_list_length(address).unwrap_or(0);
        U256::from(spec.sload_gas) * U256::from(length + 1)
    }
}

impl<S: StorageStateTrait + Send + Sync> ExecutionTrait<S>
    for GetLockedStakingBalance<S>
{
    fn execute_inner(
        &self, (address, block_number): (Address, U256), _: &ActionParams,
        env: &Env, _spec: &Spec, state: &mut StateGeneric<S>,
        _substate: &mut Substate, _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<U256>
    {
        Ok(get_locked_staking(
            address,
            block_number,
            env.number,
            state,
        )?)
    }
}

make_solidity_function! {
    struct GetVotePower((Address,U256), "getVotePower(address,uint256)", U256);
}
impl_function_type!(GetVotePower, "query");

impl<S: StorageStateTrait + Send + Sync> UpfrontPaymentTrait<S>
    for GetVotePower<S>
{
    fn upfront_gas_payment(
        &self, (address, _): &(Address, U256), _: &ActionParams, spec: &Spec,
        state: &StateGeneric<S>,
    ) -> U256
    {
        let length = state.vote_stake_list_length(address).unwrap_or(0);
        U256::from(spec.sload_gas) * U256::from(length + 1)
    }
}

impl<S: StorageStateTrait + Send + Sync> ExecutionTrait<S> for GetVotePower<S> {
    fn execute_inner(
        &self, (address, block_number): (Address, U256), _: &ActionParams,
        env: &Env, _spec: &Spec, state: &mut StateGeneric<S>,
        _substate: &mut Substate, _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<U256>
    {
        Ok(get_vote_power(address, block_number, env.number, state)?)
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
