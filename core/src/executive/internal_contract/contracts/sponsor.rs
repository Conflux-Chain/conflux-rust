// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{super::impls::sponsor::*, macros::*, ExecutionTrait, SolFnTable};
use crate::{
    evm::{ActionParams, Spec},
    executive::InternalRefContext,
    trace::{trace::ExecTrace, Tracer},
    vm,
};
use cfx_parameters::internal_contract_addresses::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS;
use cfx_state::state_trait::StateOpsTrait;
use cfx_types::{address_util::AddressUtil, Address, U256};
#[cfg(test)]
use rustc_hex::FromHex;

make_solidity_contract! {
    pub struct SponsorWhitelistControl(SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS, generate_fn_table, "active_at_genesis");
}
fn generate_fn_table() -> SolFnTable {
    make_function_table!(
        SetSponsorForGas,
        SetSponsorForCollateral,
        AddPrivilege,
        RemovePrivilege,
        GetSponsorForGas,
        GetSponsoredBalanceForGas,
        GetSponsoredGasFeeUpperBound,
        GetSponsorForCollateral,
        GetSponsoredBalanceForCollateral,
        IsWhitelisted,
        IsAllWhitelisted,
        AddPrivilegeByAdmin,
        RemovePrivilegeByAdmin
    )
}
group_impl_activate_at!(
    "genesis",
    SetSponsorForGas,
    SetSponsorForCollateral,
    AddPrivilege,
    RemovePrivilege,
    GetSponsorForGas,
    GetSponsoredBalanceForGas,
    GetSponsoredGasFeeUpperBound,
    GetSponsorForCollateral,
    GetSponsoredBalanceForCollateral,
    IsWhitelisted,
    IsAllWhitelisted,
    AddPrivilegeByAdmin,
    RemovePrivilegeByAdmin,
);

make_solidity_function! {
    struct SetSponsorForGas((Address, U256), "setSponsorForGas(address,uint256)");
}
impl_function_type!(SetSponsorForGas, "payable_write", gas: |spec: &Spec| 2 * spec.sstore_reset_gas);

impl ExecutionTrait for SetSponsorForGas {
    fn execute_inner(
        &self, inputs: (Address, U256), params: &ActionParams,
        context: &mut InternalRefContext,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        set_sponsor_for_gas(
            inputs.0,
            inputs.1,
            params,
            context.spec,
            context.state,
            context.substate,
            tracer,
            context.spec.account_start_nonce,
        )
    }
}

make_solidity_function! {
    struct SetSponsorForCollateral(Address, "setSponsorForCollateral(address)");
}
impl_function_type!(SetSponsorForCollateral, "payable_write", gas: |spec: &Spec| 2 * spec.sstore_reset_gas);

impl ExecutionTrait for SetSponsorForCollateral {
    fn execute_inner(
        &self, input: Address, params: &ActionParams,
        context: &mut InternalRefContext,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        set_sponsor_for_collateral(
            input,
            params,
            context.spec,
            context.state,
            context.substate,
            tracer,
            context.spec.account_start_nonce,
        )
    }
}

make_solidity_function! {
    struct AddPrivilege(Vec<Address>, "addPrivilege(address[])");
}
impl_function_type!(AddPrivilege, "non_payable_write");

impl UpfrontPaymentTrait for AddPrivilege {
    fn upfront_gas_payment(
        &self, input: &Vec<Address>, _: &ActionParams, spec: &Spec,
        _: &dyn StateOpsTrait,
    ) -> U256
    {
        U256::from(spec.sstore_reset_gas) * input.len()
    }
}

impl ExecutionTrait for AddPrivilege {
    fn execute_inner(
        &self, addresses: Vec<Address>, params: &ActionParams,
        context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        if !params.sender.is_contract_address() {
            return Err(vm::Error::InternalContract(
                "normal account is not allowed to set commission_privilege",
            ));
        }
        add_privilege(params.sender, addresses, params, context.state)
    }
}

make_solidity_function! {
    struct RemovePrivilege(Vec<Address>, "removePrivilege(address[])");
}
impl_function_type!(RemovePrivilege, "non_payable_write");

impl UpfrontPaymentTrait for RemovePrivilege {
    fn upfront_gas_payment(
        &self, input: &Vec<Address>, _: &ActionParams, spec: &Spec,
        _: &dyn StateOpsTrait,
    ) -> U256
    {
        U256::from(spec.sstore_reset_gas) * input.len()
    }
}

impl ExecutionTrait for RemovePrivilege {
    fn execute_inner(
        &self, addresses: Vec<Address>, params: &ActionParams,
        context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        if !params.sender.is_contract_address() {
            return Err(vm::Error::InternalContract(
                "normal account is not allowed to set commission_privilege",
            ));
        }

        remove_privilege(params.sender, addresses, params, context.state)
    }
}

make_solidity_function! {
    struct GetSponsorForGas(Address, "getSponsorForGas(address)", Address);
}
impl_function_type!(GetSponsorForGas, "query_with_default_gas");

impl ExecutionTrait for GetSponsorForGas {
    fn execute_inner(
        &self, input: Address, _: &ActionParams,
        context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<Address>
    {
        Ok(context.state.sponsor_for_gas(&input)?.unwrap_or_default())
    }
}

make_solidity_function! {
    struct GetSponsoredBalanceForGas(Address, "getSponsoredBalanceForGas(address)", U256);
}
impl_function_type!(GetSponsoredBalanceForGas, "query_with_default_gas");

impl ExecutionTrait for GetSponsoredBalanceForGas {
    fn execute_inner(
        &self, input: Address, _: &ActionParams,
        context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<U256>
    {
        Ok(context.state.sponsor_balance_for_gas(&input)?)
    }
}

make_solidity_function! {
    struct GetSponsoredGasFeeUpperBound(Address, "getSponsoredGasFeeUpperBound(address)", U256);
}
impl_function_type!(GetSponsoredGasFeeUpperBound, "query_with_default_gas");

impl ExecutionTrait for GetSponsoredGasFeeUpperBound {
    fn execute_inner(
        &self, input: Address, _: &ActionParams,
        context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<U256>
    {
        Ok(context.state.sponsor_gas_bound(&input)?)
    }
}

make_solidity_function! {
    struct GetSponsorForCollateral(Address, "getSponsorForCollateral(address)",Address);
}
impl_function_type!(GetSponsorForCollateral, "query_with_default_gas");

impl ExecutionTrait for GetSponsorForCollateral {
    fn execute_inner(
        &self, input: Address, _: &ActionParams,
        context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<Address>
    {
        Ok(context
            .state
            .sponsor_for_collateral(&input)?
            .unwrap_or_default())
    }
}

make_solidity_function! {
    struct GetSponsoredBalanceForCollateral(Address, "getSponsoredBalanceForCollateral(address)",U256);
}
impl_function_type!(GetSponsoredBalanceForCollateral, "query_with_default_gas");

impl ExecutionTrait for GetSponsoredBalanceForCollateral {
    fn execute_inner(
        &self, input: Address, _: &ActionParams,
        context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<U256>
    {
        Ok(context.state.sponsor_balance_for_collateral(&input)?)
    }
}

make_solidity_function! {
    struct IsWhitelisted((Address,Address), "isWhitelisted(address,address)", bool);
}
impl_function_type!(IsWhitelisted, "query", gas: |spec: &Spec| spec.sload_gas);

impl ExecutionTrait for IsWhitelisted {
    fn execute_inner(
        &self, (contract, user): (Address, Address), _: &ActionParams,
        context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<bool>
    {
        if contract.is_contract_address() {
            Ok(context.state.check_commission_privilege(&contract, &user)?)
        } else {
            Ok(false)
        }
    }
}

make_solidity_function! {
    struct IsAllWhitelisted(Address, "isAllWhitelisted(address)", bool);
}
impl_function_type!(IsAllWhitelisted, "query", gas: |spec: &Spec| spec.sload_gas);

impl ExecutionTrait for IsAllWhitelisted {
    fn execute_inner(
        &self, contract: Address, _: &ActionParams,
        context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<bool>
    {
        if contract.is_contract_address() {
            Ok(context
                .state
                .check_commission_privilege(&contract, &Address::zero())?)
        } else {
            Ok(false)
        }
    }
}

make_solidity_function! {
    struct AddPrivilegeByAdmin((Address,Vec<Address>), "addPrivilegeByAdmin(address,address[])");
}
impl_function_type!(AddPrivilegeByAdmin, "non_payable_write");

impl UpfrontPaymentTrait for AddPrivilegeByAdmin {
    fn upfront_gas_payment(
        &self, (_contract, addresses): &(Address, Vec<Address>),
        _: &ActionParams, spec: &Spec, _: &dyn StateOpsTrait,
    ) -> U256
    {
        U256::from(spec.sstore_reset_gas) * addresses.len()
    }
}

impl ExecutionTrait for AddPrivilegeByAdmin {
    fn execute_inner(
        &self, (contract, addresses): (Address, Vec<Address>),
        params: &ActionParams, context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        if contract.is_contract_address()
            && &params.sender == &context.state.admin(&contract)?
        {
            add_privilege(contract, addresses, params, context.state)?
        }
        Ok(())
    }
}

make_solidity_function! {
    struct RemovePrivilegeByAdmin((Address,Vec<Address>), "removePrivilegeByAdmin(address,address[])");
}
impl_function_type!(RemovePrivilegeByAdmin, "non_payable_write");

impl UpfrontPaymentTrait for RemovePrivilegeByAdmin {
    fn upfront_gas_payment(
        &self, (_contract, addresses): &(Address, Vec<Address>),
        _: &ActionParams, spec: &Spec, _: &dyn StateOpsTrait,
    ) -> U256
    {
        U256::from(spec.sstore_reset_gas) * addresses.len()
    }
}

impl ExecutionTrait for RemovePrivilegeByAdmin {
    fn execute_inner(
        &self, (contract, addresses): (Address, Vec<Address>),
        params: &ActionParams, context: &mut InternalRefContext,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        if contract.is_contract_address()
            && &params.sender == &context.state.admin(&contract)?
        {
            remove_privilege(contract, addresses, params, context.state)?
        }
        Ok(())
    }
}

#[test]
fn test_sponsor_contract_sig_v2() {
    // Check the consistency between signature generated by rust code and java
    // sdk.
    check_signature!(GetSponsorForGas, "33a1af31");
    check_signature!(GetSponsoredBalanceForGas, "b3b28fac");
    check_signature!(GetSponsoredGasFeeUpperBound, "d665f9dd");
    check_signature!(GetSponsorForCollateral, "8382c3a7");
    check_signature!(GetSponsoredBalanceForCollateral, "d47e9a57");
    check_signature!(IsWhitelisted, "b6b35272");
    check_signature!(IsAllWhitelisted, "79b47faa");
    check_signature!(AddPrivilegeByAdmin, "22effe84");
    check_signature!(RemovePrivilegeByAdmin, "217e055b");
    check_signature!(SetSponsorForGas, "3e3e6428");
    check_signature!(SetSponsorForCollateral, "e66c1bea");
    check_signature!(AddPrivilege, "10128d3e");
    check_signature!(RemovePrivilege, "d2932db6");
}
