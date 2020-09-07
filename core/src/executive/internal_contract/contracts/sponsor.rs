// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_parameters::internal_contract_addresses::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS;

use super::{
    super::impls::sponsor::*, ExecutionTrait, InterfaceTrait,
    InternalContractTrait, PreExecCheckConfTrait, SolFnTable,
    SolidityFunctionTrait, UpfrontPaymentTrait, SPEC,
};
use crate::{
    evm::{ActionParams, Spec},
    impl_function_type, make_function_table, make_solidity_contract,
    make_solidity_function, rename_interface,
    state::{State, Substate},
    vm,
};
use cfx_types::{address_util::AddressUtil, Address, U256};

lazy_static! {
    static ref CONTRACT_TABLE: SolFnTable = make_function_table!(
        SetSponsorForGasSnake,
        SetSponsorForCollateralSnake,
        AddPrivilegeSnake,
        RemovePrivilegeSnake
    );
    static ref CONTRACT_TABLE_V2: SolFnTable = make_function_table!(
        SetSponsorForGas,
        SetSponsorForCollateral,
        AddPrivilege,
        RemovePrivilege,
        GetSponsorForGas,
        GetSponsorBalanceForGas,
        GetGasFeeUpperBound,
        GetSponsorForCollateral,
        GetSponsorBalanceForCollateral,
        IsWhitelisted,
        IsAllWhitelisted,
        AddPrivilegeByAdmin,
        RemovePrivilegeByAdmin
    );
}

make_solidity_contract! {
    pub struct SponsorWhitelistControl(SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS, CONTRACT_TABLE);
}

make_solidity_function! {
    struct SetSponsorForGas((Address, U256), "setSponsorforGas(address,uint256)");
}
impl_function_type!(SetSponsorForGas, "payable_write", gas: 2 * SPEC.sstore_reset_gas);

rename_interface! {
    struct SetSponsorForGasSnake(SetSponsorForGas, "set_sponsor_for_gas(address,uint256)");
}

impl ExecutionTrait for SetSponsorForGas {
    fn execute_inner(
        &self, inputs: (Address, U256), params: &ActionParams, spec: &Spec,
        state: &mut State, substate: &mut Substate,
    ) -> vm::Result<()>
    {
        set_sponsor_for_gas(inputs.0, inputs.1, params, spec, state, substate)
    }
}

make_solidity_function! {
    struct SetSponsorForCollateral(Address, "setSponsorforCollateral(address)");
}
impl_function_type!(SetSponsorForCollateral, "payable_write", gas: 2 * SPEC.sstore_reset_gas);

rename_interface! {
    struct SetSponsorForCollateralSnake(SetSponsorForCollateral, "set_sponsor_for_collateral(address)");
}

impl ExecutionTrait for SetSponsorForCollateral {
    fn execute_inner(
        &self, input: Address, params: &ActionParams, spec: &Spec,
        state: &mut State, substate: &mut Substate,
    ) -> vm::Result<()>
    {
        set_sponsor_for_collateral(input, params, spec, state, substate)
    }
}

make_solidity_function! {
    struct AddPrivilege(Vec<Address>, "addPrivilege(address[])");
}
impl_function_type!(AddPrivilege, "non_payable_write");
rename_interface! {
    struct AddPrivilegeSnake(AddPrivilege, "add_privilege(address[])");
}

impl UpfrontPaymentTrait for AddPrivilege {
    fn upfront_gas_payment(
        &self, input: &Vec<Address>, _: &ActionParams, spec: &Spec, _: &State,
    ) -> U256 {
        U256::from(spec.sstore_reset_gas) * input.len()
    }
}

impl ExecutionTrait for AddPrivilege {
    fn execute_inner(
        &self, addresses: Vec<Address>, params: &ActionParams, _: &Spec,
        state: &mut State, _: &mut Substate,
    ) -> vm::Result<()>
    {
        if !params.sender.is_contract_address() {
            return Err(vm::Error::InternalContract(
                "normal account is not allowed to set commission_privilege",
            ));
        }
        add_privilege(params.sender, addresses, params, state)
    }
}

make_solidity_function! {
    struct RemovePrivilege(Vec<Address>, "removePrivilege(address[])");
}
impl_function_type!(RemovePrivilege, "non_payable_write");
rename_interface! {
    struct RemovePrivilegeSnake(RemovePrivilege, "remove_privilege(address[])");
}

impl UpfrontPaymentTrait for RemovePrivilege {
    fn upfront_gas_payment(
        &self, input: &Vec<Address>, _: &ActionParams, spec: &Spec, _: &State,
    ) -> U256 {
        U256::from(spec.sstore_reset_gas) * input.len()
    }
}

impl ExecutionTrait for RemovePrivilege {
    fn execute_inner(
        &self, addresses: Vec<Address>, params: &ActionParams, _: &Spec,
        state: &mut State, _: &mut Substate,
    ) -> vm::Result<()>
    {
        if !params.sender.is_contract_address() {
            return Err(vm::Error::InternalContract(
                "normal account is not allowed to set commission_privilege",
            ));
        }

        remove_privilege(params.sender, addresses, params, state)
    }
}

make_solidity_function! {
    struct GetSponsorForGas(Address, "getSponsorforGas(address)", Address);
}
impl_function_type!(GetSponsorForGas, "query_with_default_gas");

impl ExecutionTrait for GetSponsorForGas {
    fn execute_inner(
        &self, input: Address, _: &ActionParams, _: &Spec, state: &mut State,
        _: &mut Substate,
    ) -> vm::Result<Address>
    {
        Ok(state.sponsor_for_gas(&input)?.unwrap_or_default())
    }
}

make_solidity_function! {
    struct GetSponsorBalanceForGas(Address, "getSponsoredBalanceforGas(address)", U256);
}
impl_function_type!(GetSponsorBalanceForGas, "query_with_default_gas");

impl ExecutionTrait for GetSponsorBalanceForGas {
    fn execute_inner(
        &self, input: Address, _: &ActionParams, _: &Spec, state: &mut State,
        _: &mut Substate,
    ) -> vm::Result<U256>
    {
        Ok(state.sponsor_balance_for_gas(&input)?)
    }
}

make_solidity_function! {
    struct GetGasFeeUpperBound(Address, "getSponsoredGasFeeUpperbound(address)", U256);
}
impl_function_type!(GetGasFeeUpperBound, "query_with_default_gas");

impl ExecutionTrait for GetGasFeeUpperBound {
    fn execute_inner(
        &self, input: Address, _: &ActionParams, _: &Spec, state: &mut State,
        _: &mut Substate,
    ) -> vm::Result<U256>
    {
        Ok(state.sponsor_gas_bound(&input)?)
    }
}

make_solidity_function! {
    struct GetSponsorForCollateral(Address, "getSponsorforCollateral(address)",Address);
}
impl_function_type!(GetSponsorForCollateral, "query_with_default_gas");

impl ExecutionTrait for GetSponsorForCollateral {
    fn execute_inner(
        &self, input: Address, _: &ActionParams, _: &Spec, state: &mut State,
        _: &mut Substate,
    ) -> vm::Result<Address>
    {
        Ok(state.sponsor_for_collateral(&input)?.unwrap_or_default())
    }
}

make_solidity_function! {
    struct GetSponsorBalanceForCollateral(Address, "getSponsoredBalanceforCollateral(address)",U256);
}
impl_function_type!(GetSponsorBalanceForCollateral, "query_with_default_gas");

impl ExecutionTrait for GetSponsorBalanceForCollateral {
    fn execute_inner(
        &self, input: Address, _: &ActionParams, _: &Spec, state: &mut State,
        _: &mut Substate,
    ) -> vm::Result<U256>
    {
        Ok(state.sponsor_balance_for_collateral(&input)?)
    }
}

make_solidity_function! {
    struct IsWhitelisted((Address,Address), "isWhitelisted(address,address)", bool);
}
impl_function_type!(IsWhitelisted, "query", gas: SPEC.sload_gas);

impl ExecutionTrait for IsWhitelisted {
    fn execute_inner(
        &self, (contract, user): (Address, Address), _: &ActionParams,
        _: &Spec, state: &mut State, _: &mut Substate,
    ) -> vm::Result<bool>
    {
        if contract.is_contract_address() {
            Ok(state.check_commission_privilege(&contract, &user)?)
        } else {
            Ok(false)
        }
    }
}

make_solidity_function! {
    struct IsAllWhitelisted(Address, "isAllWhitelisted(address)", bool);
}
impl_function_type!(IsAllWhitelisted, "query", gas: SPEC.sload_gas);

impl ExecutionTrait for IsAllWhitelisted {
    fn execute_inner(
        &self, contract: Address, _: &ActionParams, _: &Spec,
        state: &mut State, _: &mut Substate,
    ) -> vm::Result<bool>
    {
        if contract.is_contract_address() {
            Ok(
                state
                    .check_commission_privilege(&contract, &Address::zero())?,
            )
        } else {
            Ok(false)
        }
    }
}

make_solidity_function! {
    struct AddPrivilegeByAdmin((Address,Vec<Address>), "addPrivilegebyAdmin(address,address[])");
}
impl_function_type!(AddPrivilegeByAdmin, "non_payable_write");

impl UpfrontPaymentTrait for AddPrivilegeByAdmin {
    fn upfront_gas_payment(
        &self, (_contract, addresses): &(Address, Vec<Address>),
        _: &ActionParams, spec: &Spec, _: &State,
    ) -> U256
    {
        U256::from(spec.sstore_reset_gas) * addresses.len()
    }
}

impl ExecutionTrait for AddPrivilegeByAdmin {
    fn execute_inner(
        &self, (contract, addresses): (Address, Vec<Address>),
        params: &ActionParams, _: &Spec, state: &mut State, _: &mut Substate,
    ) -> vm::Result<()>
    {
        if contract.is_contract_address()
            && &params.sender == &state.admin(&contract)?
        {
            add_privilege(contract, addresses, params, state)?
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
        _: &ActionParams, spec: &Spec, _: &State,
    ) -> U256
    {
        U256::from(spec.sstore_reset_gas) * addresses.len()
    }
}

impl ExecutionTrait for RemovePrivilegeByAdmin {
    fn execute_inner(
        &self, (contract, addresses): (Address, Vec<Address>),
        params: &ActionParams, _: &Spec, state: &mut State, _: &mut Substate,
    ) -> vm::Result<()>
    {
        if contract.is_contract_address()
            && &params.sender == &state.admin(&contract)?
        {
            remove_privilege(contract, addresses, params, state)?
        }
        Ok(())
    }
}

#[test]
fn test_sponsor_contract_sig() {
    /// The first 4 bytes of keccak('set_sponsor_for_gas(address,uint256)') is
    /// `0xe9ac3d4a`.
    static SET_SPONSOR_FOR_GAS_SIG: &'static [u8] = &[0xe9, 0xac, 0x3d, 0x4a];
    /// The first 4 bytes of keccak('set_sponsor_for_collateral(address)') is
    /// `0x0862bf68`.
    static SET_SPONSOR_FOR_COLLATERAL_SIG: &'static [u8] =
        &[0x08, 0x62, 0xbf, 0x68];
    /// The first 4 bytes of keccak('add_privilege(address[])') is `0xfe15156c`.
    static ADD_PRIVILEGE_SIG: &'static [u8] = &[0xfe, 0x15, 0x15, 0x6c];
    /// The first 4 bytes of keccak('remove_privilege(address[])') is
    /// `0x44c0bd21`.
    static REMOVE_PRIVILEGE_SIG: &'static [u8] = &[0x44, 0xc0, 0xbd, 0x21];

    assert_eq!(
        SetSponsorForGasSnake {}.function_sig().to_vec(),
        SET_SPONSOR_FOR_GAS_SIG.to_vec()
    );
    assert_eq!(
        SetSponsorForCollateralSnake {}.function_sig().to_vec(),
        SET_SPONSOR_FOR_COLLATERAL_SIG.to_vec()
    );
    assert_eq!(
        AddPrivilegeSnake {}.function_sig().to_vec(),
        ADD_PRIVILEGE_SIG.to_vec()
    );
    assert_eq!(
        RemovePrivilegeSnake {}.function_sig().to_vec(),
        REMOVE_PRIVILEGE_SIG.to_vec()
    );
}
