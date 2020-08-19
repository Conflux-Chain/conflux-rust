// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    state::{State, Substate},
    vm::{self, ActionParams, Spec},
};
use cfx_types::{address_util::AddressUtil, Address, U256};

/// Implementation of `set_sponsor_for_gas(address,uint256)`.
/// The input should consist of 32 bytes `contract_address` + 32 bytes
/// `upper_bound`.
pub fn set_sponsor_for_gas(
    contract_address: Address, upper_bound: U256, params: &ActionParams,
    spec: &Spec, state: &mut State, substate: &mut Substate,
) -> vm::Result<()>
{
    let sponsor = &params.sender;

    if !state.exists(&contract_address)? {
        return Err(vm::Error::InternalContract("contract address not exist"));
    }

    if !contract_address.is_contract_address() {
        return Err(vm::Error::InternalContract(
            "not allowed to sponsor non-contract account",
        ));
    }

    let sponsor_balance = state.balance(&params.address)?;

    if sponsor_balance / U256::from(1000) < upper_bound {
        return Err(vm::Error::InternalContract(
            "sponsor should at least sponsor upper_bound * 1000",
        ));
    }

    let prev_sponsor = state.sponsor_for_gas(&contract_address)?;
    let prev_sponsor_balance =
        state.sponsor_balance_for_gas(&contract_address)?;
    let prev_upper_bound = state.sponsor_gas_bound(&contract_address)?;
    // If previous sponsor is not the same as current sponsor, we should try
    // to replace the sponsor. Otherwise, we should try to charge
    // `sponsor_balance`.
    if prev_sponsor.as_ref().map_or_else(
        || !sponsor.is_zero(),
        |prev_sponsor| prev_sponsor != sponsor,
    ) {
        // `sponsor_balance` should exceed previous sponsor's
        // `sponsor_balance`.
        if sponsor_balance <= prev_sponsor_balance {
            return Err(vm::Error::InternalContract(
                "sponsor_balance is not exceed previous sponsor",
            ));
        }
        // `upper_bound` should exceed previous sponsor's `upper_bound`,
        // unless previous sponsor's `sponsor_balance` is not able to cover
        // the upper bound.
        if prev_sponsor_balance >= prev_upper_bound
            && upper_bound <= prev_upper_bound
        {
            return Err(vm::Error::InternalContract(
                "upper_bound is not exceed previous sponsor",
            ));
        }
        // refund to previous sponsor
        if prev_sponsor.is_some() {
            state.add_balance(
                prev_sponsor.as_ref().unwrap(),
                &prev_sponsor_balance,
                substate.to_cleanup_mode(&spec),
            )?;
        }
        state.sub_balance(
            &params.address,
            &sponsor_balance,
            &mut substate.to_cleanup_mode(&spec),
        )?;
        state.set_sponsor_for_gas(
            &contract_address,
            sponsor,
            &sponsor_balance,
            &upper_bound,
        )?;
    } else {
        // if previous sponsor's `sponsor_balance` is not able to cover
        // the `upper_bound`, we can adjust the `upper_bound` to a smaller
        // one.
        if prev_sponsor_balance >= prev_upper_bound
            && upper_bound < prev_upper_bound
        {
            return Err(vm::Error::InternalContract(
                "cannot change upper_bound to a smaller one",
            ));
        }
        state.sub_balance(
            &params.address,
            &sponsor_balance,
            &mut substate.to_cleanup_mode(&spec),
        )?;
        state.set_sponsor_for_gas(
            &contract_address,
            sponsor,
            &(sponsor_balance + prev_sponsor_balance),
            &upper_bound,
        )?;
    }

    Ok(())
}

/// Implementation of `set_sponsor_for_collateral(address)`.
/// The input should consist of 32 bytes `contract_address`.
pub fn set_sponsor_for_collateral(
    contract_address: Address, params: &ActionParams, spec: &Spec,
    state: &mut State, substate: &mut Substate,
) -> vm::Result<()>
{
    let sponsor = &params.sender;

    if !state.exists(&contract_address)? {
        return Err(vm::Error::InternalContract("contract address not exist"));
    }

    if !contract_address.is_contract_address() {
        return Err(vm::Error::InternalContract(
            "not allowed to sponsor non-contract account",
        ));
    }

    let sponsor_balance = state.balance(&params.address)?;

    if sponsor_balance.is_zero() {
        return Err(vm::Error::InternalContract(
            "zero sponsor balance is not allowed",
        ));
    }

    let prev_sponsor = state.sponsor_for_collateral(&contract_address)?;
    let prev_sponsor_balance =
        state.sponsor_balance_for_collateral(&contract_address)?;
    let collateral_for_storage =
        state.collateral_for_storage(&contract_address)?;
    // If previous sponsor is not the same as current sponsor, we should try
    // to replace the sponsor. Otherwise, we should try to charge
    // `sponsor_balance`.
    if prev_sponsor.as_ref().map_or_else(
        || !sponsor.is_zero(),
        |prev_sponsor| prev_sponsor != sponsor,
    ) {
        // `sponsor_balance` should exceed previous sponsor's
        // `sponsor_balance` + `collateral_for_storage`.
        if sponsor_balance <= prev_sponsor_balance + collateral_for_storage {
            return Err(vm::Error::InternalContract(
                    "sponsor_balance is not enough to cover previous sponsor's sponsor_balance and collateral_for_storage",
                ));
        }
        // refund to previous sponsor
        if prev_sponsor.is_some() {
            state.add_balance(
                prev_sponsor.as_ref().unwrap(),
                &(prev_sponsor_balance + collateral_for_storage),
                substate.to_cleanup_mode(&spec),
            )?;
        }
        state.sub_balance(
            &params.address,
            &sponsor_balance,
            &mut substate.to_cleanup_mode(&spec),
        )?;
        state.set_sponsor_for_collateral(
            &contract_address,
            sponsor,
            &(sponsor_balance - collateral_for_storage),
        )?;
    } else {
        state.sub_balance(
            &params.address,
            &sponsor_balance,
            &mut substate.to_cleanup_mode(&spec),
        )?;
        state.set_sponsor_for_collateral(
            &contract_address,
            sponsor,
            &(sponsor_balance + prev_sponsor_balance),
        )?;
    }
    Ok(())
}

/// Implementation of `add_privilege(address[])`.
/// The input should consist of 32 bytes location + 32 bytes `length` + ...
pub fn add_privilege(
    addresses: Vec<Address>, params: &ActionParams, state: &mut State,
) -> vm::Result<()> {
    if !params.sender.is_contract_address() {
        return Err(vm::Error::InternalContract(
            "normal account is not allowed to set commission_privilege",
        ));
    }

    let contract_address = params.sender;
    for user_addr in addresses {
        state.add_commission_privilege(
            contract_address,
            params.storage_owner,
            user_addr,
        )?;
    }

    Ok(())
}

/// Implementation of `remove_privilege(address[])`.
/// The input should consist of 32 bytes location + 32 bytes `length` + ...
pub fn remove_privilege(
    addresses: Vec<Address>, params: &ActionParams, state: &mut State,
) -> vm::Result<()> {
    if !params.sender.is_contract_address() {
        return Err(vm::Error::InternalContract(
            "normal account is not allowed to set commission_privilege",
        ));
    }

    let contract_address = params.sender;
    for user_addr in addresses {
        state.remove_commission_privilege(
            contract_address,
            params.storage_owner,
            user_addr,
        )?;
    }
    Ok(())
}
