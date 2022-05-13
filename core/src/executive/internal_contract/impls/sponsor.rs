// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    internal_bail,
    observer::{AddressPocket, VmObserve},
    state::cleanup_mode,
    vm::{self, ActionParams, Spec},
};
use cfx_state::{state_trait::StateOpsTrait, SubstateTrait};
use cfx_types::{Address, AddressSpaceUtil, U256};

use super::super::components::InternalRefContext;

/// Implementation of `set_sponsor_for_gas(address,uint256)`.
pub fn set_sponsor_for_gas(
    contract_address: Address, upper_bound: U256, params: &ActionParams,
    context: &mut InternalRefContext, tracer: &mut dyn VmObserve,
    account_start_nonce: U256,
) -> vm::Result<()>
{
    let sponsor = &params.sender;

    if !context
        .state
        .exists(&contract_address.with_native_space())?
    {
        internal_bail!("contract address not exist");
    }

    if !context.is_contract_address(&contract_address)? {
        internal_bail!("not allowed to sponsor non-contract account");
    }

    let (spec, state, substate): (
        &Spec,
        &mut dyn StateOpsTrait,
        &mut dyn SubstateTrait,
    ) = (context.spec, context.state, context.substate);

    let sponsor_balance = state.balance(&params.address.with_native_space())?;

    if sponsor_balance / U256::from(1000) < upper_bound {
        internal_bail!("sponsor should at least sponsor upper_bound * 1000");
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
            internal_bail!("sponsor_balance is not exceed previous sponsor");
        }
        // `upper_bound` should exceed previous sponsor's `upper_bound`,
        // unless previous sponsor's `sponsor_balance` is not able to cover
        // the upper bound.
        if prev_sponsor_balance >= prev_upper_bound
            && upper_bound < prev_upper_bound
        {
            internal_bail!("upper_bound is not exceed previous sponsor");
        }
        // refund to previous sponsor
        if prev_sponsor.is_some() {
            tracer.trace_internal_transfer(
                AddressPocket::SponsorBalanceForGas(contract_address),
                AddressPocket::Balance(
                    prev_sponsor.unwrap().with_native_space(),
                ),
                prev_sponsor_balance,
            );
            state.add_balance(
                &prev_sponsor.as_ref().unwrap().with_native_space(),
                &prev_sponsor_balance,
                cleanup_mode(substate, &spec),
                account_start_nonce,
            )?;
        }
        tracer.trace_internal_transfer(
            AddressPocket::Balance(params.address.with_space(params.space)),
            AddressPocket::SponsorBalanceForGas(contract_address),
            sponsor_balance,
        );
        state.sub_balance(
            &params.address.with_native_space(),
            &sponsor_balance,
            &mut cleanup_mode(substate, &spec),
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
            internal_bail!("cannot change upper_bound to a smaller one");
        }

        tracer.trace_internal_transfer(
            AddressPocket::Balance(params.address.with_space(params.space)),
            AddressPocket::SponsorBalanceForGas(contract_address),
            sponsor_balance,
        );
        state.sub_balance(
            &params.address.with_native_space(),
            &sponsor_balance,
            &mut cleanup_mode(substate, &spec),
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
pub fn set_sponsor_for_collateral(
    contract_address: Address, params: &ActionParams,
    context: &mut InternalRefContext, tracer: &mut dyn VmObserve,
    account_start_nonce: U256,
) -> vm::Result<()>
{
    let sponsor = &params.sender;

    if !context
        .state
        .exists(&contract_address.with_native_space())?
    {
        internal_bail!("contract address not exist");
    }

    if !context.is_contract_address(&contract_address)? {
        internal_bail!("not allowed to sponsor non-contract account");
    }

    let (spec, state, substate): (
        &Spec,
        &mut dyn StateOpsTrait,
        &mut dyn SubstateTrait,
    ) = (context.spec, context.state, context.substate);

    let sponsor_balance = state.balance(&params.address.with_native_space())?;

    if sponsor_balance.is_zero() {
        internal_bail!("zero sponsor balance is not allowed");
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
            internal_bail!("sponsor_balance is not enough to cover previous sponsor's sponsor_balance and collateral_for_storage");
        }
        // refund to previous sponsor
        if let Some(ref prev_sponsor) = prev_sponsor {
            tracer.trace_internal_transfer(
                AddressPocket::SponsorBalanceForStorage(contract_address),
                AddressPocket::Balance(prev_sponsor.with_native_space()),
                prev_sponsor_balance,
            );
            tracer.trace_internal_transfer(
                AddressPocket::Balance(params.address.with_space(params.space)),
                AddressPocket::Balance(prev_sponsor.with_native_space()),
                collateral_for_storage,
            );
            state.add_balance(
                &prev_sponsor.with_native_space(),
                &(prev_sponsor_balance + collateral_for_storage),
                cleanup_mode(substate, &spec),
                account_start_nonce,
            )?;
        } else {
            assert_eq!(collateral_for_storage, U256::zero());
        }
        tracer.trace_internal_transfer(
            AddressPocket::Balance(params.address.with_space(params.space)),
            AddressPocket::SponsorBalanceForStorage(contract_address),
            sponsor_balance - collateral_for_storage,
        );
        state.sub_balance(
            &params.address.with_native_space(),
            &sponsor_balance,
            &mut cleanup_mode(substate, &spec),
        )?;
        state.set_sponsor_for_collateral(
            &contract_address,
            sponsor,
            &(sponsor_balance - collateral_for_storage),
        )?;
    } else {
        tracer.trace_internal_transfer(
            AddressPocket::Balance(params.address.with_space(params.space)),
            AddressPocket::SponsorBalanceForStorage(contract_address),
            sponsor_balance,
        );
        state.sub_balance(
            &params.address.with_native_space(),
            &sponsor_balance,
            &mut cleanup_mode(substate, &spec),
        )?;
        state.set_sponsor_for_collateral(
            &contract_address,
            sponsor,
            &(sponsor_balance + prev_sponsor_balance),
        )?;
    }
    Ok(())
}

/// Implementation of `addPrivilege(address[])` and
/// `addPrivilegeByAdmin(address,address[])`.
pub fn add_privilege(
    contract: Address, addresses: Vec<Address>, params: &ActionParams,
    state: &mut dyn StateOpsTrait,
) -> vm::Result<()>
{
    for user_addr in addresses {
        state.add_commission_privilege(
            contract,
            params.storage_owner,
            user_addr,
        )?;
    }

    Ok(())
}

/// Implementation of `removePrivilege(address[])` and
/// `removePrivilegeByAdmin(address,address[])`.
pub fn remove_privilege(
    contract: Address, addresses: Vec<Address>, params: &ActionParams,
    state: &mut dyn StateOpsTrait,
) -> vm::Result<()>
{
    for user_addr in addresses {
        state.remove_commission_privilege(
            contract,
            params.storage_owner,
            user_addr,
        )?;
    }
    Ok(())
}
