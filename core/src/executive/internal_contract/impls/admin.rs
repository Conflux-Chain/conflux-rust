// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    observer::{AddressPocket, VmObserve},
    state::cleanup_mode,
    vm::{self, ActionParams, Spec},
};
use cfx_state::{state_trait::StateOpsTrait, SubstateTrait};
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, AddressWithSpace,
    Space, U256,
};

use super::super::components::InternalRefContext;

fn available_admin_address(_spec: &Spec, address: &Address) -> bool {
    address.is_user_account_address() || address.is_null_address()
}

/// The Actual Implementation of `suicide`.
/// The contract which has non zero `collateral_for_storage` cannot suicide,
/// otherwise it will:
///   1. refund collateral for code
///   2. refund sponsor balance
///   3. refund contract balance
///   4. kill the contract
pub fn suicide(
    contract_address: &AddressWithSpace, refund_address: &AddressWithSpace,
    state: &mut dyn StateOpsTrait, spec: &Spec,
    substate: &mut dyn SubstateTrait, tracer: &mut dyn VmObserve,
    account_start_nonce: U256,
) -> vm::Result<()>
{
    substate.suicides_mut().insert(contract_address.clone());
    let balance = state.balance(contract_address)?;

    if refund_address == contract_address
        || (!spec.is_valid_address(&refund_address.address)
            && refund_address.space == Space::Native)
    {
        tracer.trace_internal_transfer(
            AddressPocket::Balance(*contract_address),
            AddressPocket::MintBurn,
            balance,
        );
        // When destroying, the balance will be burnt.
        state.sub_balance(
            contract_address,
            &balance,
            &mut cleanup_mode(substate, spec),
        )?;
        state.subtract_total_issued(balance);
        if contract_address.space == Space::Ethereum {
            state.subtract_total_evm_tokens(balance);
        }
    } else {
        trace!(target: "context", "Destroying {} -> {} (xfer: {})", contract_address.address, refund_address.address, balance);
        tracer.trace_internal_transfer(
            AddressPocket::Balance(*contract_address),
            AddressPocket::Balance(*refund_address),
            balance,
        );
        state.transfer_balance(
            contract_address,
            refund_address,
            &balance,
            cleanup_mode(substate, spec),
            account_start_nonce,
        )?;
    }

    Ok(())
}

/// Implementation of `set_admin(address,address)`.
/// The input should consist of 20 bytes `contract_address` + 20 bytes
/// `new_admin_address`
pub fn set_admin(
    contract_address: Address, new_admin_address: Address,
    params: &ActionParams, context: &mut InternalRefContext,
) -> vm::Result<()>
{
    let requester = &params.sender;
    debug!(
        "set_admin requester {:?} contract {:?}, \
         new_admin {:?}, contract_in_creation {:?}",
        requester,
        contract_address,
        new_admin_address,
        context.callstack.contract_in_creation(),
    );

    let clear_admin_in_create = context.callstack.contract_in_creation()
        == Some(&contract_address.with_native_space())
        && new_admin_address.is_null_address();

    if context.is_contract_address(&contract_address)?
        && context.state.exists(&contract_address.with_native_space())?
        // Allow set admin if requester matches or in contract creation to clear admin.
        && (context.state.admin(&contract_address)?.eq(requester)
        || clear_admin_in_create)
        // Only allow user account to be admin, if not to clear admin.
        && available_admin_address(&context.spec, &new_admin_address)
    {
        debug!("set_admin to {:?}", new_admin_address);
        // Admin is cleared by set new_admin_address to null address.
        context
            .state
            .set_admin(&contract_address, &new_admin_address)?;
    }
    Ok(())
}

/// Implementation of `destroy(address)`.
/// The input should consist of 20 bytes `contract_address`
pub fn destroy(
    contract_address: Address, params: &ActionParams,
    state: &mut dyn StateOpsTrait, spec: &Spec,
    substate: &mut dyn SubstateTrait, tracer: &mut dyn VmObserve,
) -> vm::Result<()>
{
    debug!("contract_address={:?}", contract_address);

    let requester = &params.sender;
    let admin = state.admin(&contract_address)?;
    if admin == *requester {
        suicide(
            &contract_address.with_native_space(),
            &admin.with_native_space(),
            state,
            spec,
            substate,
            tracer,
            spec.account_start_nonce,
        )
    } else {
        Ok(())
    }
}
