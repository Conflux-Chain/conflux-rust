// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    state::{State, Substate},
    vm::{self, ActionParams, Spec},
};
use cfx_types::{address_util::AddressUtil, Address};

/// The Actual Implementation of `suicide`.
/// The contract which has non zero `collateral_for_storage` cannot suicide,
/// otherwise it will:
///   1. refund collateral for code
///   2. refund sponsor balance
///   3. refund contract balance
///   4. kill the contract
pub fn suicide(
    contract_address: &Address, refund_address: &Address, state: &mut State,
    spec: &Spec, substate: &mut Substate,
) -> vm::Result<()>
{
    substate.suicides.insert(contract_address.clone());
    let balance = state.balance(contract_address)?;

    if refund_address == contract_address || !refund_address.is_valid_address()
    {
        // When destroying, the balance will be burnt.
        state.sub_balance(
            contract_address,
            &balance,
            &mut substate.to_cleanup_mode(spec),
        )?;
        state.subtract_total_issued(balance);
    } else {
        trace!(target: "context", "Destroying {} -> {} (xfer: {})", contract_address, refund_address, balance);
        state.transfer_balance(
            contract_address,
            refund_address,
            &balance,
            substate.to_cleanup_mode(spec),
        )?;
    }

    Ok(())
}

/// Implementation of `set_admin(address,address)`.
/// The input should consist of 20 bytes `contract_address` + 20 bytes
/// `new_admin_address`
pub fn set_admin(
    contract_address: Address, new_admin_address: Address,
    params: &ActionParams, state: &mut State,
) -> vm::Result<()>
{
    Ok(state.set_admin(
        &params.original_sender,
        &contract_address,
        &new_admin_address,
    )?)
}

/// Implementation of `destroy(address)`.
/// The input should consist of 20 bytes `contract_address`
pub fn destroy(
    contract_address: Address, params: &ActionParams, state: &mut State,
    spec: &Spec, substate: &mut Substate,
) -> vm::Result<()>
{
    debug!("contract_address={:?}", contract_address);

    let requester = &params.original_sender;
    let admin = state.admin(&contract_address)?;
    if admin == *requester {
        suicide(&contract_address, &admin, state, spec, substate)
    } else {
        Ok(())
    }
}
